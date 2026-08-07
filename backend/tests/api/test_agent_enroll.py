"""PRA-154 slice #1c: redemption endpoint tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.access_models import AuditEvent
from app.db.models import (
    ActivationToken,
    ActivationTokenRedemption,
    Credential,
    Group,
    System,
    Tag,
)
from app.services import activation_token_service as svc

# ----------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = Group(name="m14-enroll-group", description="PRA-154 #1c")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def other_group(db):
    g = Group(name="m14-other-group", description="other")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def tag(db, admin_user):
    t = Tag(name="m14-enroll-tag", color="#abcdef", created_by=admin_user.id)
    db.add(t)
    db.flush()
    return t


@pytest.fixture
def system_in_group(db, group, seed_distro):
    cred = Credential(name="cred-enroll", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="enroll-host.example.com",
        ip_address="10.0.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


@pytest.fixture
def system_in_other_group(db, other_group, seed_distro):
    cred = Credential(name="cred-other", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="other-host.example.com",
        ip_address="10.0.0.2",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=other_group.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


@pytest.fixture
def issued_token(db, admin_user, group, system_in_group):
    issued = svc.issue_token(
        db,
        name="enroll-test",
        default_group_id=group.id,
        target_system_id=system_in_group.id,
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        created_by_user_id=admin_user.id,
    )
    db.commit()
    return issued


def _stub_sign(serial="ser-c", expires_in=timedelta(hours=1)):
    def _impl(self, system, csr_pem):  # noqa: ARG001
        return {
            "certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            "serial_number": serial,
            "fingerprint": "fp-c",
            "expires_at": datetime.utcnow() + expires_in,
            "ca_chain": ["ca-pem"],
            "issuing_ca": "ca-pem",
        }

    return _impl


def _enroll(client, *, token, system_id, fingerprint="fp-1", csr="csr-pem"):
    return client.post(
        "/agent/enroll",
        json={
            "system_id": system_id,
            "host_fingerprint": fingerprint,
            "csr_pem": csr,
            "hostname": "enroll-host.example.com",
        },
        headers={"X-Praxis-Activation-Token": token},
    )


# ----------------------------------------------------------- happy path


def test_enroll_links_existing_system_and_returns_cert(
    client, db, issued_token, system_in_group
):
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="happy-1"),
    ):
        res = _enroll(
            client, token=issued_token.plaintext, system_id=system_in_group.id
        )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["system_id"] == system_in_group.id
    assert body["serial_number"] == "happy-1"
    assert body["agent_status"] == "active"
    assert body["was_first_redeem"] is True

    # Ledger row landed; uses_count incremented exactly once.
    db.expire_all()
    persisted_token = (
        db.query(ActivationToken).filter_by(id=issued_token.token.id).one()
    )
    assert persisted_token.uses_count == 1
    redemptions = (
        db.query(ActivationTokenRedemption)
        .filter_by(activation_token_id=issued_token.token.id)
        .all()
    )
    assert len(redemptions) == 1
    assert redemptions[0].system_id == system_in_group.id


def test_enroll_applies_token_tags_as_union(
    client, db, admin_user, group, system_in_group, tag, seed_distro
):
    # Pre-attach an unrelated tag so we can prove union behavior.
    other_tag = Tag(name="op-applied", color="#222222", created_by=admin_user.id)
    db.add(other_tag)
    db.flush()
    system_in_group.tags.append(other_tag)
    db.flush()

    issued = svc.issue_token(
        db,
        name="tagged-token",
        default_group_id=group.id,
        target_system_id=system_in_group.id,
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        created_by_user_id=admin_user.id,
        default_tag_ids=[tag.id],
    )
    db.commit()

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(),
    ):
        res = _enroll(client, token=issued.plaintext, system_id=system_in_group.id)
    assert res.status_code == 200

    db.expire_all()
    refreshed = db.query(System).filter_by(id=system_in_group.id).one()
    tag_ids = sorted(t.id for t in refreshed.tags)
    # Operator tag preserved; token tag added.
    assert tag.id in tag_ids
    assert other_tag.id in tag_ids


def test_idempotent_re_redeem_returns_fresh_cert_without_burning_use(
    client, db, issued_token, system_in_group
):
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="first"),
    ):
        a = _enroll(client, token=issued_token.plaintext, system_id=system_in_group.id)
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="second"),
    ):
        b = _enroll(client, token=issued_token.plaintext, system_id=system_in_group.id)
    assert a.status_code == 200 and b.status_code == 200
    assert b.json()["was_first_redeem"] is False
    assert b.json()["serial_number"] == "second"

    db.expire_all()
    persisted_token = (
        db.query(ActivationToken).filter_by(id=issued_token.token.id).one()
    )
    assert persisted_token.uses_count == 1  # rerun does not burn cap

    redemption = (
        db.query(ActivationTokenRedemption)
        .filter_by(activation_token_id=issued_token.token.id)
        .one()
    )
    assert redemption.redeem_count == 2


# ----------------------------------------------------------- failure paths


def test_enroll_missing_token_header_returns_401(client, system_in_group):
    res = client.post(
        "/agent/enroll",
        json={
            "system_id": system_in_group.id,
            "host_fingerprint": "fp",
            "csr_pem": "csr",
        },
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "invalid activation token"


def test_enroll_garbage_token_returns_401(client, system_in_group):
    res = _enroll(client, token="not-a-real-token", system_id=system_in_group.id)
    assert res.status_code == 401


def test_enroll_revoked_token_returns_401(
    client, db, issued_token, system_in_group, admin_user
):
    svc.revoke_token(db, issued_token.token, revoked_by_user_id=admin_user.id)
    db.commit()
    res = _enroll(client, token=issued_token.plaintext, system_id=system_in_group.id)
    assert res.status_code == 401


def test_enroll_expired_token_returns_401(
    client, db, admin_user, group, system_in_group
):
    issued = svc.issue_token(
        db,
        name="expired",
        default_group_id=group.id,
        target_system_id=system_in_group.id,
        ttl_expires_at=datetime.utcnow() + timedelta(seconds=-1),
        max_uses=1,
        created_by_user_id=admin_user.id,
    )
    db.commit()
    res = _enroll(client, token=issued.plaintext, system_id=system_in_group.id)
    assert res.status_code == 401


def test_enroll_unknown_system_returns_404(client, issued_token):
    res = _enroll(client, token=issued_token.plaintext, system_id=999_999)
    assert res.status_code == 404


def test_enroll_scope_mismatch_returns_409(client, issued_token, system_in_other_group):
    res = _enroll(
        client, token=issued_token.plaintext, system_id=system_in_other_group.id
    )
    assert res.status_code == 409


def test_enroll_second_host_with_different_fingerprint_returns_401_after_cap(
    client, db, issued_token, system_in_group
):
    """With max_uses=1 (forced at create), a different fingerprint
    hitting an already-redeemed token bounces off the cap before the
    (token, system_id) unique check is reachable. The bootstrap
    response is the same generic 401 as any other gate failure — we
    don't want to leak which arm tripped."""
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(),
    ):
        first = _enroll(
            client,
            token=issued_token.plaintext,
            system_id=system_in_group.id,
            fingerprint="host-a",
        )
        assert first.status_code == 200
        second = _enroll(
            client,
            token=issued_token.plaintext,
            system_id=system_in_group.id,
            fingerprint="host-b",
        )
    assert second.status_code == 401


def test_enroll_csr_failure_returns_400(client, issued_token, system_in_group):
    from app.services.agent_identity_service import AgentIdentityError

    def _boom(self, system, csr_pem):  # noqa: ARG001
        raise AgentIdentityError("bad CSR")

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_boom,
    ):
        res = _enroll(
            client, token=issued_token.plaintext, system_id=system_in_group.id
        )
    assert res.status_code == 400


def test_enroll_exhausted_token_returns_401(
    client, db, admin_user, group, system_in_group
):
    issued = svc.issue_token(
        db,
        name="one-use",
        default_group_id=group.id,
        target_system_id=system_in_group.id,
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        created_by_user_id=admin_user.id,
    )
    db.commit()

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(),
    ):
        first = _enroll(
            client,
            token=issued.plaintext,
            system_id=system_in_group.id,
            fingerprint="host-a",
        )
        assert first.status_code == 200

    # New host trying the same exhausted token must be rejected at the
    # token gate, before the (token, system_id) collision is reachable.
    res = _enroll(
        client,
        token=issued.plaintext,
        system_id=system_in_group.id,
        fingerprint="host-b",
    )
    assert res.status_code == 401


# ----------------------------------------------------------- audit


def test_success_emits_audit_with_token_identity_in_context(
    client, db, issued_token, system_in_group
):
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="audit-1"),
    ):
        _enroll(client, token=issued_token.plaintext, system_id=system_in_group.id)
    rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "activation_token.redeem",
            AuditEvent.outcome == "success",
            AuditEvent.target_id == str(issued_token.token.id),
        )
        .all()
    )
    assert len(rows) == 1
    import json

    ctx = json.loads(rows[0].context_json)
    assert ctx["activation_token_id"] == issued_token.token.id
    assert ctx["token_prefix"] == issued_token.token.token_prefix
    assert ctx["system_id"] == system_in_group.id
    assert ctx["was_first_redeem"] is True
    assert ctx["cert_serial"] == "audit-1"


def test_failure_emits_audit_with_reason_and_no_plaintext(client, db):
    res = client.post(
        "/agent/enroll",
        json={
            "system_id": 1,
            "host_fingerprint": "fp",
            "csr_pem": "csr",
        },
        headers={"X-Praxis-Activation-Token": "praxis_garbage_attempt"},
    )
    assert res.status_code == 401
    rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "activation_token.redeem",
            AuditEvent.outcome == "failure",
        )
        .all()
    )
    assert len(rows) >= 1
    import json

    for row in rows:
        ctx = json.loads(row.context_json)
        # Plaintext must not appear anywhere in the context.
        assert "praxis_garbage_attempt" not in json.dumps(ctx)
        assert ctx["reason"] in svc.RedemptionError.REASONS
