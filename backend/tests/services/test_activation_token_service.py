"""PRA-154 slice #1a: tests for activation token service."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    ActivationToken,
    ActivationTokenRedemption,
    Credential,
    Group,
    System,
)
from app.services import activation_token_service as svc
from tests.conftest import unique_test_ip


@pytest.fixture
def group(db):
    g = Group(name="m14-bootstrap-test", description="PRA-154 test")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def target_system(db, group, seed_distro):
    return _make_system(db, group, seed_distro, "target.example.com")


def _make_system(db, group, seed_distro, hostname: str) -> System:
    cred = Credential(
        name=f"cred-{hostname}",
        auth_method="ssh_key",
        username="root",
    )
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname=hostname,
        ip_address=unique_test_ip(),
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    return sys_row


def _mint_raw_token(
    db, *, admin, group, target_system, max_uses: int
) -> ActivationToken:
    """Build an ActivationToken row directly, bypassing the
    issue_token() service entirely.

    Used by ledger tests that need ``max_uses > 1`` to exercise the
    record_redemption invariants. issue_token() now refuses
    max_uses != 1 (the link-only invariant); the ledger itself
    keeps working for any max_uses value, so the right test shape
    is to mint by hand.
    """
    from passlib.hash import bcrypt

    plaintext = "praxis_" + ("a" * 56)  # any well-formed value; not verified here
    token = ActivationToken(
        name="raw-test",
        token_hash=bcrypt.hash(plaintext),
        token_prefix=plaintext[len("praxis_") : len("praxis_") + 8],
        default_group_id=group.id,
        target_system_id=target_system.id,
        default_tag_ids=[],
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=max_uses,
        uses_count=0,
        created_by_user_id=admin.id,
    )
    db.add(token)
    db.flush()
    return token


def _issue(db, *, admin, group, target=None, seed_distro=None, **overrides):
    """Create an issued token, ensuring a target_system exists.

    Many tests don't care which system is the target; passing
    ``seed_distro`` lets us synthesize one. Tests that care can pass
    ``target=`` explicitly.
    """
    if target is None:
        if seed_distro is None:
            raise ValueError("either target= or seed_distro= must be provided")
        target = _make_system(
            db,
            group,
            seed_distro,
            f"auto-{datetime.utcnow().timestamp()}.example.com",
        )
    defaults = dict(
        name="test token",
        default_group_id=group.id,
        target_system_id=target.id,
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        created_by_user_id=admin.id,
    )
    defaults.update(overrides)
    return svc.issue_token(db, **defaults)


# ---------------------------------------------------------------- issue


def test_issue_does_not_commit_or_emit_audit(db, admin_user, group, seed_distro):
    """The service mutators must not commit the request
    transaction or emit audit events from inside an in-flight write.
    Audit emission is the route's job, post-commit.
    """
    from app.db.access_models import AuditEvent

    before = db.query(AuditEvent).count()
    _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    # Mutators flush but do not commit. A rollback here must wipe the
    # token row AND must not have produced an audit event.
    db.rollback()
    after_tokens = db.query(ActivationToken).count()
    after_audits = db.query(AuditEvent).count()
    assert after_tokens == 0
    assert after_audits == before


def test_revoke_does_not_emit_audit(db, admin_user, group, seed_distro):
    from app.db.access_models import AuditEvent

    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    db.commit()
    before = db.query(AuditEvent).count()
    svc.revoke_token(db, issued.token, revoked_by_user_id=admin_user.id)
    # No audit row should appear from the service alone — the route
    # is responsible for emitting after its own commit.
    assert db.query(AuditEvent).count() == before


def test_issue_returns_plaintext_and_persists_hash(db, admin_user, group, seed_distro):
    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)

    assert issued.plaintext.startswith("praxis_")
    assert len(issued.plaintext) > len("praxis_") + 8

    persisted = db.query(ActivationToken).filter_by(id=issued.token.id).one()
    assert persisted.token_hash != issued.plaintext
    assert persisted.token_hash.startswith("$2")  # bcrypt
    assert (
        persisted.token_prefix == issued.plaintext[len("praxis_") : len("praxis_") + 8]
    )
    assert persisted.uses_count == 0
    assert persisted.revoked_at is None


def test_issue_rejects_max_uses_below_one(db, admin_user, group, seed_distro):
    with pytest.raises(ValueError):
        _issue(db, admin=admin_user, group=group, seed_distro=seed_distro, max_uses=0)


def test_issue_rejects_blank_name(db, admin_user, group, seed_distro):
    with pytest.raises(ValueError):
        _issue(db, admin=admin_user, group=group, seed_distro=seed_distro, name="   ")


def test_issued_plaintext_is_not_predictable(db, admin_user, group, seed_distro):
    a = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    b = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    assert a.plaintext != b.plaintext


# ---------------------------------------------------------------- verify


def test_verify_resolves_a_live_token(db, admin_user, group, seed_distro):
    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    found = svc.verify_plaintext(db, issued.plaintext)
    assert found is not None
    assert found.id == issued.token.id


def test_verify_returns_none_for_garbage(db):
    assert svc.verify_plaintext(db, "") is None
    assert svc.verify_plaintext(db, "not-a-token") is None
    assert svc.verify_plaintext(db, "praxis_") is None
    assert svc.verify_plaintext(db, "praxis_short") is None


def test_verify_returns_none_for_unknown_token(db, admin_user, group, seed_distro):
    _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    # Right shape, wrong secret.
    assert (
        svc.verify_plaintext(db, "praxis_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        is None
    )


def test_verify_returns_none_for_expired(db, admin_user, group, seed_distro):
    issued = _issue(
        db,
        admin=admin_user,
        group=group,
        seed_distro=seed_distro,
        ttl_expires_at=datetime.utcnow() - timedelta(seconds=1),
    )
    assert svc.verify_plaintext(db, issued.plaintext) is None


def test_verify_returns_none_for_revoked(db, admin_user, group, seed_distro):
    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    svc.revoke_token(db, issued.token, revoked_by_user_id=admin_user.id)
    assert svc.verify_plaintext(db, issued.plaintext) is None


def test_verify_returns_none_when_uses_exhausted(db, admin_user, group, seed_distro):
    issued = _issue(
        db, admin=admin_user, group=group, seed_distro=seed_distro, max_uses=1
    )
    svc.record_redemption(db, token=issued.token, host_fingerprint="aa:bb:cc")
    assert svc.verify_plaintext(db, issued.plaintext) is None


# ---------------------------------------------------------------- revoke


def test_revoke_is_idempotent(db, admin_user, group, seed_distro):
    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    first = svc.revoke_token(db, issued.token, revoked_by_user_id=admin_user.id)
    assert first.revoked_at is not None
    stamp = first.revoked_at
    again = svc.revoke_token(db, issued.token, revoked_by_user_id=admin_user.id)
    assert again.revoked_at == stamp


# ---------------------------------------------------------------- ledger


def test_record_redemption_creates_and_increments_uses(
    db, admin_user, group, target_system
):
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=5
    )
    rec, created = svc.record_redemption(
        db,
        token=token,
        host_fingerprint="aa:bb:cc:dd",
        last_seen_hostname="host-a",
    )
    assert created is True
    assert rec.redeem_count == 1
    assert rec.first_redeemed_at == rec.last_redeemed_at
    db.refresh(token)
    assert token.uses_count == 1


def test_record_redemption_is_idempotent_on_same_fingerprint(
    db, admin_user, group, target_system
):
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=5
    )
    rec1, created1 = svc.record_redemption(db, token=token, host_fingerprint="aa:bb")
    rec2, created2 = svc.record_redemption(db, token=token, host_fingerprint="aa:bb")
    assert created1 is True
    assert created2 is False
    assert rec1.id == rec2.id
    assert rec2.redeem_count == 2
    db.refresh(token)
    assert token.uses_count == 1


def test_record_redemption_does_not_hash_raw_fingerprint_into_db(
    db, admin_user, group, target_system
):
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=1
    )
    raw = "raw-fingerprint-should-not-leak"
    rec, _ = svc.record_redemption(db, token=token, host_fingerprint=raw)
    persisted = db.query(ActivationTokenRedemption).filter_by(id=rec.id).one()
    assert persisted.host_fingerprint_hash != raw
    assert len(persisted.host_fingerprint_hash) == 64  # sha256 hex


def test_record_redemption_keeps_system_id_stable(
    db, admin_user, group, seed_distro, target_system
):
    sys_row = _make_system(db, group, seed_distro, "host-stable.example.com")
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=5
    )
    rec, _ = svc.record_redemption(
        db, token=token, host_fingerprint="x", system_id=sys_row.id
    )
    assert rec.system_id == sys_row.id
    rec2, _ = svc.record_redemption(db, token=token, host_fingerprint="x")
    assert rec2.system_id == sys_row.id


def test_record_redemption_refuses_rebind_to_different_system(
    db, admin_user, group, seed_distro, target_system
):
    sys_a = _make_system(db, group, seed_distro, "host-a.example.com")
    sys_b = _make_system(db, group, seed_distro, "host-b.example.com")
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=5
    )
    svc.record_redemption(db, token=token, host_fingerprint="x", system_id=sys_a.id)
    with pytest.raises(ValueError):
        svc.record_redemption(db, token=token, host_fingerprint="x", system_id=sys_b.id)


def test_record_redemption_different_fingerprints_each_consume_a_use(
    db, admin_user, group, target_system
):
    token = _mint_raw_token(
        db, admin=admin_user, group=group, target_system=target_system, max_uses=3
    )
    svc.record_redemption(db, token=token, host_fingerprint="host-a")
    svc.record_redemption(db, token=token, host_fingerprint="host-b")
    svc.record_redemption(db, token=token, host_fingerprint="host-c")
    db.refresh(token)
    assert token.uses_count == 3


# ---------------------------------------------------------------- issue invariants


def test_issue_rejects_max_uses_above_one(db, admin_user, group, seed_distro):
    """The link-only invariant lives in the service,
    not just the route. A future internal caller that bypasses the
    Pydantic clamp must still be refused."""
    target = _make_system(db, group, seed_distro, "iss-cap.example.com")
    with pytest.raises(ValueError, match="exactly 1"):
        svc.issue_token(
            db,
            name="bulk-attempt",
            default_group_id=group.id,
            target_system_id=target.id,
            ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
            max_uses=2,
            created_by_user_id=admin_user.id,
        )


def test_issue_rejects_target_in_different_group(db, admin_user, group, seed_distro):
    other_group = Group(name="iss-other-group", description="iss-other")
    db.add(other_group)
    db.flush()
    target = _make_system(db, other_group, seed_distro, "iss-cross.example.com")
    with pytest.raises(ValueError, match="group"):
        svc.issue_token(
            db,
            name="cross-group",
            default_group_id=group.id,
            target_system_id=target.id,
            ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
            max_uses=1,
            created_by_user_id=admin_user.id,
        )


def test_issued_plaintext_matches_alphabet_contract(db, admin_user, group, seed_distro):
    """Every issued plaintext must satisfy
    ^praxis_[a-z2-7]+$ so the bootstrap_command builder can rely on
    no shell-special characters surviving the embed."""
    issued = _issue(db, admin=admin_user, group=group, seed_distro=seed_distro)
    assert svc._TOKEN_PLAINTEXT_RE.match(issued.plaintext) is not None


# ---------------------------------------------------------------- redeem idempotency


def test_redeem_rerun_succeeds_when_uses_count_equals_max_uses(
    db, admin_user, group, target_system
):
    """Pin the rerun behavior independent of
    max_uses. Even with uses_count == max_uses, the same fingerprint
    must be allowed back through redeem_token (otherwise the bypass
    is a regression risk once create-on-redemption loosens the cap).
    """
    from datetime import timedelta as _td
    from unittest.mock import patch

    issued = svc.issue_token(
        db,
        name="rerun-test",
        default_group_id=group.id,
        target_system_id=target_system.id,
        ttl_expires_at=datetime.utcnow() + _td(hours=1),
        max_uses=1,
        created_by_user_id=admin_user.id,
    )
    db.commit()

    def _fake_sign(self, system, csr_pem):  # noqa: ARG001
        return {
            "certificate": "FAKE",
            "serial_number": "s-1",
            "fingerprint": "fp-1",
            "expires_at": datetime.utcnow() + _td(hours=1),
            "ca_chain": [],
            "issuing_ca": None,
        }

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_fake_sign,
    ):
        first = svc.redeem_token(
            db,
            plaintext=issued.plaintext,
            system_id=target_system.id,
            host_fingerprint="machine-id-A",
            csr_pem="csr",
        )
        assert first.was_first_redeem is True

        # uses_count is now 1, max_uses is 1 — verify_plaintext would
        # treat this token as exhausted. redeem_token must still let
        # the same fingerprint through.
        db.refresh(issued.token)
        assert issued.token.uses_count == issued.token.max_uses

        second = svc.redeem_token(
            db,
            plaintext=issued.plaintext,
            system_id=target_system.id,
            host_fingerprint="machine-id-A",
            csr_pem="csr",
        )
        assert second.was_first_redeem is False

        # And a NEW fingerprint against the same exhausted token
        # must still be refused.
        with pytest.raises(svc.RedemptionError, match="invalid_token"):
            svc.redeem_token(
                db,
                plaintext=issued.plaintext,
                system_id=target_system.id,
                host_fingerprint="machine-id-B",
                csr_pem="csr",
            )
