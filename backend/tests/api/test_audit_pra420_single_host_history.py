"""PRA-420: the remaining single-host events reach their host's history.

``GET /audit/events?system_id=`` returns the union of the events that name a
host in ``audit_events.target_system_id`` and the events linked to it as an
affected host. A family of emitters described exactly one managed system in
their target vocabulary or their context and filled in neither, so those events
were missing from the history of the host they were about.

The repaired set covered here:

* mirror serve credential issue and revoke, against the route's system;
* the host content-profile apply outcome, applied, refused, or failed;
* the advisory applicability recompute, against the host recomputed;
* successful agent enrolment, against the system the redemption resolved;
* the activation-token lifecycle, create and revoke, against the host the token
  is bound to at issue time;
* direct host content-profile subscription add and remove; and
* host-scoped revocation work reconcile.

These tests hold each of them to both halves of the contract: the event comes
back from the host it concerns, and it does not come back from another host.

Three cases are here for the opposite reason, to pin what must stay hostless.
A failed enrolment's only host reference is the system id an unauthenticated
request asked for, so it must stay out of every host history rather than let a
caller write into one it never proved a claim to. Group and smart-group
subscriptions resolve to a membership that changes over time and have no single
subject, so they name no host even when the group currently holds exactly one.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List
from unittest.mock import patch

import pytest

from app.db.access_models import AuditEvent, RevocationWork
from app.db.models import (
    ContentProfile,
    Credential,
    Group,
    HostContentProfileSubscription,
    HostFacts,
    MirrorRepo,
    Package,
    SmartGroup,
    System,
    SystemMetadata,
)
from app.services import activation_token_service as token_svc
from app.services import audit_event_service as aes
from app.services import (
    fleet_reconciliation_service,
    patch_advisory_service,
    revocation_service,
    ssh_service,
)
from app.services.content_profile_apply import apply_content_profile_to_host
from app.services.patch_advisory_service import (
    AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED,
    SOURCE_KIND_UBUNTU_USN,
    normalize_ubuntu_usn,
)
from tests.conftest import unique_test_ip

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def group(db) -> Group:
    g = Group(name="pra420-api-group", description="t")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def credentials(db) -> Credential:
    c = Credential(
        name="pra420-api-cred",
        auth_method="password",
        username="root",
        vault_path="x",
    )
    db.add(c)
    db.flush()
    return c


@pytest.fixture
def host_builder(db, seed_distro, group, credentials):
    counter = {"n": 0}

    def make(*, with_facts: bool = False) -> System:
        counter["n"] += 1
        row = System(
            hostname=f"pra420-api-{counter['n']}.example.com",
            ip_address=unique_test_ip(),
            distro_id=seed_distro.id,
            os_version="22.04",
            status="Active",
            group_id=group.id,
            credentials_id=credentials.id,
        )
        db.add(row)
        db.flush()
        if with_facts:
            db.add(
                HostFacts(
                    system_id=row.id,
                    schema_version=1,
                    collected_at=datetime.utcnow(),
                    source_transport="agent",
                    distro_id_facts="ubuntu",
                    distro_release="22.04",
                )
            )
            db.flush()
        db.commit()
        return row

    return make


@pytest.fixture
def hosts(host_builder) -> List[System]:
    """Two hosts, so 'belongs only to the other host' is testable."""
    return [host_builder(), host_builder()]


@pytest.fixture
def deb_mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="pra420-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components='["main"]',
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    return m


@pytest.fixture
def admin_headers(client, admin_user) -> dict:
    """Audit reads need admin or auditor. The header is passed per request so
    the anonymous enrolment surface is still exercised anonymously."""
    res = client.post(
        "/auth/login",
        data={"username": admin_user.username, "password": "testpass123"},
    )
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _history(client, headers, system_id: int) -> List[dict]:
    res = client.get(f"/audit/events?system_id={system_id}&limit=1000", headers=headers)
    assert res.status_code == 200, res.text
    return res.json()["events"]


def _actions(events: List[dict]) -> List[str]:
    return [e["action"] for e in events]


# ---------------------------------------------------------------------------
# Mirror serve credentials
# ---------------------------------------------------------------------------


def test_serve_credential_issue_and_revoke_reach_the_hosts_history(
    client, admin_headers, hosts, deb_mirror
):
    host, other = hosts
    issued = client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id},
        headers=admin_headers,
    )
    assert issued.status_code == 201, issued.text
    credential_id = issued.json()["credential_id"]
    revoked = client.delete(
        f"/systems/{host.id}/mirror-serve-credentials/{credential_id}",
        headers=admin_headers,
    )
    assert revoked.status_code == 204, revoked.text

    events = _history(client, admin_headers, host.id)
    assert "mirror_serve_credential.issued" in _actions(events)
    assert "mirror_serve_credential.revoked" in _actions(events)
    for event in events:
        assert event["target"]["system_id"] == host.id
        assert event["target"]["kind"] == "system"
        assert event["target"]["id"] == str(host.id)

    assert _history(client, admin_headers, other.id) == []


def test_serve_credential_events_record_their_credential_context(
    client, admin_headers, hosts, deb_mirror
):
    """Naming the host must not cost the context the event already carried."""
    host, _other = hosts
    issued = client.post(
        f"/systems/{host.id}/mirror-serve-credentials",
        json={"mirror_id": deb_mirror.id, "ttl_days": 7},
        headers=admin_headers,
    ).json()

    events = _history(client, admin_headers, host.id)
    matching = [e for e in events if e["action"] == "mirror_serve_credential.issued"]
    assert len(matching) == 1
    context = matching[0]["context"]
    assert context["credential_id"] == issued["credential_id"]
    assert context["mirror_id"] == deb_mirror.id
    assert context["ttl_days"] == 7


# ---------------------------------------------------------------------------
# Content profile apply
# ---------------------------------------------------------------------------


class _NoTransport:
    name = "ssh"

    @staticmethod
    async def run(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("refused apply must not reach the host")


@pytest.mark.asyncio
async def test_content_profile_apply_outcome_reaches_the_applied_host(
    client, admin_headers, db, hosts
):
    host, other = hosts
    first = ContentProfile(slug="pra420-api-a", display_name="x", package_family="deb")
    second = ContentProfile(slug="pra420-api-b", display_name="x", package_family="deb")
    db.add_all([first, second])
    db.flush()
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=first.id))
    db.add(HostContentProfileSubscription(host_id=host.id, profile_id=second.id))
    db.commit()

    outcome = await apply_content_profile_to_host(db, host, _NoTransport())
    assert outcome.state == "refused_conflict"

    events = _history(client, admin_headers, host.id)
    assert _actions(events) == ["host_content_profile.refused"]
    assert events[0]["target"]["system_id"] == host.id
    assert _history(client, admin_headers, other.id) == []


# ---------------------------------------------------------------------------
# Advisory applicability recompute
# ---------------------------------------------------------------------------


def test_advisory_recompute_reaches_the_recomputed_host(
    client, admin_headers, db, admin_user, host_builder, monkeypatch
):
    host = host_builder(with_facts=True)
    other = host_builder(with_facts=True)
    db.add(
        Package(
            system_id=host.id,
            name="openssl",
            installed_version="3.0.2-0ubuntu1.10",
            package_type="deb",
        )
    )
    db.commit()

    # The recompute emits on a session of its own, which cannot see rows this
    # test has not committed past the fixture's outer transaction. Forwarding
    # the emitter's own kwargs onto the test session is the only substitution:
    # the action, target, and host attribution under test are its own.
    monkeypatch.setattr(
        patch_advisory_service, "safe_emit", lambda **kw: aes.emit(db, **kw)
    )

    payload = normalize_ubuntu_usn(
        {
            "id": "USN-PRA420-API-1",
            "title": "USN-PRA420-API-1 title",
            "summary": "test",
            "severity": "High",
            "release_packages": {
                "jammy": [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}],
            },
        }
    )
    patch_advisory_service.import_advisories(
        db,
        source_kind=SOURCE_KIND_UBUNTU_USN,
        payloads=[payload],
        actor_user_id=admin_user.id,
    )

    events = _history(client, admin_headers, host.id)
    assert AUDIT_PATCH_ADVISORY_APPLICABLE_RECOMPUTED in _actions(events)
    assert _history(client, admin_headers, other.id) == []


# ---------------------------------------------------------------------------
# Agent enrolment
# ---------------------------------------------------------------------------


def _stub_sign(self, system, csr_pem):  # noqa: ARG001
    return {
        "certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
        "serial_number": "pra420-serial",
        "fingerprint": "pra420-fp",
        "expires_at": datetime.utcnow() + timedelta(hours=1),
        "ca_chain": ["ca-pem"],
        "issuing_ca": "ca-pem",
    }


def _enroll(client, *, token, system_id):
    return client.post(
        "/agent/enroll",
        json={
            "system_id": system_id,
            "host_fingerprint": "pra420-host-fp",
            "csr_pem": "csr-pem",
        },
        headers={"X-Praxis-Activation-Token": token},
    )


@pytest.fixture
def enrolment_token(db, admin_user, group, hosts):
    issued = token_svc.issue_token(
        db,
        name="pra420-enroll",
        default_group_id=group.id,
        target_system_id=hosts[0].id,
        ttl_expires_at=datetime.utcnow() + timedelta(hours=1),
        max_uses=1,
        created_by_user_id=admin_user.id,
    )
    db.commit()
    return issued


def test_successful_enrolment_reaches_the_enrolled_hosts_history(
    client, admin_headers, hosts, enrolment_token
):
    host, other = hosts
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign,
    ):
        res = _enroll(client, token=enrolment_token.plaintext, system_id=host.id)
    assert res.status_code == 200, res.text

    events = _history(client, admin_headers, host.id)
    redeemed = [e for e in events if e["action"] == "activation_token.redeem"]
    assert len(redeemed) == 1
    assert redeemed[0]["outcome"] == "success"
    assert redeemed[0]["target"]["system_id"] == host.id
    # The redeemed token is still what the event targets; the host is the
    # additional attribution, not a replacement for it.
    assert redeemed[0]["target"]["kind"] == "activation_token"
    assert redeemed[0]["target"]["id"] == str(enrolment_token.token.id)
    assert redeemed[0]["context"]["system_id"] == host.id

    assert _history(client, admin_headers, other.id) == []


def test_failed_enrolment_is_attributed_to_no_host(
    client, admin_headers, db, hosts, enrolment_token
):
    """The system id on a failed enrolment is an unauthenticated caller's
    claim. It stays in context and out of every host history."""
    host, _other = hosts
    res = _enroll(client, token="not-a-real-activation-token", system_id=host.id)
    assert res.status_code == 401

    rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "activation_token.redeem",
            AuditEvent.outcome == "failure",
        )
        .all()
    )
    assert len(rows) == 1
    assert rows[0].target_system_id is None

    assert _history(client, admin_headers, host.id) == []


# ---------------------------------------------------------------------------
# Activation token lifecycle
# ---------------------------------------------------------------------------


def _token_body(host: System) -> dict:
    return {
        "name": "pra420 enrollment",
        "default_group_id": host.group_id,
        "target_system_id": host.id,
        "ttl_seconds": 600,
        "max_uses": 1,
    }


def test_token_lifecycle_reaches_the_bound_hosts_history(client, admin_headers, hosts):
    """A token is bound to one host at issue time, so create and revoke are both
    about that host."""
    host, other = hosts
    created = client.post(
        "/agent/activation-tokens", json=_token_body(host), headers=admin_headers
    )
    assert created.status_code == 201, created.text
    token_id = created.json()["id"]
    revoked = client.post(
        f"/agent/activation-tokens/{token_id}/revoke", headers=admin_headers
    )
    assert revoked.status_code == 200, revoked.text

    events = _history(client, admin_headers, host.id)
    assert sorted(_actions(events)) == [
        "activation_token.create",
        "activation_token.revoke",
    ]
    for event in events:
        assert event["target"]["system_id"] == host.id
        # The token remains what the action acts on.
        assert event["target"]["kind"] == "activation_token"
        assert event["target"]["id"] == str(token_id)
    assert _history(client, admin_headers, other.id) == []


def test_token_events_keep_their_context(client, admin_headers, hosts):
    host, _other = hosts
    created = client.post(
        "/agent/activation-tokens", json=_token_body(host), headers=admin_headers
    ).json()

    events = _history(client, admin_headers, host.id)
    context = [e for e in events if e["action"] == "activation_token.create"][0][
        "context"
    ]
    assert context["name"] == "pra420 enrollment"
    assert context["token_prefix"] == created["token_prefix"]
    assert context["default_group_id"] == host.group_id
    assert context["max_uses"] == 1


# ---------------------------------------------------------------------------
# Content profile subscriptions
# ---------------------------------------------------------------------------


@pytest.fixture
def profile(client, admin_headers) -> dict:
    res = client.post(
        "/content-profiles",
        json={
            "slug": "pra420-sub-profile",
            "display_name": "x",
            "package_family": "deb",
        },
        headers=admin_headers,
    )
    assert res.status_code == 201, res.text
    return res.json()


def test_direct_host_subscription_reaches_that_hosts_history(
    client, admin_headers, hosts, profile
):
    host, other = hosts
    added = client.post(
        f"/content-profiles/{profile['id']}/hosts",
        json={"host_id": host.id},
        headers=admin_headers,
    )
    assert added.status_code == 201, added.text
    removed = client.delete(
        f"/content-profiles/{profile['id']}/hosts/{host.id}", headers=admin_headers
    )
    assert removed.status_code == 204, removed.text

    events = _history(client, admin_headers, host.id)
    assert sorted(_actions(events)) == [
        "content_profile.subscription_added",
        "content_profile.subscription_removed",
    ]
    for event in events:
        assert event["target"]["system_id"] == host.id
        # The profile remains the target; the host is added attribution.
        assert event["target"]["kind"] == "content_profile"
        assert event["target"]["id"] == str(profile["id"])
        assert event["context"]["scope_kind"] == "host"
        assert event["context"]["scope_id"] == host.id

    assert _history(client, admin_headers, other.id) == []


def test_group_subscription_claims_no_host(
    client, admin_headers, db, hosts, group, profile
):
    """A group subscription resolves to a membership that changes over time. It
    has no single subject and must not name one, even when the group currently
    holds exactly one host."""
    host, other = hosts
    added = client.post(
        f"/content-profiles/{profile['id']}/groups",
        json={"group_id": group.id},
        headers=admin_headers,
    )
    assert added.status_code == 201, added.text

    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "content_profile.subscription_added")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].target_system_id is None
    assert _history(client, admin_headers, host.id) == []
    assert _history(client, admin_headers, other.id) == []


def test_smart_group_subscription_claims_no_host(
    client, admin_headers, db, hosts, profile
):
    host, other = hosts
    smart_group = SmartGroup(name="pra420-sg", rule_json='{"op":"and","rules":[]}')
    db.add(smart_group)
    db.commit()
    added = client.post(
        f"/content-profiles/{profile['id']}/smart-groups",
        json={"smart_group_id": smart_group.id},
        headers=admin_headers,
    )
    assert added.status_code == 201, added.text

    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "content_profile.subscription_added")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].target_system_id is None
    assert _history(client, admin_headers, host.id) == []
    assert _history(client, admin_headers, other.id) == []


def test_group_subscription_removal_claims_no_host(
    client, admin_headers, db, hosts, group, profile
):
    host, _other = hosts
    client.post(
        f"/content-profiles/{profile['id']}/groups",
        json={"group_id": group.id},
        headers=admin_headers,
    )
    removed = client.delete(
        f"/content-profiles/{profile['id']}/groups/{group.id}", headers=admin_headers
    )
    assert removed.status_code == 204, removed.text

    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "content_profile.subscription_removed")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].target_system_id is None
    assert _history(client, admin_headers, host.id) == []


# ---------------------------------------------------------------------------
# Revocation work reconcile
# ---------------------------------------------------------------------------


def test_host_scoped_revocation_reaches_that_hosts_history(
    client, admin_headers, db, hosts, monkeypatch
):
    host, other = hosts
    for system in (host, other):
        db.add(SystemMetadata(system_id=system.id))
    db.add(
        RevocationWork(
            reason="test",
            system_id=host.id,
            login="alice",
            status="pending",
            attempt_count=0,
        )
    )
    db.commit()

    monkeypatch.setattr(
        fleet_reconciliation_service, "reconcile_pending_privilege", lambda db_: None
    )
    monkeypatch.setattr(ssh_service, "is_host_cooling_down", lambda *a, **k: None)
    monkeypatch.setattr(
        fleet_reconciliation_service,
        "reconcile_system",
        lambda _db, _sid: {
            "provisioned": 0,
            "removed": 0,
            "errors": 0,
            "skipped": 0,
            "conflicts": 0,
            "manual_intervention": 0,
        },
    )
    # The drain emits on a session of its own, which cannot see rows this test
    # has not committed past the fixture's outer transaction. Forwarding the
    # emitter's own kwargs onto the test session is the only substitution.
    monkeypatch.setattr(
        revocation_service, "safe_emit", lambda **kw: aes.emit(db, **kw)
    )

    revocation_service.drain(db, now=datetime.utcnow())

    events = _history(client, admin_headers, host.id)
    assert _actions(events) == ["revocation.reconcile"]
    assert events[0]["target"]["system_id"] == host.id
    assert events[0]["target"]["kind"] == "revocation_work"
    assert _history(client, admin_headers, other.id) == []
