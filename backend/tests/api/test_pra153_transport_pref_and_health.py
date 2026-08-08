"""PRA-153 #4: transport_preference + agent-health endpoints.

Covers the operator-facing surface that backs the slice #4 UI badge
+ admin toggle:

    PATCH /systems/{id}/transport-preference
    GET   /systems/{id}/agent-health
    GET   /systems/agent-health
    plus  the _compute_badge helper matrix.

Broker calls go through a patched BrokerClient.health so tests don't
spin up the broker; we test the routing matrix at the badge layer
(the BrokerClient → broker stack itself is covered in
test_pra153_force_mode_integration.py).
"""

from __future__ import annotations

from datetime import date
from unittest.mock import patch

import pytest

from app.api.routes.systems import _compute_badge
from app.db.models import Distro, System
from app.services.broker_client import TunnelHealth

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def distro(db):
    d = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not d:
        d = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 1),
        )
        db.add(d)
        db.flush()
    return d


def _make_group(authed_client, name="g"):
    res = authed_client.post("/groups", json={"name": name, "description": "g"})
    assert res.status_code == 201, res.text
    return res.json()


def _make_credential(authed_client, name="c"):
    res = authed_client.post(
        "/credentials",
        json={
            "name": name,
            "auth_method": "password",
            "username": "root",
            "password": "x",
            "sudo_method": "none",
        },
    )
    assert res.status_code == 201, res.text
    return res.json()


def _make_system(authed_client, distro_id, group_id, cred_id, *, hostname, ip):
    body = {
        "hostname": hostname,
        "ip_address": ip,
        "distro_id": distro_id,
        "status": "Active",
        "group_id": group_id,
        "credentials_id": cred_id,
    }
    res = authed_client.post("/systems/add-system", json=body)
    assert res.status_code == 201, res.text
    return res.json()


def _seed_system(authed_client, distro, *, hostname="h-1", ip="10.0.0.1"):
    g = _make_group(authed_client, f"grp-{hostname}")
    c = _make_credential(authed_client, f"cred-{hostname}")
    return _make_system(
        authed_client, distro.id, g["id"], c["id"], hostname=hostname, ip=ip
    )


def _login_as(client, user, password="testpass123"):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": password}
    )
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _grant_scope(db, user, system_id, role_name):
    """PRA-281: give ``user`` a fleet grant on ``system_id`` so scoped read
    endpoints resolve. Isolates role behavior from fleet-scope in these tests."""
    from app.db.access_models import AccessGrant, FleetRole

    role = FleetRole(
        name=role_name,
        login_mode="per_user",
        allowed_actions_json="[]",
        os_groups_json="[]",
    )
    db.add(role)
    db.flush()
    db.add(
        AccessGrant(
            user_id=user.id,
            system_id=system_id,
            fleet_role_id=role.id,
            login=user.username,
        )
    )
    db.commit()


# --------------------------------------------------------------------------
# _compute_badge unit matrix — the single source of truth for UI labels.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pref,state,expected_badge,expected_eff",
    [
        # pref=ssh: forced regardless of broker state.
        ("ssh", "healthy", "ssh_forced", "ssh"),
        ("ssh", "stale", "ssh_forced", "ssh"),
        ("ssh", "unregistered", "ssh_forced", "ssh"),
        ("ssh", "unknown", "ssh_forced", "ssh"),
        # pref=auto: agent if healthy, ssh fallback otherwise, unknown
        # if broker call itself failed.
        ("auto", "healthy", "agent_connected", "agent"),
        ("auto", "stale", "ssh_fallback", "ssh"),
        ("auto", "unregistered", "ssh_fallback", "ssh"),
        ("auto", "unknown", "unknown", "ssh"),
        # pref=agent: forced if healthy, "unavailable" otherwise. The
        # unknown case must NOT silently imply agent works — render as
        # unknown (the only signal we have is "we couldn't tell").
        ("agent", "healthy", "agent_forced", "agent"),
        ("agent", "stale", "agent_unavailable", None),
        ("agent", "unregistered", "agent_unavailable", None),
        ("agent", "unknown", "unknown", None),
    ],
)
def test_compute_badge_matrix(pref, state, expected_badge, expected_eff):
    out = _compute_badge(pref, state)
    assert out["badge_state"] == expected_badge
    assert out["effective_transport"] == expected_eff


# --------------------------------------------------------------------------
# PATCH /systems/{id}/transport-preference
# --------------------------------------------------------------------------


def test_patch_transport_preference_admin_can_update(
    authed_client, mock_vault, distro, db
):
    sys_obj = _seed_system(authed_client, distro, hostname="patch-1", ip="10.1.0.1")
    res = authed_client.patch(
        f"/systems/{sys_obj['id']}/transport-preference",
        json={"transport_preference": "agent"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["transport_preference"] == "agent"

    # DB row reflects the change.
    row = db.query(System).filter_by(id=sys_obj["id"]).one()
    assert row.transport_preference == "agent"


def test_patch_transport_preference_writes_audit_row(
    authed_client, mock_vault, distro, db
):
    """Old/new value pair lands in system_audits so the change shows
    up in the host's history alongside other lifecycle events."""
    from app.db.models import SystemAudit

    sys_obj = _seed_system(authed_client, distro, hostname="audit-1", ip="10.1.0.2")
    res = authed_client.patch(
        f"/systems/{sys_obj['id']}/transport-preference",
        json={"transport_preference": "ssh"},
    )
    assert res.status_code == 200

    audits = (
        db.query(SystemAudit)
        .filter(
            SystemAudit.system_id == sys_obj["id"],
            SystemAudit.audit_type == "transport_preference",
        )
        .all()
    )
    assert len(audits) == 1
    assert audits[0].old_value == "auto"
    assert audits[0].new_value == "ssh"


def test_patch_transport_preference_rejects_invalid_value(
    authed_client, mock_vault, distro
):
    sys_obj = _seed_system(authed_client, distro, hostname="bad-1", ip="10.1.0.3")
    res = authed_client.patch(
        f"/systems/{sys_obj['id']}/transport-preference",
        json={"transport_preference": "carrier-pigeon"},
    )
    assert res.status_code == 422  # pydantic validation failure


def test_patch_transport_preference_404_for_unknown_system(authed_client):
    res = authed_client.patch(
        "/systems/99999/transport-preference",
        json={"transport_preference": "auto"},
    )
    assert res.status_code == 404


def test_patch_transport_preference_maintainer_forbidden(
    authed_client, client, maintainer_user, mock_vault, distro
):
    """Per the slice #4 lock: maintainers can SEE but not change."""
    sys_obj = _seed_system(authed_client, distro, hostname="maint-1", ip="10.1.0.4")
    headers = _login_as(client, maintainer_user)
    res = client.patch(
        f"/systems/{sys_obj['id']}/transport-preference",
        json={"transport_preference": "ssh"},
        headers=headers,
    )
    assert res.status_code == 403


def test_patch_transport_preference_auditor_forbidden(
    authed_client, client, auditor_user, mock_vault, distro
):
    sys_obj = _seed_system(authed_client, distro, hostname="aud-1", ip="10.1.0.5")
    headers = _login_as(client, auditor_user)
    res = client.patch(
        f"/systems/{sys_obj['id']}/transport-preference",
        json={"transport_preference": "ssh"},
        headers=headers,
    )
    assert res.status_code == 403


# --------------------------------------------------------------------------
# GET /systems/{id}/agent-health
# --------------------------------------------------------------------------


def _patch_health(state: str, **extra):
    """Patch BrokerClient.health to return a fixed TunnelHealth."""

    async def _fake(self, system_id):
        return TunnelHealth(system_id=system_id, state=state, **extra)

    return patch("app.services.broker_client.BrokerClient.health", new=_fake)


def test_get_agent_health_returns_full_payload(authed_client, mock_vault, distro):
    sys_obj = _seed_system(authed_client, distro, hostname="health-1", ip="10.2.0.1")
    with _patch_health(
        "healthy",
        tunnel_session_id="sess-x",
        since_seconds=42.0,
        last_heartbeat_age_seconds=2.0,
    ):
        res = authed_client.get(f"/systems/{sys_obj['id']}/agent-health")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["system_id"] == sys_obj["id"]
    assert body["transport_preference"] == "auto"
    assert body["agent_health"]["state"] == "healthy"
    assert body["agent_health"]["tunnel_session_id"] == "sess-x"
    assert body["effective_transport"] == "agent"
    assert body["badge_state"] == "agent_connected"


def test_get_agent_health_unknown_when_broker_call_fails(
    authed_client, mock_vault, distro
):
    """BrokerClient.health degrades httpx errors to state='unknown'.
    The endpoint must surface that as badge_state='unknown' rather
    than implying agent missing."""
    sys_obj = _seed_system(authed_client, distro, hostname="health-2", ip="10.2.0.2")
    with _patch_health("unknown"):
        res = authed_client.get(f"/systems/{sys_obj['id']}/agent-health")
    assert res.status_code == 200
    body = res.json()
    assert body["agent_health"]["state"] == "unknown"
    assert body["badge_state"] == "unknown"


def test_get_agent_health_404_for_unknown_system(authed_client):
    res = authed_client.get("/systems/99999/agent-health")
    assert res.status_code == 404


def test_get_agent_health_visible_to_maintainer(
    authed_client, client, db, maintainer_user, mock_vault, distro
):
    """Maintainers can read state even though they can't change pref.

    PRA-281: agent-health is now fleet-scoped, so the maintainer needs a grant on
    the system. Role visibility (read-yes, change-no) is what this test exercises.
    """
    sys_obj = _seed_system(authed_client, distro, hostname="m-health", ip="10.2.0.3")
    _grant_scope(db, maintainer_user, sys_obj["id"], "pra153-mhealth")
    headers = _login_as(client, maintainer_user)
    with _patch_health(
        "healthy",
        tunnel_session_id="s",
        since_seconds=1.0,
        last_heartbeat_age_seconds=0.5,
    ):
        res = client.get(f"/systems/{sys_obj['id']}/agent-health", headers=headers)
    assert res.status_code == 200
    assert res.json()["badge_state"] == "agent_connected"


# --------------------------------------------------------------------------
# GET /systems/agent-health (bulk)
# --------------------------------------------------------------------------


def test_bulk_agent_health_returns_one_entry_per_system(
    authed_client, mock_vault, distro
):
    a = _seed_system(authed_client, distro, hostname="bulk-a", ip="10.3.0.1")
    b = _seed_system(authed_client, distro, hostname="bulk-b", ip="10.3.0.2")

    async def _fake_health(self, system_id):
        # a healthy, b unregistered — verifies per-host mapping.
        if system_id == a["id"]:
            return TunnelHealth(
                system_id=system_id,
                state="healthy",
                tunnel_session_id="sa",
                since_seconds=1.0,
                last_heartbeat_age_seconds=0.5,
            )
        return TunnelHealth(system_id=system_id, state="unregistered")

    with patch("app.services.broker_client.BrokerClient.health", new=_fake_health):
        res = authed_client.get("/systems/agent-health")
    assert res.status_code == 200, res.text
    by_id = {row["system_id"]: row for row in res.json()["systems"]}
    assert by_id[a["id"]]["badge_state"] == "agent_connected"
    assert by_id[b["id"]]["badge_state"] == "ssh_fallback"


def test_bulk_agent_health_one_host_failure_does_not_500_request(
    authed_client, mock_vault, distro
):
    """A single host's broker error must NOT take down the whole list.
    Per-host failures degrade to badge_state='unknown'."""
    good = _seed_system(authed_client, distro, hostname="bulk-good", ip="10.3.0.3")
    bad = _seed_system(authed_client, distro, hostname="bulk-bad", ip="10.3.0.4")

    async def _fake_health(self, system_id):
        if system_id == bad["id"]:
            raise RuntimeError("simulated broker explosion for this host")
        return TunnelHealth(
            system_id=system_id,
            state="healthy",
            tunnel_session_id="sg",
            since_seconds=1.0,
            last_heartbeat_age_seconds=0.5,
        )

    with patch("app.services.broker_client.BrokerClient.health", new=_fake_health):
        res = authed_client.get("/systems/agent-health")
    assert res.status_code == 200
    by_id = {row["system_id"]: row for row in res.json()["systems"]}
    assert by_id[good["id"]]["badge_state"] == "agent_connected"
    assert by_id[bad["id"]]["badge_state"] == "unknown"
    assert by_id[bad["id"]]["agent_health"]["state"] == "unknown"


def test_bulk_agent_health_empty_when_no_systems(authed_client):
    """Cleanly returns {systems: []} rather than tripping the
    asyncio.gather call with an empty list."""
    res = authed_client.get("/systems/agent-health")
    assert res.status_code == 200
    assert res.json() == {"systems": []}


# --------------------------------------------------------------------------
# transport_preference exposed on existing GET endpoints
# --------------------------------------------------------------------------


def test_get_system_detail_includes_transport_preference(
    authed_client, mock_vault, distro
):
    sys_obj = _seed_system(authed_client, distro, hostname="show-1", ip="10.4.0.1")
    res = authed_client.get(f"/systems/{sys_obj['id']}")
    assert res.status_code == 200
    assert res.json()["transport_preference"] == "auto"


def test_get_all_systems_includes_transport_preference(
    authed_client, mock_vault, distro
):
    _seed_system(authed_client, distro, hostname="list-pref", ip="10.4.0.2")
    res = authed_client.get("/systems/all")
    assert res.status_code == 200
    assert res.json(), "expected at least one system"
    assert "transport_preference" in res.json()[0]
