"""PRA-324: GET /agent/status derives live tunnel liveness from the broker.

The DB only stores ``agent_last_seen_at`` (a timestamp); the authoritative
online/stale/offline signal lives in the broker's in-memory registry. The
status route now consults ``BrokerClient.health`` and maps the tunnel state
onto an operator-facing ``agent_liveness`` label. A broker that is
unreachable yields ``unknown`` (never ``offline``) so we don't imply the
agent is gone when we simply couldn't ask.
"""

from __future__ import annotations

from datetime import date
from unittest.mock import patch

import pytest

from app.db.models import Credential, Distro, Group, System
from app.services.broker_client import TunnelHealth


@pytest.fixture
def sys_row(db):
    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if distro is None:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()
    group = db.query(Group).filter_by(name="Default").first()
    if group is None:
        group = Group(name="Default")
        db.add(group)
        db.flush()
    cred = db.query(Credential).filter_by(name="liveness-api-cred").first()
    if cred is None:
        cred = Credential(
            name="liveness-api-cred",
            auth_method="password",
            username="root",
            vault_path="v/liveness-api",
        )
        db.add(cred)
        db.flush()
    s = System(
        hostname="liveness-api-host",
        ip_address="10.20.0.2",
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


def _fake_health(state):
    async def _h(self, system_id):  # noqa: ANN001, ARG001
        return TunnelHealth(system_id=system_id, state=state)

    return _h


@pytest.mark.parametrize(
    "tunnel_state,expected_liveness",
    [
        ("healthy", "online"),
        ("stale", "stale"),
        ("unregistered", "offline"),
        ("unknown", "unknown"),
    ],
)
def test_status_maps_tunnel_state_to_liveness(
    authed_client, sys_row, tunnel_state, expected_liveness
):
    with patch(
        "app.services.broker_client.BrokerClient.health",
        new=_fake_health(tunnel_state),
    ):
        res = authed_client.get(f"/agent/status/{sys_row.id}")
    assert res.status_code == 200, res.text
    assert res.json()["agent_liveness"] == expected_liveness


def test_status_liveness_unknown_when_broker_call_raises(authed_client, sys_row):
    async def _boom(self, system_id):  # noqa: ANN001, ARG001
        raise RuntimeError("broker down")

    with patch("app.services.broker_client.BrokerClient.health", new=_boom):
        res = authed_client.get(f"/agent/status/{sys_row.id}")
    assert res.status_code == 200, res.text
    assert res.json()["agent_liveness"] == "unknown"


def test_status_still_returns_lifecycle_fields(authed_client, sys_row):
    """Liveness is additive — the enrollment-lifecycle fields still come
    through so the two axes (agent_status vs agent_liveness) coexist."""
    with patch(
        "app.services.broker_client.BrokerClient.health",
        new=_fake_health("unregistered"),
    ):
        res = authed_client.get(f"/agent/status/{sys_row.id}")
    body = res.json()
    assert body["agent_status"] == "not_enrolled"
    assert body["agent_liveness"] == "offline"
    assert body["transport_preference"] in ("auto", "ssh", "agent")
