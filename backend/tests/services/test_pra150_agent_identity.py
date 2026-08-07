"""Tests for PRA-150: agent identity service + state machine.

Covers the service layer transitions (issue / renew / disable / enable /
revoke), the 24h renewal grace window, the expiry-aware tunnel-admission
gate, and the terminal nature of ``revoked``.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

import pytest

from app.db.models import Credential, Distro, Group, System
from app.services.agent_identity_service import (
    AgentIdentityError,
    AgentIdentityService,
    _agent_cn,
)

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seed_default_group(db):
    g = db.query(Group).filter_by(name="Default").first()
    if not g:
        g = Group(name="Default")
        db.add(g)
        db.flush()
    return g


@pytest.fixture
def seed_cred(db):
    c = db.query(Credential).filter_by(name="pra150-cred").first()
    if c is None:
        c = Credential(
            name="pra150-cred",
            auth_method="password",
            username="root",
            vault_path="v/pra150",
        )
        db.add(c)
        db.flush()
    return c


@pytest.fixture
def seed_distro(db):
    d = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if d is None:
        d = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(d)
        db.flush()
    return d


@pytest.fixture
def system_row(db, seed_distro, seed_default_group, seed_cred):
    s = System(
        hostname="agent-host-1",
        ip_address="10.9.0.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=seed_default_group.id,
        credentials_id=seed_cred.id,
    )
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def svc(db):
    return AgentIdentityService(db)


def _stub_sign(svc, *, expires_in: timedelta = timedelta(hours=1), serial="ser-1"):
    """Replace svc._sign with a deterministic stub. Each call returns a
    serial suffixed with the call count so renew vs issue can be told
    apart in assertions."""
    counter = {"n": 0}

    def fake_sign(system, csr_pem):  # noqa: ARG001
        counter["n"] += 1
        return {
            "certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            "serial_number": f"{serial}-{counter['n']}",
            "fingerprint": f"fp-{counter['n']}",
            "expires_at": datetime.utcnow() + expires_in,
            "ca_chain": ["ca-cert-pem"],
            "issuing_ca": "ca-cert-pem",
        }

    svc._sign = fake_sign  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# state machine
# ---------------------------------------------------------------------------


def test_initial_state_is_not_enrolled(system_row):
    assert system_row.agent_status == "not_enrolled"
    assert system_row.agent_cert_serial is None
    assert system_row.transport_preference == "auto"


def test_bootstrap_transitions_not_enrolled_to_active(svc, system_row, db):
    _stub_sign(svc)
    res = svc.issue_for_bootstrap(system_row.id, csr_pem="csr-pem")
    db.refresh(system_row)
    assert system_row.agent_status == "active"
    assert system_row.agent_cert_serial == "ser-1-1"
    assert system_row.agent_cert_fingerprint == "fp-1"
    assert system_row.agent_cert_expires_at is not None
    assert res["serial_number"] == "ser-1-1"
    assert res["agent_status"] == "active"


def test_bootstrap_clears_status_reason(svc, system_row, db):
    system_row.agent_status = "disabled"
    system_row.agent_status_reason = "manual pause"
    db.flush()
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    db.refresh(system_row)
    assert system_row.agent_status == "active"
    assert system_row.agent_status_reason is None


def test_bootstrap_denied_when_revoked(svc, system_row, db):
    system_row.agent_status = "revoked"
    db.flush()
    _stub_sign(svc)
    with pytest.raises(AgentIdentityError, match="revoked"):
        svc.issue_for_bootstrap(system_row.id, csr_pem="csr")


def test_renew_only_when_active(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.renew(system_row.id, csr_pem="csr2")
    db.refresh(system_row)
    assert system_row.agent_cert_serial == "ser-1-2"


def test_renew_denied_when_disabled(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.disable(system_row.id, reason="testing")
    with pytest.raises(AgentIdentityError, match="renewal denied"):
        svc.renew(system_row.id, csr_pem="csr2")


def test_renew_within_grace_window_succeeds(svc, system_row, db):
    # Cert expired 12h ago — within the 24h grace window.
    _stub_sign(svc, expires_in=timedelta(hours=-12))
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    db.refresh(system_row)
    assert system_row.agent_cert_expires_at < datetime.utcnow()
    # Renew with a longer-lived stub
    _stub_sign(svc, expires_in=timedelta(hours=1), serial="renewed")
    svc.renew(system_row.id, csr_pem="csr-renew")
    db.refresh(system_row)
    assert system_row.agent_cert_serial == "renewed-1"


def test_renew_beyond_grace_window_denied(svc, system_row, db):
    # Cert expired 25h ago — past 24h grace.
    _stub_sign(svc, expires_in=timedelta(hours=-25))
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    with pytest.raises(AgentIdentityError, match="grace"):
        svc.renew(system_row.id, csr_pem="csr-renew")


def test_disable_then_enable_round_trip(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.disable(system_row.id, reason="maintenance")
    db.refresh(system_row)
    assert system_row.agent_status == "disabled"
    assert system_row.agent_status_reason == "maintenance"
    svc.enable(system_row.id)
    db.refresh(system_row)
    assert system_row.agent_status == "active"
    assert system_row.agent_status_reason is None


def test_enable_only_from_disabled(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    with pytest.raises(AgentIdentityError, match="Cannot enable"):
        svc.enable(system_row.id)


def test_revoke_is_terminal(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.revoke(system_row.id, reason="key compromise")
    db.refresh(system_row)
    assert system_row.agent_status == "revoked"
    assert system_row.agent_revoked_at is not None
    assert system_row.agent_revocation_reason == "key compromise"
    # Cannot disable/enable/renew/bootstrap a revoked system
    with pytest.raises(AgentIdentityError):
        svc.enable(system_row.id)
    with pytest.raises(AgentIdentityError):
        svc.disable(system_row.id)
    with pytest.raises(AgentIdentityError):
        svc.renew(system_row.id, csr_pem="csr")
    with pytest.raises(AgentIdentityError, match="revoked"):
        svc.issue_for_bootstrap(system_row.id, csr_pem="csr")


def test_revoke_idempotent(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.revoke(system_row.id, reason="first")
    # Second revoke is a no-op (does not raise)
    svc.revoke(system_row.id, reason="ignored")
    db.refresh(system_row)
    assert system_row.agent_revocation_reason == "first"


def test_revoke_rejected_for_never_enrolled(svc, system_row):
    with pytest.raises(AgentIdentityError, match="never-enrolled"):
        svc.revoke(system_row.id, reason="why")


def test_disable_disable_keeps_disabled(svc, system_row, db):
    _stub_sign(svc)
    svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    svc.disable(system_row.id, reason="first")
    svc.disable(system_row.id, reason="second")
    db.refresh(system_row)
    assert system_row.agent_status == "disabled"
    assert system_row.agent_status_reason == "second"


# ---------------------------------------------------------------------------
# is_serial_active (tunnel admission gate)
# ---------------------------------------------------------------------------


def test_serial_active_only_when_status_active_and_cert_valid(svc, system_row, db):
    _stub_sign(svc)
    res = svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    serial = res["serial_number"]
    assert svc.is_serial_active(serial) is True

    svc.disable(system_row.id, reason="x")
    assert svc.is_serial_active(serial) is False

    svc.enable(system_row.id)
    assert svc.is_serial_active(serial) is True

    svc.revoke(system_row.id, reason="bye")
    assert svc.is_serial_active(serial) is False


def test_serial_active_rejects_expired_cert(svc, system_row, db):
    # Issue a cert that expires immediately in the past.
    _stub_sign(svc, expires_in=timedelta(seconds=-1))
    res = svc.issue_for_bootstrap(system_row.id, csr_pem="csr")
    db.refresh(system_row)
    # Status is still active (renewal grace covers re-sign), but the tunnel
    # gate must NOT honor an expired cert.
    assert system_row.agent_status == "active"
    assert svc.is_serial_active(res["serial_number"]) is False


def test_serial_active_unknown_serial(svc):
    assert svc.is_serial_active("not-a-real-serial") is False
    assert svc.is_serial_active("") is False


# ---------------------------------------------------------------------------
# CN construction
# ---------------------------------------------------------------------------


def test_agent_cn_is_backend_controlled():
    assert _agent_cn(42) == "system-42.agent.praxis.internal"
    assert _agent_cn(1) == "system-1.agent.praxis.internal"
