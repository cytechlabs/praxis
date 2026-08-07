"""PRA-132: entitlement registry, EE loader boundary, and paid-route gates.

Free/no-EE mode is the production default. The ``_default_entitlements`` autouse
fixture (conftest) puts every test in the fully-entitled enterprise edition, so
these tests explicitly ``registry.reset()`` to assert free-mode behavior.
"""

import sys
import types

import pytest

from app.core.entitlements import (
    ACCESS_ACCESS_REVIEWS,
    ACCESS_SESSION_LOCKS,
    EDITION_ENTERPRISE,
    EDITION_FREE,
    FREE_HOST_CAP,
    PAID_ENTITLEMENTS,
    EntitlementError,
    EntitlementRegistry,
    registry,
)
from app.ee.loader import EELoaderError, load_ee

# Representative GET routes covering every router-level and endpoint-level gate.
GATED_GET_ROUTES = [
    "/session-locks",  # access.session_locks (router-level)
    "/session-approvals",  # access.session_approvals (router-level)
    "/access-reviews",  # access.access_reviews (router-level)
    "/command-approvals",  # commands.approvals (router-level)
    "/compliance/exports/evidence.jsonl",  # compliance.bulk_exports (router-level)
    "/command-results/metrics/report",  # commands.metrics (endpoint-level)
]


# --------------------------------------------------------------------------- #
# Registry unit behavior
# --------------------------------------------------------------------------- #


def test_registry_defaults_to_free():
    reg = EntitlementRegistry()
    assert reg.edition == EDITION_FREE
    assert reg.host_cap == FREE_HOST_CAP
    assert reg.active_entitlements() == []
    assert all(v is False for v in reg.entitlement_map().values())
    assert set(reg.entitlement_map().keys()) == set(PAID_ENTITLEMENTS)


def test_registry_grant_unknown_key_fails_loudly():
    reg = EntitlementRegistry()
    with pytest.raises(EntitlementError):
        reg.grant("bogus.not.a.key")


def test_registry_grant_and_reset():
    reg = EntitlementRegistry()
    assert reg.is_active(ACCESS_SESSION_LOCKS) is False
    reg.grant(ACCESS_SESSION_LOCKS)
    assert reg.is_active(ACCESS_SESSION_LOCKS) is True
    reg.reset()
    assert reg.is_active(ACCESS_SESSION_LOCKS) is False
    assert reg.edition == EDITION_FREE


def test_registry_enable_enterprise():
    reg = EntitlementRegistry()
    reg.enable_enterprise()
    assert reg.edition == EDITION_ENTERPRISE
    assert all(v is True for v in reg.entitlement_map().values())


# --------------------------------------------------------------------------- #
# EE loader boundary
# --------------------------------------------------------------------------- #


def test_load_ee_absent_is_free(monkeypatch):
    """No praxis_ee installed -> free edition, no error."""
    monkeypatch.delitem(sys.modules, "praxis_ee", raising=False)
    reg = EntitlementRegistry()
    assert load_ee(registry=reg) is False
    assert reg.edition == EDITION_FREE


def test_load_ee_present_but_no_register_raises(monkeypatch):
    """praxis_ee present but broken contract -> fail loud."""
    fake = types.ModuleType("praxis_ee")  # no register_ee attribute
    monkeypatch.setitem(sys.modules, "praxis_ee", fake)
    reg = EntitlementRegistry()
    with pytest.raises(EELoaderError):
        load_ee(registry=reg)


def test_load_ee_register_raises_wrapped(monkeypatch):
    """A register_ee that raises is wrapped in EELoaderError (fail loud)."""
    fake = types.ModuleType("praxis_ee")

    def register_ee(**_kwargs):
        raise ValueError("license file corrupt")

    fake.register_ee = register_ee
    monkeypatch.setitem(sys.modules, "praxis_ee", fake)
    reg = EntitlementRegistry()
    with pytest.raises(EELoaderError):
        load_ee(registry=reg)


def test_load_ee_valid_registers(monkeypatch):
    """A well-formed praxis_ee registers paid entitlements."""
    fake = types.ModuleType("praxis_ee")

    def register_ee(*, registry, app=None, db_session_factory=None, config=None):
        registry.enable_enterprise()

    fake.register_ee = register_ee
    monkeypatch.setitem(sys.modules, "praxis_ee", fake)
    reg = EntitlementRegistry()
    assert load_ee(registry=reg) is True
    assert reg.edition == EDITION_ENTERPRISE
    assert reg.is_active(ACCESS_ACCESS_REVIEWS) is True


def test_load_ee_internal_dependency_missing_raises(monkeypatch):
    """praxis_ee is installed but one of ITS imports is missing -> fail loud, not
    a silent downgrade to free."""
    import app.ee.loader as loader_mod

    def boom(_name):
        raise ModuleNotFoundError("No module named 'psycopg2'", name="psycopg2")

    monkeypatch.setattr(loader_mod.importlib, "import_module", boom)
    reg = EntitlementRegistry()
    with pytest.raises(EELoaderError):
        load_ee(registry=reg)


def test_load_ee_top_level_missing_is_free(monkeypatch):
    """A ModuleNotFoundError naming praxis_ee itself -> free edition, no error."""
    import app.ee.loader as loader_mod

    def missing(name):
        raise ModuleNotFoundError(f"No module named '{name}'", name=name)

    monkeypatch.setattr(loader_mod.importlib, "import_module", missing)
    reg = EntitlementRegistry()
    assert load_ee(registry=reg) is False
    assert reg.edition == EDITION_FREE


# --------------------------------------------------------------------------- #
# Edition endpoint
# --------------------------------------------------------------------------- #


def test_edition_endpoint_free(authed_client):
    registry.reset()
    res = authed_client.get("/edition")
    assert res.status_code == 200
    data = res.json()
    assert data["edition"] == EDITION_FREE
    assert data["host_cap"] == FREE_HOST_CAP
    assert set(data["entitlements"].keys()) == set(PAID_ENTITLEMENTS)
    assert all(v is False for v in data["entitlements"].values())
    assert "host_count" in data
    assert data["hosts_over_cap"] is False  # empty fleet in tests


def test_edition_endpoint_enterprise(authed_client):
    # autouse fixture already put us in enterprise mode
    res = authed_client.get("/edition")
    assert res.status_code == 200
    data = res.json()
    assert data["edition"] == EDITION_ENTERPRISE
    assert all(v is True for v in data["entitlements"].values())


def test_edition_endpoint_requires_auth(client):
    assert client.get("/edition").status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Server-side gates
# --------------------------------------------------------------------------- #


def test_gated_get_routes_blocked_in_free_mode(authed_client):
    registry.reset()
    for path in GATED_GET_ROUTES:
        res = authed_client.get(path)
        assert (
            res.status_code == 402
        ), f"{path} should be 402 in free mode, got {res.status_code}"


def test_gated_get_routes_allowed_when_entitled(authed_client):
    # autouse enterprise mode; a paid feature must NOT be paywalled.
    for path in GATED_GET_ROUTES:
        res = authed_client.get(path)
        assert (
            res.status_code != 402
        ), f"{path} unexpectedly paywalled when entitled ({res.status_code})"


def test_scheduled_report_export_gate(authed_client):
    body = {"name": "demo", "report_kind": "compliance_evidence", "cadence": "daily"}
    registry.reset()
    res = authed_client.post("/reports/schedules", json=body)
    assert res.status_code == 402
    registry.enable_enterprise()
    res2 = authed_client.post("/reports/schedules", json=body)
    assert res2.status_code != 402


def test_free_core_routes_not_gated(authed_client):
    """Sanity: core/free surfaces are never paywalled. Command history stays
    free even though command metrics is paid."""
    registry.reset()
    for path in ("/reports/runs", "/command-results/history"):
        res = authed_client.get(path)
        assert res.status_code != 402, f"{path} should be free, got {res.status_code}"


def test_command_execution_free_mode_creates_no_approval(
    db, admin_user, seed_distro, monkeypatch
):
    """A whitelist entry that requires approval must not strand a pending
    CommandApproval in the free edition — the paid approval workflow is gated
    with a 402 before any row is inserted."""
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.db.models import (
        CommandApproval,
        CommandWhitelist,
        Credential,
        Group,
        System,
    )
    from app.services.command_execution_service import CommandExecutionService

    group = Group(name="pra132-cmd", description="x")
    db.add(group)
    db.flush()
    cred = Credential(name="pra132-cmd-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    system = System(
        hostname="pra132-cmd-host.example.com",
        ip_address="198.51.100.60",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(system)
    db.flush()
    wl = CommandWhitelist(
        name="approval-required",
        command_pattern="ls",
        risk_level="low",
        category="system_info",
        requires_approval=True,
        required_approvals=1,
        created_by=admin_user.id,
    )
    db.add(wl)
    db.flush()
    db.commit()

    svc = CommandExecutionService(db)
    monkeypatch.setattr(
        svc,
        "_get_execution_policy",
        lambda *a, **k: SimpleNamespace(
            require_validation=True, default_timeout_seconds=30
        ),
    )
    monkeypatch.setattr(
        svc.validation_service,
        "validate_command",
        lambda *a, **k: {"status": "allowed", "command_id": wl.id, "risk_level": "low"},
    )

    registry.reset()  # free edition
    with pytest.raises(HTTPException) as excinfo:
        svc.execute_command(
            system_id=system.id,
            user_id=admin_user.id,
            command="ls",
            bypass_validation=False,
        )
    assert excinfo.value.status_code == 402
    assert db.query(CommandApproval).count() == 0
