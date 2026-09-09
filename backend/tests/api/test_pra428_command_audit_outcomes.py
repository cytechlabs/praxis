"""PRA-428: command.exec audit outcomes follow the service response contract.

``POST /command-execution/execute`` audits every governed command. The service
reports terminal state under ``execution_status`` (``success`` for a completed run
with exit code 0, ``failed`` otherwise, ``pending_approval`` when an approval gate
holds the command). The route used to read a ``status`` key that the service never
sets, so a successful live command persisted as ``outcome=failure``.

These tests drive the real route, the real ``CommandExecutionService`` (policy,
validation, approval, ledger row, response shaping) and the real audit sink. Only
the transport boundary is doubled: ``_execute_command_with_monitoring`` returns the
same dict shape a real transport run produces, so the response that reaches the
route is the genuine service contract. The persisted ``AuditEvent`` rows are the
evidence, read both directly and through the per-host audit query.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from app.db.access_models import AuditEvent
from app.db.command_execution_models import CommandExecutionPolicy
from app.db.models import CommandApproval, CommandWhitelist, Credential, Group, System
from app.services.access_binding_service import recompute_grants
from app.services.command_execution_service import CommandExecutionService

# The context keys the audit schema documents for command.exec success/failure.
_EXEC_CONTEXT_KEYS = {"command", "exit_code", "execution_time_ms", "bypass_validation"}

# --------------------------------------------------------------------- helpers


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def _system(db, seed_distro, hostname: str, ip: str) -> System:
    g = db.query(Group).filter_by(name="pra428-grp").first()
    if not g:
        g = Group(name="pra428-grp", description="x")
        db.add(g)
        db.flush()
    c = Credential(
        name=f"pra428-cred-{hostname}", auth_method="ssh_key", username="root"
    )
    db.add(c)
    db.flush()
    s = System(
        hostname=hostname,
        ip_address=ip,
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=c.id,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    # Materialize the fleet grants the binding service maintains in production:
    # active admins receive an implicit grant on every system, a maintainer with
    # no binding receives none.
    recompute_grants(db)
    return s


def _policy(db, admin_user) -> CommandExecutionPolicy:
    """A global execution policy that requires validation, as the service's own
    default does. Seeded explicitly because the built-in default names a system
    user the throwaway test database does not carry."""
    p = CommandExecutionPolicy(
        name="pra428-policy",
        description="x",
        require_validation=True,
        applies_to_all_systems=True,
        applies_to_all_users=True,
        is_active=True,
        created_by=admin_user.id,
    )
    db.add(p)
    db.commit()
    return p


def _whitelist(db, admin_user, *, pattern: str, requires_approval: bool = False):
    e = CommandWhitelist(
        name=f"pra428-{pattern}",
        command_pattern=pattern,
        is_regex=False,
        is_active=True,
        risk_level="low",
        category="general",
        requires_sudo=False,
        requires_approval=requires_approval,
        timeout_seconds=30,
        created_by=admin_user.id,
    )
    db.add(e)
    db.commit()
    return e


def _exec_events(db, system_id: int) -> List[AuditEvent]:
    return (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "command.exec",
            AuditEvent.target_system_id == system_id,
        )
        .order_by(AuditEvent.id.asc())
        .all()
    )


def _context(row: AuditEvent) -> Dict[str, Any]:
    return json.loads(row.context_json or "{}")


@pytest.fixture
def transport(monkeypatch):
    """Double the transport boundary only.

    ``_execute_command_with_monitoring`` is what a real SSH or agent transport run
    resolves to; it returns ``status``/``exit_code``/``stdout``/``stderr``/
    ``execution_time_ms``/``transport``. Everything above it (policy resolution,
    validation, the ledger row, result processing, response shaping) runs for real,
    so the route receives the genuine service contract.
    """
    calls: List[Dict[str, Any]] = []
    outcomes: Dict[str, Dict[str, Any]] = {}

    def _script(command: str, **result):
        outcomes[command] = result

    def _fake(self, system, command, timeout_seconds, resource_limits, execution_id):
        calls.append({"system_id": system.id, "command": command})
        scripted = outcomes.get(command)
        assert scripted is not None, f"unexpected command reached transport: {command}"
        return {
            "status": scripted.get("status", "failed"),
            "exit_code": scripted.get("exit_code"),
            "stdout": scripted.get("stdout", ""),
            "stderr": scripted.get("stderr", ""),
            "execution_time_ms": 7,
            "transport": "ssh",
            **{
                k: v
                for k, v in scripted.items()
                if k in ("error_type", "error_message")
            },
        }

    monkeypatch.setattr(
        CommandExecutionService, "_execute_command_with_monitoring", _fake
    )
    return type("Transport", (), {"calls": calls, "script": staticmethod(_script)})


# ------------------------------------------------------------- success path


def test_successful_execution_audits_success_for_actor_and_host(
    db, client, admin_user, seed_distro, transport
):
    """The core regression. A whitelisted command that completes with exit code 0
    comes back from the service as ``execution_status=success`` and must be
    persisted as ``outcome=success`` attributed to the calling user and the
    target host. Before the fix the same run was recorded as ``failure``."""
    s = _system(db, seed_distro, "pra428-ok", "10.42.8.1")
    _policy(db, admin_user)
    _whitelist(db, admin_user, pattern="echo praxis-428-ok")
    transport.script("echo praxis-428-ok", status="success", exit_code=0)

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": s.id, "command": "echo praxis-428-ok"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_status"] == "success"
    assert body["exit_code"] == 0
    assert "status" not in body

    rows = _exec_events(db, s.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == "success"
    assert row.actor_user_id == admin_user.id
    assert row.actor_username == admin_user.username
    assert row.target_kind == "system"
    assert row.target_id == str(s.id)
    ctx = _context(row)
    assert set(ctx) == _EXEC_CONTEXT_KEYS
    assert ctx["command"] == "echo praxis-428-ok"
    assert ctx["exit_code"] == 0
    assert ctx["bypass_validation"] is False
    assert transport.calls == [{"system_id": s.id, "command": "echo praxis-428-ok"}]


# ------------------------------------------------------------- failure paths


def test_nonzero_exit_audits_failure_with_sanitized_context(
    db, client, admin_user, seed_distro, transport
):
    """A permitted command that ran and exited nonzero is ``execution_status=failed``
    and audits as ``failure``. The context carries the exit code and the documented
    keys only: no stdout/stderr, which may contain host data."""
    s = _system(db, seed_distro, "pra428-nonzero", "10.42.8.2")
    _policy(db, admin_user)
    _whitelist(db, admin_user, pattern="ls /praxis-428-missing")
    transport.script(
        "ls /praxis-428-missing",
        status="failed",
        exit_code=2,
        stderr="ls: cannot access '/praxis-428-missing': No such file or directory",
    )

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": s.id, "command": "ls /praxis-428-missing"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["execution_status"] == "failed"
    assert res.json()["exit_code"] == 2

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["failure"]
    ctx = _context(rows[0])
    assert set(ctx) == _EXEC_CONTEXT_KEYS
    assert ctx["exit_code"] == 2
    assert "praxis-428-missing" not in json.dumps(
        {k: v for k, v in ctx.items() if k != "command"}
    )
    assert rows[0].actor_user_id == admin_user.id


def test_transport_failure_audits_failure(
    db, client, admin_user, seed_distro, transport
):
    """An execution that never produced an exit code (transport error) is also a
    ``failure`` with a null exit code, not a success."""
    s = _system(db, seed_distro, "pra428-transport", "10.42.8.3")
    _policy(db, admin_user)
    _whitelist(db, admin_user, pattern="uptime")
    transport.script(
        "uptime",
        status="failed",
        error_type="transport_error",
        error_message="connection reset",
    )

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute", json={"system_id": s.id, "command": "uptime"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["execution_status"] == "failed"
    assert res.json()["error_type"] == "transport_error"

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["failure"]
    assert _context(rows[0])["exit_code"] is None


# ------------------------------------------------------------- refusal paths


def test_validation_refusal_audits_failure_and_runs_nothing(
    db, client, admin_user, seed_distro, transport
):
    """A command the whitelist refuses is returned as ``execution_status=failed`` /
    ``validation_status=failed`` without reaching the transport. The audit row
    keeps the established ``failure`` outcome and is never ``success``."""
    s = _system(db, seed_distro, "pra428-refused", "10.42.8.4")
    _policy(db, admin_user)

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": s.id, "command": "rm -rf /praxis-428-nope"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_status"] == "failed"
    assert body["validation_status"] == "failed"
    assert body["error_type"] == "validation_error"
    assert transport.calls == [], "a refused command must never reach a transport"

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["failure"]
    assert _context(rows[0])["exit_code"] is None
    assert rows[0].actor_user_id == admin_user.id


def test_fleet_denial_audits_denied_and_runs_nothing(
    db, client, maintainer_user, seed_distro, transport
):
    """A caller without a fleet grant is denied before the service runs. The only
    audit row is ``denied`` with the documented denial context."""
    s = _system(db, seed_distro, "pra428-denied", "10.42.8.5")

    _login(client, maintainer_user)
    res = client.post(
        "/command-execution/execute", json={"system_id": s.id, "command": "uptime"}
    )
    assert res.status_code == 403, res.text
    assert transport.calls == []

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["denied"]
    assert rows[0].actor_user_id == maintainer_user.id
    assert set(_context(rows[0])) == {"reason_code", "reason"}


def test_approval_required_is_pending_and_never_audits_success(
    db, client, admin_user, seed_distro, transport
):
    """A whitelist entry that requires approval parks the command as
    ``execution_status=pending_approval`` with an approval request and no
    execution. The audit outcome keeps its established non-success value."""
    s = _system(db, seed_distro, "pra428-approval", "10.42.8.6")
    _policy(db, admin_user)
    _whitelist(
        db, admin_user, pattern="systemctl restart praxis-428", requires_approval=True
    )

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute",
        json={"system_id": s.id, "command": "systemctl restart praxis-428"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["execution_status"] == "pending_approval"
    assert transport.calls == []
    approvals = (
        db.query(CommandApproval).filter(CommandApproval.system_id == s.id).all()
    )
    assert len(approvals) == 1 and approvals[0].status == "pending"

    rows = _exec_events(db, s.id)
    assert len(rows) == 1
    assert rows[0].outcome == "failure"
    assert rows[0].outcome != "success"


# ------------------------------------------------ status classification bound


@pytest.mark.parametrize(
    "execution_status",
    [None, "running", "timeout", "failed", "pending_approval", "unknown", ""],
    ids=[
        "missing",
        "running",
        "timeout",
        "failed",
        "pending_approval",
        "unknown",
        "empty",
    ],
)
def test_non_success_status_is_never_classified_success(
    db, client, admin_user, seed_distro, monkeypatch, execution_status: Optional[str]
):
    """The audit outcome is decided from the service result before the response
    model validates it. Any status other than ``success``, including a missing
    one, must be persisted as ``failure`` even when the response model then
    rejects the malformed result."""
    s = _system(db, seed_distro, "pra428-bound", "10.42.8.7")

    def _fake_execute(self, **kwargs):
        shaped = {
            "id": 1,
            "system_id": s.id,
            "system_hostname": s.hostname,
            "user_id": admin_user.id,
            "username": admin_user.username,
            "session_id": None,
            "command": kwargs["command"],
            "normalized_command": kwargs["command"],
            "command_hash": "x" * 64,
            "exit_code": None,
            "stdout": None,
            "stderr": None,
            "started_at": None,
            "completed_at": None,
            "execution_time_ms": 1,
            "timeout_seconds": 30,
            "max_memory_usage_bytes": None,
            "cpu_time_ms": None,
            "validation_status": "validated",
            "risk_level": "low",
            "requires_sudo": False,
            "actual_user": None,
            "transport": "ssh",
            "error_type": None,
            "error_message": None,
            "retry_count": 0,
            "execution_context": None,
        }
        if execution_status is not None:
            shaped["execution_status"] = execution_status
        return shaped

    monkeypatch.setattr(CommandExecutionService, "execute_command", _fake_execute)

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute", json={"system_id": s.id, "command": "uptime"}
    )
    # A missing status is malformed for the response model and surfaces as a
    # server error; every other value returns normally. Either way the audit
    # decision has already been persisted.
    assert res.status_code in (200, 500), res.text

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["failure"]


def test_legacy_status_key_does_not_decide_the_outcome(
    db, client, admin_user, seed_distro, monkeypatch
):
    """The service never emits a top-level ``status`` key. A result that carries
    one anyway must not be classified from it: ``execution_status`` is the
    contract, so ``status=success`` alongside ``execution_status=failed`` is a
    ``failure``. This is the exact key mismatch the original route had."""
    s = _system(db, seed_distro, "pra428-legacy", "10.42.8.8")

    def _fake_execute(self, **kwargs):
        return {
            "id": 1,
            "system_id": s.id,
            "user_id": admin_user.id,
            "session_id": None,
            "command": kwargs["command"],
            "command_hash": "x" * 64,
            "status": "success",
            "execution_status": "failed",
            "exit_code": 1,
            "stdout": None,
            "stderr": None,
            "started_at": None,
            "completed_at": None,
            "execution_time_ms": 1,
            "timeout_seconds": 30,
            "max_memory_usage_bytes": None,
            "cpu_time_ms": None,
            "validation_status": "validated",
            "risk_level": "low",
            "requires_sudo": False,
            "actual_user": None,
            "error_type": None,
            "error_message": None,
            "retry_count": 0,
            "execution_context": None,
        }

    monkeypatch.setattr(CommandExecutionService, "execute_command", _fake_execute)

    _login(client, admin_user)
    res = client.post(
        "/command-execution/execute", json={"system_id": s.id, "command": "uptime"}
    )
    assert res.status_code == 200, res.text

    rows = _exec_events(db, s.id)
    assert [r.outcome for r in rows] == ["failure"]


# ------------------------------------------------------- per-host retrieval


def test_per_host_audit_query_returns_only_that_hosts_outcomes(
    db, client, admin_user, seed_distro, transport
):
    """Two hosts, one success and one nonzero exit. The per-host audit query
    returns each host's own command.exec outcome and nothing from the other."""
    a = _system(db, seed_distro, "pra428-host-a", "10.42.8.9")
    b = _system(db, seed_distro, "pra428-host-b", "10.42.8.10")
    _policy(db, admin_user)
    _whitelist(db, admin_user, pattern="true")
    _whitelist(db, admin_user, pattern="false")
    transport.script("true", status="success", exit_code=0)
    transport.script("false", status="failed", exit_code=1)

    _login(client, admin_user)
    assert (
        client.post(
            "/command-execution/execute", json={"system_id": a.id, "command": "true"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/command-execution/execute", json={"system_id": b.id, "command": "false"}
        ).status_code
        == 200
    )

    def _host_events(system_id: int):
        res = client.get(
            "/audit/events", params={"system_id": system_id, "action": "command.exec"}
        )
        assert res.status_code == 200, res.text
        return res.json()["events"]

    events_a = _host_events(a.id)
    events_b = _host_events(b.id)
    assert [(e["target"]["system_id"], e["outcome"]) for e in events_a] == [
        (a.id, "success")
    ]
    assert [(e["target"]["system_id"], e["outcome"]) for e in events_b] == [
        (b.id, "failure")
    ]
    assert events_a[0]["context"]["command"] == "true"
    assert events_b[0]["context"]["command"] == "false"
    assert events_a[0]["actor"]["user_id"] == admin_user.id
