"""PRA-166 Slice 2a — live-SSH compliance probe smoke.

This module runs only when ``PRA166_E2E_SSH_HOST`` (and password) are
set in the environment. ``scripts/test-cold-rebuild.sh`` brings up a
throwaway Ubuntu sshd container on the ``praxis_backend_net`` Docker
network, exports the connection details, and invokes pytest with them
set — so the smoke runs as part of the cold-rebuild gate. A plain
``pytest tests/`` outside that gate skips this module cleanly: no
docker socket needed inside the backend container, no extra
dependencies.

The smoke proves three things end-to-end against a real sshd:

* The PRA-166 read-only probe runner can reach a real target through
  :class:`SSHService.get_connection` and run the bounded shell
  commands.
* ``file_exists`` and ``command_exit_code`` produce the expected
  ``runner_executed`` verdicts (``pass`` for ``/etc/passwd`` and
  ``/bin/true``).
* The PRA-166 Slice 1b no-host-mutation contract holds on a live
  connection: ``SSHHostKey`` / ``SSHSecurityLog`` row counts and
  ``SystemMetadata`` / ``System.status`` for the target are
  unchanged across the probe call.

Kept tight — two probes, one cleanup pass — so the cold-rebuild gate
doesn't pay an OS-bootstrap cost per assertion.
"""

from __future__ import annotations

import os
import uuid

import pytest

from app.db.models import (
    CompliancePolicyEvidence,
    Credential,
    Distro,
    Group,
    System,
    SystemMetadata,
)
from app.db.session import SessionLocal
from app.db.ssh_security_models import SSHHostKey, SSHSecurityLog
from app.services.compliance_probe_runner_service import VERDICT_PASS, run_probe
from app.services.vault_service import VaultService

_SSH_HOST = os.environ.get("PRA166_E2E_SSH_HOST")
_SSH_PASSWORD = os.environ.get("PRA166_E2E_SSH_PASSWORD")
_SSH_USER = os.environ.get("PRA166_E2E_SSH_USER", "root")
_SSH_IP = os.environ.get("PRA166_E2E_SSH_IP", _SSH_HOST)

pytestmark = pytest.mark.skipif(
    not (_SSH_HOST and _SSH_PASSWORD),
    reason="PRA166_E2E_SSH_HOST / PRA166_E2E_SSH_PASSWORD not set "
    "(set by scripts/test-cold-rebuild.sh — the regular pytest run "
    "skips this module on purpose)",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db():
    """Real (non-SAVEPOINT) DB session. The probe runner reaches the
    SSH layer, which in the base ``SSHService`` is pool-backed and
    commit-aware; the PRA-166 subclass suppresses those writes but we
    still want a real session to count SSH-side audit rows after the
    probe.
    """
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def smoke_host(db):
    """Materialize a ``System`` row + Vault-backed credential pointing
    at the cold-rebuild SSH target. Cleans up its rows on teardown.
    """
    from datetime import date

    distro = db.query(Distro).filter_by(name="Ubuntu", version="22.04").first()
    if not distro:
        distro = Distro(
            name="Ubuntu",
            version="22.04",
            release_date=date(2022, 4, 21),
            end_of_life_date=date(2027, 4, 21),
        )
        db.add(distro)
        db.flush()

    group = db.query(Group).filter_by(name="pra166-smoke").first()
    if not group:
        group = Group(name="pra166-smoke", description="x")
        db.add(group)
        db.flush()

    vault_path = f"praxis/pra166-smoke/{uuid.uuid4().hex[:8]}"
    VaultService(db).write_secret(vault_path, {"password": _SSH_PASSWORD})

    cred = Credential(
        name=f"pra166-smoke-cred-{uuid.uuid4().hex[:6]}",
        auth_method="password",
        username=_SSH_USER,
        vault_path=vault_path,
    )
    db.add(cred)
    db.flush()

    host = System(
        hostname=_SSH_HOST,
        ip_address=_SSH_IP,
        distro_id=distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    try:
        yield host
    finally:
        # Best-effort cleanup so a follow-up cold-rebuild gate run
        # doesn't trip over leftover rows.
        sys_id = host.id
        db.query(CompliancePolicyEvidence).filter(
            CompliancePolicyEvidence.system_id == sys_id
        ).delete(synchronize_session=False)
        db.query(SSHHostKey).filter(SSHHostKey.system_id == sys_id).delete(
            synchronize_session=False
        )
        db.query(SSHSecurityLog).filter(SSHSecurityLog.system_id == sys_id).delete(
            synchronize_session=False
        )
        db.query(SystemMetadata).filter(SystemMetadata.system_id == sys_id).delete(
            synchronize_session=False
        )
        db.query(System).filter(System.id == sys_id).delete()
        db.query(Credential).filter(Credential.id == cred.id).delete()
        db.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ssh_audit_counts(db, system_id):
    return {
        "security_logs": (
            db.query(SSHSecurityLog)
            .filter(SSHSecurityLog.system_id == system_id)
            .count()
        ),
        "host_keys": (
            db.query(SSHHostKey).filter(SSHHostKey.system_id == system_id).count()
        ),
    }


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------


def test_live_file_exists_probe(db, smoke_host):
    """``file_exists`` against ``/etc/passwd`` on a real sshd target
    must return ``pass`` / ``exists``, AND must not produce any
    SSH-side audit rows or flip ``System.status`` /
    ``SystemMetadata`` for the target.
    """
    before_audit = _ssh_audit_counts(db, smoke_host.id)
    before_meta_count = (
        db.query(SystemMetadata)
        .filter(SystemMetadata.system_id == smoke_host.id)
        .count()
    )
    before_status = smoke_host.status

    outcome = run_probe(
        db,
        kind="file_exists",
        system_id=smoke_host.id,
        definition={"path": "/etc/passwd"},
    )
    assert outcome.verdict == VERDICT_PASS, outcome
    assert outcome.observed_value == "exists"

    after_audit = _ssh_audit_counts(db, smoke_host.id)
    after_meta_count = (
        db.query(SystemMetadata)
        .filter(SystemMetadata.system_id == smoke_host.id)
        .count()
    )
    db.refresh(smoke_host)

    assert after_audit == before_audit, (
        f"compliance probe added SSH audit rows on a live target: "
        f"before={before_audit} after={after_audit}"
    )
    assert (
        after_meta_count == before_meta_count
    ), "compliance probe created/mutated SystemMetadata on a live target"
    assert (
        smoke_host.status == before_status
    ), "compliance probe flipped System.status on a live target"


def test_live_command_exit_code_probe(db, smoke_host):
    """``command_exit_code`` against ``/bin/true`` on a real sshd
    target must return ``pass`` / ``0``.
    """
    outcome = run_probe(
        db,
        kind="command_exit_code",
        system_id=smoke_host.id,
        definition={"command": "/bin/true", "expected_exit_code": 0},
    )
    assert outcome.verdict == VERDICT_PASS, outcome
    assert outcome.observed_value == "0"
