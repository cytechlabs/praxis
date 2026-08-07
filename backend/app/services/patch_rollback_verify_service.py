"""Patch rollback verification service (PRA-173 slice 4).

Closes the rollback lifecycle. After a Slice 3 dispatch host reaches
``succeeded`` or ``failed``, the verifier reads the host's
**observed** post-rollback package versions and writes them into
:class:`PatchRollbackDispatchHostPackage.installed_version_after`,
then emits one :class:`PackageHistory` row per package so the
platform's package-history surface reflects rollback the same way
it reflects forward updates.

**Verification reads observed facts, not requested command intent.**
The whole point of the slice is that the dispatcher records *what we
asked for* (frozen plan + per-package ``target_rollback_version``);
the verifier records *what actually happened on the host*. The two
can disagree — the apt command may have exited 0 but a held
package may have been silently skipped — and the verification path
is the only honest source for that distinction.

Probe seam:

The verifier delegates the "read the host's current package
versions" step to a ``RollbackPackageProbeCallable``: a sync
``(System, list[str]) -> RollbackPackageProbeResult`` function.
Tests pass a fake; the default implementation reads the existing
``Package`` table (which the PRA-155 facts pipeline keeps current).
Slice 4 deliberately does **not** invoke the live facts collector —
that's beyond the slice's transport scope. A later slice can swap
in an SSH-side probe if operators want stronger guarantees.

PackageHistory writes happen only when the probe is ``reachable``
and observes a version for the package. ``operation`` is
``"rollback"`` for hosts whose dispatch state is ``succeeded`` and
``"rollback_attempted_failed"`` for hosts whose dispatch state is
``failed``. The ``before_version`` recorded is the dispatch row's
``installed_version_before`` (the post-update value the operator
was rolling back from); ``new_version`` is the observed
post-rollback version.

Audit events (via ``safe_emit`` no ``db=``):

- ``patch_rollback.host_verified`` — once per host whose
  verification probe ran (whether reachable or not).
- ``patch_rollback.verification_complete`` — once when every host
  on the run reaches a terminal state with either a recorded
  ``installed_version_after`` or a recorded refusal in its
  ``error_details.verification_refusal``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.models import (
    Package,
    PackageHistory,
    PatchRollbackDispatchHost,
    PatchRollbackDispatchHostPackage,
    PatchRollbackDispatchRun,
    PatchUpdateExecution,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackPackage,
    System,
    User,
)
from .audit_event_service import safe_emit
from .patch_rollback_dispatch_service import HOST_STATE_FAILED, HOST_STATE_SUCCEEDED
from .patch_rollback_service import PatchUpdateRollbackError, utc_iso

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Probe seam (tests inject a fake)
# ---------------------------------------------------------------------------


VERIFY_REASON_SYSTEM_DELETED = "system_deleted"
VERIFY_REASON_TRANSPORT_UNAVAILABLE = "transport_unavailable"
VERIFY_REASON_TRANSPORT_ERROR = "transport_error"
VERIFY_REASON_NO_PACKAGES_REPORTED = "no_packages_reported"


@dataclass
class RollbackPackageProbeResult:
    """Outcome of one rollback verification probe.

    ``reachable`` indicates the verifier could read the host's
    package state at all (system row present, transport ok). When
    ``reachable=True`` the ``observed_versions`` dict carries
    ``{package_name: installed_version_or_None}`` — note that an
    explicit ``None`` value means "the host reports the package is
    not installed" (a meaningful observation, distinct from "we
    couldn't reach the host"). ``reason`` / ``error`` carry the
    structured refusal when ``reachable=False``.
    """

    reachable: bool
    observed_versions: Dict[str, Optional[str]] = field(default_factory=dict)
    reason: Optional[str] = None
    error: Optional[str] = None


# Sync callable: takes (System, list of package names to observe)
# and returns ``RollbackPackageProbeResult``. Tests pass fakes.
RollbackPackageProbeCallable = Callable[[System, List[str]], RollbackPackageProbeResult]


def default_rollback_package_probe(
    db: Session, system: System, package_names: List[str]
) -> RollbackPackageProbeResult:
    """Default probe: trigger a fresh SSH package inventory scan via
    :class:`PackageService.scan_packages`, then read the just-
    refreshed ``packages`` table.

    Slice 4a: the original default read stale
    ``Package`` rows whose ``installed_version`` could be hours
    old, so the verifier was effectively recording
    pre-verification state as observed post-rollback state.

    Slice 4b: the first fix called
    ``ssh_facts_collector_service.collect_and_ingest``, but that
    seam only refreshes ``HostFacts`` (uptime, kernel,
    distro_release). ``Package.installed_version`` is refreshed
    by :class:`PackageService.scan_packages`, which is the
    *package inventory* SSH primitive. Production now goes
    through ``scan_packages`` so the post-rollback observation
    reflects the actual package state on the host.

    SSH / scan failures surface as ``transport_unavailable``
    refusal so the route layer can record a structured refusal
    block; subsequent verify-due batches re-probe and may
    resolve a transient outage.

    Tests still inject a fake ``RollbackPackageProbeCallable`` and
    never exercise this code path.
    """
    if not package_names:
        return RollbackPackageProbeResult(reachable=True, observed_versions={})

    # Trigger a fresh package inventory scan. Any failure here
    # surfaces as ``transport_unavailable`` so the caller records a
    # structured refusal block; the host gets re-probed on the
    # next verify-due batch.
    from .package_service import PackageService

    try:
        scan_result = PackageService(db).scan_packages(system.id)
    except Exception as exc:  # pylint: disable=broad-except
        # ``scan_packages`` can raise ``ValueError`` (unknown system
        # / unsupported distro) and a variety of SSH-transport
        # errors. Treat every raise as transport_unavailable so the
        # host gets a structured refusal block that operators can
        # triage; re-probe on the next batch.
        return RollbackPackageProbeResult(
            reachable=False,
            reason=VERIFY_REASON_TRANSPORT_UNAVAILABLE,
            error=str(exc),
        )

    if scan_result.get("status") != "success":
        # ``scan_packages`` returns ``status='error'`` when SSH
        # connected but the remote ``list_installed`` command
        # produced no usable output. The structured message goes
        # into the refusal so operators see what went wrong.
        return RollbackPackageProbeResult(
            reachable=False,
            reason=VERIFY_REASON_TRANSPORT_UNAVAILABLE,
            error=str(scan_result.get("message") or "package scan failed"),
        )

    rows = (
        db.query(Package.name, Package.installed_version)
        .filter(
            Package.system_id == system.id,
            Package.name.in_(package_names),
        )
        .all()
    )
    by_name: Dict[str, Optional[str]] = {name: None for name in package_names}
    for name, version in rows:
        by_name[name] = version
    return RollbackPackageProbeResult(reachable=True, observed_versions=by_name)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

AUDIT_ROLLBACK_HOST_VERIFIED = "patch_rollback.host_verified"
AUDIT_ROLLBACK_VERIFICATION_COMPLETE = "patch_rollback.verification_complete"


PACKAGE_HISTORY_OPERATION_ROLLBACK = "rollback"
PACKAGE_HISTORY_OPERATION_ROLLBACK_FAILED = "rollback_attempted_failed"


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------


@dataclass
class RollbackVerifyHostOutcome:
    """Per-host outcome inside a verify-due batch result."""

    rollback_dispatch_host_id: int
    system_id: Optional[int]
    reachable: bool
    verified_package_count: int = 0
    package_history_written_count: int = 0
    reason: Optional[str] = None


@dataclass
class RollbackVerifyBatchSummary:
    """Result envelope returned by ``verify_due_rollbacks``."""

    rollback_dispatch_run_id: int
    attempted_host_count: int = 0
    reachable_host_count: int = 0
    unreachable_host_count: int = 0
    no_due: bool = False
    verification_complete: bool = False
    host_outcomes: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_user(db: Session, user_id: int) -> None:
    if not db.query(User.id).filter(User.id == user_id).first():
        raise PatchUpdateRollbackError(
            f"actor_user_id={user_id} does not reference a user"
        )


def _require_run(db: Session, run_id: int) -> PatchRollbackDispatchRun:
    run = (
        db.query(PatchRollbackDispatchRun)
        .filter(PatchRollbackDispatchRun.id == run_id)
        .first()
    )
    if run is None:
        raise PatchUpdateRollbackError(
            f"patch rollback dispatch run id={run_id} not found"
        )
    return run


def _due_hosts(db: Session, run_id: int) -> List[PatchRollbackDispatchHost]:
    """Hosts whose dispatch reached a terminal state (succeeded /
    failed) AND at least one package row still lacks
    ``installed_version_after``."""
    return (
        db.query(PatchRollbackDispatchHost)
        .filter(
            PatchRollbackDispatchHost.rollback_dispatch_run_id == run_id,
            PatchRollbackDispatchHost.state.in_(
                [HOST_STATE_SUCCEEDED, HOST_STATE_FAILED]
            ),
        )
        .order_by(PatchRollbackDispatchHost.id.asc())
        .all()
    )


def _packages_pending_verification(
    db: Session, host_id: int
) -> List[PatchRollbackDispatchHostPackage]:
    """Slice 4a: pending = ``verified_at IS NULL``.
    Previously this used ``installed_version_after IS NULL``, which
    collided with the legitimate "verified, package not installed"
    observation (also null). The new ``verified_at`` marker is
    the unambiguous "this row has been verified" sentinel."""
    return (
        db.query(PatchRollbackDispatchHostPackage)
        .filter(
            PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host_id,
            PatchRollbackDispatchHostPackage.verified_at.is_(None),
        )
        .order_by(PatchRollbackDispatchHostPackage.package_name.asc())
        .all()
    )


def _resolve_system(db: Session, system_id: Optional[int]) -> Optional[System]:
    if system_id is None:
        return None
    return db.query(System).filter(System.id == system_id).first()


def _resolve_probe(
    db: Session, override: Optional[RollbackPackageProbeCallable]
) -> RollbackPackageProbeCallable:
    if override is not None:
        return override

    def _impl(system: System, package_names: List[str]) -> RollbackPackageProbeResult:
        return default_rollback_package_probe(db, system, package_names)

    return _impl


def _emit_host_verified_audit(
    *,
    run: PatchRollbackDispatchRun,
    host_row: PatchRollbackDispatchHost,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Dict[str, Any],
) -> None:
    context: Dict[str, Any] = {
        "rollback_id": run.rollback_id,
        "rollback_dispatch_run_id": run.id,
        "rollback_dispatch_host_id": host_row.id,
        "rollback_host_id": host_row.rollback_host_id,
        "system_id": host_row.system_id_snapshot,
        "system_hostname": host_row.system_hostname_snapshot,
    }
    context.update(extra)
    safe_emit(
        action=AUDIT_ROLLBACK_HOST_VERIFIED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_rollback_dispatch_host",
        target_id=str(host_row.id),
        context=context,
    )


def _emit_verification_complete_audit(
    *,
    run: PatchRollbackDispatchRun,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    extra: Dict[str, Any],
) -> None:
    context: Dict[str, Any] = {
        "rollback_id": run.rollback_id,
        "rollback_dispatch_run_id": run.id,
    }
    context.update(extra)
    safe_emit(
        action=AUDIT_ROLLBACK_VERIFICATION_COMPLETE,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_rollback_dispatch_run",
        target_id=str(run.id),
        context=context,
    )


def _verification_is_complete(db: Session, run_id: int) -> bool:
    """A run is "fully verified" when every reachable host's
    package rows have an ``installed_version_after`` set OR the
    host's ``error_details`` records a verification refusal that
    the operator already saw. We treat both as "the verifier did
    its job"."""
    hosts = (
        db.query(PatchRollbackDispatchHost)
        .filter(
            PatchRollbackDispatchHost.rollback_dispatch_run_id == run_id,
            PatchRollbackDispatchHost.state.in_(
                [HOST_STATE_SUCCEEDED, HOST_STATE_FAILED]
            ),
        )
        .all()
    )
    if not hosts:
        return False
    for host in hosts:
        refusal = (host.error_details or {}).get("verification_refusal")
        if refusal is not None:
            continue
        pending = (
            db.query(PatchRollbackDispatchHostPackage.id)
            .filter(
                PatchRollbackDispatchHostPackage.rollback_dispatch_host_id == host.id,
                PatchRollbackDispatchHostPackage.verified_at.is_(None),
            )
            .first()
        )
        if pending is not None:
            return False
    return True


def _package_history_operation_for_host(host_state: str) -> str:
    if host_state == HOST_STATE_SUCCEEDED:
        return PACKAGE_HISTORY_OPERATION_ROLLBACK
    return PACKAGE_HISTORY_OPERATION_ROLLBACK_FAILED


def _record_package_history(
    db: Session,
    *,
    host_row: PatchRollbackDispatchHost,
    package_row: PatchRollbackDispatchHostPackage,
    observed_version: Optional[str],
    actor_user_id: int,
    now: datetime,
) -> bool:
    """Write one ``PackageHistory`` row for a verified package.

    Returns True when a row was written; False when the host has
    no matching ``Package`` row (we cannot satisfy the FK, so the
    history is silently skipped — the dispatch row already records
    the observation). Mirrors the
    ``operation='rollback'`` / ``operation='rollback_attempted_failed'``
    contract from the Slice 4 spec.

    ``old_version`` resolution:

    1. ``PatchRollbackDispatchHostPackage.installed_version_before``
       (the value the dispatcher observed pre-rollback) if set.
    2. The source feasibility package's
       ``installed_version_after_snapshot`` (the post-update value
       that the rollback was rolling *back from*). Slice 3 dispatch
       does not populate column #1, so this is the normal source.

    ``new_version`` is the verifier's observed post-rollback
    value. Both may be null in edge cases; the column is nullable.
    """
    if host_row.system_id_snapshot is None:
        return False
    package_id = (
        db.query(Package.id)
        .filter(
            Package.system_id == host_row.system_id_snapshot,
            Package.name == package_row.package_name,
        )
        .scalar()
    )
    if package_id is None:
        return False

    old_version: Optional[str] = package_row.installed_version_before
    if old_version is None and package_row.rollback_package_id is not None:
        old_version = (
            db.query(
                PatchUpdateExecutionRollbackPackage.installed_version_after_snapshot
            )
            .filter(
                PatchUpdateExecutionRollbackPackage.id
                == package_row.rollback_package_id
            )
            .scalar()
        )

    operation = _package_history_operation_for_host(host_row.state)
    db.add(
        PackageHistory(
            package_id=package_id,
            system_id=host_row.system_id_snapshot,
            operation=operation,
            old_version=old_version,
            new_version=observed_version,
            status=(
                "completed" if host_row.state == HOST_STATE_SUCCEEDED else "failed"
            ),
            error_message=(package_row.error_code or None),
            performed_at=now,
            performed_by=actor_user_id,
        )
    )
    db.flush()
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_due_rollbacks(
    db: Session,
    run_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    probe_callable: Optional[RollbackPackageProbeCallable] = None,
    now: Optional[datetime] = None,
) -> RollbackVerifyBatchSummary:
    """Verify one bounded batch of due rollback dispatch hosts.

    Walks dispatch hosts whose state is ``succeeded`` or
    ``failed`` and whose package rows still have
    ``installed_version_after IS NULL``. For each due host:

    1. Resolve the System ORM row from the snapshot id. Missing
       system → record ``verification_refusal`` of
       ``system_deleted`` and continue.
    2. Call the probe (default reads ``Package`` rows; tests
       inject a fake). Unreachable host → record refusal of
       ``transport_unavailable`` / ``transport_error``.
    3. For each pending package row: set
       ``installed_version_after`` to the observed value (which
       may be ``None`` — "host reports not installed"). Write
       one :class:`PackageHistory` row per package when the host
       has a matching ``Package`` row to FK against.
    4. Emit ``patch_rollback.host_verified`` per host.

    After processing the batch, if every dispatched host is now
    either verified or has a recorded refusal, emit
    ``patch_rollback.verification_complete`` once.

    Re-running the function on a fully-verified run is a no-op:
    pending-packages queries return empty, and the completion
    audit is suppressed by checking whether the run was already
    marked complete via the ``progress_summary``.
    """
    _require_user(db, actor_user_id)
    run = _require_run(db, run_id)
    current_now = now or datetime.utcnow()
    probe = _resolve_probe(db, probe_callable)
    summary = RollbackVerifyBatchSummary(rollback_dispatch_run_id=run.id)

    # Due hosts are those whose dispatch is terminal AND at least
    # one package row still lacks ``installed_version_after``. A
    # host with a prior recorded refusal IS re-tried on subsequent
    # batches so a transient transport outage doesn't permanently
    # disable verification — the verifier clears the refusal block
    # on a successful re-probe (see "Clear any prior refusal"
    # below).
    due_hosts = [
        h for h in _due_hosts(db, run.id) if _packages_pending_verification(db, h.id)
    ]
    if not due_hosts:
        # Either nothing was due, OR everything is already verified
        # / refused. Compute completion and emit if newly complete.
        summary.no_due = True
        complete = _verification_is_complete(db, run.id)
        summary.verification_complete = complete
        if complete and not (run.progress_summary or {}).get(
            "verification_complete_emitted"
        ):
            run.progress_summary = {
                **(run.progress_summary or {}),
                "verification_complete_emitted": True,
                "verification_complete_at": utc_iso(current_now),
            }
            db.commit()
            db.refresh(run)
            _emit_verification_complete_audit(
                run=run,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={"completed_at": utc_iso(current_now)},
            )
        return summary

    for host in due_hosts:
        summary.attempted_host_count += 1
        pending_packages = _packages_pending_verification(db, host.id)
        package_names = [p.package_name for p in pending_packages]
        system = _resolve_system(db, host.system_id_snapshot)

        if system is None:
            host.error_details = {
                **(host.error_details or {}),
                "verification_refusal": {
                    "reason": VERIFY_REASON_SYSTEM_DELETED,
                    "verified_at": utc_iso(current_now),
                },
            }
            db.flush()
            db.commit()
            summary.unreachable_host_count += 1
            summary.host_outcomes.append(
                {
                    "rollback_dispatch_host_id": host.id,
                    "system_id": host.system_id_snapshot,
                    "reachable": False,
                    "verified_package_count": 0,
                    "package_history_written_count": 0,
                    "reason": VERIFY_REASON_SYSTEM_DELETED,
                }
            )
            _emit_host_verified_audit(
                run=run,
                host_row=host,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={
                    "reachable": False,
                    "reason": VERIFY_REASON_SYSTEM_DELETED,
                },
            )
            continue

        try:
            probe_result = probe(system, package_names)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("rollback verify probe raised for host=%d: %s", host.id, exc)
            probe_result = RollbackPackageProbeResult(
                reachable=False,
                reason=VERIFY_REASON_TRANSPORT_ERROR,
                error=str(exc),
            )

        if not probe_result.reachable:
            host.error_details = {
                **(host.error_details or {}),
                "verification_refusal": {
                    "reason": probe_result.reason
                    or VERIFY_REASON_TRANSPORT_UNAVAILABLE,
                    "error": probe_result.error,
                    "verified_at": utc_iso(current_now),
                },
            }
            db.flush()
            db.commit()
            summary.unreachable_host_count += 1
            summary.host_outcomes.append(
                {
                    "rollback_dispatch_host_id": host.id,
                    "system_id": host.system_id_snapshot,
                    "reachable": False,
                    "verified_package_count": 0,
                    "package_history_written_count": 0,
                    "reason": probe_result.reason,
                }
            )
            _emit_host_verified_audit(
                run=run,
                host_row=host,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                extra={
                    "reachable": False,
                    "reason": probe_result.reason,
                    "error": probe_result.error,
                },
            )
            continue

        # Reachable: record observed versions and write PackageHistory.
        verified_count = 0
        history_count = 0
        for pkg in pending_packages:
            observed = probe_result.observed_versions.get(pkg.package_name)
            pkg.installed_version_after = observed
            # Slice 4a: explicit "this row has been
            # verified" marker. NULL means "not yet verified";
            # non-null means the verifier observed the host state at
            # this moment, and ``installed_version_after`` is
            # authoritative (including None = "host reports package
            # not installed").
            pkg.verified_at = current_now
            pkg.details = {
                **(pkg.details or {}),
                "verification": {
                    "observed_version": observed,
                    "verified_at": utc_iso(current_now),
                },
            }
            verified_count += 1
            if _record_package_history(
                db,
                host_row=host,
                package_row=pkg,
                observed_version=observed,
                actor_user_id=actor_user_id,
                now=current_now,
            ):
                history_count += 1
        # Clear any prior refusal so a transient probe failure
        # followed by a successful re-verify doesn't leave a stale
        # refusal block on the host.
        if (host.error_details or {}).get("verification_refusal") is not None:
            new_details = dict(host.error_details or {})
            new_details.pop("verification_refusal", None)
            host.error_details = new_details
        db.flush()
        db.commit()
        summary.reachable_host_count += 1
        summary.host_outcomes.append(
            {
                "rollback_dispatch_host_id": host.id,
                "system_id": host.system_id_snapshot,
                "reachable": True,
                "verified_package_count": verified_count,
                "package_history_written_count": history_count,
                "reason": None,
            }
        )
        _emit_host_verified_audit(
            run=run,
            host_row=host,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={
                "reachable": True,
                "verified_package_count": verified_count,
                "package_history_written_count": history_count,
            },
        )

    # Completion check after the batch.
    complete = _verification_is_complete(db, run.id)
    summary.verification_complete = complete
    if complete and not (run.progress_summary or {}).get(
        "verification_complete_emitted"
    ):
        run.progress_summary = {
            **(run.progress_summary or {}),
            "verification_complete_emitted": True,
            "verification_complete_at": utc_iso(current_now),
        }
        db.commit()
        db.refresh(run)
        _emit_verification_complete_audit(
            run=run,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            extra={"completed_at": utc_iso(current_now)},
        )

    return summary


def host_refusal_already_recorded(host: PatchRollbackDispatchHost) -> bool:
    """Helper exposed for the route layer + tests. True when a
    previous verification batch recorded a refusal for this host.
    Note: the verifier still re-probes such hosts on subsequent
    batches; this helper is purely a read-side convenience for
    callers that want to surface "we tried, last time we couldn't
    reach"."""
    return (host.error_details or {}).get("verification_refusal") is not None
