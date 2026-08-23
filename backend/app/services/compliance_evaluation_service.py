"""Compliance evaluation runner (PRA-165 Slice 2 + PRA-166 Slice 1).

PRA-165 Slice 2 made the Slice 1 substrate evaluable for the package
+ fact kinds. It reads existing ``HostFacts`` rows and the existing
``packages`` inventory only — it never refreshes facts or scans
packages itself.

PRA-166 Slice 1 layers in file/command probe execution through the
:mod:`compliance_probe_runner_service` module: ``file_exists``,
``file_sha256``, ``command_stdout_contains``, and
``command_exit_code`` now run against the target host via the
existing ``SSHService`` transport, with bounded read-only commands,
per-probe timeouts, and explicit transport / permission / timeout /
invalid-output error reasons. The evaluation module does not import
``ssh_service`` directly — the probe runner module is the seam —
so the long-standing "evaluation service does not surface probe-
runner symbols" boundary still holds.

Verdict vocabulary on each evidence row:

* ``pass``   — observed value matches the check's expectation.
* ``fail``   — observed value does not match.
* ``error``  — the runner could not evaluate (missing host facts row,
  unmapped fact key, malformed version, SSH transport failure, probe
  timeout, etc.). Each error verdict carries a stable
  ``verdict_reason`` so operators can fix the gap.

Unknown kinds remain explicitly deferred — calling the runner on an
unsupported kind records an ``error`` verdict with a stable reason
rather than attempting execution. The pre-PRA-166 deferred reason
(``runner_owner_deferred_pra166``) is preserved as a vocabulary
entry so historical evidence rows continue to read cleanly.

Scheduler integration:

* :func:`evaluate_due_policies` picks every enabled policy whose
  ``last_run_at`` is either NULL or older than
  ``schedule_interval_hours`` and runs it across all hosts.
* :func:`retain_evidence` enforces per-policy
  ``evidence_retention_days`` via bulk DELETE.

Audit events (all via ``safe_emit`` AFTER commit, no ``db=`` per
``feedback_safe_emit_session_boundary``):

* ``compliance_evaluation.run``       — once per ``evaluate_policy_*``
  call; carries policy_id + run_id + verdict counts.
* ``compliance_evidence.persisted``   — once per ``evaluate_policy_*``
  call (NOT once per row); carries the inserted count.
* ``compliance_evidence.retained``    — once per retention sweep; carries
  the pruned count and the cutoff timestamp.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import false
from sqlalchemy.orm import Session

from ..db.models import (
    CompliancePolicy,
    CompliancePolicyCheck,
    CompliancePolicyEvidence,
    HostFacts,
    Package,
    System,
)
from . import compliance_labels, compliance_probe_runner_service
from .audit_event_service import safe_emit
from .compliance_service import (
    RUNNER_OWNER_PRA166,
    RUNNER_OWNER_SLICE_2,
    ComplianceError,
    runner_owner_for_kind,
    utc_iso,
)
from .package_version_compare import (
    is_valid_version,
    scheme_for_package_family,
    version_at_least,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"
VALID_VERDICTS: Tuple[str, ...] = (VERDICT_PASS, VERDICT_FAIL, VERDICT_ERROR)


# Stable reason codes — recorded inside ``verdict_reason`` so operators
# can grep for them in evidence exports later.
REASON_NO_HOST_FACTS = "no_host_facts_row"
REASON_FACT_KEY_UNMAPPED = "fact_key_not_in_slice_2_schema"
REASON_FACT_VALUE_NULL = "fact_value_null"
REASON_PACKAGE_NOT_INSTALLED = "package_not_installed"
REASON_PACKAGE_INSTALLED = "package_installed"
REASON_VERSION_MISMATCH = "installed_version_below_min"
REASON_VERSION_UNPARSEABLE = "installed_version_unparseable"
REASON_MIN_VERSION_UNPARSEABLE = "min_version_unparseable"
REASON_UNSUPPORTED_PACKAGE_FAMILY = "unsupported_package_family"
REASON_DEFERRED_PRA166 = "runner_owner_deferred_pra166"


# Mapping from compliance fact_key (the operator-facing dotted name)
# to ``HostFacts`` column. Only keys here are evaluable; anything else
# returns a stable ``error`` verdict with ``REASON_FACT_KEY_UNMAPPED`` so a
# genuinely uncollected fact reads as ``coverage_pending`` (PRA-346) rather
# than masquerading as pass/fail. PRA-359 adds the SSH-config + kernel-sysctl
# keys the CIS starter pack needs, backed by real read-only host facts.
FACT_KEY_TO_HOSTFACTS_COLUMN: Dict[str, str] = {
    "host.cpu_cores": "cpu_cores",
    "host.cpu_model": "cpu_model",
    "host.ram_total_bytes": "ram_total_bytes",
    "host.kernel_version": "kernel_version",
    "host.distro_id": "distro_id_facts",
    "host.distro_release": "distro_release",
    "host.uptime_seconds": "uptime_seconds",
    "host.reboot_required": "reboot_required",
    "host.package_manager": "package_manager",
    "host.package_manager_version": "package_manager_version",
    "host.virtualization": "virtualization",
    "host.cloud_provider": "cloud_provider",
    # PRA-359: SSH server config + kernel sysctls.
    "ssh.config.PermitRootLogin": "ssh_permit_root_login",
    "ssh.config.PasswordAuthentication": "ssh_password_authentication",
    "sysctl.kernel.randomize_va_space": "sysctl_kernel_randomize_va_space",
    "sysctl.net.ipv4.ip_forward": "sysctl_net_ipv4_ip_forward",
    "sysctl.net.ipv4.conf.all.rp_filter": "sysctl_net_ipv4_conf_all_rp_filter",
}


AUDIT_COMPLIANCE_EVALUATION_RUN = "compliance_evaluation.run"
AUDIT_COMPLIANCE_EVIDENCE_PERSISTED = "compliance_evidence.persisted"
AUDIT_COMPLIANCE_EVIDENCE_RETAINED = "compliance_evidence.retained"


# Evidence-row ``runner_status`` vocabulary. Distinct from Slice 1's
# check-read ``runner_status`` (``runner_not_implemented_in_slice_1``)
# because an evidence row, by definition, came out of the runner —
# either from an actual evaluator (``runner_executed``) or from a
# legacy/PRA-165-era deferred row (``runner_deferred``).
#
# Post-PRA-166: all known kinds have implemented runners, so every
# **new** evidence row is ``runner_executed`` (including ``error``
# verdicts — the runner attempted to evaluate and recorded the
# failure). The ``runner_deferred`` bucket is preserved for two cases:
#
# * Unknown / unsupported kinds (defensive — write-time validation
#   should already reject these).
# * Historical evidence rows persisted by PRA-165 Slice 2 carrying
#   ``verdict_reason = REASON_DEFERRED_PRA166``. The export-row
#   helper inspects the stored reason so legacy rows continue to read
#   as ``runner_deferred`` after the PRA-166 runner ships.
RUNNER_STATUS_EXECUTED = "runner_executed"
RUNNER_STATUS_DEFERRED = "runner_deferred"


def runner_status_for_kind(kind: str) -> str:
    """Map a check ``kind`` to the evidence-row ``runner_status``
    bucket for **newly produced** rows. Historical rows that pre-date
    the kind's runner are corrected per-row inside
    :func:`evidence_export_row` so a re-export does not retroactively
    claim execution.
    """
    try:
        runner_owner_for_kind(kind)
    except ComplianceError:
        return RUNNER_STATUS_DEFERRED
    return RUNNER_STATUS_EXECUTED


# ---------------------------------------------------------------------------
# Per-verdict result container — fed to the persistence layer below
# ---------------------------------------------------------------------------


@dataclass
class CheckVerdict:
    verdict: str
    reason: Optional[str] = None
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None


def _pass(observed: Any = None, expected: Any = None) -> CheckVerdict:
    return CheckVerdict(
        verdict=VERDICT_PASS,
        observed_value=None if observed is None else str(observed),
        expected_value=None if expected is None else str(expected),
    )


def _fail(reason: str, observed: Any = None, expected: Any = None) -> CheckVerdict:
    return CheckVerdict(
        verdict=VERDICT_FAIL,
        reason=reason,
        observed_value=None if observed is None else str(observed),
        expected_value=None if expected is None else str(expected),
    )


def _error(reason: str, observed: Any = None, expected: Any = None) -> CheckVerdict:
    return CheckVerdict(
        verdict=VERDICT_ERROR,
        reason=reason,
        observed_value=None if observed is None else str(observed),
        expected_value=None if expected is None else str(expected),
    )


# ---------------------------------------------------------------------------
# Per-kind evaluators
# ---------------------------------------------------------------------------


def _evaluate_package_installed(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    package_name = definition["package"]
    row = (
        db.query(Package.id, Package.installed_version)
        .filter(Package.system_id == system_id, Package.name == package_name)
        .first()
    )
    if row is None:
        return _fail(
            REASON_PACKAGE_NOT_INSTALLED,
            observed="absent",
            expected=package_name,
        )
    return _pass(observed=row.installed_version, expected=package_name)


def _evaluate_package_absent(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    package_name = definition["package"]
    row = (
        db.query(Package.id, Package.installed_version)
        .filter(Package.system_id == system_id, Package.name == package_name)
        .first()
    )
    if row is None:
        return _pass(observed="absent", expected="absent")
    return _fail(
        REASON_PACKAGE_INSTALLED,
        observed=row.installed_version,
        expected="absent",
    )


def _evaluate_package_version_min(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    # Lazy import: the family resolver lives in the patch stack, and
    # importing it eagerly would drag that whole import graph into every
    # compliance evaluation.
    from .patch_update_plan_service import _derive_package_manager_family

    package_name = definition["package"]
    min_version = definition["min_version"]
    expected = f">= {min_version}"
    row = (
        db.query(Package.id, Package.installed_version, Package.package_type)
        .filter(Package.system_id == system_id, Package.name == package_name)
        .first()
    )
    if row is None:
        return _fail(
            REASON_PACKAGE_NOT_INSTALLED,
            observed="absent",
            expected=expected,
        )

    # Distro packages are ordered by their own grammar, not by PEP 440,
    # so the comparison semantics come from the host's package family.
    # Host facts are authoritative; the inventory row's own package_type
    # is the fallback, recorded by the collector that read this version
    # off the host. Neither infers anything from the version string.
    facts = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    scheme = scheme_for_package_family(_derive_package_manager_family(facts))
    if scheme is None:
        scheme = scheme_for_package_family(row.package_type)
    if scheme is None:
        return _error(
            REASON_UNSUPPORTED_PACKAGE_FAMILY,
            observed=row.installed_version,
            expected=expected,
        )

    if not is_valid_version(scheme, str(row.installed_version)):
        return _error(
            REASON_VERSION_UNPARSEABLE,
            observed=row.installed_version,
            expected=expected,
        )
    if not is_valid_version(scheme, str(min_version)):
        return _error(
            REASON_MIN_VERSION_UNPARSEABLE,
            observed=row.installed_version,
            expected=expected,
        )
    if version_at_least(scheme, str(row.installed_version), str(min_version)):
        return _pass(observed=row.installed_version, expected=expected)
    return _fail(
        REASON_VERSION_MISMATCH,
        observed=row.installed_version,
        expected=expected,
    )


def _get_facts_value(db: Session, system_id: int, fact_key: str) -> Tuple[bool, Any]:
    """Return ``(mapped, value)``. ``mapped`` is False when the
    operator-facing ``fact_key`` isn't bound to any HostFacts column
    yet. Caller decides verdict shape.
    """
    column = FACT_KEY_TO_HOSTFACTS_COLUMN.get(fact_key)
    if column is None:
        return False, None
    row = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    if row is None:
        # Mapped key, but no facts row yet for this host — explicit
        # error so the operator knows facts must be collected first.
        return True, None
    return True, getattr(row, column)


def _evaluate_fact_equals(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    fact_key = definition["fact_key"]
    expected = definition["expected"]
    mapped, value = _get_facts_value(db, system_id, fact_key)
    if not mapped:
        return _error(
            REASON_FACT_KEY_UNMAPPED,
            observed=None,
            expected=str(expected),
        )
    facts_row = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    if facts_row is None:
        return _error(REASON_NO_HOST_FACTS, expected=str(expected))
    if value is None:
        return _error(
            REASON_FACT_VALUE_NULL,
            observed=None,
            expected=str(expected),
        )
    if str(value) == str(expected):
        return _pass(observed=value, expected=expected)
    return _fail(reason=None, observed=value, expected=expected)


def _evaluate_fact_present(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    fact_key = definition["fact_key"]
    mapped, value = _get_facts_value(db, system_id, fact_key)
    if not mapped:
        return _error(REASON_FACT_KEY_UNMAPPED)
    facts_row = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    if facts_row is None:
        return _error(REASON_NO_HOST_FACTS)
    if value is None:
        return _fail(REASON_FACT_VALUE_NULL, observed=None, expected="present")
    return _pass(observed=value, expected="present")


def _evaluate_fact_absent(
    db: Session, system_id: int, definition: Dict[str, Any]
) -> CheckVerdict:
    fact_key = definition["fact_key"]
    mapped, value = _get_facts_value(db, system_id, fact_key)
    if not mapped:
        return _error(REASON_FACT_KEY_UNMAPPED)
    facts_row = db.query(HostFacts).filter(HostFacts.system_id == system_id).first()
    if facts_row is None:
        return _error(REASON_NO_HOST_FACTS)
    if value is None:
        return _pass(observed=None, expected="absent")
    return _fail(reason=None, observed=value, expected="absent")


_SLICE_2_RUNNERS = {
    "package_installed": _evaluate_package_installed,
    "package_absent": _evaluate_package_absent,
    "package_version_min": _evaluate_package_version_min,
    "fact_equals": _evaluate_fact_equals,
    "fact_present": _evaluate_fact_present,
    "fact_absent": _evaluate_fact_absent,
}


def _evaluate_check_against_host(
    db: Session, check: CompliancePolicyCheck, system_id: int
) -> CheckVerdict:
    """Dispatch a single check evaluation against a single host.

    * Package / fact kinds route to the in-process Slice 2 evaluators
      that read existing DB rows.
    * File / command kinds route to the PRA-166 probe runner module,
      which executes a bounded, read-only command on the host over
      SSH and maps its :class:`ProbeOutcome` back into a
      :class:`CheckVerdict`. Transport failures, timeouts, permission
      denials, etc. surface as ``error`` verdicts with stable reason
      codes — see ``compliance_probe_runner_service``.
    * Unknown kinds (which should never reach the runner because
      write-time validation rejects them) record a defensive error
      verdict instead of crashing the sweep.
    """
    try:
        owner = runner_owner_for_kind(check.kind)
    except ComplianceError:
        return _error(f"unknown_kind:{check.kind}")

    if owner == RUNNER_OWNER_PRA166:
        return _run_probe_kind(db, check, system_id)
    if owner != RUNNER_OWNER_SLICE_2:
        return _error(f"unknown_runner_owner:{owner}")

    runner = _SLICE_2_RUNNERS.get(check.kind)
    if runner is None:
        return _error(f"missing_runner_for_kind:{check.kind}")
    return runner(db, system_id, dict(check.definition_json or {}))


def _run_probe_kind(
    db: Session, check: CompliancePolicyCheck, system_id: int
) -> CheckVerdict:
    """Adapter that bridges :class:`ProbeOutcome` (PRA-166 probe
    runner's transport-neutral result type) into the local
    :class:`CheckVerdict` shape used by the persistence layer.

    Kept thin so the evaluation module owns the evidence-row contract
    and the probe-runner module owns SSH/shell semantics.
    """
    try:
        outcome = compliance_probe_runner_service.run_probe(
            db,
            kind=check.kind,
            system_id=system_id,
            definition=dict(check.definition_json or {}),
        )
    except compliance_probe_runner_service.UnsupportedProbeKind:
        return _error(f"unsupported_probe_kind:{check.kind}")
    return CheckVerdict(
        verdict=outcome.verdict,
        reason=outcome.reason,
        observed_value=outcome.observed_value,
        expected_value=outcome.expected_value,
    )


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _resolve_severity(policy: CompliancePolicy, check: CompliancePolicyCheck) -> str:
    return check.severity_override or policy.severity


def _persist_evidence_rows(
    db: Session,
    policy: CompliancePolicy,
    rows_to_insert: List[Dict[str, Any]],
) -> List[CompliancePolicyEvidence]:
    """Bulk-insert evidence rows + flush. Caller commits."""
    persisted: List[CompliancePolicyEvidence] = []
    for row in rows_to_insert:
        evidence = CompliancePolicyEvidence(**row)
        db.add(evidence)
        persisted.append(evidence)
    db.flush()
    return persisted


# ---------------------------------------------------------------------------
# Public API — single-host + per-policy + due sweep
# ---------------------------------------------------------------------------


@dataclass
class EvaluationSummary:
    """Aggregate result of an evaluation call.

    Returned by every entry point so callers (scheduler hook, future
    UI) can read per-policy verdict counts without re-querying. The
    persistence layer is what's authoritative — this summary is
    derived from the rows it just wrote.
    """

    policy_id: int
    policy_slug: str
    run_id: str
    evaluated_at: datetime
    counts: Dict[str, int]
    evidence_count: int


def _empty_counts() -> Dict[str, int]:
    return {VERDICT_PASS: 0, VERDICT_FAIL: 0, VERDICT_ERROR: 0}


def evaluate_policy_for_host(
    db: Session,
    *,
    policy_id: int,
    system_id: int,
    run_id: Optional[str] = None,
    now: Optional[datetime] = None,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> EvaluationSummary:
    """Evaluate every enabled check on ``policy_id`` against
    ``system_id``. Persists one evidence row per enabled check, emits
    ``compliance_evaluation.run`` + ``compliance_evidence.persisted``
    AFTER commit (no ``db=`` per the session-boundary pattern).

    Disabled checks are skipped — no evidence row, no audit row.
    """
    policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
    if policy is None:
        raise ComplianceError(f"compliance policy id={policy_id} not found")
    if not db.query(System.id).filter(System.id == system_id).first():
        raise ComplianceError(f"system id={system_id} not found")

    run_id = run_id or str(uuid.uuid4())
    evaluated_at = now or datetime.utcnow()
    counts = _empty_counts()
    rows_to_insert: List[Dict[str, Any]] = []

    enabled_checks = (
        db.query(CompliancePolicyCheck)
        .filter(
            CompliancePolicyCheck.policy_id == policy.id,
            CompliancePolicyCheck.enabled.is_(True),
        )
        .order_by(
            CompliancePolicyCheck.display_order.asc(),
            CompliancePolicyCheck.slug.asc(),
        )
        .all()
    )

    for check in enabled_checks:
        verdict = _evaluate_check_against_host(db, check, system_id)
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
        rows_to_insert.append(
            {
                "policy_id": policy.id,
                "check_id": check.id,
                "system_id": system_id,
                "policy_slug": policy.slug,
                "policy_version": policy.version,
                "check_slug": check.slug,
                "check_kind": check.kind,
                "verdict": verdict.verdict,
                "verdict_reason": (verdict.reason[:512] if verdict.reason else None),
                "observed_value": verdict.observed_value,
                "expected_value": verdict.expected_value,
                "severity": _resolve_severity(policy, check),
                "evaluation_run_id": run_id,
                "evaluated_at": evaluated_at,
            }
        )

    persisted = _persist_evidence_rows(db, policy, rows_to_insert)
    db.commit()

    safe_emit(
        action=AUDIT_COMPLIANCE_EVALUATION_RUN,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        target_system_id=system_id,
        context={
            "policy_slug": policy.slug,
            "policy_version": policy.version,
            "system_id": system_id,
            "run_id": run_id,
            "counts": counts,
            "scope": "per_host",
        },
    )
    safe_emit(
        action=AUDIT_COMPLIANCE_EVIDENCE_PERSISTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        target_system_id=system_id,
        context={
            "policy_slug": policy.slug,
            "run_id": run_id,
            "evidence_count": len(persisted),
            "scope": "per_host",
        },
    )
    # PRA-178 Slice 3: emit compliance.evaluated notification. Pick the
    # dominant verdict for this per-host evaluation so the operator
    # sees one notification per (policy, host) probe rather than one
    # per check (the audit row carries per-check detail already).
    from . import notification_events

    if counts.get("fail", 0) > 0:
        dominant_verdict = "fail"
    elif counts.get("error", 0) > 0:
        dominant_verdict = "error"
    else:
        dominant_verdict = "pass"
    notification_events.emit_compliance_evaluated(
        db,
        policy_id=policy.id,
        policy_slug=policy.slug,
        system_id=system_id,
        verdict=dominant_verdict,
    )
    return EvaluationSummary(
        policy_id=policy.id,
        policy_slug=policy.slug,
        run_id=run_id,
        evaluated_at=evaluated_at,
        counts=counts,
        evidence_count=len(persisted),
    )


def evaluate_policy_for_fleet(
    db: Session,
    *,
    policy_id: int,
    now: Optional[datetime] = None,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> EvaluationSummary:
    """Evaluate ``policy_id`` against every existing system row.

    Per-host evidence rows are written; a single ``run_id`` covers
    the entire sweep so an auditor can group "what did this run
    produce". Updates ``policy.last_run_at`` so the scheduler knows
    the policy was just evaluated.
    """
    policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
    if policy is None:
        raise ComplianceError(f"compliance policy id={policy_id} not found")

    run_id = str(uuid.uuid4())
    evaluated_at = now or datetime.utcnow()
    counts = _empty_counts()
    total_persisted = 0

    enabled_checks = (
        db.query(CompliancePolicyCheck)
        .filter(
            CompliancePolicyCheck.policy_id == policy.id,
            CompliancePolicyCheck.enabled.is_(True),
        )
        .order_by(
            CompliancePolicyCheck.display_order.asc(),
            CompliancePolicyCheck.slug.asc(),
        )
        .all()
    )
    systems = db.query(System.id).all()

    rows_to_insert: List[Dict[str, Any]] = []
    for (system_id,) in systems:
        for check in enabled_checks:
            verdict = _evaluate_check_against_host(db, check, system_id)
            counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
            rows_to_insert.append(
                {
                    "policy_id": policy.id,
                    "check_id": check.id,
                    "system_id": system_id,
                    "policy_slug": policy.slug,
                    "policy_version": policy.version,
                    "check_slug": check.slug,
                    "check_kind": check.kind,
                    "verdict": verdict.verdict,
                    "verdict_reason": (
                        verdict.reason[:512] if verdict.reason else None
                    ),
                    "observed_value": verdict.observed_value,
                    "expected_value": verdict.expected_value,
                    "severity": _resolve_severity(policy, check),
                    "evaluation_run_id": run_id,
                    "evaluated_at": evaluated_at,
                }
            )

    persisted = _persist_evidence_rows(db, policy, rows_to_insert)
    total_persisted = len(persisted)

    # Stamp the policy's last run AFTER its evidence is durable. PRA-312: record
    # the success outcome alongside so the operator UI can distinguish a clean run
    # from a failed one (last_run_at only ever advances on success).
    policy.last_run_at = evaluated_at
    policy.last_run_status = "success"
    db.commit()

    safe_emit(
        action=AUDIT_COMPLIANCE_EVALUATION_RUN,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "policy_version": policy.version,
            "host_count": len(systems),
            "run_id": run_id,
            "counts": counts,
            "scope": "per_fleet",
        },
        related_system_ids=[s.id for s in systems],
    )
    safe_emit(
        action=AUDIT_COMPLIANCE_EVIDENCE_PERSISTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "run_id": run_id,
            "evidence_count": total_persisted,
            "scope": "per_fleet",
        },
        related_system_ids=[s.id for s in systems],
    )
    return EvaluationSummary(
        policy_id=policy.id,
        policy_slug=policy.slug,
        run_id=run_id,
        evaluated_at=evaluated_at,
        counts=counts,
        evidence_count=total_persisted,
    )


def list_due_policies(
    db: Session, *, now: Optional[datetime] = None
) -> List[CompliancePolicy]:
    """Return enabled policies whose ``last_run_at`` is NULL or older
    than ``schedule_interval_hours``. The scheduler hook iterates this
    list and calls :func:`evaluate_policy_for_fleet` on each.

    Disabled policies are skipped — runtime contract matches the
    Slice 1 lock that the runner must never act on disabled rows.
    """
    now = now or datetime.utcnow()
    enabled = (
        db.query(CompliancePolicy).filter(CompliancePolicy.enabled.is_(True)).all()
    )
    due: List[CompliancePolicy] = []
    for policy in enabled:
        if policy.last_run_at is None:
            due.append(policy)
            continue
        due_at = policy.last_run_at + timedelta(hours=policy.schedule_interval_hours)
        if now >= due_at:
            due.append(policy)
    return due


def evaluate_due_policies(
    db: Session, *, now: Optional[datetime] = None
) -> Dict[int, EvaluationSummary]:
    """Sweep entry point. Runs every enabled, due policy across the
    fleet and returns a per-policy summary keyed by policy id.

    A single failed-to-evaluate policy is logged and skipped — the
    sweep keeps moving so one bad row doesn't starve the rest.
    """
    summaries: Dict[int, EvaluationSummary] = {}
    for policy in list_due_policies(db, now=now):
        try:
            summaries[policy.id] = evaluate_policy_for_fleet(
                db, policy_id=policy.id, now=now
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "compliance evaluation: policy %d (%s) failed: %s",
                policy.id,
                policy.slug,
                exc,
            )
            # PRA-312: record the failed outcome so it's visible in the UI, WITHOUT
            # advancing last_run_at — the policy stays due and retries next sweep.
            _mark_policy_error(db, policy.id)
    return summaries


def _mark_policy_error(db: Session, policy_id: int) -> None:
    """Flag a policy's most-recent-run outcome as 'error' on a clean session
    handle (the evaluation may have left the session mid-transaction)."""
    try:
        db.rollback()
        policy = (
            db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
        )
        if policy is not None:
            policy.last_run_status = "error"
            db.commit()
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("failed to record error status for policy %d: %s", policy_id, exc)
        db.rollback()


def run_policy_now(
    db: Session,
    *,
    policy_id: int,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    now: Optional[datetime] = None,
) -> EvaluationSummary:
    """PRA-312: operator-triggered immediate evaluation of one policy.

    Same evaluation path as the scheduler sweep (existing facts + inventory, no live
    SSH), so it is fast and does not wait for the 15-minute tick or the policy's
    schedule interval. Refuses a disabled policy (the sweep never runs disabled rows,
    so running one on demand would be surprising). Records the error outcome on
    failure without advancing last_run_at.
    """
    policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
    if policy is None:
        raise ComplianceError(f"compliance policy id={policy_id} not found")
    if not policy.enabled:
        raise ComplianceError("policy is disabled; enable it before running")
    try:
        return evaluate_policy_for_fleet(
            db,
            policy_id=policy_id,
            now=now,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
        )
    except Exception:
        _mark_policy_error(db, policy_id)
        raise


def retain_evidence(
    db: Session,
    *,
    now: Optional[datetime] = None,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> Dict[int, int]:
    """Per-policy retention sweep.

    Each policy declares ``evidence_retention_days``. This function
    bulk-deletes evidence rows older than ``now - retention_days``
    and emits one ``compliance_evidence.retained`` event per policy
    that actually pruned anything.

    Returns ``{policy_id: deleted_count}`` for policies that pruned.
    Policies with zero prunings are silent (no audit row).
    """
    now = now or datetime.utcnow()
    pruned: Dict[int, int] = {}
    pruned_meta: List[Tuple[CompliancePolicy, int, datetime]] = []

    policies = db.query(CompliancePolicy).all()
    for policy in policies:
        cutoff = now - timedelta(days=policy.evidence_retention_days)
        deleted = (
            db.query(CompliancePolicyEvidence)
            .filter(
                CompliancePolicyEvidence.policy_id == policy.id,
                CompliancePolicyEvidence.evaluated_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        if deleted:
            pruned[policy.id] = deleted
            pruned_meta.append((policy, deleted, cutoff))
    db.commit()

    for policy, deleted, cutoff in pruned_meta:
        safe_emit(
            action=AUDIT_COMPLIANCE_EVIDENCE_RETAINED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="compliance_policy",
            target_id=str(policy.id),
            context={
                "policy_slug": policy.slug,
                "retention_days": policy.evidence_retention_days,
                "cutoff_at": cutoff.isoformat() + "Z",
                "deleted_count": deleted,
            },
        )
    return pruned


# ---------------------------------------------------------------------------
# Read helpers — kept thin (Slice 3 owns the dashboard/export read models).
# ---------------------------------------------------------------------------


def list_recent_evidence_for_host(
    db: Session,
    *,
    system_id: int,
    limit: int = 100,
) -> List[CompliancePolicyEvidence]:
    """Return the most recent evidence rows for one host, newest first.
    Used by the per-host detail surface in Slice 3.
    """
    if not (1 <= limit <= 1000):
        raise ComplianceError("limit must be in 1..1000")
    return (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.system_id == system_id)
        .order_by(CompliancePolicyEvidence.evaluated_at.desc())
        .limit(limit)
        .all()
    )


def list_recent_evidence_for_policy(
    db: Session,
    *,
    policy_id: int,
    limit: int = 100,
) -> List[CompliancePolicyEvidence]:
    """Return the most recent evidence rows for one policy, newest first."""
    if not (1 <= limit <= 1000):
        raise ComplianceError("limit must be in 1..1000")
    return (
        db.query(CompliancePolicyEvidence)
        .filter(CompliancePolicyEvidence.policy_id == policy_id)
        .order_by(CompliancePolicyEvidence.evaluated_at.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Slice 3 — paginated evidence list, per-policy/fleet summaries, streaming
# JSONL/CSV export generators, and the export-audit emit helper.
#
# Read helpers stay in this module (alongside the evaluation runner) so the
# Slice 1 / Slice 2 / Slice 3 boundary lives at the route layer; the
# service layer is one cohesive compliance surface.
# ---------------------------------------------------------------------------


# Maximum rows returnable by the paginated list endpoints. Mirrors the
# Slice 1 list-policies limit so operators don't have to remember a
# different cap per surface.
EVIDENCE_PAGE_MAX = 500

# Default page size when the route doesn't override.
EVIDENCE_PAGE_DEFAULT = 100

# Hard ceiling for the export windows. Operators can still page through
# longer ranges by chunking calls; this guard exists so a 1-hour misclick
# doesn't dump 6M rows into a single response. Mirrors the storage-growth
# math captured in the Slice 2 risks section.
EXPORT_WINDOW_MAX_DAYS = 366

# yield_per chunk for the streaming export queries. Tuned to balance
# memory footprint against round-trip overhead; matches the patch-
# lifecycle export pattern.
EXPORT_STREAM_CHUNK = 500

# Stale flag rule, exposed on the fleet summary. A policy is stale
# when its last_run_at is null OR older than twice its configured
# schedule interval. Documented on the route + schema so consumers
# don't have to re-derive the threshold.
STALE_INTERVAL_FACTOR = 2


AUDIT_COMPLIANCE_EXPORT_REQUESTED = "compliance_export.requested"


def evidence_scope_clause(allowed_system_ids: Optional[Set[int]]):
    """PRA-281: WHERE expression restricting evidence to the caller's fleet
    scope, or ``None`` for tenant-wide (admin). ``allowed_system_ids`` is the
    set returned by ``scoped_system_ids``: ``None`` = admin (no restriction);
    empty set = access to nothing (always-false, so counts/rows are zero); a
    non-empty set = ``system_id IN (...)``.
    """
    if allowed_system_ids is None:
        return None
    if not allowed_system_ids:
        return false()
    return CompliancePolicyEvidence.system_id.in_(allowed_system_ids)


def _evidence_filter_clauses(
    *,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    verdict: Optional[str] = None,
    evaluated_after: Optional[datetime] = None,
    evaluated_before: Optional[datetime] = None,
    allowed_system_ids: Optional[Set[int]] = None,
):
    """Build the WHERE-clause list shared by list + export queries.

    Returns a list of SQLAlchemy expressions; the query builder ANDs
    them. Verdict is normalized + range-checked here so route layers
    can pass user input directly without sanitizing twice.

    ``allowed_system_ids`` (PRA-281) is an ADDITIONAL fleet-scope restriction,
    independent of the scalar ``system_id`` user filter.
    """
    clauses = []
    if policy_id is not None:
        clauses.append(CompliancePolicyEvidence.policy_id == policy_id)
    if system_id is not None:
        clauses.append(CompliancePolicyEvidence.system_id == system_id)
    if verdict is not None:
        if verdict not in VALID_VERDICTS:
            raise ComplianceError(f"verdict must be one of: {list(VALID_VERDICTS)}")
        clauses.append(CompliancePolicyEvidence.verdict == verdict)
    if evaluated_after is not None:
        clauses.append(CompliancePolicyEvidence.evaluated_at >= evaluated_after)
    if evaluated_before is not None:
        clauses.append(CompliancePolicyEvidence.evaluated_at < evaluated_before)
    scope_clause = evidence_scope_clause(allowed_system_ids)
    if scope_clause is not None:
        clauses.append(scope_clause)
    return clauses


def list_evidence_paginated(
    db: Session,
    *,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    verdict: Optional[str] = None,
    evaluated_after: Optional[datetime] = None,
    evaluated_before: Optional[datetime] = None,
    offset: int = 0,
    limit: int = EVIDENCE_PAGE_DEFAULT,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Tuple[List[CompliancePolicyEvidence], int]:
    """Paginated evidence query.

    Either ``policy_id`` or ``system_id`` is typically supplied via the
    route, but the helper itself doesn't require either — that lets
    tests assert the unfiltered total cleanly.

    ``allowed_system_ids`` (PRA-281) restricts rows AND the total to the
    caller's fleet scope (``None`` = admin/tenant-wide; empty = nothing).

    Returns ``(rows, total_matching_filter)``. Rows are newest-first
    so paged consumers see "most recent" without re-sorting.
    """
    if offset < 0:
        raise ComplianceError("offset must be >= 0")
    if not (1 <= limit <= EVIDENCE_PAGE_MAX):
        raise ComplianceError(f"limit must be in 1..{EVIDENCE_PAGE_MAX}")

    clauses = _evidence_filter_clauses(
        policy_id=policy_id,
        system_id=system_id,
        verdict=verdict,
        evaluated_after=evaluated_after,
        evaluated_before=evaluated_before,
        allowed_system_ids=allowed_system_ids,
    )
    base = db.query(CompliancePolicyEvidence)
    for c in clauses:
        base = base.filter(c)
    total = base.with_entities(CompliancePolicyEvidence.id).count()
    rows = (
        base.order_by(
            CompliancePolicyEvidence.evaluated_at.desc(),
            CompliancePolicyEvidence.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def _hostname_map(db: Session, system_ids: List[int]) -> Dict[int, str]:
    """Bulk ``system_id -> hostname`` for per-host summary display (PRA-312 follow-up).

    A missing id (evidence outlives a decommissioned host) simply isn't in the map, so
    the caller renders ``None`` and the UI falls back to the id. One bounded query.
    """
    if not system_ids:
        return {}
    return {
        int(sid): hostname
        for sid, hostname in db.query(System.id, System.hostname)
        .filter(System.id.in_(system_ids))
        .all()
    }


def policy_summary(
    db: Session,
    *,
    policy_id: int,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """Per-policy rollup over the latest evaluation run.

    Returns a dict shaped for ``CompliancePolicySummary``. When the
    policy has never been evaluated, per_check / per_host are empty
    lists and ``latest_run_*`` keys are None — this is a normal
    no-data state, not an error.

    ``allowed_system_ids`` (PRA-281) scopes every per-check / per-host / total
    aggregate to the caller's fleet scope (``None`` = admin; empty = all-zero).
    """
    policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
    if policy is None:
        raise ComplianceError(f"compliance policy id={policy_id} not found")

    # Use ``policy.last_run_at`` as the anchor: the fleet sweep stamps
    # this to the evaluation timestamp of the run that produced the
    # rows we want to summarize. This avoids a redundant scan to
    # rediscover the latest evaluated_at via MAX().
    latest_at = policy.last_run_at
    if latest_at is None:
        return {
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "severity": policy.severity,
            "enabled": policy.enabled,
            "schedule_interval_hours": policy.schedule_interval_hours,
            "latest_run_id": None,
            "latest_run_at": None,
            "pass_count": 0,
            "fail_count": 0,
            "error_count": 0,
            "per_check": [],
            "per_host": [],
        }

    from sqlalchemy import case, func

    latest_filter = (CompliancePolicyEvidence.policy_id == policy.id) & (
        CompliancePolicyEvidence.evaluated_at == latest_at
    )
    # PRA-281: restrict every aggregate below to the caller's fleet scope.
    scope_clause = evidence_scope_clause(allowed_system_ids)
    if scope_clause is not None:
        latest_filter = latest_filter & scope_clause

    # One row per (check_slug, check_kind) — denormalized identity on
    # the evidence row lets us group without joining back to the
    # potentially-edited check table.
    per_check_rows = (
        db.query(
            CompliancePolicyEvidence.check_id,
            CompliancePolicyEvidence.check_slug,
            CompliancePolicyEvidence.check_kind,
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_PASS, 1))),
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_FAIL, 1))),
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_ERROR, 1))),
        )
        .filter(latest_filter)
        .group_by(
            CompliancePolicyEvidence.check_id,
            CompliancePolicyEvidence.check_slug,
            CompliancePolicyEvidence.check_kind,
        )
        .order_by(CompliancePolicyEvidence.check_slug.asc())
        .all()
    )
    per_check = []
    for check_id, check_slug, check_kind, p, f, e in per_check_rows:
        try:
            owner = runner_owner_for_kind(check_kind)
        except ComplianceError:
            owner = "unknown"
        per_check.append(
            {
                "check_id": check_id,
                "check_slug": check_slug,
                "check_kind": check_kind,
                "runner_owner": owner,
                "runner_label": compliance_labels.runner_label(owner),
                "pass_count": int(p),
                "fail_count": int(f),
                "error_count": int(e),
            }
        )

    per_host_rows = (
        db.query(
            CompliancePolicyEvidence.system_id,
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_PASS, 1))),
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_FAIL, 1))),
            func.count(case((CompliancePolicyEvidence.verdict == VERDICT_ERROR, 1))),
        )
        .filter(latest_filter)
        .group_by(CompliancePolicyEvidence.system_id)
        .order_by(CompliancePolicyEvidence.system_id.asc())
        .all()
    )
    _hostnames = _hostname_map(db, [int(r[0]) for r in per_host_rows])
    per_host = [
        {
            "system_id": int(system_id),
            "hostname": _hostnames.get(int(system_id)),
            "pass_count": int(p),
            "fail_count": int(f),
            "error_count": int(e),
        }
        for system_id, p, f, e in per_host_rows
    ]

    # Single-row tally (sum of per-check counts; cheaper than a third query).
    pass_total = sum(c["pass_count"] for c in per_check)
    fail_total = sum(c["fail_count"] for c in per_check)
    error_total = sum(c["error_count"] for c in per_check)

    latest_run_id = (
        db.query(CompliancePolicyEvidence.evaluation_run_id)
        .filter(latest_filter)
        .limit(1)
        .scalar()
    )

    return {
        "policy_id": policy.id,
        "policy_slug": policy.slug,
        "severity": policy.severity,
        "enabled": policy.enabled,
        "schedule_interval_hours": policy.schedule_interval_hours,
        "latest_run_id": latest_run_id,
        "latest_run_at": utc_iso(latest_at),
        "pass_count": pass_total,
        "fail_count": fail_total,
        "error_count": error_total,
        "per_check": per_check,
        "per_host": per_host,
    }


def fleet_summary(
    db: Session,
    *,
    now: Optional[datetime] = None,
    allowed_system_ids: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """Fleet-wide rollup over each policy's latest evaluation run.

    Stale = last_run_at is null OR older than ``STALE_INTERVAL_FACTOR
    * schedule_interval_hours``. The fleet summary surface documents
    this so operators don't re-derive the threshold from the schema.

    ``allowed_system_ids`` (PRA-281) scopes every per-policy / per-severity /
    per-host / total aggregate to the caller's fleet scope (``None`` = admin;
    empty = all-zero counts and ``host_count`` 0). The policy roster
    (``policy_count`` / ``enabled_policy_count`` and the per_policy rows) stays
    global — policy definitions are tenant-wide taxonomy, not host data — but
    every count on those rows is scoped.
    """
    from sqlalchemy import case, func

    now = now or datetime.utcnow()

    policies: List[CompliancePolicy] = db.query(CompliancePolicy).all()
    policy_index = {p.id: p for p in policies}
    enabled_policy_count = sum(1 for p in policies if p.enabled)

    # Latest evaluated_at per policy — anchors the rest of the
    # aggregates. Single bounded query; no Python-side full-table scan.
    latest_per_policy = dict(
        db.query(
            CompliancePolicyEvidence.policy_id,
            func.max(CompliancePolicyEvidence.evaluated_at),
        )
        .group_by(CompliancePolicyEvidence.policy_id)
        .all()
    )

    # Build a single set of OR-clauses so the per-axis aggregates all
    # see the same "latest run per policy" universe.
    from sqlalchemy import and_, or_

    latest_run_clauses = [
        and_(
            CompliancePolicyEvidence.policy_id == policy_id,
            CompliancePolicyEvidence.evaluated_at == latest_at,
        )
        for policy_id, latest_at in latest_per_policy.items()
    ]
    if not latest_run_clauses:
        # No evaluations recorded yet — return empty rollups but still
        # show the policy roster so operators know what's stale.
        per_policy = []
        for p in policies:
            per_policy.append(
                {
                    "policy_id": p.id,
                    "policy_slug": p.slug,
                    "severity": p.severity,
                    "enabled": p.enabled,
                    "schedule_interval_hours": p.schedule_interval_hours,
                    "last_run_at": None,
                    "next_run_at": None,
                    "last_run_status": p.last_run_status,
                    "never_run": p.last_run_at is None,
                    "stale": True,
                    "pass_count": 0,
                    "fail_count": 0,
                    "error_count": 0,
                }
            )
        return {
            "generated_at": utc_iso(now),
            "policy_count": len(policies),
            "enabled_policy_count": enabled_policy_count,
            "host_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "error_count": 0,
            "per_policy": per_policy,
            "per_severity": [],
            "per_host": [],
        }

    latest_filter = or_(*latest_run_clauses)
    # PRA-281: restrict every per-axis aggregate below to the caller's scope.
    scope_clause = evidence_scope_clause(allowed_system_ids)
    if scope_clause is not None:
        latest_filter = and_(latest_filter, scope_clause)

    pass_case = case((CompliancePolicyEvidence.verdict == VERDICT_PASS, 1))
    fail_case = case((CompliancePolicyEvidence.verdict == VERDICT_FAIL, 1))
    error_case = case((CompliancePolicyEvidence.verdict == VERDICT_ERROR, 1))

    per_policy_rows = (
        db.query(
            CompliancePolicyEvidence.policy_id,
            func.count(pass_case),
            func.count(fail_case),
            func.count(error_case),
        )
        .filter(latest_filter)
        .group_by(CompliancePolicyEvidence.policy_id)
        .all()
    )
    per_policy_counts = {pid: (p, f, e) for pid, p, f, e in per_policy_rows}

    per_severity_rows = (
        db.query(
            CompliancePolicyEvidence.severity,
            func.count(pass_case),
            func.count(fail_case),
            func.count(error_case),
        )
        .filter(latest_filter)
        .group_by(CompliancePolicyEvidence.severity)
        .order_by(CompliancePolicyEvidence.severity.asc())
        .all()
    )
    per_severity = [
        {
            "severity": severity,
            "pass_count": int(p),
            "fail_count": int(f),
            "error_count": int(e),
        }
        for severity, p, f, e in per_severity_rows
    ]

    per_host_rows = (
        db.query(
            CompliancePolicyEvidence.system_id,
            func.count(pass_case),
            func.count(fail_case),
            func.count(error_case),
        )
        .filter(latest_filter)
        .group_by(CompliancePolicyEvidence.system_id)
        .order_by(CompliancePolicyEvidence.system_id.asc())
        .all()
    )
    _hostnames = _hostname_map(db, [int(r[0]) for r in per_host_rows])
    per_host = [
        {
            "system_id": int(system_id),
            "hostname": _hostnames.get(int(system_id)),
            "pass_count": int(p),
            "fail_count": int(f),
            "error_count": int(e),
        }
        for system_id, p, f, e in per_host_rows
    ]

    per_policy = []
    pass_total = 0
    fail_total = 0
    error_total = 0
    for policy in sorted(policies, key=lambda x: x.slug):
        p, f, e = per_policy_counts.get(policy.id, (0, 0, 0))
        pass_total += int(p)
        fail_total += int(f)
        error_total += int(e)
        stale = _policy_is_stale(policy, now)
        per_policy.append(
            {
                "policy_id": policy.id,
                "policy_slug": policy.slug,
                "severity": policy.severity,
                "enabled": policy.enabled,
                "schedule_interval_hours": policy.schedule_interval_hours,
                "last_run_at": utc_iso(policy.last_run_at),
                "next_run_at": (
                    utc_iso(
                        policy.last_run_at
                        + timedelta(hours=policy.schedule_interval_hours)
                    )
                    if policy.last_run_at
                    else None
                ),
                "last_run_status": policy.last_run_status,
                "never_run": policy.last_run_at is None,
                "stale": stale,
                "pass_count": int(p),
                "fail_count": int(f),
                "error_count": int(e),
            }
        )

    return {
        "generated_at": utc_iso(now),
        "policy_count": len(policies),
        "enabled_policy_count": enabled_policy_count,
        "host_count": len(per_host),
        "pass_count": pass_total,
        "fail_count": fail_total,
        "error_count": error_total,
        "per_policy": per_policy,
        "per_severity": per_severity,
        "per_host": per_host,
    }


def _policy_is_stale(policy: CompliancePolicy, now: datetime) -> bool:
    if policy.last_run_at is None:
        return True
    threshold = timedelta(hours=policy.schedule_interval_hours * STALE_INTERVAL_FACTOR)
    return (now - policy.last_run_at) > threshold


def evidence_export_row(
    evidence: CompliancePolicyEvidence,
) -> Dict[str, Any]:
    """Stable wire-shape used by both JSONL and CSV exports plus the
    paginated evidence read endpoints.

    ``runner_owner`` is recomputed from the denormalized ``check_kind``
    on the row, not stored — that string survives the FK SET NULL on
    check delete.

    ``runner_status`` is derived per-row: legacy PRA-165 evidence rows
    that carry the stable ``REASON_DEFERRED_PRA166`` reason continue
    to read as ``runner_deferred`` so a re-export of pre-PRA-166
    history does not retroactively claim execution. Every other known
    kind reads as ``runner_executed`` (PRA-166's probe runner records
    both success and failure paths as actual runs).
    """
    try:
        owner = runner_owner_for_kind(evidence.check_kind)
    except ComplianceError:
        owner = "unknown"
    if evidence.verdict_reason == REASON_DEFERRED_PRA166:
        runner_status = RUNNER_STATUS_DEFERRED
    else:
        runner_status = runner_status_for_kind(evidence.check_kind)
    return {
        "id": evidence.id,
        "policy_id": evidence.policy_id,
        "check_id": evidence.check_id,
        "system_id": evidence.system_id,
        "policy_slug": evidence.policy_slug,
        "policy_version": evidence.policy_version,
        "check_slug": evidence.check_slug,
        "check_kind": evidence.check_kind,
        "verdict": evidence.verdict,
        "verdict_reason": evidence.verdict_reason,
        "observed_value": evidence.observed_value,
        "expected_value": evidence.expected_value,
        "severity": evidence.severity,
        "runner_owner": owner,
        "runner_status": runner_status,
        # PRA-346: product-facing siblings. The raw enums above stay stable
        # (pinned auditor/export contract); these humanized fields are what
        # operator UI renders. ``status`` splits the single ``error`` verdict
        # into distinguishable, actionable states.
        "status": compliance_labels.evidence_status(
            evidence.verdict, evidence.verdict_reason
        ),
        "status_label": compliance_labels.status_label_for(
            evidence.verdict, evidence.verdict_reason
        ),
        "verdict_reason_label": compliance_labels.verdict_reason_label(
            evidence.verdict_reason
        ),
        "runner_label": compliance_labels.runner_label(owner),
        "evaluation_run_id": evidence.evaluation_run_id,
        "evaluated_at": utc_iso(evidence.evaluated_at),
        "created_at": utc_iso(evidence.created_at),
        "updated_at": utc_iso(evidence.updated_at),
    }


# Stable column order for the CSV export. Documented here so external
# auditor scripts can pin against it. ``runner_status`` sits next to
# ``runner_owner`` so both deferral markers land in adjacent columns. PRA-346
# appends the humanized ``status`` / ``verdict_reason_label`` / ``runner_label``
# columns AFTER the stable set so existing column positions are unchanged.
EXPORT_CSV_COLUMNS: Tuple[str, ...] = (
    "id",
    "policy_id",
    "check_id",
    "system_id",
    "policy_slug",
    "policy_version",
    "check_slug",
    "check_kind",
    "verdict",
    "verdict_reason",
    "observed_value",
    "expected_value",
    "severity",
    "runner_owner",
    "runner_status",
    "evaluation_run_id",
    "evaluated_at",
    "created_at",
    "updated_at",
    "status",
    "status_label",
    "verdict_reason_label",
    "runner_label",
)


def iter_evidence_for_export(
    db: Session,
    *,
    evaluated_after: datetime,
    evaluated_before: datetime,
    policy_id: Optional[int] = None,
    system_id: Optional[int] = None,
    verdict: Optional[str] = None,
    allowed_system_ids: Optional[Set[int]] = None,
):
    """Yield evidence rows in chunks suitable for streaming exports.

    ``allowed_system_ids`` (PRA-281) is the caller's fleet scope, applied at the
    SQL level BEFORE the first row is yielded (``None`` = admin; empty = nothing).

    The query uses SQLAlchemy's ``yield_per`` so the backend does not
    materialize the full result set in memory — critical for the
    multi-million-row fleet exports captured in the Slice 2 risks.
    """
    if evaluated_before <= evaluated_after:
        raise ComplianceError(
            "evaluated_before must be strictly greater than evaluated_after"
        )
    window = evaluated_before - evaluated_after
    if window > timedelta(days=EXPORT_WINDOW_MAX_DAYS):
        raise ComplianceError(f"export window must be <= {EXPORT_WINDOW_MAX_DAYS} days")

    clauses = _evidence_filter_clauses(
        policy_id=policy_id,
        system_id=system_id,
        verdict=verdict,
        evaluated_after=evaluated_after,
        evaluated_before=evaluated_before,
        allowed_system_ids=allowed_system_ids,
    )
    q = db.query(CompliancePolicyEvidence)
    for c in clauses:
        q = q.filter(c)
    q = q.order_by(
        CompliancePolicyEvidence.evaluated_at.asc(),
        CompliancePolicyEvidence.id.asc(),
    ).yield_per(EXPORT_STREAM_CHUNK)
    for row in q:
        yield row


def emit_export_requested_audit(
    *,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    export_format: str,
    filters: Dict[str, Any],
    row_count: int,
) -> None:
    """Audit emit AFTER the export stream has finished. ``filters`` is
    the operator-supplied filter set (window, policy_id, system_id,
    verdict). Emit goes through ``safe_emit`` with no ``db=`` so it
    opens its own ``SessionLocal`` per the session-boundary pattern.
    """
    safe_emit(
        action=AUDIT_COMPLIANCE_EXPORT_REQUESTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="compliance_evidence_export",
        target_id=None,
        context={
            "format": export_format,
            "filters": filters,
            "row_count": row_count,
        },
    )
