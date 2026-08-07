"""Patch rollback feasibility service (PRA-173 slice 1).

Builds and maintains the per-execution rollback feasibility artifact
that sits on top of a PRA-171 :class:`PatchUpdateExecution` and its
PRA-164 :class:`PatchUpdatePlan`. Slice 1 ships *only* the storage
substrate and read surface: it consumes the existing PRA-164 plan
host / preflight evidence and the PRA-171 per-host / per-package
execution results, evaluates per-package rollback feasibility against
the host's effective content profile / mirror index (PRA-159 / 164),
persists three layers of rows
(:class:`PatchUpdateExecutionRollback`,
:class:`PatchUpdateExecutionRollbackHost`,
:class:`PatchUpdateExecutionRollbackPackage`), and exposes idempotent
read APIs the route layer consumes.

Slice 1 deliberately stops before any real rollback work. There is
**no rollback command planning**, **no rollback approval**, **no
rollback execution / dispatch**, **no SSH or agent transport**, **no
package-history mutation**, **no re-scan / facts refresh / rollback
verification loop**, and **no automatic rollback on patch failure**.
Those land in later PRA-173 slices.

The feasibility evaluation is a *strict read* against existing DB
content indexes: it never reads mirror files on disk, never calls
``mirror_package_index.backfill_run_if_missing``, and never inserts
or updates ``MirrorSyncRunPackage`` rows. Candidate sync runs that
have no per-package index rows are surfaced explicitly as
``content_evidence_missing`` rather than silently backfilled into
evidence by the rollback path. Index population is owned by the
PRA-157 sync-completion hook and the PRA-164 preflight resolver.

Initialization is explicit (the route layer calls
:func:`evaluate_rollback_feasibility` once the parent execution
reaches a terminal state); this slice does not introduce a
background daemon. The evaluation pass is idempotent: re-running it
upserts the rollback header / host / package rows in place rather
than producing duplicates, and uses the moment-in-time content-profile
snapshot on the source :class:`PatchUpdatePlanHost` rather than re-
resolving the host's *current* profile — so later policy / content
edits do not silently rewrite historical intent.

Per-package feasibility cascade (first match wins, highest-priority
first):

* ``package_not_succeeded`` — execution did not succeed for this
  package (``outcome != 'succeeded'``).
* ``missing_before_version`` — the execution did not capture the
  pre-update installed version, so there is no version to roll back
  to.
* ``missing_after_version`` — neither ``installed_version_after``
  nor ``requested_version_snapshot`` is known, so we cannot prove
  the package changed.
* ``version_unchanged`` — ``installed_version_before`` already
  equals the post-update / requested version, so there is nothing
  to roll back.
* ``unsupported_package_family`` — the recorded family is not in
  ``{apt, dnf}``.
* ``content_profile_missing`` — the host has no resolved content
  profile (state was ``no_profile`` or ``conflict`` at plan-build
  time).
* ``content_evidence_missing`` — the host has a resolved content
  profile but no candidate sync run has per-package index rows
  (no successful sync run, no pinned run, or every candidate
  run's index is empty) — so no usable evidence exists. The
  rollback path never backfills the index from disk; missing rows
  are surfaced as a refusal.
* ``old_version_unavailable`` — the content profile resolves and
  at least one candidate sync run has index evidence, but no
  mirror publishes the ``installed_version_before`` value.
* Otherwise: ``feasible`` — the old version is published by at
  least one mirror in the host's effective content source.

Host-level state is derived from the per-package rollup:

* If the execution-host state is not ``succeeded``, the host is
  ``infeasible`` with ``host_not_succeeded`` regardless of any
  per-package feasibility.
* Otherwise, if every package row is feasible: ``feasible``.
* If at least one package row is feasible: ``partial_feasible``.
* Else: ``infeasible``.

Plan-level state is ``evaluated`` when the parent execution is in
a terminal state at evaluation time. Non-terminal executions
produce a ``refused`` header row with ``execution_not_terminal`` so
the read surface always has an artifact to show.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    Package,
    PatchApproval,
    PatchUpdateExecution,
    PatchUpdateExecutionHost,
    PatchUpdateExecutionHostPackage,
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackApproval,
    PatchUpdateExecutionRollbackHost,
    PatchUpdateExecutionRollbackPackage,
    PatchUpdatePlan,
    PatchUpdatePlanHost,
    User,
)
from . import mirror_package_index, patch_approval_service
from .audit_event_service import safe_emit
from .content_profile_service import ContentProfileService
from .patch_execution_service import (
    EXECUTION_HOST_STATE_SUCCEEDED,
    TERMINAL_EXECUTION_STATES,
)
from .patch_update_plan_service import (
    CONTENT_PROFILE_STATE_RESOLVED,
    PACKAGE_MANAGER_FAMILY_APT,
    PACKAGE_MANAGER_FAMILY_DNF,
    PACKAGE_MANAGER_FAMILY_UNKNOWN,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vocabularies (mirror the DB CHECK constraints)
# ---------------------------------------------------------------------------

ROLLBACK_PLAN_STATE_EVALUATED = "evaluated"
ROLLBACK_PLAN_STATE_REFUSED = "refused"

VALID_ROLLBACK_PLAN_STATES = frozenset(
    {ROLLBACK_PLAN_STATE_EVALUATED, ROLLBACK_PLAN_STATE_REFUSED}
)

ROLLBACK_HOST_STATE_FEASIBLE = "feasible"
ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE = "partial_feasible"
ROLLBACK_HOST_STATE_INFEASIBLE = "infeasible"

VALID_ROLLBACK_HOST_STATES = frozenset(
    {
        ROLLBACK_HOST_STATE_FEASIBLE,
        ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE,
        ROLLBACK_HOST_STATE_INFEASIBLE,
    }
)

ROLLBACK_PACKAGE_STATE_FEASIBLE = "feasible"
ROLLBACK_PACKAGE_STATE_INFEASIBLE = "infeasible"

VALID_ROLLBACK_PACKAGE_STATES = frozenset(
    {ROLLBACK_PACKAGE_STATE_FEASIBLE, ROLLBACK_PACKAGE_STATE_INFEASIBLE}
)


# Refusal codes (machine-readable) — kept short so the operator UI
# can render structured "why not" copy alongside JSONB details.
REFUSAL_EXECUTION_NOT_TERMINAL = "execution_not_terminal"
REFUSAL_HOST_NOT_SUCCEEDED = "host_not_succeeded"
REFUSAL_PACKAGE_NOT_SUCCEEDED = "package_not_succeeded"
REFUSAL_MISSING_BEFORE_VERSION = "missing_before_version"
REFUSAL_MISSING_AFTER_VERSION = "missing_after_version"
REFUSAL_VERSION_UNCHANGED = "version_unchanged"
REFUSAL_UNSUPPORTED_PACKAGE_FAMILY = "unsupported_package_family"
REFUSAL_CONTENT_PROFILE_MISSING = "content_profile_missing"
REFUSAL_CONTENT_EVIDENCE_MISSING = "content_evidence_missing"
REFUSAL_OLD_VERSION_UNAVAILABLE = "old_version_unavailable"


# Audit-event action — Slice 1 emits only the feasibility-computed
# event. Reserved-but-not-yet-emitted ``patch_rollback.*`` actions
# (requested / approved / started / host_succeeded / host_failed /
# completed) live in later PRA-173 slices that own real rollback
# request / approval / execution.
AUDIT_ROLLBACK_FEASIBILITY_COMPUTED = "patch_rollback.feasibility_computed"

# PRA-173 slice 2: rollback request / vote-result audit actions.
# Emitted from the patch_rollback_service boundary via safe_emit no
# db= so the audit row commits on its own SessionLocal (per
# feedback_safe_emit_session_boundary).
AUDIT_ROLLBACK_REQUESTED = "patch_rollback.requested"
AUDIT_ROLLBACK_APPROVED = "patch_rollback.approved"
AUDIT_ROLLBACK_REJECTED = "patch_rollback.rejected"


# Package-manager families we can plan rollback commands for in
# future slices. The vocabulary check stays at apt/dnf/unknown, but
# only apt/dnf are *rollback-supportable* — ``unknown`` is recorded
# as ``unsupported_package_family`` so the read surface surfaces the
# refusal explicitly.
ROLLBACK_SUPPORTED_FAMILIES = frozenset(
    {PACKAGE_MANAGER_FAMILY_APT, PACKAGE_MANAGER_FAMILY_DNF}
)


# ---------------------------------------------------------------------------
# Local exception
# ---------------------------------------------------------------------------


class PatchUpdateRollbackError(ValueError):
    """Raised when a rollback-feasibility read / evaluate is rejected
    for semantic reasons (unknown execution id, malformed request,
    etc.). Route layer maps "not found" wording to 404 and
    everything else to 422 via the standard error-to-HTTP helper
    (PRA-161 / PRA-162 / PRA-164 service-error disambiguation
    contract)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime as an absolute-UTC ISO 8601 string.

    The patch-lifecycle DB convention is naive-UTC datetimes; this
    helper makes the wire shape unambiguous by appending ``Z`` for
    naive values and normalizing tz-aware values to ``...Z``. PRA-173
    review lock #2 (carry-forward from PRA-172) requires persisted /
    detail / read payload timestamps to be absolute UTC so API
    consumers cannot mistake them for local time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_execution(db: Session, execution_id: int) -> PatchUpdateExecution:
    execution = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.id == execution_id)
        .first()
    )
    if execution is None:
        raise PatchUpdateRollbackError(
            f"patch update execution id={execution_id} not found"
        )
    return execution


def _resolve_target_version(
    pkg: PatchUpdateExecutionHostPackage,
) -> Optional[str]:
    """Resolved post-update version for a package row.

    ``installed_version_after`` is the live observation; when the
    dispatcher cannot reliably read it, ``requested_version_snapshot``
    is the next-best signal. Either being non-null is enough to
    answer "did this package change?".
    """
    if pkg.installed_version_after is not None:
        return pkg.installed_version_after
    if pkg.requested_version_snapshot is not None:
        return pkg.requested_version_snapshot
    return None


def _build_content_profile_snapshot(
    plan_host: Optional[PatchUpdatePlanHost],
) -> Dict[str, Any]:
    """Capture the host's effective-content-profile context from the
    PRA-164 plan-host row. Mirrors the columns the plan resolver
    already snapshots, so the rollback audit trail is self-contained
    (later edits to the host's profile binding cannot silently
    rewrite history).
    """
    if plan_host is None:
        return {
            "content_profile_state": None,
            "content_profile_id_snapshot": None,
            "content_profile_slug_snapshot": None,
            "content_profile_display_name_snapshot": None,
            "content_profile_package_family_snapshot": None,
            "content_profile_conflict_snapshot": [],
        }
    return {
        "content_profile_state": plan_host.content_profile_state,
        "content_profile_id_snapshot": plan_host.content_profile_id_snapshot,
        "content_profile_slug_snapshot": plan_host.content_profile_slug_snapshot,
        "content_profile_display_name_snapshot": (
            plan_host.content_profile_display_name_snapshot
        ),
        "content_profile_package_family_snapshot": (
            plan_host.content_profile_package_family_snapshot
        ),
        "content_profile_conflict_snapshot": list(
            plan_host.content_profile_conflict_snapshot or []
        ),
    }


def _evaluate_old_version_availability(
    db: Session,
    *,
    plan_host: PatchUpdatePlanHost,
    package_name: str,
    old_version: str,
    profile_service: ContentProfileService,
) -> Tuple[str, Dict[str, Any]]:
    """Strict version-level lookup of ``old_version`` against the
    host's effective content profile / mirror index.

    Returns ``(state, evidence)`` where ``state`` is one of
    :data:`ROLLBACK_PACKAGE_STATE_FEASIBLE` (old version published by
    at least one mirror in the host's effective content source) or
    :data:`ROLLBACK_PACKAGE_STATE_INFEASIBLE` plus a structured
    refusal code in ``evidence['refusal']``.

    Reuses :func:`mirror_package_index.mirror_publishes` for the
    DB-only equality lookup. **Does NOT call**
    :func:`mirror_package_index.backfill_run_if_missing` — Slice 1
    review lock requires rollback feasibility to read existing DB
    content indexes only, never read mirror files on disk, and
    never mutate ``MirrorSyncRunPackage`` rows during evaluation.
    Candidate runs that have no existing index rows are surfaced
    explicitly as ``content_evidence_missing`` rather than being
    backfilled into evidence by the rollback path. Index population
    remains the responsibility of the PRA-157 sync-completion hook
    and the PRA-164 preflight resolver (which owns the
    feasibility-write surface for the update path); the rollback
    surface is a strict read.

    Refusal cases:

    * ``content_profile_missing`` — the host's
      ``content_profile_state`` is not ``resolved`` (e.g.
      ``no_profile`` / ``conflict``).
    * ``content_evidence_missing`` — the profile resolves but every
      candidate sync run has no per-package index rows (no
      successful sync run, no pinned run, or the index has not yet
      been populated for the run). Slice 1 surfaces this as a
      separate refusal rather than silently treating "no index
      rows" as "version not published".
    * ``old_version_unavailable`` — at least one candidate sync run
      has index evidence, but no mirror publishes the requested old
      version.
    """
    if plan_host.content_profile_state != CONTENT_PROFILE_STATE_RESOLVED:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            {
                "refusal": REFUSAL_CONTENT_PROFILE_MISSING,
                "content_profile_state": plan_host.content_profile_state,
            },
        )

    if plan_host.content_profile_id_snapshot is None:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            {
                "refusal": REFUSAL_CONTENT_PROFILE_MISSING,
                "content_profile_state": plan_host.content_profile_state,
                "message": "host has no content_profile_id_snapshot",
            },
        )

    entries = profile_service.resolve_mirror_entries_for_profile(
        plan_host.content_profile_id_snapshot
    )
    if not entries:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            {
                "refusal": REFUSAL_CONTENT_EVIDENCE_MISSING,
                "message": "profile resolves but has no mirror entries",
            },
        )

    # Bulk-load candidate runs (pinned first, latest-ok fallback)
    # exactly like the PRA-164 preflight resolver.
    from ..db.models import MirrorSyncRun

    pinned_run_ids = [e.pinned_run_id for e in entries if e.pinned_run_id is not None]
    pinned_runs: Dict[int, MirrorSyncRun] = {}
    if pinned_run_ids:
        for run in (
            db.query(MirrorSyncRun).filter(MirrorSyncRun.id.in_(pinned_run_ids)).all()
        ):
            pinned_runs[run.id] = run

    unpinned_mirror_ids = [e.mirror_id for e in entries if e.pinned_run_id is None]
    latest_runs: Dict[int, MirrorSyncRun] = {}
    if unpinned_mirror_ids:
        for mirror_id in unpinned_mirror_ids:
            run_id = mirror_package_index.latest_ok_run_id(db, mirror_id)
            if run_id is not None:
                run = db.query(MirrorSyncRun).filter(MirrorSyncRun.id == run_id).first()
                if run is not None:
                    latest_runs[mirror_id] = run

    candidates: List[Tuple[Any, MirrorSyncRun]] = []
    for entry in entries:
        if entry.pinned_run_id is not None:
            run = pinned_runs.get(entry.pinned_run_id)
            if run is not None and run.status == "ok":
                candidates.append((entry, run))
        else:
            run = latest_runs.get(entry.mirror_id)
            if run is not None:
                candidates.append((entry, run))

    if not candidates:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            {
                "refusal": REFUSAL_CONTENT_EVIDENCE_MISSING,
                "message": ("profile resolves but no mirror has a usable sync run"),
                "checked_channel_count": 0,
            },
        )

    # Bulk-check which candidate runs already have per-package
    # index rows. Slice 1 lock: rollback feasibility must read
    # existing DB indexes only — runs whose index has not yet been
    # populated are surfaced as ``content_evidence_missing``, never
    # silently backfilled and never treated as "version not
    # published".
    from ..db.models import MirrorSyncRunPackage

    candidate_run_ids = [run.id for _, run in candidates]
    indexed_run_ids: set = set()
    if candidate_run_ids:
        for (rid,) in (
            db.query(MirrorSyncRunPackage.mirror_sync_run_id)
            .filter(MirrorSyncRunPackage.mirror_sync_run_id.in_(candidate_run_ids))
            .distinct()
            .all()
        ):
            indexed_run_ids.add(rid)

    matched_channels: List[Dict[str, Any]] = []
    checked: List[Dict[str, Any]] = []
    indexed_checked_count = 0
    for entry, run in candidates:
        record = {
            "channel_id": entry.channel_id,
            "channel_slug": entry.channel_slug,
            "mirror_id": entry.mirror_id,
            "mirror_slug": entry.mirror_slug,
            "mirror_sync_run_id": run.id,
            "package_family": entry.package_family,
        }
        if run.id not in indexed_run_ids:
            # No per-package index rows for this run. Slice 1 must
            # NOT call ``backfill_run_if_missing`` here — that would
            # read the mirror manifest from disk and insert
            # ``MirrorSyncRunPackage`` rows from the rollback path,
            # which violates the "feasibility reads only" lock.
            # Record the gap explicitly and move on.
            record["matched"] = False
            record["index_status"] = "index_missing"
            checked.append(record)
            continue
        indexed_checked_count += 1
        published = mirror_package_index.mirror_publishes(
            db,
            mirror_sync_run_id=run.id,
            package_name=package_name,
            version=old_version,
        )
        record["matched"] = published
        record["index_status"] = "indexed"
        checked.append(record)
        if published:
            matched_channels.append(record)

    if matched_channels:
        return (
            ROLLBACK_PACKAGE_STATE_FEASIBLE,
            {
                "matched_channels": matched_channels,
                "checked_channel_count": len(checked),
                "indexed_checked_count": indexed_checked_count,
            },
        )

    if indexed_checked_count == 0:
        # Every candidate run lacks per-package index evidence.
        # Surface as ``content_evidence_missing`` rather than
        # ``old_version_unavailable`` so the operator UI can
        # distinguish "we have not indexed this mirror yet" from
        # "the mirror genuinely does not publish this version".
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            {
                "refusal": REFUSAL_CONTENT_EVIDENCE_MISSING,
                "message": (
                    "candidate mirror sync runs have no per-package "
                    "index rows; rollback feasibility never backfills "
                    "the index"
                ),
                "checked_channels": checked,
                "checked_channel_count": len(checked),
                "indexed_checked_count": 0,
            },
        )

    return (
        ROLLBACK_PACKAGE_STATE_INFEASIBLE,
        {
            "refusal": REFUSAL_OLD_VERSION_UNAVAILABLE,
            "checked_channels": checked,
            "checked_channel_count": len(checked),
            "indexed_checked_count": indexed_checked_count,
        },
    )


# ---------------------------------------------------------------------------
# PRA-173 slice 2: rollback command-plan rendering.
#
# Renders the package-family-specific rollback command for a feasible
# rollback package row. Slice 2 is non-executing: the returned JSONB
# blob is structured intent only — the future PRA-173 dispatch slice
# reads this exact shape and runs the recorded ``argv`` through the
# established transport. No SSH / agent / package-manager invocation
# happens here.
#
# Held-package handling: ``Package.is_held`` (PRA-155 facts) carries
# the apt hold flag. When present and True for a given (host_system,
# package_name), the plan records ``held_package_handling.is_held =
# true`` plus the pre/post unhold-rehold step shape; otherwise the
# plan records ``is_held = false`` and an empty step list. The
# *dispatch* shape (whether to actually run ``apt-mark unhold`` /
# ``apt-mark hold``) is decided in Slice 3. Slice 2 only records
# what we know now.
#
# Versionlock (dnf) handling: there is no per-package versionlock
# fact in the existing PRA-155 schema. Slice 2 records
# ``versionlock_handling = { supported: false, reason:
# 'no_versionlock_facts' }`` so the dispatch slice can choose to
# probe at execution time or refuse, but the rollback feasibility
# read surface is honest about what is unknown.
# ---------------------------------------------------------------------------


def _shell_quote(value: str) -> str:
    """Conservative quoter for the rendered ``command_string``.

    Used only for the human-readable mirror of ``argv``. Slice 3
    dispatch reads ``argv`` directly (the canonical form) so the
    rendered string is decoration, not a correctness boundary.
    Identical behavior to ``shlex.quote`` but inlined to avoid an
    extra import in this module's hot path.
    """
    if not value:
        return "''"
    safe = all(c.isalnum() or c in "@%+=:,./-_" for c in value)
    if safe:
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _build_held_package_metadata(
    *,
    is_held: Optional[bool],
    package_name: str,
) -> Dict[str, Any]:
    """Slice 2 apt held-package handling block.

    ``is_held`` mirrors ``Package.is_held`` at the moment of
    evaluation. When True, the plan carries the pre/post-step shape
    Slice 3 dispatch will execute (apt-mark unhold ... → primary
    rollback → apt-mark hold ...). When False or None, the plan
    records ``is_held = false`` and empty step lists so the read
    surface is honest about the absence of hold.
    """
    if is_held is True:
        return {
            "supported": True,
            "is_held": True,
            "pre_steps": [
                {
                    "argv": ["apt-mark", "unhold", package_name],
                    "command_string": (f"apt-mark unhold {_shell_quote(package_name)}"),
                    "purpose": "release_apt_hold",
                }
            ],
            "post_steps": [
                {
                    "argv": ["apt-mark", "hold", package_name],
                    "command_string": (f"apt-mark hold {_shell_quote(package_name)}"),
                    "purpose": "restore_apt_hold",
                }
            ],
        }
    return {
        "supported": True,
        "is_held": False,
        "pre_steps": [],
        "post_steps": [],
    }


def _build_versionlock_metadata() -> Dict[str, Any]:
    """Slice 2 dnf versionlock handling block.

    The existing PRA-155 facts schema does not carry per-package
    versionlock state, so the plan records the unknown explicitly.
    Slice 3 dispatch may add an in-transport probe step; that is
    intentionally a later decision.
    """
    return {
        "supported": False,
        "reason": "no_versionlock_facts",
        "pre_steps": [],
        "post_steps": [],
    }


def _render_command_plan(
    *,
    family: str,
    package_name: str,
    target_rollback_version: str,
    post_version: Optional[str],
    is_held: Optional[bool],
) -> Optional[Dict[str, Any]]:
    """Build the JSONB command-plan blob for one feasible package row.

    Returns ``None`` for non-rollback-supportable families
    (anything outside ``{apt, dnf}``); the per-package feasibility
    cascade already refuses those with
    ``unsupported_package_family``, so this guard is defensive.

    Plan shape stays family-agnostic at the top:

    ::

        {
          "family": "apt" | "dnf",
          "package_name": "openssl",
          "target_rollback_version": "1.0",
          "post_version": "1.1",
          "primary_command": {
            "argv": [...],
            "command_string": "...",
          },
          "held_package_handling": {...},     # apt only — meaningful
          "versionlock_handling": {...},      # dnf only — meaningful
        }
    """
    if family == PACKAGE_MANAGER_FAMILY_APT:
        version_spec = f"{package_name}={target_rollback_version}"
        argv = [
            "apt-get",
            "install",
            "-y",
            "--allow-downgrades",
            version_spec,
        ]
        return {
            "family": PACKAGE_MANAGER_FAMILY_APT,
            "package_name": package_name,
            "target_rollback_version": target_rollback_version,
            "post_version": post_version,
            "primary_command": {
                "argv": argv,
                "command_string": " ".join(_shell_quote(a) for a in argv),
            },
            "held_package_handling": _build_held_package_metadata(
                is_held=is_held, package_name=package_name
            ),
            "versionlock_handling": {
                "supported": False,
                "reason": "not_applicable_for_family",
                "pre_steps": [],
                "post_steps": [],
            },
        }
    if family == PACKAGE_MANAGER_FAMILY_DNF:
        version_spec = f"{package_name}-{target_rollback_version}"
        argv = [
            "dnf",
            "downgrade",
            "-y",
            version_spec,
        ]
        return {
            "family": PACKAGE_MANAGER_FAMILY_DNF,
            "package_name": package_name,
            "target_rollback_version": target_rollback_version,
            "post_version": post_version,
            "primary_command": {
                "argv": argv,
                "command_string": " ".join(_shell_quote(a) for a in argv),
            },
            "held_package_handling": {
                "supported": False,
                "reason": "not_applicable_for_family",
                "is_held": False,
                "pre_steps": [],
                "post_steps": [],
            },
            "versionlock_handling": _build_versionlock_metadata(),
        }
    # Defensive — should never reach for feasible rows.
    return None


def _held_flags_for_host(
    db: Session, system_id: Optional[int], package_names: List[str]
) -> Dict[str, bool]:
    """Bulk-load ``Package.is_held`` for the (host, package_name)
    pairs we are planning. Returns ``{package_name: is_held}``;
    packages without a ``Package`` row are absent from the dict
    (the caller treats absence as ``is_held=None``).
    """
    if system_id is None or not package_names:
        return {}
    rows = (
        db.query(Package.name, Package.is_held)
        .filter(
            Package.system_id == system_id,
            Package.name.in_(package_names),
        )
        .all()
    )
    return {name: bool(is_held) for name, is_held in rows}


def _decide_package_feasibility(
    db: Session,
    *,
    plan_host: PatchUpdatePlanHost,
    pkg: PatchUpdateExecutionHostPackage,
    profile_service: ContentProfileService,
) -> Tuple[str, Optional[str], Dict[str, Any], Optional[str], Dict[str, Any]]:
    """Per-package feasibility cascade.

    Returns ``(state, refusal_reason, refusal_details,
    target_rollback_version, content_evidence)``.

    ``state`` is one of :data:`ROLLBACK_PACKAGE_STATE_FEASIBLE` /
    :data:`ROLLBACK_PACKAGE_STATE_INFEASIBLE`. ``refusal_reason``
    is null only when the row is feasible.
    ``target_rollback_version`` is set only on feasible rows (equal
    to ``installed_version_before``).
    ``content_evidence`` carries the channel/mirror/run records we
    inspected; on feasible rows it lists the matching channels, on
    ``old_version_unavailable`` it lists the negative results.
    """
    before = pkg.installed_version_before
    after = pkg.installed_version_after
    requested = pkg.requested_version_snapshot
    family = pkg.package_manager_family_snapshot

    # 1. Package outcome gate. Anything other than ``succeeded`` is
    #    not rollback-eligible because the package didn't actually
    #    change state.
    if pkg.outcome != "succeeded":
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            REFUSAL_PACKAGE_NOT_SUCCEEDED,
            {
                "package_outcome": pkg.outcome,
                "error_code": pkg.error_code,
            },
            None,
            {},
        )

    # 2. Missing-before-version: cannot roll back to a version we
    #    never recorded.
    if before is None:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            REFUSAL_MISSING_BEFORE_VERSION,
            {
                "package_outcome": pkg.outcome,
                "installed_version_after": after,
                "requested_version_snapshot": requested,
            },
            None,
            {},
        )

    target = _resolve_target_version(pkg)

    # 3. Missing-after-version: we know the before version but can't
    #    prove a change happened.
    if target is None:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            REFUSAL_MISSING_AFTER_VERSION,
            {
                "package_outcome": pkg.outcome,
                "installed_version_before": before,
            },
            None,
            {},
        )

    # 4. Version-unchanged: nothing to roll back to.
    if before == target:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            REFUSAL_VERSION_UNCHANGED,
            {
                "installed_version_before": before,
                "installed_version_after": after,
                "requested_version_snapshot": requested,
                "resolved_target_version": target,
            },
            None,
            {},
        )

    # 5. Unsupported package family. ``unknown`` and anything outside
    #    apt/dnf is recorded as a refusal rather than silently
    #    omitted.
    if family not in ROLLBACK_SUPPORTED_FAMILIES:
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            REFUSAL_UNSUPPORTED_PACKAGE_FAMILY,
            {
                "package_manager_family_snapshot": family,
                "supported_families": sorted(ROLLBACK_SUPPORTED_FAMILIES),
            },
            None,
            {},
        )

    # 6. Old-version availability against the host's effective
    #    content source. ``content_profile_missing`` /
    #    ``content_evidence_missing`` / ``old_version_unavailable``
    #    are explicit refusal states.
    availability_state, availability_details = _evaluate_old_version_availability(
        db,
        plan_host=plan_host,
        package_name=pkg.package_name,
        old_version=before,
        profile_service=profile_service,
    )
    if availability_state == ROLLBACK_PACKAGE_STATE_INFEASIBLE:
        refusal = availability_details.pop("refusal", None) or (
            REFUSAL_OLD_VERSION_UNAVAILABLE
        )
        return (
            ROLLBACK_PACKAGE_STATE_INFEASIBLE,
            refusal,
            {
                "installed_version_before": before,
                "resolved_target_version": target,
                **availability_details,
            },
            None,
            availability_details,
        )

    # Feasible.
    return (
        ROLLBACK_PACKAGE_STATE_FEASIBLE,
        None,
        {},
        before,
        availability_details,
    )


def _derive_host_state_and_summary(
    *,
    execution_host_state: str,
    package_rows: List[Dict[str, Any]],
) -> Tuple[str, Optional[str], Dict[str, Any], Dict[str, Any]]:
    """Derive the rollback host's ``state`` / ``refusal_reason`` /
    ``refusal_details`` / ``package_summary`` from the per-package
    rollup.

    Hosts whose execution-host state is not ``succeeded`` are
    ``infeasible`` with ``host_not_succeeded`` regardless of any
    per-package outcome (which mostly cascades to
    ``package_not_succeeded`` anyway). This keeps the host-level
    refusal explicit so the read surface always answers "why is
    this host not rollback-eligible".
    """
    feasible = sum(
        1 for row in package_rows if row["state"] == ROLLBACK_PACKAGE_STATE_FEASIBLE
    )
    infeasible = sum(
        1 for row in package_rows if row["state"] == ROLLBACK_PACKAGE_STATE_INFEASIBLE
    )
    refusal_counts: Dict[str, int] = {}
    for row in package_rows:
        reason = row.get("refusal_reason")
        if reason is not None:
            refusal_counts[reason] = refusal_counts.get(reason, 0) + 1

    package_summary = {
        "package_count": len(package_rows),
        "feasible_count": feasible,
        "infeasible_count": infeasible,
        "refusal_counts": dict(sorted(refusal_counts.items())),
    }

    if execution_host_state != EXECUTION_HOST_STATE_SUCCEEDED:
        return (
            ROLLBACK_HOST_STATE_INFEASIBLE,
            REFUSAL_HOST_NOT_SUCCEEDED,
            {"execution_host_state": execution_host_state},
            package_summary,
        )

    if not package_rows:
        # Host succeeded but produced no package rows. Treat as
        # infeasible with an explicit refusal so the operator UI can
        # render the gap rather than silently rendering "feasible
        # with 0 packages".
        return (
            ROLLBACK_HOST_STATE_INFEASIBLE,
            REFUSAL_HOST_NOT_SUCCEEDED,
            {
                "execution_host_state": execution_host_state,
                "message": "host has no execution-package rows",
            },
            package_summary,
        )

    if feasible == 0:
        return (
            ROLLBACK_HOST_STATE_INFEASIBLE,
            None,
            {},
            package_summary,
        )
    if infeasible == 0:
        return (
            ROLLBACK_HOST_STATE_FEASIBLE,
            None,
            {},
            package_summary,
        )
    return (
        ROLLBACK_HOST_STATE_PARTIAL_FEASIBLE,
        None,
        {},
        package_summary,
    )


def _build_feasibility_summary(
    host_rollups: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Plan-level rollup over per-host state + per-package state."""
    host_counts: Dict[str, int] = {s: 0 for s in sorted(VALID_ROLLBACK_HOST_STATES)}
    package_counts: Dict[str, int] = {
        s: 0 for s in sorted(VALID_ROLLBACK_PACKAGE_STATES)
    }
    refusal_counts: Dict[str, int] = {}

    for host in host_rollups:
        host_counts[host["state"]] = host_counts.get(host["state"], 0) + 1
        for pkg in host["packages"]:
            package_counts[pkg["state"]] = package_counts.get(pkg["state"], 0) + 1
            reason = pkg.get("refusal_reason")
            if reason is not None:
                refusal_counts[reason] = refusal_counts.get(reason, 0) + 1

    return {
        "host_count": len(host_rollups),
        "host_counts_by_state": host_counts,
        "package_count": sum(len(h["packages"]) for h in host_rollups),
        "package_counts_by_state": package_counts,
        "refusal_counts": dict(sorted(refusal_counts.items())),
    }


# ---------------------------------------------------------------------------
# Public API — evaluate
# ---------------------------------------------------------------------------


def evaluate_rollback_feasibility(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    now: Optional[datetime] = None,
) -> PatchUpdateExecutionRollback:
    """Initialize or refresh the rollback feasibility artifact for an
    execution.

    Idempotent: re-running upserts the rollback header row, per-host
    rows, and per-package rows in place. Existing rows are matched
    by ``(execution_id)`` at the header, ``(rollback_id,
    execution_host_id)`` at the host layer, and ``(rollback_host_id,
    package_name)`` at the package layer.

    The execution does NOT need to be in a terminal state — non-
    terminal executions produce a ``refused`` header row with
    ``execution_not_terminal`` so the read API always has an
    artifact. Per-host / per-package rows are NOT written when the
    execution is non-terminal.

    Emits a single :data:`AUDIT_ROLLBACK_FEASIBILITY_COMPUTED` audit
    event via ``safe_emit`` no ``db=`` (per the established session-
    boundary lock).
    """
    execution = _require_execution(db, execution_id)
    current_now = now or datetime.utcnow()

    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )

    # ------------------------------------------------------------------
    # Plan-level gate: non-terminal executions produce a ``refused``
    # header row with no per-host / per-package rows.
    # ------------------------------------------------------------------
    if execution.state not in TERMINAL_EXECUTION_STATES:
        if rollback_row is None:
            rollback_row = PatchUpdateExecutionRollback(
                execution_id=execution.id,
                plan_id_snapshot=execution.plan_id,
                execution_state_snapshot=execution.state,
                state=ROLLBACK_PLAN_STATE_REFUSED,
                refusal_reason=REFUSAL_EXECUTION_NOT_TERMINAL,
                refusal_details={
                    "execution_state": execution.state,
                    "terminal_states": sorted(TERMINAL_EXECUTION_STATES),
                },
                feasibility_summary={
                    "host_count": 0,
                    "host_counts_by_state": {
                        s: 0 for s in sorted(VALID_ROLLBACK_HOST_STATES)
                    },
                    "package_count": 0,
                    "package_counts_by_state": {
                        s: 0 for s in sorted(VALID_ROLLBACK_PACKAGE_STATES)
                    },
                    "refusal_counts": {},
                },
                evaluated_at=current_now,
            )
            db.add(rollback_row)
        else:
            rollback_row.plan_id_snapshot = execution.plan_id
            rollback_row.execution_state_snapshot = execution.state
            rollback_row.state = ROLLBACK_PLAN_STATE_REFUSED
            rollback_row.refusal_reason = REFUSAL_EXECUTION_NOT_TERMINAL
            rollback_row.refusal_details = {
                "execution_state": execution.state,
                "terminal_states": sorted(TERMINAL_EXECUTION_STATES),
            }
            rollback_row.feasibility_summary = {
                "host_count": 0,
                "host_counts_by_state": {
                    s: 0 for s in sorted(VALID_ROLLBACK_HOST_STATES)
                },
                "package_count": 0,
                "package_counts_by_state": {
                    s: 0 for s in sorted(VALID_ROLLBACK_PACKAGE_STATES)
                },
                "refusal_counts": {},
            }
            rollback_row.evaluated_at = current_now
            # Drop any stale per-host / per-package rows: the gate
            # decision invalidates them. Cascade handles the package
            # rows under each host.
            db.query(PatchUpdateExecutionRollbackHost).filter(
                PatchUpdateExecutionRollbackHost.rollback_id == rollback_row.id
            ).delete(synchronize_session=False)
        db.flush()
        db.commit()
        db.refresh(rollback_row)

        safe_emit(
            action=AUDIT_ROLLBACK_FEASIBILITY_COMPUTED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_update_execution_rollback",
            target_id=str(rollback_row.id),
            context={
                "execution_id": execution.id,
                "plan_id": execution.plan_id,
                "state": rollback_row.state,
                "refusal_reason": rollback_row.refusal_reason,
                "evaluated_at": utc_iso(current_now),
            },
        )
        return rollback_row

    # ------------------------------------------------------------------
    # Terminal execution: build per-host and per-package rollups.
    # ------------------------------------------------------------------
    hosts: List[PatchUpdateExecutionHost] = (
        db.query(PatchUpdateExecutionHost)
        .filter(PatchUpdateExecutionHost.execution_id == execution.id)
        .order_by(
            PatchUpdateExecutionHost.wave_index.asc(),
            PatchUpdateExecutionHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionHost.id.asc(),
        )
        .all()
    )

    plan_host_ids = [h.plan_host_id for h in hosts]
    plan_hosts_by_id: Dict[int, PatchUpdatePlanHost] = {}
    if plan_host_ids:
        for ph in (
            db.query(PatchUpdatePlanHost)
            .filter(PatchUpdatePlanHost.id.in_(plan_host_ids))
            .all()
        ):
            plan_hosts_by_id[ph.id] = ph

    profile_service = ContentProfileService(db)

    host_rollups: List[Dict[str, Any]] = []
    for host in hosts:
        plan_host = plan_hosts_by_id.get(host.plan_host_id)

        # Fetch this host's per-package execution rows.
        pkg_rows = (
            db.query(PatchUpdateExecutionHostPackage)
            .filter(PatchUpdateExecutionHostPackage.execution_host_id == host.id)
            .order_by(PatchUpdateExecutionHostPackage.package_name.asc())
            .all()
        )

        # PRA-173 slice 2: bulk-load ``Package.is_held`` per
        # (host_system, package_name) so the apt held-package
        # metadata in the rendered command plan is correct.
        held_flags = _held_flags_for_host(
            db,
            host.system_id_snapshot,
            [pkg.package_name for pkg in pkg_rows],
        )

        package_rollup: List[Dict[str, Any]] = []
        # When the execution-host is not ``succeeded`` we still
        # build per-package rows so the audit trail is complete,
        # but the package-feasibility cascade will mostly resolve
        # to ``package_not_succeeded`` (outcome != succeeded) — and
        # the host-level state will be ``infeasible`` /
        # ``host_not_succeeded`` regardless.
        for pkg in pkg_rows:
            if plan_host is None:
                # Defensive: an execution-host without a resolvable
                # plan-host snapshot cannot prove content availability
                # — record as content_profile_missing.
                state = ROLLBACK_PACKAGE_STATE_INFEASIBLE
                refusal = REFUSAL_CONTENT_PROFILE_MISSING
                refusal_details = {
                    "message": "plan-host row not found for execution-host",
                }
                target = None
                content_evidence: Dict[str, Any] = {}
            else:
                (
                    state,
                    refusal,
                    refusal_details,
                    target,
                    content_evidence,
                ) = _decide_package_feasibility(
                    db,
                    plan_host=plan_host,
                    pkg=pkg,
                    profile_service=profile_service,
                )

            # PRA-173 slice 2: render the command plan for feasible
            # rows; infeasible rows keep ``command_plan = None`` so
            # the read surface stays honest about which packages are
            # dispatch-ready.
            command_plan: Optional[Dict[str, Any]]
            if state == ROLLBACK_PACKAGE_STATE_FEASIBLE and target is not None:
                command_plan = _render_command_plan(
                    family=pkg.package_manager_family_snapshot,
                    package_name=pkg.package_name,
                    target_rollback_version=target,
                    post_version=_resolve_target_version(pkg),
                    is_held=held_flags.get(pkg.package_name),
                )
            else:
                command_plan = None

            package_rollup.append(
                {
                    "package_name": pkg.package_name,
                    "execution_host_package_id": pkg.id,
                    "package_manager_family_snapshot": (
                        pkg.package_manager_family_snapshot
                    ),
                    "installed_version_before_snapshot": pkg.installed_version_before,
                    "installed_version_after_snapshot": pkg.installed_version_after,
                    "requested_version_snapshot": pkg.requested_version_snapshot,
                    "target_rollback_version": target,
                    "package_outcome_snapshot": pkg.outcome,
                    "state": state,
                    "refusal_reason": refusal,
                    "refusal_details": refusal_details,
                    "content_evidence": content_evidence,
                    "command_plan": command_plan,
                }
            )

        (
            host_state,
            host_refusal_reason,
            host_refusal_details,
            package_summary,
        ) = _derive_host_state_and_summary(
            execution_host_state=host.state, package_rows=package_rollup
        )

        host_rollups.append(
            {
                "execution_host": host,
                "plan_host_id_snapshot": host.plan_host_id,
                "system_id_snapshot": host.system_id_snapshot,
                "system_hostname_snapshot": host.system_hostname_snapshot,
                "wave_index": host.wave_index,
                "execution_host_state_snapshot": host.state,
                "state": host_state,
                "refusal_reason": host_refusal_reason,
                "refusal_details": host_refusal_details,
                "content_profile_snapshot": _build_content_profile_snapshot(plan_host),
                "package_summary": package_summary,
                "packages": package_rollup,
            }
        )

    feasibility_summary = _build_feasibility_summary(host_rollups)

    # ------------------------------------------------------------------
    # Persist (upsert) the three layers.
    # ------------------------------------------------------------------
    if rollback_row is None:
        rollback_row = PatchUpdateExecutionRollback(
            execution_id=execution.id,
            plan_id_snapshot=execution.plan_id,
            execution_state_snapshot=execution.state,
            state=ROLLBACK_PLAN_STATE_EVALUATED,
            refusal_reason=None,
            refusal_details={},
            feasibility_summary=feasibility_summary,
            evaluated_at=current_now,
        )
        db.add(rollback_row)
        db.flush()
    else:
        rollback_row.plan_id_snapshot = execution.plan_id
        rollback_row.execution_state_snapshot = execution.state
        rollback_row.state = ROLLBACK_PLAN_STATE_EVALUATED
        rollback_row.refusal_reason = None
        rollback_row.refusal_details = {}
        rollback_row.feasibility_summary = feasibility_summary
        rollback_row.evaluated_at = current_now

    # Upsert host rows. Cascade handles the per-package rows under a
    # deleted host row, but we keep the row when possible so existing
    # ids stay stable for future read endpoints.
    existing_hosts = {
        row.execution_host_id: row
        for row in db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rollback_row.id)
        .all()
    }

    seen_host_ids: List[int] = []
    for rollup in host_rollups:
        host = rollup["execution_host"]
        seen_host_ids.append(host.id)
        host_row = existing_hosts.get(host.id)
        if host_row is None:
            host_row = PatchUpdateExecutionRollbackHost(
                rollback_id=rollback_row.id,
                execution_host_id=host.id,
                plan_host_id_snapshot=rollup["plan_host_id_snapshot"],
                system_id_snapshot=rollup["system_id_snapshot"],
                system_hostname_snapshot=rollup["system_hostname_snapshot"],
                wave_index=rollup["wave_index"],
                execution_host_state_snapshot=(rollup["execution_host_state_snapshot"]),
                state=rollup["state"],
                refusal_reason=rollup["refusal_reason"],
                refusal_details=rollup["refusal_details"],
                content_profile_snapshot=rollup["content_profile_snapshot"],
                package_summary=rollup["package_summary"],
                evaluated_at=current_now,
            )
            db.add(host_row)
            db.flush()
        else:
            host_row.plan_host_id_snapshot = rollup["plan_host_id_snapshot"]
            host_row.system_id_snapshot = rollup["system_id_snapshot"]
            host_row.system_hostname_snapshot = rollup["system_hostname_snapshot"]
            host_row.wave_index = rollup["wave_index"]
            host_row.execution_host_state_snapshot = rollup[
                "execution_host_state_snapshot"
            ]
            host_row.state = rollup["state"]
            host_row.refusal_reason = rollup["refusal_reason"]
            host_row.refusal_details = rollup["refusal_details"]
            host_row.content_profile_snapshot = rollup["content_profile_snapshot"]
            host_row.package_summary = rollup["package_summary"]
            host_row.evaluated_at = current_now

        # Upsert per-package rows for this host.
        existing_packages = {
            row.package_name: row
            for row in db.query(PatchUpdateExecutionRollbackPackage)
            .filter(PatchUpdateExecutionRollbackPackage.rollback_host_id == host_row.id)
            .all()
        }
        seen_package_names: List[str] = []
        for pkg_dict in rollup["packages"]:
            name = pkg_dict["package_name"]
            seen_package_names.append(name)
            existing_pkg = existing_packages.get(name)
            if existing_pkg is None:
                db.add(
                    PatchUpdateExecutionRollbackPackage(
                        rollback_host_id=host_row.id,
                        execution_host_package_id=pkg_dict["execution_host_package_id"],
                        package_name=name,
                        package_manager_family_snapshot=pkg_dict[
                            "package_manager_family_snapshot"
                        ],
                        installed_version_before_snapshot=pkg_dict[
                            "installed_version_before_snapshot"
                        ],
                        installed_version_after_snapshot=pkg_dict[
                            "installed_version_after_snapshot"
                        ],
                        requested_version_snapshot=pkg_dict[
                            "requested_version_snapshot"
                        ],
                        target_rollback_version=pkg_dict["target_rollback_version"],
                        package_outcome_snapshot=pkg_dict["package_outcome_snapshot"],
                        state=pkg_dict["state"],
                        refusal_reason=pkg_dict["refusal_reason"],
                        refusal_details=pkg_dict["refusal_details"],
                        content_evidence=pkg_dict["content_evidence"],
                        command_plan=pkg_dict["command_plan"],
                        evaluated_at=current_now,
                    )
                )
            else:
                existing_pkg.execution_host_package_id = pkg_dict[
                    "execution_host_package_id"
                ]
                existing_pkg.package_manager_family_snapshot = pkg_dict[
                    "package_manager_family_snapshot"
                ]
                existing_pkg.installed_version_before_snapshot = pkg_dict[
                    "installed_version_before_snapshot"
                ]
                existing_pkg.installed_version_after_snapshot = pkg_dict[
                    "installed_version_after_snapshot"
                ]
                existing_pkg.requested_version_snapshot = pkg_dict[
                    "requested_version_snapshot"
                ]
                existing_pkg.target_rollback_version = pkg_dict[
                    "target_rollback_version"
                ]
                existing_pkg.package_outcome_snapshot = pkg_dict[
                    "package_outcome_snapshot"
                ]
                existing_pkg.state = pkg_dict["state"]
                existing_pkg.refusal_reason = pkg_dict["refusal_reason"]
                existing_pkg.refusal_details = pkg_dict["refusal_details"]
                existing_pkg.content_evidence = pkg_dict["content_evidence"]
                existing_pkg.command_plan = pkg_dict["command_plan"]
                existing_pkg.evaluated_at = current_now

        # Drop per-package rows for packages no longer in the current
        # evidence set (e.g. a PRA-171 execution-host package row was
        # archived between evaluates).
        stale_packages = [
            existing_packages[name]
            for name in existing_packages
            if name not in seen_package_names
        ]
        for stale in stale_packages:
            db.delete(stale)
        db.flush()

    # Drop host rows that no longer correspond to an execution-host
    # (e.g. a host row was deleted between evaluates). Cascade
    # handles their package rows.
    stale_hosts = [
        existing_hosts[hid] for hid in existing_hosts if hid not in seen_host_ids
    ]
    for stale in stale_hosts:
        db.delete(stale)
    db.flush()
    db.commit()
    db.refresh(rollback_row)

    safe_emit(
        action=AUDIT_ROLLBACK_FEASIBILITY_COMPUTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution_rollback",
        target_id=str(rollback_row.id),
        context={
            "execution_id": execution.id,
            "plan_id": execution.plan_id,
            "state": rollback_row.state,
            "host_count": feasibility_summary["host_count"],
            "package_count": feasibility_summary["package_count"],
            "host_counts_by_state": feasibility_summary["host_counts_by_state"],
            "package_counts_by_state": feasibility_summary["package_counts_by_state"],
            "evaluated_at": utc_iso(current_now),
        },
    )
    return rollback_row


# ---------------------------------------------------------------------------
# Public API — read
# ---------------------------------------------------------------------------


def get_rollback_for_execution(
    db: Session, execution_id: int
) -> Tuple[
    PatchUpdateExecution,
    Optional[PatchUpdateExecutionRollback],
    List[PatchUpdateExecutionRollbackHost],
    Dict[int, List[PatchUpdateExecutionRollbackPackage]],
]:
    """Return ``(execution, rollback_or_none, host_rows,
    packages_by_host_row_id)`` for the per-execution read endpoint.

    Returns ``None`` for the rollback row when no evaluation has been
    run yet — the read surface stays callable so the operator UI can
    decide whether to show an "Evaluate rollback feasibility"
    affordance without a separate round-trip.

    Raises :class:`PatchUpdateRollbackError` (with "not found"
    wording) when the execution id does not exist; the route layer
    maps that to 404.
    """
    execution = _require_execution(db, execution_id)
    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )
    if rollback_row is None:
        return execution, None, [], {}

    host_rows: List[PatchUpdateExecutionRollbackHost] = (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rollback_row.id)
        .order_by(
            PatchUpdateExecutionRollbackHost.wave_index.asc(),
            PatchUpdateExecutionRollbackHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionRollbackHost.id.asc(),
        )
        .all()
    )
    host_ids = [h.id for h in host_rows]
    packages_by_host: Dict[int, List[PatchUpdateExecutionRollbackPackage]] = {
        hid: [] for hid in host_ids
    }
    if host_ids:
        for row in (
            db.query(PatchUpdateExecutionRollbackPackage)
            .filter(PatchUpdateExecutionRollbackPackage.rollback_host_id.in_(host_ids))
            .order_by(
                PatchUpdateExecutionRollbackPackage.rollback_host_id.asc(),
                PatchUpdateExecutionRollbackPackage.package_name.asc(),
            )
            .all()
        ):
            packages_by_host.setdefault(row.rollback_host_id, []).append(row)
    return execution, rollback_row, host_rows, packages_by_host


def list_rollback_host_packages(
    db: Session, rollback_host_id: int
) -> Tuple[
    PatchUpdateExecutionRollbackHost,
    List[PatchUpdateExecutionRollbackPackage],
]:
    """Return ``(host_row, package_rows)`` for one rollback host.

    Used by the per-host package drill-down route. Raises
    :class:`PatchUpdateRollbackError` (with "not found" wording)
    when the host id does not exist.
    """
    host_row = (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.id == rollback_host_id)
        .first()
    )
    if host_row is None:
        raise PatchUpdateRollbackError(f"rollback host id={rollback_host_id} not found")
    package_rows = (
        db.query(PatchUpdateExecutionRollbackPackage)
        .filter(PatchUpdateExecutionRollbackPackage.rollback_host_id == host_row.id)
        .order_by(PatchUpdateExecutionRollbackPackage.package_name.asc())
        .all()
    )
    return host_row, package_rows


def get_plan_rollback_summary(
    db: Session, plan_id: int
) -> Tuple[
    PatchUpdatePlan,
    List[Tuple[PatchUpdateExecution, Optional[PatchUpdateExecutionRollback]]],
    Dict[str, Any],
]:
    """Return ``(plan, [(execution, rollback_or_none), ...],
    aggregate_summary)`` for the plan-scoped read endpoint.

    Walks every execution that has been started for ``plan_id`` and
    pairs each with its rollback header row (or ``None`` when no
    evaluation has run). The aggregate summary rolls across every
    *evaluated* rollback so a plan-detail UI can render
    "N feasible packages across the plan" without a second
    round-trip.

    Raises :class:`PatchUpdateRollbackError` when the plan id does
    not exist; the route layer maps "not found" wording to 404.
    """
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdateRollbackError(f"patch update plan id={plan_id} not found")

    executions: List[PatchUpdateExecution] = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan.id)
        .order_by(PatchUpdateExecution.started_at.asc(), PatchUpdateExecution.id.asc())
        .all()
    )
    if not executions:
        return (
            plan,
            [],
            {
                "execution_count": 0,
                "evaluated_count": 0,
                "host_count": 0,
                "host_counts_by_state": {
                    s: 0 for s in sorted(VALID_ROLLBACK_HOST_STATES)
                },
                "package_count": 0,
                "package_counts_by_state": {
                    s: 0 for s in sorted(VALID_ROLLBACK_PACKAGE_STATES)
                },
                "refusal_counts": {},
            },
        )

    execution_ids = [e.id for e in executions]
    rollback_rows = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id.in_(execution_ids))
        .all()
    )
    by_execution: Dict[int, PatchUpdateExecutionRollback] = {
        r.execution_id: r for r in rollback_rows
    }

    pairs: List[Tuple[PatchUpdateExecution, Optional[PatchUpdateExecutionRollback]]] = [
        (e, by_execution.get(e.id)) for e in executions
    ]

    aggregate = {
        "execution_count": len(executions),
        "evaluated_count": sum(
            1 for r in rollback_rows if r.state == ROLLBACK_PLAN_STATE_EVALUATED
        ),
        "host_count": 0,
        "host_counts_by_state": {s: 0 for s in sorted(VALID_ROLLBACK_HOST_STATES)},
        "package_count": 0,
        "package_counts_by_state": {
            s: 0 for s in sorted(VALID_ROLLBACK_PACKAGE_STATES)
        },
        "refusal_counts": {},
    }
    for r in rollback_rows:
        summary = dict(r.feasibility_summary or {})
        aggregate["host_count"] += int(summary.get("host_count") or 0)
        aggregate["package_count"] += int(summary.get("package_count") or 0)
        for state, count in (summary.get("host_counts_by_state") or {}).items():
            aggregate["host_counts_by_state"][state] = aggregate[
                "host_counts_by_state"
            ].get(state, 0) + int(count)
        for state, count in (summary.get("package_counts_by_state") or {}).items():
            aggregate["package_counts_by_state"][state] = aggregate[
                "package_counts_by_state"
            ].get(state, 0) + int(count)
        for reason, count in (summary.get("refusal_counts") or {}).items():
            aggregate["refusal_counts"][reason] = aggregate["refusal_counts"].get(
                reason, 0
            ) + int(count)
    aggregate["refusal_counts"] = dict(sorted(aggregate["refusal_counts"].items()))
    return plan, pairs, aggregate


# ---------------------------------------------------------------------------
# PRA-173 slice 2: rollback approval request + vote wrapper.
#
# Wires the existing PRA-161 patch_approval_service primitive
# (``subject_kind='rollback'``) to the rollback feasibility
# artifact. Slice 2 boundaries:
#
# * ``request_rollback_approval`` materializes a ``PatchApproval``
#   row, links it to the rollback header via
#   :class:`PatchUpdateExecutionRollbackApproval`, and freezes the
#   moment-in-time command plans (per feasible package) into
#   ``frozen_plan_snapshot``. Idempotent: if a non-terminal
#   approval link already exists for this rollback, return it
#   without creating a duplicate.
#
# * ``record_rollback_approval_vote`` wraps
#   ``patch_approval_service.record_vote`` and emits
#   ``patch_rollback.approved`` / ``patch_rollback.rejected`` on
#   the terminal transition. Mirrors the
#   ``patch_update_plan_service.record_approval_vote`` shape so
#   the audit boundary stays at the rollback-service layer.
#
# **No dispatch.** Approval transitions DO NOT trigger rollback
# execution. The PRA-161 lock ("patch_approval_service does not
# auto-execute on threshold") is preserved.
# ---------------------------------------------------------------------------


def _require_user(db: Session, user_id: int) -> None:
    """Fast guard so the route layer returns 422 (semantic error)
    rather than letting the FK insert below fail with an opaque
    SQLAlchemy error."""
    if not db.query(User.id).filter(User.id == user_id).first():
        raise PatchUpdateRollbackError(
            f"actor_user_id={user_id} does not reference a user"
        )


def _latest_rollback_approval_link(
    db: Session, rollback_id: int
) -> Optional[PatchUpdateExecutionRollbackApproval]:
    """Return the most-recently-requested approval link for a
    rollback, or None when no approval has ever been requested."""
    return (
        db.query(PatchUpdateExecutionRollbackApproval)
        .filter(PatchUpdateExecutionRollbackApproval.rollback_id == rollback_id)
        .order_by(
            PatchUpdateExecutionRollbackApproval.requested_at.desc(),
            PatchUpdateExecutionRollbackApproval.id.desc(),
        )
        .first()
    )


def _build_frozen_plan_snapshot(db: Session, rollback_id: int) -> Dict[str, Any]:
    """Snapshot every feasible package row's ``command_plan`` into
    one JSONB blob. Slice 3 dispatch reads this exact shape (not the
    live per-package columns) so re-evaluate between request and
    vote cannot silently rewrite the bytes operators voted on.

    Fail-closed contract (Slice 2a fix): if any
    feasible package row is missing its stored ``command_plan``
    (e.g. a pre-Slice-2 rollback artifact whose JSONB column was
    never populated, or a future regression in the evaluate
    path), raise :class:`PatchUpdateRollbackError` rather than
    silently skip the row. Approving an empty / partial snapshot
    would mean operators sign off on commands they never saw,
    which violates the "the plan operators approved is the plan
    that runs" lock. The caller (``request_rollback_approval``)
    will surface this as a 422 instructing the operator to
    re-evaluate first.
    """
    host_rows: List[PatchUpdateExecutionRollbackHost] = (
        db.query(PatchUpdateExecutionRollbackHost)
        .filter(PatchUpdateExecutionRollbackHost.rollback_id == rollback_id)
        .order_by(
            PatchUpdateExecutionRollbackHost.wave_index.asc(),
            PatchUpdateExecutionRollbackHost.system_id_snapshot.asc().nullsfirst(),
            PatchUpdateExecutionRollbackHost.id.asc(),
        )
        .all()
    )
    snapshot_hosts: List[Dict[str, Any]] = []
    total_feasible = 0
    missing_plan_refs: List[Dict[str, Any]] = []
    for host in host_rows:
        pkg_rows = (
            db.query(PatchUpdateExecutionRollbackPackage)
            .filter(
                PatchUpdateExecutionRollbackPackage.rollback_host_id == host.id,
                PatchUpdateExecutionRollbackPackage.state
                == ROLLBACK_PACKAGE_STATE_FEASIBLE,
            )
            .order_by(PatchUpdateExecutionRollbackPackage.package_name.asc())
            .all()
        )
        feasible_packages: List[Dict[str, Any]] = []
        for pkg in pkg_rows:
            if pkg.command_plan is None:
                # Slice 2a fail-closed: never silently skip a
                # feasible row that lacks a command plan. Record
                # for the structured error and continue collecting
                # so the operator sees every missing row in one go.
                missing_plan_refs.append(
                    {
                        "rollback_package_id": pkg.id,
                        "rollback_host_id": host.id,
                        "package_name": pkg.package_name,
                    }
                )
                continue
            feasible_packages.append(
                {
                    "rollback_package_id": pkg.id,
                    "package_name": pkg.package_name,
                    "target_rollback_version": pkg.target_rollback_version,
                    "package_manager_family": pkg.package_manager_family_snapshot,
                    "command_plan": dict(pkg.command_plan),
                }
            )
        total_feasible += len(feasible_packages)
        snapshot_hosts.append(
            {
                "rollback_host_id": host.id,
                "execution_host_id": host.execution_host_id,
                "system_id_snapshot": host.system_id_snapshot,
                "system_hostname_snapshot": host.system_hostname_snapshot,
                "wave_index": host.wave_index,
                "host_state": host.state,
                "feasible_packages": feasible_packages,
            }
        )

    if missing_plan_refs:
        # Refuse loudly so a pre-Slice-2 rollback artifact (or any
        # future regression that lets a feasible row exist with
        # command_plan=None) cannot be approved as an empty /
        # partial snapshot. The operator-facing message names
        # every missing row so the fix is a single re-evaluate.
        names = sorted({m["package_name"] for m in missing_plan_refs})
        raise PatchUpdateRollbackError(
            "cannot freeze rollback plan snapshot: "
            f"{len(missing_plan_refs)} feasible package row(s) have no "
            f"stored command_plan ({', '.join(names)}); re-evaluate the "
            "rollback to render command plans for every feasible package "
            "before requesting approval"
        )
    return {
        "snapshot_version": 1,
        "captured_at": utc_iso(datetime.utcnow()),
        "feasible_package_count": total_feasible,
        "hosts": snapshot_hosts,
    }


def request_rollback_approval(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    required_approvals: int = 1,
    expires_at: Optional[datetime] = None,
    comment: Optional[str] = None,
) -> Tuple[
    PatchUpdateExecutionRollback,
    PatchUpdateExecutionRollbackApproval,
    PatchApproval,
]:
    """Create or reuse a rollback-scoped approval request.

    Refuses (route 422) when:

    * the parent execution does not exist (404 via "not found"
      wording);
    * no rollback evaluation has been run yet for this execution
      (call ``evaluate_rollback_feasibility`` first);
    * the rollback header is ``refused`` (e.g.
      ``execution_not_terminal``) — there is nothing to approve;
    * the rollback has zero feasible packages — there is nothing to
      run, so requesting approval would be misleading.

    Idempotent: if the most-recent approval link for the rollback
    is still ``pending``, return it instead of creating a duplicate
    ``PatchApproval`` row. A terminal (approved / rejected /
    expired) link does NOT block re-request — operators can ask
    for a fresh vote after a rejection.

    Emits :data:`AUDIT_ROLLBACK_REQUESTED` via ``safe_emit`` no
    ``db=`` (per the session-boundary lock). NO dispatch / no
    execution / no auto-approval — caller polls
    ``get_rollback_approval_status`` and the dispatch slice
    (future) decides whether to run.
    """
    _require_user(db, actor_user_id)
    execution = _require_execution(db, execution_id)

    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )
    if rollback_row is None:
        raise PatchUpdateRollbackError(
            f"execution {execution_id} has no rollback feasibility artifact; "
            "evaluate it first"
        )
    if rollback_row.state != ROLLBACK_PLAN_STATE_EVALUATED:
        raise PatchUpdateRollbackError(
            f"rollback {rollback_row.id} is in state {rollback_row.state!r}; "
            f"only {ROLLBACK_PLAN_STATE_EVALUATED!r} rollbacks may request "
            "approval"
        )

    summary = dict(rollback_row.feasibility_summary or {})
    feasible_count = int(
        (summary.get("package_counts_by_state") or {}).get(
            ROLLBACK_PACKAGE_STATE_FEASIBLE, 0
        )
    )
    if feasible_count <= 0:
        raise PatchUpdateRollbackError(
            f"rollback {rollback_row.id} has zero feasible packages; "
            "nothing to approve"
        )

    # Idempotency check — reuse a still-pending link if one exists.
    existing_link = _latest_rollback_approval_link(db, rollback_row.id)
    if existing_link is not None:
        existing_approval = (
            db.query(PatchApproval)
            .filter(PatchApproval.id == existing_link.approval_id)
            .first()
        )
        if (
            existing_approval is not None
            and existing_approval.status == patch_approval_service.STATUS_PENDING
        ):
            return rollback_row, existing_link, existing_approval

    # Fresh request: freeze the current command plans into a
    # snapshot the dispatch slice (and the audit trail) will read.
    frozen = _build_frozen_plan_snapshot(db, rollback_row.id)

    approval = patch_approval_service.request_approval(
        db,
        subject_kind="rollback",
        subject_id=rollback_row.id,
        requested_by=actor_user_id,
        required_approvals=required_approvals,
        expires_at=expires_at,
        comment=comment,
    )

    now = datetime.utcnow()
    link = PatchUpdateExecutionRollbackApproval(
        rollback_id=rollback_row.id,
        approval_id=approval.id,
        requested_by=actor_user_id,
        requested_at=now,
        frozen_plan_snapshot=frozen,
    )
    db.add(link)
    db.commit()
    db.refresh(link)

    safe_emit(
        action=AUDIT_ROLLBACK_REQUESTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_execution_rollback",
        target_id=str(rollback_row.id),
        context={
            "execution_id": execution.id,
            "plan_id": execution.plan_id,
            "approval_id": approval.id,
            "rollback_approval_link_id": link.id,
            "required_approvals": approval.required_approvals,
            "feasible_package_count": feasible_count,
            "requested_at": utc_iso(now),
        },
    )
    return rollback_row, link, approval


def record_rollback_approval_vote(
    db: Session,
    execution_id: int,
    *,
    actor_user_id: int,
    decision: str,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    comment: Optional[str] = None,
) -> Dict[str, Any]:
    """Record one approve/reject vote against the rollback's most
    recent pending approval row.

    Wraps :func:`patch_approval_service.record_vote` so the
    PRA-161 voting semantics (multi-distinct-vote spine,
    reject-shorts, expired-on-access) apply unchanged, then emits
    :data:`AUDIT_ROLLBACK_APPROVED` / :data:`AUDIT_ROLLBACK_REJECTED`
    when the vote drives a terminal transition. NO dispatch — the
    dispatch slice (future) is the only path that runs anything.

    Refuses (route 422) when:

    * the parent execution does not exist (404 wording);
    * no rollback artifact / approval link has been requested;
    * the latest approval link's approval row is not ``pending``
      (already approved / rejected / expired);
    * ``decision`` is not ``approve`` or ``reject``.
    """
    _require_user(db, actor_user_id)
    execution = _require_execution(db, execution_id)
    if decision not in {"approve", "reject"}:
        raise PatchUpdateRollbackError("decision must be 'approve' or 'reject'")

    rollback_row = (
        db.query(PatchUpdateExecutionRollback)
        .filter(PatchUpdateExecutionRollback.execution_id == execution.id)
        .first()
    )
    if rollback_row is None:
        raise PatchUpdateRollbackError(
            f"execution {execution_id} has no rollback feasibility artifact; "
            "evaluate it first"
        )

    link = _latest_rollback_approval_link(db, rollback_row.id)
    if link is None:
        raise PatchUpdateRollbackError(
            f"rollback {rollback_row.id} has no approval link; call "
            "request_rollback_approval first"
        )

    approval = (
        db.query(PatchApproval).filter(PatchApproval.id == link.approval_id).first()
    )
    if approval is None:
        raise PatchUpdateRollbackError(
            f"rollback approval link {link.id} references missing approval "
            f"row {link.approval_id}"
        )
    if approval.status != patch_approval_service.STATUS_PENDING:
        raise PatchUpdateRollbackError(
            f"rollback {rollback_row.id} approval row is in status "
            f"{approval.status!r}; only pending approvals may receive new "
            "votes"
        )

    try:
        result = patch_approval_service.record_vote(
            db,
            approval_id=approval.id,
            user_id=actor_user_id,
            decision=decision,
            comment=comment,
        )
    except patch_approval_service.PatchApprovalVoteError as exc:
        raise PatchUpdateRollbackError(str(exc)) from exc

    new_status = result.get("status")

    if new_status == patch_approval_service.STATUS_APPROVED:
        safe_emit(
            action=AUDIT_ROLLBACK_APPROVED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_update_execution_rollback",
            target_id=str(rollback_row.id),
            context={
                "execution_id": execution.id,
                "plan_id": execution.plan_id,
                "approval_id": approval.id,
                "rollback_approval_link_id": link.id,
                "via": "vote",
                "required_approvals": approval.required_approvals,
                "comment": comment,
            },
        )
    elif new_status == patch_approval_service.STATUS_REJECTED:
        safe_emit(
            action=AUDIT_ROLLBACK_REJECTED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_update_execution_rollback",
            target_id=str(rollback_row.id),
            context={
                "execution_id": execution.id,
                "plan_id": execution.plan_id,
                "approval_id": approval.id,
                "rollback_approval_link_id": link.id,
                "via": "vote",
                "comment": comment,
            },
        )

    return {
        "execution_id": execution.id,
        "rollback_id": rollback_row.id,
        "rollback_approval_link_id": link.id,
        "approval_id": approval.id,
        "status": new_status,
        "approves": result.get("approves"),
        "required": result.get("required"),
    }


def get_rollback_approval_summary(
    db: Session, rollback_id: int
) -> Optional[Dict[str, Any]]:
    """Return the rollback's most-recent approval link + status, or
    ``None`` when no approval has been requested yet.

    The read API uses this to surface approval state on the
    rollback detail payload without a separate round-trip. Reads
    the ``patch_approvals`` row directly (not via
    :func:`patch_approval_service.get_approval_status`) because we
    also need the link metadata (``frozen_plan_snapshot``,
    ``requested_at``) the join table carries.
    """
    link = _latest_rollback_approval_link(db, rollback_id)
    if link is None:
        return None
    approval = (
        db.query(PatchApproval).filter(PatchApproval.id == link.approval_id).first()
    )
    if approval is None:
        # Unexpected, but don't crash — surface enough to debug.
        return {
            "rollback_approval_link_id": link.id,
            "approval_id": link.approval_id,
            "status": None,
            "requested_by": link.requested_by,
            "requested_at": link.requested_at,
            "frozen_plan_snapshot": dict(link.frozen_plan_snapshot or {}),
            "error": "approval row missing",
        }
    return {
        "rollback_approval_link_id": link.id,
        "approval_id": approval.id,
        "status": approval.status,
        "required_approvals": approval.required_approvals,
        "expires_at": approval.expires_at,
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "requested_by": link.requested_by,
        "requested_at": link.requested_at,
        "frozen_plan_snapshot": dict(link.frozen_plan_snapshot or {}),
    }
