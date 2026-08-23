"""Patch update plan service (PRA-164 slice 1).

Dry-run substrate that turns an existing patch policy + (optional)
explicit target-host list into an auditable plan with per-host wave
assignments. **No execution semantics.** This service does not call
package managers, run SSH, fetch advisories, request approvals,
schedule work, run probes, reboot, rollback, rebuild/re-sign mirrors,
or touch airgap import/export — those land in later PRA-164 slices
(2/3/4) and PRA-171/172/173.

Resolver behavior is layered on top of the already-shipped subsystems:

* :func:`patch_policy_service.resolve_effective_policy` decides which
  policy is in force for a host (direct → static-group → smart-group
  → fleet-default, with same-tier conflict raised as
  :class:`EffectivePolicyConflict`). Slice 1 maps that exception to
  a structured blocked row, never a 5xx through the route.
* :func:`patch_ring_service.resolve_effective_ring` returns one of
  ``resolved`` / ``no_ring`` / ``conflict`` for staged plans.
* :func:`patch_policy_service.list_policy_rings` provides the ordered
  policy-bound ring set used for ``wave_index`` for staged plans.
* :class:`ContentProfileService.resolve_effective` returns
  ``resolved`` / ``no_profile`` / ``conflict``; slice 1 only
  snapshots that context — content availability is checked in a
  later slice.

Block reasons are structured: ``[{"code": "...", "details": {...}}]``
so the slice 4 UI can render them without parsing prose.

Audit emission goes through ``safe_emit`` with no ``db=`` argument so
it opens its own ``SessionLocal`` per
``feedback_safe_emit_session_boundary.md``. A plan spans a set of
hosts and has no single subject host, so every plan event passes its
resolvable target systems as ``related_system_ids`` and stays
discoverable from each affected host's audit history without any one
of them being recorded as the plan's target. Reserved event-type
constants:

* ``patch_update_plan.created`` — emitted on draft/blocked plan create.
* ``patch_update_plan.refreshed`` — emitted on rebuild of an existing
  ``draft`` / ``blocked`` plan.
* ``patch_update_plan.canceled`` — emitted on cancel of a
  ``draft`` / ``blocked`` plan.

The remaining ``patch_plan.*`` events reserved by PRA-161's design
locks (``approval_requested``, ``approved``, ``rejected``,
``scheduled``, ``superseded``) are emitted by the slices that own
those state transitions and are NOT touched here.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import (
    AuditEvent,
    HostFacts,
    MaintenanceWindow,
    MirrorSyncRun,
    Package,
    PackageUpdate,
    PatchAdvisory,
    PatchAdvisoryHostApplicability,
    PatchApproval,
    PatchPolicy,
    PatchPolicyRingBinding,
    PatchRing,
    PatchUpdateExecution,
    PatchUpdatePlan,
    PatchUpdatePlanApproval,
    PatchUpdatePlanHost,
    PatchUpdatePlanPreflightSnapshot,
    PatchUpdatePlanSelectedPackage,
    System,
    User,
)
from . import (
    mirror_package_index,
    patch_approval_service,
    patch_policy_service,
    patch_ring_service,
    patch_scope,
)
from .audit_event_service import safe_emit
from .content_profile_service import ContentProfileService
from .patch_policy_service import RESOLUTION_NO_POLICY, EffectivePolicyConflict
from .patch_ring_service import STATUS_CONFLICT, STATUS_NO_RING, STATUS_RESOLVED

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception class — kept independent from patch_policy / patch_ring /
# approval surfaces (M16 implementation lock #3 carry-forward).
# ---------------------------------------------------------------------------


class PatchUpdatePlanError(ValueError):
    """Raised when a plan create / refresh / cancel is rejected for
    semantic reasons (unknown id, bad state transition, request
    shape error, etc.).

    Subclasses ``ValueError`` so route layers can map the family to
    HTTP 422; "not found" wording maps to 404 by the same disambiguation
    convention used in PRA-161 / PRA-162 routes.
    """


# ---------------------------------------------------------------------------
# Vocabulary constants — DB CHECKs already enforce these; we mirror the
# strings here so service callers and tests don't reach into the model.
# ---------------------------------------------------------------------------

PLAN_STATE_DRAFT = "draft"
PLAN_STATE_AWAITING_APPROVAL = "awaiting_approval"
PLAN_STATE_APPROVED = "approved"
PLAN_STATE_SCHEDULED = "scheduled"
PLAN_STATE_BLOCKED = "blocked"
PLAN_STATE_SUPERSEDED = "superseded"
PLAN_STATE_CANCELED = "canceled"

VALID_PLAN_STATES = frozenset(
    {
        PLAN_STATE_DRAFT,
        PLAN_STATE_AWAITING_APPROVAL,
        PLAN_STATE_APPROVED,
        PLAN_STATE_SCHEDULED,
        PLAN_STATE_BLOCKED,
        PLAN_STATE_SUPERSEDED,
        PLAN_STATE_CANCELED,
    }
)

# States a slice-1 cancel is allowed to transition out of. Approval /
# scheduled / superseded transitions belong to later slices.
CANCELABLE_STATES = frozenset({PLAN_STATE_DRAFT, PLAN_STATE_BLOCKED})

# PRA-355: states a plan may be hard-deleted from — true pre-history cleanup
# only. Hard delete additionally requires ZERO approval / schedule / execution
# history (see delete_plan); those states are the only ones that can be free of
# it. ``superseded`` is deliberately NOT here: SUPERSEDE_FROM_STATES is
# {awaiting_approval, approved, scheduled}, so every superseded plan carries
# approval and/or schedule evidence and must be ARCHIVED, not deleted. Plans
# with history are retired via archive_plan (tombstone, evidence preserved).
DELETABLE_STATES = frozenset(
    {
        PLAN_STATE_DRAFT,
        PLAN_STATE_BLOCKED,
        PLAN_STATE_CANCELED,
    }
)

# Refresh applies to in-progress drafts only — once a plan has been
# approved or scheduled the snapshot is the contract for the rollout
# and must not be silently rebuilt out from under approvers.
REFRESHABLE_STATES = frozenset({PLAN_STATE_DRAFT, PLAN_STATE_BLOCKED})

PLAN_HOST_STATE_PLANNED = "planned"
PLAN_HOST_STATE_BLOCKED = "blocked"

RING_RESOLUTION_RESOLVED = "resolved"
RING_RESOLUTION_NO_RING = "no_ring"
RING_RESOLUTION_CONFLICT = "conflict"
RING_RESOLUTION_NOT_APPLICABLE = "not_applicable"

CONTENT_PROFILE_STATE_RESOLVED = "resolved"
CONTENT_PROFILE_STATE_NO_PROFILE = "no_profile"
CONTENT_PROFILE_STATE_CONFLICT = "conflict"

# ---------------------------------------------------------------------------
# Audit constants — slice 1 emits create/refreshed/canceled. The rest of
# the ``patch_plan.*`` namespace reserved in PRA-161's design locks is
# emitted by later slices that own the corresponding state transitions.
# ---------------------------------------------------------------------------

AUDIT_PLAN_CREATED = "patch_update_plan.created"
AUDIT_PLAN_REFRESHED = "patch_update_plan.refreshed"
AUDIT_PLAN_CANCELED = "patch_update_plan.canceled"
# PRA-355: hard delete for cleanup of test/pre-execution plans.
AUDIT_PLAN_DELETED = "patch_update_plan.deleted"
# PRA-355: admin archive/retire for plans WITH history — evidence-preserving
# tombstone, hidden from normal lists but fully queryable/exportable.
AUDIT_PLAN_ARCHIVED = "patch_update_plan.archived"

# Slice 2: emitted once per create / refresh recomputation when at
# least one ``planned`` host had its selection rebuilt. No emission
# when every host is ``blocked`` and selection is a no-op.
AUDIT_PLAN_SELECTION_RECOMPUTED = "patch_update_plan.selection_recomputed"

# Slice 3: emitted once per create / refresh recomputation when at
# least one ``planned`` host had its preflight rebuilt. Same
# suppress-when-all-blocked pattern as selection_recomputed.
AUDIT_PLAN_PREFLIGHT_RECOMPUTED = "patch_update_plan.preflight_recomputed"

# Slice 4: state-machine + audit-export events.
AUDIT_PLAN_APPROVAL_REQUESTED = "patch_update_plan.approval_requested"
AUDIT_PLAN_APPROVED = "patch_update_plan.approved"
AUDIT_PLAN_REJECTED = "patch_update_plan.rejected"
AUDIT_PLAN_SCHEDULED = "patch_update_plan.scheduled"
AUDIT_PLAN_SUPERSEDED = "patch_update_plan.superseded"
AUDIT_PLAN_EXPORTED = "patch_update_plan.exported"


# ---------------------------------------------------------------------------
# Slice 4 state-machine guards
# ---------------------------------------------------------------------------
#
# Slice 1 already declared the full state CHECK enum
# (draft, awaiting_approval, approved, scheduled, blocked,
# superseded, canceled). Slice 4 adds the transition rules:
#
#   draft               -> awaiting_approval  (request_approval)
#   draft               -> approved           (approve_directly,
#                                              policy.requires_approval=False)
#   awaiting_approval   -> approved           (record_approval_vote on
#                                              threshold reached)
#   awaiting_approval   -> blocked            (record_approval_vote on
#                                              reject; block_reason
#                                              ``approval_rejected``)
#   approved            -> scheduled          (schedule_plan)
#   any non-terminal    -> superseded         (supersede_plan, explicit
#                                              operator action only)
#   draft / blocked     -> canceled           (cancel_plan; Slice 1)
#
# Terminal states: canceled, superseded.
# Auto-supersede on newer-plan approval is OUT OF SCOPE for Slice 4
# (a deliberate product decision).

REQUEST_APPROVAL_FROM_STATES = frozenset({PLAN_STATE_DRAFT})
DIRECT_APPROVE_FROM_STATES = frozenset({PLAN_STATE_DRAFT})
SCHEDULE_FROM_STATES = frozenset({PLAN_STATE_APPROVED})
SUPERSEDE_FROM_STATES = frozenset(
    {
        PLAN_STATE_DRAFT,
        PLAN_STATE_AWAITING_APPROVAL,
        PLAN_STATE_APPROVED,
        PLAN_STATE_SCHEDULED,
        PLAN_STATE_BLOCKED,
    }
)

BLOCK_APPROVAL_REJECTED = "approval_rejected"


# ---------------------------------------------------------------------------
# Slice 3 preflight vocabulary (mirrors DB CHECKs)
# ---------------------------------------------------------------------------

PACKAGE_MANAGER_FAMILY_APT = "apt"
PACKAGE_MANAGER_FAMILY_DNF = "dnf"
PACKAGE_MANAGER_FAMILY_UNKNOWN = "unknown"

VALID_PACKAGE_MANAGER_FAMILIES = frozenset(
    {
        PACKAGE_MANAGER_FAMILY_APT,
        PACKAGE_MANAGER_FAMILY_DNF,
        PACKAGE_MANAGER_FAMILY_UNKNOWN,
    }
)

CONTENT_AVAILABILITY_AVAILABLE = "available"
CONTENT_AVAILABILITY_UNAVAILABLE = "unavailable"
CONTENT_AVAILABILITY_PROFILE_MISSING = "profile_missing"
CONTENT_AVAILABILITY_NOT_APPLICABLE = "not_applicable"

VALID_CONTENT_AVAILABILITY_STATES = frozenset(
    {
        CONTENT_AVAILABILITY_AVAILABLE,
        CONTENT_AVAILABILITY_UNAVAILABLE,
        CONTENT_AVAILABILITY_PROFILE_MISSING,
        CONTENT_AVAILABILITY_NOT_APPLICABLE,
    }
)

# HostFacts.package_manager → family enum mapping. Strings the agent /
# SSH collector report (apt-get, dpkg, dnf, yum, rpm, ...) collapse to
# the apt/dnf families the mirror_repos.package_family vocabulary uses.
_PACKAGE_MANAGER_TO_FAMILY = {
    "apt": PACKAGE_MANAGER_FAMILY_APT,
    "apt-get": PACKAGE_MANAGER_FAMILY_APT,
    "dpkg": PACKAGE_MANAGER_FAMILY_APT,
    "dnf": PACKAGE_MANAGER_FAMILY_DNF,
    "yum": PACKAGE_MANAGER_FAMILY_DNF,
    "rpm": PACKAGE_MANAGER_FAMILY_DNF,
}

# Distro fallback when HostFacts.package_manager is null but
# distro_id_facts is set. Keeps the mapping conservative — the
# resolver records ``unknown`` rather than guessing wrong.
_DISTRO_TO_FAMILY = {
    "ubuntu": PACKAGE_MANAGER_FAMILY_APT,
    "debian": PACKAGE_MANAGER_FAMILY_APT,
    "rhel": PACKAGE_MANAGER_FAMILY_DNF,
    "centos": PACKAGE_MANAGER_FAMILY_DNF,
    "fedora": PACKAGE_MANAGER_FAMILY_DNF,
    "rocky": PACKAGE_MANAGER_FAMILY_DNF,
    "almalinux": PACKAGE_MANAGER_FAMILY_DNF,
    "alma": PACKAGE_MANAGER_FAMILY_DNF,
    "ol": PACKAGE_MANAGER_FAMILY_DNF,
    "oraclelinux": PACKAGE_MANAGER_FAMILY_DNF,
    "amzn": PACKAGE_MANAGER_FAMILY_DNF,
    "amazonlinux": PACKAGE_MANAGER_FAMILY_DNF,
}


# ---------------------------------------------------------------------------
# Slice 2 selection-preview vocabulary (mirrors DB CHECKs)
# ---------------------------------------------------------------------------

SELECTION_REASON_POLICY_FULL = "policy_full"
SELECTION_REASON_POLICY_SECURITY_ADVISORY = "policy_security_advisory"
SELECTION_REASON_POLICY_ALLOWLIST_MATCH = "policy_allowlist_match"
SELECTION_REASON_POLICY_DENYLIST_EXCLUDED = "policy_denylist_excluded"
SELECTION_REASON_POLICY_DENYLIST_DEFAULT_SELECT = "policy_denylist_default_select"
SELECTION_REASON_NO_AVAILABLE_UPDATE = "no_available_update"
SELECTION_REASON_INVENTORY_MISSING = "inventory_missing"

VALID_SELECTION_REASONS = frozenset(
    {
        SELECTION_REASON_POLICY_FULL,
        SELECTION_REASON_POLICY_SECURITY_ADVISORY,
        SELECTION_REASON_POLICY_ALLOWLIST_MATCH,
        SELECTION_REASON_POLICY_DENYLIST_EXCLUDED,
        SELECTION_REASON_POLICY_DENYLIST_DEFAULT_SELECT,
        SELECTION_REASON_NO_AVAILABLE_UPDATE,
        SELECTION_REASON_INVENTORY_MISSING,
    }
)

SELECTION_STATE_SELECTED = "selected"
SELECTION_STATE_EXCLUDED = "excluded"
SELECTION_STATE_UNRESOLVABLE = "unresolvable"

VALID_SELECTION_STATES = frozenset(
    {
        SELECTION_STATE_SELECTED,
        SELECTION_STATE_EXCLUDED,
        SELECTION_STATE_UNRESOLVABLE,
    }
)

# Empty string is the sentinel ``package_name`` used by the
# inventory-missing placeholder row described in the slice spec. The
# partial unique on ``advisory_id_snapshot IS NULL`` ensures at most
# one such row per plan host.
INVENTORY_MISSING_PACKAGE_NAME = ""


# ---------------------------------------------------------------------------
# Block-reason codes (stable; consumed by API + UI in later slices)
# ---------------------------------------------------------------------------

BLOCK_POLICY_DISABLED = "policy_disabled"
BLOCK_STAGED_NO_RING_BINDINGS = "staged_no_ring_bindings"
BLOCK_STAGED_NO_ENABLED_RINGS = "staged_no_enabled_rings"
BLOCK_NO_TARGET_HOSTS = "no_target_hosts"

BLOCK_HOST_EFFECTIVE_POLICY_NONE = "effective_policy_none"
BLOCK_HOST_EFFECTIVE_POLICY_CONFLICT = "effective_policy_conflict"
BLOCK_HOST_EFFECTIVE_POLICY_MISMATCH = "effective_policy_mismatch"
BLOCK_HOST_RING_NO_RING = "ring_no_ring"
BLOCK_HOST_RING_CONFLICT = "ring_conflict"
BLOCK_HOST_RING_NOT_IN_POLICY_SET = "ring_not_in_policy_set"


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def _policy_snapshot(policy: PatchPolicy) -> Dict[str, Any]:
    """Capture the policy fields slice 1 audit needs to reconstruct
    what was planned even after a later policy edit.

    Per PRA-161 1a-a / 1c locks, we never serialize ORM objects
    directly — every field is named explicitly so a future column
    addition does not silently leak into the snapshot.
    """
    return {
        "id": policy.id,
        "slug": policy.slug,
        "name": policy.name,
        "scope_kind": policy.scope_kind,
        "scope_packages": list(policy.scope_packages or []),
        "reboot_policy": policy.reboot_policy,
        "rollout_cadence": policy.rollout_cadence,
        "failure_policy": policy.failure_policy,
        "requires_approval": policy.requires_approval,
        "required_approvals": policy.required_approvals,
        "enabled": policy.enabled,
        "is_fleet_default": policy.is_fleet_default,
        "maintenance_window_id": policy.maintenance_window_id,
        "reboot_window_id": policy.reboot_window_id,
    }


def _ring_sequence_snapshot(
    ordered_rings: Sequence[Tuple[PatchPolicyRingBinding, PatchRing]],
) -> List[Dict[str, Any]]:
    """Snapshot the ordered policy-bound ring set in canonical
    rollout order (canary → pilot → prod). Disabled rings are
    included so operators can see why a wave didn't expand."""
    return [
        {
            "ring_id": ring.id,
            "ring_slug": ring.slug,
            "ring_name": ring.name,
            "sort_order": ring.sort_order,
            "enabled": ring.enabled,
        }
        for _binding, ring in ordered_rings
    ]


def _request_snapshot(
    *,
    policy_id: int,
    requested_target_system_ids: Optional[List[int]],
    name: str,
    description: Optional[str],
    scheduled_start_at: Optional[datetime],
    maintenance_window_id: Optional[int],
    reboot_window_id: Optional[int],
) -> Dict[str, Any]:
    """Capture exactly what the operator asked for so the audit row
    survives later policy/host/window changes.

    ``requested_target_system_ids`` is preserved verbatim — including
    ``None`` for "auto-select" — so a refresh can replay the original
    request shape. ``datetime`` values are isoformatted for JSONB
    portability.
    """
    return {
        "policy_id": policy_id,
        "requested_target_system_ids": (
            list(requested_target_system_ids)
            if requested_target_system_ids is not None
            else None
        ),
        "name": name,
        "description": description,
        "scheduled_start_at": (
            scheduled_start_at.isoformat() if scheduled_start_at is not None else None
        ),
        "maintenance_window_id": maintenance_window_id,
        "reboot_window_id": reboot_window_id,
    }


def _ring_summary(ring: PatchRing) -> Dict[str, Any]:
    return {
        "ring_id": ring.id,
        "ring_slug": ring.slug,
        "ring_name": ring.name,
        "sort_order": ring.sort_order,
        "enabled": ring.enabled,
    }


# ---------------------------------------------------------------------------
# Per-host resolver
# ---------------------------------------------------------------------------


def _resolve_host_row(
    db: Session,
    *,
    host: System,
    policy: PatchPolicy,
    enabled_ring_order: List[PatchRing],
    enabled_ring_index: Dict[int, int],
    profile_service: ContentProfileService,
    explicit_target: bool,
) -> Dict[str, Any]:
    """Compute one ``PatchUpdatePlanHost`` row's worth of data.

    Returns a dict suitable for ``PatchUpdatePlanHost(**row)`` (the
    caller adds ``plan_id`` after the plan is persisted).

    Effective-policy mismatches ``->`` blocked row regardless of
    whether the host was an explicit target or auto-discovered. The
    ``explicit_target`` flag is recorded in the block-reason details
    so the UI can highlight "you asked for this host but the
    resolver disagreed" cases.
    """
    block_reasons: List[Dict[str, Any]] = []

    # ---- effective policy ------------------------------------------------
    policy_resolution_kind = RESOLUTION_NO_POLICY
    policy_id_snapshot: Optional[int] = None
    policy_slug_snapshot: Optional[str] = None
    try:
        resolved_policy, kind = patch_policy_service.resolve_effective_policy(
            db, host.id
        )
    except EffectivePolicyConflict as exc:
        block_reasons.append(
            {
                "code": BLOCK_HOST_EFFECTIVE_POLICY_CONFLICT,
                "details": {
                    "tier": exc.tier,
                    "policies": [
                        {"id": pid, "slug": slug} for pid, slug in exc.policies
                    ],
                    "explicit_target": explicit_target,
                },
            }
        )
        resolved_policy = None
        kind = "conflict"
        # ``policy_resolution_kind`` is one of the DB-CHECK enums; map a
        # conflict at any tier to ``no_policy`` so we never violate the
        # CHECK while still surfacing the truth via block_reasons.
        policy_resolution_kind = RESOLUTION_NO_POLICY
    else:
        if resolved_policy is not None:
            policy_resolution_kind = kind
            policy_id_snapshot = resolved_policy.id
            policy_slug_snapshot = resolved_policy.slug

    if resolved_policy is None and not block_reasons:
        block_reasons.append(
            {
                "code": BLOCK_HOST_EFFECTIVE_POLICY_NONE,
                "details": {"explicit_target": explicit_target},
            }
        )
    elif resolved_policy is not None and resolved_policy.id != policy.id:
        block_reasons.append(
            {
                "code": BLOCK_HOST_EFFECTIVE_POLICY_MISMATCH,
                "details": {
                    "requested_policy_id": policy.id,
                    "requested_policy_slug": policy.slug,
                    "effective_policy_id": resolved_policy.id,
                    "effective_policy_slug": resolved_policy.slug,
                    "effective_policy_resolution_kind": kind,
                    "explicit_target": explicit_target,
                },
            }
        )

    # ---- ring placement --------------------------------------------------
    ring_resolution_status = RING_RESOLUTION_NOT_APPLICABLE
    ring_id_snapshot: Optional[int] = None
    ring_slug_snapshot: Optional[str] = None
    ring_name_snapshot: Optional[str] = None
    ring_sort_order_snapshot: Optional[int] = None
    ring_source_tier: Optional[str] = None
    wave_index = 0

    is_staged = policy.rollout_cadence == "staged"
    if is_staged:
        ring_result = patch_ring_service.resolve_effective_ring(db, host.id)
        ring_resolution_status = ring_result.status
        ring_source_tier = ring_result.source_tier

        if ring_result.status == STATUS_NO_RING:
            block_reasons.append(
                {
                    "code": BLOCK_HOST_RING_NO_RING,
                    "details": {
                        "explicit_target": explicit_target,
                    },
                }
            )
        elif ring_result.status == STATUS_CONFLICT:
            block_reasons.append(
                {
                    "code": BLOCK_HOST_RING_CONFLICT,
                    "details": {
                        "tier": ring_result.source_tier,
                        "candidates": [
                            _ring_summary(r) for r in ring_result.candidates
                        ],
                        "explicit_target": explicit_target,
                    },
                }
            )
        elif ring_result.status == STATUS_RESOLVED and ring_result.ring is not None:
            ring = ring_result.ring
            ring_id_snapshot = ring.id
            ring_slug_snapshot = ring.slug
            ring_name_snapshot = ring.name
            ring_sort_order_snapshot = ring.sort_order
            if ring.id in enabled_ring_index:
                wave_index = enabled_ring_index[ring.id]
            else:
                block_reasons.append(
                    {
                        "code": BLOCK_HOST_RING_NOT_IN_POLICY_SET,
                        "details": {
                            "ring": _ring_summary(ring),
                            "policy_id": policy.id,
                            "policy_slug": policy.slug,
                            "policy_ring_set": [
                                _ring_summary(r) for r in enabled_ring_order
                            ],
                            "explicit_target": explicit_target,
                        },
                    }
                )

    # ---- content-profile context ----------------------------------------
    effective_profile = profile_service.resolve_effective(host.id)
    content_profile_state = effective_profile.state
    content_profile_id_snapshot: Optional[int] = None
    content_profile_slug_snapshot: Optional[str] = None
    content_profile_display_name_snapshot: Optional[str] = None
    content_profile_package_family_snapshot: Optional[str] = None
    content_profile_conflict_snapshot: List[Dict[str, Any]] = []

    if (
        content_profile_state == CONTENT_PROFILE_STATE_RESOLVED
        and effective_profile.profile is not None
    ):
        binding = effective_profile.profile
        content_profile_id_snapshot = binding.profile_id
        content_profile_slug_snapshot = binding.profile_slug
        content_profile_display_name_snapshot = binding.profile_display_name
        # Look up package_family on the underlying ContentProfile row so
        # later slices' content availability checks have it without
        # re-resolving. ``ResolvedBinding`` doesn't carry it.
        from ..db.models import ContentProfile  # local import: avoid cycles

        family_row = (
            db.query(ContentProfile.package_family)
            .filter(ContentProfile.id == binding.profile_id)
            .first()
        )
        if family_row is not None:
            content_profile_package_family_snapshot = family_row[0]
    elif content_profile_state == CONTENT_PROFILE_STATE_CONFLICT:
        content_profile_conflict_snapshot = [
            {
                "profile_id": b.profile_id,
                "profile_slug": b.profile_slug,
                "profile_display_name": b.profile_display_name,
                "via_kind": b.via_kind,
                "via_id": b.via_id,
                "via_label": b.via_label,
            }
            for b in effective_profile.conflict_bindings
        ]

    state = PLAN_HOST_STATE_BLOCKED if block_reasons else PLAN_HOST_STATE_PLANNED

    return {
        "system_id": host.id,
        "system_hostname_snapshot": getattr(host, "hostname", None),
        "policy_id_snapshot": policy_id_snapshot,
        "policy_slug_snapshot": policy_slug_snapshot,
        "policy_resolution_kind": policy_resolution_kind,
        "ring_id_snapshot": ring_id_snapshot,
        "ring_slug_snapshot": ring_slug_snapshot,
        "ring_name_snapshot": ring_name_snapshot,
        "ring_sort_order_snapshot": ring_sort_order_snapshot,
        "ring_source_tier": ring_source_tier,
        "ring_resolution_status": ring_resolution_status,
        "wave_index": wave_index,
        "content_profile_state": content_profile_state,
        "content_profile_id_snapshot": content_profile_id_snapshot,
        "content_profile_slug_snapshot": content_profile_slug_snapshot,
        "content_profile_display_name_snapshot": (
            content_profile_display_name_snapshot
        ),
        "content_profile_package_family_snapshot": (
            content_profile_package_family_snapshot
        ),
        "content_profile_conflict_snapshot": content_profile_conflict_snapshot,
        "state": state,
        "block_reasons": block_reasons,
    }


# ---------------------------------------------------------------------------
# Candidate-host enumeration
# ---------------------------------------------------------------------------


def _auto_discover_targets(db: Session, policy: PatchPolicy) -> List[System]:
    """Return systems whose effective patch policy resolves to
    ``policy.id``.

    Brute-force resolver call per system. Slice 1 is the substrate;
    if this becomes hot in production a future optimization can
    replace it with a join, but it is correct and aligned with the
    existing resolver semantics.
    """
    systems = db.query(System).order_by(System.id.asc()).all()
    matches: List[System] = []
    for host in systems:
        try:
            resolved, _kind = patch_policy_service.resolve_effective_policy(db, host.id)
        except EffectivePolicyConflict:
            # Conflict hosts are not auto-included — operator must
            # name them explicitly so the conflict appears as a per-host
            # block reason rather than disappearing into a no-op.
            continue
        if resolved is not None and resolved.id == policy.id:
            matches.append(host)
    return matches


# ---------------------------------------------------------------------------
# Plan-level invariants
# ---------------------------------------------------------------------------


def _plan_level_block_reasons(
    *,
    policy: PatchPolicy,
    ordered_rings: Sequence[Tuple[PatchPolicyRingBinding, PatchRing]],
    target_hosts: Sequence[System],
) -> List[Dict[str, Any]]:
    """Compute structured plan-level blockers.

    A plan with these reasons is created in state ``blocked`` so the
    audit row exists; we never throw away the request envelope.
    """
    reasons: List[Dict[str, Any]] = []
    if not policy.enabled:
        reasons.append(
            {
                "code": BLOCK_POLICY_DISABLED,
                "details": {"policy_id": policy.id, "policy_slug": policy.slug},
            }
        )
    if policy.rollout_cadence == "staged":
        if not ordered_rings:
            reasons.append(
                {
                    "code": BLOCK_STAGED_NO_RING_BINDINGS,
                    "details": {
                        "policy_id": policy.id,
                        "policy_slug": policy.slug,
                    },
                }
            )
        elif not any(ring.enabled for _b, ring in ordered_rings):
            reasons.append(
                {
                    "code": BLOCK_STAGED_NO_ENABLED_RINGS,
                    "details": {
                        "policy_id": policy.id,
                        "policy_slug": policy.slug,
                        "ring_set": [_ring_summary(r) for _b, r in ordered_rings],
                    },
                }
            )
    if not target_hosts:
        reasons.append(
            {
                "code": BLOCK_NO_TARGET_HOSTS,
                "details": {
                    "policy_id": policy.id,
                    "policy_slug": policy.slug,
                },
            }
        )
    return reasons


# ---------------------------------------------------------------------------
# Public API — create / refresh / cancel / list / get
# ---------------------------------------------------------------------------


def _require_actor(db: Session, actor_user_id: int) -> None:
    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchUpdatePlanError(
            f"actor_user_id={actor_user_id} does not reference a user"
        )


def _validate_plan_window(
    db: Session, window_id: Optional[int], field_label: str
) -> None:
    """Existence check for plan-level MW overrides (Slice 1a fix).

    ``patch_update_plans.maintenance_window_id`` /
    ``patch_update_plans.reboot_window_id`` are FK ``ON DELETE SET NULL``,
    so an unknown id at create time would otherwise surface as a raw
    ``IntegrityError`` (HTTP 500) rather than the slice's
    "hard exceptions for unknown ids" contract. Mirror PRA-161
    ``patch_policy_service._validate_window_binding`` shape but keep
    Slice 1 to existence-only — enabled/schedule semantics already
    live on the policy's own MW bindings, and the plan-level override
    is just an audit reference until later slices consume it.
    """
    if window_id is None:
        return
    exists = (
        db.query(MaintenanceWindow.id).filter(MaintenanceWindow.id == window_id).first()
    )
    if exists is None:
        raise PatchUpdatePlanError(
            f"{field_label}={window_id} does not reference an existing "
            "maintenance window"
        )


def _resolve_inputs(
    db: Session,
    *,
    policy_id: int,
    target_system_ids: Optional[List[int]],
) -> Tuple[
    PatchPolicy,
    List[Tuple[PatchPolicyRingBinding, PatchRing]],
    List[System],
    List[int],
]:
    """Look up the policy, the ordered ring set, and resolve the
    candidate hosts.

    Returns ``(policy, ordered_rings, target_hosts, explicit_ids)``.
    ``explicit_ids`` is the de-duplicated list of explicit host ids
    in original order, or an empty list when auto-discovery was used.

    Raises :class:`PatchUpdatePlanError` for unknown policy or unknown
    explicit host ids; explicit-target validation refuses unknown ids
    rather than silently dropping them (per slice spec).
    """
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == policy_id).first()
    if policy is None:
        raise PatchUpdatePlanError(f"patch policy id={policy_id} not found")

    ordered_rings: List[Tuple[PatchPolicyRingBinding, PatchRing]] = []
    if policy.rollout_cadence == "staged":
        ordered_rings = patch_policy_service.list_policy_rings(db, policy.id)

    explicit_ids: List[int] = []
    if target_system_ids is not None:
        # Preserve order, drop duplicates. Validate every id exists; the
        # slice spec requires explicit targets never be silently dropped.
        seen = set()
        for sid in target_system_ids:
            if sid in seen:
                continue
            seen.add(sid)
            explicit_ids.append(sid)

        existing_ids = {
            row[0]
            for row in db.query(System.id).filter(System.id.in_(explicit_ids)).all()
        }
        missing = [sid for sid in explicit_ids if sid not in existing_ids]
        if missing:
            raise PatchUpdatePlanError(
                "target_system_ids reference unknown systems: "
                + ", ".join(str(sid) for sid in missing)
            )
        # Preserve caller order for downstream determinism.
        host_by_id = {
            h.id: h for h in db.query(System).filter(System.id.in_(explicit_ids)).all()
        }
        target_hosts = [host_by_id[sid] for sid in explicit_ids if sid in host_by_id]
    else:
        target_hosts = _auto_discover_targets(db, policy)

    return policy, ordered_rings, target_hosts, explicit_ids


# ---------------------------------------------------------------------------
# Slice 2: package / advisory selection preview
# ---------------------------------------------------------------------------
#
# Reads existing DB facts only — Package / PackageUpdate /
# PatchAdvisoryHostApplicability — and writes preview rows under the
# Slice 1 plan envelope. Never invokes a package manager, SSH, agent
# call, or live facts collection. Runs as part of create_plan /
# refresh_plan for every host whose state is ``planned``; ``blocked``
# hosts skip selection entirely.


def _empty_selection_summary() -> Dict[str, Any]:
    return {
        "selected": 0,
        "excluded": 0,
        "unresolvable": 0,
        "inventory_missing": False,
    }


def _summarize(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    summary = _empty_selection_summary()
    for row in rows:
        summary[row["state"]] = summary.get(row["state"], 0) + 1
        if row["selection_reason"] == SELECTION_REASON_INVENTORY_MISSING:
            summary["inventory_missing"] = True
    return summary


def _advisory_snapshot(
    advisory: Optional[PatchAdvisory],
) -> Dict[str, Any]:
    """Snapshot the advisory metadata fields the slice 4 UI / audit
    surface need without joining ``patch_advisories`` again."""
    if advisory is None:
        return {
            "advisory_id_snapshot": None,
            "advisory_source_kind_snapshot": None,
            "advisory_class_snapshot": None,
            "advisory_severity_snapshot": None,
        }
    return {
        "advisory_id_snapshot": advisory.id,
        "advisory_source_kind_snapshot": advisory.source_kind,
        "advisory_class_snapshot": advisory.advisory_class,
        "advisory_severity_snapshot": advisory.severity,
    }


def _compute_host_selection(
    db: Session,
    *,
    system_id: int,
    policy: PatchPolicy,
) -> List[Dict[str, Any]]:
    """Compute the selection-preview row dicts for one ``planned``
    host. Returns rows ready for ``PatchUpdatePlanSelectedPackage``
    construction (caller adds ``plan_host_id``).

    Reads only ``Package`` / ``PackageUpdate`` /
    ``PatchAdvisoryHostApplicability`` for ``system_id``. Never calls
    package managers, SSH, agents, or live facts collection.
    """
    installed_rows: List[Package] = (
        db.query(Package).filter(Package.system_id == system_id).all()
    )
    update_rows: List[Tuple[PackageUpdate, Package]] = (
        db.query(PackageUpdate, Package)
        .join(Package, Package.id == PackageUpdate.package_id)
        .filter(
            PackageUpdate.system_id == system_id,
            # Defensive: PackageUpdate carries its own system_id, but
            # double-check the join target really belongs to the same
            # host so a malformed PackageUpdate row cannot leak a
            # different system's package into the preview.
            Package.system_id == system_id,
        )
        .all()
    )

    # Inventory-missing short-circuit (spec: host has no Package AND
    # no PackageUpdate rows -> single placeholder row).
    if not installed_rows and not update_rows:
        return [
            {
                "package_name": INVENTORY_MISSING_PACKAGE_NAME,
                "installed_version_snapshot": None,
                "available_version_snapshot": None,
                "selection_reason": SELECTION_REASON_INVENTORY_MISSING,
                "state": SELECTION_STATE_UNRESOLVABLE,
                "details": {
                    "scope_kind": policy.scope_kind,
                    "system_id": system_id,
                    "message": (
                        "host has no installed packages and no available "
                        "updates recorded; selection preview cannot be "
                        "computed without inventory"
                    ),
                },
                **_advisory_snapshot(None),
            }
        ]

    installed_by_name: Dict[str, Package] = {pkg.name: pkg for pkg in installed_rows}
    update_by_name: Dict[str, Tuple[PackageUpdate, Package]] = {
        pkg.name: (upd, pkg) for upd, pkg in update_rows
    }

    scope_kind = policy.scope_kind
    scope_packages = set(policy.scope_packages or [])

    rows: List[Dict[str, Any]] = []

    if scope_kind == "security_only":
        rows.extend(
            _select_security_only(
                db,
                system_id=system_id,
                installed_by_name=installed_by_name,
                update_by_name=update_by_name,
            )
        )
    elif scope_kind == "full":
        rows.extend(
            _select_full(
                update_by_name=update_by_name,
                installed_by_name=installed_by_name,
            )
        )
    elif scope_kind == "package_allowlist":
        rows.extend(
            _select_allowlist(
                allowlist=scope_packages,
                update_by_name=update_by_name,
                installed_by_name=installed_by_name,
            )
        )
    elif scope_kind == "package_denylist":
        rows.extend(
            _select_denylist(
                denylist=scope_packages,
                update_by_name=update_by_name,
                installed_by_name=installed_by_name,
            )
        )
    else:
        # Defensive: PRA-161 CHECK already restricts scope_kind, so
        # reaching here means the schema was widened without updating
        # this branch. Fail loud so the gap is caught in tests.
        raise PatchUpdatePlanError(
            f"unsupported scope_kind={scope_kind!r}; selection-preview "
            "needs an explicit branch for every scope vocabulary value"
        )

    return rows


def _select_security_only(
    db: Session,
    *,
    system_id: int,
    installed_by_name: Dict[str, Package],
    update_by_name: Dict[str, Tuple[PackageUpdate, Package]],
) -> List[Dict[str, Any]]:
    """One row per (package_name, advisory_id) where the host has an
    ``applicable`` advisory row. Rows missing a ``PackageUpdate``
    candidate are recorded as ``unresolvable / no_available_update``
    so operators can spot drift between the advisory data and the
    fleet's available updates."""
    applicability_rows: List[Tuple[PatchAdvisoryHostApplicability, PatchAdvisory]] = (
        db.query(PatchAdvisoryHostApplicability, PatchAdvisory)
        .join(
            PatchAdvisory,
            PatchAdvisory.id == PatchAdvisoryHostApplicability.advisory_id,
        )
        .filter(
            PatchAdvisoryHostApplicability.system_id == system_id,
            PatchAdvisoryHostApplicability.state == "applicable",
        )
        .order_by(
            PatchAdvisoryHostApplicability.package_name.asc(),
            PatchAdvisory.id.asc(),
        )
        .all()
    )

    rows: List[Dict[str, Any]] = []
    for app_row, advisory in applicability_rows:
        package_name = app_row.package_name
        installed_pkg = installed_by_name.get(package_name)
        update_pair = update_by_name.get(package_name)
        installed_version = (
            installed_pkg.installed_version if installed_pkg is not None else None
        )
        available_version = (
            update_pair[0].available_version if update_pair is not None else None
        )

        if update_pair is None:
            state = SELECTION_STATE_UNRESOLVABLE
            reason = SELECTION_REASON_NO_AVAILABLE_UPDATE
            details_message = (
                f"applicable advisory {advisory.source_kind}/"
                f"{advisory.source_advisory_id} targets {package_name!r} "
                "but no PackageUpdate candidate is recorded for the host"
            )
        else:
            state = SELECTION_STATE_SELECTED
            reason = SELECTION_REASON_POLICY_SECURITY_ADVISORY
            details_message = None

        details: Dict[str, Any] = {
            "scope_kind": "security_only",
            "advisory": {
                "id": advisory.id,
                "source_kind": advisory.source_kind,
                "source_advisory_id": advisory.source_advisory_id,
                "advisory_class": advisory.advisory_class,
                "severity": advisory.severity,
            },
            "required_version": app_row.required_version,
        }
        if details_message is not None:
            details["message"] = details_message

        rows.append(
            {
                "package_name": package_name,
                "installed_version_snapshot": installed_version,
                "available_version_snapshot": available_version,
                "selection_reason": reason,
                "state": state,
                "details": details,
                **_advisory_snapshot(advisory),
            }
        )
    return rows


def _select_full(
    *,
    update_by_name: Dict[str, Tuple[PackageUpdate, Package]],
    installed_by_name: Dict[str, Package],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name in sorted(update_by_name.keys()):
        upd, _pkg = update_by_name[name]
        installed_pkg = installed_by_name.get(name)
        rows.append(
            {
                "package_name": name,
                "installed_version_snapshot": (
                    installed_pkg.installed_version if installed_pkg else None
                ),
                "available_version_snapshot": upd.available_version,
                "selection_reason": SELECTION_REASON_POLICY_FULL,
                "state": SELECTION_STATE_SELECTED,
                "details": {
                    "scope_kind": "full",
                    "update_type": upd.update_type,
                },
                **_advisory_snapshot(None),
            }
        )
    return rows


def _select_allowlist(
    *,
    allowlist: set,
    update_by_name: Dict[str, Tuple[PackageUpdate, Package]],
    installed_by_name: Dict[str, Package],
) -> List[Dict[str, Any]]:
    """Allowlist names with a matching ``PackageUpdate`` become
    ``selected``; allowlist names without a matching update become
    ``unresolvable / no_available_update`` so allowlist drift is
    visible. Other update rows are not surfaced — they're outside
    the policy scope."""
    rows: List[Dict[str, Any]] = []
    for name in sorted(allowlist):
        update_pair = update_by_name.get(name)
        installed_pkg = installed_by_name.get(name)
        if update_pair is None:
            rows.append(
                {
                    "package_name": name,
                    "installed_version_snapshot": (
                        installed_pkg.installed_version if installed_pkg else None
                    ),
                    "available_version_snapshot": None,
                    "selection_reason": SELECTION_REASON_NO_AVAILABLE_UPDATE,
                    "state": SELECTION_STATE_UNRESOLVABLE,
                    "details": {
                        "scope_kind": "package_allowlist",
                        "message": (
                            f"allowlist entry {name!r} has no PackageUpdate "
                            "candidate recorded for the host"
                        ),
                    },
                    **_advisory_snapshot(None),
                }
            )
            continue
        upd, _pkg = update_pair
        rows.append(
            {
                "package_name": name,
                "installed_version_snapshot": (
                    installed_pkg.installed_version if installed_pkg else None
                ),
                "available_version_snapshot": upd.available_version,
                "selection_reason": SELECTION_REASON_POLICY_ALLOWLIST_MATCH,
                "state": SELECTION_STATE_SELECTED,
                "details": {
                    "scope_kind": "package_allowlist",
                    "update_type": upd.update_type,
                },
                **_advisory_snapshot(None),
            }
        )
    return rows


def _select_denylist(
    *,
    denylist: set,
    update_by_name: Dict[str, Tuple[PackageUpdate, Package]],
    installed_by_name: Dict[str, Package],
) -> List[Dict[str, Any]]:
    """Every ``PackageUpdate`` becomes a row. Names in the denylist
    flip to ``excluded / policy_denylist_excluded``; other names
    land as ``selected / policy_denylist_default_select`` (a
    distinct enum value the migration adds beyond the initial
    six so the reason column is self-explanatory without parsing
    ``details``)."""
    rows: List[Dict[str, Any]] = []
    for name in sorted(update_by_name.keys()):
        upd, _pkg = update_by_name[name]
        installed_pkg = installed_by_name.get(name)
        if name in denylist:
            state = SELECTION_STATE_EXCLUDED
            reason = SELECTION_REASON_POLICY_DENYLIST_EXCLUDED
        else:
            state = SELECTION_STATE_SELECTED
            reason = SELECTION_REASON_POLICY_DENYLIST_DEFAULT_SELECT
        rows.append(
            {
                "package_name": name,
                "installed_version_snapshot": (
                    installed_pkg.installed_version if installed_pkg else None
                ),
                "available_version_snapshot": upd.available_version,
                "selection_reason": reason,
                "state": state,
                "details": {
                    "scope_kind": "package_denylist",
                    "denylisted": name in denylist,
                    "update_type": upd.update_type,
                },
                **_advisory_snapshot(None),
            }
        )
    return rows


def _materialize_selection_for_host(
    db: Session,
    *,
    plan_host: PatchUpdatePlanHost,
    policy: PatchPolicy,
) -> Dict[str, Any]:
    """Compute and persist the selection rows for one ``planned``
    host. Updates ``plan_host.selection_summary`` in place. Returns
    the summary dict.

    Idempotent — caller is responsible for clearing existing rows
    before re-running (refresh path drops the parent host rows via
    cascade, so this is naturally clean during refresh; create path
    starts with no rows).
    """
    if plan_host.system_id is None:
        # System was deleted between plan creation and selection;
        # leave the summary null and skip — without a system_id we
        # cannot read Package / PackageUpdate / applicability rows.
        plan_host.selection_summary = None
        return _empty_selection_summary()

    rows = _compute_host_selection(
        db,
        system_id=plan_host.system_id,
        policy=policy,
    )
    for row in rows:
        db.add(PatchUpdatePlanSelectedPackage(plan_host_id=plan_host.id, **row))
    summary = _summarize(rows)
    plan_host.selection_summary = summary
    return summary


def _run_selection_for_planned_hosts(
    db: Session,
    *,
    plan: PatchUpdatePlan,
    policy: PatchPolicy,
) -> Dict[str, Any]:
    """Run selection for every ``planned`` host on ``plan``.

    Returns aggregate counters for the audit emit (number of hosts
    processed, fleet-wide row counts by state). ``blocked`` hosts
    are skipped per the slice spec — their block reason already
    explains why; selection preview would just be noise.
    """
    planned_hosts = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.plan_id == plan.id,
            PatchUpdatePlanHost.state == PLAN_HOST_STATE_PLANNED,
        )
        .all()
    )
    aggregate = {
        "hosts_processed": 0,
        "selected": 0,
        "excluded": 0,
        "unresolvable": 0,
        "inventory_missing_hosts": 0,
    }
    for host in planned_hosts:
        summary = _materialize_selection_for_host(
            db,
            plan_host=host,
            policy=policy,
        )
        aggregate["hosts_processed"] += 1
        aggregate["selected"] += summary["selected"]
        aggregate["excluded"] += summary["excluded"]
        aggregate["unresolvable"] += summary["unresolvable"]
        if summary.get("inventory_missing"):
            aggregate["inventory_missing_hosts"] += 1
    return aggregate


# ---------------------------------------------------------------------------
# Slice 3: preflight snapshot + content-availability check
# ---------------------------------------------------------------------------
#
# Reads existing DB facts only — Package, HostFacts,
# ContentProfile/Channel/Mirror metadata, and the Slice 3 derived
# mirror_sync_run_packages index. Strict version-level availability:
# a selected (package_name, available_version_snapshot) is "available"
# iff the index contains a row for at least one mirror reachable
# through the host's effective content profile.
#
# Manifest file IO is confined to mirror_package_index — the resolver
# itself never touches the filesystem. When a successful sync run
# has no index rows yet (e.g. it predates Slice 3 or was missed by
# the sync hook), the resolver lazily backfills via
# mirror_package_index.backfill_run_if_missing.


def _empty_preflight_summary() -> Dict[str, Any]:
    return {
        CONTENT_AVAILABILITY_AVAILABLE: 0,
        CONTENT_AVAILABILITY_UNAVAILABLE: 0,
        CONTENT_AVAILABILITY_PROFILE_MISSING: 0,
        CONTENT_AVAILABILITY_NOT_APPLICABLE: 0,
        "installed_drift_count": 0,
    }


def _summarize_preflight(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    summary = _empty_preflight_summary()
    for row in rows:
        state = row["content_availability_state"]
        summary[state] = summary.get(state, 0) + 1
        if row.get("_installed_drift", False):
            summary["installed_drift_count"] += 1
    return summary


def _derive_package_manager_family(facts: Optional[HostFacts]) -> str:
    if facts is None:
        return PACKAGE_MANAGER_FAMILY_UNKNOWN
    pm = (facts.package_manager or "").strip().lower()
    if pm in _PACKAGE_MANAGER_TO_FAMILY:
        return _PACKAGE_MANAGER_TO_FAMILY[pm]
    distro = (facts.distro_id_facts or "").strip().lower()
    if distro in _DISTRO_TO_FAMILY:
        return _DISTRO_TO_FAMILY[distro]
    return PACKAGE_MANAGER_FAMILY_UNKNOWN


def _candidate_runs_for_profile(
    db: Session,
    *,
    plan_host: PatchUpdatePlanHost,
    profile_service: ContentProfileService,
) -> List[Tuple[Any, MirrorSyncRun]]:
    """Return a list of (mirror_entry, sync_run) tuples for every
    mirror reachable through the host's resolved effective content
    profile.

    For each mirror entry: the candidate sync run is the entry's
    ``pinned_run_id`` if set (PRA-159 tracking pin), otherwise the
    most recent ``ok`` run for the mirror. Entries whose mirror has
    no successful sync run AND no pinned run are skipped — they
    contribute zero availability evidence.

    The list also pulls the actual ``MirrorSyncRun`` rows so the
    caller can backfill missing index rows in one pass.
    """
    if plan_host.system_id is None:
        return []
    if plan_host.content_profile_state != CONTENT_PROFILE_STATE_RESOLVED:
        return []
    if plan_host.content_profile_id_snapshot is None:
        return []

    entries = profile_service.resolve_mirror_entries_for_profile(
        plan_host.content_profile_id_snapshot
    )
    if not entries:
        return []

    # Bulk-load candidate runs in one pass to avoid N+1 queries.
    pinned_run_ids = [e.pinned_run_id for e in entries if e.pinned_run_id is not None]
    pinned_runs: Dict[int, MirrorSyncRun] = {}
    if pinned_run_ids:
        for run in (
            db.query(MirrorSyncRun).filter(MirrorSyncRun.id.in_(pinned_run_ids)).all()
        ):
            pinned_runs[run.id] = run

    # For unpinned entries, look up the latest ok run per mirror.
    unpinned_mirror_ids = [e.mirror_id for e in entries if e.pinned_run_id is None]
    latest_runs: Dict[int, MirrorSyncRun] = {}
    if unpinned_mirror_ids:
        for mirror_id in unpinned_mirror_ids:
            run_id = mirror_package_index.latest_ok_run_id(db, mirror_id)
            if run_id is not None:
                run = db.query(MirrorSyncRun).filter(MirrorSyncRun.id == run_id).first()
                if run is not None:
                    latest_runs[mirror_id] = run

    pairs: List[Tuple[Any, MirrorSyncRun]] = []
    for entry in entries:
        if entry.pinned_run_id is not None:
            run = pinned_runs.get(entry.pinned_run_id)
            # Pinned-but-missing run is skipped; the entry contributes
            # no evidence. Slice 4 UI will surface this gap via the
            # mirror-side state, not via preflight.
            if run is not None and run.status == "ok":
                pairs.append((entry, run))
        else:
            run = latest_runs.get(entry.mirror_id)
            if run is not None:
                pairs.append((entry, run))
    return pairs


def _check_strict_availability(
    db: Session,
    *,
    package_name: str,
    required_version: str,
    candidates: List[Tuple[Any, MirrorSyncRun]],
) -> Tuple[str, Dict[str, Any]]:
    """Return ``(state, details)`` for one (package_name, version)
    against a list of (entry, run) candidates.

    Backfills the index for any candidate run that has no index rows
    yet. Returns ``available`` on the first match, including the
    matching channel/mirror/run in details. Returns ``unavailable``
    when no candidate matches, with a structured summary of what
    was checked so operators can see the negative-result evidence."""
    matched_channels: List[Dict[str, Any]] = []
    checked: List[Dict[str, Any]] = []
    for entry, run in candidates:
        # Lazy backfill so legacy ok runs without index rows answer
        # the question on first preflight rather than silently
        # reporting unavailable.
        mirror_package_index.backfill_run_if_missing(db, run)
        # Slice 3a fix: scope the lookup to THIS run.id
        # (latest-ok or pinned), not the mirror as a whole — an
        # older retained run for the same mirror cannot satisfy
        # availability when the selected current/pinned run does not.
        published = mirror_package_index.mirror_publishes(
            db,
            mirror_sync_run_id=run.id,
            package_name=package_name,
            version=required_version,
        )
        checked.append(
            {
                "channel_id": entry.channel_id,
                "channel_slug": entry.channel_slug,
                "mirror_id": entry.mirror_id,
                "mirror_slug": entry.mirror_slug,
                "mirror_sync_run_id": run.id,
                "package_family": entry.package_family,
                "matched": published,
            }
        )
        if published:
            matched_channels.append(checked[-1])
    if matched_channels:
        return CONTENT_AVAILABILITY_AVAILABLE, {
            "matched_channels": matched_channels,
            "checked_channel_count": len(checked),
        }
    return CONTENT_AVAILABILITY_UNAVAILABLE, {
        "checked_channels": checked,
        "checked_channel_count": len(checked),
    }


def _aggregate_selected_packages(
    selected_rows: Sequence[PatchUpdatePlanSelectedPackage],
) -> Dict[str, Dict[str, Any]]:
    """Collapse Slice 2 selected-package rows into one entry per
    ``package_name`` for the preflight resolver.

    Per-package shape::

        {
          "package_name": str,
          "available_version_snapshot": Optional[str],
          "installed_version_snapshot": Optional[str],
          "any_state": "selected" | "excluded" | "unresolvable",
          "any_reason": str,  # one of the SELECTION_REASON_* enums
          "advisory_count": int,
        }

    The ``any_state`` / ``any_reason`` fields collapse multiple
    advisory rows for the same package into a single bucket:

      * If any row is ``state=selected``, the package counts as
        selected (security_only with both matched + drift advisories
        still produces a selected-overall view since at least one
        match exists).
      * Else if any row is ``state=excluded``, the package counts
        as excluded.
      * Else (all rows ``unresolvable``), keep the source reason —
        ``inventory_missing`` collapses to itself; the rest collapse
        to ``no_available_update``.
    """
    bucket: Dict[str, Dict[str, Any]] = {}
    for row in selected_rows:
        name = row.package_name
        existing = bucket.setdefault(
            name,
            {
                "package_name": name,
                "available_version_snapshot": row.available_version_snapshot,
                "installed_version_snapshot": row.installed_version_snapshot,
                "any_state": row.state,
                "any_reason": row.selection_reason,
                "advisory_count": 0,
            },
        )
        if row.advisory_id_snapshot is not None:
            existing["advisory_count"] += 1
        # Promotion order: selected > excluded > inventory_missing >
        # no_available_update. A single ``selected`` row makes the
        # package check-worthy; ``inventory_missing`` only stands when
        # nothing else applies.
        if row.state == SELECTION_STATE_SELECTED:
            existing["any_state"] = SELECTION_STATE_SELECTED
            existing["any_reason"] = row.selection_reason
            if row.available_version_snapshot is not None:
                existing["available_version_snapshot"] = row.available_version_snapshot
            if row.installed_version_snapshot is not None:
                existing["installed_version_snapshot"] = row.installed_version_snapshot
        elif (
            row.state == SELECTION_STATE_EXCLUDED
            and existing["any_state"] != SELECTION_STATE_SELECTED
        ):
            existing["any_state"] = SELECTION_STATE_EXCLUDED
            existing["any_reason"] = row.selection_reason
        elif (
            existing["any_state"]
            not in (
                SELECTION_STATE_SELECTED,
                SELECTION_STATE_EXCLUDED,
            )
            and row.selection_reason == SELECTION_REASON_INVENTORY_MISSING
        ):
            existing["any_state"] = SELECTION_STATE_UNRESOLVABLE
            existing["any_reason"] = SELECTION_REASON_INVENTORY_MISSING
    return bucket


def _materialize_preflight_for_host(
    db: Session,
    *,
    plan_host: PatchUpdatePlanHost,
    profile_service: ContentProfileService,
    now: datetime,
) -> Dict[str, Any]:
    """Compute and persist preflight rows for one ``planned`` host.
    Updates ``plan_host.preflight_summary`` in place. Returns the
    summary dict."""
    # Refresh dropped the parent host row + cascaded preflight rows;
    # create starts with no rows. Either way: a fresh empty slate.
    summary = _empty_preflight_summary()

    # Hosts whose system was deleted between create-time and
    # selection get a null summary and no rows — same skip-with-null
    # as Slice 2.
    if plan_host.system_id is None:
        plan_host.preflight_summary = None
        return summary

    selected_rows = (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(PatchUpdatePlanSelectedPackage.plan_host_id == plan_host.id)
        .order_by(
            PatchUpdatePlanSelectedPackage.package_name.asc(),
            PatchUpdatePlanSelectedPackage.advisory_id_snapshot.asc().nullsfirst(),
        )
        .all()
    )
    if not selected_rows:
        # Host had selection skipped (e.g. it was blocked) or had no
        # eligible packages. Either way, nothing to preflight.
        plan_host.preflight_summary = None
        return summary

    packages = _aggregate_selected_packages(selected_rows)

    facts = (
        db.query(HostFacts).filter(HostFacts.system_id == plan_host.system_id).first()
    )
    package_manager_family = _derive_package_manager_family(facts)

    installed_by_name: Dict[str, str] = {
        pkg.name: pkg.installed_version
        for pkg in db.query(Package)
        .filter(Package.system_id == plan_host.system_id)
        .all()
    }

    candidates = _candidate_runs_for_profile(
        db, plan_host=plan_host, profile_service=profile_service
    )

    rows: List[Dict[str, Any]] = []
    for name in sorted(packages.keys()):
        pkg = packages[name]
        installed_now = installed_by_name.get(name)

        # Determine state.
        if pkg["any_state"] == SELECTION_STATE_EXCLUDED:
            state = CONTENT_AVAILABILITY_NOT_APPLICABLE
            details: Dict[str, Any] = {
                "scope_kind": plan_host.policy_slug_snapshot,
                "selection_state": SELECTION_STATE_EXCLUDED,
                "selection_reason": pkg["any_reason"],
                "message": "selected-package row was excluded; preflight skipped",
            }
        elif pkg["any_reason"] == SELECTION_REASON_INVENTORY_MISSING:
            state = CONTENT_AVAILABILITY_NOT_APPLICABLE
            details = {
                "selection_reason": SELECTION_REASON_INVENTORY_MISSING,
                "message": "host inventory missing; preflight cannot be computed",
            }
        elif plan_host.content_profile_state != CONTENT_PROFILE_STATE_RESOLVED:
            state = CONTENT_AVAILABILITY_PROFILE_MISSING
            details = {
                "content_profile_state": plan_host.content_profile_state,
                "message": (
                    "host has no resolved content profile; defer "
                    "version-level availability check"
                ),
            }
        elif pkg["available_version_snapshot"] is None:
            # Selection layer already flagged this as unresolvable
            # (no PackageUpdate candidate). There is no version to
            # query the index against — record as unavailable so the
            # operator UI surfaces it as a content gap rather than
            # losing the row entirely.
            state = CONTENT_AVAILABILITY_UNAVAILABLE
            details = {
                "selection_reason": pkg["any_reason"],
                "message": (
                    "no available_version_snapshot recorded by the "
                    "selection layer; mirror index cannot be queried"
                ),
            }
        else:
            state, details = _check_strict_availability(
                db,
                package_name=name,
                required_version=pkg["available_version_snapshot"],
                candidates=candidates,
            )

        installed_drift = (
            installed_now is not None
            and pkg["installed_version_snapshot"] is not None
            and installed_now != pkg["installed_version_snapshot"]
        )
        if installed_drift:
            details["installed_version_drift"] = {
                "selection_snapshot": pkg["installed_version_snapshot"],
                "preflight_observed": installed_now,
            }

        rows.append(
            {
                "package_name": name,
                "installed_version_at_preflight": installed_now,
                "package_manager_family_snapshot": package_manager_family,
                "content_availability_state": state,
                "availability_details": details,
                "evaluated_at": now,
                "_installed_drift": installed_drift,
            }
        )

    for row in rows:
        # Strip the internal-only marker before constructing the ORM row.
        drift = row.pop("_installed_drift")
        db.add(PatchUpdatePlanPreflightSnapshot(plan_host_id=plan_host.id, **row))
        # Re-attach for the summary helper.
        row["_installed_drift"] = drift

    summary = _summarize_preflight(rows)
    plan_host.preflight_summary = summary
    return summary


def _run_preflight_for_planned_hosts(
    db: Session,
    *,
    plan: PatchUpdatePlan,
) -> Dict[str, Any]:
    """Run preflight for every ``planned`` host on ``plan``.

    Returns aggregate counters for the audit emit. ``blocked``
    hosts are skipped per the slice spec. Hosts whose selection
    rows are absent (Slice 2 had nothing to preview) skip cleanly
    with a null summary."""
    planned_hosts = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.plan_id == plan.id,
            PatchUpdatePlanHost.state == PLAN_HOST_STATE_PLANNED,
        )
        .all()
    )
    profile_service = ContentProfileService(db)
    now = datetime.utcnow()
    aggregate = {
        "hosts_processed": 0,
        CONTENT_AVAILABILITY_AVAILABLE: 0,
        CONTENT_AVAILABILITY_UNAVAILABLE: 0,
        CONTENT_AVAILABILITY_PROFILE_MISSING: 0,
        CONTENT_AVAILABILITY_NOT_APPLICABLE: 0,
        "installed_drift_packages": 0,
    }
    for host in planned_hosts:
        summary = _materialize_preflight_for_host(
            db,
            plan_host=host,
            profile_service=profile_service,
            now=now,
        )
        aggregate["hosts_processed"] += 1
        for key in (
            CONTENT_AVAILABILITY_AVAILABLE,
            CONTENT_AVAILABILITY_UNAVAILABLE,
            CONTENT_AVAILABILITY_PROFILE_MISSING,
            CONTENT_AVAILABILITY_NOT_APPLICABLE,
        ):
            aggregate[key] += summary.get(key, 0)
        aggregate["installed_drift_packages"] += summary.get("installed_drift_count", 0)
    return aggregate


def _build_host_rows(
    db: Session,
    *,
    policy: PatchPolicy,
    ordered_rings: Sequence[Tuple[PatchPolicyRingBinding, PatchRing]],
    target_hosts: Sequence[System],
    explicit_ids: Sequence[int],
) -> List[Dict[str, Any]]:
    """Run the per-host resolver across ``target_hosts`` and return
    the row dicts ready for ORM construction."""
    enabled_ring_order = [r for _b, r in ordered_rings if r.enabled]
    enabled_ring_index = {r.id: idx for idx, r in enumerate(enabled_ring_order)}
    explicit_set = set(explicit_ids)

    profile_service = ContentProfileService(db)
    rows: List[Dict[str, Any]] = []
    for host in target_hosts:
        rows.append(
            _resolve_host_row(
                db,
                host=host,
                policy=policy,
                enabled_ring_order=enabled_ring_order,
                enabled_ring_index=enabled_ring_index,
                profile_service=profile_service,
                explicit_target=host.id in explicit_set,
            )
        )
    return rows


def create_plan(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    policy_id: int,
    name: str,
    description: Optional[str] = None,
    target_system_ids: Optional[List[int]] = None,
    scheduled_start_at: Optional[datetime] = None,
    maintenance_window_id: Optional[int] = None,
    reboot_window_id: Optional[int] = None,
) -> PatchUpdatePlan:
    """Create a dry-run :class:`PatchUpdatePlan` and its host rows.

    The plan is always persisted: plan-level invariant failures land
    the plan in state ``blocked`` with structured reasons rather than
    raising, so the audit trail captures what was attempted. Hard
    exceptions are reserved for unknown ids, missing actor, and
    request-shape errors that prevent the plan envelope from being
    built at all.
    """
    _require_actor(db, actor_user_id)
    # Slice 1a fix: validate optional MW overrides before
    # touching the DB so unknown ids surface as PatchUpdatePlanError
    # (route 422) instead of a raw IntegrityError on commit (500).
    _validate_plan_window(db, maintenance_window_id, "maintenance_window_id")
    _validate_plan_window(db, reboot_window_id, "reboot_window_id")
    policy, ordered_rings, target_hosts, explicit_ids = _resolve_inputs(
        db,
        policy_id=policy_id,
        target_system_ids=target_system_ids,
    )

    plan_block_reasons = _plan_level_block_reasons(
        policy=policy,
        ordered_rings=ordered_rings,
        target_hosts=target_hosts,
    )

    plan_state = PLAN_STATE_BLOCKED if plan_block_reasons else PLAN_STATE_DRAFT

    plan = PatchUpdatePlan(
        policy_id=policy.id,
        name=name,
        description=description,
        state=plan_state,
        scheduled_start_at=scheduled_start_at,
        maintenance_window_id=maintenance_window_id,
        reboot_window_id=reboot_window_id,
        policy_snapshot=_policy_snapshot(policy),
        ring_sequence_snapshot=_ring_sequence_snapshot(ordered_rings),
        request_snapshot=_request_snapshot(
            policy_id=policy.id,
            requested_target_system_ids=(
                target_system_ids if target_system_ids is not None else None
            ),
            name=name,
            description=description,
            scheduled_start_at=scheduled_start_at,
            maintenance_window_id=maintenance_window_id,
            reboot_window_id=reboot_window_id,
        ),
        block_reasons=plan_block_reasons,
        created_by=actor_user_id,
    )
    db.add(plan)
    db.flush()  # need plan.id for child rows

    host_rows = _build_host_rows(
        db,
        policy=policy,
        ordered_rings=ordered_rings,
        target_hosts=target_hosts,
        explicit_ids=explicit_ids,
    )
    for row in host_rows:
        db.add(PatchUpdatePlanHost(plan_id=plan.id, **row))
    db.flush()  # Slice 2: selection needs persisted plan_host.id values

    selection_aggregate = _run_selection_for_planned_hosts(
        db,
        plan=plan,
        policy=policy,
    )
    db.flush()  # Slice 3: preflight reads selection rows persisted above
    preflight_aggregate = _run_preflight_for_planned_hosts(db, plan=plan)

    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "plan_state": plan.state,
            "host_count": len(host_rows),
            "blocked_host_count": sum(
                1 for row in host_rows if row["state"] == PLAN_HOST_STATE_BLOCKED
            ),
            "explicit_target_count": (
                len(target_system_ids) if target_system_ids is not None else 0
            ),
            "auto_discovered": target_system_ids is None,
            "rollout_cadence": policy.rollout_cadence,
            "ring_count_in_set": len(ordered_rings),
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    _emit_selection_audit(
        db,
        plan=plan,
        policy=policy,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        aggregate=selection_aggregate,
    )
    _emit_preflight_audit(
        db,
        plan=plan,
        policy=policy,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        aggregate=preflight_aggregate,
    )
    return plan


def refresh_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchUpdatePlan:
    """Rebuild a draft/blocked plan against the current world state.

    Replays the original request envelope through the resolver and
    overwrites snapshots + host rows. The plan id and audit trail are
    preserved. Approved / scheduled / superseded / canceled plans
    cannot be refreshed — operators create a fresh plan instead so
    the prior contract stays auditable.
    """
    _require_actor(db, actor_user_id)
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    if plan.state not in REFRESHABLE_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(REFRESHABLE_STATES)} plans may be refreshed"
        )

    request = plan.request_snapshot or {}
    requested_targets = request.get("requested_target_system_ids")
    if requested_targets is not None and not isinstance(requested_targets, list):
        # Defensive: a malformed snapshot should not silently widen the
        # plan to all systems.
        raise PatchUpdatePlanError(
            f"plan {plan_id} request_snapshot.requested_target_system_ids "
            "is not a list; refresh refused to avoid widening scope"
        )

    policy, ordered_rings, target_hosts, explicit_ids = _resolve_inputs(
        db,
        policy_id=plan.policy_id,
        target_system_ids=requested_targets,
    )

    plan_block_reasons = _plan_level_block_reasons(
        policy=policy,
        ordered_rings=ordered_rings,
        target_hosts=target_hosts,
    )

    # Drop existing host rows; ``cascade='all, delete-orphan'`` means we
    # also have to remove via the relationship to keep the session clean.
    db.query(PatchUpdatePlanHost).filter(PatchUpdatePlanHost.plan_id == plan.id).delete(
        synchronize_session=False
    )
    db.flush()

    plan.state = PLAN_STATE_BLOCKED if plan_block_reasons else PLAN_STATE_DRAFT
    plan.policy_snapshot = _policy_snapshot(policy)
    plan.ring_sequence_snapshot = _ring_sequence_snapshot(ordered_rings)
    plan.block_reasons = plan_block_reasons

    host_rows = _build_host_rows(
        db,
        policy=policy,
        ordered_rings=ordered_rings,
        target_hosts=target_hosts,
        explicit_ids=explicit_ids,
    )
    for row in host_rows:
        db.add(PatchUpdatePlanHost(plan_id=plan.id, **row))
    # Slice 2: existing plan_host rows were dropped above with
    # synchronize_session=False; the FK CASCADE on
    # patch_update_plan_selected_packages.plan_host_id removes any
    # selection rows that belonged to them. Flush so the freshly
    # added host rows have ids before selection runs.
    db.flush()

    selection_aggregate = _run_selection_for_planned_hosts(
        db,
        plan=plan,
        policy=policy,
    )
    db.flush()  # Slice 3: preflight reads selection rows persisted above
    preflight_aggregate = _run_preflight_for_planned_hosts(db, plan=plan)

    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_REFRESHED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "plan_state": plan.state,
            "host_count": len(host_rows),
            "blocked_host_count": sum(
                1 for row in host_rows if row["state"] == PLAN_HOST_STATE_BLOCKED
            ),
            "rollout_cadence": policy.rollout_cadence,
            "ring_count_in_set": len(ordered_rings),
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    _emit_selection_audit(
        db,
        plan=plan,
        policy=policy,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        aggregate=selection_aggregate,
    )
    _emit_preflight_audit(
        db,
        plan=plan,
        policy=policy,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        aggregate=preflight_aggregate,
    )
    return plan


def cancel_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchUpdatePlan:
    """Cancel a draft/blocked plan.

    Slice 1 only: approved / scheduled / superseded transitions are
    owned by later slices. A canceled plan keeps its host rows and
    snapshots so the audit trail is intact.
    """
    _require_actor(db, actor_user_id)
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    if plan.state == PLAN_STATE_CANCELED:
        # Idempotent: no-op, no audit, no commit.
        return plan
    if plan.state not in CANCELABLE_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(CANCELABLE_STATES)} plans may be canceled"
        )

    prior_state = plan.state
    plan.state = PLAN_STATE_CANCELED
    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_CANCELED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": plan.policy_id,
            "prior_state": prior_state,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    return plan


def _plan_approval_ids(db: Session, plan_id: int) -> List[int]:
    """All PatchApproval ids ever linked to a plan (audit evidence)."""
    return [
        row[0]
        for row in db.query(PatchUpdatePlanApproval.approval_id)
        .filter(PatchUpdatePlanApproval.plan_id == plan_id)
        .order_by(PatchUpdatePlanApproval.id.asc())
        .all()
    ]


def _plan_execution_ids(db: Session, plan_id: int) -> List[int]:
    """All PatchUpdateExecution ids for a plan (audit evidence)."""
    return [
        row[0]
        for row in db.query(PatchUpdateExecution.id)
        .filter(PatchUpdateExecution.plan_id == plan_id)
        .order_by(PatchUpdateExecution.id.asc())
        .all()
    ]


def _plan_has_schedule_history(plan: PatchUpdatePlan) -> bool:
    """True when a plan carries scheduling evidence — an explicit
    ``scheduled_start_at`` was ever set, or the plan reached the
    ``scheduled`` state (schedule_plan sets both)."""
    return plan.scheduled_start_at is not None or plan.state == PLAN_STATE_SCHEDULED


def delete_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    """PRA-355: hard-delete a TRUE pre-history (test/draft) plan for cleanup.

    Allowed only for a plan in a ``DELETABLE_STATES`` state that has NO
    approval, schedule, or execution history. Plan-scoped derived rows (hosts,
    approvals links, preflight snapshots, selected packages) are ON DELETE
    CASCADE and go with it. Any plan carrying real patch-lifecycle history is
    refused with operator copy pointing at archive/retire — that history
    (executions, reboot rows, rollback rows, approval rows, evidence) is
    immutable audit data and is never destroyed here.

    History guards: a ``superseded`` plan always comes
    from awaiting_approval/approved/scheduled, so it carries approval and/or
    schedule evidence — hard-deleting it would CASCADE its
    ``PatchUpdatePlanApproval`` link and orphan the surviving ``PatchApproval``
    row against a deleted plan id. These checks refuse that path; use
    :func:`archive_plan` instead.
    """
    _require_actor(db, actor_user_id)
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")

    if plan.archived_at is not None:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is archived and is retained as an audit record; it "
            "cannot be hard-deleted"
        )

    execution_count = (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan_id)
        .count()
    )
    if execution_count:
        raise PatchUpdatePlanError(
            f"plan {plan_id} has execution history and cannot be deleted; it is "
            "retained as an audit record. Archive it instead to preserve the "
            "audit trail"
        )
    approval_count = (
        db.query(PatchUpdatePlanApproval)
        .filter(PatchUpdatePlanApproval.plan_id == plan_id)
        .count()
    )
    if approval_count:
        raise PatchUpdatePlanError(
            f"plan {plan_id} has approval history and cannot be deleted; it is "
            "retained as an audit record. Archive it instead to preserve the "
            "audit trail"
        )
    if _plan_has_schedule_history(plan):
        raise PatchUpdatePlanError(
            f"plan {plan_id} has schedule history and cannot be deleted; it is "
            "retained as an audit record. Archive it instead to preserve the "
            "audit trail"
        )
    if plan.state not in DELETABLE_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r} and cannot be deleted; "
            f"only {sorted(DELETABLE_STATES)} plans with no approval, schedule, "
            "or execution history may be deleted. Archive it instead"
        )

    policy_id = plan.policy_id
    prior_state = plan.state
    # Read the plan's hosts while the rows still exist: the cascade takes them
    # with the plan, and the audit event still has to reach each of them.
    related_system_ids = patch_scope.plan_target_system_ids(db, plan_id)
    db.delete(plan)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.warning(
            "patch update plan id=%s delete blocked by a database reference: %s",
            plan_id,
            exc,
        )
        raise PatchUpdatePlanError(
            f"plan {plan_id} is still referenced by other records and cannot be "
            "deleted"
        ) from exc

    safe_emit(
        action=AUDIT_PLAN_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan_id),
        context={
            "policy_id": policy_id,
            "prior_state": prior_state,
        },
        related_system_ids=related_system_ids,
    )


def archive_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    reason: Optional[str] = None,
) -> PatchUpdatePlan:
    """PRA-355: admin archive/retire of a plan WITH patch-lifecycle history.

    Non-destructive: every row (hosts, approval links + ``PatchApproval`` rows,
    executions, reboot rows, rollback rows, selected-package evidence) stays in
    place and queryable/exportable from audit/reporting surfaces. The plan is
    marked ``archived_at`` so normal operator lists/selectors hide it by
    default. ``state`` is left untouched as the tombstone's ``prior_state``.

    Emits ``patch_update_plan.archived`` capturing the tombstone: plan id, name,
    policy id/slug, creator, prior state, approval ids, execution ids,
    archived_by, archived_at, and the optional reason.
    """
    _require_actor(db, actor_user_id)
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    if plan.archived_at is not None:
        raise PatchUpdatePlanError(f"plan {plan_id} is already archived")

    snapshot = dict(plan.policy_snapshot or {})
    policy_slug = snapshot.get("slug")
    if policy_slug is None and plan.policy_id is not None:
        policy_slug = (
            db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
        )
    approval_ids = _plan_approval_ids(db, plan_id)
    execution_ids = _plan_execution_ids(db, plan_id)
    prior_state = plan.state

    archived_at = datetime.utcnow()
    plan.archived_at = archived_at
    plan.archived_by = actor_user_id
    plan.archive_reason = reason
    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_ARCHIVED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan_id),
        context={
            "plan_id": plan_id,
            "name": plan.name,
            "policy_id": plan.policy_id,
            "policy_slug": policy_slug,
            "created_by": plan.created_by,
            "prior_state": prior_state,
            "approval_ids": approval_ids,
            "execution_ids": execution_ids,
            "archived_by": actor_user_id,
            "archived_at": archived_at.isoformat(),
            "reason": reason,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan_id),
    )
    return plan


# ---------------------------------------------------------------------------
# PRA-355: backend-authoritative cleanup affordances for the plan list/detail
# UI. The list previously inferred delete-vs-archive from ``state`` alone,
# which stranded a ``blocked`` plan that carries approval history (e.g. an
# approval rejection) with a Delete-only row that the backend then refuses.
# These flags are the single source of truth the UI renders from.
# ---------------------------------------------------------------------------


def plan_has_lifecycle_history(db: Session, plan: PatchUpdatePlan) -> bool:
    """True when a plan carries approval, schedule, or execution evidence —
    i.e. hard-delete is refused and archive is the correct cleanup tool."""
    if _plan_has_schedule_history(plan):
        return True
    if (
        db.query(PatchUpdatePlanApproval)
        .filter(PatchUpdatePlanApproval.plan_id == plan.id)
        .count()
    ):
        return True
    if (
        db.query(PatchUpdateExecution)
        .filter(PatchUpdateExecution.plan_id == plan.id)
        .count()
    ):
        return True
    return False


def lifecycle_history_by_plan(
    db: Session, plans: List[PatchUpdatePlan]
) -> Dict[int, bool]:
    """Batch (N-query, not N+1) map of ``plan.id`` -> has-lifecycle-history for
    a page of plans. Approval + execution presence are two ``IN`` queries;
    schedule history is derived per-row from the plan itself."""
    ids = [p.id for p in plans]
    if not ids:
        return {}
    have: set[int] = set()
    for (pid,) in (
        db.query(PatchUpdatePlanApproval.plan_id)
        .filter(PatchUpdatePlanApproval.plan_id.in_(ids))
        .distinct()
    ):
        have.add(pid)
    for (pid,) in (
        db.query(PatchUpdateExecution.plan_id)
        .filter(PatchUpdateExecution.plan_id.in_(ids))
        .distinct()
    ):
        have.add(pid)
    return {p.id: (p.id in have or _plan_has_schedule_history(p)) for p in plans}


def plan_action_flags(
    plan: PatchUpdatePlan, *, has_lifecycle_history: bool
) -> Dict[str, bool]:
    """Cleanup affordances for a plan row. ``can_hard_delete`` is a TRUE
    pre-history plan in a deletable state; ``can_archive`` is any non-archived
    plan that is not hard-deletable (the audit-preserving retire path, admin
    only at the route layer). Exactly one is true for a non-archived plan; both
    are false for an already-archived tombstone."""
    archived = plan.archived_at is not None
    can_hard_delete = (
        not archived and plan.state in DELETABLE_STATES and not has_lifecycle_history
    )
    return {
        "has_lifecycle_history": has_lifecycle_history,
        "can_hard_delete": can_hard_delete,
        "can_archive": (not archived) and not can_hard_delete,
    }


# ---------------------------------------------------------------------------
# Slice 4: state-machine transitions
# ---------------------------------------------------------------------------
#
# Approval integration goes through patch_approval_service. The plan
# service itself queries approval status and gates plan state — the
# approval service NEVER auto-executes anything (PRA-161 lock #1).
#
# Two distinct flows depending on the policy:
#
#   policy.requires_approval = False:
#     draft -> approved via approve_directly(). No PatchApproval row
#     created; the audit event captures the decision.
#
#   policy.requires_approval = True:
#     draft -> awaiting_approval via request_approval() (creates a
#     PatchApproval pending row + a PatchUpdatePlanApproval link).
#     Voters call record_approval_vote() which records a vote on the
#     linked patch_approvals row and, on threshold reached, transitions
#     the plan accordingly.


def _require_plan(db: Session, plan_id: int) -> PatchUpdatePlan:
    plan = db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()
    if plan is None:
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    return plan


def _latest_approval_for_plan(
    db: Session, plan: PatchUpdatePlan
) -> Optional[PatchUpdatePlanApproval]:
    """Return the most recent ``PatchUpdatePlanApproval`` link for a
    plan, or None when no approval has ever been requested. Ordered
    by id desc so a re-request after expiry returns the new row."""
    return (
        db.query(PatchUpdatePlanApproval)
        .filter(PatchUpdatePlanApproval.plan_id == plan.id)
        .order_by(PatchUpdatePlanApproval.id.desc())
        .first()
    )


def request_approval(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    comment: Optional[str] = None,
) -> PatchUpdatePlan:
    """Transition ``draft`` → ``awaiting_approval`` and create the
    PRA-161 patch-approval row + link.

    Refuses (route 422) when:
    - plan is not in ``draft``
    - the plan's policy does NOT require approval (operator should
      use :func:`approve_directly` instead)
    """
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)
    if plan.state not in REQUEST_APPROVAL_FROM_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(REQUEST_APPROVAL_FROM_STATES)} plans may request approval"
        )
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == plan.policy_id).first()
    if policy is None:
        raise PatchUpdatePlanError(
            f"plan {plan_id} references missing patch policy {plan.policy_id}"
        )
    if not policy.requires_approval:
        raise PatchUpdatePlanError(
            f"policy {policy.slug!r} does not require approval; use the "
            "direct approve path instead"
        )

    approval = patch_approval_service.request_approval(
        db,
        subject_kind="plan",
        subject_id=plan.id,
        requested_by=actor_user_id,
        required_approvals=policy.required_approvals,
        expires_at=expires_at,
        comment=comment,
    )

    now = datetime.utcnow()
    db.add(
        PatchUpdatePlanApproval(
            plan_id=plan.id,
            approval_id=approval.id,
            requested_by=actor_user_id,
            requested_at=now,
        )
    )
    plan.state = PLAN_STATE_AWAITING_APPROVAL
    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_APPROVAL_REQUESTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "approval_id": approval.id,
            "required_approvals": policy.required_approvals,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    return plan


def approve_directly(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    comment: Optional[str] = None,
) -> PatchUpdatePlan:
    """Direct ``draft`` → ``approved`` for plans whose policy does NOT
    require approval. Refuses (route 422) when the policy requires
    approval (operator should use :func:`request_approval` +
    :func:`record_approval_vote` instead)."""
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)
    if plan.state not in DIRECT_APPROVE_FROM_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(DIRECT_APPROVE_FROM_STATES)} plans may be directly approved"
        )
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == plan.policy_id).first()
    if policy is None:
        raise PatchUpdatePlanError(
            f"plan {plan_id} references missing patch policy {plan.policy_id}"
        )
    if policy.requires_approval:
        raise PatchUpdatePlanError(
            f"policy {policy.slug!r} requires approval; use the request "
            "approval + vote flow instead"
        )

    plan.state = PLAN_STATE_APPROVED
    db.commit()
    db.refresh(plan)

    safe_emit(
        action=AUDIT_PLAN_APPROVED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "via": "direct",
            "comment": comment,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    return plan


def record_approval_vote(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    decision: str,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    comment: Optional[str] = None,
) -> PatchUpdatePlan:
    """Record one approval vote (``approve`` or ``reject``) against
    the plan's most recent approval row, then transition the plan
    state if the threshold was reached.

    Refuses (route 422) when:
    - plan is not in ``awaiting_approval``
    - no approval row has been requested for this plan
    - the latest approval row is not ``pending``
    - ``decision`` is not ``approve`` / ``reject``
    """
    _require_actor(db, actor_user_id)
    if decision not in {"approve", "reject"}:
        raise PatchUpdatePlanError("decision must be 'approve' or 'reject'")
    plan = _require_plan(db, plan_id)
    if plan.state != PLAN_STATE_AWAITING_APPROVAL:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{PLAN_STATE_AWAITING_APPROVAL!r} plans may record approval votes"
        )

    link = _latest_approval_for_plan(db, plan)
    if link is None:
        raise PatchUpdatePlanError(
            f"plan {plan_id} has no approval row; call request_approval first"
        )
    approval = (
        db.query(PatchApproval).filter(PatchApproval.id == link.approval_id).first()
    )
    if approval is None:
        raise PatchUpdatePlanError(
            f"plan {plan_id} approval link {link.id} references missing "
            f"approval row {link.approval_id}"
        )
    if approval.status != patch_approval_service.STATUS_PENDING:
        raise PatchUpdatePlanError(
            f"plan {plan_id} approval row is in status {approval.status!r}; "
            "only pending approvals may receive new votes"
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
        raise PatchUpdatePlanError(str(exc)) from exc

    new_status = result.get("status")

    if new_status == patch_approval_service.STATUS_APPROVED:
        plan.state = PLAN_STATE_APPROVED
        db.commit()
        db.refresh(plan)
        policy_slug = (
            db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
        )
        safe_emit(
            action=AUDIT_PLAN_APPROVED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_update_plan",
            target_id=str(plan.id),
            context={
                "policy_id": plan.policy_id,
                "policy_slug": policy_slug,
                "via": "vote",
                "approval_id": approval.id,
                "comment": comment,
            },
            related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
        )
    elif new_status == patch_approval_service.STATUS_REJECTED:
        # Append the rejection block reason to the existing list so the
        # operator UI shows both the original Slice 1 reasons (if any)
        # and the approval rejection in one place.
        existing = list(plan.block_reasons or [])
        existing.append(
            {
                "code": BLOCK_APPROVAL_REJECTED,
                "details": {
                    "approval_id": approval.id,
                    "rejected_by": actor_user_id,
                    "comment": comment,
                },
            }
        )
        plan.block_reasons = existing
        plan.state = PLAN_STATE_BLOCKED
        db.commit()
        db.refresh(plan)
        policy_slug = (
            db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
        )
        safe_emit(
            action=AUDIT_PLAN_REJECTED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_update_plan",
            target_id=str(plan.id),
            context={
                "policy_id": plan.policy_id,
                "policy_slug": policy_slug,
                "approval_id": approval.id,
                "comment": comment,
            },
            related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
        )
    else:
        # Vote recorded but threshold not reached — plan stays in
        # awaiting_approval. The vote itself lives in patch_approval_service;
        # no plan-state change to commit, no plan-state audit to emit.
        db.commit()
        db.refresh(plan)
    return plan


def schedule_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    scheduled_start_at: datetime,
    maintenance_window_id: Optional[int] = None,
    reboot_window_id: Optional[int] = None,
) -> PatchUpdatePlan:
    """Transition ``approved`` → ``scheduled``. Validates the
    optional plan-level MW overrides via the existing Slice 1a
    helper (existence-only) so unknown ids surface as
    PatchUpdatePlanError (route 422) instead of an IntegrityError on
    commit.

    Slice 4 only sets the artifact metadata; no execution scheduling
    happens here. ``scheduled_start_at`` is the operator's intent;
    PRA-171 will consume it when wiring the live executor."""
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)
    if plan.state not in SCHEDULE_FROM_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(SCHEDULE_FROM_STATES)} plans may be scheduled"
        )
    if not isinstance(scheduled_start_at, datetime):
        raise PatchUpdatePlanError("scheduled_start_at must be a datetime")
    _validate_plan_window(db, maintenance_window_id, "maintenance_window_id")
    _validate_plan_window(db, reboot_window_id, "reboot_window_id")

    plan.scheduled_start_at = scheduled_start_at
    if maintenance_window_id is not None:
        plan.maintenance_window_id = maintenance_window_id
    if reboot_window_id is not None:
        plan.reboot_window_id = reboot_window_id
    plan.state = PLAN_STATE_SCHEDULED
    db.commit()
    db.refresh(plan)

    policy_slug = (
        db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
    )
    safe_emit(
        action=AUDIT_PLAN_SCHEDULED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": plan.policy_id,
            "policy_slug": policy_slug,
            "scheduled_start_at": scheduled_start_at.isoformat(),
            "maintenance_window_id": plan.maintenance_window_id,
            "reboot_window_id": plan.reboot_window_id,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    return plan


def supersede_plan(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    comment: Optional[str] = None,
) -> PatchUpdatePlan:
    """Explicit operator-driven ``superseded`` transition. Slice 4
    does NOT auto-fire on newer-plan approval (a deliberate product
    decision); this is the only path that flips a plan to
    ``superseded``.

    Refuses (route 422) when the plan is already in a terminal state
    (``canceled`` / ``superseded``)."""
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)
    if plan.state not in SUPERSEDE_FROM_STATES:
        raise PatchUpdatePlanError(
            f"plan {plan_id} is in state {plan.state!r}; only "
            f"{sorted(SUPERSEDE_FROM_STATES)} plans may be superseded"
        )

    prior_state = plan.state
    plan.state = PLAN_STATE_SUPERSEDED
    db.commit()
    db.refresh(plan)

    policy_slug = (
        db.query(PatchPolicy.slug).filter(PatchPolicy.id == plan.policy_id).scalar()
    )
    safe_emit(
        action=AUDIT_PLAN_SUPERSEDED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": plan.policy_id,
            "policy_slug": policy_slug,
            "prior_state": prior_state,
            "comment": comment,
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )
    return plan


def get_plan(db: Session, plan_id: int) -> Optional[PatchUpdatePlan]:
    return db.query(PatchUpdatePlan).filter(PatchUpdatePlan.id == plan_id).first()


def get_plan_approval(db: Session, plan: PatchUpdatePlan) -> Optional[Dict[str, Any]]:
    """Return the most recent approval status for a plan (joined
    through the link table) or ``None`` when no approval was ever
    requested. Slice 4 plan-detail endpoint surfaces this so the UI
    can render the approve/reject controls."""
    link = _latest_approval_for_plan(db, plan)
    if link is None:
        return None
    status = patch_approval_service.get_approval_status(
        db, subject_kind="plan", subject_id=plan.id
    )
    if status is None:
        return None
    return {
        "approval_id": link.approval_id,
        "link_id": link.id,
        "requested_by": link.requested_by,
        "requested_at": link.requested_at,
        **status,
    }


def list_plans(
    db: Session,
    *,
    policy_id: Optional[int] = None,
    state: Optional[str] = None,
    include_archived: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> Tuple[List[PatchUpdatePlan], int]:
    if state is not None and state not in VALID_PLAN_STATES:
        raise PatchUpdatePlanError(
            f"state={state!r} must be one of {sorted(VALID_PLAN_STATES)}"
        )
    q = db.query(PatchUpdatePlan)
    if policy_id is not None:
        q = q.filter(PatchUpdatePlan.policy_id == policy_id)
    if state is not None:
        q = q.filter(PatchUpdatePlan.state == state)
    # PRA-355: archived/retired plans are hidden from normal operator lists
    # and selectors by default; audit/reporting surfaces pass include_archived.
    if not include_archived:
        q = q.filter(PatchUpdatePlan.archived_at.is_(None))
    total = q.count()
    rows = q.order_by(PatchUpdatePlan.id.desc()).offset(offset).limit(limit).all()
    return rows, total


def list_plan_hosts(
    db: Session,
    plan_id: int,
) -> List[PatchUpdatePlanHost]:
    """Return ``PatchUpdatePlanHost`` rows for ``plan_id`` ordered by
    ``(wave_index, system_id)`` so the slice 4 UI can group by wave
    deterministically."""
    if (
        db.query(PatchUpdatePlan.id).filter(PatchUpdatePlan.id == plan_id).first()
        is None
    ):
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    return (
        db.query(PatchUpdatePlanHost)
        .filter(PatchUpdatePlanHost.plan_id == plan_id)
        .order_by(
            PatchUpdatePlanHost.wave_index.asc(),
            PatchUpdatePlanHost.system_id.asc(),
        )
        .all()
    )


# ---------------------------------------------------------------------------
# Slice 2: selection-preview readers + audit emit
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Slice 4: audit-export bundle
# ---------------------------------------------------------------------------


def _serialize_for_export(value: Any) -> Any:
    """Best-effort JSON-friendly conversion for export bundle values.

    DateTime → isoformat; everything else passes through (callers
    are expected to hand in already-serializable structures)."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def build_export_bundle(
    db: Session,
    plan_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the canonical audit-export JSON for a plan.

    Reads existing storage only — no new audit table; the existing
    ``audit_events`` rows for ``target_kind='patch_update_plan'`` and
    ``target_id=str(plan.id)`` provide the timeline. Bundle ordering
    is canonical so two exports of the same plan at the same instant
    produce byte-identical bytes:

      plan envelope
      hosts ordered by (wave_index, system_id, id)
      selected_packages ordered by
        (plan_host_id, package_name, advisory_id_snapshot NULLS FIRST, id)
      preflight_snapshots ordered by
        (plan_host_id, content_availability_state, package_name, id)
      approval link + status (most recent only)
      audit_events ordered by (timestamp, id)

    Emits ``patch_update_plan.exported`` after the bundle is built."""
    _require_actor(db, actor_user_id)
    plan = _require_plan(db, plan_id)

    hosts = (
        db.query(PatchUpdatePlanHost)
        .filter(PatchUpdatePlanHost.plan_id == plan.id)
        .order_by(
            PatchUpdatePlanHost.wave_index.asc(),
            PatchUpdatePlanHost.system_id.asc().nullslast(),
            PatchUpdatePlanHost.id.asc(),
        )
        .all()
    )
    host_ids = [h.id for h in hosts]
    selected = (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(PatchUpdatePlanSelectedPackage.plan_host_id.in_(host_ids))
        .order_by(
            PatchUpdatePlanSelectedPackage.plan_host_id.asc(),
            PatchUpdatePlanSelectedPackage.package_name.asc(),
            PatchUpdatePlanSelectedPackage.advisory_id_snapshot.asc().nullsfirst(),
            PatchUpdatePlanSelectedPackage.id.asc(),
        )
        .all()
        if host_ids
        else []
    )
    preflight = (
        db.query(PatchUpdatePlanPreflightSnapshot)
        .filter(PatchUpdatePlanPreflightSnapshot.plan_host_id.in_(host_ids))
        .order_by(
            PatchUpdatePlanPreflightSnapshot.plan_host_id.asc(),
            PatchUpdatePlanPreflightSnapshot.content_availability_state.asc(),
            PatchUpdatePlanPreflightSnapshot.package_name.asc(),
            PatchUpdatePlanPreflightSnapshot.id.asc(),
        )
        .all()
        if host_ids
        else []
    )
    approval = get_plan_approval(db, plan)

    # Slice 4a fix: emit the export audit event BEFORE
    # reading audit_events so the downloaded bundle includes the
    # current export action's row. ``safe_emit`` opens its own
    # ``SessionLocal`` and commits independently of ``db``, so the
    # subsequent query sees the freshly written row. This makes the
    # downloaded JSON a complete record of every plan event up to
    # and including the export itself.
    safe_emit(
        action=AUDIT_PLAN_EXPORTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": plan.policy_id,
            "host_count": len(hosts),
            "selected_count": len(selected),
            "preflight_count": len(preflight),
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )

    audit_events = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.target_kind == "patch_update_plan",
            AuditEvent.target_id == str(plan.id),
        )
        .order_by(AuditEvent.timestamp.asc(), AuditEvent.id.asc())
        .all()
    )

    bundle = {
        "praxis_patch_update_plan_export_version": 1,
        "exported_at": datetime.utcnow().isoformat(),
        "plan": {
            "id": plan.id,
            "policy_id": plan.policy_id,
            "name": plan.name,
            "description": plan.description,
            "state": plan.state,
            "scheduled_start_at": _serialize_for_export(plan.scheduled_start_at),
            "maintenance_window_id": plan.maintenance_window_id,
            "reboot_window_id": plan.reboot_window_id,
            "policy_snapshot": dict(plan.policy_snapshot or {}),
            "ring_sequence_snapshot": list(plan.ring_sequence_snapshot or []),
            "request_snapshot": dict(plan.request_snapshot or {}),
            "block_reasons": list(plan.block_reasons or []),
            "created_by": plan.created_by,
            "created_at": _serialize_for_export(plan.created_at),
            "updated_at": _serialize_for_export(plan.updated_at),
        },
        "hosts": [
            {
                "id": h.id,
                "system_id": h.system_id,
                "system_hostname_snapshot": h.system_hostname_snapshot,
                "policy_id_snapshot": h.policy_id_snapshot,
                "policy_slug_snapshot": h.policy_slug_snapshot,
                "policy_resolution_kind": h.policy_resolution_kind,
                "ring_id_snapshot": h.ring_id_snapshot,
                "ring_slug_snapshot": h.ring_slug_snapshot,
                "ring_name_snapshot": h.ring_name_snapshot,
                "ring_sort_order_snapshot": h.ring_sort_order_snapshot,
                "ring_source_tier": h.ring_source_tier,
                "ring_resolution_status": h.ring_resolution_status,
                "wave_index": h.wave_index,
                "content_profile_state": h.content_profile_state,
                "content_profile_id_snapshot": h.content_profile_id_snapshot,
                "content_profile_slug_snapshot": h.content_profile_slug_snapshot,
                "content_profile_display_name_snapshot": (
                    h.content_profile_display_name_snapshot
                ),
                "content_profile_package_family_snapshot": (
                    h.content_profile_package_family_snapshot
                ),
                "content_profile_conflict_snapshot": list(
                    h.content_profile_conflict_snapshot or []
                ),
                "state": h.state,
                "block_reasons": list(h.block_reasons or []),
                "selection_summary": (
                    dict(h.selection_summary) if h.selection_summary else None
                ),
                "preflight_summary": (
                    dict(h.preflight_summary) if h.preflight_summary else None
                ),
            }
            for h in hosts
        ],
        "selected_packages": [
            {
                "id": s.id,
                "plan_host_id": s.plan_host_id,
                "package_name": s.package_name,
                "installed_version_snapshot": s.installed_version_snapshot,
                "available_version_snapshot": s.available_version_snapshot,
                "advisory_id_snapshot": s.advisory_id_snapshot,
                "advisory_source_kind_snapshot": s.advisory_source_kind_snapshot,
                "advisory_class_snapshot": s.advisory_class_snapshot,
                "advisory_severity_snapshot": s.advisory_severity_snapshot,
                "selection_reason": s.selection_reason,
                "state": s.state,
                "details": dict(s.details or {}),
            }
            for s in selected
        ],
        "preflight_snapshots": [
            {
                "id": p.id,
                "plan_host_id": p.plan_host_id,
                "package_name": p.package_name,
                "installed_version_at_preflight": p.installed_version_at_preflight,
                "package_manager_family_snapshot": p.package_manager_family_snapshot,
                "content_availability_state": p.content_availability_state,
                "availability_details": dict(p.availability_details or {}),
                "evaluated_at": _serialize_for_export(p.evaluated_at),
            }
            for p in preflight
        ],
        "approval": (
            {
                "approval_id": approval["approval_id"],
                "link_id": approval["link_id"],
                "requested_by": approval["requested_by"],
                "requested_at": _serialize_for_export(approval["requested_at"]),
                "status": approval["status"],
                "required_approvals": approval["required_approvals"],
                "expires_at": _serialize_for_export(approval["expires_at"]),
                "decided_by": approval["decided_by"],
                "decided_at": _serialize_for_export(approval["decided_at"]),
            }
            if approval is not None
            else None
        ),
        "audit_events": [
            {
                "id": ev.id,
                "event_uuid": ev.event_uuid,
                "timestamp": _serialize_for_export(ev.timestamp),
                "action": ev.action,
                "outcome": ev.outcome,
                "actor_user_id": ev.actor_user_id,
                "actor_username": ev.actor_username,
                "actor_ip": ev.actor_ip,
                "target_kind": ev.target_kind,
                "target_id": ev.target_id,
                "context_json": ev.context_json,
            }
            for ev in audit_events
        ],
    }

    return bundle


def list_host_selected_packages(
    db: Session,
    *,
    plan_id: int,
    plan_host_id: int,
) -> List[PatchUpdatePlanSelectedPackage]:
    """Return the selection-preview rows for a single plan host.

    Raises :class:`PatchUpdatePlanError` (route 404) if the plan does
    not exist or the host is not part of that plan. Rows are ordered
    by ``(state, package_name, advisory_id_snapshot)`` so the slice 4
    UI groups by state deterministically.
    """
    plan_host = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.id == plan_host_id,
            PatchUpdatePlanHost.plan_id == plan_id,
        )
        .first()
    )
    if plan_host is None:
        raise PatchUpdatePlanError(
            f"plan host id={plan_host_id} not found on plan {plan_id}"
        )
    return (
        db.query(PatchUpdatePlanSelectedPackage)
        .filter(PatchUpdatePlanSelectedPackage.plan_host_id == plan_host_id)
        .order_by(
            PatchUpdatePlanSelectedPackage.state.asc(),
            PatchUpdatePlanSelectedPackage.package_name.asc(),
            PatchUpdatePlanSelectedPackage.advisory_id_snapshot.asc().nullsfirst(),
        )
        .all()
    )


def list_plan_selected_packages(
    db: Session,
    *,
    plan_id: int,
    state: Optional[str] = None,
) -> List[PatchUpdatePlanSelectedPackage]:
    """Plan-wide selection lookup. Optional ``state`` filter is one of
    ``selected`` / ``excluded`` / ``unresolvable``; invalid values
    raise :class:`PatchUpdatePlanError` (route 422)."""
    if (
        db.query(PatchUpdatePlan.id).filter(PatchUpdatePlan.id == plan_id).first()
        is None
    ):
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    if state is not None and state not in VALID_SELECTION_STATES:
        raise PatchUpdatePlanError(
            f"state={state!r} must be one of {sorted(VALID_SELECTION_STATES)}"
        )
    q = (
        db.query(PatchUpdatePlanSelectedPackage)
        .join(
            PatchUpdatePlanHost,
            PatchUpdatePlanHost.id == PatchUpdatePlanSelectedPackage.plan_host_id,
        )
        .filter(PatchUpdatePlanHost.plan_id == plan_id)
    )
    if state is not None:
        q = q.filter(PatchUpdatePlanSelectedPackage.state == state)
    return q.order_by(
        PatchUpdatePlanSelectedPackage.plan_host_id.asc(),
        PatchUpdatePlanSelectedPackage.state.asc(),
        PatchUpdatePlanSelectedPackage.package_name.asc(),
    ).all()


def _emit_selection_audit(
    db: Session,
    *,
    plan: PatchUpdatePlan,
    policy: PatchPolicy,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    aggregate: Dict[str, Any],
) -> None:
    """Emit ``patch_update_plan.selection_recomputed`` only when at
    least one ``planned`` host had its selection rebuilt. Plans where
    every host is ``blocked`` skip the audit row — selection was a
    no-op so emitting an event would be misleading."""
    if aggregate.get("hosts_processed", 0) <= 0:
        return
    safe_emit(
        action=AUDIT_PLAN_SELECTION_RECOMPUTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "scope_kind": policy.scope_kind,
            "hosts_processed": aggregate["hosts_processed"],
            "selected_total": aggregate["selected"],
            "excluded_total": aggregate["excluded"],
            "unresolvable_total": aggregate["unresolvable"],
            "inventory_missing_hosts": aggregate["inventory_missing_hosts"],
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )


def _emit_preflight_audit(
    db: Session,
    *,
    plan: PatchUpdatePlan,
    policy: PatchPolicy,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
    aggregate: Dict[str, Any],
) -> None:
    """Emit ``patch_update_plan.preflight_recomputed`` only when at
    least one ``planned`` host had its preflight rebuilt. Same
    suppress-when-all-blocked pattern as
    ``_emit_selection_audit``."""
    if aggregate.get("hosts_processed", 0) <= 0:
        return
    safe_emit(
        action=AUDIT_PLAN_PREFLIGHT_RECOMPUTED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_update_plan",
        target_id=str(plan.id),
        context={
            "policy_id": policy.id,
            "policy_slug": policy.slug,
            "scope_kind": policy.scope_kind,
            "hosts_processed": aggregate["hosts_processed"],
            "available_total": aggregate[CONTENT_AVAILABILITY_AVAILABLE],
            "unavailable_total": aggregate[CONTENT_AVAILABILITY_UNAVAILABLE],
            "profile_missing_total": aggregate[CONTENT_AVAILABILITY_PROFILE_MISSING],
            "not_applicable_total": aggregate[CONTENT_AVAILABILITY_NOT_APPLICABLE],
            "installed_drift_packages": aggregate["installed_drift_packages"],
        },
        related_system_ids=patch_scope.plan_target_system_ids(db, plan.id),
    )


# ---------------------------------------------------------------------------
# Slice 3: preflight readers
# ---------------------------------------------------------------------------


def list_host_preflight(
    db: Session,
    *,
    plan_id: int,
    plan_host_id: int,
) -> List[PatchUpdatePlanPreflightSnapshot]:
    """Return preflight rows for one plan host ordered by
    ``(content_availability_state, package_name)``. Raises
    :class:`PatchUpdatePlanError` (route 404) if the host is not
    part of the plan."""
    plan_host = (
        db.query(PatchUpdatePlanHost)
        .filter(
            PatchUpdatePlanHost.id == plan_host_id,
            PatchUpdatePlanHost.plan_id == plan_id,
        )
        .first()
    )
    if plan_host is None:
        raise PatchUpdatePlanError(
            f"plan host id={plan_host_id} not found on plan {plan_id}"
        )
    return (
        db.query(PatchUpdatePlanPreflightSnapshot)
        .filter(PatchUpdatePlanPreflightSnapshot.plan_host_id == plan_host_id)
        .order_by(
            PatchUpdatePlanPreflightSnapshot.content_availability_state.asc(),
            PatchUpdatePlanPreflightSnapshot.package_name.asc(),
        )
        .all()
    )


def list_plan_preflight(
    db: Session,
    *,
    plan_id: int,
    content_availability_state: Optional[str] = None,
) -> List[PatchUpdatePlanPreflightSnapshot]:
    """Plan-wide preflight lookup. Optional
    ``content_availability_state`` filter; invalid values raise
    :class:`PatchUpdatePlanError` (route 422)."""
    if (
        db.query(PatchUpdatePlan.id).filter(PatchUpdatePlan.id == plan_id).first()
        is None
    ):
        raise PatchUpdatePlanError(f"patch update plan id={plan_id} not found")
    if (
        content_availability_state is not None
        and content_availability_state not in VALID_CONTENT_AVAILABILITY_STATES
    ):
        raise PatchUpdatePlanError(
            f"content_availability_state={content_availability_state!r} must "
            f"be one of {sorted(VALID_CONTENT_AVAILABILITY_STATES)}"
        )
    q = (
        db.query(PatchUpdatePlanPreflightSnapshot)
        .join(
            PatchUpdatePlanHost,
            PatchUpdatePlanHost.id == PatchUpdatePlanPreflightSnapshot.plan_host_id,
        )
        .filter(PatchUpdatePlanHost.plan_id == plan_id)
    )
    if content_availability_state is not None:
        q = q.filter(
            PatchUpdatePlanPreflightSnapshot.content_availability_state
            == content_availability_state
        )
    return q.order_by(
        PatchUpdatePlanPreflightSnapshot.plan_host_id.asc(),
        PatchUpdatePlanPreflightSnapshot.content_availability_state.asc(),
        PatchUpdatePlanPreflightSnapshot.package_name.asc(),
    ).all()
