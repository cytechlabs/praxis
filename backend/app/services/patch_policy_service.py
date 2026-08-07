"""Patch policy CRUD + bind-time MW validation + triple-source bindings.

Slice 1b: policy CRUD with bind-time MW validation.
Slice 1c (this addition): host / static-group / smart-group bindings
plus their CRUD methods. Effective-policy resolver is slice 1d.

Bind-time MW validation enforces three things on every create or
update that touches ``maintenance_window_id`` or ``reboot_window_id``:

1. The referenced window row exists.
2. ``window.enabled`` is True.
3. ``window.schedule`` JSON parses (uses the same parser the
   ``maintenance_window_service`` consumes at apply time, so a
   malformed window can never be silently bound).

A patch policy that fails any of these checks raises
:class:`PatchPolicyError`; the route translates this to HTTP 422
with a structured ``detail``.

Audit emission for ``patch_policy.created`` / ``patch_policy.bound`` /
``patch_policy.unbound`` runs *after* the service commits its own
transaction, with no ``db=`` argument so ``safe_emit`` opens its own
``SessionLocal`` (per ``feedback_safe_emit_session_boundary.md``).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import (
    Group,
    MaintenanceWindow,
    PatchPolicy,
    PatchPolicyGroupBinding,
    PatchPolicyHostBinding,
    PatchPolicyRingBinding,
    PatchPolicySmartGroupBinding,
    PatchRing,
    PatchUpdatePlan,
    SmartGroup,
    SmartGroupMembership,
    System,
    User,
)
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception class — kept local so this service stays independent
# from approval / command surfaces (M16 implementation lock #3).
# ---------------------------------------------------------------------------


class PatchPolicyError(ValueError):
    """Raised when a patch policy create/update is rejected for
    semantic reasons (slug conflict, MW bind validation, etc.).

    Subclasses ``ValueError`` so route layers can map the whole
    family to HTTP 422.
    """


class EffectivePolicyConflict(PatchPolicyError):
    """Raised by :func:`resolve_effective_policy` when more than one
    enabled patch policy matches a host at the same precedence tier.

    The slice-1c lock is that the binding layer DOES allow multiple
    distinct policies bound to the same target. The resolver is the
    one that turns same-tier overlap into a loud failure. Routes map
    this to HTTP 409 Conflict with structured ``detail``.
    """

    def __init__(self, tier: str, policies):  # type: ignore[override]
        self.tier = tier
        # ``policies`` is a list of ``(policy_id, policy_slug)`` tuples
        # so the API response can name the rows the operator must fix.
        self.policies = list(policies)
        slug_summary = ", ".join(f"{pid}={slug!r}" for pid, slug in self.policies)
        super().__init__(
            f"effective patch policy conflict at tier={tier}: {slug_summary}"
        )


# ---------------------------------------------------------------------------
# Resolution-kind vocabulary (stable; consumed by API + smart-group
# predicates in slice 1e)
# ---------------------------------------------------------------------------


def _recompute_patch_smart_groups(db: Session) -> None:
    """Lazy hook into smart_group_service after a patch-policy mutation.

    Imported at call time so this module stays free of a hard
    dependency on smart_group_service (which already lazy-imports
    *this* module inside ``compute_patch_policy_index``). Exceptions
    are swallowed and logged — smart-group cache staleness is a
    background-sweep concern, not a reason to fail the operator's
    mutation.
    """
    try:
        from . import smart_group_service  # pylint: disable=import-outside-toplevel

        smart_group_service.recompute_patch_groups(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("recompute_patch_groups follow-on failed: %s", exc)


RESOLUTION_DIRECT_HOST = "direct_host"
RESOLUTION_STATIC_GROUP = "static_group"
RESOLUTION_SMART_GROUP = "smart_group"
RESOLUTION_FLEET_DEFAULT = "fleet_default"
RESOLUTION_NO_POLICY = "no_policy"


# ---------------------------------------------------------------------------
# Audit event-type strings — full M16 namespace reserved here per
# the design lock. Only ``patch_policy.created`` is emitted in slice 1b;
# other prefixes are reservation-only and will be emitted by their
# owning effort. Constants are sufficient — no fake audit rows.
# ---------------------------------------------------------------------------

AUDIT_PATCH_POLICY_CREATED = "patch_policy.created"
AUDIT_PATCH_POLICY_UPDATED = "patch_policy.updated"
AUDIT_PATCH_POLICY_DELETED = "patch_policy.deleted"
AUDIT_PATCH_POLICY_BOUND = "patch_policy.bound"
AUDIT_PATCH_POLICY_UNBOUND = "patch_policy.unbound"
AUDIT_PATCH_POLICY_FLEET_DEFAULT_SET = "patch_policy.fleet_default_set"
AUDIT_PATCH_POLICY_FLEET_DEFAULT_CLEARED = "patch_policy.fleet_default_cleared"
AUDIT_PATCH_POLICY_SCOPE_CHANGED = "patch_policy.scope_changed"  # slice 1e+
AUDIT_PATCH_POLICY_RING_BOUND = "patch_policy.ring_bound"
AUDIT_PATCH_POLICY_RING_UNBOUND = "patch_policy.ring_unbound"

# Reserved prefixes for downstream M16 efforts (no emission yet):
#   patch_ring.*          PRA-162
#   patch_advisory.*      PRA-163
#   patch_plan.*          PRA-164
#   patch_execution.*     PRA-171
#   patch_reboot.*        PRA-172
#   patch_rollback.*      PRA-173

# Staged-readiness vocabulary (slice 3) — surfaced via service +
# ``GET /patch/policies/{id}/staged-readiness``.
READINESS_NOT_STAGED = "not_staged"
READINESS_READY = "ready"
READINESS_MISSING_RING_SET = "missing_ring_set"
READINESS_NO_ENABLED_RINGS = "no_enabled_rings"


# ---------------------------------------------------------------------------
# Bind-time MW validation
# ---------------------------------------------------------------------------


def _parse_hhmm(value) -> bool:
    """Validate ``HH:MM`` shape and ranges the runtime consumes.

    ``maintenance_window_service`` parses via ``int().split(":")`` and
    silently skips bad shapes — which is exactly the trap a policy
    can fall into if we accept anything that "looks JSON-ish." Mirror
    the runtime's parser strictly here so a bound window is
    guaranteed-active at apply time.
    """
    if not isinstance(value, str):
        return False
    parts = value.split(":")
    if len(parts) != 2:
        return False
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
    except (TypeError, ValueError):
        return False
    if not (0 <= hours <= 23):
        return False
    if not (0 <= minutes <= 59):
        return False
    return True


def _parse_schedule(schedule_text: Optional[str]) -> bool:
    """Return True iff every schedule field the runtime consumes is
    well-formed.

    Required surface (slice 1b-a lock):

    * ``day_of_week`` — non-empty list of integers in ``[0, 6]``.
      An empty list silently disables the window at runtime, which
      would be a no-op bind.
    * ``start_time`` / ``end_time`` — present, ``HH:MM`` string,
      hours ``[0..23]``, minutes ``[0..59]``. The runtime's
      ``int().split(":")`` parser silently skips any other shape,
      which would also produce a no-op bind.

    Booleans are explicitly rejected for ``day_of_week`` entries
    because ``isinstance(True, int)`` is True (PRA-161 slice 1a
    bool-as-int trap carry-forward).
    """
    if not isinstance(schedule_text, str) or not schedule_text.strip():
        return False
    try:
        parsed = json.loads(schedule_text)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(parsed, dict):
        return False

    days = parsed.get("day_of_week")
    if not isinstance(days, list) or not days:
        return False
    for d in days:
        if isinstance(d, bool) or not isinstance(d, int):
            return False
        if not (0 <= d <= 6):
            return False

    if not _parse_hhmm(parsed.get("start_time")):
        return False
    if not _parse_hhmm(parsed.get("end_time")):
        return False

    return True


def _validate_window_binding(
    db: Session, window_id: Optional[int], field_label: str
) -> None:
    if window_id is None:
        return
    window = (
        db.query(MaintenanceWindow).filter(MaintenanceWindow.id == window_id).first()
    )
    if window is None:
        raise PatchPolicyError(
            f"{field_label}={window_id} does not reference an existing window"
        )
    if not window.enabled:
        raise PatchPolicyError(
            f"{field_label}={window_id} references a disabled window"
        )
    if not _parse_schedule(window.schedule):
        raise PatchPolicyError(
            f"{field_label}={window_id} window has a malformed schedule"
        )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def create_policy(
    db: Session,
    *,
    actor_user_id: int,
    actor_ip: Optional[str] = None,
    actor_username: Optional[str] = None,
    slug: str,
    name: str,
    description: Optional[str] = None,
    scope_kind: str,
    scope_packages: Optional[List[str]] = None,
    reboot_policy: str = "if_required",
    reboot_window_id: Optional[int] = None,
    maintenance_window_id: Optional[int] = None,
    requires_approval: bool = False,
    required_approvals: int = 1,
    rollout_cadence: str = "immediate",
    failure_policy: str = "pause_fleet",
    enabled: bool = True,
) -> PatchPolicy:
    if db.query(PatchPolicy.id).filter(PatchPolicy.slug == slug).first() is not None:
        raise PatchPolicyError(f"patch policy slug {slug!r} already exists")

    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchPolicyError(
            f"actor_user_id={actor_user_id} does not reference a user"
        )

    _validate_window_binding(db, maintenance_window_id, "maintenance_window_id")
    _validate_window_binding(db, reboot_window_id, "reboot_window_id")

    # Slice 3 draft-mode lock: a fresh policy has no ring bindings yet
    # by definition, so creating ``enabled=True`` + ``staged`` is the
    # exact silent-unusable state the guard exists to prevent.
    # Operators must create the policy disabled, bind enabled rings,
    # then enable. Mirrors the ``update_policy`` enable-without-rings
    # guard so create + update share the same invariant.
    if enabled and rollout_cadence == "staged":
        raise PatchPolicyError(
            "cannot create an enabled staged policy without ring bindings; "
            "create the policy disabled first, bind at least one enabled "
            "ring, then enable"
        )

    policy = PatchPolicy(
        slug=slug,
        name=name,
        description=description,
        scope_kind=scope_kind,
        scope_packages=list(scope_packages or []),
        reboot_policy=reboot_policy,
        reboot_window_id=reboot_window_id,
        maintenance_window_id=maintenance_window_id,
        requires_approval=requires_approval,
        required_approvals=required_approvals,
        rollout_cadence=rollout_cadence,
        failure_policy=failure_policy,
        enabled=enabled,
        created_by=actor_user_id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    # Audit AFTER our own commit, no db= so safe_emit opens its own
    # SessionLocal (feedback_safe_emit_session_boundary.md).
    safe_emit(
        action=AUDIT_PATCH_POLICY_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={
            "slug": policy.slug,
            "name": policy.name,
            "scope_kind": policy.scope_kind,
            "rollout_cadence": policy.rollout_cadence,
            "failure_policy": policy.failure_policy,
            "requires_approval": policy.requires_approval,
            "required_approvals": policy.required_approvals,
            "maintenance_window_id": policy.maintenance_window_id,
            "reboot_window_id": policy.reboot_window_id,
        },
    )

    _recompute_patch_smart_groups(db)
    return policy


def get_policy(db: Session, policy_id: int) -> Optional[PatchPolicy]:
    return db.query(PatchPolicy).filter(PatchPolicy.id == policy_id).first()


def get_policy_by_slug(db: Session, slug: str) -> Optional[PatchPolicy]:
    return db.query(PatchPolicy).filter(PatchPolicy.slug == slug).first()


def list_policies(
    db: Session,
    *,
    enabled_only: bool = False,
    offset: int = 0,
    limit: int = 100,
) -> Tuple[List[PatchPolicy], int]:
    q = db.query(PatchPolicy)
    if enabled_only:
        q = q.filter(PatchPolicy.enabled.is_(True))
    total = q.count()
    rows = q.order_by(PatchPolicy.slug.asc()).offset(offset).limit(limit).all()
    return rows, total


def update_policy(
    db: Session,
    policy_id: int,
    updates: Dict[str, Any],
    *,
    actor_user_id: int,
) -> PatchPolicy:
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == policy_id).first()
    if policy is None:
        raise PatchPolicyError(f"patch policy id={policy_id} not found")

    # MW binding validation must happen against the *new* values
    # before we mutate the row. We accept either explicit None (unbind)
    # or a positive int (rebind).
    if "maintenance_window_id" in updates:
        _validate_window_binding(
            db, updates["maintenance_window_id"], "maintenance_window_id"
        )
    if "reboot_window_id" in updates:
        _validate_window_binding(db, updates["reboot_window_id"], "reboot_window_id")

    # Cross-field invariant: scope_kind change can invalidate scope_packages.
    new_scope_kind = updates.get("scope_kind", policy.scope_kind)
    new_scope_packages = updates.get("scope_packages", policy.scope_packages)
    if new_scope_kind in {"security_only", "full"} and new_scope_packages:
        raise PatchPolicyError(
            f"scope_packages must be empty when scope_kind={new_scope_kind!r}"
        )
    if (
        new_scope_kind in {"package_allowlist", "package_denylist"}
        and not new_scope_packages
    ):
        raise PatchPolicyError(
            f"scope_packages must be non-empty when scope_kind={new_scope_kind!r}"
        )

    # Slice 3 staged-readiness guard: an enabled staged policy must
    # have at least one enabled bound ring. The pre-mutation effective
    # state is built from {existing fields} + {requested updates}; if
    # that combo would land an enabled+staged policy with zero enabled
    # rings, reject the update. Disabled-staged is a legal draft state.
    new_enabled = updates.get("enabled", policy.enabled)
    new_cadence = updates.get("rollout_cadence", policy.rollout_cadence)
    if new_enabled and new_cadence == "staged":
        if _enabled_ring_count_for_policy(db, policy.id) == 0:
            raise PatchPolicyError(
                f"cannot leave enabled staged policy {policy.slug!r} "
                "with no enabled bound rings; bind an enabled ring "
                "first or keep the policy disabled until ready"
            )

    # Slice 3 staged-to-immediate guard: rolling a policy back to
    # ``immediate`` while it still has ring bindings would orphan the
    # bindings on a policy whose semantics no longer use them. Force
    # the operator to unbind explicitly so the audit trail records
    # the cleanup; no silent data loss.
    if (
        new_cadence == "immediate"
        and policy.rollout_cadence == "staged"
        and (
            db.query(PatchPolicyRingBinding.id)
            .filter(PatchPolicyRingBinding.policy_id == policy.id)
            .first()
            is not None
        )
    ):
        raise PatchPolicyError(
            f"cannot transition staged policy {policy.slug!r} to "
            "immediate while ring bindings exist; unbind all rings "
            "first to record the cleanup explicitly"
        )

    for key, value in updates.items():
        setattr(policy, key, value)

    db.commit()
    db.refresh(policy)
    _recompute_patch_smart_groups(db)
    return policy


def delete_policy(db: Session, policy_id: int) -> None:
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == policy_id).first()
    if policy is None:
        raise PatchPolicyError(f"patch policy id={policy_id} not found")

    # PRA-355: bounded, operator-readable refusals for protected / in-use
    # policies — previously these fell through to db.commit() and raised an
    # unhandled IntegrityError (patch_update_plans.policy_id is ON DELETE
    # RESTRICT), which the route surfaced as a raw HTTP 500.
    if policy.is_fleet_default:
        raise PatchPolicyError(
            f"patch policy id={policy_id} is the fleet default and cannot be "
            "deleted; clear the fleet default first, then delete it"
        )
    # PRA-355: distinguish ACTIVE (visible) plans from ARCHIVED/retired ones.
    # Active plans still block the delete via the RESTRICT FK — refuse with
    # operator copy. Archived plans are audit tombstones: an admin may delete a
    # policy whose only remaining links are archived, so we DETACH them
    # (policy_id → NULL). Their policy_snapshot preserves the policy identity,
    # so the audit trail survives.
    active_plan_count = (
        db.query(PatchUpdatePlan)
        .filter(
            PatchUpdatePlan.policy_id == policy_id,
            PatchUpdatePlan.archived_at.is_(None),
        )
        .count()
    )
    if active_plan_count:
        raise PatchPolicyError(
            f"patch policy id={policy_id} is used by {active_plan_count} active "
            f"patch update plan{'s' if active_plan_count != 1 else ''} and cannot "
            "be deleted; archive or delete linked update plans first"
        )
    detached = (
        db.query(PatchUpdatePlan)
        .filter(
            PatchUpdatePlan.policy_id == policy_id,
            PatchUpdatePlan.archived_at.isnot(None),
        )
        .update({PatchUpdatePlan.policy_id: None}, synchronize_session="fetch")
    )
    if detached:
        logger.info(
            "patch policy id=%s delete: detached %s archived update plan(s) "
            "(policy identity preserved in each plan's policy_snapshot)",
            policy_id,
            detached,
        )

    # Host / group / smart-group / ring bindings are ON DELETE CASCADE, so an
    # unused policy deletes cleanly. Any remaining RESTRICT reference is caught
    # defensively and surfaced as a bounded 422 rather than a 500.
    db.delete(policy)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.warning(
            "patch policy id=%s delete blocked by a database reference: %s",
            policy_id,
            exc,
        )
        raise PatchPolicyError(
            f"patch policy id={policy_id} is still referenced by other records "
            "and cannot be deleted"
        ) from exc
    _recompute_patch_smart_groups(db)


# ---------------------------------------------------------------------------
# Bindings — slice 1c
# ---------------------------------------------------------------------------
#
# Three sibling tables (host / static-group / smart-group) bind a policy
# to a target. Each binding is independent: a second policy bound to the
# same target IS allowed at this layer; the resolver (slice 1d) is the
# one that turns multi-policy-at-same-tier into a loud
# ``EffectivePolicyConflict``.


def _require_policy(db: Session, policy_id: int) -> PatchPolicy:
    policy = db.query(PatchPolicy).filter(PatchPolicy.id == policy_id).first()
    if policy is None:
        raise PatchPolicyError(f"patch policy id={policy_id} not found")
    return policy


def _require_target(db: Session, model, target_id: int, label: str):
    """Validate that a binding target row exists.

    Worded "does not exist" rather than "not found" on purpose: the
    route's HTTP-status disambiguation maps "not found" → 404 (used
    for missing-policy errors). A missing *target* is a 422 — the
    request was syntactically valid but the FK does not resolve.
    """
    row = db.query(model).filter(model.id == target_id).first()
    if row is None:
        raise PatchPolicyError(f"{label}={target_id} does not exist")
    return row


def _emit_binding_audit(
    *,
    action: str,
    policy: PatchPolicy,
    kind: str,
    target_id: int,
    actor_user_id: int,
    actor_username: Optional[str],
    actor_ip: Optional[str],
) -> None:
    safe_emit(
        action=action,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "binding_kind": kind,
            "target_id": target_id,
        },
    )


def bind_host(
    db: Session,
    *,
    policy_id: int,
    system_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicyHostBinding:
    policy = _require_policy(db, policy_id)
    _require_target(db, System, system_id, "system_id")

    existing = (
        db.query(PatchPolicyHostBinding)
        .filter(
            PatchPolicyHostBinding.policy_id == policy_id,
            PatchPolicyHostBinding.system_id == system_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchPolicyError(
            f"policy {policy_id} is already bound to host {system_id}"
        )

    binding = PatchPolicyHostBinding(
        policy_id=policy_id,
        system_id=system_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_BOUND,
        policy=policy,
        kind="host",
        target_id=system_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)
    return binding


def unbind_host(
    db: Session,
    *,
    policy_id: int,
    system_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    policy = _require_policy(db, policy_id)
    binding = (
        db.query(PatchPolicyHostBinding)
        .filter(
            PatchPolicyHostBinding.policy_id == policy_id,
            PatchPolicyHostBinding.system_id == system_id,
        )
        .first()
    )
    if binding is None:
        raise PatchPolicyError(f"policy {policy_id} is not bound to host {system_id}")
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_UNBOUND,
        policy=policy,
        kind="host",
        target_id=system_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)


def bind_group(
    db: Session,
    *,
    policy_id: int,
    group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicyGroupBinding:
    policy = _require_policy(db, policy_id)
    _require_target(db, Group, group_id, "group_id")

    existing = (
        db.query(PatchPolicyGroupBinding)
        .filter(
            PatchPolicyGroupBinding.policy_id == policy_id,
            PatchPolicyGroupBinding.group_id == group_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchPolicyError(
            f"policy {policy_id} is already bound to group {group_id}"
        )

    binding = PatchPolicyGroupBinding(
        policy_id=policy_id,
        group_id=group_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_BOUND,
        policy=policy,
        kind="group",
        target_id=group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)
    return binding


def unbind_group(
    db: Session,
    *,
    policy_id: int,
    group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    policy = _require_policy(db, policy_id)
    binding = (
        db.query(PatchPolicyGroupBinding)
        .filter(
            PatchPolicyGroupBinding.policy_id == policy_id,
            PatchPolicyGroupBinding.group_id == group_id,
        )
        .first()
    )
    if binding is None:
        raise PatchPolicyError(f"policy {policy_id} is not bound to group {group_id}")
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_UNBOUND,
        policy=policy,
        kind="group",
        target_id=group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)


def bind_smart_group(
    db: Session,
    *,
    policy_id: int,
    smart_group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicySmartGroupBinding:
    policy = _require_policy(db, policy_id)
    sg = _require_target(db, SmartGroup, smart_group_id, "smart_group_id")

    # Cycle guard (slice 1e lock): a smart group whose rule references
    # ``patch.*`` cannot be bound as a patch-policy target. Membership
    # of such a smart group depends on the resolver result, which in
    # turn would depend on this very binding — a feedback loop. The
    # guard runs at bind time so the bad state is never persisted.
    from . import smart_group_service  # pylint: disable=import-outside-toplevel

    if smart_group_service.rule_references_patch(sg.rule_json):
        raise PatchPolicyError(
            f"smart group {smart_group_id} ({sg.name!r}) references patch.* "
            f"predicates and cannot be bound as a patch-policy target — "
            f"this would create a feedback loop where membership depends "
            f"on the policy that membership assigns"
        )

    existing = (
        db.query(PatchPolicySmartGroupBinding)
        .filter(
            PatchPolicySmartGroupBinding.policy_id == policy_id,
            PatchPolicySmartGroupBinding.smart_group_id == smart_group_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchPolicyError(
            f"policy {policy_id} is already bound to smart group " f"{smart_group_id}"
        )

    binding = PatchPolicySmartGroupBinding(
        policy_id=policy_id,
        smart_group_id=smart_group_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_BOUND,
        policy=policy,
        kind="smart_group",
        target_id=smart_group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)
    return binding


def unbind_smart_group(
    db: Session,
    *,
    policy_id: int,
    smart_group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    policy = _require_policy(db, policy_id)
    binding = (
        db.query(PatchPolicySmartGroupBinding)
        .filter(
            PatchPolicySmartGroupBinding.policy_id == policy_id,
            PatchPolicySmartGroupBinding.smart_group_id == smart_group_id,
        )
        .first()
    )
    if binding is None:
        raise PatchPolicyError(
            f"policy {policy_id} is not bound to smart group " f"{smart_group_id}"
        )
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_POLICY_UNBOUND,
        policy=policy,
        kind="smart_group",
        target_id=smart_group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_patch_smart_groups(db)


def list_bindings(db: Session, policy_id: int) -> Dict[str, Any]:
    """Return all three binding kinds for a policy in one envelope.

    Lets the slice-1f UI render a policy detail page without three
    round trips. Raises ``PatchPolicyError`` (→ 404) if the policy
    does not exist; an empty list per kind is the legitimate
    "no bindings" answer.
    """
    _require_policy(db, policy_id)
    hosts = (
        db.query(PatchPolicyHostBinding)
        .filter(PatchPolicyHostBinding.policy_id == policy_id)
        .order_by(PatchPolicyHostBinding.system_id.asc())
        .all()
    )
    groups = (
        db.query(PatchPolicyGroupBinding)
        .filter(PatchPolicyGroupBinding.policy_id == policy_id)
        .order_by(PatchPolicyGroupBinding.group_id.asc())
        .all()
    )
    smart_groups = (
        db.query(PatchPolicySmartGroupBinding)
        .filter(PatchPolicySmartGroupBinding.policy_id == policy_id)
        .order_by(PatchPolicySmartGroupBinding.smart_group_id.asc())
        .all()
    )
    return {
        "policy_id": policy_id,
        "hosts": hosts,
        "groups": groups,
        "smart_groups": smart_groups,
    }


# ---------------------------------------------------------------------------
# Effective-policy resolver — slice 1d
# ---------------------------------------------------------------------------


def _enabled_policies_for_host_direct(db: Session, host_id: int) -> List[PatchPolicy]:
    return (
        db.query(PatchPolicy)
        .join(
            PatchPolicyHostBinding,
            PatchPolicyHostBinding.policy_id == PatchPolicy.id,
        )
        .filter(
            PatchPolicyHostBinding.system_id == host_id,
            PatchPolicy.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _enabled_policies_for_static_group(db: Session, group_id: int) -> List[PatchPolicy]:
    return (
        db.query(PatchPolicy)
        .join(
            PatchPolicyGroupBinding,
            PatchPolicyGroupBinding.policy_id == PatchPolicy.id,
        )
        .filter(
            PatchPolicyGroupBinding.group_id == group_id,
            PatchPolicy.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _enabled_policies_for_smart_groups(db: Session, host_id: int) -> List[PatchPolicy]:
    """Smart-group tier: a patch policy is effective via this tier only
    when **all three** rows are enabled — the policy itself, the smart
    group it is bound to, and the host's membership in that smart group.

    ``SmartGroupMembership`` rows are a materialized cache that can
    remain present after a smart group is disabled (the cache is
    rebuilt on rule change, not on enable-toggle). Filtering on
    ``SmartGroup.enabled = true`` here matches the operator
    expectation that disabling a smart group removes it from policy
    targeting, and matches the join the content-profile resolver uses
    for smart-group subscriptions.
    """
    return (
        db.query(PatchPolicy)
        .join(
            PatchPolicySmartGroupBinding,
            PatchPolicySmartGroupBinding.policy_id == PatchPolicy.id,
        )
        .join(
            SmartGroup,
            SmartGroup.id == PatchPolicySmartGroupBinding.smart_group_id,
        )
        .join(
            SmartGroupMembership,
            SmartGroupMembership.smart_group_id == SmartGroup.id,
        )
        .filter(
            SmartGroupMembership.system_id == host_id,
            SmartGroup.enabled.is_(True),
            PatchPolicy.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _enabled_fleet_defaults(db: Session) -> List[PatchPolicy]:
    return (
        db.query(PatchPolicy)
        .filter(
            PatchPolicy.is_fleet_default.is_(True),
            PatchPolicy.enabled.is_(True),
        )
        .all()
    )


def _resolve_tier(tier: str, policies: List[PatchPolicy]) -> Optional[PatchPolicy]:
    """Return the single enabled policy at this tier, or raise on
    same-tier overlap. Empty list means "fall through to next tier"."""
    if not policies:
        return None
    if len(policies) > 1:
        raise EffectivePolicyConflict(tier, [(p.id, p.slug) for p in policies])
    return policies[0]


def resolve_effective_policy(
    db: Session, host_id: int
) -> Tuple[Optional[PatchPolicy], str]:
    """Walk direct → static-group → smart-group → fleet-default and
    return ``(policy, resolution_kind)``.

    Returns ``(None, "no_policy")`` when no tier matches and no enabled
    fleet default is configured. Raises :class:`PatchPolicyError` if
    the host does not exist, and :class:`EffectivePolicyConflict` if
    multiple distinct enabled policies match at the same tier.

    Disabled policies are skipped at every tier (a disabled policy is
    never effective, even if it has the ``is_fleet_default`` flag set).
    """
    host = db.query(System).filter(System.id == host_id).first()
    if host is None:
        raise PatchPolicyError(f"host id={host_id} not found")

    direct = _resolve_tier(
        RESOLUTION_DIRECT_HOST,
        _enabled_policies_for_host_direct(db, host_id),
    )
    if direct is not None:
        return direct, RESOLUTION_DIRECT_HOST

    if host.group_id is not None:
        static = _resolve_tier(
            RESOLUTION_STATIC_GROUP,
            _enabled_policies_for_static_group(db, host.group_id),
        )
        if static is not None:
            return static, RESOLUTION_STATIC_GROUP

    smart = _resolve_tier(
        RESOLUTION_SMART_GROUP,
        _enabled_policies_for_smart_groups(db, host_id),
    )
    if smart is not None:
        return smart, RESOLUTION_SMART_GROUP

    fleet = _resolve_tier(RESOLUTION_FLEET_DEFAULT, _enabled_fleet_defaults(db))
    if fleet is not None:
        return fleet, RESOLUTION_FLEET_DEFAULT

    return None, RESOLUTION_NO_POLICY


# ---------------------------------------------------------------------------
# Fleet-default set / clear — slice 1d
# ---------------------------------------------------------------------------


def set_fleet_default(
    db: Session,
    policy_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicy:
    """Mark ``policy_id`` as the fleet default, atomically clearing any
    previous fleet-default row first.

    The DB partial unique index on ``is_fleet_default = true`` guards
    against races that bypass the service. This service path keeps the
    invariant clean for callers that go through it: at-most-one
    is_fleet_default=true row at any time.

    Idempotent: if ``policy_id`` is already the fleet default, no
    write happens and no audit row is emitted.
    """
    policy = _require_policy(db, policy_id)
    if policy.is_fleet_default:
        return policy

    prior = (
        db.query(PatchPolicy)
        .filter(
            PatchPolicy.is_fleet_default.is_(True),
            PatchPolicy.id != policy.id,
        )
        .first()
    )
    prior_slug: Optional[str] = None
    prior_id: Optional[int] = None
    if prior is not None:
        prior.is_fleet_default = False
        prior_slug = prior.slug
        prior_id = prior.id
        db.flush()

    policy.is_fleet_default = True
    db.commit()
    db.refresh(policy)

    safe_emit(
        action=AUDIT_PATCH_POLICY_FLEET_DEFAULT_SET,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "previous_fleet_default_id": prior_id,
            "previous_fleet_default_slug": prior_slug,
        },
    )
    _recompute_patch_smart_groups(db)
    return policy


def clear_fleet_default(
    db: Session,
    policy_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicy:
    """Clear the fleet-default flag on ``policy_id``.

    Idempotent: if the policy is not currently the fleet default, no
    write happens and no audit row is emitted.
    """
    policy = _require_policy(db, policy_id)
    if not policy.is_fleet_default:
        return policy

    policy.is_fleet_default = False
    db.commit()
    db.refresh(policy)

    safe_emit(
        action=AUDIT_PATCH_POLICY_FLEET_DEFAULT_CLEARED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={"policy_slug": policy.slug},
    )
    _recompute_patch_smart_groups(db)
    return policy


# ---------------------------------------------------------------------------
# Policy → ring-set binding + staged-readiness — slice 3
# ---------------------------------------------------------------------------
#
# A staged patch policy declares the rings it is allowed to roll out
# across. Immediate policies do not use ring sets. Bind/unbind enforce:
#
#   * policy must exist and be ``rollout_cadence='staged'``
#   * ring must exist
#   * new bindings to a disabled ring are rejected (existing bindings
#     to a later-disabled ring stay visible so operators can fix them)
#   * duplicate (policy_id, ring_id) is a strict 422 (slice 1c convention)
#   * unbinding the last enabled ring from an ENABLED staged policy is
#     rejected — disabled policies may be drained to empty as a draft
#     state per the slice 3 design choice
#
# The enable-without-rings guard (``update_policy``) blocks the other
# silent-unusable path: an enabled staged policy with no enabled rings
# cannot remain in that state via update either.


def _enabled_ring_count_for_policy(db: Session, policy_id: int) -> int:
    return (
        db.query(PatchPolicyRingBinding.id)
        .join(PatchRing, PatchRing.id == PatchPolicyRingBinding.ring_id)
        .filter(
            PatchPolicyRingBinding.policy_id == policy_id,
            PatchRing.enabled.is_(True),
        )
        .count()
    )


def bind_policy_ring(
    db: Session,
    *,
    policy_id: int,
    ring_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchPolicyRingBinding:
    policy = _require_policy(db, policy_id)
    if policy.rollout_cadence != "staged":
        raise PatchPolicyError(
            f"policy {policy.slug!r} is not staged "
            f"(rollout_cadence={policy.rollout_cadence!r}); "
            "ring bindings only apply to staged policies"
        )

    ring = db.query(PatchRing).filter(PatchRing.id == ring_id).first()
    if ring is None:
        raise PatchPolicyError(f"ring_id={ring_id} does not exist")
    if not ring.enabled:
        raise PatchPolicyError(
            f"ring {ring.slug!r} is disabled; new bindings to disabled "
            "rings are not allowed"
        )

    existing = (
        db.query(PatchPolicyRingBinding)
        .filter(
            PatchPolicyRingBinding.policy_id == policy_id,
            PatchPolicyRingBinding.ring_id == ring_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchPolicyError(f"policy {policy_id} is already bound to ring {ring_id}")

    binding = PatchPolicyRingBinding(
        policy_id=policy_id,
        ring_id=ring_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    safe_emit(
        action=AUDIT_PATCH_POLICY_RING_BOUND,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "ring_id": ring.id,
            "ring_slug": ring.slug,
        },
    )
    return binding


def unbind_policy_ring(
    db: Session,
    *,
    policy_id: int,
    ring_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    policy = _require_policy(db, policy_id)
    binding = (
        db.query(PatchPolicyRingBinding)
        .filter(
            PatchPolicyRingBinding.policy_id == policy_id,
            PatchPolicyRingBinding.ring_id == ring_id,
        )
        .first()
    )
    if binding is None:
        raise PatchPolicyError(f"policy {policy_id} is not bound to ring {ring_id}")

    # Last-enabled-ring guard for ENABLED staged policies. Disabled
    # policies may be drained to empty as a draft state.
    if policy.enabled and policy.rollout_cadence == "staged":
        ring = db.query(PatchRing).filter(PatchRing.id == ring_id).first()
        # If the ring being removed is enabled, removing it might leave
        # the policy with zero usable rings.
        if ring is not None and ring.enabled:
            remaining_enabled = (
                db.query(PatchPolicyRingBinding.id)
                .join(PatchRing, PatchRing.id == PatchPolicyRingBinding.ring_id)
                .filter(
                    PatchPolicyRingBinding.policy_id == policy_id,
                    PatchPolicyRingBinding.ring_id != ring_id,
                    PatchRing.enabled.is_(True),
                )
                .count()
            )
            if remaining_enabled == 0:
                raise PatchPolicyError(
                    f"cannot unbind last enabled ring from enabled staged "
                    f"policy {policy.slug!r}; disable the policy first or "
                    "bind a replacement ring"
                )

    ring_slug = binding.ring.slug if binding.ring is not None else None
    db.delete(binding)
    db.commit()

    safe_emit(
        action=AUDIT_PATCH_POLICY_RING_UNBOUND,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_policy",
        target_id=str(policy.id),
        context={
            "policy_slug": policy.slug,
            "ring_id": ring_id,
            "ring_slug": ring_slug,
        },
    )


def list_policy_rings(
    db: Session, policy_id: int
) -> List[Tuple[PatchPolicyRingBinding, PatchRing]]:
    """Return ``(binding, ring)`` tuples ordered by global rollout
    order: ``PatchRing.sort_order`` ascending then ``slug`` for tiebreak.

    Operators reading the list want to see canary → pilot → prod, not
    "in the order I happened to bind them in." A disabled ring still
    appears here so the operator can spot stale bindings; readiness
    explicitly distinguishes that case.
    """
    _require_policy(db, policy_id)
    rows = (
        db.query(PatchPolicyRingBinding, PatchRing)
        .join(PatchRing, PatchRing.id == PatchPolicyRingBinding.ring_id)
        .filter(PatchPolicyRingBinding.policy_id == policy_id)
        .order_by(PatchRing.sort_order.asc(), PatchRing.slug.asc())
        .all()
    )
    return rows


def get_staged_readiness(db: Session, policy_id: int) -> Dict[str, Any]:
    """Return a structured readiness verdict for a patch policy.

    Status vocabulary (string constants live next to ``RESOLUTION_*``):

    * ``"not_staged"``  – ``rollout_cadence='immediate'``; rings N/A.
    * ``"ready"``       – staged + ≥ 1 enabled bound ring.
    * ``"missing_ring_set"`` – staged + zero bindings.
    * ``"no_enabled_rings"`` – staged + has bindings, all disabled.

    Readiness is pure validation/state. It does not generate plans,
    promote rings, or emit audit rows.
    """
    policy = _require_policy(db, policy_id)

    base: Dict[str, Any] = {
        "policy_id": policy.id,
        "policy_slug": policy.slug,
        "rollout_cadence": policy.rollout_cadence,
        "enabled": policy.enabled,
    }

    if policy.rollout_cadence != "staged":
        return {
            **base,
            "status": READINESS_NOT_STAGED,
            "message": (
                f"policy is {policy.rollout_cadence!r}; ring sets only "
                "apply to staged policies"
            ),
            "ring_count": 0,
            "enabled_ring_count": 0,
        }

    rows = list_policy_rings(db, policy.id)
    enabled_count = sum(1 for _, ring in rows if ring.enabled)

    if not rows:
        return {
            **base,
            "status": READINESS_MISSING_RING_SET,
            "message": "staged policy has no bound rings",
            "ring_count": 0,
            "enabled_ring_count": 0,
        }
    if enabled_count == 0:
        return {
            **base,
            "status": READINESS_NO_ENABLED_RINGS,
            "message": (
                "staged policy is bound only to disabled rings; rebind "
                "an enabled ring or re-enable the existing rings"
            ),
            "ring_count": len(rows),
            "enabled_ring_count": 0,
        }
    return {
        **base,
        "status": READINESS_READY,
        "message": None,
        "ring_count": len(rows),
        "enabled_ring_count": enabled_count,
    }
