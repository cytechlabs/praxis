"""Patch ring CRUD + triple-source membership bindings (PRA-162 slice 1)
plus the effective-ring resolver (PRA-162 slice 2).

Pure data layer + binding CRUD. Policy → ring-set binding and gate
evaluation are deliberately out of scope (deferred to later slices).

Design locks (carry-forward from PRA-161):

* Local exception class (``PatchRingError``) so this service stays
  independent from the patch_policy / approval surfaces.
* ``safe_emit`` audit emission with no ``db=`` argument so it opens
  its own ``SessionLocal`` per ``feedback_safe_emit_session_boundary.md``.
* Audit happens AFTER the service's own commit. No audit on
  idempotent no-ops.
* No fake namespace-reservation rows — only real configuration
  changes hit audit.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import (
    Group,
    PatchRing,
    PatchRingGateDefinition,
    PatchRingGateSignal,
    PatchRingGroupBinding,
    PatchRingHostBinding,
    PatchRingSmartGroupBinding,
    SmartGroup,
    SmartGroupMembership,
    System,
    User,
)
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local exception class
# ---------------------------------------------------------------------------


class PatchRingError(ValueError):
    """Raised when a ring create/update/binding is rejected for
    semantic reasons (slug conflict, unknown FK target, etc.).

    Subclasses ``ValueError`` so route layers can map the family to
    HTTP 422.
    """


# ---------------------------------------------------------------------------
# Audit event-type strings — slice 1 ships create/updated/deleted +
# bound/unbound. Promotion / gate audit lands in later slices.
# ---------------------------------------------------------------------------

AUDIT_PATCH_RING_CREATED = "patch_ring.created"
AUDIT_PATCH_RING_UPDATED = "patch_ring.updated"
AUDIT_PATCH_RING_DELETED = "patch_ring.deleted"
AUDIT_PATCH_RING_BOUND = "patch_ring.bound"
AUDIT_PATCH_RING_UNBOUND = "patch_ring.unbound"

# Slice 4: gate definition + stored signal mutation audits.
AUDIT_PATCH_RING_GATE_CREATED = "patch_ring.gate_created"
AUDIT_PATCH_RING_GATE_UPDATED = "patch_ring.gate_updated"
AUDIT_PATCH_RING_GATE_DELETED = "patch_ring.gate_deleted"
AUDIT_PATCH_RING_GATE_SIGNAL_RECORDED = "patch_ring.gate_signal_recorded"
AUDIT_PATCH_RING_GATE_SIGNAL_DELETED = "patch_ring.gate_signal_deleted"

# Reserved for downstream PRA-162 slices (constants, no emission yet):
#   patch_ring.promoted           — auto-promotion slice (deferred)


# ---------------------------------------------------------------------------
# Slice 4 vocabularies (stable; consumed by API + tests)
# ---------------------------------------------------------------------------

GATE_KIND_BOOLEAN = "boolean"
GATE_KIND_THRESHOLD = "threshold"
VALID_GATE_KINDS = {GATE_KIND_BOOLEAN, GATE_KIND_THRESHOLD}

VALID_COMPARATORS = {"eq", "ne", "gt", "gte", "lt", "lte"}

SIGNAL_STATUS_PASS = "pass"
SIGNAL_STATUS_FAIL = "fail"
VALID_SIGNAL_STATUSES = {SIGNAL_STATUS_PASS, SIGNAL_STATUS_FAIL}

VALID_SOURCE_KINDS = {"manual", "execution", "reboot", "probe", "external"}

# Promotion-readiness verdicts (priority order: ring_disabled > blocked
# > missing_signal > no_gates > ready). Blocked beats missing because
# a failing signal is a louder signal than absence.
PROMOTION_RING_DISABLED = "ring_disabled"
PROMOTION_BLOCKED = "blocked"
PROMOTION_MISSING_SIGNAL = "missing_signal"
PROMOTION_NO_GATES = "no_gates"
PROMOTION_READY = "ready"

# Per-gate detail status values (consumed by ``promotion-readiness``
# response). ``ignored_optional`` covers an optional gate that would
# have been blocking/missing if required — kept distinct so operators
# can spot near-misses.
GATE_DETAIL_SATISFIED = "satisfied"
GATE_DETAIL_FAILING = "failing"
GATE_DETAIL_MISSING = "missing"
GATE_DETAIL_EXPIRED = "expired"
GATE_DETAIL_DISABLED = "disabled"
GATE_DETAIL_IGNORED_OPTIONAL = "ignored_optional"


# ---------------------------------------------------------------------------
# Smart-group ring.* recompute hook (PRA-162 #5)
# ---------------------------------------------------------------------------


def _recompute_ring_smart_groups(db: Session) -> None:
    """Lazy hook into smart_group_service after a ring mutation.

    Imported at call time so this module stays free of a hard
    dependency on smart_group_service (which already lazy-imports
    *this* module inside ``compute_ring_index``). Exceptions are
    swallowed and logged — smart-group cache staleness is a
    background-sweep concern, not a reason to fail the operator's
    mutation.
    """
    try:
        from . import smart_group_service  # pylint: disable=import-outside-toplevel

        smart_group_service.recompute_ring_groups(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("recompute_ring_groups follow-on failed: %s", exc)


# ---------------------------------------------------------------------------
# Default ring set
# ---------------------------------------------------------------------------

DEFAULT_RING_SEED: List[Dict[str, Any]] = [
    {
        "slug": "canary",
        "name": "Canary",
        "description": (
            "Smallest rollout tier. First to receive an update; the "
            "set of hosts that prove the change is safe before pilot."
        ),
        "sort_order": 1,
    },
    {
        "slug": "pilot",
        "name": "Pilot",
        "description": (
            "Second rollout tier. Validates an update on a wider but "
            "still-bounded set of hosts before prod."
        ),
        "sort_order": 2,
    },
    {
        "slug": "prod",
        "name": "Prod",
        "description": (
            "Terminal rollout tier. The fleet at large; only "
            "promoted to after canary and pilot pass their gates."
        ),
        "sort_order": 3,
    },
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_ring(db: Session, ring_id: int) -> PatchRing:
    ring = db.query(PatchRing).filter(PatchRing.id == ring_id).first()
    if ring is None:
        raise PatchRingError(f"patch ring id={ring_id} not found")
    return ring


def _require_target(db: Session, model, target_id: int, label: str):
    """Validate that a binding target row exists.

    Worded "does not exist" rather than "not found" on purpose —
    same convention as PRA-161 slice 1c-a so the route's HTTP-status
    disambiguation maps missing-ring → 404 and missing-FK-target → 422.
    """
    row = db.query(model).filter(model.id == target_id).first()
    if row is None:
        raise PatchRingError(f"{label}={target_id} does not exist")
    return row


def _emit_binding_audit(
    *,
    action: str,
    ring: PatchRing,
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
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "ring_slug": ring.slug,
            "binding_kind": kind,
            "target_id": target_id,
        },
    )


# ---------------------------------------------------------------------------
# Ring CRUD
# ---------------------------------------------------------------------------


def create_ring(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    slug: str,
    name: str,
    description: Optional[str] = None,
    sort_order: int,
    enabled: bool = True,
) -> PatchRing:
    if db.query(PatchRing.id).filter(PatchRing.slug == slug).first() is not None:
        raise PatchRingError(f"patch ring slug {slug!r} already exists")

    if (
        db.query(PatchRing.id).filter(PatchRing.sort_order == sort_order).first()
        is not None
    ):
        raise PatchRingError(f"patch ring sort_order={sort_order} already exists")

    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchRingError(f"actor_user_id={actor_user_id} does not reference a user")

    ring = PatchRing(
        slug=slug,
        name=name,
        description=description,
        sort_order=sort_order,
        enabled=enabled,
        created_by=actor_user_id,
    )
    db.add(ring)
    db.commit()
    db.refresh(ring)

    safe_emit(
        action=AUDIT_PATCH_RING_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "slug": ring.slug,
            "name": ring.name,
            "sort_order": ring.sort_order,
            "enabled": ring.enabled,
        },
    )
    return ring


def get_ring(db: Session, ring_id: int) -> Optional[PatchRing]:
    return db.query(PatchRing).filter(PatchRing.id == ring_id).first()


def get_ring_by_slug(db: Session, slug: str) -> Optional[PatchRing]:
    return db.query(PatchRing).filter(PatchRing.slug == slug).first()


def list_rings(
    db: Session,
    *,
    enabled_only: bool = False,
) -> List[PatchRing]:
    """List rings ordered by ``sort_order`` ascending, then ``slug``
    as a tiebreaker (DB unique enforces no actual ties).
    """
    q = db.query(PatchRing)
    if enabled_only:
        q = q.filter(PatchRing.enabled.is_(True))
    return q.order_by(PatchRing.sort_order.asc(), PatchRing.slug.asc()).all()


def update_ring(
    db: Session,
    ring_id: int,
    updates: Dict[str, Any],
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchRing:
    ring = db.query(PatchRing).filter(PatchRing.id == ring_id).first()
    if ring is None:
        raise PatchRingError(f"patch ring id={ring_id} not found")

    # If sort_order is being changed, defend the unique constraint at
    # the service layer too so the route can map collisions to 422
    # instead of bubbling an IntegrityError.
    if "sort_order" in updates:
        new_order = updates["sort_order"]
        if new_order is not None and new_order != ring.sort_order:
            collision = (
                db.query(PatchRing.id)
                .filter(
                    PatchRing.sort_order == new_order,
                    PatchRing.id != ring.id,
                )
                .first()
            )
            if collision is not None:
                raise PatchRingError(
                    f"patch ring sort_order={new_order} already exists"
                )

    changed: Dict[str, Tuple[Any, Any]] = {}
    for key, value in updates.items():
        if value is None and key in {"sort_order", "name", "enabled"}:
            # These fields are NOT NULL on the model — never accept None
            # via a partial update (the route schema marks them
            # ``Optional[...]`` only so omitted fields can be skipped).
            raise PatchRingError(f"{key} cannot be null")
        before = getattr(ring, key)
        if before != value:
            changed[key] = (before, value)
            setattr(ring, key, value)

    if not changed:
        # Idempotent no-op — no commit, no audit (audit is for real
        # configuration changes only per the slice 1 acceptance crit).
        return ring

    db.commit()
    db.refresh(ring)

    safe_emit(
        action=AUDIT_PATCH_RING_UPDATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "slug": ring.slug,
            "changed_fields": sorted(changed.keys()),
        },
    )
    # PRA-162 #5 / #5-a: refresh ring.* smart groups whenever a field
    # the predicate surface reads is changed. ``enabled`` flips
    # ``ring.has_effective_ring`` and the resolver's verdict;
    # ``name`` is exposed via ``ring.effective_name`` predicates so a
    # rename must propagate to dependent groups.
    # ``description`` / ``sort_order`` are not in any ring.* field, so
    # they correctly skip the recompute. ``slug`` is immutable
    # post-create at the schema layer, so we don't need to handle it.
    if changed.keys() & {"enabled", "name"}:
        _recompute_ring_smart_groups(db)
    return ring


def delete_ring(
    db: Session,
    ring_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = db.query(PatchRing).filter(PatchRing.id == ring_id).first()
    if ring is None:
        raise PatchRingError(f"patch ring id={ring_id} not found")
    slug = ring.slug
    sort_order = ring.sort_order
    db.delete(ring)
    db.commit()

    safe_emit(
        action=AUDIT_PATCH_RING_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring_id),
        context={"slug": slug, "sort_order": sort_order},
    )
    # PRA-162 #5: deleting a ring (FK CASCADE removes its bindings) can
    # change resolver verdicts for hosts that were resolving via this
    # ring. Refresh ring.* smart groups.
    _recompute_ring_smart_groups(db)


# ---------------------------------------------------------------------------
# Default ring seed
# ---------------------------------------------------------------------------


def seed_default_rings(
    db: Session,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Idempotently create the default canary → pilot → prod ring set.

    Returns ``{"created": [...slugs], "existing": [...slugs], "rings":
    [...PatchRing]}`` so the caller knows which rows were new in this
    call. Audit emits one ``patch_ring.created`` event per *new* row;
    no audit row is emitted for already-existing slugs (the function
    is a no-op for those).

    If a default slug exists but is owned by someone else (a previous
    operator's CRUD), it is left untouched — only missing slugs are
    created. The function does not adjust sort_order on existing rows;
    if an operator deliberately reordered their existing canary, the
    seed call respects that.
    """
    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchRingError(f"actor_user_id={actor_user_id} does not reference a user")

    created: List[str] = []
    existing: List[str] = []
    for spec in DEFAULT_RING_SEED:
        slug = spec["slug"]
        row = db.query(PatchRing).filter(PatchRing.slug == slug).first()
        if row is not None:
            existing.append(slug)
            continue

        # If the canonical sort_order is already taken (operator
        # reshuffled), fall back to the next free integer >= the spec
        # so the seed never crashes the call.
        target_order = spec["sort_order"]
        if (
            db.query(PatchRing.id).filter(PatchRing.sort_order == target_order).first()
            is not None
        ):
            highest = (
                db.query(PatchRing.sort_order)
                .order_by(PatchRing.sort_order.desc())
                .limit(1)
                .scalar()
            )
            target_order = (highest or 0) + 1

        new_ring = PatchRing(
            slug=slug,
            name=spec["name"],
            description=spec["description"],
            sort_order=target_order,
            enabled=True,
            created_by=actor_user_id,
        )
        db.add(new_ring)
        db.commit()
        db.refresh(new_ring)
        created.append(slug)

        safe_emit(
            action=AUDIT_PATCH_RING_CREATED,
            outcome="success",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_ip=actor_ip,
            target_kind="patch_ring",
            target_id=str(new_ring.id),
            context={
                "slug": new_ring.slug,
                "name": new_ring.name,
                "sort_order": new_ring.sort_order,
                "enabled": new_ring.enabled,
                "via": "seed_default_rings",
            },
        )

    rings = list_rings(db)
    return {"created": created, "existing": existing, "rings": rings}


# ---------------------------------------------------------------------------
# Membership bindings
# ---------------------------------------------------------------------------


def bind_host(
    db: Session,
    *,
    ring_id: int,
    system_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchRingHostBinding:
    ring = _require_ring(db, ring_id)
    _require_target(db, System, system_id, "system_id")

    existing = (
        db.query(PatchRingHostBinding)
        .filter(
            PatchRingHostBinding.ring_id == ring_id,
            PatchRingHostBinding.system_id == system_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchRingError(f"ring {ring_id} is already bound to host {system_id}")

    binding = PatchRingHostBinding(
        ring_id=ring_id,
        system_id=system_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_BOUND,
        ring=ring,
        kind="host",
        target_id=system_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)
    return binding


def unbind_host(
    db: Session,
    *,
    ring_id: int,
    system_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = _require_ring(db, ring_id)
    binding = (
        db.query(PatchRingHostBinding)
        .filter(
            PatchRingHostBinding.ring_id == ring_id,
            PatchRingHostBinding.system_id == system_id,
        )
        .first()
    )
    if binding is None:
        raise PatchRingError(f"ring {ring_id} is not bound to host {system_id}")
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_UNBOUND,
        ring=ring,
        kind="host",
        target_id=system_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)


def bind_group(
    db: Session,
    *,
    ring_id: int,
    group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchRingGroupBinding:
    ring = _require_ring(db, ring_id)
    _require_target(db, Group, group_id, "group_id")

    existing = (
        db.query(PatchRingGroupBinding)
        .filter(
            PatchRingGroupBinding.ring_id == ring_id,
            PatchRingGroupBinding.group_id == group_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchRingError(f"ring {ring_id} is already bound to group {group_id}")

    binding = PatchRingGroupBinding(
        ring_id=ring_id,
        group_id=group_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_BOUND,
        ring=ring,
        kind="group",
        target_id=group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)
    return binding


def unbind_group(
    db: Session,
    *,
    ring_id: int,
    group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = _require_ring(db, ring_id)
    binding = (
        db.query(PatchRingGroupBinding)
        .filter(
            PatchRingGroupBinding.ring_id == ring_id,
            PatchRingGroupBinding.group_id == group_id,
        )
        .first()
    )
    if binding is None:
        raise PatchRingError(f"ring {ring_id} is not bound to group {group_id}")
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_UNBOUND,
        ring=ring,
        kind="group",
        target_id=group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)


def bind_smart_group(
    db: Session,
    *,
    ring_id: int,
    smart_group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchRingSmartGroupBinding:
    """Bind a smart group as a ring membership source.

    PRA-162 #5 cycle guard: a smart group whose rule references any
    ``ring.*`` field cannot be bound as a ring source. Membership
    would depend on the ring that membership itself assigns; the
    feedback loop would never converge. Mirrors the PRA-161 #1e
    cycle guard on the patch_policy_service side.
    """
    ring = _require_ring(db, ring_id)
    sg = _require_target(db, SmartGroup, smart_group_id, "smart_group_id")

    # Lazy import — smart_group_service transitively imports
    # patch_ring_service via compute_ring_index.
    from . import smart_group_service  # pylint: disable=import-outside-toplevel

    if smart_group_service.rule_references_ring(sg.rule_json):
        raise PatchRingError(
            f"smart group {smart_group_id} references ring.* predicates and "
            "cannot be bound as a ring membership source (cycle)"
        )

    existing = (
        db.query(PatchRingSmartGroupBinding)
        .filter(
            PatchRingSmartGroupBinding.ring_id == ring_id,
            PatchRingSmartGroupBinding.smart_group_id == smart_group_id,
        )
        .first()
    )
    if existing is not None:
        raise PatchRingError(
            f"ring {ring_id} is already bound to smart group {smart_group_id}"
        )

    binding = PatchRingSmartGroupBinding(
        ring_id=ring_id,
        smart_group_id=smart_group_id,
        created_by=actor_user_id,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_BOUND,
        ring=ring,
        kind="smart_group",
        target_id=smart_group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)
    return binding


def unbind_smart_group(
    db: Session,
    *,
    ring_id: int,
    smart_group_id: int,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = _require_ring(db, ring_id)
    binding = (
        db.query(PatchRingSmartGroupBinding)
        .filter(
            PatchRingSmartGroupBinding.ring_id == ring_id,
            PatchRingSmartGroupBinding.smart_group_id == smart_group_id,
        )
        .first()
    )
    if binding is None:
        raise PatchRingError(
            f"ring {ring_id} is not bound to smart group {smart_group_id}"
        )
    db.delete(binding)
    db.commit()

    _emit_binding_audit(
        action=AUDIT_PATCH_RING_UNBOUND,
        ring=ring,
        kind="smart_group",
        target_id=smart_group_id,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
    )
    _recompute_ring_smart_groups(db)


def list_bindings(db: Session, ring_id: int) -> Dict[str, Any]:
    """Return all three binding kinds for a ring in one envelope."""
    _require_ring(db, ring_id)
    hosts = (
        db.query(PatchRingHostBinding)
        .filter(PatchRingHostBinding.ring_id == ring_id)
        .order_by(PatchRingHostBinding.system_id.asc())
        .all()
    )
    groups = (
        db.query(PatchRingGroupBinding)
        .filter(PatchRingGroupBinding.ring_id == ring_id)
        .order_by(PatchRingGroupBinding.group_id.asc())
        .all()
    )
    smart_groups = (
        db.query(PatchRingSmartGroupBinding)
        .filter(PatchRingSmartGroupBinding.ring_id == ring_id)
        .order_by(PatchRingSmartGroupBinding.smart_group_id.asc())
        .all()
    )
    return {
        "ring_id": ring_id,
        "hosts": hosts,
        "groups": groups,
        "smart_groups": smart_groups,
    }


# ---------------------------------------------------------------------------
# Effective-ring resolver (PRA-162 slice 2)
# ---------------------------------------------------------------------------
#
# Walks direct host > static group > smart group ring bindings and
# returns a structured result with one of three statuses:
#
#   "no_ring"   no enabled candidate at any tier
#   "resolved"  exactly one distinct enabled ring at the winning tier
#   "conflict"  same-tier overlap of distinct enabled rings
#
# Conflict is exposed as a *state*, not an exception, so the route can
# return 200 with both status and candidate summaries — same shape the
# patch-policy resolver's frontend client converts to internally and
# the same conflict-as-state pattern PRA-161 slice 1e established for
# `patch.*` predicates. The route still 404s on unknown hosts via
# ``PatchRingError`` from ``_require_target``.

STATUS_NO_RING = "no_ring"
STATUS_RESOLVED = "resolved"
STATUS_CONFLICT = "conflict"

SOURCE_TIER_HOST = "host"
SOURCE_TIER_GROUP = "group"
SOURCE_TIER_SMART_GROUP = "smart_group"


@dataclasses.dataclass(frozen=True)
class EffectiveRingResult:
    """Structured resolver result.

    ``ring`` is populated when ``status == "resolved"``.
    ``candidates`` is populated when ``status == "conflict"`` (the
    distinct enabled rings that collided at ``source_tier``).
    ``source_tier`` is set for both ``resolved`` and ``conflict``;
    it is ``None`` for ``no_ring``.
    """

    status: str
    system_id: int
    source_tier: Optional[str]
    ring: Optional[PatchRing]
    candidates: List[PatchRing]
    message: Optional[str]


def _enabled_rings_for_host_direct(db: Session, host_id: int) -> List[PatchRing]:
    return (
        db.query(PatchRing)
        .join(
            PatchRingHostBinding,
            PatchRingHostBinding.ring_id == PatchRing.id,
        )
        .filter(
            PatchRingHostBinding.system_id == host_id,
            PatchRing.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _enabled_rings_for_static_group(db: Session, group_id: int) -> List[PatchRing]:
    return (
        db.query(PatchRing)
        .join(
            PatchRingGroupBinding,
            PatchRingGroupBinding.ring_id == PatchRing.id,
        )
        .filter(
            PatchRingGroupBinding.group_id == group_id,
            PatchRing.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _enabled_rings_for_smart_groups(db: Session, host_id: int) -> List[PatchRing]:
    """Smart-group tier: a ring is effective via this tier only when
    all three rows are enabled — the ring, the smart group it is bound
    to, and the host's membership in that smart group.

    Mirrors the patch-policy resolver's smart-group filter: the
    materialized ``SmartGroupMembership`` cache can outlive a smart
    group's enable-toggle, so we filter on ``SmartGroup.enabled = true``
    explicitly rather than relying on the cache's freshness.
    """
    return (
        db.query(PatchRing)
        .join(
            PatchRingSmartGroupBinding,
            PatchRingSmartGroupBinding.ring_id == PatchRing.id,
        )
        .join(
            SmartGroup,
            SmartGroup.id == PatchRingSmartGroupBinding.smart_group_id,
        )
        .join(
            SmartGroupMembership,
            SmartGroupMembership.smart_group_id == SmartGroup.id,
        )
        .filter(
            SmartGroupMembership.system_id == host_id,
            SmartGroup.enabled.is_(True),
            PatchRing.enabled.is_(True),
        )
        .distinct()
        .all()
    )


def _resolve_tier(
    tier: str,
    rings: List[PatchRing],
    *,
    system_id: int,
) -> Optional[EffectiveRingResult]:
    """Return a resolver result for this tier, or ``None`` to fall
    through. ``distinct()`` already collapses same-ring duplicates at
    the SQL layer; if more than one row remains we treat that as a
    same-tier conflict."""
    if not rings:
        return None
    if len(rings) == 1:
        return EffectiveRingResult(
            status=STATUS_RESOLVED,
            system_id=system_id,
            source_tier=tier,
            ring=rings[0],
            candidates=[],
            message=None,
        )
    # Order by sort_order then slug so the conflict payload reads in a
    # stable, operator-friendly order regardless of insertion order.
    ordered = sorted(rings, key=lambda r: (r.sort_order, r.slug))
    summary = ", ".join(f"{r.id}={r.slug!r}" for r in ordered)
    return EffectiveRingResult(
        status=STATUS_CONFLICT,
        system_id=system_id,
        source_tier=tier,
        ring=None,
        candidates=ordered,
        message=(f"effective patch ring conflict at tier={tier}: {summary}"),
    )


def resolve_effective_ring(db: Session, host_id: int) -> EffectiveRingResult:
    """Walk direct → static-group → smart-group and return the
    :class:`EffectiveRingResult` for ``host_id``.

    Raises :class:`PatchRingError` if the host does not exist (route
    layer maps that to HTTP 404). All three success/no-ring/conflict
    outcomes are returned as a structured value so the route can
    surface them as 200 with an explicit ``status`` field.
    """
    host = db.query(System).filter(System.id == host_id).first()
    if host is None:
        raise PatchRingError(f"host id={host_id} not found")

    direct = _resolve_tier(
        SOURCE_TIER_HOST,
        _enabled_rings_for_host_direct(db, host_id),
        system_id=host_id,
    )
    if direct is not None:
        return direct

    if host.group_id is not None:
        static = _resolve_tier(
            SOURCE_TIER_GROUP,
            _enabled_rings_for_static_group(db, host.group_id),
            system_id=host_id,
        )
        if static is not None:
            return static

    smart = _resolve_tier(
        SOURCE_TIER_SMART_GROUP,
        _enabled_rings_for_smart_groups(db, host_id),
        system_id=host_id,
    )
    if smart is not None:
        return smart

    return EffectiveRingResult(
        status=STATUS_NO_RING,
        system_id=host_id,
        source_tier=None,
        ring=None,
        candidates=[],
        message="no enabled patch ring resolves for this host",
    )


# ---------------------------------------------------------------------------
# Slice 4: ring gate definitions, stored gate signals, promotion readiness
# ---------------------------------------------------------------------------
#
# Definitions describe what evidence a ring expects before it can be
# promoted. Signals carry that evidence (recorded manually here; future
# PRA-171/172 writers attach via ``source_kind``). Promotion-readiness
# is computed from stored rows only — no probes, no execution, no
# auto-promotion. Disabled gates are skipped; expired signals do not
# satisfy a gate; the latest non-expired signal per (ring, signal_key)
# wins.


# -- Gate definition CRUD --------------------------------------------------


def _validate_gate_kind(gate_kind: str) -> None:
    if gate_kind not in VALID_GATE_KINDS:
        raise PatchRingError(
            f"gate_kind={gate_kind!r} must be one of {sorted(VALID_GATE_KINDS)}"
        )


def _validate_comparator(comparator: Optional[str]) -> None:
    if comparator is None:
        return
    if comparator not in VALID_COMPARATORS:
        raise PatchRingError(
            f"comparator={comparator!r} must be one of " f"{sorted(VALID_COMPARATORS)}"
        )


def _validate_gate_shape(
    gate_kind: str,
    comparator: Optional[str],
    parameters: Optional[Dict[str, Any]],
) -> None:
    """Cross-field invariants for gate kinds.

    * ``boolean`` gates ignore ``comparator``; ``parameters`` may be
      ``None`` (defaulted to ``{"expected": true}``) or
      ``{"expected": <bool>}``.
    * ``threshold`` gates require ``comparator`` and a numeric
      ``parameters.threshold``. The signal value at evaluation time
      must also be numeric; that's a runtime check.
    """
    if gate_kind == GATE_KIND_BOOLEAN:
        if parameters is not None:
            if not isinstance(parameters, dict):
                raise PatchRingError("boolean gate parameters must be an object")
            if "expected" in parameters and not isinstance(
                parameters["expected"], bool
            ):
                raise PatchRingError(
                    "boolean gate parameters.expected must be a boolean"
                )
        return

    if gate_kind == GATE_KIND_THRESHOLD:
        if comparator is None:
            raise PatchRingError(
                "threshold gates require a comparator (eq/ne/gt/gte/lt/lte)"
            )
        if not isinstance(parameters, dict) or "threshold" not in parameters:
            raise PatchRingError(
                "threshold gates require parameters.threshold (numeric)"
            )
        threshold = parameters["threshold"]
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise PatchRingError("threshold gate parameters.threshold must be numeric")


def create_gate(
    db: Session,
    ring_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    signal_key: str,
    name: str,
    description: Optional[str] = None,
    gate_kind: str,
    comparator: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    required: bool = True,
    enabled: bool = True,
) -> PatchRingGateDefinition:
    ring = _require_ring(db, ring_id)
    _validate_gate_kind(gate_kind)
    _validate_comparator(comparator)
    _validate_gate_shape(gate_kind, comparator, parameters)

    if (
        db.query(PatchRingGateDefinition.id)
        .filter(
            PatchRingGateDefinition.ring_id == ring_id,
            PatchRingGateDefinition.signal_key == signal_key,
        )
        .first()
        is not None
    ):
        raise PatchRingError(
            f"ring {ring_id} already has a gate for signal_key {signal_key!r}"
        )

    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchRingError(f"actor_user_id={actor_user_id} does not reference a user")

    gate = PatchRingGateDefinition(
        ring_id=ring_id,
        signal_key=signal_key,
        name=name,
        description=description,
        gate_kind=gate_kind,
        comparator=comparator if gate_kind == GATE_KIND_THRESHOLD else None,
        parameters=parameters,
        required=required,
        enabled=enabled,
        created_by=actor_user_id,
    )
    db.add(gate)
    db.commit()
    db.refresh(gate)

    safe_emit(
        action=AUDIT_PATCH_RING_GATE_CREATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "gate_id": gate.id,
            "ring_slug": ring.slug,
            "signal_key": gate.signal_key,
            "gate_kind": gate.gate_kind,
            "required": gate.required,
            "enabled": gate.enabled,
        },
    )
    return gate


def list_gates(
    db: Session, ring_id: int, *, enabled_only: bool = False
) -> List[PatchRingGateDefinition]:
    _require_ring(db, ring_id)
    q = db.query(PatchRingGateDefinition).filter(
        PatchRingGateDefinition.ring_id == ring_id
    )
    if enabled_only:
        q = q.filter(PatchRingGateDefinition.enabled.is_(True))
    return q.order_by(PatchRingGateDefinition.signal_key.asc()).all()


def get_gate(db: Session, gate_id: int) -> Optional[PatchRingGateDefinition]:
    return (
        db.query(PatchRingGateDefinition)
        .filter(PatchRingGateDefinition.id == gate_id)
        .first()
    )


def update_gate(
    db: Session,
    ring_id: int,
    gate_id: int,
    updates: Dict[str, Any],
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> PatchRingGateDefinition:
    ring = _require_ring(db, ring_id)
    gate = (
        db.query(PatchRingGateDefinition)
        .filter(
            PatchRingGateDefinition.id == gate_id,
            PatchRingGateDefinition.ring_id == ring_id,
        )
        .first()
    )
    if gate is None:
        raise PatchRingError(f"gate id={gate_id} not found on ring {ring_id}")

    # ``signal_key`` is intentionally immutable post-create (cleaner to
    # delete + recreate; otherwise stored signals lose their definition
    # link). Reject the field at the service layer too.
    if "signal_key" in updates:
        raise PatchRingError("signal_key is immutable on a gate definition")

    new_kind = updates.get("gate_kind", gate.gate_kind)
    new_comparator = updates.get("comparator", gate.comparator)
    new_parameters = updates.get("parameters", gate.parameters)
    if any(k in updates for k in ("gate_kind", "comparator", "parameters")):
        _validate_gate_kind(new_kind)
        _validate_comparator(new_comparator)
        _validate_gate_shape(new_kind, new_comparator, new_parameters)

    changed: Dict[str, Tuple[Any, Any]] = {}
    for key, value in updates.items():
        if value is None and key in {"name", "gate_kind", "required", "enabled"}:
            raise PatchRingError(f"{key} cannot be null")
        before = getattr(gate, key)
        if before != value:
            changed[key] = (before, value)
            setattr(gate, key, value)

    if not changed:
        return gate

    # Boolean gates store a NULL comparator (kind invariant).
    if gate.gate_kind == GATE_KIND_BOOLEAN:
        gate.comparator = None

    db.commit()
    db.refresh(gate)

    safe_emit(
        action=AUDIT_PATCH_RING_GATE_UPDATED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "gate_id": gate.id,
            "ring_slug": ring.slug,
            "signal_key": gate.signal_key,
            "changed_fields": sorted(changed.keys()),
        },
    )
    return gate


def delete_gate(
    db: Session,
    ring_id: int,
    gate_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = _require_ring(db, ring_id)
    gate = (
        db.query(PatchRingGateDefinition)
        .filter(
            PatchRingGateDefinition.id == gate_id,
            PatchRingGateDefinition.ring_id == ring_id,
        )
        .first()
    )
    if gate is None:
        raise PatchRingError(f"gate id={gate_id} not found on ring {ring_id}")
    signal_key = gate.signal_key
    db.delete(gate)
    db.commit()

    safe_emit(
        action=AUDIT_PATCH_RING_GATE_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "gate_id": gate_id,
            "ring_slug": ring.slug,
            "signal_key": signal_key,
        },
    )


# -- Stored gate signals ---------------------------------------------------


def record_gate_signal(
    db: Session,
    ring_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    signal_key: str,
    status: str,
    value: Optional[Any] = None,
    details: Optional[Dict[str, Any]] = None,
    source_kind: str = "manual",
    source_ref_kind: Optional[str] = None,
    source_ref_id: Optional[str] = None,
    observed_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
) -> PatchRingGateSignal:
    """Record a stored gate signal on a ring.

    The signal is matched to a gate definition by ``signal_key`` —
    same string the definition declares. We also store an optional
    ``gate_definition_id`` FK for navigation; if no matching enabled
    definition exists, the signal is still accepted (operators can
    record evidence ahead of declaring a gate, and PRA-171/172
    writers may emit signals without a 1:1 definition mapping).
    The FK is ``ON DELETE SET NULL`` so historical signals survive
    a definition removal.
    """
    ring = _require_ring(db, ring_id)
    if status not in VALID_SIGNAL_STATUSES:
        raise PatchRingError(
            f"status={status!r} must be one of {sorted(VALID_SIGNAL_STATUSES)}"
        )
    if source_kind not in VALID_SOURCE_KINDS:
        raise PatchRingError(
            f"source_kind={source_kind!r} must be one of "
            f"{sorted(VALID_SOURCE_KINDS)}"
        )

    if not db.query(User.id).filter(User.id == actor_user_id).first():
        raise PatchRingError(f"actor_user_id={actor_user_id} does not reference a user")

    matching_def = (
        db.query(PatchRingGateDefinition)
        .filter(
            PatchRingGateDefinition.ring_id == ring_id,
            PatchRingGateDefinition.signal_key == signal_key,
        )
        .first()
    )

    signal = PatchRingGateSignal(
        ring_id=ring_id,
        gate_definition_id=matching_def.id if matching_def is not None else None,
        signal_key=signal_key,
        status=status,
        value=value,
        details=details,
        source_kind=source_kind,
        source_ref_kind=source_ref_kind,
        source_ref_id=source_ref_id,
        observed_at=observed_at or datetime.utcnow(),
        expires_at=expires_at,
        created_by=actor_user_id,
    )
    db.add(signal)
    db.commit()
    db.refresh(signal)

    safe_emit(
        action=AUDIT_PATCH_RING_GATE_SIGNAL_RECORDED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "signal_id": signal.id,
            "ring_slug": ring.slug,
            "signal_key": signal_key,
            "status": status,
            "source_kind": source_kind,
        },
    )
    return signal


def list_gate_signals(
    db: Session,
    ring_id: int,
    *,
    signal_key: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[PatchRingGateSignal]:
    """List signals ordered by latest ``observed_at`` first.

    Filters by ``signal_key`` when provided. ``limit`` caps the
    returned rows; readiness evaluation uses an internal latest-only
    query, not this list."""
    _require_ring(db, ring_id)
    q = db.query(PatchRingGateSignal).filter(PatchRingGateSignal.ring_id == ring_id)
    if signal_key is not None:
        q = q.filter(PatchRingGateSignal.signal_key == signal_key)
    q = q.order_by(
        PatchRingGateSignal.observed_at.desc(),
        PatchRingGateSignal.id.desc(),
    )
    if limit is not None:
        q = q.limit(limit)
    return q.all()


def delete_gate_signal(
    db: Session,
    ring_id: int,
    signal_id: int,
    *,
    actor_user_id: int,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
) -> None:
    ring = _require_ring(db, ring_id)
    signal = (
        db.query(PatchRingGateSignal)
        .filter(
            PatchRingGateSignal.id == signal_id,
            PatchRingGateSignal.ring_id == ring_id,
        )
        .first()
    )
    if signal is None:
        raise PatchRingError(f"gate signal id={signal_id} not found on ring {ring_id}")
    signal_key = signal.signal_key
    db.delete(signal)
    db.commit()

    safe_emit(
        action=AUDIT_PATCH_RING_GATE_SIGNAL_DELETED,
        outcome="success",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        actor_ip=actor_ip,
        target_kind="patch_ring",
        target_id=str(ring.id),
        context={
            "signal_id": signal_id,
            "ring_slug": ring.slug,
            "signal_key": signal_key,
        },
    )


# -- Promotion readiness ---------------------------------------------------


def _latest_non_expired_signal(
    db: Session, ring_id: int, signal_key: str, *, now: datetime
) -> Optional[PatchRingGateSignal]:
    return (
        db.query(PatchRingGateSignal)
        .filter(
            PatchRingGateSignal.ring_id == ring_id,
            PatchRingGateSignal.signal_key == signal_key,
            (PatchRingGateSignal.expires_at.is_(None))
            | (PatchRingGateSignal.expires_at > now),
        )
        .order_by(
            PatchRingGateSignal.observed_at.desc(),
            PatchRingGateSignal.id.desc(),
        )
        .first()
    )


def _signal_satisfies_gate(
    gate: PatchRingGateDefinition, signal: PatchRingGateSignal
) -> bool:
    """Check whether a signal's value satisfies a gate's
    kind+comparator+parameters. ``signal.status`` must be ``pass``;
    a fail signal never satisfies regardless of value."""
    if signal.status != SIGNAL_STATUS_PASS:
        return False

    if gate.gate_kind == GATE_KIND_BOOLEAN:
        expected = True
        if isinstance(gate.parameters, dict) and "expected" in gate.parameters:
            expected = bool(gate.parameters["expected"])
        # If the signal value is missing, ``status==pass`` already
        # implies the gate's binary outcome; require the value to
        # match expected only when the operator recorded one.
        if signal.value is None:
            return True
        return bool(signal.value) == expected

    if gate.gate_kind == GATE_KIND_THRESHOLD:
        if not isinstance(gate.parameters, dict) or "threshold" not in gate.parameters:
            return False
        threshold = gate.parameters["threshold"]
        comparator = gate.comparator or "gte"
        value = signal.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if comparator == "eq":
            return value == threshold
        if comparator == "ne":
            return value != threshold
        if comparator == "gt":
            return value > threshold
        if comparator == "gte":
            return value >= threshold
        if comparator == "lt":
            return value < threshold
        if comparator == "lte":
            return value <= threshold
        return False

    return False


def evaluate_promotion_readiness(
    db: Session, ring_id: int, *, now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Return a structured promotion-readiness verdict for a ring.

    Pure stored-state evaluation — no probes, no execution. Disabled
    rings short-circuit to ``ring_disabled`` regardless of gate state.
    Optional gates appear in ``gates`` but never determine ``status``.
    """
    ring = _require_ring(db, ring_id)
    now = now or datetime.utcnow()

    if not ring.enabled:
        return {
            "ring_id": ring.id,
            "ring_slug": ring.slug,
            "ring_enabled": False,
            "status": PROMOTION_RING_DISABLED,
            "message": "ring is disabled; promotion readiness is not actionable",
            "required_gate_count": 0,
            "enabled_gate_count": 0,
            "gates": [],
        }

    all_gates = (
        db.query(PatchRingGateDefinition)
        .filter(PatchRingGateDefinition.ring_id == ring_id)
        .order_by(PatchRingGateDefinition.signal_key.asc())
        .all()
    )

    enabled_gates = [g for g in all_gates if g.enabled]
    if not enabled_gates:
        # Surface disabled gates in the per-gate list so the operator
        # can still see what was once configured.
        gate_details = [
            {
                "gate_id": g.id,
                "signal_key": g.signal_key,
                "name": g.name,
                "gate_kind": g.gate_kind,
                "required": g.required,
                "enabled": g.enabled,
                "gate_status": GATE_DETAIL_DISABLED,
                "message": "gate is disabled",
                "signal": None,
            }
            for g in all_gates
        ]
        return {
            "ring_id": ring.id,
            "ring_slug": ring.slug,
            "ring_enabled": True,
            "status": PROMOTION_NO_GATES,
            "message": "ring has no enabled gate definitions",
            "required_gate_count": 0,
            "enabled_gate_count": 0,
            "gates": gate_details,
        }

    gate_details: List[Dict[str, Any]] = []
    has_blocking_required = False
    has_missing_required = False
    required_count = 0

    for gate in enabled_gates:
        if gate.required:
            required_count += 1

        signal = _latest_non_expired_signal(db, ring_id, gate.signal_key, now=now)
        # Stale-but-present: an expired signal is treated as missing
        # for verdict purposes but reported with its own detail status
        # so operators see the difference.
        expired_signal = None
        if signal is None:
            expired_signal = (
                db.query(PatchRingGateSignal)
                .filter(
                    PatchRingGateSignal.ring_id == ring_id,
                    PatchRingGateSignal.signal_key == gate.signal_key,
                )
                .order_by(
                    PatchRingGateSignal.observed_at.desc(),
                    PatchRingGateSignal.id.desc(),
                )
                .first()
            )

        if signal is None:
            if expired_signal is not None:
                detail_status = GATE_DETAIL_EXPIRED
                message = "latest signal has expired"
            else:
                detail_status = GATE_DETAIL_MISSING
                message = "no signal recorded for this gate"
            if not gate.required:
                detail_status = GATE_DETAIL_IGNORED_OPTIONAL
            elif gate.required:
                has_missing_required = True
            gate_details.append(
                {
                    "gate_id": gate.id,
                    "signal_key": gate.signal_key,
                    "name": gate.name,
                    "gate_kind": gate.gate_kind,
                    "required": gate.required,
                    "enabled": gate.enabled,
                    "gate_status": detail_status,
                    "message": message,
                    "signal": expired_signal,
                }
            )
            continue

        if _signal_satisfies_gate(gate, signal):
            gate_details.append(
                {
                    "gate_id": gate.id,
                    "signal_key": gate.signal_key,
                    "name": gate.name,
                    "gate_kind": gate.gate_kind,
                    "required": gate.required,
                    "enabled": gate.enabled,
                    "gate_status": GATE_DETAIL_SATISFIED,
                    "message": None,
                    "signal": signal,
                }
            )
        else:
            if gate.required:
                has_blocking_required = True
                detail_status = GATE_DETAIL_FAILING
            else:
                detail_status = GATE_DETAIL_IGNORED_OPTIONAL
            gate_details.append(
                {
                    "gate_id": gate.id,
                    "signal_key": gate.signal_key,
                    "name": gate.name,
                    "gate_kind": gate.gate_kind,
                    "required": gate.required,
                    "enabled": gate.enabled,
                    "gate_status": detail_status,
                    "message": (
                        f"signal status={signal.status!r} does not satisfy "
                        f"gate (kind={gate.gate_kind})"
                    ),
                    "signal": signal,
                }
            )

    if has_blocking_required:
        verdict = PROMOTION_BLOCKED
        message = "one or more required gates have a failing signal"
    elif has_missing_required:
        verdict = PROMOTION_MISSING_SIGNAL
        message = "one or more required gates have no current passing signal"
    else:
        verdict = PROMOTION_READY
        message = None

    return {
        "ring_id": ring.id,
        "ring_slug": ring.slug,
        "ring_enabled": True,
        "status": verdict,
        "message": message,
        "required_gate_count": required_count,
        "enabled_gate_count": len(enabled_gates),
        "gates": gate_details,
    }
