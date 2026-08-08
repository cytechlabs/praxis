"""Smart group rule evaluator + cache refresher (PRA-126).

Rule DSL:
    {"op": "and"|"or", "rules": [ <group> | <condition>, ... ]}
    <condition> = {"field": "<name>", "op": "<op>", "value": <scalar|list|bool>}

Supported fields and ops:
    hostname, ip_address, os_version, update_policy   — eq, neq, contains, regex
    status, distro, group, tag, environment_type      — in, not_in
    has_pending_updates, has_security_updates,
    ca_trust_deployed                                 — eq
    days_since_last_audit                             — eq, gt, lt, gte, lte
    lifecycle.status (PRA-156 #3c)                    — in, not_in
    lifecycle.days_to_eol (PRA-156 #3c)               — eq, gt, lt, gte, lte

``facts.*`` predicates follow the PRA-155 #2d null-FALSE rule:
missing/null facts evaluate FALSE for every predicate including
negative arms.

``lifecycle.*`` predicates follow their OWN namespace rule (PRA-156
#3c lock): ``unknown`` is a real value of ``lifecycle.status``, so
``lifecycle.status in ["unknown"]`` matches missing/stale-fact hosts
and ``lifecycle.status not_in ["supported"]`` includes them.
``lifecycle.days_to_eol`` is NULL for unknown hosts; numeric
predicates against it follow standard SQL three-valued logic
(operators wanting unknown hosts must use ``lifecycle.status``).

Membership is cached in smart_group_memberships and recomputed on:
    - SmartGroup create/update
    - System mutations (best-effort; a scheduled sweep handles gaps)
    - Tag / static-group reassignment
    - host_facts upserts (recompute_fact_groups_for_system AND
      recompute_lifecycle_groups_for_system both fire from
      FactsService.ingest)
    - Daily lifecycle recompute pass (today moves without a facts
      upsert; scheduler_service runs the pass on a fixed cadence)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import and_, exists, func, not_, or_, select
from sqlalchemy.orm import Session

from ..db.models import (
    Distro,
    Group,
    HostFacts,
    Package,
    PackageUpdate,
    SmartGroup,
    SmartGroupMembership,
    System,
    SystemMetadata,
    Tag,
    system_tag,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Field catalog
# ---------------------------------------------------------------------------


STRING_FIELDS: Set[str] = {
    "hostname",
    "ip_address",
    "os_version",
    "update_policy",
    # PRA-155 #2d: facts.* fields. Prefix keeps fact predicates
    # visually grouped + future-proofs against name collisions with
    # System columns. ``kernel_version`` ships as STRING (eq/contains/
    # regex). Semver compare is a separate operator family that
    # PRA-155 explicitly defers — operators wanting "kernel < X" can
    # use regex for v1.
    "facts.kernel_version",
    "facts.package_manager_version",
    # PRA-161 #1e: effective patch-policy slug for the host. Populated
    # only when the resolver returns a single enabled policy.
    # null-FALSE for no_policy / conflict (operators wanting those
    # states use ``patch.resolution_kind``).
    "patch.effective_policy_slug",
    # PRA-162 #5: effective ring slug + name for the host. Populated
    # only when the resolver returns a single resolved ring.
    # null-FALSE for no_ring / conflict (operators wanting those states
    # use ``ring.status`` directly).
    "ring.effective_slug",
    "ring.effective_name",
}

ENUM_FIELDS: Set[str] = {
    "status",
    "distro",
    "group",
    "tag",
    "environment_type",
    "facts.distro_id",
    "facts.package_manager",
    "facts.virtualization",
    "facts.cloud_provider",
    # PRA-156 #3c: lifecycle.status uses its own namespace, NOT facts.*,
    # because the missing/null semantics differ — `unknown` is a real
    # value that matches `in ["unknown"]`, whereas facts.* predicates
    # follow PRA-155 null-FALSE rules.
    "lifecycle.status",
    # PRA-159 #4: profile.subscribed_to filters on the host's
    # effective content profile (resolved via direct → static-group
    # → smart-group precedence in ContentProfileService.resolve_effective).
    # Hosts in no_profile / conflict states evaluate FALSE for both
    # ``in`` and ``not_in`` arms — facts.* null-FALSE rule, NOT
    # lifecycle.* "unknown is real" — because the binding itself is
    # missing, not present-but-unknown.
    "profile.subscribed_to",
    # PRA-161 #1e: patch-policy resolver state for the host.
    # Mirrors ``lifecycle.status`` "real value" semantics — every host
    # has a resolution_kind, including ``no_policy`` (no tier matches)
    # and ``conflict`` (multiple enabled policies at the same tier).
    # ``in ["no_policy"]`` therefore matches hosts with no effective
    # policy, and ``not_in ["fleet_default"]`` includes them.
    "patch.resolution_kind",
    # PRA-161 #1e: rollout cadence of the host's effective policy.
    # Populated only when the resolver returns a single enabled
    # policy; no_policy / conflict evaluate null-FALSE.
    "patch.rollout_cadence",
    # PRA-162 #5: ring resolver state for the host. Mirrors
    # ``lifecycle.status`` "real value" semantics — every host has a
    # ring.status, including ``no_ring`` (no tier matches) and
    # ``conflict`` (multiple distinct enabled rings at the same tier).
    # Maps directly to the Slice 2 effective-ring resolver's STATUS_*
    # constants and to GET /systems/{id}/patch-ring's ``status`` field.
    "ring.status",
    # PRA-162 #5: which precedence tier the ring resolver matched.
    # null-FALSE for no_ring / conflict — operators wanting those
    # states use ``ring.status`` directly. Maps to SOURCE_TIER_*.
    "ring.source_kind",
}

BOOL_FIELDS: Set[str] = {
    "has_pending_updates",
    "has_security_updates",
    "ca_trust_deployed",
    "facts.reboot_required",
    # PRA-159 #4: True iff the host's effective content profile
    # contains any channel with any repo carrying a non-null
    # pinned_run_id (manifest pin / tracking pin per the PRA-159
    # design lock — bytes still come from live/, the pin is
    # metadata). FALSE for no_profile / conflict (null-FALSE).
    "profile.pinned",
    # PRA-161 #1e: True iff the resolver returns a single enabled
    # policy (``resolution_kind`` ∈ {direct_host, static_group,
    # smart_group, fleet_default}). FALSE for no_policy / conflict
    # (null-FALSE — neither ``eq=true`` nor ``eq=false`` matches).
    "patch.has_effective_policy",
    # PRA-161 #1e: requires_approval flag of the host's effective
    # policy. null-FALSE for no_policy / conflict.
    "patch.policy_requires_approval",
    # PRA-162 #5: True iff the ring resolver returns a single resolved
    # ring (``ring.status == "resolved"``). FALSE for no_ring /
    # conflict (null-FALSE — neither ``eq=true`` nor ``eq=false``
    # matches those states; use ``ring.status`` directly to surface
    # them). Mirrors ``patch.has_effective_policy`` semantics.
    "ring.has_effective_ring",
    # PRA-163 #3: True iff the host has at least one row in
    # patch_advisory_host_applicability with state='applicable' (the
    # PRA-163 Slice 2 resolver wrote it from native-source advisory
    # data). FALSE when the host has zero applicable rows AND when the
    # host has no applicability rows at all (Slice 2 quiet path for
    # missing facts → no rows). Operators wanting the "no facts" case
    # should not rely on this BOOL; PRA-163 Slice 3 deliberately ships
    # without ``advisory.applicability_unresolvable`` because Slice 2
    # does not persist that state.
    "advisory.has_open_advisories",
}

NUMBER_FIELDS: Set[str] = {
    "days_since_last_audit",
    "facts.ram_total_bytes",
    "facts.cpu_cores",
    "facts.uptime_seconds",
    # PRA-156 #3c: lifecycle.days_to_eol is null for unknown hosts.
    # Predicates follow standard SQL three-valued logic on null —
    # operators wanting unknown hosts must use lifecycle.status.
    "lifecycle.days_to_eol",
    # PRA-163 #3: counts derived from patch_advisory_host_applicability.
    # All four are non-null integers (default zero when the host has no
    # applicability rows), so standard NUMBER_OPS comparisons match
    # intuitively without three-valued logic. Critical/high/security
    # counts join through patch_advisories for severity / advisory_class.
    "advisory.applicable_count",
    "advisory.applicable_critical_count",
    "advisory.applicable_high_count",
    "advisory.applicable_security_count",
    "advisory.unknown_count",
}

# PRA-156 #3c: every lifecycle.* field, used to scope ingest-time
# recompute (recompute_lifecycle_groups_for_system) and the daily
# recompute pass — only smart groups whose rules reference one of
# these fields need re-evaluation when host_facts upserts OR when
# `today` advances past a host's eol_date threshold.
LIFECYCLE_FIELDS: Set[str] = {
    "lifecycle.status",
    "lifecycle.days_to_eol",
}

# PRA-159 #4: every profile.* field, used to scope ingest-time
# recompute. Triggered by content-profile / channel / subscription
# CRUD paths in the route layer.
PROFILE_FIELDS: Set[str] = {
    "profile.subscribed_to",
    "profile.pinned",
}

# PRA-161 #1e: every patch.* field, used to scope ingest-time recompute.
# Triggered by patch-policy CRUD, binding mutations, and fleet-default
# set/clear. The cycle guard in patch_policy_service rejects binding a
# smart group whose rule references any of these fields to a patch
# policy (would create a feedback loop where membership depends on
# the policy that membership itself assigns).
PATCH_FIELDS: Set[str] = {
    "patch.resolution_kind",
    "patch.effective_policy_slug",
    "patch.has_effective_policy",
    "patch.policy_requires_approval",
    "patch.rollout_cadence",
}

# PRA-162 #5: every ring.* field, used to scope ingest-time recompute.
# Triggered by ring CRUD (enable toggle / delete), ring host / static-
# group / smart-group binding mutations, and the smart-group membership
# cascade when a smart group bound as a ring source has its membership
# change. The cycle guard in patch_ring_service.bind_smart_group rejects
# binding a smart group whose rule references any of these fields as a
# ring membership source (would create a feedback loop where membership
# depends on the ring that membership itself assigns).
RING_FIELDS: Set[str] = {
    "ring.status",
    "ring.source_kind",
    "ring.effective_slug",
    "ring.effective_name",
    "ring.has_effective_ring",
}

# PRA-163 #3: every advisory.* field, used to scope advisory smart
# group recompute. Triggered by the Slice 2 resolver
# (``patch_advisory_service.compute_host_applicability``) ONLY when its
# row delta is non-zero — no-op recomputes do not fan out. Unlike
# ``patch.*`` and ``ring.*``, advisory.* reads stored applicability
# rows that do NOT depend on patch-policy or ring smart-group
# bindings, so an advisory.* smart group MAY be bound as a patch-
# policy / ring smart-group source without creating a feedback loop
# (Slice 3 design lock).
ADVISORY_FIELDS: Set[str] = {
    "advisory.applicable_count",
    "advisory.applicable_critical_count",
    "advisory.applicable_high_count",
    "advisory.applicable_security_count",
    "advisory.unknown_count",
    "advisory.has_open_advisories",
}

# PRA-162 #5: locked enum values for `ring.status` and
# `ring.source_kind`. Mirror the patch_ring_service constants
# (STATUS_*, SOURCE_TIER_*) but inlined for the same import-order
# reason as the patch.* enums below.
_RING_STATUS_VALUES = frozenset(("resolved", "no_ring", "conflict"))
_RING_SOURCE_KIND_VALUES = frozenset(("host", "group", "smart_group"))


# PRA-161 #1e: locked enum values for `patch.resolution_kind` and
# `patch.rollout_cadence`. Mirror the patch_policy_service constants
# (RESOLUTION_*, VALID_ROLLOUT_CADENCES) but inlined to avoid
# importing the service at module-load time (patch_policy_service
# transitively imports SmartGroup so import order is fragile).
_PATCH_RESOLUTION_KIND_VALUES = frozenset(
    (
        "direct_host",
        "static_group",
        "smart_group",
        "fleet_default",
        "no_policy",
        "conflict",
    )
)
_PATCH_ROLLOUT_CADENCE_VALUES = frozenset(("immediate", "staged"))

# Validation set for lifecycle.status `in` / `not_in` values. Mirrors
# lifecycle_service.LIFECYCLE_STATUSES; duplicated here to avoid
# importing the service at module load time (lifecycle_service in turn
# imports from db.models which can race on import order).
_LIFECYCLE_STATUS_VALUES = frozenset(
    ("supported", "approaching-eol", "unsupported", "unknown")
)

# PRA-155 #2d: every facts.* field, used to scope ingest-time
# recompute (recompute_fact_groups_for_system) — only smart groups
# whose rules reference one of these fields need re-evaluation when
# host_facts upserts.
FACTS_FIELDS: Set[str] = {
    f
    for f in (STRING_FIELDS | ENUM_FIELDS | BOOL_FIELDS | NUMBER_FIELDS)
    if f.startswith("facts.")
}

# Map facts.<name> -> the underlying HostFacts ORM column. ``distro_id``
# resolves to ``distro_id_facts`` because the ORM column was named that
# way in #2a to avoid colliding with System.distro_id (the FK).
_FACTS_COLUMN_MAP = {
    "facts.kernel_version": HostFacts.kernel_version,
    "facts.package_manager_version": HostFacts.package_manager_version,
    "facts.distro_id": HostFacts.distro_id_facts,
    "facts.package_manager": HostFacts.package_manager,
    "facts.virtualization": HostFacts.virtualization,
    "facts.cloud_provider": HostFacts.cloud_provider,
    "facts.reboot_required": HostFacts.reboot_required,
    "facts.ram_total_bytes": HostFacts.ram_total_bytes,
    "facts.cpu_cores": HostFacts.cpu_cores,
    "facts.uptime_seconds": HostFacts.uptime_seconds,
}

ALL_FIELDS = STRING_FIELDS | ENUM_FIELDS | BOOL_FIELDS | NUMBER_FIELDS

STRING_OPS = {"eq", "neq", "contains", "regex"}
ENUM_OPS = {"in", "not_in"}
BOOL_OPS = {"eq"}
NUMBER_OPS = {"eq", "gt", "lt", "gte", "lte"}
GROUP_OPS = {"and", "or"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class RuleValidationError(ValueError):
    """Raised when a rule JSON body is malformed."""


def validate_rule(node: Any, depth: int = 0) -> None:
    """Recursively validate a rule node. Raises RuleValidationError on failure."""
    if depth > 10:
        raise RuleValidationError("Rule nesting exceeds depth 10")
    if not isinstance(node, dict):
        raise RuleValidationError("Rule node must be an object")

    if node.get("op") in GROUP_OPS:
        rules = node.get("rules")
        if not isinstance(rules, list) or not rules:
            raise RuleValidationError(
                f"'{node['op']}' group requires non-empty 'rules' list"
            )
        for child in rules:
            validate_rule(child, depth + 1)
        return

    field = node.get("field")
    op = node.get("op")
    if field not in ALL_FIELDS:
        raise RuleValidationError(f"Unknown field: {field!r}")

    if field in STRING_FIELDS:
        if op not in STRING_OPS:
            raise RuleValidationError(
                f"Field '{field}' only supports ops {sorted(STRING_OPS)}"
            )
        if not isinstance(node.get("value"), str):
            raise RuleValidationError(f"Field '{field}' value must be a string")
    elif field in ENUM_FIELDS:
        if op not in ENUM_OPS:
            raise RuleValidationError(
                f"Field '{field}' only supports ops {sorted(ENUM_OPS)}"
            )
        value = node.get("value")
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise RuleValidationError(
                f"Field '{field}' value must be a list of strings"
            )
        # PRA-156 #3c: lifecycle.status accepts only the four locked
        # status values. A typo in the rule (`"approaching"` instead of
        # `"approaching-eol"`) would silently match nothing — fail
        # validation up-front so operators catch it at save time.
        if field == "lifecycle.status":
            unknown_values = [v for v in value if v not in _LIFECYCLE_STATUS_VALUES]
            if unknown_values:
                raise RuleValidationError(
                    f"lifecycle.status values must be in "
                    f"{sorted(_LIFECYCLE_STATUS_VALUES)}; got {unknown_values}"
                )
        # PRA-161 #1e: same validation discipline for the locked
        # patch.* enums — typos surface at save time, not "0 hosts
        # match" later.
        if field == "patch.resolution_kind":
            unknown_values = [
                v for v in value if v not in _PATCH_RESOLUTION_KIND_VALUES
            ]
            if unknown_values:
                raise RuleValidationError(
                    f"patch.resolution_kind values must be in "
                    f"{sorted(_PATCH_RESOLUTION_KIND_VALUES)}; got {unknown_values}"
                )
        if field == "ring.status":
            unknown_values = [v for v in value if v not in _RING_STATUS_VALUES]
            if unknown_values:
                raise RuleValidationError(
                    f"ring.status values must be in "
                    f"{sorted(_RING_STATUS_VALUES)}; got {unknown_values}"
                )
        if field == "ring.source_kind":
            unknown_values = [v for v in value if v not in _RING_SOURCE_KIND_VALUES]
            if unknown_values:
                raise RuleValidationError(
                    f"ring.source_kind values must be in "
                    f"{sorted(_RING_SOURCE_KIND_VALUES)}; got {unknown_values}"
                )
        if field == "patch.rollout_cadence":
            unknown_values = [
                v for v in value if v not in _PATCH_ROLLOUT_CADENCE_VALUES
            ]
            if unknown_values:
                raise RuleValidationError(
                    f"patch.rollout_cadence values must be in "
                    f"{sorted(_PATCH_ROLLOUT_CADENCE_VALUES)}; got {unknown_values}"
                )
    elif field in BOOL_FIELDS:
        if op not in BOOL_OPS:
            raise RuleValidationError(
                f"Field '{field}' only supports ops {sorted(BOOL_OPS)}"
            )
        if not isinstance(node.get("value"), bool):
            raise RuleValidationError(f"Field '{field}' value must be boolean")
    elif field in NUMBER_FIELDS:
        if op not in NUMBER_OPS:
            raise RuleValidationError(
                f"Field '{field}' only supports ops {sorted(NUMBER_OPS)}"
            )
        value = node.get("value")
        # ``isinstance(True, int)`` is True in Python, so a naive
        # int/float check would accept booleans here and compile to a
        # int-column-vs-bool comparison on Postgres. Mirror the
        # sanitizer discipline from PRA-155 #2a-α and reject explicitly.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuleValidationError(f"Field '{field}' value must be a number")

    if op == "regex":
        try:
            re.compile(node["value"])
        except re.error as e:
            raise RuleValidationError(f"Invalid regex: {e}") from e


# ---------------------------------------------------------------------------
# SQLAlchemy translator
# ---------------------------------------------------------------------------


def _string_clause(column, op: str, value: str):
    # All text ops are case-insensitive to match user expectations
    # (hostnames, distro names, etc. should not care about case).
    if op == "eq":
        return func.lower(column) == value.lower()
    if op == "neq":
        return func.lower(column) != value.lower()
    if op == "contains":
        return column.ilike(f"%{value}%")
    if op == "regex":
        # PostgreSQL POSIX regex; ~ is case-sensitive, ~* is insensitive.
        return column.op("~*")(value)
    raise RuleValidationError(f"Bad string op: {op}")


def _ci_in(column, value: List[str]):
    """Case-insensitive IN match."""
    lowered = [v.lower() for v in value]
    return func.lower(column).in_(lowered)


def _number_clause(column, op: str, value):
    return {
        "eq": column == value,
        "gt": column > value,
        "lt": column < value,
        "gte": column >= value,
        "lte": column <= value,
    }[op]


def _compile(
    node: Dict[str, Any],
    db: Session,
    lifecycle_index: Optional[Dict[int, Any]] = None,
    profile_index: Optional[Dict[int, "_ProfileFacts"]] = None,
    patch_index: Optional[Dict[int, "_PatchPolicyFacts"]] = None,
    ring_index: Optional[Dict[int, "_RingFacts"]] = None,
    advisory_index: Optional[Dict[int, "_AdvisoryFacts"]] = None,
):
    """Return a SQLAlchemy boolean expression selecting matching System rows.

    ``lifecycle_index`` is a precomputed
    ``Dict[system_id, LifecycleVerdict]`` (PRA-156 #3c). The caller
    (``evaluate``) builds it once if the rule references any
    ``lifecycle.*`` field, then threads it through nested compiles so a
    rule referencing lifecycle multiple times shares one bulk
    computation. ``None`` is fine when the rule has no lifecycle
    predicate; it's only consulted on the lifecycle dispatch branch.

    ``profile_index`` is the parallel precomputed map for
    ``profile.*`` predicates (PRA-159 #4): ``Dict[system_id,
    _ProfileFacts]`` where ``_ProfileFacts`` carries the host's
    effective profile slug (or None for no_profile/conflict) and
    a "any pinned channel?" bool.
    """
    if node.get("op") in GROUP_OPS:
        children = [
            _compile(
                r,
                db,
                lifecycle_index,
                profile_index,
                patch_index,
                ring_index,
                advisory_index,
            )
            for r in node["rules"]
        ]
        return and_(*children) if node["op"] == "and" else or_(*children)

    field = node["field"]
    op = node["op"]
    value = node["value"]

    if field == "hostname":
        return _string_clause(System.hostname, op, value)
    if field == "ip_address":
        return _string_clause(func.host(System.ip_address), op, value)
    if field == "os_version":
        return _string_clause(System.os_version, op, value)
    if field == "update_policy":
        return _string_clause(System.update_policy, op, value)

    if field == "status":
        clause = _ci_in(System.status, value)
        return clause if op == "in" else not_(clause)
    if field == "distro":
        subq = select(Distro.id).where(_ci_in(Distro.name, value))
        clause = System.distro_id.in_(subq)
        return clause if op == "in" else not_(clause)
    if field == "group":
        subq = select(Group.id).where(_ci_in(Group.name, value))
        clause = System.group_id.in_(subq)
        return clause if op == "in" else not_(clause)
    if field == "tag":
        subq = select(system_tag.c.system_id).where(
            system_tag.c.tag_id.in_(select(Tag.id).where(_ci_in(Tag.name, value)))
        )
        clause = System.id.in_(subq)
        return clause if op == "in" else not_(clause)
    if field == "environment_type":
        subq = select(SystemMetadata.system_id).where(
            _ci_in(SystemMetadata.environment_type, value)
        )
        clause = System.id.in_(subq)
        return clause if op == "in" else not_(clause)

    if field == "has_pending_updates":
        # any PackageUpdate rows joined via Package.system_id
        existsq = exists(
            select(PackageUpdate.id)
            .join(Package, PackageUpdate.package_id == Package.id)
            .where(Package.system_id == System.id)
        )
        return existsq if value else not_(existsq)
    if field == "has_security_updates":
        existsq = exists(
            select(PackageUpdate.id)
            .join(Package, PackageUpdate.package_id == Package.id)
            .where(
                Package.system_id == System.id,
                Package.is_security_critical.is_(True),
            )
        )
        return existsq if value else not_(existsq)
    if field == "ca_trust_deployed":
        return System.ca_trust_deployed.is_(value)

    if field == "days_since_last_audit":
        # Translate to an absolute cutoff so Postgres can use indexes.
        cutoff = datetime.utcnow() - timedelta(days=float(value))
        # days_since_last_audit > N  <=>  last_audited < now - N
        inverted = {"eq": "eq", "gt": "lt", "lt": "gt", "gte": "lte", "lte": "gte"}
        return _number_clause(System.last_audited, inverted[op], cutoff)

    # PRA-155 #2d: facts.* predicates. Locked semantics — a fact
    # predicate evaluates FALSE when host_facts is missing for the
    # host OR the specific column is NULL. Implementation: always
    # build a POSITIVE subquery (column IS NOT NULL AND <compare>)
    # and wrap in System.id.in_(subq); never use SQL NOT IN against a
    # nullable column, because NOT IN would let missing/null hosts
    # match the negative arm of an inequality predicate.
    if field in _FACTS_COLUMN_MAP:
        return _facts_clause(field, op, value)

    # PRA-156 #3c: lifecycle.* predicates. Different namespace,
    # different null semantics — `unknown` is a real value of
    # `lifecycle.status` that must match `in ["unknown"]` for the
    # saved-view filter (PRA-156 lock). Evaluation is precomputed in
    # Python via the bulk index because the verdict depends on
    # host_facts (collected_at, distro_id_facts, distro_release) AND
    # the distro_lifecycle reference table AND `today` — composing
    # all three in pure SQL gets complex and would re-compute per
    # group; a single bulk fetch shared across the rule is simpler
    # and faster at fleet scale.
    if field in LIFECYCLE_FIELDS:
        return _lifecycle_clause(field, op, value, db, lifecycle_index)

    # PRA-159 #4: profile.* predicates. Same in-Python bulk-index
    # pattern as lifecycle.* — the binding requires walking three
    # subscription tables under strict precedence (the
    # ContentProfileService.resolve_effective contract), so a single
    # bulk fetch shared across the rule is simpler and faster than
    # composing the resolver in pure SQL.
    if field in PROFILE_FIELDS:
        return _profile_clause(field, op, value, db, profile_index)

    # PRA-161 #1e: patch.* predicates. Same bulk-index pattern — the
    # resolver walks four binding tiers per host and any single rule
    # may reference patch.* multiple times, so we build the index
    # once in evaluate() and thread it through.
    if field in PATCH_FIELDS:
        return _patch_clause(field, op, value, db, patch_index)

    # PRA-162 #5: ring.* predicates. Same bulk-index pattern — the
    # resolver walks three binding tiers per host (direct host >
    # static group > smart group); a single rule may reference ring.*
    # multiple times so we build the index once in evaluate().
    if field in RING_FIELDS:
        return _ring_clause(field, op, value, db, ring_index)

    # PRA-163 #3: advisory.* predicates. Bulk-index pattern derived
    # from stored ``patch_advisory_host_applicability`` rows joined to
    # ``patch_advisories``. Counts default to zero for hosts with no
    # rows so ``< N`` predicates match every host intuitively.
    if field in ADVISORY_FIELDS:
        return _advisory_clause(field, op, value, db, advisory_index)

    raise RuleValidationError(f"Unhandled field: {field}")


def _facts_clause(field: str, op: str, value):
    """Compile a ``facts.*`` predicate into a System.id IN (...) clause.

    Locked semantics (PRA-155 #2d):
      * host_facts row missing → predicate FALSE.
      * column NULL → predicate FALSE.
      * not_eq / not_in is encoded as a POSITIVE compare inside the
        subquery (column IS NOT NULL AND column != value), never as a
        SQL NOT IN against the result. NOT IN against a nullable
        column would let missing/null hosts match the negative arm.
    """
    column = _FACTS_COLUMN_MAP[field]

    if field in STRING_FIELDS:
        return _facts_string_clause(column, op, value)
    if field in ENUM_FIELDS:
        return _facts_enum_clause(column, op, value)
    if field in BOOL_FIELDS:
        # Bool: explicit IS comparisons so NULL is excluded from both
        # arms (eq=true → IS TRUE; eq=false → IS FALSE).
        sub = select(HostFacts.system_id).where(
            HostFacts.system_id == HostFacts.system_id,  # noqa: WPS465
            column.is_(value),
        )
        return System.id.in_(sub)
    if field in NUMBER_FIELDS:
        return _facts_number_clause(column, op, value)
    raise RuleValidationError(f"Unhandled facts field: {field}")


def _facts_string_clause(column, op: str, value: str):
    if op == "eq":
        compare = func.lower(column) == value.lower()
    elif op == "neq":
        # Positive encoding: only match rows whose column is NOT NULL
        # AND not the given value. Missing host_facts rows / NULL
        # columns drop out of the subquery → predicate is False.
        compare = and_(column.isnot(None), func.lower(column) != value.lower())
    elif op == "contains":
        compare = column.ilike(f"%{value}%")
    elif op == "regex":
        compare = column.op("~*")(value)
    else:
        raise RuleValidationError(f"Bad facts string op: {op}")
    sub = select(HostFacts.system_id).where(column.isnot(None), compare)
    return System.id.in_(sub)


def _facts_enum_clause(column, op: str, value: List[str]):
    in_clause = _ci_in(column, value)
    if op == "in":
        sub = select(HostFacts.system_id).where(column.isnot(None), in_clause)
    elif op == "not_in":
        # Positive encoding for not_in (see module docstring).
        lowered = [v.lower() for v in value]
        sub = select(HostFacts.system_id).where(
            column.isnot(None), func.lower(column).notin_(lowered)
        )
    else:
        raise RuleValidationError(f"Bad facts enum op: {op}")
    return System.id.in_(sub)


def _facts_number_clause(column, op: str, value):
    cmp_map = {
        "eq": column == value,
        "gt": column > value,
        "lt": column < value,
        "gte": column >= value,
        "lte": column <= value,
    }
    if op not in cmp_map:
        raise RuleValidationError(f"Bad facts number op: {op}")
    sub = select(HostFacts.system_id).where(column.isnot(None), cmp_map[op])
    return System.id.in_(sub)


# ---------------------------------------------------------------------------
# Lifecycle predicate compile (PRA-156 #3c)
# ---------------------------------------------------------------------------


def _lifecycle_clause(
    field: str,
    op: str,
    value,
    db: Session,
    lifecycle_index: Optional[Dict[int, Any]],
):
    """Compile a ``lifecycle.*`` predicate into a System.id IN (...) clause.

    The verdict for every system was precomputed by ``evaluate``'s
    bulk fetch via ``lifecycle_service.compute_for_all_systems``.
    Filtering happens in pure Python against that index, then we hand
    SQLAlchemy a static IN-list. The evaluator is therefore correct
    for the namespace's "unknown is a real value" semantics — every
    system has an entry in the index, including hosts with missing
    facts (status="unknown").

    If ``lifecycle_index`` is None we build it on the spot (defensive
    — should never happen on the normal evaluate path because
    ``evaluate`` precomputes once per call when the rule references
    lifecycle).
    """
    if lifecycle_index is None:
        # Lazy import to avoid a circular load chain (lifecycle_service
        # imports from db.models; this module is already mid-import).
        from . import lifecycle_service  # pylint: disable=import-outside-toplevel

        lifecycle_index = lifecycle_service.compute_for_all_systems(db)

    if field == "lifecycle.status":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad lifecycle op: {op}")
        # Case-insensitive compare to stay consistent with other ENUM
        # predicates. The locked status values are already lowercase
        # so the .lower() is just defensive against operator typos
        # the validator already rejected.
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid for sid, v in lifecycle_index.items() if v.status.lower() in wanted
            ]
        else:
            matches = [
                sid
                for sid, v in lifecycle_index.items()
                if v.status.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "lifecycle.days_to_eol":
        if op not in NUMBER_OPS:
            raise RuleValidationError(f"Bad lifecycle op: {op}")
        # NULL days_to_eol (unknown hosts) drops out of every numeric
        # predicate — operators wanting unknowns must use
        # lifecycle.status. This matches standard SQL three-valued
        # logic on NULL comparisons.
        cmp = {
            "eq": lambda d: d == value,
            "gt": lambda d: d > value,
            "lt": lambda d: d < value,
            "gte": lambda d: d >= value,
            "lte": lambda d: d <= value,
        }[op]
        matches = [
            sid
            for sid, v in lifecycle_index.items()
            if v.days_to_eol is not None and cmp(v.days_to_eol)
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    raise RuleValidationError(f"Unhandled lifecycle field: {field}")


# ---------------------------------------------------------------------------
# Profile predicate compile (PRA-159 #4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProfileFacts:
    """Per-host snapshot consulted by ``_profile_clause``.

    ``effective_slug`` is the host's resolved profile slug, or
    ``None`` for no_profile / conflict. ``has_pinned_channel`` is
    True iff the resolved entries include any non-null
    ``pinned_run_id``.
    """

    effective_slug: Optional[str]
    has_pinned_channel: bool


def compute_profile_index(db: Session) -> Dict[int, _ProfileFacts]:
    """Build the per-system profile/pinned snapshot used by
    smart-group ``profile.*`` predicates.

    Walks every system and runs
    ``ContentProfileService.resolve_content_for_host``. Per the
    PRA-159 #4 lock, hosts in no_profile / conflict states evaluate
    FALSE for both arms of every profile.* predicate (facts.* style
    null-FALSE rule), so we record ``effective_slug=None`` for them
    and the clause filters them out.

    O(N hosts × resolve cost) at v1 fleet sizes — fine. At larger
    fleets a single SQL aggregation could replace this; the locked
    "build per call" pattern matches what ``lifecycle_service``
    does.
    """
    # Lazy import — content_profile_service imports from db.models;
    # this module is already mid-import.
    from . import content_profile_service  # pylint: disable=import-outside-toplevel

    service = content_profile_service.ContentProfileService(db)
    out: Dict[int, _ProfileFacts] = {}
    system_ids = [row[0] for row in db.query(System.id).all()]  # type: ignore[arg-type]
    for sid in system_ids:
        resolved = service.resolve_content_for_host(sid)
        if resolved.state != "resolved" or resolved.profile is None:
            out[sid] = _ProfileFacts(effective_slug=None, has_pinned_channel=False)
            continue
        any_pinned = any(e.pinned_run_id is not None for e in resolved.entries)
        out[sid] = _ProfileFacts(
            effective_slug=resolved.profile.profile_slug,
            has_pinned_channel=any_pinned,
        )
    return out


def _profile_clause(
    field: str,
    op: str,
    value,
    db: Session,
    profile_index: Optional[Dict[int, _ProfileFacts]],
):
    """Compile a ``profile.*`` predicate into a System.id IN (...) clause.

    Bulk-index pattern (parallel to lifecycle.*): ``evaluate`` builds
    the index once per call when the rule references profile.*; if
    the kwarg is None we build it defensively here.

    Locked semantics (PRA-159 #4):
      * ``profile.subscribed_to in [a, b]`` — TRUE iff effective
        profile slug ∈ {a, b}.
      * ``profile.subscribed_to not_in [a, b]`` — TRUE iff host has
        an effective profile AND its slug ∉ {a, b}. Hosts in
        no_profile / conflict evaluate FALSE for the negative arm
        (facts.* null-FALSE rule).
      * ``profile.pinned eq true|false`` — TRUE iff host has an
        effective profile AND ``has_pinned_channel`` matches.
    """
    if profile_index is None:
        profile_index = compute_profile_index(db)

    if field == "profile.subscribed_to":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad profile op: {op}")
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid
                for sid, pf in profile_index.items()
                if pf.effective_slug is not None and pf.effective_slug.lower() in wanted
            ]
        else:  # not_in — null-FALSE: unbound hosts don't match
            matches = [
                sid
                for sid, pf in profile_index.items()
                if pf.effective_slug is not None
                and pf.effective_slug.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "profile.pinned":
        if op not in BOOL_OPS:
            raise RuleValidationError(f"Bad profile op: {op}")
        if not isinstance(value, bool):
            raise RuleValidationError("profile.pinned value must be boolean")
        # null-FALSE: hosts without an effective profile match neither
        # eq=true nor eq=false.
        matches = [
            sid
            for sid, pf in profile_index.items()
            if pf.effective_slug is not None and pf.has_pinned_channel == value
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    raise RuleValidationError(f"Unhandled profile field: {field}")


# ---------------------------------------------------------------------------
# Patch-policy predicate compile (PRA-161 #1e)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PatchPolicyFacts:
    """Per-host snapshot consulted by ``_patch_clause``.

    ``resolution_kind`` is one of ``direct_host`` / ``static_group`` /
    ``smart_group`` / ``fleet_default`` / ``no_policy`` / ``conflict``
    — every host has one (the resolver classifies "no enabled policy
    matched" as ``no_policy`` and raises ``EffectivePolicyConflict``
    on same-tier overlap, which the index builder converts to
    ``conflict``).

    The other fields are populated only when a single enabled policy
    is effective; for ``no_policy`` / ``conflict`` they are left at
    their null-FALSE defaults (``policy_slug=None``,
    ``has_effective_policy=False``,
    ``policy_requires_approval=False``, ``rollout_cadence=None``)
    so policy-specific predicates do not accidentally match either
    arm. Operators wanting to match those states use
    ``patch.resolution_kind`` directly.
    """

    resolution_kind: str
    policy_slug: Optional[str]
    has_effective_policy: bool
    policy_requires_approval: bool
    rollout_cadence: Optional[str]


def compute_patch_policy_index(db: Session) -> Dict[int, _PatchPolicyFacts]:
    """Build the per-system patch-policy snapshot used by smart-group
    ``patch.*`` predicates.

    Walks every system and runs the slice 1d
    ``patch_policy_service.resolve_effective_policy``. Catches
    ``EffectivePolicyConflict`` per-host and records
    ``resolution_kind="conflict"`` so a duplicate-binding state never
    crashes smart-group evaluation — operators can build a
    "needs-attention" smart group via
    ``patch.resolution_kind in ["conflict"]`` to surface the rows
    they need to fix.

    O(N hosts × resolver cost) at v1 fleet sizes — fine. Mirrors the
    pattern ``compute_profile_index`` and ``compute_for_all_systems``
    use.
    """
    # Lazy import — patch_policy_service transitively pulls
    # SmartGroup; this module is mid-import.
    from . import patch_policy_service  # pylint: disable=import-outside-toplevel

    out: Dict[int, _PatchPolicyFacts] = {}
    system_ids = [row[0] for row in db.query(System.id).all()]
    for sid in system_ids:
        try:
            policy, kind = patch_policy_service.resolve_effective_policy(db, sid)
        except patch_policy_service.EffectivePolicyConflict:
            out[sid] = _PatchPolicyFacts(
                resolution_kind="conflict",
                policy_slug=None,
                has_effective_policy=False,
                policy_requires_approval=False,
                rollout_cadence=None,
            )
            continue
        except patch_policy_service.PatchPolicyError:
            # Unknown host id — should not happen here because we
            # just queried System.id, but defensive: drop into
            # no_policy rather than crashing the whole evaluation.
            out[sid] = _PatchPolicyFacts(
                resolution_kind="no_policy",
                policy_slug=None,
                has_effective_policy=False,
                policy_requires_approval=False,
                rollout_cadence=None,
            )
            continue

        if policy is None:
            out[sid] = _PatchPolicyFacts(
                resolution_kind=kind,
                policy_slug=None,
                has_effective_policy=False,
                policy_requires_approval=False,
                rollout_cadence=None,
            )
        else:
            out[sid] = _PatchPolicyFacts(
                resolution_kind=kind,
                policy_slug=policy.slug,
                has_effective_policy=True,
                policy_requires_approval=bool(policy.requires_approval),
                rollout_cadence=policy.rollout_cadence,
            )
    return out


def _patch_clause(
    field: str,
    op: str,
    value,
    db: Session,
    patch_index: Optional[Dict[int, _PatchPolicyFacts]],
):
    """Compile a ``patch.*`` predicate into a ``System.id IN (...)``
    clause.

    Bulk-index pattern parallel to lifecycle.* / profile.*: the
    ``evaluate`` entry-point builds the index once per call when the
    rule references any ``patch.*`` field. ``_PATCH_FIELDS_REQUIRING_POLICY``
    fields follow the facts.* null-FALSE rule — no_policy / conflict
    hosts match neither arm. ``patch.resolution_kind`` follows the
    lifecycle.* "real value" rule — every host has a kind.
    """
    if patch_index is None:
        patch_index = compute_patch_policy_index(db)

    if field == "patch.resolution_kind":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad patch op: {op}")
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.resolution_kind.lower() in wanted
            ]
        else:
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.resolution_kind.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "patch.effective_policy_slug":
        if op not in STRING_OPS:
            raise RuleValidationError(f"Bad patch op: {op}")
        if not isinstance(value, str):
            raise RuleValidationError(
                "patch.effective_policy_slug value must be a string"
            )
        # null-FALSE: hosts without an effective policy match neither
        # the positive nor the negative arm.
        wanted = value.lower()
        if op == "eq":
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.policy_slug is not None and pf.policy_slug.lower() == wanted
            ]
        elif op == "neq":
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.policy_slug is not None and pf.policy_slug.lower() != wanted
            ]
        elif op == "contains":
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.policy_slug is not None and wanted in pf.policy_slug.lower()
            ]
        elif op == "regex":
            try:
                pattern = re.compile(value, re.IGNORECASE)
            except re.error as exc:
                raise RuleValidationError(f"Invalid regex: {exc}") from exc
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.policy_slug is not None and pattern.search(pf.policy_slug)
            ]
        else:
            raise RuleValidationError(f"Bad patch string op: {op}")
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "patch.has_effective_policy":
        if op not in BOOL_OPS:
            raise RuleValidationError(f"Bad patch op: {op}")
        if not isinstance(value, bool):
            raise RuleValidationError(
                "patch.has_effective_policy value must be boolean"
            )
        # has_effective_policy is itself a real bool per host (always
        # set in the index), so bool eq is a direct compare. The
        # "null-FALSE" surface here is that no_policy / conflict hosts
        # have ``has_effective_policy=False``; eq=True matches none of
        # them and eq=False matches all of them, which is what we want.
        matches = [
            sid for sid, pf in patch_index.items() if pf.has_effective_policy == value
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "patch.policy_requires_approval":
        if op not in BOOL_OPS:
            raise RuleValidationError(f"Bad patch op: {op}")
        if not isinstance(value, bool):
            raise RuleValidationError(
                "patch.policy_requires_approval value must be boolean"
            )
        # Strict null-FALSE: hosts without an effective policy must
        # match neither eq=true nor eq=false. Filter on the policy
        # presence first, then on the bool value.
        matches = [
            sid
            for sid, pf in patch_index.items()
            if pf.has_effective_policy and pf.policy_requires_approval == value
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "patch.rollout_cadence":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad patch op: {op}")
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.rollout_cadence is not None
                and pf.rollout_cadence.lower() in wanted
            ]
        else:
            matches = [
                sid
                for sid, pf in patch_index.items()
                if pf.rollout_cadence is not None
                and pf.rollout_cadence.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    raise RuleValidationError(f"Unhandled patch field: {field}")


def rule_references_patch(rule_json: str | Dict[str, Any] | None) -> bool:
    """PRA-161 #1e: True iff ``rule_json`` references any ``patch.*``
    field. Same fast-path-then-parse pattern as the other
    ``rule_references_*`` helpers.

    Used in two places:

    * The patch-policy smart-group bind path (cycle guard) — a smart
      group whose rule references ``patch.*`` cannot itself be bound
      as a patch-policy target, because membership would depend on
      the policy that membership assigns.
    * The recompute trigger — only enabled smart groups with
      ``patch.*`` references need re-evaluation when a patch policy /
      binding / fleet default changes.
    """
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        if "patch." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_patch(tree)


def _walk_for_patch(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_patch(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("patch.")


# ---------------------------------------------------------------------------
# Ring resolver predicates (PRA-162 #5)
# ---------------------------------------------------------------------------
#
# Mirrors the patch.* bulk-index pattern: build a per-host snapshot of
# the Slice 2 effective-ring resolver once, then evaluate ring.*
# predicates against that snapshot. Conflict-as-state and disabled-ring
# filtering are inherited from the resolver — no second-source-of-truth.


@dataclass(frozen=True)
class _RingFacts:
    """Per-host snapshot of the effective-ring resolver.

    Maps directly to the Slice 2 ``EffectiveRingResult`` shape:

    * ``status`` ∈ ``{resolved, no_ring, conflict}`` — every host has one.
    * ``source_kind`` — populated only for ``resolved`` (host / group /
      smart_group) and left ``None`` for ``no_ring`` / ``conflict``.
    * ``ring_slug`` / ``ring_name`` / ``has_effective_ring`` are
      populated only when ``status == "resolved"``; null-FALSE
      otherwise so policy-specific predicates do not accidentally match
      either arm. Operators wanting those states use ``ring.status``.
    """

    status: str
    source_kind: Optional[str]
    ring_slug: Optional[str]
    ring_name: Optional[str]
    has_effective_ring: bool


def compute_ring_index(db: Session) -> Dict[int, _RingFacts]:
    """Build the per-system ring-resolver snapshot used by smart-group
    ``ring.*`` predicates.

    Walks every system and runs the slice 2
    ``patch_ring_service.resolve_effective_ring``. The resolver returns
    a structured result (no exception path for conflict — slice 2
    locked conflict-as-state at the API layer), so a duplicate-binding
    state never crashes smart-group evaluation. Operators can build a
    "needs-attention" smart group via
    ``ring.status in ["conflict"]``.

    O(N hosts × resolver cost) at v1 fleet sizes — fine. Same shape as
    ``compute_patch_policy_index`` and ``compute_profile_index``.
    """
    # Lazy import — patch_ring_service transitively pulls SmartGroup
    # via db.models; this module is mid-import.
    from . import patch_ring_service  # pylint: disable=import-outside-toplevel

    out: Dict[int, _RingFacts] = {}
    system_ids = [row[0] for row in db.query(System.id).all()]
    for sid in system_ids:
        try:
            result = patch_ring_service.resolve_effective_ring(db, sid)
        except patch_ring_service.PatchRingError:
            # Unknown host id — should not happen because we just
            # queried System.id, but defensive: synthesise no_ring.
            out[sid] = _RingFacts(
                status="no_ring",
                source_kind=None,
                ring_slug=None,
                ring_name=None,
                has_effective_ring=False,
            )
            continue

        if result.status == "resolved" and result.ring is not None:
            out[sid] = _RingFacts(
                status="resolved",
                source_kind=result.source_tier,
                ring_slug=result.ring.slug,
                ring_name=result.ring.name,
                has_effective_ring=True,
            )
        else:
            out[sid] = _RingFacts(
                status=result.status,
                source_kind=None,
                ring_slug=None,
                ring_name=None,
                has_effective_ring=False,
            )
    return out


def _ring_clause(
    field: str,
    op: str,
    value,
    db: Session,
    ring_index: Optional[Dict[int, _RingFacts]],
):
    """Compile a ``ring.*`` predicate into a ``System.id IN (...)``
    clause.

    Bulk-index pattern parallel to lifecycle.* / profile.* / patch.*:
    the ``evaluate`` entry-point builds the index once per call when
    the rule references any ``ring.*`` field. The five fields follow:

    * ``ring.status`` — "real value" rule (every host has one,
      including ``no_ring`` and ``conflict``); enum in/not_in.
    * ``ring.source_kind`` — null-FALSE for no_ring / conflict; enum
      in/not_in.
    * ``ring.effective_slug`` / ``ring.effective_name`` — null-FALSE
      for no_ring / conflict; STRING ops.
    * ``ring.has_effective_ring`` — direct bool compare; no_ring /
      conflict have ``has_effective_ring=False`` so eq=False matches
      them and eq=True matches resolved hosts.
    """
    if ring_index is None:
        ring_index = compute_ring_index(db)

    if field == "ring.status":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad ring op: {op}")
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid for sid, rf in ring_index.items() if rf.status.lower() in wanted
            ]
        else:
            matches = [
                sid for sid, rf in ring_index.items() if rf.status.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "ring.source_kind":
        if op not in ENUM_OPS:
            raise RuleValidationError(f"Bad ring op: {op}")
        wanted = {v.lower() for v in value}
        if op == "in":
            matches = [
                sid
                for sid, rf in ring_index.items()
                if rf.source_kind is not None and rf.source_kind.lower() in wanted
            ]
        else:
            matches = [
                sid
                for sid, rf in ring_index.items()
                if rf.source_kind is not None and rf.source_kind.lower() not in wanted
            ]
        return System.id.in_(matches) if matches else System.id.in_([])

    if field in ("ring.effective_slug", "ring.effective_name"):
        if op not in STRING_OPS:
            raise RuleValidationError(f"Bad ring op: {op}")
        if not isinstance(value, str):
            raise RuleValidationError(f"{field} value must be a string")
        attr = "ring_slug" if field == "ring.effective_slug" else "ring_name"
        wanted = value.lower()
        if op == "eq":
            matches = [
                sid
                for sid, rf in ring_index.items()
                if getattr(rf, attr) is not None and getattr(rf, attr).lower() == wanted
            ]
        elif op == "neq":
            matches = [
                sid
                for sid, rf in ring_index.items()
                if getattr(rf, attr) is not None and getattr(rf, attr).lower() != wanted
            ]
        elif op == "contains":
            matches = [
                sid
                for sid, rf in ring_index.items()
                if getattr(rf, attr) is not None and wanted in getattr(rf, attr).lower()
            ]
        elif op == "regex":
            try:
                pattern = re.compile(value, re.IGNORECASE)
            except re.error as exc:
                raise RuleValidationError(f"Invalid regex: {exc}") from exc
            matches = [
                sid
                for sid, rf in ring_index.items()
                if getattr(rf, attr) is not None and pattern.search(getattr(rf, attr))
            ]
        else:
            raise RuleValidationError(f"Bad ring string op: {op}")
        return System.id.in_(matches) if matches else System.id.in_([])

    if field == "ring.has_effective_ring":
        if op not in BOOL_OPS:
            raise RuleValidationError(f"Bad ring op: {op}")
        if not isinstance(value, bool):
            raise RuleValidationError("ring.has_effective_ring value must be boolean")
        # has_effective_ring is itself a real bool per host (always set
        # in the index). no_ring / conflict have has_effective_ring=False;
        # eq=True matches none of them and eq=False matches all of them.
        matches = [
            sid for sid, rf in ring_index.items() if rf.has_effective_ring == value
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    raise RuleValidationError(f"Unhandled ring field: {field}")


def rule_references_ring(rule_json: str | Dict[str, Any] | None) -> bool:
    """PRA-162 #5: True iff ``rule_json`` references any ``ring.*``
    field. Same fast-path-then-parse pattern as the other
    ``rule_references_*`` helpers.

    Used in two places:

    * The ring smart-group bind path (cycle guard) — a smart group
      whose rule references ``ring.*`` cannot itself be bound as a
      ring membership source, because membership would depend on the
      ring that membership assigns.
    * The recompute trigger — only enabled smart groups with ``ring.*``
      references need re-evaluation when a ring / ring binding /
      ring enabled state changes.
    """
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        if "ring." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_ring(tree)


def _walk_for_ring(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_ring(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("ring.")


# ---------------------------------------------------------------------------
# Advisory predicates (PRA-163 #3)
# ---------------------------------------------------------------------------
#
# Mirrors the patch.* / ring.* bulk-index pattern: build a per-host
# snapshot of stored advisory applicability counts once, then evaluate
# advisory.* predicates against that snapshot. Source of truth is
# ``patch_advisory_host_applicability`` joined to ``patch_advisories``
# for severity / advisory_class. Hosts with no applicability rows
# default to zero across every count + ``has_open_advisories=False``.
#
# Unlike patch.* / ring.* there is no cycle guard — advisory facts are
# materialized by ``patch_advisory_service.compute_host_applicability``
# from independent inputs (HostFacts, Package, advisory tables) that do
# not consult patch-policy or ring smart-group bindings, so an
# advisory.* smart group can safely back patch-policy and ring
# membership without a feedback loop. The Slice 3 packet locks this.


@dataclass(frozen=True)
class _AdvisoryFacts:
    """Per-host snapshot of stored advisory applicability counts.

    All five count fields default to zero for hosts with no rows in
    ``patch_advisory_host_applicability`` (Slice 2 quiet path: a host
    with no facts produces no rows). ``has_open_advisories`` is the
    boolean derivative of ``applicable_count > 0``.
    """

    applicable_count: int
    applicable_critical_count: int
    applicable_high_count: int
    applicable_security_count: int
    unknown_count: int
    has_open_advisories: bool


_EMPTY_ADVISORY_FACTS = _AdvisoryFacts(
    applicable_count=0,
    applicable_critical_count=0,
    applicable_high_count=0,
    applicable_security_count=0,
    unknown_count=0,
    has_open_advisories=False,
)


def compute_advisory_index(db: Session) -> Dict[int, _AdvisoryFacts]:
    """Build the per-system advisory-applicability snapshot used by
    ``advisory.*`` predicates.

    One pass over every ``patch_advisory_host_applicability`` row,
    grouped per system, joined to ``patch_advisories`` for
    severity / advisory_class. Then a second pass fills missing
    systems with ``_EMPTY_ADVISORY_FACTS`` so absent applicability
    rows produce zero counts (NOT null) — operators writing
    ``advisory.applicable_count < 1`` get every host, not just the
    hosts that have at least one row.

    Joining in SQL via ``func.count`` + ``func.sum(case(...))`` would
    be one round-trip, but the in-memory roll-up keeps the
    fixture-defensible classification logic in Python alongside the
    Slice 2 resolver so both sides stay in lockstep.
    """
    # Lazy imports — patch_advisory_service transitively pulls
    # SmartGroup via db.models; this module is mid-import.
    from ..db.models import (  # pylint: disable=import-outside-toplevel
        PatchAdvisory,
        PatchAdvisoryHostApplicability,
    )

    out: Dict[int, _AdvisoryFacts] = {}
    rows = (
        db.query(
            PatchAdvisoryHostApplicability.system_id,
            PatchAdvisoryHostApplicability.state,
            PatchAdvisory.severity,
            PatchAdvisory.advisory_class,
        )
        .join(
            PatchAdvisory,
            PatchAdvisory.id == PatchAdvisoryHostApplicability.advisory_id,
        )
        .all()
    )

    counters: Dict[int, Dict[str, int]] = {}
    for system_id, state, severity, advisory_class in rows:
        bucket = counters.setdefault(
            system_id,
            {
                "applicable": 0,
                "applicable_critical": 0,
                "applicable_high": 0,
                "applicable_security": 0,
                "unknown": 0,
            },
        )
        if state == "applicable":
            bucket["applicable"] += 1
            if severity == "critical":
                bucket["applicable_critical"] += 1
            if severity == "high":
                bucket["applicable_high"] += 1
            if advisory_class == "security":
                bucket["applicable_security"] += 1
        elif state == "unknown":
            bucket["unknown"] += 1
        # ``fixed`` and ``not_applicable`` rows do not bump any count
        # in the Slice 3 catalog. They remain queryable via the Slice 2
        # read helpers and Slice 4 UI.

    for system_id, b in counters.items():
        out[system_id] = _AdvisoryFacts(
            applicable_count=b["applicable"],
            applicable_critical_count=b["applicable_critical"],
            applicable_high_count=b["applicable_high"],
            applicable_security_count=b["applicable_security"],
            unknown_count=b["unknown"],
            has_open_advisories=b["applicable"] > 0,
        )

    # Fill every other system with zero-counts so absent-row hosts
    # match ``< 1`` predicates correctly.
    for (sid,) in db.query(System.id).all():
        out.setdefault(sid, _EMPTY_ADVISORY_FACTS)
    return out


def _advisory_clause(
    field: str,
    op: str,
    value,
    db: Session,
    advisory_index: Optional[Dict[int, _AdvisoryFacts]],
):
    """Compile an ``advisory.*`` predicate into a ``System.id IN (...)``
    clause.

    Bulk-index pattern parallel to ``_patch_clause`` / ``_ring_clause``:
    ``evaluate`` builds the index once per call when the rule
    references any ``advisory.*`` field; if the dispatch is reached
    without a precomputed index (defensive: tests, programmatic
    callers) the index is built lazily here.

    Counts are non-null integers per host. ``has_open_advisories`` is
    a real bool per host so eq=True matches hosts with at least one
    applicable row and eq=False matches the rest.
    """
    if advisory_index is None:
        advisory_index = compute_advisory_index(db)

    if field == "advisory.has_open_advisories":
        if op not in BOOL_OPS:
            raise RuleValidationError(f"Bad advisory op: {op}")
        if not isinstance(value, bool):
            raise RuleValidationError(
                "advisory.has_open_advisories value must be boolean"
            )
        matches = [
            sid for sid, af in advisory_index.items() if af.has_open_advisories == value
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    # Numeric count fields share dispatch logic.
    _COUNT_ATTRS = {
        "advisory.applicable_count": "applicable_count",
        "advisory.applicable_critical_count": "applicable_critical_count",
        "advisory.applicable_high_count": "applicable_high_count",
        "advisory.applicable_security_count": "applicable_security_count",
        "advisory.unknown_count": "unknown_count",
    }
    if field in _COUNT_ATTRS:
        if op not in NUMBER_OPS:
            raise RuleValidationError(f"Bad advisory op: {op}")
        # validate_rule already rejected non-numeric / bool values, but
        # be defensive in case _advisory_clause is called from a test
        # without going through validate_rule.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuleValidationError(f"{field} value must be a number")
        attr = _COUNT_ATTRS[field]
        if op == "eq":
            cmp_fn = lambda v: v == value  # noqa: E731
        elif op == "gt":
            cmp_fn = lambda v: v > value  # noqa: E731
        elif op == "gte":
            cmp_fn = lambda v: v >= value  # noqa: E731
        elif op == "lt":
            cmp_fn = lambda v: v < value  # noqa: E731
        elif op == "lte":
            cmp_fn = lambda v: v <= value  # noqa: E731
        else:  # pragma: no cover - NUMBER_OPS exhaustive above
            raise RuleValidationError(f"Bad advisory numeric op: {op}")
        matches = [
            sid for sid, af in advisory_index.items() if cmp_fn(getattr(af, attr))
        ]
        return System.id.in_(matches) if matches else System.id.in_([])

    raise RuleValidationError(f"Unhandled advisory field: {field}")


def rule_references_advisory(rule_json: str | Dict[str, Any] | None) -> bool:
    """PRA-163 #3: True iff ``rule_json`` references any ``advisory.*``
    field. Same fast-path-then-parse pattern as the other
    ``rule_references_*`` helpers.

    Used in two places:

    * The recompute trigger in
      ``patch_advisory_service.compute_host_applicability`` — only
      enabled smart groups with ``advisory.*`` references need
      re-evaluation when applicability rows change.
    * The advisory recompute fan-out
      (``recompute_advisory_groups``) for the same reason.

    There is no cycle guard for ``advisory.*`` (Slice 3 design lock):
    advisory facts derive from independent inputs, so an
    ``advisory.*`` smart group may safely back patch-policy / ring
    bindings.
    """
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        if "advisory." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_advisory(tree)


def _walk_for_advisory(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_advisory(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("advisory.")


def rule_references_facts(rule_json: str | Dict[str, Any] | None) -> bool:
    """Return True iff ``rule_json`` references any ``facts.*`` field.

    Walks the rule tree by structure (group -> children, leaf -> field
    name). Uses raw JSON only as a *fast path* skip — if the substring
    ``facts.`` is absent we can answer False without parsing — but the
    correctness boundary is the parse; the text substring must not
    be the only check.
    """
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        # Fast-path skip: if the substring isn't present, no parsed
        # tree could possibly carry a facts.* field. Saves a json.loads
        # on the hot path of "this group is unrelated".
        if "facts." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_facts(tree)


def _walk_for_facts(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_facts(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("facts.")


def rule_references_lifecycle(rule_json: str | Dict[str, Any] | None) -> bool:
    """PRA-156 #3c: True iff ``rule_json`` references any
    ``lifecycle.*`` field. Same fast-path-then-parse pattern as
    ``rule_references_facts``."""
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        if "lifecycle." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_lifecycle(tree)


def _walk_for_lifecycle(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_lifecycle(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("lifecycle.")


def validate_rule_against_db(rule_json: str | Dict[str, Any], db: Session) -> None:
    """Second-stage validator that consults the DB for value
    correctness (PRA-159 #5).

    ``validate_rule`` is DB-free — it checks shape and the locked
    enum sets. This helper additionally validates dynamic value sets
    that depend on DB state. Today that's just ``profile.subscribed_to``
    (slugs must reference a non-deleted ``ContentProfile``); future
    DB-backed enums would extend this hook the same way.

    Called from the smart-group create / update / preview routes
    after ``validate_rule`` so syntactic errors surface first. A
    typo'd slug raises ``RuleValidationError`` so operators see it
    at save time instead of "rule matched 0 hosts" silently.
    """
    rule = json.loads(rule_json) if isinstance(rule_json, str) else rule_json
    if not rule_references_profile(rule):
        return
    referenced_slugs: Set[str] = set()
    _collect_profile_subscribed_to_slugs(rule, referenced_slugs)
    if not referenced_slugs:
        return
    # Lazy import — content_profile_service imports from db.models;
    # this module is already mid-import.
    from ..db.models import ContentProfile  # pylint: disable=import-outside-toplevel

    existing_slugs = {
        row[0]
        for row in (
            db.query(ContentProfile.slug)
            .filter(ContentProfile.deleted_at.is_(None))
            .all()
        )
    }
    unknown = sorted(
        s
        for s in referenced_slugs
        if s.lower() not in {existing.lower() for existing in existing_slugs}
    )
    if unknown:
        raise RuleValidationError(
            f"profile.subscribed_to references unknown profile slug(s): "
            f"{unknown}. Existing live profiles: "
            f"{sorted(existing_slugs)}"
        )


def _collect_profile_subscribed_to_slugs(node: Any, out: Set[str]) -> None:
    """Walk the rule tree, collecting every value seen in a
    ``profile.subscribed_to`` predicate. Both ``in`` and ``not_in``
    arms contribute (a typo on either side is operator-hostile)."""
    if not isinstance(node, dict):
        return
    op = node.get("op")
    if op in GROUP_OPS:
        for child in node.get("rules") or []:
            _collect_profile_subscribed_to_slugs(child, out)
        return
    if node.get("field") == "profile.subscribed_to":
        value = node.get("value")
        if isinstance(value, list):
            for v in value:
                if isinstance(v, str):
                    out.add(v)


def rule_references_profile(rule_json: str | Dict[str, Any] | None) -> bool:
    """PRA-159 #4: True iff ``rule_json`` references any
    ``profile.*`` field. Same fast-path-then-parse pattern as
    ``rule_references_facts`` / ``rule_references_lifecycle``."""
    if rule_json is None:
        return False
    if isinstance(rule_json, str):
        if "profile." not in rule_json:
            return False
        try:
            tree = json.loads(rule_json)
        except json.JSONDecodeError:
            return False
    else:
        tree = rule_json
    return _walk_for_profile(tree)


def _walk_for_profile(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    op = node.get("op")
    if op in GROUP_OPS:
        children = node.get("rules") or []
        return any(_walk_for_profile(child) for child in children)
    field = node.get("field")
    return isinstance(field, str) and field.startswith("profile.")


def recompute_fact_groups_for_system(db: Session, system_id: int) -> int:
    """PRA-155 #2d: scoped ingest-time recompute hook.

    Called from ``FactsService.ingest`` after a successful upsert.
    Re-evaluates ONLY the smart groups whose rules reference at least
    one ``facts.*`` field; groups with no fact dependency are not
    touched. The general 5-min sweep (``recompute_all``) remains the
    catch-all safety net.

    Returns the number of smart groups whose membership was
    recomputed (not the number of membership-row changes).
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_facts(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "recompute_fact_groups_for_system: group_id=%s system_id=%s failed",
                group.id,
                system_id,
            )
    if touched:
        logger.info(
            "facts ingest recomputed %d smart group(s) for system_id=%s",
            touched,
            system_id,
        )
    return touched


def recompute_lifecycle_groups_for_system(db: Session, system_id: int) -> int:
    """PRA-156 #3c: scoped ingest-time recompute for lifecycle.* groups.

    Parallel to ``recompute_fact_groups_for_system`` because lifecycle
    is derived from facts: a host_facts upsert can move a host across
    a lifecycle threshold (e.g. fresh distro_release matches a
    different EOL row) and any group filtering on ``lifecycle.*``
    needs immediate re-evaluation.

    The daily lifecycle pass (``recompute_lifecycle_groups``) is the
    other trigger — it covers the "today moved past eol_date without
    a facts upsert" case.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_lifecycle(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "recompute_lifecycle_groups_for_system: group_id=%s "
                "system_id=%s failed",
                group.id,
                system_id,
            )
    if touched:
        logger.info(
            "facts ingest recomputed %d lifecycle smart group(s) for system_id=%s",
            touched,
            system_id,
        )
    return touched


def recompute_dependent_groups_for_system(db: Session, system_id: int) -> int:
    """PRA-156 #3c: combined ingest-time recompute hook.

    A facts upsert can move a host across a ``facts.*`` predicate
    AND a ``lifecycle.*`` predicate (lifecycle is derived from
    facts), so both kinds of group need re-evaluation. This helper
    walks the smart_groups table ONCE and recomputes any group
    whose rule references either namespace — a mixed-predicate
    group is touched a single time, not twice.

    Returns the number of distinct smart groups whose membership was
    recomputed.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not (
            rule_references_facts(group.rule_json)
            or rule_references_lifecycle(group.rule_json)
        ):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "recompute_dependent_groups_for_system: group_id=%s "
                "system_id=%s failed",
                group.id,
                system_id,
            )
    if touched:
        logger.info(
            "facts ingest recomputed %d dependent smart group(s) for system_id=%s",
            touched,
            system_id,
        )
    return touched


def recompute_profile_groups_for_system(db: Session, system_id: int) -> int:
    """PRA-159 #4: scoped recompute hook fired from
    content-profile / channel / subscription mutation paths.

    Re-evaluates ONLY smart groups whose rules reference at least
    one ``profile.*`` field. The ``system_id`` argument is
    informational (logging) — the bulk profile index built inside
    ``evaluate`` covers the whole fleet so we can't scope by host
    cheaply.

    Returns the number of smart groups whose membership was
    recomputed.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_profile(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "recompute_profile_groups_for_system: group_id=%s system_id=%s failed",
                group.id,
                system_id,
            )
    if touched:
        logger.info(
            "profile mutation recomputed %d smart group(s) for system_id=%s",
            touched,
            system_id,
        )
    return touched


# PRA-159 #4-a: two flags drive the loop-until-stable
# protocol for ``recompute_profile_groups``:
#
#   * ``_RECOMPUTING_PROFILE_GROUPS`` — re-entry guard. While set,
#     calls to ``recompute_profile_groups`` from inside the sweep
#     short-circuit (preventing infinite recursion when a profile.*-
#     using group is ALSO a SmartGroupContentProfileSubscription
#     binder).
#   * ``_PROFILE_RESWEEP_PENDING`` — dirty flag.
#     Set by ``recompute_membership`` when a binder group's
#     membership changed during the sweep. The outer ``while`` loop
#     in ``recompute_profile_groups`` reads + clears it and re-sweeps
#     so any earlier-evaluated profile.* groups that observed an
#     older effective-profile index get re-evaluated against the new
#     bindings.
#
# Both flags are module-level: recompute is single-threaded per
# worker, and these track "are we inside this sweep?" boundaries,
# not concurrency primitives.
_RECOMPUTING_PROFILE_GROUPS = False
_PROFILE_RESWEEP_PENDING = False

# Cap on outer loop iterations. A pathological chain of N binder
# groups whose membership changes ripple through each other could in
# theory iterate up to N times. 5 covers any realistic
# profile-binding topology and is a tight cap for runaway protection.
_PROFILE_RESWEEP_MAX_ITERATIONS = 5


def recompute_profile_groups(db: Session) -> int:
    """PRA-159 #4: fleet-wide profile recompute.

    Used by route paths that affect many hosts at once (group /
    smart-group binding changes, channel CRUD that changes the
    composition of a profile, profile soft-delete). Walks every
    enabled smart group whose rule references ``profile.*`` and
    re-evaluates.

    Also fired as a follow-on by ``recompute_membership`` when the
    smart group whose membership just changed is a
    ``SmartGroupContentProfileSubscription`` binder.

    **Loop-until-stable**: a single sweep can
    process a profile.* filter group BEFORE a binder group's
    membership change has happened. The earlier filter group sees
    the old effective-profile index; once the binder group changes
    membership later in the same sweep, the filter group is stale.
    The re-entry guard prevents the obvious recursive trigger, but
    we still need to re-sweep at least once.
    Implementation: ``recompute_membership`` sets
    ``_PROFILE_RESWEEP_PENDING`` whenever a binder group's
    membership actually changed during a guarded sweep. The outer
    loop here drains that flag — re-sweeping until no binder
    membership changed in the prior pass — capped at
    ``_PROFILE_RESWEEP_MAX_ITERATIONS`` for runaway protection.

    Returns the total number of groups touched across all passes
    (a re-sweep that touches the same group again counts each
    pass).
    """
    global _RECOMPUTING_PROFILE_GROUPS
    global _PROFILE_RESWEEP_PENDING

    if _RECOMPUTING_PROFILE_GROUPS:
        # Already inside a sweep — the inner caller (e.g. a
        # recompute_membership follow-on) should not recurse.
        # The dirty flag set by that caller will drive a re-sweep
        # via the outer loop here.
        return 0

    _RECOMPUTING_PROFILE_GROUPS = True
    total_touched = 0
    try:
        for iteration in range(_PROFILE_RESWEEP_MAX_ITERATIONS):
            # Clear the dirty flag at the START of each pass so a
            # binder-driven change during this pass re-arms it.
            _PROFILE_RESWEEP_PENDING = False
            groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
            pass_touched = 0
            for group in groups:
                if not rule_references_profile(group.rule_json):
                    continue
                try:
                    recompute_membership(db, group.id)
                    pass_touched += 1
                except Exception:  # pylint: disable=broad-except
                    logger.exception(
                        "recompute_profile_groups: group_id=%s failed (pass=%d)",
                        group.id,
                        iteration,
                    )
            total_touched += pass_touched
            if not _PROFILE_RESWEEP_PENDING:
                # No binder changed membership during this pass —
                # the index is stable; we can stop.
                break
            logger.info(
                "recompute_profile_groups: re-sweep needed (pass=%d touched=%d)",
                iteration,
                pass_touched,
            )
        else:
            # Loop fell off the end without breaking — hit the
            # iteration cap. Log so the operator sees a runaway
            # profile-binding topology if one ever exists.
            logger.warning(
                "recompute_profile_groups: hit max iterations (%d); "
                "remaining staleness is operator-actionable — review "
                "profile-binding smart groups for cycles",
                _PROFILE_RESWEEP_MAX_ITERATIONS,
            )
        if total_touched:
            logger.info("fleet profile recompute total_touched=%d", total_touched)
        return total_touched
    finally:
        _RECOMPUTING_PROFILE_GROUPS = False
        _PROFILE_RESWEEP_PENDING = False


def recompute_patch_groups(db: Session) -> int:
    """PRA-161 #1e: fleet-wide patch.* recompute.

    Triggered by ``patch_policy_service`` from every mutation that
    can move hosts across a ``patch.*`` predicate boundary:

    * patch policy CRUD (create / update fields the resolver reads /
      enabled toggle / delete)
    * binding mutations (host / static-group / smart-group bind +
      unbind)
    * fleet-default set / clear

    Re-evaluates every enabled smart group whose rule references at
    least one ``patch.*`` field. Broad-recompute is intentional — a
    single binding change can shift the resolver result for any
    host the policy targets via any tier, and targeted recompute
    would need cross-tier scope analysis the slice-1e packet
    explicitly defers ("correctness beats cleverness").

    Returns the number of smart groups whose membership was
    recomputed.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_patch(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception("recompute_patch_groups: group_id=%s failed", group.id)
    if touched:
        logger.info("patch policy recompute touched %d smart group(s)", touched)
    return touched


def recompute_ring_groups(db: Session) -> int:
    """PRA-162 #5: fleet-wide ring.* recompute.

    Triggered by ``patch_ring_service`` from every mutation that can
    move hosts across a ``ring.*`` predicate boundary:

    * ring CRUD that affects the resolver (enable toggle, delete)
    * binding mutations (host / static-group / smart-group bind +
      unbind)

    Re-evaluates every enabled smart group whose rule references at
    least one ``ring.*`` field. Broad-recompute is intentional — same
    rationale as ``recompute_patch_groups``: a single binding change
    can shift the resolver result for any host the ring targets via
    any tier.

    Returns the number of smart groups whose membership was recomputed.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_ring(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception("recompute_ring_groups: group_id=%s failed", group.id)
    if touched:
        logger.info("ring recompute touched %d smart group(s)", touched)
    return touched


def recompute_advisory_groups(db: Session) -> int:
    """PRA-163 #3: advisory.* recompute.

    Triggered by ``patch_advisory_service.compute_host_applicability``
    AFTER its commit, ONLY when the per-host row delta is non-zero
    (``ApplicabilityResult.changed`` is True). Idempotent applicability
    recomputes do not fan out, so a daily reimport that changes
    nothing also touches no smart groups.

    Re-evaluates every enabled smart group whose rule references at
    least one ``advisory.*`` field. Broad-recompute is intentional —
    same rationale as ``recompute_patch_groups`` /
    ``recompute_ring_groups``: a single applicability row change can
    shift any number of advisory.* predicates for any host.

    Returns the number of smart groups whose membership was recomputed.
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_advisory(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception("recompute_advisory_groups: group_id=%s failed", group.id)
    if touched:
        logger.info("advisory recompute touched %d smart group(s)", touched)
    return touched


def recompute_lifecycle_groups(db: Session) -> int:
    """PRA-156 #3c: daily lifecycle recompute.

    Iterates every enabled smart group whose rule references
    ``lifecycle.*`` and re-evaluates membership. ``today`` advances
    once per day without any facts upsert, so a host can cross from
    ``approaching-eol`` to ``unsupported`` (or any other transition)
    without a per-host event the per-ingest hook would catch. The
    scheduler runs this on a daily cadence (see scheduler_service).
    """
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    touched = 0
    for group in groups:
        if not rule_references_lifecycle(group.rule_json):
            continue
        try:
            recompute_membership(db, group.id)
            touched += 1
        except Exception:  # pylint: disable=broad-except
            logger.exception("recompute_lifecycle_groups: group_id=%s failed", group.id)
    if touched:
        logger.info("daily lifecycle recompute touched %d group(s)", touched)
    return touched


def evaluate(rule_json: str | Dict[str, Any], db: Session) -> List[int]:
    """Return list of system IDs matching rule_json.

    PRA-156 #3c: when the rule references ``lifecycle.*``, build the
    bulk lifecycle index ONCE here and thread it through ``_compile``
    so a rule referencing lifecycle multiple times shares one
    computation. Rules with no lifecycle predicate skip the bulk
    fetch entirely.

    PRA-159 #4: same pattern for ``profile.*`` — built once via
    ``compute_profile_index`` and threaded through.
    """
    rule = json.loads(rule_json) if isinstance(rule_json, str) else rule_json
    validate_rule(rule)
    lifecycle_index: Optional[Dict[int, Any]] = None
    if rule_references_lifecycle(rule):
        # Lazy import — see _lifecycle_clause for why.
        from . import lifecycle_service  # pylint: disable=import-outside-toplevel

        lifecycle_index = lifecycle_service.compute_for_all_systems(db)
    profile_index: Optional[Dict[int, _ProfileFacts]] = None
    if rule_references_profile(rule):
        profile_index = compute_profile_index(db)
    patch_index: Optional[Dict[int, _PatchPolicyFacts]] = None
    if rule_references_patch(rule):
        patch_index = compute_patch_policy_index(db)
    ring_index: Optional[Dict[int, _RingFacts]] = None
    if rule_references_ring(rule):
        ring_index = compute_ring_index(db)
    advisory_index: Optional[Dict[int, _AdvisoryFacts]] = None
    if rule_references_advisory(rule):
        advisory_index = compute_advisory_index(db)
    clause = _compile(
        rule,
        db,
        lifecycle_index=lifecycle_index,
        profile_index=profile_index,
        patch_index=patch_index,
        ring_index=ring_index,
        advisory_index=advisory_index,
    )
    ids = db.query(System.id).filter(clause).all()
    return [row[0] for row in ids]


# ---------------------------------------------------------------------------
# Cache refresh
# ---------------------------------------------------------------------------


def recompute_membership(db: Session, smart_group_id: int) -> int:
    """Re-materialise membership for one smart group. Returns member count."""
    group = db.query(SmartGroup).filter(SmartGroup.id == smart_group_id).first()
    if not group:
        return 0

    try:
        matched_ids: Set[int] = set(evaluate(group.rule_json, db))
    except Exception as e:  # pylint: disable=broad-except
        logger.error(
            "recompute_membership: rule eval failed for group %d: %s",
            smart_group_id,
            e,
        )
        return 0

    existing = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == smart_group_id
        )
    }

    to_add = matched_ids - existing
    to_remove = existing - matched_ids

    if to_remove:
        db.query(SmartGroupMembership).filter(
            SmartGroupMembership.smart_group_id == smart_group_id,
            SmartGroupMembership.system_id.in_(to_remove),
        ).delete(synchronize_session=False)
    for sid in to_add:
        db.add(SmartGroupMembership(smart_group_id=smart_group_id, system_id=sid))
    db.commit()

    # PRA-159 #4-a: if THIS smart group's cached membership is the
    # source for some host's effective profile (via
    # ``SmartGroupContentProfileSubscription``), and membership
    # actually changed, ``profile.*`` predicate results may now be
    # stale.
    #
    # Two paths depending on whether we're inside a
    # ``recompute_profile_groups`` sweep:
    #
    #   * Outside a sweep — call ``recompute_profile_groups``
    #     directly so any profile.*-filter groups re-evaluate.
    #   * Inside a sweep — set
    #     ``_PROFILE_RESWEEP_PENDING``. The outer loop reads + clears
    #     this flag and re-sweeps before exit, so an earlier-
    #     evaluated filter group that saw the old effective-profile
    #     index gets re-evaluated against the new bindings.
    if to_add or to_remove:
        # Lazy import to avoid touching db.models a second time at
        # the top of this module — we already import it above for
        # SmartGroup / SmartGroupMembership, but the
        # SmartGroupContentProfileSubscription model is added by
        # PRA-159 and only needed here.
        from ..db.models import (  # pylint: disable=import-outside-toplevel
            PatchPolicySmartGroupBinding,
            PatchRingSmartGroupBinding,
            SmartGroupContentProfileSubscription,
        )

        is_profile_binder = (
            db.query(SmartGroupContentProfileSubscription.id)
            .filter(
                SmartGroupContentProfileSubscription.smart_group_id == smart_group_id
            )
            .first()
            is not None
        )
        if is_profile_binder:
            global _PROFILE_RESWEEP_PENDING
            if _RECOMPUTING_PROFILE_GROUPS:
                _PROFILE_RESWEEP_PENDING = True
            else:
                recompute_profile_groups(db)

        # PRA-161 #1e-a: if THIS smart group is
        # bound to a patch policy via ``PatchPolicySmartGroupBinding``,
        # its cached membership is part of the effective-policy
        # resolver input (smart-group tier). Membership changes here
        # can move hosts into or out of ``patch.has_effective_policy``
        # / ``patch.resolution_kind`` etc., so dependent ``patch.*``
        # smart groups need a refresh. The cycle guard in
        # ``patch_policy_service.bind_smart_group`` prevents ``patch.*``
        # smart groups from being patch-policy binding targets, so
        # there is no binder→filter→binder feedback loop here — a
        # direct ``recompute_patch_groups`` call is sufficient (no
        # re-sweep flag like profile.* needs).
        is_patch_binder = (
            db.query(PatchPolicySmartGroupBinding.id)
            .filter(PatchPolicySmartGroupBinding.smart_group_id == smart_group_id)
            .first()
            is not None
        )
        if is_patch_binder:
            recompute_patch_groups(db)

        # PRA-162 #5: same cascade for ring.* predicates. If THIS
        # smart group is bound to a ring via PatchRingSmartGroupBinding,
        # its cached membership is part of the effective-ring resolver
        # input (smart-group tier). Membership changes here can move
        # hosts into or out of ``ring.has_effective_ring`` /
        # ``ring.status`` etc., so dependent ``ring.*`` smart groups
        # need a refresh. The cycle guard in
        # ``patch_ring_service.bind_smart_group`` prevents ``ring.*``
        # smart groups from being ring binding targets, so there is no
        # binder→filter→binder feedback loop — a direct
        # ``recompute_ring_groups`` call is sufficient.
        is_ring_binder = (
            db.query(PatchRingSmartGroupBinding.id)
            .filter(PatchRingSmartGroupBinding.smart_group_id == smart_group_id)
            .first()
            is not None
        )
        if is_ring_binder:
            recompute_ring_groups(db)

    return len(matched_ids)


def recompute_all(db: Session) -> Dict[int, int]:
    """Recompute membership for every enabled smart group."""
    groups = db.query(SmartGroup).filter(SmartGroup.enabled.is_(True)).all()
    return {g.id: recompute_membership(db, g.id) for g in groups}


def members(db: Session, smart_group_id: int) -> List[int]:
    """Return cached member system IDs."""
    rows = (
        db.query(SmartGroupMembership.system_id)
        .filter(SmartGroupMembership.smart_group_id == smart_group_id)
        .all()
    )
    return [r[0] for r in rows]


def is_member(db: Session, smart_group_id: int, system_id: int) -> bool:
    """Fast O(1)-style lookup using the composite index."""
    return (
        db.query(SmartGroupMembership.id)
        .filter(
            SmartGroupMembership.smart_group_id == smart_group_id,
            SmartGroupMembership.system_id == system_id,
        )
        .first()
        is not None
    )


def recompute_for_system(db: Session, system_id: int) -> None:
    """Called after a single-system mutation — cheap full recompute.

    At fleet scale of 15-200 hosts per PRA-131 cap, full recompute is <100ms.
    Replace with targeted refresh later if needed.
    """
    recompute_all(db)


# ---------------------------------------------------------------------------
# ORM event hooks: recompute membership when System rows change.
# ---------------------------------------------------------------------------


def _register_system_mutation_hooks():
    """Install SA ORM events so System CRUD triggers a membership refresh.

    Mapper-level events fire mid-flush, so we only set a flag; the real
    recompute runs on a fresh SessionLocal in ``after_commit``.
    """
    from sqlalchemy import event
    from sqlalchemy.orm import Session as ORMSession

    from ..db.session import SessionLocal

    _DIRTY_ATTR = "_sg_dirty"

    def _mark_dirty(mapper, connection, target):  # noqa: D401
        sess = ORMSession.object_session(target)
        if sess is not None:
            setattr(sess, _DIRTY_ATTR, True)

    event.listen(System, "after_insert", _mark_dirty)
    event.listen(System, "after_update", _mark_dirty)
    event.listen(System, "after_delete", _mark_dirty)

    @event.listens_for(ORMSession, "after_commit")
    def _on_commit(sess):  # noqa: D401
        if not getattr(sess, _DIRTY_ATTR, False):
            return
        setattr(sess, _DIRTY_ATTR, False)
        fresh = SessionLocal()
        try:
            recompute_all(fresh)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("post-commit smart group recompute failed: %s", e)
        finally:
            fresh.close()


_register_system_mutation_hooks()
