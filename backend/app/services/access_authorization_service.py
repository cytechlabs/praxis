"""Fleet access authorization service (PRA-139).

Single source of truth for the permission check that gates session open,
command exec, and file transfer. Callers (routes / session service) invoke
``authorize_action`` and act on the returned flags:

    result = authorize_action(db, user, system, "command_exec")
    if result.requires_totp and not has_fresh_totp(db, user.id):
        raise HTTPException(403, "totp step-up required")
    # ... proceed ...

Permission denials come through ``PermissionDenied`` with a ``code`` field so
callers can render actionable UI:

    * ``forbidden``          — no matching grant at all
    * ``action_not_allowed`` — grant exists but fleet role disallows this action
    * ``approval_required`` — fleet role requires session approval and none is live
    * ``totp_required``     — fleet role requires TOTP and step-up is stale
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..db.access_models import AccessGrant, FleetRole, TotpChallenge
from ..db.models import SmartGroupMembership, System, User

logger = logging.getLogger(__name__)

VALID_ACTIONS = {"session_open", "command_exec", "file_transfer"}
DEFAULT_TOTP_WINDOW_S = 900  # 15 min
# Fallbacks matching the FleetRole column defaults, for the conservative
# session-policy resolution when a role leaves a field NULL (PRA-287).
DEFAULT_IDLE_TIMEOUT_S = 900
DEFAULT_MAX_SESSION_S = 3600
DEFAULT_RECORDING_RETENTION_DAYS = 90

# PRA-288: immutable SSH cert identity. The certificate principal for managed user
# access is derived from the Praxis user's immutable primary key, NEVER the mutable
# username and NEVER the (possibly shared) target Linux login. This is the single
# source of the mapping — sessions, file transfer, and the host principals files all
# build principals through cert_principal_for_user so they always agree.
CERT_PRINCIPAL_PREFIX = "praxis-user-"


def cert_principal_for_user(user_or_id) -> str:
    """Immutable, namespaced SSH cert principal for a Praxis user.

    Bound to the immutable ``user.id`` so a username rename cannot break cert auth
    and a deleted-then-recreated username cannot inherit the old user's certificate
    authority (PRA-288). Accepts a ``User`` or a raw user id. The result uses only
    characters accepted by the host-side principal validation (``-`` and digits).
    """
    uid = user_or_id.id if isinstance(user_or_id, User) else int(user_or_id)
    return f"{CERT_PRINCIPAL_PREFIX}{uid}"


# ---------------------------------------------------- grant expiry (PRA-284)
# Grant expiry is a SYNCHRONOUS, fail-closed authorization boundary: an expired
# grant stops authorizing at the decision itself, without waiting for a recompute,
# cleanup sweep, or any unrelated DB mutation. ``AccessGrant.expires_at`` is copied
# from the source binding at recompute (NULL = never expires, e.g. implicit active
# app-admin grants). Every authorization surface filters through the single helper
# below so the ``expires_at IS NULL OR expires_at > now`` rule is defined once.
#
# The ``now`` parameter is an injectable clock: tests advance it past a grant's
# ``expires_at`` to prove expiry takes effect with no DB change. Boundary is exact —
# ``expires_at <= now`` is expired.


def active_grant_filter(now: Optional[datetime] = None):
    """SQLAlchemy predicate selecting grants still active at ``now``."""
    if now is None:
        now = datetime.utcnow()
    return or_(AccessGrant.expires_at.is_(None), AccessGrant.expires_at > now)


def is_grant_active(grant: AccessGrant, now: Optional[datetime] = None) -> bool:
    """In-memory equivalent of :func:`active_grant_filter` for a single grant."""
    if now is None:
        now = datetime.utcnow()
    return grant.expires_at is None or grant.expires_at > now


# ------------------------------------------------------- fleet scope (PRA-281)
# A user's *fleet scope* is the set of systems they may see or operate on. It is
# the authoritative filter for every system-addressable and fleet-aggregate API,
# so a scoped maintainer/auditor can never observe or act outside their grants.
#
# The tenant-wide (app-admin) decision lives HERE, not in per-route bypasses:
# ``scoped_system_ids`` returns ``None`` to mean "all systems". Callers that
# thread scope into a query treat ``None`` as "no filter" and a set as an
# explicit allow-list (an empty set therefore yields zero rows, never a leak).


def user_is_tenant_admin(user: User) -> bool:
    """True when the user's global app role grants tenant-wide fleet scope.

    Application admins are intentionally tenant-wide (product decision), but they
    reach that scope through this policy function — the same one maintainers and
    auditors flow through — rather than a route-level ``if is_admin`` short-circuit.
    """
    return any((getattr(r, "name", None) == "admin") for r in (user.roles or []))


def scoped_system_ids(
    db: Session, user: User, now: Optional[datetime] = None
) -> Optional[Set[int]]:
    """The set of ``system.id`` the user may access, or ``None`` for tenant-wide.

    - App admins: ``None`` (all systems).
    - Everyone else: the distinct systems they hold a non-expired ``AccessGrant``
      on (PRA-284). A user with no active grants gets an empty set (access to
      nothing), never global access.
    """
    if user_is_tenant_admin(user):
        return None
    rows = (
        db.query(AccessGrant.system_id)
        .filter(AccessGrant.user_id == user.id, active_grant_filter(now))
        .distinct()
        .all()
    )
    return {row[0] for row in rows}


def user_can_access_system(
    db: Session, user: User, system_id: int, now: Optional[datetime] = None
) -> bool:
    """Membership check for a single system. Admins (scope ``None``) always pass."""
    ids = scoped_system_ids(db, user, now)
    return ids is None or system_id in ids


# Package-management cohort scoping. The supported scope selectors for
# scoped package views: fleet-wide, a single system, a static group, or a smart
# group. Kept next to ``scoped_system_ids`` because it composes ON TOP of it.
PACKAGE_SCOPE_TYPES = frozenset({"all", "system", "group", "smart_group"})


def resolve_package_scope_ids(
    db: Session,
    user: User,
    scope_type: Optional[str] = None,
    scope_id: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Optional[Set[int]]:
    """Resolve a package-scope selector to the effective system-id set.

    Composes a cohort selector with the caller's FLEET SCOPE
    (``scoped_system_ids``) so a scoped caller can never widen past their grants:

    * ``all`` → the caller's scope verbatim (``None`` = tenant-wide admin, no
      filter; otherwise the grant set).
    * ``system`` → ``{scope_id}`` intersected with the caller scope.
    * ``group`` → the static group's members (``System.group_id``) intersected
      with the caller scope.
    * ``smart_group`` → the smart-group membership intersected with the caller
      scope.

    Returns ``None`` ONLY for a tenant-wide admin under ``all`` (truly
    unfiltered). Otherwise a concrete set, POSSIBLY EMPTY: an empty cohort, or a
    cohort disjoint from the caller's scope, yields an empty set — which downstream
    scope-application turns into zero rows, never a global fallback, so hidden or
    out-of-scope membership is never leaked.

    Raises ``ValueError`` for an unknown ``scope_type`` or a missing ``scope_id``
    where one is required; routes translate that to a 400.
    """
    caller = scoped_system_ids(db, user, now)  # None = admin; else a set
    kind = (scope_type or "all").strip().lower()
    if kind == "all":
        return None if caller is None else set(caller)
    if kind not in PACKAGE_SCOPE_TYPES:
        raise ValueError(f"invalid scope_type: {scope_type!r}")
    if scope_id is None:
        raise ValueError("scope_id is required for scope_type " + kind)

    if kind == "system":
        target = {int(scope_id)}
    elif kind == "group":
        target = {
            row[0]
            for row in db.query(System.id)
            .filter(System.group_id == int(scope_id))
            .all()
        }
    else:  # smart_group
        target = {
            row[0]
            for row in db.query(SmartGroupMembership.system_id)
            .filter(SmartGroupMembership.smart_group_id == int(scope_id))
            .all()
        }

    return target if caller is None else (target & caller)


def scope_query_by_system(
    query, db: Session, user: User, system_id_column, now: Optional[datetime] = None
):
    """Constrain a SQLAlchemy ``query`` to the user's fleet scope.

    ``system_id_column`` is the mapped column to filter on (e.g.
    ``Package.system_id``). Admins get the query unchanged; a scoped user gets an
    ``IN (their ids)`` filter; a user with an empty scope gets a query that
    returns nothing — so aggregate counts/lists never include inaccessible
    systems and never leak their ids.
    """
    ids = scoped_system_ids(db, user, now)
    if ids is None:
        return query
    if not ids:
        from sqlalchemy import false

        return query.filter(false())
    return query.filter(system_id_column.in_(ids))


def scope_in_clause(system_id_column, allowed_system_ids: Optional[Set[int]]):
    """Service-layer scope predicate for callers that already hold the scope set.

    Unlike :func:`scope_query_by_system` (which needs the ``user`` and issues a
    query), this returns a bare WHERE expression to AND into an existing query,
    for services that receive ``allowed_system_ids`` directly:

    * ``None``      → ``None`` (tenant-wide admin; add no filter);
    * empty set     → ``false()`` (access to nothing; zero rows);
    * non-empty set → ``system_id_column IN (ids)``.
    """
    if allowed_system_ids is None:
        return None
    if not allowed_system_ids:
        from sqlalchemy import false

        return false()
    return system_id_column.in_(allowed_system_ids)


class PermissionDenied(Exception):
    """Raised when an action is not authorized. ``code`` is machine-readable."""

    def __init__(self, reason: str, code: str = "forbidden"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


@dataclass
class AuthorizationResult:
    grant: AccessGrant
    fleet_role: FleetRole
    login: str
    requires_approval: bool
    requires_totp: bool
    # PRA-287: conservative (strictest) session policy across every allowing role
    # for this login, so a looser role can't grant a longer session/less recording
    # through a shared account. Shortest timeouts, longest recording retention.
    idle_timeout_s: int = DEFAULT_IDLE_TIMEOUT_S
    max_session_s: int = DEFAULT_MAX_SESSION_S
    recording_retention_days: int = DEFAULT_RECORDING_RETENTION_DAYS


# ----------------------------------------------------------------- resolver
#
# PRA-289: overlap between grants is resolved by an EXPLICIT, deterministic policy
# that never depends on ``fleet_role.id`` (primary-key/insertion order). This same
# policy is the single decision source shared by authorization here and by
# reconciliation's desired-host-state resolver, so both agree on overlap.


def _role_actions(role: FleetRole) -> Set[str]:
    """The action set a fleet role explicitly allows (empty on malformed JSON)."""
    try:
        return set(json.loads(role.allowed_actions_json or "[]"))
    except (TypeError, ValueError):
        return set()


def role_sort_key(role: FleetRole) -> Tuple[int, str]:
    """Deterministic, primary-key-independent role precedence.

    A role that explicitly allows MORE actions ranks stronger (sorts first);
    ties break by the unique role name. Never uses ``fleet_role.id`` so the
    result is stable regardless of database insertion order. Shared by
    authorization and reconciliation so overlap resolves identically in both.
    """
    return (-len(_role_actions(role)), role.name or "")


def applicable_grants(
    db: Session,
    user_id: int,
    system_id: int,
    login: Optional[str] = None,
    now: Optional[datetime] = None,
) -> List[Tuple[AccessGrant, FleetRole]]:
    """Every non-expired grant for ``(user, system[, login])`` paired with its
    fleet role, ordered by the shared deterministic precedence (grants whose role
    is missing are dropped). Authorization evaluates ALL of these, not a single
    PK-winner. PRA-284: expired grants are filtered out at the decision boundary."""
    q = db.query(AccessGrant).filter(
        AccessGrant.user_id == user_id,
        AccessGrant.system_id == system_id,
        active_grant_filter(now),
    )
    if login is not None:
        q = q.filter(AccessGrant.login == login)
    pairs: List[Tuple[AccessGrant, FleetRole]] = []
    for grant in q.all():
        role = db.query(FleetRole).filter(FleetRole.id == grant.fleet_role_id).first()
        if role is not None:
            pairs.append((grant, role))
    pairs.sort(key=lambda gr: (role_sort_key(gr[1]), gr[0].login or ""))
    return pairs


# ------------------------------------------- shared-login compatibility (PRA-287)
#
# Multiple fleet roles can resolve to the SAME ``(system, login)`` — a shared Linux
# account (role_account mode) or one user holding several roles (per_user mode). Two
# categories of role field are handled DIFFERENTLY:
#
# 1. ACCOUNT-SHAPE fields define the Linux account itself. There is no safe merge:
#    you cannot provision one account with two different group sets or login modes.
#    If applicable roles disagree on any of these the login is CONFLICTED — Praxis
#    1.0 prefers fail-closed surfacing over inventing IAM semantics, so
#    authorization fails closed and reconciliation refuses to converge (and does not
#    destructively remove) host state until an operator fixes the bindings/roles.
#      * login_mode / role_account_name — which account the login maps to;
#      * os_groups — supplementary group membership provisioned on the host;
#      * sudoers_snippet — sudo profile state; must be NULL in 1.0 post-PRA-282, but
#        still compared so a stray value can never silently merge.
#
# 2. SESSION-POLICY fields do NOT change the account; they gate each session and are
#    resolved CONSERVATIVELY (strictest wins) at authorization rather than treated as
#    a hard conflict, so a lower-control role can never bypass a stricter one and
#    reconciliation can still provision the (identically shaped) account:
#      * session_requires_approval / totp_required — required if ANY applicable role
#        requires it;
#      * idle_timeout_s / max_session_s — the SHORTEST wins (tightest session);
#      * recording_retention_days — the LONGEST wins (most audit coverage retained).
#
# ``allowed_actions_json`` is deliberately in neither set: it does not change the
# account shape, and authorization already unions it across a user's roles. Per-grant
# EXPIRY is not a shape field either — PRA-284 enforces it per-principal (expired
# grants drop from the principals list), so users sharing a login may hold different
# expiries without changing the account itself.
_ACCOUNT_SHAPE_FIELDS: Tuple[str, ...] = (
    "login_mode",
    "role_account_name",
    "os_groups",
    "sudoers_snippet",
)


def _role_shape_dict(role: FleetRole) -> Dict[str, object]:
    """The account-shape fields of a role as hashable values (conflict inputs)."""
    try:
        groups = tuple(sorted(set(json.loads(role.os_groups_json or "[]"))))
    except (TypeError, ValueError):
        groups = ("<malformed-os-groups>",)
    return {
        "login_mode": role.login_mode,
        "role_account_name": role.role_account_name,
        "os_groups": groups,
        "sudoers_snippet": role.sudoers_snippet,
    }


def _role_shape_fingerprint(role: FleetRole) -> Tuple:
    d = _role_shape_dict(role)
    return tuple(d[f] for f in _ACCOUNT_SHAPE_FIELDS)


@dataclass
class LoginResolution:
    """Resolution for one ``(system, login)``: either a single compatible desired
    role, or a structured conflict (mutually exclusive)."""

    login: str
    role: Optional[FleetRole]
    conflict: Optional[Dict[str, object]]

    @property
    def is_conflict(self) -> bool:
        return self.conflict is not None


def _resolve_login(
    system_id: int, login: str, roles: List[FleetRole]
) -> LoginResolution:
    """Compatibility gate for one shared login. Compatible iff every role has the
    SAME account-shape fingerprint; then the deterministic representative
    (``role_sort_key``, PK-independent) is returned. Otherwise a conflict listing
    the differing account-shape fields + role names. Session-policy differences are
    NOT conflicts — they are resolved conservatively at authorization."""
    fingerprints = {_role_shape_fingerprint(r) for r in roles}
    if len(fingerprints) <= 1:
        return LoginResolution(
            login=login, role=min(roles, key=role_sort_key), conflict=None
        )
    field_values: Dict[str, set] = {f: set() for f in _ACCOUNT_SHAPE_FIELDS}
    for r in roles:
        d = _role_shape_dict(r)
        for f in _ACCOUNT_SHAPE_FIELDS:
            field_values[f].add(d[f])
    differing = sorted(f for f, vals in field_values.items() if len(vals) > 1)
    logger.warning(
        "system %d login %r has INCOMPATIBLE shared-account roles %s; differing on "
        "%s — refusing to converge (PRA-287)",
        system_id,
        login,
        sorted({r.name for r in roles}),
        differing,
    )
    return LoginResolution(
        login=login,
        role=None,
        conflict={
            "system_id": system_id,
            "login": login,
            "role_names": sorted({r.name for r in roles}),
            "differing_fields": differing,
        },
    )


def _roles_for_login(
    db: Session, system_id: int, login: Optional[str], now: Optional[datetime]
) -> Dict[str, List[FleetRole]]:
    q = db.query(AccessGrant).filter(
        AccessGrant.system_id == system_id, active_grant_filter(now)
    )
    if login is not None:
        q = q.filter(AccessGrant.login == login)
    by_login: Dict[str, List[FleetRole]] = {}
    for grant in q.all():
        role = db.query(FleetRole).filter(FleetRole.id == grant.fleet_role_id).first()
        if role is not None:
            by_login.setdefault(grant.login, []).append(role)
    return by_login


def resolve_login_roles(
    db: Session, system_id: int, now: Optional[datetime] = None
) -> Dict[str, LoginResolution]:
    """Per-login resolution for every NON-EXPIRED login on the system. The single
    shared decision source for BOTH authorization and reconciliation."""
    return {
        login: _resolve_login(system_id, login, roles)
        for login, roles in _roles_for_login(db, system_id, None, now).items()
    }


def resolve_login_resolution(
    db: Session, system_id: int, login: str, now: Optional[datetime] = None
) -> LoginResolution:
    """Resolution for one ``(system, login)`` across every user sharing it (so a
    role_account conflict is seen). No active grants -> no role, no conflict."""
    roles = _roles_for_login(db, system_id, login, now).get(login, [])
    if not roles:
        return LoginResolution(login=login, role=None, conflict=None)
    return _resolve_login(system_id, login, roles)


def shared_login_conflicts(
    db: Session,
    system_ids: Optional[List[int]] = None,
    now: Optional[datetime] = None,
) -> List[Dict[str, object]]:
    """Operator-visible list of shared-login conflicts (across the given systems, or
    all Active systems). Surfaces conflicts BEFORE any host change is applied."""
    if system_ids is None:
        system_ids = [
            r[0] for r in db.query(System.id).filter(System.status == "Active").all()
        ]
    out: List[Dict[str, object]] = []
    for sid in system_ids:
        for res in resolve_login_roles(db, sid, now).values():
            if res.is_conflict:
                out.append(res.conflict)
    return out


def resolve_desired_login_roles(
    db: Session, system_id: int, now: Optional[datetime] = None
) -> Dict[str, FleetRole]:
    """Desired host-account role per ``(system, login)`` for reconciliation —
    COMPATIBLE logins only. Conflicted shared logins are omitted (surfaced via
    ``resolve_login_roles`` / ``shared_login_conflicts``) so reconciliation never
    converges an ambiguous account shape. Uses the same PK-independent precedence as
    authorization."""
    return {
        login: res.role
        for login, res in resolve_login_roles(db, system_id, now).items()
        if res.role is not None
    }


def authorize_action(
    db: Session,
    user: User,
    system: System,
    action: str,
    login: Optional[str] = None,
    now: Optional[datetime] = None,
) -> AuthorizationResult:
    """Decide whether ``user`` can perform ``action`` on ``system``.

    PRA-289: evaluates EVERY applicable grant, not a single primary-key winner.
    The action is allowed if any applicable fleet role explicitly includes it.
    Approval/TOTP requirements are the CONSERVATIVE union across the allowing
    roles — if any otherwise-applicable allowing role requires approval or TOTP,
    that requirement is preserved rather than bypassed by a looser overlapping
    role. PRA-284: only NON-EXPIRED grants are considered, synchronously at the
    decision. Raises ``PermissionDenied`` on hard rejects (no active grant at all,
    or an active grant exists but no applicable role allows the action).
    """
    if action not in VALID_ACTIONS:
        raise PermissionDenied(f"unknown action {action!r}", code="forbidden")

    # PRA-146: an active session lock on the user (direct or via role)
    # short-circuits every gated action regardless of grants.
    from . import session_lock_service

    lock = session_lock_service.is_user_locked(db, user)
    if lock is not None:
        raise PermissionDenied(
            f"user is locked (lock #{lock.id}: {lock.reason})",
            code="locked",
        )

    pairs = applicable_grants(db, user.id, system.id, login, now=now)
    if not pairs:
        raise PermissionDenied(
            f"no access grant for user {user.id} on system {system.id}",
            code="forbidden",
        )

    allowing = [(g, r) for (g, r) in pairs if action in _role_actions(r)]
    if not allowing:
        raise PermissionDenied(
            f"no fleet role for user {user.id} on system {system.id} allows {action}",
            code="action_not_allowed",
        )

    # PRA-287: fail closed on an incompatible shared login rather than selecting a
    # representative role — a lower-privilege principal must never inherit another
    # binding's OS groups / approval / TOTP / timeout / recording policy through a
    # shared account. Uses the SAME resolver reconciliation uses, so both agree.
    _conflict_cache: Dict[str, Optional[Dict[str, object]]] = {}

    def _conflict_for(lg: str) -> Optional[Dict[str, object]]:
        if lg not in _conflict_cache:
            _conflict_cache[lg] = resolve_login_resolution(
                db, system.id, lg, now
            ).conflict
        return _conflict_cache[lg]

    if login is not None:
        conflict = _conflict_for(login)
        if conflict is not None:
            raise PermissionDenied(
                f"shared login {login!r} on system {system.id} has incompatible "
                f"role policy (differ on {conflict['differing_fields']}); resolve "
                "the conflicting fleet-role bindings before access",
                code="login_conflict",
            )
        usable = allowing
    else:
        # Login unspecified: use only non-conflicted logins; fail closed if every
        # applicable login is conflicted.
        usable = [(g, r) for (g, r) in allowing if _conflict_for(g.login) is None]
        if not usable:
            conflict = _conflict_for(allowing[0][0].login)
            raise PermissionDenied(
                f"every applicable login for user {user.id} on system {system.id} "
                f"has incompatible role policy (e.g. {conflict['login']} differ on "
                f"{conflict['differing_fields']}); resolve bindings before access",
                code="login_conflict",
            )

    # Conservative current-state result: preserve any allowing role's requirement.
    requires_approval = any(bool(r.session_requires_approval) for (_, r) in usable)
    requires_totp = any(bool(r.totp_required) for (_, r) in usable)

    # PRA-287 conservative session policy: strictest across allowing roles so a
    # looser role cannot lengthen a session or shorten recording via a shared login.
    usable_roles = [r for (_, r) in usable]
    idle_timeout_s = min(
        (r.idle_timeout_s for r in usable_roles if r.idle_timeout_s is not None),
        default=DEFAULT_IDLE_TIMEOUT_S,
    )
    max_session_s = min(
        (r.max_session_s for r in usable_roles if r.max_session_s is not None),
        default=DEFAULT_MAX_SESSION_S,
    )
    recording_retention_days = max(
        (
            r.recording_retention_days
            for r in usable_roles
            if r.recording_retention_days is not None
        ),
        default=DEFAULT_RECORDING_RETENTION_DAYS,
    )

    # Deterministic representative among the usable grants (already ordered by
    # the shared precedence). The returned login is the account the session opens.
    chosen_grant, chosen_role = usable[0]
    return AuthorizationResult(
        grant=chosen_grant,
        fleet_role=chosen_role,
        login=chosen_grant.login,
        requires_approval=requires_approval,
        requires_totp=requires_totp,
        idle_timeout_s=idle_timeout_s,
        max_session_s=max_session_s,
        recording_retention_days=recording_retention_days,
    )


# --------------------------------------------------------------- TOTP gate


def has_fresh_totp(
    db: Session, user_id: int, window_s: int = DEFAULT_TOTP_WINDOW_S
) -> bool:
    """True when the user has a TotpChallenge row that hasn't yet expired."""
    now = datetime.utcnow()
    row = (
        db.query(TotpChallenge)
        .filter(
            TotpChallenge.user_id == user_id,
            TotpChallenge.expires_at > now,
        )
        .order_by(TotpChallenge.expires_at.desc())
        .first()
    )
    return row is not None


def record_totp_challenge(
    db: Session, user_id: int, window_s: int = DEFAULT_TOTP_WINDOW_S
) -> TotpChallenge:
    """Insert a fresh challenge row valid for ``window_s`` seconds."""
    row = TotpChallenge(
        user_id=user_id,
        expires_at=datetime.utcnow() + timedelta(seconds=window_s),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def clear_expired_challenges(db: Session) -> int:
    """Nightly sweeper: delete expired challenges. Returns row count."""
    now = datetime.utcnow()
    count = (
        db.query(TotpChallenge)
        .filter(TotpChallenge.expires_at < now - timedelta(days=1))
        .delete(synchronize_session=False)
    )
    db.commit()
    return count


# ------------------------------------------------------- convenience gate


def enforce_action(
    db: Session,
    user: User,
    system: System,
    action: str,
    login: Optional[str] = None,
    now: Optional[datetime] = None,
) -> AuthorizationResult:
    """Full gate: resolves grant + checks TOTP freshness. Raises on any gap.

    Session approvals are caller-specific (PRA-140 will own the workflow), so
    ``enforce_action`` surfaces ``approval_required`` but does not try to look
    up live approvals here.
    """
    result = authorize_action(db, user, system, action, login=login, now=now)
    if result.requires_totp and not has_fresh_totp(db, user.id):
        raise PermissionDenied("TOTP step-up required", code="totp_required")
    if result.requires_approval:
        raise PermissionDenied("session approval required", code="approval_required")
    return result
