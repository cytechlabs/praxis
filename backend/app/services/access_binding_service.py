"""Fleet access binding service (PRA-137).

Owns the lifecycle of AccessBindings and materialises AccessGrants. Grants are
the authoritative desired state the reconciler converges host accounts toward.

Core operations:
    * create/update/delete/list bindings
    * ``recompute_grants`` — full rebuild from bindings x memberships
    * ``eligible_logins`` — powers the "Connect as..." dropdown in E4

Grant computation is full-rebuild at fleet scale (<= a few hundred hosts).
Future optimisation: targeted recompute keyed on binding/membership diffs.

Implicit rule: every user with the app-level ``admin`` role is treated as if
they held an AccessBinding for the built-in ``admin`` fleet role on every
system. Rows are flagged ``is_implicit_admin=True`` and have ``via_binding_id``
NULL so the UI can distinguish them from operator-created bindings.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..db.access_models import AccessBinding, AccessGrant, FleetRole
from ..db.models import Role, SmartGroupMembership, System, User, user_role
from .access_authorization_service import active_grant_filter

logger = logging.getLogger(__name__)

BUILTIN_ADMIN_ROLE = "admin"

# PRA-289: a stable key for the transaction-scoped advisory lock that serializes
# concurrent grant recomputes on Postgres. Value is arbitrary but must be constant.
_RECOMPUTE_LOCK_KEY = 0x50524139  # "PRA9"


# --------------------------------------------------------------------- errors


class BindingValidationError(ValueError):
    """Raised when an AccessBinding payload fails validation."""


# ------------------------------------------------------------- validation


def _validate_binding_shape(
    subject_user_id: Optional[int],
    subject_app_role_id: Optional[int],
    scope_group_id: Optional[int],
    scope_smart_group_id: Optional[int],
) -> None:
    subject_set = sum(
        1 for v in (subject_user_id, subject_app_role_id) if v is not None
    )
    scope_set = sum(1 for v in (scope_group_id, scope_smart_group_id) if v is not None)
    if subject_set != 1:
        raise BindingValidationError(
            "exactly one of subject_user_id / subject_app_role_id must be set"
        )
    if scope_set != 1:
        raise BindingValidationError(
            "exactly one of scope_group_id / scope_smart_group_id must be set"
        )


# --------------------------------------------------------------------- CRUD


def create_binding(
    db: Session,
    *,
    fleet_role_id: int,
    subject_user_id: Optional[int] = None,
    subject_app_role_id: Optional[int] = None,
    scope_group_id: Optional[int] = None,
    scope_smart_group_id: Optional[int] = None,
    enabled: bool = True,
    expires_at: Optional[datetime] = None,
    created_by: Optional[int] = None,
) -> AccessBinding:
    _validate_binding_shape(
        subject_user_id, subject_app_role_id, scope_group_id, scope_smart_group_id
    )
    binding = AccessBinding(
        fleet_role_id=fleet_role_id,
        subject_user_id=subject_user_id,
        subject_app_role_id=subject_app_role_id,
        scope_group_id=scope_group_id,
        scope_smart_group_id=scope_smart_group_id,
        enabled=enabled,
        expires_at=expires_at,
        created_by=created_by,
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)
    recompute_grants(db)
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="binding.create",
            actor_user_id=created_by,
            target_kind="binding",
            target_id=str(binding.id),
            context={
                "fleet_role_id": fleet_role_id,
                "subject_user_id": subject_user_id,
                "subject_app_role_id": subject_app_role_id,
                "scope_group_id": scope_group_id,
                "scope_smart_group_id": scope_smart_group_id,
                "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
            },
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return binding


def update_binding(
    db: Session,
    binding_id: int,
    *,
    enabled: Optional[bool] = None,
    expires_at: Optional[datetime] = None,
    fleet_role_id: Optional[int] = None,
    reason: str = "binding_update",
    source: Optional[str] = None,
) -> AccessBinding:
    binding = db.query(AccessBinding).filter(AccessBinding.id == binding_id).first()
    if not binding:
        raise BindingValidationError(f"binding {binding_id} not found")
    if enabled is not None:
        binding.enabled = enabled
    if expires_at is not None:
        binding.expires_at = expires_at
    if fleet_role_id is not None:
        binding.fleet_role_id = fleet_role_id
    # PRA-285 fix-pass: FLUSH (do not commit) the source change, then recompute in
    # the SAME transaction so the binding change, the grant rebuild, and the
    # RevocationWork outbox all commit together. If recompute fails it rolls the
    # whole transaction back — the source mutation never persists with stale grants
    # and no outbox.
    db.flush()
    recompute_grants(db, reason=reason, source=source)
    db.refresh(binding)
    return binding


def delete_binding(
    db: Session,
    binding_id: int,
    *,
    reason: str = "binding_delete",
    source: Optional[str] = None,
) -> bool:
    binding = db.query(AccessBinding).filter(AccessBinding.id == binding_id).first()
    if not binding:
        return False
    snapshot = {
        "fleet_role_id": binding.fleet_role_id,
        "subject_user_id": binding.subject_user_id,
        "subject_app_role_id": binding.subject_app_role_id,
        "scope_group_id": binding.scope_group_id,
        "scope_smart_group_id": binding.scope_smart_group_id,
    }
    # PRA-285 fix-pass: disable FIRST so the recompute's before/after active-grant
    # diff captures the removed scopes and enqueues reconcile work (a straight hard
    # delete would CASCADE the grants away via AccessGrant.via_binding_id ON DELETE
    # CASCADE before recompute could diff them). FLUSH (not commit) the disable so
    # the disable + grant rebuild + outbox commit ATOMICALLY inside recompute; a
    # recompute failure rolls all of it back (binding stays enabled, grants intact,
    # no orphan work). Only AFTER that commit succeeds is it safe to hard-delete the
    # now-grantless binding.
    binding.enabled = False
    db.flush()
    recompute_grants(db, reason=reason, source=source)
    db.delete(binding)
    db.commit()
    try:
        from .audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="binding.delete",
            target_kind="binding",
            target_id=str(binding_id),
            context=snapshot,
        )
    except Exception:  # pylint: disable=broad-except
        pass
    return True


def list_bindings(
    db: Session,
    *,
    subject_user_id: Optional[int] = None,
    fleet_role_id: Optional[int] = None,
    enabled_only: bool = False,
) -> List[AccessBinding]:
    q = db.query(AccessBinding)
    if subject_user_id is not None:
        q = q.filter(AccessBinding.subject_user_id == subject_user_id)
    if fleet_role_id is not None:
        q = q.filter(AccessBinding.fleet_role_id == fleet_role_id)
    if enabled_only:
        q = q.filter(AccessBinding.enabled.is_(True))
    return q.order_by(AccessBinding.id.asc()).all()


# ------------------------------------------------------ subject/scope resolve


def _resolve_subject_users(db: Session, binding: AccessBinding) -> List[User]:
    # PRA-290: only ACTIVE users materialize grants. Deactivating a user therefore
    # drops their grants (and host desired state) on the next recompute, so access
    # no longer appears live.
    if binding.subject_user_id is not None:
        user = db.query(User).filter(User.id == binding.subject_user_id).first()
        return [user] if user and user.is_active else []
    # app-role subject: all active users holding that role
    users = (
        db.query(User)
        .join(user_role, user_role.c.user_id == User.id)
        .filter(
            user_role.c.role_id == binding.subject_app_role_id,
            User.is_active.is_(True),
        )
        .all()
    )
    return users


def _resolve_scope_systems(db: Session, binding: AccessBinding) -> List[System]:
    if binding.scope_group_id is not None:
        return db.query(System).filter(System.group_id == binding.scope_group_id).all()
    # smart-group scope: cached memberships
    rows = (
        db.query(System)
        .join(SmartGroupMembership, SmartGroupMembership.system_id == System.id)
        .filter(SmartGroupMembership.smart_group_id == binding.scope_smart_group_id)
        .all()
    )
    return rows


def _login_for(user: User, role: FleetRole) -> Optional[str]:
    """Compute the local login a grant should target."""
    if role.login_mode == "per_user":
        return user.username
    if role.login_mode == "role_account":
        return role.role_account_name
    logger.warning("fleet_role %d has unknown login_mode=%r", role.id, role.login_mode)
    return None


# ------------------------------------------------------------- recomputation


def _serialize_recompute(db: Session) -> None:
    """Serialize concurrent recomputes with a transaction-scoped advisory lock.

    On Postgres, ``pg_advisory_xact_lock`` blocks until this transaction can hold
    the lock and auto-releases at commit/rollback, so two racing recomputes run
    one-after-another and both converge on the same deterministic final grant set.
    It is re-entrant within a session (so nested calls in one test transaction are
    safe).

    PRA-289 fix-pass: this is FAIL-CLOSED. If the lock cannot be acquired/executed
    on Postgres the exception PROPAGATES — the caller aborts and rolls back rather
    than continuing unlocked, because proceeding without the lock would drop the
    exact serialization guarantee this control exists to provide.

    On non-Postgres backends (e.g. SQLite, whose single-writer model already
    serializes write transactions) this is an intentional no-op.
    """
    if db.get_bind().dialect.name != "postgresql":
        return
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _RECOMPUTE_LOCK_KEY})


def recompute_grants(
    db: Session, *, reason: str = "grant_recompute", source: Optional[str] = None
) -> int:
    """Atomically rebuild the ``access_grants`` table from bindings + memberships.

    PRA-289: the delete and the rebuild happen in a SINGLE transaction with ONE
    commit, so a concurrent reader never observes an empty/partial grant table
    (it sees the previous committed set until the swap commits). Any failure —
    including a failure to acquire the serialization advisory lock on Postgres —
    rolls the whole transaction back, preserving the previously valid grant set.

    PRA-285: this is the common revocation choke point. The rebuild computes the
    set of ``(user, system, login)`` scopes that LOST active access and enqueues
    reconcile work in the SAME transaction (outbox — if the narrowed grants commit,
    the work exists). ``reason``/``source`` are carried for audit only. After the
    commit, reachable in-process sessions for the removed scopes are closed
    best-effort; a close failure never rolls the grant change back (the drain
    retries). Returns the number of rows in the new set.
    """
    try:
        # Fail-closed: a lock failure raises here and aborts (rollback below); the
        # delete has not run yet, so the prior grant set is untouched regardless.
        _serialize_recompute(db)
        removed, count = _rebuild_grants_locked(db, reason=reason, source=source)
    except Exception:
        # Roll back the (possible) delete + partial inserts, and clear any aborted
        # transaction state, so the prior grant set survives.
        db.rollback()
        raise

    # Post-commit (grants + outbox work already durable): best-effort synchronous
    # session close + a single revocation.request audit. Never rolls access back.
    if removed:
        from . import revocation_service

        try:
            revocation_service.close_sessions_for_removed(db, removed, reason="revoked")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("revocation: post-commit session close failed: %s", exc)
        # safe_emit with no db= opens its own session so this audit does not commit
        # on top of the grant transaction.
        try:
            from .audit_event_service import safe_emit

            safe_emit(
                action="revocation.request",
                target_kind="revocation",
                context={
                    "reason": reason,
                    "source": source,
                    "removed_scopes": len(removed),
                },
            )
        except Exception:  # pylint: disable=broad-except
            pass
    return count


def _merge_expiry(a: Optional[datetime], b: Optional[datetime]) -> Optional[datetime]:
    """Effective expiry when one grant key is produced by multiple sources.

    PRA-284: ``None`` (never expires) DOMINATES — an app-admin's implicit
    never-expiring grant must not be shortened by an overlapping expiring binding.
    Otherwise the LATER expiry wins, since access is valid as long as any
    contributing binding is valid.
    """
    if a is None or b is None:
        return None
    return max(a, b)


def _rebuild_grants_locked(
    db: Session, *, reason: str = "grant_recompute", source: Optional[str] = None
):
    """Returns ``(removed, count)`` — the set of ``(user, system, login)`` scopes
    that lost ACTIVE access, and the new grant-row count."""
    now = datetime.utcnow()
    # PRA-285: snapshot the ACTIVE (PRA-284 expiry-aware) grant scope BEFORE the
    # rebuild, so we can diff what lost access. Only currently-authorizing grants
    # count — an already-expired grant was not authorizing, so its removal is not a
    # new revocation.
    before_active: Set[Tuple[int, int, str]] = {
        (r[0], r[1], r[2])
        for r in db.query(AccessGrant.user_id, AccessGrant.system_id, AccessGrant.login)
        .filter(active_grant_filter(now))
        .all()
    }

    # NOTE: no intermediate commit — the delete is not visible to other readers
    # until the single commit at the end makes the swap atomic.
    db.query(AccessGrant).delete(synchronize_session=False)
    # key -> materialized grant fields, merged across every contributing source so
    # each (user, system, role, login) is inserted exactly once with the correct
    # effective expiry (PRA-284) and implicit-admin marker.
    grants: Dict[Tuple[int, int, int, str], dict] = {}

    def _accumulate(
        *,
        user_id: int,
        system_id: int,
        fleet_role_id: int,
        login: str,
        expires_at: Optional[datetime],
        via_binding_id: Optional[int],
        is_implicit_admin: bool,
    ) -> None:
        key = (user_id, system_id, fleet_role_id, login)
        existing = grants.get(key)
        if existing is None:
            grants[key] = {
                "user_id": user_id,
                "system_id": system_id,
                "fleet_role_id": fleet_role_id,
                "login": login,
                "expires_at": expires_at,
                "via_binding_id": via_binding_id,
                "is_implicit_admin": is_implicit_admin,
            }
            return
        existing["expires_at"] = _merge_expiry(existing["expires_at"], expires_at)
        if is_implicit_admin:
            # The implicit app-admin rule is the authoritative never-expiring
            # source for this key; let it own the marker + drop the binding ref.
            existing["is_implicit_admin"] = True
            existing["via_binding_id"] = None

    # --- explicit bindings --------------------------------------------------
    bindings = db.query(AccessBinding).filter(AccessBinding.enabled.is_(True)).all()
    for binding in bindings:
        # Already-expired bindings do not materialize grants (boundary: <= now).
        if binding.expires_at is not None and binding.expires_at <= now:
            continue
        role = db.query(FleetRole).filter(FleetRole.id == binding.fleet_role_id).first()
        if role is None:
            continue
        subjects = _resolve_subject_users(db, binding)
        systems = _resolve_scope_systems(db, binding)
        for user in subjects:
            login = _login_for(user, role)
            if not login:
                continue
            for system in systems:
                _accumulate(
                    user_id=user.id,
                    system_id=system.id,
                    fleet_role_id=role.id,
                    login=login,
                    # PRA-284: copy the source binding's expiry onto the grant.
                    expires_at=binding.expires_at,
                    via_binding_id=binding.id,
                    is_implicit_admin=False,
                )

    # --- implicit admin rule ------------------------------------------------
    admin_fleet_role = (
        db.query(FleetRole)
        .filter(FleetRole.name == BUILTIN_ADMIN_ROLE, FleetRole.is_builtin.is_(True))
        .first()
    )
    admin_app_role = db.query(Role).filter(Role.name == BUILTIN_ADMIN_ROLE).first()
    if admin_fleet_role and admin_app_role:
        # PRA-290: only active admins get implicit all-system grants. Removing the
        # admin role (or deactivating the admin) drops these on recompute.
        admin_users = (
            db.query(User)
            .join(user_role, user_role.c.user_id == User.id)
            .filter(
                user_role.c.role_id == admin_app_role.id,
                User.is_active.is_(True),
            )
            .all()
        )
        systems = db.query(System).all()
        for user in admin_users:
            login = _login_for(user, admin_fleet_role)
            if not login:
                continue
            for system in systems:
                _accumulate(
                    user_id=user.id,
                    system_id=system.id,
                    fleet_role_id=admin_fleet_role.id,
                    login=login,
                    # PRA-284: implicit app-admin grants never expire (their
                    # boundary is app role + active user, per PRA-290).
                    expires_at=None,
                    via_binding_id=None,
                    is_implicit_admin=True,
                )

    for fields in grants.values():
        db.add(AccessGrant(**fields))
    inserted = len(grants)

    # PRA-285: diff the ACTIVE scope. Everything the rebuild materializes is active
    # (expired bindings are skipped), so the new scope is the grant keys.
    after: Set[Tuple[int, int, str]] = {
        (g["user_id"], g["system_id"], g["login"]) for g in grants.values()
    }
    removed = before_active - after
    if removed:
        # Outbox: enqueue reconcile work in THIS transaction so it commits atomically
        # with the narrowed grants. A row is a signal to reconverge a scope, not a
        # replayed "remove" — the drain re-derives desired state via reconcile_system.
        from . import revocation_service

        revocation_service.enqueue_grant_removals(
            db, removed, reason=reason, source=source, now=now
        )

    db.commit()
    logger.info(
        "recompute_grants: inserted %d rows, %d scope(s) revoked",
        inserted,
        len(removed),
    )
    return removed, inserted


# ------------------------------------------------------------ read / lookup


def eligible_logins(
    db: Session, user_id: int, system_id: int, now=None
) -> List[AccessGrant]:
    """Return every NON-EXPIRED grant for this (user, system) — the 'Connect
    as...' data. PRA-284: expired grants are omitted synchronously."""
    return (
        db.query(AccessGrant)
        .filter(
            AccessGrant.user_id == user_id,
            AccessGrant.system_id == system_id,
            active_grant_filter(now),
        )
        .order_by(AccessGrant.login.asc())
        .all()
    )


def grants_for_system(db: Session, system_id: int, now=None) -> List[AccessGrant]:
    return (
        db.query(AccessGrant)
        .filter(AccessGrant.system_id == system_id, active_grant_filter(now))
        .order_by(AccessGrant.login.asc(), AccessGrant.user_id.asc())
        .all()
    )


def grants_for_user(db: Session, user_id: int, now=None) -> List[AccessGrant]:
    return (
        db.query(AccessGrant)
        .filter(AccessGrant.user_id == user_id, active_grant_filter(now))
        .order_by(AccessGrant.system_id.asc(), AccessGrant.login.asc())
        .all()
    )


# ------------------------------------------------------- mutation hooks


def _register_grant_recompute_hooks() -> None:
    """Rebuild grants whenever binding/membership/user-role shape changes.

    Mapper events fire mid-flush; we only mark the session dirty and run the
    recompute on a fresh session in after_commit. Same pattern as
    smart_group_service.

    Skipped under TESTING: the fresh SessionLocal would write to the real
    test DB outside the per-test SAVEPOINT rollback and pollute subsequent
    runs. Tests call ``recompute_grants`` explicitly when needed.
    """
    import os

    if os.environ.get("TESTING", "").lower() in ("1", "true", "yes"):
        return

    from sqlalchemy import event
    from sqlalchemy.orm import Session as ORMSession

    from ..db.session import SessionLocal

    _DIRTY = "_ag_dirty"

    def _mark(mapper, connection, target):  # noqa: D401
        sess = ORMSession.object_session(target)
        if sess is not None:
            setattr(sess, _DIRTY, True)

    # System mutations matter for the implicit-admin rule: a fresh System
    # row needs admin grants materialised, and a decommissioned System should
    # drop its grants. User mutations matter for the same rule in the other
    # direction (new admin user -> grants on every existing host).
    for model in (AccessBinding, SmartGroupMembership, System, User):
        event.listen(model, "after_insert", _mark)
        event.listen(model, "after_update", _mark)
        event.listen(model, "after_delete", _mark)

    @event.listens_for(ORMSession, "after_commit")
    def _on_commit(sess):  # noqa: D401
        if not getattr(sess, _DIRTY, False):
            return
        setattr(sess, _DIRTY, False)
        fresh = SessionLocal()
        try:
            recompute_grants(fresh)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("post-commit access grant recompute failed: %s", e)
        finally:
            fresh.close()


_register_grant_recompute_hooks()
