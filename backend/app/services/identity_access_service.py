"""Identity-access service (PRA-290).

One explicit path for the identity events that must keep materialized access in
sync: application-role changes, user (de)activation, and OIDC/federated role sync.
Every such change flows through here so it deterministically updates grants via the
PRA-289 atomic recompute and invokes the currently-available access-impact hooks,
instead of relying on ``user.roles = ...; commit()`` scattered across routes and on
SQLAlchemy relationship hooks that do not reliably observe ``user_role``
association-table changes.

Failures surface: recompute and the session-impact hook raise, and the caller
rolls back / returns an error, rather than a best-effort post-commit log that would
leave stale authorization behind.

Scope boundary: this slice invokes the existing session-lock impact hook to close
live sessions and deny new ones on deactivation. It does NOT build the PRA-285
durable, bounded-retry revocation/host-reconcile orchestrator — host account
convergence still happens through the normal fleet reconciliation path once grants
(the desired state) drop the deactivated user.
"""

from __future__ import annotations

import logging
from typing import List

from sqlalchemy.orm import Session

from ..db.access_models import SessionLock
from ..db.models import RefreshToken, Role, User
from . import access_binding_service, session_lock_service

logger = logging.getLogger(__name__)

# Marker reason for the auto-lock created on deactivation, so reactivation can
# release exactly those locks without disturbing operator-created ones.
DEACTIVATION_LOCK_REASON = "account deactivated"


def apply_role_assignment(db: Session, user: User, roles: List[Role]) -> User:
    """Set ``user``'s application roles and atomically recompute grants.

    The single identity-access path shared by the admin role-update endpoint and
    OIDC role sync. Grants are recomputed through the PRA-289 atomic path, which
    commits on success and rolls back + raises on failure — so a recompute failure
    surfaces to the caller instead of silently committing stale authorization.
    """
    user.roles = list(roles)
    # Flush the user_role association change so recompute's queries observe it —
    # we do not depend on relationship/after_commit hooks to notice it.
    db.flush()
    # PRA-285: recompute is the common revocation choke point; role removal that
    # narrows access enqueues reconcile work through it. Reason carried for audit.
    access_binding_service.recompute_grants(
        db, reason="role_change", source=f"user:{user.id}"
    )
    return user


def invalidate_refresh_tokens(db: Session, user_id: int) -> int:
    """Mark every still-valid refresh token for ``user_id`` invalid. Not committed
    here — the caller commits it as one unit with the rest of the change."""
    return (
        db.query(RefreshToken)
        .filter(RefreshToken.user_id == user_id, RefreshToken.is_valid.is_(True))
        .update({RefreshToken.is_valid: False}, synchronize_session=False)
    )


def deactivate_user(db: Session, user: User, *, actor: User) -> User:
    """Deactivate ``user`` through the explicit path, fail-closed and ordered so a
    later failure only ever leaves access MORE restricted:

    1. ``is_active = False`` — denies new login / current-user / refresh.
    2. invalidate all refresh tokens — no successor access can be minted.
    3. atomic recompute — the now-inactive user's grants (and host desired state)
       drop out.
    4. session-impact hook — ``session_lock_service.create_lock`` force-closes live
       sessions and denies new ones (``authorize_action`` honors the lock).

    Steps 1-3 commit together (inside recompute); step 4 commits the lock. Any
    failure raises to the caller.
    """
    user.is_active = False
    invalidate_refresh_tokens(db, user.id)
    db.flush()
    # PRA-285: recompute drops the now-inactive user's grants and enqueues host
    # reconcile work through the common revocation outbox.
    access_binding_service.recompute_grants(
        db, reason="user_deactivation", source=f"user:{user.id}"
    )
    # Session impact: create_lock force-closes live sessions AND enqueues a
    # user-scoped session sweep through the common revocation service (PRA-285).
    session_lock_service.create_lock(
        db,
        creator=actor,
        reason=DEACTIVATION_LOCK_REASON,
        subject_user_id=user.id,
    )
    return user


def activate_user(db: Session, user: User, *, actor: User) -> User:
    """Reactivate ``user``: restore grants via recompute and release the auto-lock
    created at deactivation (operator-created locks are left untouched)."""
    user.is_active = True
    db.flush()
    access_binding_service.recompute_grants(db)
    _release_deactivation_locks(db, user, actor)
    return user


def set_user_active(db: Session, user: User, *, active: bool, actor: User) -> User:
    """Route a toggle to the appropriate explicit path."""
    if active:
        return activate_user(db, user, actor=actor)
    return deactivate_user(db, user, actor=actor)


def _release_deactivation_locks(db: Session, user: User, actor: User) -> None:
    locks = (
        db.query(SessionLock)
        .filter(
            SessionLock.subject_user_id == user.id,
            SessionLock.released_at.is_(None),
            SessionLock.reason == DEACTIVATION_LOCK_REASON,
        )
        .all()
    )
    for lock in locks:
        session_lock_service.release_lock(db, lock_id=lock.id, releaser=actor)
