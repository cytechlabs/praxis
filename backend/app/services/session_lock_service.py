"""Session locks (PRA-146): emergency subject cut-off.

A SessionLock row, while active (``released_at IS NULL``), denies every
gated action — ``session_open``, ``command_exec``, ``file_transfer`` —
for the locked subject. ``create_lock`` also kills any live sessions
belonging to the subject so revocation takes effect immediately.

Subject is XOR: a lock targets either a single ``User`` or every user
holding a given app-level ``Role``. The DB enforces the XOR with a
CheckConstraint; this service raises ``LockError`` on subject errors so
the API layer can return a clean 400.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session as DbSession

from ..db.access_models import Session as SessionRow
from ..db.access_models import SessionLock
from ..db.models import Role, User
from . import session_runtime as rt_registry
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)


class LockError(ValueError):
    """Bad lock input — subject XOR violated, missing subject, etc."""


# ---------------------------------------------------------------- queries


def is_user_locked(db: DbSession, user: User) -> Optional[SessionLock]:
    """Return the active lock that gates ``user``, or None.

    A user is locked if either (a) a lock targets them directly or
    (b) a lock targets any app-level role they hold.
    """
    role_ids = [r.id for r in (user.roles or [])]
    q = db.query(SessionLock).filter(SessionLock.released_at.is_(None))
    if role_ids:
        from sqlalchemy import or_

        q = q.filter(
            or_(
                SessionLock.subject_user_id == user.id,
                SessionLock.subject_app_role_id.in_(role_ids),
            )
        )
    else:
        q = q.filter(SessionLock.subject_user_id == user.id)
    return q.order_by(SessionLock.id.asc()).first()


def list_locks(db: DbSession, *, active_only: bool = False) -> List[SessionLock]:
    q = db.query(SessionLock)
    if active_only:
        q = q.filter(SessionLock.released_at.is_(None))
    return q.order_by(SessionLock.id.desc()).all()


# ------------------------------------------------------------- mutations


def create_lock(
    db: DbSession,
    *,
    creator: User,
    reason: str,
    subject_user_id: Optional[int] = None,
    subject_app_role_id: Optional[int] = None,
    actor_ip: Optional[str] = None,
) -> SessionLock:
    """Create a lock and immediately close every matching live session."""
    if not reason or not reason.strip():
        raise LockError("reason is required")
    if (subject_user_id is None) == (subject_app_role_id is None):
        raise LockError(
            "exactly one of subject_user_id / subject_app_role_id must be set"
        )

    if subject_user_id is not None:
        subject_user = db.query(User).filter(User.id == subject_user_id).first()
        if subject_user is None:
            raise LockError(f"user {subject_user_id} not found")
    else:
        subject_role = db.query(Role).filter(Role.id == subject_app_role_id).first()
        if subject_role is None:
            raise LockError(f"role {subject_app_role_id} not found")

    lock = SessionLock(
        subject_user_id=subject_user_id,
        subject_app_role_id=subject_app_role_id,
        reason=reason.strip(),
        created_by=creator.id,
        created_at=datetime.utcnow(),
    )
    db.add(lock)
    db.commit()
    db.refresh(lock)

    killed = _close_live_sessions_for_subject(
        db,
        subject_user_id=subject_user_id,
        subject_app_role_id=subject_app_role_id,
        lock_id=lock.id,
    )

    # PRA-285: route the session impact through the common revocation service so a
    # live session opened in ANOTHER worker (DB-only here) is swept by the guarded
    # drain. Belt-and-suspenders over the immediate close above; never blocks the
    # lock. Role-subject locks enqueue a user-scoped sweep for EACH current member,
    # so cross-worker sessions for those users also enter the common queued path.
    if subject_user_id is not None:
        sweep_user_ids = [subject_user_id]
    else:
        sweep_user_ids = [
            u.id
            for u in db.query(User)
            .join(User.roles)
            .filter(Role.id == subject_app_role_id)
            .all()
        ]
    if sweep_user_ids:
        try:
            from . import revocation_service

            for uid in sweep_user_ids:
                revocation_service.enqueue_session_sweep(
                    db,
                    user_id=uid,
                    reason="session_lock",
                    source=f"lock:{lock.id}",
                )
            db.commit()
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("revocation session-sweep enqueue failed: %s", exc)

    safe_emit(
        db=db,
        action="lock.create",
        actor_user_id=creator.id,
        actor_username=creator.username,
        actor_ip=actor_ip,
        target_kind="session_lock",
        target_id=str(lock.id),
        context={
            "subject_user_id": subject_user_id,
            "subject_app_role_id": subject_app_role_id,
            "reason": lock.reason,
            "killed_session_ids": killed,
        },
    )
    logger.info(
        "session lock %d created by %s (subject_user=%s subject_role=%s, killed=%d)",
        lock.id,
        creator.username,
        subject_user_id,
        subject_app_role_id,
        len(killed),
    )
    return lock


def release_lock(
    db: DbSession,
    *,
    lock_id: int,
    releaser: User,
    actor_ip: Optional[str] = None,
) -> SessionLock:
    lock = db.query(SessionLock).filter(SessionLock.id == lock_id).first()
    if lock is None:
        raise LockError(f"lock {lock_id} not found")
    if lock.released_at is not None:
        raise LockError(f"lock {lock_id} already released")
    lock.released_at = datetime.utcnow()
    lock.released_by = releaser.id
    db.commit()
    db.refresh(lock)

    safe_emit(
        db=db,
        action="lock.release",
        actor_user_id=releaser.id,
        actor_username=releaser.username,
        actor_ip=actor_ip,
        target_kind="session_lock",
        target_id=str(lock.id),
        context={
            "subject_user_id": lock.subject_user_id,
            "subject_app_role_id": lock.subject_app_role_id,
        },
    )
    return lock


# ----------------------------------------------------------- internals


def _close_live_sessions_for_subject(
    db: DbSession,
    *,
    subject_user_id: Optional[int],
    subject_app_role_id: Optional[int],
    lock_id: int,
) -> List[int]:
    """Force-close every active session belonging to the locked subject.

    Returns the list of session ids that were closed. Imports
    ``session_service`` lazily to avoid circular import (it imports
    ``audit_event_service`` which is part of the same M11/M12 spine).
    """
    from . import session_service

    if subject_user_id is not None:
        target_user_ids = {subject_user_id}
    else:
        users = (
            db.query(User).join(User.roles).filter(Role.id == subject_app_role_id).all()
        )
        target_user_ids = {u.id for u in users}

    if not target_user_ids:
        return []

    rows = (
        db.query(SessionRow)
        .filter(
            SessionRow.user_id.in_(target_user_ids),
            SessionRow.status.in_(("opening", "active")),
        )
        .all()
    )
    closed: List[int] = []
    for row in rows:
        try:
            session_service.close_session(db, row.id, reason="locked")
            closed.append(row.id)
            safe_emit(
                db=db,
                action="session.locked_close",
                actor_user_id=None,
                target_system_id=row.system_id,
                target_kind="session",
                target_id=str(row.id),
                context={
                    "lock_id": lock_id,
                    "subject_user_id": row.user_id,
                    "login": row.login,
                },
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.warning(
                "lock %d: failed to close session %d: %s", lock_id, row.id, e
            )

    # Defensive sweep of the in-process registry — covers sessions whose
    # paramiko channel is alive but whose DB row drifted out of "active".
    for rt in rt_registry.list_active():
        sess = db.query(SessionRow).filter(SessionRow.id == rt.session_id).first()
        if (
            sess is not None
            and sess.user_id in target_user_ids
            and not rt.closed.is_set()
        ):
            rt.close(reason="locked")

    return closed
