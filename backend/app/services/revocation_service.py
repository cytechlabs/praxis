"""Common access-revocation orchestration (PRA-285).

One shared path for every revocation trigger. It does NOT decide policy — grant
state (materialized by ``access_binding_service.recompute_grants``, filtered by
PRA-284 expiry) is the authority. This service is the plumbing that, once access
has narrowed:

1. persists reconcile work in the SAME transaction as the grant change (outbox:
   if narrowed grants commit, matching work exists), so pending host cleanup
   survives a restart;
2. best-effort closes reachable in-process sessions immediately (valid under the
   supported single-worker topology — see the 1.0 revocation SLA in
   ``docs/access-revocation.md``; this becomes dispatched termination if the
   backend scales out);
3. lets the guarded scheduler drain close DB-only/cross-worker sessions and
   reconcile hosts, retrying boundedly and surfacing pending/error state.

Design guardrails (locked):

- New-auth denial is the hard, synchronous boundary; a failed session-close or
  reconcile NEVER rolls access back on. Failures become retry/visible state.
- A work row is a SIGNAL to reconverge a ``(user, system, login)`` scope, NOT a
  stored "remove login X" imperative. The drain re-derives current desired state
  via ``reconcile_system`` at execution time, so access restored before the drain
  runs is preserved.
- Offline/unreachable hosts stay visibly pending/error and are retried — never a
  reason to preserve access.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..db.access_models import AccessBinding, AccessGrant, RevocationWork
from ..db.access_models import Session as SessionRow
from ..db.models import System
from .audit_event_service import safe_emit

logger = logging.getLogger(__name__)

# Bounded retry backoff (seconds) by attempt count; caps so an unreachable host
# retries indefinitely but not hot.
_RETRY_BACKOFF_S = [30, 60, 300, 900, 1800, 3600]
_DRAIN_LIMIT = 200

# PRA-342: an unmanaged-account ownership conflict (PRA-286) is terminal until an
# operator acts or an access change re-enqueues the work. It stays VISIBLE
# (status="manual" — manual intervention — with last_error set) but on a
# deliberately long backoff so it never hot-retries SSH every 30s and piles
# sessions on the host. The value fits the status column's 16-char width.
_MANUAL_STATUS = "manual"
_MANUAL_BACKOFF_S = 4 * 3600  # 4h

# (user_id, system_id, login) tuples that lost active access.
GrantKey = Tuple[Optional[int], Optional[int], Optional[str]]


# ------------------------------------------------------------- enqueue (outbox)


def _match(query, column, value):
    return query.filter(column.is_(None) if value is None else column == value)


def enqueue(
    db: Session,
    *,
    reason: str,
    user_id: Optional[int],
    system_id: Optional[int],
    login: Optional[str],
    source: Optional[str] = None,
    now: Optional[datetime] = None,
) -> RevocationWork:
    """Idempotent upsert of one outstanding work row for a scope.

    Does NOT commit — callers enqueue inside the transaction that narrows grants
    (outbox). Repeated triggers for the same outstanding ``(user, system, login)``
    re-arm the existing row (reason/source refreshed, back to ``pending``) instead
    of creating unbounded duplicates.
    """
    now = now or datetime.utcnow()
    # Flush pending inserts so the existence check sees rows enqueued earlier in
    # THIS (uncommitted) transaction — the session runs autoflush=False.
    db.flush()
    q = db.query(RevocationWork).filter(RevocationWork.status != "completed")
    q = _match(q, RevocationWork.user_id, user_id)
    q = _match(q, RevocationWork.system_id, system_id)
    q = _match(q, RevocationWork.login, login)
    existing = q.first()
    if existing is not None:
        existing.reason = reason
        existing.source = source
        existing.status = "pending"
        existing.next_retry_at = None
        existing.last_error = None
        existing.updated_at = now
        return existing
    row = RevocationWork(
        reason=reason,
        source=source,
        user_id=user_id,
        system_id=system_id,
        login=login,
        status="pending",
        attempt_count=0,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    return row


def enqueue_grant_removals(
    db: Session,
    removed: Iterable[GrantKey],
    *,
    reason: str = "grant_recompute",
    source: Optional[str] = None,
    now: Optional[datetime] = None,
) -> int:
    """Enqueue one reconcile signal per removed ``(user, system, login)`` — in the
    caller's (uncommitted) transaction. Returns the number of scopes enqueued."""
    now = now or datetime.utcnow()
    n = 0
    for user_id, system_id, login in removed:
        if system_id is None:
            continue
        enqueue(
            db,
            reason=reason,
            user_id=user_id,
            system_id=system_id,
            login=login,
            source=source,
            now=now,
        )
        n += 1
    return n


def enqueue_session_sweep(
    db: Session,
    *,
    user_id: int,
    reason: str,
    source: Optional[str] = None,
    now: Optional[datetime] = None,
) -> RevocationWork:
    """User-scoped work (``system_id`` NULL): close the user's remaining live
    sessions via the drain, no host reconcile. For emergency/session lock, whose
    live-session close should also cover other workers."""
    return enqueue(
        db,
        reason=reason,
        user_id=user_id,
        system_id=None,
        login=None,
        source=source,
        now=now,
    )


# ------------------------------------------------- synchronous session close


def close_sessions_for_removed(
    db: Session, removed: Iterable[GrantKey], *, reason: str = "revoked"
) -> List[int]:
    """Best-effort immediate close of reachable in-process sessions for scopes that
    lost access. Called AFTER the grant change commits. Re-derives at the exact
    ``(user, system, login)`` granularity so a still-valid login on the same system
    is left alone. Failures are logged and left to the drain — they never roll
    access back on."""
    from . import session_service
    from .access_authorization_service import applicable_grants

    closed: List[int] = []
    for user_id, system_id, login in removed:
        if user_id is None or system_id is None:
            continue
        q = db.query(SessionRow).filter(
            SessionRow.user_id == user_id,
            SessionRow.system_id == system_id,
            SessionRow.status.in_(("opening", "active")),
        )
        if login is not None:
            q = q.filter(SessionRow.login == login)
        for row in q.all():
            # Re-derive: skip a session whose exact login is still authorized.
            if applicable_grants(db, row.user_id, row.system_id, login=row.login):
                continue
            try:
                session_service.close_session(db, row.id, reason=reason)
                closed.append(row.id)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(
                    "revocation: immediate close of session %d failed (drain will "
                    "retry): %s",
                    row.id,
                    exc,
                )
    return closed


def _close_work_sessions(db: Session, item: RevocationWork, *, reason: str) -> int:
    """Close the DB sessions a work item covers, RE-DERIVING at the exact
    ``(user, system, login)`` granularity so restored access is not torn down and a
    still-valid login on the same system is left alone.

    - System-scoped grant-removal work (``system_id`` set, and ``login`` set when
      known): close only sessions on the revoked login that are no longer
      authorized. Losing ``login=A`` must not close a still-valid ``login=B``
      session on the same system.
    - User-scoped work (``system_id`` NULL, e.g. a session lock) closes all of the
      user's live sessions unconditionally — the lock is the cutoff and
      ``authorize_action`` already denies via ``is_user_locked``.
    """
    from . import session_service
    from .access_authorization_service import applicable_grants

    q = db.query(SessionRow).filter(SessionRow.status.in_(("opening", "active")))
    if item.user_id is not None:
        q = q.filter(SessionRow.user_id == item.user_id)
    if item.system_id is not None:
        q = q.filter(SessionRow.system_id == item.system_id)
    # A login-scoped grant-removal item only touches sessions on that exact login.
    if item.system_id is not None and item.login is not None:
        q = q.filter(SessionRow.login == item.login)

    closed = 0
    for row in q.all():
        if item.system_id is not None:
            # Re-derive per (user, system, login): if that exact login still has an
            # active grant, leave the session alone.
            still = applicable_grants(db, row.user_id, row.system_id, login=row.login)
            if still:
                continue
        session_service.close_session(db, row.id, reason=reason)
        closed += 1
    return closed


# --------------------------------------------------------------- drain (guarded)


def _backoff(attempt: int) -> int:
    idx = min(max(attempt - 1, 0), len(_RETRY_BACKOFF_S) - 1)
    return _RETRY_BACKOFF_S[idx]


def _finalize(
    item: RevocationWork,
    now: datetime,
    *,
    status: str,
    last_error: Optional[str],
    next_retry_at: Optional[datetime],
) -> None:
    """Set a work item's terminal/retry fields (caller commits + emits)."""
    item.status = status
    item.last_error = last_error
    item.next_retry_at = next_retry_at
    item.updated_at = now
    if status == "completed":
        item.completed_at = now


def _emit_result(item: RevocationWork) -> None:
    safe_emit(
        action="revocation.reconcile",
        outcome="success" if item.status == "completed" else "failure",
        target_kind="revocation_work",
        target_id=str(item.id),
        context={
            "reason": item.reason,
            "user_id": item.user_id,
            "system_id": item.system_id,
            "login": item.login,
            "status": item.status,
            "attempt": item.attempt_count,
        },
    )


def _process_db_only_item(db: Session, item: RevocationWork, now: datetime) -> None:
    """A session-only work item (no system_id): close DB sessions, no SSH."""
    item.attempt_count += 1
    try:
        _close_work_sessions(db, item, reason="revoked")
        _finalize(item, now, status="completed", last_error=None, next_retry_at=None)
    except Exception as exc:  # pylint: disable=broad-except
        _finalize(
            item,
            now,
            status="error",
            last_error=str(exc)[:2000],
            next_retry_at=now + timedelta(seconds=_backoff(item.attempt_count)),
        )
        logger.warning("revocation work %d (session-only) failed: %s", item.id, exc)
    db.commit()
    _emit_result(item)


def _process_host(
    db: Session, system_id: int, items: List[RevocationWork], now: datetime
) -> None:
    """Reconcile ONE host ONCE per tick and apply the outcome to ALL its due
    revocation-work items.

    PRA-342: previously each item called ``reconcile_system`` independently, so N
    due rows for one failing host opened N SSH sessions per 30s tick. Coalescing
    bounds that to a single reconcile (≈1 SSH) per host per tick, and:
      - hosts in transport cooldown (PRA-313) are skipped with NO SSH — items stay
        pending for a later tick;
      - unmanaged-account ownership conflicts get a deliberately long backoff
        (manual_intervention) instead of hot-retrying every 30s.
    """
    from . import fleet_reconciliation_service as frs
    from .ssh_service import is_host_cooling_down

    system = db.query(System).filter(System.id == system_id).first()
    if system is not None and is_host_cooling_down(db, system, now=now) is not None:
        logger.info(
            "revocation drain: system %d in transport cooldown — skipping %d "
            "item(s), no SSH this tick (PRA-313)",
            system_id,
            len(items),
        )
        return  # leave items pending; re-picked once the host stops cooling down

    for it in items:
        it.attempt_count += 1
        it.updated_at = now
        _close_work_sessions(db, it, reason="revoked")

    err_msg: Optional[str] = None
    manual = False
    try:
        res = frs.reconcile_system(db, system_id)
        errors = res.get("errors", 0)
        if errors > 0:
            # All errors ownership => manual intervention (long backoff). A mix
            # with transient errors keeps the normal (retryable) backoff.
            manual = res.get("manual_intervention", 0) >= errors
            detail = (
                "manual intervention required: unmanaged-account ownership conflict"
                if manual
                else "host unreachable / cleanup failed"
            )
            err_msg = (
                f"reconcile reported {errors} error(s) on system {system_id} "
                f"({detail})"
            )
    except Exception as exc:  # pylint: disable=broad-except
        err_msg = str(exc)[:2000]

    for it in items:
        if err_msg is None:
            _finalize(it, now, status="completed", last_error=None, next_retry_at=None)
        elif manual:
            _finalize(
                it,
                now,
                status=_MANUAL_STATUS,
                last_error=err_msg,
                next_retry_at=now + timedelta(seconds=_MANUAL_BACKOFF_S),
            )
            logger.warning(
                "revocation work %d -> manual_intervention: long backoff %ds "
                "(no hot retry until operator action/state change): %s",
                it.id,
                _MANUAL_BACKOFF_S,
                err_msg,
            )
        else:
            backoff = _backoff(it.attempt_count)
            _finalize(
                it,
                now,
                status="error",
                last_error=err_msg,
                next_retry_at=now + timedelta(seconds=backoff),
            )
            logger.warning(
                "revocation work %d failed (attempt %d): retry in %ds: %s",
                it.id,
                it.attempt_count,
                backoff,
                err_msg,
            )
    db.commit()
    for it in items:
        _emit_result(it)


def drain(
    db: Session, *, limit: int = _DRAIN_LIMIT, now: Optional[datetime] = None
) -> int:
    """Process due revocation work: close DB-only sessions, reconcile hosts, retry
    on failure with visible pending/error/manual_intervention state. Also sweeps
    time-based expiry and folds the PRA-282 privilege-baseline reconcile queue
    through the same path. Returns the number of work items processed. Runs under
    the guarded scheduler tick (one worker per interval).

    PRA-342: due items are COALESCED by host so multiple rows for one host produce
    a single reconcile (≈1 SSH) per tick rather than one SSH per row.
    """
    now = now or datetime.utcnow()
    sweep_expiry(db, now=now)

    items = (
        db.query(RevocationWork)
        .filter(RevocationWork.status.in_(("pending", "error", _MANUAL_STATUS)))
        .filter(
            or_(
                RevocationWork.next_retry_at.is_(None),
                RevocationWork.next_retry_at <= now,
            )
        )
        .order_by(RevocationWork.id.asc())
        .limit(limit)
        .all()
    )

    host_items: Dict[int, List[RevocationWork]] = {}
    for item in items:
        if item.system_id is None:
            _process_db_only_item(db, item, now)
        else:
            host_items.setdefault(item.system_id, []).append(item)

    for system_id, group in host_items.items():
        _process_host(db, system_id, group, now)

    # PRA-282 privilege-baseline sudoers cleanup drains through the same scheduled
    # path rather than a bespoke sweep.
    try:
        from . import fleet_reconciliation_service as frs

        frs.reconcile_pending_privilege(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("privilege-baseline reconcile drain failed: %s", exc)

    return len(items)


# --------------------------------------------------------------- expiry sweep


def sweep_expiry(db: Session, *, now: Optional[datetime] = None) -> bool:
    """Realize time-based expiry (JIT + binding). PRA-284 already denies expired
    grants synchronously; this drops the stale grant ROWS and enqueues host
    reconcile. Bounded: recompute only when an expired binding still has a
    materialized grant, so it converges (afterwards there is nothing to drop).
    Returns True if a recompute was triggered."""
    now = now or datetime.utcnow()
    try:
        from . import access_request_service

        access_request_service.expire_past_due(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("JIT expire_past_due failed: %s", exc)

    stale = (
        db.query(AccessGrant.id)
        .join(AccessBinding, AccessGrant.via_binding_id == AccessBinding.id)
        .filter(AccessBinding.expires_at.isnot(None), AccessBinding.expires_at <= now)
        .first()
    )
    if stale is None:
        return False
    from . import access_binding_service

    access_binding_service.recompute_grants(db, reason="jit_expiry", source="scheduler")
    return True


# --------------------------------------------------------------- status (ops)


def revocation_status(db: Session) -> Dict[str, object]:
    """Operator-facing summary: pending/error/manual/completed counts + per-host
    detail for the systems still unreconciled, so operators know what remains."""
    active_statuses = ("pending", "error", _MANUAL_STATUS)
    counts = {
        status: db.query(RevocationWork).filter(RevocationWork.status == status).count()
        for status in (*active_statuses, "completed")
    }
    outstanding = (
        db.query(RevocationWork)
        .filter(RevocationWork.status.in_(active_statuses))
        .order_by(RevocationWork.system_id.asc(), RevocationWork.id.asc())
        .all()
    )
    items = [
        {
            "id": w.id,
            "reason": w.reason,
            "user_id": w.user_id,
            "system_id": w.system_id,
            "login": w.login,
            "status": w.status,
            "attempt_count": w.attempt_count,
            "last_error": w.last_error,
            "next_retry_at": (
                w.next_retry_at.isoformat() + "Z" if w.next_retry_at else None
            ),
        }
        for w in outstanding
    ]
    return {
        "counts": counts,
        "outstanding": items,
        "pending_systems": sorted(
            {w.system_id for w in outstanding if w.system_id is not None}
        ),
    }
