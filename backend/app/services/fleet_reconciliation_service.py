"""Fleet access reconciliation service (PRA-137).

Converges target host state to match the ``access_grants`` table produced by
``access_binding_service.recompute_grants``. Grants are the source of truth;
this module is the plumber.

Two public entrypoints:
    * ``reconcile_system(db, system_id)`` — sync reconcile of one host.
    * ``reconcile_all(max_workers=8)`` — parallel reconcile of every active
      host using ThreadPoolExecutor, each worker with its own Session.

Overlap policy (per-user mode only): when a single Praxis user has multiple
fleet roles on the same host (e.g. both ``admin`` and ``maintainer`` via two
bindings), the Linux account is provisioned from the role with the lowest
fleet_role_id — ``admin`` (id=1) by seed order — which deterministically fixes
the account's login mode and (non-privileged) group set. As of PRA-282 no
built-in fleet role carries standing sudo, so the overlap winner no longer
changes what the user can escalate to; it only fixes login/mode/groups.

PRA-282 privilege baseline: reconciliation is also the path that removes any
legacy ``/etc/sudoers.d/praxis-<login>`` drop-in left on hosts by pre-1.0
deployments. The migration flags affected accounts
(``host_user_states.privilege_reconcile_pending``); ``reconcile_pending_privilege``
drains that queue and ``privilege_reconcile_status`` reports what is still
outstanding.

Grant recompute vs. reconcile: ``recompute_grants`` runs automatically on
binding/membership changes (access_binding_service hooks). ``reconcile_*``
has network side effects and runs only on operator trigger or nightly
schedule. Operators can review pending state in the UI before pushing.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.access_models import FleetRole, HostUserState
from ..db.models import System
from ..db.session import SessionLocal
from . import access_authorization_service as authz
from .host_user_provisioning_service import ensure_user, remove_user

logger = logging.getLogger(__name__)

# PRA-313: bound how many hosts one privilege-reconcile drain touches so a large
# backlog (or a handful of timing-out hosts) can't monopolize a scheduler tick.
_PRIVILEGE_RECONCILE_LIMIT = 50


def _desired_logins(db: Session, system_id: int) -> Dict[str, FleetRole]:
    """Logins that SHOULD exist on ``system_id``, keyed by login name.

    PRA-289: overlap is resolved by the SAME deterministic, primary-key-independent
    policy authorization uses (``access_authorization_service.role_sort_key`` via
    ``resolve_desired_login_roles``) — not by ``fleet_role_id`` order. Authorization
    and reconciliation therefore agree on which role shapes a given login's account.
    """
    return authz.resolve_desired_login_roles(db, system_id)


def _actual_states(db: Session, system_id: int) -> Dict[str, HostUserState]:
    rows = db.query(HostUserState).filter(HostUserState.system_id == system_id).all()
    return {s.login: s for s in rows}


# PRA-342: an unmanaged-account ownership refusal (PRA-286) is a TERMINAL,
# operator-action-required state — not a transient SSH failure. reconcile_system
# counts it in `manual_intervention` (a subset of `errors`) so the revocation
# drain can give it a deliberately long backoff instead of hot-retrying every
# 30s and piling SSH sessions on the host.
_OWNERSHIP_ERROR_MARKER = "PRAXIS_OWNERSHIP_ERROR"


def _is_manual_intervention(last_error: Optional[str]) -> bool:
    """True when a host-state error is an unmanaged-account ownership conflict."""
    return bool(last_error) and _OWNERSHIP_ERROR_MARKER in last_error


def reconcile_system(db: Session, system_id: int) -> Dict[str, int]:
    """Converge one host. Returns counts of provisioned/removed/errors/conflicts.

    ``manual_intervention`` (a subset of ``errors``) counts unmanaged-account
    ownership conflicts that require operator action (PRA-342)."""
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        logger.warning("reconcile_system: no system %d", system_id)
        return {
            "provisioned": 0,
            "removed": 0,
            "errors": 0,
            "skipped": 0,
            "conflicts": 0,
            "manual_intervention": 0,
        }

    # PRA-287: the SAME resolver authorization uses. Compatible logins get a single
    # desired role; incompatible shared logins resolve to a conflict and must NOT be
    # converged — reconciliation neither provisions an arbitrary winner nor (below)
    # destructively removes existing host state merely because a conflict exists.
    resolutions = authz.resolve_login_roles(db, system_id)
    desired = {
        login: res.role for login, res in resolutions.items() if res.role is not None
    }
    conflicted = {login for login, res in resolutions.items() if res.is_conflict}
    actual = _actual_states(db, system_id)

    counts = {
        "provisioned": 0,
        "removed": 0,
        "errors": 0,
        "skipped": 0,
        "conflicts": len(conflicted),
        "manual_intervention": 0,
    }
    for login in sorted(conflicted):
        logger.warning(
            "reconcile_system: system %d login %r is CONFLICTED (%s) — not "
            "provisioning or removing; operator must fix bindings (PRA-287)",
            system_id,
            login,
            resolutions[login].conflict["differing_fields"],
        )

    # Ensure every desired login (idempotent — rewrites principals even if
    # account already exists, so role-account principal lists stay in sync)
    for login, role in desired.items():
        try:
            state = ensure_user(db, system, login, role)
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "reconcile_system: ensure_user(%s, %s) raised: %s",
                system.hostname,
                login,
                e,
            )
            counts["errors"] += 1
            continue
        if state.state == "error":
            counts["errors"] += 1
            if _is_manual_intervention(state.last_error):
                counts["manual_intervention"] += 1
                logger.warning(
                    "reconcile_system: system %d login %r needs MANUAL INTERVENTION "
                    "(unmanaged-account ownership conflict) — long backoff, no hot "
                    "retry (PRA-342)",
                    system_id,
                    login,
                )
        else:
            counts["provisioned"] += 1

    # Remove logins that exist in our ledger but are no longer desired
    for login, state in actual.items():
        if login in desired:
            continue
        if login in conflicted:
            # PRA-287: a conflict is not a signal to revoke — leave last-known-good
            # host state intact and surface the conflict; deliberate revocation
            # routes through the PRA-285 machinery, not this convergence loop.
            continue
        if state.state == "removed":
            counts["skipped"] += 1
            continue
        try:
            new_state = remove_user(db, system, login, state.mode)
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "reconcile_system: remove_user(%s, %s) raised: %s",
                system.hostname,
                login,
                e,
            )
            counts["errors"] += 1
            continue
        if new_state.state == "error":
            counts["errors"] += 1
            if _is_manual_intervention(new_state.last_error):
                counts["manual_intervention"] += 1
                logger.warning(
                    "reconcile_system: system %d login %r removal needs MANUAL "
                    "INTERVENTION (unmanaged-account ownership conflict) — long "
                    "backoff (PRA-342)",
                    system_id,
                    login,
                )
        else:
            counts["removed"] += 1

    return counts


def _reconcile_one_in_worker(system_id: int) -> Dict[str, int]:
    """Worker entrypoint: fresh SessionLocal per thread (PRA-86 pattern)."""
    db = SessionLocal()
    try:
        return reconcile_system(db, system_id)
    except Exception as e:  # pylint: disable=broad-except
        logger.error("worker reconcile of system %d failed: %s", system_id, e)
        return {
            "provisioned": 0,
            "removed": 0,
            "errors": 1,
            "skipped": 0,
            "conflicts": 0,
            "manual_intervention": 0,
        }
    finally:
        db.close()


def reconcile_all(max_workers: int = 8) -> Dict[str, int]:
    """Reconcile every Active system in parallel. Returns aggregate counts."""
    db = SessionLocal()
    try:
        system_ids: List[int] = [
            row[0]
            for row in db.query(System.id).filter(System.status == "Active").all()
        ]
    finally:
        db.close()

    totals = {
        "provisioned": 0,
        "removed": 0,
        "errors": 0,
        "skipped": 0,
        "conflicts": 0,
        "hosts": 0,
    }
    if not system_ids:
        return totals

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_reconcile_one_in_worker, sid): sid for sid in system_ids}
        for fut in as_completed(futures):
            res = fut.result()
            totals["provisioned"] += res["provisioned"]
            totals["removed"] += res["removed"]
            totals["errors"] += res["errors"]
            totals["skipped"] += res["skipped"]
            totals["conflicts"] += res.get("conflicts", 0)
            totals["hosts"] += 1
    logger.info("reconcile_all: %s", totals)
    return totals


# --------------------------------------------------------------------------- #
# PRA-282: privilege-baseline reconcile queue                                  #
#                                                                              #
# The 1.0 migration clears fleet-role sudoers from the DB and flags every live #
# host account (``privilege_reconcile_pending``) so reconciliation removes the #
# on-host drop-in. These helpers give operators visibility into what is still  #
# outstanding and a bounded interim drain until the PRA-285 reconcile          #
# scheduler subsumes the queue.                                                #
# --------------------------------------------------------------------------- #


def count_pending_privilege_reconcile(db: Session) -> int:
    """Host accounts still flagged for PRA-282 sudoers drop-in removal."""
    return (
        db.query(HostUserState)
        .filter(HostUserState.privilege_reconcile_pending.is_(True))
        .count()
    )


def privilege_reconcile_status(db: Session) -> Dict[str, object]:
    """Operator-facing summary of PRA-282 privilege-reconcile progress.

    Lists the systems/accounts still carrying a (possibly stale) fleet-role
    sudoers drop-in that reconciliation has not yet removed, so an upgrade notice
    can report hosts pending cleanup. Systems whose last reconcile errored are
    flagged ``errored`` so they surface as visibly unreconciled/noncompliant.
    Returns counts + per-system logins only — never sudoers text.
    """
    rows = (
        db.query(HostUserState)
        .filter(HostUserState.privilege_reconcile_pending.is_(True))
        .all()
    )
    systems: Dict[int, Dict[str, object]] = {}
    for r in rows:
        entry = systems.setdefault(
            r.system_id,
            {"system_id": r.system_id, "pending_logins": [], "errored": False},
        )
        entry["pending_logins"].append(r.login)  # type: ignore[attr-defined]
        if r.state == "error":
            entry["errored"] = True
    return {
        "pending_accounts": len(rows),
        "pending_systems": len(systems),
        "systems": sorted(systems.values(), key=lambda s: s["system_id"]),
    }


def reconcile_pending_privilege(
    db: Session,
    *,
    limit: int = _PRIVILEGE_RECONCILE_LIMIT,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Bounded interim drain of the PRA-282 privilege-reconcile queue.

    Reconciles the systems that still have at least one host account flagged
    ``privilege_reconcile_pending``. A successful reconcile removes the on-host
    sudoers drop-in and clears the marker; an unreachable host stays flagged and
    ``error`` (visibly pending) for the next run — cleanup is never silently
    dropped. This is the interim path the PRA-285 reconcile scheduler will subsume;
    until then an operator or nightly job calls it. Runs serially on the caller's
    session.

    PRA-313 boundedness — so one down host (or a big backlog) can't monopolize the
    scheduler tick:

    - Hosts currently in transport cooldown are SKIPPED without opening a socket.
      They stay flagged pending (fail-closed — cleanup is never marked complete on
      a host we didn't actually reconcile) and are retried once the cooldown
      elapses.
    - At most ``limit`` eligible hosts are processed per call; the rest remain
      pending for the next tick. ``still_pending`` / ``skipped_cooldown`` /
      ``truncated`` make the bounded behavior observable.
    """
    now = now or datetime.utcnow()
    # Import here (not at module load) to avoid a cross-service import cycle.
    from .ssh_service import is_host_cooling_down

    pending_ids: List[int] = [
        row[0]
        for row in db.query(HostUserState.system_id)
        .filter(HostUserState.privilege_reconcile_pending.is_(True))
        .distinct()
        .all()
    ]

    eligible: List[int] = []
    skipped_cooldown = 0
    for sid in pending_ids:
        system = db.query(System).filter(System.id == sid).first()
        if system is not None and (
            is_host_cooling_down(db, system, now=now) is not None
        ):
            skipped_cooldown += 1
            continue
        eligible.append(sid)

    truncated = len(eligible) > limit
    to_process = eligible[:limit]

    totals = {"provisioned": 0, "removed": 0, "errors": 0, "skipped": 0, "hosts": 0}
    for sid in to_process:
        res = reconcile_system(db, sid)
        for key in ("provisioned", "removed", "errors", "skipped"):
            totals[key] += res[key]
        totals["hosts"] += 1
    totals["still_pending"] = count_pending_privilege_reconcile(db)
    totals["skipped_cooldown"] = skipped_cooldown
    totals["truncated"] = int(truncated)
    if skipped_cooldown or truncated:
        logger.info(
            "privilege reconcile bounded: processed %d host(s), skipped_cooldown %d, "
            "truncated %s, still_pending %d",
            totals["hosts"],
            skipped_cooldown,
            truncated,
            totals["still_pending"],
        )
    return totals
