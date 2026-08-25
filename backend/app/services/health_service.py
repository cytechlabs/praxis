"""
Fleet health service - PRA-112, PRA-103.

Provides connectivity health checks and fleet dashboard aggregation.
"""

import logging
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import false, func
from sqlalchemy.orm import Session, joinedload

from ..db.models import (
    Distro,
    Group,
    Job,
    JobHistory,
    PackageUpdate,
    System,
    SystemMetadata,
)
from .notification_service import create_notification
from .security_scan_status_service import build_security_posture
from .ssh_service import SSHService, is_host_cooling_down

logger = logging.getLogger(__name__)

# Number of consecutive failures before marking as Unreachable
UNREACHABLE_THRESHOLD = 2

# PRA-323: process-local single-flight for the fleet health SWEEP (check-all).
# Repeated "Check All Systems" clicks (or poller/scheduler overlap) must not launch
# overlapping serial SSH sweeps that pile up on the (single-worker) threadpool. The
# 1.0 topology is a single backend worker, so a process-local lock is sufficient; a
# non-blocking acquire returns an ``already_running`` result instead of queuing.
_fleet_sweep_lock = threading.Lock()


def _scope(query, column, system_ids: Optional[Set[int]]):
    """PRA-281: constrain a fleet-aggregate query to a caller's fleet scope.

    ``system_ids is None`` = tenant-wide (admin), no filter. An explicit set is an
    allow-list; an empty set yields zero rows, so scoped counts/rows never include
    or reveal inaccessible systems.
    """
    if system_ids is None:
        return query
    if not system_ids:
        return query.filter(false())
    return query.filter(column.in_(system_ids))


class HealthService:
    """Service for fleet connectivity health checks and dashboard aggregation."""

    def __init__(self, db: Session):
        self.db = db
        self.ssh_service = SSHService(db)

    def check_system(
        self, system_id: int, *, bypass_cooldown: bool = False
    ) -> Dict[str, Any]:
        """Run a connectivity check on a single system and update health state.

        ``bypass_cooldown`` (PRA-313): an explicit operator recheck ignores the
        transport circuit breaker so a cooling-down host is actually retried (and
        its cooldown cleared on success). Sweep callers leave it False.
        """
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise ValueError(f"System {system_id} not found")

        previous_status = (
            system.system_metadata.connection_status if system.system_metadata else None
        )

        try:
            result = self.ssh_service.test_connection(
                system_id, bypass_cooldown=bypass_cooldown
            )
        except Exception as e:  # pylint: disable=broad-except
            result = {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "failed",
                "message": str(e),
                "response_time_ms": 0,
            }

        # Refresh metadata
        metadata = system.system_metadata
        if not metadata:
            metadata = SystemMetadata(system_id=system.id)
            self.db.add(metadata)

        ok = result.get("status") == "success"
        if ok:
            metadata.consecutive_failures = 0
        else:
            metadata.consecutive_failures = (metadata.consecutive_failures or 0) + 1
            if metadata.consecutive_failures >= UNREACHABLE_THRESHOLD:
                system.status = "Unreachable"
                metadata.connection_status = "unreachable"

        self.db.commit()

        new_status = metadata.connection_status

        # Notification on status transition.
        # PRA-344: recovery (offline -> connected) is now emitted centrally by
        # SSHService._update_system_connection_status, which runs via
        # test_connection() above whenever this check succeeds — so a reconnect
        # alerts no matter which backend path observes it first, and we avoid a
        # duplicate recovery alert here. Health owns only the unreachable
        # transition (the threshold state it sets itself).
        if (
            previous_status
            and new_status == "unreachable"
            and previous_status != new_status
        ):
            self._notify(
                "system_unreachable",
                f"System '{system.hostname}' is unreachable",
                f"{metadata.consecutive_failures} consecutive failed health checks",
                "error",
                system_id=system.id,
            )

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": result.get("status"),
            "connection_status": new_status,
            "consecutive_failures": metadata.consecutive_failures,
            "response_time_ms": result.get("response_time_ms", 0),
            "message": result.get("message", ""),
            "checked_at": datetime.utcnow().isoformat(),
        }

    def check_systems(
        self, system_ids: List[int], *, bypass_cooldown: bool = False
    ) -> Dict[str, Any]:
        """Run connectivity checks on multiple systems.

        ``bypass_cooldown`` (PRA-313) forwards to each check so an explicit
        (forced) sweep retries cooling-down hosts instead of fast-failing them.
        """
        results = []
        ok = 0
        fail = 0
        for sid in system_ids:
            try:
                r = self.check_system(sid, bypass_cooldown=bypass_cooldown)
                results.append(r)
                if r.get("status") == "success":
                    ok += 1
                else:
                    fail += 1
            except ValueError as e:
                results.append(
                    {"system_id": sid, "status": "failed", "message": str(e)}
                )
                fail += 1
        return {
            "total": len(system_ids),
            "ok": ok,
            "failed": fail,
            "results": results,
        }

    def check_all_systems(
        self, scope_system_ids: Optional[Set[int]] = None, *, force: bool = False
    ) -> Dict[str, Any]:
        """Run health checks against every active system in fleet scope.

        PRA-323: single-flight — a fleet sweep already in progress makes a repeated
        "Check All" return ``already_running`` immediately instead of launching an
        overlapping serial SSH sweep.
        """
        if not _fleet_sweep_lock.acquire(blocking=False):
            return {
                "total": 0,
                "ok": 0,
                "failed": 0,
                "results": [],
                "skipped_cooldown": 0,
                "status": "already_running",
                "message": (
                    "A fleet health sweep is already running; wait for it to finish."
                ),
            }
        try:
            return self._check_all_systems_impl(
                scope_system_ids=scope_system_ids, force=force
            )
        finally:
            _fleet_sweep_lock.release()

    def _check_all_systems_impl(
        self, scope_system_ids: Optional[Set[int]] = None, *, force: bool = False
    ) -> Dict[str, Any]:
        """Run health checks against every active system in fleet scope.

        ``scope_system_ids`` (PRA-281): None = tenant-wide (admin); a set restricts
        the target set to the caller's granted systems, so ``check-all`` never
        touches hosts outside the caller's scope.

        PRA-313: by DEFAULT the sweep does NOT open sockets to hosts currently in
        transport cooldown — one bad host can no longer make the whole sweep (and
        the scheduled health check) wait on its SSH timeout. Those hosts are
        reported as ``skipped_cooldown`` and left in their existing state (never
        marked reachable without an actual connection). ``force=True`` (an explicit
        operator recheck) retries every host and bypasses the breaker, clearing the
        cooldown on any that reconnect.
        """
        q = self.db.query(System.id).filter(
            System.status.in_(["Active", "Unreachable"])
        )
        q = _scope(q, System.id, scope_system_ids)
        system_ids = [sid for (sid,) in q.all()]

        if force:
            return self.check_systems(system_ids, bypass_cooldown=True)

        now = datetime.utcnow()
        eligible: List[int] = []
        skipped: List[Dict[str, Any]] = []
        for sid in system_ids:
            system = self.db.query(System).filter(System.id == sid).first()
            if system is not None and (
                is_host_cooling_down(self.db, system, now=now) is not None
            ):
                skipped.append(
                    {
                        "system_id": sid,
                        "hostname": system.hostname,
                        "status": "skipped",
                        "message": "host cooling down (transport circuit open) — "
                        "use force to retry",
                    }
                )
                continue
            eligible.append(sid)

        result = self.check_systems(eligible)
        # Surface skipped hosts so the caller/operator sees they were not hammered
        # (and were not silently marked healthy).
        result["skipped_cooldown"] = len(skipped)
        if skipped:
            result["results"].extend(skipped)
        return result

    def get_fleet_health(self, system_ids: Optional[Set[int]] = None) -> Dict[str, Any]:
        """Summary of fleet connectivity health.

        ``system_ids`` (PRA-281) scopes every count to the caller's fleet scope
        (None = tenant-wide admin), so totals never include inaccessible systems.
        """
        total = _scope(self.db.query(System), System.id, system_ids).count()

        by_connection = (
            _scope(
                self.db.query(
                    SystemMetadata.connection_status,
                    func.count(SystemMetadata.id),
                ),
                SystemMetadata.system_id,
                system_ids,
            )
            .group_by(SystemMetadata.connection_status)
            .all()
        )
        connection_counts = {
            (status or "unknown"): count for status, count in by_connection
        }

        unreachable = _scope(
            self.db.query(System).filter(System.status == "Unreachable"),
            System.id,
            system_ids,
        ).count()

        # Systems never checked
        never_checked = (
            _scope(
                self.db.query(System).outerjoin(
                    SystemMetadata, SystemMetadata.system_id == System.id
                ),
                System.id,
                system_ids,
            )
            .filter(
                (SystemMetadata.last_connection.is_(None))
                | (SystemMetadata.id.is_(None))
            )
            .count()
        )

        # Stale (last checked > 1h ago)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        stale = (
            _scope(
                self.db.query(SystemMetadata),
                SystemMetadata.system_id,
                system_ids,
            )
            .filter(
                SystemMetadata.last_connection.isnot(None),
                SystemMetadata.last_connection < one_hour_ago,
            )
            .count()
        )

        return {
            "total_systems": total,
            "unreachable": unreachable,
            "never_checked": never_checked,
            "stale": stale,
            "connection_counts": connection_counts,
            "checked_at": datetime.utcnow().isoformat(),
        }

    def get_fleet_dashboard(
        self, system_ids: Optional[Set[int]] = None
    ) -> Dict[str, Any]:
        """PRA-103: Aggregate fleet operations dashboard data.

        ``system_ids`` (PRA-281) scopes every system/package aggregate to the
        caller's fleet scope (None = tenant-wide admin), so no count, rollup, or
        attention row includes or reveals inaccessible systems. Job history is not
        system-scoped in this slice (jobs are a separate route family; see the
        PRA-281 inventory doc).
        """
        # Systems by status
        status_counts = dict(
            _scope(
                self.db.query(System.status, func.count(System.id)),
                System.id,
                system_ids,
            )
            .group_by(System.status)
            .all()
        )

        # Systems by group
        group_rows = (
            _scope(
                self.db.query(Group.name, func.count(System.id)).outerjoin(
                    System, System.group_id == Group.id
                ),
                System.id,
                system_ids,
            )
            .group_by(Group.name)
            .all()
        )
        systems_by_group = [
            {"group": name, "count": count} for name, count in group_rows
        ]

        # Systems by distro
        distro_rows = (
            _scope(
                self.db.query(Distro.name, func.count(System.id)).join(
                    System, System.distro_id == Distro.id
                ),
                System.id,
                system_ids,
            )
            .group_by(Distro.name)
            .all()
        )
        systems_by_distro = [
            {"distro": name, "count": count} for name, count in distro_rows
        ]

        # Patch compliance. PRA-277: the dashboard must distinguish the number of
        # SYSTEMS affected from the number of pending package-update ROWS — a
        # fleet can have hundreds of pending updates across only a handful of
        # systems. count(distinct system_id) = systems affected; count(*) =
        # pending package-update rows.
        systems_with_updates = (
            _scope(
                self.db.query(func.count(func.distinct(PackageUpdate.system_id))),
                PackageUpdate.system_id,
                system_ids,
            ).scalar()
            or 0
        )
        # Systems with security updates specifically
        systems_with_security = (
            _scope(
                self.db.query(func.count(func.distinct(PackageUpdate.system_id))),
                PackageUpdate.system_id,
                system_ids,
            )
            .filter(PackageUpdate.update_type == "security")
            .scalar()
            or 0
        )
        # Total pending package-update rows (scoped to the caller's fleet).
        pending_package_updates = (
            _scope(
                self.db.query(func.count(PackageUpdate.id)),
                PackageUpdate.system_id,
                system_ids,
            ).scalar()
            or 0
        )
        # Total pending security package-update rows (scoped).
        pending_security_updates = (
            _scope(
                self.db.query(func.count(PackageUpdate.id)),
                PackageUpdate.system_id,
                system_ids,
            )
            .filter(PackageUpdate.update_type == "security")
            .scalar()
            or 0
        )
        total_systems = (
            _scope(self.db.query(func.count(System.id)), System.id, system_ids).scalar()
            or 0
        )
        up_to_date = max(0, total_systems - systems_with_updates)

        # Job summaries (PRA-281 Slice 4): active_jobs / recent_jobs carry job names
        # and target/completed/failed counts. A job row is shown only when it is
        # fully visible in the caller's fleet scope — i.e. every one of its resolved
        # target systems is authorized — using the shared ``JobService`` visibility
        # helper (also used by the jobs API). Tenant-wide admins see everything;
        # scoped callers see only fully-in-scope jobs and out-of-scope/mixed-scope
        # jobs are suppressed, so no out-of-scope name, count, or history leaks. A
        # fully-in-scope job's counts are all in-scope systems, so they are safe.
        from .job_service import JobService

        job_svc = JobService(self.db, scope=system_ids)

        active_jobs = []
        recent_jobs = []

        # Active running jobs with progress
        running_jobs = self.db.query(Job).filter(Job.status == "running").all()
        for job in running_jobs:
            if not job_svc.is_job_visible(job):
                continue
            history = (
                self.db.query(JobHistory)
                .filter(
                    JobHistory.job_id == job.id,
                    JobHistory.status == "running",
                )
                .order_by(JobHistory.id.desc())
                .first()
            )
            if history:
                targeted = max(history.systems_targeted or 0, 1)
                done = (history.systems_completed or 0) + (history.systems_failed or 0)
                active_jobs.append(
                    {
                        "job_id": job.id,
                        "name": job.name,
                        "job_type": job.job_type,
                        "systems_targeted": history.systems_targeted,
                        "systems_completed": history.systems_completed,
                        "systems_failed": history.systems_failed,
                        "progress_pct": round(done / targeted * 100),
                        "started_at": (
                            history.start_time.isoformat() + "Z"
                            if history.start_time
                            else None
                        ),
                    }
                )

        # Recent job history (last 10 finished among visible jobs). Admins keep the
        # efficient LIMIT 10; scoped callers must scan more and stop at 10 visible.
        recent_q = (
            self.db.query(JobHistory)
            .options(joinedload(JobHistory.job))
            .filter(JobHistory.status.in_(["completed", "failed", "cancelled"]))
            .order_by(JobHistory.start_time.desc())
        )
        recent_history = (recent_q.limit(10) if system_ids is None else recent_q).all()
        for h in recent_history:
            if len(recent_jobs) >= 10:
                break
            job = h.job or self.db.query(Job).filter(Job.id == h.job_id).first()
            # Suppress histories whose job is deleted or not fully in scope.
            if not job or not job_svc.is_job_visible(job):
                continue
            recent_jobs.append(
                {
                    "history_id": h.id,
                    "job_id": h.job_id,
                    "job_name": job.name,
                    "status": h.status,
                    "systems_completed": h.systems_completed,
                    "systems_failed": h.systems_failed,
                    "started_at": (
                        h.start_time.isoformat() + "Z" if h.start_time else None
                    ),
                    "ended_at": (h.end_time.isoformat() + "Z" if h.end_time else None),
                }
            )

        # Systems needing attention
        attention = []
        # Unreachable systems
        unreachable_systems = (
            _scope(
                self.db.query(System).filter(System.status == "Unreachable"),
                System.id,
                system_ids,
            )
            .limit(20)
            .all()
        )
        for s in unreachable_systems:
            attention.append(
                {
                    "system_id": s.id,
                    "hostname": s.hostname,
                    "reason": "unreachable",
                    "detail": "System has failed consecutive health checks",
                }
            )
        # Stale scans (last_audited > 7 days ago or never)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        stale_systems = (
            _scope(
                self.db.query(System).filter(
                    (System.last_audited.is_(None))
                    | (System.last_audited < seven_days_ago)
                ),
                System.id,
                system_ids,
            )
            .limit(20)
            .all()
        )
        for s in stale_systems[:10]:
            if s.last_audited is None:
                detail = "Never scanned"
                reason = "never_scanned"
            else:
                days = (datetime.utcnow() - s.last_audited).days
                detail = f"Not scanned in {days} days"
                reason = "stale_scan"
            attention.append(
                {
                    "system_id": s.id,
                    "hostname": s.hostname,
                    "reason": reason,
                    "detail": detail,
                }
            )

        # Security-scan provenance for the same scope. Security counts mean
        # nothing without it: an inventory scan never classifies an update as
        # security related, so a zero can equally mean "none pending" or "never
        # asked".
        security_posture = build_security_posture(
            self.db,
            system_ids=system_ids,
            systems_with_security_updates=systems_with_security,
            pending_security_updates=pending_security_updates,
        )

        # Health summary
        health = self.get_fleet_health(system_ids=system_ids)

        return {
            "status_counts": status_counts,
            "systems_by_group": systems_by_group,
            "systems_by_distro": systems_by_distro,
            "patch_compliance": {
                "total": total_systems,
                "up_to_date": up_to_date,
                # Systems-affected counts (kept for backward compatibility).
                "with_updates": systems_with_updates,
                "with_security_updates": systems_with_security,
                # PRA-277: explicit package-update ROW totals across all systems.
                "pending_package_updates": pending_package_updates,
                "pending_security_updates": pending_security_updates,
            },
            "security_posture": security_posture,
            "active_jobs": active_jobs,
            "recent_jobs": recent_jobs,
            "attention": attention,
            "health": health,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _notify(
        self,
        type_: str,
        title: str,
        message: str,
        severity: str,
        *,
        system_id: Optional[int] = None,
    ) -> None:
        create_notification(
            self.db,
            type=type_,
            title=title,
            message=message,
            severity=severity,
            system_id=system_id,
        )


def run_scheduled_health_check() -> None:
    """Top-level scheduler callback - creates own DB session."""
    from ..db.session import SessionLocal

    db = SessionLocal()
    try:
        service = HealthService(db)
        result = service.check_all_systems()
        logger.info(
            "Scheduled health check: %d systems checked, %d ok, %d failed",
            result["total"],
            result["ok"],
            result["failed"],
        )
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Scheduled health check failed: %s", str(e))
    finally:
        db.close()
