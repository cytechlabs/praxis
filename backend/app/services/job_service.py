"""
Job scheduling service for creating, managing, and executing jobs.
"""

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from croniter import croniter
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session, joinedload

from ..db.models import (
    Group,
    Job,
    JobHistory,
    Package,
    PackageHistory,
    System,
    Tag,
    User,
    system_tag,
)
from ..db.session import SessionLocal
from .notification_service import create_notification

logger = logging.getLogger(__name__)


class JobNotFound(ValueError):
    """Raised when a job/history is missing OR not visible in the caller's fleet
    scope. PRA-281: out-of-scope jobs are indistinguishable from nonexistent ones
    (non-disclosing) — this subclasses ValueError so existing not-found handling
    keeps working, while routes can map it to a 404 explicitly."""


def _utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime as ISO string with Z suffix for UTC."""
    if dt is None:
        return None
    return dt.isoformat() + "Z"


# --- Per-system concurrency locks (PRA-76) ---
_system_locks: Dict[int, threading.Lock] = {}
_locks_lock = threading.Lock()  # protects _system_locks dict


def _get_system_lock(system_id: int) -> threading.Lock:
    """Get or create a lock for a system."""
    with _locks_lock:
        if system_id not in _system_locks:
            _system_locks[system_id] = threading.Lock()
        return _system_locks[system_id]


# --- Running job tracking for cancellation (PRA-77) ---
_running_jobs: Dict[int, Dict[str, Any]] = {}  # job_id -> {"cancelled": Event}
_running_jobs_lock = threading.Lock()

# Scheduled-run maintenance-window policy by job type. Only read/refresh jobs
# (package_scan/audit — they SSH-read inventory and never mutate a host) may run
# outside a window; everything else is window-governed. This is an explicit
# allowlist so an unknown/future job type FAILS CLOSED (stays window-governed).
_READ_REFRESH_JOB_TYPES = frozenset({"package_scan", "audit"})


def job_type_respects_maintenance_window(job_type: str) -> bool:
    """Whether a SCHEDULED job of ``job_type`` must run inside a maintenance window.

    Only ``package_scan``/``audit`` (read/refresh) may run any time; every other
    type — including unknown/future ones — stays window-governed (fail closed).
    Manual "Run now" already bypasses windows regardless of type.
    """
    return job_type not in _READ_REFRESH_JOB_TYPES


class JobService:
    """Service for managing scheduled jobs."""

    def __init__(self, db: Session, scope: Optional[Set[int]] = None):
        """``scope`` (PRA-281) is the caller's fleet scope: ``None`` = tenant-wide
        admin (no filtering, unchanged behavior); otherwise the set of system ids
        the caller may access. Job visibility/enforcement is derived from a job's
        resolved target systems relative to this scope."""
        self.db = db
        self.scope = scope
        self._vis_cache: Dict[int, bool] = {}

    def _get_job_or_raise(self, job_id: int) -> Job:
        """Get a job by ID or raise ValueError (existence only; no scope check)."""
        job = self.db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise ValueError(f"Job with ID {job_id} not found")
        return job

    # --- PRA-281: fleet-scope visibility/enforcement -----------------------

    def _resolve_target_system_ids(self, job: Job) -> Set[int]:
        """The set of ACTIVE system ids a job currently resolves to."""
        return {s.id for s in self._resolve_target_systems(job)}

    def _compute_visible(self, job: Job) -> bool:
        """A job is visible to a scoped caller only when its whole target is
        authorized — fail closed for out-of-scope-only and mixed-scope jobs."""
        if job.target_type == "system":
            # Declared ids are system ids: require every one in scope so an
            # out-of-scope declared id can never leak (even if inactive/unresolved).
            try:
                raw = set(json.loads(job.target_ids)) if job.target_ids else set()
            except (json.JSONDecodeError, TypeError):
                return False
            return bool(raw) and raw.issubset(self.scope)
        # all / group / tag / smart_group: visible only when the resolved active
        # targets are non-empty AND entirely in scope (a group/tag containing any
        # out-of-scope system is hidden — its id, hostnames, and counts stay hidden).
        resolved = self._resolve_target_system_ids(job)
        return bool(resolved) and resolved.issubset(self.scope)

    def is_job_visible(self, job: Job) -> bool:
        """Whether ``job`` is visible/operable in the caller's fleet scope.

        Admins (``scope is None``) always see everything. Result is cached per
        job id for the life of this service instance (list/history endpoints
        check many rows that share jobs)."""
        if self.scope is None:
            return True
        if job.id is not None and job.id in self._vis_cache:
            return self._vis_cache[job.id]
        visible = self._compute_visible(job)
        if job.id is not None:
            self._vis_cache[job.id] = visible
        return visible

    def _get_visible_job_or_raise(self, job_id: int) -> Job:
        """Get a job by id, or raise ``JobNotFound`` if it does not exist OR is
        not visible in the caller's scope (the two are indistinguishable)."""
        job = self.db.query(Job).filter(Job.id == job_id).first()
        if not job or not self.is_job_visible(job):
            raise JobNotFound(f"Job with ID {job_id} not found")
        return job

    def _enforce_target_scope(
        self,
        target_type: str,
        target_ids: Optional[List[int]],
        tag_match_logic: str = "or",
    ) -> None:
        """Reject create/update targets that could execute outside the caller's
        fleet scope. No-op for admins (``scope is None``)."""
        if self.scope is None:
            return
        if target_type == "all":
            raise ValueError(
                "target_type 'all' is not permitted within your access scope"
            )
        if target_type == "system":
            req = set(target_ids or [])
            if not req or not req.issubset(self.scope):
                # Generic: never reveal which id is out of scope vs nonexistent.
                raise ValueError(
                    "one or more target systems are outside your access scope"
                )
            return
        # group / tag / smart_group: resolve now; require a non-empty target set
        # fully inside scope (fail closed otherwise).
        probe = Job(
            target_type=target_type,
            target_ids=(json.dumps(list(target_ids)) if target_ids else None),
            tag_match_logic=tag_match_logic or "or",
        )
        resolved = self._resolve_target_system_ids(probe)
        if not resolved or not resolved.issubset(self.scope):
            raise ValueError("resolved target systems are outside your access scope")

    def _resolve_target_systems(self, job: Job) -> List[System]:
        """Convert target_type/target_ids to a list of System objects."""
        if job.target_type == "all":
            return self.db.query(System).filter(System.status == "Active").all()

        if not job.target_ids:
            return []

        try:
            ids = json.loads(job.target_ids)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid target_ids JSON for job %d", job.id)
            return []

        if job.target_type == "system":
            return (
                self.db.query(System)
                .filter(System.id.in_(ids), System.status == "Active")
                .all()
            )

        if job.target_type == "group":
            # PRA-106: Resolve group hierarchy — include descendant groups
            all_group_ids = set(ids)
            queue = list(ids)
            while queue:
                current_id = queue.pop(0)
                children = (
                    self.db.query(Group.id).filter(Group.parent_id == current_id).all()
                )
                for (child_id,) in children:
                    if child_id not in all_group_ids:
                        all_group_ids.add(child_id)
                        queue.append(child_id)

            return (
                self.db.query(System)
                .filter(
                    System.group_id.in_(list(all_group_ids)),
                    System.status == "Active",
                )
                .distinct()
                .all()
            )

        if job.target_type == "tag":
            # PRA-102: Tag-based targeting
            match_logic = getattr(job, "tag_match_logic", "or") or "or"

            if match_logic == "and":
                # Systems must have ALL specified tags
                tag_count = len(ids)
                system_ids_query = (
                    self.db.query(system_tag.c.system_id)
                    .filter(system_tag.c.tag_id.in_(ids))
                    .group_by(system_tag.c.system_id)
                    .having(
                        func.count(  # pylint: disable=not-callable
                            distinct(system_tag.c.tag_id)
                        )
                        == tag_count
                    )
                    .subquery()
                )
                return (
                    self.db.query(System)
                    .filter(
                        System.id.in_(self.db.query(system_ids_query.c.system_id)),
                        System.status == "Active",
                    )
                    .all()
                )
            else:
                # Systems with ANY of the specified tags
                tagged_system_ids = (
                    self.db.query(distinct(system_tag.c.system_id))
                    .filter(system_tag.c.tag_id.in_(ids))
                    .all()
                )
                sid_list = [row[0] for row in tagged_system_ids]
                if not sid_list:
                    return []
                return (
                    self.db.query(System)
                    .filter(
                        System.id.in_(sid_list),
                        System.status == "Active",
                    )
                    .all()
                )

        if job.target_type == "smart_group":
            # PRA-126: Smart group targeting — use cached membership
            from ..db.models import SmartGroupMembership

            member_sids = (
                self.db.query(SmartGroupMembership.system_id)
                .filter(SmartGroupMembership.smart_group_id.in_(ids))
                .distinct()
                .all()
            )
            sid_list = [row[0] for row in member_sids]
            if not sid_list:
                return []
            return (
                self.db.query(System)
                .filter(
                    System.id.in_(sid_list),
                    System.status == "Active",
                )
                .all()
            )

        return []

    def _validate_cron(self, expression: str) -> bool:
        """Validate a cron expression. Raises ValueError if invalid."""
        if not croniter.is_valid(expression):
            raise ValueError(f"Invalid cron expression: {expression}")
        return True

    def _calculate_next_run(self, cron_expression: str) -> datetime:
        """Calculate the next run time from a cron expression."""
        cron = croniter(cron_expression, datetime.utcnow())
        return cron.get_next(datetime)

    def _job_to_dict(self, job: Job, include_systems: bool = False) -> Dict[str, Any]:
        """Convert a Job model to a dictionary."""
        result = {
            "id": job.id,
            "name": job.name,
            "description": job.description,
            "job_type": job.job_type,
            "schedule": job.schedule,
            "is_recurring": job.is_recurring,
            "status": job.status,
            "target_type": job.target_type,
            "target_ids": (json.loads(job.target_ids) if job.target_ids else None),
            "package_filter": (
                json.loads(job.package_filter) if job.package_filter else None
            ),
            "last_run": _utc_iso(job.last_run),
            "next_run": _utc_iso(job.next_run),
            "created_at": _utc_iso(job.created_at),
            "created_by": job.created_by,
            "updated_at": _utc_iso(job.updated_at),
            "tag_match_logic": job.tag_match_logic,
            "max_parallel": job.max_parallel,
            "depends_on_job_id": job.depends_on_job_id,
            "chain_condition": job.chain_condition,
            "dependency_name": None,
        }

        # Resolve dependency job name. PRA-281: for a scoped caller, a visible job
        # must not leak an out-of-scope parent — hide BOTH the dependency id and
        # name unless the dependency job is itself visible in the same scope.
        if job.depends_on_job_id:
            dep = self.db.query(Job).filter(Job.id == job.depends_on_job_id).first()
            if dep and self.is_job_visible(dep):
                result["dependency_name"] = dep.name
            elif self.scope is not None:
                # Hidden or missing dependency for a scoped caller: null it out.
                result["depends_on_job_id"] = None

        if include_systems:
            systems = self._resolve_target_systems(job)
            result["systems"] = [
                {
                    "id": s.id,
                    "hostname": s.hostname,
                    "ip_address": str(s.ip_address),
                    "status": s.status,
                }
                for s in systems
            ]

        return result

    def _history_to_dict(self, history: JobHistory) -> Dict[str, Any]:
        """Convert a JobHistory model to a dictionary."""
        result = {
            "id": history.id,
            "job_id": history.job_id,
            "start_time": _utc_iso(history.start_time),
            "end_time": _utc_iso(history.end_time),
            "status": history.status,
            "result": (json.loads(history.result) if history.result else None),
            "error_message": history.error_message,
            "systems_targeted": history.systems_targeted,
            "systems_completed": history.systems_completed,
            "systems_failed": history.systems_failed,
            "created_at": _utc_iso(history.created_at),
        }
        # Include job details if relationship is loaded
        if history.job:
            result["job_name"] = history.job.name
            result["job_type"] = history.job.job_type
        else:
            result["job_name"] = f"Job #{history.job_id}"
            result["job_type"] = "unknown"
        return result

    def create_job(self, data: Dict[str, Any], user_id: int) -> Dict[str, Any]:
        """Create a new job."""
        valid_types = {"update", "security_update", "audit", "package_scan"}
        if data.get("job_type") not in valid_types:
            raise ValueError(
                f"Invalid job_type. Must be one of: {', '.join(sorted(valid_types))}"
            )

        valid_targets = {"system", "group", "tag", "all"}
        if data.get("target_type") not in valid_targets:
            raise ValueError(
                f"Invalid target_type. Must be one of: "
                f"{', '.join(sorted(valid_targets))}"
            )

        if data.get("target_type") != "all" and not data.get("target_ids"):
            raise ValueError("target_ids is required when target_type is not 'all'")

        # PRA-281: a scoped caller may not create a job that could execute on
        # systems outside their fleet scope. Checked before existence validation
        # so an out-of-scope id reads the same as a nonexistent one.
        self._enforce_target_scope(
            data["target_type"],
            data.get("target_ids"),
            data.get("tag_match_logic", "or"),
        )

        is_recurring = data.get("is_recurring", False)
        schedule = data.get("schedule")

        if is_recurring and not schedule:
            raise ValueError("schedule is required for recurring jobs")

        next_run = None
        if schedule:
            self._validate_cron(schedule)
            next_run = self._calculate_next_run(schedule)

        # Validate target_ids exist
        target_ids = data.get("target_ids")
        if target_ids:
            if data["target_type"] == "system":
                existing = (
                    self.db.query(System.id).filter(System.id.in_(target_ids)).all()
                )
                existing_ids = {row[0] for row in existing}
                missing = set(target_ids) - existing_ids
                if missing:
                    raise ValueError(f"Systems not found: {sorted(missing)}")
            elif data["target_type"] == "group":
                existing = (
                    self.db.query(Group.id).filter(Group.id.in_(target_ids)).all()
                )
                existing_ids = {row[0] for row in existing}
                missing = set(target_ids) - existing_ids
                if missing:
                    raise ValueError(f"Groups not found: {sorted(missing)}")
            elif data["target_type"] == "tag":
                existing = self.db.query(Tag.id).filter(Tag.id.in_(target_ids)).all()
                existing_ids = {row[0] for row in existing}
                missing = set(target_ids) - existing_ids
                if missing:
                    raise ValueError(f"Tags not found: {sorted(missing)}")

        package_filter = data.get("package_filter")

        tag_match_logic = data.get("tag_match_logic", "or")
        if tag_match_logic not in ("or", "and"):
            raise ValueError("tag_match_logic must be 'or' or 'and'")

        max_parallel = data.get("max_parallel", 1) or 1
        if not isinstance(max_parallel, int) or max_parallel < 1 or max_parallel > 50:
            raise ValueError("max_parallel must be an integer between 1 and 50")

        # PRA-81: Job chaining
        depends_on_job_id = data.get("depends_on_job_id")
        chain_condition = data.get("chain_condition", "on_success") or "on_success"
        if chain_condition not in ("on_success", "on_complete", "on_failure"):
            raise ValueError(
                "chain_condition must be 'on_success', 'on_complete', or 'on_failure'"
            )
        if depends_on_job_id is not None:
            dep = self.db.query(Job).filter(Job.id == depends_on_job_id).first()
            # PRA-281: a scoped caller may only depend on a job that is itself
            # visible in scope. Missing and out-of-scope are one generic,
            # non-disclosing error (never reveals the hidden job's name/existence).
            if self.scope is not None:
                if not dep or not self.is_job_visible(dep):
                    raise ValueError("dependency job is outside your access scope")
            elif not dep:
                raise ValueError(f"Dependency job {depends_on_job_id} not found")

        job = Job(
            name=data["name"],
            description=data.get("description"),
            job_type=data["job_type"],
            schedule=schedule,
            is_recurring=is_recurring,
            status="scheduled",
            target_type=data["target_type"],
            target_ids=(json.dumps(target_ids) if target_ids else None),
            package_filter=(json.dumps(package_filter) if package_filter else None),
            tag_match_logic=tag_match_logic,
            max_parallel=max_parallel,
            next_run=next_run,
            created_by=user_id,
            depends_on_job_id=depends_on_job_id,
            chain_condition=chain_condition,
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        logger.info("Created job %d: %s", job.id, job.name)

        return {
            "status": "success",
            "message": f"Job '{job.name}' created successfully",
            "job": self._job_to_dict(job),
        }

    def update_job(
        self, job_id: int, data: Dict[str, Any], user_id: int
    ) -> Dict[str, Any]:
        """Update an existing job."""
        # PRA-281: caller must be able to see the job (out-of-scope → non-disclosing
        # not-found), and the resulting target must stay within scope so the job
        # cannot be repointed to execute out-of-scope.
        job = self._get_visible_job_or_raise(job_id)
        eff_target_type = data.get("target_type", job.target_type)
        if "target_ids" in data:
            eff_target_ids = data["target_ids"]
        else:
            eff_target_ids = json.loads(job.target_ids) if job.target_ids else None
        eff_tag_logic = data.get("tag_match_logic", job.tag_match_logic)
        self._enforce_target_scope(eff_target_type, eff_target_ids, eff_tag_logic)

        if "job_type" in data:
            valid_types = {
                "update",
                "security_update",
                "audit",
                "package_scan",
            }
            if data["job_type"] not in valid_types:
                raise ValueError(
                    f"Invalid job_type. Must be one of: "
                    f"{', '.join(sorted(valid_types))}"
                )
            job.job_type = data["job_type"]

        if "target_type" in data:
            valid_targets = {"system", "group", "tag", "all"}
            if data["target_type"] not in valid_targets:
                raise ValueError(
                    f"Invalid target_type. Must be one of: "
                    f"{', '.join(sorted(valid_targets))}"
                )
            job.target_type = data["target_type"]

        if "name" in data:
            job.name = data["name"]
        if "description" in data:
            job.description = data["description"]
        if "is_recurring" in data:
            job.is_recurring = data["is_recurring"]
        if "status" in data:
            job.status = data["status"]

        if "target_ids" in data:
            target_ids = data["target_ids"]
            job.target_ids = json.dumps(target_ids) if target_ids else None

        if "package_filter" in data:
            pf = data["package_filter"]
            job.package_filter = json.dumps(pf) if pf else None

        if "tag_match_logic" in data:
            if data["tag_match_logic"] not in ("or", "and"):
                raise ValueError("tag_match_logic must be 'or' or 'and'")
            job.tag_match_logic = data["tag_match_logic"]

        if "max_parallel" in data:
            mp = data["max_parallel"] or 1
            if not isinstance(mp, int) or mp < 1 or mp > 50:
                raise ValueError("max_parallel must be an integer between 1 and 50")
            job.max_parallel = mp

        # PRA-81: Job chaining
        if "depends_on_job_id" in data:
            dep_id = data["depends_on_job_id"]
            if dep_id is not None:
                if dep_id == job_id:
                    raise ValueError("A job cannot depend on itself")
                dep = self.db.query(Job).filter(Job.id == dep_id).first()
                # PRA-281: a scoped caller may only repoint a dependency to a job
                # that is itself visible in scope (generic, non-disclosing error).
                if self.scope is not None:
                    if not dep or not self.is_job_visible(dep):
                        raise ValueError("dependency job is outside your access scope")
                elif not dep:
                    raise ValueError(f"Dependency job {dep_id} not found")
                # Circular dependency check
                visited = {job_id}
                current = dep
                while current and current.depends_on_job_id:
                    if current.depends_on_job_id in visited:
                        raise ValueError("Circular dependency detected")
                    visited.add(current.depends_on_job_id)
                    current = (
                        self.db.query(Job)
                        .filter(Job.id == current.depends_on_job_id)
                        .first()
                    )
            job.depends_on_job_id = dep_id

        if "chain_condition" in data:
            cc = data["chain_condition"] or "on_success"
            if cc not in ("on_success", "on_complete", "on_failure"):
                raise ValueError(
                    "chain_condition must be 'on_success', 'on_complete', or 'on_failure'"
                )
            job.chain_condition = cc

        if "schedule" in data:
            schedule = data["schedule"]
            if schedule:
                self._validate_cron(schedule)
                job.schedule = schedule
                job.next_run = self._calculate_next_run(schedule)
            else:
                job.schedule = None
                job.next_run = None

        if job.is_recurring and not job.schedule:
            raise ValueError("schedule is required for recurring jobs")

        job.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(job)

        logger.info("Updated job %d: %s", job.id, job.name)

        return {
            "status": "success",
            "message": f"Job '{job.name}' updated successfully",
            "job": self._job_to_dict(job),
        }

    def delete_job(self, job_id: int) -> Dict[str, Any]:
        """Delete a job and its history."""
        job = self._get_visible_job_or_raise(job_id)
        job_name = job.name

        self.db.delete(job)
        self.db.commit()

        logger.info("Deleted job %d: %s", job_id, job_name)

        return {
            "status": "success",
            "message": f"Job '{job_name}' deleted successfully",
        }

    def get_job(self, job_id: int) -> Dict[str, Any]:
        """Get job details including resolved systems."""
        job = self._get_visible_job_or_raise(job_id)
        return {
            "status": "success",
            "job": self._job_to_dict(job, include_systems=True),
        }

    def list_jobs(
        self,
        status: Optional[str] = None,
        job_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List jobs with optional filtering and pagination."""
        query = self.db.query(Job)

        if status:
            query = query.filter(Job.status == status)
        if job_type:
            query = query.filter(Job.job_type == job_type)

        if self.scope is None:
            total = query.count()
            jobs = (
                query.order_by(Job.created_at.desc()).offset(offset).limit(limit).all()
            )
        else:
            # PRA-281: visibility depends on resolved targets, so filter in Python
            # and paginate the visible set (total reflects visible jobs only).
            ordered = query.order_by(Job.created_at.desc()).all()
            visible = [j for j in ordered if self.is_job_visible(j)]
            total = len(visible)
            jobs = visible[offset : offset + limit]

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "jobs": [self._job_to_dict(j) for j in jobs],
        }

    def get_active_jobs(self) -> List[Dict[str, Any]]:
        """Get all currently running jobs with progress."""
        running_jobs = self.db.query(Job).filter(Job.status == "running").all()
        result = []
        for job in running_jobs:
            # PRA-281: hide running jobs the caller cannot fully see.
            if not self.is_job_visible(job):
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

            job_dict = self._job_to_dict(job)
            if history:
                targeted = max(history.systems_targeted, 1)
                done = (history.systems_completed or 0) + (history.systems_failed or 0)
                job_dict["current_run"] = {
                    "history_id": history.id,
                    "start_time": _utc_iso(history.start_time),
                    "systems_targeted": history.systems_targeted,
                    "systems_completed": history.systems_completed,
                    "systems_failed": history.systems_failed,
                    "progress_pct": round(done / targeted * 100),
                }
            result.append(job_dict)
        return result

    def get_failed_jobs(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Get failed job runs with pagination."""
        query = self.db.query(JobHistory).filter(JobHistory.status == "failed")

        if self.scope is None:
            total = query.count()
            history = (
                query.order_by(JobHistory.start_time.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
        else:
            history, total = self._scoped_history_page(query, limit, offset)

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "history": [self._history_to_dict(h) for h in history],
        }

    def start_job(self, job_id: int) -> int:
        """Validate and mark a job as running. Returns history_id.

        PRA-281: uses the scope-aware lookup so runtime execution re-checks fleet
        scope against the CURRENT resolved target (grants/targets may have changed
        since create) — an out-of-scope or mixed-scope job is rejected fail-closed,
        indistinguishable from a nonexistent job."""
        job = self._get_visible_job_or_raise(job_id)
        if job.status == "running":
            raise ValueError(f"Job '{job.name}' is already running")
        systems = self._resolve_target_systems(job)
        if not systems:
            raise ValueError(f"No active systems found for job '{job.name}'")
        history = JobHistory(
            job_id=job.id,
            start_time=datetime.utcnow(),
            status="running",
            systems_targeted=len(systems),
            systems_completed=0,
            systems_failed=0,
        )
        self.db.add(history)
        job.status = "running"
        self.db.commit()
        self.db.refresh(history)
        return history.id

    def run_job(
        self,
        job_id: int,
        user_id: int,
        ignore_maintenance_window: bool = False,
    ) -> Dict[str, Any]:
        """Execute a job (call from background thread).

        Args:
            job_id: The job to run.
            user_id: Who triggered the run.
            ignore_maintenance_window: If True, skip maintenance window
                enforcement (used for manual/on-demand runs).
        """
        from .package_service import PackageService

        job = self._get_job_or_raise(job_id)
        systems = self._resolve_target_systems(job)

        # Find the latest running history record
        history = (
            self.db.query(JobHistory)
            .filter(
                JobHistory.job_id == job_id,
                JobHistory.status == "running",
            )
            .order_by(JobHistory.id.desc())
            .first()
        )
        if not history:
            # Fallback: create one if called directly
            history = JobHistory(
                job_id=job.id,
                start_time=datetime.utcnow(),
                status="running",
                systems_targeted=len(systems),
                systems_completed=0,
                systems_failed=0,
            )
            self.db.add(history)
            job.status = "running"
            self.db.commit()
            self.db.refresh(history)

        # Register cancel event for this job (PRA-77)
        cancel_event = threading.Event()
        with _running_jobs_lock:
            _running_jobs[job_id] = {"cancelled": cancel_event}

        logger.info(
            "Running job %d (%s) on %d systems",
            job.id,
            job.name,
            len(systems),
        )

        # Parse package filter
        package_filter = None
        if job.package_filter:
            try:
                package_filter = json.loads(job.package_filter)
            except (json.JSONDecodeError, TypeError):
                pass

        completed = 0
        failed = 0
        skipped = 0
        maintenance_skipped = 0
        cancelled = False
        results = []

        # PRA-101: Parallel execution with configurable concurrency
        max_parallel = max(1, getattr(job, "max_parallel", 1) or 1)
        logger.info(
            "Job %d executing with max_parallel=%d on %d systems",
            job.id,
            max_parallel,
            len(systems),
        )

        # Snapshot per-system info before parallelizing (avoid SA session reuse)
        system_info = [(s.id, s.hostname) for s in systems]

        # Only mutating job types are maintenance-window governed on a scheduled
        # run; read/refresh jobs (package_scan/audit) run any time.
        enforce_maintenance_window = (
            not ignore_maintenance_window
            and job_type_respects_maintenance_window(job.job_type)
        )

        def _worker(system_id: int, hostname: str) -> Dict[str, Any]:
            """Run job on one system in its own DB session."""
            if cancel_event.is_set():
                return {
                    "system_id": system_id,
                    "hostname": hostname,
                    "result": {
                        "status": "skipped",
                        "message": "Cancelled before execution",
                    },
                }

            # Maintenance-window enforcement — scheduled runs of mutating job
            # types only (read/refresh jobs and manual runs skip it).
            if enforce_maintenance_window:
                from .maintenance_window_service import (
                    get_next_window,
                    is_in_maintenance_window,
                )

                mw_db = SessionLocal()
                try:
                    in_window, window_info = is_in_maintenance_window(mw_db, system_id)
                    if not in_window:
                        next_win = get_next_window(mw_db, system_id)
                        next_msg = ""
                        if next_win:
                            next_msg = (
                                f" Next window: {next_win['window_name']}"
                                f" at {next_win['next_start']}"
                            )
                        return {
                            "system_id": system_id,
                            "hostname": hostname,
                            "result": {
                                "status": "maintenance_skipped",
                                "message": (
                                    "Skipped — outside maintenance window." + next_msg
                                ),
                            },
                        }
                finally:
                    mw_db.close()

            lock = _get_system_lock(system_id)
            if not lock.acquire(timeout=2):
                return {
                    "system_id": system_id,
                    "hostname": hostname,
                    "result": {
                        "status": "skipped",
                        "message": "System busy - another job is running",
                    },
                }

            worker_db = SessionLocal()
            try:
                worker_pkg_service = PackageService(worker_db)
                worker_system = (
                    worker_db.query(System).filter(System.id == system_id).first()
                )
                if not worker_system:
                    return {
                        "system_id": system_id,
                        "hostname": hostname,
                        "result": {
                            "status": "error",
                            "message": "System not found",
                        },
                    }
                result = self._execute_on_system(
                    worker_pkg_service,
                    job.job_type,
                    worker_system,
                    user_id,
                    package_filter,
                    history_id=history.id,
                )
                return {
                    "system_id": system_id,
                    "hostname": hostname,
                    "result": result,
                }
            except Exception as e:  # pylint: disable=broad-except
                logger.error(
                    "Job %d failed on system %d: %s", job.id, system_id, str(e)
                )
                return {
                    "system_id": system_id,
                    "hostname": hostname,
                    "result": {"status": "error", "message": str(e)},
                }
            finally:
                worker_db.close()
                lock.release()

        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            future_to_sys = {
                executor.submit(_worker, sid, hostname): (sid, hostname)
                for sid, hostname in system_info
            }
            for future in as_completed(future_to_sys):
                if cancel_event.is_set() and not cancelled:
                    cancelled = True
                    logger.info("Job %d cancelled, stopping execution", job.id)

                entry = future.result()
                results.append(entry)
                status = entry["result"].get("status")
                if status == "success":
                    completed += 1
                elif status == "maintenance_skipped":
                    maintenance_skipped += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    failed += 1

                # Update progress in history (main thread session)
                history.systems_completed = completed
                history.systems_failed = failed
                self.db.commit()

        # Clean up running job tracking (PRA-77)
        with _running_jobs_lock:
            _running_jobs.pop(job_id, None)

        # Update history
        history.end_time = datetime.utcnow()
        history.systems_completed = completed
        history.systems_failed = failed
        history.result = json.dumps(results)

        if cancelled:
            history.status = "cancelled"
            history.error_message = "Cancelled by user"
        else:
            history.status = "completed" if failed == 0 else "failed"

        if not cancelled:
            if failed > 0 and completed == 0:
                history.error_message = f"All {failed} systems failed"
            elif failed > 0:
                history.error_message = f"{failed} of {len(systems)} systems failed"

        if skipped > 0:
            skip_msg = f"{skipped} systems skipped (busy)"
            if history.error_message:
                history.error_message += f"; {skip_msg}"
            else:
                history.error_message = skip_msg

        if maintenance_skipped > 0:
            mw_msg = (
                f"{maintenance_skipped} systems skipped" " (outside maintenance window)"
            )
            if history.error_message:
                history.error_message += f"; {mw_msg}"
            else:
                history.error_message = mw_msg

        # Update job
        if cancelled:
            job.status = "scheduled" if job.is_recurring else "cancelled"
        else:
            job.status = "scheduled" if job.is_recurring else "completed"
        job.last_run = datetime.utcnow()
        if job.is_recurring and job.schedule:
            job.next_run = self._calculate_next_run(job.schedule)

        self.db.commit()
        self.db.refresh(history)

        # Create notification (PRA-78)
        if cancelled:
            notif_type = "job_cancelled"
            notif_title = f"Job '{job.name}' cancelled"
            notif_message = "Job was cancelled by user"
            notif_severity = "warning"
        elif history.status == "completed":
            notif_type = "job_completed"
            notif_title = f"Job '{job.name}' completed"
            notif_message = (
                f"All {completed} systems completed successfully"
                if failed == 0
                else f"{completed} systems completed, {failed} failed"
            )
            notif_severity = "info"
        else:
            notif_type = "job_failed"
            notif_title = f"Job '{job.name}' failed"
            notif_message = f"{completed} systems completed, {failed} failed"
            notif_severity = "error"

        create_notification(
            self.db,
            type=notif_type,
            title=notif_title,
            message=notif_message,
            severity=notif_severity,
            related_job_id=job.id,
            user_id=user_id,
        )

        # PRA-81: Trigger dependent jobs (job chaining)
        if not cancelled:
            self._trigger_dependent_jobs(job.id, history.status, user_id)

        logger.info(
            "Job %d finished: %d succeeded, %d failed, %d skipped, "
            "%d maintenance-skipped%s",
            job.id,
            completed,
            failed,
            skipped,
            maintenance_skipped,
            " (cancelled)" if cancelled else "",
        )

        return {
            "status": "success",
            "message": (
                f"Job '{job.name}' {'cancelled' if cancelled else 'completed'}: "
                f"{completed} succeeded, {failed} failed, {skipped} skipped"
                + (
                    f", {maintenance_skipped} outside maintenance window"
                    if maintenance_skipped > 0
                    else ""
                )
            ),
            "history": self._history_to_dict(history),
        }

    def _execute_on_system(
        self,
        pkg_service: Any,
        job_type: str,
        system: System,
        user_id: int,
        package_filter: Optional[Dict[str, Any]] = None,
        history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a job type on a single system."""
        if job_type == "package_scan":
            return pkg_service.scan_packages(system.id)
        elif job_type == "update":
            package_names = None
            if package_filter and package_filter.get("names"):
                package_names = package_filter["names"]
            return pkg_service.apply_updates(
                system.id,
                package_names=package_names,
                user_id=user_id,
                job_history_id=history_id,
            )
        elif job_type == "security_update":
            return pkg_service.apply_security_updates(
                system.id,
                user_id=user_id,
                job_history_id=history_id,
            )
        elif job_type == "audit":
            return pkg_service.scan_packages(system.id)
        else:
            raise ValueError(f"Unsupported job type: {job_type}")

    def dry_run_job(self, job_id: int) -> Dict[str, Any]:
        """PRA-82: Preview what a job would do without executing it."""
        from .package_service import PackageService

        # PRA-281: fail-closed for out-of-scope/mixed-scope jobs; a visible job's
        # resolved targets are all in scope, so the preview never exposes
        # out-of-scope hostnames or package operations.
        job = self._get_visible_job_or_raise(job_id)
        systems = self._resolve_target_systems(job)

        package_filter = None
        if job.package_filter:
            try:
                package_filter = json.loads(job.package_filter)
            except (json.JSONDecodeError, TypeError):
                pass

        pkg_service = PackageService(self.db)
        preview = []
        total_packages = 0

        for system in systems:
            sys_preview: Dict[str, Any] = {
                "system_id": system.id,
                "hostname": system.hostname,
            }

            if job.job_type == "package_scan" or job.job_type == "audit":
                pkg_count = (
                    self.db.query(Package)
                    .filter(Package.system_id == system.id)
                    .count()
                )
                sys_preview["action"] = "Would scan packages"
                sys_preview["installed_packages"] = pkg_count
                sys_preview["packages_affected"] = []
            elif job.job_type == "update":
                updates = pkg_service.get_updates(system_id=system.id)
                if package_filter and package_filter.get("names"):
                    names_filter = set(package_filter["names"])
                    updates = [u for u in updates if u["package_name"] in names_filter]
                # Skip held packages
                held = {
                    p.name
                    for p in self.db.query(Package)
                    .filter(
                        Package.system_id == system.id,
                        Package.is_held.is_(True),
                    )
                    .all()
                }
                updates = [u for u in updates if u["package_name"] not in held]
                sys_preview["action"] = "Would update packages"
                sys_preview["packages_affected"] = [
                    {
                        "name": u["package_name"],
                        "from_version": u["installed_version"],
                        "to_version": u["available_version"],
                        "type": u["update_type"],
                    }
                    for u in updates
                ]
                total_packages += len(updates)
            elif job.job_type == "security_update":
                updates = pkg_service.get_security_updates(system_id=system.id)
                held = {
                    p.name
                    for p in self.db.query(Package)
                    .filter(
                        Package.system_id == system.id,
                        Package.is_held.is_(True),
                    )
                    .all()
                }
                updates = [u for u in updates if u["package_name"] not in held]
                sys_preview["action"] = "Would apply security updates"
                sys_preview["packages_affected"] = [
                    {
                        "name": u["package_name"],
                        "from_version": u["installed_version"],
                        "to_version": u["available_version"],
                        "type": "security",
                    }
                    for u in updates
                ]
                total_packages += len(updates)
            else:
                sys_preview["action"] = f"Unknown job type: {job.job_type}"
                sys_preview["packages_affected"] = []

            preview.append(sys_preview)

        return {
            "status": "success",
            "dry_run": True,
            "job_id": job.id,
            "job_name": job.name,
            "job_type": job.job_type,
            "systems_targeted": len(systems),
            "total_packages_affected": total_packages,
            "preview": preview,
        }

    def rollback_job_history(self, history_id: int, user_id: int) -> Dict[str, Any]:
        """PRA-83: Rollback packages updated by a job execution."""
        from .package_service import PackageService

        history = self.db.query(JobHistory).filter(JobHistory.id == history_id).first()
        if not history:
            raise ValueError(f"Job history {history_id} not found")

        job = self.db.query(Job).filter(Job.id == history.job_id).first()
        # PRA-281: a scoped caller may only roll back a history whose job is fully
        # in scope; an out-of-scope/mixed-scope (or orphaned) history is
        # indistinguishable from a nonexistent one.
        if self.scope is not None and (not job or not self.is_job_visible(job)):
            raise JobNotFound(f"Job history {history_id} not found")
        if not job or job.job_type not in ("update", "security_update"):
            raise ValueError("Rollback only supported for update/security_update jobs")

        # Find all completed package operations from this job execution
        package_ops = (
            self.db.query(PackageHistory)
            .filter(
                PackageHistory.job_history_id == history_id,
                PackageHistory.status == "completed",
                PackageHistory.operation == "update",
                PackageHistory.old_version.isnot(None),
            )
            .all()
        )

        if not package_ops:
            raise ValueError(
                "No rollback-eligible package operations found for this job"
            )

        # Group by system: { system_id: [(package_name, old_version), ...] }
        by_system: Dict[int, List[tuple]] = {}
        for op in package_ops:
            pkg = self.db.query(Package).filter(Package.id == op.package_id).first()
            if not pkg:
                continue
            by_system.setdefault(op.system_id, []).append((pkg.name, op.old_version))

        # PRA-281 defense-in-depth: never partially roll back out-of-scope package
        # operations for a scoped caller. If the history touched any system now
        # outside scope (e.g. grants changed since the run), fail closed.
        if self.scope is not None and not set(by_system).issubset(self.scope):
            raise JobNotFound(f"Job history {history_id} not found")

        pkg_service = PackageService(self.db)
        results = []
        total_rolled_back = 0
        total_failed = 0

        for system_id, pkg_versions in by_system.items():
            system = self.db.query(System).filter(System.id == system_id).first()
            if not system:
                continue
            try:
                result = pkg_service.install_specific_versions(
                    system_id=system_id,
                    package_versions=pkg_versions,
                    user_id=user_id,
                )
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname,
                        "result": result,
                    }
                )
                if result.get("status") == "success":
                    total_rolled_back += result.get("packages_rolled_back", 0)
                else:
                    total_failed += 1
            except Exception as e:  # pylint: disable=broad-except
                logger.error("Rollback failed on system %d: %s", system_id, str(e))
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname,
                        "result": {"status": "error", "message": str(e)},
                    }
                )
                total_failed += 1

        # Create notification for rollback
        create_notification(
            self.db,
            type="job_rollback",
            title=f"Job '{job.name}' rolled back",
            message=(
                f"Rolled back {total_rolled_back} packages "
                f"across {len(by_system)} system(s)"
            ),
            severity="warning" if total_failed == 0 else "error",
            related_job_id=job.id,
            user_id=user_id,
        )

        return {
            "status": "success",
            "history_id": history_id,
            "job_id": job.id,
            "total_systems": len(by_system),
            "total_rolled_back": total_rolled_back,
            "total_failed": total_failed,
            "results": results,
        }

    def cancel_job_run(self, job_id: int) -> Dict[str, Any]:
        """Cancel a running job by job ID."""
        # PRA-281: enforce scope BEFORE any side effect — a scoped caller must not
        # be able to signal cancellation of an out-of-scope job. Out-of-scope →
        # non-disclosing not-found.
        job = self._get_visible_job_or_raise(job_id)

        # Signal the running thread to stop (PRA-77)
        with _running_jobs_lock:
            running = _running_jobs.get(job_id)

        if running:
            running["cancelled"].set()
            logger.info("Sent cancel signal for job %d", job_id)

        if job.status != "running":
            raise ValueError(f"Job '{job.name}' is not currently running")

        # Find and update the running history entry
        history = (
            self.db.query(JobHistory)
            .filter(
                JobHistory.job_id == job_id,
                JobHistory.status == "running",
            )
            .order_by(JobHistory.id.desc())
            .first()
        )

        if history:
            history.status = "cancelled"
            history.end_time = datetime.utcnow()
            history.error_message = "Cancelled by user"

        job.status = "scheduled" if job.is_recurring else "cancelled"

        # Create cancellation notification (PRA-78)
        create_notification(
            self.db,
            type="job_cancelled",
            title=f"Job '{job.name}' cancelled",
            message="Job was cancelled by user",
            severity="warning",
            related_job_id=job.id,
        )

        logger.info("Cancelled job %d: %s", job_id, job.name)

        result = {
            "status": "success",
            "message": f"Job '{job.name}' cancelled",
        }
        if history:
            result["history"] = self._history_to_dict(history)
        return result

    def get_job_history(
        self, job_id: int, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        """Get execution history for a specific job."""
        # PRA-281: out-of-scope job → non-disclosing not-found; a visible job's
        # histories are all for in-scope systems.
        self._get_visible_job_or_raise(job_id)

        total = self.db.query(JobHistory).filter(JobHistory.job_id == job_id).count()
        history = (
            self.db.query(JobHistory)
            .options(joinedload(JobHistory.job))
            .filter(JobHistory.job_id == job_id)
            .order_by(JobHistory.start_time.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "history": [self._history_to_dict(h) for h in history],
        }

    def get_all_history(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Get all job execution history with pagination."""
        query = self.db.query(JobHistory).options(joinedload(JobHistory.job))

        if self.scope is None:
            total = self.db.query(JobHistory).count()
            history = (
                query.order_by(JobHistory.start_time.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
        else:
            history, total = self._scoped_history_page(query, limit, offset)

        return {
            "status": "success",
            "total": total,
            "limit": limit,
            "offset": offset,
            "history": [self._history_to_dict(h) for h in history],
        }

    def _scoped_history_page(self, query, limit: int, offset: int):
        """PRA-281: order+filter a JobHistory query to histories whose job is
        visible in the caller's scope, then paginate. Histories whose job is
        deleted (unresolvable target) are hidden fail-closed. Returns
        ``(page_rows, visible_total)``."""
        ordered = query.order_by(JobHistory.start_time.desc()).all()
        job_cache: Dict[int, bool] = {}
        visible = []
        for h in ordered:
            jid = h.job_id
            if jid not in job_cache:
                job = h.job or self.db.query(Job).filter(Job.id == jid).first()
                job_cache[jid] = bool(job) and self.is_job_visible(job)
            if job_cache[jid]:
                visible.append(h)
        return visible[offset : offset + limit], len(visible)

    # --- PRA-81: Job chaining ---

    def _trigger_dependent_jobs(
        self, completed_job_id: int, completion_status: str, user_id: int
    ):
        """After a job completes, check for and trigger dependent jobs."""
        dependents = (
            self.db.query(Job)
            .filter(
                Job.depends_on_job_id == completed_job_id,
                Job.status.in_(["scheduled", "completed"]),
            )
            .all()
        )

        for dep_job in dependents:
            condition = dep_job.chain_condition or "on_success"
            should_run = False

            if condition == "on_complete":
                should_run = True
            elif condition == "on_success" and completion_status == "completed":
                should_run = True
            elif condition == "on_failure" and completion_status == "failed":
                should_run = True

            if should_run:
                logger.info(
                    "Chain trigger: job %d -> job %d (%s) [condition=%s, status=%s]",
                    completed_job_id,
                    dep_job.id,
                    dep_job.name,
                    condition,
                    completion_status,
                )
                try:
                    self.run_job(dep_job.id, user_id)
                except Exception as e:  # pylint: disable=broad-except
                    logger.error(
                        "Failed to trigger dependent job %d: %s",
                        dep_job.id,
                        str(e),
                    )
            else:
                logger.info(
                    "Chain skip: job %d condition '%s' not met (parent status=%s)",
                    dep_job.id,
                    condition,
                    completion_status,
                )

    def get_job_chains(self) -> List[Dict[str, Any]]:
        """Return all job chains (jobs with dependencies, shown as a tree)."""
        all_jobs = self.db.query(Job).all()
        if self.scope is not None:
            # PRA-281: drop jobs the caller cannot fully see; a child whose parent
            # is out of scope is handled as an orphan dependent by the logic below.
            all_jobs = [j for j in all_jobs if self.is_job_visible(j)]
        dep_ids = {
            j.depends_on_job_id for j in all_jobs if j.depends_on_job_id is not None
        }
        chain_job_ids = dep_ids | {
            j.id for j in all_jobs if j.depends_on_job_id is not None
        }

        if not chain_job_ids:
            return []

        chains = []
        visited = set()

        for job in all_jobs:
            if job.id in dep_ids and job.depends_on_job_id is None:
                if job.id not in visited:
                    chain = self._build_chain(job, all_jobs, visited)
                    chains.append(chain)

        # Also include orphan dependents (parent deleted)
        for job in all_jobs:
            if job.depends_on_job_id is not None and job.id not in visited:
                chains.append(
                    {
                        "id": job.id,
                        "name": job.name,
                        "status": job.status,
                        "chain_condition": job.chain_condition,
                        "depends_on_job_id": job.depends_on_job_id,
                        "children": [],
                    }
                )
                visited.add(job.id)

        # PRA-281: a visible orphan dependent whose parent was filtered out (hidden)
        # must not expose the hidden parent id. Null any depends_on_job_id that does
        # not reference a job in the visible set.
        if self.scope is not None:
            visible_ids = {j.id for j in all_jobs}
            for chain in chains:
                self._sanitize_chain_parents(chain, visible_ids)

        return chains

    def _sanitize_chain_parents(
        self, node: Dict[str, Any], visible_ids: Set[int]
    ) -> None:
        """Null ``depends_on_job_id`` on any chain node that references a job not in
        the visible set, so a hidden parent id never leaks (recurses children)."""
        if node.get("depends_on_job_id") not in visible_ids:
            node["depends_on_job_id"] = None
        for child in node.get("children", []):
            self._sanitize_chain_parents(child, visible_ids)

    def _build_chain(
        self, root: Job, all_jobs: List[Job], visited: set
    ) -> Dict[str, Any]:
        """Recursively build a chain tree from a root job."""
        visited.add(root.id)
        children = []
        for job in all_jobs:
            if job.depends_on_job_id == root.id and job.id not in visited:
                children.append(self._build_chain(job, all_jobs, visited))

        return {
            "id": root.id,
            "name": root.name,
            "status": root.status,
            "chain_condition": root.chain_condition,
            "depends_on_job_id": root.depends_on_job_id,
            "children": children,
        }
