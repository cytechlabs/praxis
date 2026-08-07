"""
Maintenance window service for checking and managing maintenance windows (PRA-79).
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from ..db.models import Group, MaintenanceWindow, System

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PRA-281: maintenance-window fleet-scope visibility.
#
# A window targets a single system, a group (its active member systems), or the
# whole fleet ("all"). Visibility is a subset relationship: a scoped caller may
# see/operate a window only when its resolvable target systems are non-empty AND
# entirely in scope. ``target_type='all'`` is tenant-wide and hidden from scoped
# callers; a group with any out-of-scope (or no active) member fails closed.
# ---------------------------------------------------------------------------


def window_target_system_ids(
    db: Session, window: MaintenanceWindow
) -> Optional[Set[int]]:
    """Resolve a window's target systems. ``None`` means tenant-wide ('all')."""
    if window.target_type == "all":
        return None
    if window.target_type == "system":
        return {window.target_id} if window.target_id else set()
    if window.target_type == "group" and window.target_id:
        return {
            row[0]
            for row in db.query(System.id)
            .filter(
                System.group_id == window.target_id,
                System.status == "Active",
            )
            .all()
        }
    return set()


def window_visible_to_scope(
    db: Session, window: MaintenanceWindow, scope: Optional[Set[int]]
) -> bool:
    """Whether a maintenance window is visible/operable in the caller's scope.

    Admin (``scope is None``) → always. ``target_type='all'`` → hidden for scoped
    callers (tenant-wide). Otherwise the resolved target systems must be non-empty
    and entirely in scope (fail closed for out-of-scope/mixed/empty groups)."""
    if scope is None:
        return True
    ids = window_target_system_ids(db, window)
    if ids is None:  # tenant-wide 'all'
        return False
    return bool(ids) and ids.issubset(scope)


def _parse_schedule(schedule_json: str) -> Optional[Dict[str, Any]]:
    """Parse the schedule JSON string."""
    try:
        return (
            json.loads(schedule_json)
            if isinstance(schedule_json, str)
            else schedule_json
        )
    except (json.JSONDecodeError, TypeError):
        return None


def get_windows_for_system(db: Session, system_id: int) -> List[MaintenanceWindow]:
    """Return all applicable maintenance windows for a system."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        return []

    # Direct system match
    windows = (
        db.query(MaintenanceWindow)
        .filter(
            MaintenanceWindow.enabled.is_(True),
            MaintenanceWindow.target_type == "system",
            MaintenanceWindow.target_id == system_id,
        )
        .all()
    )

    # Group match
    if system.group_id:
        group_windows = (
            db.query(MaintenanceWindow)
            .filter(
                MaintenanceWindow.enabled.is_(True),
                MaintenanceWindow.target_type == "group",
                MaintenanceWindow.target_id == system.group_id,
            )
            .all()
        )
        windows.extend(group_windows)

    # "all" type match
    all_windows = (
        db.query(MaintenanceWindow)
        .filter(
            MaintenanceWindow.enabled.is_(True),
            MaintenanceWindow.target_type == "all",
        )
        .all()
    )
    windows.extend(all_windows)

    return windows


def is_in_maintenance_window(
    db: Session, system_id: int, check_time: Optional[datetime] = None
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Check if current time falls within any applicable window.

    Returns (is_in_window, window_details_or_None).
    """
    now = check_time or datetime.utcnow()
    windows = get_windows_for_system(db, system_id)

    for window in windows:
        schedule = _parse_schedule(window.schedule)
        if not schedule:
            continue

        day_of_week = schedule.get("day_of_week", [])
        start_time_str = schedule.get("start_time", "00:00")
        end_time_str = schedule.get("end_time", "00:00")

        # Current day of week (0=Monday in Python, convert: spec uses 0=Mon..6=Sun)
        current_dow = now.weekday()  # 0=Monday
        if current_dow not in day_of_week:
            continue

        # Parse start/end times
        try:
            start_h, start_m = map(int, start_time_str.split(":"))
            end_h, end_m = map(int, end_time_str.split(":"))
        except (ValueError, AttributeError):
            continue

        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        current_minutes = now.hour * 60 + now.minute

        # Handle overnight windows (e.g., 22:00 - 06:00)
        if start_minutes <= end_minutes:
            in_window = start_minutes <= current_minutes < end_minutes
        else:
            in_window = (
                current_minutes >= start_minutes or current_minutes < end_minutes
            )

        if in_window:
            return True, {
                "window_id": window.id,
                "window_name": window.name,
                "start_time": start_time_str,
                "end_time": end_time_str,
            }

    return False, None


def get_next_window(db: Session, system_id: int) -> Optional[Dict[str, Any]]:
    """Return the next upcoming maintenance window start time for a system."""
    now = datetime.utcnow()
    windows = get_windows_for_system(db, system_id)

    next_start = None
    next_window_info = None

    for window in windows:
        schedule = _parse_schedule(window.schedule)
        if not schedule:
            continue

        day_of_week = schedule.get("day_of_week", [])
        start_time_str = schedule.get("start_time", "00:00")

        try:
            start_h, start_m = map(int, start_time_str.split(":"))
        except (ValueError, AttributeError):
            continue

        # Check next 7 days
        for day_offset in range(8):
            candidate = now + timedelta(days=day_offset)
            candidate_dow = candidate.weekday()
            if candidate_dow not in day_of_week:
                continue

            candidate_start = candidate.replace(
                hour=start_h, minute=start_m, second=0, microsecond=0
            )
            if candidate_start <= now:
                continue

            if next_start is None or candidate_start < next_start:
                next_start = candidate_start
                next_window_info = {
                    "window_id": window.id,
                    "window_name": window.name,
                    "next_start": candidate_start.isoformat() + "Z",
                }
            break  # Found the next occurrence for this window

    return next_window_info


def get_upcoming_windows(
    db: Session, days: int = 7, scope_system_ids: Optional[Set[int]] = None
) -> List[Dict[str, Any]]:
    """Return all upcoming maintenance windows for the next N days.

    PRA-281: ``scope_system_ids`` (``None`` = tenant-wide admin) restricts the
    result to windows visible in the caller's fleet scope, and non-visible windows
    are skipped BEFORE their target hostname/group name is resolved."""
    now = datetime.utcnow()
    windows = (
        db.query(MaintenanceWindow).filter(MaintenanceWindow.enabled.is_(True)).all()
    )

    upcoming = []
    for window in windows:
        if scope_system_ids is not None and not window_visible_to_scope(
            db, window, scope_system_ids
        ):
            continue
        schedule = _parse_schedule(window.schedule)
        if not schedule:
            continue

        day_of_week = schedule.get("day_of_week", [])
        start_time_str = schedule.get("start_time", "00:00")
        end_time_str = schedule.get("end_time", "00:00")

        try:
            start_h, start_m = map(int, start_time_str.split(":"))
            end_h, end_m = map(int, end_time_str.split(":"))
        except (ValueError, AttributeError):
            continue

        # Resolve target name
        target_name = "All Systems"
        if window.target_type == "system" and window.target_id:
            system = db.query(System).filter(System.id == window.target_id).first()
            target_name = system.hostname if system else f"System #{window.target_id}"
        elif window.target_type == "group" and window.target_id:
            group = db.query(Group).filter(Group.id == window.target_id).first()
            target_name = group.name if group else f"Group #{window.target_id}"

        for day_offset in range(days + 1):
            candidate = now + timedelta(days=day_offset)
            candidate_dow = candidate.weekday()
            if candidate_dow not in day_of_week:
                continue

            start_dt = candidate.replace(
                hour=start_h, minute=start_m, second=0, microsecond=0
            )
            end_dt = candidate.replace(
                hour=end_h, minute=end_m, second=0, microsecond=0
            )
            if end_dt <= start_dt:
                end_dt += timedelta(days=1)

            if end_dt < now:
                continue

            upcoming.append(
                {
                    "window_id": window.id,
                    "window_name": window.name,
                    "target_type": window.target_type,
                    "target_name": target_name,
                    "start": start_dt.isoformat() + "Z",
                    "end": end_dt.isoformat() + "Z",
                }
            )

    upcoming.sort(key=lambda x: x["start"])
    return upcoming
