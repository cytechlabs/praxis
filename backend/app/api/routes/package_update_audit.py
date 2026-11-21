"""Audit recording and access gates for ad-hoc package updates.

``POST /packages/{system_id}/update`` and ``POST /packages/bulk/update`` own the
``package.update`` audit event. The service layer stays event-free so scheduled
jobs and plan executions, which reach it directly, never record a second one.
"""

from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends, HTTPException, Path, Request
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, get_user_roles
from ...core.redaction import redact_text
from ...db.models import System, User
from ...db.session import get_db
from ...services.access_authorization_service import user_can_access_system
from ...services.audit_event_service import safe_emit

# Bounds for the audit context of an ad-hoc package update. Package names are
# validated at the request boundary, so the list is capped only to keep one
# event small, and the failure reason is redacted and capped because it carries
# package-manager output from the host.
_AUDIT_PACKAGE_NAMES_MAX = 50
_AUDIT_REASON_MAX = 512


def classify_package_update(
    result: Dict[str, Any],
) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Classify a ``PackageService.apply_updates`` result into an audit outcome.

    Returns ``(outcome, context_fields)``, or ``None`` when the request did no
    work and therefore owns no event: a request that lost the per-host
    single-flight leaves the one outcome to the request already running.

    The outcome follows what verification proved, not the transport exit code.
    Only a run whose attempted packages all moved to their new version is a
    success, and a version change the history had no row for still counts as an
    update because it is read from the before and after host readings. A run with
    some packages unmoved is ``partial``, including when the version change that
    was verified is one the history had no row for. A request with nothing to
    apply is a ``no_change`` only when the host was left alone or the readings
    taken before and after the command prove nothing moved; when either reading
    is missing the result is ``unverified`` and is never reported as a success.

    A count the service did not measure is ``None`` rather than ``0``: a command
    that exited nonzero says nothing reliable about how many packages changed.
    """
    status = result.get("status")
    if status == "already_running":
        return None

    def _count(key: str) -> Optional[int]:
        value = result.get(key)
        return int(value) if value is not None else None

    if status != "success":
        reason = redact_text(str(result.get("message") or "Update failed"))
        return "failure", {
            "result": "failed",
            "packages_updated": None,
            "packages_skipped": _count("packages_skipped"),
            "packages_failed": _count("packages_failed"),
            "packages_unrecorded": None,
            "reason": reason[:_AUDIT_REASON_MAX],
        }

    failed = _count("packages_failed")
    base: Dict[str, Any] = {"packages_skipped": _count("packages_skipped") or 0}

    if result.get("verification") == "unavailable":
        # Host evidence from this operation was missing, so no version outcome
        # is asserted: counts that need it stay unknown rather than zero.
        return "failure", {
            **base,
            "result": "unverified",
            "packages_updated": None,
            "packages_failed": failed,
            "packages_unrecorded": None,
        }

    updated = _count("packages_updated") or 0
    unrecorded = _count("packages_unrecorded") or 0
    fields: Dict[str, Any] = {
        **base,
        "packages_updated": updated,
        "packages_failed": failed or 0,
        "packages_unrecorded": unrecorded,
    }

    if (failed or 0) > 0:
        # A verified change next to a tracked failure is a partial result.
        fields["result"] = "partial" if updated + unrecorded > 0 else "failed"
        return "failure", fields
    if updated + unrecorded > 0:
        fields["result"] = "updated"
        return "success", fields
    fields["result"] = "no_change"
    return "success", fields


def emit_package_update(
    db: Session,
    request: Request,
    user: User,
    result: Dict[str, Any],
    system_id: int,
    package_names: Optional[List[str]],
) -> None:
    """Persist the ``package.update`` audit event for one host.

    The route owns the event so that scheduled jobs and plan executions, which
    reach ``PackageService`` directly, never record a second one. Emission is
    best effort in the same way as command execution: the update has already
    happened on the host and its history is committed, so an audit store fault
    is logged by ``safe_emit`` rather than reported as a failed update.
    """
    classified = classify_package_update(result)
    if classified is None:
        return
    outcome, fields = classified
    names = list(package_names) if package_names else None
    context: Dict[str, Any] = {
        "hostname": result.get("hostname"),
        "package_names": names[:_AUDIT_PACKAGE_NAMES_MAX] if names else None,
        "package_count": len(names) if names else 0,
        **fields,
    }
    safe_emit(
        db=db,
        action="package.update",
        outcome=outcome,
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=request.client.host if request.client else None,
        target_system_id=system_id,
        target_kind="system",
        target_id=str(system_id),
        context=context,
    )


_UPDATE_ROLES = ("admin", "maintainer")
_AUDIT_DENIED_SYSTEMS_MAX = 50


def emit_package_update_denial(
    db: Session,
    request: Request,
    user: User,
    *,
    code: str,
    reason: str,
    system_id: Optional[int] = None,
    system_ids: Optional[List[int]] = None,
) -> None:
    """Persist a ``denied`` ``package.update`` event for an authenticated caller.

    The response the caller receives is decided before this runs and is not
    changed by it. Hosts are attributed only when they exist, so a probe of an
    unknown id leaves the requested id in ``target.id`` without a host link, and
    the context never carries a hostname the caller could not have learned.
    """
    requested = [system_id] if system_id is not None else list(system_ids or [])
    existing = {
        sid for (sid,) in db.query(System.id).filter(System.id.in_(requested)).all()
    }
    context: Dict[str, Any] = {"reason_code": code, "reason": reason}
    kwargs: Dict[str, Any] = {}
    if system_id is not None:
        kwargs["target_system_id"] = system_id if system_id in existing else None
        kwargs["target_kind"] = "system"
        kwargs["target_id"] = str(system_id)
    elif requested:
        context["system_ids"] = requested[:_AUDIT_DENIED_SYSTEMS_MAX]
        context["system_count"] = len(requested)
        kwargs["related_system_ids"] = sorted(existing)
    safe_emit(
        db=db,
        action="package.update",
        outcome="denied",
        actor_user_id=user.id,
        actor_username=user.username,
        actor_ip=request.client.host if request.client else None,
        context=context,
        **kwargs,
    )


def _has_update_role(user: User) -> bool:
    return any(role in _UPDATE_ROLES for role in get_user_roles(user))


def update_gate(
    request: Request,
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Fleet scope then role gate for ``POST /{system_id}/update``.

    Same checks, order and responses as ``require_system_access()`` followed by
    ``require_role("admin", "maintainer")``: an out-of-scope caller gets the
    non-disclosing 404 before the role is considered, and an in-scope caller
    without the role gets 403. Each refusal is recorded before it is raised.
    """
    if not user_can_access_system(db, current_user, system_id):
        emit_package_update_denial(
            db,
            request,
            current_user,
            code="system_not_in_scope",
            reason="Caller has no fleet scope on the target system",
            system_id=system_id,
        )
        raise HTTPException(status_code=404, detail="System not found")
    if not _has_update_role(current_user):
        emit_package_update_denial(
            db,
            request,
            current_user,
            code="role_not_permitted",
            reason="Caller lacks the role required to apply package updates",
            system_id=system_id,
        )
        raise HTTPException(
            status_code=403, detail=f"Requires one of: {', '.join(_UPDATE_ROLES)}"
        )
    return current_user


def bulk_update_gate(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Role gate for ``POST /bulk/update``, as ``require_role`` with a record.

    The request names no single host at this point, so a role refusal is not
    attributed to one.
    """
    if not _has_update_role(current_user):
        emit_package_update_denial(
            db,
            request,
            current_user,
            code="role_not_permitted",
            reason="Caller lacks the role required to apply package updates",
        )
        raise HTTPException(
            status_code=403, detail=f"Requires one of: {', '.join(_UPDATE_ROLES)}"
        )
    return current_user


def record_bulk_scope_denial(
    db: Session, request: Request, user: User, system_ids: List[int]
) -> None:
    """Record one denial naming every requested host the caller has no scope on.

    Does nothing when the whole request is in scope. The caller still raises the
    non-disclosing refusal, so the response never says which ids were refused.
    """
    denied = [sid for sid in system_ids if not user_can_access_system(db, user, sid)]
    if denied:
        emit_package_update_denial(
            db,
            request,
            user,
            code="system_not_in_scope",
            reason="Caller has no fleet scope on one or more target systems",
            system_ids=denied,
        )
