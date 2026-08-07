"""Admin-only diagnostic support bundle endpoint (PRA-310)."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from ...core.auth import require_role
from ...db.models import User
from ...db.session import get_db
from ...services import audit_event_service
from ...services import diagnostics_service as diag

router = APIRouter(redirect_slashes=False)


@router.post("/bundle")
def generate_support_bundle(
    time_range: str = Query("72h"),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Generate and download a redacted diagnostic support bundle (admin-only).

    The bundle is bounded, compressed, deterministic, and built from a fixed set of DB
    summaries + the in-memory log buffer — it never reads a caller-supplied path, so
    it cannot stream arbitrary files. Secrets are redacted and config is allowlisted;
    generation is audited. ``time_range`` is a closed set (24h/72h/7d).

    Sync ``def`` (runs in the FastAPI threadpool, PRA-323): bundle generation does
    blocking DB work and now a bounded broker-logs HTTP fetch, none of which
    should run on the event loop."""
    if time_range not in diag.TIME_RANGES:
        raise HTTPException(
            status_code=400,
            detail=f"time_range must be one of {sorted(diag.TIME_RANGES)}",
        )

    try:
        data, manifest = diag.generate_bundle(db, current_user.id, time_range)
    except diag.DiagnosticsError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    audit_event_service.emit(
        db,
        action="support.bundle.generated",
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        target_kind="diagnostics",
        context={
            "time_range": time_range,
            "bytes": manifest["bytes"],
            "file_count": len(manifest["files"]),
        },
    )

    filename = f"praxis-support-bundle-{time_range}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Bundle-Bytes": str(manifest["bytes"]),
            "X-Bundle-Files": str(len(manifest["files"])),
        },
    )
