"""Airgap export/import API routes (PRA-160 slices #1 + #2 + #3).

Mounts at ``/airgap``. Surface:

  Export (slices #1 + #2):
    * ``POST /airgap/signing-key`` — idempotent ensure-active for
      the instance-wide bundle signing key.
    * ``POST /airgap/exports`` — synchronously builds the descriptor
      and schedules tar assembly via ``BackgroundTasks``.
    * ``GET /airgap/exports/{bundle_id}`` — poll export row state.

  Import (slice #3):
    * ``POST /airgap/import-trust`` — pin a bundle public key
      (admin only) for verifying ``bundle.json.sig`` at import time.
    * ``GET /airgap/import-trust`` — list active pins.
    * ``DELETE /airgap/import-trust/{key_id}`` — soft-delete a pin.
    * ``POST /airgap/imports`` — verify + ingest a bundle tar
      mounted under ``PRAXIS_AIRGAP_IMPORT_STAGING``. Schedules the
      heavy work via ``BackgroundTasks``.
    * ``GET /airgap/imports/{bundle_id}`` — poll import row state.

Route ordering note (``feedback_fastapi_route_ordering.md``): literal
sub-paths declared before parameterised routes so the wildcard match
doesn't swallow them.

PRA-160 design lock: planner / importer refusals return a flat 422
body ``{code, message, context}`` — not nested under
``detail``.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.schemas.airgap import (
    BundleSigningKeyBootstrapResponse,
    BundleSigningKeyRead,
    BundleSigningKeyRotateResponse,
    ExportRequest,
    ExportResponse,
    ImportRequest,
    ImportResponse,
    ImportTrustKeyCreate,
    ImportTrustKeyRead,
)
from app.core.auth import get_current_user, require_role
from app.db.models import AirgapBundle, AirgapImport
from app.db.session import get_db
from app.services.access_authorization_service import scoped_system_ids
from app.services.airgap.import_trust_service import (
    ImportTrustKeyExists,
    ImportTrustKeyService,
)
from app.services.airgap.importer import ImporterRefusal
from app.services.airgap.orchestrator import (
    AirgapExportOrchestrator,
    run_build_in_background,
)
from app.services.airgap.planner import PlannerRefusal
from app.services.airgap.signing_key_service import (
    AirgapBundleSigningKeyService,
    NoActiveKeyToRotate,
    RetireActiveKeyRefused,
    SigningKeyNotFound,
)
from app.services.audit_event_service import safe_emit

logger = logging.getLogger(__name__)


def _require_tenant_wide_admin(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """PRA-281: airgap bundle signing keys, export/import rows, import-trust
    pins, local bundle/tar/descriptor paths, payload hashes, byte counts, and
    build/import errors are instance-wide OPERATIONAL state — none of it is
    attributable to a single ``system_id``, so a scoped caller cannot be given a
    robust per-fleet view. The whole airgap surface is therefore tenant-wide-
    admin-only: a scoped caller (``scoped_system_ids(...) is not None``) is
    refused with 403 as a router-level dependency, BEFORE any route body runs —
    so no service call, descriptor planning, GPG/Vault/key work, row lookup,
    row create/update, background task, file-path validation, import preflight,
    or audit emission happens. App-admins (scope ``None``) are unchanged.
    """
    if scoped_system_ids(db, current_user) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Airgap operations require tenant-wide admin access",
        )


router = APIRouter(
    redirect_slashes=False,
    tags=["airgap"],
    dependencies=[Depends(_require_tenant_wide_admin)],
)


def _actor_id(current_user) -> Optional[int]:
    return getattr(current_user, "id", None) if current_user is not None else None


# ---------------------------------------------------------------------------
# Signing-key bootstrap
# ---------------------------------------------------------------------------


@router.post(
    "/signing-key",
    response_model=BundleSigningKeyBootstrapResponse,
    status_code=status.HTTP_200_OK,
)
async def ensure_signing_key(
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Idempotent ensure-active for the bundle signing key.

    First call generates and stores the key. Subsequent calls return
    the existing active key. ``created`` in the response distinguishes
    the two so an operator script can reason about whether a new key
    was just generated.
    """
    service = AirgapBundleSigningKeyService(db)
    pre_existing = service.get_active()
    key = service.ensure_active()
    created = pre_existing is None
    if created:
        # PRA-196: audit the initial bootstrap. No armored key / Vault path /
        # private material in context — fingerprint + uid + status only.
        safe_emit(
            db=db,
            action="airgap.signing_key.created",
            actor_user_id=_actor_id(current_user),
            target_kind="airgap_signing_key",
            target_id=key.gpg_fingerprint,
            context={
                "key_id": key.id,
                "fingerprint": key.gpg_fingerprint,
                "key_uid": key.key_uid,
                "status": key.status,
            },
        )
    return BundleSigningKeyBootstrapResponse(
        fingerprint=key.gpg_fingerprint,
        key_uid=key.key_uid,
        status=key.status,
        created=created,
    )


def _signing_key_to_read(
    service: AirgapBundleSigningKeyService, key
) -> BundleSigningKeyRead:
    return BundleSigningKeyRead(
        id=key.id,
        fingerprint=key.gpg_fingerprint,
        key_uid=key.key_uid,
        status=key.status,
        armored_public_key=service.get_public_armored(key),
        created_at=key.created_at,
        updated_at=key.updated_at,
    )


@router.get(
    "/signing-keys",
    response_model=List[BundleSigningKeyRead],
)
async def list_signing_keys(
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """List all bundle signing keys (active, rotating-out, retired).

    Includes the armored public key for each so an operator can distribute the
    current and rotating-out public keys to import-side instances. Private
    material and Vault paths are never returned.
    """
    service = AirgapBundleSigningKeyService(db)
    return [_signing_key_to_read(service, k) for k in service.list_keys()]


@router.post(
    "/signing-keys/rotate",
    response_model=BundleSigningKeyRotateResponse,
    status_code=status.HTTP_200_OK,
)
async def rotate_signing_key(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """Rotate the active bundle signing key (admin-only, PRA-196).

    Demotes the current active key to ``rotating_out`` (still valid for
    verifying already-exported bundles) and generates a fresh active key.
    Bundles produced after this call are signed by the new key, so the
    import-side instance must pin the new public key before importing them.
    """
    service = AirgapBundleSigningKeyService(db)
    try:
        old_key, new_key = service.rotate()
    except NoActiveKeyToRotate as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    safe_emit(
        db=db,
        action="airgap.signing_key.rotated",
        actor_user_id=_actor_id(current_user),
        target_kind="airgap_signing_key",
        target_id=new_key.gpg_fingerprint,
        context={
            "old_key_id": old_key.id,
            "old_fingerprint": old_key.gpg_fingerprint,
            "old_status": old_key.status,
            "new_key_id": new_key.id,
            "new_fingerprint": new_key.gpg_fingerprint,
            "new_status": new_key.status,
        },
    )
    return BundleSigningKeyRotateResponse(
        old=_signing_key_to_read(service, old_key),
        new=_signing_key_to_read(service, new_key),
    )


@router.post(
    "/signing-keys/{key_id}/retire",
    response_model=BundleSigningKeyRead,
    status_code=status.HTTP_200_OK,
)
async def retire_signing_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),
) -> Any:
    """Retire a rotating-out bundle signing key (admin-only, PRA-196).

    Refuses to retire the active key (rotate first). Idempotent on an
    already-retired key.
    """
    service = AirgapBundleSigningKeyService(db)
    existing = service.get(key_id)
    already_retired = existing is not None and existing.status == "retired"
    try:
        key = service.retire(key_id)
    except SigningKeyNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except RetireActiveKeyRefused as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    if not already_retired:
        safe_emit(
            db=db,
            action="airgap.signing_key.retired",
            actor_user_id=_actor_id(current_user),
            target_kind="airgap_signing_key",
            target_id=key.gpg_fingerprint,
            context={
                "key_id": key.id,
                "fingerprint": key.gpg_fingerprint,
                "status": key.status,
            },
        )
    return _signing_key_to_read(service, key)


# ---------------------------------------------------------------------------
# Export — slice #1 ships descriptor-only build
# ---------------------------------------------------------------------------


@router.post(
    "/exports",
    response_model=ExportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_export(
    body: ExportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Plan + sign the bundle descriptor, then schedule tar assembly.

    The descriptor build runs synchronously in the request lifetime
    (it's a small, fast operation) and returns
    ``status='descriptor_ready'``. The tar assembly is scheduled via
    ``BackgroundTasks``; the operator polls
    ``GET /airgap/exports/{bundle_id}`` to observe the
    ``descriptor_ready → building → ok`` (or ``failed``) transition.

    Mirrors PRA-157's ``POST /mirrors/{id}/sync`` async-build pattern.
    """
    orchestrator = AirgapExportOrchestrator(db)
    actor_user_id = _actor_id(current_user)
    try:
        row = orchestrator.create_descriptor_export(
            profile_slugs=body.profile_slugs,
            snapshot_selector_base=body.snapshot_selector.base,
            snapshot_overrides=body.snapshot_selector.overrides,
            kind=body.kind,
            parent_bundle_id=body.parent_bundle_id,
            actor_user_id=actor_user_id,
        )
    except PlannerRefusal as exc:
        # Flat body, not nested under ``detail``.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "code": exc.code,
                "message": str(exc),
                "context": exc.context,
            },
        )

    # Schedule the tar build. ``BackgroundTasks`` runs after the
    # response is sent; the task opens its own session and walks
    # the row from ``descriptor_ready`` → ``ok`` (or ``failed``).
    background_tasks.add_task(run_build_in_background, row.bundle_id, actor_user_id)

    return _row_to_response(row)


@router.get(
    "/exports/{bundle_id}",
    response_model=ExportResponse,
)
async def get_export(
    bundle_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Return the current row state for ``bundle_id``.

    Operator/CLI poll target. Returns 404 if the bundle id is
    unknown. Returns ``status`` ∈
    ``descriptor_ready | building | ok | failed`` plus the bytes
    + path columns once they're populated.
    """
    row = (
        db.query(AirgapBundle).filter(AirgapBundle.bundle_id == bundle_id).one_or_none()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"airgap bundle bundle_id={bundle_id!r} not found",
        )
    return _row_to_response(row)


def _row_to_response(row: AirgapBundle) -> ExportResponse:
    return ExportResponse(
        bundle_id=row.bundle_id,
        kind=row.kind,
        status=row.status,
        bundle_descriptor_path=row.bundle_descriptor_path,
        bundle_path=row.bundle_path,
        payload_sha256=row.payload_sha256,
        byte_count=row.byte_count,
        error_text=row.error_text,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


# ---------------------------------------------------------------------------
# Slice #3: import trust keys
# ---------------------------------------------------------------------------


@router.post(
    "/import-trust",
    response_model=ImportTrustKeyRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_import_trust_key(
    body: ImportTrustKeyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),  # pylint: disable=unused-argument
) -> Any:
    """Pin a bundle public key for the import path (admin-only).

    The service derives the fingerprint via gpg --import + --list-keys
    so we never trust an operator-supplied fingerprint string. Active
    fingerprint uniqueness is DB-enforced via a partial unique index.
    """
    service = ImportTrustKeyService(db)
    try:
        row = service.add_armored_public_key(body.armored_public_key)
    except ImportTrustKeyExists as exc:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "code": "trust_key_exists",
                "message": str(exc),
            },
        )
    # PRA-196: audit the pin. Armored key body is never placed in context.
    safe_emit(
        db=db,
        action="airgap.import_trust.added",
        actor_user_id=_actor_id(current_user),
        target_kind="airgap_import_trust",
        target_id=row.gpg_fingerprint,
        context={
            "key_id": row.id,
            "fingerprint": row.gpg_fingerprint,
            "key_uid": row.key_uid,
        },
    )
    return _trust_key_to_read(row)


@router.get(
    "/import-trust",
    response_model=List[ImportTrustKeyRead],
)
async def list_import_trust_keys(
    db: Session = Depends(get_db),
    include_deleted: bool = False,
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """List active (or all, with ``?include_deleted=true``) trust pins."""
    service = ImportTrustKeyService(db)
    rows = service.list_all() if include_deleted else service.list_active()
    return [_trust_key_to_read(r) for r in rows]


@router.delete(
    "/import-trust/{key_id}",
    response_model=ImportTrustKeyRead,
)
async def delete_import_trust_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin")),  # pylint: disable=unused-argument
) -> Any:
    """Soft-delete a trust pin (admin-only). Idempotent on
    already-deleted rows."""
    service = ImportTrustKeyService(db)
    existing = service.get(key_id)
    already_deleted = existing is not None and existing.deleted_at is not None
    try:
        row = service.soft_delete(key_id)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    # PRA-196: audit only a real removal, so an idempotent re-delete of an
    # already-removed pin doesn't emit a duplicate event.
    if not already_deleted:
        safe_emit(
            db=db,
            action="airgap.import_trust.removed",
            actor_user_id=_actor_id(current_user),
            target_kind="airgap_import_trust",
            target_id=row.gpg_fingerprint,
            context={
                "key_id": row.id,
                "fingerprint": row.gpg_fingerprint,
                "key_uid": row.key_uid,
            },
        )
    return _trust_key_to_read(row)


def _trust_key_to_read(row) -> ImportTrustKeyRead:
    return ImportTrustKeyRead(
        id=row.id,
        gpg_fingerprint=row.gpg_fingerprint,
        key_uid=row.key_uid,
        added_at=row.added_at,
        deleted_at=row.deleted_at,
    )


# ---------------------------------------------------------------------------
# Slice #3: imports
# ---------------------------------------------------------------------------


@router.post(
    "/imports",
    response_model=ImportResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_import(
    body: ImportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Verify + ingest a bundle tar mounted at ``body.path``.

    The verify step (small descriptor read + sig check) runs
    synchronously to give the operator immediate feedback on
    ``bundle_already_imported`` / ``tar_path_outside_staging``
    style refusals. The heavy verify+ingest work runs in
    ``BackgroundTasks``; the operator polls
    ``GET /airgap/imports/{bundle_id}`` for the
    ``verifying → extracting → ok | failed`` transitions.

    Path-resolved tar must live under
    ``PRAXIS_AIRGAP_IMPORT_STAGING`` (or whatever the env var
    points at). Symlinks are followed during resolution; an
    escaping symlink is refused with
    ``tar_path_outside_staging``.
    """
    actor_user_id = _actor_id(current_user)
    # The synchronous pre-flight creates/reuses the
    # ``airgap_imports`` row at status='verifying' so an immediate
    # GET poll sees real state, not a synthesized placeholder.
    # The shared ``pre_flight_check`` runs path safety + descriptor
    # sniff + structural validation + idempotency + row create.
    # The BG runner reloads the row by bundle_id and runs only the
    # heavy verify+ingest.
    from app.services.airgap.importer import (  # pylint: disable=import-outside-toplevel
        AirgapImportOrchestrator,
        run_execute_in_background,
    )

    orchestrator = AirgapImportOrchestrator(db)
    try:
        row = orchestrator.pre_flight_check(
            path=body.path, force=body.force, actor_user_id=actor_user_id
        )
    except ImporterRefusal as exc:
        # Map idempotency-style refusals to 409, the rest to 422.
        is_conflict = exc.code in ("bundle_already_imported",)
        return JSONResponse(
            status_code=(
                status.HTTP_409_CONFLICT
                if is_conflict
                else status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            content={
                "code": exc.code,
                "message": str(exc),
                "context": exc.context,
            },
        )

    # Schedule the heavy work. The BG runner reloads the row by
    # bundle_id and runs verify + ingest.
    background_tasks.add_task(run_execute_in_background, row.bundle_id, actor_user_id)
    return _import_row_to_response(row)


@router.get(
    "/imports/{bundle_id}",
    response_model=ImportResponse,
)
async def get_import(
    bundle_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Return the current row state for an import bundle_id.

    Operator/CLI poll target. 404 if the bundle id is unknown."""
    row = (
        db.query(AirgapImport).filter(AirgapImport.bundle_id == bundle_id).one_or_none()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"airgap import bundle_id={bundle_id!r} not found",
        )
    return _import_row_to_response(row)


def _import_row_to_response(row: AirgapImport) -> ImportResponse:
    return ImportResponse(
        bundle_id=row.bundle_id,
        kind=row.kind,
        status=row.status,
        path=row.path,
        payload_sha256=row.payload_sha256,
        byte_count=row.byte_count,
        target_mirror_slugs=list(row.target_mirror_slugs or []),
        error_text=row.error_text,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def _utcnow():
    from datetime import datetime  # pylint: disable=import-outside-toplevel

    return datetime.utcnow()
