"""Mirror engine API routes (PRA-157 #2b).

Surface:

  * ``POST /mirrors`` — create
  * ``GET /mirrors`` — list (excludes soft-deleted)
  * ``POST /mirrors/{id}/sync`` — on-demand sync (BackgroundTasks)
  * ``GET /mirrors/{id}/runs`` — paginated sync history
  * ``GET /mirrors/{id}/runs/{run_id}/manifest`` — manifest JSON
  * ``GET /mirrors/{id}`` — detail
  * ``PATCH /mirrors/{id}`` — update (slug immutable)
  * ``DELETE /mirrors/{id}`` — soft-delete (``deleted_at = now``)

Route ordering note (``feedback_fastapi_route_ordering.md``): literal
sub-paths and parameterised sub-resources MUST be declared before the
``/{id}`` detail route, otherwise FastAPI's wildcard match swallows
them and returns 422.

DELETE is soft-only — the on-disk byte tree under ``mirror_data``
stays put. PRA-160 / a future maintenance job owns async byte
cleanup. Soft-deleted mirrors are excluded from list, refuse on-
demand sync, and the scheduler's ``sweep_eligible_mirrors_query`` skips them.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.schemas.mirrors import (
    CutoverBlockedResponse,
    CutoverPreviewResponse,
    CutoverRequest,
    InstallTrustRequest,
    InstallTrustResponse,
    MirrorRepoCreate,
    MirrorRepoRead,
    MirrorRepoUpdate,
    MirrorSignCurrentQueuedResponse,
    MirrorSigningKeyBootstrapResponse,
    MirrorSigningKeyDetail,
    MirrorSyncQueuedResponse,
    MirrorSyncRunRead,
    TrustBundleResponse,
)
from app.core.auth import get_current_user, require_role
from app.db.models import MirrorRepo, MirrorSigningKey, MirrorSyncRun, System
from app.db.session import get_db
from app.services.access_authorization_service import scoped_system_ids
from app.services.broker_client import BrokerClient
from app.services.mirror_host_trust import install_mirror_trust_on_host
from app.services.mirror_sign_current import claim_and_sign_current
from app.services.mirror_signing_key_service import (
    CutoverBlocked,
    MirrorSigningKeyService,
    RotationError,
    RotationNotFound,
)
from app.services.mirror_sweep import claim_and_sync_one_mirror
from app.services.ssh_service import SSHService
from app.services.transport.factory import get_transport

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mirrors"])


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _decode_string_list(raw: str | None) -> List[str]:
    if raw is None or raw == "":
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        logger.warning("mirror row has malformed JSON-array column: %r", raw[:200])
        return []
    if not isinstance(decoded, list):
        return []
    return [item for item in decoded if isinstance(item, str)]


def _encode_string_list(values: List[str]) -> str:
    return json.dumps(values, separators=(",", ":"))


def _compute_signing_status(db: Session, mirror: MirrorRepo) -> str:
    """Derive the UI ``signing_status`` badge value (PRA-158 #5c).

    Locked vocabulary: no_key_yet, key_ready, rotation_in_progress,
    signed_ok, signing_failed, upstream_invalid. Three short queries
    per mirror — fine at typical fleet sizes (few mirrors per
    install). Bulk-friendly optimization is a future concern.

    Order of precedence:
      1. pending_cutover key present → rotation_in_progress (operator
         is mid-rotation; everything else is secondary).
      2. no active key → no_key_yet.
      3. otherwise look at the most recent run row to discriminate
         signed_ok / signing_failed / upstream_invalid / key_ready.
    """
    pending = (
        db.query(MirrorSigningKey)
        .filter(
            MirrorSigningKey.mirror_repo_id == mirror.id,
            MirrorSigningKey.status == "pending_cutover",
        )
        .first()
    )
    if pending is not None:
        return "rotation_in_progress"

    active = (
        db.query(MirrorSigningKey)
        .filter(
            MirrorSigningKey.mirror_repo_id == mirror.id,
            MirrorSigningKey.status == "active",
        )
        .first()
    )
    if active is None:
        return "no_key_yet"

    last_run = (
        db.query(MirrorSyncRun)
        .filter(MirrorSyncRun.mirror_repo_id == mirror.id)
        .order_by(MirrorSyncRun.started_at.desc())
        .first()
    )

    if last_run is None:
        return "key_ready"

    # Status-first discrimination: real PRA-158 failure
    # paths generally don't set signed_with_key_id — upstream-verify
    # fails BEFORE signing, and signing/promote failures call
    # _finalize_failed without copying signed_with_key_id onto the
    # run. Classifying failed runs first surfaces the actionable
    # badge; falling through to the NULL-key bootstrap rule would
    # hide them as "key_ready".
    if last_run.status == "failed":
        if "upstream signature invalid" in (last_run.error_text or ""):
            return "upstream_invalid"
        return "signing_failed"

    if last_run.status == "ok":
        # ok rows that predate slice #2c (signed_with_key_id NULL) are
        # bootstrap state, not signed_ok — treating them as signed
        # would falsely advertise trust on pre-#2c manifests.
        if last_run.signed_with_key_id is None:
            return "key_ready"
        return "signed_ok"

    # status='running' or any future status: surface key_ready until
    # the run finalizes.
    return "key_ready"


def _to_read(mirror: MirrorRepo, db: Optional[Session] = None) -> dict:
    return {
        "id": mirror.id,
        "slug": mirror.slug,
        "display_name": mirror.display_name,
        "package_family": mirror.package_family,
        "upstream_url": mirror.upstream_url,
        "distribution": mirror.distribution,
        "components": _decode_string_list(mirror.components),
        "architectures": _decode_string_list(mirror.architectures),
        "sync_schedule_cron": mirror.sync_schedule_cron,
        "enabled": mirror.enabled,
        "source_mode": mirror.source_mode,
        "verify_upstream_signature": mirror.verify_upstream_signature,
        "retention_keep_count": mirror.retention_keep_count,
        "retention_keep_within_days": mirror.retention_keep_within_days,
        "disk_budget_bytes": mirror.disk_budget_bytes,
        "last_sync_started_at": mirror.last_sync_started_at,
        "last_sync_finished_at": mirror.last_sync_finished_at,
        "last_sync_status": mirror.last_sync_status,
        "last_sync_error": mirror.last_sync_error,
        "current_disk_bytes": mirror.current_disk_bytes,
        "deleted_at": mirror.deleted_at,
        "created_at": mirror.created_at,
        "updated_at": mirror.updated_at,
        "signing_status": (
            _compute_signing_status(db, mirror) if db is not None else "no_key_yet"
        ),
    }


def _run_to_read(run: MirrorSyncRun) -> dict:
    return {
        "id": run.id,
        "mirror_repo_id": run.mirror_repo_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "run_kind": run.run_kind,
        "manifest_signature_path": run.manifest_signature_path,
        "signed_with_key_id": run.signed_with_key_id,
        "byte_count": run.byte_count,
        "package_count": run.package_count,
        "manifest_sha256": run.manifest_sha256,
        "manifest_path": run.manifest_path,
        "error_text": run.error_text,
        "estimate_unavailable": run.estimate_unavailable,
        "created_at": run.created_at,
    }


def _live_or_404(db: Session, mirror_id: int) -> MirrorRepo:
    """Look up a mirror by id, excluding soft-deleted rows. 404 if
    not found OR soft-deleted — caller should not be able to
    distinguish "never existed" from "was deleted" through the API.
    """
    mirror = (
        db.query(MirrorRepo)
        .filter(MirrorRepo.id == mirror_id, MirrorRepo.deleted_at.is_(None))
        .first()
    )
    if mirror is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mirror {mirror_id} not found",
        )
    return mirror


# ---------------------------------------------------------------------------
# CRUD — list / create at the collection root
# ---------------------------------------------------------------------------


@router.post("", response_model=MirrorRepoRead, status_code=status.HTTP_201_CREATED)
async def create_mirror(
    body: MirrorRepoCreate,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    existing = db.query(MirrorRepo).filter(MirrorRepo.slug == body.slug).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mirror with slug '{body.slug}' already exists",
        )

    mirror = MirrorRepo(
        slug=body.slug,
        display_name=body.display_name,
        package_family=body.package_family,
        upstream_url=body.upstream_url,
        distribution=body.distribution,
        components=_encode_string_list(body.components or []),
        architectures=_encode_string_list(body.architectures),
        sync_schedule_cron=body.sync_schedule_cron,
        enabled=body.enabled,
        source_mode=body.source_mode,
        verify_upstream_signature=body.verify_upstream_signature,
        retention_keep_count=body.retention_keep_count,
        retention_keep_within_days=body.retention_keep_within_days,
        disk_budget_bytes=body.disk_budget_bytes,
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(mirror)
    db.commit()
    db.refresh(mirror)
    logger.info("Created mirror %s (id=%d)", mirror.slug, mirror.id)
    return _to_read(mirror, db)


@router.get("", response_model=List[MirrorRepoRead])
async def list_mirrors(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    mirrors = (
        db.query(MirrorRepo)
        .filter(MirrorRepo.deleted_at.is_(None))
        .order_by(MirrorRepo.slug)
        .all()
    )
    return [_to_read(m, db) for m in mirrors]


# ---------------------------------------------------------------------------
# Sub-resources (ordered BEFORE /{id} to avoid wildcard shadowing)
# ---------------------------------------------------------------------------


@router.post(
    "/{mirror_id}/sync",
    response_model=MirrorSyncQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_on_demand_sync(
    mirror_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    mirror = _live_or_404(db, mirror_id)

    if mirror.source_mode == "imported_offline":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Mirror '{mirror.slug}' is in source_mode='imported_offline' "
                "and does not pull from upstream. On-demand sync is refused."
            ),
        )
    if not mirror.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Mirror '{mirror.slug}' is disabled. Enable it via PATCH "
                "before triggering a sync."
            ),
        )
    if mirror.last_sync_status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Mirror '{mirror.slug}' has a sync in progress. Wait for "
                "it to finish, or check /runs for the current run."
            ),
        )

    slug = mirror.slug
    background_tasks.add_task(claim_and_sync_one_mirror, mirror_id, slug)
    return {
        "mirror_repo_id": mirror_id,
        "queued": True,
        "message": (
            f"Sync queued for '{slug}'. The advisory lock decides whether "
            "this dispatch wins or another worker is already syncing; "
            "poll GET /mirrors/{id}/runs to observe."
        ),
    }


@router.post(
    "/{mirror_id}/sign-current",
    response_model=MirrorSignCurrentQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_sign_current(
    mirror_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Sign whatever is currently in the mirror's ``live/`` tree
    (PRA-158 #2c).

    Distinct from ``POST /sync`` because:

      * Works for ``imported_offline`` mirrors (which refuse /sync).
      * Works on pre-PRA-158 trees that are already published but
        unsigned.
      * Does NOT pull from upstream; only signs the existing bytes.

    Inserts a ``mirror_sync_runs`` row with ``run_kind='sign_only'``
    and finalizes it via the same per-mirror advisory lock the sync
    path uses, so a sign-current and a real sync can never race.

    Refuses if a sync is already running for this mirror — wait for
    the sync to complete (which itself signs the new tree) instead of
    queueing a sign-current that would block on the advisory lock.
    """
    mirror = _live_or_404(db, mirror_id)
    if mirror.last_sync_status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Mirror '{mirror.slug}' has a sync in progress. Wait for "
                "it to finish — the sync will sign the new tree on its own."
            ),
        )

    slug = mirror.slug
    background_tasks.add_task(claim_and_sign_current, mirror_id, slug)
    return {
        "mirror_repo_id": mirror_id,
        "queued": True,
        "run_kind": "sign_only",
        "message": (
            f"Sign-current queued for '{slug}'. Poll GET /mirrors/{{id}}/runs "
            "for the sign_only row to observe; the per-mirror advisory lock "
            "decides whether this dispatch wins or another worker is acting."
        ),
    }


@router.get("/{mirror_id}/runs", response_model=List[MirrorSyncRunRead])
async def list_runs(
    mirror_id: int,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    _live_or_404(db, mirror_id)
    runs = (
        db.query(MirrorSyncRun)
        .filter(MirrorSyncRun.mirror_repo_id == mirror_id)
        .order_by(MirrorSyncRun.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_run_to_read(r) for r in runs]


@router.get("/{mirror_id}/browse")
async def browse_mirror(
    mirror_id: int,
    path: str = Query("", description="Relative path under live/"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Read-only directory listing of a mirror's published ``live/``
    tree (PRA-157 #5).

    ``path`` is a forward-slash relative path under ``live/``; empty
    string means the live root. Path traversal (``..``, leading
    ``/``, embedded null) is rejected at the query parameter — we
    must not expose the host filesystem outside the mirror's own
    ``live_dir(slug)``.

    Returns ``{path, entries: [{name, type, size}], parent}`` where
    ``type`` is ``"file"`` or ``"dir"`` and ``parent`` is the
    relative path of the parent directory (``None`` at the root) so
    a browse UI can render a "back up" link without keeping its own
    breadcrumb stack.
    """
    from app.services.mirror_paths import live_dir

    mirror = _live_or_404(db, mirror_id)

    safe_relative = _validate_browse_path(path)

    base = live_dir(mirror.slug)
    target = (base / safe_relative).resolve() if safe_relative else base.resolve()
    base_resolved = base.resolve()

    # Belt against symlink-escape — even after _validate_browse_path,
    # a ``live/`` containing a symlink could resolve outside the
    # base. Always confirm the resolved target is inside.
    try:
        target.relative_to(base_resolved)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"path={path!r} resolves outside mirror live root",
        )

    if not base.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Mirror '{mirror.slug}' has no live/ tree yet — no "
                "successful sync has produced one. Trigger a sync first."
            ),
        )
    if not target.exists() or not target.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"path={path!r} not found under mirror live root",
        )

    entries = []
    for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name)):
        try:
            stat = child.stat()
        except OSError:
            continue
        entries.append(
            {
                "name": child.name,
                "type": "dir" if child.is_dir() else "file",
                "size": stat.st_size if child.is_file() else None,
            }
        )

    parent: str | None = None
    if safe_relative:
        parent_parts = safe_relative.rsplit("/", 1)
        parent = parent_parts[0] if len(parent_parts) > 1 else ""

    return {"path": safe_relative, "parent": parent, "entries": entries}


def _validate_browse_path(raw: str) -> str:
    """Normalize a browse path query param. Rejects path-traversal
    attempts and absolute paths. Returns a forward-slash relative
    path or ``""`` for the root.
    """
    if raw is None:
        return ""
    s = raw.strip().lstrip("/")
    if not s:
        return ""
    if "\x00" in s:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="path contains null byte",
        )
    parts = s.replace("\\", "/").split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"path={raw!r} must not contain '..' or empty segments",
            )
    return "/".join(parts)


@router.get("/{mirror_id}/runs/{run_id}", response_model=MirrorSyncRunRead)
async def get_run(
    mirror_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Fetch a single sync run by id (PRA-157 #5-a). The list
    endpoint already exists; the single-row variant is here so a UI
    rendering manifest summary can co-fetch the run row's
    ``manifest_sha256`` (the *content fingerprint*, distinct from
    the manifest body's ``praxis_mirror_manifest`` *format version*)
    without paginating the full history.
    """
    _live_or_404(db, mirror_id)
    run = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.id == run_id,
            MirrorSyncRun.mirror_repo_id == mirror_id,
        )
        .first()
    )
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run {run_id} not found for mirror {mirror_id}",
        )
    return _run_to_read(run)


@router.get("/{mirror_id}/runs/{run_id}/manifest")
async def get_run_manifest(
    mirror_id: int,
    run_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    _live_or_404(db, mirror_id)
    run = (
        db.query(MirrorSyncRun)
        .filter(
            MirrorSyncRun.id == run_id,
            MirrorSyncRun.mirror_repo_id == mirror_id,
        )
        .first()
    )
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run {run_id} not found for mirror {mirror_id}",
        )
    if run.status != "ok" or not run.manifest_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Run {run_id} did not produce a manifest " f"(status={run.status!r})"
            ),
        )

    path = Path(run.manifest_path)
    if not path.is_file():
        # Manifest row says ok but file is gone — likely retention
        # ahead of #4 or operator-side cleanup. Surface a 410 Gone
        # rather than a 500.
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                f"Manifest for run {run_id} is no longer available on disk "
                f"({run.manifest_path})"
            ),
        )
    return Response(content=path.read_bytes(), media_type="application/json")


# ---------------------------------------------------------------------------
# Signing-key sub-resources (PRA-158 slice #1) — metadata-only surface.
# Slice #2 will add the signing engine; slice #3 the trust bundle download;
# slice #5 the rotation endpoints. The mirror_signing_status field is
# locked at no_key_yet | key_ready — DO NOT promote to "trusted" or
# "signed_ok" until slice #2 lands real signing.
# ---------------------------------------------------------------------------


def _signing_key_to_read(key: MirrorSigningKey) -> dict:
    return {
        "id": key.id,
        "mirror_repo_id": key.mirror_repo_id,
        "status": key.status,
        "gpg_fingerprint": key.gpg_fingerprint,
        "key_uid": key.key_uid,
        "cutover_at": key.cutover_at,
        "retired_at": key.retired_at,
        "created_at": key.created_at,
    }


@router.post(
    "/{mirror_id}/signing-key",
    response_model=MirrorSigningKeyBootstrapResponse,
)
async def bootstrap_signing_key(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Create the active signing key for a mirror, idempotently.

    First call generates a 4096-bit RSA keypair under an ephemeral
    GNUPGHOME, stores armored private+public in Vault at
    ``praxis/mirror-signing-keys/<slug>/<fingerprint>``, and inserts
    the metadata row. Subsequent calls return the existing active key
    with ``created=false``.

    Returns metadata + the armored public key. The response
    deliberately does NOT include any "signed" / "trusted" badge —
    having a key is not the same as having signed published content.
    Slice #2 wires the signing engine; until then ``mirror_signing_status``
    stays at ``key_ready``.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    existed = service.get_active(mirror.id) is not None
    key = service.ensure_active(mirror)
    public_armored = service.get_public_armored(key)
    detail = {**_signing_key_to_read(key), "public_key_armored": public_armored}
    return {
        "created": not existed,
        "mirror_signing_status": "key_ready",
        "key": detail,
    }


@router.post(
    "/{mirror_id}/install-trust",
    response_model=InstallTrustResponse,
)
async def install_trust(
    mirror_id: int,
    body: InstallTrustRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Install the mirror's trust bundle on the named hosts (PRA-158 #3c).

    Awaits all installs inline and returns per-host results. Trust
    install is fast (concatenated armored bundle for deb / one file
    per fingerprint for rpm; a handful of ``run_command`` round-trips
    per host — ``install`` to a ``.praxis-tmp`` then ``mv -f`` swap);
    inline feedback beats async dispatch for the operator UX.

    Per the PRA-158 design lock, this primitive only writes key
    material. It does NOT generate ``/etc/apt/sources.list.d/*`` or
    ``.repo`` files (PRA-159 channel territory) and does NOT run
    ``rpm --import`` (host trust requires a future ``.repo``
    ``gpgkey=file://...`` reference or an explicit operator action).

    400 if ``host_ids`` is empty. 404 on missing mirror or any
    referenced host (atomic — no partial dispatch).
    """
    if not body.host_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="host_ids must not be empty",
        )

    # PRA-281: host_ids is a host-derived batch. Reject the WHOLE request with a
    # non-disclosing 404 if any host is out of the caller's fleet scope, BEFORE the
    # mirror lookup (so mirror_id is never a probe), the host lookup, transport
    # setup, SSH/broker work, trust-file writes, or per-host result serialization.
    # A missing OR out-of-scope host is indistinguishable for a scoped caller.
    scope = scoped_system_ids(db, current_user)
    if scope is not None:
        for hid in body.host_ids:
            if hid not in scope:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="host not found"
                )

    mirror = _live_or_404(db, mirror_id)

    # Resolve all hosts up front so a missing host_id returns a 404
    # before any remote action — atomic dispatch.
    hosts: list[System] = []
    for hid in body.host_ids:
        host = db.query(System).filter(System.id == hid).first()
        if host is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"host_id {hid} not found",
            )
        hosts.append(host)

    results: list[dict] = []
    overall_ok = True
    ssh_service = SSHService(db)
    async with BrokerClient() as broker:
        for host in hosts:
            try:
                transport = await get_transport(host, broker, ssh_service=ssh_service)
            except Exception as exc:  # pylint: disable=broad-except
                overall_ok = False
                results.append(
                    {
                        "host_id": host.id,
                        "ok": False,
                        "installed_fingerprints": [],
                        "written_paths": [],
                        "error_text": f"transport setup: {exc}",
                    }
                )
                continue

            res = await install_mirror_trust_on_host(db, mirror, host, transport)
            if not res.ok:
                overall_ok = False
            results.append(
                {
                    "host_id": res.host_id,
                    "ok": res.ok,
                    "installed_fingerprints": res.installed_fingerprints,
                    "written_paths": res.written_paths,
                    "error_text": res.error_text,
                }
            )

    return {"mirror_id": mirror.id, "ok": overall_ok, "results": results}


@router.get(
    "/{mirror_id}/trust-bundle",
    response_model=TrustBundleResponse,
)
async def get_trust_bundle_json(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the public-key trust bundle for a mirror as JSON
    (PRA-158 #3b).

    Includes ``active`` + ``pending_cutover`` + ``rotating_out`` keys
    (NEVER ``retired`` — locked invariant). Authenticated; no anonymous
    access. Slice #3c's host-side install primitive consumes this
    endpoint via the existing ``HostTransport`` abstraction.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    keys = service.bundle_public_keys(mirror.id)

    entries = []
    active_fpr: str | None = None
    for k in keys:
        armored = service.get_public_armored(k)
        entries.append(
            {
                "id": k.id,
                "fingerprint": k.gpg_fingerprint,
                "uid": k.key_uid,
                "status": k.status,
                "armored": armored,
            }
        )
        if k.status == "active" and active_fpr is None:
            active_fpr = k.gpg_fingerprint
    return {
        "mirror_id": mirror.id,
        "mirror_slug": mirror.slug,
        "active_fingerprint": active_fpr,
        "keys": entries,
    }


@router.get("/{mirror_id}/trust-bundle.asc")
async def get_trust_bundle_asc(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the public-key trust bundle as concatenated armored bodies
    (PRA-158 #3b).

    Format: PGP PUBLIC KEY BLOCKs back-to-back, separated by single
    newlines. Apt's ``signed-by=/etc/apt/keyrings/...`` and rpm's
    ``gpgkey=file://...`` both accept multi-key bundles. Authenticated.

    Empty body (with 200 OK) when the mirror has no current trust
    keys yet — slice #5's UI will surface this; clients shouldn't
    treat empty-body as an error.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    keys = service.bundle_public_keys(mirror.id)

    armored_blocks = [service.get_public_armored(k) for k in keys]
    body = "\n".join(armored_blocks)
    headers = {
        "Content-Disposition": (
            f'attachment; filename="praxis-mirror-{mirror.slug}.asc"'
        )
    }
    return Response(content=body, media_type="application/pgp-keys", headers=headers)


@router.get(
    "/{mirror_id}/signing-key",
    response_model=MirrorSigningKeyDetail,
)
async def get_active_signing_key(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    """Return the active signing key for a mirror, or 404 if none yet.

    Mirror-status callers should use the bootstrap endpoint or list
    endpoint to disambiguate "no key yet" from "fetch failed"; this
    endpoint is the metadata-plus-public-key shape for an existing
    active key.
    """
    _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    key = service.get_active(mirror_id)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mirror {mirror_id} has no active signing key (no_key_yet)",
        )
    public_armored = service.get_public_armored(key)
    return {**_signing_key_to_read(key), "public_key_armored": public_armored}


# ---------------------------------------------------------------------------
# PRA-158 #5b — rotation endpoints (declared BEFORE /{mirror_id} wildcard
# per the FastAPI route-ordering trap).
# ---------------------------------------------------------------------------


@router.post(
    "/{mirror_id}/signing-key/rotate-prepare",
    response_model=MirrorSigningKeyDetail,
    status_code=status.HTTP_201_CREATED,
)
async def rotate_prepare(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Generate a new ``pending_cutover`` signing key (PRA-158 #5b).

    Native signing keeps using the current ``active`` key. The new
    pending key joins the trust bundle so hosts can install ahead of
    cutover. 409 if a pending_cutover key already exists for this
    mirror — caller must cut over or retire it before another prepare.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    try:
        key = service.rotate_prepare(mirror)
    except RotationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {
        **_signing_key_to_read(key),
        "public_key_armored": service.get_public_armored(key),
    }


@router.get(
    "/{mirror_id}/signing-key/cutover-preview",
    response_model=CutoverPreviewResponse,
)
async def cutover_preview(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Preview the cutover hard-gate without performing it (PRA-158 #5b).

    Returns the same shape that a blocked-cutover 409 would carry,
    so a UI can render the "would-block" preview before showing the
    Cut Over button. 409 if no pending_cutover key exists.
    """
    _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    try:
        return service.cutover_preview(mirror_id)
    except RotationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.post(
    "/{mirror_id}/signing-key/cutover",
    response_model=MirrorSigningKeyDetail,
    responses={
        status.HTTP_409_CONFLICT: {
            "model": CutoverBlockedResponse,
            "description": (
                "Cutover blocked: hosts not yet trusting the pending key, "
                "and ``force`` was not set."
            ),
        },
    },
)
async def cutover(
    mirror_id: int,
    body: CutoverRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("admin", "maintainer")),
) -> Any:
    """Promote ``pending_cutover`` → ``active`` (PRA-158 #5b).

    Hard-gated: refuses unless every host in ``host_mirror_trust``
    for this mirror has the pending fingerprint installed. Returns
    409 with a structured ``preview`` body listing the blocking
    hosts so the operator (or UI) knows exactly which hosts need
    install-trust before the gate opens.

    ``force=True`` overrides the gate AND emits an audit event
    ``mirror.signing_key.cutover.forced`` with structured counts of
    each host bucket. The audit event is emitted on a fresh session
    AFTER the state-transition commit (PRA-158 #5-a) — the audit row
    can never describe an override that didn't actually land.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    try:
        key = service.cutover(mirror, force=body.force, actor_user_id=current_user.id)
    except CutoverBlocked as exc:
        # Flatten the 409 body to match the declared CutoverBlockedResponse
        # schema: plain HTTPException(detail=dict) wraps
        # the wire body as {"detail": {"detail": ..., "preview": {...}}},
        # which doesn't match the OpenAPI declaration. Returning a
        # JSONResponse directly puts ``{detail, preview}`` at the top
        # level so the UI in #5c consumes the same shape it sees on the
        # cutover-preview 200 response.
        body_payload = CutoverBlockedResponse(
            detail=str(exc),
            preview=CutoverPreviewResponse(**exc.preview),
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=body_payload.model_dump(),
        )
    except RotationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {
        **_signing_key_to_read(key),
        "public_key_armored": service.get_public_armored(key),
    }


@router.post(
    "/{mirror_id}/signing-key/retire/{key_id}",
    response_model=MirrorSigningKeyDetail,
)
async def retire_key(
    mirror_id: int,
    key_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    """Demote ``rotating_out`` → ``retired`` (PRA-158 #5b).

    Only ``rotating_out`` keys are retire-able. 409 on any other
    source status (active / pending_cutover / already retired) and
    on cross-mirror or unknown key ids — the message does not leak
    whether a key with that id exists for a different mirror.
    """
    mirror = _live_or_404(db, mirror_id)
    service = MirrorSigningKeyService(db)
    try:
        key = service.retire(mirror.id, key_id)
    except RotationNotFound as exc:
        # Type-mapping rather than substring on the
        # error text — API status semantics no longer depend on
        # service copy. Cross-mirror id and unknown id share this
        # path so callers can't probe cross-mirror existence.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except RotationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return {
        **_signing_key_to_read(key),
        "public_key_armored": service.get_public_armored(key),
    }


# ---------------------------------------------------------------------------
# /{id} detail / update / delete (declared LAST per route-ordering trap)
# ---------------------------------------------------------------------------


@router.get("/{mirror_id}", response_model=MirrorRepoRead)
async def get_mirror(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),  # pylint: disable=unused-argument
) -> Any:
    return _to_read(_live_or_404(db, mirror_id), db)


@router.patch("/{mirror_id}", response_model=MirrorRepoRead)
async def update_mirror(
    mirror_id: int,
    body: MirrorRepoUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Any:
    mirror = _live_or_404(db, mirror_id)

    updates = body.dict(exclude_unset=True)
    for field, value in updates.items():
        if field == "components":
            mirror.components = _encode_string_list(value or [])
        elif field == "architectures":
            mirror.architectures = _encode_string_list(value)
        else:
            setattr(mirror, field, value)

    db.commit()
    db.refresh(mirror)
    logger.info("Updated mirror %s (id=%d): %s", mirror.slug, mirror.id, list(updates))
    return _to_read(mirror, db)


@router.delete("/{mirror_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mirror(
    mirror_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(  # pylint: disable=unused-argument
        require_role("admin", "maintainer")
    ),
) -> Response:
    mirror = _live_or_404(db, mirror_id)
    mirror.deleted_at = datetime.utcnow()
    mirror.enabled = False
    db.commit()
    logger.info(
        "Soft-deleted mirror %s (id=%d). Bytes under "
        "mirror_data/<slug>/ remain on disk; PRA-160 / future "
        "maintenance owns async cleanup.",
        mirror.slug,
        mirror.id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
