"""Mirror serve endpoint (PRA-159 slice #2).

``GET /mirrors/{slug}/serve/{path:path}`` streams files from
``PRAXIS_MIRROR_ROOT/<slug>/live/<path>`` to authenticated hosts.

Auth model (slice #2 ships Mode A only — bearer):
  * ``Authorization: Bearer <token>`` matched against
    ``host_mirror_serve_credentials`` via
    ``MirrorServeCredentialService.verify``. The credential is
    bound to a specific ``(host_id, mirror_id)``; we additionally
    enforce that the credential's ``mirror_id`` matches the mirror
    being served.
  * Mode B (mTLS via the agent's PKI cert from PRA-150/PRA-153) is
    deliberately deferred: it requires either a reverse-proxy
    bridge (Caddy/nginx → header) or FastAPI-level SSL context
    plumbing. Slice #2 ships bearer-only with the credential
    embedded in apt's ``/etc/apt/auth.conf.d/...`` (mode 0600 root)
    or dnf's ``.repo`` ``username=``/``password=`` (mode 0600 root)
    — see PRA-159 slice #2 design lock + PRA-158 host trust install
    docstring. Slice #3 issues the credential as part of apply.

Path-traversal guard (CRITICAL):
  * Compute ``target = (live_root / requested_path).resolve()``.
  * Verify ``target`` is strictly under ``live_root.resolve()``.
  * Reject anything else with 404 (NOT 400 — don't tell the caller
    whether their attempt was syntactically wrong vs syntactically
    OK but escaping; both look like "file not found").
  * Symlinks inside ``live/`` that point outside live/ are also
    rejected by the realpath-prefix check.

Authentication is ENFORCED — this router is mounted with
``prefix="/mirrors/{slug}/serve"`` BEFORE the bare ``/mirrors``
CRUD router so the string ``{slug}`` match wins over the
``{mirror_id}: int`` matches in the CRUD router (FastAPI tries
registered routes in order; locking declaration order avoids
surprises). The JWT auth middleware allow-lists this prefix so
apt/dnf can present the bearer in the standard ``Authorization``
header without going through the JWT login flow.

NOT in scope for slice #2:
  * Directory listing (``HEAD`` returns 405; only regular file
    GET is supported).
  * Range requests (apt/dnf don't typically need them for repo
    metadata; range support can land later if mirror sizes make
    full-body downloads costly).
"""

from __future__ import annotations

import base64
import binascii
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.models import HostMirrorServeCredential, MirrorRepo
from app.db.session import get_db
from app.services.mirror_paths import live_dir
from app.services.mirror_serve_credential_service import MirrorServeCredentialService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mirror-serve"])


# The Basic-auth username slot is enforced as this constant so apt /
# dnf install templates from slice #3 are self-describing and so a
# malformed config with a different username fails fast with 401
# instead of silently working.
BASIC_AUTH_USERNAME = "praxis"


def _extract_bearer(request: Request) -> Optional[str]:
    """Extract the bearer token from either ``Bearer <token>`` or
    ``Basic <base64(user:token)>``.

    apt and dnf both speak HTTP Basic out of the box (apt via
    ``auth.conf.d``, dnf via ``.repo`` ``username=``/``password=``);
    neither has first-class bearer support. We accept both so the
    same credential can be embedded with either client. For Basic,
    the username MUST be ``praxis`` — the slice #3 apt/dnf install
    templates emit that fixed marker, and rejecting other usernames
    catches malformed config at install time instead of silently
    accepting it.
    """
    auth = request.headers.get("Authorization") or ""
    lowered = auth.lower()
    if lowered.startswith("bearer "):
        token = auth[7:].strip()
        return token or None
    if lowered.startswith("basic "):
        b64 = auth[6:].strip()
        try:
            decoded = base64.b64decode(b64, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        if ":" not in decoded:
            return None
        username, _, token = decoded.partition(":")
        if username != BASIC_AUTH_USERNAME:
            return None
        return token or None
    return None


def _resolve_safe_target(slug: str, requested: str) -> Optional[Path]:
    """Realpath-prefix guard.

    Returns the resolved path on success, ``None`` if anything looks
    like traversal / symlink escape / nonexistent.
    """
    live_root = live_dir(slug).resolve()
    if not live_root.exists():
        return None

    # Strip leading slashes so the join behaves intuitively (bare
    # ``foo/bar`` not ``/foo/bar`` which would discard the live_root
    # prefix on POSIX).
    safe = requested.lstrip("/")
    if not safe:
        return None

    candidate = (live_root / safe).resolve()
    try:
        candidate.relative_to(live_root)
    except ValueError:
        return None

    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def _verify_bearer(
    db: Session, mirror: MirrorRepo, plaintext: str
) -> Optional[HostMirrorServeCredential]:
    """Verify the bearer matches a credential bound to ``mirror``.

    Two-stage check: pbkdf2_sha256 verify (constant-time per row) +
    cross-check that the credential's ``mirror_id`` is the mirror
    being served. A token issued for mirror A MUST NOT serve
    mirror B even if the bearer is otherwise valid.
    """
    service = MirrorServeCredentialService(db)
    cred = service.verify(plaintext)
    if cred is None:
        return None
    if cred.mirror_id != mirror.id:
        return None
    return cred


@router.get("/{path:path}")
async def serve_mirror_file(
    slug: str,
    path: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """Stream a file from ``mirror/live/<path>`` to an authenticated host.

    Auth: ``Authorization: Bearer <token>`` matching a non-revoked,
    non-expired credential bound to this mirror.

    Errors:
      * 401 — missing or invalid bearer / credential not bound to
        this mirror / credential expired or revoked.
      * 404 — mirror not found (or soft-deleted), live tree absent,
        or the requested path doesn't resolve to a regular file
        inside ``live/`` (covers traversal attempts).
    """
    # Resolve mirror by slug (excluding soft-deleted). 404 obscures
    # whether the mirror exists vs is soft-deleted; matches the
    # PRA-157 _live_or_404 pattern.
    mirror = (
        db.query(MirrorRepo)
        .filter(MirrorRepo.slug == slug, MirrorRepo.deleted_at.is_(None))
        .one_or_none()
    )
    if mirror is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    plaintext = _extract_bearer(request)
    if plaintext is None:
        # 401 with WWW-Authenticate per RFC 7235 so apt/dnf clients
        # know to look at their auth.conf.d / .repo creds.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="bearer required",
            headers={"WWW-Authenticate": 'Bearer realm="praxis-mirror"'},
        )

    cred = _verify_bearer(db, mirror, plaintext)
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credential",
            headers={"WWW-Authenticate": 'Bearer realm="praxis-mirror"'},
        )

    target = _resolve_safe_target(slug, path)
    if target is None:
        # 404 covers both real misses AND traversal attempts. Don't
        # leak the discrimination to the caller.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    # Best-effort last_used_at stamp. Failure here MUST NOT block
    # the response — last_used_at is diagnostic, not security.
    MirrorServeCredentialService(db).stamp_used(cred)

    return FileResponse(target, media_type="application/octet-stream")
