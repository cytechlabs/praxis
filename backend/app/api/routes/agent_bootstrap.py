"""PRA-154 slice #1d-b: bootstrap script + agent binary download.

Three anonymous routes that the host-side ``bootstrap.sh`` consumes:

  * ``GET /agent/bootstrap.sh`` — serves the committed shell script
    with ``__PRAXIS_DEFAULT_URL__`` substituted from
    ``PRAXIS_PUBLIC_URL``. Fails closed with 500 when the env var is
    unset rather than serving a script with the unresolved sentinel.

  * ``GET /agent/download/{arch}/{filename}`` — closed allow-list of
    arches and filenames. Streams from a local artifact directory
    when present; falls back to the pinned GitHub Release tag using
    a server-side token. The host's TLS chain anchors trust for the
    artifact (script + tarball + checksum all share the same
    control-plane CA), so the script's checksum check is verifying
    a trusted-control-plane statement, not a cosign signature.
    Cosign is an explicit follow-up.

  * ``GET /agent/ca-bundle`` already exists (PRA-151) and stays
    where it is.

All three are added to the ``JWTAuthMiddleware`` allow-list. Token
validation lives entirely in ``/agent/enroll``; these routes are
either public-by-design (script, ca-bundle) or signed/checksummed
artifacts that are safe to serve anonymously.
"""

from __future__ import annotations

import logging
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator, Optional, Tuple

from fastapi import APIRouter, HTTPException
from fastapi import Path as PathParam
from fastapi.responses import Response, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


# ---------------------------------------------------------------- bootstrap.sh

_SENTINEL = "__PRAXIS_DEFAULT_URL__"
_SCRIPT_PATH = Path(__file__).resolve().parent / "_assets" / "bootstrap.sh"
_script_cache: Optional[str] = None
_script_lock = threading.Lock()


def _load_script() -> str:
    """Read the committed bootstrap script once and cache. Reading on
    each request is fine but pointless — the file does not change at
    runtime."""
    global _script_cache
    if _script_cache is None:
        with _script_lock:
            if _script_cache is None:
                _script_cache = _SCRIPT_PATH.read_text(encoding="utf-8")
    return _script_cache


@router.get("/bootstrap.sh")
def get_bootstrap_script() -> Response:
    """Serve the host-side bootstrap script with the control-plane URL
    substituted. Anonymous; the script itself contains no secret."""
    public_url = os.getenv("PRAXIS_PUBLIC_URL")
    if not public_url:
        raise HTTPException(
            status_code=500,
            detail=(
                "PRAXIS_PUBLIC_URL is not configured on this control plane; "
                "bootstrap script cannot be served"
            ),
        )
    script = _load_script().replace(_SENTINEL, public_url.rstrip("/"))
    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="bootstrap.sh"'},
    )


# ---------------------------------------------------------------- download
#
# The agent release pipeline (.github/workflows/agent-release.yml)
# uploads three assets per release:
#
#     praxis-agent-<version>-linux-amd64.tar.gz
#     praxis-agent-<version>-linux-arm64.tar.gz
#     checksums.txt          (BSD-format, both tarballs)
#     checksums.txt.sig      (cosign keyless signature)
#     checksums.txt.pem      (cosign cert)
#
# The host script downloads ``agent.tar.gz`` + ``agent.tar.gz.sha256``
# under canonical names so it doesn't have to know the version. The
# control plane translates those canonical names into the real
# release assets and synthesizes a single-line checksum file pointing
# at the canonical name. Trust is anchored by the control plane's
# TLS chain; cosign signatures on ``checksums.txt`` are an explicit
# follow-up (verification would happen here, not on the host).
#
# Local artifact dir mirrors the release output exactly — operator
# drops the three asset files into PRAXIS_AGENT_ARTIFACT_DIR and the
# control plane serves them airgap-friendly, no per-arch subdirs.

_ALLOWED_ARCHES = frozenset({"amd64", "arm64"})
_ALLOWED_FILENAMES = frozenset({"agent.tar.gz", "agent.tar.gz.sha256"})

_RELEASE_VERSION = "v0.0.0-rc1"
_RELEASE_TAG = f"agent-{_RELEASE_VERSION}"
_GH_RELEASE_BASE = (
    f"https://github.com/cytechlabs/praxis/releases/download/{_RELEASE_TAG}"
)
_DEFAULT_ARTIFACT_DIR = "/opt/praxis/agent-artifacts"


def _real_tarball_name(arch: str) -> str:
    return f"praxis-agent-{_RELEASE_VERSION}-linux-{arch}.tar.gz"


def _artifact_dir() -> Path:
    return Path(os.getenv("PRAXIS_AGENT_ARTIFACT_DIR", _DEFAULT_ARTIFACT_DIR))


def _local_file(name: str) -> Optional[Path]:
    """Return the local artifact path if the file exists in the
    configured artifact directory, else None. The arch is encoded in
    the asset name itself so we don't need a per-arch subdir."""
    base = _artifact_dir()
    candidate = (base / name).resolve()
    if not str(candidate).startswith(str(base.resolve()) + os.sep):
        return None
    if candidate.is_file():
        return candidate
    return None


def _stream_local(path: Path) -> Iterator[bytes]:
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            yield chunk


def _gh_request(asset_name: str) -> "urllib.request.Request":
    token = os.getenv("GITHUB_TOKEN")
    headers = {"Accept": "application/octet-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(f"{_GH_RELEASE_BASE}/{asset_name}", headers=headers)


def _stream_github(asset_name: str) -> Tuple[Iterator[bytes], int]:
    """Stream a named release asset from the pinned tag.

    Failures map to 502 without leaking which arm tripped (local
    misconfigured vs upstream unreachable vs auth wrong)."""
    request = _gh_request(asset_name)
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as exc:
        logger.warning(
            "agent download fallback failed for %s: HTTP %s",
            asset_name,
            exc.code,
        )
        raise HTTPException(status_code=502, detail="agent artifact unavailable")
    except urllib.error.URLError as exc:
        logger.warning(
            "agent download fallback unreachable for %s: %s",
            asset_name,
            exc.reason,
        )
        raise HTTPException(status_code=502, detail="agent artifact unavailable")

    total = int(response.headers.get("Content-Length") or 0)

    def _iter() -> Iterator[bytes]:
        try:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            response.close()

    return _iter(), total


def _read_checksums_text() -> str:
    """Return the contents of ``checksums.txt`` for the pinned release.

    Local artifact dir wins; GitHub fallback otherwise. Used to
    synthesize the per-tarball single-line sha256 file the script
    consumes. We deliberately do NOT serve the multi-line file
    directly — the script asks for a canonical name, and we hide the
    versioned filename so the script never has to know the version.
    """
    local = _local_file("checksums.txt")
    if local is not None:
        return local.read_text(encoding="utf-8")

    request = _gh_request("checksums.txt")
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        logger.warning("checksums.txt fetch failed: %s", exc)
        raise HTTPException(status_code=502, detail="agent artifact unavailable")
    try:
        return response.read().decode("utf-8")
    finally:
        response.close()


def _checksum_line_for(arch: str) -> str:
    """Pull the line for this arch's tarball from checksums.txt and
    rewrite the filename to ``agent.tar.gz`` so the script's
    ``sha256sum -c`` works against the locally-saved canonical
    filename without any normalization step."""
    real_name = _real_tarball_name(arch)
    text = _read_checksums_text()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # sha256sum format: "<hex>  <filename>"
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, fname = parts[0], parts[1]
        # checksums.txt may use exact match or a leading "*" for
        # binary mode. Normalize both.
        fname = fname.lstrip("*").strip()
        if fname == real_name:
            return f"{digest}  agent.tar.gz\n"
    raise HTTPException(
        status_code=502,
        detail=f"checksum line for {real_name} missing from checksums.txt",
    )


@router.get("/download/{arch}/{filename}")
def get_agent_artifact(
    arch: str = PathParam(..., min_length=1, max_length=16),
    filename: str = PathParam(..., min_length=1, max_length=128),
) -> Response:
    """Serve a pinned-name agent artifact. Anonymous; trust is anchored
    by the control plane's TLS chain and verified by the bootstrap
    script's sha256 check.

    The endpoint exposes canonical names (``agent.tar.gz``,
    ``agent.tar.gz.sha256``) so the host doesn't have to know the
    release version. The server translates those to the real release
    asset names internally."""
    if arch not in _ALLOWED_ARCHES:
        raise HTTPException(status_code=404, detail="unknown arch")
    if filename not in _ALLOWED_FILENAMES:
        raise HTTPException(status_code=404, detail="unknown artifact")

    if filename == "agent.tar.gz.sha256":
        body = _checksum_line_for(arch)
        return Response(content=body, media_type="text/plain")

    real_name = _real_tarball_name(arch)
    local = _local_file(real_name)
    if local is not None:
        return StreamingResponse(
            _stream_local(local), media_type="application/octet-stream"
        )

    iterator, content_length = _stream_github(real_name)
    headers = {}
    if content_length:
        headers["Content-Length"] = str(content_length)
    return StreamingResponse(
        iterator, media_type="application/octet-stream", headers=headers
    )
