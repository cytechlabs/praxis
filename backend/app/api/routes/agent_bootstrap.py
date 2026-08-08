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
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Optional, Tuple

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

# The release download endpoint answers on the release origin and hands
# back a redirect to a short-lived object URL on a GitHub asset host.
# Only those exact hosts are followed. A "*.githubusercontent.com" rule
# is deliberately avoided because sibling subdomains on that domain serve
# user-controlled raw, gist, and Pages content.
_RELEASE_ORIGIN_HOST = "github.com"
_RELEASE_ORIGIN = f"https://{_RELEASE_ORIGIN_HOST}"
_RELEASE_ASSET_HOSTS = frozenset(
    {
        # Object host used by the current release-asset redirect.
        "release-assets.githubusercontent.com",
        # Object host still used by older release-asset redirects.
        "objects.githubusercontent.com",
    }
)
_ALLOWED_HOP_HOSTS = frozenset({_RELEASE_ORIGIN_HOST}) | _RELEASE_ASSET_HOSTS
_MAX_REDIRECT_HOPS = 4

_GH_RELEASE_BASE = (
    f"{_RELEASE_ORIGIN}/cytechlabs/praxis/releases/download/{_RELEASE_TAG}"
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


class _RedirectPolicyError(Exception):
    """An upstream hop violated the artifact redirect policy."""


def _hop_label(url: str) -> str:
    """Scheme and host of a URL, safe to log. Release object URLs carry
    signed query parameters, so a full URL is never logged."""
    try:
        parts = urllib.parse.urlsplit(url)
        return f"{parts.scheme or 'unknown'}://{parts.hostname or 'unknown'}"
    except ValueError:
        return "unparsable"


def _validate_hop(url: str) -> str:
    """Return the origin of a permitted hop.

    Fails closed on anything that is not an exact allow-listed release
    host reached over HTTPS without embedded credentials."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        port = parts.port
        has_userinfo = bool(parts.username or parts.password)
    except ValueError as exc:
        raise _RedirectPolicyError("malformed hop target") from exc
    if parts.scheme != "https":
        raise _RedirectPolicyError(f"non-https hop {_hop_label(url)}")
    if has_userinfo:
        raise _RedirectPolicyError(f"credentials embedded in hop {_hop_label(url)}")
    if not host or not host.isascii():
        raise _RedirectPolicyError("malformed hop host")
    host = host.lower()
    if host not in _ALLOWED_HOP_HOSTS:
        raise _RedirectPolicyError(f"host not allowed https://{host}")
    if port not in (None, 443):
        raise _RedirectPolicyError(f"port not allowed on https://{host}")
    return f"https://{host}"


def _build_hop_request(
    url: str, origin: str, *, allow_credentials: bool
) -> "urllib.request.Request":
    """Build the request for a single validated hop.

    The configured token is attached only on the release origin, and only
    as an unredirected header so that urllib can never copy it onto a
    redirect target."""
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream"},
        method="GET",
    )
    if allow_credentials and origin == _RELEASE_ORIGIN:
        token = os.getenv("GITHUB_TOKEN")
        if token:
            request.add_unredirected_header("Authorization", f"Bearer {token}")
    return request


# urllib's redirect handler follows 3xx responses inside urlopen(), which
# would hide intermediate hops from validation. Pre-filling its
# loop-detection budget makes it surface each redirect as an HTTPError
# carrying the Location header instead, so every hop is checked here.
_NO_FOLLOW_BUDGET = {
    f"praxis-hop-{index}": 1
    for index in range(urllib.request.HTTPRedirectHandler.max_redirections)
}


def _open_single_hop(request: "urllib.request.Request", timeout: int) -> Any:
    """Perform exactly one HTTP exchange without following a redirect."""
    request.redirect_dict = dict(_NO_FOLLOW_BUDGET)
    return urllib.request.urlopen(request, timeout=timeout)


def _redirect_target(exc: urllib.error.HTTPError) -> Optional[str]:
    """Redirect location carried by an upstream error, or None when the
    response was not a redirect. The upstream body is released without
    being read, logged, or surfaced."""
    target = None
    if 300 <= exc.code < 400 and exc.headers is not None:
        target = exc.headers.get("Location") or exc.headers.get("URI")
    body = getattr(exc, "fp", None)
    if body is not None:
        body.close()
    return target or None


def _reject_unvalidated_hop(request: "urllib.request.Request", response: Any) -> None:
    """Redirects are followed by this module, not by urllib. A response URL
    that differs from the requested URL means a hop escaped validation."""
    final_url = getattr(response, "url", None)
    if final_url is not None and final_url != request.full_url:
        response.close()
        raise _RedirectPolicyError(
            f"unvalidated upstream redirect to {_hop_label(final_url)}"
        )


def _open_release_asset(asset_name: str, timeout: int) -> Any:
    """Open a pinned release asset with every redirect hop validated.

    Artifact streaming and checksum retrieval both route through here, so
    neither reaches urllib's redirect-following default behavior. The
    configured token travels only on the release origin, and once a hop
    leaves that origin it is dropped for the remainder of the chain."""
    url = f"{_GH_RELEASE_BASE}/{asset_name}"
    allow_credentials = True
    try:
        for _ in range(_MAX_REDIRECT_HOPS + 1):
            origin = _validate_hop(url)
            if origin != _RELEASE_ORIGIN:
                allow_credentials = False
            request = _build_hop_request(
                url, origin, allow_credentials=allow_credentials
            )
            try:
                response = _open_single_hop(request, timeout)
            except urllib.error.HTTPError as exc:
                target = _redirect_target(exc)
                if target is None:
                    logger.warning(
                        "agent artifact fetch failed for %s: HTTP %s",
                        asset_name,
                        exc.code,
                    )
                    raise HTTPException(
                        status_code=502, detail="agent artifact unavailable"
                    ) from exc
                url = urllib.parse.urljoin(url, target)
                continue
            _reject_unvalidated_hop(request, response)
            return response
        raise _RedirectPolicyError("redirect chain too long")
    except _RedirectPolicyError as exc:
        logger.warning("agent artifact redirect rejected for %s: %s", asset_name, exc)
        raise HTTPException(
            status_code=502, detail="agent artifact unavailable"
        ) from exc
    except ValueError as exc:
        logger.warning("agent artifact hop target unusable for %s", asset_name)
        raise HTTPException(
            status_code=502, detail="agent artifact unavailable"
        ) from exc
    except urllib.error.URLError as exc:
        logger.warning(
            "agent artifact unreachable for %s: %s",
            asset_name,
            exc.reason,
        )
        raise HTTPException(
            status_code=502, detail="agent artifact unavailable"
        ) from exc


def _stream_github(asset_name: str) -> Tuple[Iterator[bytes], int]:
    """Stream a named release asset from the pinned tag.

    Failures map to 502 without leaking which arm tripped (local
    misconfigured vs upstream unreachable vs auth wrong)."""
    response = _open_release_asset(asset_name, timeout=30)

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

    response = _open_release_asset("checksums.txt", timeout=15)
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
