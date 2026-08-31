"""Authoritative release version for the running backend.

The version reported by ``/health``, by the OpenAPI document, and inside the
support bundle has to describe the artifact that is actually running. The only
description that always travels with that artifact is the installed package's
metadata, so that is the authority here and no module carries a release literal
of its own.

A deployment may override the reported version with ``PRAXIS_VERSION``, the
same variable that pins a release deploy. The override is accepted only when it
is a well-formed release version, with or without the ``v`` tag prefix, so a
malformed or accidental value falls back to the package metadata instead of
being reported verbatim.

When the package metadata is unavailable, as in a bare source checkout that was
never installed, the reported version is deliberately not a release number:
callers get :data:`UNKNOWN_VERSION` rather than a plausible release the tree may
not actually be.
"""

from __future__ import annotations

import logging
import os
import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import Optional

logger = logging.getLogger(__name__)

# Distribution name installed from backend/setup.py, which holds the single
# release version the backend is built with.
DISTRIBUTION_NAME = "app"

# Reported when the distribution metadata cannot be read. Not a release number
# by construction, so an uninstalled tree can never be mistaken for a build.
UNKNOWN_VERSION = "0.0.0+unknown"

# Deployment override. Documented for pinning a release deploy and already read
# at runtime by the support bundle.
OVERRIDE_ENV_VAR = "PRAXIS_VERSION"

# Same shape the release index accepts: major.minor.patch with an optional
# pre-release suffix.
_RELEASE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}(?:-[0-9A-Za-z.-]+)?$"
)


def _override_version() -> Optional[str]:
    """Return the validated ``PRAXIS_VERSION`` override, or ``None``."""
    raw = os.getenv(OVERRIDE_ENV_VAR)
    if not raw:
        return None
    candidate = raw.strip().removeprefix("v")
    if _RELEASE_VERSION_RE.fullmatch(candidate):
        return candidate
    logger.warning(
        "Ignoring %s=%r: not a release version. Reporting the installed "
        "package version instead.",
        OVERRIDE_ENV_VAR,
        raw,
    )
    return None


def get_version() -> str:
    """Return the release version this backend reports about itself."""
    override = _override_version()
    if override is not None:
        return override
    try:
        return distribution_version(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        logger.warning(
            "Package metadata for %r is unavailable; reporting %s. Install the "
            "backend package so the reported version matches the build.",
            DISTRIBUTION_NAME,
            UNKNOWN_VERSION,
        )
        return UNKNOWN_VERSION
