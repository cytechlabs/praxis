"""Shared-secret auth for the broker internal API (PRA-180 BROKER-01).

The broker internal HTTP API (``:8444 /internal/agent/ops/*``) is reachable by
any container that shares the broker's docker network. Before PRA-180 it had no
authentication at all and trusted the network — so a foothold on any other
``backend_net`` container could dispatch arbitrary agent ops, bypassing every
backend authz/approval/TOTP gate.

This module derives a bounded shared secret that the backend presents on each
internal-API call and the broker validates. Both the backend and the broker
container already receive the same ``SECRET_KEY`` in the shipped compose, so the
token is derived from it via HMAC — no new secret needs provisioning. An explicit
``PRAXIS_BROKER_INTERNAL_TOKEN`` env var overrides the derivation for operators
who want a dedicated rotating token.

This is defense-in-depth on a docker-network-only port (8444 is never published
to the host); it is not a substitute for network isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

# Lower-case on purpose: ASGI header names arrive lower-cased, and httpx
# normalizes outgoing header names, so a single canonical casing avoids
# mismatches between the client and the broker middleware.
INTERNAL_AUTH_HEADER = "x-praxis-internal-auth"

# Domain-separation label so the internal-API token is not equal to any other
# value derived from SECRET_KEY. Versioned so a future rotation of the scheme
# can change the label without colliding with the old token.
_DERIVATION_LABEL = b"praxis-broker-internal-api-v1"


def derive_internal_token() -> Optional[str]:
    """Return the shared internal-API token, or ``None`` if it can't be derived.

    Precedence:
        1. ``PRAXIS_BROKER_INTERNAL_TOKEN`` — explicit operator override.
        2. ``HMAC-SHA256(SECRET_KEY, label)`` — the backend and broker already
           share ``SECRET_KEY``, so both derive the same token with no extra
           provisioning.
        3. ``None`` — neither is available. Callers decide what to do: the
           broker fails closed at startup, the client simply sends no header.
    """
    explicit = os.environ.get("PRAXIS_BROKER_INTERNAL_TOKEN")
    if explicit:
        return explicit
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        return None
    return hmac.new(
        secret.encode("utf-8"), _DERIVATION_LABEL, hashlib.sha256
    ).hexdigest()


def tokens_match(presented: Optional[str], expected: Optional[str]) -> bool:
    """Constant-time comparison of a presented token against the expected one.

    Returns ``False`` if either side is missing so an unconfigured caller can
    never accidentally authenticate.
    """
    if not presented or not expected:
        return False
    return hmac.compare_digest(presented, expected)
