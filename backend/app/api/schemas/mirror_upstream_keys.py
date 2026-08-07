"""Pydantic schemas for upstream-trust-anchor management (PRA-158 #4a)."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class MirrorUpstreamKeyRead(BaseModel):
    """Public-key trust anchor as the API surfaces it.

    The full ``armored_public_key`` is included — it's public material
    by definition (operator imported it; future operators may need to
    re-export it to inspect or seed elsewhere).
    """

    id: int
    name: str
    gpg_fingerprint: str
    armored_public_key: str
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime


class MirrorUpstreamKeyCreate(BaseModel):
    """Body for ``POST /mirror-upstream-keys``.

    Operator provides the armored body and a human-readable name; the
    fingerprint is derived server-side via the same gpg primitive
    used elsewhere (no risk of operator-supplied fingerprint
    mismatching the body).
    """

    name: str
    armored_public_key: str
    notes: Optional[str] = None


class MirrorUpstreamKeyList(BaseModel):
    """``GET /mirror-upstream-keys`` response shape."""

    keys: List[MirrorUpstreamKeyRead]
