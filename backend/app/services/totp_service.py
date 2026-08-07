"""TOTP enrollment + step-up service (PRA-139).

Per-user second factor. Three flows:

    * ``begin_enrollment`` generates a fresh base32 secret (if one isn't already
      pending) and returns it alongside an ``otpauth://`` URI for the client
      to render as a QR code. The secret is persisted immediately but the
      user is NOT considered enrolled until ``verify_enrollment`` succeeds.
    * ``verify_enrollment`` confirms the first code, marks the user enrolled,
      and generates one-time recovery codes (returned once in cleartext,
      stored bcrypt-hashed).
    * ``verify_step_up`` takes a current TOTP code or a recovery code. On
      success it records a TotpChallenge row (via
      access_authorization_service) so subsequent gated actions pass without
      re-prompting for ``window_s`` seconds.

Secrets live in the ``user`` table rather than Vault — they're not particularly
high-value on their own (a compromised secret still needs the user's password
or OIDC session), and keeping them in the DB avoids an extra round trip per
step-up.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime
from typing import List, Optional, Tuple

import pyotp
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from ..db.models import User
from .access_authorization_service import record_totp_challenge

logger = logging.getLogger(__name__)

ISSUER = "Praxis"
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LENGTH_HEX = 8  # 4 bytes = 8 hex chars


class TotpError(RuntimeError):
    """TOTP operation failure (bad code, not enrolled, etc.)."""


# -------------------------------------------------------------- enrollment


def begin_enrollment(db: Session, user: User) -> Tuple[str, str]:
    """Generate (and persist) a fresh TOTP secret for ``user``.

    Returns ``(secret_base32, otpauth_uri)``. The secret is stored but the
    user is NOT yet considered enrolled — that requires a successful
    ``verify_enrollment`` call.
    """
    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.totp_enrolled_at = None
    user.totp_recovery_codes = None
    db.commit()
    db.refresh(user)
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email or user.username, issuer_name=ISSUER
    )
    return secret, uri


def verify_enrollment(db: Session, user: User, code: str) -> List[str]:
    """Confirm the first TOTP code after ``begin_enrollment``.

    On success: marks the user enrolled, generates + persists bcrypt-hashed
    recovery codes, returns them in cleartext (the caller displays once).
    """
    if not user.totp_secret:
        raise TotpError("no pending TOTP enrollment")
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        raise TotpError("invalid TOTP code")

    plain: List[str] = [
        secrets.token_hex(RECOVERY_CODE_LENGTH_HEX // 2)
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    # bcrypt 3.2 has a 72-byte input limit but our codes are 8 chars so fine.
    hashed = [bcrypt.hash(code) for code in plain]
    user.totp_recovery_codes = json.dumps(hashed)
    user.totp_enrolled_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return plain


def disable(db: Session, user: User) -> None:
    """Drop TOTP state entirely for ``user``."""
    user.totp_secret = None
    user.totp_enrolled_at = None
    user.totp_recovery_codes = None
    db.commit()
    db.refresh(user)


# ---------------------------------------------------------------- step-up


def is_enrolled(user: User) -> bool:
    return bool(user.totp_secret and user.totp_enrolled_at)


def verify_step_up(db: Session, user: User, code: str, window_s: int = 900) -> bool:
    """Verify ``code`` (TOTP or recovery) and mint a challenge on success."""
    if not is_enrolled(user):
        raise TotpError("user is not TOTP-enrolled")
    code = (code or "").strip().replace(" ", "")
    if not code:
        raise TotpError("empty code")

    # Try live TOTP first — matches the overwhelming common case.
    if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        record_totp_challenge(db, user.id, window_s=window_s)
        try:
            from .audit_event_service import safe_emit

            safe_emit(
                db=db,
                action="totp.step_up",
                actor_user_id=user.id,
                actor_username=user.username,
                target_kind="user",
                target_id=str(user.id),
                context={"method": "totp"},
            )
        except Exception:  # pylint: disable=broad-except
            pass
        return True

    # Fall back to recovery codes — compare against each stored hash and
    # burn the match so it can't be reused.
    hashed: List[str] = json.loads(user.totp_recovery_codes or "[]")
    for i, h in enumerate(hashed):
        try:
            ok = bcrypt.verify(code, h)
        except ValueError:
            ok = False
        if ok:
            remaining = hashed[:i] + hashed[i + 1 :]
            user.totp_recovery_codes = json.dumps(remaining)
            db.commit()
            db.refresh(user)
            record_totp_challenge(db, user.id, window_s=window_s)
            return True

    return False


def remaining_recovery_codes(user: User) -> int:
    """How many unburned recovery codes remain. Used by the UI."""
    try:
        return len(json.loads(user.totp_recovery_codes or "[]"))
    except ValueError:
        return 0


# ---------------------------------------------------------- gate helper


def require_enrolled(user: User) -> None:
    if not is_enrolled(user):
        raise TotpError("TOTP enrollment required")


def verify_current_code(user: User, code: str) -> bool:
    """Lightweight verify with no DB side effects. Used when the caller wants
    a yes/no without minting a challenge (e.g. 'confirm password-equivalent'
    flows for disable)."""
    if not is_enrolled(user):
        return False
    return pyotp.TOTP(user.totp_secret).verify((code or "").strip(), valid_window=1)


def generate_fresh_recovery_codes(db: Session, user: User) -> Optional[List[str]]:
    """Rotate recovery codes; returns new cleartext set for one-time display.

    Only valid for an already-enrolled user (we don't want the 'forgot TOTP
    reset' path to go through here — that's admin-reset territory).
    """
    if not is_enrolled(user):
        raise TotpError("not enrolled")
    plain = [
        secrets.token_hex(RECOVERY_CODE_LENGTH_HEX // 2)
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    user.totp_recovery_codes = json.dumps([bcrypt.hash(c) for c in plain])
    db.commit()
    db.refresh(user)
    return plain
