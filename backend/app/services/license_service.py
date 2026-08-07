"""Offline license spine (PRA-133).

Public core validates and applies a signed license **entirely offline** — no
call-home. A license is an EdDSA (Ed25519) JWT bound to this installation's
``instance_id``. Official builds ship a built-in **public** verification key
(``DEFAULT_LICENSE_PUBLIC_KEY``) so a purchased license applies with no env setup;
``PRAXIS_LICENSE_PUBLIC_KEY`` overrides it for dev / custom-issuer testing. The
private signing key never ships here — only a valid CytechLabs-signed license
unlocks paid features.

Behavior:

* No license applied -> free edition, 15-host cap, no paid entitlements.
* Valid paid license -> its tier, host cap, and entitlements hydrate the
  :data:`app.core.entitlements.registry`.
* Invalid / expired / wrong-instance / malformed license -> paid features stay
  inactive with an operator-readable state; existing deployment state is never
  corrupted (no host is deleted or disabled).

Purchase/issuer plumbing is a later PRA (PRA-136); this module is only the
local validate + apply + host-cap spine.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from urllib.parse import quote

import jwt
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.entitlements import (
    ALL_TIERS,
    FREE_HOST_CAP,
    LICENSE_STATE_ACTIVE,
    LICENSE_STATE_EXPIRED,
    LICENSE_STATE_INVALID,
    LICENSE_STATE_MALFORMED,
    LICENSE_STATE_NONE,
    LICENSE_STATE_WRONG_INSTANCE,
    PAID_ENTITLEMENTS,
    PAID_TIERS,
    TIER_FREE,
    edition_snapshot,
    registry,
)
from app.db.models import AppSettings, System

logger = logging.getLogger(__name__)

# AppSettings keys (written directly via the model; the /app-settings HTTP
# allowlist does not apply to service-layer writes).
INSTANCE_ID_KEY = "license.instance_id"
LICENSE_TOKEN_KEY = "license.token"
GRACE_UNTIL_KEY = "license.grace_until"

# --- Online license refresh -------------------------------------------------- #
# Connected installs can refresh an already-applied paid license after a Paddle
# renewal by calling the EE refresh endpoint with this install's instance_id +
# a stored refresh token. Offline/manual license import is unaffected: the
# refresh token is optional and everything below degrades to a no-op without it.
#
# The refresh token is a SECRET. It is stored SERVER-SIDE ONLY as a JSON blob
# bound to this install's instance_id, is NEVER returned by any status endpoint,
# is NEVER logged, and is redacted from the /app-settings dump (see
# SECRET_SETTING_KEYS in app.api.routes.app_settings).
REFRESH_KEY = "license.refresh"  # SECRET: {"instance_id": ..., "token": ...}
REFRESH_LAST_ATTEMPT_KEY = "license.refresh.last_attempt_at"
REFRESH_LAST_RESULT_KEY = "license.refresh.last_result"
REFRESH_LAST_DETAIL_KEY = "license.refresh.last_detail"

# Refresh outcome codes (surfaced to the UI; never include token/PII).
REFRESH_RESULT_OK = "ok"  # a renewed license was returned and applied
REFRESH_RESULT_NOT_CONFIGURED = "not_configured"  # no stored refresh token
REFRESH_RESULT_UNAVAILABLE = "unavailable"  # EE 503 / unreachable / timeout
REFRESH_RESULT_REJECTED = "rejected"  # EE 404 or returned license failed to apply
REFRESH_RESULT_ERROR = "error"  # unexpected EE response shape

# EE refresh endpoint. Env-configurable for dev/self-host; the app holds NO
# Paddle price IDs or Paddle API access — it only talks to the EE bridge.
EE_REFRESH_URL_ENV = "PRAXIS_EE_REFRESH_URL"
DEFAULT_EE_REFRESH_URL = "https://ee.praxisfleet.com/license/refresh"
EE_REFRESH_TIMEOUT_SECONDS = 10.0
# Auto-refresh only fires when the active license is inside this many days of
# expiry, so a normal startup makes no network call at all.
AUTO_REFRESH_WINDOW_DAYS = 7

LICENSE_PUBLIC_KEY_ENV = "PRAXIS_LICENSE_PUBLIC_KEY"
LICENSE_ALG = "EdDSA"

# Days an install that falls over the free cap (license expiry/removal) keeps
# operating existing hosts before the operator must reduce or re-license. Grace
# never disables existing hosts; it is a visible deadline + still blocks new adds.
GRACE_DAYS = 14


class LicenseError(Exception):
    """A license token was rejected. ``state`` is one of the LICENSE_STATE_* codes."""

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state = state
        self.message = message


@dataclass
class LicenseClaims:
    tier: str
    host_cap: int
    issued_to: Optional[str]
    instance_id: str
    expires_at: Optional[str]  # ISO 8601
    entitlements: List[str] = field(default_factory=list)
    license_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# AppSettings helpers (direct model access)
# --------------------------------------------------------------------------- #


def _get_setting(db: Session, key: str) -> Optional[str]:
    row = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if row is None or row.setting_value is None:
        return None
    return row.setting_value


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if row is not None:
        row.setting_value = value
    else:
        db.add(AppSettings(setting_key=key, setting_value=value))


def _clear_setting(db: Session, key: str) -> None:
    row = db.query(AppSettings).filter(AppSettings.setting_key == key).first()
    if row is not None:
        db.delete(row)


def get_or_create_instance_id(db: Session) -> str:
    """Stable per-installation id, created on first use and persisted. A license
    is bound to this value so a token cannot be copied to another install."""
    existing = _get_setting(db, INSTANCE_ID_KEY)
    if existing:
        return existing
    new_id = uuid.uuid4().hex
    _set_setting(db, INSTANCE_ID_KEY, new_id)
    db.commit()
    return new_id


def get_instance_id(db: Session) -> Optional[str]:
    """Read the instance id without creating one (safe at startup)."""
    return _get_setting(db, INSTANCE_ID_KEY)


# --------------------------------------------------------------------------- #
# Refresh-token storage (server-side secret, bound to instance_id)
# --------------------------------------------------------------------------- #


def _stored_refresh_token(db: Session) -> Optional[str]:
    """The stored refresh token IF it is bound to the current ``instance_id``,
    else ``None``. Reading through the instance binding means a token captured for
    a different install (e.g. a restored/cloned DB with a new instance) is never
    used. Never returned by any API surface — internal use only."""
    raw = _get_setting(db, REFRESH_KEY)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    instance_id = get_instance_id(db)
    if not instance_id or data.get("instance_id") != instance_id:
        return None
    token = data.get("token")
    return token or None


def refresh_configured(db: Session) -> bool:
    """Whether an online refresh token is stored for this install. Safe to expose
    (a boolean only) — the token itself is never returned."""
    return _stored_refresh_token(db) is not None


def store_refresh_token(db: Session, refresh_token: str, *, instance_id: str) -> None:
    """Persist the refresh token bound to ``instance_id``. Caller must have
    validated the license first. Does not commit."""
    token = (refresh_token or "").strip()
    if not token:
        return
    payload = json.dumps({"instance_id": instance_id, "token": token})
    _set_setting(db, REFRESH_KEY, payload)


def clear_refresh_token(db: Session) -> None:
    """Forget the stored refresh token (e.g. on license removal). Does not commit."""
    _clear_setting(db, REFRESH_KEY)


# --- Buy-license link (PRA-266) --------------------------------------------- #

# Purchase happens on the Praxis WEBSITE (the buy surface), not in-app. The app
# only sends the admin to that page with THIS install's server-owned instance_id
# prefilled; the website handles plan selection and calls the EE /checkout bridge.
# The app holds NO Paddle price IDs and never creates a checkout session.
BUY_LICENSE_URL_ENV = "PRAXIS_BUY_LICENSE_URL"
DEFAULT_BUY_LICENSE_URL = "https://praxisfleet.com/buy"


def buy_license_url(db: Session) -> str:
    """The Praxis website buy page with this install's ``instance_id`` prefilled
    as a URL-encoded query parameter. The base is env-configurable
    (``PRAXIS_BUY_LICENSE_URL``); the ``instance_id`` is server-owned (resolved
    here, never client-supplied)."""
    base = os.getenv(BUY_LICENSE_URL_ENV, DEFAULT_BUY_LICENSE_URL)
    instance_id = get_or_create_instance_id(db)
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}instance_id={quote(instance_id, safe='')}"


# Official Praxis builds ship the license verification PUBLIC key so a purchased
# license applies with no env setup — exactly as the production key ships for 1.0.
# This is the SANDBOX key for now; production cutover replaces it with the
# production public key. The PRIVATE signing key is NEVER in this repo, and this
# public key grants nothing on its own — only a valid CytechLabs-signed license
# unlocks paid features. ``PRAXIS_LICENSE_PUBLIC_KEY`` overrides it (dev / custom
# issuer testing).
DEFAULT_LICENSE_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAkMuXHM1rRlLMGt3KxsnsetZkYEBQQ+No4lcK4Cgec9E=\n"
    "-----END PUBLIC KEY-----\n"
)


def _public_key_pem() -> Optional[str]:
    """The verification key: the env override if set, else the built-in default
    shipped with official builds."""
    pem = os.getenv(LICENSE_PUBLIC_KEY_ENV, "").strip()
    return pem or DEFAULT_LICENSE_PUBLIC_KEY


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #


def _iso(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def verify_token(
    token: str,
    *,
    public_key_pem: str,
    expected_instance_id: str,
) -> LicenseClaims:
    """Verify signature + expiry + instance binding + shape. Raises
    :class:`LicenseError` with the appropriate state on any failure."""
    try:
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=[LICENSE_ALG],
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise LicenseError(LICENSE_STATE_EXPIRED, "license has expired") from exc
    except jwt.InvalidSignatureError as exc:
        raise LicenseError(LICENSE_STATE_INVALID, "invalid license signature") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise LicenseError(
            LICENSE_STATE_MALFORMED, "license is missing required claims"
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise LicenseError(LICENSE_STATE_MALFORMED, "malformed license token") from exc

    instance_id = payload.get("instance_id")
    if not instance_id:
        raise LicenseError(LICENSE_STATE_MALFORMED, "license has no instance_id")
    if instance_id != expected_instance_id:
        raise LicenseError(
            LICENSE_STATE_WRONG_INSTANCE,
            "license is bound to a different installation",
        )

    tier = payload.get("tier")
    if tier not in ALL_TIERS:
        raise LicenseError(LICENSE_STATE_INVALID, f"unsupported license tier: {tier!r}")

    host_cap = payload.get("host_cap", None)
    if not isinstance(host_cap, int) or host_cap < 0:
        raise LicenseError(LICENSE_STATE_MALFORMED, "invalid host_cap")

    raw_ents = payload.get("entitlements") or payload.get("features") or []
    if not isinstance(raw_ents, list):
        raise LicenseError(LICENSE_STATE_MALFORMED, "invalid entitlements claim")
    entitlements = [e for e in raw_ents if e in PAID_ENTITLEMENTS]

    # ``issued_to`` is the display-only organization/licensee name; its sole
    # authority is this signed claim. Normalize to a clean string (or None) so a
    # malformed/nested value can never surface raw metadata as the licensee name.
    # Only the explicit fields below are lifted from the token — arbitrary claims
    # (customer email, Paddle/checkout metadata) are never propagated.
    raw_issued_to = payload.get("issued_to")
    issued_to = raw_issued_to.strip() if isinstance(raw_issued_to, str) else None
    issued_to = issued_to or None  # empty/whitespace -> None

    return LicenseClaims(
        tier=tier,
        host_cap=host_cap,
        issued_to=issued_to,
        instance_id=instance_id,
        expires_at=_iso(payload.get("exp")),
        entitlements=entitlements,
        license_id=payload.get("license_id"),
    )


# --------------------------------------------------------------------------- #
# Evaluate / apply / remove
# --------------------------------------------------------------------------- #


def evaluate(db: Session) -> dict:
    """Validate the currently-stored token (if any) against this instance.
    Returns ``{"state": <LICENSE_STATE_*>, "claims": LicenseClaims|None}``. Pure
    read — does not mutate the registry."""
    token = _get_setting(db, LICENSE_TOKEN_KEY)
    if not token:
        return {"state": LICENSE_STATE_NONE, "claims": None}
    public_key = _public_key_pem()
    if not public_key:
        # A token is stored but the build has no verification key -> cannot trust.
        return {"state": LICENSE_STATE_INVALID, "claims": None}
    instance_id = get_instance_id(db)
    if not instance_id:
        return {"state": LICENSE_STATE_WRONG_INSTANCE, "claims": None}
    try:
        claims = verify_token(
            token, public_key_pem=public_key, expected_instance_id=instance_id
        )
    except LicenseError as exc:
        return {"state": exc.state, "claims": None}
    return {"state": LICENSE_STATE_ACTIVE, "claims": claims}


def _hydrate_from_claims(claims: LicenseClaims) -> None:
    if claims.tier in PAID_TIERS:
        registry.apply_license(
            tier=claims.tier,
            host_cap=claims.host_cap,
            entitlements=claims.entitlements,
            issued_to=claims.issued_to,
            expires_at=claims.expires_at,
            license_id=claims.license_id,
        )
    else:
        # A free-tier token grants nothing.
        registry.reset()


def hydrate_registry(db: Session) -> None:
    """Apply the stored license to the registry. **No-op when no token is
    stored** (so a stock free install — and the test harness — keeps whatever
    edition state is already configured). A stored-but-invalid token drops the
    registry to free with the matching license_state."""
    token = _get_setting(db, LICENSE_TOKEN_KEY)
    if not token:
        return
    result = evaluate(db)
    if result["state"] == LICENSE_STATE_ACTIVE and result["claims"] is not None:
        _hydrate_from_claims(result["claims"])
    else:
        registry.reset()
        registry.set_license_state(result["state"])


def active_host_count(db: Session) -> int:
    """Managed hosts that count toward the cap — everything except decommissioned
    rows (a soft-retired host does not consume a seat)."""
    return db.query(System).filter(System.status != "Decommissioned").count()


def _grace_until(db: Session) -> Optional[str]:
    return _get_setting(db, GRACE_UNTIL_KEY)


def _recompute_grace(db: Session, *, over_free_cap: bool) -> None:
    """Set a 14-day grace deadline the first time an unlicensed/over-cap install
    is seen; clear it once back within cap or re-licensed."""
    if over_free_cap:
        if not _get_setting(db, GRACE_UNTIL_KEY):
            until = (
                datetime.now(timezone.utc) + timedelta(days=GRACE_DAYS)
            ).isoformat()
            _set_setting(db, GRACE_UNTIL_KEY, until)
    else:
        _clear_setting(db, GRACE_UNTIL_KEY)


def host_cap_status(db: Session) -> dict:
    """Current host usage vs the effective cap, plus over-cap / grace status."""
    count = active_host_count(db)
    # None is internal unlimited mode, not issued-license policy.
    cap = registry.host_cap
    over_cap = cap is not None and count > cap
    at_cap = cap is not None and count >= cap
    grace_until = _grace_until(db)
    in_grace = False
    if grace_until:
        try:
            in_grace = datetime.now(timezone.utc) < datetime.fromisoformat(grace_until)
        except ValueError:
            in_grace = False
    return {
        "host_count": count,
        "host_cap": cap,
        "over_cap": over_cap,
        "at_cap": at_cap,
        "grace_until": grace_until,
        "in_grace": in_grace,
    }


def assert_can_add_host(db: Session, *, actor_user_id: Optional[int] = None) -> None:
    """Block creating a new managed host when it would exceed the effective cap.
    Never disables/deletes existing hosts. Internal unlimited mode
    (``host_cap is None``) always allows."""
    cap = registry.host_cap
    if cap is None:
        return
    count = active_host_count(db)
    if count >= cap:
        _emit(
            db,
            action="license.over_cap",
            outcome="denied",
            actor_user_id=actor_user_id,
            context={"host_count": count, "host_cap": cap, "tier": registry.tier},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Host cap reached ({count}/{cap}). The free edition manages up to "
                f"{FREE_HOST_CAP} hosts; apply a paid license to add more."
            ),
        )


# --------------------------------------------------------------------------- #
# Mutations (apply / remove) + audit
# --------------------------------------------------------------------------- #


def _emit(db: Session, **kwargs) -> None:
    """Best-effort audit; never let an audit failure block a license/host op."""
    try:
        from app.services.audit_event_service import safe_emit

        safe_emit(db=db, target_kind="license", target_id="license", **kwargs)
    except Exception:  # pragma: no cover - defensive
        logger.exception("license audit emit failed")


def apply_license(
    db: Session,
    token: str,
    *,
    actor_user_id: Optional[int] = None,
    refresh_token: Optional[str] = None,
) -> dict:
    """Validate + store + hydrate a license. On failure, nothing is stored (neither
    the license nor the refresh token) and a ``license.rejected`` audit is emitted;
    raises :class:`LicenseError`.

    ``refresh_token`` is optional online-refresh material. It is stored (bound to
    this install's ``instance_id``) **only after** the license itself validates, so
    an invalid license never leaves a refresh token behind. The token is never
    logged and never included in the audit context."""
    token = (token or "").strip()
    if not token:
        raise LicenseError(LICENSE_STATE_MALFORMED, "empty license token")
    public_key = _public_key_pem()
    if not public_key:
        raise LicenseError(
            LICENSE_STATE_INVALID,
            "this build has no license verification key configured",
        )
    instance_id = get_or_create_instance_id(db)
    try:
        claims = verify_token(
            token, public_key_pem=public_key, expected_instance_id=instance_id
        )
    except LicenseError as exc:
        _emit(
            db,
            action="license.rejected",
            outcome="denied",
            actor_user_id=actor_user_id,
            context={"reason": exc.state},
        )
        db.commit()
        raise

    _set_setting(db, LICENSE_TOKEN_KEY, token)
    _hydrate_from_claims(claims)
    _recompute_grace(db, over_free_cap=False)  # a fresh license clears grace
    # Only reached once the license validated: safe to persist the refresh token.
    if refresh_token:
        store_refresh_token(db, refresh_token, instance_id=instance_id)
    _emit(
        db,
        action="license.applied",
        outcome="success",
        actor_user_id=actor_user_id,
        context={
            "tier": claims.tier,
            "host_cap": claims.host_cap,
            "issued_to": claims.issued_to,
            "license_id": claims.license_id,
            "entitlements": claims.entitlements,
        },
    )
    db.commit()
    return license_status(db)


def remove_license(db: Session, *, actor_user_id: Optional[int] = None) -> dict:
    """Remove the applied license -> free edition. Existing hosts are untouched;
    if the install is now over the free cap, a grace deadline is recorded."""
    _clear_setting(db, LICENSE_TOKEN_KEY)
    # Forget online-refresh material too: an operator removing the license should
    # not have it silently re-applied by the auto-refresh path.
    clear_refresh_token(db)
    registry.reset()
    over = active_host_count(db) > FREE_HOST_CAP
    _recompute_grace(db, over_free_cap=over)
    _emit(
        db,
        action="license.removed",
        outcome="success",
        actor_user_id=actor_user_id,
        context={"over_free_cap": over},
    )
    db.commit()
    return license_status(db)


def reconcile_grace(db: Session) -> None:
    """Record/clear the 14-day grace deadline based on the CURRENT effective
    state. Runs on the read path so a license that lapsed at runtime (registry
    expiry) — not just via apply/remove — records grace when the install is over
    the free cap. Grace applies only when there is no covering active license.
    """
    over_free = (
        active_host_count(db) > FREE_HOST_CAP
        and registry.license_state != LICENSE_STATE_ACTIVE
    )
    _recompute_grace(db, over_free_cap=over_free)
    db.commit()


# --------------------------------------------------------------------------- #
# Online refresh (EE bridge)
# --------------------------------------------------------------------------- #


def _ee_refresh_url() -> str:
    return os.getenv(EE_REFRESH_URL_ENV, DEFAULT_EE_REFRESH_URL)


def _record_refresh_attempt(
    db: Session, result: str, detail: Optional[str] = None
) -> None:
    """Persist last-attempt timestamp + result for status/UI. All values are
    non-secret (no token, no Paddle/customer PII)."""
    _set_setting(db, REFRESH_LAST_ATTEMPT_KEY, datetime.now(timezone.utc).isoformat())
    _set_setting(db, REFRESH_LAST_RESULT_KEY, result)
    if detail:
        _set_setting(db, REFRESH_LAST_DETAIL_KEY, detail[:200])
    else:
        _clear_setting(db, REFRESH_LAST_DETAIL_KEY)


def _call_ee_refresh(
    instance_id: str, refresh_token: str
) -> Tuple[int, Optional[dict]]:
    """POST to the EE refresh bridge. Returns ``(status_code, json|None)``. Raises
    on transport failure (timeout / connection error) — the caller treats that as
    'unavailable'. Never logs the request body, refresh token, or response body."""
    import httpx  # lazy: keep the offline license path import-light

    with httpx.Client(timeout=EE_REFRESH_TIMEOUT_SECONDS) as client:
        resp = client.post(
            _ee_refresh_url(),
            json={"instance_id": instance_id, "refresh_token": refresh_token},
        )
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body


def online_refresh_status(db: Session) -> dict:
    """Non-secret online-refresh status for the frontend. **Never** includes the
    refresh token — only whether one is configured plus last-attempt metadata."""
    return {
        "configured": refresh_configured(db),
        "last_attempt_at": _get_setting(db, REFRESH_LAST_ATTEMPT_KEY),
        "last_result": _get_setting(db, REFRESH_LAST_RESULT_KEY),
        "last_detail": _get_setting(db, REFRESH_LAST_DETAIL_KEY),
    }


def refresh_license(db: Session, *, actor_user_id: Optional[int] = None) -> dict:
    """Attempt an online license refresh via the EE bridge.

    Fail-safe by contract: if refresh is not configured, EE is unavailable (503 /
    timeout / connection error), EE declines (404), or the returned license fails
    to apply, the **current license is left untouched** — this never invalidates or
    downgrades an otherwise-valid offline license. Returns
    ``{"result": <REFRESH_RESULT_*>, "detail": str|None, "status": <license_status>}``.
    """
    instance_id = get_instance_id(db)
    refresh_token = _stored_refresh_token(db)
    if not instance_id or not refresh_token:
        _record_refresh_attempt(db, REFRESH_RESULT_NOT_CONFIGURED)
        db.commit()
        return {
            "result": REFRESH_RESULT_NOT_CONFIGURED,
            "detail": "Online refresh is not configured for this installation.",
            "status": license_status(db),
        }

    try:
        status_code, body = _call_ee_refresh(instance_id, refresh_token)
    except Exception:  # pylint: disable=broad-except
        # Transport failure — never log the token; message is generic.
        logger.warning("license refresh: EE bridge unreachable")
        _record_refresh_attempt(
            db, REFRESH_RESULT_UNAVAILABLE, "License service is unreachable."
        )
        _emit(
            db,
            action="license.refresh",
            outcome="error",
            actor_user_id=actor_user_id,
            context={"result": REFRESH_RESULT_UNAVAILABLE},
        )
        db.commit()
        return {
            "result": REFRESH_RESULT_UNAVAILABLE,
            "detail": "License service is unreachable; current license kept.",
            "status": license_status(db),
        }

    if status_code == 200 and isinstance(body, dict) and body.get("license"):
        new_token = body["license"]
        try:
            # apply_license re-validates the returned JWT offline (signature +
            # instance binding) as defense in depth and commits on success.
            status_after = apply_license(db, new_token, actor_user_id=actor_user_id)
        except LicenseError:
            _record_refresh_attempt(
                db,
                REFRESH_RESULT_REJECTED,
                "Renewed license failed local validation; current license kept.",
            )
            db.commit()
            return {
                "result": REFRESH_RESULT_REJECTED,
                "detail": "Renewed license failed local validation; current license kept.",
                "status": license_status(db),
            }
        _record_refresh_attempt(db, REFRESH_RESULT_OK)
        _emit(
            db,
            action="license.refresh",
            outcome="success",
            actor_user_id=actor_user_id,
            context={"result": REFRESH_RESULT_OK},
        )
        db.commit()
        return {
            "result": REFRESH_RESULT_OK,
            "detail": None,
            "status": status_after,
        }

    if status_code == 404:
        _record_refresh_attempt(
            db,
            REFRESH_RESULT_REJECTED,
            "License service declined the refresh; current license kept.",
        )
        result = REFRESH_RESULT_REJECTED
        detail = "License service declined the refresh; current license kept."
    elif status_code == 503:
        _record_refresh_attempt(
            db, REFRESH_RESULT_UNAVAILABLE, "License service is unavailable."
        )
        result = REFRESH_RESULT_UNAVAILABLE
        detail = "License service is unavailable; current license kept."
    else:
        _record_refresh_attempt(
            db,
            REFRESH_RESULT_ERROR,
            f"Unexpected response from license service ({status_code}).",
        )
        result = REFRESH_RESULT_ERROR
        detail = "Unexpected response from license service; current license kept."

    _emit(
        db,
        action="license.refresh",
        outcome="error",
        actor_user_id=actor_user_id,
        context={"result": result, "http_status": status_code},
    )
    db.commit()
    return {"result": result, "detail": detail, "status": license_status(db)}


def _expires_within(db: Session, days: int) -> bool:
    """True when there is an active license whose expiry is within ``days``."""
    result = evaluate(db)
    if result["state"] != LICENSE_STATE_ACTIVE or result["claims"] is None:
        return False
    exp = result["claims"].expires_at
    if not exp:
        return False
    try:
        dt = datetime.fromisoformat(exp)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt - datetime.now(timezone.utc) <= timedelta(days=days)


def maybe_auto_refresh(
    db: Session, *, window_days: int = AUTO_REFRESH_WINDOW_DAYS
) -> Optional[dict]:
    """Best-effort auto-refresh for connected installs: if a refresh token is
    configured and the active license expires within ``window_days``, attempt a
    refresh. Returns the refresh outcome, or ``None`` when skipped. **Never
    raises** and never downgrades/clears the current license — safe to call on the
    startup path or a scheduled maintenance tick."""
    try:
        if not refresh_configured(db):
            return None
        if not _expires_within(db, window_days):
            return None
        logger.info("license auto-refresh: license near expiry, attempting refresh")
        return refresh_license(db)
    except Exception:  # pylint: disable=broad-except
        logger.warning("license auto-refresh failed (non-fatal)")
        return None


def license_status(db: Session) -> dict:
    """Full edition + license + host-cap status for ``GET /edition``."""
    reconcile_grace(db)
    caps = host_cap_status(db)
    snapshot = edition_snapshot(host_count=caps["host_count"])
    snapshot["instance_id"] = get_or_create_instance_id(db)
    snapshot["host_count"] = caps["host_count"]
    snapshot["over_cap"] = caps["over_cap"]
    snapshot["at_cap"] = caps["at_cap"]
    snapshot["grace_until"] = caps["grace_until"]
    snapshot["in_grace"] = caps["in_grace"]
    # Online-refresh status (never includes the token itself).
    snapshot["online_refresh"] = online_refresh_status(db)
    return snapshot
