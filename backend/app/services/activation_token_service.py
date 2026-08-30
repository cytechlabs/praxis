"""PRA-154 slice #1a: activation token issuance, verification, and ledger.

Service layer for the M14 one-line agent enrollment flow. Slice #1a is
schema + service only; HTTP endpoints, the redemption-create-host path,
and the bootstrap script land in later slices.

Token shape:

    raw secret  : 32 random bytes from ``secrets.token_bytes``
    on the wire : ``praxis_<base32-no-padding>`` (lowercase)
    at rest     : bcrypt hash of the raw bytes (passlib ``bcrypt`` scheme)
    UI/debug    : ``token_prefix`` = first 8 chars of the base32 body

Bcrypt is the right tool here even though argon2 would be marginally
nicer: passlib's bcrypt scheme is already a hard dependency for user
passwords (``app.core.security``) and TOTP recovery codes
(``totp_service``), so reusing it keeps activation tokens consistent
with the rest of the codebase and avoids a new optional dep.

Verification uses a token_prefix index lookup followed by a bcrypt
compare. Token_prefix collisions are vanishingly unlikely (8 chars of
base32 = 40 bits of entropy in the prefix alone) but the verify path
iterates all prefix matches and bcrypt-checks each — cost stays O(1)
in practice.

Redemption ledger:

    (activation_token_id, host_fingerprint_hash) is unique. Same host
    re-running bootstrap with the same token resolves to the same
    redemption row, which is how callers get a stable
    ``system_id`` across reruns. The raw fingerprint is sha256'd
    before the DB ever sees it.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets as secrets_mod
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import ActivationToken, ActivationTokenRedemption, System, Tag

logger = logging.getLogger(__name__)


_TOKEN_PREFIX = "praxis_"
_RAW_BYTES = 32
_PREFIX_DISPLAY_LEN = 8
# Documents the on-the-wire alphabet contract: praxis_ + lowercase
# RFC 4648 base32 characters (a-z2-7), no padding. Asserted at issue
# time as belt-and-suspenders against any future encoder change that
# might leak shell-special characters into the bootstrap_command
# string (which is single-quoted but still — easier to fail loud).
_TOKEN_PLAINTEXT_RE = re.compile(r"^praxis_[a-z2-7]+$")


# ---------------------------------------------------------------- helpers


@dataclass(frozen=True)
class IssuedToken:
    """Returned to the operator at create time. The plaintext is
    surfaced exactly once and must not be persisted by the caller."""

    token: ActivationToken
    plaintext: str


class RedemptionError(Exception):
    """Raised by ``redeem_token`` when bootstrap should be rejected.

    ``reason`` is a short stable code the route maps to an HTTP status
    code. The bootstrap response surfaces only a generic message — the
    reason itself is recorded in the failure audit row.
    """

    REASONS = (
        "invalid_token",  # token gate (any arm) — collapses to a single 401
        "unknown_system",
        "scope_mismatch",
        "system_already_bound",
        "csr_invalid",
    )

    def __init__(self, reason: str, message: Optional[str] = None) -> None:
        super().__init__(message or reason)
        self.reason = reason


@dataclass
class RedeemResult:
    """Output of ``redeem_token`` — used by the bootstrap route to build
    the cert response and emit success audit."""

    token: ActivationToken
    system: System
    redemption: ActivationTokenRedemption
    cert: dict
    was_first_redeem: bool


def _encode_secret(raw: bytes) -> str:
    body = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return f"{_TOKEN_PREFIX}{body}"


def _split_plaintext(plaintext: str) -> Optional[str]:
    """Return the base32 body if the plaintext looks well-formed."""
    if not plaintext or not plaintext.startswith(_TOKEN_PREFIX):
        return None
    body = plaintext[len(_TOKEN_PREFIX) :]
    if len(body) < _PREFIX_DISPLAY_LEN:
        return None
    return body


def hash_fingerprint(fingerprint: str) -> str:
    """Stable sha256 hex of a host-supplied fingerprint string. The raw
    fingerprint never lands in the database."""
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- issuance


def emit_audit(
    db: Session,
    *,
    action: str,
    token: ActivationToken,
    actor_user_id: Optional[int],
    outcome: str = "success",
    extra_context: Optional[dict] = None,
) -> None:
    """Emit an ``activation_token.*`` audit event.

    **Call this AFTER the route's business commit, never before.**

    ``audit_event_service.emit`` calls ``db.commit()`` on the session it
    receives. If a service mutator emits while the route's transaction
    is still in flight, the mutation leaks early and a later route-level
    failure can no longer roll it back. The fix is purely one of order:
    routes mutate, commit, and only then call this helper. By that
    point the request transaction is already durable, so the additional
    commit inside ``emit`` just commits the audit row alone — same
    session-reuse pattern access_request_service uses.

    A token is bound to one host at issue time and ``target_system_id`` on the
    model is not nullable, so every event in the token's lifecycle is about
    that host and names it. The target stays the token itself, which is what
    the action acts on.
    """
    context = {
        "name": token.name,
        "token_prefix": token.token_prefix,
        "default_group_id": token.default_group_id,
        "default_tag_ids": list(token.default_tag_ids or []),
        "max_uses": token.max_uses,
        "uses_count": token.uses_count,
    }
    if token.ttl_expires_at is not None:
        context["ttl_expires_at"] = token.ttl_expires_at.isoformat() + "Z"
    if extra_context:
        context.update(extra_context)
    try:
        from .audit_event_service import safe_emit  # local import on hot path

        safe_emit(
            db=db,
            action=action,
            outcome=outcome,
            actor_user_id=actor_user_id,
            target_system_id=token.target_system_id,
            target_kind="activation_token",
            target_id=str(token.id) if token.id is not None else None,
            context=context,
        )
    except Exception:  # pylint: disable=broad-except
        pass


def issue_token(
    db: Session,
    *,
    name: str,
    default_group_id: int,
    target_system_id: int,
    ttl_expires_at: datetime,
    max_uses: int,
    created_by_user_id: int,
    default_tag_ids: Optional[Iterable[int]] = None,
) -> IssuedToken:
    """Mint a new activation token and persist it.

    The plaintext is returned on the ``IssuedToken`` and is the only
    chance the operator has to see it. Callers must enforce admin
    scope.

    Service owns the placement invariants so future callers (CLI,
    internal scripts) cannot mint a token whose target system lives
    in a different group than the token's ``default_group_id``. We
    load the System inside the service for the same reason — route-
    only validation would create a soft contract that any new caller
    could miss.

    For #1c link-only redemption, ``max_uses`` is forced to ``1`` at
    the route boundary because the (token_id, system_id) ledger
    unique already implies one-shot redemption once a target is
    bound. This service still accepts larger ``max_uses`` so the
    column survives for the eventual bulk-enrollment slice.
    """
    if max_uses < 1:
        raise ValueError("max_uses must be >= 1")
    # Service owns the link-only invariant alongside
    # the placement check, so a future internal caller cannot mint a
    # token with target_system_id + max_uses>1. With one bound system
    # the (token_id, system_id) ledger unique already caps real
    # redemptions at 1 — letting max_uses exceed that just makes the
    # token look "active" after exhaustion. The route's Pydantic
    # ge=1/le=1 clamp catches HTTP callers; this catches everyone
    # else. Relax this when create-on-redemption lands.
    if max_uses != 1:
        raise ValueError(
            "max_uses must be exactly 1 while target_system_id is required"
        )
    if not name or not name.strip():
        raise ValueError("name is required")

    target = db.query(System).filter(System.id == target_system_id).first()
    if target is None:
        raise ValueError(f"target_system_id {target_system_id} not found")
    if target.group_id != default_group_id:
        raise ValueError("target system group does not match default_group_id")

    raw = secrets_mod.token_bytes(_RAW_BYTES)
    plaintext = _encode_secret(raw)
    # Pin the on-the-wire alphabet so callers (notably the
    # bootstrap_command builder, which embeds the plaintext into a
    # single-quoted shell string) can rely on no shell-special
    # characters leaking through. Failing here means our own encoder
    # produced something off-spec — a code bug, not user input.
    if _TOKEN_PLAINTEXT_RE.match(plaintext) is None:
        raise RuntimeError(
            "issued plaintext violates praxis_<lowercase base32> contract"
        )
    body = plaintext[len(_TOKEN_PREFIX) :]
    prefix = body[:_PREFIX_DISPLAY_LEN]
    token_hash = bcrypt.hash(plaintext)

    tag_ids: List[int] = list(default_tag_ids or [])

    token = ActivationToken(
        name=name.strip(),
        token_hash=token_hash,
        token_prefix=prefix,
        default_group_id=default_group_id,
        target_system_id=target_system_id,
        default_tag_ids=tag_ids,
        ttl_expires_at=ttl_expires_at,
        max_uses=max_uses,
        uses_count=0,
        created_by_user_id=created_by_user_id,
    )
    db.add(token)
    db.flush()
    return IssuedToken(token=token, plaintext=plaintext)


# ---------------------------------------------------------------- verify


def _find_token_by_plaintext(db: Session, plaintext: str) -> Optional[ActivationToken]:
    """Hash-aware token lookup with no gate checks.

    Used by ``redeem_token`` so the under-lock path can apply gate
    checks that depend on whether this redeemer already has a
    redemption row (idempotent re-runs must bypass the uses cap).
    """
    body = _split_plaintext(plaintext)
    if body is None:
        return None
    prefix = body[:_PREFIX_DISPLAY_LEN]
    candidates = (
        db.query(ActivationToken).filter(ActivationToken.token_prefix == prefix).all()
    )
    for cand in candidates:
        try:
            if bcrypt.verify(plaintext, cand.token_hash):
                return cand
        except (ValueError, TypeError) as exc:
            logger.warning(
                "activation_token verify: malformed hash on token id=%s: %s",
                cand.id,
                exc,
            )
            continue
    return None


def verify_plaintext(
    db: Session,
    plaintext: str,
    *,
    now: Optional[datetime] = None,
) -> Optional[ActivationToken]:
    """Resolve a plaintext token to a live ``ActivationToken`` row.

    Returns ``None`` for malformed, unknown, expired, exhausted, or
    revoked tokens. Callers must not branch on which of those it was —
    the redemption endpoint should respond with a single generic
    failure to avoid leaking which arm of the check failed.

    Note: this helper enforces the ``uses_count >= max_uses`` cap.
    ``redeem_token`` does NOT use this helper directly so that
    idempotent re-runs from a known fingerprint can bypass the cap;
    see ``_find_token_by_plaintext``.
    """
    cand = _find_token_by_plaintext(db, plaintext)
    if cand is None:
        return None
    now = now or datetime.utcnow()
    if cand.revoked_at is not None:
        return None
    if cand.ttl_expires_at <= now:
        return None
    if cand.uses_count >= cand.max_uses:
        return None
    return cand


# ---------------------------------------------------------------- revoke


def revoke_token(
    db: Session,
    token: ActivationToken,
    *,
    revoked_by_user_id: Optional[int],
    now: Optional[datetime] = None,
) -> ActivationToken:
    """Mark a token revoked. Idempotent — re-revoking is a no-op."""
    if token.revoked_at is not None:
        return token
    token.revoked_at = now or datetime.utcnow()
    token.revoked_by_user_id = revoked_by_user_id
    db.flush()
    return token


# ---------------------------------------------------------------- ledger


def record_redemption(
    db: Session,
    *,
    token: ActivationToken,
    host_fingerprint: str,
    system_id: Optional[int] = None,
    last_seen_hostname: Optional[str] = None,
    last_seen_ip: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Tuple[ActivationTokenRedemption, bool]:
    """Idempotent upsert into the redemption ledger.

    Returns ``(redemption, created)``. When ``created`` is True we
    also bumped ``token.uses_count``; on a repeat redemption the
    counter does not move, so a host re-running bootstrap doesn't
    burn a use against the cap.

    Callers must verify ``token`` is live (non-revoked, in-TTL,
    under cap) BEFORE calling. ``record_redemption`` only enforces
    the durable idempotency invariant; it does not re-check the
    token gate. Callers also own the transaction boundary — on
    ``IntegrityError`` this helper does not roll back; the caller
    decides whether to rollback or convert the error.

    For #1a, ``system_id`` may be passed as None because the
    create-or-link path is not wired yet. Later slices will look up
    an existing redemption first to recover a prior ``system_id``.
    """
    fp_hash = hash_fingerprint(host_fingerprint)
    now = now or datetime.utcnow()

    existing = (
        db.query(ActivationTokenRedemption)
        .filter(
            ActivationTokenRedemption.activation_token_id == token.id,
            ActivationTokenRedemption.host_fingerprint_hash == fp_hash,
        )
        .one_or_none()
    )
    if existing is not None:
        existing.last_redeemed_at = now
        existing.redeem_count += 1
        if last_seen_hostname is not None:
            existing.last_seen_hostname = last_seen_hostname
        if last_seen_ip is not None:
            existing.last_seen_ip = last_seen_ip
        # If a prior call recorded system_id and this one omits it,
        # keep the bound system_id stable. Never let a later call
        # silently re-bind to a different system_id.
        if system_id is not None and existing.system_id is None:
            existing.system_id = system_id
        elif (
            system_id is not None
            and existing.system_id is not None
            and existing.system_id != system_id
        ):
            raise ValueError(
                "redemption already bound to a different system_id; "
                "refusing to rebind"
            )
        db.flush()
        return existing, False

    redemption = ActivationTokenRedemption(
        activation_token_id=token.id,
        host_fingerprint_hash=fp_hash,
        system_id=system_id,
        first_redeemed_at=now,
        last_redeemed_at=now,
        redeem_count=1,
        last_seen_hostname=last_seen_hostname,
        last_seen_ip=last_seen_ip,
    )
    db.add(redemption)
    token.uses_count += 1
    # Either the unique (token, fingerprint) raced or the unique
    # (token, system_id) caught a different host trying to claim an
    # already-bound system_id. We do not roll back here — that's the
    # caller's responsibility, since this helper does not own the
    # transaction boundary. Caller catches IntegrityError, decides
    # whether to rollback or wrap the error, and surfaces a stable
    # response.
    db.flush()
    return redemption, True


# ---------------------------------------------------------------- redemption


def _apply_tags_union(db: Session, system: System, tag_ids: Iterable[int]) -> None:
    """Union the token's default tags onto the system. Never strips
    operator-applied tags. Unknown tag ids are silently skipped — the
    create-time validation in the route already rejected those, so
    seeing one here means the tag was deleted between create and
    redeem; it's not worth blocking enrollment for."""
    target_ids = list(tag_ids or [])
    if not target_ids:
        return
    existing_ids = {t.id for t in (system.tags or [])}
    missing = [tid for tid in target_ids if tid not in existing_ids]
    if not missing:
        return
    found = db.query(Tag).filter(Tag.id.in_(missing)).all()
    for t in found:
        system.tags.append(t)


def redeem_token(
    db: Session,
    *,
    plaintext: str,
    system_id: int,
    host_fingerprint: str,
    csr_pem: str,
    hostname: Optional[str] = None,
    last_seen_ip: Optional[str] = None,
    actor_user_id: Optional[int] = None,
) -> RedeemResult:
    """Redeem an activation token for a pre-existing System (link-only).

    Order is deliberate:

    1. ``verify_plaintext`` — locate the token (no mutation).
    2. ``SELECT ... FOR UPDATE`` on that token row — serialize concurrent
       redemptions of the same token, then re-check gates under the
       lock so a one-use token cannot be claimed by two racing hosts.
    3. Load the target System and confirm scope (group must match the
       token's ``default_group_id``).
    4. ``record_redemption`` — idempotent ledger upsert. On a repeat
       (same fingerprint, same system) ``uses_count`` does not move.
       On a different fingerprint claiming an already-bound system,
       the ``(token_id, system_id)`` unique constraint trips and we
       refuse before doing any expensive work.
    5. Apply token's default tags as a union onto the system.
    6. Sign the CSR via ``AgentIdentityService.issue_for_bootstrap``.
       Signing happens **last** so a ledger or scope failure cannot
       leave a Vault-issued cert paired with a redemption row that
       never persisted.

    ``issue_for_bootstrap`` commits the request transaction internally
    once Vault returns. Anything earlier in this function flushes
    only; if signing or any earlier step raises, the route's
    rollback wipes the ledger row, tag joins, and uses_count bump
    along with the System status update.

    For #1c this is link-only: ``system_id`` must reference an
    existing System. Create-on-redemption is deferred to a later
    slice that ships ``default_credentials_id`` on the token.
    """
    # 1. Token lookup. Gate checks come AFTER the lock + ledger lookup
    #    so an idempotent rerun from a known fingerprint can bypass
    #    the uses cap (otherwise max_uses=1 would forbid the second
    #    bootstrap from the same host).
    candidate = _find_token_by_plaintext(db, plaintext)
    if candidate is None:
        raise RedemptionError("invalid_token")

    # 2. Re-fetch under row lock so concurrent redemptions of the same
    #    token serialize through here.
    locked = (
        db.query(ActivationToken)
        .filter(ActivationToken.id == candidate.id)
        .with_for_update()
        .one()
    )
    now = datetime.utcnow()
    if locked.revoked_at is not None or locked.ttl_expires_at <= now:
        raise RedemptionError("invalid_token")

    # 2a. Was this fingerprint already redeemed? If so, this is an
    #     idempotent rerun and the uses_count cap doesn't apply.
    fp_hash = hash_fingerprint(host_fingerprint)
    prior_redemption = (
        db.query(ActivationTokenRedemption)
        .filter(
            ActivationTokenRedemption.activation_token_id == locked.id,
            ActivationTokenRedemption.host_fingerprint_hash == fp_hash,
        )
        .one_or_none()
    )
    if prior_redemption is None and locked.uses_count >= locked.max_uses:
        raise RedemptionError("invalid_token")

    # 3. Load the system and scope-check. Tokens are bound to a
    #    specific target system at create time (#1d-α); the request
    #    must agree. Group match is kept as defense-in-depth in case
    #    the system is moved between groups after token issuance.
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise RedemptionError("unknown_system")
    if system.id != locked.target_system_id:
        raise RedemptionError("scope_mismatch")
    if system.group_id != locked.default_group_id:
        raise RedemptionError("scope_mismatch")

    # 4. Ledger upsert. record_redemption raises ValueError if a prior
    #    redemption bound this fingerprint to a different system, and
    #    IntegrityError if a different fingerprint already claimed
    #    this system via this token.
    try:
        redemption, was_first_redeem = record_redemption(
            db,
            token=locked,
            host_fingerprint=host_fingerprint,
            system_id=system.id,
            last_seen_hostname=hostname,
            last_seen_ip=last_seen_ip,
        )
    except (IntegrityError, ValueError) as exc:
        raise RedemptionError("system_already_bound") from exc

    # 5. Tag union.
    _apply_tags_union(db, system, list(locked.default_tag_ids or []))

    # 6. Sign via the M13 PKI path. issue_for_bootstrap commits the
    #    request transaction itself; if Vault errors, nothing here
    #    has been committed yet.
    from .agent_identity_service import (  # local import to avoid cycle
        AgentIdentityError,
        AgentIdentityService,
    )

    try:
        cert = AgentIdentityService(db).issue_for_bootstrap(
            system_id=system.id,
            csr_pem=csr_pem,
            actor_user_id=actor_user_id,
        )
    except AgentIdentityError as exc:
        raise RedemptionError("csr_invalid", str(exc)) from exc

    return RedeemResult(
        token=locked,
        system=system,
        redemption=redemption,
        cert=cert,
        was_first_redeem=was_first_redeem,
    )


def parse_token_prefix(plaintext: Optional[str]) -> Optional[str]:
    """Best-effort parse of the displayable prefix from a plaintext token.
    Used by failure-path audit emit to record forensics without leaking
    or persisting the secret. Returns None on any parse failure."""
    if not plaintext:
        return None
    body = _split_plaintext(plaintext)
    if body is None:
        return None
    return body[:_PREFIX_DISPLAY_LEN]
