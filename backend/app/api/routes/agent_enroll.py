"""PRA-154 slice #1c: activation-token enrollment endpoint.

``POST /agent/enroll`` is the bootstrap-side companion to the admin
CRUD in ``activation_tokens.py``. A host runs the bootstrap script,
the script POSTs its CSR + the activation token here, and we return
M13 cert material so the agent can dial the broker.

Auth model is intentionally different from the rest of ``/agent/*``:

  * No JWT — the host has no Praxis user identity. The activation
    token IS the auth, surfaced as the ``X-Praxis-Activation-Token``
    header. We use a custom header (not ``Authorization: Bearer``)
    so the JWTAuthMiddleware path stays cleanly JWT-shaped and the
    enrollment trust boundary is obvious in middleware/logs.
  * The path is added to the ``JWTAuthMiddleware`` allow-list so the
    request reaches the route. Token verification is the route's
    job; there is no anonymous access.

Failure paths collapse all token-gate failures (missing, malformed,
unknown, expired, exhausted, revoked) into a single 401 with a
generic message. The specific reason is recorded in the failure
audit row but never returned to the caller — bootstrap is
internet-adjacent, so leaking which arm failed would help an
attacker iterate on a stolen token.

Link-only for #1c. ``system_id`` must already exist; the host create
path is deferred until ``default_credentials_id`` is added to the
token model.

Response scope: this endpoint returns cert material only — certificate,
ca_chain, serial_number, fingerprint, expires_at, plus
``agent_status`` and ``was_first_redeem``. It does NOT return the
broker URL or broker CA bundle. The bootstrap script in slice #1d is
expected to fetch the CA bundle from ``/agent/ca-bundle`` (anonymous,
already mounted) and obtain the broker URL from operator-supplied
config, not from this response. Keeping the redemption response
narrow avoids broadening the public bootstrap surface.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.support_logging import log_support_event
from ...db.session import get_db
from ...services import activation_token_service as svc

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


# ----------------------------------------------------------- request / response


class EnrollRequest(BaseModel):
    system_id: int = Field(..., ge=1)
    host_fingerprint: str = Field(..., min_length=1, max_length=512)
    csr_pem: str = Field(..., min_length=1)
    # Advisory only — used for the redemption ledger and audit context.
    # System.hostname comes from operator pre-registration and is never
    # overwritten by host-supplied data here.
    hostname: Optional[str] = Field(default=None, max_length=255)
    # PRA-155 #2a wires this through to FactsService.ingest after a
    # successful redemption. system_id for the ingest is taken from the
    # redeemed token's resolved system, NOT from anything in this dict —
    # never trust caller-supplied identity here.
    facts: Optional[Dict[str, Any]] = None


class EnrollResponse(BaseModel):
    system_id: int
    hostname: str
    certificate: str
    ca_chain: list
    serial_number: str
    fingerprint: str
    expires_at: str
    agent_status: str
    was_first_redeem: bool


# ---------------------------------------------------------------- helpers


_REASON_TO_STATUS = {
    "invalid_token": 401,
    "unknown_system": 404,
    "scope_mismatch": 409,
    "system_already_bound": 409,
    "csr_invalid": 400,
}

_REASON_TO_PUBLIC_DETAIL = {
    "invalid_token": "invalid activation token",
    "unknown_system": "system not found",
    "scope_mismatch": "system placement does not match token",
    "system_already_bound": "system already bound to a different host via this token",
    "csr_invalid": "CSR could not be signed",
}


def _client_ip(request: Request) -> Optional[str]:
    """Best-effort extraction. ``X-Forwarded-For`` is honored only when
    the deployment terminates TLS at a trusted proxy; for the host bootstrap
    flow we just take the immediate peer."""
    if request.client is None:
        return None
    return request.client.host


def _emit_failure(
    db: Session,
    *,
    reason: str,
    plaintext_attempt: Optional[str],
    body: Optional[EnrollRequest],
) -> None:
    """Failure-path audit. We have no token row to anchor target_id to
    when the reason is invalid_token, so target_id stays None and any
    parseable prefix lands in context. Plaintext is never persisted."""
    context: Dict[str, Any] = {"reason": reason}
    prefix = svc.parse_token_prefix(plaintext_attempt)
    if prefix is not None:
        context["token_prefix"] = prefix
    if body is not None:
        context["system_id"] = body.system_id
        context["hostname"] = body.hostname
    try:
        from ...services.audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="activation_token.redeem",
            outcome="failure",
            actor_user_id=None,
            target_kind="activation_token",
            target_id=None,
            context=context,
        )
    except Exception:  # pylint: disable=broad-except
        pass


def _emit_success(
    db: Session,
    *,
    result: svc.RedeemResult,
    last_seen_ip: Optional[str],
) -> None:
    """Post-commit success audit. actor_user_id is None: bootstrap has
    no Praxis user principal. Token identity belongs in context, not in
    actor_username (that field has historically meant a real user)."""
    cert = result.cert
    expires = cert.get("expires_at")
    expires_str = expires if isinstance(expires, str) else expires.isoformat() + "Z"
    context = {
        "activation_token_id": result.token.id,
        "token_prefix": result.token.token_prefix,
        "created_by_user_id": result.token.created_by_user_id,
        "system_id": result.system.id,
        "hostname": result.system.hostname,
        "host_fingerprint_hash": result.redemption.host_fingerprint_hash,
        "was_first_redeem": result.was_first_redeem,
        "cert_serial": cert.get("serial_number"),
        "cert_expires_at": expires_str,
        "last_seen_ip": last_seen_ip,
    }
    try:
        from ...services.audit_event_service import safe_emit

        safe_emit(
            db=db,
            action="activation_token.redeem",
            outcome="success",
            actor_user_id=None,
            target_kind="activation_token",
            target_id=str(result.token.id),
            context=context,
        )
    except Exception:  # pylint: disable=broad-except
        pass


# ---------------------------------------------------------------- route


@router.post("/enroll", response_model=EnrollResponse)
def enroll_via_activation_token(
    body: EnrollRequest,
    request: Request,
    db: Session = Depends(get_db),
    x_praxis_activation_token: Optional[str] = Header(default=None),
):
    """Redeem an activation token for cert material. Anonymous in the
    JWT sense — auth is the activation token in the
    ``X-Praxis-Activation-Token`` header. Path is added to the JWT
    middleware allow-list."""
    if not x_praxis_activation_token:
        _emit_failure(
            db,
            reason="invalid_token",
            plaintext_attempt=None,
            body=body,
        )
        db.commit()
        log_support_event(
            logger,
            "host.enroll",
            level=logging.WARNING,
            outcome="failure",
            error_category="invalid_token",
            system_id=body.system_id,
        )
        raise HTTPException(
            status_code=401,
            detail=_REASON_TO_PUBLIC_DETAIL["invalid_token"],
        )

    try:
        result = svc.redeem_token(
            db,
            plaintext=x_praxis_activation_token,
            system_id=body.system_id,
            host_fingerprint=body.host_fingerprint,
            csr_pem=body.csr_pem,
            hostname=body.hostname,
            last_seen_ip=_client_ip(request),
        )
    except svc.RedemptionError as exc:
        # record_redemption's IntegrityError path already rolled back;
        # call rollback unconditionally so any flushed-but-uncommitted
        # mutations (tag joins, pre-sign state) are wiped before we
        # emit the failure audit on a clean session.
        db.rollback()
        _emit_failure(
            db,
            reason=exc.reason,
            plaintext_attempt=x_praxis_activation_token,
            body=body,
        )
        db.commit()
        log_support_event(
            logger,
            "host.enroll",
            level=logging.WARNING,
            outcome="failure",
            error_category=exc.reason,
            system_id=body.system_id,
        )
        raise HTTPException(
            status_code=_REASON_TO_STATUS.get(exc.reason, 400),
            detail=_REASON_TO_PUBLIC_DETAIL.get(exc.reason, "enrollment failed"),
        ) from exc

    # issue_for_bootstrap committed already; this commit is a no-op
    # on the request session, kept for symmetry with the failure path
    # so the transaction boundary is obvious to a reader.
    db.commit()
    db.refresh(result.token)
    db.refresh(result.system)

    _emit_success(db, result=result, last_seen_ip=_client_ip(request))
    log_support_event(
        logger, "host.enroll", outcome="success", system_id=result.system.id
    )

    # Optional facts ingest — never blocks enrollment. system_id is the
    # post-redemption resolved system, not a caller-supplied id.
    if body.facts is not None:
        try:
            from ...services import facts_service

            facts_service.ingest(
                db,
                system_id=result.system.id,
                payload=body.facts,
                source_transport="agent",
            )
        except Exception:  # pylint: disable=broad-except
            # Facts ingest failures must not fail the cert response —
            # the bootstrap-script contract is "you got your cert, the
            # tunnel can come up". Inventory is best-effort, recoverable
            # on the next collection. Ingest already audits its own
            # failure paths.
            logger.warning(
                "facts ingest after enroll failed for system_id=%s",
                result.system.id,
                exc_info=True,
            )

    cert = result.cert
    expires = cert["expires_at"]
    expires_str = expires if isinstance(expires, str) else expires.isoformat() + "Z"
    return {
        "system_id": result.system.id,
        "hostname": result.system.hostname,
        "certificate": cert["certificate"],
        "ca_chain": cert.get("ca_chain") or [],
        "serial_number": cert["serial_number"],
        "fingerprint": cert["fingerprint"],
        "expires_at": expires_str,
        "agent_status": result.system.agent_status,
        "was_first_redeem": result.was_first_redeem,
    }
