"""PRA-150: agent identity API.

Bootstrap, renewal, and lifecycle endpoints for the M13 thin agent.

Bootstrap flow (M13: SSH-once validation):
    1. Operator clicks "enroll agent" in the control plane UI for system X.
    2. Caller posts a CSR to ``POST /agent/bootstrap/{system_id}``.
    3. Backend opens an SSH session to system X using the existing per-host
       bootstrap credential. If SSH succeeds, the host is who we say it is.
    4. Backend signs the CSR via the praxis-agent-ca PKI mount and returns
       ``{certificate, ca_chain, serial_number, fingerprint, expires_at}``.

Renewal happens over the live mTLS tunnel (PRA-151). The renewal endpoint
exposed here requires admin auth as a placeholder; PRA-151 will replace
the auth dep with mTLS cert extraction so agents can renew themselves.

All state-changing operations also emit ``agent.*`` audit events via
``agent_identity_service`` (see PRA-143 schema).
"""

import asyncio
import concurrent.futures
import logging
import os
import time
from typing import Any, Awaitable, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.auth import require_role
from ...db.models import System, User
from ...db.session import get_db
from ...services.agent_identity_service import AgentIdentityError, AgentIdentityService
from ...services.ssh_service import SSHConnectionError, SSHService

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)

# Default file paths populated by init-vault.sh. Operator overrides via
# env so external-Vault deployments (where /vault/data isn't shared)
# point at operator-managed cert paths.
DEFAULT_AGENT_CA_PATH = "/vault/data/agent-ca-cert.pem"
DEFAULT_BROKER_CA_PATH = "/vault/data/broker/ca.crt"

# Cache window for the public CA bundle. Files only change at vault
# init or operator regen; one-minute cache is plenty.
CA_BUNDLE_CACHE_SECONDS = 60.0
_ca_bundle_cache: Optional[Tuple[float, Dict[str, str]]] = None


# ---------- request models ----------


class CSRBody(BaseModel):
    csr_pem: str = Field(..., min_length=1, description="PEM-encoded PKCS#10 CSR")


class DisableBody(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=255)


class RevokeBody(BaseModel):
    reason: str = Field(..., min_length=1, max_length=255)


# ---------- response models ----------


class CertResponse(BaseModel):
    system_id: int
    hostname: str
    certificate: str
    ca_chain: list
    serial_number: str
    fingerprint: str
    expires_at: str
    agent_status: str


class StatusResponse(BaseModel):
    system_id: int
    hostname: str
    agent_status: str
    agent_cert_serial: Optional[str]
    agent_cert_fingerprint: Optional[str]
    agent_cert_expires_at: Optional[str]
    agent_revoked_at: Optional[str]
    agent_revocation_reason: Optional[str]
    agent_status_reason: Optional[str]
    agent_last_seen_at: Optional[str]
    agent_version: Optional[str]
    transport_preference: str
    # PRA-324: live tunnel liveness derived from the broker registry, NOT
    # from agent_last_seen_at (which is only a timestamp). One of:
    #   online       — broker has a live tunnel + recent heartbeat
    #   stale        — tunnel registered but heartbeat past the dead window
    #   offline      — broker has no tunnel for this system
    #   unknown      — broker itself was unreachable (couldn't tell)
    # ``agent_status`` remains the orthogonal enrollment-lifecycle axis
    # (not_enrolled / active / disabled / revoked). SSH ``auth_failed`` is a
    # separate SSH-connection concept and is not reflected here.
    agent_liveness: str


# ---------- helpers ----------


# Broker TunnelHealth.state -> operator-facing liveness label.
_LIVENESS_BY_TUNNEL_STATE = {
    "healthy": "online",
    "stale": "stale",
    "unregistered": "offline",
    "unknown": "unknown",
}


def _run_async_from_sync(coro: Awaitable) -> Any:
    """Run an awaitable from a sync route, even if a parent event loop is
    already running. ``asyncio.run`` raises when a loop is active in this
    thread, so fall back to a fresh worker thread that owns its own loop.
    Mirrors the bridge in command_execution_service."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _agent_liveness(system_id: int) -> str:
    """Consult the broker's live registry for this system's tunnel state
    and map it to an operator-facing liveness label.

    The authoritative online/stale/offline signal lives in the broker's
    in-memory registry, not the DB (the DB only stores agent_last_seen_at,
    a timestamp). A broker that is unreachable yields ``unknown`` — kept
    distinct from ``offline`` so we never imply the agent is gone when we
    simply couldn't ask (mirrors TunnelHealth's own unregistered/unknown
    split, PRA-153 #4). The BrokerClient is built inside the coroutine so
    its httpx.AsyncClient binds to the loop that actually runs it."""
    # Local import keeps the broker-client (and its async httpx dep) off the
    # module import path for contexts that only need the identity routes.
    from ...services.broker_client import (  # pylint: disable=import-outside-toplevel
        BrokerClient,
    )

    async def _run():
        return await BrokerClient().health(system_id)

    try:
        health = _run_async_from_sync(_run())
    except Exception:  # pylint: disable=broad-except
        logger.warning("broker liveness lookup failed system_id=%s", system_id)
        return "unknown"
    return _LIVENESS_BY_TUNNEL_STATE.get(health.state, "unknown")


def _validate_ssh_reachable(db: Session, system_id: int) -> None:
    """M13 bootstrap auth: prove the host is who we say it is by opening
    an SSH session with the existing bootstrap credential. M14 PRA-154 will
    replace this with activation-token validation.

    SSHService.test_connection swallows SSHConnectionError and returns a
    result dict with status in {"success", "warning", "failed"}; only
    "success" is acceptable proof here. "warning" specifically maps to
    auth failure or stderr-on-command — neither is identity proof.
    """
    try:
        result = SSHService(db).test_connection(system_id)
    except SSHConnectionError as e:
        raise HTTPException(
            status_code=502,
            detail=f"SSH bootstrap validation failed: {e}",
        ) from e
    if result.get("status") != "success":
        raise HTTPException(
            status_code=502,
            detail=(
                "SSH bootstrap validation failed: "
                f"{result.get('message', 'unknown error')}"
            ),
        )


def _status_payload(system: System, agent_liveness: str = "unknown") -> Dict[str, Any]:
    def _iso(dt):
        return dt.isoformat() + "Z" if dt is not None else None

    return {
        "system_id": system.id,
        "hostname": system.hostname,
        "agent_status": system.agent_status,
        "agent_cert_serial": system.agent_cert_serial,
        "agent_cert_fingerprint": system.agent_cert_fingerprint,
        "agent_cert_expires_at": _iso(system.agent_cert_expires_at),
        "agent_revoked_at": _iso(system.agent_revoked_at),
        "agent_revocation_reason": system.agent_revocation_reason,
        "agent_status_reason": system.agent_status_reason,
        "agent_last_seen_at": _iso(system.agent_last_seen_at),
        "agent_version": system.agent_version,
        "transport_preference": system.transport_preference,
        "agent_liveness": agent_liveness,
    }


# ---------- routes ----------


@router.post("/bootstrap/{system_id}", response_model=CertResponse)
def bootstrap_agent(
    body: CSRBody,
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Sign an agent CSR after validating the host via SSH (M13).

    Returns the freshly minted cert + CA chain so the caller (operator
    tooling, eventually the PRA-152 installer) can drop it on the host.
    """
    _validate_ssh_reachable(db, system_id)
    try:
        return AgentIdentityService(db).issue_for_bootstrap(
            system_id=system_id,
            csr_pem=body.csr_pem,
            actor_user_id=current_user.id,
        )
    except AgentIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/renew/{system_id}", response_model=CertResponse)
def renew_agent(
    body: CSRBody,
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Renew an agent cert. Admin-gated for now; PRA-151 will switch to
    mTLS-extracted cert identity so agents renew themselves over the
    tunnel without admin involvement.
    """
    try:
        return AgentIdentityService(db).renew(
            system_id=system_id,
            csr_pem=body.csr_pem,
            actor_user_id=current_user.id,
        )
    except AgentIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/disable/{system_id}", response_model=StatusResponse)
def disable_agent(
    body: DisableBody,
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Reversible pause. active -> disabled."""
    try:
        system = AgentIdentityService(db).disable(
            system_id=system_id,
            reason=body.reason,
            actor_user_id=current_user.id,
        )
        return _status_payload(system)
    except AgentIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/enable/{system_id}", response_model=StatusResponse)
def enable_agent(
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Resume agent. disabled -> active."""
    try:
        system = AgentIdentityService(db).enable(
            system_id=system_id, actor_user_id=current_user.id
        )
        return _status_payload(system)
    except AgentIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/revoke/{system_id}", response_model=StatusResponse)
def revoke_agent(
    body: RevokeBody,
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Terminal revoke. {active,disabled} -> revoked."""
    try:
        system = AgentIdentityService(db).revoke(
            system_id=system_id,
            reason=body.reason,
            actor_user_id=current_user.id,
        )
        return _status_payload(system)
    except AgentIdentityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/status/{system_id}", response_model=StatusResponse)
def get_agent_status(
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Read-only summary of the agent's current identity + status, including
    live tunnel liveness derived from the broker registry (PRA-324)."""
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail=f"System {system_id} not found")
    return _status_payload(system, agent_liveness=_agent_liveness(system_id))


# ---------------------------------------------------------------------------
# /agent/ca-bundle (PRA-151 task #19)
#
# Anonymous endpoint serving the public CA roots agents need at install
# time:
#   * agent_ca   — root used by the broker to verify agent client certs
#   * broker_ca  — root the agent uses to verify the broker's server cert
#
# Auth bypass for this exact path lives in app.api.main JWT middleware.
# The endpoint must stay on the main backend (port 8000), NOT the
# mTLS-only broker listener — agents fetching this need to do so before
# they have a cert to present.
# ---------------------------------------------------------------------------


def _ca_bundle_paths() -> Tuple[str, str]:
    return (
        os.environ.get("PRAXIS_AGENT_CA_CERT", DEFAULT_AGENT_CA_PATH),
        os.environ.get("PRAXIS_BROKER_CA_CERT", DEFAULT_BROKER_CA_PATH),
    )


def _read_ca_bundle() -> Dict[str, str]:
    """Read the two PEM files. Cached for ``CA_BUNDLE_CACHE_SECONDS`` so
    high-volume installer runs don't re-read on every hit."""
    global _ca_bundle_cache  # noqa: PLW0603
    now = time.monotonic()
    if _ca_bundle_cache and now - _ca_bundle_cache[0] < CA_BUNDLE_CACHE_SECONDS:
        return _ca_bundle_cache[1]

    agent_path, broker_path = _ca_bundle_paths()
    missing = [p for p in (agent_path, broker_path) if not os.path.isfile(p)]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=(
                "agent CA bundle not provisioned: missing "
                + ", ".join(missing)
                + " (run vault init or set PRAXIS_AGENT_CA_CERT / "
                "PRAXIS_BROKER_CA_CERT to operator-managed paths)"
            ),
        )

    try:
        with open(agent_path, encoding="utf-8") as f:
            agent_ca = f.read()
        with open(broker_path, encoding="utf-8") as f:
            broker_ca = f.read()
    except OSError as e:
        raise HTTPException(
            status_code=503, detail=f"failed reading agent CA bundle: {e}"
        ) from e

    bundle = {"agent_ca": agent_ca, "broker_ca": broker_ca}
    _ca_bundle_cache = (now, bundle)
    return bundle


class CaBundleResponse(BaseModel):
    agent_ca: str
    broker_ca: str


@router.get("/ca-bundle", response_model=CaBundleResponse)
def get_ca_bundle() -> Dict[str, str]:
    """Return the public CA roots required to install an agent. No
    auth: these are public certs and the agent has nothing to present
    yet at this stage of bootstrap."""
    return _read_ca_bundle()


def _invalidate_ca_bundle_cache() -> None:
    """Test hook to clear the in-process cache."""
    global _ca_bundle_cache  # noqa: PLW0603
    _ca_bundle_cache = None
