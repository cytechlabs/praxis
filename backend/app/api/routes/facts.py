"""PRA-155 #2b-b: on-demand facts refresh.

``POST /systems/{id}/facts/refresh`` is the operator-facing entry
point that drives a single inventory collection through the right
transport for the host. The persisted row + audit emission both
happen inside ``FactsService.ingest`` (single canonical path); this
route's job is transport selection + error mapping.

Transport selection (locked, mirrors PRA-153):
    transport_preference=ssh    → SSH always
    transport_preference=agent  → broker agent op or 503 (no fallback)
    transport_preference=auto   → agent if active + healthy + advertises
                                  ``facts`` capability, else SSH

Auth: admin role only.

Status codes:
    200  refresh completed → body {status, source_transport,
                                   collected_at, partial_error_count}
    403  caller is not an admin
    404  unknown system
    503  transport_preference=agent and agent unavailable / lacks
         facts capability / broker unreachable
    502  agent op completed with an error outcome (collector crashed,
         or back-revved agent returned no inline facts)
    504  agent didn't respond before the broker's facts hard-cap
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role, require_system_access
from ...db.models import HostFacts, System, User
from ...db.session import get_db
from ...services import facts_service, ssh_facts_collector_service
from ...services.broker_client import BrokerClient, BrokerError
from ...services.facts_freshness import STALENESS_THRESHOLD_SECONDS, freshness_of

logger = logging.getLogger(__name__)

router = APIRouter(redirect_slashes=False)


# Allowlisted keys for ``cloud_instance_metadata`` on the read path.
# Defense-in-depth: the write-path sanitizer in FactsService already
# stripped non-allowlisted keys before storage, but a future schema
# change or an out-of-band INSERT must not leak credentials. Keep
# this in sync with FactsService._ALLOWED_CLOUD_KEYS.
_READ_CLOUD_ALLOWLIST = frozenset({"cloud_provider", "instance_id", "region", "zone"})


# Capability the agent must advertise for the agent path to be picked.
# Mirrors broker.protocol.SERVER_CAPABILITIES; if a back-revved agent
# doesn't advertise it, auto-mode falls back to SSH and forced-agent
# returns 503.
FACTS_CAPABILITY = "facts"


def _format_response(result: facts_service.IngestResult, source_transport: str) -> dict:
    """Locked response shape (PRA-155 #2b-b lock).

    ``status`` mirrors ``IngestResult.status`` so callers see
    upserted / rejected_stale / rejected_invalid_timestamp / noop_empty
    directly. The full row is NOT returned here — that's #2c's
    ``GET /systems/{id}/facts`` job."""
    collected_at = None
    if result.row is not None and result.row.collected_at is not None:
        collected_at = result.row.collected_at.isoformat() + "Z"
    return {
        "status": result.status,
        "source_transport": source_transport,
        "collected_at": collected_at,
        "partial_error_count": len(result.partial_errors),
    }


async def _refresh_via_agent_inline(
    db: Session, system_id: int, broker_base_url: Optional[str]
) -> facts_service.IngestResult:
    """Concrete agent-path implementation. Separate function so tests
    can inject a stubbed BrokerClient via FastAPI dep override on
    ``_broker_client_for_request`` instead of monkeypatching httpx."""
    async with BrokerClient(base_url=broker_base_url) as bc:
        agent_facts = await bc.facts(system_id)
    if agent_facts.outcome != "success":
        # Should be unreachable — BrokerClient.facts raises on non-2xx.
        raise BrokerError(
            "agent_op_error",
            f"unexpected outcome {agent_facts.outcome!r} from broker",
        )
    payload = dict(agent_facts.facts)
    if agent_facts.partial_errors:
        existing = payload.get("partial_errors")
        merged = list(existing) if isinstance(existing, list) else []
        merged.extend(agent_facts.partial_errors)
        payload["partial_errors"] = merged
    return facts_service.ingest(
        db, system_id=system_id, payload=payload, source_transport="agent"
    )


def _resolve_system(db: Session, system_id: int) -> System:
    sys_row = db.query(System).filter(System.id == system_id).first()
    if sys_row is None:
        raise HTTPException(status_code=404, detail=f"system {system_id} not found")
    return sys_row


@router.post(
    "/{system_id}/facts/refresh",
    dependencies=[Depends(require_system_access("admin"))],
)
async def refresh_facts(
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(require_role("admin")),  # noqa: ARG001
    db: Session = Depends(get_db),
):
    """Run a single facts collection per transport preference and
    persist via FactsService.ingest. See module docstring for the
    full status-code table.
    """
    system = _resolve_system(db, system_id)
    pref = (system.transport_preference or "auto").lower()

    if pref not in {"ssh", "agent", "auto"}:
        # Defensive: System.transport_preference is validated upstream
        # by Pydantic, but a manual DB poke (or a future enum
        # extension that didn't update this gate) shouldn't surface
        # as a 500. Treat unknown as 'auto'.
        logger.warning(
            "facts refresh: system_id=%s unknown transport_preference=%r; "
            "treating as auto",
            system_id,
            pref,
        )
        pref = "auto"

    # ssh path — always SSH, regardless of agent state.
    if pref == "ssh":
        return await _do_ssh(db, system_id)

    # agent / auto both need broker health.
    try:
        async with BrokerClient() as bc:
            health = await bc.health(system_id)
    except Exception as exc:  # pylint: disable=broad-except
        # Broker unreachable. forced-agent → 503; auto → SSH fallback.
        logger.warning(
            "facts refresh: broker health lookup failed for system_id=%s: %s",
            system_id,
            exc,
        )
        if pref == "agent":
            return JSONResponse(
                status_code=503,
                content={
                    "error": "transport_unavailable",
                    "detail": "broker unreachable",
                },
            )
        return await _do_ssh(db, system_id)

    if pref == "agent":
        if not health.is_usable:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "transport_unavailable",
                    "detail": f"agent tunnel state={health.state}",
                },
            )
        if not health.has_capability(FACTS_CAPABILITY):
            return JSONResponse(
                status_code=503,
                content={
                    "error": "transport_unavailable",
                    "detail": "agent does not advertise facts capability",
                },
            )
        try:
            result = await _refresh_via_agent_inline(db, system_id, None)
        except BrokerError as exc:
            return _broker_error_to_response(exc)
        return _format_response(result, "agent")

    # auto: agent only if active + healthy + facts capability; else SSH.
    if (
        system.agent_status == "active"
        and health.is_usable
        and health.has_capability(FACTS_CAPABILITY)
    ):
        try:
            result = await _refresh_via_agent_inline(db, system_id, None)
            return _format_response(result, "agent")
        except BrokerError as exc:
            # Auto fallback to SSH on broker-side trouble. Forced-agent
            # mode never reaches this branch.
            logger.info(
                "facts refresh auto-mode: agent path failed for system_id=%s "
                "(%s); falling back to SSH",
                system_id,
                exc.reason,
            )
    return await _do_ssh(db, system_id)


def _broker_error_to_response(exc: BrokerError) -> JSONResponse:
    """Translate a broker-side failure into the locked HTTP status
    code for the forced-agent path. Auto-mode does NOT call this —
    it falls back to SSH instead."""
    if exc.reason == "transport_unavailable":
        return JSONResponse(
            status_code=503,
            content={"error": "transport_unavailable", "detail": str(exc)},
        )
    if exc.reason in {"facts_timeout", "agent_attach_timeout"}:
        return JSONResponse(
            status_code=504,
            content={"error": exc.reason, "detail": str(exc)},
        )
    # Any other reason — collector_panicked, missing_inline_facts,
    # http_5xx — is an agent-side failure.
    return JSONResponse(
        status_code=502,
        content={"error": exc.reason, "detail": str(exc)},
    )


async def _do_ssh(db: Session, system_id: int):
    """Drive the SSH path. Transport-level failures map to 502 (the
    transport contract is read-only and the host is reachable from
    Praxis's POV; if we couldn't run the script, that's an
    infrastructure-level failure to surface). Script-level partial
    errors flow into the persisted row and partial_error_count.

    PRA-323: ``refresh_facts`` is legitimately ``async`` (it awaits the agent
    broker), so this SSH fallback can't just become a sync route. The blocking
    collector (``SSHService.execute_command`` under the hood) is instead offloaded
    with ``asyncio.to_thread`` so it runs in a worker thread and never starves the
    event loop while one host's SSH collection hangs. The ``db`` session is only
    touched inside the thread (the loop awaits), so there is no concurrent use.
    """
    try:
        result = await asyncio.to_thread(
            ssh_facts_collector_service.collect_and_ingest, db, system_id=system_id
        )
    except ssh_facts_collector_service.SshFactsCollectionError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": "ssh_collector_failed", "detail": str(exc)},
        )
    return _format_response(result, "ssh")


# ----------------------------------------------------------------- read


def _sanitize_cloud_for_read(raw: Any) -> Dict[str, Any]:
    """Defense-in-depth filter on the read path.

    The write path's sanitizer already stripped non-allowlisted keys,
    but a schema change, manual INSERT, or restored backup that
    pre-dates the allowlist must not leak credential-shaped fields
    out through the read API. We do NOT expose rejected key names —
    the read endpoint is for operators looking at inventory, not
    auditing the sanitizer.
    """
    if not isinstance(raw, dict):
        return {}
    return {
        k: v
        for k, v in raw.items()
        if k in _READ_CLOUD_ALLOWLIST and isinstance(v, (str, int))
    }


def _facts_payload(row: HostFacts) -> Dict[str, Any]:
    """Project the ORM row into the wire-shape facts dict.

    Keys are the same as ``FactsService.ingest`` accepts on write —
    the read API is the inverse of the write API, so consumers (UI,
    smart-group recompute in #2d, fleet search in #2d) see one stable
    shape regardless of which transport produced the row.
    """
    return {
        "cpu_model": row.cpu_model,
        "cpu_cores": row.cpu_cores,
        "ram_total_bytes": row.ram_total_bytes,
        "kernel_version": row.kernel_version,
        # ``distro_id_facts`` on the model -> ``distro_id`` on the
        # wire (the wire name matches the ingest payload + agent
        # collector exactly).
        "distro_id": row.distro_id_facts,
        "distro_release": row.distro_release,
        "uptime_seconds": row.uptime_seconds,
        "reboot_required": row.reboot_required,
        "package_manager": row.package_manager,
        "package_manager_version": row.package_manager_version,
        "virtualization": row.virtualization,
        "cloud_provider": row.cloud_provider,
        "cloud_instance_metadata": _sanitize_cloud_for_read(
            row.cloud_instance_metadata
        ),
        "disks": list(row.disks) if isinstance(row.disks, list) else [],
    }


@router.get(
    "/{system_id}/facts",
    dependencies=[Depends(require_system_access())],
)
async def get_facts(
    system_id: int = Path(..., ge=1),
    current_user: User = Depends(get_current_user),  # noqa: ARG001
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Read the host's current facts row.

    Authenticated-readable (NOT admin-only); the refresh POST stays
    admin-only. A missing row returns 200 with ``freshness="missing"``
    rather than 404 so the UI renders a uniform empty-state instead
    of treating first-collect as an error. The read path MUST NOT
    trigger collection or mutate ``host_facts``; it is a pure read.
    """
    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        raise HTTPException(status_code=404, detail=f"system {system_id} not found")

    row = db.query(HostFacts).filter(HostFacts.system_id == system_id).one_or_none()
    freshness = freshness_of(row.collected_at if row else None)

    if row is None:
        return {
            "system_id": system_id,
            "schema_version": None,
            "collected_at": None,
            "source_transport": None,
            "freshness": freshness,
            "is_partial": False,
            "facts": None,
            "partial_errors": [],
            "staleness_threshold_seconds": STALENESS_THRESHOLD_SECONDS,
        }

    partial_errors: List[Dict[str, Any]] = []
    if isinstance(row.partial_errors, list):
        for entry in row.partial_errors:
            if isinstance(entry, dict) and "key" in entry and "error" in entry:
                partial_errors.append(
                    {"key": str(entry["key"]), "error": str(entry["error"])}
                )

    return {
        "system_id": system_id,
        "schema_version": row.schema_version,
        "collected_at": row.collected_at.isoformat() + "Z",
        "source_transport": row.source_transport,
        "freshness": freshness,
        "is_partial": bool(partial_errors),
        "facts": _facts_payload(row),
        "partial_errors": partial_errors,
        "staleness_threshold_seconds": STALENESS_THRESHOLD_SECONDS,
    }
