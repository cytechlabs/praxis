"""Agent broker process entrypoint.

Run as ``python -m app.broker.main`` from a dedicated Compose service.
Single-process, single-asyncio-loop. Owns ``/agent/tunnel``,
``/agent/op``, the in-memory ``AgentRegistry``, and the
``OperationManager``.

Cert provisioning paths (PRA-151 listener decision):
    bundled Vault: server cert/key + client CA at /vault/data/broker/*
                   and /vault/data/agent-ca-cert.pem (init-vault.sh
                   provisions these in PRA-151 task #19).
    operator-managed: PRAXIS_BROKER_TLS_KEY / TLS_CERT / TLS_CA_CLIENT
                      env vars override.

start.sh / Compose service definition lands in task #19.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Optional

import uvicorn
import websockets

from .audit import default_audit_emit
from .handlers import make_db_validator, op_handler, tunnel_handler
from .internal_api import build_internal_app
from .internal_auth import derive_internal_token
from .ops import OperationManager, init_default_manager
from .protocol import (
    CONTROL_WSS_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
    FRAME_HEADER_SIZE,
)
from .registry import default_registry
from .tls import build_server_ssl_context

logger = logging.getLogger(__name__)


DEFAULT_PORT = 8443
DEFAULT_INTERNAL_PORT = 8444

DEFAULT_SERVER_KEY = "/vault/data/broker/server.key"
DEFAULT_SERVER_CERT = "/vault/data/broker/server.crt"
DEFAULT_CLIENT_CA = "/vault/data/agent-ca-cert.pem"


def _resolve_paths():
    return (
        os.environ.get("PRAXIS_BROKER_TLS_CERT", DEFAULT_SERVER_CERT),
        os.environ.get("PRAXIS_BROKER_TLS_KEY", DEFAULT_SERVER_KEY),
        os.environ.get("PRAXIS_BROKER_TLS_CA_CLIENT", DEFAULT_CLIENT_CA),
    )


def _resolve_port() -> int:
    raw = os.environ.get("PRAXIS_BROKER_PORT")
    if not raw:
        return DEFAULT_PORT
    try:
        return int(raw)
    except ValueError as e:
        raise SystemExit(f"PRAXIS_BROKER_PORT must be an int, got {raw!r}") from e


def _resolve_internal_port() -> int:
    raw = os.environ.get("PRAXIS_BROKER_INTERNAL_PORT")
    if not raw:
        return DEFAULT_INTERNAL_PORT
    try:
        return int(raw)
    except ValueError as e:
        raise SystemExit(
            f"PRAXIS_BROKER_INTERNAL_PORT must be an int, got {raw!r}"
        ) from e


async def serve(
    *,
    host: str = "0.0.0.0",
    port: Optional[int] = None,
    internal_port: Optional[int] = None,
    validator=None,
    manager: Optional[OperationManager] = None,
) -> None:
    """Start the broker listener. Returns when the underlying server stops.

    ``validator`` lets tests inject a stubbed identity validator without
    touching the real DB. If omitted we build the live DB validator.
    ``manager`` defaults to (and initialises) the module-level
    OperationManager bound to ``default_registry``.

    ``internal_port`` controls the PRA-153 backend ↔ broker HTTP
    listener. ``None`` (default) reads ``PRAXIS_BROKER_INTERNAL_PORT``
    or falls back to ``DEFAULT_INTERNAL_PORT``. Pass ``0`` to skip the
    internal API entirely — tests that exercise only the WSS listener
    use this so they don't compete for the internal port between
    runs and don't have to manage uvicorn lifespan.
    """
    cert, key, client_ca = _resolve_paths()
    for label, path in (("cert", cert), ("key", key), ("client_ca", client_ca)):
        if not os.path.exists(path):
            raise SystemExit(f"broker {label} missing: {path}")

    if validator is None:
        # Lazy import to keep tls/handlers modules importable without app.db.
        from app.db.session import (  # pylint: disable=import-outside-toplevel
            SessionLocal,
        )

        validator = make_db_validator(SessionLocal)

    if manager is None:
        manager = init_default_manager(default_registry, audit_emit=default_audit_emit)

    # Production facts writer: SessionLocal-backed, calls into the
    # canonical FactsService.ingest path with source_transport='agent'.
    # Tests inject their own writer through tunnel_handler kwargs and
    # never reach this wiring.
    facts_writer = _build_facts_writer()
    last_seen_writer = _build_last_seen_writer()

    ssl_ctx = build_server_ssl_context(cert, key, client_ca)
    bind_port = port if port is not None else _resolve_port()

    async def dispatch(ws):
        # /agent/tunnel and /agent/op share the same listener; route
        # by path so we don't need two ports for one logical service.
        if ws.path == "/agent/tunnel":
            await tunnel_handler(
                ws,
                identity_validator=validator,
                registry=default_registry,
                manager=manager,
                audit_emit=default_audit_emit,
                facts_writer=facts_writer,
                last_seen_writer=last_seen_writer,
            )
        elif ws.path == "/agent/op":
            await op_handler(
                ws,
                identity_validator=validator,
                registry=default_registry,
                manager=manager,
                audit_emit=default_audit_emit,
            )
        else:
            await ws.close(code=4404, reason="unknown_path")

    handler = dispatch

    # Listener-level max_size applies to BOTH /agent/tunnel and
    # /agent/op (single shared websockets.serve). Set it to the per-op
    # frame ceiling so legitimate 1 MiB op frames are not rejected
    # before they reach decode_frame. The tunnel handler enforces the
    # tighter 64 KiB control-WSS cap on inbound messages itself.
    listener_max_size = DEFAULT_MAX_FRAME_PAYLOAD_BYTES + FRAME_HEADER_SIZE + 1024
    if listener_max_size < CONTROL_WSS_MAX_MESSAGE_BYTES:  # defensive
        listener_max_size = CONTROL_WSS_MAX_MESSAGE_BYTES

    # Internal HTTP API for backend ↔ broker calls (PRA-153 slice #1).
    # Bound to all interfaces on a separate port so the backend reaches
    # it via the Docker network. The port is NOT published to the host
    # in compose; trust boundary is the docker network.
    if internal_port is None:
        internal_port = _resolve_internal_port()
    internal_server: Optional[uvicorn.Server] = None
    if internal_port > 0:
        # PRA-180 BROKER-01: the internal API must not run unauthenticated.
        # Derive the shared token from SECRET_KEY (or PRAXIS_BROKER_INTERNAL_TOKEN)
        # and fail closed if neither is available rather than expose an open
        # ops-dispatch surface on the docker network.
        internal_token = derive_internal_token()
        if not internal_token:
            raise SystemExit(
                "broker internal API requires SECRET_KEY or "
                "PRAXIS_BROKER_INTERNAL_TOKEN to derive its shared-secret auth; "
                "set one or disable the internal API with "
                "PRAXIS_BROKER_INTERNAL_PORT=0"
            )
        internal_app = build_internal_app(
            default_registry, manager=manager, auth_token=internal_token
        )
        internal_config = uvicorn.Config(
            internal_app,
            host=host,
            port=internal_port,
            log_level=os.environ.get("PRAXIS_BROKER_LOG_LEVEL", "info").lower(),
            access_log=False,
        )
        internal_server = uvicorn.Server(internal_config)

    async with websockets.serve(
        handler,
        host=host,
        port=bind_port,
        ssl=ssl_ctx,
        ping_interval=None,  # heartbeat is application-level
        max_size=listener_max_size,
    ):
        logger.info(
            "agent broker listening on %s:%s (mTLS, client CA=%s)",
            host,
            bind_port,
            client_ca,
        )
        # PRA-228 BROKER-02: the AgentRegistry and OperationManager are in-memory
        # and process-local. 1.0 supports exactly ONE broker instance — running
        # replicas would split agent tunnels and op state across processes with
        # no shared registry, so an op dispatched to one broker can't reach an
        # agent connected to another. Make the invariant loud in the boot log.
        logger.info(
            "agent broker single-instance invariant: in-memory registry + op "
            "state; run exactly one broker process (no replicas / HA in 1.0)"
        )
        internal_task: Optional[asyncio.Task] = None
        if internal_server is not None:
            logger.info(
                "agent broker internal API on %s:%s "
                "(shared-secret auth, docker-net only)",
                host,
                internal_port,
            )
            # Run uvicorn alongside the WSS listener in this same loop.
            internal_task = asyncio.create_task(internal_server.serve())
        else:
            logger.info("agent broker internal API skipped (internal_port=0)")

        # Sleep until interrupted.
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                # Windows / non-default event loops — fall back to KeyboardInterrupt.
                pass
        await stop.wait()
        logger.info("agent broker shutting down")
        if internal_server is not None and internal_task is not None:
            internal_server.should_exit = True
            await internal_task


def _build_facts_writer():
    """Return a ``(system_id, payload) -> None`` callable that opens its
    own short-lived ``SessionLocal`` and invokes ``FactsService.ingest``
    with ``source_transport='agent'``.

    Imports are deferred so the broker module stays importable in
    contexts where ``app.db`` is not configured (unit tests, minimal
    images that only need the protocol surface). Errors inside the
    writer are swallowed at the call site (``_route_facts_report``);
    here we just produce the closure.
    """

    def _writer(system_id: int, payload: dict) -> None:
        # pylint: disable=import-outside-toplevel
        from app.db.session import SessionLocal
        from app.services import facts_service

        db = SessionLocal()
        try:
            facts_service.ingest(
                db,
                system_id=system_id,
                payload=payload,
                source_transport="agent",
            )
        finally:
            db.close()

    return _writer


# ``System.agent_version`` is a String(32) column; git-describe versions are
# well under that but truncate defensively so a pathological build stamp can
# never overflow the column and fail the whole liveness UPDATE.
_AGENT_VERSION_MAX_LEN = 32


def _persist_agent_liveness(db, system_id: int, agent_version: Optional[str]) -> None:
    """Stamp ``agent_last_seen_at`` (and ``agent_version`` when supplied and
    changed) on the System row. Pure DB mutation on the passed session — no
    commit/close here so it's directly unit-testable with a test session;
    the caller owns the session lifecycle. Returns silently if the system
    row is gone (deleted between connect and write)."""
    # pylint: disable=import-outside-toplevel
    from datetime import datetime

    from app.db.models import System

    system = db.query(System).filter(System.id == system_id).first()
    if system is None:
        return
    system.agent_last_seen_at = datetime.utcnow()
    if agent_version:
        trimmed = agent_version[:_AGENT_VERSION_MAX_LEN]
        if system.agent_version != trimmed:
            system.agent_version = trimmed


def _build_last_seen_writer():
    """Return a ``(system_id, agent_version=None) -> None`` callable that
    persists ``System.agent_last_seen_at`` + ``agent_version`` via a
    short-lived ``SessionLocal``.

    Wiring this in production is what makes the liveness columns real: the
    broker's throttled last-seen path defaults to a no-op writer, so without
    this closure ``agent_last_seen_at`` and ``agent_version`` would stay NULL
    forever (PRA-324). Imports are deferred so the broker stays importable
    without ``app.db`` configured; failures are swallowed by the throttled
    caller (``_maybe_write_last_seen``).
    """

    def _writer(system_id: int, agent_version: Optional[str] = None) -> None:
        # pylint: disable=import-outside-toplevel
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            _persist_agent_liveness(db, system_id, agent_version)
            db.commit()
        finally:
            db.close()

    return _writer


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("PRAXIS_BROKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s broker %(levelname)s %(name)s %(message)s",
    )
    # Credential preflight before any listener is bound. The broker receives
    # only DATABASE_URL, and a bundled deployment that never set
    # POSTGRES_PASSWORD gets an empty-password URL that no connection can use.
    from app.core.startup_validation import (  # pylint: disable=import-outside-toplevel
        StartupValidationError,
        validate_database_credentials,
    )

    try:
        validate_database_credentials()
    except StartupValidationError as exc:
        raise SystemExit(f"broker: {exc}") from exc

    # PRA-339: retain a bounded ring of recent broker log records so the admin
    # support bundle can pull them over the authenticated internal API. Same
    # in-memory, single-worker, size-bounded handler the backend uses — the
    # broker's stdout isn't readable from the backend process without a docker
    # socket, which we deliberately avoid. Records are redacted at bundle build.
    from app.core.log_buffer import (  # pylint: disable=import-outside-toplevel
        install_log_buffer,
    )

    install_log_buffer()
    asyncio.run(serve())


if __name__ == "__main__":
    main()
