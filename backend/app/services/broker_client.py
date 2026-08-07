"""Backend → broker internal HTTP client (PRA-153 slices #1 + #3b).

Thin httpx wrapper around the broker's internal API so the rest of
the backend never imports broker registry / OperationManager
modules directly. Keeps the backend / broker boundary HTTP-only —
multi-process or cross-host deployment of the broker can land later
without touching callers.

Slice #1 covered health lookups. Slice #3b adds op dispatch:
    - exec      POST /internal/agent/ops/exec
    - file_get  POST /internal/agent/ops/file_get  (streaming response)
    - file_put  POST /internal/agent/ops/file_put  (streaming request)

PTY is intentionally absent — agent-backed PTY sessions are deferred
from PRA-153 #3 until effective_login switching is designed.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import httpx

from app.broker.internal_auth import INTERNAL_AUTH_HEADER, derive_internal_token

logger = logging.getLogger(__name__)


def _auth_headers() -> dict:
    """Default headers carrying the broker internal-API shared secret.

    PRA-180 BROKER-01: the backend presents this on every internal-API call so
    the broker can reject unauthenticated callers on its docker-network port.
    Empty when no token can be derived (no SECRET_KEY / override), which matches
    the broker's own fail-closed posture — the call then gets a 401.
    """
    token = derive_internal_token()
    return {INTERNAL_AUTH_HEADER: token} if token else {}


# Read directly from env rather than the Settings model — Settings is
# defined but unused elsewhere in the backend, and turning on its
# strict-mode loader for one extra field would require fixing the
# unrelated env mismatches it currently glosses over.
DEFAULT_BROKER_INTERNAL_URL = os.environ.get(
    "PRAXIS_BROKER_INTERNAL_URL", "http://agent-broker:8444"
)
DEFAULT_BROKER_INTERNAL_TIMEOUT = float(
    os.environ.get("PRAXIS_BROKER_INTERNAL_TIMEOUT_SECONDS", "5.0")
)

# Per-op timeouts for the broker dispatch endpoints. Exec runs may
# legitimately take minutes (the broker enforces a 300s hard cap);
# file transfers may be larger. The 5s default health timeout above
# would prematurely cut these off, so each method overrides it.
DEFAULT_OP_TIMEOUT = httpx.Timeout(connect=5.0, read=320.0, write=60.0, pool=5.0)


@dataclass
class TunnelHealth:
    """Snapshot returned by ``BrokerClient.health()``.

    ``state`` is one of ``healthy``, ``stale``, ``unregistered``,
    ``unknown``.
        ``healthy``      — broker has a live tunnel + recent heartbeat.
        ``stale``        — tunnel registered but heartbeat older than
                           ``HEARTBEAT_DEAD_SECONDS`` (not usable).
        ``unregistered`` — broker has no tunnel for this system.
        ``unknown``      — broker itself was unreachable / errored.
                           Distinct from ``unregistered`` so the
                           operator UI can avoid implying "agent
                           missing" when the broker health call
                           itself failed (PRA-153 #4).
    """

    system_id: int
    state: str
    tunnel_session_id: Optional[str] = None
    since_seconds: Optional[float] = None
    last_heartbeat_age_seconds: Optional[float] = None
    # PRA-155 #2b-b: capabilities the broker accepted at handshake.
    # Empty list when no tunnel exists. Transport selection for
    # capability-gated ops (facts, eventually others) checks this so
    # auto-mode can fall back to SSH on a back-revved agent that
    # doesn't advertise the requested op.
    capabilities: tuple = ()

    @property
    def is_usable(self) -> bool:
        """Convenience for transport resolvers — only ``healthy`` counts.

        ``stale`` is intentionally NOT usable. Per the PRA-153 lock,
        a broker that thinks the tunnel is dead should not be used,
        even if the registry hasn't garbage-collected the entry yet.
        """
        return self.state == "healthy"

    def has_capability(self, name: str) -> bool:
        """Convenience for capability-gated transport selection."""
        return name in self.capabilities


class BrokerClient:
    """Low-cost HTTP client for the broker's internal API.

    Default base URL comes from ``settings.praxis_broker_internal_url``;
    tests pass an override + a stub httpx client.
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._base_url = (base_url or DEFAULT_BROKER_INTERNAL_URL).rstrip("/")
        self._timeout = (
            timeout if timeout is not None else DEFAULT_BROKER_INTERNAL_TIMEOUT
        )
        # Lets tests inject a transport-stubbed AsyncClient. We don't
        # own the lifecycle when the caller passes one in.
        self._owns_client = client is None
        self._client = client

    async def __aenter__(self) -> "BrokerClient":
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers=_auth_headers(),
            )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health(self, system_id: int) -> TunnelHealth:
        """Fetch tunnel health for ``system_id``.

        Network / 5xx failures degrade to ``state="unknown"`` — from
        the transport-resolver's perspective an unreachable broker
        and a missing tunnel both fail ``is_usable`` so routing is
        unaffected, but the operator UI distinguishes the two:
        ``unknown`` means "we couldn't tell" rather than "agent not
        registered" (PRA-153 #4).
        """
        if self._client is None:
            # Used outside the context manager — build a one-shot.
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers=_auth_headers(),
            ) as oneshot:
                return await self._do_health(oneshot, system_id)
        return await self._do_health(self._client, system_id)

    async def _do_health(
        self, client: httpx.AsyncClient, system_id: int
    ) -> TunnelHealth:
        try:
            resp = await client.get(f"/internal/agent/health/{system_id}")
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(
                "broker health lookup failed for system_id=%s: %s", system_id, exc
            )
            return TunnelHealth(system_id=system_id, state="unknown")
        body = resp.json()
        return TunnelHealth(
            system_id=body["system_id"],
            state=body["state"],
            tunnel_session_id=body.get("tunnel_session_id"),
            since_seconds=body.get("since_seconds"),
            last_heartbeat_age_seconds=body.get("last_heartbeat_age_seconds"),
            capabilities=tuple(body.get("capabilities") or ()),
        )

    async def logs(
        self, *, since_epoch: Optional[float] = None, limit: Optional[int] = None
    ) -> dict:
        """PRA-339: fetch recent broker log records for the support bundle.

        Maps to ``GET /internal/logs``; returns the parsed body
        ``{"installed": bool, "records": [...]}``. Unlike ``health``, this
        deliberately does NOT swallow errors — the diagnostics builder needs to
        tell a missing endpoint (404 -> broker too old / unsupported) apart from
        an unreachable broker (network error -> unavailable), so it lets
        ``httpx.HTTPStatusError`` / ``httpx.HTTPError`` propagate.
        """
        params: dict = {}
        if since_epoch is not None:
            params["since_epoch"] = since_epoch
        if limit is not None:
            params["limit"] = limit
        if self._client is None:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers=_auth_headers(),
            ) as oneshot:
                resp = await oneshot.get("/internal/logs", params=params)
        else:
            resp = await self._client.get("/internal/logs", params=params)
        resp.raise_for_status()
        return resp.json()

    # ---- op dispatch (slice #3b) ----

    async def exec(
        self,
        system_id: int,
        cmd: str,
        *,
        args: Optional[list[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        stdin: Optional[bytes] = None,
        timeout_s: float = 0.0,
    ) -> "BrokerExecResult":
        """Run a one-shot command on the agent. Blocks until done.

        Maps to ``POST /internal/agent/ops/exec``. Returns the parsed
        JSON body as a ``BrokerExecResult``. HTTP-level failures
        (5xx, network) raise ``BrokerError`` with the right reason
        string for AgentTransport to translate into TransportError.
        """
        body: dict = {"system_id": system_id, "cmd": cmd}
        if args:
            body["args"] = args
        if cwd is not None:
            body["cwd"] = cwd
        if env is not None:
            body["env"] = env
        if stdin is not None:
            body["stdin_b64"] = base64.b64encode(stdin).decode("ascii")
        if timeout_s > 0:
            body["timeout_s"] = timeout_s

        client = await self._ensure_client()
        try:
            resp = await client.post(
                "/internal/agent/ops/exec", json=body, timeout=DEFAULT_OP_TIMEOUT
            )
        except httpx.HTTPError as exc:
            raise BrokerError("broker_unreachable", str(exc)) from exc
        if resp.status_code == 503:
            raise BrokerError("transport_unavailable", _reason_or_text(resp))
        if resp.status_code == 504:
            raise BrokerError("agent_attach_timeout", _reason_or_text(resp))
        if resp.status_code >= 400:
            # PRA-228: surface the broker's structured reason (e.g.
            # exec_output_too_large on 413, broker_busy on 429) instead of a
            # generic http_<code>, so callers/audit see the actionable cause.
            data = _safe_json(resp)
            err = (data.get("error") or {}) if isinstance(data, dict) else {}
            raise BrokerError(
                err.get("reason", f"http_{resp.status_code}"), _reason_or_text(resp)
            )
        data = resp.json()
        return BrokerExecResult(
            outcome=data.get("outcome", "error"),
            exit_code=data.get("exit_code"),
            stdout=base64.b64decode(data.get("stdout_b64") or b""),
            stderr=base64.b64decode(data.get("stderr_b64") or b""),
            duration_ms=data.get("duration_ms"),
            error=data.get("error"),
        )

    async def file_get(
        self, system_id: int, path: str, *, max_bytes: int = 0
    ) -> "BrokerFileGetStream":
        """Open a streaming download from the agent.

        Returns a context manager yielding (size, mode, chunks)
        where ``chunks`` is an async iterator of bytes. Caller
        ``async with`` this so the underlying httpx.Response is
        cleaned up even on early exit. Mid-stream failure manifests
        as a short body (less than the declared X-Praxis-File-Size)
        or a raised httpx error during iter_bytes — the AgentTransport
        wrapper turns either into TransportError.
        """
        client = await self._ensure_client()
        body = {"system_id": system_id, "path": path}
        if max_bytes > 0:
            body["max_bytes"] = max_bytes
        try:
            cm = client.stream(
                "POST",
                "/internal/agent/ops/file_get",
                json=body,
                timeout=DEFAULT_OP_TIMEOUT,
            )
            response = await cm.__aenter__()
        except httpx.HTTPError as exc:
            raise BrokerError("broker_unreachable", str(exc)) from exc
        # Pre-stream failures come back as JSON (bodies pre-emptied).
        if response.status_code == 503:
            await cm.__aexit__(None, None, None)
            raise BrokerError("transport_unavailable", "broker reported no tunnel")
        if response.status_code == 504:
            # The broker emits 504 for both agent_attach_timeout
            # (per-op WSS never opened) and header_timeout (attached
            # but no file header). Parse the JSON reason instead of
            # collapsing them — audit / UI / on-call dashboards key
            # off the distinction.
            try:
                payload = await response.aread()
                err = json.loads(payload).get("error") or {}
                reason = err.get("reason", "broker_timeout")
            except Exception:  # pylint: disable=broad-except
                reason = "broker_timeout"
            await cm.__aexit__(None, None, None)
            raise BrokerError(reason, "pre-stream broker timeout")
        if response.status_code == 502:
            # JSON error body — read it for the reason.
            try:
                payload = await response.aread()
                err = json.loads(payload).get("error") or {}
                reason = err.get("reason", "broker_error")
            except Exception:  # pylint: disable=broad-except
                reason = "broker_error"
            await cm.__aexit__(None, None, None)
            raise BrokerError(reason, "pre-stream failure")
        if response.status_code != 200:
            await cm.__aexit__(None, None, None)
            raise BrokerError(
                f"http_{response.status_code}", "unexpected broker response"
            )
        size = int(response.headers.get("x-praxis-file-size", "0"))
        mode = response.headers.get("x-praxis-file-mode", "")
        return BrokerFileGetStream(_cm=cm, _response=response, size=size, mode=mode)

    async def file_put(
        self,
        system_id: int,
        path: str,
        body: AsyncIterator[bytes],
        *,
        declared_size: int,
        mode: Optional[str] = None,
        overwrite: bool = False,
        max_bytes: int = 0,
    ) -> "BrokerFilePutResult":
        """Stream a file body to the agent. Caller drives ``body``.

        ``body`` is an async iterator of bytes. httpx forwards it
        chunk-by-chunk into the request body; the broker streams
        each chunk into ChannelFile frames without buffering. Returns
        the parsed JSON response with ``outcome`` + ``bytes_written``.
        """
        headers = {
            "x-praxis-system-id": str(system_id),
            "x-praxis-file-path": path,
            "x-praxis-declared-size": str(declared_size),
            "x-praxis-overwrite": "true" if overwrite else "false",
        }
        if mode is not None:
            headers["x-praxis-file-mode"] = mode
        if max_bytes > 0:
            headers["x-praxis-max-bytes"] = str(max_bytes)
        client = await self._ensure_client()
        try:
            resp = await client.post(
                "/internal/agent/ops/file_put",
                content=body,
                headers=headers,
                timeout=DEFAULT_OP_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise BrokerError("broker_unreachable", str(exc)) from exc
        if resp.status_code == 503:
            raise BrokerError("transport_unavailable", _reason_or_text(resp))
        if resp.status_code == 504:
            raise BrokerError("agent_attach_timeout", _reason_or_text(resp))
        if resp.status_code == 413:
            raise BrokerError("too_large", _reason_or_text(resp))
        if resp.status_code >= 400:
            data = _safe_json(resp)
            err = (data.get("error") or {}) if isinstance(data, dict) else {}
            raise BrokerError(
                err.get("reason", f"http_{resp.status_code}"),
                _reason_or_text(resp),
            )
        data = resp.json()
        return BrokerFilePutResult(
            outcome=data.get("outcome", "success"),
            bytes_written=int(data.get("bytes_written", 0)),
        )

    # ---- facts (PRA-155 #2b-a) ----

    async def facts(self, system_id: int) -> "BrokerFactsResult":
        """Run op_type='facts' on the agent and return the inline payload.

        Maps to ``POST /internal/agent/ops/facts``. The agent's
        runFacts collects locally and reports inline on op_complete;
        the broker captures that into op.result_metadata and surfaces
        it here. Raises ``BrokerError`` with the broker's reason
        vocabulary for any non-success path so callers can map to the
        right transport-level failure.
        """
        body = {"system_id": system_id}
        client = await self._ensure_client()
        try:
            resp = await client.post(
                "/internal/agent/ops/facts", json=body, timeout=DEFAULT_OP_TIMEOUT
            )
        except httpx.HTTPError as exc:
            raise BrokerError("broker_unreachable", str(exc)) from exc
        if resp.status_code >= 400:
            # Read the broker's reason verbatim — facts_timeout vs
            # agent_attach_timeout both surface as 504 and the refresh
            # endpoint / future UI may want to distinguish them.
            data = _safe_json(resp)
            err = (data.get("error") or {}) if isinstance(data, dict) else {}
            reason = err.get("reason")
            if not reason:
                if resp.status_code == 503:
                    reason = "transport_unavailable"
                elif resp.status_code == 504:
                    reason = "facts_timeout"
                else:
                    reason = f"http_{resp.status_code}"
            raise BrokerError(reason, _reason_or_text(resp))
        data = resp.json()
        return BrokerFactsResult(
            outcome=data.get("outcome", "error"),
            facts=data.get("facts") or {},
            partial_errors=data.get("partial_errors") or [],
        )

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Auto-build for callers that didn't enter the context
            # manager. We mark ourselves as owning it so __aexit__
            # can clean up; callers that don't use `async with`
            # leak a client per call. Acceptable for slice #3b
            # because the integration entry points are async with.
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers=_auth_headers(),
            )
            self._owns_client = True
        return self._client


# ---- op response shapes ----


@dataclass
class BrokerExecResult:
    outcome: str
    exit_code: Optional[int]
    stdout: bytes
    stderr: bytes
    duration_ms: Optional[int]
    error: Optional[dict]


@dataclass
class BrokerFilePutResult:
    outcome: str
    bytes_written: int


@dataclass
class BrokerFactsResult:
    """PRA-155 #2b-a: response shape for /internal/agent/ops/facts.

    ``facts`` matches the FactsService.ingest payload shape exactly
    (FactsService is the single canonical persistence path; this
    object is just the wire envelope around that payload).
    """

    outcome: str
    facts: dict
    partial_errors: list


class BrokerFileGetStream:
    """Streaming file_get response.

    Use as ``async with stream as s: async for chunk in s.iter_bytes():``.
    Exposes ``size`` and ``mode`` from the response headers. Raises
    if the consumed body is shorter than ``size`` — the broker's
    StreamingResponse aborts mid-flight on agent error and httpx
    surfaces that as a short body.
    """

    def __init__(self, *, _cm, _response, size: int, mode: str) -> None:
        self._cm = _cm
        self._response = _response
        self.size = size
        self.mode = mode
        self._consumed = 0
        self._exited = False

    async def __aenter__(self) -> "BrokerFileGetStream":
        return self

    async def __aexit__(self, *exc) -> None:
        if not self._exited:
            self._exited = True
            await self._cm.__aexit__(None, None, None)

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._response.aiter_bytes():
                self._consumed += len(chunk)
                yield chunk
        except httpx.HTTPError as exc:
            raise BrokerError("op_stream_closed", f"mid-stream: {exc}") from exc
        if self.size > 0 and self._consumed < self.size:
            raise BrokerError(
                "op_stream_closed",
                f"truncated: got {self._consumed} bytes, header said {self.size}",
            )


# ---- exceptions ----


class BrokerError(Exception):
    """Raised on broker-level dispatch failures.

    ``reason`` mirrors the broker's error.reason vocabulary
    (transport_unavailable, agent_attach_timeout, op_stream_closed,
    etc.). AgentTransport translates these into TransportError /
    TransportUnavailable / etc.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ---- helpers ----


def _reason_or_text(resp: httpx.Response) -> str:
    data = _safe_json(resp)
    if isinstance(data, dict):
        err = data.get("error") or {}
        if isinstance(err, dict) and err.get("reason"):
            return str(err["reason"])
    return resp.text[:200]


def _safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except Exception:  # pylint: disable=broad-except
        return None
