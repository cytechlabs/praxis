"""Admin-generated diagnostic support bundle (PRA-310).

Builds a bounded, redacted, deterministic ``.zip`` of support context for Cytech Labs
to debug a 1.0 customer issue WITHOUT collecting any secret. It reads only a fixed
allowlist of DB summaries + the in-memory log ring buffer — never a caller-supplied
file path — so it can never stream arbitrary files, and every emitted text is run
through :func:`app.core.redaction.redact_text` as defense-in-depth.

Guarantees: admin-only + audited (enforced at the route), compressed, and a
deterministic file list. Byte bounds are enforced on the UNCOMPRESSED content before
compression: the log section truncates to a cap with a marker, an oversized JSON
section fails closed, and the total uncompressed size fails closed over its ceiling —
so a highly-compressible section can never expand into a large bundle behind a small
zip. A final compressed-size guard backstops all of it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..core.redaction import redact_text
from ..db.access_models import AuditEvent
from ..db.command_execution_models import CommandExecutionResult
from ..db.models import System, VaultConfig

BUNDLE_VERSION = 1

# Bounds — hard caps so the bundle is always small and cheap.
#
# Row/count caps bound how much we read from the DB + log buffer. Byte caps bound
# the produced content BEFORE compression, so a highly-compressible section can't
# expand to a huge uncompressed bundle behind a small zip. Enforcement order:
#   1. cap rows/records read (below),
#   2. truncate the log section to MAX_LOG_BYTES with a marker,
#   3. fail closed if any JSON section exceeds MAX_JSON_SECTION_BYTES,
#   4. fail closed if the total uncompressed section bytes exceed
#      MAX_TOTAL_UNCOMPRESSED_BYTES,
#   5. final compressed-size guard (MAX_BUNDLE_BYTES) as defense-in-depth.
TIME_RANGES: Dict[str, int] = {"24h": 24, "72h": 72, "7d": 168}  # hours
MAX_LOG_RECORDS = 5000
MAX_AUDIT_EVENTS = 1000
MAX_FAILED_JOBS = 300
MAX_SYSTEMS = 1000

# Byte caps (uncompressed).
MAX_LOG_BYTES = 8 * 1024 * 1024  # logs are the only section we TRUNCATE (with marker)
MAX_JSON_SECTION_BYTES = 8 * 1024 * 1024  # any JSON section over this FAILS CLOSED
# PRA-339: backend log (8M) + broker log (8M) + JSON sections must fit here.
# Raised from 25M to 33M when the second log file (logs/broker.log) was added so
# a real bundle with both logs near their caps doesn't trip the fail-closed
# total. The compressed ceiling below is unchanged — logs compress heavily, so
# the compressed bundle stays far under it.
MAX_TOTAL_UNCOMPRESSED_BYTES = 33 * 1024 * 1024  # total sections, pre-compression
MAX_BUNDLE_BYTES = 25 * 1024 * 1024  # final compressed ceiling (defense-in-depth)

# Room reserved for the truncation marker so the capped log stays strictly under
# MAX_LOG_BYTES even after the marker is appended.
_LOG_MARKER_RESERVE = 256

# Deterministic epoch for zip entries so bytes don't vary by mtime.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# NON-secret config keys allowed into the bundle. This is an explicit ALLOWLIST — we
# never iterate os.environ, so a new secret env var can never leak by default.
_CONFIG_ALLOWLIST = (
    "ENVIRONMENT",
    "COMPOSE_PROFILES",
    "VAULT_ADDR",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "REFRESH_TOKEN_EXPIRE_DAYS",
    "POSTGRES_SERVER",
    "POSTGRES_DB",
    "POSTGRES_PORT",
    "PRAXIS_DOMAIN",
    "PRAXIS_TLS_MODE",
    "LOG_LEVEL",
)


class DiagnosticsError(Exception):
    """Raised when a bundle cannot be produced within bounds."""


def _app_version() -> str:
    return os.getenv("PRAXIS_VERSION", "1.0.0")


def _json_bytes(obj: Any) -> bytes:
    # sort_keys => deterministic ordering; redact as a final safety net.
    return redact_text(json.dumps(obj, indent=2, sort_keys=True, default=str)).encode(
        "utf-8"
    )


def _safe(section: str, fn):
    """Run a collector, degrading a failure to an error note rather than aborting the
    whole bundle."""
    try:
        return fn()
    except Exception as e:  # pylint: disable=broad-except
        return {"section": section, "error": redact_text(str(e))}


# ----------------------------------------------------------------- collectors


def _schema(db: Session) -> Dict[str, Any]:
    head = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return {"alembic_head": head}


def _config_summary() -> Dict[str, Any]:
    present = {k: os.getenv(k) for k in _CONFIG_ALLOWLIST if os.getenv(k) is not None}
    return {
        "note": "Allowlisted non-secret config only; no full environment dump.",
        "config": present,
    }


def _health(db: Session) -> Dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # pylint: disable=broad-except
        db_ok = False
    vault_cfg = db.query(VaultConfig).filter(VaultConfig.is_active.is_(True)).first()
    return {
        "database_reachable": db_ok,
        "vault_config_present": vault_cfg is not None,
        "vault_health_status": (
            vault_cfg.health_status if vault_cfg else "not_configured"
        ),
    }


def _audit_summary(db: Session, since: datetime, limit: int) -> Dict[str, Any]:
    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.timestamp >= since)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    # Only safe correlation fields — NEVER context_json (may hold command text etc.).
    events = [
        {
            "timestamp": r.timestamp,
            "action": r.action,
            "outcome": r.outcome,
            "actor_user_id": r.actor_user_id,
            "target_system_id": r.target_system_id,
            "target_kind": r.target_kind,
        }
        for r in rows
    ]
    by_action: Dict[str, int] = {}
    for e in events:
        key = f"{e['action']}:{e['outcome']}"
        by_action[key] = by_action.get(key, 0) + 1
    return {
        "count": len(events),
        "limited_to": limit,
        "by_action_outcome": by_action,
        "events": events,
    }


def _reconcile_status(db: Session) -> Dict[str, Any]:
    from ..services import fleet_reconciliation_service as frs
    from ..services import revocation_service
    from ..services.access_authorization_service import shared_login_conflicts

    return {
        "revocation": _safe(
            "revocation", lambda: revocation_service.revocation_status(db)
        ),
        "privilege_reconcile": _safe(
            "privilege_reconcile", lambda: frs.privilege_reconcile_status(db)
        ),
        "shared_login_conflicts": _safe(
            "shared_login_conflicts", lambda: shared_login_conflicts(db)
        ),
    }


def _failed_jobs(db: Session, since: datetime, limit: int) -> Dict[str, Any]:
    rows = (
        db.query(CommandExecutionResult)
        .filter(
            CommandExecutionResult.started_at >= since,
            CommandExecutionResult.execution_status.in_(("failed", "error", "timeout")),
        )
        .order_by(CommandExecutionResult.started_at.desc())
        .limit(limit)
        .all()
    )
    # Metadata only — never command text, stdout, or stderr.
    return {
        "count": len(rows),
        "limited_to": limit,
        "failed_command_executions": [
            {
                "id": r.id,
                "system_id": r.system_id,
                "execution_status": r.execution_status,
                "error_type": r.error_type,
                "started_at": r.started_at,
            }
            for r in rows
        ],
    }


def _systems(db: Session, limit: int) -> Dict[str, Any]:
    rows = db.query(System).order_by(System.id.asc()).limit(limit).all()
    # Debug metadata only — no credentials, no IPs.
    return {
        "count": len(rows),
        "systems": [
            {
                "id": s.id,
                "hostname": s.hostname,
                "status": s.status,
                "os_version": s.os_version,
                "agent_status": getattr(s, "agent_status", None),
                "ca_trust_deployed": getattr(s, "ca_trust_deployed", None),
            }
            for s in rows
        ],
    }


def _logs(since_epoch: float, limit: int) -> bytes:
    from ..core.log_buffer import get_log_buffer

    buf = get_log_buffer()
    if buf is None:
        return b"(log buffer not installed)\n"
    lines = [
        redact_text(f"{r['level']} {r['logger']} {r['message']}")
        for r in buf.records(since_epoch=since_epoch, limit=limit)
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _cap_log_bytes(data: bytes, cap: int) -> Tuple[bytes, int]:
    """Truncate ``data`` to ``cap`` bytes (uncompressed), appending a marker.

    Logs are TRUNCATED rather than fail-closed: a support bundle is still useful
    with a bounded tail of logs. We cut on a line boundary to avoid splitting a
    record (and a UTF-8 multibyte char), reserve room for the marker so the result
    stays strictly under ``cap``, and report how many bytes were omitted. Returns
    ``(capped_bytes, omitted_bytes)``; ``omitted_bytes == 0`` means no truncation.
    """
    if len(data) <= cap:
        return data, 0
    keep = max(0, cap - _LOG_MARKER_RESERVE)
    kept = data[:keep]
    nl = kept.rfind(b"\n")
    if nl > 0:
        kept = kept[: nl + 1]
    omitted = len(data) - len(kept)
    marker = (
        f"«log truncated: {omitted} bytes omitted to stay within the "
        f"{cap}-byte support-bundle log cap»\n"
    ).encode("utf-8")
    return kept + marker, omitted


def _run_async_from_sync(coro):
    """Run an awaitable from sync bundle code even if a parent event loop is
    running. ``asyncio.run`` raises when a loop is active in this thread, so fall
    back to a fresh worker thread that owns its own loop. Mirrors the bridge used
    elsewhere in the backend for calling the async BrokerClient from sync code."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _broker_logs(
    since_epoch: float, limit: int
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    """PRA-339: fetch + redact recent broker log records for the bundle.

    Returns ``(log_bytes | None, metadata)``. NEVER raises — any broker problem
    degrades to metadata that explains why broker logs aren't included, so it can
    never break bundle generation (the backend log section is unaffected).

    ``status`` is one of:
      - ``included``     endpoint returned records (buffer installed).
      - ``unavailable``  broker unreachable / errored / buffer not installed.
      - ``unsupported``  no internal shared secret (external/unbundled broker),
                         or the broker build has no logs endpoint (404).

    The broker is a separate container whose stdout the backend can't read
    without a docker socket (deliberately avoided), so logs are pulled over the
    authenticated, docker-net-only internal API. A short timeout (the
    BrokerClient default) keeps a down broker from delaying bundle generation.
    """
    # Local imports keep the broker-client + auth deps off this module's import
    # path for callers that only need the pure helpers.
    from ..broker.internal_auth import (  # pylint: disable=import-outside-toplevel
        derive_internal_token,
    )
    from .broker_client import BrokerClient  # pylint: disable=import-outside-toplevel

    if not derive_internal_token():
        return None, {
            "status": "unsupported",
            "reason": (
                "broker internal API not configured for this deployment (no "
                "shared secret); broker logs are only bundled for the bundled "
                "compose deployment"
            ),
        }

    async def _fetch():
        return await BrokerClient().logs(since_epoch=since_epoch, limit=limit)

    try:
        body = _run_async_from_sync(_fetch())
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None, {
                "status": "unsupported",
                "reason": "broker build does not expose a logs endpoint",
            }
        return None, {
            "status": "unavailable",
            "reason": f"broker logs endpoint returned HTTP {exc.response.status_code}",
        }
    except Exception as exc:  # pylint: disable=broad-except
        # Network error / timeout / anything else — never break the bundle.
        return None, {
            "status": "unavailable",
            "reason": redact_text(str(exc)) or "broker unreachable",
        }

    if not body.get("installed"):
        return None, {
            "status": "unavailable",
            "reason": "broker log buffer not installed",
        }
    records = body.get("records") or []
    lines = [
        redact_text(f"{r.get('level')} {r.get('logger')} {r.get('message')}")
        for r in records
    ]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    return data, {"status": "included", "record_count": len(records)}


# ----------------------------------------------------------------- bundle


def generate_bundle(
    db: Session,
    actor_user_id: int,
    time_range: str = "72h",
    now: datetime = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Produce ``(zip_bytes, manifest)``. ``time_range`` must be a key of
    ``TIME_RANGES`` (validated at the route)."""
    if time_range not in TIME_RANGES:
        raise DiagnosticsError(f"invalid time_range: {time_range!r}")

    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=TIME_RANGES[time_range])
    since_epoch = since.timestamp()

    # Logs are the only section we truncate; everything else is row/count bounded.
    raw_logs = _logs(since_epoch, MAX_LOG_RECORDS)
    capped_logs, log_omitted_bytes = _cap_log_bytes(raw_logs, MAX_LOG_BYTES)

    # PRA-339: broker logs, pulled over the authenticated internal API. Included
    # only when the broker is reachable and its buffer is installed; otherwise a
    # metadata block records why. Never breaks bundle generation.
    broker_log_bytes, broker_meta = _broker_logs(since_epoch, MAX_LOG_RECORDS)
    broker_omitted_bytes = 0
    if broker_log_bytes is not None:
        broker_log_bytes, broker_omitted_bytes = _cap_log_bytes(
            broker_log_bytes, MAX_LOG_BYTES
        )
        broker_meta["truncated"] = broker_omitted_bytes > 0
        broker_meta["omitted_bytes"] = broker_omitted_bytes

    # A FIXED set of content files — no caller-controlled paths. Deterministic list.
    content: Dict[str, bytes] = {
        "version.json": _json_bytes(
            {
                "praxis_version": _app_version(),
                "bundle_version": BUNDLE_VERSION,
                "generated_at": now,
                "time_range": time_range,
            }
        ),
        "schema.json": _json_bytes(_safe("schema", lambda: _schema(db))),
        "config_summary.json": _json_bytes(_safe("config", _config_summary)),
        "health.json": _json_bytes(_safe("health", lambda: _health(db))),
        "audit_events.json": _json_bytes(
            _safe("audit", lambda: _audit_summary(db, since, MAX_AUDIT_EVENTS))
        ),
        "reconcile_status.json": _json_bytes(
            _safe("reconcile", lambda: _reconcile_status(db))
        ),
        "failed_jobs.json": _json_bytes(
            _safe("failed_jobs", lambda: _failed_jobs(db, since, MAX_FAILED_JOBS))
        ),
        "systems.json": _json_bytes(
            _safe("systems", lambda: _systems(db, MAX_SYSTEMS))
        ),
        "logs/backend.log": capped_logs,
    }

    # PRA-339: only add the broker log file when it was actually collected. When
    # it's unavailable/unsupported the manifest's broker_logs block explains why,
    # so the file list stays honest (no empty/stub file).
    if broker_log_bytes is not None:
        content["logs/broker.log"] = broker_log_bytes

    # Fail CLOSED on an oversized JSON section. These are curated + row-bounded, so
    # one blowing past its cap is anomalous — we refuse rather than ship a surprise.
    for name, data in content.items():
        if name.endswith(".json") and len(data) > MAX_JSON_SECTION_BYTES:
            raise DiagnosticsError(
                f"support bundle section {name!r} exceeded the per-section cap "
                f"({len(data)} > {MAX_JSON_SECTION_BYTES} bytes)"
            )

    # Fail CLOSED on total uncompressed content BEFORE we spend memory compressing.
    total_uncompressed = sum(len(d) for d in content.values())
    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise DiagnosticsError(
            f"support bundle exceeded the total uncompressed size ceiling "
            f"({total_uncompressed} > {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes)"
        )

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "praxis_version": _app_version(),
        "generated_at": now.isoformat(),
        "generated_by_user_id": actor_user_id,
        "time_range": time_range,
        "redaction": (
            "Secrets (passwords, Vault/root/unseal tokens, JWTs, refresh/access "
            "tokens, private keys, DSN credentials) are pattern-redacted; config is "
            "allowlisted (no full env dump); no command output/stdout/stderr; bounded "
            "by time and size."
        ),
        "bounds": {
            "max_log_bytes": MAX_LOG_BYTES,
            "max_json_section_bytes": MAX_JSON_SECTION_BYTES,
            "max_total_uncompressed_bytes": MAX_TOTAL_UNCOMPRESSED_BYTES,
            "max_compressed_bytes": MAX_BUNDLE_BYTES,
            "log_truncated": log_omitted_bytes > 0,
            "log_omitted_bytes": log_omitted_bytes,
        },
        # PRA-339: whether broker logs were included and, if not, why. The
        # logs/broker.log file is present in the bundle only when status is
        # "included".
        "broker_logs": broker_meta,
        # total_uncompressed_bytes counts the content sections (excludes this
        # manifest, which is small and derivative).
        "total_uncompressed_bytes": total_uncompressed,
        "files": [
            {
                "name": name,
                "bytes": len(data),  # uncompressed section size
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in sorted(content.items())
        ],
    }

    files: Dict[str, bytes] = dict(content)
    files["manifest.json"] = _json_bytes(manifest)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):  # deterministic member order
            info = zipfile.ZipInfo(filename=name, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[name])
    data = buf.getvalue()
    if (
        len(data) > MAX_BUNDLE_BYTES
    ):  # pragma: no cover - uncompressed cap keeps us under
        raise DiagnosticsError("support bundle exceeded the compressed size ceiling")

    manifest["file_list"] = sorted(files)
    manifest["bytes"] = len(data)  # compressed
    manifest["total_uncompressed_bytes"] = total_uncompressed
    return data, manifest
