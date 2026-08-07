"""Supportability logging: structured, redaction-safe log lines for support triage.

These are ordinary ``logging`` calls (so they land in the in-memory ring buffer that
feeds the diagnostic support bundle) with a consistent, greppable shape:

    support event=<event> outcome=<outcome> key=value key=value ...

Only SAFE correlation fields belong here — actor/user/admin id, system id/hostname,
job/task id, license instance id, request/correlation id, error category, and
reconcile/retry state. Never pass secrets, tokens, passwords, command text, or raw
payloads; the bundle redactor is a backstop, not a licence to log sensitive values.
"""

from __future__ import annotations

import logging
from typing import Any

# Fields that are always safe to include as correlation context. Anything not on
# this list is dropped so a careless caller can't smuggle a secret into a log line.
_SAFE_FIELDS = frozenset(
    {
        "actor_user_id",
        "admin_user_id",
        "user_id",
        "system_id",
        "hostname",
        "job_id",
        "task_id",
        "request_id",
        "correlation_id",
        "license_instance_id",
        "error_category",
        "retry",
        "reconcile_state",
        "outcome",
        "count",
        "duration_ms",
    }
)


def _fmt(fields: dict[str, Any]) -> str:
    parts = []
    for key in sorted(fields):
        if key not in _SAFE_FIELDS:
            continue
        val = fields[key]
        if val is None:
            continue
        parts.append(f"{key}={val}")
    return " ".join(parts)


def log_support_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit a structured supportability log line.

    ``event`` is a stable dotted identifier (e.g. ``auth.login``,
    ``license.apply``, ``host.enroll``). ``fields`` are safe correlation values;
    unknown keys are silently dropped. Best-effort — logging never raises.
    """
    try:
        suffix = _fmt(fields)
        logger.log(level, "support event=%s%s", event, f" {suffix}" if suffix else "")
    except Exception:  # pragma: no cover - logging must never break a request
        pass
