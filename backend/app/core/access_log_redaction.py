"""URL redaction for request and server access logs.

Two independent logging paths can write a request URL:

* the application request-logging middleware, which formats the URL itself and
  can call :func:`sanitize_url_for_log` directly; and
* the ASGI server, which logs each WebSocket upgrade with the full path *and*
  query string. That line is emitted on the ``uvicorn.error`` logger, so
  disabling the HTTP access log does not silence it and no application
  middleware sees it.

Browser terminal sessions authenticate their WebSocket upgrade with a
short-lived ticket passed as ``?token=``, because a browser cannot set an
Authorization header on a WebSocket. Short-lived is not the same as harmless:
the ticket is a bearer credential for a live interactive shell, and container
logs are collected, shipped, and retained far longer than the ticket's own
lifetime. :func:`install_access_log_redaction` therefore filters the server
loggers themselves, so the value is replaced before any handler formats it
while the route, client, and status stay intact for diagnostics.
"""

from __future__ import annotations

import logging
from typing import Any, FrozenSet
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "REDACTED"

# Query-parameter names whose values are secrets and must never reach logs.
# Some auth endpoints carry the token in the query string (logout and refresh
# both take ``token_refresh``), and the session WebSocket upgrade carries its
# ticket as ``token``.
SENSITIVE_QUERY_KEYS: FrozenSet[str] = frozenset(
    {
        "token_refresh",
        "token",
        "ticket",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "api_key",
    }
)

# Loggers that emit request/upgrade lines built from the raw URL.
_TARGET_LOGGERS = ("uvicorn.error", "uvicorn.access")


def sanitize_url_for_log(url: str) -> str:
    """Return *url* with sensitive query-parameter values redacted.

    Keeps the path and any non-sensitive query params (useful for debugging) but
    replaces the value of a known-sensitive key with ``REDACTED``, so a token
    passed as a query param (e.g. ``/auth/logout?token_refresh=...``) never lands
    in a log line. Redaction is by key name, so it holds regardless of the
    token's format. Works on absolute URLs and on the bare ``path?query`` form
    the server logs for WebSocket upgrades.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url
    redacted = [
        (key, REDACTED if key.lower() in SENSITIVE_QUERY_KEYS else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(parts._replace(query=urlencode(redacted)))


def _redact_arg(value: Any) -> Any:
    """Sanitize a single log-record argument, leaving non-URL values alone."""
    if isinstance(value, str) and "?" in value:
        return sanitize_url_for_log(value)
    return value


class QueryRedactionFilter(logging.Filter):
    """Strip sensitive query values from log records before they are formatted.

    The server passes the URL as a record argument rather than pre-formatting
    it, so the arguments are rewritten in place. A record that carries no
    arguments is already fully formed and is sanitized directly. Records
    without a query string are returned untouched, and the filter never drops
    a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not args:
            if isinstance(record.msg, str) and "?" in record.msg:
                record.msg = sanitize_url_for_log(record.msg)
        elif isinstance(args, tuple):
            record.args = tuple(_redact_arg(a) for a in args)
        elif isinstance(args, dict):
            record.args = {k: _redact_arg(v) for k, v in args.items()}
        return True


def install_access_log_redaction() -> None:
    """Attach the query-redaction filter to the server loggers.

    Idempotent, so repeated calls (module reimport, worker restart) do not stack
    duplicate filters. Filters attached to a logger survive ``dictConfig``,
    which the server re-applies per worker process, so installing this once at
    application import time holds for the life of the process.
    """
    for name in _TARGET_LOGGERS:
        logger = logging.getLogger(name)
        if any(isinstance(f, QueryRedactionFilter) for f in logger.filters):
            continue
        logger.addFilter(QueryRedactionFilter())
