"""Sanitized API error handling (PRA-255).

Unexpected backend exceptions must never send their raw text to an API client: a
`str(exc)` can carry DB URLs, hostnames/IPs, filesystem paths, SQL, tokens,
tracebacks, or broker/socket internals. This module gives routes ONE small pattern:

    from ..core.api_errors import internal_error

    try:
        ...
    except SomeDomainError as e:
        raise HTTPException(status_code=404, detail="System not found") from e
    except Exception as e:
        raise internal_error(e, context="getting fleet health", logger=logger) from e

`internal_error` logs the full exception (stack trace) server-side WITH the request
correlation id, and returns a generic `HTTPException` whose public body carries no
exception internals. Known, operator-actionable domain errors (validation, not-found,
permission, conflict) are raised explicitly by the caller and are NOT touched here —
this helper is only for the broad `except Exception` catch-alls.

The request correlation id is published by the logging middleware into a contextvar
(and `request.state.request_id`) so this helper can include it in the log line and the
response header without every handler needing a `Request` parameter.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Optional

from fastapi import HTTPException

# Stable, generic public copy. Deliberately says nothing about the failure.
GENERIC_INTERNAL_DETAIL = "Internal server error"

# Correlation id for the in-flight request, set by LoggingMiddleware at the top of
# each request so any code in the request's context can read it. Defaults to None
# outside a request (e.g. background jobs).
_request_id_ctx: ContextVar[Optional[str]] = ContextVar(
    "praxis_request_id", default=None
)


def set_request_id(request_id: Optional[str]) -> None:
    """Publish the current request's correlation id (called by the middleware)."""
    _request_id_ctx.set(request_id)


def get_request_id() -> Optional[str]:
    """The current request's correlation id, or None outside a request."""
    return _request_id_ctx.get()


def internal_error(
    exc: BaseException,
    *,
    context: str,
    logger: logging.Logger,
    status_code: int = 500,
) -> HTTPException:
    """Log ``exc`` (with stack trace + request id) and return a SANITIZED HTTPException.

    ``context`` is a short server-side description of the operation (e.g. "getting
    fleet health") — it goes only into the log, never the response. The returned
    exception's ``detail`` is the stable generic string with no exception internals;
    callers should ``raise internal_error(...) from exc`` to keep the chained trace.
    The response's ``X-Request-ID`` header (set by the middleware) lets a client quote
    a reference id for support without exposing anything sensitive.
    """
    request_id = get_request_id()
    logger.error(
        "Unhandled exception while %s [request_id=%s]",
        context,
        request_id,
        exc_info=True,
    )
    return HTTPException(status_code=status_code, detail=GENERIC_INTERNAL_DETAIL)
