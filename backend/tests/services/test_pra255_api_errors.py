"""PRA-255: unit contract for the sanitized-error helper."""

from __future__ import annotations

import logging

from fastapi import HTTPException

from app.core import api_errors


def test_internal_error_returns_generic_sanitized_exception(caplog):
    logger = logging.getLogger("pra255.test")
    api_errors.set_request_id("req-123")
    try:
        raise RuntimeError("postgresql://u:p@db/x SELECT secret /etc/passwd")
    except RuntimeError as exc:
        with caplog.at_level(logging.ERROR):
            http = api_errors.internal_error(
                exc, context="doing a thing", logger=logger
            )

    assert isinstance(http, HTTPException)
    assert http.status_code == 500
    assert http.detail == "Internal server error"
    # No exception internals in the public detail.
    for needle in ("postgresql", "SELECT", "secret", "/etc/passwd", "RuntimeError"):
        assert needle not in str(http.detail)
    # ...but the full text + request id + stack trace ARE logged server-side.
    assert "postgresql://u:p@db/x" in caplog.text
    assert "request_id=req-123" in caplog.text
    assert "doing a thing" in caplog.text


def test_request_id_defaults_to_none_outside_request():
    api_errors.set_request_id(None)
    assert api_errors.get_request_id() is None
    # Helper still works with no request id (e.g. a background context).
    http = api_errors.internal_error(
        ValueError("boom"), context="bg", logger=logging.getLogger("pra255.test")
    )
    assert http.status_code == 500 and http.detail == "Internal server error"
