"""PRA-390: WebSocket ticket values must not reach server access logs.

A browser cannot set an Authorization header on a WebSocket upgrade, so the
terminal session passes a short-lived ticket as ``?token=``. The ASGI server
logs each upgrade with the full path *and* query string on its ``uvicorn.error``
logger, which no application middleware sees and which the HTTP access-log
switch does not silence. Container logs outlive the ticket by orders of
magnitude, so the value has to be redacted inside the logging pipeline.

These tests drive the real producer: the log call is reconstructed exactly as
the server's WebSocket protocol makes it, including the same logger name and
the same path/query helper, and the redaction is re-checked after the server
re-applies its logging configuration (which it does once per worker process).
"""

from __future__ import annotations

import logging
import logging.config

import pytest
from uvicorn.config import LOGGING_CONFIG
from uvicorn.protocols.utils import get_path_with_query_string

from app.core.access_log_redaction import (
    QueryRedactionFilter,
    install_access_log_redaction,
    sanitize_url_for_log,
)

SENTINEL = "SENTINEL-WS-TICKET-VALUE"
WS_PATH = "/sessions/5/ws"
SERVER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def capture_server_log():
    """Capture ``uvicorn.error`` output with the redaction filter installed.

    Establishes its own logging preconditions rather than inheriting whatever an
    earlier test left behind: another module's ``dictConfig`` or global
    ``logging.disable`` would otherwise suppress the record before any handler
    sees it, and the assertion would pass vacuously or fail for the wrong reason.
    """
    install_access_log_redaction()
    logger = logging.getLogger("uvicorn.error")
    saved = (logger.level, logger.propagate, logger.disabled)
    saved_global_disable = logging.root.manager.disable
    handler = _Capture()
    logger.addHandler(handler)
    logging.disable(logging.NOTSET)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.disabled = False
    try:
        yield logger, handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]
        logger.disabled = saved[2]
        logging.disable(saved_global_disable)


def _ws_scope(query: str) -> dict:
    return {
        "type": "websocket",
        "path": WS_PATH,
        "root_path": "",
        "raw_path": WS_PATH.encode(),
        "query_string": query.encode(),
    }


def _log_upgrade(logger: logging.Logger, scope: dict) -> None:
    """Reproduce the server's WebSocket upgrade log call verbatim."""
    logger.info(
        '%s - "WebSocket %s" [accepted]',
        ("10.0.0.7", 51234),
        get_path_with_query_string(scope),
    )


# --------------------------------------------------------------- sanitizer


def test_sanitizer_redacts_the_ws_ticket_and_keeps_the_route():
    out = sanitize_url_for_log(f"{WS_PATH}?token={SENTINEL}")
    assert SENTINEL not in out
    assert out.startswith(WS_PATH)
    assert "token=REDACTED" in out


def test_sanitizer_keeps_non_sensitive_diagnostic_params():
    out = sanitize_url_for_log(f"{WS_PATH}?token={SENTINEL}&mode=observe")
    assert SENTINEL not in out
    assert "mode=observe" in out


# --------------------------------------------------------------- filter


def test_upgrade_log_line_carries_the_route_but_not_the_ticket(capture_server_log):
    logger, handler = capture_server_log
    _log_upgrade(logger, _ws_scope(f"token={SENTINEL}"))

    assert handler.messages, "the upgrade line was not captured"
    line = handler.messages[-1]
    assert SENTINEL not in line
    assert WS_PATH in line
    assert "token=REDACTED" in line
    # Non-sensitive diagnostic context survives.
    assert "10.0.0.7" in line
    assert "[accepted]" in line


def test_redaction_survives_the_server_reapplying_its_logging_config(
    capture_server_log,
):
    """Each worker process re-runs ``dictConfig``; logger filters must persist."""
    logger, handler = capture_server_log
    saved = {
        name: (
            logging.getLogger(name).handlers[:],
            logging.getLogger(name).filters[:],
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
            logging.getLogger(name).disabled,
        )
        for name in SERVER_LOGGERS
    }
    try:
        logging.config.dictConfig(LOGGING_CONFIG)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.disabled = False
        _log_upgrade(logger, _ws_scope(f"token={SENTINEL}"))
    finally:
        for name, (handlers, filters, level, propagate, disabled) in saved.items():
            restored = logging.getLogger(name)
            restored.handlers = handlers
            restored.filters = filters
            restored.setLevel(level)
            restored.propagate = propagate
            restored.disabled = disabled

    assert handler.messages, "the upgrade line was not captured"
    assert SENTINEL not in handler.messages[-1]
    assert WS_PATH in handler.messages[-1]


def test_records_without_a_query_string_are_untouched(capture_server_log):
    logger, handler = capture_server_log
    _log_upgrade(logger, _ws_scope(""))
    assert handler.messages[-1].endswith(f'"WebSocket {WS_PATH}" [accepted]')


def test_preformatted_messages_are_redacted_too(capture_server_log):
    logger, handler = capture_server_log
    logger.info("upgrade rejected: %s" % f"{WS_PATH}?token={SENTINEL}")
    assert SENTINEL not in handler.messages[-1]
    assert WS_PATH in handler.messages[-1]


def test_install_is_idempotent():
    install_access_log_redaction()
    install_access_log_redaction()
    for name in ("uvicorn.error", "uvicorn.access"):
        filters = [
            f
            for f in logging.getLogger(name).filters
            if isinstance(f, QueryRedactionFilter)
        ]
        assert len(filters) == 1


def test_importing_the_app_installs_the_filter():
    """Wiring check: the filter is live for anything the server logs."""
    import app.api.main  # noqa: F401

    for name in ("uvicorn.error", "uvicorn.access"):
        assert any(
            isinstance(f, QueryRedactionFilter) for f in logging.getLogger(name).filters
        )
