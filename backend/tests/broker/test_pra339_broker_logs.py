"""PRA-339: broker /internal/logs endpoint feeds the admin support bundle.

The broker keeps a bounded in-process ring buffer of its own log records (same
handler the backend uses) and exposes them over the authenticated, docker-net
internal API so the backend can bundle them without a docker socket.
"""

from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.broker.internal_api import build_internal_app
from app.core.log_buffer import install_log_buffer


def test_internal_logs_returns_records_when_buffer_installed():
    install_log_buffer()  # idempotent, process-global
    logging.getLogger("app.broker.pra339test").warning("pra339-marker-line")

    client = TestClient(build_internal_app(auth_token=None))
    resp = client.get("/internal/logs")

    assert resp.status_code == 200
    body = resp.json()
    assert body["installed"] is True
    assert any("pra339-marker-line" in rec["message"] for rec in body["records"])


def test_internal_logs_respects_limit():
    install_log_buffer()
    log = logging.getLogger("app.broker.pra339test")
    for i in range(5):
        log.warning("pra339-limit-%d", i)

    client = TestClient(build_internal_app(auth_token=None))
    resp = client.get("/internal/logs", params={"limit": 2})

    assert resp.status_code == 200
    assert len(resp.json()["records"]) <= 2


def test_internal_logs_requires_auth_when_configured():
    # The shared-secret middleware wraps every route including /internal/logs.
    client = TestClient(build_internal_app(auth_token="sekret-token"))
    resp = client.get("/internal/logs")  # no auth header
    assert resp.status_code in (401, 403)
