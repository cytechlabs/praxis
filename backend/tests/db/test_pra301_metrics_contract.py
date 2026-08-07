"""PRA-301: the backend Prometheus exporter contract is truthful + deterministic.

Every supported custom metric is emitted by normal production code paths
(``get_db`` request sessions and ``DatabaseSessionManager``), current pool state is a
real gauge, cumulative events are counters, timing is per-operation (not shared
process state), and the scrape listener starts explicitly + idempotently. Dead
collectors (the old mislabeled gauge and the unwired DB-health gauges) are gone.
"""

from __future__ import annotations

import pytest
from prometheus_client import REGISTRY, generate_latest
from sqlalchemy import text

import app.db.session as session_mod
from app.db.session import DatabaseSessionManager, get_db, start_metrics_server


def _val(name: str, labels: dict | None = None) -> float:
    v = REGISTRY.get_sample_value(name, labels or {})
    return 0.0 if v is None else v


def _drain_get_db_success():
    gen = get_db()
    db = next(gen)
    db.execute(text("SELECT 1"))
    try:
        next(gen)
    except StopIteration:
        pass


# ------------------------------------------------- operations counter + latency


def test_get_db_success_records_operation_and_latency():
    before = _val("db_operations_total", {"operation_type": "success"})
    before_count = _val("db_operation_latency_seconds_count")

    _drain_get_db_success()

    assert _val("db_operations_total", {"operation_type": "success"}) == before + 1
    assert _val("db_operation_latency_seconds_count") == before_count + 1


def test_get_db_error_records_error_outcome():
    before = _val("db_operations_total", {"operation_type": "error"})

    gen = get_db()
    next(gen)
    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("handler blew up"))

    assert _val("db_operations_total", {"operation_type": "error"}) == before + 1


def test_session_manager_success_and_error_outcomes():
    ok_before = _val("db_operations_total", {"operation_type": "success"})
    err_before = _val("db_operations_total", {"operation_type": "error"})

    with DatabaseSessionManager() as db:
        db.execute(text("SELECT 1"))
    assert _val("db_operations_total", {"operation_type": "success"}) == ok_before + 1

    with pytest.raises(RuntimeError):
        with DatabaseSessionManager() as db:
            raise RuntimeError("boom")
    assert _val("db_operations_total", {"operation_type": "error"}) == err_before + 1


# ----------------------------------------------------- connection gauge/counter


def test_connections_in_use_is_a_current_gauge():
    base = _val("db_connections_in_use")

    mgr = DatabaseSessionManager()
    db = mgr.__enter__()
    db.execute(text("SELECT 1"))  # forces a real checkout from the pool
    # While the connection is checked out the CURRENT gauge is up by one...
    assert _val("db_connections_in_use") == base + 1

    mgr.__exit__(None, None, None)
    # ...and back to baseline on checkin — the property the old lifetime-counter
    # masquerading as a gauge did not have.
    assert _val("db_connections_in_use") == base


def test_connections_created_is_a_monotonic_counter():
    before = _val("db_connections_created_total")
    # Exercising sessions never DECREASES the cumulative physical-connection counter.
    _drain_get_db_success()
    assert _val("db_connections_created_total") >= before


# ------------------------------------------------------- listener lifecycle


def test_start_metrics_server_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(
        session_mod, "start_http_server", lambda port: calls.append(port)
    )
    monkeypatch.setattr(session_mod, "_metrics_server_started", False)

    assert start_metrics_server(port=0) is True
    assert start_metrics_server(port=0) is False  # no second bind
    assert calls == [0]


# --------------------------------------------------------- exposition contract


def test_exposition_contains_supported_and_drops_dead_metrics():
    # Generate representative traffic so every series has samples.
    _drain_get_db_success()
    with DatabaseSessionManager() as db:
        db.execute(text("SELECT 1"))

    body = generate_latest(REGISTRY).decode()

    for name in (
        "db_operations_total",
        "db_operation_latency_seconds",
        "db_connections_in_use",
        "db_connections_created_total",
    ):
        assert name in body, f"supported metric missing from exposition: {name}"

    # Dead/mislabeled collectors removed in PRA-301.
    assert "db_connections_current" not in body
    assert "db_health_status" not in body
    assert "db_health_response_time_seconds" not in body
