"""PRA-323: keep blocking host work off the async event loop.

- fleet health check-all is single-flight (repeated Check All -> already_running);
- the route handlers that call blocking SSH/host services are SYNC `def` (FastAPI
  runs them in the threadpool) so one hung host sweep can't starve the event loop.
  A guard test enforces this so a future edit can't silently re-introduce
  `async def` on a blocking-host route file.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import threading

import pytest

from app.services import health_service as hs
from app.services.health_service import HealthService

# --------------------------------------------------------------- single-flight


def test_check_all_is_single_flight(db, monkeypatch):
    svc = HealthService(db)
    # A different thread holds the fleet-sweep lock (simulating an in-flight sweep).
    acquired = threading.Event()
    release = threading.Event()

    def _holder():
        hs._fleet_sweep_lock.acquire()
        acquired.set()
        release.wait(5)
        hs._fleet_sweep_lock.release()

    t = threading.Thread(target=_holder)
    t.start()
    try:
        assert acquired.wait(5)
        res = svc.check_all_systems()
        assert res["status"] == "already_running"
        assert "already running" in res["message"]
        assert res["total"] == 0
    finally:
        release.set()
        t.join(5)


def test_check_all_runs_when_free(db, monkeypatch):
    svc = HealthService(db)
    monkeypatch.setattr(
        svc,
        "_check_all_systems_impl",
        lambda *, scope_system_ids=None, force=False: {
            "total": 3,
            "ok": 3,
            "failed": 0,
            "results": [],
        },
    )
    res = svc.check_all_systems()
    assert res.get("status") != "already_running"
    assert res["total"] == 3
    # Lock released -> a subsequent sweep runs again.
    res2 = svc.check_all_systems()
    assert res2["total"] == 3


def test_single_flight_lock_released_after_impl_error(db, monkeypatch):
    svc = HealthService(db)

    def _boom(*, scope_system_ids=None, force=False):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(svc, "_check_all_systems_impl", _boom)
    with pytest.raises(RuntimeError):
        svc.check_all_systems()
    # finally released the lock, so a fresh sweep is not wedged as already_running.
    assert hs._fleet_sweep_lock.acquire(blocking=False) is True
    hs._fleet_sweep_lock.release()


# --------------------------------------------------------- event-loop sweep guard


# Route modules that invoke blocking SSH / Paramiko / SFTP / package-manager /
# host provisioning work. Every handler in these must be SYNC so FastAPI runs it
# in the threadpool instead of on the event loop (PRA-322 / PRA-323).
_BLOCKING_HOST_ROUTE_MODULES = [
    "app.api.routes.health",
    "app.api.routes.ssh",
    "app.api.routes.packages",
    "app.api.routes.command_execution",
    "app.api.routes.file_transfer",
    "app.api.routes.bulk",
    "app.api.routes.fleet_access",
    "app.api.routes.command_approvals",
    "app.api.routes.agent",
    "app.api.routes.ssh_identity",
    "app.api.routes.repos",
]


@pytest.mark.parametrize("modpath", _BLOCKING_HOST_ROUTE_MODULES)
def test_blocking_host_route_handlers_are_sync(modpath):
    mod = importlib.import_module(modpath)
    router = getattr(mod, "router")
    offenders = []
    for route in router.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None and inspect.iscoroutinefunction(endpoint):
            offenders.append(f"{modpath}:{endpoint.__name__}")
    assert not offenders, (
        "these handlers run blocking host work on the event loop; make them "
        f"sync `def`: {offenders}"
    )


def test_facts_ssh_fallback_runs_off_the_event_loop(monkeypatch):
    """PRA-323: ``facts.refresh_facts`` stays async for the agent broker path, so
    its SSH fallback (``_do_ssh``) must offload the blocking collector via
    ``asyncio.to_thread`` — it must NOT run on the event-loop thread."""
    from app.api.routes import facts as facts_mod

    ran_on = {}

    def _fake_collect(db, *, system_id):  # noqa: ARG001
        ran_on["thread"] = threading.get_ident()
        return object()

    monkeypatch.setattr(
        facts_mod.ssh_facts_collector_service, "collect_and_ingest", _fake_collect
    )
    monkeypatch.setattr(
        facts_mod, "_format_response", lambda result, transport: {"t": transport}
    )

    async def _run():
        loop_thread = threading.get_ident()
        res = await facts_mod._do_ssh(db=None, system_id=1)
        return loop_thread, res

    loop_thread, res = asyncio.run(_run())
    assert "thread" in ran_on
    assert ran_on["thread"] != loop_thread  # collector ran on a worker thread
    assert res == {"t": "ssh"}
