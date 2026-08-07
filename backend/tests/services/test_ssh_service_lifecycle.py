"""SSHService lifecycle/resource guards."""

from unittest.mock import MagicMock

from app.services import ssh_service
from app.services.ssh_service import SSHService


def _db_without_settings():
    db = MagicMock()
    db.query.return_value.first.return_value = None
    return db


def test_ssh_service_construction_does_not_start_background_threads(monkeypatch):
    """Constructing request-scoped SSHService objects must not leak threads."""
    thread_ctor = MagicMock()
    monkeypatch.setattr(ssh_service.threading, "Thread", thread_ctor)

    for _ in range(25):
        SSHService(_db_without_settings())

    thread_ctor.assert_not_called()


def test_idle_cleanup_is_opportunistic_and_throttled(monkeypatch):
    svc = SSHService(_db_without_settings())
    removed = MagicMock()
    monkeypatch.setattr(svc, "_remove_idle_connections", removed)

    svc._last_pool_cleanup_at = 1000
    svc._pool_cleanup_interval = 300
    monkeypatch.setattr(ssh_service.time, "time", lambda: 1100)
    svc._maybe_cleanup_idle_connections()
    removed.assert_not_called()

    monkeypatch.setattr(ssh_service.time, "time", lambda: 1301)
    svc._maybe_cleanup_idle_connections()
    removed.assert_called_once()
