"""PRA-255: unexpected backend exceptions must not leak internals to API clients.

Forced-failure tests prove that a broad `except Exception` path:
- logs the real exception (with its sensitive text) server-side, and
- returns a stable generic 500 body with NO exception internals, plus the
  X-Request-ID correlation header.

Known operator-actionable domain errors (4xx) must keep their explicit detail.
"""

from __future__ import annotations

import logging

from app.services.command_execution_service import CommandExecutionService
from app.services.health_service import HealthService
from app.services.package_service import PackageService

# A marker packed with the shapes we must never leak: DSN creds, SQL, a filesystem
# path, and a host:port. If any of this reaches the client, the test fails.
SENSITIVE = (
    "postgresql://praxis:s3cr3t@db:5432/praxis | SELECT * FROM users | "
    "/etc/praxis/secret.key | broker=10.0.0.5:8443"
)


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def _raise_sensitive(*_a, **_k):
    raise RuntimeError(SENSITIVE)


class _CaptureHandler(logging.Handler):
    """Capture records emitted on a specific logger, independent of pytest's caplog
    (which does not reliably capture across the TestClient worker thread)."""

    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)

    def blob(self) -> str:
        fmt = logging.Formatter()
        return "\n".join(fmt.format(r) for r in self.records)


class _capture:
    """Reliably capture ERROR records from a specific route logger, regardless of the
    global logging state left by earlier tests.

    A prior test may have left the logging system in a state that would suppress the
    record entirely: a global ``logging.disable(...)``, the target logger marked
    ``disabled``, or its level raised above ERROR — any of which makes
    ``logger.isEnabledFor(ERROR)`` False so the record is never created. We clear the
    global disable and force the target logger enabled at ERROR for the duration, then
    restore everything. The handler is attached to the logger itself, so it fires
    independent of ``propagate`` and works across the TestClient worker thread."""

    def __init__(self, name="app.api.routes.health"):
        self._name = name

    def __enter__(self):
        self._handler = _CaptureHandler()
        self._lg = logging.getLogger(self._name)
        self._prev_disable = logging.root.manager.disable
        self._prev_level = self._lg.level
        self._prev_disabled = self._lg.disabled
        logging.disable(logging.NOTSET)
        self._lg.disabled = False
        self._lg.setLevel(logging.ERROR)
        self._lg.addHandler(self._handler)
        return self._handler

    def __exit__(self, *exc):
        self._lg.removeHandler(self._handler)
        self._lg.setLevel(self._prev_level)
        self._lg.disabled = self._prev_disabled
        logging.disable(self._prev_disable)
        return False


def _assert_sanitized(res):
    assert res.status_code == 500
    body = res.text
    assert res.json()["detail"] == "Internal server error"
    # None of the internal shapes may appear anywhere in the response.
    for needle in (
        "postgresql://",
        "s3cr3t",
        "SELECT",
        "/etc/praxis",
        "10.0.0.5",
        "RuntimeError",
    ):
        assert needle not in body, f"leaked {needle!r} in response body"
    # The correlation id is returned for support reference.
    assert res.headers.get("X-Request-ID")


# --------------------------------------------------------------- sanitized 500s


def test_health_internal_error_is_sanitized(db, client, admin_user, monkeypatch):
    monkeypatch.setattr(HealthService, "get_fleet_health", _raise_sensitive)
    with _capture() as handler:
        _login(client, admin_user)
        res = client.get("/fleet/health")
    _assert_sanitized(res)
    # The real exception text (with stack trace) + correlation id ARE logged
    # server-side, so operators can still debug.
    blob = handler.blob()
    assert SENSITIVE in blob
    assert "request_id=" in blob


def test_health_dashboard_is_sanitized(db, client, admin_user, monkeypatch):
    monkeypatch.setattr(HealthService, "get_fleet_dashboard", _raise_sensitive)
    _login(client, admin_user)
    _assert_sanitized(client.get("/fleet/dashboard"))


def test_command_execution_history_is_sanitized(db, client, admin_user, monkeypatch):
    monkeypatch.setattr(
        CommandExecutionService, "get_execution_history", _raise_sensitive
    )
    _login(client, admin_user)
    _assert_sanitized(client.get("/command-execution/history"))


def test_packages_search_is_sanitized(db, client, admin_user, monkeypatch):
    monkeypatch.setattr(PackageService, "search_fleet_packages", _raise_sensitive)
    _login(client, admin_user)
    _assert_sanitized(client.get("/packages/search?name=openssl"))


def test_views_list_is_sanitized(db, client, admin_user, monkeypatch):
    # A CRUD route: force the pre-query scope helper to blow up.
    monkeypatch.setattr("app.api.routes.views.scoped_system_ids", _raise_sensitive)
    _login(client, admin_user)
    _assert_sanitized(client.get("/views"))


# --------------------------------------------------------------- domain preserved


def test_known_domain_400_keeps_explicit_detail(db, client, maintainer_user):
    """A non-admin creating a shared view is an operator-actionable 400 — the
    explicit domain message must survive (not become a generic 500/'Internal
    server error')."""
    _login(client, maintainer_user)
    res = client.post("/views", json={"name": "team", "filters": {}, "is_shared": True})
    assert res.status_code == 400
    assert res.json()["detail"] == "Only admins can create shared views"


def test_static_domain_400_preserved(db, client, maintainer_user):
    _login(client, maintainer_user)
    res = client.post("/fleet/bulk/check", json={"system_ids": []})
    assert res.status_code == 400
    assert res.json()["detail"] == "At least one system ID required"
