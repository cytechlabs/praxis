"""PRA-339: broker logs in the admin diagnostic support bundle.

Covers the three availability states recorded in the manifest's ``broker_logs``
block — included / unavailable / unsupported — plus redaction of broker log
content, and confirms the ``logs/broker.log`` file is present ONLY when included.
"""

from __future__ import annotations

import io
import zipfile

import httpx

from app.core.log_buffer import install_log_buffer
from app.services import diagnostics_service as diag


def _patch_broker_logs(monkeypatch, *, body=None, exc=None):
    async def _logs(self, *, since_epoch=None, limit=None):  # noqa: ANN001
        if exc is not None:
            raise exc
        return body

    monkeypatch.setattr("app.services.broker_client.BrokerClient.logs", _logs)


def _gen(db):
    data, manifest = diag.generate_bundle(db, actor_user_id=1, time_range="24h")
    return zipfile.ZipFile(io.BytesIO(data)), manifest


def test_broker_logs_included_and_redacted(db, monkeypatch):
    install_log_buffer()
    _patch_broker_logs(
        monkeypatch,
        body={
            "installed": True,
            "records": [
                {
                    "ts": 1.0,
                    "level": "INFO",
                    "logger": "app.broker.handlers",
                    "message": "tunnel accepted token=supersecret123",
                }
            ],
        },
    )

    zf, manifest = _gen(db)

    assert "logs/broker.log" in zf.namelist()
    assert manifest["broker_logs"]["status"] == "included"
    assert manifest["broker_logs"]["record_count"] == 1

    content = zf.read("logs/broker.log").decode()
    assert "tunnel accepted" in content
    # Same redaction path as backend logs — the secret value is gone.
    assert "supersecret123" not in content
    assert "«redacted»" in content


def test_broker_logs_unavailable_on_network_error(db, monkeypatch):
    _patch_broker_logs(monkeypatch, exc=httpx.ConnectError("no route to host"))

    zf, manifest = _gen(db)

    assert "logs/broker.log" not in zf.namelist()
    assert manifest["broker_logs"]["status"] == "unavailable"
    assert manifest["broker_logs"]["reason"]


def test_broker_logs_unavailable_when_buffer_not_installed(db, monkeypatch):
    _patch_broker_logs(monkeypatch, body={"installed": False, "records": []})

    zf, manifest = _gen(db)

    assert "logs/broker.log" not in zf.namelist()
    assert manifest["broker_logs"]["status"] == "unavailable"


def test_broker_logs_unsupported_on_404(db, monkeypatch):
    req = httpx.Request("GET", "http://broker/internal/logs")
    resp = httpx.Response(404, request=req)
    _patch_broker_logs(
        monkeypatch,
        exc=httpx.HTTPStatusError("not found", request=req, response=resp),
    )

    zf, manifest = _gen(db)

    assert "logs/broker.log" not in zf.namelist()
    assert manifest["broker_logs"]["status"] == "unsupported"


def test_broker_logs_unsupported_without_internal_token(db, monkeypatch):
    # No shared secret derivable -> broker internal API not configured for this
    # deployment; broker logs are unsupported (not merely unavailable).
    monkeypatch.setattr("app.broker.internal_auth.derive_internal_token", lambda: None)

    zf, manifest = _gen(db)

    assert "logs/broker.log" not in zf.namelist()
    assert manifest["broker_logs"]["status"] == "unsupported"


def test_backend_log_still_present_regardless_of_broker(db, monkeypatch):
    # Broker unavailable must never affect the backend log section.
    _patch_broker_logs(monkeypatch, exc=httpx.ConnectError("down"))
    zf, _ = _gen(db)
    assert "logs/backend.log" in zf.namelist()
