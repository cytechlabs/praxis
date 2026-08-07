"""PRA-310: admin-only, redacted, bounded, deterministic diagnostic support bundle.

Proves the security-critical properties: admin-only + audited; a deterministic file
list; secrets/config redaction; time/size bounds; no arbitrary file-path read; and
representative support events flow into the bundle.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile

import pytest

from app.core.log_buffer import install_log_buffer
from app.db.access_models import AuditEvent
from app.services import diagnostics_service as diag

EXPECTED_FILES = {
    "manifest.json",
    "version.json",
    "schema.json",
    "config_summary.json",
    "health.json",
    "audit_events.json",
    "reconcile_status.json",
    "failed_jobs.json",
    "systems.json",
    "logs/backend.log",
}


def _login(client, user):
    res = client.post(
        "/auth/login", data={"username": user.username, "password": "testpass123"}
    )
    assert res.status_code == 200, res.text
    client.headers.update({"Authorization": f"Bearer {res.json()['access_token']}"})


def _open_zip(body: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(body))


# --------------------------------------------------------------- authorization


def test_bundle_requires_admin(db, client, maintainer_user):
    _login(client, maintainer_user)
    res = client.post("/diagnostics/bundle?time_range=24h")
    assert res.status_code == 403


def test_admin_can_generate_bundle_with_expected_files(db, client, admin_user):
    _login(client, admin_user)
    res = client.post("/diagnostics/bundle?time_range=24h")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/zip"
    assert "attachment" in res.headers["content-disposition"]

    zf = _open_zip(res.content)
    names = set(zf.namelist())
    # Deterministic file list.
    assert names == EXPECTED_FILES

    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["generated_by_user_id"] == admin_user.id
    assert manifest["time_range"] == "24h"
    assert sorted(f["name"] for f in manifest["files"]) == sorted(
        EXPECTED_FILES - {"manifest.json"}
    )
    # Every listed file carries a sha256 + byte count.
    for f in manifest["files"]:
        assert f["sha256"] and f["bytes"] >= 0


# --------------------------------------------------------------- bounds / input


def test_invalid_time_range_is_rejected(db, client, admin_user):
    _login(client, admin_user)
    assert client.post("/diagnostics/bundle?time_range=all").status_code == 400
    # A path-y value cannot select a file — the input is a closed set, not a path.
    assert (
        client.post("/diagnostics/bundle?time_range=../../etc/passwd").status_code
        == 400
    )


def test_bundle_is_within_size_ceiling(db, client, admin_user):
    _login(client, admin_user)
    res = client.post("/diagnostics/bundle?time_range=7d")
    assert res.status_code == 200
    assert len(res.content) <= diag.MAX_BUNDLE_BYTES
    assert int(res.headers["X-Bundle-Bytes"]) == len(res.content)


# --------------------------------------------------------------- redaction


def test_secrets_in_logs_are_redacted(db, client, admin_user):
    install_log_buffer()
    logging.getLogger("pra310.test").error(
        "leak VAULT_TOKEN=hvs.CAESIBlSuperSecretToken password=hunter2 "
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
    )
    _login(client, admin_user)
    res = client.post("/diagnostics/bundle?time_range=24h")
    logs = _open_zip(res.content).read("logs/backend.log").decode()
    assert "hvs.CAESIBlSuperSecretToken" not in logs
    assert "hunter2" not in logs
    assert "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig" not in logs


def test_config_summary_has_no_secrets(db, client, admin_user, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "super-secret-key-value")
    monkeypatch.setenv("ADMIN_PASSWORD", "bootstrap-pw")
    monkeypatch.setenv("VAULT_TOKEN", "hvs.tokenvalue")
    monkeypatch.setenv("ENVIRONMENT", "development")  # allowlisted, safe
    _login(client, admin_user)
    res = client.post("/diagnostics/bundle?time_range=24h")
    cfg_bytes = _open_zip(res.content).read("config_summary.json")
    cfg = json.loads(cfg_bytes)
    keys = set(cfg["config"].keys())
    assert "SECRET_KEY" not in keys
    assert "ADMIN_PASSWORD" not in keys
    assert "VAULT_TOKEN" not in keys
    # No secret VALUES anywhere in the file either.
    for needle in ("super-secret-key-value", "bootstrap-pw", "hvs.tokenvalue"):
        assert needle not in cfg_bytes.decode()
    # Allowlisted key is present.
    assert cfg["config"].get("ENVIRONMENT") == "development"


# --------------------------------------------------------------- audit + events


def test_generation_is_audited(db, client, admin_user):
    _login(client, admin_user)
    assert client.post("/diagnostics/bundle?time_range=24h").status_code == 200
    ev = (
        db.query(AuditEvent)
        .filter(AuditEvent.action == "support.bundle.generated")
        .order_by(AuditEvent.id.desc())
        .first()
    )
    assert ev is not None
    assert ev.actor_user_id == admin_user.id
    ctx = json.loads(ev.context_json)
    assert ctx["time_range"] == "24h" and ctx["bytes"] > 0


def test_audit_summary_excludes_context_and_carries_representative_events(
    db, client, admin_user
):
    from app.services.audit_event_service import emit

    # A representative support event with sensitive context (command text).
    emit(
        db,
        action="command.exec",
        outcome="failure",
        actor_user_id=admin_user.id,
        context={"command": "cat /etc/shadow", "secret": "should-not-appear"},
    )
    _login(client, admin_user)
    res = client.post("/diagnostics/bundle?time_range=24h")
    audit_bytes = _open_zip(res.content).read("audit_events.json")
    audit = json.loads(audit_bytes)
    actions = {e["action"] for e in audit["events"]}
    assert "command.exec" in actions  # representative event present
    # The raw context (command text / secret) must NOT be in the summary.
    assert "cat /etc/shadow" not in audit_bytes.decode()
    assert "should-not-appear" not in audit_bytes.decode()
    # Only safe correlation fields are present per event.
    sample = audit["events"][0]
    assert set(sample.keys()) <= {
        "timestamp",
        "action",
        "outcome",
        "actor_user_id",
        "target_system_id",
        "target_kind",
    }
