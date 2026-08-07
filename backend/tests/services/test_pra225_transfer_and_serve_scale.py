"""PRA-180 P2 Remediation (PRA-225): transfer + mirror-serve scale hardening.

TRANSPORT-02: the agent-backed file-transfer bridge buffers the whole body in
backend memory (bounded only by the 5 GiB SSH cap). A separate,
operator-configurable agent ceiling (PRAXIS_AGENT_TRANSFER_MAX_BYTES, default
1 GiB, never above the SSH cap) now bounds the agent path.

MIRROR-01: mirror-serve bearer verification scanned every active credential and
ran pbkdf2 against each (O(N)). Tokens are now ``<token_id>.<secret>`` and
verify() looks the single row up by the indexed public ``token_id`` (O(1)),
with a bounded fallback for legacy tokens.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from passlib.hash import pbkdf2_sha256

from app.db.access_models import FileTransferAudit
from app.db.models import (
    Credential,
    Group,
    HostMirrorServeCredential,
    MirrorRepo,
    System,
)
from app.services import file_transfer_service as fts
from app.services.file_transfer_service import (
    MAX_TRANSFER_BYTES,
    FileTransferError,
    _resolve_agent_transfer_cap,
    _upload_via_agent,
)
from app.services.mirror_serve_credential_service import MirrorServeCredentialService

# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def host(db, seed_distro) -> System:
    g = Group(name="pra225-grp")
    db.add(g)
    db.flush()
    cred = Credential(name="pra225-cred", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    s = System(
        hostname="pra225.example.com",
        ip_address="10.70.80.1",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(s)
    db.commit()
    return s


@pytest.fixture
def mirror(db) -> MirrorRepo:
    m = MirrorRepo(
        slug="pra225-mirror",
        display_name="x",
        package_family="deb",
        upstream_url="http://x/y",
        distribution="jammy",
        components="[]",
        architectures='["amd64"]',
        sync_schedule_cron="0 2 * * *",
        last_sync_status="idle",
        current_disk_bytes=0,
    )
    db.add(m)
    db.commit()
    return m


# ── TRANSPORT-02: configurable agent-bridge cap ─────────────────────────────


def test_agent_cap_default(monkeypatch):
    monkeypatch.delenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES", raising=False)
    cap = _resolve_agent_transfer_cap()
    assert cap == 1 * 1024 * 1024 * 1024
    assert cap <= MAX_TRANSFER_BYTES


def test_agent_cap_env_override(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES", "1048576")  # 1 MiB
    assert _resolve_agent_transfer_cap() == 1048576


def test_agent_cap_clamped_to_ssh_cap(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES", str(10 * 1024 * 1024 * 1024))
    assert _resolve_agent_transfer_cap() == MAX_TRANSFER_BYTES


def test_agent_cap_invalid_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES", "not-a-number")
    assert _resolve_agent_transfer_cap() == 1 * 1024 * 1024 * 1024


def test_agent_cap_nonpositive_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("PRAXIS_AGENT_TRANSFER_MAX_BYTES", "0")
    assert _resolve_agent_transfer_cap() == 1 * 1024 * 1024 * 1024


def _audit(db, system) -> FileTransferAudit:
    row = FileTransferAudit(
        system_id=system.id,
        login="root",
        direction="upload",
        remote_path="/tmp/pra225",
        status="in_progress",
        started_at=datetime.utcnow(),
        transport="agent",
    )
    db.add(row)
    db.flush()
    return row


def test_upload_via_agent_rejects_oversized(db, host, monkeypatch):
    """An agent upload exceeding the (lowered) agent cap is rejected before any
    broker dispatch, and the audit row is marked error."""
    monkeypatch.setattr(fts, "AGENT_TRANSFER_MAX_BYTES", 10)
    audit = _audit(db, host)

    def _oversized():
        yield b"x" * 50

    with pytest.raises(FileTransferError, match="exceeded max size"):
        _upload_via_agent(db, host, "/tmp/pra225", _oversized(), audit)
    db.refresh(audit)
    assert audit.status == "error"


def test_upload_via_agent_allows_under_cap(db, host, monkeypatch):
    """An under-cap agent upload is not rejected by the ceiling. The broker
    dispatch is stubbed so the test stays local."""
    monkeypatch.setattr(fts, "AGENT_TRANSFER_MAX_BYTES", 1000)
    # Stub the sync->async bridge so _send() never touches a real broker.
    # close() the coroutine so it isn't reported as "never awaited".
    monkeypatch.setattr(fts, "_run_async_from_sync", lambda coro: coro.close())
    audit = _audit(db, host)

    def _small():
        yield b"x" * 50

    result = _upload_via_agent(db, host, "/tmp/pra225", _small(), audit)
    assert result["size"] == 50
    db.refresh(audit)
    assert audit.status == "success"


# ── MIRROR-01: token_id O(1) verify ─────────────────────────────────────────


def test_issue_mints_token_id_prefixed_plaintext(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    assert "." in issued.plaintext
    token_id, _, secret = issued.plaintext.partition(".")
    assert token_id and secret
    row = db.get(HostMirrorServeCredential, issued.credential_id)
    assert row.token_id == token_id


def test_verify_accepts_issued_token(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    matched = svc.verify(issued.plaintext)
    assert matched is not None
    assert matched.id == issued.credential_id


def test_verify_rejects_wrong_secret(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    token_id = issued.plaintext.split(".", 1)[0]
    assert svc.verify(f"{token_id}.totally-wrong-secret") is None


def test_verify_rejects_unknown_token_id(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    # Issue a real one so there's an active row; present a different token_id.
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    secret = issued.plaintext.split(".", 1)[1]
    assert svc.verify(f"deadbeefdeadbeef.{secret}") is None


def test_verify_one_credential_does_not_match_another(db, host, mirror):
    """Two active credentials: each token resolves only to its own row via
    token_id (proves the lookup is keyed, not a blind scan-and-accept)."""
    svc = MirrorServeCredentialService(db)
    a = svc.issue(host_id=host.id, mirror_id=mirror.id)
    b = svc.issue(host_id=host.id, mirror_id=mirror.id)
    assert svc.verify(a.plaintext).id == a.credential_id
    assert svc.verify(b.plaintext).id == b.credential_id


def test_verify_rejects_revoked(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    svc.revoke(issued.credential_id)
    assert svc.verify(issued.plaintext) is None


def test_verify_rejects_expired(db, host, mirror):
    svc = MirrorServeCredentialService(db)
    issued = svc.issue(host_id=host.id, mirror_id=mirror.id)
    row = db.get(HostMirrorServeCredential, issued.credential_id)
    row.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    assert svc.verify(issued.plaintext) is None


def test_verify_legacy_token_without_token_id(db, host, mirror):
    """A credential issued before MIRROR-01 (no token_id, whole-plaintext hash,
    no '.' separator) still verifies via the bounded legacy fallback."""
    legacy_plaintext = "legacyTokenWithoutDotSeparator0123456789"
    assert "." not in legacy_plaintext
    row = HostMirrorServeCredential(
        host_id=host.id,
        mirror_id=mirror.id,
        token_hash=pbkdf2_sha256.hash(legacy_plaintext),
        token_id=None,
        issued_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=1),
    )
    db.add(row)
    db.commit()
    matched = MirrorServeCredentialService(db).verify(legacy_plaintext)
    assert matched is not None
    assert matched.id == row.id
