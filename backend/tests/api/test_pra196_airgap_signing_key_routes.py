"""PRA-196: airgap signing-key list/rotate/retire routes + lifecycle audit.

Asserts the new operator endpoints, the one-active invariant across rotation,
that private material / Vault paths never leak, and that signing-key and
import-trust lifecycle changes emit bounded audit events.
"""

from __future__ import annotations

import json

import pytest

from app.db.access_models import AuditEvent
from app.services.airgap import import_trust_service as trust_module
from app.services.airgap import signing_key_service as svc_module
from tests.helpers.armor import pgp_private_block

_FPR_A = "AA00000000000000000000000000000000000001"
_FPR_B = "BB00000000000000000000000000000000000002"
_TRUST_FPR = "CC00000000000000000000000000000000000003"

_ARMORED = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n-----END PGP PUBLIC KEY BLOCK-----\n"
)


@pytest.fixture
def patch_gpg(monkeypatch):
    counter = {"n": 0}

    def fake_generate(home, slug):
        counter["n"] += 1
        return _FPR_A if counter["n"] == 1 else _FPR_B

    def fake_export_secret(home, fpr):
        return pgp_private_block(f"FAKE-PRIV-{fpr}")

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )
    # Import-trust add path: fake the fingerprint derivation + uid extraction.
    monkeypatch.setattr(
        trust_module.mirror_gpg,
        "import_public_and_extract_fingerprint",
        lambda home, armored: _TRUST_FPR,
    )
    monkeypatch.setattr(
        trust_module, "_extract_uid_or_fallback", lambda home, fpr: "Test Trust Key"
    )


def _events(db, action):
    return db.query(AuditEvent).filter(AuditEvent.action == action).all()


# ── list + no-leak ──────────────────────────────────────────────────────────


def test_list_signing_keys_exposes_public_not_private(authed_client, patch_gpg):
    authed_client.post("/airgap/signing-key")  # bootstrap A
    res = authed_client.get("/airgap/signing-keys")
    assert res.status_code == 200, res.text
    keys = res.json()
    assert len(keys) == 1
    assert keys[0]["fingerprint"] == _FPR_A
    assert keys[0]["status"] == "active"
    assert "FAKE-PUB-" in keys[0]["armored_public_key"]
    blob = json.dumps(keys)
    assert "PRIVATE" not in blob  # no private key material
    assert "bundle-signing-key" not in blob  # no Vault path


def test_list_signing_keys_requires_auth(client):
    assert client.get("/airgap/signing-keys").status_code in (401, 403)


# ── bootstrap audit ─────────────────────────────────────────────────────────


def test_bootstrap_emits_created_audit(authed_client, patch_gpg, db):
    authed_client.post("/airgap/signing-key")
    evs = _events(db, "airgap.signing_key.created")
    assert len(evs) == 1
    assert evs[0].target_id == _FPR_A
    ctx = json.loads(evs[0].context_json or "{}")
    assert ctx["fingerprint"] == _FPR_A
    assert "vault" not in (evs[0].context_json or "").lower()


def test_bootstrap_idempotent_emits_created_once(authed_client, patch_gpg, db):
    authed_client.post("/airgap/signing-key")
    authed_client.post("/airgap/signing-key")  # idempotent — no new key
    assert len(_events(db, "airgap.signing_key.created")) == 1


# ── rotate ──────────────────────────────────────────────────────────────────


def test_rotate_demotes_and_audits(authed_client, patch_gpg, db):
    authed_client.post("/airgap/signing-key")  # A active
    res = authed_client.post("/airgap/signing-keys/rotate")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["old"]["fingerprint"] == _FPR_A
    assert body["old"]["status"] == "rotating_out"
    assert body["new"]["fingerprint"] == _FPR_B
    assert body["new"]["status"] == "active"

    evs = _events(db, "airgap.signing_key.rotated")
    assert len(evs) == 1
    ctx = json.loads(evs[0].context_json or "{}")
    assert ctx["old_fingerprint"] == _FPR_A
    assert ctx["new_fingerprint"] == _FPR_B


def test_rotate_without_active_conflicts(authed_client, patch_gpg):
    res = authed_client.post("/airgap/signing-keys/rotate")
    assert res.status_code == 409, res.text


def test_rotate_requires_auth(client):
    assert client.post("/airgap/signing-keys/rotate").status_code in (401, 403)


# ── retire ──────────────────────────────────────────────────────────────────


def test_retire_rotating_out_and_audits(authed_client, patch_gpg, db):
    authed_client.post("/airgap/signing-key")
    rot = authed_client.post("/airgap/signing-keys/rotate")
    old_id = rot.json()["old"]["id"]
    res = authed_client.post(f"/airgap/signing-keys/{old_id}/retire")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "retired"
    assert len(_events(db, "airgap.signing_key.retired")) == 1


def test_retire_already_retired_does_not_duplicate_audit(authed_client, patch_gpg, db):
    authed_client.post("/airgap/signing-key")
    rot = authed_client.post("/airgap/signing-keys/rotate")
    old_id = rot.json()["old"]["id"]
    authed_client.post(f"/airgap/signing-keys/{old_id}/retire")
    res = authed_client.post(f"/airgap/signing-keys/{old_id}/retire")
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "retired"
    assert len(_events(db, "airgap.signing_key.retired")) == 1


def test_retire_active_conflicts(authed_client, patch_gpg):
    authed_client.post("/airgap/signing-key")
    active_id = authed_client.get("/airgap/signing-keys").json()[0]["id"]
    res = authed_client.post(f"/airgap/signing-keys/{active_id}/retire")
    assert res.status_code == 409, res.text


def test_retire_missing_is_404(authed_client, patch_gpg):
    assert authed_client.post("/airgap/signing-keys/999999/retire").status_code == 404


# ── import trust audit ──────────────────────────────────────────────────────


def test_import_trust_add_remove_emits_audit(authed_client, patch_gpg, db):
    res = authed_client.post(
        "/airgap/import-trust", json={"armored_public_key": _ARMORED}
    )
    assert res.status_code == 201, res.text
    key_id = res.json()["id"]
    added = _events(db, "airgap.import_trust.added")
    assert len(added) == 1
    assert json.loads(added[0].context_json or "{}")["fingerprint"] == _TRUST_FPR

    res = authed_client.delete(f"/airgap/import-trust/{key_id}")
    assert res.status_code == 200, res.text
    assert len(_events(db, "airgap.import_trust.removed")) == 1

    # Idempotent re-delete must NOT emit a second removal event.
    authed_client.delete(f"/airgap/import-trust/{key_id}")
    assert len(_events(db, "airgap.import_trust.removed")) == 1
