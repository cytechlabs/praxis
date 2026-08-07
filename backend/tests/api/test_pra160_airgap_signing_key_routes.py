"""PRA-160 slice #1: airgap signing-key route tests.

Surface under test:
  * ``POST /airgap/signing-key`` — idempotent bootstrap.

Locks asserted:
  * RBAC: admin or maintainer required.
  * ``created`` flips to false on the second call (idempotent).
  * Response never carries private material.
"""

from __future__ import annotations

import pytest

from app.services.airgap import signing_key_service as svc_module

_FPR = "AB00000000000000000000000000000000000001"


@pytest.fixture
def patch_gpg(monkeypatch):
    def fake_generate(home, slug):
        return _FPR

    def fake_export_secret(home, fpr):
        return (
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\nFAKE-PRIV-{fpr}\n-----END-----\n"
        )

    def fake_export_public(home, fpr):
        return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE-PUB-{fpr}\n-----END-----\n"

    monkeypatch.setattr(svc_module.mirror_gpg, "generate_keypair", fake_generate)
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_secret_armored", fake_export_secret
    )
    monkeypatch.setattr(
        svc_module.mirror_gpg, "export_public_armored", fake_export_public
    )


def test_bootstrap_creates_first_call(authed_client, patch_gpg):
    res = authed_client.post("/airgap/signing-key")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["fingerprint"] == _FPR
    assert body["status"] == "active"
    assert body["created"] is True
    # Private material never leaks.
    assert "PRIVATE" not in str(body)
    assert "private" not in body


def test_bootstrap_idempotent(authed_client, patch_gpg):
    first = authed_client.post("/airgap/signing-key")
    second = authed_client.post("/airgap/signing-key")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert first.json()["fingerprint"] == second.json()["fingerprint"]


def test_bootstrap_rejects_unauthenticated(client, patch_gpg):
    res = client.post("/airgap/signing-key")
    assert res.status_code in (401, 403)
