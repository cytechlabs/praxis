"""PRA-154 #1f: end-to-end bootstrap pipe, control-plane side.

Pins the full operator-shaped flow:

    pre-register System -> create activation token -> serve script ->
    (fake host: keypair + CSR) -> POST /agent/enroll -> System active ->
    re-redeem same fingerprint -> revoke -> re-redeem rejected.

The fake agent (tests/helpers/fake_agent.py) generates a real EC
P-256 keypair and a real PKCS#10 CSR via the ``cryptography`` lib.
We stub the Vault-backed CSR signing because the M13 PKI path is
covered by its own PRA-150 tests; this slice's job is the
activation-token plumbing and the wire shape, not Vault.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.access_models import AuditEvent
from app.db.models import (
    ActivationToken,
    ActivationTokenRedemption,
    Credential,
    Group,
    System,
)
from tests.helpers.fake_agent import FakeAgent

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def group(db):
    g = Group(name="m14-e2e", description="PRA-154 #1f")
    db.add(g)
    db.flush()
    return g


@pytest.fixture
def target_system(db, group, seed_distro):
    cred = Credential(name="cred-e2e", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="e2e-host.example.com",
        ip_address="10.0.0.5",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.commit()
    return sys_row


def _stub_sign(serial: str = "e2e-serial"):
    """Stand-in for AgentIdentityService._sign — returns a realistic
    response shape without hitting Vault."""

    def _impl(self, system, csr_pem):  # noqa: ARG001
        return {
            "certificate": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            "serial_number": serial,
            "fingerprint": f"sha256:{serial}",
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "ca_chain": ["ca-pem"],
            "issuing_ca": "ca-pem",
        }

    return _impl


# ---------------------------------------------------------------- happy path


def test_e2e_token_lifecycle(authed_client, client, db, target_system, monkeypatch):
    """Single big test that exercises the operator-shaped story
    end-to-end. Anything in the pipe drifts, this fails first."""
    monkeypatch.setenv("PRAXIS_PUBLIC_URL", "https://praxis.test.local")

    # 1. Admin creates the activation token bound to the pre-registered
    #    system. PRAXIS_PUBLIC_URL is set so the response surfaces a
    #    full bootstrap_command for the operator to copy.
    create_res = authed_client.post(
        "/agent/activation-tokens",
        json={
            "name": "e2e",
            "default_group_id": target_system.group_id,
            "target_system_id": target_system.id,
            "ttl_seconds": 600,
            "max_uses": 1,
        },
    )
    assert create_res.status_code == 201, create_res.text
    created = create_res.json()
    plaintext = created["plaintext"]
    token_id = created["id"]
    assert created["bootstrap_command"] is not None
    assert (
        "https://praxis.test.local/agent/bootstrap.sh" in created["bootstrap_command"]
    )
    assert plaintext in created["bootstrap_command"]

    # 2. Bootstrap script is fetched anonymously and contains the
    #    substituted URL plus a syntactically valid bash body.
    script_res = client.get("/agent/bootstrap.sh")
    assert script_res.status_code == 200
    script_body = script_res.text
    assert "__PRAXIS_DEFAULT_URL__" not in script_body
    assert "https://praxis.test.local" in script_body

    # bash -n is a parse-only sanity check; catches templating breaks
    # that would make the script unrunnable in the field.
    if shutil.which("bash") is not None:
        proc = subprocess.run(
            ["bash", "-n"],
            input=script_body,
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"

    # 3. Fake host generates keypair + CSR and POSTs to /agent/enroll
    #    with the canonical X-Praxis-Activation-Token header. We stub
    #    Vault-backed signing because the M13 PKI path has its own
    #    PRA-150 tests; #1f's contract is the activation-token wire.
    agent = FakeAgent(system_id=target_system.id, fingerprint="fp-e2e-A")

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="e2e-1"),
    ):
        enroll_res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(hostname="e2e-host.example.com"),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert enroll_res.status_code == 200, enroll_res.text
    enroll_body = enroll_res.json()
    assert enroll_body["system_id"] == target_system.id
    assert enroll_body["serial_number"] == "e2e-1"
    assert enroll_body["agent_status"] == "active"
    assert enroll_body["was_first_redeem"] is True

    # 4. State after enroll: System.agent_status flipped, ledger row
    #    created, uses_count incremented exactly once, audit row
    #    landed with the right context.
    db.expire_all()
    persisted_token = db.query(ActivationToken).filter_by(id=token_id).one()
    assert persisted_token.uses_count == 1
    refreshed_system = db.query(System).filter_by(id=target_system.id).one()
    assert refreshed_system.agent_status == "active"
    redemptions = (
        db.query(ActivationTokenRedemption)
        .filter_by(activation_token_id=token_id)
        .all()
    )
    assert len(redemptions) == 1
    assert redemptions[0].redeem_count == 1

    audit_rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "activation_token.redeem",
            AuditEvent.outcome == "success",
            AuditEvent.target_id == str(token_id),
        )
        .all()
    )
    assert len(audit_rows) == 1
    ctx = json.loads(audit_rows[0].context_json)
    assert ctx["activation_token_id"] == token_id
    assert ctx["system_id"] == target_system.id
    assert ctx["was_first_redeem"] is True
    assert plaintext not in audit_rows[0].context_json

    # 5. Re-redeem from the same fingerprint — fresh cert (M13 rotation
    #    expects this), uses_count unchanged (rerun bypass), redeem_count++.
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="e2e-2"),
    ):
        rerun_res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(hostname="e2e-host.example.com"),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert rerun_res.status_code == 200
    assert rerun_res.json()["serial_number"] == "e2e-2"
    assert rerun_res.json()["was_first_redeem"] is False

    db.expire_all()
    assert db.query(ActivationToken).filter_by(id=token_id).one().uses_count == 1
    assert (
        db.query(ActivationTokenRedemption)
        .filter_by(activation_token_id=token_id)
        .one()
        .redeem_count
        == 2
    )

    # 6. Operator revokes the token. Pinned: revocation must block ALL
    #    future enroll calls, including same-fingerprint reruns. The
    #    rerun bypass exists for max_uses semantics; it must not let
    #    a revoked token through.
    revoke_res = authed_client.post(f"/agent/activation-tokens/{token_id}/revoke")
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="should-not-issue"),
    ):
        post_revoke_res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(hostname="e2e-host.example.com"),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert post_revoke_res.status_code == 401
    assert post_revoke_res.json()["detail"] == "invalid activation token"

    # And confirm we did not silently mint another cert despite the 401.
    db.expire_all()
    assert (
        db.query(System).filter_by(id=target_system.id).one().agent_cert_serial
        != "should-not-issue"
    )


# ---------------------------------------------------------------- download proxy
#
# Local-artifact-dir only by design: reaching the real release would
# make this test depend on the network and on a published tag, so it
# exercises the airgap-friendly path instead. The unit tests in
# test_agent_bootstrap_routes.py already cover the closed-set arch /
# filename allow-list and the GitHub fallback path via mocked urlopen —
# this slice doesn't repeat that surface.


def test_download_proxy_serves_canonical_local_artifacts(client, monkeypatch, tmp_path):
    """End-to-end check that GET /agent/download/<arch>/agent.tar.gz
    serves the bytes from a populated PRAXIS_AGENT_ARTIFACT_DIR. This
    is the real host's first call after fetching the script; if this
    breaks the install never starts."""
    base = tmp_path / "agent-artifacts"
    base.mkdir()
    real_name = "praxis-agent-v1.0.1-linux-amd64.tar.gz"
    (base / real_name).write_bytes(b"E2E_TARBALL")
    (base / "checksums.txt").write_text(f"{'a' * 64}  {real_name}\n")
    monkeypatch.setenv("PRAXIS_AGENT_ARTIFACT_DIR", str(base))

    tar = client.get("/agent/download/amd64/agent.tar.gz")
    assert tar.status_code == 200
    assert tar.content == b"E2E_TARBALL"

    chk = client.get("/agent/download/amd64/agent.tar.gz.sha256")
    assert chk.status_code == 200
    digest, fname = chk.text.strip().split(maxsplit=1)
    assert len(digest) == 64
    assert fname == "agent.tar.gz"
