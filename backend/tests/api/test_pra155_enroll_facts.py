"""PRA-155 #2a: /agent/enroll -> FactsService.ingest wiring.

Pins that:
  * Optional ``facts`` on the enroll body lands in ``host_facts`` with
    ``source_transport='agent'``.
  * The persisted row's ``system_id`` comes from the redeemed token's
    bound System, NOT from anything caller-supplied. We don't have a
    second System to attempt cross-target spoofing in this slice (the
    enroll path's redemption already validates token-system binding),
    but we do confirm the facts row is anchored to the resolved system
    id specifically — not, say, taken from a different field on the
    body.
  * Enroll without ``facts`` is a no-op for host_facts (keeps the
    bootstrap-script contract loose: facts are best-effort, never
    required for cert issuance).
  * A failing facts ingest does not poison the cert response — the
    bootstrap script must always succeed at minting a cert as long as
    the token redemption succeeded.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import Credential, Group, HostFacts, System
from tests.helpers.fake_agent import FakeAgent


@pytest.fixture
def target_system(db, seed_distro):
    g = Group(name="pra155-enroll", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra155-enroll", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="enroll-facts.example.com",
        ip_address="10.0.0.60",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=g.id,
        credentials_id=cred.id,
    )
    db.add(sys_row)
    db.flush()
    db.commit()
    return sys_row


def _stub_sign(serial: str = "facts-serial"):
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


def _create_token(authed_client, target_system) -> str:
    res = authed_client.post(
        "/agent/activation-tokens",
        json={
            "name": "pra155",
            "default_group_id": target_system.group_id,
            "target_system_id": target_system.id,
            "ttl_seconds": 600,
            "max_uses": 1,
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["plaintext"]


def test_enroll_with_facts_persists_to_host_facts(
    authed_client, client, db, target_system
):
    plaintext = _create_token(authed_client, target_system)
    agent = FakeAgent(system_id=target_system.id, fingerprint="fp-pra155-A")

    facts_payload = {
        "schema_version": 1,
        "collected_at": "2026-05-01T08:00:00",
        "cpu_model": "Intel Xeon",
        "cpu_cores": 4,
        "ram_total_bytes": 8 * 1024**3,
        "kernel_version": "5.15.0-test",
        "distro_id": "ubuntu",
        "distro_release": "22.04",
        "package_manager": "apt",
        "virtualization": "kvm",
        "cloud_provider": "aws",
        "cloud_instance_metadata": {
            "cloud_provider": "aws",
            "instance_id": "i-pra155",
            "region": "us-east-1",
            # Must be scrubbed in the persisted row.
            "iam_role": {"access_key": "AKIA"},
        },
    }
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="pra155-1"),
    ):
        res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(
                hostname=target_system.hostname, facts=facts_payload
            ),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert res.status_code == 200, res.text

    db.expire_all()
    row = db.query(HostFacts).filter_by(system_id=target_system.id).one()
    assert row.source_transport == "agent"
    assert row.cpu_model == "Intel Xeon"
    assert row.cpu_cores == 4
    assert row.kernel_version == "5.15.0-test"
    # Cloud metadata sanitizer must have stripped iam_role.
    assert "iam_role" not in row.cloud_instance_metadata
    assert row.cloud_instance_metadata["instance_id"] == "i-pra155"


def test_enroll_without_facts_does_not_create_host_facts_row(
    authed_client, client, db, target_system
):
    plaintext = _create_token(authed_client, target_system)
    agent = FakeAgent(system_id=target_system.id, fingerprint="fp-pra155-B")

    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="pra155-2"),
    ):
        res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(hostname=target_system.hostname),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert res.status_code == 200, res.text

    db.expire_all()
    assert db.query(HostFacts).filter_by(system_id=target_system.id).count() == 0


def test_enroll_facts_failure_does_not_break_cert_response(
    authed_client, client, db, target_system
):
    """If FactsService.ingest blows up for any reason, enrollment must
    still return a valid cert. Inventory is best-effort."""
    plaintext = _create_token(authed_client, target_system)
    agent = FakeAgent(system_id=target_system.id, fingerprint="fp-pra155-C")

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated ingest crash")

    with (
        patch(
            "app.services.agent_identity_service.AgentIdentityService._sign",
            new=_stub_sign(serial="pra155-3"),
        ),
        patch("app.services.facts_service.ingest", new=_boom),
    ):
        res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(
                hostname=target_system.hostname,
                facts={"cpu_cores": 1},
            ),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert res.status_code == 200, res.text
    assert res.json()["serial_number"] == "pra155-3"
    db.expire_all()
    assert db.query(HostFacts).filter_by(system_id=target_system.id).count() == 0
