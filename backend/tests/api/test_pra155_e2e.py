"""PRA-155 #2e: end-to-end operator-shaped tests.

Three tests that bundle the slice-level units into the wires-connect
path. Anything in the pipe drifts, one of these fails first.

  1. ``test_e2e_agent_path_enroll_to_membership`` — token create →
     ``/agent/enroll`` with a facts payload → ``host_facts`` row exists
     with ``source_transport=agent`` → ``GET /systems/{id}/facts``
     reports ``freshness=fresh`` → smart group with ``facts.distro_id
     IN [ubuntu]`` rule has the host as a member.
     Anchors:  EnrollRequest.facts wiring (#2a),
               FactsService.ingest (#2a),
               read endpoint freshness verdict (#2c),
               ingest-time scoped recompute (#2d).
  2. ``test_e2e_ssh_refresh_path_stub_to_membership`` — pre-register
     host with ``transport_preference=ssh`` → ``POST /systems/{id}/
     facts/refresh`` against a stubbed SSHService that returns canned
     ``KEY=<base64>`` lines → ``host_facts`` row exists with
     ``source_transport=ssh`` → smart group membership reflects the
     new fact.
     Anchors:  refresh endpoint transport selection (#2b-b),
               SSH script parser (#2b-b),
               ingest-time scoped recompute (#2d).
  3. ``test_e2e_stale_then_refresh_returns_fresh`` — seed a 25h-old
     row → ``GET`` reports ``freshness=stale`` → ``POST /refresh``
     (stubbed SSH) → ``GET`` reports ``freshness=fresh``.
     Anchors:  staleness verdict (#2c),
               refresh endpoint (#2b-b),
               FactsService.ingest stale-write semantics (#2a-α).

Each test does ONE thing across the layers. Slice-level units cover
the per-component contracts; this file proves the wires connect.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app.db.models import (
    Credential,
    Group,
    HostFacts,
    SmartGroup,
    SmartGroupMembership,
    System,
)
from tests.helpers.fake_agent import FakeAgent

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def host_with_group(db, seed_distro):
    g = Group(name="pra155-e2e", description="x")
    db.add(g)
    db.flush()
    cred = Credential(name="cred-pra155-e2e", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    sys_row = System(
        hostname="e2e-facts.example.com",
        ip_address="10.0.2.10",
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


def _make_smart_group(db, *, name, rule):
    sg = SmartGroup(name=name, rule_json=json.dumps(rule), enabled=True)
    db.add(sg)
    db.flush()
    db.commit()
    return sg


def _stub_sign(serial: str = "e2e-pra155-1"):
    """Stand-in for AgentIdentityService._sign — returns realistic cert
    material without hitting Vault. Same shape PRA-154's e2e uses."""

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


def _ssh_collector_output(**fields) -> str:
    """Build the KEY=<base64> output the SSH collector script produces.

    Mirrors the wire format in ``app/services/_assets/collect-facts.sh``
    so this test exercises the real ``SshFactsCollectorService``
    parser end-to-end — only the SSHService transport is stubbed."""
    lines = []
    for key, value in fields.items():
        encoded = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
        lines.append(f"{key}={encoded}")
    return "\n".join(lines)


def _stub_ssh_execute(stdout: str):
    """Patch SSHService.execute_command to return canned stdout. The
    refresh endpoint walks through the real SshFactsCollectorService,
    base64-decoder, parser, sanitizer, FactsService.ingest, and
    smart-group recompute — everything except the network leg is real."""

    def _impl(self, system_id, command, timeout=None, user_id=None):  # noqa: ARG001
        return {
            "system_id": system_id,
            "hostname": "stub",
            "command": command,
            "status": "success",
            "stdout": stdout,
            "stderr": "",
            "exit_code": 0,
            "execution_time_ms": 5,
            "executed_at": datetime.utcnow().isoformat(),
        }

    return _impl


# ---------------------------------------------------------------- 1. agent path


def test_e2e_agent_path_enroll_to_membership(
    authed_client, client, db, host_with_group
):
    """token create -> /agent/enroll with facts -> host_facts(agent) ->
    GET fresh -> smart group membership reflects the fact."""
    # Smart group keyed off facts.distro_id — picks up the host iff
    # FactsService.ingest's recompute hook fires after enrollment.
    sg = _make_smart_group(
        db,
        name="ubuntu-fleet",
        rule={"field": "facts.distro_id", "op": "in", "value": ["ubuntu"]},
    )
    pre_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=sg.id)
    }
    assert host_with_group.id not in pre_members

    # 1. Operator creates the activation token bound to the host.
    create_res = authed_client.post(
        "/agent/activation-tokens",
        json={
            "name": "e2e-pra155",
            "default_group_id": host_with_group.group_id,
            "target_system_id": host_with_group.id,
            "ttl_seconds": 600,
            "max_uses": 1,
        },
    )
    assert create_res.status_code == 201, create_res.text
    plaintext = create_res.json()["plaintext"]

    # 2. Host POSTs CSR + facts to /agent/enroll.
    agent = FakeAgent(system_id=host_with_group.id, fingerprint="fp-e2e-pra155")
    # Dynamic timestamp — a fixed literal would flip the freshness
    # verdict to ``stale`` once the cold-rebuild gate runs more than
    # 24h after that instant. ``utcnow()`` keeps the test calendar-
    # independent.
    facts_payload = {
        "schema_version": 1,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "cpu_model": "AMD EPYC 7B12",
        "cpu_cores": 8,
        "ram_total_bytes": 16 * 1024**3,
        "kernel_version": "5.15.0-101-generic",
        "distro_id": "ubuntu",
        "distro_release": "22.04",
        "package_manager": "apt",
        "virtualization": "kvm",
        "cloud_provider": "aws",
        "cloud_instance_metadata": {
            "cloud_provider": "aws",
            "instance_id": "i-pra155-e2e",
            "region": "us-east-1",
        },
    }
    with patch(
        "app.services.agent_identity_service.AgentIdentityService._sign",
        new=_stub_sign(serial="e2e-pra155-1"),
    ):
        enroll_res = client.post(
            "/agent/enroll",
            json=agent.enroll_body(
                hostname=host_with_group.hostname, facts=facts_payload
            ),
            headers={"X-Praxis-Activation-Token": plaintext},
        )
    assert enroll_res.status_code == 200, enroll_res.text

    # 3. host_facts row persisted with source_transport=agent.
    db.expire_all()
    row = db.query(HostFacts).filter_by(system_id=host_with_group.id).one()
    assert row.source_transport == "agent"
    assert row.cpu_model == "AMD EPYC 7B12"
    assert row.distro_id_facts == "ubuntu"
    assert row.cloud_provider == "aws"

    # 4. GET /systems/{id}/facts reports freshness=fresh.
    read_res = authed_client.get(f"/systems/{host_with_group.id}/facts")
    assert read_res.status_code == 200
    body = read_res.json()
    assert body["freshness"] == "fresh"
    assert body["source_transport"] == "agent"
    assert body["facts"]["distro_id"] == "ubuntu"

    # 5. Smart-group recompute fired on ingest — host is now a member.
    db.expire_all()
    post_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=sg.id)
    }
    assert host_with_group.id in post_members


# ---------------------------------------------------------------- 2. ssh path


def test_e2e_ssh_refresh_path_stub_to_membership(authed_client, db, host_with_group):
    """transport_preference=ssh -> /facts/refresh with stubbed SSH ->
    host_facts(ssh) -> smart-group membership reflects the new fact."""
    host_with_group.transport_preference = "ssh"
    db.add(host_with_group)
    db.commit()

    sg = _make_smart_group(
        db,
        name="needs-reboot",
        rule={"field": "facts.reboot_required", "op": "eq", "value": True},
    )
    assert (
        db.query(SmartGroupMembership)
        .filter_by(smart_group_id=sg.id, system_id=host_with_group.id)
        .count()
        == 0
    )

    # Canned SSH stdout. The script-parser path inside
    # SshFactsCollectorService walks this real wire format end-to-end.
    # Dynamic timestamp for consistency with the lifecycle test;
    # this case doesn't assert freshness today, but a future
    # assertion-level expansion shouldn't have to revisit a literal.
    stdout = _ssh_collector_output(
        schema_version="1",
        collected_at=datetime.utcnow().isoformat() + "Z",
        cpu_model="x86_64",
        cpu_cores="2",
        ram_total_bytes="8589934592",  # 8 GiB
        kernel_version="6.1.0-test",
        distro_id="debian",
        distro_release="12",
        reboot_required="true",
        package_manager="apt",
    )

    with patch(
        "app.services.ssh_service.SSHService.execute_command",
        new=_stub_ssh_execute(stdout),
    ):
        refresh_res = authed_client.post(f"/systems/{host_with_group.id}/facts/refresh")
    assert refresh_res.status_code == 200, refresh_res.text
    body = refresh_res.json()
    assert body["status"] == "upserted"
    assert body["source_transport"] == "ssh"

    # host_facts row exists with source_transport=ssh and the parsed
    # values from the stubbed wire output.
    db.expire_all()
    row = db.query(HostFacts).filter_by(system_id=host_with_group.id).one()
    assert row.source_transport == "ssh"
    assert row.kernel_version == "6.1.0-test"
    assert row.distro_id_facts == "debian"
    assert row.reboot_required is True
    assert row.cpu_cores == 2

    # Smart-group membership: ingest hook recomputed the
    # reboot_required=True group; the host is now a member.
    post_members = {
        m.system_id
        for m in db.query(SmartGroupMembership).filter_by(smart_group_id=sg.id)
    }
    assert host_with_group.id in post_members


# ---------------------------------------------------------------- 3. lifecycle


def test_e2e_stale_then_refresh_returns_fresh(authed_client, db, host_with_group):
    """Seed a 25h-old row -> GET stale -> POST /refresh -> GET fresh.
    Pins the read-endpoint freshness verdict and the refresh round-
    trip in one test."""
    host_with_group.transport_preference = "ssh"
    db.add(host_with_group)
    db.commit()

    # Backdate by 25h so the staleness verdict (24h backend constant)
    # flips to ``stale``.
    backdated = datetime.utcnow() - timedelta(hours=25)
    db.add(
        HostFacts(
            system_id=host_with_group.id,
            schema_version=1,
            collected_at=backdated,
            source_transport="ssh",
            cpu_cores=2,
        )
    )
    db.commit()

    # 1. GET reports stale — read endpoint computes verdict server-side.
    pre = authed_client.get(f"/systems/{host_with_group.id}/facts").json()
    assert pre["freshness"] == "stale"

    # 2. Refresh through the SSH path with a stub.
    stdout = _ssh_collector_output(
        schema_version="1",
        collected_at=datetime.utcnow().isoformat() + "Z",
        cpu_cores="4",
        kernel_version="6.5.0-test",
        distro_id="ubuntu",
        distro_release="24.04",
    )
    with patch(
        "app.services.ssh_service.SSHService.execute_command",
        new=_stub_ssh_execute(stdout),
    ):
        refresh = authed_client.post(f"/systems/{host_with_group.id}/facts/refresh")
    assert refresh.status_code == 200, refresh.text
    assert refresh.json()["status"] == "upserted"

    # 3. GET now reports fresh — same row, new collected_at.
    post = authed_client.get(f"/systems/{host_with_group.id}/facts").json()
    assert post["freshness"] == "fresh"
    # Sanity: collected_at advanced (not the backdated one).
    assert post["collected_at"] != pre["collected_at"]
    # The new fact landed.
    assert post["facts"]["cpu_cores"] == 4
    assert post["facts"]["kernel_version"] == "6.5.0-test"
