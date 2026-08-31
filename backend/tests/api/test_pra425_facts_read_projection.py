"""PRA-425: the facts read endpoint projects the security-relevant scalars.

``GET /systems/{id}/facts`` is documented as the inverse of the ingest
payload, and it is the only way an operator sees a collected row. The SSH
server baseline and the kernel sysctls back compliance verdicts, so leaving
them out of the projection hides the evidence behind a verdict even though the
row on disk holds it.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.db.models import Credential, Group, System
from app.services import facts_service


@pytest.fixture
def host(db, seed_distro):
    group = Group(name="pra425-read", description="x")
    db.add(group)
    db.flush()
    cred = Credential(name="cred-pra425-read", auth_method="ssh_key", username="root")
    db.add(cred)
    db.flush()
    row = System(
        hostname="pra425-read.example.com",
        ip_address="10.0.4.25",
        distro_id=seed_distro.id,
        os_version="22.04",
        status="Active",
        group_id=group.id,
        credentials_id=cred.id,
    )
    db.add(row)
    db.flush()
    db.commit()
    return row


def test_read_endpoint_returns_the_ssh_baseline_and_sysctls(authed_client, db, host):
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "schema_version": 1,
            "collected_at": datetime.utcnow().isoformat(),
            "ssh_permit_root_login": "no",
            "ssh_password_authentication": "yes",
            "sysctl_kernel_randomize_va_space": "2",
            "sysctl_net_ipv4_ip_forward": "0",
            "sysctl_net_ipv4_conf_all_rp_filter": "1",
        },
        source_transport="ssh",
    )

    body = authed_client.get(f"/systems/{host.id}/facts").json()

    assert body["facts"]["ssh_permit_root_login"] == "no"
    assert body["facts"]["ssh_password_authentication"] == "yes"
    assert body["facts"]["sysctl_kernel_randomize_va_space"] == "2"
    assert body["facts"]["sysctl_net_ipv4_ip_forward"] == "0"
    assert body["facts"]["sysctl_net_ipv4_conf_all_rp_filter"] == "1"


def test_read_endpoint_reports_the_gap_alongside_the_null(authed_client, db, host):
    """A collection that could not establish the baseline shows a NULL value
    and the entry that says why, so the two are never confused."""
    facts_service.ingest(
        db,
        system_id=host.id,
        payload={
            "schema_version": 1,
            "collected_at": datetime.utcnow().isoformat(),
            "kernel_version": "6.8.0-generic",
        },
        source_transport="ssh",
    )

    body = authed_client.get(f"/systems/{host.id}/facts").json()

    assert body["facts"]["ssh_permit_root_login"] is None
    assert body["is_partial"] is True
    assert {
        "key": "ssh_permit_root_login",
        "error": facts_service.UNREPORTED_WITHOUT_EVIDENCE_REASON,
    } in body["partial_errors"]
