"""PRA-155 #2b-b: SSH facts collector parser tests.

The shell side of the SSH path lives in
``app/services/_assets/collect-facts.sh``; here we exercise the
Python parsing/normalization layer with synthetic raw-output strings.
End-to-end coverage that actually runs SSH lives in the cold-rebuild
gate — these unit tests pin parser shape so a refactor doesn't
silently drop a column.
"""

from __future__ import annotations

import base64
import json

from app.services import ssh_facts_collector_service as svc


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _line(key: str, value: str) -> str:
    return f"{key}={_b64(value)}"


def test_parse_payload_full_happy_path():
    disks_json = json.dumps(
        {
            "blockdevices": [
                {
                    "mountpoint": "/",
                    "fstype": "ext4",
                    "size": 100_000_000_000,
                    "fsavail": 60_000_000_000,
                },
                {
                    "mountpoint": None,
                    "fstype": None,
                    "children": [
                        {
                            "mountpoint": "/data",
                            "fstype": "xfs",
                            "size": 500_000_000_000,
                            "fsavail": 250_000_000_000,
                        }
                    ],
                },
            ]
        }
    )
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            _line("collected_at", "2026-05-01T12:00:00Z"),
            _line("cpu_model", "AMD EPYC 7B12"),
            _line("cpu_cores", "8"),
            _line("ram_total_bytes", "16777216000"),
            _line("kernel_version", "5.15.0-101-generic"),
            _line("distro_id", "ubuntu"),
            _line("distro_release", "22.04"),
            _line("uptime_seconds", "12345"),
            _line("reboot_required", "false"),
            _line("package_manager", "apt"),
            _line("package_manager_version", "apt 2.4.10 (amd64)"),
            _line("virtualization", "kvm"),
            _line("disks_json", disks_json),
            _line("cloud_provider", "aws"),
            _line("cloud_instance_id", "i-0123"),
            _line("cloud_region", "us-east-1"),
            _line("cloud_zone", "us-east-1a"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert payload["schema_version"] == 1
    assert payload["cpu_model"] == "AMD EPYC 7B12"
    assert payload["cpu_cores"] == 8
    assert payload["ram_total_bytes"] == 16_777_216_000
    assert payload["distro_id"] == "ubuntu"
    assert payload["reboot_required"] is False
    assert payload["package_manager"] == "apt"
    assert payload["virtualization"] == "kvm"
    assert payload["cloud_provider"] == "aws"
    assert payload["cloud_instance_metadata"] == {
        "cloud_provider": "aws",
        "instance_id": "i-0123",
        "region": "us-east-1",
        "zone": "us-east-1a",
    }
    # Both disks (top-level + nested via children) surface in the
    # locked v1 shape.
    mounts = {d["mountpoint"] for d in payload["disks"]}
    assert mounts == {"/", "/data"}
    for entry in payload["disks"]:
        assert set(entry.keys()) == {
            "mountpoint",
            "filesystem",
            "total_bytes",
            "free_bytes",
        }
    # No partial errors when every line parses.
    assert "partial_errors" not in payload


def test_parse_payload_missing_lines_become_null_columns_no_partial():
    """A probe that didn't run on the host produces no line; the
    parser MUST NOT invent a column or record a partial — silence is
    valid (the host genuinely doesn't have systemd-detect-virt, no
    cloud, etc.). Backend's FactsService leaves missing columns NULL."""
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            _line("collected_at", "2026-05-01T12:00:00Z"),
            _line("cpu_model", "x86_64"),
            _line("cpu_cores", "2"),
            _line("kernel_version", "5.15.0"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert payload["cpu_model"] == "x86_64"
    assert "ram_total_bytes" not in payload
    assert "disks" not in payload
    assert "cloud_provider" not in payload
    assert "partial_errors" not in payload


def test_parse_payload_malformed_int_lands_in_partial():
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            _line("cpu_cores", "many"),
            _line("ram_total_bytes", "lots"),
            _line("uptime_seconds", "soon"),
            _line("reboot_required", "maybe"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert "cpu_cores" not in payload
    assert "ram_total_bytes" not in payload
    assert "uptime_seconds" not in payload
    assert "reboot_required" not in payload
    err_keys = {e["key"] for e in payload["partial_errors"]}
    assert {
        "cpu_cores",
        "ram_total_bytes",
        "uptime_seconds",
        "reboot_required",
    } <= err_keys


def test_parse_payload_undecodable_base64_lands_in_partial():
    """A truncated/garbled SSH transcript shouldn't crash the parser
    or silently land junk; the offending key gets a partial error
    and the rest of the report flows through."""
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            "cpu_model=*notbase64*",  # invalid b64
            _line("kernel_version", "5.15.0"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert payload["kernel_version"] == "5.15.0"
    assert "cpu_model" not in payload
    keys = {e["key"] for e in payload["partial_errors"]}
    assert "cpu_model" in keys


def test_parse_payload_empty_output_records_partial():
    """Zero output is a meaningful signal — distinct from an empty
    payload poll. We synthesize a partial_error so FactsService's
    payload_attempted_facts gate doesn't accidentally noop_empty
    an SSH refresh that returned nothing."""
    payload = svc.parse_payload("")
    assert payload.get("partial_errors") == [
        {"key": "ssh_collector", "error": "no_output"}
    ]


def test_parse_payload_lsblk_unparseable_lands_in_partial():
    raw = "\n".join(
        [
            _line("schema_version", "1"),
            _line("disks_json", "this is not json"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert "disks" not in payload
    keys = [e["key"] for e in payload["partial_errors"]]
    assert "disks" in keys


def test_parse_payload_cloud_metadata_lock():
    """Sanity: even if the script accidentally emits an extra cloud
    line in some future revision, the parser only assembles allowlisted
    keys. Defense-in-depth — the FactsService cloud sanitizer would
    catch leaks too, but stopping them here keeps the audit row clean
    of rejected_cloud_keys noise from a Praxis-shipped collector."""
    raw = "\n".join(
        [
            _line("cloud_provider", "aws"),
            _line("cloud_instance_id", "i-abc"),
            _line("cloud_region", "us-west-2"),
            _line("cloud_zone", "us-west-2a"),
            # If the script ever grows a non-allowlisted line, the
            # parser ignores it because there's no branch wiring it.
            _line("cloud_iam_role", "MaliciousRole"),
        ]
    )
    payload = svc.parse_payload(raw)
    assert "iam_role" not in payload["cloud_instance_metadata"]
    assert "cloud_iam_role" not in payload["cloud_instance_metadata"]
