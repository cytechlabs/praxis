"""PRA-155 #2b-b: SSH-side facts collection.

Runs the bundled ``_assets/collect-facts.sh`` script on a managed host
through ``SSHService.execute_command()``, parses its base64-encoded
output, and hands a normalized payload to ``FactsService.ingest`` with
``source_transport='ssh'``.

The script is read-only and intentionally minimal — every collector
choice it makes mirrors the Go agent's ``runFacts`` so SSH-collected
and agent-collected rows are interchangeable for downstream consumers
(smart groups in #2d, fleet search in #2d, host detail UI in #2c).

The SSH path is the **transport-neutral fallback** for hosts without a
running M13 agent. PRA-155 explicitly requires that the backend +
schema + UI not branch on agent vs SSH; only the collector source +
freshness display change.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from . import facts_service
from .ssh_service import SSHConnectionError, SSHService

logger = logging.getLogger(__name__)


# Hard timeout on the SSH-side script run. The script itself is fast
# (a handful of /proc reads + lsblk + at most two short HTTP probes
# with their own --max-time 1 budget) so anything beyond this is a
# stuck SSH session, not slow collection. Mirrors the broker's
# FACTS_HARD_CAP_SECONDS shape.
DEFAULT_SSH_TIMEOUT_SECONDS = 30

# Path to the script relative to this module. The same shipping
# pattern PRA-154 uses for ``bootstrap.sh``.
_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "_assets", "collect-facts.sh")


class SshFactsCollectionError(Exception):
    """Raised when the SSH transport itself failed to deliver any
    output (connection refused, auth failure, command timed out
    before a single byte). Caller maps to the refresh endpoint's
    transport-error status code.

    Distinct from "script ran but every probe failed" — that case
    still produces a payload (with partial_errors) and is not an
    error from this service's perspective.
    """


def collect_and_ingest(db: Session, *, system_id: int) -> facts_service.IngestResult:
    """Top-level entry point used by the refresh endpoint and the
    scheduler. Runs the collector over SSH, parses the output, calls
    ``FactsService.ingest`` with the result.

    Errors from the SSH transport (no connection, auth failure,
    timeout) raise ``SshFactsCollectionError``. Errors inside the
    script (a probe didn't run, the host is missing /proc/meminfo)
    fall through into ``partial_errors`` and the rest of the row
    still ships.
    """
    raw = _run_script(db, system_id)
    payload = parse_payload(raw)
    return facts_service.ingest(
        db,
        system_id=system_id,
        payload=payload,
        source_transport="ssh",
    )


def _run_script(db: Session, system_id: int) -> str:
    """Read the bundled script, pipe it to the host, return stdout.

    We invoke ``sh -s`` and feed the script via stdin rather than
    copying a file out to /tmp — avoids touching the host's
    filesystem at all (read-only collector contract) and sidesteps
    every ``how does Praxis put a file there`` question that the
    file_put op would otherwise have to answer.
    """
    try:
        with open(_SCRIPT_PATH, "r", encoding="utf-8") as f:
            script = f.read()
    except OSError as exc:  # pragma: no cover — packaging bug
        raise SshFactsCollectionError(f"collector script unreadable: {exc}") from exc

    # SSHService.execute_command runs a single command line; we shell
    # in via ``sh -c '<heredoc>'`` so the script body crosses the wire
    # as a single string. The wrapping ``sh -c '...'`` is doubly
    # quoted at the wire level by paramiko, but `command` here is a
    # single argument so paramiko quoting is a non-issue.
    #
    # The script is small enough that base64-encoding + decoding host-
    # side keeps SSH command-line newlines from confusing exec.
    # Decoding via ``$(printf '%s' '<b64>' | base64 -d)`` works on every
    # POSIX coreutils + busybox.
    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = f"printf %s '{script_b64}' | base64 -d 2>/dev/null | sh -s 2>/dev/null"

    try:
        result = SSHService(db).execute_command(
            system_id=system_id,
            command=command,
            timeout=DEFAULT_SSH_TIMEOUT_SECONDS,
        )
    except SSHConnectionError as exc:
        raise SshFactsCollectionError(f"ssh transport failed: {exc}") from exc

    status = result.get("status")
    if status == "failed":
        # SSHService catches connection-level errors and surfaces them
        # via status="failed"; treat those the same as the raised case.
        raise SshFactsCollectionError(
            f"ssh transport failed: {result.get('stderr') or result.get('status')}"
        )
    return result.get("stdout") or ""


# ----------------------------------------------------------------- parsing


_TRUE_VALUES = frozenset({"true", "True", "TRUE", "1"})
_FALSE_VALUES = frozenset({"false", "False", "FALSE", "0"})


def parse_payload(raw: str) -> Dict[str, Any]:
    """Parse ``KEY=<base64>`` lines into a FactsService.ingest payload.

    Lines that are missing, malformed, or carry undecodable base64 are
    skipped silently — FactsService will land NULL for those columns.
    Parser-noticed shape errors (e.g. ``cpu_cores`` not numeric)
    accumulate in ``partial_errors`` so operators can spot a
    chronically broken collector.
    """
    decoded, parse_partials = _decode_lines(raw)
    payload: Dict[str, Any] = {}
    partial_errors: List[Dict[str, Any]] = list(parse_partials)

    if "schema_version" in decoded:
        try:
            payload["schema_version"] = int(decoded["schema_version"])
        except ValueError:
            partial_errors.append({"key": "schema_version", "error": "not_an_integer"})

    if "collected_at" in decoded:
        payload["collected_at"] = decoded["collected_at"]

    # ---- scalars ----
    if "cpu_model" in decoded:
        payload["cpu_model"] = decoded["cpu_model"]
    if "cpu_cores" in decoded:
        cores = _parse_int(decoded["cpu_cores"])
        if cores is None:
            partial_errors.append({"key": "cpu_cores", "error": "not_an_integer"})
        else:
            payload["cpu_cores"] = cores
    if "ram_total_bytes" in decoded:
        ram = _parse_int(decoded["ram_total_bytes"])
        if ram is None:
            partial_errors.append({"key": "ram_total_bytes", "error": "not_an_integer"})
        else:
            payload["ram_total_bytes"] = ram
    if "kernel_version" in decoded:
        payload["kernel_version"] = decoded["kernel_version"]
    if "distro_id" in decoded:
        payload["distro_id"] = decoded["distro_id"]
    if "distro_release" in decoded:
        payload["distro_release"] = decoded["distro_release"]
    if "uptime_seconds" in decoded:
        up = _parse_int(decoded["uptime_seconds"])
        if up is None:
            partial_errors.append({"key": "uptime_seconds", "error": "not_an_integer"})
        else:
            payload["uptime_seconds"] = up
    if "reboot_required" in decoded:
        rr = decoded["reboot_required"]
        if rr in _TRUE_VALUES:
            payload["reboot_required"] = True
        elif rr in _FALSE_VALUES:
            payload["reboot_required"] = False
        else:
            partial_errors.append({"key": "reboot_required", "error": "not_a_boolean"})
    if "package_manager" in decoded:
        payload["package_manager"] = decoded["package_manager"]
    if "package_manager_version" in decoded:
        payload["package_manager_version"] = decoded["package_manager_version"]
    if "virtualization" in decoded:
        payload["virtualization"] = decoded["virtualization"]

    # ---- PRA-359: SSH-config + kernel-sysctl scalars (string passthrough) ----
    for key in (
        "ssh_permit_root_login",
        "ssh_password_authentication",
        "sysctl_kernel_randomize_va_space",
        "sysctl_net_ipv4_ip_forward",
        "sysctl_net_ipv4_conf_all_rp_filter",
    ):
        if key in decoded:
            payload[key] = decoded[key]

    # ---- disks ----
    if "disks_json" in decoded:
        disks = _parse_disks(decoded["disks_json"])
        if disks is None:
            partial_errors.append({"key": "disks", "error": "lsblk_unparseable"})
        elif disks:
            payload["disks"] = disks

    # ---- cloud ----
    cloud_md: Dict[str, Any] = {}
    if "cloud_provider" in decoded:
        cloud_md["cloud_provider"] = decoded["cloud_provider"]
        payload["cloud_provider"] = decoded["cloud_provider"]
    if "cloud_instance_id" in decoded:
        cloud_md["instance_id"] = decoded["cloud_instance_id"]
    if "cloud_region" in decoded:
        cloud_md["region"] = decoded["cloud_region"]
    if "cloud_zone" in decoded:
        cloud_md["zone"] = decoded["cloud_zone"]
    if cloud_md:
        payload["cloud_instance_metadata"] = cloud_md

    if partial_errors:
        payload["partial_errors"] = partial_errors

    # If the script never ran at all (zero recognized lines), surface
    # that as a partial_error so the audit row is informative —
    # FactsService.ingest will treat it as payload_attempted_facts due
    # to the partial entry and the no-content path won't accidentally
    # noop-empty an SSH refresh that returned nothing.
    if not decoded and not partial_errors:
        payload["partial_errors"] = [{"key": "ssh_collector", "error": "no_output"}]

    return payload


def _decode_lines(raw: str) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    """Split ``KEY=<base64>`` lines, decode base64. Returns
    ``(decoded_map, partial_errors_for_decode_failures)``."""
    decoded: Dict[str, str] = {}
    partials: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, encoded = line.partition("=")
        key = key.strip()
        if not key:
            continue
        try:
            value = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            partials.append({"key": key, "error": "undecodable_value"})
            continue
        decoded[key] = value
    return decoded, partials


def _parse_int(s: str) -> Optional[int]:
    s = s.strip()
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _parse_disks(raw: str) -> Optional[List[Dict[str, Any]]]:
    """Walk lsblk -J output → flat list of mount-point entries with
    the locked v1 shape. ``None`` means the JSON itself was bad."""
    try:
        tree = json.loads(raw)
    except json.JSONDecodeError:
        return None
    devices = tree.get("blockdevices")
    if not isinstance(devices, list):
        return []
    out: List[Dict[str, Any]] = []
    _walk_lsblk(devices, out)
    return out


def _walk_lsblk(nodes: List[Any], out: List[Dict[str, Any]]) -> None:
    for n in nodes:
        if not isinstance(n, dict):
            continue
        mountpoint = n.get("mountpoint")
        fstype = n.get("fstype")
        if mountpoint and fstype:
            out.append(
                {
                    "mountpoint": mountpoint,
                    "filesystem": fstype,
                    "total_bytes": _lsblk_int(n.get("size")),
                    "free_bytes": _lsblk_int(n.get("fsavail")),
                }
            )
        children = n.get("children")
        if isinstance(children, list):
            _walk_lsblk(children, out)


def _lsblk_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return 0
    if isinstance(v, float):
        return int(v)
    return 0
