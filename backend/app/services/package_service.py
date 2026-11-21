"""
Package management service for scanning, listing, and updating packages via SSH.
"""

import logging
import re
import shlex
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from sqlalchemy import false, or_
from sqlalchemy import update as sql_update
from sqlalchemy.orm import Session

from ..core.redaction import redact_text
from ..db.models import Distro, Package, PackageHistory, PackageUpdate, System, User
from . import reboot_evidence_service
from .security_scan_status_service import (
    APT_DISTRO_KEYS,
    STATE_COMPLETE,
    STATE_FAILED,
    STATE_PARTIAL,
)
from .ssh_service import SSHConnectionError, SSHService

# PRA-322: per-host single-flight for expensive SSH/package-manager work. Repeated
# scan clicks, poller/scheduler overlap, or API retries must not run concurrent
# package-manager commands against the same host (which stresses the host's sshd /
# package manager and can pile up hung SSH sessions). The 1.0 supported topology is
# a single backend worker, so a process-local lock per system_id is sufficient; a
# non-blocking acquire returns an ``already_running`` result instead of queuing.
#
# The lock is REENTRANT: mutating ops (apply/remove/rollback) internally re-scan
# via ``scan_packages`` on the SAME thread, so that nested call must be allowed to
# proceed, while a CONCURRENT op from another thread is still rejected.
_host_worklocks_guard = threading.Lock()
_host_worklocks: Dict[int, "threading.RLock"] = {}


def _host_worklock(system_id: int) -> "threading.RLock":
    with _host_worklocks_guard:
        return _host_worklocks.setdefault(system_id, threading.RLock())


def _apply_system_scope(query, column, system_ids: Optional[Set[int]]):
    """PRA-281: constrain a fleet-aggregate query to a caller's fleet scope.

    ``system_ids is None`` means tenant-wide (admin) — no filter. An explicit set
    is an allow-list; an empty set yields zero rows, so a scoped caller never sees
    counts, ids, or rows for systems outside their grants.
    """
    if system_ids is None:
        return query
    if not system_ids:
        return query.filter(false())
    return query.filter(column.in_(system_ids))


logger = logging.getLogger(__name__)

# Upper bound on package names echoed back in a scan summary, so a host with a
# large unusable result set cannot return an unbounded payload.
MAX_REPORTED_PACKAGES = 10

# Package manager commands by distro family
PKG_COMMANDS = {
    "apt": {
        "list_installed": "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' | grep 'install ok installed'",
        # The parsed commands run in the C locale: the refresh and listing
        # parsers read apt's untranslated progress, error and "upgradable from"
        # text, which a host's configured language would otherwise rewrite.
        "refresh_metadata": (
            "LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get update "
            "-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 "
            "-o Acquire::Retries=0"
        ),
        # The exit status is apt's own, so a listing failure is visible. The
        # header line and non-matching lines are ignored by the parser, and the
        # security subset is selected after parsing.
        "check_updates": "LC_ALL=C apt list --upgradable 2>/dev/null",
        "check_security": "LC_ALL=C apt list --upgradable 2>/dev/null",
        "apply_update": "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade {packages}",
        "apply_all": "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
        "apply_security": "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade {packages}",
        "remove": "DEBIAN_FRONTEND=noninteractive apt-get remove -y {packages}",
        "hold": "apt-mark hold {packages}",
        "unhold": "apt-mark unhold {packages}",
        "install_version": "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades {packages}",
    },
    "yum": {
        "list_installed": "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{INSTALLTIME:date}\\n'",
        "check_updates": "yum check-update 2>/dev/null || true",
        "check_security": "yum updateinfo list security 2>/dev/null || true",
        "apply_update": "yum update -y {packages}",
        "apply_all": "yum update -y",
        "apply_security": "yum update --security -y",
        "remove": "yum remove -y {packages}",
        "hold": "yum versionlock add {packages}",
        "unhold": "yum versionlock delete {packages}",
        "install_version": "yum downgrade -y {packages}",
    },
    "dnf": {
        "list_installed": "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{INSTALLTIME:date}\\n'",
        "check_updates": "dnf check-update 2>/dev/null || true",
        "check_security": "dnf updateinfo list security 2>/dev/null || true",
        "apply_update": "dnf update -y {packages}",
        "apply_all": "dnf update -y",
        "apply_security": "dnf update --security -y",
        "remove": "dnf remove -y {packages}",
        "hold": "dnf versionlock add {packages}",
        "unhold": "dnf versionlock delete {packages}",
        "install_version": "dnf downgrade -y {packages}",
    },
}

# Map distro names to package manager
DISTRO_PKG_MANAGER = {
    **{key: "apt" for key in APT_DISTRO_KEYS},
    "centos": "yum",
    "rhel": "yum",
    "red hat": "yum",
    "rocky": "dnf",
    "alma": "dnf",
    "almalinux": "dnf",
    "fedora": "dnf",
    "oracle": "yum",
}

# ``dnf|yum updateinfo list security`` is advisory-oriented and shares no shape
# with ``check-update``. DNF4 and YUM print the advisory id, a combined
# severity and type, and the NEVRA of the fixed package:
#
#     RLSA-2024:7106 Important/Sec.  openssl-1:3.0.7-27.el9.x86_64
#
# DNF5 prints a wider table, splitting type and severity apart and appending the
# date the advisory was issued:
#
#     Name           Type     Severity  Package                        Issued
#     RLSA-2024:7106 security Important openssl-1:3.0.7-27.el9.x86_64  2024-11-05 08:00:00
#
# The package column anchors both layouts: the advisory id opens the row, the
# NEVRA is the first token that parses as one, and the columns between the two
# carry the type and severity. Anything after the package, such as the issued
# date, is not part of the update. Both tools also interleave plugin chatter,
# metadata banners, mirror lists, headers, and trailer lines with the rows, so a
# line is read as an advisory only when the advisory id sits in its expected
# column and a NEVRA follows it.
_RPM_ADVISORY_ID_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9][A-Za-z0-9.:+_-]*)+$"
)

# An RPM version or release never contains a hyphen, so the last two
# hyphen-separated fields of a NEVRA are always version and release, however
# many hyphens the package name itself carries.
_RPM_NEVRA_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._+][A-Za-z0-9._+-]*?)"
    r"-(?:(?P<epoch>\d+):)?"
    r"(?P<version>[A-Za-z0-9._+~^]+)"
    r"-(?P<release>[A-Za-z0-9._+~^]+)"
    r"\.(?P<arch>[A-Za-z0-9_]+)$"
)


def _is_rpm_advisory_id(token: str) -> bool:
    """True for advisory ids such as ``RHSA-2024:1234`` or ``ELSA-2024-1234``."""
    return bool(_RPM_ADVISORY_ID_RE.match(token)) and any(
        char.isdigit() for char in token
    )


def _split_rpm_advisory_columns(columns: List[str]) -> Tuple[str, str]:
    """Return ``(advisory_type, severity)`` from the columns before the NEVRA.

    Three layouts reach here, all of them without a severity of their own when
    the advisory carries none:

    * ``Important/Sec.`` - the combined column DNF4 and YUM print;
    * ``security Important`` - the separate ``Type`` and ``Severity`` columns of
      the DNF5 table;
    * ``Sec.`` - a bare type.

    Only the two columns closest to the package are read, so a wider table does
    not shift the fields.
    """
    if not columns:
        return "", ""
    if "/" in columns[-1]:
        severity, _, advisory_type = columns[-1].rpartition("/")
        return advisory_type, severity
    if len(columns) >= 2:
        return columns[-2], columns[-1]
    return columns[-1], ""


def _parse_rpm_nevra(token: str) -> Optional[Dict[str, str]]:
    """Split ``name-[epoch:]version-release.arch`` into its fields.

    Returns ``None`` when the token is not a NEVRA, which is what separates an
    advisory row from the surrounding package-manager chatter.
    """
    match = _RPM_NEVRA_RE.match(token)
    if not match:
        return None
    return {
        "name": match.group("name"),
        "epoch": match.group("epoch") or "",
        "version": match.group("version"),
        "release": match.group("release"),
        "arch": match.group("arch"),
    }


# APT metadata observation states. ``fresh`` is the only state that vouches for
# the candidate versions a scan reports.
APT_FRESH = "fresh"
APT_PARTIAL = "partial"
APT_FAILED = "failed"
APT_CACHED = "cached"

APT_REFRESH_TIMEOUT = 300
APT_DETAIL_MAX_CHARS = 500
APT_DETAIL_MAX_REPOS = 5

_APT_ERR_RE = re.compile(r"^Err:\d+\s+(\S+)(?:\s+(.*))?$")
_APT_PROGRESS_RE = re.compile(r"^(?:Hit|Get):\d+\s+(\S+)")
_APT_IP_RE = re.compile(r"\s*\[IP:[^\]]*\]")
_APT_DIAG_RE = re.compile(r"^[EW]:\s*(.+)$")
_APT_GENERIC_DIAG_RE = re.compile(
    r"^(?:Failed to fetch |Some index files failed to download)", re.IGNORECASE
)
# E:/W: lines that mean a source did not refresh. apt exits zero for some of
# these, and other warnings (duplicate targets, deprecated keys) are benign, so
# only fetch and signature failures count.
_APT_FETCH_FAILURE_RE = re.compile(
    r"failed to fetch|index files failed|gpg error|signature verification|"
    r"not signed|NO_PUBKEY|EXPKEYSIG|KEYEXPIRED|BADSIG|no longer has a release "
    r"file|does not have a release file|release file .* (?:expired|not valid yet)",
    re.IGNORECASE,
)
_APT_PRIVILEGE_RE = re.compile(
    r"permission denied|could not open lock file|unable to lock|are you root|"
    r"must be root|a password is required|no tty present|not in the sudoers",
    re.IGNORECASE,
)
_APT_AUTH_RE = re.compile(r"\b(?:401|403)\b|unauthorized|forbidden", re.IGNORECASE)
_APT_MISSING_RE = re.compile(r"\b404\b|not found", re.IGNORECASE)
_APT_SIGNATURE_RE = re.compile(
    r"NO_PUBKEY|EXPKEYSIG|KEYEXPIRED|BADSIG|not signed|signatures? couldn't be "
    r"verified|invalid signature|public key is not available",
    re.IGNORECASE,
)
_APT_NETWORK_RE = re.compile(
    r"could not resolve|temporary failure|connection (?:refused|timed out|failed)|"
    r"network is unreachable|no route to host|timed out",
    re.IGNORECASE,
)


def _bound_detail(text: str) -> str:
    """Redact, flatten and bound remote diagnostic text before it is stored."""
    flat = " ".join(redact_text(text).split())
    if len(flat) > APT_DETAIL_MAX_CHARS:
        flat = flat[: APT_DETAIL_MAX_CHARS - 3].rstrip() + "..."
    return flat


def _repo_label(url: str, suite: str) -> str:
    """Repository identity without credentials, query, or fragment."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    label = f"{host}{parts.path}" if host else url.split("?", 1)[0]
    return f"{label} {suite}".strip()


def _apt_guidance(text: str) -> str:
    if _APT_PRIVILEGE_RE.search(text):
        return (
            "Refreshing APT metadata needs root or passwordless sudo on the host; "
            "set the credential's sudo method, or scan cached-only."
        )
    if _APT_SIGNATURE_RE.search(text):
        return "Verify the repository signing key and that the source is signed."
    if _APT_AUTH_RE.search(text):
        return (
            "Check the repository credentials or subscription, or disable the source."
        )
    if _APT_MISSING_RE.search(text):
        return (
            "The source may have been removed or the suite renamed; fix or disable it."
        )
    if _APT_NETWORK_RE.search(text):
        return "The host could not reach the repository; check network access."
    return "Run apt-get update on the host to see the full error."


def _apt_err_reason(lines: List[str], index: int) -> Tuple[str, int]:
    """Read the indented continuation of an ``Err:`` line.

    Returns the first non-blank continuation line, with apt's bracketed address
    removed, and the index of the first line after the continuation block.
    """
    reason = ""
    while index < len(lines) and lines[index][:1].isspace():
        if not reason and lines[index].strip():
            reason = _APT_IP_RE.sub("", lines[index].strip())
        index += 1
    return reason, index


def _parse_apt_sources(lines: List[str]) -> Tuple[Dict[str, str], Set[str]]:
    """Split ``apt-get update`` stdout into failed and refreshed sources.

    Returns ``(failed, succeeded)``: ``failed`` maps a source URL to a
    credential-free label (with the failure reason when apt gave one), and
    ``succeeded`` holds the URLs that reported ``Hit`` or ``Get``.
    """
    failed: Dict[str, str] = {}
    succeeded: Set[str] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        progress = _APT_PROGRESS_RE.match(line)
        if progress:
            succeeded.add(progress.group(1))
            continue
        match = _APT_ERR_RE.match(line)
        if not match:
            continue
        reason, index = _apt_err_reason(lines, index)
        url = match.group(1)
        if url not in failed:
            label = _repo_label(url, (match.group(2) or "").strip())
            failed[url] = f"{label} ({reason})" if reason else label
    return failed, succeeded


def _collect_apt_diagnostics(
    stdout_lines: List[str], stderr: str
) -> Tuple[List[str], List[str]]:
    """Collect ``E:``/``W:`` diagnostics from stderr and stdout.

    Returns ``(diagnostics, fetch_diagnostics)``. ``fetch_diagnostics`` holds
    the ones that mean a source did not refresh; ``diagnostics`` holds every
    one that is not a generic fetch summary.
    """
    diagnostics: List[str] = []
    fetch_diagnostics: List[str] = []
    for line in (stderr or "").splitlines() + [
        row for row in stdout_lines if _APT_DIAG_RE.match(row)
    ]:
        diag = _APT_DIAG_RE.match(line.strip())
        if not diag:
            continue
        text = _APT_IP_RE.sub("", diag.group(1).strip())
        if _APT_FETCH_FAILURE_RE.search(text):
            fetch_diagnostics.append(text)
        # Generic fetch summaries repeat the per-source failures, so they are
        # evidence of failure but not worth echoing when a source is named.
        if not _APT_GENERIC_DIAG_RE.match(text):
            diagnostics.append(text)
    return diagnostics, fetch_diagnostics


def _apt_unrefreshed_state(
    failed: Dict[str, str],
    succeeded: Set[str],
    evidence: str,
    exit_code: Optional[int],
) -> str:
    """State for a refresh that is not clean: ``partial`` or ``failed``."""
    privilege_blocked = bool(_APT_PRIVILEGE_RE.search(evidence))
    other_sources_ok = bool(succeeded - set(failed))
    # apt stops the whole update on errors that carry no per-source failure
    # line (an unsigned repository), so those are partial only when apt itself
    # exited cleanly after skipping the failing source.
    if (failed or exit_code == 0) and other_sources_ok and not privilege_blocked:
        return APT_PARTIAL
    return APT_FAILED


def _apt_refresh_detail(
    failed: Dict[str, str],
    diagnostics: List[str],
    fetch_diagnostics: List[str],
    exit_code: Optional[int],
) -> str:
    """Source-scoped summary of why a refresh was not clean (unbounded)."""
    if failed:
        shown = "; ".join(list(failed.values())[:APT_DETAIL_MAX_REPOS])
        extra = len(failed) - APT_DETAIL_MAX_REPOS
        if extra > 0:
            shown += f"; and {extra} more"
        return f"{len(failed)} source(s) failed to refresh: {shown}."
    if diagnostics or fetch_diagnostics:
        shown_diagnostics = fetch_diagnostics or diagnostics
        return "apt-get update reported: " + "; ".join(shown_diagnostics[:3]) + "."
    return f"apt-get update exited with status {exit_code}."


def classify_apt_refresh(
    stdout: str, stderr: str, exit_code: Optional[int]
) -> Tuple[str, str]:
    """Classify ``apt-get update`` output as ``(state, detail)``.

    ``fresh`` requires a clean exit and no failed source. Otherwise the result is
    ``partial`` when some other source fetched cleanly alongside the failed
    ones, and ``failed`` when no source is known to have refreshed: a privilege
    or lock failure, or an error such as an unsigned repository that apt
    reports without a per-source failure and that stops the whole update.
    Detail is source-scoped, redacted, and bounded.
    """
    lines = (stdout or "").splitlines()
    failed, succeeded = _parse_apt_sources(lines)
    diagnostics, fetch_diagnostics = _collect_apt_diagnostics(lines, stderr)

    if exit_code == 0 and not failed and not fetch_diagnostics:
        if succeeded:
            return APT_FRESH, ""
        # A clean exit with no source reporting in means nothing was refreshed:
        # no enabled source, or every source skipped. It cannot vouch for the
        # cached lists, and it is not the same as a refreshed repository that
        # simply has no updates.
        return APT_FAILED, _bound_detail(
            "apt-get update refreshed no source; no enabled APT source "
            "reported in. Enable a source on the host, or treat the cached "
            "lists as unverified."
        )

    evidence = " ".join(list(failed.values()) + diagnostics)
    state = _apt_unrefreshed_state(failed, succeeded, evidence, exit_code)
    detail = _apt_refresh_detail(failed, diagnostics, fetch_diagnostics, exit_code)
    return state, _bound_detail(f"{detail} {_apt_guidance(evidence)}")


def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value else None


def apt_metadata_view(
    state: Optional[str],
    refreshed_at: Optional[datetime],
    checked_at: Optional[datetime],
    detail: Optional[str],
) -> Dict[str, Any]:
    """API shape of a host's APT metadata observation.

    ``state`` is ``unknown`` until a check has been recorded. Only ``fresh``
    vouches for candidate versions; ``verified`` repeats that as a boolean so a
    consumer cannot mistake a cached or failed check for current metadata.
    """
    return {
        "state": state or "unknown",
        "verified": state == APT_FRESH,
        "refreshed_at": _iso_utc(refreshed_at),
        "checked_at": _iso_utc(checked_at),
        "detail": detail,
    }


class PackageService:
    """Service for managing packages on remote systems via SSH."""

    def __init__(self, db: Session):
        self.db = db
        self.ssh_service = SSHService(db)

    def _single_flight(
        self, system_id: int, fn: Callable[[], Dict[str, Any]]
    ) -> Dict[str, Any]:
        """PRA-322: run ``fn`` under the per-host work lock, or return an
        ``already_running`` result immediately if expensive SSH/package-manager
        work is already in flight for this host. Non-blocking: a second scan from
        repeated clicks / polling / retries never queues or overlaps."""
        lock = _host_worklock(system_id)
        if not lock.acquire(blocking=False):
            system = self.db.query(System).filter(System.id == system_id).first()
            return {
                "system_id": system_id,
                "hostname": system.hostname if system else None,
                "status": "already_running",
                "message": (
                    "A package operation is already running for this host; "
                    "wait for it to finish."
                ),
            }
        try:
            return fn()
        finally:
            lock.release()

    def _get_system_or_raise(self, system_id: int) -> System:
        """Get a system by ID or raise an error."""
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            raise ValueError(f"System with ID {system_id} not found")
        return system

    def _get_pkg_manager(self, system: System) -> str:
        """Determine the package manager for a system based on its distro."""
        distro = self.db.query(Distro).filter(Distro.id == system.distro_id).first()
        if not distro:
            raise ValueError(f"Distro not found for system {system.hostname}")

        distro_name = distro.name.lower()
        for key, manager in DISTRO_PKG_MANAGER.items():
            if key in distro_name:
                return manager

        raise ValueError(
            f"Unsupported distribution: {distro.name}. "
            "Supported: Ubuntu, Debian, CentOS, RHEL, Rocky, Alma, Fedora, Oracle."
        )

    def _get_commands(self, pkg_manager: str) -> Dict[str, str]:
        """Get the command set for a package manager."""
        commands = PKG_COMMANDS.get(pkg_manager)
        if not commands:
            raise ValueError(f"No commands defined for package manager: {pkg_manager}")
        return commands

    def _collect_reboot_evidence(self, system: System) -> Dict[str, Any]:
        """Observe whether ``system`` needs a reboot after a mutation.

        Direct package updates are not governed by the patch-plan reboot
        queue, so this response is the only place their operator learns
        that an update left the host one reboot behind. The observation
        rides the SSH connection the update itself used, so it inherits
        the same credential and ``sudo_method``.

        Never raises. A probe that cannot answer reports an unknown
        outcome and a null value; it must not turn a package update that
        actually succeeded into a failed response.
        """
        try:
            evidence = reboot_evidence_service.collect_over_ssh(
                self.db, system, ssh_service=self.ssh_service
            )
        except Exception as exc:  # pylint: disable=broad-except
            # Category only: the exception text can carry remote output or a
            # credential. The redacted detail rides on the evidence record.
            logger.warning(
                "reboot evidence collection failed for system %s: %s",
                system.id,
                type(exc).__name__,
            )
            evidence = reboot_evidence_service.transport_failure(reason=exc)
        return evidence.to_dict()

    @staticmethod
    def _ssh_result_ok(result: Dict[str, Any]) -> bool:
        # Reject connection/auth failures and any case where the remote produced
        # no stdout but did produce stderr (silently-failed scans used to be
        # parsed as "0 packages").
        if result.get("status") not in ("success", "warning"):
            return False
        if not result.get("stdout", "").strip() and result.get("stderr", "").strip():
            return False
        return True

    @staticmethod
    def _exited_cleanly(result: Dict[str, Any]) -> bool:
        """The command ran and exited zero.

        The SSH layer reports a nonzero exit as status ``warning`` with
        ``exit_code`` set, so the status alone cannot tell success from a
        command that failed.
        """
        return result.get("status") in ("success", "warning") and result.get(
            "exit_code"
        ) in (0, None)

    @staticmethod
    def _apt_list_ok(result: Dict[str, Any]) -> bool:
        """``apt list`` succeeded: apt's own exit status was zero.

        An empty list with a clean exit means no candidates; any other outcome
        means the candidate set is unknown and must not read as zero.
        """
        return (
            result.get("status") == "success"
            and result.get("exit_code") in (0, None)
            and not result.get("truncated")
            and PackageService._ssh_result_ok(result)
        )

    @staticmethod
    def _listing_failure_reason(result: Dict[str, Any]) -> str:
        """Why a candidate listing cannot be trusted, for operator-facing text."""
        if result.get("truncated"):
            return (
                "The candidate update list exceeded the output capture limit and "
                "is incomplete."
            )
        return "The candidate update list could not be read."

    def _stored_update_count(self, system_id: int, security_only: bool = False) -> int:
        query = self.db.query(PackageUpdate).filter(
            PackageUpdate.system_id == system_id
        )
        if security_only:
            query = query.filter(PackageUpdate.update_type == "security")
        return query.count()

    def _refresh_apt_metadata(
        self, system_id: int, commands: Dict[str, str], refresh: bool
    ) -> Tuple[str, str, bool]:
        """Refresh APT metadata, or report that cached lists are being used.

        Returns ``(state, detail, incomplete)``; ``incomplete`` is True when the
        refresh output was clipped by the capture limit.

        The refresh is a privileged mutation of the host's package lists, so it
        runs through the credential's sudo method like every other privileged
        package operation. A host that cannot escalate reports a failed refresh
        with guidance; scanning is never blocked by it, and the host's cached
        lists keep answering as last-known inventory.
        """
        if not refresh:
            return (
                APT_CACHED,
                "Cached package lists were used; the metadata was not refreshed.",
                False,
            )
        try:
            result = self.ssh_service.execute_privileged_command(
                system_id, commands["refresh_metadata"], timeout=APT_REFRESH_TIMEOUT
            )
        except SSHConnectionError as exc:
            return (
                APT_FAILED,
                _bound_detail(
                    f"The connection failed during the metadata refresh: {exc}"
                ),
                False,
            )
        exit_code = result.get("exit_code")
        if exit_code is None:
            reason = (result.get("stderr") or "").strip() or "no result from the host"
            return (
                APT_FAILED,
                _bound_detail(f"The metadata refresh did not complete: {reason}"),
                False,
            )
        state, detail = classify_apt_refresh(
            result.get("stdout", ""), result.get("stderr", ""), exit_code
        )
        if result.get("truncated"):
            # The capture limit clipped the evidence, so a clean-looking prefix
            # proves nothing about the sources that came after it.
            note = (
                "The refresh output exceeded the capture limit, so the result "
                "cannot be verified."
            )
            return (
                (APT_FAILED if state == APT_FRESH else state),
                _bound_detail(f"{note} {detail}".strip()),
                True,
            )
        return state, detail, False

    def _record_apt_observation(
        self, system_id: int, observed_at: datetime, state: str, detail: str
    ) -> Dict[str, Any]:
        """Persist one APT metadata observation and return the stored summary.

        Writes are ordered by observation time: evidence older than the stored
        check cannot replace it, so a scan that finishes late never overwrites a
        newer result. Only a fresh observation advances the last verified
        refresh, and it only moves forward; every other state leaves it alone.
        """
        self.db.execute(
            sql_update(System)
            .where(
                System.id == system_id,
                or_(
                    System.apt_metadata_checked_at.is_(None),
                    System.apt_metadata_checked_at <= observed_at,
                ),
            )
            .values(
                apt_metadata_state=state,
                apt_metadata_checked_at=observed_at,
                apt_metadata_detail=(detail or None),
            )
            .execution_options(synchronize_session=False)
        )
        if state == APT_FRESH:
            self.db.execute(
                sql_update(System)
                .where(
                    System.id == system_id,
                    or_(
                        System.apt_metadata_refreshed_at.is_(None),
                        System.apt_metadata_refreshed_at < observed_at,
                    ),
                )
                .values(apt_metadata_refreshed_at=observed_at)
                .execution_options(synchronize_session=False)
            )
        self.db.commit()
        return self.get_apt_metadata(system_id)

    def get_apt_metadata(self, system_id: int) -> Dict[str, Any]:
        """Latest stored APT metadata observation for one host."""
        row = (
            self.db.query(
                System.apt_metadata_state,
                System.apt_metadata_refreshed_at,
                System.apt_metadata_checked_at,
                System.apt_metadata_detail,
            )
            .filter(System.id == system_id)
            .one_or_none()
        )
        return apt_metadata_view(*(row or (None, None, None, None)))

    def list_apt_metadata(
        self, system_ids: Optional[Set[int]] = None
    ) -> List[Dict[str, Any]]:
        """APT metadata freshness for hosts in the caller's fleet scope."""
        query = _apply_system_scope(
            self.db.query(
                System.id,
                System.hostname,
                System.apt_metadata_state,
                System.apt_metadata_refreshed_at,
                System.apt_metadata_checked_at,
                System.apt_metadata_detail,
            ),
            System.id,
            system_ids,
        )
        return [
            {"system_id": row[0], "hostname": row[1], **apt_metadata_view(*row[2:])}
            for row in query.order_by(System.hostname).all()
        ]

    def scan_scope(
        self,
        targets: List[Tuple[int, str]],
        *,
        security: bool = False,
        refresh: bool = True,
    ) -> Dict[str, Any]:
        """Run the existing single-host scan across a resolved cohort of hosts.

        ``targets`` is the already-resolved, fleet-scoped ``(system_id, hostname)``
        snapshot (the route resolves and snapshots it). Each host is scanned
        independently: a per-host failure or an ``already_running`` skip never
        aborts the cohort, so partial results are the normal, visible outcome.
        Returns aggregate counts plus a per-host status list.
        """
        results: List[Dict[str, Any]] = []
        success = failure = skipped = partial = 0
        for system_id, hostname in targets:
            scan_state = None
            try:
                summary = (
                    self.scan_security_updates(system_id, refresh=refresh)
                    if security
                    else self.scan_packages(system_id, refresh=refresh)
                )
                status = summary.get("status", "error")
                message = summary.get("message")
                scan_state = summary.get("scan_state")
            except SSHConnectionError as e:
                status, message = "error", str(e)
                scan_state = STATE_FAILED if security else None
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("Cohort scan failed for system %s: %s", system_id, e)
                status, message = "error", str(e)
                scan_state = STATE_FAILED if security else None

            if status == "success":
                success += 1
                if scan_state == STATE_PARTIAL:
                    partial += 1
            elif status == "already_running":
                skipped += 1
            else:
                failure += 1

            results.append(
                {
                    "system_id": system_id,
                    "hostname": hostname,
                    "status": status,
                    "message": message,
                    "scan_state": scan_state,
                }
            )

        return {
            "total": len(targets),
            "success_count": success,
            "failure_count": failure,
            "skipped_count": skipped,
            # Scanned hosts (counted in success_count) whose results rest on
            # unverified APT metadata.
            "partial_count": partial,
            "results": results,
        }

    def scan_packages(self, system_id: int, refresh: bool = True) -> Dict[str, Any]:
        """Scan a system for installed packages via SSH (per-host single-flight).

        ``refresh`` controls APT metadata: True refreshes it first (privileged),
        False reads the host's cached lists. Either way the observation is
        recorded, and only a verified refresh makes update counts trustworthy.
        Hosts on other package managers ignore it.
        """
        return self._single_flight(
            system_id, lambda: self._scan_packages_impl(system_id, refresh)
        )

    def _scan_packages_impl(
        self, system_id: int, refresh: bool = True
    ) -> Dict[str, Any]:
        """
        Scan a system for installed packages via SSH and store results in DB.

        Returns summary of scan results.
        """
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        # PRA-314: one timestamp for this scan, shared by System.last_audited, every
        # observed package row's last_audited, and the returned scanned_at, so the
        # freshness the UI/API report is coherent. Captured only after the scan
        # succeeds — a failed scan (early return below) never refreshes timestamps.
        scanned_at = datetime.utcnow()

        # Execute package list command
        result = self.ssh_service.execute_command(
            system_id, commands["list_installed"], timeout=120
        )

        listing_error = self._package_listing_error(system_id, system.hostname, result)
        if listing_error:
            return listing_error

        # Parse output based on package manager
        packages = self._parse_installed_packages(result["stdout"], pkg_manager)

        # Upsert packages into DB
        added, updated = self._upsert_packages(
            system_id, packages, pkg_manager, scanned_at=scanned_at
        )

        is_apt = pkg_manager == "apt"
        apt_state = apt_detail = ""
        refresh_clipped = False
        observed_at = datetime.utcnow()
        if is_apt:
            apt_state, apt_detail, refresh_clipped = self._refresh_apt_metadata(
                system_id, commands, refresh
            )

        # Now check for available updates
        update_result = self.ssh_service.execute_command(
            system_id, commands["check_updates"], timeout=120
        )
        updates_found, listing_ok, apt_state, apt_detail = self._reconcile_updates(
            system_id, pkg_manager, update_result, apt_state, apt_detail
        )

        apt_metadata = None
        if is_apt:
            apt_metadata = self._record_apt_observation(
                system_id, observed_at, apt_state, apt_detail
            )

        # Mark system as audited so dashboard "stale scan" check is accurate. Same
        # timestamp the package rows were stamped with above.
        system.last_audited = scanned_at
        self.db.commit()

        unverified = is_apt and apt_state != APT_FRESH
        self._notify_package_scan(system, len(packages), updates_found, unverified)

        summary = {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_found": len(packages),
            "packages_added": added,
            "packages_updated": updated,
            "updates_available": updates_found,
            "scanned_at": scanned_at.isoformat(),
        }
        if is_apt:
            summary["apt_metadata"] = apt_metadata
            summary["evidence_incomplete"] = refresh_clipped or not listing_ok
            summary["scan_state"] = (
                STATE_COMPLETE if apt_state == APT_FRESH else STATE_PARTIAL
            )
            if apt_state != APT_FRESH:
                summary["message"] = (
                    "Inventory scanned. Showing last-known updates; the APT "
                    f"metadata is {'cached' if apt_state == APT_CACHED else 'unverified'}"
                    f" and did not replace them. {apt_detail}"
                ).strip()
        return summary

    @staticmethod
    def _package_listing_error(
        system_id: int, hostname: str, result: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Error summary when the installed-package listing is unusable, else None."""
        if not PackageService._ssh_result_ok(result):
            return {
                "system_id": system_id,
                "hostname": hostname,
                "status": "error",
                "message": f"Failed to scan packages: {result.get('stderr', '').strip() or 'no output from remote host'}",
                "packages_found": 0,
            }

        if result.get("truncated"):
            # Reconciling a clipped listing would delete every package past the
            # cut, so the stored inventory is left as the last-known state.
            return {
                "system_id": system_id,
                "hostname": hostname,
                "status": "error",
                "evidence_incomplete": True,
                "message": (
                    "Failed to scan packages: the installed package list exceeded "
                    "the output capture limit; the stored inventory is unchanged."
                ),
                "packages_found": 0,
            }
        return None

    def _reconcile_updates(
        self,
        system_id: int,
        pkg_manager: str,
        update_result: Dict[str, Any],
        apt_state: str,
        apt_detail: str,
    ) -> Tuple[int, bool, str, str]:
        """Apply an available-updates listing to the stored candidates.

        Returns ``(updates_found, listing_ok, apt_state, apt_detail)``; the APT
        pair is downgraded to ``failed`` when the listing itself failed.
        """
        is_apt = pkg_manager == "apt"
        listing_ok = (
            self._apt_list_ok(update_result)
            if is_apt
            else self._ssh_result_ok(update_result)
        )
        if listing_ok and is_apt and apt_state != APT_FRESH:
            # The listing came from lists no refresh vouched for, so it cannot
            # replace the stored candidates: an empty or incomplete cache would
            # erase last-known updates. They stay until a verified scan.
            updates_found = (
                self.db.query(PackageUpdate)
                .filter(PackageUpdate.system_id == system_id)
                .count()
            )
        elif listing_ok:
            updates = self._parse_available_updates(
                update_result["stdout"], pkg_manager
            )
            updates_found = self._upsert_updates(system_id, updates, pkg_manager)
        else:
            updates_found = 0
            # The previous candidate rows are left in place as last-known data.
            logger.warning(
                "Update check failed for system %s: %s",
                system_id,
                update_result.get("stderr", "").strip() or "no output",
            )
            if is_apt:
                apt_state = APT_FAILED
                apt_detail = _bound_detail(
                    f"{self._listing_failure_reason(update_result)} Showing "
                    f"last-known updates. {apt_detail}"
                )
                updates_found = self._stored_update_count(system_id)
        return updates_found, listing_ok, apt_state, apt_detail

    def _notify_package_scan(
        self, system: System, package_count: int, updates_found: int, unverified: bool
    ) -> None:
        """Raise the in-app notification for a completed package scan."""
        from .notification_service import create_notification

        create_notification(
            self.db,
            type="package_scan_complete",
            title=f"Package scan complete: {system.hostname}",
            message=(
                f"Found {package_count} packages, {updates_found} updates available"
                + (
                    " (unverified: APT metadata was not refreshed)"
                    if unverified
                    else ""
                )
            ),
            severity="warning" if unverified else "info",
        )

    def _parse_installed_packages(
        self, output: str, pkg_manager: str
    ) -> List[Dict[str, str]]:
        """Parse package list output into structured data."""
        packages = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            if pkg_manager == "apt":
                # Format: name\tversion\tinstall ok installed
                parts = line.split("\t")
                if len(parts) >= 2:
                    packages.append(
                        {
                            "name": parts[0].strip(),
                            "version": parts[1].strip(),
                            "type": "deb",
                        }
                    )
            elif pkg_manager in ("yum", "dnf"):
                # Format: name\tversion-release\tinstall_date
                parts = line.split("\t")
                if len(parts) >= 2:
                    packages.append(
                        {
                            "name": parts[0].strip(),
                            "version": parts[1].strip(),
                            "type": "rpm",
                        }
                    )

        return packages

    def _parse_available_updates(
        self, output: str, pkg_manager: str
    ) -> List[Dict[str, str]]:
        """Parse available updates output into structured data."""
        updates = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            if pkg_manager == "apt":
                # Format: package/source version [upgradable from: old_version]
                match = re.match(
                    r"^(\S+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)\]", line
                )
                if match:
                    name = match.group(1)
                    update_type = "security" if "security" in line.lower() else "normal"
                    updates.append(
                        {
                            "name": name,
                            "available_version": match.group(2),
                            "current_version": match.group(3),
                            "type": update_type,
                        }
                    )
            elif pkg_manager in ("yum", "dnf"):
                # Format: package.arch  version  repo
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].rsplit(".", 1)[0]  # strip .arch
                    version = parts[1]
                    # Strip epoch prefix (e.g. "2:9.1.083" -> "9.1.083")
                    if ":" in version:
                        version = version.split(":", 1)[1]
                    updates.append(
                        {
                            "name": name,
                            "available_version": version,
                            "current_version": "",
                            "type": "normal",
                        }
                    )

        return updates

    @staticmethod
    def _parse_rpm_security_updates(output: str) -> Tuple[List[Dict[str, str]], int]:
        """Parse ``dnf|yum updateinfo list security`` output into update rows.

        Returns the parsed advisory rows plus the number of advisory rows that
        could not be read. A caller must not report an authoritative zero while
        that second value is non-zero: the host did list advisories, they were
        simply not understood here.

        ``available_version`` is the epoch-free ``version-release``, matching
        both the installed-package inventory and the ``check-update`` parser so
        the two sources stay comparable. ``advisory_type`` and ``severity`` are
        kept as the host reported them, which is why they carry both the DNF4
        spelling ("Sec.", "Important") and the DNF5 one ("security",
        "Important").
        """
        updates: List[Dict[str, str]] = []
        unreadable = 0

        for raw_line in output.splitlines():
            parts = raw_line.split()
            if not parts:
                continue

            # ``yum updateinfo list`` can prefix a row with a one-character
            # installed-state flag; every other variant starts with the advisory.
            advisory_index = 1 if len(parts[0]) == 1 and len(parts) > 3 else 0
            advisory = parts[advisory_index]
            if not _is_rpm_advisory_id(advisory):
                # Banner, mirror list, plugin chatter, or trailer line.
                continue

            nevra = None
            columns: List[str] = []
            for index in range(advisory_index + 1, len(parts)):
                nevra = _parse_rpm_nevra(parts[index])
                if nevra:
                    columns = parts[advisory_index + 1 : index]
                    break

            if not nevra:
                unreadable += 1
                continue

            advisory_type, severity = _split_rpm_advisory_columns(columns)
            updates.append(
                {
                    "name": nevra["name"],
                    "available_version": f"{nevra['version']}-{nevra['release']}",
                    "current_version": "",
                    "type": "security",
                    "advisory": advisory,
                    "advisory_type": advisory_type,
                    "severity": severity,
                    "epoch": nevra["epoch"],
                    "arch": nevra["arch"],
                }
            )

        return updates, unreadable

    def _upsert_packages(
        self,
        system_id: int,
        packages: List[Dict[str, str]],
        pkg_manager: str,
        scanned_at: Optional[datetime] = None,
    ) -> tuple:
        """Insert or update packages in the database. Returns (added, updated) counts.

        PRA-314: every package OBSERVED in this scan is stamped with ``scanned_at``
        (the single per-scan timestamp) so the inventory UI shows real scan freshness
        instead of ``Never``. Refreshing ``last_audited`` on an otherwise-unchanged
        row does NOT count as an update — only an actual installed-version change
        increments ``updated``. Packages no longer present are still deleted.
        """
        scanned_at = scanned_at or datetime.utcnow()
        added = 0
        updated = 0

        existing = {
            p.name: p
            for p in self.db.query(Package).filter(Package.system_id == system_id).all()
        }

        scanned_names = {pkg_data["name"] for pkg_data in packages}

        for pkg_data in packages:
            if pkg_data["name"] in existing:
                pkg = existing[pkg_data["name"]]
                if pkg.installed_version != pkg_data["version"]:
                    # Real version change: count it and bump updated_at.
                    pkg.installed_version = pkg_data["version"]
                    pkg.updated_at = scanned_at
                    updated += 1
                # Observed this scan — refresh freshness whether or not the version
                # changed, but do NOT inflate the updated count for a mere refresh.
                pkg.last_audited = scanned_at
            else:
                pkg = Package(
                    system_id=system_id,
                    name=pkg_data["name"],
                    installed_version=pkg_data["version"],
                    package_type=pkg_data.get("type", pkg_manager),
                    last_audited=scanned_at,
                    created_at=scanned_at,
                    updated_at=scanned_at,
                )
                self.db.add(pkg)
                added += 1

        removed = 0
        for name, pkg in existing.items():
            if name not in scanned_names:
                self.db.query(PackageUpdate).filter(
                    PackageUpdate.package_id == pkg.id
                ).delete()
                self.db.delete(pkg)
                removed += 1

        self.db.commit()
        return added, updated

    def _upsert_updates(
        self, system_id: int, updates: List[Dict[str, str]], pkg_manager: str
    ) -> int:
        """Insert or update available updates. Returns count of updates found."""
        # Clear old updates for this system
        self.db.query(PackageUpdate).filter(
            PackageUpdate.system_id == system_id
        ).delete()
        self.db.flush()

        count = 0
        for upd in updates:
            # Find the matching package
            pkg = (
                self.db.query(Package)
                .filter(Package.system_id == system_id, Package.name == upd["name"])
                .first()
            )
            if not pkg:
                continue

            update = PackageUpdate(
                package_id=pkg.id,
                system_id=system_id,
                available_version=upd["available_version"],
                update_type=upd.get("type", "normal"),
                discovered_on=datetime.utcnow(),
            )
            self.db.add(update)
            count += 1

        self.db.commit()
        return count

    def scan_security_updates(
        self, system_id: int, refresh: bool = True
    ) -> Dict[str, Any]:
        """Scan a system for security updates via SSH (per-host single-flight).

        On APT hosts the result is complete only when this scan ran against
        freshly refreshed metadata. A cached or unverified scan reports
        ``partial`` and is never counted as covered; a later refresh does not
        certify counts that an earlier scan computed from stale metadata.
        """
        return self._single_flight(
            system_id, lambda: self._scan_security_updates_impl(system_id, refresh)
        )

    def _scan_security_updates_impl(
        self, system_id: int, refresh: bool = True
    ) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        is_apt = pkg_manager == "apt"
        apt_state = apt_detail = ""
        refresh_clipped = False
        observed_at = datetime.utcnow()
        if is_apt:
            apt_state, apt_detail, refresh_clipped = self._refresh_apt_metadata(
                system_id, commands, refresh
            )

        result = self.ssh_service.execute_command(
            system_id, commands["check_security"], timeout=120
        )

        listing_ok = (
            self._apt_list_ok(result) if is_apt else self._ssh_result_ok(result)
        )
        if not listing_ok:
            return self._security_listing_failure(
                system, result, is_apt, observed_at, apt_detail
            )

        apt_metadata = None
        if is_apt:
            apt_metadata = self._record_apt_observation(
                system_id, observed_at, apt_state, apt_detail
            )

        updates, unreadable_rows = self._parse_security_listing(
            pkg_manager, result["stdout"]
        )
        if unreadable_rows and not updates:
            # The host did list advisories. Recording zero would read as "no
            # security updates", so report the scan as failed instead.
            logger.error(
                "Security scan for system %s returned %d advisory row(s) that "
                "could not be read",
                system_id,
                unreadable_rows,
            )
            return self._security_failure_summary(
                system,
                (
                    f"Security scan could not read any of the {unreadable_rows} "
                    "advisory line(s) returned by the package manager; no "
                    "security updates were recorded."
                ),
                unreadable_rows,
                [],
            )
        if unreadable_rows:
            logger.warning(
                "Security scan for system %s skipped %d unreadable advisory row(s)",
                system_id,
                unreadable_rows,
            )

        updates_found, unmatched = self._upsert_security_updates(
            system_id, updates, pkg_manager
        )
        if updates and not updates_found:
            # Every reported package is absent from this host's inventory, so
            # nothing could be stored; a zero here is indistinguishable from a
            # host with no security updates.
            logger.error(
                "Security scan for system %s reported %d update(s) for packages "
                "missing from the inventory",
                system_id,
                len(unmatched),
            )
            return self._security_failure_summary(
                system,
                (
                    f"Security scan found {len(unmatched)} update(s) for packages "
                    f"that are not in this host's package inventory "
                    f"({', '.join(unmatched[:5])}); run a package scan first."
                ),
                unreadable_rows,
                unmatched[:MAX_REPORTED_PACKAGES],
            )
        if unmatched:
            logger.warning(
                "Security scan for system %s skipped %d package(s) missing from the "
                "inventory",
                system_id,
                len(unmatched),
            )

        # Notification: security updates available (PRA-99)
        if updates_found > 0:
            from .notification_service import create_notification

            create_notification(
                self.db,
                type="security_updates",
                title=f"Security updates available: {system.hostname}",
                message=f"{updates_found} security update(s) found",
                severity="warning",
            )

        return self._security_scan_summary(
            system,
            is_apt,
            apt_state,
            apt_detail,
            apt_metadata,
            refresh_clipped,
            updates_found,
            unreadable_rows,
            unmatched,
        )

    def _security_listing_failure(
        self,
        system: System,
        result: Dict[str, Any],
        is_apt: bool,
        observed_at: datetime,
        apt_detail: str,
    ) -> Dict[str, Any]:
        """Record the failed APT observation and build the error summary for an
        unusable security listing; last-known updates stay stored."""
        system_id = system.id
        apt_metadata = None
        if is_apt:
            apt_metadata = self._record_apt_observation(
                system_id,
                observed_at,
                APT_FAILED,
                _bound_detail(f"{self._listing_failure_reason(result)} {apt_detail}"),
            )
        last_known = self._stored_update_count(system_id, security_only=True)
        reason = (
            self._listing_failure_reason(result)
            if (is_apt or result.get("truncated"))
            else result.get("stderr", "").strip() or "no output from remote host"
        )
        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "error",
            "scan_state": STATE_FAILED,
            "evidence_incomplete": True,
            "last_known_updates": last_known,
            "apt_metadata": apt_metadata,
            "message": (
                f"Failed to scan security updates: {reason} "
                f"{last_known} last-known security update(s) are retained."
            ),
            "packages_found": 0,
            "packages_added": 0,
            "packages_updated": 0,
            "updates_available": 0,
            "unreadable_advisories": 0,
            "unmatched_packages": [],
        }

    def _parse_security_listing(
        self, pkg_manager: str, output: str
    ) -> Tuple[List[Dict[str, str]], int]:
        """Parse a security listing into updates, typed ``security``.

        Returns ``(updates, unreadable_rows)``; only RPM advisories can have
        rows that could not be read.
        """
        if pkg_manager in ("yum", "dnf"):
            return self._parse_rpm_security_updates(output)
        updates = self._parse_available_updates(output, pkg_manager)
        if pkg_manager == "apt":
            updates = [u for u in updates if u["type"] == "security"]
        for upd in updates:
            upd["type"] = "security"
        return updates, 0

    @staticmethod
    def _security_failure_summary(
        system: System,
        message: str,
        unreadable_rows: int,
        unmatched: List[str],
    ) -> Dict[str, Any]:
        """Error summary for a scan that parsed or matched nothing it could store."""
        return {
            "system_id": system.id,
            "hostname": system.hostname,
            "status": "error",
            "scan_state": STATE_FAILED,
            "message": message,
            "packages_found": 0,
            "packages_added": 0,
            "packages_updated": 0,
            "updates_available": 0,
            "unreadable_advisories": unreadable_rows,
            "unmatched_packages": unmatched,
        }

    @staticmethod
    def _security_scan_summary(
        system: System,
        is_apt: bool,
        apt_state: str,
        apt_detail: str,
        apt_metadata: Optional[Dict[str, Any]],
        refresh_clipped: bool,
        updates_found: int,
        unreadable_rows: int,
        unmatched: List[str],
    ) -> Dict[str, Any]:
        """Success summary; ``partial`` when the count is a floor or unverified."""
        metadata_unverified = is_apt and apt_state != APT_FRESH
        scan_state = (
            STATE_PARTIAL
            if (unreadable_rows or unmatched or metadata_unverified)
            else STATE_COMPLETE
        )
        summary = {
            "system_id": system.id,
            "hostname": system.hostname,
            "status": "success",
            "scan_state": scan_state,
            "packages_found": 0,
            "packages_added": 0,
            "packages_updated": 0,
            "updates_available": updates_found,
            "unreadable_advisories": unreadable_rows,
            "unmatched_packages": unmatched[:MAX_REPORTED_PACKAGES],
            "scanned_at": datetime.utcnow().isoformat(),
        }
        if is_apt:
            summary["apt_metadata"] = apt_metadata
            summary["evidence_incomplete"] = refresh_clipped
        if metadata_unverified:
            # Candidates came from package lists no refresh vouched for, so the
            # count may miss updates the repositories now offer.
            summary["message"] = (
                f"Security scan stored {updates_found} update(s) from "
                f"{'cached' if apt_state == APT_CACHED else 'unverified'} APT "
                f"metadata; the count is not verified. {apt_detail}"
            ).strip()
        elif scan_state == STATE_PARTIAL:
            # A count that skipped rows is a floor, not a total, so the caller
            # is told what the scan could not account for.
            summary["message"] = (
                f"Security scan stored {updates_found} update(s) but skipped "
                f"{unreadable_rows} unreadable advisory line(s) and "
                f"{len(unmatched)} package(s) missing from this host's "
                "inventory; the count is incomplete."
            )
        return summary

    def _upsert_security_updates(
        self, system_id: int, updates: List[Dict[str, str]], pkg_manager: str
    ) -> Tuple[int, List[str]]:
        """Store security updates.

        Returns the number of stored updates and the sorted names of reported
        packages that this host's inventory has never seen. Those cannot be
        linked to a package row, so the caller reports them rather than letting
        them disappear into a zero count.

        A package can be reported once per advisory and once per architecture
        while the inventory holds a single row per package name, so the last
        reported version for a name wins and the count stays equal to the number
        of stored rows.
        """
        count = 0
        unmatched: Set[str] = set()
        by_package: Dict[str, Dict[str, str]] = {}
        for upd in updates:
            by_package[upd["name"]] = upd

        for upd in by_package.values():
            pkg = (
                self.db.query(Package)
                .filter(Package.system_id == system_id, Package.name == upd["name"])
                .first()
            )
            if not pkg:
                unmatched.add(upd["name"])
                continue

            existing = (
                self.db.query(PackageUpdate)
                .filter(
                    PackageUpdate.package_id == pkg.id,
                    PackageUpdate.system_id == system_id,
                )
                .first()
            )
            if existing:
                existing.available_version = upd["available_version"]
                existing.update_type = "security"
                existing.discovered_on = datetime.utcnow()
            else:
                update = PackageUpdate(
                    package_id=pkg.id,
                    system_id=system_id,
                    available_version=upd["available_version"],
                    update_type="security",
                    discovered_on=datetime.utcnow(),
                )
                self.db.add(update)
            count += 1

        self.db.commit()
        return count, sorted(unmatched)

    def get_security_updates(
        self,
        system_id: Optional[int] = None,
        system_ids: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        all_updates = self.get_updates(system_id=system_id, system_ids=system_ids)
        return [u for u in all_updates if u["update_type"] == "security"]

    def apply_security_updates(
        self,
        system_id: int,
        user_id: Optional[int] = None,
        job_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Apply security updates via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id,
            lambda: self._apply_security_updates_impl(
                system_id, user_id, job_history_id
            ),
        )

    def _fail_history_entries(
        self,
        history_entries: List[PackageHistory],
        label: str,
        result: Dict[str, Any],
    ) -> str:
        """Mark every entry failed after the command itself failed.

        Commits and returns the operator-facing error text, which falls back
        to the exit status when the command wrote nothing.
        """
        err_msg = (
            result.get("stderr", "")
            or result.get("error_message", "")
            or f"exit status {result.get('exit_code')}"
        )
        for entry in history_entries:
            entry.status = "failed"
            entry.error_message = f"{label}: {err_msg}"
        self.db.commit()
        return err_msg

    def _apply_security_updates_impl(
        self,
        system_id: int,
        user_id: Optional[int] = None,
        job_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        security_updates = self.get_security_updates(system_id=system_id)
        if not security_updates:
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "success",
                "message": "No security updates to apply",
                "packages_updated": 0,
                "packages_skipped": 0,
            }

        package_names = [u["package_name"] for u in security_updates]

        held = {
            p.name
            for p in self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(package_names),
                Package.is_held.is_(True),
            )
            .all()
        }
        packages_skipped = len(held)
        package_names = [n for n in package_names if n not in held]

        if not package_names:
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "success",
                "message": "All security update packages are held",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
            }

        if pkg_manager == "apt":
            cmd = commands["apply_security"].format(
                packages=" ".join(shlex.quote(p) for p in package_names)
            )
        else:
            cmd = commands["apply_security"]

        history_entries = self._create_pending_history(
            system_id, package_names, user_id, job_history_id=job_history_id
        )

        for entry in history_entries:
            entry.status = "running"
        self.db.commit()

        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=600
        )

        if not self._exited_cleanly(result):
            err_msg = self._fail_history_entries(
                history_entries, "Security update failed", result
            )
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Security update failed: {err_msg}",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
            }

        self.scan_packages(system_id, refresh=False)

        completed = 0
        for entry in history_entries:
            pkg = self.db.query(Package).filter(Package.id == entry.package_id).first()
            if pkg and pkg.installed_version == entry.new_version:
                entry.status = "completed"
                completed += 1
            else:
                entry.status = "failed"
                entry.error_message = "Package version unchanged after update"

        self._cleanup_applied_updates(system_id, package_names)

        system.last_successful_update = datetime.utcnow()
        self.db.commit()

        response: Dict[str, Any] = {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_updated": completed,
            "packages_skipped": packages_skipped,
            "applied_at": datetime.utcnow().isoformat(),
        }

        # Observe the host only when verification proved a package actually
        # changed. A package-manager command that exited zero without moving
        # any installed version mutated nothing, so there is no new reboot
        # answer to report and no reason to spend a round-trip asking for
        # one.
        if completed > 0:
            reboot_evidence = self._collect_reboot_evidence(system)
            response["reboot_required"] = reboot_evidence["value"]
            response["reboot_evidence"] = reboot_evidence

        return response

    def hold_packages(self, system_id: int, package_names: List[str]) -> Dict[str, Any]:
        """Hold packages via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id, lambda: self._hold_packages_impl(system_id, package_names)
        )

    def _hold_packages_impl(
        self, system_id: int, package_names: List[str]
    ) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        packages = (
            self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(package_names),
            )
            .all()
        )
        found_names = {p.name for p in packages}
        missing = set(package_names) - found_names
        if missing:
            raise ValueError(
                f"Packages not found on system: {', '.join(sorted(missing))}"
            )

        cmd = commands["hold"].format(
            packages=" ".join(shlex.quote(p) for p in package_names)
        )
        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=120
        )

        if result["status"] not in ("success", "warning"):
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Hold failed: {result.get('stderr', '')}",
                "packages_held": 0,
                "held_packages": [],
            }

        for pkg in packages:
            pkg.is_held = True
        self.db.commit()

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_held": len(packages),
            "held_packages": [p.name for p in packages],
        }

    def unhold_packages(
        self, system_id: int, package_names: List[str]
    ) -> Dict[str, Any]:
        """Unhold packages via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id, lambda: self._unhold_packages_impl(system_id, package_names)
        )

    def _unhold_packages_impl(
        self, system_id: int, package_names: List[str]
    ) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        packages = (
            self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(package_names),
            )
            .all()
        )
        found_names = {p.name for p in packages}
        missing = set(package_names) - found_names
        if missing:
            raise ValueError(
                f"Packages not found on system: {', '.join(sorted(missing))}"
            )

        cmd = commands["unhold"].format(
            packages=" ".join(shlex.quote(p) for p in package_names)
        )
        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=120
        )

        if result["status"] not in ("success", "warning"):
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Unhold failed: {result.get('stderr', '')}",
                "packages_unheld": 0,
                "unheld_packages": [],
            }

        for pkg in packages:
            pkg.is_held = False
        self.db.commit()

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_unheld": len(packages),
            "unheld_packages": [p.name for p in packages],
        }

    def remove_packages(
        self,
        system_id: int,
        package_names: List[str],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Remove packages via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id,
            lambda: self._remove_packages_impl(system_id, package_names, user_id),
        )

    def _settle_removals(
        self,
        system_id: int,
        history_entries: List[PackageHistory],
        removable_names: List[str],
        still_installed: Set[str],
    ) -> int:
        """Mark each removal entry from the rescan and drop gone packages.

        ``history_entries`` and ``removable_names`` are parallel. Returns how
        many packages are confirmed gone. The caller commits.
        """
        completed = 0
        for entry, pkg_name in zip(history_entries, removable_names):
            if pkg_name in still_installed:
                entry.status = "failed"
                entry.error_message = "Package still installed after remove"
                continue
            entry.status = "completed"
            completed += 1
            self.db.query(Package).filter(
                Package.system_id == system_id,
                Package.name == pkg_name,
            ).delete()
        return completed

    def _remove_packages_impl(
        self,
        system_id: int,
        package_names: List[str],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        packages = (
            self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(package_names),
            )
            .all()
        )
        found_names = {p.name for p in packages}
        missing = set(package_names) - found_names
        if missing:
            raise ValueError(
                f"Packages not found on system: {', '.join(sorted(missing))}"
            )

        held = {p.name for p in packages if p.is_held}
        packages_skipped = len(held)
        removable = [p for p in packages if p.name not in held]

        if not removable:
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "success",
                "message": "All requested packages are held",
                "packages_removed": 0,
                "packages_skipped": packages_skipped,
            }

        removable_names = [p.name for p in removable]

        history_entries = []
        for pkg in removable:
            history = PackageHistory(
                package_id=pkg.id,
                system_id=system_id,
                operation="remove",
                old_version=pkg.installed_version,
                new_version=None,
                status="pending",
                performed_at=datetime.utcnow(),
                performed_by=user_id,
            )
            self.db.add(history)
            history_entries.append(history)
        self.db.commit()

        for entry in history_entries:
            entry.status = "running"
        self.db.commit()

        cmd = commands["remove"].format(
            packages=" ".join(shlex.quote(p) for p in removable_names)
        )
        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=600
        )

        if not self._exited_cleanly(result):
            err_msg = self._fail_history_entries(
                history_entries, "Remove failed", result
            )
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Remove failed: {err_msg}",
                "packages_removed": 0,
                "packages_skipped": packages_skipped,
            }

        self.scan_packages(system_id, refresh=False)

        still_installed = {
            p.name
            for p in self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(removable_names),
            )
            .all()
        }

        completed = self._settle_removals(
            system_id, history_entries, removable_names, still_installed
        )

        self.db.commit()

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_removed": completed,
            "packages_skipped": packages_skipped,
        }

    def get_packages(
        self,
        system_id: int,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get installed packages for a system with optional search."""
        self._get_system_or_raise(system_id)

        query = self.db.query(Package).filter(Package.system_id == system_id)

        if search:
            query = query.filter(Package.name.ilike(f"%{search}%"))

        total = query.count()
        packages = query.order_by(Package.name).offset(offset).limit(limit).all()

        return {
            "system_id": system_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "packages": [
                {
                    "id": p.id,
                    "name": p.name,
                    "installed_version": p.installed_version,
                    "package_type": p.package_type,
                    "is_security_critical": p.is_security_critical,
                    "is_held": p.is_held,
                    "installation_date": (
                        p.installation_date.isoformat() if p.installation_date else None
                    ),
                    "last_audited": (
                        p.last_audited.isoformat() if p.last_audited else None
                    ),
                }
                for p in packages
            ],
        }

    def get_packages_for_scope(
        self,
        system_ids: Optional[Set[int]] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Installed packages across a cohort of systems.

        ``system_ids`` is the resolved package scope: ``None`` = tenant-wide admin
        (no filter); an explicit set constrains to those systems; an empty set
        yields zero rows (never a global fallback). Each row carries its
        ``system_id``/``hostname`` so an aggregate inventory identifies the host a
        package is installed on.
        """
        query = self.db.query(Package).join(System, Package.system_id == System.id)
        query = _apply_system_scope(query, Package.system_id, system_ids)

        if search:
            query = query.filter(Package.name.ilike(f"%{search}%"))

        total = query.count()
        rows = (
            query.order_by(Package.name, System.hostname)
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "packages": [
                {
                    "id": p.id,
                    "name": p.name,
                    "installed_version": p.installed_version,
                    "package_type": p.package_type,
                    "is_security_critical": p.is_security_critical,
                    "is_held": p.is_held,
                    "system_id": p.system_id,
                    "hostname": p.system.hostname,
                    "installation_date": (
                        p.installation_date.isoformat() if p.installation_date else None
                    ),
                    "last_audited": (
                        p.last_audited.isoformat() if p.last_audited else None
                    ),
                }
                for p in rows
            ],
        }

    def get_updates(
        self,
        system_id: Optional[int] = None,
        system_ids: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Get available updates, optionally filtered by system.

        ``system_ids`` (PRA-281) is the caller's fleet scope: ``None`` = tenant-wide
        (admin), a set = allow-list. It constrains fleet-aggregate reads so a
        scoped caller never sees updates from systems outside their grants.
        """
        query = self.db.query(PackageUpdate).join(Package)

        if system_id:
            query = query.filter(PackageUpdate.system_id == system_id)
        query = _apply_system_scope(query, PackageUpdate.system_id, system_ids)

        updates = query.order_by(PackageUpdate.discovered_on.desc()).all()

        return [
            {
                "id": u.id,
                "package_id": u.package_id,
                "package_name": u.package.name,
                "system_id": u.system_id,
                "installed_version": u.package.installed_version,
                "available_version": u.available_version,
                "update_type": u.update_type,
                "discovered_on": u.discovered_on.isoformat(),
            }
            for u in updates
        ]

    def apply_updates(
        self,
        system_id: int,
        package_names: Optional[List[str]] = None,
        user_id: Optional[int] = None,
        job_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Apply package updates via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id,
            lambda: self._apply_updates_impl(
                system_id, package_names, user_id, job_history_id
            ),
        )

    def _apply_updates_impl(
        self,
        system_id: int,
        package_names: Optional[List[str]] = None,
        user_id: Optional[int] = None,
        job_history_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Apply package updates on a system via SSH.

        If package_names is None, applies all available updates.
        """
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        cmd, package_names, packages_skipped = self._select_update_command(
            system_id, package_names, commands
        )
        if cmd is None:
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "success",
                "message": "All requested packages are held",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
            }

        # Create pending history entries before running the command
        history_entries = self._create_pending_history(
            system_id, package_names, user_id, job_history_id=job_history_id
        )

        # Mark as running
        for entry in history_entries:
            entry.status = "running"
        self.db.commit()

        # Versions are read from the host itself on both sides of the command,
        # not from the stored inventory, which may predate this request. That
        # evidence attributes a change to this operation, including changes the
        # history has no row for (a named package with no pending-update row,
        # or an upgrade-all with nothing tracked).
        tracked_names = {entry.package.name for entry in history_entries}
        versions_before = self._observe_installed_versions(
            system_id, pkg_manager, commands
        )

        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=600
        )

        if not self._exited_cleanly(result):
            err_msg = self._fail_history_entries(
                history_entries, "Update failed", result
            )
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Update failed: {err_msg}",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
                "packages_failed": len(history_entries),
            }

        # Re-scan to sync DB with actual system state
        self.scan_packages(system_id, refresh=False)

        versions_after = self._observe_installed_versions(
            system_id, pkg_manager, commands
        )

        # Without a host reading after the command the outcome of every tracked
        # package is unknown, and without one before it a change cannot be
        # attributed to this operation.
        attributable = versions_before is not None and versions_after is not None
        completed, failed = self._reconcile_update_history(
            history_entries, versions_before, versions_after
        )

        # Packages whose installed version moved without a history row to
        # verify them. Unknown, not zero, when the evidence is incomplete.
        unrecorded: Optional[int] = None
        if attributable:
            unrecorded = self._count_unrecorded_changes(
                tracked_names, versions_before, versions_after
            )

        # Clean up applied PackageUpdate rows
        self._cleanup_applied_updates(system_id, package_names)

        system.last_successful_update = datetime.utcnow()
        self.db.commit()

        response: Dict[str, Any] = {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_updated": completed,
            "packages_skipped": packages_skipped,
            "packages_failed": failed,
            "packages_unrecorded": unrecorded,
            "verification": "complete" if attributable else "unavailable",
            "applied_at": datetime.utcnow().isoformat(),
        }

        # Observe the host only when verification proved a package actually
        # changed. A package-manager command that exited zero without moving
        # any installed version mutated nothing, so there is no new reboot
        # answer to report and no reason to spend a round-trip asking for
        # one.
        if completed > 0 or (unrecorded or 0) > 0 or not attributable:
            reboot_evidence = self._collect_reboot_evidence(system)
            response["reboot_required"] = reboot_evidence["value"]
            response["reboot_evidence"] = reboot_evidence

        return response

    def _select_update_command(
        self,
        system_id: int,
        package_names: Optional[List[str]],
        commands: Dict[str, str],
    ) -> Tuple[Optional[str], Optional[List[str]], int]:
        """Choose the update command and the packages it will name.

        Returns ``(command, package_names, packages_skipped)``. The command is
        None when every requested package is held, so nothing should run.
        """
        if package_names:
            held = {
                p.name
                for p in self.db.query(Package)
                .filter(
                    Package.system_id == system_id,
                    Package.name.in_(package_names),
                    Package.is_held.is_(True),
                )
                .all()
            }
            package_names = [n for n in package_names if n not in held]
            if not package_names:
                return None, package_names, len(held)
            cmd = commands["apply_update"].format(
                packages=" ".join(shlex.quote(p) for p in package_names)
            )
            return cmd, package_names, len(held)

        held = {
            p.name
            for p in self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.is_held.is_(True),
            )
            .all()
        }
        updatable = (
            self.db.query(PackageUpdate)
            .join(Package)
            .filter(
                PackageUpdate.system_id == system_id,
                ~Package.name.in_(held) if held else True,
            )
            .all()
        )
        if not updatable:
            return commands["apply_all"], package_names, len(held)
        names = list({u.package.name for u in updatable})
        cmd = commands["apply_update"].format(
            packages=" ".join(shlex.quote(n) for n in names)
        )
        return cmd, names, len(held)

    @staticmethod
    def _reconcile_update_history(
        history_entries: List[PackageHistory],
        versions_before: Optional[Dict[str, str]],
        versions_after: Optional[Dict[str, str]],
    ) -> Tuple[int, Optional[int]]:
        """Settle each entry against the host's before and after readings.

        Returns ``(completed, failed)``. ``failed`` is None, not zero, when
        there is no reading after the command: the outcome is unknown. An entry
        already at its target is marked completed but is counted only when the
        readings show this command moved it; with no reading before, nothing
        is attributable.
        """
        completed = 0
        failed: Optional[int] = None if versions_after is None else 0
        for entry in history_entries:
            name = entry.package.name
            if versions_after is None:
                entry.status = "failed"
                entry.error_message = (
                    "Update could not be verified: the installed package list "
                    "was unavailable after the update"
                )
            elif versions_after.get(name) == entry.new_version:
                entry.status = "completed"
                if versions_before is not None and versions_before.get(name) != (
                    entry.new_version
                ):
                    completed += 1
            else:
                entry.status = "failed"
                entry.error_message = "Package version unchanged after update"
                failed = (failed or 0) + 1
        return completed, failed

    @staticmethod
    def _count_unrecorded_changes(
        tracked_names: Set[str],
        versions_before: Dict[str, str],
        versions_after: Dict[str, str],
    ) -> int:
        """Untracked packages whose installed version moved."""
        return sum(
            1
            for name, before in versions_before.items()
            if name not in tracked_names
            and name in versions_after
            and versions_after[name] != before
        )

    def _observe_installed_versions(
        self, system_id: int, pkg_manager: str, commands: Dict[str, str]
    ) -> Optional[Dict[str, str]]:
        """Installed version by package name as the host reports it right now.

        Returns None when the listing is unusable (transport failure, error
        output, clipped capture or an empty list), so callers treat the
        evidence as missing instead of reading it as "nothing installed".
        """
        try:
            result = self.ssh_service.execute_command(
                system_id, commands["list_installed"], timeout=120
            )
        except SSHConnectionError:
            return None
        if (
            not self._exited_cleanly(result)
            or not self._ssh_result_ok(result)
            or result.get("truncated")
        ):
            return None
        versions = {
            pkg["name"]: pkg["version"]
            for pkg in self._parse_installed_packages(
                result.get("stdout", ""), pkg_manager
            )
        }
        return versions or None

    def _create_pending_history(
        self,
        system_id: int,
        package_names: Optional[List[str]],
        user_id: Optional[int],
        job_history_id: Optional[int] = None,
    ) -> List[PackageHistory]:
        """Create pending PackageHistory entries for upcoming updates."""
        query = self.db.query(PackageUpdate).filter(
            PackageUpdate.system_id == system_id
        )
        if package_names:
            query = query.join(Package).filter(Package.name.in_(package_names))

        pending_updates = query.all()
        entries = []

        for upd in pending_updates:
            history = PackageHistory(
                package_id=upd.package_id,
                system_id=system_id,
                operation="update",
                old_version=upd.package.installed_version,
                new_version=upd.available_version,
                status="pending",
                performed_at=datetime.utcnow(),
                performed_by=user_id,
                job_history_id=job_history_id,
            )
            self.db.add(history)
            entries.append(history)

        self.db.commit()
        return entries

    def _cleanup_applied_updates(
        self,
        system_id: int,
        package_names: Optional[List[str]],
    ) -> None:
        """Remove PackageUpdate rows for successfully applied updates."""
        query = self.db.query(PackageUpdate).filter(
            PackageUpdate.system_id == system_id
        )
        if package_names:
            query = query.join(Package).filter(Package.name.in_(package_names))

        for upd in query.all():
            pkg = upd.package
            if pkg.installed_version == upd.available_version:
                self.db.delete(upd)

    def get_history(
        self,
        system_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        system_ids: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """Get package operation history.

        ``system_ids`` (PRA-281) constrains the fleet-aggregate history to the
        caller's fleet scope (``None`` = tenant-wide admin). ``total`` is computed
        from the scoped query, so counts never leak inaccessible systems.
        """
        query = self.db.query(PackageHistory).join(Package)

        if system_id:
            query = query.filter(PackageHistory.system_id == system_id)
        query = _apply_system_scope(query, PackageHistory.system_id, system_ids)

        total = query.count()
        history = (
            query.order_by(PackageHistory.performed_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "history": [
                {
                    "id": h.id,
                    "package_id": h.package_id,
                    "package_name": h.package.name,
                    "system_id": h.system_id,
                    "operation": h.operation,
                    "old_version": h.old_version,
                    "new_version": h.new_version,
                    "status": h.status,
                    "error_message": h.error_message,
                    "performed_at": h.performed_at.isoformat(),
                    "performed_by": (
                        self.db.query(User.username)
                        .filter(User.id == h.performed_by)
                        .scalar()
                        if h.performed_by
                        else None
                    ),
                }
                for h in history
            ],
        }

    def search_fleet_packages(
        self,
        name: str,
        version: Optional[str] = None,
        is_held: Optional[bool] = None,
        has_update: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
        system_ids: Optional[Set[int]] = None,
    ) -> Dict[str, Any]:
        """Search packages across all systems by name with optional filters.

        ``system_ids`` (PRA-281) constrains the search to the caller's fleet scope
        (``None`` = tenant-wide admin), so a scoped caller's ``total`` and results
        never include packages from systems outside their grants.
        """
        query = (
            self.db.query(Package).join(System).filter(Package.name.ilike(f"%{name}%"))
        )
        query = _apply_system_scope(query, Package.system_id, system_ids)

        if version:
            query = query.filter(Package.installed_version.ilike(f"%{version}%"))

        if is_held is not None:
            query = query.filter(Package.is_held.is_(is_held))

        if has_update is True:
            query = query.filter(
                Package.id.in_(self.db.query(PackageUpdate.package_id))
            )
        elif has_update is False:
            query = query.filter(
                ~Package.id.in_(self.db.query(PackageUpdate.package_id))
            )

        total = query.count()
        results = (
            query.order_by(Package.name, System.hostname)
            .offset(offset)
            .limit(limit)
            .all()
        )

        # Fetch updates for the visible packages in one query
        package_ids = [p.id for p in results]
        updates_map: Dict[int, Dict[str, str]] = {}
        if package_ids:
            updates = (
                self.db.query(PackageUpdate)
                .filter(PackageUpdate.package_id.in_(package_ids))
                .all()
            )
            for u in updates:
                updates_map[u.package_id] = {
                    "available_version": u.available_version,
                    "update_type": u.update_type,
                }

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "results": [
                {
                    "package_id": p.id,
                    "name": p.name,
                    "installed_version": p.installed_version,
                    "package_type": p.package_type,
                    "is_held": p.is_held,
                    "is_security_critical": p.is_security_critical,
                    "system_id": p.system_id,
                    "hostname": p.system.hostname,
                    "available_version": updates_map.get(p.id, {}).get(
                        "available_version"
                    ),
                    "update_type": updates_map.get(p.id, {}).get("update_type"),
                    "has_update": p.id in updates_map,
                }
                for p in results
            ],
        }

    def bulk_update_packages(
        self,
        system_ids: List[int],
        package_names: Optional[List[str]] = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Apply package updates across multiple systems."""
        results = []
        total_updated = 0
        total_skipped = 0
        total_errors = 0

        for system_id in system_ids:
            try:
                result = self.apply_updates(
                    system_id,
                    package_names=package_names,
                    user_id=user_id,
                )
                results.append(result)
                if result["status"] == "success":
                    total_updated += result.get("packages_updated", 0)
                    total_skipped += result.get("packages_skipped", 0)
                else:
                    total_errors += 1
            except Exception as e:
                self.db.rollback()
                system = self.db.query(System).filter(System.id == system_id).first()
                # Expected refusals carry an operator-meaningful message; any
                # other exception is reported by class only, because its text
                # can hold host or credential detail.
                reason = (
                    str(e)
                    if isinstance(e, (SSHConnectionError, ValueError))
                    else f"Update failed: {type(e).__name__}"
                )
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname if system else str(system_id),
                        "status": "error",
                        "message": reason,
                        "packages_updated": 0,
                        "packages_skipped": 0,
                    }
                )
                total_errors += 1

        return {
            "total_systems": len(system_ids),
            "total_updated": total_updated,
            "total_skipped": total_skipped,
            "total_errors": total_errors,
            "results": results,
        }

    def bulk_hold_packages(
        self,
        system_ids: List[int],
        package_names: List[str],
    ) -> Dict[str, Any]:
        """Hold packages across multiple systems."""
        results = []
        total_held = 0
        total_errors = 0

        for system_id in system_ids:
            try:
                result = self.hold_packages(system_id, package_names)
                results.append(result)
                if result["status"] == "success":
                    total_held += result.get("packages_held", 0)
                else:
                    total_errors += 1
            except Exception as e:
                system = self.db.query(System).filter(System.id == system_id).first()
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname if system else str(system_id),
                        "status": "error",
                        "message": str(e),
                        "packages_held": 0,
                    }
                )
                total_errors += 1

        return {
            "total_systems": len(system_ids),
            "total_held": total_held,
            "total_errors": total_errors,
            "results": results,
        }

    def install_specific_versions(
        self,
        system_id: int,
        package_versions: List[tuple],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Install specific package versions via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id,
            lambda: self._install_specific_versions_impl(
                system_id, package_versions, user_id
            ),
        )

    def _install_specific_versions_impl(
        self,
        system_id: int,
        package_versions: List[tuple],
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """PRA-83: Install specific versions of packages (for rollback).

        package_versions: list of (package_name, version) tuples.
        """
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        # Build package=version specifiers per package manager
        if pkg_manager == "apt":
            # apt uses package=version
            specifiers = [
                f"{shlex.quote(name)}={shlex.quote(version)}"
                for name, version in package_versions
            ]
        else:
            # yum/dnf use package-version
            specifiers = [
                f"{shlex.quote(name)}-{shlex.quote(version)}"
                for name, version in package_versions
            ]

        cmd = commands["install_version"].format(packages=" ".join(specifiers))

        # Create rollback history entries
        history_entries = []
        for name, target_version in package_versions:
            pkg = (
                self.db.query(Package)
                .filter(Package.system_id == system_id, Package.name == name)
                .first()
            )
            if not pkg:
                continue
            history = PackageHistory(
                package_id=pkg.id,
                system_id=system_id,
                operation="rollback",
                old_version=pkg.installed_version,
                new_version=target_version,
                status="running",
                performed_at=datetime.utcnow(),
                performed_by=user_id,
            )
            self.db.add(history)
            history_entries.append((history, name, target_version))
        self.db.commit()

        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=600
        )

        if result["status"] not in ("success", "warning"):
            err_msg = result.get("stderr", "") or result.get("error_message", "")
            for entry, _, _ in history_entries:
                entry.status = "failed"
                entry.error_message = f"Rollback failed: {err_msg}"
            self.db.commit()
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Rollback failed: {err_msg}",
                "packages_rolled_back": 0,
            }

        # Re-scan to verify
        self.scan_packages(system_id, refresh=False)

        rolled_back = 0
        for entry, name, target_version in history_entries:
            pkg = (
                self.db.query(Package)
                .filter(Package.system_id == system_id, Package.name == name)
                .first()
            )
            if pkg and pkg.installed_version == target_version:
                entry.status = "completed"
                rolled_back += 1
            else:
                entry.status = "failed"
                entry.error_message = "Package version unchanged after rollback"

        self.db.commit()

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_rolled_back": rolled_back,
            "rolled_back_at": datetime.utcnow().isoformat(),
        }

    def bulk_unhold_packages(
        self,
        system_ids: List[int],
        package_names: List[str],
    ) -> Dict[str, Any]:
        """Unhold packages across multiple systems."""
        results = []
        total_unheld = 0
        total_errors = 0

        for system_id in system_ids:
            try:
                result = self.unhold_packages(system_id, package_names)
                results.append(result)
                if result["status"] == "success":
                    total_unheld += result.get("packages_unheld", 0)
                else:
                    total_errors += 1
            except Exception as e:
                system = self.db.query(System).filter(System.id == system_id).first()
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname if system else str(system_id),
                        "status": "error",
                        "message": str(e),
                        "packages_unheld": 0,
                    }
                )
                total_errors += 1

        return {
            "total_systems": len(system_ids),
            "total_unheld": total_unheld,
            "total_errors": total_errors,
            "results": results,
        }
