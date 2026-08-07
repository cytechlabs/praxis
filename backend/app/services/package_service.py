"""
Package management service for scanning, listing, and updating packages via SSH.
"""

import logging
import re
import shlex
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from sqlalchemy import false, func
from sqlalchemy.orm import Session

from ..db.models import Distro, Package, PackageHistory, PackageUpdate, System, User
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

# Package manager commands by distro family
PKG_COMMANDS = {
    "apt": {
        "list_installed": "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' | grep 'install ok installed'",
        "check_updates": "apt list --upgradable 2>/dev/null | tail -n +2",
        "check_security": "apt list --upgradable 2>/dev/null | grep -i security | tail -n +2",
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
    "ubuntu": "apt",
    "debian": "apt",
    "centos": "yum",
    "rhel": "yum",
    "red hat": "yum",
    "rocky": "dnf",
    "alma": "dnf",
    "almalinux": "dnf",
    "fedora": "dnf",
    "oracle": "yum",
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

    def scan_scope(
        self, targets: List[Tuple[int, str]], *, security: bool = False
    ) -> Dict[str, Any]:
        """Run the existing single-host scan across a resolved cohort of hosts.

        ``targets`` is the already-resolved, fleet-scoped ``(system_id, hostname)``
        snapshot (the route resolves and snapshots it). Each host is scanned
        independently: a per-host failure or an ``already_running`` skip never
        aborts the cohort, so partial results are the normal, visible outcome.
        Returns aggregate counts plus a per-host status list.
        """
        results: List[Dict[str, Any]] = []
        success = failure = skipped = 0
        for system_id, hostname in targets:
            try:
                summary = (
                    self.scan_security_updates(system_id)
                    if security
                    else self.scan_packages(system_id)
                )
                status = summary.get("status", "error")
                message = summary.get("message")
            except SSHConnectionError as e:
                status, message = "error", str(e)
            except Exception as e:  # pylint: disable=broad-except
                logger.warning("Cohort scan failed for system %s: %s", system_id, e)
                status, message = "error", str(e)

            if status == "success":
                success += 1
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
                }
            )

        return {
            "total": len(targets),
            "success_count": success,
            "failure_count": failure,
            "skipped_count": skipped,
            "results": results,
        }

    def scan_packages(self, system_id: int) -> Dict[str, Any]:
        """Scan a system for installed packages via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id, lambda: self._scan_packages_impl(system_id)
        )

    def _scan_packages_impl(self, system_id: int) -> Dict[str, Any]:
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

        if not self._ssh_result_ok(result):
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Failed to scan packages: {result.get('stderr', '').strip() or 'no output from remote host'}",
                "packages_found": 0,
            }

        # Parse output based on package manager
        packages = self._parse_installed_packages(result["stdout"], pkg_manager)

        # Upsert packages into DB
        added, updated = self._upsert_packages(
            system_id, packages, pkg_manager, scanned_at=scanned_at
        )

        # Now check for available updates
        update_result = self.ssh_service.execute_command(
            system_id, commands["check_updates"], timeout=120
        )

        updates_found = 0
        if self._ssh_result_ok(update_result):
            updates = self._parse_available_updates(
                update_result["stdout"], pkg_manager
            )
            updates_found = self._upsert_updates(system_id, updates, pkg_manager)
        else:
            logger.warning(
                "Update check failed for system %s: %s",
                system_id,
                update_result.get("stderr", "").strip() or "no output",
            )

        # Mark system as audited so dashboard "stale scan" check is accurate. Same
        # timestamp the package rows were stamped with above (PRA-314).
        system.last_audited = scanned_at
        self.db.commit()

        # Notification: package scan complete (PRA-99)
        from .notification_service import create_notification

        create_notification(
            self.db,
            type="package_scan_complete",
            title=f"Package scan complete: {system.hostname}",
            message=(
                f"Found {len(packages)} packages, {updates_found} updates available"
            ),
            severity="info",
        )

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_found": len(packages),
            "packages_added": added,
            "packages_updated": updated,
            "updates_available": updates_found,
            "scanned_at": scanned_at.isoformat(),
        }

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

    def scan_security_updates(self, system_id: int) -> Dict[str, Any]:
        """Scan a system for security updates via SSH (per-host single-flight)."""
        return self._single_flight(
            system_id, lambda: self._scan_security_updates_impl(system_id)
        )

    def _scan_security_updates_impl(self, system_id: int) -> Dict[str, Any]:
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = self._get_commands(pkg_manager)

        result = self.ssh_service.execute_command(
            system_id, commands["check_security"], timeout=120
        )

        if not self._ssh_result_ok(result):
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Failed to scan security updates: {result.get('stderr', '').strip() or 'no output from remote host'}",
                "packages_found": 0,
                "packages_added": 0,
                "packages_updated": 0,
                "updates_available": 0,
            }

        updates = self._parse_available_updates(result["stdout"], pkg_manager)
        for upd in updates:
            upd["type"] = "security"

        updates_found = self._upsert_security_updates(system_id, updates, pkg_manager)

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

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_found": 0,
            "packages_added": 0,
            "packages_updated": 0,
            "updates_available": updates_found,
            "scanned_at": datetime.utcnow().isoformat(),
        }

    def _upsert_security_updates(
        self, system_id: int, updates: List[Dict[str, str]], pkg_manager: str
    ) -> int:
        count = 0
        for upd in updates:
            pkg = (
                self.db.query(Package)
                .filter(Package.system_id == system_id, Package.name == upd["name"])
                .first()
            )
            if not pkg:
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
        return count

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

        if result["status"] not in ("success", "warning"):
            err_msg = result.get("stderr", "") or result.get("error_message", "")
            for entry in history_entries:
                entry.status = "failed"
                entry.error_message = f"Security update failed: {err_msg}"
            self.db.commit()
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Security update failed: {err_msg}",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
            }

        self.scan_packages(system_id)

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

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_updated": completed,
            "packages_skipped": packages_skipped,
            "applied_at": datetime.utcnow().isoformat(),
        }

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

        if result["status"] not in ("success", "warning"):
            err_msg = result.get("stderr", "") or result.get("error_message", "")
            for entry in history_entries:
                entry.status = "failed"
                entry.error_message = f"Remove failed: {err_msg}"
            self.db.commit()
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Remove failed: {err_msg}",
                "packages_removed": 0,
                "packages_skipped": packages_skipped,
            }

        self.scan_packages(system_id)

        still_installed = {
            p.name
            for p in self.db.query(Package)
            .filter(
                Package.system_id == system_id,
                Package.name.in_(removable_names),
            )
            .all()
        }

        completed = 0
        for i, entry in enumerate(history_entries):
            pkg_name = removable_names[i]
            if pkg_name not in still_installed:
                entry.status = "completed"
                completed += 1
            else:
                entry.status = "failed"
                entry.error_message = "Package still installed after remove"

        for pkg_name in removable_names:
            if pkg_name not in still_installed:
                self.db.query(Package).filter(
                    Package.system_id == system_id,
                    Package.name == pkg_name,
                ).delete()

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

        packages_skipped = 0
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
            packages_skipped = len(held)
            package_names = [n for n in package_names if n not in held]
            if not package_names:
                return {
                    "system_id": system_id,
                    "hostname": system.hostname,
                    "status": "success",
                    "message": "All requested packages are held",
                    "packages_updated": 0,
                    "packages_skipped": packages_skipped,
                }
            cmd = commands["apply_update"].format(
                packages=" ".join(shlex.quote(p) for p in package_names)
            )
        else:
            held = {
                p.name
                for p in self.db.query(Package)
                .filter(
                    Package.system_id == system_id,
                    Package.is_held.is_(True),
                )
                .all()
            }
            packages_skipped = len(held)
            updatable = (
                self.db.query(PackageUpdate)
                .join(Package)
                .filter(
                    PackageUpdate.system_id == system_id,
                    ~Package.name.in_(held) if held else True,
                )
                .all()
            )
            if updatable:
                names = list({u.package.name for u in updatable})
                package_names = names
                cmd = commands["apply_update"].format(
                    packages=" ".join(shlex.quote(n) for n in names)
                )
            else:
                cmd = commands["apply_all"]

        # Create pending history entries before running the command
        history_entries = self._create_pending_history(
            system_id, package_names, user_id, job_history_id=job_history_id
        )

        # Mark as running
        for entry in history_entries:
            entry.status = "running"
        self.db.commit()

        result = self.ssh_service.execute_privileged_command(
            system_id, cmd, timeout=600
        )

        if result["status"] not in ("success", "warning"):
            err_msg = result.get("stderr", "") or result.get("error_message", "")
            for entry in history_entries:
                entry.status = "failed"
                entry.error_message = f"Update failed: {err_msg}"
            self.db.commit()
            return {
                "system_id": system_id,
                "hostname": system.hostname,
                "status": "error",
                "message": f"Update failed: {err_msg}",
                "packages_updated": 0,
                "packages_skipped": packages_skipped,
            }

        # Re-scan to sync DB with actual system state
        self.scan_packages(system_id)

        # Check which packages actually updated
        completed = 0
        for entry in history_entries:
            pkg = self.db.query(Package).filter(Package.id == entry.package_id).first()
            if pkg and pkg.installed_version == entry.new_version:
                entry.status = "completed"
                completed += 1
            else:
                entry.status = "failed"
                entry.error_message = "Package version unchanged after update"

        # Clean up applied PackageUpdate rows
        self._cleanup_applied_updates(system_id, package_names)

        system.last_successful_update = datetime.utcnow()
        self.db.commit()

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": "success",
            "packages_updated": completed,
            "packages_skipped": packages_skipped,
            "applied_at": datetime.utcnow().isoformat(),
        }

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
                system = self.db.query(System).filter(System.id == system_id).first()
                results.append(
                    {
                        "system_id": system_id,
                        "hostname": system.hostname if system else str(system_id),
                        "status": "error",
                        "message": str(e),
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
        self.scan_packages(system_id)

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
