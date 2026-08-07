"""
Repository source management service for managing apt/yum/dnf repos via SSH (PRA-37).
"""

import logging
import re
import shlex
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..db.models import Distro, RepoSource, System
from .ssh_service import SSHService

logger = logging.getLogger(__name__)

# Commands for repo operations by package manager
REPO_COMMANDS = {
    "apt": {
        "list_repos": "find /etc/apt/sources.list.d/ -name '*.list' -o -name '*.sources' 2>/dev/null | xargs cat 2>/dev/null; cat /etc/apt/sources.list 2>/dev/null",
        "sync": "apt-get update",
        "add_repo": 'echo "{entry}" | tee /etc/apt/sources.list.d/{filename}',
        "remove_repo": "rm -f {file_path}",
    },
    "yum": {
        "list_repos": "find /etc/yum.repos.d/ -name '*.repo' 2>/dev/null | xargs cat 2>/dev/null",
        "sync": "yum makecache",
        "remove_repo": "rm -f {file_path}",
    },
    "dnf": {
        "list_repos": "find /etc/yum.repos.d/ -name '*.repo' 2>/dev/null | xargs cat 2>/dev/null",
        "sync": "dnf makecache",
        "remove_repo": "rm -f {file_path}",
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

# Distro-specific repo templates
REPO_TEMPLATES = {
    "ubuntu": [
        {
            "name": "Ubuntu Universe",
            "url": "http://archive.ubuntu.com/ubuntu",
            "components": "universe",
            "description": "Community-maintained open source software",
        },
        {
            "name": "Ubuntu Multiverse",
            "url": "http://archive.ubuntu.com/ubuntu",
            "components": "multiverse",
            "description": "Software with copyright or legal restrictions",
        },
        {
            "name": "Ubuntu Security",
            "url": "http://security.ubuntu.com/ubuntu",
            "components": "main restricted universe multiverse",
            "description": "Security updates",
        },
    ],
    "debian": [
        {
            "name": "Debian Security",
            "url": "http://security.debian.org/debian-security",
            "components": "main contrib non-free",
            "description": "Security updates",
        },
        {
            "name": "Debian Backports",
            "url": "http://deb.debian.org/debian",
            "components": "main contrib non-free",
            "description": "Newer package versions from testing",
        },
    ],
    "centos": [
        {
            "name": "EPEL",
            "url": "https://dl.fedoraproject.org/pub/epel/$releasever/$basearch/",
            "description": "Extra Packages for Enterprise Linux",
        },
        {
            "name": "CentOS Extras",
            "url": "http://mirror.centos.org/centos/$releasever/extras/$basearch/os/",
            "description": "CentOS extra packages",
        },
    ],
    "rhel": [
        {
            "name": "EPEL",
            "url": "https://dl.fedoraproject.org/pub/epel/$releasever/$basearch/",
            "description": "Extra Packages for Enterprise Linux",
        },
    ],
    "rocky": [
        {
            "name": "EPEL",
            "url": "https://dl.fedoraproject.org/pub/epel/$releasever/$basearch/",
            "description": "Extra Packages for Enterprise Linux",
        },
    ],
    "alma": [
        {
            "name": "EPEL",
            "url": "https://dl.fedoraproject.org/pub/epel/$releasever/$basearch/",
            "description": "Extra Packages for Enterprise Linux",
        },
    ],
}


class RepoService:
    """Service for managing package repository sources on remote systems."""

    def __init__(self, db: Session):
        self.db = db
        self.ssh_service = SSHService(db)

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

        raise ValueError(f"Unsupported distribution: {distro.name}")

    def _get_distro_key(self, system: System) -> Optional[str]:
        """Get the distro key for template lookup."""
        distro = self.db.query(Distro).filter(Distro.id == system.distro_id).first()
        if not distro:
            return None
        distro_name = distro.name.lower()
        for key in REPO_TEMPLATES:
            if key in distro_name:
                return key
        return None

    def list_repos(self, system_id: int) -> Dict[str, Any]:
        """
        List configured repos on a system.

        Fetches from SSH and syncs with DB records.
        """
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = REPO_COMMANDS.get(pkg_manager, {})

        # Get repos from SSH
        result = self.ssh_service.execute_command(
            system_id, commands["list_repos"], timeout=30
        )

        ssh_repos = []
        if result["status"] in ("success", "warning") and result["stdout"].strip():
            ssh_repos = self._parse_repo_output(result["stdout"], pkg_manager)

        # Get DB records
        db_repos = (
            self.db.query(RepoSource)
            .filter(RepoSource.system_id == system_id)
            .order_by(RepoSource.name)
            .all()
        )

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "package_manager": pkg_manager,
            "repos": [
                {
                    "id": r.id,
                    "name": r.name,
                    "url": r.url,
                    "repo_type": r.repo_type,
                    "enabled": r.enabled,
                    "file_path": r.file_path,
                    "components": r.components,
                    "distribution": r.distribution,
                }
                for r in db_repos
            ],
            "detected_repos": ssh_repos,
        }

    def _parse_repo_output(self, output: str, pkg_manager: str) -> List[Dict[str, str]]:
        """Parse repo listing output."""
        repos = []

        if pkg_manager == "apt":
            # Try DEB822 format first (Ubuntu 24.04+: .sources files)
            deb822_repos = self._parse_deb822(output)
            if deb822_repos:
                repos.extend(deb822_repos)

            # Also parse traditional one-line format
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # deb http://archive.ubuntu.com/ubuntu jammy main restricted
                match = re.match(r"^(deb(?:-src)?)\s+(\S+)\s+(\S+)\s+(.*)", line)
                if match:
                    repos.append(
                        {
                            "type": match.group(1),
                            "url": match.group(2),
                            "distribution": match.group(3),
                            "components": match.group(4).strip(),
                        }
                    )
        elif pkg_manager in ("yum", "dnf"):
            # Parse INI-style .repo files
            current_repo = {}
            for line in output.strip().split("\n"):
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    if current_repo.get("name"):
                        repos.append(current_repo)
                    current_repo = {"section": line[1:-1]}
                elif "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip().lower()
                    value = value.strip()
                    if key == "name":
                        current_repo["name"] = value
                    elif key == "baseurl":
                        current_repo["url"] = value
                    elif key == "enabled":
                        current_repo["enabled"] = value == "1"
                    elif key == "gpgkey":
                        current_repo["gpg_key_url"] = value
            if current_repo.get("name"):
                repos.append(current_repo)

        return repos

    def _parse_deb822(self, output: str) -> List[Dict[str, str]]:
        """Parse DEB822 .sources format (Ubuntu 24.04+)."""
        repos = []
        current: Dict[str, str] = {}

        for line in output.split("\n"):
            line = line.rstrip()
            if not line:
                if current.get("uris"):
                    # Expand suites into individual entries
                    uris = current.get("uris", "")
                    suites = current.get("suites", "").split()
                    components = current.get("components", "")
                    types = current.get("types", "deb")
                    for suite in suites:
                        repos.append(
                            {
                                "type": types,
                                "url": uris,
                                "distribution": suite,
                                "components": components,
                            }
                        )
                current = {}
                continue
            if ":" in line and not line.startswith(" "):
                key, _, value = line.partition(":")
                current[key.strip().lower()] = value.strip()

        # Handle last entry if no trailing blank line
        if current.get("uris"):
            uris = current.get("uris", "")
            suites = current.get("suites", "").split()
            components = current.get("components", "")
            types = current.get("types", "deb")
            for suite in suites:
                repos.append(
                    {
                        "type": types,
                        "url": uris,
                        "distribution": suite,
                        "components": components,
                    }
                )

        return repos

    def add_repo(self, system_id: int, repo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a repository source to a system."""
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)

        name = repo_data["name"]
        url = repo_data["url"]

        # Check for duplicates
        existing = (
            self.db.query(RepoSource)
            .filter(
                RepoSource.system_id == system_id,
                RepoSource.name == name,
            )
            .first()
        )
        if existing:
            raise ValueError(f"Repository '{name}' already exists on this system")

        # Build the repo file on the remote system
        if pkg_manager == "apt":
            components = repo_data.get("components", "main")
            distribution = repo_data.get("distribution", "")
            if not distribution:
                raise ValueError(
                    "Distribution is required for apt repos "
                    "(e.g. 'noble', 'jammy', 'bookworm')"
                )
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower())
            filename = f"{safe_name}.list"
            file_path = f"/etc/apt/sources.list.d/{filename}"

            # Use printf with escaped args to avoid shell injection
            entry = f"deb {url} {distribution} {components}"
            cmd = f"printf %s {shlex.quote(entry)} > {shlex.quote(file_path)}"
        elif pkg_manager in ("yum", "dnf"):
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "-", name.lower())
            filename = f"{safe_name}.repo"
            file_path = f"/etc/yum.repos.d/{filename}"
            gpg_key = repo_data.get("gpg_key_url", "")

            repo_content = (
                f"[{safe_name}]\n"
                f"name={safe_name}\n"
                f"baseurl={url}\n"
                f"enabled=1\n"
                f"gpgcheck={'1' if gpg_key else '0'}\n"
            )
            if gpg_key:
                repo_content += f"gpgkey={gpg_key}\n"

            cmd = (
                f"printf %s {shlex.quote(repo_content)}" f" > {shlex.quote(file_path)}"
            )
        else:
            raise ValueError(f"Unsupported package manager: {pkg_manager}")

        # Execute on remote system
        result = self.ssh_service.execute_privileged_command(system_id, cmd, timeout=30)

        if result["status"] not in ("success", "warning"):
            raise ValueError(
                f"Failed to add repo on remote system: {result.get('stderr', '')}"
            )

        # Save to DB
        repo = RepoSource(
            system_id=system_id,
            name=name,
            url=url,
            repo_type=pkg_manager,
            enabled=True,
            file_path=file_path,
            gpg_key_url=repo_data.get("gpg_key_url"),
            components=repo_data.get("components"),
            distribution=repo_data.get("distribution"),
        )
        self.db.add(repo)
        self.db.commit()
        self.db.refresh(repo)

        return {
            "id": repo.id,
            "system_id": system_id,
            "name": repo.name,
            "url": repo.url,
            "repo_type": repo.repo_type,
            "file_path": repo.file_path,
            "status": "added",
        }

    def remove_repo(self, system_id: int, repo_id: int) -> Dict[str, Any]:
        """Remove a repository source from a system."""
        self._get_system_or_raise(system_id)

        repo = (
            self.db.query(RepoSource)
            .filter(RepoSource.id == repo_id, RepoSource.system_id == system_id)
            .first()
        )
        if not repo:
            raise ValueError(f"Repository with ID {repo_id} not found on this system")

        # Remove file from remote system
        if repo.file_path:
            pkg_manager = repo.repo_type
            commands = REPO_COMMANDS.get(pkg_manager, {})
            cmd = commands.get("remove_repo", "").format(
                file_path=shlex.quote(repo.file_path)
            )

            if cmd:
                result = self.ssh_service.execute_privileged_command(
                    system_id, cmd, timeout=30
                )
                if result["status"] not in ("success", "warning"):
                    logger.warning(
                        "Failed to remove repo file %s: %s",
                        repo.file_path,
                        result.get("stderr", ""),
                    )

        # Remove from DB
        repo_name = repo.name
        self.db.delete(repo)
        self.db.commit()

        return {
            "system_id": system_id,
            "repo_id": repo_id,
            "name": repo_name,
            "status": "removed",
        }

    def sync_repos(self, system_id: int) -> Dict[str, Any]:
        """Run repo sync (apt update / yum makecache) on a system."""
        system = self._get_system_or_raise(system_id)
        pkg_manager = self._get_pkg_manager(system)
        commands = REPO_COMMANDS.get(pkg_manager, {})

        result = self.ssh_service.execute_privileged_command(
            system_id, commands["sync"], timeout=120
        )

        return {
            "system_id": system_id,
            "hostname": system.hostname,
            "status": (
                "success" if result["status"] in ("success", "warning") else "error"
            ),
            "message": result.get("stdout", "")[:500],
            "error": (
                result.get("stderr", "")[:500] if result["status"] == "failed" else None
            ),
            "synced_at": datetime.utcnow().isoformat(),
        }

    def get_templates(self, system_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Get distro-specific repo templates.

        If system_id is provided, returns templates for that system's distro.
        Otherwise returns all templates.
        """
        if system_id:
            system = self._get_system_or_raise(system_id)
            distro_key = self._get_distro_key(system)
            if distro_key and distro_key in REPO_TEMPLATES:
                return {
                    "distro": distro_key,
                    "templates": REPO_TEMPLATES[distro_key],
                }
            return {"distro": distro_key, "templates": []}

        return {"templates": REPO_TEMPLATES}
