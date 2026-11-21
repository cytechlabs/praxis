"""
Repository source management service for managing apt/yum/dnf repos via SSH (PRA-37).
"""

import logging
import re
import shlex
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..db.models import Distro, RepoSource, System
from .ssh_service import SSHService

logger = logging.getLogger(__name__)

# Marker line emitted before each APT source file so the parser can keep file
# boundaries. The leading newline in the shell template guarantees the marker
# starts its own line even when the previous file lacks a trailing newline.
APT_FILE_MARKER = "@@praxis-source-file@@ "

# APT only reads sources.list.d entries whose names use these characters, do not
# start with a dot, and end in a lower-case .list or .sources extension.
_APT_PART_NAME_RE = re.compile(r"[A-Za-z0-9_:-][A-Za-z0-9_.:-]*\.(?:list|sources)")


def apt_list_repos_command(apt_dir: str = "/etc/apt") -> str:
    """Shell command printing every APT source file, each preceded by a marker.

    The main file comes first, then sources.list.d entries in byte order, which
    matches the order APT reads them.
    """
    apt_dir = apt_dir.rstrip("/")
    main = shlex.quote(f"{apt_dir}/sources.list")
    parts = shlex.quote(f"{apt_dir}/sources.list.d")
    marker = shlex.quote("\n" + APT_FILE_MARKER + "%s\n")
    return (
        "{ "
        f"if [ -r {main} ]; then printf {marker} {main}; cat {main}; fi; "
        f"LC_ALL=C find {parts} -maxdepth 1 \\( -type f -o -type l \\) "
        "\\( -name '*.list' -o -name '*.sources' \\) "
        "! -name '.*' ! -name '*[!A-Za-z0-9_.:-]*' -print 2>/dev/null "
        "| LC_ALL=C sort | while IFS= read -r f; do "
        f'printf {marker} "$f"; cat "$f" 2>/dev/null; done; '
        "true; } 2>/dev/null"
    )


APT_LIST_REPOS_COMMAND = apt_list_repos_command()

# Commands for repo operations by package manager
REPO_COMMANDS = {
    "apt": {
        "list_repos": APT_LIST_REPOS_COMMAND,
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

_ONE_LINE_RE = re.compile(
    r"^(?P<type>deb(?:-src)?)\s+(?:\[[^\]]*\]\s+)?(?P<uri>\S+)\s+(?P<suite>\S+)"
    r"(?:\s+(?P<rest>.*))?$"
)
_FALSE_WORDS = {"no", "false", "off", "without", "disable"}
_APT_INT_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)")


def _deb822_enabled(value: Optional[str]) -> bool:
    """Evaluate Enabled the way APT does.

    A value that parses fully as an integer (C strtol, base 0) is false only
    when it is zero. Otherwise the words no, false, off, without and disable
    (any case) are false. Absent or unrecognised values keep the default, true.
    """
    if value is None:
        return True
    text = value.strip()
    if _APT_INT_RE.fullmatch(text):
        digits = text.lstrip("+-")
        if digits[:2].lower() == "0x":
            return int(digits, 16) != 0
        if digits.startswith("0") and set(digits) <= set("01234567"):
            return int(digits, 8) != 0
        if not digits.startswith("0"):
            return True
        # a leading zero with an 8 or 9 stops strtol before the end: not numeric
    return text.lower() not in _FALSE_WORDS


def _looks_like_deb822(text: str) -> bool:
    return any(re.match(r"(?i)^types\s*:", line.strip()) for line in text.split("\n"))


def _deb822_stanzas(text: str) -> List[Dict[str, str]]:
    """Split one file into stanzas of lower-cased field -> folded value."""
    stanzas: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    key: Optional[str] = None
    for raw in text.split("\n"):
        line = raw.rstrip()
        if line.lstrip().startswith("#"):
            continue
        if not line.strip():
            if current:
                stanzas.append(current)
            current, key = {}, None
        elif line[0] in " \t":
            if key is not None and line.strip() != ".":
                current[key] = f"{current[key]} {line.strip()}".strip()
        elif ":" in line:
            name, _, value = line.partition(":")
            key = name.strip().lower()
            current.setdefault(key, value.strip())
    if current:
        stanzas.append(current)
    return stanzas


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

        ssh_repos: List[Dict[str, Any]] = []
        disabled_repos: List[Dict[str, Any]] = []
        if result["status"] in ("success", "warning") and result["stdout"].strip():
            if pkg_manager == "apt":
                ssh_repos, disabled_repos = self._parse_apt_inventory(result["stdout"])
            else:
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
            "disabled_repos": disabled_repos,
        }

    def _parse_repo_output(self, output: str, pkg_manager: str) -> List[Dict[str, str]]:
        """Parse repo listing output."""
        repos = []

        if pkg_manager == "apt":
            repos.extend(self._parse_apt_inventory(output)[0])
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

    def _parse_apt_inventory(
        self, output: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse marker-delimited APT source output into (active, disabled).

        Every file is parsed on its own so stanzas and entries never carry
        over a file boundary. Entries keep the order APT reads them in.
        """
        active: List[Dict[str, Any]] = []
        disabled: List[Dict[str, Any]] = []
        for file_path, text in self._split_apt_files(output):
            if file_path is not None and not self._is_apt_source_path(file_path):
                continue
            if file_path is not None and file_path.endswith(".sources"):
                entries = self._parse_deb822(text, file_path)
            elif file_path is None and _looks_like_deb822(text):
                entries = self._parse_deb822(text, None)
            else:
                entries = self._parse_one_line(text, file_path)
            for entry in entries:
                (active if entry["enabled"] else disabled).append(entry)
        return active, disabled

    @staticmethod
    def _is_apt_source_path(file_path: str) -> bool:
        return bool(_APT_PART_NAME_RE.fullmatch(file_path.rsplit("/", 1)[-1]))

    @staticmethod
    def _split_apt_files(output: str) -> List[Tuple[Optional[str], str]]:
        """Split output on file markers. Text before any marker has no path."""
        files: List[Tuple[Optional[str], List[str]]] = []
        for line in output.splitlines():
            if line.startswith(APT_FILE_MARKER):
                files.append((line[len(APT_FILE_MARKER) :].strip(), []))
            elif files:
                files[-1][1].append(line)
            elif line.strip():
                files.append((None, [line]))
            # leading blank lines before any content are dropped
        return [(path, "\n".join(lines)) for path, lines in files]

    @staticmethod
    def _parse_one_line(text: str, file_path: Optional[str]) -> List[Dict[str, Any]]:
        """Parse classic one-line entries (`deb [opts] uri suite comps...`)."""
        entries = []
        for raw in text.split("\n"):
            line = raw.split("#", 1)[0].strip()
            match = _ONE_LINE_RE.match(line)
            if not match:
                continue
            components = (match.group("rest") or "").split()
            entries.append(
                {
                    "type": match.group("type"),
                    "url": match.group("uri"),
                    "distribution": match.group("suite"),
                    "components": " ".join(components),
                    "enabled": True,
                    "file_path": file_path,
                    "format": "list",
                }
            )
        return entries

    def _parse_deb822(
        self, text: str, file_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Parse a single DEB822 .sources file.

        Entries are expanded per Types x URIs x Suites like APT does. A
        stanza with `Enabled` set to a false value is returned with
        enabled=False; an absent or unrecognised value means enabled.
        """
        entries: List[Dict[str, Any]] = []
        for stanza in _deb822_stanzas(text):
            types = stanza.get("types", "").split()
            uris = stanza.get("uris", "").split()
            suites = stanza.get("suites", "").split()
            if not (types and uris and suites):
                continue
            enabled = _deb822_enabled(stanza.get("enabled"))
            comps = " ".join(stanza.get("components", "").split())
            for repo_type in types:
                for uri in uris:
                    for suite in suites:
                        entries.append(
                            {
                                "type": repo_type,
                                "url": uri,
                                "distribution": suite,
                                "components": "" if suite.endswith("/") else comps,
                                "enabled": enabled,
                                "file_path": file_path,
                                "format": "sources",
                            }
                        )
        return entries

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
