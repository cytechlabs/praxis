"""
Script to populate the command whitelist with common Linux package management commands.
This script adds basic whitelist entries and validation rules for package management operations.
"""

import os
import sys
from datetime import datetime

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session

from app.db.models import (
    CommandDistroMapping,
    CommandValidationRule,
    CommandWhitelist,
    Distro,
    User,
)
from app.db.session import SessionLocal


def get_admin_user(db: Session) -> User:
    """Get or create admin user for script operations.

    Idempotent (start.prod.sh runs this on every boot and documents these seeds
    as idempotent). The real admin username is deployment-specific (default
    ``praxisadmin`` since PRA-304), so the literal ``admin`` lookup usually misses
    and we fall back to a reusable ``system`` placeholder. That fallback must be
    get-or-create: previously it INSERTed unconditionally, so any 2nd+ boot — or a
    restore into a DB that already has the ``system`` user (PRA-264) — hit a
    ``user_email_key`` unique-constraint violation and crashed startup.
    """
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = db.query(User).filter(User.username == "system").first()
    if not admin_user:
        print(
            "Warning: No admin user found. Creating a temporary system user for script operations."
        )
        # Create a system user for script operations
        admin_user = User(
            username="system",
            email="system@localhost",
            hashed_password="system_user",
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
    return admin_user


def create_distros(db: Session):
    """Create basic Linux distributions if they don't exist."""
    distros_data = [
        {
            "name": "Ubuntu",
            "version": "20.04",
            "release_date": "2020-04-23",
            "end_of_life_date": "2025-04-23",
        },
        {
            "name": "Ubuntu",
            "version": "22.04",
            "release_date": "2022-04-21",
            "end_of_life_date": "2027-04-21",
        },
        {
            "name": "Debian",
            "version": "11",
            "release_date": "2021-08-14",
            "end_of_life_date": "2026-08-14",
        },
        {
            "name": "CentOS",
            "version": "8",
            "release_date": "2019-09-24",
            "end_of_life_date": "2024-12-31",
        },
        {
            "name": "RHEL",
            "version": "8",
            "release_date": "2019-05-07",
            "end_of_life_date": "2029-05-31",
        },
        {
            "name": "SUSE",
            "version": "15",
            "release_date": "2018-07-16",
            "end_of_life_date": "2028-07-31",
        },
    ]

    created_distros = {}
    for distro_data in distros_data:
        existing = (
            db.query(Distro)
            .filter(
                Distro.name == distro_data["name"],
                Distro.version == distro_data["version"],
            )
            .first()
        )

        if not existing:
            distro = Distro(
                name=distro_data["name"],
                version=distro_data["version"],
                release_date=datetime.strptime(
                    distro_data["release_date"], "%Y-%m-%d"
                ).date(),
                end_of_life_date=datetime.strptime(
                    distro_data["end_of_life_date"], "%Y-%m-%d"
                ).date(),
            )
            db.add(distro)
            db.commit()
            db.refresh(distro)
            created_distros[f"{distro_data['name']}-{distro_data['version']}"] = distro
            print(f"Created distro: {distro.name} {distro.version}")
        else:
            created_distros[
                f"{distro_data['name']}-{distro_data['version']}"
            ] = existing

    return created_distros


def create_whitelist_entries(db: Session, admin_user: User):
    """Create command whitelist entries for package management."""

    whitelist_entries = [
        # APT commands (Debian/Ubuntu)
        {
            "name": "APT Update",
            "description": "Update package lists",
            "command_pattern": "apt-get update",
            "is_regex": False,
            "risk_level": "low",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 300,
        },
        {
            "name": "APT Upgrade",
            "description": "Upgrade installed packages",
            "command_pattern": "apt-get upgrade",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 1800,
        },
        {
            "name": "APT Install Package",
            "description": "Install specific packages",
            "command_pattern": "apt-get install *",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 600,
        },
        {
            "name": "APT Remove Package",
            "description": "Remove specific packages",
            "command_pattern": "apt-get remove *",
            "is_regex": False,
            "risk_level": "high",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 300,
        },
        {
            "name": "APT Search",
            "description": "Search for packages",
            "command_pattern": "apt-cache search *",
            "is_regex": False,
            "risk_level": "low",
            "category": "package_management",
            "requires_sudo": False,
            "timeout_seconds": 60,
        },
        {
            "name": "APT Show Package Info",
            "description": "Show package information",
            "command_pattern": "apt-cache show *",
            "is_regex": False,
            "risk_level": "low",
            "category": "package_management",
            "requires_sudo": False,
            "timeout_seconds": 30,
        },
        # YUM/DNF commands (RHEL/CentOS)
        {
            "name": "YUM Update",
            "description": "Update package lists and packages",
            "command_pattern": "yum update",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 1800,
        },
        {
            "name": "YUM Install Package",
            "description": "Install specific packages",
            "command_pattern": "yum install *",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 600,
        },
        {
            "name": "YUM Remove Package",
            "description": "Remove specific packages",
            "command_pattern": "yum remove *",
            "is_regex": False,
            "risk_level": "high",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 300,
        },
        {
            "name": "YUM Search",
            "description": "Search for packages",
            "command_pattern": "yum search *",
            "is_regex": False,
            "risk_level": "low",
            "category": "package_management",
            "requires_sudo": False,
            "timeout_seconds": 60,
        },
        # ZYPPER commands (SUSE)
        {
            "name": "Zypper Refresh",
            "description": "Refresh package repositories",
            "command_pattern": "zypper refresh",
            "is_regex": False,
            "risk_level": "low",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 300,
        },
        {
            "name": "Zypper Update",
            "description": "Update packages",
            "command_pattern": "zypper update",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 1800,
        },
        {
            "name": "Zypper Install Package",
            "description": "Install specific packages",
            "command_pattern": "zypper install *",
            "is_regex": False,
            "risk_level": "medium",
            "category": "package_management",
            "requires_sudo": True,
            "timeout_seconds": 600,
        },
        # System information commands
        {
            "name": "List Installed Packages (dpkg)",
            "description": "List installed packages using dpkg",
            "command_pattern": "dpkg -l",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 30,
        },
        {
            "name": "List Installed Packages (rpm)",
            "description": "List installed packages using rpm",
            "command_pattern": "rpm -qa",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 30,
        },
        {
            "name": "System Information",
            "description": "Display system information",
            "command_pattern": "uname -a",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 10,
        },
        {
            "name": "OS Release Information",
            "description": "Display OS release information",
            "command_pattern": "cat /etc/os-release",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 10,
        },
        # Common read-only diagnostic commands (available on every distro)
        {
            "name": "Uptime",
            "description": "Show how long the system has been running",
            "command_pattern": "uptime",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 10,
        },
        {
            "name": "Current User",
            "description": "Show the current user",
            "command_pattern": "whoami",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 5,
        },
        {
            "name": "Hostname",
            "description": "Show the system hostname",
            "command_pattern": "hostname",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 5,
        },
        {
            "name": "Disk Free",
            "description": "Show disk space usage",
            "command_pattern": "df -h",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
        {
            "name": "Memory Free",
            "description": "Show memory usage",
            "command_pattern": "free -h",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 10,
        },
        {
            "name": "Process List",
            "description": "List running processes",
            "command_pattern": "ps aux",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
        {
            "name": "List Directory",
            "description": "List directory contents",
            "command_pattern": "ls *",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
        {
            "name": "Print Working Directory",
            "description": "Show current working directory",
            "command_pattern": "pwd",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 5,
        },
        {
            "name": "Kernel Version",
            "description": "Display kernel version",
            "command_pattern": "uname -r",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 5,
        },
        {
            "name": "Date",
            "description": "Show current date and time",
            "command_pattern": "date",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 5,
        },
        {
            "name": "Read File",
            "description": "Display contents of a file",
            "command_pattern": "cat *",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
        {
            "name": "Tail File",
            "description": "Show last lines of a file",
            "command_pattern": "tail *",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
        {
            "name": "Head File",
            "description": "Show first lines of a file",
            "command_pattern": "head *",
            "is_regex": False,
            "risk_level": "low",
            "category": "system_info",
            "requires_sudo": False,
            "timeout_seconds": 15,
        },
    ]

    created_entries = []
    for entry_data in whitelist_entries:
        # Check if entry already exists
        existing = (
            db.query(CommandWhitelist)
            .filter(CommandWhitelist.name == entry_data["name"])
            .first()
        )

        if not existing:
            entry = CommandWhitelist(
                name=entry_data["name"],
                description=entry_data["description"],
                command_pattern=entry_data["command_pattern"],
                is_regex=entry_data["is_regex"],
                risk_level=entry_data["risk_level"],
                category=entry_data["category"],
                requires_sudo=entry_data["requires_sudo"],
                timeout_seconds=entry_data["timeout_seconds"],
                created_by=admin_user.id,
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            created_entries.append(entry)
            print(f"Created whitelist entry: {entry.name}")
        else:
            created_entries.append(existing)

    return created_entries


def create_distro_mappings(db: Session, whitelist_entries, distros):
    """Create distribution-specific command mappings."""

    mappings = [
        # APT commands for Debian/Ubuntu
        {
            "command_name": "APT Update",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "APT Upgrade",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "APT Install Package",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "APT Remove Package",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "APT Search",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "APT Show Package Info",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        # YUM commands for RHEL/CentOS
        {"command_name": "YUM Update", "distros": ["CentOS-8", "RHEL-8"]},
        {"command_name": "YUM Install Package", "distros": ["CentOS-8", "RHEL-8"]},
        {"command_name": "YUM Remove Package", "distros": ["CentOS-8", "RHEL-8"]},
        {"command_name": "YUM Search", "distros": ["CentOS-8", "RHEL-8"]},
        # ZYPPER commands for SUSE
        {"command_name": "Zypper Refresh", "distros": ["SUSE-15"]},
        {"command_name": "Zypper Update", "distros": ["SUSE-15"]},
        {"command_name": "Zypper Install Package", "distros": ["SUSE-15"]},
        # System info commands for specific distros
        {
            "command_name": "List Installed Packages (dpkg)",
            "distros": ["Ubuntu-20.04", "Ubuntu-22.04", "Debian-11"],
        },
        {
            "command_name": "List Installed Packages (rpm)",
            "distros": ["CentOS-8", "RHEL-8", "SUSE-15"],
        },
    ]

    # Create a lookup for whitelist entries by name
    entry_lookup = {entry.name: entry for entry in whitelist_entries}

    for mapping_data in mappings:
        command_entry = entry_lookup.get(mapping_data["command_name"])
        if not command_entry:
            continue

        for distro_key in mapping_data["distros"]:
            distro = distros.get(distro_key)
            if not distro:
                continue

            # Check if mapping already exists
            existing = (
                db.query(CommandDistroMapping)
                .filter(
                    CommandDistroMapping.command_id == command_entry.id,
                    CommandDistroMapping.distro_id == distro.id,
                )
                .first()
            )

            if not existing:
                mapping = CommandDistroMapping(
                    command_id=command_entry.id,
                    distro_id=distro.id,
                    is_supported=True,
                    notes=f"Default mapping for {distro.name} {distro.version}",
                )
                db.add(mapping)
                print(
                    f"Created distro mapping: {command_entry.name} -> {distro.name} {distro.version}"
                )

    db.commit()


def create_validation_rules(db: Session, admin_user: User):
    """Create validation rules for command security."""

    validation_rules = [
        {
            "name": "Dangerous File Operations",
            "description": "Block dangerous file operations",
            "validation_type": "blacklist",
            "pattern": r"rm\s+-rf\s+/",
            "is_regex": True,
            "severity": "critical",
            "error_message": "Dangerous recursive delete operation detected",
        },
        {
            "name": "Format Commands",
            "description": "Block disk formatting commands",
            "validation_type": "blacklist",
            "pattern": r"(mkfs|fdisk|parted).*",
            "is_regex": True,
            "severity": "critical",
            "error_message": "Disk formatting/partitioning commands are not allowed",
        },
        {
            "name": "Network Configuration",
            "description": "Block network configuration changes",
            "validation_type": "blacklist",
            "pattern": r"(ifconfig|ip\s+route|iptables).*",
            "is_regex": True,
            "severity": "error",
            "error_message": "Network configuration changes are not allowed",
        },
        {
            "name": "Service Management",
            "description": "Warn about service management commands",
            "validation_type": "pattern",
            "pattern": r"(systemctl|service).*",
            "is_regex": True,
            "severity": "warning",
            "error_message": "Service management command detected - use with caution",
        },
        {
            "name": "Sudo Usage",
            "description": "Log sudo command usage",
            "validation_type": "pattern",
            "pattern": r"sudo.*",
            "is_regex": True,
            "severity": "info",
            "error_message": "Command requires elevated privileges",
        },
        # PRA-307: privilege-escalation commands are denied and classified critical
        # even when unwhitelisted (Praxis 1.0 ships no standing user sudo/root;
        # privileged host work runs via named Praxis automation). This critical rule
        # supersedes the informational "Sudo Usage" rule above via most-severe match.
        {
            "name": "Privilege Escalation Commands",
            "description": "Deny interactive privilege escalation (sudo/su/doas/pkexec)",
            "validation_type": "blacklist",
            "pattern": r"(?:^|\s)(?:sudo|su|doas|pkexec)(?:\s|$)",
            "is_regex": True,
            "severity": "critical",
            "error_message": (
                "Privilege escalation is not permitted; privileged host work runs "
                "via named Praxis automation, not interactive sudo/root."
            ),
        },
        # PRA-307: reading secret/credential material is denied and classified
        # critical regardless of a broad file-read whitelist entry (cat/head/tail/ls).
        {
            "name": "Read Sensitive Secret Files",
            "description": (
                "Deny reads of secrets/credentials: /etc/shadow, /etc/sudoers, "
                "/etc/ssh, private keys, .env, kubeconfig, cloud/service credentials"
            ),
            "validation_type": "blacklist",
            "pattern": (
                r"(?:/etc/shadow|/etc/sudoers|/etc/ssh/|id_rsa|id_dsa|id_ecdsa|"
                r"id_ed25519|\.pem\b|\.env\b|kubeconfig|\.kube/config|"
                r"\.aws/credentials|\.docker/config)"
            ),
            "is_regex": True,
            "severity": "critical",
            "error_message": (
                "Reading secret or credential material is not permitted."
            ),
        },
        # PRA-307: the local account database is recon-sensitive — at least medium,
        # still readable (warning) rather than denied.
        {
            "name": "Read Account Database",
            "description": "Escalate reads of the local account database (/etc/passwd)",
            "validation_type": "pattern",
            "pattern": r"/etc/passwd\b",
            "is_regex": True,
            "severity": "warning",
            "error_message": ("Reading the local account database is recon-sensitive."),
        },
        {
            "name": "Package Manager Consistency",
            "description": "Ensure consistent package manager usage",
            "validation_type": "pattern",
            "pattern": r"(apt|yum|dnf|zypper).*",
            "is_regex": True,
            "severity": "info",
            "error_message": "Package manager command detected",
        },
    ]

    for rule_data in validation_rules:
        # Check if rule already exists
        existing = (
            db.query(CommandValidationRule)
            .filter(CommandValidationRule.name == rule_data["name"])
            .first()
        )

        if not existing:
            rule = CommandValidationRule(
                name=rule_data["name"],
                description=rule_data["description"],
                validation_type=rule_data["validation_type"],
                pattern=rule_data["pattern"],
                is_regex=rule_data["is_regex"],
                severity=rule_data["severity"],
                error_message=rule_data["error_message"],
                created_by=admin_user.id,
            )
            db.add(rule)
            print(f"Created validation rule: {rule.name}")

    db.commit()


def main():
    """Main function to populate command whitelist."""
    print("Populating command whitelist and validation rules...")

    db = SessionLocal()
    try:
        # Get admin user
        admin_user = get_admin_user(db)
        print(f"Using user: {admin_user.username}")

        # Create basic distributions
        print("\nCreating Linux distributions...")
        distros = create_distros(db)

        # Create whitelist entries
        print("\nCreating whitelist entries...")
        whitelist_entries = create_whitelist_entries(db, admin_user)

        # Create distribution mappings
        print("\nCreating distribution mappings...")
        create_distro_mappings(db, whitelist_entries, distros)

        # Create validation rules
        print("\nCreating validation rules...")
        create_validation_rules(db, admin_user)

        print(f"\nCompleted! Created:")
        print(f"- {len(distros)} distributions")
        print(f"- {len(whitelist_entries)} whitelist entries")
        print(f"- Distribution mappings")
        print(f"- Validation rules")

    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
