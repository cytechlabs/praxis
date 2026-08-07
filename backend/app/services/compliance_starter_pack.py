"""Built-in compliance starter pack metadata.

Pure data — no behavior. ``seed_starter_pack`` in
``compliance_service`` reads ``STARTER_PACK`` and inserts any policy
whose ``starter_pack_key`` is not yet present.

This module is INTENTIONALLY careful about wording:

* These are CIS-aligned spot checks. They are not a compliance
  attestation, not a complete CIS profile, and not a Praxis claim
  that running them produces certifiable evidence. The descriptions
  and remediation guidance must keep that language explicit.
* Checks describe their prerequisites in operator terms: fact-shaped
  checks require host facts, file/command-shaped checks require file
  probe evidence. Checks whose evidence is not yet available surface
  through the read APIs as deferred via ``runner_status`` /
  ``runner_owner`` (customer-facing copy must stay in product terms,
  never internal ticket or implementation history).
"""

from __future__ import annotations

from typing import Any, Dict, List

# Each policy dict is normalized by the seeder; checks reference the
# kinds validated in ``compliance_service.KNOWN_CHECK_KINDS``.
STARTER_PACK: List[Dict[str, Any]] = [
    {
        "starter_pack_key": "cis-package-hygiene-v1",
        "slug": "package-hygiene",
        "name": "Package Hygiene — Legacy & Insecure Services",
        "description": (
            "CIS-aligned spot checks for legacy clear-text services and "
            "core hardening packages. Not a complete CIS profile."
        ),
        "category": "package-hygiene",
        "severity": "high",
        "schedule_interval_hours": 24,
        "evidence_retention_days": 90,
        "remediation_guidance": (
            "Remove clear-text remote-access packages (telnet, rsh, talk) "
            "and ensure the host's auditing + secure-shell packages are "
            "installed. This list is illustrative and not a complete CIS "
            "Level 1 profile."
        ),
        "checks": [
            {
                "slug": "telnet-absent",
                "title": "Legacy telnet client must not be installed",
                "kind": "package_absent",
                "definition": {"package": "telnet"},
                "severity_override": "high",
                "display_order": 10,
                "remediation_guidance": (
                    "Remove the legacy telnet client; use ssh instead."
                ),
            },
            {
                "slug": "rsh-client-absent",
                "title": "Legacy rsh-client must not be installed",
                "kind": "package_absent",
                "definition": {"package": "rsh-client"},
                "display_order": 20,
                "remediation_guidance": (
                    "Remove rsh-client; clear-text remote shells are "
                    "unauthenticated and unencrypted."
                ),
            },
            {
                "slug": "talk-absent",
                "title": "Legacy talk client must not be installed",
                "kind": "package_absent",
                "definition": {"package": "talk"},
                "display_order": 30,
            },
            {
                "slug": "openssh-server-installed",
                "title": "OpenSSH server should be installed",
                "kind": "package_installed",
                "definition": {"package": "openssh-server"},
                "display_order": 40,
            },
            {
                "slug": "auditd-installed",
                "title": "auditd should be installed for local audit logging",
                "kind": "package_installed",
                "definition": {"package": "auditd"},
                "display_order": 50,
            },
        ],
    },
    {
        "starter_pack_key": "cis-ssh-baseline-v1",
        "slug": "ssh-baseline",
        "name": "SSH Baseline — Server Configuration",
        "description": (
            "CIS-aligned spot checks for sshd configuration. Fact-shaped "
            "checks require host facts; file-shaped checks require file "
            "probe evidence."
        ),
        "category": "access-control",
        "severity": "high",
        "schedule_interval_hours": 24,
        "evidence_retention_days": 180,
        "remediation_guidance": (
            "Disable direct root SSH login and password authentication. "
            "Ensure /etc/ssh/sshd_config permissions are 0600. This is a "
            "spot check, not a full SSH hardening review."
        ),
        "checks": [
            {
                "slug": "permit-root-login-disabled",
                "title": "sshd_config PermitRootLogin must be 'no'",
                "kind": "fact_equals",
                "definition": {
                    "fact_key": "ssh.config.PermitRootLogin",
                    "expected": "no",
                },
                "severity_override": "high",
                "display_order": 10,
            },
            {
                "slug": "password-authentication-disabled",
                "title": "sshd_config PasswordAuthentication must be 'no'",
                "kind": "fact_equals",
                "definition": {
                    "fact_key": "ssh.config.PasswordAuthentication",
                    "expected": "no",
                },
                "severity_override": "high",
                "display_order": 20,
            },
            {
                "slug": "sshd-config-exists",
                "title": "/etc/ssh/sshd_config must be present",
                "kind": "file_exists",
                "definition": {"path": "/etc/ssh/sshd_config"},
                "display_order": 30,
                "remediation_guidance": (
                    "Reinstall openssh-server if the configuration file is "
                    "missing. This check requires file probe evidence."
                ),
            },
        ],
    },
    {
        "starter_pack_key": "cis-kernel-baseline-v1",
        "slug": "kernel-baseline",
        "name": "Kernel Baseline — sysctl Hardening Spot Checks",
        "description": (
            "Spot checks for a small subset of CIS-recommended sysctl "
            "values. These checks require host facts."
        ),
        "category": "kernel-baseline",
        "severity": "medium",
        "schedule_interval_hours": 24,
        "evidence_retention_days": 90,
        "checks": [
            {
                "slug": "randomize-va-space",
                "title": "kernel.randomize_va_space must be 2 (full ASLR)",
                "kind": "fact_equals",
                "definition": {
                    "fact_key": "sysctl.kernel.randomize_va_space",
                    "expected": "2",
                },
                "display_order": 10,
            },
            {
                "slug": "ip-forward-disabled",
                "title": "net.ipv4.ip_forward must be 0 on non-router hosts",
                "kind": "fact_equals",
                "definition": {
                    "fact_key": "sysctl.net.ipv4.ip_forward",
                    "expected": "0",
                },
                "display_order": 20,
                "remediation_guidance": (
                    "Disable IP forwarding unless the host intentionally "
                    "routes traffic. Override on dedicated routers."
                ),
            },
            {
                "slug": "rp-filter-enabled",
                "title": "net.ipv4.conf.all.rp_filter must be 1",
                "kind": "fact_equals",
                "definition": {
                    "fact_key": "sysctl.net.ipv4.conf.all.rp_filter",
                    "expected": "1",
                },
                "display_order": 30,
            },
        ],
    },
    {
        "starter_pack_key": "cis-account-baseline-v1",
        "slug": "account-baseline",
        "name": "Account Baseline — Password & Account Hygiene",
        "description": (
            "Spot checks for account-related configuration files. All "
            "checks in this starter policy require file probe evidence."
        ),
        "category": "access-control",
        "severity": "medium",
        "schedule_interval_hours": 168,
        "evidence_retention_days": 90,
        "checks": [
            {
                "slug": "sudoers-present",
                "title": "/etc/sudoers must be present",
                "kind": "file_exists",
                "definition": {"path": "/etc/sudoers"},
                "display_order": 10,
            },
            {
                "slug": "passwd-present",
                "title": "/etc/passwd must be present",
                "kind": "file_exists",
                "definition": {"path": "/etc/passwd"},
                "display_order": 20,
            },
            {
                "slug": "shadow-present",
                "title": "/etc/shadow must be present",
                "kind": "file_exists",
                "definition": {"path": "/etc/shadow"},
                "display_order": 30,
                "remediation_guidance": (
                    "If /etc/shadow is missing, the account database is "
                    "corrupted; restore from backup before further changes."
                ),
            },
        ],
    },
]


def starter_pack_keys() -> List[str]:
    """Stable list of starter_pack_key values for introspection / tests."""
    return [item["starter_pack_key"] for item in STARTER_PACK]
