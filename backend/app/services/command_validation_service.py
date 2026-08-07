"""
Command validation service for managing command whitelists and validation rules.
Provides comprehensive command validation, pattern matching, and security checks.
"""

import re
from typing import Any, Dict, List, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ..db.models import (
    CommandDistroMapping,
    CommandValidationLog,
    CommandValidationRule,
    CommandWhitelist,
    System,
)

# PRA-306: risk classification is separate from (but connected to) validation.
# The whitelist entry is the risk BASELINE for a known allowed command; validation
# rules may ESCALATE risk but never downgrade below the whitelist baseline. Ordered
# so ``_max_risk`` can compare.
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# A matched validation rule has only a ``severity`` (no explicit risk field), so its
# severity maps to a risk contribution. This is used both to escalate an allowed
# command's risk and to classify a DENIED command for audit (a matching critical rule
# on an unwhitelisted `rm -rf /` should record ``critical``, not ``unknown``).
_RULE_SEVERITY_RISK = {"critical": "critical", "error": "high", "warning": "medium"}

# Explicit severity ordering so the MOST SEVERE matching rule wins, instead of the
# database's string ORDER BY (which sorts "warning" above "critical").
_SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def _max_risk(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """The higher-severity of two risk levels. Unknown/None ranks below ``low`` so a
    known baseline always wins over it, and neither input is ever downgraded."""
    ra = _RISK_ORDER.get(a or "", -1)
    rb = _RISK_ORDER.get(b or "", -1)
    return a if ra >= rb else b


class CommandValidationService:
    """Service for command validation and whitelist management."""

    def __init__(self, db: Session):
        self.db = db

    def validate_command(
        self,
        raw_command: str,
        system_id: int,
        user_id: int,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a command against whitelist and validation rules.

        Args:
            raw_command: The raw command to validate
            system_id: ID of the target system
            user_id: ID of the user executing the command
            session_id: Optional session identifier
            ip_address: Optional IP address of the user
            user_agent: Optional user agent string

        Returns:
            Dict containing validation result with status, reason, and matched command info
        """
        # Get system and distro information
        system = self.db.query(System).filter(System.id == system_id).first()
        if not system:
            return self._create_validation_result(
                "denied",
                "System not found",
                raw_command,
                system_id,
                user_id,
                session_id,
                ip_address,
                user_agent,
            )

        # Normalize the command
        normalized_command = self._normalize_command(raw_command)

        # Check against whitelist
        whitelist_result = self._check_whitelist(normalized_command, system.distro_id)

        # PRA-306: the whitelist match (if any) is the risk baseline. Even on a
        # whitelist denial (e.g. unsupported for this distro) we persist whatever
        # classification the matched entry provided; a no-match denial has none.
        baseline_risk = whitelist_result.get("risk_level")
        requires_sudo = whitelist_result.get("requires_sudo")
        category = whitelist_result.get("category")

        # Evaluate validation rules regardless of the whitelist decision. On a
        # whitelist denial this is AUDIT CLASSIFICATION ONLY — it never allows the
        # command; it lets a matching rule's severity classify an otherwise
        # unclassified denial (e.g. an unwhitelisted `rm -rf /` matched by an active
        # critical rule records ``critical`` instead of ``unknown``).
        rule_result = self._check_validation_rules(normalized_command)
        matched_rule_id = rule_result.get("rule_id")
        rule_risk = _RULE_SEVERITY_RISK.get(rule_result.get("severity") or "")

        if whitelist_result["status"] == "denied":
            return self._create_validation_result(
                "denied",
                whitelist_result["reason"],
                raw_command,
                system_id,
                user_id,
                session_id,
                ip_address,
                user_agent,
                normalized_command,
                whitelist_result.get("command_id"),
                matched_rule_id,
                risk_level=_max_risk(baseline_risk, rule_risk),
                requires_sudo=requires_sudo,
                category=category,
            )

        # Whitelist allowed. A warning rule may ESCALATE risk above the baseline but
        # never downgrade it; a rule denial keeps the (baseline + rule) classification.
        final_status = "allowed"
        final_reason = "Command passed all validation checks"
        effective_risk = baseline_risk

        if rule_result["status"] == "warning":
            final_status = "warning"
            final_reason = rule_result["reason"]
            effective_risk = _max_risk(baseline_risk, rule_risk)
        elif rule_result["status"] == "denied":
            final_status = "denied"
            final_reason = rule_result["reason"]
            effective_risk = _max_risk(baseline_risk, rule_risk)

        return self._create_validation_result(
            final_status,
            final_reason,
            raw_command,
            system_id,
            user_id,
            session_id,
            ip_address,
            user_agent,
            normalized_command,
            whitelist_result.get("command_id"),
            matched_rule_id,
            risk_level=effective_risk,
            requires_sudo=requires_sudo,
            category=category,
        )

    def _normalize_command(self, command: str) -> str:
        """Normalize command by removing extra whitespace and standardizing format."""
        # Remove leading/trailing whitespace and collapse multiple spaces
        normalized = re.sub(r"\s+", " ", command.strip())
        return normalized

    def _entry_meta(self, entry: CommandWhitelist) -> Dict[str, Any]:
        """PRA-306: the matched whitelist entry's classification — the risk BASELINE
        for a known allowed command. Carried through validation so execution records
        and API responses can show a real risk instead of ``unknown``."""
        return {
            "risk_level": entry.risk_level,
            "requires_sudo": bool(entry.requires_sudo),
            "category": entry.category,
            "requires_approval": bool(entry.requires_approval),
            "timeout_seconds": entry.timeout_seconds,
        }

    def _check_whitelist(self, command: str, distro_id: int) -> Dict[str, Any]:
        """Check if command matches whitelist patterns."""
        # Get active whitelist entries
        whitelist_entries = (
            self.db.query(CommandWhitelist)
            .filter(CommandWhitelist.is_active.is_(True))
            .all()
        )

        for entry in whitelist_entries:
            # Check if command matches the pattern
            if self._matches_pattern(command, entry.command_pattern, entry.is_regex):
                meta = self._entry_meta(entry)
                # Check distribution-specific mappings
                distro_mapping = (
                    self.db.query(CommandDistroMapping)
                    .filter(
                        and_(
                            CommandDistroMapping.command_id == entry.id,
                            CommandDistroMapping.distro_id == distro_id,
                            CommandDistroMapping.is_supported.is_(True),
                        )
                    )
                    .first()
                )

                if distro_mapping:
                    # Use distribution-specific command if available
                    if distro_mapping.command_override:
                        return {
                            "status": "allowed",
                            "reason": f"Command matches whitelist entry: {entry.name}",
                            "command_id": entry.id,
                            "override_command": distro_mapping.command_override,
                            **meta,
                        }
                    return {
                        "status": "allowed",
                        "reason": f"Command matches whitelist entry: {entry.name}",
                        "command_id": entry.id,
                        **meta,
                    }

                # Check if there are any distro mappings for this command
                has_distro_mappings = (
                    self.db.query(CommandDistroMapping)
                    .filter(CommandDistroMapping.command_id == entry.id)
                    .first()
                ) is not None

                if not has_distro_mappings:
                    # No distro-specific mappings, allow for all distros
                    return {
                        "status": "allowed",
                        "reason": f"Command matches whitelist entry: {entry.name}",
                        "command_id": entry.id,
                        **meta,
                    }

                # Has distro mappings but not for this distro. Denied, but we still
                # carry the matched entry's classification so the denial record is
                # auditable rather than ``unknown``.
                return {
                    "status": "denied",
                    "reason": "Command not supported for this distribution",
                    "command_id": entry.id,
                    **meta,
                }

        return {"status": "denied", "reason": "Command not found in whitelist"}

    def _check_validation_rules(self, command: str) -> Dict[str, Any]:
        """Check command against validation rules.

        Selects the MOST SEVERE matching rule (PRA-307). The previous
        ``ORDER BY severity DESC`` relied on string ordering, which ranks
        ``warning`` above ``critical`` — a warning rule could shadow a critical
        deny for a command that matched both. We now compare by an explicit rank so
        the strongest guardrail always wins.
        """
        best_rule = None
        best_rank = -1
        for rule in (
            self.db.query(CommandValidationRule)
            .filter(CommandValidationRule.is_active.is_(True))
            .all()
        ):
            if not self._matches_pattern(command, rule.pattern, rule.is_regex):
                continue
            rank = _SEVERITY_RANK.get(rule.severity, -1)
            if rank > best_rank:
                best_rule, best_rank = rule, rank

        if best_rule is None:
            return {"status": "allowed", "reason": "No validation rules triggered"}

        if best_rule.severity in ("critical", "error"):
            status = "denied"
            default_reason = f"Command violates validation rule: {best_rule.name}"
        elif best_rule.severity == "warning":
            status = "warning"
            default_reason = f"Command triggers warning rule: {best_rule.name}"
        else:
            # info (or unrecognised): record the matched rule for audit but neither
            # deny nor escalate risk (no classification contribution).
            status = "allowed"
            default_reason = f"Command matches informational rule: {best_rule.name}"

        return {
            "status": status,
            "reason": best_rule.error_message or default_reason,
            "rule_id": best_rule.id,
            "severity": best_rule.severity,
        }

    def _matches_pattern(self, command: str, pattern: str, is_regex: bool) -> bool:
        """Check if command matches a pattern."""
        if is_regex:
            try:
                return bool(re.search(pattern, command, re.IGNORECASE))
            except re.error:
                # Invalid regex pattern, treat as literal string
                return pattern.lower() in command.lower()

        # Simple string matching with wildcards
        pattern_regex = pattern.replace("*", ".*").replace("?", ".")
        try:
            return bool(re.match(f"^{pattern_regex}$", command, re.IGNORECASE))
        except re.error:
            # Fallback to simple substring matching
            return pattern.lower() in command.lower()

    def _create_validation_result(
        self,
        status: str,
        reason: str,
        raw_command: str,
        system_id: int,
        user_id: int,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        normalized_command: Optional[str] = None,
        command_id: Optional[int] = None,
        validation_rule_id: Optional[int] = None,
        risk_level: Optional[str] = None,
        requires_sudo: Optional[bool] = None,
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create validation result and log the attempt."""

        # Log the validation attempt
        log_entry = CommandValidationLog(
            command_id=command_id,
            validation_rule_id=validation_rule_id,
            system_id=system_id,
            raw_command=raw_command,
            normalized_command=normalized_command,
            validation_status=status,
            validation_reason=reason,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.add(log_entry)
        self.db.commit()

        # PRA-306: propagate the resolved risk classification so the executor can
        # persist it. ``risk_level`` is None only when nothing classified the
        # command (e.g. no whitelist match) — the executor maps that to ``unknown``.
        return {
            "status": status,
            "reason": reason,
            "raw_command": raw_command,
            "normalized_command": normalized_command,
            "log_id": log_entry.id,
            "command_id": command_id,
            "validation_rule_id": validation_rule_id,
            "risk_level": risk_level,
            "requires_sudo": requires_sudo,
            "category": category,
        }

    def add_whitelist_entry(
        self,
        name: str,
        command_pattern: str,
        category: str,
        risk_level: str,
        user_id: int,
        description: Optional[str] = None,
        is_regex: bool = False,
        requires_sudo: bool = False,
        timeout_seconds: int = 30,
    ) -> CommandWhitelist:
        """Add a new command to the whitelist."""

        whitelist_entry = CommandWhitelist(
            name=name,
            description=description,
            command_pattern=command_pattern,
            is_regex=is_regex,
            risk_level=risk_level,
            category=category,
            requires_sudo=requires_sudo,
            timeout_seconds=timeout_seconds,
            created_by=user_id,
        )

        self.db.add(whitelist_entry)
        self.db.commit()
        self.db.refresh(whitelist_entry)

        return whitelist_entry

    def add_distro_mapping(
        self,
        command_id: int,
        distro_id: int,
        distro_version_pattern: Optional[str] = None,
        command_override: Optional[str] = None,
        is_supported: bool = True,
        notes: Optional[str] = None,
    ) -> CommandDistroMapping:
        """Add distribution-specific mapping for a command."""

        mapping = CommandDistroMapping(
            command_id=command_id,
            distro_id=distro_id,
            distro_version_pattern=distro_version_pattern,
            command_override=command_override,
            is_supported=is_supported,
            notes=notes,
        )

        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)

        return mapping

    def add_validation_rule(
        self,
        name: str,
        validation_type: str,
        pattern: str,
        severity: str,
        user_id: int,
        description: Optional[str] = None,
        is_regex: bool = False,
        error_message: Optional[str] = None,
    ) -> CommandValidationRule:
        """Add a new validation rule."""

        rule = CommandValidationRule(
            name=name,
            description=description,
            validation_type=validation_type,
            pattern=pattern,
            is_regex=is_regex,
            severity=severity,
            error_message=error_message,
            created_by=user_id,
        )

        self.db.add(rule)
        self.db.commit()
        self.db.refresh(rule)

        return rule

    def get_whitelist_entries(
        self,
        category: Optional[str] = None,
        risk_level: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[CommandWhitelist]:
        """Get whitelist entries with optional filtering."""

        query = self.db.query(CommandWhitelist)

        if category:
            query = query.filter(CommandWhitelist.category == category)
        if risk_level:
            query = query.filter(CommandWhitelist.risk_level == risk_level)
        if is_active is not None:
            query = query.filter(CommandWhitelist.is_active == is_active)

        return query.all()

    def get_validation_logs(
        self,
        system_id: Optional[int] = None,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[CommandValidationLog]:
        """Get validation logs with optional filtering."""

        query = self.db.query(CommandValidationLog)

        if system_id:
            query = query.filter(CommandValidationLog.system_id == system_id)
        if user_id:
            query = query.filter(CommandValidationLog.user_id == user_id)
        if status:
            query = query.filter(CommandValidationLog.validation_status == status)

        return query.order_by(CommandValidationLog.created_at.desc()).limit(limit).all()

    def check_version_compatibility(
        self, version_pattern: str, actual_version: str
    ) -> bool:
        """Check if actual version matches the version pattern."""
        if not version_pattern:
            return True

        # Handle comparison operators
        comparison_result = self._handle_version_comparison(
            version_pattern, actual_version
        )
        if comparison_result is not None:
            return comparison_result

        # Handle wildcard patterns
        if "*" in version_pattern:
            pattern_regex = version_pattern.replace("*", ".*")
            return bool(re.match(f"^{pattern_regex}$", actual_version))

        # Exact match
        return actual_version == version_pattern

    def _handle_version_comparison(
        self, version_pattern: str, actual_version: str
    ) -> Optional[bool]:
        """Handle version comparison operators. Returns None if no operator found."""
        operators = [
            (">=", lambda a, b: self._compare_versions(a, b) >= 0),
            ("<=", lambda a, b: self._compare_versions(a, b) <= 0),
            (">", lambda a, b: self._compare_versions(a, b) > 0),
            ("<", lambda a, b: self._compare_versions(a, b) < 0),
            ("==", lambda a, b: a == b),
        ]

        for operator, comparison_func in operators:
            if version_pattern.startswith(operator):
                target_version = version_pattern[len(operator) :].strip()
                return comparison_func(actual_version, target_version)

        return None

    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""

        def normalize_version(v):
            return [int(x) for x in re.sub(r"[^\d.]", "", v).split(".") if x.isdigit()]

        v1_parts = normalize_version(version1)
        v2_parts = normalize_version(version2)

        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))

        for i in range(max_len):
            if v1_parts[i] < v2_parts[i]:
                return -1
            if v1_parts[i] > v2_parts[i]:
                return 1

        return 0
