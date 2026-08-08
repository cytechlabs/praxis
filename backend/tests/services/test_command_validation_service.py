"""
Tests for command validation service.
"""

from unittest.mock import Mock, patch

import pytest
from sqlalchemy.orm import Session

from app.db.models import (
    CommandDistroMapping,
    CommandValidationLog,
    CommandValidationRule,
    CommandWhitelist,
    System,
)
from app.services.command_validation_service import CommandValidationService


class TestCommandValidationService:
    """Test cases for CommandValidationService."""

    @pytest.fixture
    def mock_db(self):
        """Mock database session."""
        return Mock(spec=Session)

    @pytest.fixture
    def service(self, mock_db):
        """Command validation service instance."""
        return CommandValidationService(mock_db)

    @pytest.fixture
    def mock_system(self):
        """Mock system object."""
        system = Mock()
        system.id = 1
        system.distro_id = 1
        return system

    @pytest.fixture
    def mock_distro(self):
        """Mock distro object."""
        distro = Mock()
        distro.id = 1
        distro.name = "Ubuntu"
        distro.version = "20.04"
        return distro

    @pytest.fixture
    def mock_whitelist_entry(self):
        """Mock whitelist entry."""
        entry = Mock()
        entry.id = 1
        entry.name = "apt-get update"
        entry.command_pattern = "apt-get update"
        entry.is_regex = False
        entry.is_active = True
        entry.risk_level = "low"
        entry.category = "package_management"
        entry.requires_sudo = True
        entry.timeout_seconds = 30
        return entry

    def test_normalize_command(self, service):
        """Test command normalization."""
        # Test basic normalization
        result = service._normalize_command("  apt-get    update  ")
        assert result == "apt-get update"

        # Test multiple spaces
        result = service._normalize_command("apt-get     install     vim")
        assert result == "apt-get install vim"

        # Test tabs and newlines
        result = service._normalize_command("apt-get\t\nupdate")
        assert result == "apt-get update"

    def test_matches_pattern_literal(self, service):
        """Test literal pattern matching."""
        # Exact match
        assert service._matches_pattern("apt-get update", "apt-get update", False)

        # Case insensitive
        assert service._matches_pattern("APT-GET UPDATE", "apt-get update", False)

        # No match
        assert not service._matches_pattern("apt-get install", "apt-get update", False)

        # Wildcard matching
        assert service._matches_pattern(
            "apt-get install vim", "apt-get install *", False
        )
        assert service._matches_pattern("apt-get update", "apt-get *", False)
        assert not service._matches_pattern("yum install vim", "apt-get *", False)

    def test_matches_pattern_regex(self, service):
        """Test regex pattern matching."""
        # Basic regex
        assert service._matches_pattern("apt-get update", r"apt-get.*", True)
        assert service._matches_pattern(
            "apt-get install vim", r"apt-get (install|update).*", True
        )

        # Case insensitive regex
        assert service._matches_pattern("APT-GET UPDATE", r"apt-get.*", True)

        # No match
        assert not service._matches_pattern("yum update", r"apt-get.*", True)

        # Invalid regex fallback to literal
        assert service._matches_pattern("test[invalid", "test[invalid", True)

    def test_check_whitelist_allowed(self, service, mock_db):
        """Test whitelist check allowing command."""
        # Mock whitelist entry
        mock_entry = Mock()
        mock_entry.id = 1
        mock_entry.name = "apt-get update"
        mock_entry.command_pattern = "apt-get update"
        mock_entry.is_regex = False

        mock_db.query.return_value.filter.return_value.all.return_value = [mock_entry]

        # Mock no distro mappings
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with patch.object(service, "_matches_pattern", return_value=True):
            result = service._check_whitelist("apt-get update", 1)

        assert result["status"] == "allowed"
        assert result["command_id"] == 1

    def test_check_whitelist_denied(self, service, mock_db):
        """Test whitelist check denying command."""
        # Mock empty whitelist
        mock_db.query.return_value.filter.return_value.all.return_value = []

        result = service._check_whitelist("rm -rf /", 1)

        assert result["status"] == "denied"
        assert "not found in whitelist" in result["reason"]

    def test_check_whitelist_with_distro_mapping(self, service, mock_db):
        """Test whitelist check with distribution-specific mapping."""
        # Mock whitelist entry
        mock_entry = Mock()
        mock_entry.id = 1
        mock_entry.name = "package update"
        mock_entry.command_pattern = "update packages"
        mock_entry.is_regex = False

        # Mock distro mapping with override
        mock_mapping = Mock()
        mock_mapping.command_override = "apt-get update"
        mock_mapping.is_supported = True

        mock_db.query.return_value.filter.return_value.all.return_value = [mock_entry]
        mock_db.query.return_value.filter.return_value.first.return_value = mock_mapping

        with patch.object(service, "_matches_pattern", return_value=True):
            result = service._check_whitelist("update packages", 1)

        assert result["status"] == "allowed"
        assert result["override_command"] == "apt-get update"

    def test_check_validation_rules_allowed(self, service, mock_db):
        """Test validation rules allowing command."""
        # Mock empty validation rules
        mock_db.query.return_value.filter.return_value.all.return_value = []

        result = service._check_validation_rules("apt-get update")

        assert result["status"] == "allowed"

    def test_check_validation_rules_denied(self, service, mock_db):
        """Test validation rules denying command."""
        # Mock critical validation rule
        mock_rule = Mock()
        mock_rule.id = 1
        mock_rule.name = "Dangerous commands"
        mock_rule.pattern = "rm -rf"
        mock_rule.is_regex = False
        mock_rule.severity = "critical"
        mock_rule.error_message = "Dangerous command detected"

        mock_db.query.return_value.filter.return_value.all.return_value = [mock_rule]

        with patch.object(service, "_matches_pattern", return_value=True):
            result = service._check_validation_rules("rm -rf /")

        assert result["status"] == "denied"
        assert result["rule_id"] == 1
        assert "Dangerous command detected" in result["reason"]

    def test_check_validation_rules_warning(self, service, mock_db):
        """Test validation rules with warning."""
        # Mock warning validation rule
        mock_rule = Mock()
        mock_rule.id = 1
        mock_rule.name = "Potentially risky"
        mock_rule.pattern = "sudo"
        mock_rule.is_regex = False
        mock_rule.severity = "warning"
        mock_rule.error_message = "Command requires elevated privileges"

        mock_db.query.return_value.filter.return_value.all.return_value = [mock_rule]

        with patch.object(service, "_matches_pattern", return_value=True):
            result = service._check_validation_rules("sudo apt-get update")

        assert result["status"] == "warning"
        assert result["rule_id"] == 1

    def test_validate_command_system_not_found(self, service, mock_db):
        """Test command validation when system is not found."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = service.validate_command("apt-get update", 999, 1)

        assert result["status"] == "denied"
        assert "System not found" in result["reason"]

    def test_validate_command_success(self, service, mock_db, mock_system):
        """Test successful command validation."""
        # Mock system query
        mock_db.query.return_value.filter.return_value.first.return_value = mock_system

        # Mock validation log creation
        mock_log = Mock()
        mock_log.id = 1
        mock_db.add.return_value = None
        mock_db.commit.return_value = None

        with (
            patch.object(service, "_normalize_command", return_value="apt-get update"),
            patch.object(
                service,
                "_check_whitelist",
                return_value={"status": "allowed", "command_id": 1},
            ),
            patch.object(
                service, "_check_validation_rules", return_value={"status": "allowed"}
            ),
            patch(
                "app.services.command_validation_service.CommandValidationLog",
                return_value=mock_log,
            ),
        ):
            result = service.validate_command("apt-get update", 1, 1)

        assert result["status"] == "allowed"
        assert result["command_id"] == 1

    def test_add_whitelist_entry(self, service, mock_db):
        """Test adding whitelist entry."""
        mock_entry = Mock()
        mock_entry.id = 1

        with patch(
            "app.services.command_validation_service.CommandWhitelist",
            return_value=mock_entry,
        ):
            result = service.add_whitelist_entry(
                name="Test Command",
                command_pattern="test *",
                category="testing",
                risk_level="low",
                user_id=1,
            )

        assert result == mock_entry
        mock_db.add.assert_called_once_with(mock_entry)
        mock_db.commit.assert_called_once()

    def test_add_distro_mapping(self, service, mock_db):
        """Test adding distribution mapping."""
        mock_mapping = Mock()
        mock_mapping.id = 1

        with patch(
            "app.services.command_validation_service.CommandDistroMapping",
            return_value=mock_mapping,
        ):
            result = service.add_distro_mapping(
                command_id=1, distro_id=1, command_override="apt-get update"
            )

        assert result == mock_mapping
        mock_db.add.assert_called_once_with(mock_mapping)
        mock_db.commit.assert_called_once()

    def test_add_validation_rule(self, service, mock_db):
        """Test adding validation rule."""
        mock_rule = Mock()
        mock_rule.id = 1

        with patch(
            "app.services.command_validation_service.CommandValidationRule",
            return_value=mock_rule,
        ):
            result = service.add_validation_rule(
                name="Test Rule",
                validation_type="pattern",
                pattern="dangerous.*",
                severity="error",
                user_id=1,
            )

        assert result == mock_rule
        mock_db.add.assert_called_once_with(mock_rule)
        mock_db.commit.assert_called_once()

    def test_get_whitelist_entries_no_filter(self, service, mock_db):
        """Test getting whitelist entries without filters."""
        mock_entries = [Mock(), Mock()]
        mock_db.query.return_value.all.return_value = mock_entries

        result = service.get_whitelist_entries()

        assert result == mock_entries

    def test_get_whitelist_entries_with_filters(self, service, mock_db):
        """Test getting whitelist entries with filters."""
        mock_entries = [Mock()]
        mock_query = mock_db.query.return_value
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = mock_entries

        result = service.get_whitelist_entries(
            category="package_management", risk_level="low", is_active=True
        )

        assert result == mock_entries
        assert mock_query.filter.call_count == 3

    def test_get_validation_logs(self, service, mock_db):
        """Test getting validation logs."""
        mock_logs = [Mock(), Mock()]
        mock_query = mock_db.query.return_value
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = mock_logs

        result = service.get_validation_logs(system_id=1, user_id=1, status="allowed")

        assert result == mock_logs

    def test_check_version_compatibility(self, service):
        """Test version compatibility checking."""
        # No pattern should always match
        assert service.check_version_compatibility("", "20.04")
        assert service.check_version_compatibility(None, "20.04")

        # Greater than or equal
        assert service.check_version_compatibility(">=18.04", "20.04")
        assert service.check_version_compatibility(">=20.04", "20.04")
        assert not service.check_version_compatibility(">=22.04", "20.04")

        # Less than or equal
        assert service.check_version_compatibility("<=22.04", "20.04")
        assert service.check_version_compatibility("<=20.04", "20.04")
        assert not service.check_version_compatibility("<=18.04", "20.04")

        # Greater than
        assert service.check_version_compatibility(">18.04", "20.04")
        assert not service.check_version_compatibility(">20.04", "20.04")

        # Less than
        assert service.check_version_compatibility("<22.04", "20.04")
        assert not service.check_version_compatibility("<20.04", "20.04")

        # Exact match
        assert service.check_version_compatibility("==20.04", "20.04")
        assert not service.check_version_compatibility("==18.04", "20.04")

        # Wildcard
        assert service.check_version_compatibility("20.*", "20.04")
        assert service.check_version_compatibility("2*", "20.04")
        assert not service.check_version_compatibility("18.*", "20.04")

    def test_compare_versions(self, service):
        """Test version comparison."""
        # Equal versions
        assert service._compare_versions("20.04", "20.04") == 0
        assert service._compare_versions("1.0.0", "1.0.0") == 0

        # First version greater
        assert service._compare_versions("20.04", "18.04") == 1
        assert service._compare_versions("2.0.0", "1.9.9") == 1

        # First version lesser
        assert service._compare_versions("18.04", "20.04") == -1
        assert service._compare_versions("1.9.9", "2.0.0") == -1

        # Different number of parts
        assert service._compare_versions("20.04.1", "20.04") == 1
        assert service._compare_versions("20.04", "20.04.1") == -1
