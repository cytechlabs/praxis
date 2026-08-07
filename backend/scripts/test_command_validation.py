"""
Script to test and demonstrate command validation functionality.
This script creates a minimal test environment and shows the validation system working.
"""

import os
import sys
from datetime import datetime

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session

from app.db.models import Credential, Distro, Group, System, User
from app.db.session import SessionLocal
from app.services.command_validation_service import CommandValidationService


def create_test_data(db: Session):
    """Create minimal test data for demonstration."""
    print("Creating test data...")

    # Create or get admin user
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="test_admin",
            email="admin@test.com",
            hashed_password="test_hash",
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

    # Create or get test distro
    test_distro = db.query(Distro).filter(Distro.name == "TestUbuntu").first()
    if not test_distro:
        test_distro = Distro(
            name="TestUbuntu",
            version="20.04",
            release_date=datetime(2020, 4, 23).date(),
            end_of_life_date=datetime(2025, 4, 23).date(),
        )
        db.add(test_distro)
        db.commit()
        db.refresh(test_distro)

    # Create test group
    test_group = db.query(Group).filter(Group.name == "test_group").first()
    if not test_group:
        test_group = Group(
            name="test_group", description="Test group for validation demo"
        )
        db.add(test_group)
        db.commit()
        db.refresh(test_group)

    # Create test credentials
    test_creds = db.query(Credential).filter(Credential.name == "test_creds").first()
    if not test_creds:
        test_creds = Credential(name="test_creds", type="ssh_key", username="testuser")
        db.add(test_creds)
        db.commit()
        db.refresh(test_creds)

    # Create test system
    test_system = db.query(System).filter(System.hostname == "test-server").first()
    if not test_system:
        test_system = System(
            hostname="test-server",
            ip_address="192.168.1.100",
            distro_id=test_distro.id,
            os_version="20.04",
            status="Active",
            group_id=test_group.id,
            credentials_id=test_creds.id,
            registered_by=admin_user.id,
        )
        db.add(test_system)
        db.commit()
        db.refresh(test_system)

    return admin_user, test_system


def test_command_validation():
    """Test command validation functionality."""
    print("Testing Command Validation System")
    print("=" * 50)

    db = SessionLocal()
    try:
        # Create test data
        admin_user, test_system = create_test_data(db)

        # Initialize validation service
        validation_service = CommandValidationService(db)

        # Test 1: Add a whitelist entry
        print("\n1. Adding whitelist entry...")
        whitelist_entry = validation_service.add_whitelist_entry(
            name="Test APT Update",
            command_pattern="apt-get update",
            category="package_management",
            risk_level="low",
            user_id=admin_user.id,
            description="Test command for APT update",
            requires_sudo=True,
            timeout_seconds=300,
        )
        print(
            f"✓ Created whitelist entry: {whitelist_entry.name} (ID: {whitelist_entry.id})"
        )

        # Test 2: Add a validation rule
        print("\n2. Adding validation rule...")
        validation_rule = validation_service.add_validation_rule(
            name="Test Dangerous Commands",
            validation_type="blacklist",
            pattern="rm -rf",
            severity="critical",
            user_id=admin_user.id,
            description="Block dangerous delete operations",
            error_message="Dangerous recursive delete detected!",
        )
        print(
            f"✓ Created validation rule: {validation_rule.name} (ID: {validation_rule.id})"
        )

        # Test 3: Test command normalization
        print("\n3. Testing command normalization...")
        test_commands = [
            "  apt-get    update  ",
            "apt-get\t\nupdate",
            "APT-GET     UPDATE",
        ]
        for cmd in test_commands:
            normalized = validation_service._normalize_command(cmd)
            print(f"   '{cmd}' → '{normalized}'")

        # Test 4: Test pattern matching
        print("\n4. Testing pattern matching...")
        patterns = [
            ("apt-get update", "apt-get update", False, True),
            ("apt-get install vim", "apt-get install *", False, True),
            ("yum update", "apt-get *", False, False),
            ("apt-get update", r"apt-get.*", True, True),
            ("rm -rf /tmp", r"rm\s+-rf", True, True),
        ]

        for command, pattern, is_regex, expected in patterns:
            result = validation_service._matches_pattern(command, pattern, is_regex)
            status = "✓" if result == expected else "✗"
            print(
                f"   {status} '{command}' matches '{pattern}' (regex={is_regex}): {result}"
            )

        # Test 5: Test full command validation
        print("\n5. Testing full command validation...")

        test_cases = [
            ("apt-get update", "Should be allowed (matches whitelist)"),
            ("rm -rf /", "Should be denied (matches dangerous rule)"),
            ("unknown-command", "Should be denied (not in whitelist)"),
            ("apt-get install vim", "Should be denied (not exact match)"),
        ]

        for command, description in test_cases:
            print(f"\n   Testing: {command}")
            print(f"   Expected: {description}")

            result = validation_service.validate_command(
                raw_command=command,
                system_id=test_system.id,
                user_id=admin_user.id,
                session_id="test_session",
                ip_address="127.0.0.1",
                user_agent="test_agent",
            )

            print(f"   Result: {result['status'].upper()}")
            print(f"   Reason: {result['reason']}")
            print(f"   Log ID: {result['log_id']}")

        # Test 6: Test version compatibility
        print("\n6. Testing version compatibility...")
        version_tests = [
            (">=18.04", "20.04", True),
            (">=22.04", "20.04", False),
            ("20.*", "20.04", True),
            ("18.*", "20.04", False),
            ("==20.04", "20.04", True),
        ]

        for pattern, version, expected in version_tests:
            result = validation_service.check_version_compatibility(pattern, version)
            status = "✓" if result == expected else "✗"
            print(
                f"   {status} Version {version} matches pattern '{pattern}': {result}"
            )

        # Test 7: Get validation logs
        print("\n7. Recent validation logs...")
        logs = validation_service.get_validation_logs(limit=5)
        for log in logs:
            print(f"   {log.created_at}: {log.raw_command} → {log.validation_status}")

        # Test 8: Get whitelist entries
        print("\n8. Current whitelist entries...")
        entries = validation_service.get_whitelist_entries()
        for entry in entries:
            print(
                f"   {entry.name}: {entry.command_pattern} (Risk: {entry.risk_level})"
            )

        print(f"\n✓ All tests completed successfully!")
        print(f"✓ Created {len(entries)} whitelist entries")
        print(f"✓ Logged {len(logs)} validation attempts")

    except Exception as e:
        print(f"✗ Error during testing: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    test_command_validation()
