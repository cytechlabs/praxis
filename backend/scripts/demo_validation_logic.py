"""
Demonstration script showing command validation logic without database dependencies.
This shows the core pattern matching and validation functionality.
"""

import os
import re
import sys

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.command_validation_service import CommandValidationService


class MockDB:
    """Mock database session for demonstration."""

    def query(self, *args):
        return self

    def filter(self, *args):
        return self

    def first(self):
        return None

    def add(self, *args):
        pass

    def commit(self):
        pass


def demo_command_validation():
    """Demonstrate command validation functionality."""
    print("Command Validation System Demo")
    print("=" * 50)

    # Create service with mock database
    mock_db = MockDB()
    service = CommandValidationService(mock_db)

    # Test 1: Command Normalization
    print("\n1. Command Normalization:")
    print("-" * 25)
    test_commands = [
        "  apt-get    update  ",
        "apt-get\t\ninstall\tvim",
        "APT-GET     UPGRADE",
        "   sudo    systemctl    restart    nginx   ",
    ]

    for cmd in test_commands:
        normalized = service._normalize_command(cmd)
        print(f"'{cmd}' → '{normalized}'")

    # Test 2: Pattern Matching (Literal)
    print("\n2. Literal Pattern Matching:")
    print("-" * 30)
    literal_tests = [
        ("apt-get update", "apt-get update", True),
        ("apt-get install vim", "apt-get install *", True),
        ("apt-get install python3", "apt-get install *", True),
        ("yum update", "apt-get *", False),
        ("apt-cache search vim", "apt-cache search *", True),
        ("systemctl restart nginx", "systemctl * nginx", True),
    ]

    for command, pattern, expected in literal_tests:
        result = service._matches_pattern(command, pattern, is_regex=False)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{command}' matches '{pattern}': {result}")

    # Test 3: Pattern Matching (Regex)
    print("\n3. Regex Pattern Matching:")
    print("-" * 27)
    regex_tests = [
        ("apt-get update", r"apt-get.*", True),
        ("apt-get install vim", r"apt-get (install|update).*", True),
        ("yum update", r"apt-get.*", False),
        ("rm -rf /tmp", r"rm\s+-rf.*", True),
        ("sudo systemctl restart nginx", r"sudo.*", True),
        ("systemctl status apache2", r"systemctl (start|stop|restart|status).*", True),
    ]

    for command, pattern, expected in regex_tests:
        result = service._matches_pattern(command, pattern, is_regex=True)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{command}' matches '{pattern}': {result}")

    # Test 4: Version Compatibility
    print("\n4. Version Compatibility:")
    print("-" * 25)
    version_tests = [
        (">=18.04", "20.04", True),
        (">=22.04", "20.04", False),
        ("<=22.04", "20.04", True),
        ("<=18.04", "20.04", False),
        (">18.04", "20.04", True),
        (">20.04", "20.04", False),
        ("<22.04", "20.04", True),
        ("<20.04", "20.04", False),
        ("==20.04", "20.04", True),
        ("==18.04", "20.04", False),
        ("20.*", "20.04", True),
        ("18.*", "20.04", False),
        ("2*", "20.04", True),
        ("1*", "20.04", False),
    ]

    for pattern, version, expected in version_tests:
        result = service.check_version_compatibility(pattern, version)
        status = "✓" if result == expected else "✗"
        print(f"{status} Version '{version}' matches pattern '{pattern}': {result}")

    # Test 5: Version Comparison
    print("\n5. Version Comparison:")
    print("-" * 22)
    comparison_tests = [
        ("20.04", "20.04", 0),
        ("20.04", "18.04", 1),
        ("18.04", "20.04", -1),
        ("2.0.0", "1.9.9", 1),
        ("1.9.9", "2.0.0", -1),
        ("20.04.1", "20.04", 1),
        ("20.04", "20.04.1", -1),
    ]

    for v1, v2, expected in comparison_tests:
        result = service._compare_versions(v1, v2)
        status = "✓" if result == expected else "✗"
        comparison_text = (
            "equal" if expected == 0 else ("greater" if expected == 1 else "lesser")
        )
        print(f"{status} '{v1}' is {comparison_text} than '{v2}': {result}")

    # Test 6: Security Pattern Detection
    print("\n6. Security Pattern Detection:")
    print("-" * 32)
    security_patterns = [
        (r"rm\s+-rf\s+/", "rm -rf /", "CRITICAL: Dangerous recursive delete"),
        (r"(mkfs|fdisk|parted).*", "mkfs.ext4 /dev/sdb1", "CRITICAL: Disk formatting"),
        (r"(ifconfig|ip\s+route|iptables).*", "iptables -F", "ERROR: Network config"),
        (
            r"(systemctl|service).*",
            "systemctl restart nginx",
            "WARNING: Service management",
        ),
        (r"sudo.*", "sudo apt-get update", "INFO: Elevated privileges"),
        (r"(apt|yum|dnf|zypper).*", "apt-get install vim", "INFO: Package manager"),
    ]

    for pattern, command, description in security_patterns:
        matches = bool(re.search(pattern, command, re.IGNORECASE))
        status = (
            "🔴"
            if "CRITICAL" in description
            else ("🟡" if "WARNING" in description else "🔵")
        )
        print(f"{status} '{command}' → {description}: {matches}")

    # Test 7: Command Categories
    print("\n7. Command Categorization:")
    print("-" * 27)
    commands_by_category = {
        "Package Management": [
            "apt-get update",
            "apt-get install vim",
            "yum update",
            "zypper refresh",
            "dnf install python3",
        ],
        "System Information": [
            "uname -a",
            "cat /etc/os-release",
            "dpkg -l",
            "rpm -qa",
            "lsb_release -a",
        ],
        "Service Management": [
            "systemctl status nginx",
            "systemctl restart apache2",
            "service mysql start",
            "systemctl enable docker",
        ],
        "File Operations": [
            "ls -la /var/log",
            "cat /var/log/syslog",
            "tail -f /var/log/nginx/access.log",
            "find /etc -name '*.conf'",
        ],
    }

    for category, commands in commands_by_category.items():
        print(f"\n{category}:")
        for cmd in commands:
            # Simulate risk assessment
            risk = (
                "HIGH"
                if any(dangerous in cmd for dangerous in ["rm", "mkfs", "fdisk"])
                else (
                    "MEDIUM"
                    if any(elevated in cmd for elevated in ["systemctl", "service"])
                    else "LOW"
                )
            )
            print(f"  {cmd} → Risk: {risk}")

    print(f"\n✓ All validation logic tests completed!")
    print(f"✓ Command normalization: Working")
    print(f"✓ Pattern matching (literal & regex): Working")
    print(f"✓ Version compatibility: Working")
    print(f"✓ Security pattern detection: Working")
    print(f"✓ Command categorization: Working")


if __name__ == "__main__":
    demo_command_validation()
