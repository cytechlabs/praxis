#!/usr/bin/env python3
"""
Test script for SSH host key verification functionality.
This script helps test and demonstrate the host key verification process.
"""

import os
import sys

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.db.models import System
from app.db.session import SessionLocal
from app.db.ssh_security_models import SSHHostKey, SSHSecurityPolicy
from app.services.ssh_service import SSHConnectionError, SSHService


def test_host_key_verification():
    """Test the host key verification process."""
    db = SessionLocal()
    ssh_service = SSHService(db)

    try:
        print("=== SSH Host Key Verification Test ===\n")

        # Get all systems
        systems = db.query(System).all()
        if not systems:
            print("No systems found in database. Please add a system first.")
            return

        print(f"Found {len(systems)} system(s) in database:")
        for i, system in enumerate(systems, 1):
            policy_name = (
                system.ssh_security_policy.name
                if system.ssh_security_policy
                else "None"
            )
            host_key_verification = (
                "Enabled"
                if (
                    system.ssh_security_policy
                    and system.ssh_security_policy.require_host_key_verification
                )
                else "Disabled"
            )
            print(
                f"  {i}. {system.hostname} ({system.ip_address}) - Policy: {policy_name} - Host Key Verification: {host_key_verification}"
            )

        print("\n=== Host Key Status ===")

        # Check host keys for each system
        for system in systems:
            print(f"\nSystem: {system.hostname}")

            # Get host keys for this system
            host_keys = (
                db.query(SSHHostKey).filter(SSHHostKey.system_id == system.id).all()
            )

            if not host_keys:
                print("  No host keys stored")
            else:
                for hk in host_keys:
                    status = "✓ VERIFIED" if hk.verified else "⚠ UNVERIFIED"
                    print(f"  Host Key: {hk.key_type} - {status}")
                    print(f"    Fingerprint: {hk.fingerprint[:32]}...")
                    print(f"    First seen: {hk.first_seen}")
                    print(f"    Last seen: {hk.last_seen}")

        print("\n=== Testing Host Key Verification Process ===")

        # Test connection to each system with host key verification enabled
        for system in systems:
            print(f"\nTesting connection to {system.hostname}...")

            if (
                not system.ssh_security_policy
                or not system.ssh_security_policy.require_host_key_verification
            ):
                print("  Host key verification is disabled for this system")
                continue

            try:
                # This will trigger the host key verification process
                result = ssh_service.test_connection(system.id)
                print(f"  Connection result: {result['status']}")
                print(f"  Message: {result['message']}")

            except SSHConnectionError as e:
                error_msg = str(e)
                if "Host key verification failed" in error_msg:
                    print(
                        "  ⚠ Host key verification failed - this is expected for unverified keys"
                    )
                    print(f"  Error: {error_msg}")

                    # Show how to verify the host key
                    print("\n  To verify this host key:")
                    print("  1. Check the fingerprint matches the actual server")
                    print("  2. Use the API endpoint to verify:")

                    # Get the unverified host key
                    unverified_key = (
                        db.query(SSHHostKey)
                        .filter(
                            SSHHostKey.system_id == system.id,
                            SSHHostKey.verified == False,
                        )
                        .first()
                    )

                    if unverified_key:
                        print(
                            f"     curl -X POST 'http://localhost:8000/ssh-security/host-keys/{unverified_key.id}/verify'"
                        )
                        print(f"  3. Or manually verify in database:")
                        print(
                            f"     UPDATE ssh_host_keys SET verified = true WHERE id = {unverified_key.id};"
                        )
                else:
                    print(f"  Connection error: {error_msg}")
            except Exception as e:
                print(f"  Unexpected error: {str(e)}")

        print("\n=== Unverified Host Keys ===")
        unverified_keys = (
            db.query(SSHHostKey).filter(SSHHostKey.verified == False).all()
        )

        if not unverified_keys:
            print("No unverified host keys found")
        else:
            print(f"Found {len(unverified_keys)} unverified host key(s):")
            for key in unverified_keys:
                system = db.query(System).filter(System.id == key.system_id).first()
                print(
                    f"  ID: {key.id} - {system.hostname if system else 'Unknown'} - {key.key_type}"
                )
                print(f"    Fingerprint: {key.fingerprint}")
                print(
                    f"    To verify: curl -X POST 'http://localhost:8000/ssh-security/host-keys/{key.id}/verify'"
                )

        print("\n=== API Endpoints for Host Key Management ===")
        print("Get all host keys:")
        print("  curl 'http://localhost:8000/ssh-security/host-keys'")
        print("\nGet unverified host keys:")
        print("  curl 'http://localhost:8000/ssh-security/host-keys/unverified'")
        print("\nVerify a host key:")
        print(
            "  curl -X POST 'http://localhost:8000/ssh-security/host-keys/{id}/verify'"
        )
        print("\nUnverify a host key:")
        print(
            "  curl -X POST 'http://localhost:8000/ssh-security/host-keys/{id}/unverify'"
        )

    finally:
        db.close()


def show_host_key_verification_workflow():
    """Show the complete host key verification workflow."""
    print("\n=== Host Key Verification Workflow ===")
    print("1. Enable host key verification in SSH security policy:")
    print("   - Set 'require_host_key_verification' to true")
    print("   - Assign the policy to your systems")
    print()
    print("2. First connection attempt:")
    print("   - System will capture the host key automatically")
    print("   - Connection will fail with 'Host key verification failed' message")
    print("   - Host key is stored as 'unverified' in database")
    print()
    print("3. Verify the host key:")
    print("   - Check the fingerprint against the actual server")
    print("   - Use: ssh-keyscan -t rsa,ed25519 hostname | ssh-keygen -lf -")
    print("   - If fingerprint matches, mark as verified via API or database")
    print()
    print("4. Subsequent connections:")
    print("   - System will use the verified host key")
    print("   - Connections will succeed if host key matches")
    print("   - Connections will fail if host key changes (potential security issue)")


if __name__ == "__main__":
    print("SSH Host Key Verification Test Script")
    print("=====================================")

    try:
        test_host_key_verification()
        show_host_key_verification_workflow()

    except Exception as e:
        print(f"Error running test: {str(e)}")
        import traceback

        traceback.print_exc()
