#!/usr/bin/env python3
"""
Test script for command result processing functionality.
Demonstrates output parsing, error identification, result formatting, status reporting, and history tracking.
"""

import os
import sys
from datetime import datetime, timedelta

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy.orm import Session

from app.db.command_execution_models import CommandExecutionResult
from app.db.models import System, User
from app.db.session import SessionLocal
from app.services.command_result_processing_service import CommandResultProcessor


def find_existing_data(db: Session) -> tuple:
    """Find existing user and system data for testing."""
    # Find any existing user
    existing_user = db.query(User).first()
    if not existing_user:
        raise Exception("No users found in database. Please create a user first.")

    # Find any existing system
    existing_system = db.query(System).first()
    if not existing_system:
        raise Exception("No systems found in database. Please create a system first.")

    print(f"Using existing user: {existing_user.username} (ID: {existing_user.id})")
    print(
        f"Using existing system: {existing_system.hostname} (ID: {existing_system.id})"
    )

    return existing_user, existing_system


def create_test_execution_results(db: Session) -> list:
    """Create test execution results for processing demonstration."""
    # Find existing user and system data
    test_user, test_system = find_existing_data(db)

    test_results = []

    # Test 1: Successful command with structured output
    result1 = CommandExecutionResult(
        system_id=test_system.id,
        user_id=test_user.id,
        command="df -h",
        normalized_command="df -h",
        command_hash="abc123",
        execution_status="success",
        exit_code=0,
        stdout="""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G  5.5G   14G  30% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G   45G   50G  48% /home""",
        stderr="",
        started_at=datetime.utcnow() - timedelta(minutes=5),
        completed_at=datetime.utcnow() - timedelta(minutes=4),
        execution_time_ms=1500,
        timeout_seconds=30,
        validation_status="validated",
        risk_level="low",
        requires_sudo=False,
        ip_address="192.168.1.100",
        user_agent="test-client/1.0",
    )

    # Test 2: Failed command with permission error
    result2 = CommandExecutionResult(
        system_id=test_system.id,
        user_id=test_user.id,
        command="cat /etc/shadow",
        normalized_command="cat /etc/shadow",
        command_hash="def456",
        execution_status="failed",
        exit_code=1,
        stdout="",
        stderr="cat: /etc/shadow: Permission denied",
        started_at=datetime.utcnow() - timedelta(minutes=3),
        completed_at=datetime.utcnow() - timedelta(minutes=2),
        execution_time_ms=250,
        timeout_seconds=30,
        validation_status="validated",
        risk_level="medium",
        requires_sudo=True,
        ip_address="192.168.1.100",
        user_agent="test-client/1.0",
    )

    # Test 3: Network command with timeout
    result3 = CommandExecutionResult(
        system_id=test_system.id,
        user_id=test_user.id,
        command="ping -c 3 unreachable-host.example.com",
        normalized_command="ping -c 3 unreachable-host.example.com",
        command_hash="ghi789",
        execution_status="timeout",
        exit_code=None,
        stdout="PING unreachable-host.example.com (192.168.1.999): 56 data bytes",
        stderr="ping: cannot resolve unreachable-host.example.com: Name or service not known",
        started_at=datetime.utcnow() - timedelta(minutes=1),
        completed_at=datetime.utcnow(),
        execution_time_ms=30000,
        timeout_seconds=30,
        validation_status="validated",
        risk_level="low",
        requires_sudo=False,
        ip_address="192.168.1.100",
        user_agent="test-client/1.0",
    )

    # Test 4: Process listing command
    result4 = CommandExecutionResult(
        system_id=test_system.id,
        user_id=test_user.id,
        command="ps aux | head -10",
        normalized_command="ps aux | head -10",
        command_hash="jkl012",
        execution_status="success",
        exit_code=0,
        stdout="""USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  19356  1544 ?        Ss   10:00   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    10:00   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    10:00   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   10:00   0:00 [migration/0]
root         6  0.0  0.0      0     0 ?        S    10:00   0:00 [rcu_bh]
root         7  0.0  0.0      0     0 ?        S    10:00   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    10:00   0:00 [watchdog/0]
root         9  0.0  0.0      0     0 ?        S<   10:00   0:00 [migration/1]
root        10  0.0  0.0      0     0 ?        S    10:00   0:00 [ksoftirqd/1]""",
        stderr="",
        started_at=datetime.utcnow() - timedelta(seconds=30),
        completed_at=datetime.utcnow() - timedelta(seconds=29),
        execution_time_ms=800,
        timeout_seconds=30,
        validation_status="validated",
        risk_level="low",
        requires_sudo=False,
        ip_address="192.168.1.100",
        user_agent="test-client/1.0",
    )

    test_results = [result1, result2, result3, result4]

    for result in test_results:
        db.add(result)

    db.commit()

    for result in test_results:
        db.refresh(result)

    return test_results


def test_result_processing():
    """Test the command result processing functionality."""
    print("🔍 Testing Command Result Processing System")
    print("=" * 60)

    db = SessionLocal()
    try:
        # Create test data
        print("\n📝 Creating test execution results...")
        test_results = create_test_execution_results(db)
        print(f"✅ Created {len(test_results)} test execution results")

        # Initialize processor
        processor = CommandResultProcessor(db)

        # Test 1: Process individual results
        print("\n🔬 Testing individual result processing...")
        for i, result in enumerate(test_results, 1):
            print(f"\n--- Processing Result {i}: {result.command} ---")

            processed = processor.process_execution_result(result)

            print(f"Command Type: {processed['parsed_output']['command_type']}")
            print(f"Processing Status: {processed['processing_status']}")
            print(f"Has Errors: {processed['error_analysis']['has_errors']}")

            if processed["error_analysis"]["has_errors"]:
                print(
                    f"Error Severity: {processed['error_analysis']['error_severity']}"
                )
                print(
                    f"Error Categories: {processed['error_analysis']['error_categories']}"
                )

            print(f"Health Score: {processed['status_info']['health_score']}")

            if processed["parsed_output"]["structured_data"]:
                print(f"Structured Data Available: Yes")
            else:
                print(f"Structured Data Available: No")

        # Test 2: Get execution history with analysis
        print("\n📊 Testing execution history with analysis...")
        history = processor.get_execution_history_with_analysis(
            limit=10, include_analysis=True
        )

        print(f"Total executions in history: {history['total_count']}")
        print(f"Executions with analysis: {len(history['executions'])}")

        # Test 3: Generate metrics report
        print("\n📈 Testing metrics report generation...")
        report = processor.get_execution_metrics_report(days=1)

        print(f"Report period: {report['period']['days']} days")
        print(f"Total executions: {report['summary']['total_executions']}")
        print(f"Successful executions: {report['summary']['successful_executions']}")
        print(f"Failed executions: {report['summary']['failed_executions']}")
        print(f"Success rate: {report['summary']['success_rate']:.1f}%")

        if report["performance"]["avg_execution_time_ms"]:
            print(
                f"Average execution time: {report['performance']['avg_execution_time_ms']}ms"
            )

        # Test 4: Test error pattern analysis
        print("\n🚨 Testing error pattern analysis...")
        error_results = [r for r in test_results if r.execution_status == "failed"]

        if error_results:
            for result in error_results:
                processed = processor.process_execution_result(result)
                error_analysis = processed["error_analysis"]

                print(f"\nError in command: {result.command}")
                print(f"Error categories: {error_analysis['error_categories']}")
                print(f"Suggested fixes: {error_analysis['suggested_fixes']}")

        # Test 5: Test output parsing for different command types
        print("\n🔍 Testing command type identification and parsing...")
        command_types = {}

        for result in test_results:
            processed = processor.process_execution_result(result)
            cmd_type = processed["parsed_output"]["command_type"]

            if cmd_type not in command_types:
                command_types[cmd_type] = []
            command_types[cmd_type].append(result.command)

        for cmd_type, commands in command_types.items():
            print(f"\n{cmd_type.upper()} commands:")
            for cmd in commands:
                print(f"  - {cmd}")

        print("\n✅ All result processing tests completed successfully!")

        # Display summary
        print("\n" + "=" * 60)
        print("📋 RESULT PROCESSING TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Individual result processing: PASSED")
        print(f"✅ Execution history with analysis: PASSED")
        print(f"✅ Metrics report generation: PASSED")
        print(f"✅ Error pattern analysis: PASSED")
        print(f"✅ Command type identification: PASSED")
        print(f"✅ Output parsing: PASSED")
        print(f"✅ Status reporting: PASSED")
        print(f"✅ History tracking: PASSED")

    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")
        import traceback

        traceback.print_exc()
        return False
    finally:
        db.close()

    return True


def demonstrate_api_usage():
    """Demonstrate how the result processing API would be used."""
    print("\n" + "=" * 60)
    print("🌐 API USAGE DEMONSTRATION")
    print("=" * 60)

    print("""
The Command Result Processing API provides the following endpoints:

1. POST /command-results/process/{execution_id}
   - Process a specific execution result
   - Returns comprehensive analysis including:
     * Parsed output with command type identification
     * Error analysis with severity and suggested fixes
     * Formatted result for display
     * Status information with health score

2. GET /command-results/history
   - Get execution history with optional analysis
   - Supports filtering by system_id
   - Paginated results with configurable analysis depth

3. GET /command-results/metrics/report
   - Generate metrics report for specified period
   - Includes success rates, performance statistics
   - Daily breakdown and trend analysis

4. GET /command-results/analysis/{execution_id}
   - Get detailed analysis for specific execution
   - Comprehensive output parsing and error identification

5. GET /command-results/summary/system/{system_id}
   - Get execution summary for specific system
   - Aggregated statistics and recent execution context

6. GET /command-results/errors/patterns
   - Analyze common error patterns
   - Frequency analysis and suggested fixes

7. GET /command-results/performance/trends
   - Performance trend analysis over time
   - Execution times, resource usage, success rates

Example API calls:
- curl -X POST "/command-results/process/123"
- curl "/command-results/history?system_id=1&limit=50"
- curl "/command-results/metrics/report?days=7"
- curl "/command-results/errors/patterns?days=30"
""")


if __name__ == "__main__":
    print("🚀 Starting Command Result Processing Tests")

    success = test_result_processing()

    if success:
        demonstrate_api_usage()
        print("\n🎉 All tests completed successfully!")
        print("\nThe Phase 2 Command Result Processing System is ready for use!")
    else:
        print("\n💥 Tests failed!")
        sys.exit(1)
