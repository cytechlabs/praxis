"""Unit tests for PackageService helpers (PRA-116 silent-failure fix)."""

from app.services.package_service import PackageService


def test_ssh_result_ok_success_with_stdout():
    assert (
        PackageService._ssh_result_ok(
            {"status": "success", "stdout": "data", "stderr": ""}
        )
        is True
    )


def test_ssh_result_ok_warning_with_stdout():
    """Warning status with actual output is legitimate (e.g. apt check-update exit=100)."""
    assert (
        PackageService._ssh_result_ok(
            {"status": "warning", "stdout": "data", "stderr": ""}
        )
        is True
    )


def test_ssh_result_ok_rejects_failed_status():
    """Auth/connection failures must be rejected."""
    assert (
        PackageService._ssh_result_ok(
            {"status": "failed", "stdout": "", "stderr": "auth error"}
        )
        is False
    )


def test_ssh_result_ok_rejects_silent_failure():
    """PRA-116: warning + empty stdout + non-empty stderr = silent failure."""
    assert (
        PackageService._ssh_result_ok(
            {"status": "warning", "stdout": "", "stderr": "some error"}
        )
        is False
    )


def test_ssh_result_ok_empty_result_no_error():
    """Legit case: command succeeded but produced no output and no error."""
    assert (
        PackageService._ssh_result_ok({"status": "warning", "stdout": "", "stderr": ""})
        is True
    )


def test_ssh_result_ok_rejects_error_status():
    assert (
        PackageService._ssh_result_ok(
            {"status": "error", "stdout": "whatever", "stderr": ""}
        )
        is False
    )


def test_ssh_result_ok_stdout_only_whitespace_with_stderr():
    """Whitespace-only stdout + stderr should be treated as silent failure."""
    assert (
        PackageService._ssh_result_ok(
            {"status": "success", "stdout": "   \n", "stderr": "boom"}
        )
        is False
    )
