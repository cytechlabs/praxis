"""PRA-435: which scan callers refresh APT metadata.

Explicit and scheduled package scans refresh by default. Callers that only read
installed inventory (rollback verification, inventory-only audit jobs) read the
host's cached lists, so they never run a privileged metadata refresh.
"""

from app.db.models import System
from app.services.job_service import JobService


class _RecordingPackageService:
    def __init__(self):
        self.calls = []

    def scan_packages(self, system_id, refresh=True):
        self.calls.append((system_id, refresh))
        return {"status": "success"}


def _run(db, job_type):
    service = _RecordingPackageService()
    JobService(db)._execute_on_system(
        service, job_type, System(id=7, hostname="h"), user_id=1
    )
    return service.calls


def test_scheduled_package_scan_refreshes_by_default(db):
    assert _run(db, "package_scan") == [(7, True)]


def test_inventory_only_audit_job_reads_cached_lists(db):
    assert _run(db, "audit") == [(7, False)]
