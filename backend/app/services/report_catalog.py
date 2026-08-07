"""PRA-358 — the report-kind catalog: the single documented source of truth
for the reporting contract.

The report-kind vocabulary itself lives in ``report_run_service`` (and the DB
CHECK constraints); this module attaches the *product* metadata each kind needs
to be discoverable and self-describing: a human label, a one-line description,
its category, the formats it can be exported as, the scopes it accepts, and the
filter keys it understands. ``GET /reports/catalog`` serves this so the UI can
render human labels + capability without hard-coding backend enum names, and so
"the contract is documented" is true in-product, not just in a markdown file.

This is metadata only — it does not materialize rows. Manual generation happens
on each domain's export route; scheduled generation happens through
``report_schedule_service.DISPATCH_MAP``. Both key off the same ``report_kind``
strings enumerated here.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from . import report_run_service as rrs

# Scope tokens a report kind may support. These describe how a caller narrows a
# report; fleet scope / RBAC are enforced at the route regardless.
SCOPE_FLEET = "fleet"
SCOPE_SYSTEM = "system"
SCOPE_SMART_GROUP = "smart_group"
SCOPE_DATE_RANGE = "date_range"
SCOPE_EXECUTION = "execution"

CATEGORY_PATCH = "patch"
CATEGORY_COMPLIANCE = "compliance"
CATEGORY_PACKAGE = "package"

# Ordered so the catalog reads by domain. Each descriptor is pure metadata.
_CATALOG: List[Dict[str, Any]] = [
    {
        "report_kind": rrs.REPORT_KIND_PACKAGE_OUTDATED,
        "label": "Outdated Packages",
        "description": "Every installed package with an available update, fleet-wide or scoped to a smart group.",
        "category": CATEGORY_PACKAGE,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_SYSTEM, SCOPE_SMART_GROUP],
        "filter_keys": ["security_only", "name_filter", "smart_group_id", "system_id"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_PACKAGE_COMPLIANCE,
        "label": "Update Compliance",
        "description": "Per-system update-compliance percentage (up-to-date vs installed), fleet-wide or per smart group.",
        "category": CATEGORY_PACKAGE,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_SMART_GROUP],
        "filter_keys": ["smart_group_id"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_PATCH_EXECUTIONS,
        "label": "Patch Executions",
        "description": "Patch update execution runs across the fleet over a review window.",
        "category": CATEGORY_PATCH,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_DATE_RANGE],
        "filter_keys": ["started_after", "started_before", "plan_id", "state"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_PATCH_UPDATE_PLANS,
        "label": "Patch Update Plans",
        "description": "Patch update plans (dry-run artifacts) created over a review window.",
        "category": CATEGORY_PATCH,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_DATE_RANGE],
        "filter_keys": ["created_after", "created_before", "policy_id", "state"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_PATCH_REBOOT_QUEUES,
        "label": "Patch Reboot Queues",
        "description": "Reboot queue rows for a single patch execution.",
        "category": CATEGORY_PATCH,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_EXECUTION],
        "filter_keys": ["execution_id"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_PATCH_ROLLBACK_RUNS,
        "label": "Patch Rollback Runs",
        "description": "Rollback run rows for a single patch execution.",
        "category": CATEGORY_PATCH,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_EXECUTION],
        "filter_keys": ["execution_id"],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_COMPLIANCE_EVIDENCE,
        "label": "Compliance Evidence",
        "description": "Compliance evaluation evidence stream over a review window (streamed JSONL or CSV).",
        "category": CATEGORY_COMPLIANCE,
        "formats": ["jsonl", "csv"],
        "scopes": [SCOPE_FLEET, SCOPE_SYSTEM, SCOPE_DATE_RANGE],
        "filter_keys": [
            "evaluated_after",
            "evaluated_before",
            "policy_id",
            "system_id",
            "verdict",
        ],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_COMPLIANCE_REMEDIATION_REQUESTS,
        "label": "Compliance Remediation Requests",
        "description": "Remediation requests raised from compliance findings over a review window.",
        "category": CATEGORY_COMPLIANCE,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_SYSTEM, SCOPE_DATE_RANGE],
        "filter_keys": [
            "created_after",
            "created_before",
            "policy_id",
            "system_id",
            "state",
        ],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_COMPLIANCE_REMEDIATION_PLANS,
        "label": "Compliance Remediation Plans",
        "description": "Remediation plans built from compliance findings over a review window.",
        "category": CATEGORY_COMPLIANCE,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_SYSTEM, SCOPE_DATE_RANGE],
        "filter_keys": [
            "created_after",
            "created_before",
            "policy_id",
            "system_id",
            "state",
            "current_only",
        ],
        "records_run": True,
        "schedulable": True,
    },
    {
        "report_kind": rrs.REPORT_KIND_COMPLIANCE_REMEDIATION_EXECUTIONS,
        "label": "Compliance Remediation Executions",
        "description": "Remediation execution attempts over a review window.",
        "category": CATEGORY_COMPLIANCE,
        "formats": ["csv", "json"],
        "scopes": [SCOPE_FLEET, SCOPE_SYSTEM, SCOPE_DATE_RANGE],
        "filter_keys": [
            "created_after",
            "created_before",
            "policy_id",
            "system_id",
            "state",
        ],
        "records_run": True,
        "schedulable": True,
    },
]

# Fail-closed invariant: every registered report kind must appear in the catalog
# exactly once, and the catalog must not describe an unknown kind. This keeps
# the documented contract and the enforced vocabulary from drifting apart.


def _validate_catalog_kinds(
    catalog_kinds: Iterable[str], valid_kinds: Iterable[str]
) -> None:
    """Raise when the catalog and the enforced kind vocabulary disagree.

    Raised explicitly rather than asserted so the invariant still fails closed
    on an optimized interpreter, where assertions are stripped.
    """
    if sorted(catalog_kinds) != sorted(valid_kinds):
        raise RuntimeError(
            "report_catalog and report_run_service.VALID_REPORT_KINDS are out of sync"
        )


_KINDS_IN_CATALOG = [entry["report_kind"] for entry in _CATALOG]
_validate_catalog_kinds(_KINDS_IN_CATALOG, rrs.VALID_REPORT_KINDS)


def list_catalog() -> List[Dict[str, Any]]:
    """Return the full report catalog (a fresh copy per call)."""
    return [dict(entry) for entry in _CATALOG]


def get_descriptor(report_kind: str) -> Dict[str, Any]:
    """Return one kind's descriptor, or raise KeyError for an unknown kind."""
    for entry in _CATALOG:
        if entry["report_kind"] == report_kind:
            return dict(entry)
    raise KeyError(report_kind)
