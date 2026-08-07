# Praxis reporting contract

Praxis has one contract for turning fleet data into a downloadable, auditable
report. This document is the human-readable companion to the machine-readable
catalog served at `GET /reports/catalog`.

## Two tiers

- **Table export (shortcut)** — downloads the visible table (current page +
  filters) as CSV/JSON. A convenience only; **not** recorded as a report run,
  **not** schedulable. Lives on data pages (Systems, Package Inventory, Job
  History, Config Audit, System Comparison, Access Review CSV).
- **Report generation (contract)** — a named **report kind** with a defined
  scope, filters, and format. Generating one materializes rows, streams a
  bounded download, records a durable `report_runs` row, and is schedulable.
  Manual and scheduled runs go through the **same** report-kind contract.

## The report-kind contract

Source of truth:

- Vocabulary: `report_run_service.VALID_REPORT_KINDS` (mirrored by the
  `report_runs` / `report_schedules` `report_kind` CHECK constraints).
- Catalog (labels, formats, scopes, filter keys): `report_catalog.py`, served at
  `GET /reports/catalog`. A fail-closed module assert keeps the catalog and the
  vocabulary from drifting apart.
- Manual materialization: each domain's `*_export_service.collect_export_rows`
  (package posture: `package_reports_export_service`).
- Scheduled materialization: `report_schedule_service.DISPATCH_MAP` (same
  collectors; the scheduler records a row-count run).
- Run recording: `report_run_service.safe_record_completed_run` (never breaks a
  download if persistence fails).

Every report kind records a `report_runs` row with: `report_kind`,
`triggered_by` (`user` | `system_scheduled`), `format`, `filters_snapshot`
(scope + filters), `row_count`, `state`, actor, and timestamps.

## Supported report kinds (1.0)

| Report kind | Category | Formats | Scope / filters |
|---|---|---|---|
| `package_outdated` | package | csv, json | fleet, smart_group, system; `security_only`, `name_filter` |
| `package_compliance` | package | csv, json | fleet, smart_group |
| `patch_executions` | patch | csv, json | fleet, date range; `plan_id`, `state` |
| `patch_update_plans` | patch | csv, json | fleet, date range; `policy_id`, `state` |
| `patch_reboot_queues` | patch | csv, json | per `execution_id` |
| `patch_rollback_runs` | patch | csv, json | per `execution_id` |
| `compliance_evidence` | compliance | jsonl, csv | fleet, system, date range; `policy_id`, `verdict` |
| `compliance_remediation_requests` | compliance | csv, json | fleet, system, date range; `policy_id`, `state` |
| `compliance_remediation_plans` | compliance | csv, json | fleet, system, date range; `policy_id`, `state`, `current_only` |
| `compliance_remediation_executions` | compliance | csv, json | fleet, system, date range; `policy_id`, `state` |

## RBAC & fleet scope

- Report generation: `require_role("admin", "maintainer")`. Report-run /
  schedule reads: admin/maintainer/auditor. Schedule mutations: tenant-wide
  admin only (+ `REPORTS_SCHEDULED_EXPORTS` entitlement).
- Fleet scope is enforced **before** any rows are materialized: a scoped caller
  sees only in-scope systems; an explicit out-of-scope `system_id` is a
  non-disclosing 404; an empty scope yields an empty export. No out-of-scope
  system ids, hostnames, package names, counts, or schedule metadata leak.
- Credential secrets are never exportable.

## Bounding

Exports cap the review window (≤ 366 days) and row count
(`_export_helpers.EXPORT_MAX_ROWS = 50_000`), and chunk queries with
`yield_per`. Compliance evidence streams row-by-row. Oversized requests are
rejected with HTTP 422; narrow the window/filters and retry.

## Deferred for 1.0 (table export or read-only dashboard only)

Not yet first-class report kinds — candidates for post-1.0 promotion:

- Fleet inventory (Systems) — `GET /export/systems` (table export).
- Package inventory — `GET /export/packages` (table export).
- Job / automation history — `GET /export/jobs` (table export).
- Audit events — `GET /export/audits` (table export).
- System comparison — `GET /systems/compare/export` (table export).
- Access reviews — `GET /access-reviews/{id}/export.csv` (table export).
- Session recordings — `GET /recordings/{id}/cast` (artifact download).
- Content / mirror / airgap history — read dashboards; airgap bundles build via
  `POST /airgap/exports` (own bundle lifecycle, not a report run).

Deferred scheduling UX: **structured per-kind schedule filter controls.** 1.0
report schedules carry their scope/filters as a raw JSON `filters_snapshot`
(validated for date keys + size, not per-kind form controls). Form-based
schedule filter builders are a post-1.0 item; the report catalog
(`GET /reports/catalog`) already exposes each kind's `filter_keys` so a future UI
can generate those controls from it.

Explicitly out of scope for 1.0: a custom report query language, PDF output, and
any credential-secret export.
