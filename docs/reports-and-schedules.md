---
title: Reports and schedules
description: Report kinds, exports, scheduled runs, and the reporting audit trail.
---

The **Report** workspace is the read and evidence side of Praxis - what happened, what's drifting, and what you can hand to an auditor. None of these screens change fleet state.

## Two kinds of "export"

Praxis distinguishes two things that both produce a download:

- **Table export (shortcut).** A button that downloads *the table you're looking at* - the current page, with its current filters - as CSV/JSON. It's a convenience; it is **not** recorded as a report run. Examples: the export buttons on Systems, Package Inventory, Job History, Config Audit, System Comparison, and Access Review CSV.
- **Report generation (contract).** A named **report kind** with a defined scope, filters, and format. Generating one materializes the rows, streams a bounded CSV/JSON/JSONL download, **and records a durable `report_run`** you can see under **Recent Reports**. Report kinds are also what a **schedule** produces - manual and scheduled runs share the exact same report-kind contract.

Recent Reports (on **Package Reports**) shows the last runs across every report kind, whoever or whatever triggered them.

## Supported report kinds (1.0)

Each is generatable on demand from its screen and recordable as a run; all can also be scheduled.

| Domain | Report kind | Formats | Scope / filters |
|---|---|---|---|
| Package | Outdated Packages | CSV, JSON | fleet, smart group, system; security-only, name filter |
| Package | Update Compliance | CSV, JSON | fleet, smart group |
| Patch | Patch Executions | CSV, JSON | fleet, review window; plan, state |
| Patch | Patch Update Plans | CSV, JSON | fleet, review window; policy, state |
| Patch | Patch Reboot Queues | CSV, JSON | per execution |
| Patch | Patch Rollback Runs | CSV, JSON | per execution |
| Compliance | Compliance Evidence | JSONL, CSV | fleet, system, review window; policy, verdict |
| Compliance | Compliance Remediation Requests | CSV, JSON | fleet, system, review window; policy, state |
| Compliance | Compliance Remediation Plans | CSV, JSON | fleet, system, review window; policy, state |
| Compliance | Compliance Remediation Executions | CSV, JSON | fleet, system, review window; policy, state |

The machine-readable version of this table is served at `GET /reports/catalog` and drives the UI's labels and capability - the product never shows a report kind the backend can't actually produce.

## Where to generate each report

- `Report > Package Reports` - inventory + update posture across the fleet. The **Outdated Packages** and **Update Compliance** sections each have an **Export report** button (records a run). The page also hosts **Recent Reports** and **Scheduled Reports**.
- Patch report kinds generate from the **Patch Update Plans / Executions** pages (per-plan, per-execution, and review-window exports).
- Compliance report kinds generate from the **Compliance** pages (evidence + remediation exports).
- `Report > Fleet Operations`, `Activity Feed`, `Analytics` are read dashboards; `Config Audit` offers a **table export** of audit rows.

## Manual vs scheduled

A report kind can be run **on demand** (open its screen, apply scope/filters, Export) or produced on a **schedule** so a fresh run lands regularly without someone remembering to click. A schedule references the same report kinds; prefer one for anything an auditor or compliance regime expects on a cadence. Scheduled exports require the **Scheduled Exports** entitlement.

A schedule's scope and filters are entered as a **JSON filter snapshot**, using the same `filters_snapshot` keys the report kind accepts. Read the keys for a kind from `GET /reports/catalog` and paste them into the JSON field; there are no per-kind form controls.

Exports are **bounded**: report and evidence exports cap the review window and row count rather than letting one export pull an unbounded range. If an export is rejected for being too large, narrow the window or filters and re-run.

## Scope & access

Report generation enforces role (admin/maintainer) and **fleet scope** before any rows are materialized: a scoped operator only ever sees in-scope systems, an explicit out-of-scope system is a not-found, and an empty scope yields an empty export - no out-of-scope hostnames, package names, or counts leak. Report-run and schedule *management* is tenant-wide-admin only. Credential secrets are never exportable.

> **Reports read; they don't act.** Nothing on these screens mutates a host. That's deliberate - the reporting surface is safe to hand to read-only auditors.

## What is not a report kind

Some domains are viewable in the product but are not report kinds, so they produce no recorded run and cannot be scheduled. They export as table shortcuts or are read-only dashboards: fleet inventory, package inventory, job and automation history, audit events, access grants and reviews, session recordings, and content, mirror, and airgap history.

There is no custom report query language and no PDF output. CSV, JSON, and JSONL are the supported formats.

## Audit trail

Configuration changes, access decisions, patch/remediation dispatches, report exports, and retention changes all write audit rows. Retention is set under **Admin** (`Settings > Admin > Audit`). The event shapes an external SIEM would consume are documented in the [audit event schema](audit-schema.md).

## Related

- Report kind contract: [reporting contract](reporting-contract.md). Audit events: [audit event schema](audit-schema.md).
- **Monitoring & Alerts** - live dashboard, drift detection, and outbound webhooks.
- **Compliance Workflows** - verdicts and evidence exports for compliance regimes.
