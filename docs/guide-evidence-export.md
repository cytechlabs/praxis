---
title: Export evidence for an audit
description: Produce the compliance, patch, and access records an auditor asks for, in a form that stands up.
---

An auditor asks what happened, who approved it, and how you know. This is where
each of those lives and how to get it out.

Bulk exports are admin and maintainer only. A read-only auditor can review every
record in the interface without being able to pull bulk exports. Bulk compliance
and evidence exports, and scheduled exports, are paid entitlements. See
[editions and feature tiers](editions.md).

## Know which kind of export you are producing

Praxis distinguishes two things that both produce a download:

- **A table export** downloads the table you are looking at, with its current
  filters. It is a convenience and it is **not recorded** as a report run.
- **A report** is a named report kind with a defined scope, filters, and
  format. Generating one materialises the rows, streams the download, **and
  records a durable run** you can point at afterwards.

For anything an auditor will rely on, generate a report. The recorded run is
what lets you show later which export you gave them.

## Compliance evidence

**Verify > Compliance Policies**, or a policy's Evidence tab. Filter to the policy,
verdict, and review window the auditor asked for, then export as JSONL or CSV.

Export rows carry both the stable internal fields (`verdict`, `verdict_reason`,
`runner_owner`, `runner_status`) and the humanised columns (`status`,
`verdict_reason_label`, `runner_label`). The internal fields are pinned, so a
script an auditor writes against them keeps working.

Be straight about what a verdict is. Praxis reports what its checks observed
against host facts and probe evidence. It is not a certification. Statuses like
**Awaiting host scan** and **Coverage pending** mean a check has not been
evaluated, not that it failed. Say so rather than letting a reader treat them as
passes. The control mapping is in the
[compliance evidence map](compliance-map.md).

## Change evidence for patching

For "show me that this vulnerability was fixed, with approval":

- **Patch update plans** and **patch executions** export per plan, per
  execution, or across a review window.
- Rollback runs and reboot queues export per execution.

Each carries the approval that gated it. Because approval freezes the plan, the
approved record and the dispatched change are the same thing, which is usually
the point the auditor is testing.

## Remediation evidence

**Verify > Compliance Remediation** exports requests, plans, and executions
separately, each with its own labelled export. Together they show the full
governed path: a failing check, a request, an approval, a plan, and a dispatch.

## Access evidence

- An access review exports as CSV at completion. See
  [run an access review](guide-access-review.md).
- Access requests, decisions, and session activity are in the audit log.
- **Operate > Active Sessions** is the live picture, not evidence; export the
  audit window instead.

## The audit log

**Secure > Audit Log** is the forensic record: every mutating action with
the actor, the previous value, and the new value. Filter by actor, host, type,
and date range, and export to CSV.

Retention is configurable under **Settings > Admin > Audit** and defaults to 90
days. **Check it against the retention your regime requires before you need
the data**, because a sweep that has already run cannot be undone. Increasing
retention does not bring back rows that were purged.

The event shapes an external SIEM would consume are in the
[audit event schema](audit-schema.md). Shipping audit events off-box is the
durable answer to a retention window shorter than your obligation.

## Bounds on exports

Report and evidence exports cap the review window and the row count rather than
letting one export pull an unbounded range. If an export is rejected as too
large, narrow the window or the filters and run it again. For a long period,
several bounded exports are the supported shape.

Exports respect fleet scope. A scoped operator's export contains only in-scope
hosts, and out-of-scope hostnames, package names, and counts do not leak into
it. If an auditor needs fleet-wide coverage, produce the export as someone whose
scope is fleet-wide.

## Put it on a schedule

Anything a regime expects on a cadence should be a scheduled report rather than
a recurring calendar reminder. Scheduled exports are a paid entitlement, and a
schedule's scope and filters are entered as a JSON filter snapshot using the
keys from `GET /reports/catalog`. See
[reports and schedules](reports-and-schedules.md).

## Related

- [Reporting contract](reporting-contract.md) for what each report kind
  guarantees.
- [Compliance workflows](compliance-workflows.md)
- [Remediation workflow](remediation-workflow.md)
