---
title: Remediation workflow
description: The governed request, approve, plan, acknowledge, and dispatch lifecycle that turns a failing check into a fix.
---

The compliance remediation workflow turns a failing compliance evidence row into a tracked, auditable plan of intent, without running anything on a host.

**Praxis does not execute remediation.** The remediation substrate is a non-executing workflow: it records what an operator intends to fix, who approved it, what the fix *would* do, and whether that plan is ready to run. The readiness gate described below is a contract that an executor can consult, not a dispatcher.

This document covers the operator-facing surface of the workflow. For auditor-facing evidence mapping see [`compliance-map.md`](compliance-map.md). For the wire format of the audit events fired along the way see [`audit-schema.md`](audit-schema.md).

---

## Workflow at a glance

```
failing evidence row
      │
      ▼
remediation request  ──reject──▶  (terminal)
  state: requested        ─cancel▶  (terminal, requester or admin)
      │
      ▼ approve  (admin; separation of duties: approver != requester)
remediation request
  state: approved
      │
      ▼ build plan preview
remediation plan
  state: planned | unsupported | failed
  plan_kind: package_install_preview | package_remove_preview |
             package_upgrade_preview | facts_review_required |
             file_review_required | command_review_required |
             unsupported
      │
      ▼ acknowledge  (admin; current plans only)
acknowledged plan
      │
      ├── rebuild ─────────▶ supersede + new current draft plan
      │
      ▼
ready_for_execution gate
  (metadata only; nothing dispatches on it)
```

Every transition emits an audit event via the existing `safe_emit` pipeline. No transition runs commands, dispatches jobs, refreshes facts, scans packages, mutates a host, installs or removes packages, reboots, rolls back, or auto-executes after approval.

---

## Stages

### 1. Remediation request

A maintainer opens a remediation request against a single failing compliance evidence row. The service:

- requires `evidence.verdict == 'fail'`; `pass` and `error` rows cannot be remediated;
- snapshots the policy / check / system / evidence identity (`policy_slug`, `policy_version`, `check_slug`, `check_kind`, `severity_snapshot`, `verdict_snapshot`, `verdict_reason_snapshot`, `evaluation_run_id`);
- resolves remediation guidance, where check-level wins and policy-level is the fallback, bounded to 16 384 chars;
- records the requester and a free-form `justification` (bounded to 4 096 chars).

Audit event: `compliance_remediation.requested`.

States: `requested` (initial), `approved`, `rejected`, `cancelled`. Terminal states refuse further transitions; re-opening means filing a new request so the audit trail records the new intent explicitly.

RBAC:

- create: `admin` or `maintainer`
- read: any authenticated user (auditor inclusive)
- approve / reject: `admin`, and the actor must not be the original requester (separation of duties; SOC 2 CC6.3)
- cancel: `admin` or the original requester (self-withdraw; audit context records `self_cancel`)

### 2. Plan preview (build / refresh)

Once a request is `approved` an operator builds a plan preview. The preview is a structured, operator-readable JSON description of what the fix *would* do. It is **not** executable shell.

The plan vocabulary maps 1:1 to the compliance check kinds:

| Check kind | Plan kind | What the plan says |
|---|---|---|
| `package_installed` | `package_install_preview` | install package X on host Y |
| `package_absent` | `package_remove_preview` | remove package X from host Y |
| `package_version_min` | `package_upgrade_preview` | upgrade package X to >= version |
| `fact_*` | `facts_review_required` | facts describe observed host state; operator must decide what change to make |
| `file_*` | `file_review_required` | file content source is not in the plan; operator must supply intended body |
| `command_*` | `command_review_required` | commands observe a probe; remediation requires operator-defined change |
| (anything else) | `unsupported` | future / unknown check kind; operator must provide remediation manually |

Each step in the plan is a structured object: `action_intent`, `target` descriptor, expected value, and `safety_notes` (`"non-executing preview only; no host change"`). Steps are bounded at 32 entries and 16 384 serialized bytes; truncation is loud (an explicit `review_required` step is appended so consumers cannot mistake a truncated plan for a complete one).

Plan state vocabulary: `planned`, `unsupported`, `failed`.

A SHA-256 fingerprint of the canonical-JSON live check definition is captured at build time. The fingerprint is the **only** staleness signal; the full live definition is never persisted twice.

Audit events: `compliance_remediation_plan.built` on first build, `.refreshed` when an existing draft is rebuilt in place, `.unsupported` paired with the build event when the plan resolves to `unsupported`.

### 3. Acknowledgement and supersede

An operator who has reviewed a plan **acknowledges** it, which is the explicit "this is the plan I intend to run" signal. Once acknowledged the row is immutable from the service layer. A subsequent rebuild creates a new current draft and points the old row's `superseded_by_plan_id` at it; the old row keeps its `acknowledged_at` / `acknowledged_by` verbatim as supersede history.

A partial unique index in the database (`request_id WHERE superseded_by_plan_id IS NULL`) guarantees exactly one current plan per remediation request.

Acknowledgement fails closed when the plan is:

- already acknowledged;
- not current (already superseded);
- not in state `planned` (cannot acknowledge `unsupported` / `failed` previews);
- stale (live check definition no longer matches the build-time fingerprint, or the source check has been deleted; a NULL fingerprint also reads as stale);
- belongs to a request whose state is no longer `approved`.

RBAC: `admin` only (operator-level decision; intentionally stricter than the cancel RBAC).

Audit events: `compliance_remediation_plan.acknowledged`, and `compliance_remediation_plan.superseded` when a rebuild replaces an acknowledged plan.

### 4. The `ready_for_execution` gate

The plan read envelope surfaces a derived `ready_for_execution` boolean. It is **true** only when every condition below holds:

- the source request is still `approved`;
- the plan is current (`superseded_by_plan_id IS NULL`);
- the plan state is `planned` (not `unsupported` / `failed`);
- the plan is acknowledged;
- the plan is not stale;
- the plan kind is one that can be acted on, meaning one of `package_install_preview`, `package_remove_preview`, or `package_upgrade_preview`. Review-required and unsupported kinds always read `ready_for_execution=false`.

The gate consults the live check definition (to recompute staleness) but never touches a host. The flag is the contract an executor would read; on its own it dispatches nothing.

### 5. Read-only rollups

Two read-only API surfaces summarize the workflow without changing it:

- **Fleet summary**: `GET /compliance/remediation/fleet-summary` returns counts by request state, current-plan state, acknowledgement, `ready_for_execution`, staleness, plus a per-severity rollup keyed on the request `severity_snapshot`.
- **Per-host inventory**: `GET /compliance/systems/{system_id}/remediation` returns five bounded paged sections: `open_requests`, `approved_requests`, `current_plans`, `ready_plans`, `superseded_history`. A shared `limit` (default 50, max 500) plus per-section `*_offset` query params let operators page through one section without disturbing the others. Missing hosts return 404.

Both endpoints accept any authenticated user (auditor inclusive). Neither emits new audit events.

---

## Common failure / not-ready cases

Operators reading the inventory will see specific lifecycle states. The most common ones, and what they mean:

- **`request.state == 'requested'`, no plan yet.** Approval pending. Build the plan after approving.
- **`plan.state == 'unsupported'`.** The check kind has no preview shape; operator must provide remediation manually. `unsupported_reason` explains why.
- **`plan.state == 'failed'`.** A row referenced during build vanished mid-transaction. `error_message` explains; rebuild the plan.
- **`plan.plan_kind == '*_review_required'`.** The plan persists but `ready_for_execution=false`. There's no safe automated remediation; the step text tells the operator what manual change to make.
- **`is_stale=true`.** Live check definition no longer matches the build-time fingerprint, or the source check is gone. Rebuild the plan and re-acknowledge the fresh row.
- **`is_current=false` (superseded).** This row is historical; consult `superseded_by_plan_id` for the new current plan.
- **`acknowledged_at IS NOT NULL` but `ready_for_execution=false`.** Check the lifecycle metadata: state may be non-`planned`, the request may have been rejected/cancelled out-of-band, the plan may have gone stale after acknowledgement, or the plan_kind may be `*_review_required`/`unsupported`.

---

## What the remediation workflow is not

- **Not a runner.** No SSH, no subprocess, no package install/remove, no facts refresh, no package scan, no OpenSCAP, no rollback, no reboot, no approval auto-execution.
- **Not a dispatcher.** Approving a request or acknowledging a plan only flips metadata; nothing is queued, scheduled, or enqueued as a side effect.
- **Not a content store.** File-restore and command-style checks produce `*_review_required` previews; Praxis does not currently store the source content needed to automate them.
- **Not a notification system.** The remediation workflow emits audit events but does not push inbox notifications, chat messages, or email. Operators consume the audit log and the rollup endpoints.
- **Not a frontend.** No dashboard widgets, exports, or UI affordances: the workflow is backend, API, and data-model substrate plus this documentation.

---

## Where to look next

- [Compliance evidence map](compliance-map.md): how remediation audit events line up with SOC 2, PCI, and HIPAA control families.
- [Audit event schema](audit-schema.md): wire format and stable context keys for every audit action listed above.
