---
title: Audit event schema
description: The audit event wire format and delivery contract an external SIEM consumes.
---

**Schema version: 1**

Every security-relevant action in Praxis emits an audit event. Events land in the built-in `audit_events` table and fan out to any configured external sinks (Settings → Audit Export).

This document is the wire format contract. Breaking changes bump `schema_version`.

---

## Wire format

```json
{
  "schema_version": 1,
  "event_uuid": "c9f1…",
  "timestamp": "2026-04-22T00:00:00.000Z",
  "action": "session.open",
  "outcome": "success",
  "actor": {
    "user_id": 42,
    "username": "alice",
    "ip": "10.0.0.5"
  },
  "target": {
    "kind": "session",
    "system_id": 7,
    "id": "123"
  },
  "context": { ... per-action payload ... }
}
```

Fields:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | int | Bumped on breaking changes. Consumers should reject unknown versions. |
| `event_uuid` | string | Stable ID. Dedup key for at-least-once sinks. |
| `timestamp` | ISO 8601 UTC | Event time at the Praxis server. |
| `action` | dotted string | See vocabulary below. |
| `outcome` | `success` / `failure` / `denied` | `denied` = permission gate rejected; `failure` = ran but errored. |
| `actor` | object | User who triggered the action. All fields nullable. |
| `target` | object | What the action applied to. All fields nullable. |
| `context` | object | Action-specific payload. Stable within a given `action`+`schema_version`. |

## Action vocabulary

### Sessions

| Action | When it fires | `context` keys |
|---|---|---|
| `session.open` | Interactive terminal session established | `login`, `fleet_role`, `cert_serial`, `ttl_s` |
| `session.close` | User clicked Disconnect or remote EOF | `reason`, `login` |
| `session.idle_kill` | Idle timeout sweeper closed the session | `reason`, `login` |
| `session.max_duration` | Cert TTL hit, hard close | `reason`, `login` |

### Command execution

| Action | `outcome` | `context` keys |
|---|---|---|
| `command.exec` | `success` / `failure` | `command`, `exit_code`, `execution_time_ms`, `bypass_validation` |
| `command.exec` | `denied` | `reason_code`, `reason` |

### File transfer

| Action | When it fires | `context` keys |
|---|---|---|
| `file.upload` | Web UI → host SFTP upload | `login`, `size_bytes`, `sha256`, `local_filename`, `error?` |
| `file.download` | Host → web UI SFTP download | `login`, `size_bytes`, `sha256`, `error?` |
| `file.mkdir` | New remote directory | `login`, `error?` |
| `file.unlink` | Remote file/dir deletion | `login`, `error?` |

`target.kind` is `path` and `target.id` is the remote path.

### Access bindings + requests

| Action | `context` keys |
|---|---|
| `binding.create` | `fleet_role_id`, `subject_user_id`, `subject_app_role_id`, `scope_group_id`, `scope_smart_group_id`, `expires_at` |
| `binding.delete` | Snapshot of the deleted binding shape |
| `access_request.create` | `fleet_role_id`, `scope_group_id`, `scope_smart_group_id`, `duration_seconds`, `justification` |
| `access_request.approve` | `requested_by`, `fleet_role_id`, `resulting_binding_id`, `duration_seconds`, `comment` |
| `access_request.reject` | `requested_by`, `comment` |
| `access_request.revoke` | none |

### Authentication

| Action | `context` keys |
|---|---|
| `totp.step_up` | `method` = `totp` or `recovery` |

### Secrets, Vault & PKI

Sensitive secret and PKI actions emit unified audit events so secret access and
CA lifecycle changes reach external sinks. `context` carries only locators and
non-secret metadata, never secret values, passwords, private keys, certificate
material, tokens, or raw Vault exception text.

`ssh.user_cert.sign` fires when Vault signs a short-lived SSH *user* certificate
for host access, at mint time (independent of whether the subsequent SSH
connection succeeds), for the actor-attributed paths: interactive sessions
(`purpose=session`) and web file transfer (`purpose=file_transfer`). Backend
SSH that reuses the pooled connection helper (e.g. command execution) has no
single user actor at the mint point; that host access is audited via its parent
`command.exec` event instead. Note `session.open` separately records the same
`cert_serial` as part of the session lifecycle.

| Action | When it fires | `context` keys |
|---|---|---|
| `credential.secret.reveal` | A credential's secret is revealed from Vault | `name`, `auth_method`, `vault_path` |
| `credential.create` | New credential created (managed or linked) | `name`, `auth_method`, `vault_path`, `mode` |
| `credential.update` | Credential metadata and/or its Vault secret updated | `name`, `auth_method`, `secret_updated` (bool) |
| `credential.delete` | Credential deleted (Vault secret + DB metadata) | `name`, `auth_method` |
| `vault.secret.read` | Direct Vault secret read (incl. specific version) | `vault_path`, `version?` |
| `vault.secret.write` | Direct Vault secret create/update | `vault_path` |
| `vault.secret.password_update` | Password field updated within a Vault secret | `vault_path`, `username` |
| `vault.secret.delete` | Direct Vault secret deleted | `vault_path` |
| `ssh.user_cert.sign` | Short-lived SSH user cert minted for host access | `login`, `ttl_s`, `cert_serial`, `purpose` |
| `ssh.ca.rotate` | SSH CA keypair regenerated in Vault | none |
| `ssh.ca.revoke_user_certs` | SSH CA identifier bumped and pooled sessions dropped | none |

`target.kind` is `credential` (with `target.id` = credential id), `vault_secret`
(with `target.id` = vault path), `system` (for `ssh.user_cert.sign` when the
target system is known; otherwise `ssh_user_cert`), or `ssh_ca`.

### Guided system onboarding

A setup holds no secret and creates nothing until it finishes, so these events
record decisions and outcomes rather than state changes. `target.kind` is
`onboarding_draft` and `target.id` is the setup's opaque handle, except on a
successful finish, where the target is the host that now exists.

| `action` | When | `outcome` | `context` |
| --- | --- | --- | --- |
| `onboarding.draft.create` | An operator opens a guided setup | `success` | none |
| `onboarding.draft.cancel` | An operator abandons a setup | `success` | none |
| `onboarding.verify` | A verification run completes | `success` when verified, else `failure` | `reason_code`, `checks` (per-check `check` / `status` / `reason_code`) |
| `onboarding.host_key.decision` | An operator approves or rejects an offered host key | `success` on approval, `denied` on rejection | `decision`, `fingerprint`, `key_type` |
| `onboarding.verify.skipped` | An operator explicitly declines verification | `success` | none |
| `onboarding.discover` | Discovery completes | `success` | `support_mapping`, `package_family` |
| `onboarding.finish` | Finalization is attempted | `success`, `failure`, or `denied` | on success `hostname`, `status`, `verification_skipped`, `host_key_decision`; otherwise `code` |

Verification context carries reason codes only. The transport and library text
behind a failure is never recorded, so an audit row cannot leak a path, a key,
or an internal hostname.

### Airgap signing keys and import trust

Airgap bundle signing-key and import trust-pin lifecycle events carry only public
identifiers and status metadata. Context must never include armored key bodies,
private key material, Vault paths, bundle tar contents, or raw GPG/Vault
exception text.

| Action | When it fires | `target.kind` | `context` keys |
|---|---|---|---|
| `airgap.signing_key.created` | Initial instance bundle signing key is bootstrapped | `airgap_signing_key` | `key_id`, `fingerprint`, `key_uid`, `status` |
| `airgap.signing_key.rotated` | Active bundle signing key is rotated: old active becomes `rotating_out`, new key becomes `active` | `airgap_signing_key` | `old_key_id`, `old_fingerprint`, `old_status`, `new_key_id`, `new_fingerprint`, `new_status` |
| `airgap.signing_key.retired` | A `rotating_out` bundle signing key is retired | `airgap_signing_key` | `key_id`, `fingerprint`, `status` |
| `airgap.import_trust.added` | Import-side public key trust pin is added | `airgap_import_trust` | `key_id`, `fingerprint`, `key_uid` |
| `airgap.import_trust.removed` | Import-side public key trust pin is soft-deleted | `airgap_import_trust` | `key_id`, `fingerprint`, `key_uid` |

### Compliance remediation requests

Non-executing workflow that captures operator intent to remediate a failing compliance evidence row plus the approval-gate state. Approval flips the request state only: no host mutation, no command execution, no dispatch.

`target.kind` is `compliance_remediation_request` and `target.id` is the request id. `target.system_id` is the host the request applies to.

All four actions emit `outcome=success` (no `denied` or `failure` paths in the current release; validation errors raise before any audit row is written).

Stable `context` keys present on every action: `policy_id`, `policy_slug`, `policy_version`, `check_id`, `check_slug`, `check_kind`, `system_id`, `evidence_id`, `evaluation_run_id`, `verdict_snapshot`, `severity_snapshot`, `state`, `requested_by`, `decided_by`.

| Action | When it fires | Additional `context` keys |
|---|---|---|
| `compliance_remediation.requested` | Operator opens a remediation request for a failing evidence row | `has_guidance_snapshot` (bool), `justification_length` (int, 0 when omitted) |
| `compliance_remediation.approved` | Admin approves the request; state flips to `approved`. Does NOT execute anything | `separation_of_duties_enforced` (bool, always `true` in the current release), `decided_reason_length` (int) |
| `compliance_remediation.rejected` | Admin rejects the request; terminal state | `decided_reason_length` (int) |
| `compliance_remediation.cancelled` | Admin or original requester withdraws the request; terminal state | `self_cancel` (bool, `true` when the requester withdrew their own request), `decided_reason_length` (int) |

### Compliance remediation plan previews

Non-executing execution-plan previews derived from approved remediation requests. Building a plan never runs anything on a host, dispatches a job, or mutates the source request. `plan_steps` is a JSON list of structured operator-readable intent objects (action, target, expected value, safety notes), NOT executable shell.

`target.kind` is `compliance_remediation_plan` and `target.id` is the plan id. `target.system_id` is the host the plan applies to.

All three actions emit `outcome=success`. Validation failures (e.g. building against a non-approved request) raise before any audit row is written.

Stable `context` keys present on every action: `request_id`, `policy_id`, `check_id`, `system_id`, `policy_slug`, `policy_version`, `check_slug`, `check_kind`, `severity_snapshot`.

| Action | When it fires | Additional `context` keys |
|---|---|---|
| `compliance_remediation_plan.built` | First plan preview is generated for an approved remediation request | `plan_state` (`planned` / `unsupported` / `failed`), `plan_kind`, `step_count` (int), `refreshed` (bool, always `false`), `superseded_plan_id` (int or null) |
| `compliance_remediation_plan.refreshed` | A non-acknowledged current draft plan is rebuilt in place (idempotent recompute; row id stable) | `plan_state`, `plan_kind`, `step_count`, `refreshed` (bool, always `true`), `superseded_plan_id` (always null) |
| `compliance_remediation_plan.unsupported` | The resolved plan kind is `unsupported` (paired with the matching `built`/`refreshed` event) | `unsupported_reason` (string) |
| `compliance_remediation_plan.acknowledged` | Operator explicitly acknowledges the current plan ("this is what I intend to run"); metadata only, no execution | `plan_kind`, `ready_for_execution` (bool) |
| `compliance_remediation_plan.superseded` | An acknowledged current plan is replaced by a fresh build (the new plan becomes current; the old one is locked as history) | `superseded_by_plan_id` (int, the new current plan id) |

The plan read envelope also exposes lifecycle metadata fields: `check_definition_fingerprint`, `is_current`, `superseded_by_plan_id`, `acknowledged_at`, `acknowledged_by`, `is_stale`, and `ready_for_execution`. These are derived/snapshot fields and are not separate audit events. `ready_for_execution` is the gate an execution flow consults; it is true only when the source request is still `approved`, the plan is current, `state='planned'`, acknowledged, not stale, and of an executable plan_kind (i.e. one of `package_install_preview` / `package_remove_preview` / `package_upgrade_preview`; review-required kinds always read `false`).

### Compliance remediation execution attempts

Durable, **pre-dispatch** record of an operator's intent to execute a current acknowledged ready-for-execution package remediation plan. The `.created` action persists the snapshot + actor + approval lineage and emits one audit event; it does **not** run commands, dispatch jobs, queue work, mutate hosts, refresh facts, scan packages, reboot, or roll back. The dispatch actions below add transport selection, dispatch, and outcome recording on top of the same row via `.dispatched` / `.succeeded` / `.failed` / `.cancelled` events.

`target.kind` is `compliance_remediation_execution_attempt` and `target.id` is the attempt id. `target.system_id` is the host the attempt applies to.

The readiness gate is re-checked at write time so a stale UI cannot bypass it by replaying a previously-true `ready_for_execution` flag. Validation failures (missing plan, superseded plan, non-`planned` state, unacknowledged, stale, non-package plan_kind, source request no longer `approved`) raise **before** any audit row is written.

| Action | When it fires | `context` keys |
|---|---|---|
| `compliance_remediation_execution.created` | Operator creates a durable execution-attempt row for an acknowledged, ready, package remediation plan. State persists as `pending`; nothing dispatches yet. | `attempt_id` (the attempt id; also surfaced as the `target.id`), `request_id`, `plan_id`, `policy_id`, `check_id`, `system_id`, `policy_slug`, `policy_version`, `check_slug`, `check_kind`, `severity_snapshot`, `plan_kind_snapshot` (one of the three executable package plan kinds), `package_name` (nullable when the plan was built against a deleted check), `package_version_target` (set for upgrade plans), `state` (always `pending` for this action), `approval_decided_by` (snapshot of the request's approver, nullable if the user row is later deleted), `dispatched` (bool, always `false` for this action) |
| `compliance_remediation_execution.dispatched` | Operator dispatches a `pending` attempt through the governed patch transport. State flips from `pending` → `dispatched`; `dispatched_at` is set. The audit row commits BEFORE the transport call so a transport hang still leaves a durable record. | Same stable keys as `.created` (without `dispatched`), plus `package_family` (`apt` / `dnf`) and `command_program` (the argv[0], i.e. `apt-get` or `dnf`) |
| `compliance_remediation_execution.succeeded` | Dispatch returned exit 0 with no transport error. State flips from `dispatched` → `succeeded`; `completed_at` set; `exit_code`, `duration_ms`, `transport`, bounded `stdout_summary` / `stderr_summary` written to the attempt row. | Same stable keys as `.created` (without `dispatched`), plus `package_family`, `exit_code` (always `0`), `duration_ms`, `transport`, `failure_reason` (always `null`) |
| `compliance_remediation_execution.failed` | Dispatch returned a non-zero exit code, the transport raised, or the adapter raised. State flips `dispatched` → `failed`; `failure_reason` carries the short stable code (`transport_unavailable`, `transport_error`, `package_manager_failed`, etc.); `error_message` carries a bounded operator-readable summary. | Same stable keys as `.created` (without `dispatched`), plus `package_family`, `exit_code` (may be `-1` for transport errors), `duration_ms`, `transport`, `failure_reason` |
| `compliance_remediation_execution.batch_dispatched` | Operator triggers a bounded request-scoped batch dispatch. The batch loops `dispatch_attempt(...)` over every `pending` attempt for the named request (capped by `limit`, default = `MAX_BATCH_SIZE = 500`); per-attempt `.dispatched` / `.succeeded` / `.failed` events still fire from the inner path. This event records the aggregate once per batch call, after the loop finishes. `target.kind` is `compliance_remediation_request` (not the attempt) because the batch is request-scoped; `target.id` is the request id. | `request_id`, `policy_id`, `policy_slug`, `check_slug`, `check_kind`, `system_id`, `limit`, `total_eligible` (≤ `limit`), `dispatched_count` (succeeded + failed; excludes refused), `succeeded_count`, `failed_count`, `refused_count` (count of attempts whose pre-flight `ComplianceError` left the row in `pending`), `failure_breakdown_by_reason` (dict keyed on `failure_reason` for the failed subset) |

The attempt read envelope additionally exposes `approval_decided_at`, `transport`, `failure_reason`, `error_message`, `exit_code`, `duration_ms`, `stdout_summary`, `stderr_summary`, `dispatched_at`, and `completed_at`. These are reserved on `pending` attempts and populated on the same row as the attempt moves through `dispatched → succeeded | failed`. Bounded fields: `stdout_summary` / `stderr_summary` are truncated to 64 KiB each at the service layer; `error_message` is truncated to 2048 chars; `transport` and `failure_reason` are bounded by the column type.

The readiness gate is re-checked at dispatch time so a stale UI cannot bypass it by replaying a previously-true `ready_for_execution` flag. Lineage drift (mismatched request_id, plan_kind drift, missing package_name, unsafe package_name, missing/unparsable upgrade version target, unknown host package-manager family, source request no longer approved, plan superseded/stale/unacknowledged/non-`planned`) raises **before** any audit row is written and before any host mutation. The dispatch path uses only the governed transport seam (`patch_execution_dispatch_service.default_dispatch`); there is no raw SSH/agent/subprocess/local-fallback path.

### Patch reboot reconciliation

The reboot queue for an execution is rebuilt by a reconcile pass. When that pass raises, the failure is recorded rather than left to a log line, because the queue counts are what an operator reads as "what still has to reboot".

`target.kind` is `patch_update_execution` and `target.id` is the execution id.

| Action | When it fires | `outcome` | `context` keys |
|---|---|---|---|
| `patch_update_execution_reboot.reconcile_failed` | A reboot reconcile pass for an execution raises, and the failure is surfaced. A queue that merely reads as incomplete does not emit this action | `failure` | `execution_id`, `plan_id`, `phase`, `wave_index`, `reason` (redacted and bounded), `recorded` (bool, whether the marker was persisted on the execution) |

The same failure raises a `patch.reboot_required` notification at `error` severity and blocks dependent waves. See [when the reboot queue is incomplete](patch-workflows.md#when-the-reboot-queue-is-incomplete) for the operator path.

### Patch and compliance notifications

This release expands the **notification** vocabulary alongside the existing audit-event vocabulary. Notifications flow through the existing `notification_service.create_notification` → `alert_service.send_alert` path: per-user disable (`notification_preferences`), per-fleet smart-group scope, and the existing retry/dead-letter behavior all apply unchanged. There are no new audit-event actions here; emission lives **beside** the existing service-level audit emits at the same stable state transitions, and the helper functions in `app.services.notification_events` are best-effort (failures log + swallow so an audit event always wins precedence).

Event vocabulary (each is also a valid `disabled_types` entry on the `/notification-preferences` route and a valid `events[]` entry on an `AlertConfig`):

| Event | Severity | Fires from |
|---|---|---|
| `patch.executed` | `info` on succeeded, `warning` on canceled, `error` on failed | `patch_execution_dispatch_service._maybe_finalize_execution` when an execution reaches its terminal state |
| `patch.reboot_required` | `warning` on a queued reboot, `error` on a failed reconcile | `patch_reboot_service.auto_reconcile_on_terminal` when a `queued` reboot row is added for a host that needs a reboot, and `patch_reboot_service.surface_reconciliation_failure` when a reconcile pass raises. A queue that merely reads as incomplete raises no notification |
| `patch.reboot_completed` | `info` on healthy, `error` on failed | `patch_reboot_verify_service.verify_due_reboots` once per row's terminal verify transition |
| `patch.rollback_started` | `warning` | `patch_rollback_dispatch_service.start_rollback_execution` |
| `patch.rollback_completed` | `info` on succeeded, `warning` on canceled, `error` on failed | `patch_rollback_dispatch_service._maybe_finalize_run` when the run reaches its terminal state |
| `compliance.evaluated` | tracks the dominant per-host verdict (`pass` → info, `fail` → warning, `error` → error) | `compliance_evaluation_service.evaluate_policy_for_host` after the evidence rows commit |
| `remediation.requested` | `warning` | `compliance_remediation_service.create_request` after commit |
| `remediation.ready` | `info` | `compliance_remediation_plan_service.acknowledge_plan` only when the acknowledgement flipped `ready_for_execution` to true |
| `remediation.executed` | `info` | `compliance_remediation_execution_service.dispatch_attempt` on `succeeded` |
| `remediation.failed` | `error` | `compliance_remediation_execution_service.dispatch_attempt` on `failed` (carries `failure_reason` in the message body) |

Titles and message bodies are bounded at 160 / 1024 chars respectively. Notifications are broadcast (no `user_id` target) so they appear in the unread feed for every operator who has the event enabled.

### Patch and compliance reporting / exports

Manual operator-driven export endpoints for review-period reporting. Each event emits **after** the response body is built so the recorded `row_count` matches the bytes the operator received. `target.id` is `null` because the export is a bounded multi-row query, not a single-resource read. `outcome` is always `success`: bad windows, bad filter values, and row-cap violations raise HTTP 422 before any audit row is written.

| Action | When it fires | `target.kind` | `context` keys |
|---|---|---|---|
| `compliance_export.requested` | Operator downloads compliance evidence over a bounded review window via `GET /compliance/exports/evidence.{jsonl,csv}` | `compliance_evidence_export` | `format` (`jsonl` / `csv`), `filters` (`evaluated_after`, `evaluated_before`, `policy_id`, `system_id`, `verdict`), `row_count` |
| `compliance_remediation_export.requested` | Operator downloads compliance remediation requests over a bounded review window via `GET /compliance/exports/remediation-requests` | `compliance_remediation_request_export` | `format` (`csv` / `json`), `filters` (`created_after`, `created_before`, `policy_id`, `system_id`, `state`), `row_count` |
| `patch_execution_export.requested` | Operator downloads patch update executions over a bounded review window via `GET /patch/update-executions/export` | `patch_execution_export` | `format` (`csv` / `json`), `filters` (`started_after`, `started_before`, `plan_id`, `state`), `row_count` |
| `patch_plan_export.requested` | Operator downloads patch update plans over a bounded review window via `GET /patch/update-plans/export` | `patch_update_plan_export` | `format` (`csv` / `json`), `filters` (`created_after`, `created_before`, `policy_id`, `state`), `row_count` |
| `patch_reboot_export.requested` | Operator downloads the per-execution reboot queue via `GET /patch/update-executions/{id}/reboots/export` | `patch_reboot_queue_export` | `format` (`csv` / `json`), `filters` (`execution_id`), `row_count` |
| `patch_rollback_export.requested` | Operator downloads the per-execution rollback dispatch run + per-host rows via `GET /patch/update-executions/{id}/rollback/export` | `patch_rollback_run_export` | `format` (`csv` / `json`), `filters` (`execution_id`), `row_count` |
| `compliance_remediation_plan_export.requested` | Operator downloads compliance remediation plans (current + superseded) over a bounded review window via `GET /compliance/exports/remediation-plans` | `compliance_remediation_plan_export` | `format` (`csv` / `json`), `filters` (`created_after`, `created_before`, `policy_id`, `system_id`, `state`, `current_only`), `row_count` |
| `compliance_remediation_execution_export.requested` | Operator downloads compliance remediation execution attempts over a bounded review window via `GET /compliance/exports/remediation-executions` | `compliance_remediation_execution_export` | `format` (`csv` / `json`), `filters` (`created_after`, `created_before`, `policy_id`, `system_id`, `state`), `row_count` |

Scheduled report runs do NOT add a new audit-event action: the scheduler tick (apscheduler `report_schedules_due` job, every 5 minutes) invokes the same per-kind dispatcher used by the manual export routes, so the same `*_export.requested` audit events fire from the scheduled-firing path. The only persisted difference is the matching `report_runs` row, which is written with `triggered_by='system_scheduled'` (vs `'user'` for manual exports). Operators distinguish manual vs scheduled runs by reading the `triggered_by` column on `GET /reports/runs`. Schedule definitions live in the `report_schedules` table (admin/maintainer write, auditor read via `GET /reports/schedules`) with plain-language cadence (`daily`, `weekly`, or `monthly`). No cron expression ever reaches the wire.

Bounded review-window guard: `created_after`/`created_before` (and `started_after`/`started_before`) default to the last 30 days when both bounds are omitted and a single request cannot span more than `EXPORT_WINDOW_MAX_DAYS = 366` days. The remediation-request and patch-execution exports additionally cap a single response at `EXPORT_MAX_ROWS = 50_000`; oversized filters raise HTTP 422 with operator-readable text rather than truncate. The compliance evidence export is streamed (`yield_per`) and therefore not row-capped.

RBAC: all three export endpoints require `admin` or `maintainer`. Auditors can read individual records through the per-resource detail routes but cannot trigger a bulk export.

---

## Delivery guarantees

Events persist to the database synchronously with the action that emitted them (same DB transaction where reasonable). External sinks receive events **at least once** via the delivery queue:

- Pending delivery rows are drained every 30 seconds.
- Transport failures retry with exponential backoff: 5s → 15s → 1m → 5m → 15m → 1h.
- After 6 attempts, deliveries move to `dead_letter` and stop retrying automatically. Admin can re-queue via `POST /audit/deliveries/{id}/retry`.
- Sink receivers should deduplicate on `event_uuid`.

## Transport formats

### HTTP

```
POST {target}
Content-Type: application/json
X-Praxis-Signature: sha256={hex}   # when hmac_secret is configured
User-Agent: Praxis-Audit/1.0

{ event JSON }
```

Signature = HMAC-SHA256 of the request body bytes keyed with the sink's secret.

### Syslog (RFC 5424)

TCP (TLS by default, disable via `config.tls=false`). Octet-counting framing per RFC 6587. MSG part is the event JSON. Facility/severity configurable (defaults: user / informational).

### File

JSONL append at the configured path. One event per line. Receiver is expected to rotate.

## Versioning policy

We bump `schema_version` only for breaking changes (field rename, field removal, semantic change to an existing field). Additive changes (new actions, new context keys) do NOT bump version, so consumers must tolerate unknown fields.
