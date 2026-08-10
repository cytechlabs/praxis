---
title: Monitoring and alerts
description: Dashboards, activity, audit logs, drift detection, and outbound webhooks.
---

Praxis is an ops tool; visibility into what's happening on the fleet is the whole point. This section covers dashboards, activity streams, drift detection, and outbound alerting.

## Dashboard

`Operate > Dashboard` is the top-level operational view. Covered in [Getting Started](getting-started.md); the short version is: StatCards for fleet posture at the top, HealthBanner for critical alerts, detail cards below for breakdowns.

The **Drifted Systems** card counts systems that diverge from at least one enabled baseline. Click through to the drift matrix ([see below](#drift-detection)).

## Activity Feed

`Report > Activity Feed` is a live event stream - system registrations, job starts/completes, credential changes, alert fires, approval decisions, anything interesting. It's the same data the `ActivitySidebar` polls every 15 s, just paginated and filterable. Use it for "what happened in the last hour?" incident triage.

## Audit Logs

`Secure > Audit Log` is the **forensic** log - every mutating action, with the actor's user_id, old value, new value, and a SHA256 of the command where relevant. Unlike Activity Feed (which is about human-readable recent activity), Audit Logs is immutable and complete, intended for post-incident investigation and compliance.

Filters by actor, system, audit_type, and date range. Export to CSV for offline analysis.

## Fleet Operations

`Report > Fleet Operations` records every bulk action: CA trust deploy, bulk status change, bulk tag, bulk decommission. Each operation has a `target_count`, per-system success/failure counts, and the full parameter snapshot. Useful when you want to know "which of the 50 systems I bulk-updated actually took the change?"

## Analytics

`Report > Analytics` provides fleet-wide time-series - patch compliance over time, failure rate, approval throughput. Useful for reporting to non-operators who want the big picture.

## Alerts and Webhooks

Praxis emits **events** for interesting state changes. An **AlertConfig** subscribes to one or more event types and routes matching events to Slack or a generic webhook.

### Supported events

`job_completed`, `job_failed`, `job_cancelled`, `job_rollback`, `system_unreachable`, `system_recovered`, `security_updates`, `host_eol_approaching`, `host_eol_reached`, `host_key_changed`, `package_scan_complete`, `credential_change`, `system_added`, `system_removed`, `bulk_operation_complete`, `audit_event`, `fleet_operation_complete`

### Creating an alert config

`Settings > Alert Configs > New Alert Config`. Provide:

- **Name** - human-readable label
- **Type** - `slack` or `webhook` (generic JSON)
- **Destination URL** - Slack incoming webhook or your generic endpoint
- **Events** - checkbox list; pick the events this config should fire on
- **Scope (smart group)** - optional; when set, only events from systems in this smart group dispatch. Leave blank for fleet-wide.
- **HMAC Secret** - optional; when set Praxis signs every request with `X-Praxis-Signature: sha256=<hex>` so your endpoint can verify authenticity

### Payloads

**Slack** configs get Block Kit formatted messages with severity colour, title, message, event type, and timestamp. Drop them straight into any Slack channel.

**Generic** configs get a flat JSON body:

```json
{
  "event_type": "job_failed",
  "title": "Job 'Weekly patch' failed on web-01",
  "message": "exit_code=1: package 'nginx' failed to install",
  "severity": "error",
  "timestamp": "2026-04-20T21:15:32.441Z"
}
```

### HMAC verification

When you set a secret, Praxis signs the raw body with HMAC-SHA256 and sends `X-Praxis-Signature: sha256=<hex>`. On your endpoint:

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers["X-Praxis-Signature"]):
    abort(401)
```

### Retry queue and dead-letter

Delivery is not fire-and-forget. Every dispatched event creates an `AlertHistory` row that tracks status, attempt count, response code, and next retry time. A scheduler sweep runs every 30 seconds and retries failed rows on exponential backoff (30 s, 2 min, 10 min, 30 min, then **dead_letter** after 5 attempts).

Alert history is browsable per config. Dead-lettered rows surface a red retry button - click to force an immediate retry when the downstream has recovered.

### Test fire

Every alert config has a **Test** button that delivers a synthetic payload so you can verify the destination URL + HMAC setup before real events fire.

## Drift Detection

Drift detection tells you what systems *should* look like, and surfaces where they don't. A **Baseline** is a named rule set; a **BaselineCheck** is a snapshot of one system's compliance against one baseline at one moment.

### Defining a baseline

`Verify > Baselines > New Baseline`. The editor has three sections:

1. **Basics** - name, description, scope (entire fleet or a smart group), enabled, check interval in hours (default 24)
2. **Packages** - rules of the form `{name, check}` where `check` is `required`, `forbidden`, or `version_pin` (version-pin adds a `version` field)
3. **Services** - rules of the form `{name, check}` where `check` is `running`, `stopped`, `enabled`, or `disabled`

### How checks run

A scheduler sweep runs every 15 minutes and triggers any baseline whose last run is older than its interval. For each targeted system:

- **Package state** is read from the existing `packages` inventory table - no extra SSH load
- **Service state** is queried fresh via `systemctl is-active <name>` + `systemctl is-enabled <name>` over the system's SSH credential, batched in one round-trip per service

The diff engine compares actual state against each rule and records a `BaselineCheck` row with status `compliant`, `drifted`, or `error`. Drifted rows carry a `drift_details` JSON array listing each offending rule and the reason.

Click **Run now** on a baseline for on-demand evaluation when you don't want to wait for the scheduled sweep.

### Viewing drift

`Verify > Drift` shows the matrix - systems x baselines with a cell per pair showing the latest status icon. Green tick = compliant; red X = drifted; amber triangle = error; grey question mark = never evaluated. Click any drifted cell to open the drawer with the full list of failing rules.

The dashboard's **Drifted Systems** StatCard counts systems drifted against at least one baseline, for the fleet-wide quick pulse.

### Retention

`BaselineCheck` rows accumulate over time (100 systems x 10 baselines x daily = 1,000/day). Praxis keeps 90 days of history and a daily retention sweep at 03:00 UTC purges older rows. Latest-per-(baseline,system) is preserved regardless of retention.

### Pairing with alerts

There is no drift-specific event type. To get drift into a chat channel, schedule a daily `report` job that reads `/drift/summary` and carries the drifted count in its title, then subscribe an alert config to `job_completed`.

## Related workflows

Monitoring is the live pulse; two adjacent areas cover evidence and scheduled reporting:

- **Reports & Schedules** - package reports, fleet operations history, analytics, and config audit, run on demand or on a schedule with bounded exports.
- **Compliance Workflows** - policy verdicts, per-host evidence, and the remediation lifecycle for turning failing checks into approved, dispatched fixes.
