---
title: Fleet and hosts
description: Register hosts, organise them into groups and tags, and target them by rule.
---

Praxis treats every managed host as a **System** - a row in the `systems` table with an FK to exactly one static **Group**, zero-or-more **Tags**, and exactly one **Credential** for SSH auth.

## All Systems

`Operate > All Systems` is the master list. Columns include hostname, IP, status, OS, group, last audit, and the SSH Identity (zero-trust CA) deploy state. Filters at the top are URL-synced - share a filtered view by copying the URL. Click any system to open the detail page with packages, audit trail, host keys, and drift posture.

### Status values

- **Active** - Praxis expects to reach this host and runs it through scheduled jobs
- **Decommissioned** - kept for audit/history but excluded from all jobs and alerts
- **Unreachable** - set by the fleet health checker after N consecutive SSH failures ([see Monitoring](monitoring-and-alerts.md))

### Bulk actions

Select rows with the checkbox column for bulk operations: update status, change group, assign/remove tags, deploy CA trust, decommission. Every bulk action records a `FleetOperation` row visible in `Report > Fleet Operations`.

## Static Groups

A **Group** is a static, hierarchical container. Every system belongs to exactly one group. Groups can have a `parent_id` so you can nest (`All > Production > Web > EU-West`). Jobs targeting `Production` pick up systems in its descendants as well.

Use static groups for **ownership** - teams, business units, physical locations. Use smart groups for **rule-based targeting** (see below).

## Smart Groups

A **Smart Group** is a saved rule (JSON AND/OR tree) that resolves to a list of systems, recomputed as the fleet changes. Pick `Operate > Smart Groups > New Smart Group` and use the visual rule builder.

Supported fields:

| Field | Type | Ops |
|---|---|---|
| `hostname`, `ip_address`, `os_version`, `update_policy` | string | `eq`, `neq`, `contains`, `regex` |
| `status`, `distro`, `group`, `tag`, `environment_type` | enum | `in`, `not_in` |
| `has_pending_updates`, `has_security_updates`, `ca_trust_deployed` | bool | `eq` |
| `days_since_last_audit` | number | `eq`, `gt`, `lt`, `gte`, `lte` |

All text matching is **case-insensitive** - `ubuntu`, `Ubuntu`, `UBUNTU` all match the same distro.

### The rule builder

The builder supports nested AND/OR groups. As you edit, the preview panel fires against the `/smart-groups/preview` endpoint and shows the matching count in near-real-time. An example rule for "production Ubuntu hosts with pending security updates":

```json
{
  "op": "and",
  "rules": [
    { "field": "distro", "op": "in", "value": ["Ubuntu"] },
    { "field": "environment_type", "op": "in", "value": ["production"] },
    { "field": "has_security_updates", "op": "eq", "value": true }
  ]
}
```

### Cached membership

Membership is materialised into the `smart_group_memberships` table so reads are cheap. The cache is refreshed on three triggers:

1. **SmartGroup CRUD** - creating or editing a rule recomputes immediately
2. **System mutation** - adding / updating / deleting a System fires an ORM hook that recomputes all groups on commit
3. **Scheduler safety net** - every 5 minutes the scheduler recomputes everything, in case a hook was missed

You can also click the **Recompute** icon on any smart group to force an immediate refresh.

### Where smart groups are used

Smart groups are a first-class target across Praxis:

- **Jobs** - pick "Smart Groups" in the target selector when scheduling a job
- **Alerts** - scope an alert config to a smart group so events only fire for members
- **Reports** - scope `/package-reports/*` endpoints to a smart group
- **Baselines** - scope drift detection to a subset of the fleet

## Tags

Tags are free-form labels. Unlike groups, a system can carry many tags. They're handy for transient classification (`needs-reboot`, `gpu`, `public-facing`). Manage them from `Operate > All Systems > bulk tag` or per-system on the detail page. Smart group rules can match on tag membership (`tag in [gpu]`).

## SSH Identity (zero-trust CA)

Praxis can push a Vault-signed SSH CA public key to every system so future connections use short-lived user certs instead of passwords. On the system detail page, **Deploy CA Trust** pushes the CA, updates `sshd_config`, and reloads sshd. After that Praxis signs a fresh user cert per connection (default TTL 5 minutes).

See [SSH & Security](ssh-and-security.md) for CA rotation and revocation workflows.

## Health checking

Every 30 minutes Praxis runs a lightweight SSH probe against every Active system and updates `last_audited`. Consecutive failures (default 2) flip status to `Unreachable` and fire a `system_unreachable` event; recovery fires `system_recovered`. Tune the threshold under `Settings > Connection Settings`.
