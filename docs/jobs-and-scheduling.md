---
title: Jobs and scheduling
description: Build, target, schedule, and audit fleet-wide jobs.
---

A **Job** is a defined unit of work that runs against one or more systems. Every job has a type, a target specification, an optional schedule, and a recorded execution history.

## Job types

- **update** - run the distro package manager with upgrade intent. Fully supported on the deb (`apt`) and EL (`dnf`/`yum`) families; other package managers (`zypper`, `pacman`, `apk`) are detect-only and not serviced for updates - see the [Linux support matrix](support-matrix.md)
- **install** - install one or more named packages
- **remove** - remove one or more named packages
- **command** - run a validated command against the system (goes through the whitelist + approval flow - see [SSH & Security](ssh-and-security.md))
- **script** - run a pre-defined script from the Jobs library
- **report** - gather inventory only, no state change

## Scheduled jobs

`Automate > Scheduled Jobs` is where you define recurring work. The form breaks into four sections:

1. **Basics** - name, description, job type
2. **Schedule** - plain-language schedule builder (daily, weekly on X, monthly on day Y, etc.); Praxis stores a cron expression under the hood but you never write cron directly
3. **Target** - see below
4. **Execution** - max parallel, timeout, dependencies on other jobs

Toggle `is_recurring` off and the job becomes a one-shot queued for immediate run when you click **Save**.

> **For OS patching, prefer the patch lifecycle over raw update jobs.** Ad-hoc update jobs run immediately against their target. Staged rings/waves, approvals, reboot control, and rollback come from **Patch Policies** and **Update Plans** - which bind the **Maintenance Windows** you define here. See the **Patch Workflows** help entry.

### Targeting

Praxis supports five target modes:

| `target_type` | Behaviour |
|---|---|
| `all` | every Active system (no target_ids needed) |
| `system` | `target_ids` is a list of System IDs |
| `group` | `target_ids` is a list of Group IDs; child groups are included recursively |
| `tag` | `target_ids` is a list of Tag IDs; tag_match_logic chooses `or`/`and` |
| `smart_group` | `target_ids` is a list of Smart Group IDs; members resolved via the cached membership table |

Smart group targeting is the most common choice for production fleets because the system list auto-refreshes as hosts register or change attributes. See [Smart Groups](fleet-and-hosts.md#smart-groups).

### Package filters

When job type is `update`, the optional package filter narrows the scope:

- **names** - explicit list of packages to update
- **keywords** - substring match across package names
- **security_only** - only security-critical updates

Leave all three blank to update everything with a pending update.

### Dependencies (job chains)

A job can depend on another job's last execution via `depends_on_job_id` plus a `chain_condition`:

- `on_success` - run only if the upstream completed successfully
- `on_failure` - run only if the upstream failed (useful for remediation jobs)
- `on_complete` - run whenever the upstream finishes, regardless of outcome

Chains let you compose workflows: backup > update > smoke-test, with remediation jobs on failure branches.

### Parallelism

`max_parallel` caps how many target systems the job touches concurrently. Each parallel worker gets its own SSH connection and DB session. Default is 1 - raise it for patch jobs that hit a big fleet where serial execution would take hours.

## Active jobs

`Automate > Active Jobs` shows currently-executing jobs with per-system progress. The page auto-refreshes every 5 seconds while jobs are running. Click into a job to see the live log stream and cancel/pause if needed.

## Job history

`Automate > Job History` is the paginated audit trail of every execution. Each row links to a detail view with:

- Per-system status + exit code + duration
- Stdout and stderr from each target
- Triggering user or scheduler reason
- Rollback status (when relevant for update jobs)

Use the status filter to triage failures across the fleet, and the date-range filter for scoped investigation.

## Failed jobs

`Automate > Failed Jobs` is a convenience filter over Job History where any target system returned non-zero. It exists as its own page because it's the most-visited in an incident.

## Job templates

`Automate > Job Templates` saves a reusable job definition (target + params + schedule). Templates are great for "I run this same weekly patch job across 5 different smart groups" patterns - instantiate a template with a different target and you're done.

## Maintenance windows

`Automate > Maintenance Windows` defines time boundaries during which jobs for a target (system / group / all) are allowed to run. A window is a name + target + schedule + enabled flag. Jobs matching a target that has an active window are queued until the window opens.

Use windows for:

- Database servers where you want patches confined to Sunday 02:00-04:00
- Edge nodes in specific timezones
- Freeze periods (ship tag <-> no unattended changes)

If a job fires outside its window, the scheduler logs the skip and the next attempt waits for the next window opening.

## Notifications

Job completion fires one of four events: `job_completed`, `job_failed`, `job_cancelled`, `job_rollback`. Each creates an in-app Notification for the requesting user and, if any Alert Config subscribes to the event, dispatches to Slack / a webhook. See [Monitoring & Alerts](monitoring-and-alerts.md) for alert wiring.
