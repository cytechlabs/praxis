---
title: Packages
description: Package inventory, available updates, repository status, and fleet-wide package reports.
---

Praxis inventories installed packages on every system and tracks available updates so you can schedule patching at your own pace, not the distro's.

## Inventory

`Update > Package Inventory` lists every installed package across the fleet. Filters narrow by package name, system, category, security-critical status, and whether the package is held. Use **Fleet Search** when you want to answer "which systems have `openssl` <= 3.0.7?"-style questions across all hosts.

Scans run on a schedule (daily by default) and on-demand from the system detail page. Each scan writes the current package list to the `packages` table and deltas to `package_history`, so you can see when a package was installed, upgraded, or removed.

### Package types and scanners

Praxis auto-detects the package manager per distro:

- `apt` - Debian, Ubuntu (scans `/var/lib/dpkg/status` + `apt list --upgradable`)
- `yum`/`dnf` - RHEL, Rocky, Alma, Fedora (scans `rpm -qa` + `dnf check-update`)
- `zypper` - openSUSE / SLES (inventory only)
- `pacman` - Arch (inventory only)

Scanners shell out via the system's credential and capture structured output, not plain text parsing - version comparisons are reliable.

> **Inventory is not servicing.** Detection and inventory are broader than update servicing. Update/install/remove jobs and the patch lifecycle are supported only on the deb (`apt`) and EL (`dnf`/`yum`) families; `zypper`, `pacman`, and `apk` hosts appear in inventory but are not serviced for changes. See the [Linux support matrix](support-matrix.md).

> **Patching at scale is governed, not ad hoc.** This page is inventory and one-off updates. To roll updates out in staged rings/waves with approvals, reboot control, and rollback, use **Patch Policies**, **Patch Advisories**, and **Update Plans** - see the **Patch Workflows** help entry.

## Available updates

`Update > Available Updates` shows every package with a newer version available. Columns: package, installed version, available version, system, security-critical flag, advisory if known. The **Security only** toggle filters to security-critical updates.

Two common workflows from this page:

1. **Target a specific package** - use the filters to find every system running `openssl` < 3.0.7, then **Schedule job** against the matching systems to patch just that package
2. **Patch everything** - open any system detail page > "Update All" for an ad-hoc run, or schedule a recurring job against a smart group

## Security updates

`Update > Security Updates` is a convenience filter over Available Updates. Packages marked `is_security_critical` surface advisory references where the distro provides them.

### A security count needs a security scan

An ordinary package scan asks a host what is upgradable. It never asks which of those updates carries a security advisory, so it classifies nothing as a security update. Until a security scan has asked that question, the absence of security rows means "not asked", not "none pending".

Ask it explicitly:

- **one host**, from `Update > Security Updates`: select the system and run its security scan;
- **a cohort**, from the scope scan with the security option enabled.

### Scan states on the dashboard

The Fleet Dashboard reports the state of security scanning across the hosts in your fleet scope rather than a bare number:

| State | Shown as | Meaning |
|---|---|---|
| Never scanned | `Not scanned` | No security scan has run for these hosts. |
| In flight | `Scanning` | A security scan is running. |
| Failed | `Scan failed` | A scan ran and produced no usable result. The failure reason and the last successful scan time are shown with it. |
| Partial | `Partial scan` | Some hosts in scope are covered and some are not, or a scan stored rows but could not use part of its result. Any count is a floor, rendered `N+`. |
| Complete | a number | Every host in scope has a successful scan behind it. This is the only state in which a count, zero included, is trustworthy. |

A zero appears only after a completed scan. Failed and partial states never render as zero, and the health banner does not call a fleet healthy while security state is unknown, in flight, failed, or partially covered.

A scan is **partial** rather than successful when the host was reached but part of the result could not be used: advisory output that could not be read, or reported packages absent from that host's inventory. The host does not count as covered, so its number stays a floor.

A scan still marked running after 30 minutes stops being reported as in progress, which releases a host pinned by a process that died mid-scan.

`GET /fleet/dashboard` carries this as a `security_posture` object: `state`, `counts_trustworthy`, `coverage_complete`, `systems_total`, `systems_scanned`, `systems_partial`, `systems_failed`, `systems_scanning`, `systems_never_scanned`, `last_successful_scan_at`, `last_scan_at`, `last_failure_detail`, `coverage_detail`, `systems_with_security_updates`, and `pending_security_updates`. The existing `patch_compliance` block is unchanged.

Scans are recorded in the operation trail: a single-host scan as `security_scan`, a cohort scan as `cohort_security_scan`. A per-host result is `success`, `partial`, `failure`, or `skipped`.

## Direct updates and reboot evidence

An update run from the package pages applies immediately. It is not part of a patch plan, so it is not governed by the patch-plan reboot queue: nothing is queued, scheduled, or dispatched for reboot on its behalf. See [reboot scheduling](patch-workflows.md#reboot-scheduling) for the governed path.

When such a run verifies that at least one installed version actually moved, Praxis asks the host whether it now needs a reboot and returns the answer with the result: `reboot_required` plus a structured `reboot_evidence` block. The update surfaces show that as required, not required, or unknown.

Those two fields are **absent** when nothing was changed: every package held, no updates to apply, or a package-manager command that exited cleanly without moving a single installed version. Their absence means no observation was made, not that no reboot is needed.

## Update history

Every package update Praxis runs (manual or scheduled) records a `package_history` row with `from_version`, `to_version`, `status`, `error_message`, and the triggering user or job. `Update > Update History` is a paginated audit trail across the fleet. Use it to answer "when did this system last patch `kernel-*`?" or to verify rollout after a scheduled job.

## Repository status

`Update > Repository Status` lists the configured repositories on each system (sources.list, dnf `.repo` files) along with their reachability. Useful for catching a stale mirror or a typo in a repo URL before a scheduled job hits the failure.

## Reports

`Report > Package Reports` provides fleet-wide roll-ups:

- **Summary** - total installed, security-critical count, held count, updates available, stale-scan systems, compliance average
- **Outdated** - paginated list of all outdated packages with filters for security-only and by system
- **Compliance** - per-system compliance percentage (up-to-date / total) with a fleet average

All three endpoints accept an optional `smart_group_id` query param. The report header has a scope dropdown - pick a smart group and the stats recompute for that subset. Fleet-wide is the default.

## Held packages

Marking a package as "held" tells Praxis' update jobs to skip it, even when a newer version is available. Hold state is per-system and visible on the system detail page. Held packages still show in inventory and still get version pinning checks from baselines.

## Pairing with drift detection

Packages integrate with [Drift Detection](monitoring-and-alerts.md#drift-detection) through the baseline `packages` ruleset:

- **required** - package must be installed (any version)
- **forbidden** - package must not be installed
- **version_pin** - package must be installed at exactly this version

Version pinning uses the inventory table as its source of truth, so as long as your scans are fresh, baselines catch drift without extra SSH cost.
