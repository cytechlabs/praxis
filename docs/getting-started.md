---
title: Getting started
description: A tour of the Praxis interface, from first login to a registered host running a job.
---

Praxis is a centralized Linux fleet management platform. This guide gets you from first login to a registered system running a job against Vault-backed credentials.

## Logging in

Point your browser at the Praxis URL (Caddy serves it - `https://localhost` for a local install, or your configured domain). Sign in with an administrator account - the initial admin is seeded on first boot; check your deployment docs for the bootstrap password or OIDC setup. If your deployment wires in an OIDC provider (Okta, Keycloak, Azure AD, etc.) you'll see a "Sign in with SSO" button; otherwise use local username + password.

Session tokens rotate on each page load via refresh tokens - you stay logged in across restarts until your refresh token expires, at which point you re-authenticate.

## The dashboard

The Fleet Dashboard (`/fleet-dashboard`) is your landing page. Top row StatCards summarise fleet posture at a glance:

- **Total Systems** - every registered host, active or decommissioned
- **Patch Compliance** - percentage of systems fully up to date
- **Unreachable** - hosts Praxis could not reach on the last health check (click for the filtered list)
- **Active Jobs** - anything currently running
- **Drifted Systems** - hosts that diverge from at least one enabled baseline ([see Drift Detection](monitoring-and-alerts.md#drift-detection))

Below the cards is a HealthBanner that surfaces critical alerts (unreachable hosts, failed jobs, security posture) and a set of detail cards: systems-by-status pie, recent activity, groups breakdown.

The Patch Compliance card's security tile reports the **state** of security scanning, not a bare count: a number appears only once every host in scope has a completed security scan, and the banner will not call the fleet healthy while that state is unknown, in flight, failed, or partial. [Security updates](packages.md#security-updates) explains each state.

## Tour of the interface

Navigation is six workspace tabs across the top, named for what you are doing
rather than for a subsystem. Clicking a tab opens a drawer of its destinations
over the current page.

| Workspace | What lives there |
|---|---|
| **Operate** | Fleet dashboard, all systems, groups, registration, sessions, access requests and reviews, running commands, approvals |
| **Update** | Package inventory, available and security updates, repository status, patch policies, advisories, update plans |
| **Secure** | Credentials, secrets service, SSH security, audit log |
| **Automate** | Jobs, schedules, maintenance windows, mirrors, channels, profiles, airgap keys |
| **Verify** | Alerts, system status, baselines, drift, compliance dashboard, policies, remediation |
| **Report** | Package reports, fleet operations, analytics, config audit, activity feed |

The top bar also holds fleet-wide search, exception badges for systems needing
attention, your user menu, and notifications. `Ctrl-K` (or `Cmd-K`) opens the
command palette, which reaches every destination directly and is the fastest
route once you know what you want.

Settings and account preferences sit behind the user icon rather than in a
workspace. The **(?)** icon in a page header opens the guide for that page.

Every list page in Praxis follows the same shape: filters at the top, paginated table below, action buttons on the right of each row. Tables share a consistent look so muscle memory transfers.

## Add your first system

From the sidebar pick **Operate > Register System**. Provide:

- **Hostname** - must resolve on the network Praxis lives on (or use an IP)
- **IP address** - unique across the fleet
- **Distribution + version** - picked from the Distro dropdown (Ubuntu, Debian, RHEL, Rocky, etc.)
- **Group** - static group the system belongs to; all systems must live in exactly one group
- **Credential** - the login used to reach this host; see [Credentials & Vault](credentials-and-vault.md)

Praxis runs a connectivity test during registration. If it fails you'll see the SSH error inline - fix the credential or DNS and retry. After registration the system appears in **All Systems** and Praxis begins the first inventory scan.

> **Supported platforms.** The full patch lifecycle (mirror, content profile, patch, rollback) is supported on the **deb** family (Ubuntu, Debian) and the **EL/dnf** family (RHEL, Rocky, AlmaLinux). Other distributions may enroll and collect facts on a best-effort basis but are not serviced for patching. See the [Linux support matrix](support-matrix.md) for the full supported / best-effort / unsupported breakdown and known limitations.

## Register a credential

Before registering a system you need a credential. From the sidebar open **Secure > All Credentials > New Credential**:

- **Name** - human-readable label
- **Auth method** - `password` or `ssh_key`
- **Username** - the Linux user Praxis connects as (typically a dedicated automation account, e.g. `ubuntu` or a `praxis-svc` user)
- **Secret** - paste the password or private key body; it's written straight to Vault, never stored in the Praxis database
- **Sudo method** - none, password, or nopasswd (how Praxis **automation** escalates for privileged workflows; fleet-role user accounts get no standing sudo in 1.0)

Credentials can be shared across many systems. See [Credentials & Vault](credentials-and-vault.md) for managed vs linked credentials and rotation.

## Next steps

- Add the rest of your fleet via the bulk-register form or CSV import
- [Create a smart group](fleet-and-hosts.md#smart-groups) so jobs can target hosts by rule
- [Define a baseline](monitoring-and-alerts.md#drift-detection) for package + service drift detection
- [Wire up alerts](monitoring-and-alerts.md#alerts-and-webhooks) so incidents land in Slack / your on-call system
