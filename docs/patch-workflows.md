---
title: Patch workflows
description: Patch policies, advisories, rings and waves, update plans, approvals, reboots, and rollback.
---

Praxis separates *inventory* (what is installed and updatable, covered in [packages](packages.md)) from *patching* (a governed, staged, approvable process). Everything below lives under the **Update** workspace.

## Patch policies

`Update > Patch Policies` defines **how** a set of hosts gets patched, not when a single job runs. A policy carries:

- **Scope** - which packages the policy governs: security-only, or an explicit allow-list / deny-list of package names. This is the blast-radius control; a too-broad scope means a policy can move more packages than you intended.
- **Rings** - an ordered list of host cohorts (e.g. `canary > early > broad`). Lower rings patch first so you catch a bad update on a few hosts before it reaches the fleet.
- **Maintenance window binding** - patches only dispatch inside the bound window (see **Jobs & Scheduling > Maintenance Windows**). No window means nothing is time-boxed.
- **Reboot behavior** - whether a patch that requires a reboot triggers one, and whether that reboot is held for the maintenance window.
- **Approval requirement** - whether producing/dispatching an update plan needs an approver.

> **The scope + ring pairing is the safety model.** A policy with a wide scope and a single ring patches everything everywhere at once. Start narrow (security-only, canary ring first) and widen deliberately.

## Patch advisories

`Update > Patch Advisories` holds native distribution advisories - Ubuntu USN, Debian security (DSA), and Red Hat updateinfo (RHSA). Praxis joins each advisory's fixed-package targets against host facts and installed packages to compute **per-host applicability** (`applicable` / `fixed` / `not_applicable` / `unknown`).

Admins and maintainers populate advisories with **Import advisories**: pick a source and paste one raw native advisory object or a JSON array of them. The import records a run (status + imported/refreshed/unchanged/error counts) and recomputes applicability for affected hosts. A host showing `unknown` usually means its facts are missing - recompute after a facts refresh.

## Update plans, rings, and waves

`Update > Update Plans` is where a policy becomes a concrete, reviewable change. A plan is organized into **waves** that follow the policy's **ring** order: wave 1 targets the first ring, and later waves only proceed once earlier ones are healthy.

On a plan's detail page you see the per-wave, per-host package changes *before* anything runs. Building a plan flips metadata only - it never touches a host.

## Approvals

When the policy requires approval, dispatching a plan (or a rollback) is gated: an approver reviews the frozen plan and approves, rejects, or the request is cancelled. Approvals can be multi-level. The approval snapshots ("freezes") the plan so what gets dispatched is exactly what was approved, even if the live inventory shifts afterward.

Approval queues for patch and command actions are reachable from **Operate > Approval Queue** and the plan and rollback surfaces themselves.

## Reboot scheduling

Reboot behavior is a **patch policy** setting, not a separate screen. When a patch needs a reboot, the policy decides whether Praxis reboots the host and whether that reboot is deferred into the bound maintenance window. After a reboot, Praxis re-checks the host so you can confirm it came back and the update actually took effect.

> **A reboot can reach a host.** Enabling automatic reboots without a maintenance window means a security patch can bounce a production box immediately. Bind a window unless you intend that.

**Pending reboots retry once you fix the window.** If a reboot can't be scheduled because the maintenance window is missing, disabled, or unusable (for example, bound but with no valid time range), the reboot stays **pending** with a structured reason (`window_missing`, `window_disabled`, or `window_unusable`) instead of failing. Correct the window and re-run scheduling/promotion - the pending reboots dispatch on the next pass, with no need to rebuild the plan.

**Credentials must declare how to escalate.** Patch, rollback, and reboot dispatch honor the host credential's sudo method (`none`, `nopasswd`, or `password`). If a credential has no sudo method set, or an unrecognized one, dispatch is **refused with a structured condition on the row** (`missing_sudo_method` / `unknown_sudo_method`) instead of silently running unprivileged and failing opaquely as non-root. Set a valid sudo method on the credential, then re-dispatch.

## Rollback

If a dispatched update causes trouble, open the **Rollback** panel on the plan execution (`Update Plans > plan > execution`). Rollback is never automatic - it walks an explicit lifecycle:

1. **Evaluate** - Praxis computes rollback feasibility for the execution.
2. **Request approval** - a feasibility summary plus a frozen-plan preview goes to an approver; approvers vote.
3. **Start dispatch** - once approved, rollback begins, batch by batch.
4. **Dispatch next batch / Cancel** - you advance or stop the rollback per cohort, watching per-host state.
5. **Verify due** - after the rollback completes, verification confirms hosts are back to the intended state.

The frozen plan preview always reflects the approval snapshot, not live package state - so an approver reviews exactly what will be undone.

## Related

- **Packages** - inventory, available/security updates, and the support matrix for which package families are serviceable.
- **Compliance Workflows** - turn failing evidence into approved remediation.
- Linux support matrix: [supported distributions](support-matrix.md). Hardening: [production hardening](production-hardening.md).
