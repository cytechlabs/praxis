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

**A plan with nothing to install will not start.** If no host in the plan has selected package work that can actually be dispatched, starting the execution is **refused with `no_selected_packages`** rather than recorded as a run. Praxis does not create a successful execution that installed nothing, so a green execution always means real package work was attempted. Mixed plans are unaffected: hosts with no applicable work are skipped individually, and the hosts that do have work still patch. The refusal says which case it is - the plan selected nothing at all, the selected work has no dispatchable host left (for example its target system was removed), an earlier run already applied the work, or an earlier attempt failed or only partly succeeded, in which case it reports how many package results succeeded out of the total.

## Approvals

When the policy requires approval, dispatching a plan (or a rollback) is gated: an approver reviews the frozen plan and approves, rejects, or the request is cancelled. Approvals can be multi-level. The approval snapshots ("freezes") the plan so what gets dispatched is exactly what was approved, even if the live inventory shifts afterward.

Approval queues for patch and command actions are reachable from **Operate > Approval Queue** and the plan and rollback surfaces themselves.

## Reboot scheduling

Reboot behavior is a **patch policy** setting, not a separate screen. When a patch needs a reboot, the policy decides whether Praxis reboots the host and whether that reboot is deferred into the bound maintenance window. After a reboot, Praxis re-checks the host so you can confirm it came back and the update actually took effect.

> **A reboot can reach a host.** Enabling automatic reboots without a maintenance window means a security patch can bounce a production box immediately. Bind a window unless you intend that.

### Reboot evidence

**The decision is made from a fresh observation, not from stored inventory.** After a host's package work succeeds under `if_required`, Praxis asks the host directly instead of reading the `reboot_required` fact collected by the last inventory sweep, which predates the update. Each package family answers through the indicator it treats as authoritative:

- **Debian family**: the `/var/run/reboot-required` or `/run/reboot-required` marker.
- **RPM family**: `needs-restarting -r`, read from its exit status (`0` no reboot needed, `1` reboot needed). Any other status is the tool failing rather than an answer. `needs-restarting` ships in `dnf-utils` / `yum-utils` and is absent from a minimal install; see [known distro-specific limitations](support-matrix.md#known-distro-specific-limitations).

The probe is read-only. It rides the same transport and sudo method as the package command, installs nothing, and reboots nothing.

Each observation is recorded on the reboot row under `decision_details.reboot_evidence`: the value, the indicator it came from (`source`), the probe `outcome`, the UTC `collected_at`, the package `family`, the `exit_code`, and a bounded `detail`. The reboot CSV export carries `reboot_evidence_source`, `reboot_evidence_outcome`, and `reboot_evidence_collected_at`.

An observation is reused for up to an hour, and only when it was collected at or after the host finished its package work, so a pre-update reading can never decide a row. Hosts on `never` or `always` are not probed at all, because the answer cannot change their decision; their rows record the outcome `not_collected` with the reason.

**Unknown evidence fails closed.** A row reads `not_required` only on a fresh, successful, negative observation. Everything else - missing, stale, unsupported, timed out, transport failure, malformed output, or a failed probe - produces a **pending** row with the decision code `reboot_evidence_unknown`. On such a row `reboot_required_fact` is `null`, and null does not mean "no reboot needed": read it together with the decision code. Pending rows keep dependent waves blocked with the gate reason `prior_wave_reboots_in_progress`.

To clear one, fix why the host could not answer (install `dnf-utils` on an RPM host, restore connectivity), then re-run the reboot reconcile for that execution.

### When the reboot queue is incomplete

The queue answers "what still has to reboot". It also reports whether it is a complete account of the run. `GET /patch/update-executions/{id}/reboots` and `GET /patch/update-plans/{id}/reboots` return a `summary.reconciliation` block: `status` (`ok`, `incomplete`, or `failed`), `action_required`, `succeeded_host_count`, `reboot_row_count`, `missing_row_count`, and `last_failure`. The plan-scoped response adds `execution_ids_action_required`.

While `action_required` is set, **the counts are not that answer**, and the plan and execution detail pages carry a *Reboot queue incomplete* warning saying so. `incomplete` means hosts finished patching without a queue row; `failed` means a reconcile pass itself failed.

A failed pass also records a marker on the execution, emits the audit action `patch_update_execution_reboot.reconcile_failed` with outcome `failure`, raises a `patch.reboot_required` notification at `error` severity, and blocks dependent waves with the gate reason `reboot_reconcile_failed`.

Re-run the reboot reconcile for the execution to rebuild the queue. A successful pass clears the marker.

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
