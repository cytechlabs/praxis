---
title: Run a patch window
description: Set up recurring, time-boxed patching that dispatches inside an agreed maintenance window.
---

Routine patching should be boring: it happens on a schedule, inside a window
someone agreed to, and it tells you when it did not work.

## 1. Define the window

**Automate > Maintenance Windows > New**. A window is a name, a target (a host, a
group, or the whole fleet), a schedule, and an enabled flag. Use the plain
language schedule builder.

Define windows around the constraint that actually exists: a database host that
may only be touched on Sunday early morning, an edge site in a different
timezone, a change freeze before a release.

Work that matches a target with an active window is held until the window
opens. If a job fires outside its window, the scheduler records the skip and the
next attempt waits for the next opening.

## 2. Bind the window to a patch policy

**Update > Patch Policies**. Bind the window to the policy that governs these
hosts. A policy with no window binding is not time-boxed, whatever windows exist
elsewhere.

Set the reboot behaviour at the same time. The useful combination for routine
patching is to allow reboots but hold them for the window, so a patch that needs
a restart does not bounce a host in the middle of the day.

## 3. Order the rings

Rings are cohorts, patched in order. A workable default:

1. **canary**, a handful of hosts you can afford to lose for an hour.
2. **early**, a representative slice including at least one of each host role.
3. **broad**, everything else.

Later waves proceed only when earlier ones are healthy, so an ordering that puts
something representative early is what makes staging worth anything.

Use a smart group for each ring where you can, so cohort membership follows the
fleet instead of drifting as hosts are added. See
[fleet and hosts](fleet-and-hosts.md).

## 4. Decide whether approval is needed

If your change process requires sign-off, set approval on the policy. The plan
is frozen when it is approved, so an approver reviews exactly what will run.

For routine security-only patching inside an agreed window, many teams do not
require per-window approval. That is a policy decision, not a technical one.

## 5. Run it, then check the tail

After each window, the interesting hosts are the ones that did not finish
cleanly:

- **Update > Update Plans**, open the execution and filter to failures.
- Pending reboots that could not be scheduled stay **pending** with a reason
  (`window_missing`, `window_disabled`, or `window_unusable`) rather than
  failing. Fix the window and re-run scheduling; the pending reboots dispatch on
  the next pass with no need to rebuild the plan.
- A host refused with `missing_sudo_method` or `unknown_sudo_method` has a
  credential that does not declare how to escalate. Set a valid escalation
  method on the credential and re-dispatch.

## 6. Make failures reach you

Subscribe an alert configuration to `job_failed` so a failed window does not
wait for someone to open the interface on Monday. See
[monitoring and alerts](monitoring-and-alerts.md).

## Common mistakes

- **A window bound to nothing.** Windows do not apply themselves. The binding
  lives on the patch policy.
- **A single ring.** One ring is not staging; it is the whole fleet at once.
- **A window too short for the fleet.** If waves do not finish, the remainder
  waits for the next opening. Either widen the window or raise the parallelism.
- **Automatic reboots with no window.** This will restart a production host as
  soon as a patch needs it.

## Related

- [Patch workflows](patch-workflows.md)
- [Jobs and scheduling](jobs-and-scheduling.md)
- [Roll back a bad update](guide-rollback.md)
