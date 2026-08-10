---
title: Respond to a critical update
description: Take a newly disclosed vulnerability from advisory to verified fix across the fleet.
---

An advisory lands. This is the path from "is it us?" to "it is fixed, and here
is the record".

## 1. Find out whether you are exposed

Open **Update > Patch Advisories** and import or refresh the advisory if it
is not already there. Praxis joins the advisory's fixed-package targets against
host facts and installed packages and computes per-host applicability:
`applicable`, `fixed`, `not_applicable`, or `unknown`.

A host showing `unknown` has stale or missing facts rather than an unknown
exposure. Refresh its facts and recompute before you decide it is safe.

If the package is not covered by an advisory, answer the question directly from
inventory instead. **Update > Fleet Package Search** answers "which hosts run this
package below this version" across the whole fleet.

## 2. Decide the blast radius

Do not reach for an ad-hoc update job. Use the patch lifecycle, which gives you
staging, approval, and a rollback path.

Pick or create a patch policy in **Update > Patch Policies** with:

- a **scope** narrowed to the package or to security-only, not everything;
- **rings** ordered so a small cohort goes first;
- a **maintenance window** if this can wait for one, and none if it cannot;
- **reboot behaviour** set deliberately;
- **approval** required if your change process needs a second pair of eyes.

Scope plus rings is the safety model. A wide scope with a single ring patches
everything everywhere at once.

## 3. Build a plan and read it

**Update > Update Plans**, build a plan from the policy. Building changes
metadata only; it never touches a host.

Read the per-wave, per-host package changes before dispatching. This is the
step that catches a scope that was broader than intended.

## 4. Get it approved

If the policy requires approval, the plan is frozen at approval time. What
dispatches is exactly what was approved, even if live inventory shifts in
between. Approvals can require more than one approver.

## 5. Dispatch the first ring

Dispatch wave one. Watch per-host state. Later waves proceed only once the
earlier ones are healthy.

For a genuine emergency where waiting for a window is worse than the risk of
patching now, dispatch without a window binding. Make that an explicit choice
rather than a policy you forgot to configure, and note that a policy allowing
automatic reboots without a window can bounce a production host immediately.

## 6. Confirm the fix landed

Do not stop at "the job succeeded".

- The plan execution shows each host completing.
- The advisory's per-host applicability moves to `fixed` after the next facts
  refresh.
- **Update > Update History** records the version transition per host.
- If the update needed a reboot, confirm the host came back and re-check it.

## 7. Keep the evidence

The plan, its approval, the dispatch, and the per-host results are all audited.
For a report you can hand to someone, export the patch execution report from the
plan. See [export evidence for an audit](guide-evidence-export.md).

## If a ring goes wrong

Stop. Do not dispatch the next wave. Go to
[roll back a bad update](guide-rollback.md).

## Related

- [Patch workflows](patch-workflows.md) for the full model.
- [Run a patch window](guide-patch-windows.md) for routine, scheduled patching.
- [Packages](packages.md) for inventory and one-off updates.
