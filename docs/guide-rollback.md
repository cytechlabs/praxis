---
title: Roll back a bad update
description: Undo a dispatched patch execution through the approved, staged rollback lifecycle.
---

A patch went out and something broke. Rollback in Praxis is never automatic; it
is an explicit, approved, staged lifecycle, for the same reason the patch was.

## First: stop the bleeding

Before starting a rollback, stop the damage spreading.

1. **Do not dispatch the next wave.** If the plan is mid-flight, leave later
   waves undispatched.
2. Note which hosts already took the change. The plan execution shows per-host
   state.

If the problem is limited to one host and you can fix it in place faster than
you can run a rollback, do that. Rollback is for the case where the change
itself was wrong.

## The rollback lifecycle

Open the plan execution: **Update > Update Plans**, the plan, then its
execution, then the **Rollback** panel.

1. **Evaluate.** Praxis computes rollback feasibility for the execution. Read
   this before anything else; it tells you what can actually be reversed.
2. **Request approval.** A feasibility summary and a frozen plan preview go to
   an approver. Approvers vote.
3. **Start dispatch.** Once approved, rollback begins, batch by batch.
4. **Dispatch next batch, or cancel.** You advance cohort by cohort, watching
   per-host state, and you can stop.
5. **Verify.** After the rollback completes, verification confirms hosts are
   back at the intended state.

The frozen plan preview reflects the approval snapshot, not live package state,
so an approver reviews exactly what will be undone.

## What rollback does not do

- **It does not undo control plane state.** If the newer version completed
  work, that work stands.
- **It does not reverse a reboot** or anything the updated software did while
  it was running, such as a data migration performed by an application package.
- **It cannot recover a package version the host can no longer obtain.** If the
  previous version has been removed from the repository your host points at,
  rollback has nothing to install. Mirrors you control avoid this; see
  [mirrors and content](mirrors-and-airgap.md).

Rollback restores packages. It does not restore state. For anything stateful,
your restore path is the host backup, not Praxis.

## Rolling back the agent

The agent is separate from the patch lifecycle. To move a host back to a
previous agent, run `sudo ./install.sh` from the older verified tarball.
Identity material survives, so no re-enrollment is needed. See
[upgrade](upgrade.md).

## Rolling back the control plane

Also separate. See [upgrade](upgrade.md) for redeploying previous image digests
and the database constraint that governs whether you can.

## Afterwards

- Confirm the affected hosts are healthy and inventory reflects the reverted
  versions.
- Narrow the patch policy scope, or reorder the rings, so the same change cannot
  reach the whole fleet next time.
- The rollback request, its approval, and the per-host dispatch results are all
  audited. Export them if this needs a change record. See
  [export evidence for an audit](guide-evidence-export.md).

## Related

- [Patch workflows](patch-workflows.md)
- [Respond to a critical update](guide-critical-updates.md)
