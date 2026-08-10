---
title: Grant temporary access
description: Give someone time-limited, scoped access to part of the fleet, and cut it off immediately when you need to.
---

Standing access is the thing you are trying to avoid. Praxis grants access
just in time: someone requests a role over a scope for a duration, an approver
decides, and the grant expires on its own.

Session approvals, session locks, and access reviews are paid entitlements. See
[editions and feature tiers](editions.md).

## Request access

**Operate > Access Requests**. A request carries:

- **Fleet role**, the access being asked for.
- **Scope**, exactly one of a static group or a smart group. Not both, and not
  neither, so a request always names a bounded set of hosts.
- **Justification**, free text, and the thing an approver actually reads.
- **Duration**, from five minutes to seven days. The default is one hour.

Ask for the shortest duration that will realistically do the job. Extending a
grant is cheap; a week-long grant that nobody revisits is how standing access
comes back.

## Approve or reject

Approvers see pending requests in the same place. A decision takes an optional
comment, which is recorded with the decision.

Before approving, check:

- The scope is the hosts the work actually needs, not a convenient superset.
- The duration matches the work, not the requester's calendar.
- The justification would make sense to someone reading it in six months.

On approval the grant is provisioned and expires by itself at the end of its
duration. There is no cleanup step to forget.

## Approving an individual session

Where session approvals are enabled, opening an interactive session is gated
separately from holding the role: someone with access still needs a decision
before a specific session opens. Use this for production hosts where you want a
record of every shell, not only of every grant.

Interactive sessions always run over SSH, on every host including agent-enrolled
ones, so the target host needs SSH reachability and deployed certificate trust.
See [transports](transports.md).

## Cut access off now

**Operate > Session Locks** is the emergency control. An administrator or
maintainer creates a lock on a subject, which immediately closes every live
session that subject holds and blocks all gated actions for them until the lock
is released.

Use it when you need access gone now and you do not want to wait for a grant to
expire or for deprovisioning to converge. It is reversible: release the lock and
the subject is back to whatever their grants allow.

A lock is not a substitute for revocation. It stops activity; it does not remove
the underlying grant. For a departure, do both. See
[onboard and offboard people](guide-onboarding-offboarding.md).

## Know what "revoked" actually means

Different kinds of access stop working at different speeds. Read
[access revocation](access-revocation.md) before you tell someone that access is
gone. If you need certainty rather than convergence, use a session lock and
then verify.

## What gets recorded

Every request, decision, session open, and lock is audited, with the actor, the
scope, and the justification. **Operate > Active Sessions** shows what is open
right now.

That trail is what an access review reads. See
[run an access review](guide-access-review.md).

## Related

- [SSH and security](ssh-and-security.md) for command approvals and whitelisting.
- [Administration](admin.md) for roles and their envelopes.
