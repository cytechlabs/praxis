---
title: Run an access review
description: Work a review queue to attest, revoke, or extend every access grant, and export the result as evidence.
---

An access review answers one question for every grant that exists: does this
person still need this. Most compliance regimes want it on a cadence, and want
the record afterwards.

Access reviews are a paid entitlement. See
[editions and feature tiers](editions.md).

## Before you start

Decide the scope and the cadence, and write them down somewhere that is not
this tool. Quarterly across the whole fleet is a common shape; monthly for
production only is another. A review nobody scheduled is a review that will not
happen twice.

Get offboarding done first. Reviewing grants for people who have already left
wastes the reviewers' attention on entries that should never have reached the
queue. See [onboard and offboard people](guide-onboarding-offboarding.md).

## Work the queue

**Operate > Access Reviews**. A review produces a queue of items, one per grant.
For each item there are three answers:

- **Attest.** Still needed, still correctly scoped. Records that a named person
  confirmed it on a date.
- **Revoke.** No longer needed. Removes the grant.
- **Extend.** Still needed, but the expiry should move out.

Revoke is the default answer for anything you cannot justify in a sentence. A
reviewer who attests everything has produced a document, not a review.

Watch for the patterns that matter more than individual entries:

- Grants scoped to the whole fleet where the work is one group.
- Grants that have been extended repeatedly, which usually means standing access
  wearing a temporary label.
- Roles wider than the person's actual work, particularly `admin`.
- Accounts belonging to people who no longer appear in your identity provider.

## Complete the review

Completing a review closes it and fixes the record of who reviewed what, and
when. An incomplete review is not evidence of anything, so do not leave a queue
part-worked at the end of a cycle. If some items genuinely need more time,
revoke them and let the owners re-request; that is faster than leaving the cycle
open.

## Export the evidence

The review exports as CSV for a compliance package. Export it at completion,
while the review is the thing you just did, rather than reconstructing it later.

Bulk evidence export is admin and maintainer only. A read-only auditor can read
every record in the interface but cannot pull bulk exports. See
[export evidence for an audit](guide-evidence-export.md).

## Act on what it found

A review that produced no changes and no follow-up either found a healthy
estate or was not a review. If it found problems:

- Narrow the scopes that were too wide.
- Move repeat extensions onto a properly scoped standing grant, or remove them.
- Shorten the default duration on requests if a week keeps being requested for a
  day of work. See [grant temporary access](guide-temporary-access.md).

## Related

- [Access revocation](access-revocation.md) for how quickly a revocation takes
  effect.
- [Compliance workflows](compliance-workflows.md) for policy verdicts and
  remediation.
- [Administration](admin.md) for roles and audit retention.
