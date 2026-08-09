---
title: Rotate a licence
description: Replace a licence on renewal, on a tier change, or when moving a deployment, without losing paid features.
---

A licence is bound to one installation and has an expiry. Rotating one is
pasting a new key; the care is in the order and in knowing what happens if you
get it wrong.

Background is in [licensing and activation](licensing.md).

## What a rotation cannot break

Applying a licence is validated before anything changes. A key that is bound to
a different installation, expired, malformed, or signed by an unknown key is
rejected with a stated reason and **leaves the current edition exactly as it
was**. There is no partial application, so a failed paste is a non-event.

Hosts you already manage are never disabled or deleted, even if a rotation
leaves you over the cap.

## Renewal

For a connected install, an already-applied paid licence can refresh itself
after a renewal, so the expiry advances with no action. Confirm under
**Settings > License** that the expiry moved after your renewal date.

If it has not, or the deployment is disconnected, apply the renewed key by hand:

1. **Settings > License**, copy the installation ID.
2. Obtain the renewed licence for that installation ID.
3. Paste it in.
4. Confirm the edition, expiry, and host cap are what you expect.

Do this before the current licence expires. There is no outage when one does,
but you will be over the free cap and new host registrations will be blocked
once the grace period ends.

## Changing tier

Upgrading, for example Pro to Team, is the same operation: obtain a licence for
the new tier bound to the same installation ID and paste it. The new cap applies
immediately.

Downgrading works too, and is where the grace behaviour matters. If the new cap
is below your current host count:

- Every existing host keeps running. Nothing is disabled.
- New registrations are blocked once you reach the cap.
- Praxis records a **14-day grace deadline**, shown under
  **Settings > License**, during which new registrations still work.

Use the grace window to decommission hosts you no longer need. Decommissioned
hosts do not count toward the cap, and decommissioning keeps their history.

## Moving to a new deployment

The installation ID is generated per install, so a licence does not move with a
restore or a migration onto new infrastructure.

1. Stand up the new deployment and let it generate its installation ID.
2. Read the new ID from **Settings > License**.
3. Get a licence reissued for it.
4. Apply it, and confirm the edition before cutting traffic over.

Do this before you decommission the old deployment, so a reissue problem does
not happen while you have nothing running.

Restoring a backup onto the same installation keeps the same identity and the
same licence.

## Air-gapped deployments

No difference. Activation is offline by default: copy the installation ID out,
carry the licence key back in. There is no online step and no refresh
requirement, so a disconnected deployment is not on a clock beyond its own
expiry.

## Verify after any rotation

Check under **Settings > License**:

- Edition is the tier you bought.
- Expiry is the new one.
- Host cap matches the tier.
- No grace deadline is showing, unless you are deliberately over cap.

Any authenticated user can read the same state from the `/edition` endpoint, so
this check can be scripted and alerted on. Alerting on an approaching expiry is
worth doing; the failure mode is quiet until someone tries to add a host.

## If paid features are missing after a valid rotation

A paid action without the entitlement returns HTTP 402 and shows as locked. If
that happens with a licence you believe is good:

1. Re-read **Settings > License**. If the edition still shows free, the key was
   rejected, and the reason is stated there.
2. Confirm the installation ID on the licence matches the one this deployment
   shows. A licence minted against a different install is the usual cause.
3. Confirm the capability is in the tier you bought. See
   [editions and feature tiers](editions.md).
