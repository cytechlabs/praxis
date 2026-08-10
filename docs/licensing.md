---
title: Licensing and activation
description: How the free edition, the host cap, and offline licence activation work.
---

Praxis is open core. The free edition is a complete control plane; a paid
licence lifts the host cap and unlocks a set of governance controls. What sits
on each side of that line is stated in
[editions and feature tiers](editions.md).

This page is the mechanics: how a licence is applied, what happens when one
expires, and what leaves your network.

## Nothing calls home

The free edition needs no licence, no account, and no network call.

Paid activation is **offline-first**. A licence is a signed token that Praxis
verifies **locally** against a public key that is built into official images.
There is no activation server to reach, no licence check on startup that can
fail because a network is down, and no telemetry.

## The installation ID

Every install generates a stable installation ID on first use. Find it under
**Settings > License**.

A licence is minted bound to one installation ID. That binding is what a
licence is; a licence issued for one installation will not validate on another.
Copy the ID from the running deployment rather than typing it from memory.

## Applying a licence

1. Open **Settings > License** and copy the installation ID.
2. Buy the tier you need, supplying that installation ID. The purchase surface
   is on the Praxis website; the application never holds price identifiers and
   never starts a checkout itself.
3. Paste the returned licence key into **Settings > License**.

Praxis verifies the signature, the expiry, and the installation binding
locally, then unlocks the licensed host cap and the paid entitlements on the
same deployment. There is no separate paid image and no private registry to
authenticate against.

A licence that is bound to a different installation, expired, malformed, or
signed by a key Praxis does not know is rejected with a stated reason, and the
edition is left exactly as it was. A failed activation never partially unlocks
anything.

## Host caps

| Edition | Managed hosts |
|---|---|
| Free | 15 |
| Pro | 50 |
| Team | 200 |
| Business | 500 |
| Enterprise | Negotiated, and written explicitly into the licence |

Decommissioned hosts do not count.

The current edition, entitlement set, host count, and licence status are
readable by any signed-in user from the `/edition` endpoint, so a check can be
scripted without an administrator token.

## What happens at the cap

Registering a **new** host is blocked once you reach the effective cap. The API
returns a clear over-cap error and the interface shows an upgrade prompt.

Hosts you already manage are **never** disabled or deleted for being over cap.
If a licence expires or downgrades and you are left above the free cap, you
keep operating every host you have. Praxis records a 14-day grace deadline,
shown under **Settings > License**, during which new registrations still work
so you have time to reduce usage or re-license.

## Paid actions without an entitlement

Enforcement is server-side. A paid API action without the entitlement returns
HTTP 402 and the interface shows the control as locked. This is the same answer
whether the deployment is free or a paid tier that does not include that
capability, so a scripted client can treat 402 as a single case.

## Connected installs and renewals

A connected install can refresh an already-applied paid licence after a renewal
so the expiry advances without anyone pasting a new key. This is a refresh of a
licence you already hold, not an activation check: it never gates a running
deployment, and a deployment that cannot reach the refresh path keeps working
until the licence it holds actually expires.

Customer email and billing metadata are never propagated into the deployment or
exposed by the edition endpoint.

## Air-gapped deployments

Offline activation is the default path, so a disconnected deployment applies a
licence exactly like a connected one: copy the installation ID out, paste the
licence key in. There is no online-only step and no refresh requirement.

## Rotating or replacing a licence

See [rotate a licence](guide-license-rotation.md).
