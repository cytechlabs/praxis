---
title: Editions and feature tiers
description: What the free tier includes, what the paid tiers add, and how entitlements are enforced.
---

Praxis is **open core**. The free edition is a complete, self-hostable Linux
fleet control plane — inventory, access, content, patching, and compliance — and
is meant to stay that way. A paid edition adds scale beyond the free host cap and
a set of governance controls.

The features that ship free in 1.0 are intended to remain free. Paid gates are
set at launch, on purpose, so there is no bait-and-switch: nothing that is free
today moves behind the paywall later.

## How it works

- The free edition runs entirely on the open-source build. No license, no
  external service, no call-home.
- The paid edition activates through a license applied to the **same
  deployment** — the model is: install the open-source build, run free up to the
  host cap, buy later, apply a license key, and the same install unlocks the paid
  host cap and governance controls. (This document defines the edition boundary
  itself; the license and activation flow are part of the remaining 1.0 launch
  work.)
- Enforcement is server-side. Paid API actions return **HTTP 402** without the
  entitlement; the UI shows a locked/upgrade state for paid controls.

## Free / core (1.0)

Everything needed to operate a fleet, including:

- **Users & SSO** — unlimited users, OIDC/SSO (bring your own provider), session
  recordings. These are **not** paid.
- **Fleet** — up to **15 managed hosts**, fleet dashboard, all systems, groups,
  smart groups, registration.
- **Access & security** — credentials, Vault management, SSH security basics,
  active sessions, access requests, audit log.
- **Commands** — command execution, command whitelist, validation rules, command
  history.
- **Packages & patching** — inventory/search/updates/advisories/history/repo
  status, patch advisories, patch policies, patch update plans.
- **Content** — mirrors, content channels, content profiles, air-gap keys.
- **Jobs** — jobs, scheduled jobs, job history, templates, failed jobs,
  maintenance windows.
- **Systems** — system status, comparison, baselines, drift.
- **Compliance** — dashboard, policies, remediation, starter pack.
- **Monitoring & reporting** — package reports, fleet operations, activity feed,
  analytics, config audit, settings, preferences, help.

## Paid (from 1.0)

The paid edition is about **scale plus governance**. The 1.0 self-serve tiers are
Pro (50 hosts), Team (200 hosts), and Business (500 hosts). Enterprise is
sales-assisted for fleets above 500 hosts, air-gapped deployments, or SLA needs
(sales@praxisfleet.com); Enterprise licenses still carry an explicit negotiated
host cap.

| Capability | Entitlement key |
|---|---|
| Managed hosts above the free cap | `hosts.over_free_cap` |
| Session locks | `access.session_locks` |
| Session approvals | `access.session_approvals` |
| Access reviews | `access.access_reviews` |
| Command approval queue / multi-approval execution | `commands.approvals` |
| Command metrics | `commands.metrics` |
| Bulk compliance / evidence exports | `compliance.bulk_exports` |
| Scheduled / recurring report exports | `reports.scheduled_exports` |

Core compliance (dashboard, policies, evidence reads, remediation) and command
history stay free; only the bulk-export and governance layers above are paid.

## The free host cap

The free edition manages up to **15 hosts**. A paid license lifts the cap to the
licensed tier's numeric limit. Self-serve caps are Pro 50, Team 200, and Business
500; Enterprise caps are negotiated and encoded explicitly in the license. The
current edition, entitlement set, host count, and license status are visible to
any authenticated user via the read-only `/edition` endpoint.

## License activation (offline)

Licensing is **offline-first — there is no call-home**. A license is a signed
(Ed25519) token bound to your installation's stable `instance_id`:

1. Every install generates a stable **installation ID** on first use, shown under
   **Settings → License**.
2. You provide that installation ID when purchasing; the license is minted bound
   to it.
3. Paste the license key under **Settings → License**. Praxis verifies the
   signature, expiry, and installation binding **locally** and unlocks the
   licensed host cap and paid entitlements on the same deployment.

A license is verified against a **public** key only; no secret ever ships in the
open-source build or the container image. **Official builds include the public
verification key built in**, so a purchased license applies with no extra setup.
(Advanced/dev builds can point at a custom issuer by setting
`PRAXIS_LICENSE_PUBLIC_KEY`, which overrides the built-in key.) A license bound to
a different installation, expired, malformed, or signed by an unknown key is
rejected with a clear reason and leaves the edition unchanged (no paid features
unlocked).

The purchase/checkout and license-issuing service are tracked separately in a
later launch step; this release implements the local validate/apply/status path.

### Host cap and downgrade behavior

- New host registration is blocked once you reach the effective host cap; the API
  returns a clear over-cap error and the UI shows an upgrade prompt.
- Existing hosts are **never** disabled or deleted when you are over cap (for
  example after a license expires or downgrades). You keep operating them.
- When an install falls over the free cap after losing a paid license, Praxis
  records a **14-day grace deadline** (surfaced in **Settings → License**) so you
  have time to reduce usage or re-license before new additions stay blocked.
- Decommissioned hosts do not count toward the cap.

## Open core and the paid extension (for operators / builders)

Everything in this repository is the open-source core (Apache 2.0). Paid
functionality is delivered by a **separate, closed-source** extension package,
`praxis-ee`, which is **not** in this repository and which customers never need:

- **You install one normal Praxis.** There is no separate "enterprise image" and
  no private registry to authenticate to. A stock install runs free; a valid
  license unlocks paid mode on the same install.
- **Official builds ship the public license verification key built in**, so the
  offline license spine can validate a real license out of the box — a stock
  install runs free until a valid license is applied. Only a **public** key ever
  ships; the private signing key stays with CytechLabs, so only CytechLabs-issued
  licenses validate.
- `PRAXIS_LICENSE_PUBLIC_KEY` overrides the built-in key for development or when
  testing against a custom issuer; the extension loader (`backend/app/ee/`) can
  also install it. The verification key grants nothing on its own — paid state
  comes only from a valid license.

### Building a paid-capable image

`backend/Dockerfile.prod` builds a free-capable OSS image by default. A
paid-capable build opts in explicitly:

```sh
# Default (OSS / free-capable) — no extension:
docker build -f backend/Dockerfile.prod -t praxis-backend backend/

# Paid-capable — bundles the private extension (internal build only). Drop the
# pre-built praxis-ee wheel into the build context first, then opt in:
cp path/to/praxis_ee-*.whl backend/ee-wheels/
docker build -f backend/Dockerfile.prod --build-arg PRAXIS_EE=1 -t praxis-backend backend/
```

The extension is installed **only** from the local `backend/ee-wheels/` directory
with `--no-index` — no package-index URL, token, or credential is ever passed as
a build arg (so nothing leaks into image metadata, provenance, or logs). The
release pipeline fetches the wheel with a narrowly-scoped deploy-token **secret**
(see `.github/workflows/publish.yml`, `paid_backend` dispatch input), never a
build arg. The paid-capable build **fails closed**: if `PRAXIS_EE=1` is requested
but no wheel is present, the build fails rather than silently producing a
free-only image. No private source, signing keys, or registry credentials live
in this repository or in any image.
