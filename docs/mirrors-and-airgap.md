---
title: Mirrors and content
description: Package mirrors, content channels and profiles, signing keys, and airgapped transfer.
---

Praxis can serve packages to your fleet from mirrors you control, and can move that content into fully disconnected (airgapped) environments. Everything lives under the **Automate** workspace.

## Mirrors

`Automate > Mirrors` lists the package repositories Praxis maintains. A mirror has a **package family** (`deb` or `rpm`) and a **source mode**:

- **Upstream sync** - Praxis pulls from an upstream repo on a schedule. Each sync is a **run** with a status; the mirror detail page shows run history and lets you trigger an on-demand sync.
- **Imported offline** - content arrives via an airgap bundle rather than a live upstream (see below).

Mirrors are signed so downstream hosts can verify what they install. The mirror's **signing key** and the **upstream trust** it validates against are managed as part of the mirror; a mirror that can't validate its upstream or sign its output will surface an error state rather than serve unverified content.

> **A mirror that looks "synced" but shows a signing or upstream-trust error is not safe to serve.** Check the run status and signing state on the mirror detail page before pointing hosts at it.

## Channels and profiles

Mirrors are raw repositories; **channels** and **profiles** compose them into something hosts subscribe to:

- `Automate > Channels` - a **channel** bundles one or more mirrors of the same package family, optionally pinned to a specific mirror run.
- `Automate > Profiles` - a **profile** is the host-facing object. Hosts, groups, and smart groups **subscribe** to a profile. Each host resolves to a **single effective profile**; when subscriptions conflict, the host is flagged rather than guessing.

Applying a profile writes the host's `/etc` source-list configuration and installs the trust needed to consume the channel's mirrors. Apply is explicit - resolving/previewing a profile never changes a host until you apply it.

> **Conflicting profile subscriptions block a host.** If a host is subscribed to two profiles (directly and via a group, say), it resolves to a conflict state and won't apply until you remove the ambiguity.

> **A run pin is a tracking pin, not a byte freeze (1.0).** Praxis keeps mirror *bytes* live-only - only the last-promoted sync exists on disk; retention keeps older runs as metadata/manifests, not bytes. A channel pin records a content state, but an airgap export can reproduce it byte-exact only while that run is still what's live. If you pin to an older run and then re-sync, an export with **pinned** snapshot selection is **refused** (`historical_bytes_unavailable`) rather than exporting the wrong bytes - export **latest**, re-pin to the current run, or keep the earlier **bundle tar** as your byte-exact archive. See the airgap runbook.

## Airgap export / import

For disconnected sites, Praxis exports a signed **airgap bundle** of mirror content and metadata that you physically transfer to the offline instance, which imports it into an *imported-offline* mirror. The bundle is signed with an instance airgap key so the offline side can verify integrity before trusting the content.

This is a procedure with real operational steps (key handling, transfer, verification); the in-app screens drive it, but the full runbook is [airgap export and import](airgap.md).

## Airgap signing keys & trust pins

`Automate > Airgap Keys` is where you manage the two sides of bundle trust - no database edits required.

- **Bundle signing key (connected/export side).** One key is `active` and signs every bundle you export. Bootstrap it once, then **copy its armored public key** and hand it to the offline instance out-of-band.
- **Rotating a key.** Rotation is immediate: the current key becomes `rotating_out` (still valid for verifying bundles you already exported) and a new `active` key is generated. **Before you import any bundle exported after the rotation, pin the new public key on the offline side** - bundles signed by the new key won't verify until its pin exists. Keep the old pin during the overlap: the importer accepts a bundle if *any* active pin verifies it, so old and new bundles both import cleanly.
- **Retire** a `rotating_out` key once nothing needs to verify bundles it signed. You can't retire the `active` key - rotate first.
- **Import trust pins (offline/import side).** The offline instance trusts a bundle only if a pinned public key verifies its signature - never the armored bytes carried inside the tar. Add a pin from the exporter's armored public key; **remove the old pin only after you stop importing bundles it signed.** Removed pins are soft-deleted and kept for audit.

Every signing-key create/rotate/retire and trust-pin add/remove is written to the audit log (fingerprints and statuses only - never private key material or Vault paths).

## Common failure modes

- **Unverified/expired upstream key** - sync fails closed; the mirror won't serve until trust is repaired.
- **Signing key not yet provisioned** - the mirror can pull but can't sign; hosts won't trust it.
- **Profile conflict** - a host subscribed via multiple paths won't apply.
- **Family mismatch** - a channel can only bundle mirrors of the same `deb`/`rpm` family.

## Related

- Airgap runbook: [airgap export and import](airgap.md). Serviceable families: the [Linux support matrix](support-matrix.md).
- Hardening guidance for offline and edge deployments: [production hardening](production-hardening.md).
- **Patch Workflows** - mirrors/profiles decide *where* hosts get packages; patch policies decide *how and when* they're applied.
