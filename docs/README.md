# Praxis Documentation

This directory is the source of the Praxis documentation site. Every top-level
`*.md` file here is published, both on the public documentation site and as the
offline copy bundled into the application at `/help`. It is written for people
deploying and operating Praxis.

Documentation for people working on the repository lives in subdirectories,
which are never routed:

- `maintainers/` - cutting a release, publishing images, importing the public
  repository.
- `contributors/` - the branch model, and what belongs in a public document.
- `design/` - interface tokens and primitives.

`docs-site/src/published.mjs` names the two top-level files that also stay
unpublished.

Pages are written as plain Markdown so they read correctly here and on the
site. Link to a neighbouring page as `other-page.md`; the build rewrites it to
the routed URL. See `docs-site/README.md` for how to build, add a page, and
publish.

The index below is a reading order for the repository. The site's own
navigation is grouped differently, in `docs-site/src/sidebar.mjs`.

Praxis is a self-hosted **Linux fleet lifecycle control plane**: it owns the
lifecycle of a Linux fleet, from host enrollment and inventory through package
and content, patching, compliance evidence, and remediation, from one backend
that stays the policy authority. Access brokering (SSH sessions, approvals, file
transfer, session recording) is part of the product but not the whole of it.

## What Praxis manages

- **Host enrollment and identity**: register hosts, establish identity, and
  reach them over SSH by default or an optional thin agent.
- **Inventory and facts**: installed packages, distribution/kernel/uptime,
  reboot state, and end-of-life status across the fleet.
- **Access and audit**: fleet-scoped RBAC, just-in-time access requests and
  approvals, interactive SSH sessions, command approvals, file transfer, and a
  stable audit trail for all of it.
- **Package and content lifecycle**: package inventory and updates, repository
  mirrors, signed channels and content profiles, and air-gapped export/import.
- **Patch lifecycle**: patch policies and rings (rollout policy) modeled
  separately from update plans and executions (the instances), with approvals,
  reboot control, and rollback.
- **Compliance and remediation**: compliance policies and per-host evidence, and
  a governed, approval-gated remediation workflow.
- **Operational reporting**: package reports, fleet operations history,
  activity, analytics, and configuration audit.

## What Praxis does not manage

Praxis is deliberately scoped. It is **not** a compliance attestation (it
produces evidence, not certification), **not** an endpoint DLP product, and does
**not** own encryption-at-rest for the data tier or set your audit-retention
policy for you. Interactive browser sessions use SSH rather than the agent in
1.0, and not every compliance finding can be auto-remediated. See
[Known Limitations](known-limitations.md) for the full, explicit list.

## Architecture And Security

- [Fleet Lifecycle Architecture](fleet-lifecycle-architecture.md) - durable
  product and architecture frame for Praxis as a Linux fleet lifecycle manager.
- [Security Model and Trust Boundaries](security-model.md) - tiers, trust
  boundaries, what each component (frontend, backend, PostgreSQL, Vault, broker,
  agent, mirrors) is trusted to do, and the content/airgap trust chain, with an
  architecture diagram.
- [Agent Protocol](agent-protocol.md) - thin-agent identity, tunnel, operation,
  and audit protocol contract.

## Operations

- [Production Hardening](production-hardening.md) - supported deployment shapes,
  install / upgrade / backup-restore / Vault posture, environment validation,
  and database migration/rollback posture.
- [Airgap Export / Import](airgap.md) - the disconnected workflow: export a
  signed content bundle on a connected control plane and verify/import it on an
  air-gapped one.
- [Linux Support Matrix](support-matrix.md) - the official 1.0 managed-host
  support boundary (supported / best-effort / unsupported distros,
  package-manager families, architectures), the per-capability validation grid,
  and known distro-specific limitations.
- [Known Limitations](known-limitations.md) - what Praxis does not do, stated
  plainly, so you can plan complementary controls.

## Identity And Authentication

- [OIDC / SSO Setup](oidc-setup.md) - configure single sign-on via the OIDC
  Authorization Code flow: Praxis URLs and environment variables, a Keycloak
  walkthrough, a generic provider checklist, ID-token role-claim mapping to
  `admin` / `maintainer` / `auditor`, and troubleshooting.

## Audit And Compliance

- [Audit Event Schema](audit-schema.md) - audit event wire format and delivery
  contract.
- [Compliance Evidence Map](compliance-map.md) - public evidence mapping for
  SOC 2, PCI DSS, and HIPAA control discussions.
- [Remediation Workflow](remediation-workflow.md) - the governed
  request to approve to plan to acknowledge remediation lifecycle and how it
  produces change-management evidence.
