# Changelog

All notable changes to Praxis are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Praxis
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Container images and the agent binary share the application version. The app is
released under the `vX.Y.Z` tag (images `ghcr.io/cytechlabs/praxis-backend` and
`praxis-frontend` at `X.Y.Z`); the fleet agent ships under the matching
`agent-vX.Y.Z` tag. See [docs/maintainers/release-checklist.md](docs/maintainers/release-checklist.md)
for the release runbook.

## 1.0.0 — first stable release

The 1.0 line is the first supported, self-hostable release of Praxis: a
self-hosted control plane for the full lifecycle of a Linux fleet — inventory,
access, content, patching, and compliance — with an auditable supply chain.

The date is finalized when the `v1.0.0` tag is cut; until then this section is
the running summary of what 1.0 ships.

### Fleet inventory and facts

- Host inventory with groups and smart groups, driven by collected host facts
  (distro, release, package manager, reboot-required, and more).
- Distribution lifecycle / EOL tracking: hosts are classified against a shipped
  support matrix so the fleet dashboard surfaces supported, best-effort, and
  end-of-life systems. Reference data is refreshable with
  `python -m app.scripts.update_eol_data`.

### Access and secrets

- All credentials are HashiCorp Vault-backed, in either a Praxis-managed or a
  linked mode; no secret material is stored in the application database.
- Zero-trust SSH access broker: per-user provisioning, an SSH certificate
  authority with host-key TOFU, command approvals, and connection tunables.
- Browser-based interactive SSH terminal with full session recording, SFTP,
  per-user TOTP, fleet RBAC, and audit export.
- OIDC / SSO: bring your own identity provider (no bundled IdP).

### Thin fleet agent

- Optional Go agent that connects a host to the backend over a long-lived mTLS
  WebSocket, for hosts you cannot or do not want to reach over SSH.
- Keyless-cosign-signed release artifacts with per-arch tarballs and checksums;
  see [agent/packaging/README.md](agent/packaging/README.md) for verification.

### Content backbone

- Repository mirror engine with manifest snapshots, a multi-worker-safe
  scheduler, and a global free-space reserve.
- Repository signing and trust: staged manual key rotation with an ephemeral,
  fingerprint-checked signing environment.
- Content channels and content profiles: a single effective profile per host,
  version pins, and explicit apply.
- Air-gap export / import for moving content into disconnected environments.

### Patch lifecycle

- Patch policy engine with rings for staged rollout.
- Patch update plans with preflight snapshots, scoped approvals, maintenance
  windows, per-host execution, and rollback feasibility evaluation.

### Compliance

- Compliance policies with checks, per-host evidence, and pass/fail findings.
- Remediation requests raised from failing findings, tracked to resolution.
- Operator and auditor demo walkthroughs plus a repeatable, synthetic demo
  fixture ([docs/demo-walkthrough-operator.md](docs/demo-walkthrough-operator.md),
  [docs/demo-walkthrough-auditor.md](docs/demo-walkthrough-auditor.md)).

### Packaging, supply chain, and operations

- Open-core edition model with a 15-host free cap enforced by a license JWT.
- Production deployment via `docker-compose.prod.yml`, with images pinned by
  `PRAXIS_VERSION` and runtime healthchecks on the backend and frontend.
- Backend production image runs on Python 3.14 (`python:3.14.6-slim-bookworm`);
  every dependency installs from a wheel (no source builds in the release image).
- Every release attaches a CycloneDX 1.5 SBOM per image; CI runs Trivy against
  both production images and blocks any `CRITICAL` CVE, with SARIF reports
  published as build artifacts.
- Supported production posture is a single backend worker (`UVICORN_WORKERS=1`)
  while interactive SSH sessions are enabled; the entrypoint enforces this.

### Known limitations

See [docs/upgrade-notes-1-0.md](docs/upgrade-notes-1-0.md) for the full list.
Highlights:

- Single-instance backend is the supported topology; horizontal scale-out and
  Docker Swarm are not supported in 1.0.
- Multi-worker interactive SSH sessions are not supported.
- The prod-overlay, end-to-end, upgrade, and backup/restore smokes are manual
  release gates, not blocking CI lanes.
