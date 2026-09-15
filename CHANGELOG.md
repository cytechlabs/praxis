# Changelog

All notable changes to Praxis are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Praxis
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Container images and the agent binary share the application version. The app is
released under the `vX.Y.Z` tag (images `ghcr.io/cytechlabs/praxis-backend` and
`praxis-frontend` at `X.Y.Z`); the fleet agent ships under the matching
`agent-vX.Y.Z` tag. See [docs/maintainers/release-checklist.md](docs/maintainers/release-checklist.md)
for the release runbook.

## 1.0.1 - maintenance release

A maintenance release for the 1.0 line. It corrects host-facing defects found
after 1.0.0, closes framework and SSH dependency advisories, and adds a guided
flow for adding the first system. Every change landed on `main` first and was
cherry-picked onto `release/1.0`.

### Security

- FastAPI and Starlette move to releases whose form and multipart parsers are
  not affected by the advisories that applied to the 1.0.0 pins, and the login
  route bounds oversized password candidates.
- SSH connections refuse DSA keys, RSA signatures over SHA-1, SHA-1 key
  exchange, and GSSAPI, on every path including browser sessions and file
  transfer. RSA key material is unaffected and is signed with RSA-SHA2.
- Browser terminal sessions and SFTP negotiate RSA-SHA2 certificates against
  OpenSSH 10 hosts instead of failing authentication.
- Secret scanning detects again: the repository gitleaks configuration loads
  the pinned built-in rule set, and a pre-commit contract fails the commit if
  it ever stops doing so.

### Correctness

- Security scans on RPM-family hosts parse advisory output with its own
  parser, so a host with listed advisories no longer reports zero.
- The fleet dashboard tells apart a fleet that was never security-scanned from
  one scanned with no findings.
- Compliance orders Debian and RPM package versions by their own grammars
  rather than by PEP 440.
- Per-host audit history is complete again: an event about one host names it,
  and an event spanning a set of hosts records every host it affects.
- A patch execution with no dispatchable package work is refused instead of
  being recorded as a successful run that installed nothing.
- Reboot evidence is collected fresh after patching and fails closed when it
  cannot be established.
- Stored SSH credential keys load for Ed25519, ECDSA, and RSA in both the
  OpenSSH container and the older PEM envelopes.
- Access Broker enrollment works on minimal Debian and EL hosts, including
  those without systemd.
- A command policy entry an administrator deleted stays deleted across
  restarts, and the bootstrap administrator is provisioned once per
  installation rather than recreated on every boot.
- Application loggers stay enabled through in-process migrations.

### Added

- A guided flow for adding the first system: connect, authenticate, verify,
  discover, organize, confirm, finish. Nothing permanent is created until the
  final step, host keys are approved explicitly, and a host that cannot be
  reached leaves no record and consumes no licence capacity. This is the one
  approved feature exception in the 1.0 line.

### Packaging and operations

- The production backend image is pinned to Python 3.14.7.
- The backend runtime shell assets ship in the installed wheel and source
  distribution.
- Native select controls are readable in both themes.
- Documentation describes the current release only, and CI publishes
  multi-language test coverage.

### Upgrade notes

`systems.ip_address` gains a uniqueness constraint. The upgrade refuses to run
while duplicate addresses exist and names them rather than merging them; see
[docs/upgrade-notes-1-0.md](docs/upgrade-notes-1-0.md) for the remediation.

### Accepted security findings

The qualified backend image reports no fixable CRITICAL findings, two fixable
HIGH findings and one fixable MEDIUM finding. These findings are accepted for
1.0.1 under the report-only policy in
[docs/maintainers/dependency-security-policy.md](docs/maintainers/dependency-security-policy.md).
No per-finding suppression or scanner gate change was made:

- HIGH: `CVE-2025-47273`, setuptools 70.3.0, fixed in 78.1.1
- HIGH: `GHSA-6v7p-g79w-8964`, msgpack 1.1.2, fixed in 1.2.1
- MEDIUM: `CVE-2026-59890`, setuptools 70.3.0, fixed in 83.0.0

These copies are vendored inside pip, rather than separately installed Python
distributions. Their absence from package metadata does not mean the code is
absent. Remediation must verify patched vendored copies or their safe removal
in the built image; upgrading pip or the base image alone is not proof of a fix.

The qualified frontend image has zero fixable findings. The source dependency
scan reports three additional findings in the documentation build dependencies,
also accepted for 1.0.1:

- HIGH: `CVE-2026-84375`, js-yaml 4.3.1, fixed in 4.3.2
- HIGH: `CVE-2026-84370`, svgo 4.0.2, fixed in 4.1.0
- MEDIUM: `CVE-2026-84369`, svgo 4.0.2, fixed in 4.1.0

These documentation-build packages are absent from both qualified runtime
images, but execute during documentation builds. No exploit path was
demonstrated; absence from runtime images is not a claim of unreachability.
Both sets of accepted findings are scheduled for 1.0.2 maintenance.

The qualification used Trivy 0.70.0 with the vulnerability database updated
2026-09-10. The existing `ignore-unfixed: true` gate excludes findings without
available fixes. Unfiltered scans still reported 17 backend and 4 frontend
CRITICAL findings without fixes; a passing gate does not mean these are absent
or harmless. This reporting limitation is explicitly acknowledged for 1.0.1;
final publication artifacts must be checked for materially changed findings.

The Starlette form-parsing advisories affecting the 1.0.0 pins and the six
libssh2 findings covered by Debian DLA-4773-1 are remediated in the qualified
images, not accepted debt. The backend carries libssh2-1 1.10.0-3+deb12u1.

### Known limitations

Unchanged from 1.0.0; see
[docs/upgrade-notes-1-0.md](docs/upgrade-notes-1-0.md).

A failed file download can return HTTP 200 after streaming headers have been
sent, even though the server audit records failure. Clients should not treat
the status alone as proof of transfer completeness. Correction is scheduled for
1.0.2.

Browser qualification includes accepted test limitations: the full suite is
not green because of authentication prerequisites, login-rate budgeting,
obsolete UI assertions and edition-specific expectations. Focused onboarding
and live operational controls passed. Paid bulk-export downloads, demo and
rollback fixtures, and the routes covered only by the excluded screenshot
suite were not fully exercised. Test repairs and coverage follow-ups are
scheduled for 1.0.2; these gaps are not reported as passing tests.

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
