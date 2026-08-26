# Dependency and container security policy

How dependency and image vulnerabilities are gated, triaged, and updated. This
is maintainer process for this repository, not operator documentation, so it is
not part of the published documentation set.

Two mechanisms, with different jobs:

- **Dependabot** keeps dependencies *up to date* (opens grouped update PRs).
- **Trivy** is the *gate*: it fails CI on CRITICAL vulnerabilities in both the
  built container images and the repo's dependency manifests.

This document is the maintainer policy for both. It does **not** cover static
analysis (SAST) or SBOM/signing/GHCR publishing, which are tracked separately.

## Dependabot

Config: [`.github/dependabot.yml`](https://github.com/cytechlabs/praxis/blob/main/.github/dependabot.yml).

### Coverage

| Ecosystem | Path | Group(s) | Day (UTC) |
| --- | --- | --- | --- |
| GitHub Actions | `/` | `github-actions` | Mon |
| npm (frontend) | `/frontend-next` | `frontend-prod`, `frontend-dev` | Mon |
| pip (backend) | `/backend` | `backend-python` | Tue |
| Go modules (agent) | `/agent` | `agent-go` | Tue |
| Docker base (backend) | `/backend` | `docker-backend` | Wed |
| Docker base (frontend) | `/frontend-next` | `docker-frontend` | Wed |
| Docker base (agent, **dev-only**) | `/agent` | `docker-agent` | Wed |

- **Grouped** so a week's bumps arrive as a handful of reviewable PRs, not
  dozens. Frontend is split **production vs development** so runtime
  (security-relevant) bumps are reviewed apart from tooling churn.
- **Staggered** across Mon/Tue/Wed mornings to avoid a single-day flood.
- **Agent honesty:** the shipped agent is a static Go binary (tarball release),
  so its **Go modules** are the real supply-chain surface (covered by both
  Dependabot `gomod` and the Trivy filesystem gate). `agent/Dockerfile.dev` is a
  **dev-only** build image, tracked for dev-toolchain hygiene, labeled
  `dev-only`, and **not** shipped or image-gated.
- **Docker filename note:** Dependabot's docker ecosystem detects the
  non-standard `Dockerfile.prod` / `Dockerfile.dev` names by filename match.

### Labels

PRs are labeled `dependencies` plus an ecosystem label (`github-actions`,
`frontend`, `backend`, `agent`, `docker`; agent's dev image also `dev-only`).
Dependabot auto-creates `dependencies`; create the others in the repo so they
apply cleanly (a missing label is skipped with a warning, not a failure).

### DCO exemption

The DCO gate ([`.github/workflows/dco.yml`](https://github.com/cytechlabs/praxis/blob/main/.github/workflows/dco.yml))
requires a `Signed-off-by` trailer on every non-merge commit. Dependabot commits
are bot-authored and cannot carry one, so the DCO job **exempts the Dependabot
GitHub App** only when the pull request author is `dependabot[bot]` and the
commit author email is its noreply address
(ending `dependabot[bot]@users.noreply.github.com`). The match is Dependabot-specific,
does not exempt bots in general, and does not trust a commit email by itself.

### Triage cadence

1. **Weekly:** review open Dependabot PRs. CI (lint/test/build + Trivy gates)
   runs on each; merge green ones.
2. **Security updates first.** GitHub raises Dependabot *security* PRs out of
   band when an advisory affects a pinned dependency; prioritize these over the
   scheduled version bumps.
3. **Grouped-PR failures:** if one member of a grouped PR breaks CI, either pin
   that member back in the manifest (Dependabot re-groups the rest) or split it
   out; don't merge a red group.
4. **Majors:** major-version bumps may need code changes, so treat them as normal work,
   not a rubber-stamp.

## Trivy vulnerability gates

Config: the `security-scan` and `dependency-scan` jobs in
[`.github/workflows/ci.yml`](https://github.com/cytechlabs/praxis/blob/main/.github/workflows/ci.yml).

| Gate | Scans | Blocks on |
| --- | --- | --- |
| `security-scan` (image) | backend + frontend **production images** | CRITICAL |
| `dependency-scan` (filesystem) | repo manifests: backend pip, frontend npm, **agent Go modules** | CRITICAL |

- **CRITICAL blocks; HIGH is report-only.** Both gates fail CI on any
  unignored **CRITICAL** CVE (`ignore-unfixed: true`, so only fixable ones). A
  full **CRITICAL / HIGH / MEDIUM** report is emitted as a SARIF build artifact
  (`security-reports`, `dependency-scan-reports`) for inspection.
- **Why HIGH is not gated:** at 1.0 there is a non-empty HIGH backlog in
  upstream pip/npm dependencies that we can't always fix immediately. Blocking on
  HIGH would wedge CI on noise; instead HIGH is visible in the SARIF and driven
  down by Dependabot. Revisit blocking HIGH once the backlog is consistently
  empty.
- **Surfacing in the Security tab:** the SARIF artifacts can be uploaded to
  GitHub code scanning via `github/codeql-action/upload-sarif` where GitHub
  Advanced Security is enabled (see the notes in `ci.yml`).

### Allowlist / `.trivyignore`

There is currently **no** `.trivyignore`; the CRITICAL gates are clean without
one. Add an ignore **only** when a CRITICAL is unfixable/inapplicable and would
otherwise wedge CI. Every entry must be justified inline:

```
# CVE-XXXX-YYYYY  package@version  path/to/manifest
# Reason:  <why this is not exploitable / no fix available>
# Owner:   <github-handle>
# Review:  <YYYY-MM-DD, re-evaluate or remove by this date>
CVE-XXXX-YYYYY
```

Ignores are a temporary escape hatch, not a backlog: each carries an owner and a
review/expiry date, and is removed once the dependency is patched.
