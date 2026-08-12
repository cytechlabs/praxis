# Public import checklist

This document defines how the Praxis source tree is imported into the public
`cytechlabs/praxis` repository as a clean, single-history import: what gets
included, what stays private, how namespaces are normalized, and how to validate
the tree before the first public commit.

It is a **preparation and verification** guide. It does not itself create the
public repository, rewrite history, or push anything — those are operator
actions taken deliberately once every check below passes.

The read-only companion `scripts/check-public-import-readiness.sh` enforces the
machine-checkable parts of this document.

## Source

- Import from the tagged release commit on `main` (or the corresponding
  `release/X.Y` branch) — the same commit that is tagged for the release (see
  [release-checklist.md](release-checklist.md) and
  [branching-model.md](../contributors/branching-model.md)).
- The public repository starts with a **fresh history**: the import is a clean
  snapshot, not a mirror of the internal Git history.

## Included / excluded top-level paths

### Included (imported)

| Path | Notes |
|---|---|
| `backend/` | App, Alembic migrations, tests. |
| `frontend-next/` | Next.js app, components, help content. |
| `agent/` | Go fleet agent + packaging. |
| `e2e/` | Playwright end-to-end specs. |
| `scripts/` | Operator + release/import helper scripts. |
| `caddy/`, `vault/` | Proxy config and Vault bootstrap **config** (no secrets). |
| `docker-compose.yml`, `docker-compose.prod.yml` | Deployment. |
| `.env.example` | Template only — never a real `.env`. |
| `.github/` | CI, publish, and agent-release workflows. |
| `package.json` | Build entry points. |
| Top-level docs | `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `NOTICE`. |
| `docs/*.md` | Product/operator docs (see classification below). |
| `backend/docs/`, `frontend-next/docs/` | Developer reference docs (verified free of process wording). |

### Excluded (stay private / not imported)

| Path | Why | State |
|---|---|---|
| `claude-codex/` | Internal review/handoff protocol notes. | git-ignored, untracked |
| `project-docs/` | Internal dev fixtures and working notes. | git-ignored, untracked |
| `.claude/`, `.secrets/`, memory files | Local tooling / secrets. | git-ignored |
| `docs/dev-notes/` | Developer working notes (implementation-history tone). | **tracked — drop at export** |
| `praxis-do-import.json` | Local provider import artifact. | untracked |
| `.env`, `*.pem`, `*.key`, `*_rsa`, `ssh_host_*` | Secrets / key material. | git-ignored |
| `*.log`, `test-results/` | Local run artifacts. | git-ignored |

`docs/dev-notes/` is the only **tracked** exclusion: it is intentionally kept in
the internal tree but must be dropped from the exported snapshot before the first
public commit (it retains implementation-history wording by design and is not
part of the product docs). It holds developer working notes and internal
engineering references — the thin-agent notes, the backend test inventory, the
real-host access-control regression matrix, and the fleet-scope inventory.
Because it is dropped at export, the public-tone checks (internal-process markers
and `PRA-NNN`/"slice" wording) are **exempt** for `docs/dev-notes/`; the secret,
namespace, and disallowed-path checks still apply.

**Private paid extension (`praxis-ee`):** the closed-source paid extension lives
in a **separate private repository**, never inside this tree. The readiness
checker fails on any tracked `praxis[_-]ee/` source path or `license_private*`
key so private extension source or signing keys can't leak into the public
import. Only the loader boundary (`backend/app/ee/`) and the opt-in
`PRAXIS_EE=1` build arg in `backend/Dockerfile.prod` are public.

## Public-doc classification

The curated public narrative docs must read as product/operator documentation —
no `PRA-NNN`, "slice", or internal-process wording. This is enforced by the
readiness checker.

| Doc | Disposition |
|---|---|
| `README.md` | Keep — product/operator tone. |
| `CHANGELOG.md`, `docs/upgrade-notes-1-0.md` | Keep — release docs. |
| `docs/maintainers/*` | Keep — release and repository runbooks. |
| `docs/agent-protocol.md`, `docs/airgap.md`, `docs/audit-schema.md` | Keep — scrubbed of issue/slice wording. |
| `docs/compliance-map.md`, `docs/eol-data.md`, `docs/remediation-workflow.md` | Keep — scrubbed. |
| `docs/production-hardening.md`, `docs/support-matrix.md`, `docs/oidc-setup.md` | Keep — scrubbed / already clean. |
| `docs/demo-walkthrough-operator.md`, `docs/demo-walkthrough-auditor.md` | Keep — demo path. |
| `agent/README.md`, `agent/packaging/README.md` | Keep — scrubbed / already clean. |
| `backend/docs/*`, `frontend-next/docs/*` | Keep — developer reference; verified free of process wording. |
| `docs/design/*` | Keep — design-system developer reference; scrubbed. |
| `docs/dev-notes/*` | **Exclude** — developer working notes + internal engineering references (test inventory, real-host regression matrix, fleet-scope inventory). |

## Namespace normalization

All release-facing references use the public namespace:

- GitHub: `github.com/cytechlabs/praxis`
- Container images: `ghcr.io/cytechlabs/praxis-backend`, `ghcr.io/cytechlabs/praxis-frontend`
- Go module: `github.com/cytechlabs/praxis/agent`
- cosign identity regex: pinned to `cytechlabs/praxis` (see `agent/packaging/README.md`)

Checks:

- No `cfreeman29` references anywhere in tracked files.
- No `ghcr.io/<org>/praxis` or `github.com/<org>/praxis` reference where `<org>`
  is not `cytechlabs`.

## Secret / artifact checks

- No tracked private key material (`*.pem`, `*.key`, `*_rsa`, `ssh_host_*`).
- No tracked `.env` (only `.env.example`).
- No tracked logs, `test-results/`, or the local `praxis-do-import.json`.
- No tracked `claude-codex/`, `project-docs/`, or `.secrets/`.

## Engineering-history references (accepted, non-blocking)

Code, migrations, tests, and workflow YAML retain ordinary issue-tracker
references as engineering history — these are **not** scrubbed and are **not**
launch-blocking:

- Migration and test **filenames** contain issue slugs (e.g. `..._pra159_...`);
  these are immutable identifiers and are left as-is.
- Some code docstrings reference internal design notes by filename
  (`project_praNNN_design_locks.md`) to explain a design constraint. These are
  dangling references in the public tree but leak no secret; treat as optional
  future cleanup, not an import blocker.

The readiness checker deliberately scopes its `PRA-`/"slice" gate to the curated
narrative docs above, and only hard-fails tree-wide on genuine private-leak
markers (Codex/Claude/handoff-protocol/`claude-codex`/`cfreeman29`).

## Validate before importing

Run from a clean tree:

```sh
git diff --check
scripts/check-public-import-readiness.sh
scripts/check-release-readiness.sh 1.0.0
docker compose run --rm frontend npm run lint
docker compose run --rm frontend npx tsc --noEmit --incremental false
```

All must pass. Then, as a final confidence step, validate the *exported* snapshot
from a fresh checkout (see below) rather than the working tree.

## Clean-import procedure (operator, run deliberately)

These steps are the plan for the actual import. Do **not** run them as part of
readiness prep; run them only when cutting the public repo.

1. Produce a clean snapshot of the release commit (no history):

   ```sh
   git archive --format=tar --prefix=praxis/ <release-commit> | (cd /tmp && tar -xf -)
   ```

2. Drop tracked exclusions from the snapshot (`/tmp/praxis/`):
   - `docs/dev-notes/`
   - anything else listed as excluded above that happens to be tracked.

3. From `/tmp/praxis/`, re-run the validation commands above against the
   snapshot to confirm the exported tree is clean and builds.

4. Initialize the public repository from the snapshot as a single initial
   commit and push to `cytechlabs/praxis`.

> This document and the readiness checker cover steps 1–3's verification. Step 4
> is a deliberate operator action outside this prep.
