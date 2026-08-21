# AGENTS.md

Guidance for coding assistants and automated reviewers working in this
repository. Human contributors should start with
[CONTRIBUTING.md](CONTRIBUTING.md); this file adds the repository-specific
rules an automated change is most likely to get wrong.

Praxis is a self-hosted Linux fleet lifecycle control plane. A FastAPI backend
is the single policy authority for a fleet of Linux hosts, reached over SSH by
default or through an optional Go thin agent. The public core is Apache-2.0.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI service. `app/api` routes and schemas, `app/services` domain logic, `app/db` SQLAlchemy models, `app/core` cross-cutting concerns (auth, config, redaction, entitlements), `app/broker` agent broker, `app/cli` operator commands, `alembic/` migrations, `tests/` |
| `frontend-next/` | Next.js application. Application pages and API routes live under `src/pages` (Pages Router, with API handlers in `src/pages/api`); `src/app` holds only the app-router root layout and global assets such as `globals.css` and fonts. Also `src/components`, `src/services` API clients, `src/__tests__` and co-located unit tests |
| `agent/` | Go thin agent. `cmd/praxis-agent`, `internal/`, `packaging/`, plus `VERSION` and `GO_VERSION` |
| `docs/` | Documentation source. Top-level `*.md` is published; `contributors/`, `maintainers/`, and `design/` are not routed |
| `docs-site/` | Astro build tooling for the documentation. Content is not here |
| `scripts/` | Documentation verification, release, and backup tooling |
| `e2e/` | Playwright specs that run against a running stack |
| `.github/workflows/` | CI, DCO enforcement, image publishing, agent release |
| `caddy/`, `vault/`, `docker-compose*.yml` | Deployment topology |

Ownership boundaries follow the trust model in
[docs/security-model.md](docs/security-model.md): the backend decides policy,
the broker only carries operations, the agent exposes primitives only, and the
frontend holds no secrets and makes no host connections.

## Verification

Run the checks for the areas you touched, and say plainly what you did not
run. The backend, frontend, agent, and documentation blocks below are what CI
runs, directly or through an equivalent lane split or image build. The
end-to-end block is not part of CI, and the agent artifact and reproducibility
targets run only in the tag-driven release pipeline, so neither is covered by a
green pull request.

**Backend**, from `backend/` in a Python 3.14 virtualenv with a throwaway
Postgres (one-time setup in [backend/tests/README.md](backend/tests/README.md)):

```sh
black .
isort --profile black --settings-path setup.cfg .
pylint app --fail-under=5.0
pylint --disable=all --enable=unused-import --score=n app alembic tests scripts
alembic upgrade head
pytest
```

The test suite runs as three CI lanes: `tests/services`, `tests/api`, and
`tests --ignore=tests/services --ignore=tests/api`. The last is defined by
exclusion, so a new top-level `tests/` directory is gated automatically.

**Frontend**, from `frontend-next/`:

```sh
npm ci
npx eslint src
npm run check:colors
npx tsc --noEmit
npm test
```

`check:colors` blocks raw `red-*` / `blue-*` utilities and `#DC2626` in the
foundation surfaces (`src/components/ui`, `src/components/layout`,
`src/components/MainLayout.tsx`, `src/app/globals.css`, `tailwind.config.ts`).
Use the semantic tokens documented in
[docs/design/ui-foundation.md](docs/design/ui-foundation.md). Run `npm run
build` as well when routes or the build configuration change.

**Agent**, from `agent/`:

```sh
gofmt -l .          # must print nothing
go vet ./...
go test ./...
go mod tidy         # must leave the tree clean
```

`make lint` runs golangci-lint (CI pins v2.11.0, matching `agent/Dockerfile.dev`),
and `make build` / `make build-all` produce binaries. `make release` and
`make verify-repro` are release-surface checks: run them yourself when you change
packaging, build flags, or a toolchain pin, because only the release pipeline
runs them.

**Documentation**, from `docs-site/`:

```sh
npm ci
npx playwright install --with-deps chromium   # needed for the diagram check
npm run verify
```

**End to end**, from the repository root, against a running stack:

```sh
npm run test:e2e
```

The default base URL is `https://localhost` (the Caddy ingress); override with
`E2E_BASE_URL`. Run these when you change a flow the specs cover or the ingress
topology; no pull request check exercises them for you.

## Generated and synchronized files

- `frontend-next/public/help/**` is **generated** from `docs/` and committed so
  the frontend image serves documentation offline. Never edit it directly. After
  changing `docs/`, run `node scripts/build-docs.mjs --bundled` and commit the
  result. CI rebuilds it and fails if the committed bytes differ.
- `docs-site/diagrams/*.svg` are rendered from Mermaid sources and committed.
  Regenerate with `node scripts/build-docs-diagrams.mjs`.
- `docs-site/published-routes.json` is the reviewed page inventory. Update it
  with `node scripts/check-docs-public-content.mjs --write`.
- `agent/VERSION` is the only place the released agent version is decided. Do
  not restate it elsewhere.
- `agent/GO_VERSION` is authoritative for the Go toolchain, and
  `agent/Dockerfile.dev` deliberately mirrors it twice: the `GO_VERSION` build
  argument and the immutable base-image digest that argument selects. That
  mirror is required, not duplication to remove. Bump the file, the tag, and the
  digest together; the release contract tests fail if they drift apart.
- Lockfiles are produced by the package manager, not edited by hand.

Adding a documentation page: create `docs/<slug>.md` with `title` and
`description` frontmatter and no top-level heading, link to neighbours as
`other-page.md` (site-absolute links are rejected), add the slug to
`docs-site/src/sidebar.mjs`, register it in the inventory, then rebuild the
bundled copy. Slugs are flat and must not contain a dot.

Public documentation must stay free of internal-only detail: no credentials,
personal paths, private hostnames, or unpublished strategy. A CI check enforces
the boundary described in
[docs/contributors/documentation-boundaries.md](docs/contributors/documentation-boundaries.md).

## Migrations and model registration

- `app/db/base.py` gives every model `id`, `created_at`, and `updated_at`. A
  migration that creates a table must include all three columns.
- Models register on `Base.metadata` by being imported. `app/db/models.py` and
  `alembic/env.py` therefore keep imports that look unused and are marked
  `# noqa: F401; pylint: disable=unused-import`. Removing one can leave
  `Base.metadata` incomplete, and autogenerate would then emit `drop_table` for
  live tables. Keep the same marker on any new registration or re-export import.
- The migration chain is linear. A new revision sets `down_revision` to the
  current head; file names carry a date-ordered prefix so the directory sorts in
  application order.
- Migrations run against real operator data. Do not rewrite or drop data without
  an explicit decision, and provide a working `downgrade` where one is possible.
- `alembic/env.py` requires `DATABASE_URL` or an explicit `POSTGRES_PASSWORD`;
  it deliberately never falls back to a default password.

New routers are created with `APIRouter(redirect_slashes=False)`, declare
collection routes with an empty path string, and place literal paths before
parameterized ones. Wiring one up takes two steps, both load-bearing: re-export
it from `backend/app/api/routes/__init__.py`, adding the name to that module's
`__all__`, then include it in `backend/app/api/main.py`. Dropping the re-export
stops the backend importing at all, and leaving the name out of `__all__` makes
the re-export read as an unused import to the analyzers.

## Security invariants

These are contracts, not preferences. A change that weakens one needs a
maintainer decision first.

- **Policy authority.** Authorization decisions live in the backend. Never move
  one into the frontend, the broker, or the agent.
- **Fleet scope.** Host-facing actions are authorized against fleet-scoped roles
  and grants, and fail closed when scope cannot be established.
- **Audit completeness.** Security-relevant actions emit through
  `app/services/audit_event_service.py`, which persists the audit row as the
  source of truth before fanning out to sinks. The event shape is a stable
  versioned contract; see [docs/audit-schema.md](docs/audit-schema.md). Ad-hoc
  logging is not a substitute.
- **Mandatory recording.** If a session recording cannot be started, the session
  is refused and torn down rather than run unrecorded.
- **Secret redaction.** Support and diagnostic output passes through
  `app/core/redaction.py`, and request/upgrade URLs through
  `app/core/access_log_redaction.py`. Never log tokens, credentials, or
  recording paths, including in exception text.
- **Host key verification.** SSH connections pin a stored host key and reject an
  unknown one unless policy permits trust on first use. A changed key is
  surfaced for review, never silently accepted.
- **Governed command execution.** Whitelist entries set the risk baseline and
  validation rules may escalate it, never downgrade it. Approval gates stay on
  the path they guard.
- **Outbound requests.** Operator-configured outbound HTTP goes through
  `app/services/outbound_http_guard.py`: address validation that fails closed,
  delivery pinned to the validated IP, and no redirects. Private targets are
  blocked unless the caller's own explicit opt-in is set.
- **Fail-closed startup.** `app/core/startup_validation.py` rejects unsafe or
  missing production configuration at boot. A new required setting belongs
  there too.
- **Secret custody.** Credential material lives in the secrets service, not in
  PostgreSQL and not in the repository. Never commit keys, tokens, or a `.env`.
  gitleaks runs in the pre-commit hooks.
- **Open core.** Entitlements are read from `app/core/entitlements.py`, free is
  the default, and a build without the optional extension must behave as free.
  Do not add license or call-home checks to the core.

## Tests

Match test depth to risk: targeted tests for the behavior you changed,
regression tests for adjacent contracts, and the full suite when shared
behavior, a security boundary, a schema, or a broad mechanical edit is involved.
Frontend route or build changes need a production build.

A test must prove the intended behavior and fail for the right reason. Avoid
vacuous assertions, requests malformed enough to fail before reaching the
boundary under test, and snapshots broad enough to hide a regression.

## Analyzer findings and review

- Prefer fixing a finding to silencing it. A suppression must be narrow, inline,
  and carry the reason it is correct. The deliberate registration imports above
  are the standard example: the hosted analyzer honours `# noqa` but not the
  pylint pragma, so both markers go on the same import.
- Do not change analyzer or linter configuration to make a finding disappear.
- Container and dependency scans gate on CRITICAL and report HIGH. Do not
  weaken a gate to land a change.
- Dismissing or classifying a finding is a maintainer decision. Investigate and
  recommend; do not apply the disposition yourself.

## Source hygiene

- Match the surrounding code: naming, comment density, and idiom.
- Comments explain behavior, contracts, and safety invariants, not issue history
  or review process. Issue identifiers belong in commit messages, and in
  existing test filenames and test docstrings, not in production or
  operator-facing content.
- Keep added content ASCII. No em dashes or decorative non-ASCII punctuation.
- No private paths, personal hostnames, internal-only names, or credentials in
  tracked files.
- `.editorconfig` governs whitespace: LF endings, a final newline, no trailing
  whitespace.

## Changes, commits, and pull requests

- Keep a change scoped to what was asked. Do not reformat, re-lint, or tidy
  unrelated files, and leave unrelated working-tree changes alone.
- Stage exact paths. Avoid `git add .`, `git add -A`, broad `git restore`,
  `git reset --hard`, `git clean`, and `git stash` in a tree you do not fully
  own.
- Sign off every commit with `git commit -s`. Exactly one `Signed-off-by`
  trailer, matching the commit author. The DCO workflow enforces this on pull
  requests; see [CONTRIBUTING.md](CONTRIBUTING.md).
- No `Co-Authored-By`, generated-by, model, or assistant attribution in commit
  messages or pull request descriptions.
- Do not commit, push, open, or merge a pull request unless you were explicitly
  asked to. Branch from `main` and target `main`; frozen `release/X.Y` branches
  take cherry-picked backports only.
- Do not change CI workflows, release tooling, or dependency pins as a side
  effect of an unrelated change.

Report security vulnerabilities privately through [SECURITY.md](SECURITY.md),
never in a public issue.
