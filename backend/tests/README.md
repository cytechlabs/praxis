# Backend tests

How the backend suite is organized, how it maps to CI lanes, and how to run it
locally.

## Layout

All tests live under `backend/tests/` in path-based groups:

| Directory           | Tests  | Contents                                             |
| ------------------- | ------ | ---------------------------------------------------- |
| `tests/services/`   | ~2,175 | Service-/domain-layer unit tests (the bulk of logic) |
| `tests/api/`        | ~1,117 | FastAPI route/HTTP-surface tests                     |
| `tests/broker/`     | ~118   | Agent-broker internal API + op lifecycle             |
| `tests/db/`         | ~16    | Migrations / model-level DB behavior                 |
| `tests/cli/`        | ~16    | CLI entry points                                     |
| `tests/integration/`| ~3     | Real docker + Vault e2e (self-skip unless `PRAXIS_E2E=1`) |

Counts are approximate — regenerate with `pytest --collect-only -q <dir>`.

## CI lanes (PRA-278)

`.github/workflows/ci.yml` runs the suite as **parallel lanes** so a failure in
one area returns without waiting on the whole monolith, and the slowest lane —
not the sum of all tests — sets feedback time:

| Lane       | Path selector                                        |
| ---------- | ---------------------------------------------------- |
| `services` | `tests/services`                                     |
| `api`      | `tests/api`                                          |
| `rest`     | `tests --ignore=tests/services --ignore=tests/api`   |

The lanes are **mutually exhaustive**: `rest` is defined by exclusion, so any new
top-level `tests/` directory is automatically gated (it lands in `rest`) and the
split can never silently drop release coverage. `fail-fast` is off, so every lane
reports independently. Pylint runs in its own `backend-pylint` lane; formatting
(black/isort) stays in `backend-lint`.

Slow and integration coverage stays **in-gate**: `slow` (subprocess-heavy) tests
live under `tests/services`, and `tests/integration` runs in `rest` (self-skipping
unless `PRAXIS_E2E=1`). The tag-time release gate in `publish.yml` runs the full
suite in a single job as a comprehensive backstop.

## Local commands

PRA-299 retired the dev container, so the production image no longer carries
pytest. Backend tests run in a Python 3.14 virtualenv against a throwaway
Postgres — exactly the way the CI `backend-test` lanes run them, and on the same
Python line as the shipped 3.14 backend runtime (PRA-319). One-time setup
(from `backend/`):

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && pip install -e . && pip install pytest
# a disposable Postgres on localhost:5432 (mirrors the CI service container)
docker run -d --name praxis-test-db -p 5432:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=praxis \
  postgres:15-alpine
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/praxis
export SECRET_KEY=dev-test-secret ENVIRONMENT=testing
alembic upgrade head
```

Then drive pytest directly (same commands the CI lanes run):

```sh
pytest                              # full suite — CI-equivalent (all lanes)
pytest tests/services              # the `services` lane
pytest tests/api                   # the `api` lane
pytest tests --ignore=tests/services --ignore=tests/api   # the `rest` lane
pytest -m "not slow" tests/api     # fast: API surface only, slow excluded
pytest --collect-only -q           # what would run
pytest -v tests/api/test_auth.py   # -v to debug one file
```

If a local run disagrees with green CI, drop the throwaway DB and recreate it
(`docker rm -f praxis-test-db`, then repeat the setup) to clear stale schema/seed.

Default output is quiet (`-q -rfE --tb=short --disable-warnings` in `pytest.ini`):
a progress char per test, short tracebacks, and an end-of-run recap of only
failures/errors. Pass/skip/warning counts still print on the summary line. Pass
`-v` to restore per-test names, or `-W default` to restore the warnings dump, when
debugging.

## Database / test-state model

- Tests **never** touch the dev `praxis` DB. `tests/conftest.py` resolves
  `TEST_DATABASE_URL` (or swaps `DATABASE_URL`'s db name to its `_test` sibling)
  and **assigns** `DATABASE_URL` to it, overriding the dev container's exported
  value (PRA-170).
- `praxis_test` is auto-created if missing and migrated to `head` once per pytest
  session. Its **schema persists** between runs; **data is isolated per test** via
  an outer-transaction SAVEPOINT rollback (`db` fixture), so residual rows do not
  leak across tests.
- CI starts from an empty postgres service each run, so local and CI differ only
  in persistence. If a local run disagrees with green CI, the usual cause is stale
  local schema/seed after a branch switch — drop and recreate the throwaway test
  Postgres (`docker rm -f praxis-test-db`, then repeat the setup above).
- `mock_vault` (autouse via the `client` fixture) keeps unit tests off real Vault;
  the entitlement registry defaults to enterprise so paid routes exercise real
  behavior (entitlement-gate tests opt back into free mode explicitly).
