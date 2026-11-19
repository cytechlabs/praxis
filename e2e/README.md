# Browser suite

Playwright specs that run against a running, production-shaped stack. They are
not part of pull request CI; run them yourself when a flow they cover or the
ingress topology changes.

## Prerequisites

1. A stack reachable through the Caddy ingress, brought up from the production
   compose files with `--profile bundled --profile proxy`. Use a disposable
   project (`COMPOSE_PROJECT_NAME`, its own env file, alternate host port) so the
   suite never touches an operator's data.
2. The bootstrap administrator credentials of that stack.
3. The synthetic demo fleet, seeded once per stack (idempotent, secret-free):

   ```sh
   e2e/fixtures/seed-demo.sh
   ```

   See the header of that script for the compose variables it honours. The
   `fixtures` project checks for the fleet and names this command when it is
   missing.
4. `npm ci` at the repository root, then `npx playwright install chromium`.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_BASE_URL` | `https://localhost` | Browser origin (the Caddy ingress). |
| `PRAXIS_API_BASE` | `$E2E_BASE_URL/api/backend` | API origin, if different. |
| `E2E_USERNAME` | `praxisadmin` | Bootstrap administrator. |
| `E2E_PASSWORD` | none, required | Bootstrap administrator password. |
| `E2E_EDITION` | `free` | `free` or `paid`; must match the stack (checked by a test). |

## Running

```sh
E2E_BASE_URL=https://localhost:18443 E2E_PASSWORD=... npm run test:e2e
```

Projects: `setup` (sign in), `fixtures` (fleet check), `chromium` (specs that
create their own disposable data), `chromium-fixtures` (specs that read the
seeded fleet), and `unit` (pure logic, no stack needed:
`npx playwright test --project=unit`).

## Authentication and the login limiter

The login endpoint allows five attempts a minute and the limiter is not
relaxed for tests. The suite signs in once in `setup`, saves the session to
`test-results/.auth/user.json` (reused on later runs while it is valid), and
every spec uses that session. The only specs that submit the login form are the
two in `smoke.spec.ts` that test login itself. Do not add specs that sign in.

## Edition matrix

| Case | free (`E2E_EDITION=free`) | paid (`E2E_EDITION=paid`) |
| --- | --- | --- |
| Locked "Export evidence (Pro)" control | runs | skipped, not rendered when licensed |
| Evidence export links and filter hrefs | skipped, needs the entitlement | runs |
| Edition matches `E2E_EDITION` | runs | runs |
| Everything else | runs | runs |

The paid cases need a stack running with a legitimate test licence that grants
`compliance.bulk_exports`. There is no bypass: without a licence they are
reported as skipped with that reason.

## Real-host qualification (unavailable evidence)

The browser suite does not reach a real managed host. Coverage of unavailable
compliance evidence on a real host is a separate owned procedure:

```sh
NETWORK=<project>_backend_net e2e/fixtures/qualify-unavailable-evidence.sh
```

It starts a disposable Ubuntu sshd container on the stack's backend network
and checks, against that host: a host with no stored facts returns the readable
reason `no_host_facts_row` with a `runner_executed` row; a real probe passes;
with sshd stopped the probe returns `ssh_transport_failure` (still
`runner_executed`); after sshd restarts it returns a real pass. It then removes
only the resources this invocation created (everything carries a per-run id, so
overlapping runs and existing rows are untouched), verifies they are gone, and
prints the pass line only after that. It needs the Ubuntu 24.04 distro row that ships with the product and never creates or deletes shared rows. Absence is accepted only as a Vault 404 or a "no such container"; an unavailable or denying service or Docker daemon fails the run. Each step requires exactly one evidence
row per expected check. `--selftest` (no stack needed) shows the verification
rejects empty, missing, duplicate, extra and mismatched results, and
`QUAL_TAMPER=empty|missing|duplicate` damages live evidence on purpose to show
a real run fails. The script needs
network access to install `openssh-server` in the container.

Not covered by it: recovery of stored-facts evidence after a real facts
collection, and any run on lab hosts. Those remain pending real-host
qualification.

## Artifacts

Traces and failure screenshots go to `test-results/run/`, screenshots to
`test-results/help-screenshots/` and the report to `playwright-report/`, all
ignored by git. Nothing is written to the tracked bundled help tree.

## Teardown

Specs delete the data they create (onboarding credential, mirror, decoy patch
plan) and assert in `afterAll` that each delete succeeded and the record is
gone. The seeded fleet is removed by discarding the disposable stack
(`docker compose down -v`). Starter-pack policies seeded by the compliance spec
are idempotent product data and are not removed.
