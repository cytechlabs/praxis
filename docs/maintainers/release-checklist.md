# 1.0 Release runbook and verification checklist

This is the step-by-step runbook for cutting a Praxis release, written so that
someone other than the implementer can follow it from a release candidate
through to a published, verified release. It records which checks are enforced
automatically and which are **manual gates** an operator must run.

The application and its container images share one version and are released
under the `vX.Y.Z` tag. The fleet agent is released separately under the
matching `agent-vX.Y.Z` tag. For 1.0 that is app tag **`v1.0.0`** and agent tag
**`agent-v1.0.0`**.

> Context: several release-verification paths (production overlay, end-to-end,
> upgrade, backup/restore) are exercised only by manual scripts, not by blocking
> CI. They are captured here as explicit gates rather than left implicit.

The runbook is ordered. Do not skip ahead — later steps assume earlier gates
passed.

For a patch in an existing supported minor line, first follow the
[patch release runbook](patch-release.md). It defines the `main`-first fix,
backport branch, release-line PR, and version-bump workflow. Return here for the
pre-tag gates, tag order, publication, and post-publish verification.

---

## 0. What runs automatically (context, no action)

These run in CI and gate merges / publishes; keep them green.

- **PR / push CI** (`.github/workflows/ci.yml`): backend `black`/`isort`/
  `pylint` + `pytest`, frontend `eslint` + `tsc`, agent `gofmt`/`vet`/
  `golangci-lint`/`go test` + cross-compile, dev image builds, and the **Trivy
  CRITICAL** gate + CycloneDX SBOM + SARIF artifacts on the prod images. Runs on
  PRs to `main` and `release/**` and on pushes to `main` and `release/**` (see
  [branching-model.md](../contributors/branching-model.md)).
- **Publish gate** (`.github/workflows/publish.yml`): three jobs, in order.
  `verify` resolves the release inputs, runs `check-release-readiness.sh`, and
  re-runs backend migrations + tests and frontend lint/type-check against the
  exact tagged ref. `build` then builds both production images, runs the Trivy
  CRITICAL gate against them, generates their SBOMs, and assembles a validation
  release index. Both hold read-only tokens and cannot push. Only `publish`
  holds write, package, OIDC, and attestation permissions, and it runs only for
  a `vX.Y.Z` tag on `cytechlabs/praxis`.
- **Runtime healthchecks**: backend and frontend prod images
  carry `HEALTHCHECK` instructions, and `docker-compose.prod.yml` declares
  matching healthchecks, so a hung app service is detected by `docker compose
  ps` and restart policies.

### Repository settings (operator-owned, outside version control)

These cannot be fully enforced by workflow files alone. Confirm in GitHub
settings before relying on the release line:

- **Branch protection on `main`**: require a pull request and a passing CI
  check before merge; disallow direct pushes that bypass review.
- **Branch protection on each `release/X.Y` line**: mirror `main`'s PR, CI,
  conversation-resolution, linear-history, force-push, and deletion policy.
- **Tag protection**: restrict who can create `v*.*.*` and `agent-v*` tags so a
  release can only be cut from a verified commit.
- **Package visibility and Actions access**: each GHCR package is configured
  individually, once, in the GitHub UI after its first publish. Repository
  visibility does not propagate to packages. See
  [docs/maintainers/ghcr-release-operations.md](ghcr-release-operations.md).

---

## 1. Pre-tag state checks

Confirm the commit you intend to tag is release-ready.

- [ ] You are on the exact commit you intend to release: the newly frozen
      `release/X.Y` commit for a minor/major release, or the merged patch commit
      on the existing `release/X.Y` line. `git status` is clean.
- [ ] CI is **green** on that commit (the same ref you will tag).
- [ ] `CHANGELOG.md` has an entry for this version, grouped by capability area,
      with the known-limitations list current.
- [ ] `docs/upgrade-notes-1-0.md` (or the version-specific upgrade notes) is
      current for this release.
- [ ] No unreviewed unrelated changes are in the working tree.

```sh
git status
git log -1 --oneline
git diff --check        # no whitespace/conflict errors
```

## 2. Local dry-run checks (manual gates)

Run these against the release candidate before tagging. None publish artifacts;
they are verification only.

1. **Cold-rebuild gate** — `scripts/test-cold-rebuild.sh`. Tears the stack down
   (`down -v`), rebuilds from scratch, reconciles seeded sequences, and runs the
   curated end-to-end suite, including the 1.0-hardening remediation tests. This
   is the authoritative "survives a clean rebuild" gate.
2. **Production overlay fresh install** — bring up the prod overlay and confirm
   `docker compose ps` reports backend and frontend `healthy`:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --profile bundled --profile proxy up -d --build
   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     --profile bundled --profile proxy ps
   ```

3. **End-to-end (Playwright)** — run `e2e/smoke.spec.ts` against the running
   prod-proxy stack (started above with `--profile proxy`). Playwright defaults
   its browser base URL to Caddy at `https://localhost` and accepts the internal
   self-signed cert (`ignoreHTTPSErrors`); override with `E2E_BASE_URL` for a real
   TLS host:

   ```sh
   npx playwright test e2e/smoke.spec.ts
   # against a real domain:
   E2E_BASE_URL=https://praxis.example.com npx playwright test e2e/smoke.spec.ts
   ```
4. **Upgrade path** — start from the previous release images, then
   `alembic upgrade head` on the new backend image; confirm migrations apply
   cleanly and the app boots. (`scripts/test-upgrade-smoke.sh`.)
   For a patch, test the immediately preceding supported patch (for example,
   `1.0.0 -> 1.0.1`). For a minor, test the newest supported patch in the prior
   minor line (for example, `1.0.latest -> 1.1.0`).
5. **Backup / restore** — exercise `scripts/backup.sh` and the documented
   restore procedure (see `backend/docs/database-backup-restore.md`); confirm a
   restored database boots the app. (`scripts/test-backup-restore-smoke.sh`.)
6. **SBOM + Trivy review** — review the CycloneDX SBOMs and Trivy reports
   attached to the build; confirm no unaccepted CRITICAL/HIGH findings.
7. **Lifecycle / EOL seed refresh** — after pull/build/migrations on an existing
   database, reconcile the lifecycle reference data and confirm it is already
   current:

   ```sh
   docker compose exec -T backend python -m app.scripts.update_eol_data
   # Then confirm nothing else is pending:
   docker compose exec -T backend python -m app.scripts.update_eol_data --dry-run
   #   -> summary should report "0 new, 0 pruned"
   ```

   (A fresh database already loads the seed via the Alembic migration; this gate
   catches an existing DB whose lifecycle rows drifted from the shipped seed.)
8. **Demo proof path** — seed the synthetic demo fixture and run the
   demo walkthrough end to end as a release-confidence smoke:

   ```sh
   docker compose exec -T backend python -m app.scripts.seed_demo_fixture
   npx playwright test e2e/demo-walkthrough.spec.ts
   ```

   Confirm the walkthrough passes (it asserts stable headings **and** the seeded
   demo data) and that the captured screenshots under
   `test-results/demo-walkthrough/` reflect the final UI — three supported demo
   hosts, an approved plan with a succeeded execution, a compliance finding, and
   a remediation request. See
   [docs/demo-walkthrough-operator.md](../demo-walkthrough-operator.md) and
   [docs/demo-walkthrough-auditor.md](../demo-walkthrough-auditor.md) for the full
   operator and auditor stories.

## 3. Version alignment

Package metadata versions must match the tag you are about to cut. For a
`vX.Y.Z` release all three should read `X.Y.Z`:

- [ ] `package.json` (root) → `X.Y.Z`
- [ ] `frontend-next/package.json` → `X.Y.Z`
- [ ] `frontend-next/package-lock.json` → `X.Y.Z`
- [ ] `backend/setup.py` → `X.Y.Z`

- [ ] `agent/VERSION` → `X.Y.Z`
- [ ] `_DEFAULT_RELEASE_VERSION` in
      `backend/app/api/routes/agent_bootstrap.py` → `vX.Y.Z`

`agent/VERSION` is the agent's source of truth: artifact names and the binary's
embedded version both derive from it, and the release workflow refuses a tag
that disagrees with it. The backend carries a mirror because its image does not
ship the agent source tree. See [docs/maintainers/agent-release.md](agent-release.md) for
the full list of places a version bump touches.

`scripts/check-release-readiness.sh` verifies this alignment; see step 8.

For a minor or major release, align these values in a focused release-preparation
PR to `main`, then create `release/X.Y` from that verified merge commit. For a
patch, keep the original fix PR version-neutral and align them in the backport
PR to the existing `release/X.Y` branch, as described in
[patch-release.md](patch-release.md).

## 4. Tag plan

Two tags per release, both cut from the same verified commit. **The agent tag
goes first**, because the application's release index is the whole-product
record and requires the agent release to already exist:

1. **Agent release:** `agent-vX.Y.Z` (e.g. `agent-v1.0.0`).
   - Triggers `agent-release.yml`: builds the per-arch tarballs reproducibly
     with the Go toolchain pinned by `agent/GO_VERSION`, generates a per-arch
     agent SBOM and checksums, signs `checksums.txt` with keyless cosign, and
     attaches the seven assets to the Release.
   - Verify it (step 8) before continuing.
2. **App / container release:** `vX.Y.Z` (e.g. `v1.0.0`).
   - Triggers `publish.yml`: builds and gates the backend/frontend images once,
     promotes those exact images to GHCR, and attaches the SBOMs and release
     index to the GitHub Release.
   - It requires `agent-vX.Y.Z` to be published and fails deliberately if it is
     not, rather than recording the agent as outstanding.
   - It also resolves `agent-vX.Y.Z` to the commit it names (peeling annotated
     tags) and refuses to publish unless that is the same commit as `vX.Y.Z`.
     Cutting both tags from one commit is enforced, not just procedure.

> Do not create these tags until every check above has passed. Tag protection
> (step 0) should restrict who can push them.

Before pushing either tag, run both release workflows once via
`workflow_dispatch` with `dry_run` left checked:

- **Publish** builds both production images, archives them, runs the
  release-time Trivy CRITICAL gate against those archives, generates both SBOMs,
  and assembles a validation release index, without pushing an image, creating a
  release, or minting an attestation. The output is the
  `release-validation-<X.Y.Z>` run artifact.
- **Agent Release** builds and verifies the agent artifacts without publishing,
  signing, or contacting Sigstore. See [docs/maintainers/agent-release.md](agent-release.md).

- [ ] Publish dry run passed; the validation index names the expected version
      and commit.
- [ ] Agent release dry run passed.

## 5. Publish workflow verification

After pushing the `vX.Y.Z` tag (which follows the agent tag, per step 4):

- [ ] `publish.yml` ran for the tag.
- [ ] The `verify` job (release readiness + migrations + backend tests +
      frontend lint/type-check against the tagged ref) **passed**.
- [ ] The `build` job (single image build + archive + Trivy CRITICAL gate +
      SBOMs + validation index) **passed** before `publish` started.
- [ ] The `publish` job promoted the archived images without rebuilding, and
      completed without error, including both provenance and both SBOM
      attestations.

After pushing the `agent-vX.Y.Z` tag:

- [ ] `agent-release.yml` ran and completed for the tag.
- [ ] The `build` job's reproducibility step passed (it builds the release
      twice and compares checksums).
- [ ] The `publish` job ran only after the tag/`agent/VERSION` match, the
      upstream-repository check, and the no-existing-release check all passed.

## 6. GHCR image tag / digest verification

Full operator guide, including the one-time GitHub settings and every
verification command: [docs/maintainers/ghcr-release-operations.md](ghcr-release-operations.md).

Confirm the published images exist and match the release record:

```sh
docker pull ghcr.io/cytechlabs/praxis-backend:X.Y.Z
docker pull ghcr.io/cytechlabs/praxis-frontend:X.Y.Z
docker buildx imagetools inspect ghcr.io/cytechlabs/praxis-backend:X.Y.Z
docker buildx imagetools inspect ghcr.io/cytechlabs/praxis-frontend:X.Y.Z
```

- [ ] Both `X.Y.Z` image tags are present in GHCR.
- [ ] The digests match the ones recorded in `release-index.json` on the Release.
- [ ] For a stable release, the `X.Y` and `latest` tags also point at this
      release's digests.
- [ ] Package visibility is **Public** (GitHub → Packages → package settings)
      if the images are meant to be publicly pullable, and an anonymous
      `docker pull` succeeds after `docker logout ghcr.io`.

## 7. Supply-chain artifact review

The publish workflow attaches `release-index.json` (the machine-readable release
record) and generates the release body from it. It names the source commit,
every shipped component, both image digests, the SBOM files, the agent artifact
checksums, and the security gates that ran.

```sh
gh release download vX.Y.Z --pattern release-index.json
jq -r '.source.commit, (.components[] | "\(.name) \(.digest // "n/a")")' release-index.json

gh attestation verify oci://ghcr.io/cytechlabs/praxis-backend@sha256:<digest> \
    --repo cytechlabs/praxis
```

- [ ] `release-index.json` names the commit that was tagged and both image
      digests from step 6.
- [ ] The CycloneDX 1.6 SBOMs `sbom-backend-X.Y.Z.cdx.json` and
      `sbom-frontend-X.Y.Z.cdx.json` are attached to the GitHub Release, and
      each one's `metadata.component.name` is the digest reference it describes.
- [ ] `gh attestation verify` succeeds for both image digests (build provenance
      and SBOM attestation, keyless via GitHub OIDC).
- [ ] The Trivy CRITICAL gate passed in the `build` job for this ref (no
      unaccepted CRITICAL CVEs).
- [ ] SARIF reports for HIGH-and-below were reviewed from the `security-reports`
      build artifact on the corresponding CI run; any accepted findings are
      noted in the release record.

## 8. Agent artifact checksum + cosign verification

Download the agent artifacts from the Release and verify them exactly as an end
user would (see [agent/packaging/README.md](../../agent/packaging/README.md)):

```sh
cosign verify-blob \
    --certificate checksums.txt.pem \
    --signature   checksums.txt.sig \
    --certificate-identity-regexp '^https://github.com/cytechlabs/praxis/.github/workflows/agent-release.yml@refs/tags/agent-v.*$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    checksums.txt
sha256sum -c checksums.txt
```

- [ ] `cosign verify-blob` succeeds and the certificate identity matches the
      `cytechlabs/praxis` agent-release workflow.
- [ ] `sha256sum -c checksums.txt` reports OK for both tarballs and both SBOMs.
- [ ] The seven artifacts (two tarballs, two per-arch
      `praxis-agent-vX.Y.Z-linux-<arch>-sbom.cdx.json`, `checksums.txt`,
      `.sig`, `.pem`) are attached to the Release.
- [ ] The downloaded binary reports the released version:
      `praxis-agent version --json` shows `"version": "vX.Y.Z"`, the full
      40-character `"commit"` of the tagged ref, and `"stamped": true`.
- [ ] Install, update, rollback, and uninstall were exercised against a test
      host per [agent/packaging/README.md](../../agent/packaging/README.md).
      `scripts/test-agent-release-smoke.sh` covers the same lifecycle in a
      container and is the cheaper pre-tag gate.

### Optional pre-tag readiness helper

`scripts/check-release-readiness.sh` is a read-only local check that verifies
package-version alignment, the presence of the required release docs and
workflows, and clean whitespace. It does **not** tag, push, publish, or mutate
anything. Run it before step 4:

```sh
scripts/check-release-readiness.sh            # checks against root package.json version
scripts/check-release-readiness.sh 1.0.0      # or assert an explicit target version
```

## 9. Post-publish smoke with `PRAXIS_VERSION`

Deploy the *published* images (not a local build) and confirm they run. Release
deploys MUST pin an exact `PRAXIS_VERSION` — the compose default is the unpinned
`:latest`, which must never be used for a release (an accidental `latest` deploy
tracks whatever GHCR most recently published, not the version under test). Add
`--profile proxy` for the public browser ingress:

```sh
export PRAXIS_VERSION=X.Y.Z   # exact tag — never leave unset (would be :latest)
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy ps
```

- [ ] `PRAXIS_VERSION` is set to the exact release tag (not `latest`); the
      pulled images carry the digests recorded in step 6.
- [ ] Backend and frontend report `healthy`.
- [ ] A basic login + fleet-dashboard smoke passes.
- [ ] `UVICORN_WORKERS=1` (the supported posture while interactive SSH sessions
      are enabled).

## 10. Known limitations and upgrade notes review

- [ ] `CHANGELOG.md` known-limitations section is accurate for what shipped.
- [ ] `docs/upgrade-notes-1-0.md` matches the actual upgrade steps and rollback
      guidance.
- [ ] The release notes (from `docs/maintainers/release-notes-template.md`) link the upgrade
      notes and carry the known-limitations summary.

---

## Notes

- The cold-rebuild test list is curated per-PRA at closeout; adding each new
  remediation's test files to `scripts/test-cold-rebuild.sh` is part of "green
  gate."
- Making the prod-overlay / E2E / upgrade / backup-restore smokes blocking CI
  jobs (e.g. a Playwright lane) is a reasonable post-1.0 enhancement; until then
  they are explicit manual gates per this document.
