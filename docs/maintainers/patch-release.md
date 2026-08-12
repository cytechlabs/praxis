# Patch Release Runbook

Use this procedure for a maintenance release in an existing supported minor
line, such as `1.0.1`. Typical inputs are security fixes, dependency updates,
compatibility fixes, and narrowly scoped bug fixes. New features belong on
`main` for the next minor release unless the maintainers explicitly approve an
exception.

This runbook supplements the full
[release checklist](release-checklist.md). The checklist still governs dry
runs, tag order, publication, artifact verification, and the post-publish
smoke.

## Rules

- Fix `main` first so a correction is not lost from the next release.
- Keep release-version changes out of the original fix PR to `main`.
- Never merge a moving `main` branch into `release/X.Y`.
- Backport only reviewed commits, using `git cherry-pick -x` to record origin.
- Make backports through a short-lived branch and a PR to `release/X.Y`; do not
  push fixes directly to the protected release branch.
- Keep one maintenance branch per minor line. `1.0.1`, `1.0.2`, and later
  patches all ship from `release/1.0`.
- Cut `agent-vX.Y.Z` and `vX.Y.Z` from the same verified release-branch commit,
  with the agent tag first.

## 1. Land the fix on `main`

Create a focused branch from current `main`:

```sh
git switch main
git pull --ff-only
git switch -c security/update-dependency
```

Implement and test the fix. For a vulnerable dependency, update the manifest
and lockfile, confirm the vulnerable version is absent, and run the affected
tests, build, and vulnerability scans. Record the advisory or CVE and the fixed
version in the PR.

Do not bump the Praxis product version in this PR. Commit with DCO sign-off,
open the PR to `main`, and merge only after its required checks pass.

## 2. Create the backport branch

Start from the current maintenance line, not from `main`:

```sh
git switch release/1.0
git pull --ff-only
git switch -c backport/1.0-update-dependency
git cherry-pick -x <main-fix-commit>
```

Prefer the focused or squash commit that represents the fix. Do not cherry-pick
an arbitrary merge commit. If the fix spans several intentional commits,
cherry-pick all of them in dependency order and retain `-x` on each.

Resolve conflicts in favor of the supported `1.0` code line, then rerun the
tests relevant to the backport before preparing the release metadata.

## 3. Prepare the patch version

On the same backport branch, update every synchronized version to the patch
target, for example `1.0.1`:

- root `package.json`
- displayed product version
- `frontend-next/package.json` and `frontend-next/package-lock.json`
- `backend/setup.py`
- `agent/VERSION`
- `_DEFAULT_RELEASE_VERSION` in
  `backend/app/api/routes/agent_bootstrap.py`
- `CHANGELOG.md` and the applicable release/upgrade notes

The agent version changes even when agent source did not. Praxis publishes one
whole-product version, and the application release requires a matching agent
release from the same commit.

Verify alignment:

```sh
scripts/check-release-readiness.sh 1.0.1
git diff --check
```

## 4. Merge into the maintenance line

Push the backport branch and open a PR with base `release/1.0`:

```sh
git push -u origin backport/1.0-update-dependency
gh pr create --base release/1.0 --head backport/1.0-update-dependency
```

The PR should identify:

- the original `main` PR or commit;
- why the fix applies to the `1.0` line;
- any backport conflict or behavioral difference;
- the patch version and changelog changes; and
- the tests and release-readiness checks run.

Merge only after the protected release branch's CI, DCO, analysis, and review
requirements pass.

## 5. Verify and publish

Use the merge result on `release/1.0` as the release commit. Confirm it is clean,
current, and fully green, then execute every applicable pre-tag gate in the
[release checklist](release-checklist.md). For a patch, the upgrade smoke must
exercise the immediately preceding supported release, such as
`1.0.0 -> 1.0.1`.

Run fresh dry runs for both release workflows on the exact release commit. Then
publish in order:

```text
agent-v1.0.1
v1.0.1
```

Verify both tags resolve to the same `release/1.0` commit. Complete the release
checklist, including agent checksums/signature, image digests, CycloneDX SBOMs,
attestations, anonymous pulls, stable aliases, and the post-publish application
smoke.

For a stable patch, `1.0` and `latest` should move to the `1.0.1` image digests;
the immutable `1.0.0` tags must remain unchanged.

## Hotfix exception

If an emergency requires fixing `release/X.Y` first, use the same protected
backport-branch and PR process. After publication, cherry-pick the fix (without
the old-line version bump) back to `main` when it remains applicable. Record the
exception and both commit relationships in the PRs so neither line silently
loses the correction.

## Multiple supported lines

When a fix affects more than one supported minor line, land it on `main` once,
then create a separate backport PR for each affected branch. For example,
backport independently to `release/1.1` and `release/1.0`; do not merge one
release branch into another.
