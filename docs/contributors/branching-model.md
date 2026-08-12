# Praxis Branching Model

Praxis uses a **trunk-based** model: one integration branch (`main`) plus frozen
per-release branches (`release/X.Y`). The older GitFlow-style
`feature → dev → main` flow (a permanent `dev` integration branch) has been
retired — it added overhead without meaningful safety for a solo-maintainer
workflow, and a long-lived divergent `dev` confuses PR-diff / security / quality
tooling (DeepSource, Dependabot, and most reviewers assume a single canonical
default branch).

## Branches

| Branch | Role | Lifetime |
|---|---|---|
| **`main`** | The CI-gated integration branch for the **next** release. Always CI-green and releasable. The GitHub default branch. | permanent |
| **`release/X.Y`** | A **frozen** release line cut from `main` at ship time (e.g. `release/1.0`). Receives only cherry-picked backport fixes for its `X.Y` series. | per minor release |
| `feature/…`, `bug/…`, `security/…` | Short-lived work branches off `main`. | until merged |

There is **no long-lived integration branch** other than `main`.

## Day-to-day workflow

1. Branch off `main`: `git switch -c bug/short-title main`.
2. Commit with DCO sign-off (`git commit -s`; see [CONTRIBUTING.md](../../CONTRIBUTING.md)).
3. Open a pull request **to `main`**. CI (`.github/workflows/ci.yml`) and DCO
   (`.github/workflows/dco.yml`) run on the PR.
4. Merge once CI is green. `main` stays releasable at all times.

> **CI note.** Push CI runs only on `main` and `release/**`. Any other branch
> gets CI by opening a pull request to `main` (or to the relevant `release/**`
> branch for a backport). Pushing to an arbitrary branch does **not** trigger CI.

## Cutting a minor or major release

Features and other release scope land on `main` through normal PRs. When the
minor or major release is ready, merge a focused release-preparation PR into
`main` that aligns versions and updates the changelog, upgrade notes, and
release documentation. At ship time, cut a frozen release branch from that
verified `main` commit, protect it, then tag from it. Tags — not branches —
drive the publish/agent-release workflows
(`publish.yml`, `agent-release.yml`), so those are unaffected by this model.

```bash
git switch main && git pull
git switch -c release/1.0 main
git push -u origin release/1.0
# then tag the release commit per docs/maintainers/release-checklist.md (vX.Y.Z, agent-vX.Y.Z)
```

The branch is named for the minor line, not the individual release. A later
`1.0.1` patch still ships from `release/1.0`; a new `1.1.0` release creates
`release/1.1` from its verified `main` commit.

See [release-checklist.md](../maintainers/release-checklist.md) for the full release runbook and
[public-import-checklist.md](../maintainers/public-import-checklist.md) for the public-repo import
(import from the tagged release commit on `main` / the `release/X.Y` branch).

## Patch releases and backports

A fix for a shipped `X.Y` series is developed on `main` first (so `main` never
regresses), then **cherry-picked onto a short-lived backport branch based on
`release/X.Y`**. Release-version changes stay out of the original `main` fix and
are added in the backport PR:

```bash
git switch release/1.0
git pull --ff-only
git switch -c backport/1.0-short-title
git cherry-pick -x <main-fix-commit>
# align versions/changelog to 1.0.1, then open a PR to release/1.0
```

Never merge the moving `main` branch into a frozen release line. After the
backport PR passes and merges, cut `agent-v1.0.1` and then `v1.0.1` from the
same verified `release/1.0` commit.

If a fix is made directly on a `release/**` branch first (hotfix), cherry-pick it
**back to `main`** when it is still relevant so the next release keeps it.

See the [patch release runbook](../maintainers/patch-release.md) for the complete
fix, backport, versioning, publication, and verification procedure.

---

## Cutover checklist (operator / admin)

The repo-owned files above already describe the new model. The following steps
change branch state and GitHub / third-party **settings** and are **not**
performed by the implementation change — do them intentionally, in order, after
the change is reviewed. None are reversible-by-accident, so verify each.

- [ ] **Final `dev → main` merge.** Open a PR from `dev` to `main` (or fast-forward
      if `main` is an ancestor), get CI green, and merge so `main` contains all
      integrated work. `main` is now the source of truth.
- [ ] **GitHub default branch → `main`.** Settings → Branches → default branch.
      (Do this before deleting `dev` so open PRs auto-retarget.)
- [ ] **Branch protection.**
      - `main`: require a pull request + passing CI status checks before merge;
        no direct pushes.
      - `release/**`: protect the release lines (require PR + CI) so backports are
        gated the same way.
- [ ] **Retarget open PRs** that still target `dev` to `main` (GitHub retargets
      most automatically when the default branch changes; confirm each).
- [ ] **DeepSource.** Point the analysis **default/base branch** at `main` and
      re-baseline so previously-known issues are not re-reported as new on PRs.
- [ ] **Dependabot.** It follows the GitHub default branch; after the default is
      `main`, confirm `.github/dependabot.yml` needs no explicit `target-branch`
      (none is set today) and that update PRs open against `main`.
- [ ] **Verify** the new model end to end: open a throwaway PR to `main` and
      confirm CI + DCO run; confirm no automation still expects `dev`.
- [ ] **Delete `dev`** — only after all of the above verify clean.

> Scope note: the public repository transfer to `cytechlabs/praxis` is a separate
> effort and is **not** part of this cutover.
