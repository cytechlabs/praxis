# Contributing to Praxis

Thanks for your interest in contributing to Praxis. This document explains how to
propose changes, the sign-off we require, and the checks your change needs to
pass.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** Please follow the
responsible-disclosure process in [SECURITY.md](SECURITY.md) instead.

## Developer Certificate of Origin (DCO), not a CLA

Praxis uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) rather than a Contributor License Agreement (CLA). The DCO is a lightweight
statement that you have the right to submit your contribution under the project's
license. There is nothing to sign up for and no separate agreement to send.

To certify a contribution, add a `Signed-off-by` trailer to every commit:

```
Signed-off-by: Jane Developer <jane@example.com>
```

The name and email must match the commit author. Git can add the trailer for you:

```bash
git commit -s -m "Your commit message"
```

If you forget, amend the most recent commit:

```bash
git commit --amend -s --no-edit
```

For a branch of several commits, rebase and sign off each one:

```bash
git rebase --signoff main
```

Sign-off is required and is checked automatically on pull requests. By adding the
`Signed-off-by` trailer you are certifying the statements in the DCO for that
contribution. Contributions are accepted under the project's
[Apache License 2.0](LICENSE).

## Branch and pull-request model

- **`main`** is the CI-gated integration branch for the next release. Base normal
  work on `main` and open your pull request against `main`. `main` must stay
  CI-green and releasable.
- Frozen **`release/X.Y`** branches are cut from `main` at ship time and only
  receive cherry-picked backport fixes; those backports also open PRs against the
  relevant `release/**` branch (CI runs there too).
- See [docs/contributors/branching-model.md](docs/contributors/branching-model.md) for the full model.
- Keep pull requests focused. Smaller, single-purpose changes are easier to
  review and land faster.
- Write a clear description of what changed and why. Reference any related issue.

## Local checks

Please run the relevant checks before opening a pull request. They mirror what
Continuous Integration runs, so passing locally means fewer round trips.

**Backend (Python)** - from `backend/`:

```bash
black .                 # format
isort --profile black --settings-path setup.cfg .   # import order
pylint app              # lint
pytest                  # tests
```

Run these from a Python virtualenv (see `backend/tests/README.md` for the
one-time venv + throwaway-Postgres setup that mirrors CI). `black`, `isort`, and
`pylint` match the CI Backend Lint / Pylint lanes; `pytest` matches the
Backend Test lanes.

**Frontend (TypeScript / Next.js)** - from `frontend-next/`:

```bash
npx next lint --dir src
npx tsc --noEmit
```

**Agent (Go)** - from `agent/`:

```bash
gofmt -l .              # should print nothing
go vet ./...
go test ./...
```

Continuous Integration additionally builds the container images and runs a
container vulnerability scan; you do not need to reproduce those locally, but be
aware a change that breaks the image build or introduces a critical CVE will fail
CI.

## Style expectations

- Match the style of the surrounding code: naming, comment density, and idioms.
- Keep public-facing documentation accurate and free of internal or private
  details.
- Add or update tests for behavior you change.

## License of contributions

Unless you state otherwise, contributions you submit are provided under the
[Apache License 2.0](LICENSE), consistent with your DCO sign-off. The public core
of Praxis is Apache-2.0; any optional enterprise extensions are distributed
separately under their own terms and are not part of this repository.
