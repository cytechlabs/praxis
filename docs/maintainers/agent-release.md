# Cutting a fleet agent release

The fleet agent is released independently of the application images: it is a
static Go binary distributed as a signed tarball, not a container. This is
the maintainer procedure for building, verifying, and publishing one.

Operator-facing install, update, rollback, and uninstall steps live in
[agent/packaging/README.md](../../agent/packaging/README.md). The whole-release
runbook, including the application images, is
[docs/maintainers/release-checklist.md](release-checklist.md).

## The version source of truth

`agent/VERSION` holds a bare `X.Y.Z` and is the only place the agent's
version is decided. Everything else derives from it or is checked against
it:

| Location | Role | Checked by |
|---|---|---|
| `agent/VERSION` | source of truth | - |
| artifact names, `-X main.Version`, SBOM primary component | derived at build time | `agent/Makefile` |
| the `agent-vX.Y.Z` tag | publication trigger | `make verify-version` |
| `_DEFAULT_RELEASE_VERSION` in `backend/app/api/routes/agent_bootstrap.py` | version the control plane serves | `test_pra389_agent_release_contract.py` |
| `_RELEASE_VERSION` in the agent download tests | deliberate tripwire | the tests themselves |

The backend keeps a mirror rather than reading `agent/VERSION` because the
backend image is built from `backend/` alone and does not contain the agent
source tree.

## The Go toolchain pin

`agent/GO_VERSION` holds the exact Go patch release, and it is a build input
in the same sense the source is: a different patch release produces a
different binary from identical source. Declaring only `go 1.26` in `go.mod`
would let any later 1.26.x silently change published artifacts, so nothing in
the release path resolves the toolchain from `go.mod`.

| Consumer | How it uses the pin |
|---|---|
| `agent/Makefile` | exports `GOTOOLCHAIN=go<version>`, so the go command uses exactly that toolchain rather than whatever is installed |
| `agent/Dockerfile.dev` | `ARG GO_VERSION` selects the tag, and the base is additionally pinned to the image index digest |
| `.github/workflows/agent-release.yml` | passes it to `setup-go` and then asserts `go env GOVERSION` matches |
| `.github/workflows/ci.yml` (`agent-build`) | same pin, so the PR lane builds with the toolchain that ships |

The release contract tests fail if any of these drift apart. Bumping Go means
editing `agent/GO_VERSION` and the digest in `agent/Dockerfile.dev` together;
resolve the new digest with:

```sh
docker buildx imagetools inspect golang:<version>-alpine
```

Use the top-level `Digest:` value, which is the multi-architecture index, not
one of the per-platform manifest digests listed under it.

## The tag convention

Agent releases are tagged `agent-vX.Y.Z`. Application releases are tagged
`vX.Y.Z`. Both are cut from the same commit and share one `X.Y.Z`.

The `agent-` prefix is deliberate on two counts. It keeps
`.github/workflows/agent-release.yml` from firing on an application tag, and
it stays clear of Go's submodule tag namespace (`agent/vX.Y.Z`), which would
advertise the agent module as independently importable at that version.

Changing this prefix is a breaking change: the cosign certificate identity
that operators verify against is pinned to
`refs/tags/agent-v.*`, and it appears in the packaged README, the release
notes template, and the release checklist.

## Reproducible builds

Release artifacts are reproducible. Building the same commit with the same
Go toolchain produces byte-identical tarballs, so a third party can confirm
the published artifact came from the published source.

That relies on five things, all in `agent/Makefile`:

- the exact Go toolchain from `agent/GO_VERSION`, enforced with
  `GOTOOLCHAIN`.
- `-trimpath` keeps absolute build paths out of the binary.
- `-buildvcs=false` keeps the linker from stamping working-tree state; the
  commit is injected explicitly with `-X main.Commit`, in full.
- archive metadata (member order, owner, mode, mtime) is pinned, with mtimes
  taken from the source commit rather than the current clock.
- `gzip -n` drops the filename and timestamp from the gzip header.

No wall-clock build time is embedded anywhere. The binary's identity is its
version, full commit SHA, toolchain, and target platform, all readable with
`praxis-agent version --json`.

The commit is stamped in full rather than abbreviated: how many characters
git needs to disambiguate a short hash depends on how many objects the
repository holds, so rebuilding an old commit after the repository grows
could otherwise pick a different abbreviation and produce a different binary.

One caveat worth knowing before you promise bit-for-bit reproduction to
someone: each SBOM records the hash of the `cyclonedx-gomod` binary that
generated it, and that binary is compiled locally by `go install`. The SBOMs
are reproducible for a fixed builder image plus pinned tool version, which is
a weaker guarantee than the tarballs carry.

## Dry run

Every change to the agent build or release path should be dry-run first.
Nothing below publishes, signs, tags, or contacts Sigstore.

Locally, in the dev container (which carries GNU tar and the pinned SBOM
tool):

```sh
docker build -f agent/Dockerfile.dev -t praxis-agent-dev agent
docker run --rm -v "$(pwd):/src" -w /src/agent praxis-agent-dev \
    sh -c 'git config --global --add safe.directory /src && make verify-repro'
```

`make verify-repro` builds the full release twice and fails if any artifact
checksum differs. To inspect the artifacts instead of just the verdict:

```sh
make release          # both tarballs, both SBOMs, and checksums.txt in dist/
cd dist && sha256sum -c checksums.txt
tar -tvzf praxis-agent-v*-linux-amd64.tar.gz
```

`make release` runs `verify-sbom`, which parses each generated SBOM and fails
if the primary component does not report the release version, the expected
CycloneDX spec version, or the architecture the file is named for. There is
one SBOM per published binary, because the dependency set is resolved per
`GOOS`/`GOARCH` and a single module-level SBOM would not describe either
tarball accurately.

To exercise the operator lifecycle against real tarballs, run:

```sh
scripts/test-agent-release-smoke.sh
```

It builds two releases in a disposable container and walks clean install,
update, rollback, uninstall, and purge, asserting that identity material
survives everything except `--purge`. Nothing is installed on the machine
running it.

In CI, run the **Agent Release** workflow with `workflow_dispatch` and leave
`dry_run` checked. The build job runs with a read-only token, verifies
reproducibility and checksums, confirms the binary reports the expected
version, and uploads the assets as a workflow artifact. The publish job does
not run.

## Publishing

1. Confirm the application release gates in
   [docs/maintainers/release-checklist.md](release-checklist.md) have passed. The agent
   tag is cut from the same verified commit as the application tag.
2. Confirm `agent/VERSION` is the version you intend to publish and that
   `scripts/check-release-readiness.sh` passes.
3. Run the dry run above and read its output.
4. Push the tag:

   ```sh
   git tag agent-v<X.Y.Z> <commit>
   git push origin agent-v<X.Y.Z>
   ```

   Tag creation should be restricted by tag protection; see the repository
   settings section of the release checklist.

The workflow then refuses to continue unless the tag matches `agent/VERSION`,
the ref is a tag matching `agent-v*`, the repository is `cytechlabs/praxis`,
and no release already exists for that tag. Only after those checks does it
sign `checksums.txt` with keyless cosign and create the GitHub Release.

Re-running against an already published tag fails on purpose: replacing
assets that end users may already have verified is not something a rerun
should do quietly. Republishing means deleting the release deliberately
first.

## After publishing

Verify the published artifacts exactly as an operator would, using the
commands in [agent/packaging/README.md](../../agent/packaging/README.md). The
workflow runs `cosign verify-blob` against its own output before creating
the release, but that proves the signature was well-formed at build time,
not that the right bytes reached the Release page.

## Advancing the version the control plane serves

The control plane hands hosts an agent tarball from a pinned release. That
pin does not move on its own. To advance it:

1. Edit `agent/VERSION` to the new `X.Y.Z`.
2. Edit `_DEFAULT_RELEASE_VERSION` in
   `backend/app/api/routes/agent_bootstrap.py` to the matching `vX.Y.Z`.
3. Edit `_RELEASE_VERSION` in `backend/tests/api/test_agent_bootstrap_routes.py`
   and `backend/tests/api/test_pra374_agent_artifact_redirects.py`, and the
   asset name in `backend/tests/api/test_pra154_bootstrap_e2e.py`. These are
   hand-mirrored so a version bump has to be acknowledged in the tests.
4. Run the backend agent download tests and
   `scripts/check-release-readiness.sh`.

An individual deployment can pin a different published release without a
rebuild by setting `PRAXIS_AGENT_RELEASE_VERSION` to an exact `vX.Y.Z`.
Moving references such as `latest` are rejected: hosts verify a checksum
against whatever the control plane serves, so the served artifact must not
change underneath them.

For airgapped installs, drop the release assets into
`PRAXIS_AGENT_ARTIFACT_DIR` (default `/opt/praxis/agent-artifacts`) using
their published filenames. The local directory is preferred over the
network path.

## Withdrawing a bad release

There is no recall channel; hosts that already installed a bad agent keep
running it until an operator updates them.

1. Do not delete the tag or the release if anyone may have installed it.
   Removing published artifacts breaks the verification instructions people
   were given.
2. Publish a fixed `X.Y.Z+1` and advance the control plane pin as above.
3. Tell operators to update, and to roll back to the last good tarball if
   they cannot update immediately.
