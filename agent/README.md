# Praxis thin agent

The Go binary that runs on managed Linux hosts and dials the Praxis
agent broker over mTLS WSS. See `docs/agent-protocol.md` for the wire
contract.

## What it does

A single static binary that establishes a long-lived mTLS WebSocket to
the Praxis agent broker and services backend requests over a multiplexed
tunnel: host facts collection, command execution, and file transfer.
Identity is bootstrapped once, then the agent runs as a systemd service.
The agent contains a PTY primitive, but Praxis 1.0 keeps browser
interactive sessions on the SSH transport until user impersonation and
session-governance semantics are wired for agent-backed shells. See
`packaging/README.md` for install and artifact verification.

## Layout

```
agent/
├── cmd/praxis-agent/    process entrypoint
├── internal/            tunnel, identity, facts, exec, file, pty
├── packaging/           install.sh, uninstall.sh, systemd unit, operator README
├── scripts/             release build helpers (SBOM verification)
├── VERSION              released agent version (source of truth)
├── GO_VERSION           exact Go patch release used to build artifacts
├── go.mod               module: github.com/cytechlabs/praxis/agent
├── Makefile             build / release / test / lint helpers
├── Dockerfile.dev       dev image with Go + golangci-lint pinned
└── .golangci.yml        conservative linter set (gofmt, goimports,
                         errcheck, staticcheck, revive)
```

## Local development

With Go 1.26+ on the host:

```sh
cd agent
make build          # binary at dist/praxis-agent
make test           # go test ./...
make lint           # golangci-lint run
make build-all      # cross-compile linux/amd64 + linux/arm64
```

Or via the dev container (matches CI):

```sh
docker build -f agent/Dockerfile.dev -t praxis-agent-dev agent
docker run --rm -v $(pwd)/agent:/agent praxis-agent-dev make lint test build-all
```

## Versioning and releases

`VERSION` holds a bare `X.Y.Z` and is the only place the released version is
decided. Artifact names and the version compiled into the binary both derive
from it, and the release workflow refuses an `agent-vX.Y.Z` tag that
disagrees with it:

```sh
make verify-version TAG=agent-v1.0.0
```

`GO_VERSION` pins the exact Go patch release artifacts are built with. The
Makefile enforces it through `GOTOOLCHAIN`, the dev image and both workflows
consume the same file, and the release contract tests fail if they drift.

`make release` produces both tarballs, a per-arch CycloneDX SBOM, and
`checksums.txt` in `dist/`, then verifies each SBOM reports the release
version. Release builds are reproducible: the same commit built with the same
pinned toolchain yields identical checksums, which `make verify-repro`
asserts by building twice and comparing. Reproducible packaging needs GNU tar,
so run it from the dev container rather than a BusyBox shell.

`praxis-agent version --json` reports the version, full commit SHA,
toolchain, and target platform of an installed binary. No build timestamp is
embedded.

Maintainer procedure: [docs/maintainers/agent-release.md](../docs/maintainers/agent-release.md).
Operator install, update, rollback, and uninstall steps:
[packaging/README.md](packaging/README.md).

## CI

The `agent-build` job in `.github/workflows/ci.yml` runs gofmt diff,
go vet, golangci-lint, go test, and cross-compiles for both target
architectures on every push and PR.

`.github/workflows/agent-release.yml` builds and publishes releases. It runs
on an `agent-v*` tag push, and on `workflow_dispatch` for a non-publishing
dry run.
