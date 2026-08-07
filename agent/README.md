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
├── go.mod               module: github.com/cytechlabs/praxis/agent
├── Makefile             build / test / lint helpers
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

## CI

The `agent-build` job in `.github/workflows/ci.yml` runs gofmt diff,
go vet, golangci-lint, go test, and cross-compiles for both target
architectures on every push and PR.
