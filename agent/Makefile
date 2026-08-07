# Praxis thin agent — task #1 tooling skeleton.
#
# All targets are intentionally simple shell + go invocations so they
# work both from a host with Go installed and from agent/Dockerfile.dev.

BINARY      := praxis-agent
PKG         := ./cmd/praxis-agent
DIST        := dist
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS     := -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
GOFLAGS     := -trimpath -ldflags "$(LDFLAGS)"

.PHONY: help build build-all package release checksums test lint fmt vet tidy clean

help:
	@echo "praxis-agent targets:"
	@echo "  build       compile for the host platform into $(DIST)/$(BINARY)"
	@echo "  build-all   cross-compile linux/amd64 + linux/arm64 into $(DIST)/"
	@echo "  package     build-all + assemble per-arch tarballs in $(DIST)/"
	@echo "  checksums   write $(DIST)/checksums.txt over the tarballs"
	@echo "  release     build-all + package + checksums (signing happens in CI)"
	@echo "  test        go test ./..."
	@echo "  lint        golangci-lint run"
	@echo "  fmt         gofmt -w + goimports -w"
	@echo "  vet         go vet ./..."
	@echo "  tidy        go mod tidy (verifies go.mod is clean)"
	@echo "  clean       remove $(DIST)/"

build:
	@mkdir -p $(DIST)
	go build $(GOFLAGS) -o $(DIST)/$(BINARY) $(PKG)

build-all:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(DIST)/$(BINARY)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(DIST)/$(BINARY)-linux-arm64 $(PKG)

# package assembles per-arch tarballs containing:
#   <stem>/praxis-agent
#   <stem>/install.sh
#   <stem>/praxis-agent.service
#   <stem>/README.md
#   <stem>/LICENSE
# where <stem> is praxis-agent-<version>-linux-<arch>. Operators
# extract and run install.sh.
package: build-all
	@set -e; \
	for arch in amd64 arm64; do \
		stem=$(BINARY)-$(VERSION)-linux-$$arch; \
		stage=$(DIST)/$$stem; \
		rm -rf $$stage; \
		mkdir -p $$stage; \
		install -m 0755 $(DIST)/$(BINARY)-linux-$$arch $$stage/$(BINARY); \
		install -m 0755 packaging/install.sh             $$stage/install.sh; \
		install -m 0644 packaging/praxis-agent.service   $$stage/praxis-agent.service; \
		install -m 0644 packaging/README.md              $$stage/README.md; \
		install -m 0644 ../LICENSE                       $$stage/LICENSE 2>/dev/null || \
		install -m 0644 LICENSE                          $$stage/LICENSE 2>/dev/null || true; \
		tar -C $(DIST) -czf $(DIST)/$$stem.tar.gz $$stem; \
		echo "packaged $(DIST)/$$stem.tar.gz"; \
	done

# checksums emits sha256sums in BSD format that `sha256sum -c` reads.
# Path-stripped so verification works from inside dist/.
checksums:
	@set -e; \
	cd $(DIST) && \
	rm -f checksums.txt && \
	for f in $(BINARY)-$(VERSION)-linux-*.tar.gz; do \
		sha256sum $$f >> checksums.txt; \
	done && \
	echo "wrote $(DIST)/checksums.txt"

release: package checksums

test:
	go test ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w . || true

vet:
	go vet ./...

tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum >/dev/null 2>&1 || \
		(echo "go.mod / go.sum changed after 'go mod tidy' — commit the result" && exit 1)

clean:
	rm -rf $(DIST)
