# Praxis thin agent build and release tooling.
#
# All targets are plain shell + go invocations so they work both from a
# host with Go installed and from agent/Dockerfile.dev.
#
# Release builds are reproducible: identical source at the same commit,
# built with the same Go toolchain, produces byte-identical artifacts.
# That is achieved by trimming absolute paths out of the binary, pinning
# archive metadata to the commit timestamp rather than the current clock,
# and dropping the gzip header timestamp. Verify with `make verify-repro`.

BINARY      := praxis-agent
PKG         := ./cmd/praxis-agent
DIST        := dist

# agent/VERSION is the single source of truth for the released agent
# version. Artifacts and the `agent-v<version>` release tag both derive
# from it; nothing else may define the version independently.
VERSION_FILE := VERSION
VERSION      ?= v$(shell tr -d '[:space:]' < $(VERSION_FILE) 2>/dev/null)

# The full 40-character commit SHA, never an abbreviation: how many
# characters git needs to disambiguate a short hash depends on how many
# objects the local repository holds, so an abbreviation is not a stable
# identifier and would change the binary for the same source.
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# An unreadable version file would otherwise produce artifacts named for an
# empty version instead of failing.
ifeq ($(strip $(VERSION)),v)
$(error $(VERSION_FILE) is missing or empty)
endif

# agent/GO_VERSION pins the exact Go patch release used to build published
# artifacts. The Go toolchain version is a build input: a different patch
# release produces a different binary from identical source. GOTOOLCHAIN
# makes the go command use exactly this toolchain rather than whatever
# happens to be installed, fetching it if necessary.
GO_VERSION_FILE := GO_VERSION
GO_VERSION      ?= $(shell tr -d '[:space:]' < $(GO_VERSION_FILE) 2>/dev/null)

ifeq ($(strip $(GO_VERSION)),)
$(error $(GO_VERSION_FILE) is missing or empty)
endif

export GOTOOLCHAIN := go$(GO_VERSION)

# Archive timestamps come from the source commit, never from the current
# clock, so rebuilding an old commit reproduces its artifacts. The 0
# fallback keeps builds outside a git checkout deterministic too.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

# -buildvcs=false keeps the linker from stamping VCS status into the
# binary: the commit is already injected explicitly below, and the
# stamped "dirty" bit would vary with unrelated working-tree state.
LDFLAGS    := -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
BUILDFLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

# Static, dependency-free binaries. Set explicitly rather than relying on
# cross-compilation implicitly disabling cgo, so host builds match too.
export CGO_ENABLED := 0

# GNU tar >= 1.28 flags that remove every source of archive nondeterminism:
# member order, owner/group names, and mtimes. gzip -n additionally drops
# the filename and timestamp from the gzip header.
TAR_REPRO := --sort=name --format=gnu --numeric-owner --owner=0 --group=0 \
             --mtime=@$(SOURCE_DATE_EPOCH)

SBOM_TOOL_VERSION := v1.10.0
# CycloneDX 1.5 matches the spec version the application image SBOMs use.
SBOM_SPEC_VERSION := 1.5

ARCHES := amd64 arm64

# One SBOM per published artifact. The dependency set is resolved per
# GOOS/GOARCH, so a single module-level SBOM would not describe either
# tarball accurately.
SBOM_FILES := $(foreach arch,$(ARCHES),$(BINARY)-$(VERSION)-linux-$(arch)-sbom.cdx.json)

.PHONY: help build build-all package release checksums sbom verify-sbom \
        verify-version verify-repro test lint fmt vet tidy clean

help:
	@echo "praxis-agent targets:"
	@echo "  build          compile for the host platform into $(DIST)/$(BINARY)"
	@echo "  build-all      cross-compile linux/amd64 + linux/arm64 into $(DIST)/"
	@echo "  package        build-all + assemble per-arch tarballs in $(DIST)/"
	@echo "  checksums      write $(DIST)/checksums.txt over the release artifacts"
	@echo "  sbom           write a CycloneDX SBOM per released binary"
	@echo "  verify-sbom    check each SBOM reports the release version"
	@echo "  release        package + sbom + verify-sbom + checksums (signing happens in CI)"
	@echo "  verify-version check TAG=agent-vX.Y.Z matches $(VERSION_FILE)"
	@echo "  verify-repro   build the release twice and compare checksums"
	@echo "  test           go test ./..."
	@echo "  lint           golangci-lint run"
	@echo "  fmt            gofmt -w + goimports -w"
	@echo "  vet            go vet ./..."
	@echo "  tidy           go mod tidy (verifies go.mod is clean)"
	@echo "  clean          remove $(DIST)/"
	@echo ""
	@echo "current version: $(VERSION) (commit $(COMMIT), go $(GO_VERSION))"

build:
	@install -d -m 0755 $(DIST)
	go build $(BUILDFLAGS) -o $(DIST)/$(BINARY) $(PKG)

build-all:
	@install -d -m 0755 $(DIST)
	@set -e; \
	for arch in $(ARCHES); do \
		GOOS=linux GOARCH=$$arch \
			go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-linux-$$arch $(PKG); \
	done

# package assembles per-arch tarballs containing:
#   <stem>/praxis-agent
#   <stem>/install.sh
#   <stem>/uninstall.sh
#   <stem>/praxis-agent.service
#   <stem>/README.md
#   <stem>/LICENSE
# where <stem> is praxis-agent-<version>-linux-<arch>. Operators extract
# and run install.sh.
#
# Every member gets an explicit mode and the staging directory is created
# with an explicit mode, so the archive does not inherit the builder's
# umask. A missing LICENSE is a hard failure rather than a silently
# smaller tarball.
package: build-all
	@set -e; \
	for arch in $(ARCHES); do \
		stem=$(BINARY)-$(VERSION)-linux-$$arch; \
		stage=$(DIST)/$$stem; \
		rm -rf $$stage; \
		install -d -m 0755 $$stage; \
		install -m 0755 $(DIST)/$(BINARY)-linux-$$arch  $$stage/$(BINARY); \
		install -m 0755 packaging/install.sh            $$stage/install.sh; \
		install -m 0755 packaging/uninstall.sh          $$stage/uninstall.sh; \
		install -m 0644 packaging/praxis-agent.service  $$stage/praxis-agent.service; \
		install -m 0644 packaging/README.md             $$stage/README.md; \
		install -m 0644 ../LICENSE                      $$stage/LICENSE; \
		tar $(TAR_REPRO) -C $(DIST) -cf - $$stem | gzip -n -9 > $(DIST)/$$stem.tar.gz; \
		rm -rf $$stage; \
		echo "packaged $(DIST)/$$stem.tar.gz"; \
	done

# sbom emits one CycloneDX SBOM per released binary, describing the exact
# artifact that ships. -version stamps the primary component with the
# release version from $(VERSION_FILE) so the binary, the tarball name, the
# release tag, and the SBOM all agree; without it the generator falls back
# to a Go pseudo-version derived from git history. -noserial and
# -notimestamp remove the two fields that would otherwise change on every
# run, so the SBOM is reproducible for a given commit and tool version.
sbom: build-all
	@set -e; \
	tool="$$(command -v cyclonedx-gomod 2>/dev/null || true)"; \
	if [ -z "$$tool" ]; then \
		go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(SBOM_TOOL_VERSION); \
		tool="$$(go env GOPATH)/bin/cyclonedx-gomod"; \
	fi; \
	for arch in $(ARCHES); do \
		out=$(DIST)/$(BINARY)-$(VERSION)-linux-$$arch-sbom.cdx.json; \
		GOOS=linux GOARCH=$$arch "$$tool" bin \
			-json -licenses -noserial -notimestamp \
			-output-version $(SBOM_SPEC_VERSION) \
			-version $(VERSION) \
			-output $$out \
			$(DIST)/$(BINARY)-linux-$$arch; \
		echo "wrote $$out"; \
	done

# verify-sbom parses each generated SBOM and fails if the primary component
# does not carry the release version. Run as part of `release` so a
# generator change cannot silently ship an SBOM that disagrees with the
# artifact it describes.
verify-sbom:
	@set -e; \
	for arch in $(ARCHES); do \
		python3 scripts/verify_sbom.py \
			--sbom $(DIST)/$(BINARY)-$(VERSION)-linux-$$arch-sbom.cdx.json \
			--version $(VERSION) \
			--spec-version $(SBOM_SPEC_VERSION) \
			--goarch $$arch; \
	done

# checksums emits sha256sums that `sha256sum -c` reads, covering the
# tarballs and the SBOM. Path-stripped so verification works from inside
# dist/, and sorted so the file itself is reproducible.
checksums:
	@set -e; \
	cd $(DIST) && \
	rm -f checksums.txt && \
	ls $(BINARY)-$(VERSION)-linux-*.tar.gz $(SBOM_FILES) | LC_ALL=C sort | \
		xargs sha256sum > checksums.txt && \
	echo "wrote $(DIST)/checksums.txt"

release: package sbom verify-sbom checksums

# verify-version refuses a release whose tag disagrees with VERSION.
# The tag is the publication trigger; VERSION is the source of truth. If
# they diverge the artifacts would be named for one version and released
# under another.
verify-version:
	@set -e; \
	if [ -z "$(TAG)" ]; then \
		echo "verify-version: pass TAG=agent-vX.Y.Z" >&2; exit 2; \
	fi; \
	expected="agent-$(VERSION)"; \
	if [ "$(TAG)" != "$$expected" ]; then \
		echo "tag $(TAG) does not match $(VERSION_FILE) (expected $$expected)" >&2; \
		exit 1; \
	fi; \
	echo "tag $(TAG) matches $(VERSION_FILE)"

# verify-repro builds the full release twice from the same source and
# compares the resulting checksums. Any nondeterminism in the compiler
# flags, archive metadata, or SBOM generation shows up as a mismatch.
verify-repro:
	@set -e; \
	first=$$(mktemp); \
	trap 'rm -f "$$first"' EXIT INT TERM; \
	$(MAKE) clean >/dev/null; \
	$(MAKE) release >/dev/null; \
	cp $(DIST)/checksums.txt "$$first"; \
	$(MAKE) clean >/dev/null; \
	$(MAKE) release >/dev/null; \
	if diff -u "$$first" $(DIST)/checksums.txt; then \
		echo "reproducible: both builds produced identical checksums"; \
	else \
		echo "NOT reproducible: checksums differ between builds" >&2; \
		exit 1; \
	fi

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
