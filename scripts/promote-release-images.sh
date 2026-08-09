#!/usr/bin/env bash
# Push an already-built image to its registry repository and report the digest
# the registry gave it.
#
# This does not build anything. The image must already exist locally, having
# been built and gated earlier in the release; promotion is the step that makes
# those exact bytes public.
#
# stdout carries exactly one thing: the validated `sha256:` digest. Everything
# else, including `docker push` progress, goes to stderr. That separation is
# load-bearing rather than cosmetic: the caller captures stdout with command
# substitution and writes it to a single-line workflow output, and push progress
# ends its final line with `digest: sha256:... size: ...`, so letting it reach
# stdout would silently corrupt the digest with something that still looks
# digest-shaped.
#
# Usage:
#   promote-release-images.sh <registry/owner/package> <version> <is-stable> [major-minor]
#
# The version tag is always pushed. The moving `<major.minor>` and `latest` tags
# are pushed only for a stable release, so a prerelease can never become what a
# new user pulls by default.
#
# Exit status:
#   0  pushed; the digest is on stdout
#   1  the push failed, or the digest could not be established unambiguously

set -euo pipefail

DIGEST_PATTERN='^sha256:[0-9a-f]{64}$'

abort() {
    printf 'promote-release-images: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'usage: %s <registry/owner/package> <version> <is-stable> [major-minor]\n' \
        "${0##*/}" >&2
    exit 1
}

main() {
    [ "$#" -ge 3 ] || usage

    local repository="$1" version="$2" is_stable="$3" major_minor="${4:-}"
    local primary="${repository}:${version}"

    command -v docker >/dev/null 2>&1 || abort "docker is not installed"

    case "${repository}" in
        */*/*) ;;
        *) abort "expected <registry>/<owner>/<package>, got '${repository}'" ;;
    esac

    # Every command below writes to stderr. Only the final printf uses stdout.
    docker push "${primary}" >&2

    if [ "${is_stable}" = "true" ]; then
        [ -n "${major_minor}" ] || abort "a stable release needs a major.minor tag"
        local moving
        for moving in "${repository}:${major_minor}" "${repository}:latest"; do
            docker tag "${primary}" "${moving}" >&2
            docker push "${moving}" >&2
        done
    fi

    # Ask the daemon what the registry stored rather than parsing push progress,
    # whose format is not a contract.
    local digests count digest
    digests="$(docker image inspect \
        --format '{{range .RepoDigests}}{{println .}}{{end}}' "${primary}" 2>/dev/null \
        | sed -n "s|^${repository}@||p" \
        | sort -u)"

    count="$(printf '%s\n' "${digests}" | grep -c . || true)"
    if [ "${count}" -ne 1 ]; then
        abort "expected exactly one digest for ${repository}, got ${count}: ${digests}"
    fi

    digest="$(printf '%s\n' "${digests}" | grep .)"
    if ! printf '%s' "${digest}" | grep -Eq "${DIGEST_PATTERN}"; then
        abort "push did not yield a usable digest for ${repository}: '${digest}'"
    fi

    printf '%s\n' "${digest}"
}

main "$@"
