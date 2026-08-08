#!/usr/bin/env bash
# Confirm a release artifact does not exist yet, and fail closed when that
# cannot be established.
#
# Publication must never replace something a consumer may already have pulled
# and verified, so "does this already exist?" has to be answered
# authoritatively. A command that fails because of an expired token, a rate
# limit, a network fault, a missing tool, or a registry outage says nothing
# about existence. Treating that silence as "absent" is exactly how an
# existing release gets overwritten, so only an authoritative not-found answer
# allows publication to continue. Every other outcome stops it, including an
# unexpected success from a command that should have failed.
#
# Usage:
#   check-release-absence.sh release <owner/repo> <tag>
#   check-release-absence.sh image   <registry/owner/package:tag>
#
# Exit status:
#   0  the artifact is confirmed absent; publication may proceed
#   1  the artifact exists, or its existence could not be determined
#
# Both modes are read-only. Nothing here creates, deletes, or modifies a
# release, package, or image.

set -euo pipefail

# The registry answers with one of these when it can read a repository but the
# requested reference is not in it. That is the only answer that means "free to
# publish". Notably absent: the 403 the registry returns for a repository it
# will not describe at all, which is indistinguishable from a token problem and
# is therefore not an answer.
NOT_FOUND_PATTERN=': not found|MANIFEST_UNKNOWN|manifest unknown|NAME_UNKNOWN|name unknown'

# The GitHub CLI reports an authoritative missing resource this way. Any other
# failure, including 401, 403, 5xx, and transport errors, is not a not-found.
API_NOT_FOUND_PATTERN='HTTP 404'

CAPTURED_OUTPUT=''
CAPTURED_STATUS=0

note() { printf 'check-release-absence: %s\n' "$1"; }

abort() {
    printf 'check-release-absence: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'usage: %s release <owner/repo> <tag>\n' "${0##*/}" >&2
    printf '       %s image <registry/owner/package:tag>\n' "${0##*/}" >&2
    exit 1
}

# Run a command and capture its combined output and status without `set -e`
# turning a expected non-zero exit into an early abort.
capture() {
    set +e
    CAPTURED_OUTPUT="$("$@" 2>&1)"
    CAPTURED_STATUS=$?
    set -e
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        abort "$1 is not installed; cannot establish whether $2 already exists"
    fi
}

check_release() {
    local repository="$1" tag="$2"
    require_tool gh "release ${tag}"

    capture gh api "repos/${repository}/releases/tags/${tag}"

    if [ "${CAPTURED_STATUS}" -eq 0 ]; then
        abort "release ${tag} already exists; refusing to overwrite it"
    fi
    if printf '%s' "${CAPTURED_OUTPUT}" | grep -Eq "${API_NOT_FOUND_PATTERN}"; then
        note "no release ${tag} exists"
        return 0
    fi

    printf '%s\n' "${CAPTURED_OUTPUT}" >&2
    abort "could not determine whether release ${tag} exists; refusing to publish"
}

# A package that has never been published cannot be described by the registry
# at all, and the refusal looks like an authorization failure. Ask GitHub
# whether the package exists before deciding what the registry's silence meant.
package_is_unpublished() {
    local owner="$1" package="$2"
    require_tool gh "package ${owner}/${package}"

    capture gh api "/orgs/${owner}/packages/container/${package}"

    if [ "${CAPTURED_STATUS}" -eq 0 ]; then
        return 1
    fi
    if printf '%s' "${CAPTURED_OUTPUT}" | grep -Eq "${API_NOT_FOUND_PATTERN}"; then
        return 0
    fi

    printf '%s\n' "${CAPTURED_OUTPUT}" >&2
    return 1
}

check_image() {
    local reference="$1"
    require_tool docker "image ${reference}"

    case "${reference}" in
        */*/*:*) ;;
        *) abort "expected <registry>/<owner>/<package>:<tag>, got '${reference}'" ;;
    esac

    local without_registry="${reference#*/}"
    local owner="${without_registry%%/*}"
    local package_and_tag="${without_registry#*/}"
    local package="${package_and_tag%%:*}"

    capture docker buildx imagetools inspect "${reference}"

    if [ "${CAPTURED_STATUS}" -eq 0 ]; then
        abort "${reference} already exists; refusing to overwrite it"
    fi
    if printf '%s' "${CAPTURED_OUTPUT}" | grep -Eq "${NOT_FOUND_PATTERN}"; then
        note "no image ${reference} exists"
        return 0
    fi

    local registry_error="${CAPTURED_OUTPUT}"
    if package_is_unpublished "${owner}" "${package}"; then
        note "package ${owner}/${package} has never been published"
        return 0
    fi

    printf '%s\n' "${registry_error}" >&2
    abort "could not determine whether ${reference} exists; refusing to publish"
}

main() {
    [ "$#" -ge 1 ] || usage
    local mode="$1"
    shift

    case "${mode}" in
        release)
            [ "$#" -eq 2 ] || usage
            check_release "$1" "$2"
            ;;
        image)
            [ "$#" -eq 1 ] || usage
            check_image "$1"
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
