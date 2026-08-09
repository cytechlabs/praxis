#!/usr/bin/env bash
# Confirm a tag points at an expected source commit, and fail closed when that
# cannot be established.
#
# A release that ships several tags cut from "the same commit" only holds that
# property if something checks it. Version numbers do not: a tag carrying the
# right version can have been cut from an older commit, moved afterwards, or
# created by hand, and the resulting release record would claim one source
# commit for artifacts built from two.
#
# The tag is resolved to the commit it actually names, which takes two steps for
# an annotated tag: the ref points at a tag object, and the tag object points at
# the commit. A lightweight tag points at the commit directly. Both are
# supported; anything else is refused rather than guessed at.
#
# A release's `target_commitish` is deliberately not used. It records the branch
# or commit a release was created against, is mutable, and can disagree with
# what the tag resolves to.
#
# Usage:
#   check-tag-commit.sh <owner/repo> <tag> <expected-commit-sha>
#
# Exit status:
#   0  the tag resolves to the expected commit
#   1  it does not, or the tag could not be resolved

set -euo pipefail

API_NOT_FOUND_PATTERN='HTTP 404'
COMMIT_PATTERN='^[0-9a-f]{40}$'

CAPTURED_OUTPUT=''
CAPTURED_STATUS=0

abort() {
    printf 'check-tag-commit: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'usage: %s <owner/repo> <tag> <expected-commit-sha>\n' "${0##*/}" >&2
    exit 1
}

capture() {
    set +e
    CAPTURED_OUTPUT="$("$@" 2>&1)"
    CAPTURED_STATUS=$?
    set -e
}

# Resolve the tag to the commit it names, peeling an annotated tag object.
resolve_tag_commit() {
    local repository="$1" tag="$2"

    capture gh api "repos/${repository}/git/ref/tags/${tag}" \
        --jq '.object.sha + " " + .object.type'

    if [ "${CAPTURED_STATUS}" -ne 0 ]; then
        if printf '%s' "${CAPTURED_OUTPUT}" | grep -Eq "${API_NOT_FOUND_PATTERN}"; then
            abort "tag ${tag} does not exist"
        fi
        printf '%s\n' "${CAPTURED_OUTPUT}" >&2
        abort "could not resolve tag ${tag}"
    fi

    local sha object_type
    sha="$(printf '%s' "${CAPTURED_OUTPUT}" | awk 'NR==1 {print $1}')"
    object_type="$(printf '%s' "${CAPTURED_OUTPUT}" | awk 'NR==1 {print $2}')"

    if ! printf '%s' "${sha}" | grep -Eq "${COMMIT_PATTERN}"; then
        abort "tag ${tag} resolved to a malformed object id"
    fi

    case "${object_type}" in
        commit)
            # Lightweight tag: the ref names the commit itself.
            ;;
        tag)
            # Annotated tag: the ref names a tag object that names the commit.
            capture gh api "repos/${repository}/git/tags/${sha}" --jq '.object.sha'
            if [ "${CAPTURED_STATUS}" -ne 0 ]; then
                printf '%s\n' "${CAPTURED_OUTPUT}" >&2
                abort "could not peel annotated tag ${tag}"
            fi
            sha="$(printf '%s' "${CAPTURED_OUTPUT}" | awk 'NR==1 {print $1}')"
            if ! printf '%s' "${sha}" | grep -Eq "${COMMIT_PATTERN}"; then
                abort "annotated tag ${tag} peeled to a malformed commit id"
            fi
            ;;
        *)
            abort "tag ${tag} names an unsupported object type '${object_type}'"
            ;;
    esac

    printf '%s' "${sha}"
}

main() {
    [ "$#" -eq 3 ] || usage

    local repository="$1" tag="$2" expected="$3"

    command -v gh >/dev/null 2>&1 || abort "gh is not installed; cannot resolve ${tag}"

    if ! printf '%s' "${expected}" | grep -Eq "${COMMIT_PATTERN}"; then
        abort "expected commit '${expected}' is not a full 40 character sha"
    fi

    local actual
    actual="$(resolve_tag_commit "${repository}" "${tag}")"

    if [ "${actual}" != "${expected}" ]; then
        printf 'check-tag-commit: %s\n' "tag ${tag} points at ${actual}" >&2
        abort "tag ${tag} was not cut from ${expected}; refusing to publish"
    fi

    printf 'check-tag-commit: %s resolves to %s\n' "${tag}" "${actual}"
}

main "$@"
