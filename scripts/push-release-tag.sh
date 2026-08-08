#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "release tag push failed: $1" >&2
    exit 1
}

REMOTE="${1:-}"
TAG="${2:-}"
RELEASE_COMMIT="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$REMOTE" ]; then
    fail "expected a release remote"
fi
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    fail "expected a semver tag with a leading 'v'"
fi
if [[ ! "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    fail "expected a full 40-character release commit SHA"
fi

if ! "$SCRIPT_DIR/check-release-remote.sh" "$REMOTE" >/dev/null; then
    fail "release remote is not canonical"
fi
if ! "$SCRIPT_DIR/check-release-lineage.sh" "$REMOTE" "$RELEASE_COMMIT" >/dev/null; then
    fail "release commit is stale relative to canonical main"
fi

TAG_REF="refs/tags/${TAG}"
if ! TAG_OBJECT=$(git rev-parse --verify "$TAG_REF"); then
    fail "tag '${TAG}' does not exist locally"
fi
if [ "$(git cat-file -t "$TAG_OBJECT")" != "tag" ]; then
    fail "tag '${TAG}' must be annotated"
fi
if ! TAG_COMMIT=$(git rev-parse --verify "${TAG_OBJECT}^{commit}"); then
    fail "tag '${TAG}' does not resolve to a commit"
fi
if [ "$TAG_COMMIT" != "$RELEASE_COMMIT" ]; then
    fail "tag '${TAG}' does not point to the validated release commit"
fi

if ! git push "$REMOTE" "${TAG_OBJECT}:${TAG_REF}"; then
    fail "remote tag state changed after release validation"
fi

echo "pushed ${TAG} from validated release commit ${RELEASE_COMMIT}"
