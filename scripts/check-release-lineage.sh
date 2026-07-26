#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "release lineage check failed: $1" >&2
    exit 1
}

REMOTE="${1:-origin}"
COMMIT="${2:-HEAD}"

if ! REMOTE_MAIN_OUTPUT=$(git ls-remote --exit-code --heads "$REMOTE" refs/heads/main); then
    fail "could not resolve current main from remote '$REMOTE'"
fi

REMOTE_MAIN=$(awk '
    $2 == "refs/heads/main" && $1 ~ /^[0-9a-f]{40}$/ {
        print $1
        count++
    }
    END {
        if (count != 1) exit 1
    }
' <<<"$REMOTE_MAIN_OUTPUT") || fail "remote '$REMOTE' returned an invalid main reference"

if ! git cat-file -e "${REMOTE_MAIN}^{commit}" 2>/dev/null; then
    if ! git fetch --quiet --no-tags "$REMOTE" "$REMOTE_MAIN"; then
        fail "could not fetch current main commit ${REMOTE_MAIN}"
    fi
fi

if ! git merge-base --is-ancestor "$REMOTE_MAIN" "$COMMIT"; then
    fail "release commit does not descend from current '$REMOTE/main' (${REMOTE_MAIN})"
fi

echo "release commit descends from current '$REMOTE/main' (${REMOTE_MAIN})"
