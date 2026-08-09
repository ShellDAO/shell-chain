#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "release remote check failed: $1" >&2
    exit 1
}

is_canonical_url() {
    case "$1" in
        https://github.com/ShellDAO/shell-chain | \
        https://github.com/ShellDAO/shell-chain.git | \
        git@github.com:ShellDAO/shell-chain | \
        git@github.com:ShellDAO/shell-chain.git | \
        ssh://git@github.com/ShellDAO/shell-chain | \
        ssh://git@github.com/ShellDAO/shell-chain.git)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

REMOTE="${1:-origin}"
if ! PUSH_URLS=$(git remote get-url --push --all "$REMOTE" 2>/dev/null); then
    fail "remote '$REMOTE' has no push URL"
fi
PUSH_URL_COUNT=$(printf '%s\n' "$PUSH_URLS" | awk 'NF { count++ } END { print count + 0 }')
if [ "$PUSH_URL_COUNT" -ne 1 ]; then
    fail "remote '$REMOTE' must have exactly one push URL (found $PUSH_URL_COUNT)"
fi
if ! is_canonical_url "$PUSH_URLS"; then
    fail "remote '$REMOTE' push URL does not target ShellDAO/shell-chain"
fi

if ! FETCH_URLS=$(git remote get-url --all "$REMOTE" 2>/dev/null); then
    fail "remote '$REMOTE' has no fetch URL"
fi
FETCH_URL_COUNT=$(printf '%s\n' "$FETCH_URLS" | awk 'NF { count++ } END { print count + 0 }')
if [ "$FETCH_URL_COUNT" -ne 1 ]; then
    fail "remote '$REMOTE' must have exactly one fetch URL (found $FETCH_URL_COUNT)"
fi
if ! is_canonical_url "$FETCH_URLS"; then
    fail "remote '$REMOTE' fetch URL does not target ShellDAO/shell-chain"
fi

echo "release remote '$REMOTE' fetches from and pushes to ShellDAO/shell-chain"
