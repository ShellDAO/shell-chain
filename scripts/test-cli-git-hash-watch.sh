#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

rustc "$SCRIPT_DIR/../crates/cli/build.rs" -o "$TMP_DIR/cli-build-script"

REPO="$TMP_DIR/repository"
git init -q -b main "$REPO"
git -C "$REPO" config user.name "ShellDAO Release Test"
git -C "$REPO" config user.email "release-test@shelldao.org"
touch "$REPO/tracked"
git -C "$REPO" add tracked
git -C "$REPO" commit -qm "fixture"

check_watch_paths() {
    local checkout=$1
    local output head_path head_ref ref_path
    output=$(cd "$checkout" && "$TMP_DIR/cli-build-script")
    head_path=$(git -C "$checkout" rev-parse --git-path HEAD)
    grep -Fxq "cargo:rerun-if-changed=$head_path" <<<"$output"

    head_ref=$(git -C "$checkout" symbolic-ref -q HEAD)
    ref_path=$(git -C "$checkout" rev-parse --git-path "$head_ref")
    grep -Fxq "cargo:rerun-if-changed=$ref_path" <<<"$output"
}

check_watch_paths "$REPO"

WORKTREE="$TMP_DIR/linked-worktree"
git -C "$REPO" worktree add -qb linked "$WORKTREE"
check_watch_paths "$WORKTREE"

echo "CLI git hash watch tests passed"
