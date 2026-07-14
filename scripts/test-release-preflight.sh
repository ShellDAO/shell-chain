#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
    echo "release preflight test failed: $1" >&2
    exit 1
}

make_fixture() {
    local changelog=$1
    local fixture="$TMP_DIR/fixture"

    rm -rf "$fixture"
    mkdir -p "$fixture/scripts"
    cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/supply-chain-tool-versions.sh" "$fixture/scripts/"
    printf '[workspace.package]\nversion = "0.27.1"\n' > "$fixture/Cargo.toml"
    printf '%s\n' "$changelog" > "$fixture/CHANGELOG.md"
    git -C "$fixture" init -q
    git -C "$fixture" config user.name "ShellDAO Release Test"
    git -C "$fixture" config user.email "release-test@shelldao.org"
    git -C "$fixture" add .
    git -C "$fixture" commit -qm "test fixture"
    printf '%s\n' "$fixture"
}

assert_fails_with() {
    local fixture=$1
    local version=$2
    local expected=$3
    local output

    if output=$(cd "$fixture" && ./scripts/release.sh "$version" 2>&1); then
        fail "release unexpectedly passed for version $version"
    fi
    if ! grep -Fq "$expected" <<<"$output"; then
        fail "expected '$expected' in output: $output"
    fi
}

fixture=$(make_fixture '## [0.27.1] - test release')
assert_fails_with "$fixture" '0x27x1' "Version must be semver"

touch "$fixture/untracked-release-input"
assert_fails_with "$fixture" '0.27.1' "uncommitted or untracked files"

fixture=$(make_fixture '[0.27.1]: https://example.invalid/release')
assert_fails_with "$fixture" '0.27.1' "does not contain a ## [0.27.1] release heading"

echo "release preflight tests passed"
