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

"$SCRIPT_DIR/check-release-metadata.sh"

if ! grep -Fq 'cargo audit --file tools/tx-generator/Cargo.lock' "$SCRIPT_DIR/release.sh"; then
    fail "release audit does not cover the transaction generator lockfile"
fi
if ! grep -Fq 'cargo audit --file deps/libp2p-yamux/Cargo.lock' "$SCRIPT_DIR/release.sh"; then
    fail "release audit does not cover the patched libp2p-yamux lockfile"
fi

make_fixture() {
    local changelog=$1
    local fixture="$TMP_DIR/fixture"

    rm -rf "$fixture"
    mkdir -p "$fixture/scripts"
    cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/check-release-metadata.sh" \
        "$SCRIPT_DIR/supply-chain-tool-versions.sh" "$fixture/scripts/"
    printf '[workspace.package]\nversion = "0.27.1"\n' > "$fixture/Cargo.toml"
    mkdir -p "$fixture/fuzz"
    printf '[package]\nname = "shell-fuzz"\nversion = "0.27.1"\n' > "$fixture/fuzz/Cargo.toml"
    printf '| v0.27.x | supported |\n| < v0.27.0 | end of life |\n\n**v0.27.x is the current supported release line.** v0.27.x receives security-only backports. Users older than v0.27.0 should upgrade.\n' > "$fixture/SECURITY.md"
    printf 'https://img.shields.io/badge/version-0.27.1-green.svg\n' > "$fixture/README.md"
    printf 'FROM example.invalid/base\n# ghcr.io/shelldao/shell-chain:v0.27.1\n' > "$fixture/Dockerfile"
    printf '%s\n' "$changelog" > "$fixture/CHANGELOG.md"
    git -C "$fixture" init -q -b main
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

assert_metadata_fails_with() {
    local fixture=$1
    local expected=$2
    local output

    if output=$("$fixture/scripts/check-release-metadata.sh" "$fixture" 2>&1); then
        fail "release metadata check unexpectedly passed"
    fi
    if ! grep -Fq "$expected" <<<"$output"; then
        fail "expected '$expected' in metadata output: $output"
    fi
}

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - test release')
assert_fails_with "$fixture" '0x27x1' "Version must be semver"

printf '| v0.24.x | stale support claim |\n' >> "$fixture/SECURITY.md"
assert_metadata_fails_with "$fixture" "exactly one supported release row (found 2)"

sed -i.bak 's/v0.27.x/v0.24.x/g' "$fixture/SECURITY.md"
rm "$fixture/SECURITY.md.bak"
git -C "$fixture" add SECURITY.md
git -C "$fixture" commit -qm "stale security policy"
assert_fails_with "$fixture" '0.27.1' "Public release metadata is stale"

touch "$fixture/untracked-release-input"
assert_fails_with "$fixture" '0.27.1' "uncommitted or untracked files"

fixture=$(make_fixture $'## [Unreleased]\n\n[0.27.1]: https://example.invalid/release')
assert_fails_with "$fixture" '0.27.1' "exactly one ## [0.27.1] release heading (found 0)"

fixture=$(make_fixture '## [0.27.1] - test release')
assert_fails_with "$fixture" '0.27.1' "exactly one ## [Unreleased] heading (found 0)"

fixture=$(make_fixture $'## [Unreleased]\n\n## [Unreleased]\n\n## [0.27.1] - test release')
assert_fails_with "$fixture" '0.27.1' "exactly one ## [Unreleased] heading (found 2)"

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - first\n\n## [0.27.1] - duplicate')
assert_fails_with "$fixture" '0.27.1' "exactly one ## [0.27.1] release heading (found 2)"

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - test release')
git -C "$fixture" switch -qc topic/release
assert_fails_with "$fixture" '0.27.1' "must run from 'main' or 'release/v0.27.1'"

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - test release')
git -C "$fixture" checkout -q --detach
assert_fails_with "$fixture" '0.27.1' "must run from 'main' or 'release/v0.27.1'"

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - test release')
git -C "$fixture" switch -qc release/v0.27.1
assert_fails_with "$fixture" '0.27.1' "cargo fmt check failed"

fixture=$(make_fixture $'## [Unreleased]\n\n## [0.27.1] - test release')
git -C "$fixture" switch -q --orphan release/v0.27.1
mkdir -p "$fixture/scripts"
cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/supply-chain-tool-versions.sh" "$fixture/scripts/"
printf '[workspace.package]\nversion = "0.27.1"\n' > "$fixture/Cargo.toml"
printf '## [Unreleased]\n\n## [0.27.1] - test release\n' > "$fixture/CHANGELOG.md"
git -C "$fixture" add .
git -C "$fixture" commit -qm "unrelated release history"
assert_fails_with "$fixture" '0.27.1' "must descend from 'main'"

echo "release preflight tests passed"
