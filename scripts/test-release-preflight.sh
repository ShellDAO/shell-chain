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

CODEQL_WORKFLOW="$ROOT_DIR/.github/workflows/codeql.yml"
if [ ! -f "$CODEQL_WORKFLOW" ]; then
    fail "the advanced CodeQL workflow is missing"
fi
for required_entry in \
    "  pull_request:" \
    "  security-events: write" \
    "          - language: actions" \
    "          - language: python" \
    "          - language: rust"; do
    if ! grep -Fqx "$required_entry" "$CODEQL_WORKFLOW"; then
        fail "the advanced CodeQL workflow is missing: $required_entry"
    fi
done
for required_action in \
    "      - uses: github/codeql-action/init@" \
    "      - uses: github/codeql-action/analyze@"; do
    if ! grep -Fq "$required_action" "$CODEQL_WORKFLOW"; then
        fail "the advanced CodeQL workflow is missing: $required_action"
    fi
done
if grep -Eq '^[[:space:]]*pull_request_target:' "$CODEQL_WORKFLOW"; then
    fail "the CodeQL workflow must not execute pull request code with a write token"
fi

"$SCRIPT_DIR/check-release-metadata.sh"
"$SCRIPT_DIR/check-release-lockfile.sh"

if ! grep -Fq 'cargo audit --file tools/tx-generator/Cargo.lock' "$SCRIPT_DIR/release.sh"; then
    fail "release audit does not cover the transaction generator lockfile"
fi
if ! grep -Fq 'cargo audit --file deps/libp2p-yamux/Cargo.lock' "$SCRIPT_DIR/release.sh"; then
    fail "release audit does not cover the patched libp2p-yamux lockfile"
fi
if ! grep -Fq 'check-release-ci.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not verify hosted CI for HEAD"
fi
if ! grep -Fq 'check-release-remote.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not verify the tag push remote"
fi
if ! grep -Fq 'check-release-lockfile.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not verify the workspace lockfile"
fi
if ! grep -Fq 'check-release-lineage.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not verify current canonical main ancestry"
fi
if ! grep -Fq 'check-release-tag.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not verify remote tag availability"
fi
if ! grep -Fq 'check-release-source.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not revalidate the tagged source"
fi
if ! grep -Fq 'git tag -a "$TAG" "$RELEASE_COMMIT"' "$SCRIPT_DIR/release.sh"; then
    fail "release tag is not pinned to the validated commit"
fi
if ! grep -Fq '"$SCRIPT_DIR/build-release-binary.sh"' "$SCRIPT_DIR/release.sh"; then
    fail "release preflight does not build the production binary before tagging"
fi
if ! grep -Fq '"$SCRIPT_DIR/push-release-tag.sh"' "$SCRIPT_DIR/release.sh"; then
    fail "release tag push does not preserve the validated source and main refs"
fi
if ! grep -Fq 'check-release-publication.sh' "$SCRIPT_DIR/release.sh"; then
    fail "release instructions do not verify the published GitHub release"
fi
if grep -Fq 'Run: git push' "$SCRIPT_DIR/release.sh"; then
    fail "deferred release instructions bypass the validated tag push helper"
fi
if ! grep -Fq 'check-release-remote.sh' "$SCRIPT_DIR/push-release-tag.sh"; then
    fail "release tag push does not revalidate the canonical remote"
fi

PUBLICATION_HELPER="$TMP_DIR/publication-helpers"
mkdir -p "$PUBLICATION_HELPER"
cp "$SCRIPT_DIR/check-release-publication.sh" "$PUBLICATION_HELPER/"
cat > "$PUBLICATION_HELPER/check-release-remote.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$PUBLICATION_HELPER/check-release-remote.sh"
FAKE_PUBLICATION_GH="$TMP_DIR/fake-publication-gh"
cat > "$FAKE_PUBLICATION_GH" <<'EOF'
#!/usr/bin/env bash
cat "$RELEASE_FIXTURE"
EOF
chmod +x "$FAKE_PUBLICATION_GH"

PUBLICATION_REMOTE="$TMP_DIR/publication-remote.git"
PUBLICATION_FIXTURE="$TMP_DIR/publication-fixture"
git init -q --bare "$PUBLICATION_REMOTE"
git init -q -b main "$PUBLICATION_FIXTURE"
git -C "$PUBLICATION_FIXTURE" config user.name "ShellDAO Release Test"
git -C "$PUBLICATION_FIXTURE" config user.email "release-test@shelldao.org"
printf 'release\n' > "$PUBLICATION_FIXTURE/history"
git -C "$PUBLICATION_FIXTURE" add history
git -C "$PUBLICATION_FIXTURE" commit -qm "release publication fixture"
git -C "$PUBLICATION_FIXTURE" remote add canonical "$PUBLICATION_REMOTE"
git -C "$PUBLICATION_FIXTURE" push -q -u canonical main
PUBLICATION_COMMIT=$(git -C "$PUBLICATION_FIXTURE" rev-parse HEAD)
git -C "$PUBLICATION_FIXTURE" tag -a v0.27.9 -m "publication fixture"
git -C "$PUBLICATION_FIXTURE" push -q canonical v0.27.9
cat > "$TMP_DIR/release.json" <<'EOF'
{"tag_name":"v0.27.9","draft":false,"published_at":"2026-01-01T00:00:00Z","html_url":"https://github.com/ShellDAO/shell-chain/releases/tag/v0.27.9"}
EOF
(cd "$PUBLICATION_FIXTURE" && GH_BIN="$FAKE_PUBLICATION_GH" \
    RELEASE_FIXTURE="$TMP_DIR/release.json" \
    "$PUBLICATION_HELPER/check-release-publication.sh" \
    canonical v0.27.9 "$PUBLICATION_COMMIT" >/dev/null)
cat > "$TMP_DIR/release.json" <<'EOF'
{"tag_name":"v0.27.9","draft":true,"published_at":null,"html_url":"https://github.com/ShellDAO/shell-chain/releases/tag/v0.27.9"}
EOF
if PUBLICATION_OUTPUT=$(cd "$PUBLICATION_FIXTURE" && \
    GH_BIN="$FAKE_PUBLICATION_GH" RELEASE_FIXTURE="$TMP_DIR/release.json" \
    "$PUBLICATION_HELPER/check-release-publication.sh" \
    canonical v0.27.9 "$PUBLICATION_COMMIT" 2>&1); then
    fail "release publication check unexpectedly accepted a draft"
fi
if ! grep -Fq "release is still a draft" <<<"$PUBLICATION_OUTPUT"; then
    fail "draft release rejection was not specific: $PUBLICATION_OUTPUT"
fi

LOCK_FIXTURE="$TMP_DIR/lock-fixture"
mkdir -p "$LOCK_FIXTURE/src"
printf '[package]\nname = "release-lock-fixture"\nversion = "0.27.1"\nedition = "2021"\n' \
    > "$LOCK_FIXTURE/Cargo.toml"
printf 'fn main() {}\n' > "$LOCK_FIXTURE/src/main.rs"
cargo generate-lockfile --manifest-path "$LOCK_FIXTURE/Cargo.toml"
"$SCRIPT_DIR/check-release-lockfile.sh" "$LOCK_FIXTURE" >/dev/null
mkdir -p "$LOCK_FIXTURE/helper/src"
printf '[package]\nname = "release-lock-helper"\nversion = "0.1.0"\nedition = "2021"\n' \
    > "$LOCK_FIXTURE/helper/Cargo.toml"
printf 'pub fn helper() {}\n' > "$LOCK_FIXTURE/helper/src/lib.rs"
printf '\n[dependencies]\nrelease-lock-helper = { path = "helper" }\n' \
    >> "$LOCK_FIXTURE/Cargo.toml"
if LOCK_OUTPUT=$("$SCRIPT_DIR/check-release-lockfile.sh" "$LOCK_FIXTURE" 2>&1); then
    fail "release lockfile check unexpectedly accepted a stale lockfile"
fi
if ! grep -Fq "Cargo.lock does not match the workspace manifests" <<<"$LOCK_OUTPUT"; then
    fail "stale lockfile rejection was not specific: $LOCK_OUTPUT"
fi

LONG_CHANGELOG="$TMP_DIR/long-changelog.md"
{
    printf '## [Unreleased]\n\n## [0.27.1] - test release\n'
    for line in $(seq 1 35); do
        printf 'release line %s\n' "$line"
    done
    printf '## [0.27.0] - prior release\nprior line\n'
} > "$LONG_CHANGELOG"
CHANGELOG_EXCERPT=$("$SCRIPT_DIR/changelog-excerpt.sh" "$LONG_CHANGELOG" 0.27.1)
if [ "$(printf '%s\n' "$CHANGELOG_EXCERPT" | wc -l | tr -d ' ')" -ne 30 ]; then
    fail "long changelog excerpt was not limited to 30 lines"
fi
if ! grep -Fq 'release line 30' <<<"$CHANGELOG_EXCERPT" \
    || grep -Fq 'release line 31' <<<"$CHANGELOG_EXCERPT"; then
    fail "long changelog excerpt used the wrong section boundary"
fi

REMOTE_FIXTURE="$TMP_DIR/remote-fixture"
git -C "$TMP_DIR" init -q -b main remote-fixture
git -C "$REMOTE_FIXTURE" remote add canonical https://github.com/ShellDAO/shell-chain.git
git -C "$REMOTE_FIXTURE" remote add canonical-ssh git@github.com:ShellDAO/shell-chain.git
git -C "$REMOTE_FIXTURE" remote add fork https://github.com/example/shell-chain.git
git -C "$REMOTE_FIXTURE" remote add split https://github.com/example/shell-chain.git
git -C "$REMOTE_FIXTURE" remote set-url --push split \
    https://github.com/ShellDAO/shell-chain.git
git -C "$REMOTE_FIXTURE" remote add multi https://github.com/ShellDAO/shell-chain.git
git -C "$REMOTE_FIXTURE" remote set-url --add --push multi \
    https://github.com/ShellDAO/shell-chain.git
git -C "$REMOTE_FIXTURE" remote set-url --add --push multi \
    https://github.com/example/shell-chain.git

(cd "$REMOTE_FIXTURE" && "$SCRIPT_DIR/check-release-remote.sh" canonical >/dev/null)
(cd "$REMOTE_FIXTURE" && "$SCRIPT_DIR/check-release-remote.sh" canonical-ssh >/dev/null)
if REMOTE_OUTPUT=$(cd "$REMOTE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-remote.sh" fork 2>&1); then
    fail "release remote check unexpectedly accepted a fork"
fi
if ! grep -Fq "does not target ShellDAO/shell-chain" <<<"$REMOTE_OUTPUT"; then
    fail "fork rejection did not explain the required release target: $REMOTE_OUTPUT"
fi
if REMOTE_OUTPUT=$(cd "$REMOTE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-remote.sh" split 2>&1); then
    fail "release remote check unexpectedly accepted a noncanonical fetch URL"
fi
if ! grep -Fq "fetch URL does not target ShellDAO/shell-chain" <<<"$REMOTE_OUTPUT"; then
    fail "split fetch/push rejection was not specific: $REMOTE_OUTPUT"
fi
if REMOTE_OUTPUT=$(cd "$REMOTE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-remote.sh" multi 2>&1); then
    fail "release remote check unexpectedly accepted multiple push URLs"
fi
if ! grep -Fq "must have exactly one push URL (found 2)" <<<"$REMOTE_OUTPUT"; then
    fail "multiple push URL rejection was not specific: $REMOTE_OUTPUT"
fi
if REMOTE_OUTPUT=$(cd "$REMOTE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-remote.sh" missing 2>&1); then
    fail "release remote check unexpectedly accepted a missing remote"
fi
if ! grep -Fq "has no push URL" <<<"$REMOTE_OUTPUT"; then
    fail "missing push URL rejection was not specific: $REMOTE_OUTPUT"
fi

TAG_REMOTE="$TMP_DIR/tag-remote.git"
TAG_FIXTURE="$TMP_DIR/tag-fixture"
TAG_CHECKOUT="$TMP_DIR/tag-checkout"
PUSH_HELPER_DIR="$TMP_DIR/push-helpers"
mkdir -p "$PUSH_HELPER_DIR"
cp "$SCRIPT_DIR/push-release-tag.sh" "$SCRIPT_DIR/check-release-lineage.sh" \
    "$PUSH_HELPER_DIR/"
cat > "$PUSH_HELPER_DIR/check-release-remote.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$PUSH_HELPER_DIR/check-release-remote.sh"
git init -q --bare "$TAG_REMOTE"
git init -q -b main "$TAG_FIXTURE"
git -C "$TAG_FIXTURE" config user.name "ShellDAO Release Test"
git -C "$TAG_FIXTURE" config user.email "release-test@shelldao.org"
printf 'release\n' > "$TAG_FIXTURE/history"
git -C "$TAG_FIXTURE" add history
git -C "$TAG_FIXTURE" commit -qm "release base"
git -C "$TAG_FIXTURE" remote add canonical "$TAG_REMOTE"
git -C "$TAG_FIXTURE" push -q -u canonical main
git -C "$TAG_REMOTE" symbolic-ref HEAD refs/heads/main
git -C "$TAG_FIXTURE" tag -a v0.27.10 -m "prefix fixture"
git -C "$TAG_FIXTURE" push -q canonical v0.27.10
(cd "$TAG_FIXTURE" && \
    "$SCRIPT_DIR/check-release-tag.sh" canonical v0.27.1 >/dev/null)

PUSH_COMMIT=$(git -C "$TAG_FIXTURE" rev-parse HEAD)
git -C "$TAG_FIXTURE" tag -a v0.27.3 -m "validated release"
(cd "$TAG_FIXTURE" && "$PUSH_HELPER_DIR/push-release-tag.sh" \
    canonical v0.27.3 "$PUSH_COMMIT" >/dev/null)
if [ "$(git --git-dir="$TAG_REMOTE" rev-parse refs/tags/v0.27.3^\{commit\})" \
    != "$PUSH_COMMIT" ]; then
    fail "validated release tag push used the wrong commit"
fi

printf 'advance before confirmation\n' >> "$TAG_FIXTURE/history"
git -C "$TAG_FIXTURE" commit -qam "advance canonical main before confirmation"
git -C "$TAG_FIXTURE" push -q canonical main
git -C "$TAG_FIXTURE" tag -a v0.27.4 "$PUSH_COMMIT" -m "stale release"
if PUSH_OUTPUT=$(cd "$TAG_FIXTURE" && "$PUSH_HELPER_DIR/push-release-tag.sh" \
    canonical v0.27.4 "$PUSH_COMMIT" 2>&1); then
    fail "release tag push unexpectedly accepted changed canonical main"
fi
if ! grep -Fq "release commit is stale relative to canonical main" <<<"$PUSH_OUTPUT"; then
    fail "stale canonical main rejection was not specific: $PUSH_OUTPUT"
fi
if git --git-dir="$TAG_REMOTE" show-ref --verify --quiet refs/tags/v0.27.4; then
    fail "release push published a tag after canonical main changed"
fi

CURRENT_MAIN=$(git -C "$TAG_FIXTURE" rev-parse HEAD)
git -C "$TAG_FIXTURE" tag -a v0.27.5 "$PUSH_COMMIT" -m "wrong release source"
if PUSH_OUTPUT=$(cd "$TAG_FIXTURE" && "$PUSH_HELPER_DIR/push-release-tag.sh" \
    canonical v0.27.5 "$CURRENT_MAIN" 2>&1); then
    fail "release tag push unexpectedly accepted a changed tag target"
fi
if ! grep -Fq "does not point to the validated release commit" <<<"$PUSH_OUTPUT"; then
    fail "changed tag target rejection was not specific: $PUSH_OUTPUT"
fi

git -C "$TAG_FIXTURE" tag -a v0.27.2 -m "local release"
if TAG_OUTPUT=$(cd "$TAG_FIXTURE" && \
    "$SCRIPT_DIR/check-release-tag.sh" canonical v0.27.2 2>&1); then
    fail "release tag check unexpectedly accepted an existing local tag"
fi
if ! grep -Fq "already exists locally" <<<"$TAG_OUTPUT"; then
    fail "existing local tag rejection was not specific: $TAG_OUTPUT"
fi
git -C "$TAG_FIXTURE" tag -a v0.27.1 -m "existing release"
git -C "$TAG_FIXTURE" push -q canonical v0.27.1
git clone -q --no-tags "$TAG_REMOTE" "$TAG_CHECKOUT"
git -C "$TAG_CHECKOUT" config user.name "ShellDAO Release Test"
git -C "$TAG_CHECKOUT" config user.email "release-test@shelldao.org"
if TAG_OUTPUT=$(cd "$TAG_CHECKOUT" && \
    "$SCRIPT_DIR/check-release-tag.sh" origin v0.27.1 2>&1); then
    fail "release tag check unexpectedly accepted an existing remote tag"
fi
if ! grep -Fq "already exists on remote 'origin'" <<<"$TAG_OUTPUT"; then
    fail "existing remote tag rejection was not specific: $TAG_OUTPUT"
fi
git -C "$TAG_CHECKOUT" remote add unavailable "$TMP_DIR/missing-tag-remote.git"
if TAG_OUTPUT=$(cd "$TAG_CHECKOUT" && \
    "$SCRIPT_DIR/check-release-tag.sh" unavailable v0.27.2 2>&1); then
    fail "release tag check unexpectedly accepted an unavailable remote"
fi
if ! grep -Fq "could not verify tag 'v0.27.2'" <<<"$TAG_OUTPUT"; then
    fail "unavailable remote rejection was not specific: $TAG_OUTPUT"
fi

SOURCE_COMMIT=$(git -C "$TAG_CHECKOUT" rev-parse HEAD)
(cd "$TAG_CHECKOUT" && \
    "$SCRIPT_DIR/check-release-source.sh" "$SOURCE_COMMIT" >/dev/null)
printf 'advanced\n' > "$TAG_CHECKOUT/source-drift"
git -C "$TAG_CHECKOUT" add source-drift
git -C "$TAG_CHECKOUT" commit -qm "advance release source"
if SOURCE_OUTPUT=$(cd "$TAG_CHECKOUT" && \
    "$SCRIPT_DIR/check-release-source.sh" "$SOURCE_COMMIT" 2>&1); then
    fail "release source check unexpectedly accepted a moved HEAD"
fi
if ! grep -Fq "HEAD moved after release validation" <<<"$SOURCE_OUTPUT"; then
    fail "moved HEAD rejection was not specific: $SOURCE_OUTPUT"
fi
SOURCE_COMMIT=$(git -C "$TAG_CHECKOUT" rev-parse HEAD)
touch "$TAG_CHECKOUT/untracked-release-input"
if SOURCE_OUTPUT=$(cd "$TAG_CHECKOUT" && \
    "$SCRIPT_DIR/check-release-source.sh" "$SOURCE_COMMIT" 2>&1); then
    fail "release source check unexpectedly accepted a dirty worktree"
fi
if ! grep -Fq "working tree changed after release validation" <<<"$SOURCE_OUTPUT"; then
    fail "dirty source rejection was not specific: $SOURCE_OUTPUT"
fi

LINEAGE_REMOTE="$TMP_DIR/lineage-remote.git"
LINEAGE_FIXTURE="$TMP_DIR/lineage-fixture"
git init -q --bare "$LINEAGE_REMOTE"
git init -q -b main "$LINEAGE_FIXTURE"
git -C "$LINEAGE_FIXTURE" config user.name "ShellDAO Release Test"
git -C "$LINEAGE_FIXTURE" config user.email "release-test@shelldao.org"
printf 'base\n' > "$LINEAGE_FIXTURE/history"
git -C "$LINEAGE_FIXTURE" add history
git -C "$LINEAGE_FIXTURE" commit -qm "base"
git -C "$LINEAGE_FIXTURE" remote add canonical "$LINEAGE_REMOTE"
git -C "$LINEAGE_FIXTURE" push -q -u canonical main
git -C "$LINEAGE_FIXTURE" switch -qc release/v0.27.1
(cd "$LINEAGE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-lineage.sh" canonical HEAD >/dev/null)

git -C "$LINEAGE_FIXTURE" switch -q main
printf 'advanced\n' >> "$LINEAGE_FIXTURE/history"
git -C "$LINEAGE_FIXTURE" commit -qam "advance main"
git -C "$LINEAGE_FIXTURE" push -q canonical main
git -C "$LINEAGE_FIXTURE" switch -q release/v0.27.1
if LINEAGE_OUTPUT=$(cd "$LINEAGE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-lineage.sh" canonical HEAD 2>&1); then
    fail "release lineage check unexpectedly accepted a stale release branch"
fi
if ! grep -Fq "does not descend from current 'canonical/main'" <<<"$LINEAGE_OUTPUT"; then
    fail "stale release branch rejection was not specific: $LINEAGE_OUTPUT"
fi

git -C "$LINEAGE_FIXTURE" merge -q --ff-only main
(cd "$LINEAGE_FIXTURE" && \
    "$SCRIPT_DIR/check-release-lineage.sh" canonical HEAD >/dev/null)

CHECK_SHA=1111111111111111111111111111111111111111
FAKE_GH="$TMP_DIR/fake-gh"
cat > "$FAKE_GH" <<'EOF'
#!/usr/bin/env bash
cat "$CHECK_RUNS_FIXTURE"
EOF
chmod +x "$FAKE_GH"

write_check_runs() {
    local test_status=$1
    local test_conclusion=$2
    local test_sha=${3:-$CHECK_SHA}
    local test_app=${4:-github-actions}
    local test_app_owner=${5:-github}
    cat > "$TMP_DIR/check-runs.json" <<EOF
{
  "check_runs": [
    {"name":"Check & Lint","head_sha":"$CHECK_SHA","status":"completed","conclusion":"success","app":{"slug":"github-actions","owner":{"login":"github"}}},
    {"name":"Test","head_sha":"$test_sha","status":"$test_status","conclusion":$test_conclusion,"app":{"slug":"$test_app","owner":{"login":"$test_app_owner"}}},
    {"name":"Supply Chain Security","head_sha":"$CHECK_SHA","status":"completed","conclusion":"success","app":{"slug":"github-actions","owner":{"login":"github"}}},
    {"name":"Analyze (actions)","head_sha":"$CHECK_SHA","status":"completed","conclusion":"success","app":{"slug":"github-actions","owner":{"login":"github"}}},
    {"name":"Analyze (python)","head_sha":"$CHECK_SHA","status":"completed","conclusion":"success","app":{"slug":"github-actions","owner":{"login":"github"}}},
    {"name":"Analyze (rust)","head_sha":"$CHECK_SHA","status":"completed","conclusion":"success","app":{"slug":"github-actions","owner":{"login":"github"}}}
  ]
}
EOF
}

assert_ci_fails_with() {
    local expected=$1
    local output
    if output=$(GH_BIN="$FAKE_GH" CHECK_RUNS_FIXTURE="$TMP_DIR/check-runs.json" \
        "$SCRIPT_DIR/check-release-ci.sh" "$CHECK_SHA" 2>&1); then
        fail "release CI check unexpectedly passed"
    fi
    if ! grep -Fq "$expected" <<<"$output"; then
        fail "expected '$expected' in CI check output: $output"
    fi
}

write_check_runs completed '"success"'
GH_BIN="$FAKE_GH" CHECK_RUNS_FIXTURE="$TMP_DIR/check-runs.json" \
    "$SCRIPT_DIR/check-release-ci.sh" "$CHECK_SHA" >/dev/null

python3 - "$TMP_DIR/check-runs.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    payload = json.load(source)
payload["check_runs"] = [
    run for run in payload["check_runs"] if run["name"] != "Analyze (rust)"
]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(payload, destination)
PY
assert_ci_fails_with "required check 'Analyze (rust)' is missing"

write_check_runs in_progress null
assert_ci_fails_with "required check 'Test' has not succeeded"

write_check_runs completed '"success"' 2222222222222222222222222222222222222222
assert_ci_fails_with "required check 'Test' is associated with another commit"

write_check_runs completed '"success"' "$CHECK_SHA" untrusted-checks example
assert_ci_fails_with "required check 'Test' is from an untrusted app"

printf '{"check_runs":[]}' > "$TMP_DIR/check-runs.json"
assert_ci_fails_with "required check 'Check & Lint' is missing"

make_fixture() {
    local changelog=$1
    local fixture="$TMP_DIR/fixture"

    rm -rf "$fixture"
    mkdir -p "$fixture/scripts"
    cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/changelog-excerpt.sh" \
        "$SCRIPT_DIR/check-release-ci.sh" \
        "$SCRIPT_DIR/check-release-lineage.sh" \
        "$SCRIPT_DIR/check-release-lockfile.sh" \
        "$SCRIPT_DIR/check-release-remote.sh" \
        "$SCRIPT_DIR/check-release-tag.sh" \
        "$SCRIPT_DIR/check-release-source.sh" \
        "$SCRIPT_DIR/check-release-metadata.sh" \
        "$SCRIPT_DIR/push-release-tag.sh" \
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
    git -C "$fixture" remote add origin https://github.com/ShellDAO/shell-chain.git
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
cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/changelog-excerpt.sh" \
    "$SCRIPT_DIR/check-release-ci.sh" \
    "$SCRIPT_DIR/check-release-lineage.sh" \
    "$SCRIPT_DIR/check-release-lockfile.sh" \
    "$SCRIPT_DIR/check-release-remote.sh" \
    "$SCRIPT_DIR/check-release-tag.sh" \
    "$SCRIPT_DIR/check-release-source.sh" \
    "$SCRIPT_DIR/check-release-metadata.sh" \
    "$SCRIPT_DIR/push-release-tag.sh" \
    "$SCRIPT_DIR/supply-chain-tool-versions.sh" "$fixture/scripts/"
printf '[workspace.package]\nversion = "0.27.1"\n' > "$fixture/Cargo.toml"
mkdir -p "$fixture/fuzz"
printf '[package]\nname = "shell-fuzz"\nversion = "0.27.1"\n' > "$fixture/fuzz/Cargo.toml"
printf '| v0.27.x | supported |\n| < v0.27.0 | end of life |\n\n**v0.27.x is the current supported release line.** v0.27.x receives security-only backports. Users older than v0.27.0 should upgrade.\n' > "$fixture/SECURITY.md"
printf 'https://img.shields.io/badge/version-0.27.1-green.svg\n' > "$fixture/README.md"
printf 'FROM example.invalid/base\n# ghcr.io/shelldao/shell-chain:v0.27.1\n' > "$fixture/Dockerfile"
printf '## [Unreleased]\n\n## [0.27.1] - test release\n' > "$fixture/CHANGELOG.md"
git -C "$fixture" add .
git -C "$fixture" commit -qm "unrelated release history"
assert_fails_with "$fixture" '0.27.1' "must descend from 'main'"

echo "release preflight tests passed"
