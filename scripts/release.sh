#!/usr/bin/env bash
# Shell-chain Release Script
#
# Automates the git tagging and release checklist for a new version.
#
# Usage: ./scripts/release.sh <version>
#   e.g.  ./scripts/release.sh 0.27.1
#
# Pre-conditions:
#   - Working tree must be clean (no uncommitted changes)
#   - Cargo.toml workspace version must match <version>
#   - CHANGELOG.md must have one Unreleased section and one section for [<version>]
#   - CI must be passing on HEAD
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"
source "$SCRIPT_DIR/supply-chain-tool-versions.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "  e.g. $0 0.27.1"
    exit 1
fi
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    fail "Version must be semver without a leading 'v' (for example, 0.27.1 or 0.28.0-rc.1)"
fi

TAG="v${VERSION}"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Shell-chain Release: ${TAG}                "
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ────────────────────────────────────────

echo "── Pre-flight checks ──"

# 1. Working tree clean, including untracked files
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    fail "Working tree has uncommitted or untracked files. Commit or remove them before releasing."
fi
ok "Working tree is clean"

# 2. Workspace version matches
CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "//;s/"//')
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    fail "Cargo.toml workspace version is '${CARGO_VERSION}', expected '${VERSION}'"
fi
ok "Cargo.toml version: ${CARGO_VERSION}"

# 3. CHANGELOG has one Unreleased heading and one release heading for this version
UNRELEASED_HEADING_COUNT=$(awk '$0 == "## [Unreleased]" { count++ } END { print count + 0 }' CHANGELOG.md)
if [ "$UNRELEASED_HEADING_COUNT" -ne 1 ]; then
    fail "CHANGELOG.md must contain exactly one ## [Unreleased] heading (found ${UNRELEASED_HEADING_COUNT})"
fi

RELEASE_HEADING_COUNT=$(awk -v heading="## [${VERSION}]" '
    index($0, heading) == 1 {
        suffix = substr($0, length(heading) + 1, 1)
        if (suffix == "" || suffix ~ /[[:space:]]/) count++
    }
    END { print count + 0 }
' CHANGELOG.md)
if [ "$RELEASE_HEADING_COUNT" -ne 1 ]; then
    fail "CHANGELOG.md must contain exactly one ## [${VERSION}] release heading (found ${RELEASE_HEADING_COUNT})"
fi
ok "CHANGELOG.md has unique Unreleased and ## [${VERSION}] release headings"

# 4. Tag does not already exist
if git tag -l | grep -q "^${TAG}$"; then
    fail "Tag '${TAG}' already exists"
fi
ok "Tag '${TAG}' does not yet exist"

# 5. On main or feat branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
ok "Current branch: ${BRANCH}"

# ── Format check ─────────────────────────────────────────────

echo ""
echo "── Format check ──"
if cargo fmt --all --check; then
    ok "cargo fmt --all --check passed"
else
    fail "cargo fmt check failed — run 'cargo fmt --all' then commit"
fi

# ── Fuzz target syntax check ──────────────────────────────────

echo ""
echo "── Fuzz targets ──"
if [ -d fuzz ]; then
    if cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets; then
        ok "Fuzz targets compile: fuzz_rlp, fuzz_rpc, fuzz_p2p_msg"
    else
        fail "Fuzz target check failed"
    fi
else
    fail "fuzz/ directory not found"
fi

# ── Deny check ────────────────────────────────────────────────

echo ""
echo "── Dependency audit ──"
if command -v cargo-deny &>/dev/null; then
    INSTALLED_DENY_VERSION=$(cargo deny --version | awk '{print $2}')
    if [ "$INSTALLED_DENY_VERSION" != "$CARGO_DENY_VERSION" ]; then
        fail "cargo-deny ${CARGO_DENY_VERSION} required, found ${INSTALLED_DENY_VERSION} (install: cargo install cargo-deny --version ${CARGO_DENY_VERSION} --locked)"
    fi
    if cargo deny check; then
        ok "cargo deny check passed"
    else
        fail "cargo deny check reported issues (see above)"
    fi
else
    fail "cargo-deny not installed (install: cargo install cargo-deny --version ${CARGO_DENY_VERSION} --locked)"
fi

# ── Cargo audit ──────────────────────────────────────────────

echo ""
echo "── Security audit ──"
if command -v cargo-audit &>/dev/null; then
    INSTALLED_AUDIT_VERSION=$(cargo audit --version | awk '{print $2}')
    if [ "$INSTALLED_AUDIT_VERSION" != "$CARGO_AUDIT_VERSION" ]; then
        fail "cargo-audit ${CARGO_AUDIT_VERSION} required, found ${INSTALLED_AUDIT_VERSION} (install: cargo install cargo-audit --version ${CARGO_AUDIT_VERSION} --locked)"
    fi
    if cargo audit && cargo audit --file fuzz/Cargo.lock; then
        ok "cargo audit passed for workspace and fuzz dependencies"
    else
        fail "cargo audit found advisories (review before tagging)"
    fi
else
    fail "cargo-audit not installed (install: cargo install cargo-audit --version ${CARGO_AUDIT_VERSION} --locked)"
fi

# ── Create and push tag ──────────────────────────────────────

echo ""
echo "── Tagging ──"

CHANGELOG_EXCERPT=$(awk -v heading="## [${VERSION}]" '
    index($0, heading) == 1 {
        suffix = substr($0, length(heading) + 1, 1)
        if (suffix == "" || suffix ~ /[[:space:]]/) found = 1
        next
    }
    found && /^## \[/ { exit }
    found { print }
' CHANGELOG.md | head -30)

git tag -a "$TAG" -m "Release ${TAG}

${CHANGELOG_EXCERPT}"

ok "Created annotated tag: ${TAG}"

echo ""
read -r -p "Push tag ${TAG} to origin? [y/N] " CONFIRM
if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
    git push origin "$TAG"
    ok "Pushed tag ${TAG} to origin"
    echo ""
    echo "Next steps:"
    echo "  1. Create a GitHub Release at https://github.com/ShellDAO/shell-chain/releases/new?tag=${TAG}"
    echo "  2. Add CHANGELOG excerpt to the release body"
    echo "  3. Attach pre-compiled binaries (linux-amd64, linux-arm64, darwin-arm64, windows-amd64)"
    echo "  4. Publish Docker image: docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/shelldao/shell-chain:${TAG} --push ."
else
    warn "Tag created locally but NOT pushed. Run: git push origin ${TAG}"
fi

echo ""
echo -e "${GREEN}Release ${TAG} complete!${NC}"
