#!/usr/bin/env bash
# Shell-chain Release Script
#
# Automates the git tagging and release checklist for a new version.
#
# Usage: ./scripts/release.sh <version>
#   e.g.  ./scripts/release.sh 0.13.0
#
# Pre-conditions:
#   - Working tree must be clean (no uncommitted changes)
#   - Cargo.toml workspace version must match <version>
#   - CHANGELOG.md must have a section for [<version>]
#   - CI must be passing on HEAD
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

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
    echo "  e.g. $0 0.13.0"
    exit 1
fi

TAG="v${VERSION}"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Shell-chain Release: ${TAG}                "
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ────────────────────────────────────────

echo "── Pre-flight checks ──"

# 1. Working tree clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    fail "Working tree is not clean. Commit or stash changes before releasing."
fi
ok "Working tree is clean"

# 2. Workspace version matches
CARGO_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "//;s/"//')
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    fail "Cargo.toml workspace version is '${CARGO_VERSION}', expected '${VERSION}'"
fi
ok "Cargo.toml version: ${CARGO_VERSION}"

# 3. CHANGELOG has a section for this version
if ! grep -q "\[${VERSION}\]" CHANGELOG.md; then
    fail "CHANGELOG.md does not contain a [${VERSION}] section"
fi
ok "CHANGELOG.md has [${VERSION}] section"

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
    ok "fuzz/ directory present (${TAG} targets: fuzz_rlp, fuzz_rpc, fuzz_p2p_msg)"
else
    warn "fuzz/ directory not found — skipping fuzz check"
fi

# ── Deny check ────────────────────────────────────────────────

echo ""
echo "── Dependency audit ──"
if command -v cargo-deny &>/dev/null; then
    if cargo deny check; then
        ok "cargo deny check passed"
    else
        warn "cargo deny check reported issues (see above)"
    fi
else
    warn "cargo-deny not installed — skipping (install: cargo install cargo-deny)"
fi

# ── Cargo audit ──────────────────────────────────────────────

echo ""
echo "── Security audit ──"
if command -v cargo-audit &>/dev/null; then
    if cargo audit; then
        ok "cargo audit passed (no known vulnerabilities)"
    else
        warn "cargo audit found advisories (review before tagging)"
    fi
else
    warn "cargo-audit not installed — skipping (install: cargo install cargo-audit)"
fi

# ── Create and push tag ──────────────────────────────────────

echo ""
echo "── Tagging ──"

CHANGELOG_EXCERPT=$(awk "/\[${VERSION}\]/{found=1; next} found && /^## \[/{exit} found{print}" CHANGELOG.md | head -30)

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
