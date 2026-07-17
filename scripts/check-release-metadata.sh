#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

fail() {
    echo "release metadata check failed: $1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail "python3 is required to parse release manifests"

toml_version() {
    local manifest=$1
    local section=$2
    python3 - "$manifest" "$section" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as manifest:
    data = tomllib.load(manifest)

value = data
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
PY
}

VERSION=$(toml_version "$ROOT_DIR/Cargo.toml" "workspace.package.version")
if [[ ! "$VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$ ]]; then
    fail "workspace version '$VERSION' is not supported semver"
fi
SERIES="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"

require_text() {
    local file=$1
    local text=$2
    local description=$3
    if ! grep -Fq -- "$text" "$ROOT_DIR/$file"; then
        fail "$file does not contain the current $description '$text'"
    fi
}

require_single_match() {
    local file=$1
    local pattern=$2
    local description=$3
    local count
    count=$(awk -v pattern="$pattern" '$0 ~ pattern { count++ } END { print count + 0 }' \
        "$ROOT_DIR/$file")
    if [ "$count" -ne 1 ]; then
        fail "$file must contain exactly one $description (found $count)"
    fi
}

require_text SECURITY.md "| v${SERIES}.x |" "supported release series"
require_text SECURITY.md "| < v${SERIES}.0 |" "end-of-life boundary"
require_text SECURITY.md "**v${SERIES}.x is the current supported release line.**" "supported release statement"
require_text SECURITY.md "v${SERIES}.x receives security-only backports" "security backport statement"
require_text SECURITY.md "older than v${SERIES}.0" "upgrade boundary"
require_single_match SECURITY.md '^[|] v[0-9]+[.][0-9]+[.]x [|]' "supported release row"
require_single_match SECURITY.md '^[|] < v[0-9]+[.][0-9]+[.]0 [|]' "end-of-life row"
require_single_match SECURITY.md 'is the current supported release line' "supported release statement"
require_text README.md "version-${VERSION}-green.svg" "version badge"
require_single_match README.md 'img[.]shields[.]io/badge/version-' "version badge"
require_text Dockerfile "ghcr.io/shelldao/shell-chain:v${VERSION}" "container example version"
require_single_match Dockerfile 'ghcr[.]io/shelldao/shell-chain:v' "container example"

FUZZ_VERSION=$(toml_version "$ROOT_DIR/fuzz/Cargo.toml" "package.version")
if [ "$FUZZ_VERSION" != "$VERSION" ]; then
    fail "fuzz/Cargo.toml version '$FUZZ_VERSION' does not match workspace version '$VERSION'"
fi

echo "release metadata matches version ${VERSION}"
