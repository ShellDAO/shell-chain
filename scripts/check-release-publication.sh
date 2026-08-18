#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "release publication check failed: $1" >&2
    exit 1
}

REMOTE="${1:-}"
TAG="${2:-}"
RELEASE_COMMIT="${3:-}"
GH_BIN="${GH_BIN:-gh}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/release-version.sh"

if [ -z "$REMOTE" ]; then
    fail "expected a release remote"
fi
if ! release_tag_is_valid "$TAG"; then
    fail "expected a semver tag with a leading 'v'"
fi
if [[ ! "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    fail "expected a full 40-character release commit SHA"
fi
command -v "$GH_BIN" >/dev/null 2>&1 || fail "GitHub CLI is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
if ! "$SCRIPT_DIR/check-release-remote.sh" "$REMOTE" >/dev/null; then
    fail "release remote is not canonical"
fi

TAG_REF="refs/tags/${TAG}"
if ! REMOTE_TAGS=$(git ls-remote --exit-code "$REMOTE" "$TAG_REF" "${TAG_REF}^{}"); then
    fail "could not resolve '${TAG}' on remote '${REMOTE}'"
fi
REMOTE_TAG_COMMIT=$(awk -v peeled="${TAG_REF}^{}" '
    $2 == peeled && $1 ~ /^[0-9a-f]{40}$/ { print $1; count++ }
    END { if (count != 1) exit 1 }
' <<<"$REMOTE_TAGS") || fail "remote tag '${TAG}' is not annotated or has an invalid target"
if [ "$REMOTE_TAG_COMMIT" != "$RELEASE_COMMIT" ]; then
    fail "remote tag '${TAG}' does not point to the validated release commit"
fi

RELEASE_FILE=$(mktemp)
trap 'rm -f "$RELEASE_FILE"' EXIT
if ! "$GH_BIN" api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/ShellDAO/shell-chain/releases/tags/${TAG}" > "$RELEASE_FILE"; then
    fail "could not load the GitHub release for '${TAG}'"
fi

python3 - "$TAG" "$RELEASE_FILE" <<'PY'
import json
import sys

tag, path = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as source:
        release = json.load(source)
except (OSError, json.JSONDecodeError) as error:
    print(f"release publication check failed: invalid release response: {error}", file=sys.stderr)
    raise SystemExit(1)

errors = []
expected_prerelease = "-" in tag.removeprefix("v")
if release.get("tag_name") != tag:
    errors.append("release tag does not match the validated tag")
if release.get("draft") is not False:
    errors.append("release is still a draft")
if release.get("prerelease") is not expected_prerelease:
    errors.append(
        f"release prerelease state does not match tag (expected {expected_prerelease})"
    )
if not isinstance(release.get("published_at"), str) or not release["published_at"]:
    errors.append("release has no publication timestamp")
if not isinstance(release.get("html_url"), str) or not release["html_url"]:
    errors.append("release has no public URL")

assets = release.get("assets")
if not isinstance(assets, list) or not assets:
    errors.append("release has no downloadable assets")
else:
    asset_names = set()
    for asset in assets:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str) or not name:
            errors.append("release has an asset without a name")
            continue
        asset_names.add(name)
        if asset.get("state") != "uploaded":
            errors.append(f"release asset '{name}' is not fully uploaded")
        if not isinstance(asset.get("size"), int) or asset["size"] <= 0:
            errors.append(f"release asset '{name}' is empty")
        url = asset.get("browser_download_url")
        if not isinstance(url, str) or not url:
            errors.append(f"release asset '{name}' has no download URL")

    archive_prefix = f"shell-node-{tag}-"
    if not any(
        name.startswith(archive_prefix) and name.endswith(".tar.gz")
        for name in asset_names
    ):
        errors.append("release has no versioned shell-node archive")
    if "SHA256SUMS" not in asset_names:
        errors.append("release has no SHA256SUMS manifest")

if errors:
    for error in errors:
        print(f"release publication check failed: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"published GitHub release verified for {tag}: {release['html_url']}")
PY
