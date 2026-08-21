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
ARCHIVE_LIST=$(mktemp)
ASSET_DIR=$(mktemp -d)
trap 'rm -f "$RELEASE_FILE" "$ARCHIVE_LIST"; rm -rf "$ASSET_DIR"' EXIT
if ! "$GH_BIN" api \
    -H 'Accept: application/vnd.github+json' \
    "/repos/ShellDAO/shell-chain/releases/tags/${TAG}" > "$RELEASE_FILE"; then
    fail "could not load the GitHub release for '${TAG}'"
fi

python3 - "$TAG" "$RELEASE_FILE" "$ARCHIVE_LIST" <<'PY'
import json
import sys

tag, path, archive_list_path = sys.argv[1:]
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
    archive_names = sorted(
        name
        for name in asset_names
        if name.startswith(archive_prefix) and name.endswith(".tar.gz")
    )
    if not archive_names:
        errors.append("release has no versioned shell-node archive")
    if "SHA256SUMS" not in asset_names:
        errors.append("release has no SHA256SUMS manifest")

if errors:
    for error in errors:
        print(f"release publication check failed: {error}", file=sys.stderr)
    raise SystemExit(1)

with open(archive_list_path, "w", encoding="utf-8") as destination:
    destination.writelines(f"{name}\n" for name in archive_names)
PY

DOWNLOAD_ARGS=(
    release download "$TAG"
    --repo ShellDAO/shell-chain
    --dir "$ASSET_DIR"
    --pattern SHA256SUMS
)
while IFS= read -r archive_name; do
    DOWNLOAD_ARGS+=(--pattern "$archive_name")
done < "$ARCHIVE_LIST"
if ! "$GH_BIN" "${DOWNLOAD_ARGS[@]}"; then
    fail "could not download release archives and checksum manifest"
fi

python3 - "$ASSET_DIR" "$ARCHIVE_LIST" "$TAG" <<'PY'
import hashlib
import pathlib
import re
import struct
import sys
import tarfile

asset_dir = pathlib.Path(sys.argv[1])
archive_list_path = pathlib.Path(sys.argv[2])
tag = sys.argv[3]
archive_names = archive_list_path.read_text(encoding="utf-8").splitlines()
manifest_path = asset_dir / "SHA256SUMS"


def binary_matches_target(header, member_path, target):
    arch = target.split("-", 1)[0]
    if arch not in {"x86_64", "aarch64"}:
        return False

    if "-linux-" in target:
        if member_path.name != "shell-node" or len(header) < 20:
            return False
        byteorder = {1: "little", 2: "big"}.get(header[5])
        if header[:4] != b"\x7fELF" or header[4] != 2 or byteorder is None:
            return False
        file_type = int.from_bytes(header[16:18], byteorder)
        machine = int.from_bytes(header[18:20], byteorder)
        return file_type in {2, 3} and machine == {
            "x86_64": 0x3E,
            "aarch64": 0xB7,
        }[arch]

    if target.endswith("-apple-darwin"):
        if member_path.name != "shell-node" or len(header) < 16:
            return False
        byteorder = {
            b"\xcf\xfa\xed\xfe": "little",
            b"\xfe\xed\xfa\xcf": "big",
        }.get(header[:4])
        if byteorder is None:
            return False
        cpu_type = int.from_bytes(header[4:8], byteorder)
        file_type = int.from_bytes(header[12:16], byteorder)
        return file_type == 2 and cpu_type == {
            "x86_64": 0x01000007,
            "aarch64": 0x0100000C,
        }[arch]

    if "-windows-" in target:
        if member_path.name != "shell-node.exe" or len(header) < 64:
            return False
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if header[:2] != b"MZ" or len(header) < pe_offset + 26:
            return False
        if header[pe_offset : pe_offset + 4] != b"PE\0\0":
            return False
        machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
        optional_magic = struct.unpack_from("<H", header, pe_offset + 24)[0]
        return optional_magic == 0x20B and machine == {
            "x86_64": 0x8664,
            "aarch64": 0xAA64,
        }[arch]

    return False

try:
    manifest_lines = manifest_path.read_text(encoding="utf-8").splitlines()
except OSError as error:
    print(
        f"release publication check failed: could not read SHA256SUMS: {error}",
        file=sys.stderr,
    )
    raise SystemExit(1)

checksums = {}
for line_number, line in enumerate(manifest_lines, start=1):
    if not line.strip():
        continue
    match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
    if match is None:
        print(
            f"release publication check failed: malformed SHA256SUMS line {line_number}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    digest, name = match.groups()
    if name in checksums:
        print(
            f"release publication check failed: duplicate SHA256SUMS entry for '{name}'",
            file=sys.stderr,
        )
        raise SystemExit(1)
    checksums[name] = digest.lower()

for name in archive_names:
    expected = checksums.get(name)
    if expected is None:
        print(
            f"release publication check failed: SHA256SUMS does not cover '{name}'",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        archive = asset_dir / name
        actual = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    except OSError as error:
        print(
            f"release publication check failed: could not read release asset '{name}': {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if actual != expected:
        print(
            f"release publication check failed: checksum mismatch for release asset '{name}'",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        with tarfile.open(archive, mode="r:gz") as package:
            members = package.getmembers()
    except (OSError, tarfile.TarError) as error:
        print(
            f"release publication check failed: release asset '{name}' is not a "
            f"readable gzip tar archive: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    files = []
    for member in members:
        member_path = pathlib.PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            print(
                f"release publication check failed: release asset '{name}' "
                "contains an unsafe archive path",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if member.isdir():
            continue
        if not member.isfile():
            print(
                f"release publication check failed: release asset '{name}' "
                "contains a non-regular archive entry",
                file=sys.stderr,
            )
            raise SystemExit(1)
        files.append((member_path, member))

    if len(files) != 1 or files[0][0] not in {
        pathlib.PurePosixPath("shell-node"),
        pathlib.PurePosixPath("shell-node.exe"),
    }:
        print(
            f"release publication check failed: release asset '{name}' must "
            "contain exactly one root shell-node executable",
            file=sys.stderr,
        )
        raise SystemExit(1)

    member = files[0][1]
    if member.size <= 0:
        print(
            f"release publication check failed: release asset '{name}' "
            "contains an empty node binary",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if member.mode & 0o111 == 0:
        print(
            f"release publication check failed: release asset '{name}' "
            "contains a non-executable node binary",
            file=sys.stderr,
        )
        raise SystemExit(1)

    archive_prefix = f"shell-node-{tag}-"
    target = name[len(archive_prefix) : -len(".tar.gz")]
    member_path, member = files[0]
    try:
        with tarfile.open(archive, mode="r:gz") as package:
            source = package.extractfile(member.name)
            if source is None:
                raise tarfile.ExtractError("node binary is not readable")
            header = source.read(65536)
    except (OSError, tarfile.TarError) as error:
        print(
            f"release publication check failed: could not inspect node binary "
            f"in release asset '{name}': {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if not binary_matches_target(header, member_path, target):
        print(
            f"release publication check failed: node binary format or architecture "
            f"does not match archive target '{target}' in release asset '{name}'",
            file=sys.stderr,
        )
        raise SystemExit(1)
PY

echo "published GitHub release verified for ${TAG}: https://github.com/ShellDAO/shell-chain/releases/tag/${TAG}"
