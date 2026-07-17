#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

grep -Fxq 'RUN scripts/build-release-binary.sh' "$SCRIPT_DIR/../Dockerfile"

FIXTURE="$TMP_DIR/project with spaces"
mkdir -p "$FIXTURE/scripts" "$FIXTURE/bin"
cp "$SCRIPT_DIR/build-release-binary.sh" "$FIXTURE/scripts/"

cat > "$FIXTURE/bin/uname" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${FAKE_UNAME:-Darwin}"
EOF
chmod +x "$FIXTURE/bin/uname"

cat > "$FIXTURE/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$CARGO_ENCODED_RUSTFLAGS" > "$CAPTURE_DIR/flags"
printf '%s\n' "$@" > "$CAPTURE_DIR/args"
mkdir -p target/release
if [ -n "${FAKE_BINARY_CONTENT:-}" ]; then
    printf '%s' "$FAKE_BINARY_CONTENT" > "target/release/shell-node${FAKE_EXE_SUFFIX:-}"
else
    printf '#!/usr/bin/env sh\nexit 0\n' > "target/release/shell-node${FAKE_EXE_SUFFIX:-}"
fi
chmod +x "target/release/shell-node${FAKE_EXE_SUFFIX:-}"
EOF
chmod +x "$FIXTURE/bin/cargo"

CAPTURE_DIR="$TMP_DIR/capture"
mkdir -p "$CAPTURE_DIR"
HOME="$TMP_DIR/home with spaces" \
CARGO_HOME="$TMP_DIR/cargo home outside build home" \
PATH="$FIXTURE/bin:$PATH" \
CAPTURE_DIR="$CAPTURE_DIR" \
CARGO_ENCODED_RUSTFLAGS=$'--cfg\x1fexisting' \
    "$FIXTURE/scripts/build-release-binary.sh"

FLAGS=$(tr '\037' '\n' < "$CAPTURE_DIR/flags")
grep -Fxq -- '--cfg' <<<"$FLAGS"
grep -Fxq 'existing' <<<"$FLAGS"
grep -Fxq -- "--remap-path-prefix=$FIXTURE=/source" <<<"$FLAGS"
grep -Fxq -- "--remap-path-prefix=$TMP_DIR/home with spaces=/build-home" <<<"$FLAGS"
grep -Fxq -- "--remap-path-prefix=$TMP_DIR/cargo home outside build home=/cargo-home" <<<"$FLAGS"
grep -Fxq -- '--release' "$CAPTURE_DIR/args"
grep -Fxq -- '--locked' "$CAPTURE_DIR/args"
grep -Fxq -- 'rustc' "$CAPTURE_DIR/args"
grep -Fxq -- '--bin' "$CAPTURE_DIR/args"
grep -Fxq -- 'shell-node' "$CAPTURE_DIR/args"
grep -Fxq 'rocksdb,libp2p' "$CAPTURE_DIR/args"
grep -Fxq -- '--' "$CAPTURE_DIR/args"
grep -Fxq -- '-Clink-arg=-Wl,-no_uuid' "$CAPTURE_DIR/args"

FAKE_UNAME=MINGW64_NT FAKE_EXE_SUFFIX=.exe \
HOME="$TMP_DIR/windows home" PATH="$FIXTURE/bin:$PATH" CAPTURE_DIR="$CAPTURE_DIR" \
    "$FIXTURE/scripts/build-release-binary.sh"
if grep -Fq -- '-Wl,-no_uuid' "$CAPTURE_DIR/args"; then
    echo "release build passed a Darwin linker flag on Windows" >&2
    exit 1
fi

LEAKED_HOME="$TMP_DIR/leaked build home"
if LEAK_OUTPUT=$(FAKE_UNAME=Linux FAKE_BINARY_CONTENT="$LEAKED_HOME/private/source.rs" \
    HOME="$LEAKED_HOME" PATH="$FIXTURE/bin:$PATH" CAPTURE_DIR="$CAPTURE_DIR" \
    "$FIXTURE/scripts/build-release-binary.sh" 2>&1); then
    echo "release build accepted a binary containing the build-home path" >&2
    exit 1
fi
grep -Fq 'release binary contains an unremapped build path' <<<"$LEAK_OUTPUT"

if RUSTFLAGS='--cfg unsupported' HOME="$TMP_DIR/home" PATH="$FIXTURE/bin:$PATH" \
    CAPTURE_DIR="$CAPTURE_DIR" "$FIXTURE/scripts/build-release-binary.sh" 2>/dev/null; then
    echo "release build unexpectedly accepted ambiguous RUSTFLAGS" >&2
    exit 1
fi

echo "release binary build tests passed"
