#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_HOME="${HOME:?HOME must be set}"
SEPARATOR=$'\x1f'

if [ -n "${RUSTFLAGS:-}" ]; then
    echo "RUSTFLAGS is not supported for release builds; use CARGO_ENCODED_RUSTFLAGS" >&2
    exit 1
fi

append_flag() {
    if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
        CARGO_ENCODED_RUSTFLAGS+="${SEPARATOR}$1"
    else
        CARGO_ENCODED_RUSTFLAGS="$1"
    fi
}

append_flag "--remap-path-prefix=${PROJECT_DIR}=/source"
append_flag "--remap-path-prefix=${BUILD_HOME}=/build-home"
export CARGO_ENCODED_RUSTFLAGS

cd "$PROJECT_DIR"
cargo build --release --locked -p shell-cli --features "rocksdb,libp2p"

BINARY_NAME="shell-node"
case "$(uname -s)" in
    CYGWIN* | MINGW* | MSYS*) BINARY_NAME+=".exe" ;;
esac
BINARY="$PROJECT_DIR/target/release/$BINARY_NAME"
if [ ! -x "$BINARY" ]; then
    echo "release binary not found: target/release/$BINARY_NAME" >&2
    exit 1
fi

if grep -aFq "$BUILD_HOME" "$BINARY"; then
    echo "release binary contains an unremapped build-home path" >&2
    exit 1
fi

echo "release binary: target/release/$BINARY_NAME"
