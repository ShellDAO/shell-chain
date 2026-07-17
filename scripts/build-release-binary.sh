#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_HOME="${HOME:?HOME must be set}"
CARGO_HOME_PATH="${CARGO_HOME:-$BUILD_HOME/.cargo}"
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

append_flag "--remap-path-prefix=${BUILD_HOME}=/build-home"
append_flag "--remap-path-prefix=${CARGO_HOME_PATH}=/cargo-home"
append_flag "--remap-path-prefix=${PROJECT_DIR}=/source"
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

for path in "$BUILD_HOME" "$CARGO_HOME_PATH" "$PROJECT_DIR"; do
    if grep -aFq "$path" "$BINARY"; then
        echo "release binary contains an unremapped build path" >&2
        exit 1
    fi
done

echo "release binary: target/release/$BINARY_NAME"
