#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != run && $1 != verify && $1 != consecutive && $1 != batch && $1 != first-use && $1 != wide && $1 != mixed && $1 != eight-keys && $1 != sixteen-keys && $1 != mixed-first-use && $1 != rotation ) ]]; then
  echo "usage: $0 run|consecutive|batch|first-use|wide|mixed|eight-keys|sixteen-keys|mixed-first-use|rotation|verify output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --release --locked -p shell-node --features rocksdb --example mldsa-produce-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-full-proof.py "$1" "$proof_target/release/examples/mldsa-produce-proof" "$2"
