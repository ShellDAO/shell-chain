#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != run && $1 != verify && $1 != consecutive && $1 != batch && $1 != wide && $1 != mixed && $1 != eight-keys ) ]]; then
  echo "usage: $0 run|consecutive|batch|wide|mixed|eight-keys|verify output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked -p shell-node --features rocksdb --example mldsa-produce-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-full-proof.py "$1" "$proof_target/debug/examples/mldsa-produce-proof" "$2"
