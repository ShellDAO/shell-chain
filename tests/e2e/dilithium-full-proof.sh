#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != run && $1 != verify ) ]]; then
  echo "usage: $0 run|verify output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --release --locked -p shell-node --features rocksdb --example mldsa-produce-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-full-proof.py "dilithium-$1" "$proof_target/release/examples/mldsa-produce-proof" "$2"
