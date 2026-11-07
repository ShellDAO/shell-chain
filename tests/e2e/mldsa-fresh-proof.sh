#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 || ( $1 != run && $1 != verify ) ]]; then
  echo "usage: $0 run|verify native-node-fixture rpc-proof-fixture output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked -p shell-cli --features rocksdb
cargo build --locked -p shell-node --features rocksdb --example mldsa-fresh-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-fresh-proof.py "$1" "$proof_target/debug/shell-node" \
  "$proof_target/debug/examples/mldsa-fresh-proof" "$2" "$3" "$4"
