#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != run && $1 != verify ) ]]; then
  echo "usage: $0 run|verify output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
if [[ $1 == run && ! -f $2/job/manifest.json ]]; then
  tests/e2e/mldsa-automatic-proof.sh run "$2"
fi
cargo build --locked -p shell-node --features rocksdb --example mldsa-produce-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-live-peer-proof.py "$1" "$proof_target/debug/examples/mldsa-produce-proof" "$2"
