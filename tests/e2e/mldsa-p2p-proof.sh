#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 || ( $1 != transfer && $1 != verify ) ]]; then
  echo "usage: $0 transfer|verify native-node-fixture rpc-proof-fixture output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo run --locked -p shell-node --features rocksdb --example mldsa-p2p-proof -- "$@"
