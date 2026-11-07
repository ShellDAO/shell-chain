#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 6 || ( $1 != produce && $1 != resume && $1 != verify ) ]]; then
  echo "usage: $0 produce|resume|verify first-graph second-graph account-state native-node output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo run --locked -p shell-node --features rocksdb --example mldsa-rpc-proof -- "$@"
