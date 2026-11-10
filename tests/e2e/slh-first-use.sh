#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 || ( $1 != prepare && $1 != capture && $1 != pause && $1 != resume && $1 != verify && $1 != refuse ) ]]; then
  echo "usage: $0 prepare|capture|pause|resume|verify|refuse original-native bound-proof-output first-use-output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" "slh-first-use-$1" "${@:2}"
