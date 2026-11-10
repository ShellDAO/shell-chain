#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 || ( $1 != prepare && $1 != pause && $1 != resume && $1 != verify && $1 != refuse && $1 != inspect ) ]]; then
  echo "usage: $0 prepare|pause|resume|verify|refuse|inspect native-output automatic-output peer-output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" "slh-peer-$1" "${@:2}"
