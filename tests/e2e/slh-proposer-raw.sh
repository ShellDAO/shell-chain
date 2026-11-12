#!/usr/bin/env bash
set -euo pipefail
if [[ $# == 2 && ( $1 == capture || $1 == pause || $1 == resume || $1 == verify || $1 == refuse || $1 == publish ) ]]; then
  exec "$(dirname "$0")/slh-proposer.sh" "$@"
fi
if [[ $# != 3 || ( $1 != prepare && $1 != prepare-first-use ) ]]; then
  echo "usage: $0 prepare|prepare-first-use retained-raw-native-output raw-slh-output; capture|pause|resume|verify|refuse|publish raw-slh-output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
mode=prepare-slh-proposer-raw-bound
if [[ $1 == prepare-first-use ]]; then mode=prepare-slh-proposer-raw-first-use; fi
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" "$mode" "$2" "$3"
