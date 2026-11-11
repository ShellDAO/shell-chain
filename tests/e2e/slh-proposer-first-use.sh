#!/usr/bin/env bash
set -euo pipefail
if [[ $# == 2 && ( $1 == capture || $1 == pause || $1 == resume || $1 == verify || $1 == refuse || $1 == publish ) ]]; then
  exec "$(dirname "$0")/slh-proposer.sh" "$@"
fi
if [[ $# != 3 || $1 != prepare ]]; then
  echo "usage: $0 prepare retained-primary-native-output first-use-output; capture|pause|resume|verify|refuse|publish first-use-output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" prepare-slh-proposer-first-use "$2" "$3"
