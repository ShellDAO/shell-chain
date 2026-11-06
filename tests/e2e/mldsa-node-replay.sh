#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 5 || ( $1 != prove && $1 != verify ) ]]; then
  echo "usage: $0 prove|verify first-graph second-graph account-state output" >&2
  exit 2
fi
mode=$1
shift
cd "$(dirname "$0")/../.."
run() { cargo run --locked -p shell-node --features rocksdb --example mldsa-node-replay -- "$1" "${@:2}"; }
if [[ $mode == prove ]]; then run init "$@"; fi
run verify "$@"
run rejections "$@"
run reopen "$@"
