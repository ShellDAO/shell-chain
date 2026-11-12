#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 5 && $# != 6 && ( $# != 3 || ( $1 != capture && $1 != automatic-fresh-* ) ) && ( $# != 4 || $1 != automatic-* ) ]]; then
  echo "usage: $0 capture native-output proof-output; pause|prove|resume|verify|refusals native-output proof-output signature-cache body-cache [prior-job-output]" >&2
  echo "       $0 automatic-prepare|automatic-pause|automatic-resume|automatic-verify|automatic-refuse|automatic-rpc-refuse native-output completed-checkpoint automatic-output" >&2
  echo "       $0 automatic-fresh-prepare|automatic-fresh-pause|automatic-fresh-resume|automatic-fresh-verify|automatic-fresh-refuse|automatic-fresh-rpc-refuse native-output automatic-output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example slh-canonical
exec "${CARGO_TARGET_DIR:-target}/release/examples/slh-canonical" "$@"
