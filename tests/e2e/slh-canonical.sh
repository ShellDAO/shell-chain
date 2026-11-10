#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 5 && $# != 6 && ( $# != 3 || $1 != capture ) ]]; then
  echo "usage: $0 capture native-output proof-output; pause|prove|resume|verify|refusals native-output proof-output signature-cache body-cache [prior-job-output]" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example slh-canonical
exec "${CARGO_TARGET_DIR:-target}/release/examples/slh-canonical" "$@"
