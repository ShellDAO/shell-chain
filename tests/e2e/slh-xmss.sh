#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 && $# != 3 ]]; then
  echo 'usage: slh-xmss.sh output [fors-input.json fors.cbor]' >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
cargo build --locked --release -p shell-stark-prover --example slh-xmss
python3 tests/e2e/slh_xmss_regression.py "${CARGO_TARGET_DIR:-target}/release/examples/slh-xmss" "$@"
