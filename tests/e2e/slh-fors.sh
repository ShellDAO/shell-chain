#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 && $# != 3 ]]; then
  echo 'usage: slh-fors.sh output [signed.json public-key.json]' >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
cargo build --locked --release -p shell-stark-prover --example slh-fors
python3 tests/e2e/slh_fors_regression.py "${CARGO_TARGET_DIR:-target}/release/examples/slh-fors" "$@"
