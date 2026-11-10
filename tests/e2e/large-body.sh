#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 && $# != 2 && $# != 3 ]]; then
  echo 'usage: large-body.sh output [original-native-block.json [retained-proof-directory]]' >&2
  exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
cargo build --locked --release -p shell-stark-prover --example large-body
python3 tests/e2e/large_body_regression.py "${CARGO_TARGET_DIR:-target}/release/examples/large-body" "$@"
