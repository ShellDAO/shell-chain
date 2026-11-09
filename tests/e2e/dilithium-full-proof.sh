#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != run && $1 != proposer && $1 != both && $1 != unbound && $1 != sdk && $1 != sdk-unbound && $1 != sdk-proposer && $1 != verify ) ]]; then
  echo "usage: $0 run|proposer|both|unbound|sdk|sdk-unbound|sdk-proposer|verify output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
if [[ ( "$1" == sdk || "$1" == sdk-unbound || "$1" == sdk-proposer ) && ! -f "$2.client/node_modules/shell-sdk/package.json" ]]; then
  [[ ! -e "$2.client" ]] || { echo "retained SDK consumer is incomplete; inspect it before continuing" >&2; exit 1; }
  npm install --prefix "$2.client" --cache "$2.client/.npm-cache" --ignore-scripts --no-audit --no-fund shell-sdk@0.14.0-rc.3
fi
cargo build --release --locked -p shell-node --features rocksdb --example mldsa-produce-proof
proof_target="${CARGO_TARGET_DIR:-target}"
python3 tests/e2e/mldsa-full-proof.py "dilithium-$1" "$proof_target/release/examples/mldsa-produce-proof" "$2"
