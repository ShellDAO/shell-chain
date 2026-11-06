#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 9 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph second-graph state registered canonical body header seal" >&2
  exit 2
fi
mode="$1"
seal_dir="$9"
shift
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
stage() {
  local name="$1"
  shift
  echo "stage: $name"
  set +e
  "$@"
  local result=$?
  set -e
  echo "stage: $name exit: $result"
  return "$result"
}
if [[ "$mode" == "prove" ]]; then
  stage seal-init cargo run --locked -p shell-stark-prover --example mldsa-canonical -- seal-init "$@"
  stage seal-matrix cargo run --locked -p shell-stark-prover --example mldsa-matrix -- prove "$seal_dir/matrix"
  stage seal-equation cargo run --locked -p shell-stark-prover --example mldsa-equation -- prove "$seal_dir/matrix" "$seal_dir/equation"
  stage seal-signature cargo run --locked -p shell-stark-prover --example mldsa-verify -- prove "$seal_dir/matrix" "$seal_dir/equation" "$seal_dir/signature"
  stage seal-honest-invalid-hint cargo run --locked -p shell-stark-prover --example mldsa-verify -- reject-hint-tamper "$seal_dir/matrix" "$seal_dir/equation" "$seal_dir/signature" "$seal_dir/rejection"
fi
stage seal-verification cargo run --locked -p shell-stark-prover --example mldsa-canonical -- seal-verify "$@"
stage seal-invalid-verification cargo run --locked -p shell-stark-prover --example mldsa-canonical -- seal-check-invalid "$@"
stage sealed-RocksDB-reopen cargo run --locked -p shell-stark-prover --example mldsa-canonical -- seal-reopen "$@"
