#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph-dir-or-manifest second-graph-dir batch-dir state-dir" >&2
  exit 2
fi
mode="$1"
first="$2"
second="$3"
batch="$4"
state="$5"
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
  if [[ ! -f "$batch/batch-proof.json" ]]; then
    stage signature-batch-source tests/e2e/mldsa-batch-proof.sh prove "$first" "$second" "$batch"
  fi
  stage account-native-source cargo run --locked -p shell-stark-prover --example mldsa-account-state -- init "$first" "$second" "$batch" "$state"
  stage account-hash-controls cargo run --locked -p shell-stark-prover --example mldsa-account-state -- hash-controls "$state"
  stage account-proofs cargo run --locked -p shell-stark-prover --example mldsa-account-state -- prove "$state"
else
  stage account-hash-controls cargo run --locked -p shell-stark-prover --example mldsa-account-state -- verify-hash-controls "$state"
fi
stage account-bound-batch cargo run --locked -p shell-stark-prover --example mldsa-account-state -- verify "$first" "$second" "$batch" "$state"
stage account-rejections cargo run --locked -p shell-stark-prover --example mldsa-account-state -- check-rejections "$first" "$second" "$batch" "$state"
stage account-native-history cargo run --locked -p shell-stark-prover --example mldsa-account-state -- native-reopen "$state"
