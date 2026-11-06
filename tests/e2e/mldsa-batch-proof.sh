#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 4 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph-dir-or-manifest second-graph-dir batch-dir" >&2
  exit 2
fi
mode="$1"
first="$2"
second="$3"
batch="$4"
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
  if [[ ! -f "$first" ]]; then
    mkdir -p "$first"
    stage first-graph tests/e2e/mldsa-source-proof.sh prove "$first/source" "$first/equation" "$first/signature" "$first/rejection" "$first/sender" "$first/id" "$first/entry"
  fi
  stage template-entry-verification cargo run --locked -p shell-stark-prover --example mldsa-batch -- verify-entry "$first"
  stage second-identity cargo run --locked -p shell-stark-prover --example mldsa-batch -- init-second "$first" "$second/source"
  stage second-source-hashes cargo run --locked -p shell-stark-prover --example blake3-sources -- prove "$second/source"
  stage second-first-matrix cargo run --locked -p shell-stark-prover --example mldsa-matrix -- prove "$second/source" 1
  stage second-graph tests/e2e/mldsa-source-proof.sh prove "$second/source" "$second/equation" "$second/signature" "$second/rejection" "$second/sender" "$second/id" "$second/entry"
fi
stage authenticated-batch cargo run --locked -p shell-stark-prover --example mldsa-batch -- "$mode" "$first" "$second" "$batch"
stage authenticated-batch-rejections cargo run --locked -p shell-stark-prover --example mldsa-batch -- check-rejections "$first" "$second" "$batch"
