#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph-dir-or-manifest second-graph-dir old-state-dir registered-dir" >&2
  exit 2
fi
mode="$1"
first="$2"
second="$3"
old="$4"
registered="$5"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
stage() {
  local operation="$1"
  echo "stage: $operation"
  set +e
  cargo run --locked -p shell-stark-prover --example mldsa-registered -- "$operation" "$first" "$second" "$old" "$registered"
  local result=$?
  set -e
  echo "stage: $operation exit: $result"
  return "$result"
}
if [[ "$mode" == "prove" ]]; then
  stage init
  stage prove
fi
stage verify
stage native-execute
stage check-rejections
