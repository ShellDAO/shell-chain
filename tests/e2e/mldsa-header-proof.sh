#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 8 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph second-graph old-state-dir registered-dir accepted-canonical-dir body-dir header-dir" >&2
  exit 2
fi
mode="$1"
shift
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
stage() {
  local operation="$1"
  shift
  echo "stage: $operation"
  set +e
  cargo run --locked -p shell-stark-prover --example mldsa-canonical -- "$operation" "$@"
  local result=$?
  set -e
  echo "stage: $operation exit: $result"
  return "$result"
}
if [[ "$mode" == "prove" ]]; then
  stage header-prove "$@"
fi
stage header-verify "$@"
stage header-check-rejections "$@"
stage header-reopen "$@"
