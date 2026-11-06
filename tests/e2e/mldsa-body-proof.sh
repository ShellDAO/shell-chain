#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 7 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify first-graph second-graph old-state-dir registered-dir accepted-canonical-dir body-dir" >&2
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
  stage body-init "$@"
  stage body-prove "$@"
fi
stage body-verify "$@"
stage body-check-rejections "$@"
stage body-reopen "$@"
