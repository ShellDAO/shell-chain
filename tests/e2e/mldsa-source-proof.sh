#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 || ( "$1" != "prove" && "$1" != "verify" ) ]]; then
  echo "usage: $0 prove|verify source-dir equation-dir signature-dir rejection-dir" >&2
  exit 2
fi
mode="$1"
source_dir="$2"
equation_dir="$3"
signature_dir="$4"
rejection_dir="$5"
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
  stage source-hashes cargo run --locked -p shell-stark-prover --example blake3-sources -- prove "$source_dir"
  stage full-matrix cargo run --locked -p shell-stark-prover --example mldsa-matrix -- prove "$source_dir"
  stage full-equation cargo run --locked -p shell-stark-prover --example mldsa-equation -- prove "$source_dir" "$equation_dir"
  stage full-signature cargo run --locked -p shell-stark-prover --example mldsa-verify -- prove "$source_dir" "$equation_dir" "$signature_dir"
  stage honest-invalid-hint cargo run --locked -p shell-stark-prover --example mldsa-verify -- reject-hint-tamper "$source_dir" "$equation_dir" "$signature_dir" "$rejection_dir"
fi
stage joint-verification cargo run --locked -p shell-stark-prover --example mldsa-source -- verify "$source_dir" "$equation_dir" "$signature_dir"
stage joint-rejections cargo run --locked -p shell-stark-prover --example mldsa-source -- check-rejections "$source_dir" "$equation_dir" "$signature_dir" "$rejection_dir"
