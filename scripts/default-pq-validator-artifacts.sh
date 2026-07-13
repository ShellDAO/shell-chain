#!/usr/bin/env bash
set -euo pipefail

readonly SOLC_VERSION="0.8.35"
readonly CONTRACT="contracts/DefaultPQValidator.sol"
readonly ABI="contracts/DefaultPQValidator.abi.json"
readonly RUNTIME="contracts/DefaultPQValidator.bin-runtime"

mode="${1:---check}"
if [[ "$mode" != "--check" && "$mode" != "--write" ]]; then
  echo "usage: $0 [--check|--write]" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

jq -Rs '{
  language: "Solidity",
  sources: {"DefaultPQValidator.sol": {content: .}},
  settings: {
    optimizer: {enabled: true, runs: 200},
    outputSelection: {"*": {"*": ["abi", "evm.deployedBytecode.object"]}}
  }
}' "$CONTRACT" > "$tmp_dir/input.json"

npx --yes "solc@${SOLC_VERSION}" --standard-json \
  < "$tmp_dir/input.json" > "$tmp_dir/output.json"

if ! jq -e '.contracts["DefaultPQValidator.sol"].DefaultPQValidator' \
  "$tmp_dir/output.json" >/dev/null; then
  jq '.errors // []' "$tmp_dir/output.json" >&2
  exit 1
fi

jq '.contracts["DefaultPQValidator.sol"].DefaultPQValidator.abi' \
  "$tmp_dir/output.json" > "$tmp_dir/abi.json"
jq -r '.contracts["DefaultPQValidator.sol"].DefaultPQValidator.evm.deployedBytecode.object' \
  "$tmp_dir/output.json" | tr -d '\n' > "$tmp_dir/runtime"

if [[ "$mode" == "--write" ]]; then
  cp "$tmp_dir/abi.json" "$ABI"
  cp "$tmp_dir/runtime" "$RUNTIME"
  exit 0
fi

status=0
if ! diff -u "$ABI" "$tmp_dir/abi.json"; then
  echo "$ABI is stale; run scripts/default-pq-validator-artifacts.sh --write" >&2
  status=1
fi
if ! diff -u "$RUNTIME" "$tmp_dir/runtime"; then
  echo "$RUNTIME is stale; run scripts/default-pq-validator-artifacts.sh --write" >&2
  status=1
fi
exit "$status"
