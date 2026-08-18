#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

new_fixture() {
  local name="$1"
  local fixture="$TMP_DIR/$name"
  mkdir -p "$fixture/scripts" "$fixture/contracts" \
    "$fixture/tools/default-pq-validator-artifacts"
  cp "$SCRIPT_DIR/default-pq-validator-artifacts.sh" "$fixture/scripts/"
  chmod +x "$fixture/scripts/default-pq-validator-artifacts.sh"
  printf '%s\n' 'contract DefaultPQValidator {}' \
    > "$fixture/contracts/DefaultPQValidator.sol"
  printf '%s\n' '[]' > "$fixture/contracts/DefaultPQValidator.abi.json"
  printf '%s' '00' > "$fixture/contracts/DefaultPQValidator.bin-runtime"
  printf '%s\n' '{}' > "$fixture/tools/default-pq-validator-artifacts/package.json"
  printf '%s\n' '{}' > "$fixture/tools/default-pq-validator-artifacts/package-lock.json"
  git -C "$fixture" init -q -b main
  printf '%s\n' "$fixture"
}

expect_rejected() {
  local fixture="$1"
  local expected="$2"
  local output
  if output=$(cd "$fixture" && scripts/default-pq-validator-artifacts.sh --write 2>&1); then
    echo "artifact writer accepted unsafe path: $expected" >&2
    exit 1
  fi
  grep -Fq "$expected" <<<"$output"
}

VICTIM="$TMP_DIR/victim"
printf '%s\n' 'preserve me' > "$VICTIM"

ABI_FIXTURE=$(new_fixture abi-symlink)
rm "$ABI_FIXTURE/contracts/DefaultPQValidator.abi.json"
ln -s "$VICTIM" "$ABI_FIXTURE/contracts/DefaultPQValidator.abi.json"
expect_rejected "$ABI_FIXTURE" \
  'contracts/DefaultPQValidator.abi.json must be a regular file or absent, not a symlink'
grep -Fxq 'preserve me' "$VICTIM"

RUNTIME_FIXTURE=$(new_fixture runtime-symlink)
rm "$RUNTIME_FIXTURE/contracts/DefaultPQValidator.bin-runtime"
ln -s "$VICTIM" "$RUNTIME_FIXTURE/contracts/DefaultPQValidator.bin-runtime"
expect_rejected "$RUNTIME_FIXTURE" \
  'contracts/DefaultPQValidator.bin-runtime must be a regular file or absent, not a symlink'
grep -Fxq 'preserve me' "$VICTIM"

SOURCE_FIXTURE=$(new_fixture source-symlink)
rm "$SOURCE_FIXTURE/contracts/DefaultPQValidator.sol"
ln -s "$VICTIM" "$SOURCE_FIXTURE/contracts/DefaultPQValidator.sol"
expect_rejected "$SOURCE_FIXTURE" \
  'contracts/DefaultPQValidator.sol must be a regular file, not a symlink'

CONTRACTS_FIXTURE=$(new_fixture contracts-symlink)
rm -rf "$CONTRACTS_FIXTURE/contracts"
mkdir "$CONTRACTS_FIXTURE/external-contracts"
ln -s "$CONTRACTS_FIXTURE/external-contracts" "$CONTRACTS_FIXTURE/contracts"
expect_rejected "$CONTRACTS_FIXTURE" \
  'contracts must be a directory, not a symlink'

TOOL_FIXTURE=$(new_fixture tool-symlink)
rm -rf "$TOOL_FIXTURE/tools/default-pq-validator-artifacts"
ln -s "$TMP_DIR" "$TOOL_FIXTURE/tools/default-pq-validator-artifacts"
expect_rejected "$TOOL_FIXTURE" \
  'tools/default-pq-validator-artifacts must be a directory, not a symlink'

TOOLS_FIXTURE=$(new_fixture tools-symlink)
rm -rf "$TOOLS_FIXTURE/tools"
mkdir "$TOOLS_FIXTURE/external-tools"
ln -s "$TOOLS_FIXTURE/external-tools" "$TOOLS_FIXTURE/tools"
expect_rejected "$TOOLS_FIXTURE" \
  'tools must be a directory, not a symlink'

MODULES_FIXTURE=$(new_fixture node-modules-symlink)
ln -s "$TMP_DIR" \
  "$MODULES_FIXTURE/tools/default-pq-validator-artifacts/node_modules"
expect_rejected "$MODULES_FIXTURE" \
  'tools/default-pq-validator-artifacts/node_modules must not be a symlink'

echo "default validator artifact path tests passed"
