#!/usr/bin/env bash
# Source acceptance for the unreleased native-address profile on Linux/macOS.
# Requires the repository Rust toolchain, RocksDB build prerequisites and Bash.
set -euo pipefail
case "${1:-all}" in
  address) test_name=native_typed_interface_address_owner_aa_survives_process_exit ;;
  bytes32) test_name=native_typed_interface_bytes32_aa_survives_process_exit ;;
  pure-address) test_name=native_pure_balance_address_aa_survives_process_exit ;;
  pure-bytes32) test_name=native_pure_balance_bytes32_aa_survives_process_exit ;;
  pure-uint256) test_name=native_pure_balance_uint256 ;;
  pure) test_name=native_pure_balance_ ;;
  struct) test_name=native_struct_argument_aa_survives_process_exit ;;
  all) test_name=aa_survives_process_exit ;;
  *) echo "usage: $0 [address|bytes32|pure-address|pure-bytes32|pure-uint256|pure|struct|all]" >&2; exit 2 ;;
esac
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in
  /*) ;;
  *) target_dir="$repo_dir/$target_dir" ;;
esac
cargo build -p shell-cli --bin shell-node --target-dir "$target_dir"
SHELL_TEST_NATIVE_AA_CLI="$target_dir/debug/shell-node" \
cargo test -p shell-node --features rocksdb --lib --target-dir "$target_dir" \
  "$test_name" -- --nocapture
