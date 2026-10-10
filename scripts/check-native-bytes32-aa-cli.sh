#!/usr/bin/env bash
# Source acceptance for the unreleased native-address profile on Linux/macOS.
# Requires the repository Rust toolchain, RocksDB build prerequisites and Bash.
set -euo pipefail
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
  native_typed_interface_bytes32_aa_survives_process_exit -- --nocapture
