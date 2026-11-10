#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != native && $1 != recover-native && $1 != capture && $1 != capture-recovered ) ]]; then
  echo "usage: $0 native|recover-native|capture|capture-recovered output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --release --locked -p shell-node --features rocksdb --example mldsa-produce-proof
case "$1" in
  native) command=prepare-slh ;;
  recover-native) command=slh-recover-native ;;
  capture) command=slh-capture ;;
  capture-recovered) command=slh-capture-recovered ;;
esac
exec target/release/examples/mldsa-produce-proof "$command" "$2"
