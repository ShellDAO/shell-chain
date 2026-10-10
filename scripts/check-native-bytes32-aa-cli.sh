#!/usr/bin/env bash
# Compatibility entry for the bytes32 owner recovery acceptance.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/check-native-owner-aa-cli.sh" bytes32
