#!/usr/bin/env bash
# Repeatable multinode regression entrypoint.
#
# Profiles:
#   sync                  Docker 3-node sync/RPC/health checks.
#   restart-recovery      Local two-validator restart/redial/finality smoke.
#   chaos-docker          Docker crash, partition, leader restart, rapid restart.
#   validator-prover      Local STARK/prover path smoke test.
#   local-p0-p2           Local no-Docker P0-P2 suite.
#   single-validator-testnet
#                         Alias for sync.
#   two-validator-devnet  Alias for restart-recovery until a dedicated
#                         generated-key fixture lands.
#   two-validator-testnet-profile
#                         Alias for validator-prover.
#   non-authority-validator-negative
#                         Runs script-level deployment guard checks.
#   all                   sync + restart-recovery + validator-prover + guard checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

PROFILE="${1:-all}"
shift || true

usage() {
  cat <<'USAGE'
Usage: ./tests/e2e/run-multinode-regression.sh [profile]

Profiles:
  sync                  Run Docker 3-node sync/RPC/health checks.
  restart-recovery      Run local two-validator restart/redial/finality checks.
  chaos-docker          Run Docker crash/partition/restart recovery checks.
  validator-prover      Run local STARK/prover smoke checks.
  local-p0-p2           Run local restart, prover no-tx, prover tx, and guard checks.
  single-validator-testnet
                        Alias for sync.
  two-validator-devnet  Alias for restart-recovery.
  two-validator-testnet-profile
                        Alias for validator-prover.
  non-authority-validator-negative
                        Validate deployment guard failure paths.
  all                   Run every profile in order.

Environment:
  REUSE=true            Reuse existing Docker compose nodes for Docker profiles.
  NODE_BIN=...          Binary for validator-prover profile.
  TXS_PER_BATCH=...     Override STARK test transaction count.
  NUM_BATCHES=...       Override STARK test batch count.
  LOCAL_P0_P2_TXS=...    Transactions per batch for local-p0-p2 tx leg (default: 2).
  LOCAL_P0_P2_BATCHES=... Batches for local-p0-p2 tx leg (default: 2).
USAGE
}

run_profile() {
  local profile="$1"
  shift
  case "$profile" in
    sync)
      if [[ "${REUSE:-false}" == "true" ]]; then
        "$SCRIPT_DIR/run-e2e.sh" --reuse
      else
        "$SCRIPT_DIR/run-e2e.sh"
      fi
      ;;
    restart-recovery)
      "$SCRIPT_DIR/run-local-restart-recovery.sh" "$@"
      ;;
    chaos-docker)
      if [[ "${REUSE:-false}" == "true" ]]; then
        "$SCRIPT_DIR/run-chaos-test.sh" --reuse
      else
        "$SCRIPT_DIR/run-chaos-test.sh"
      fi
      ;;
    validator-prover)
      "$SCRIPT_DIR/run-stark-compression-test.sh" "$@"
      ;;
    local-p0-p2)
      run_profile restart-recovery
      TXS_PER_BATCH=0 NUM_BATCHES=1 WAIT_BLOCKS="${LOCAL_P0_P2_WAIT_BLOCKS:-3}" \
        BLOCK_TIME="${LOCAL_P0_P2_BLOCK_TIME:-1000}" \
        run_profile validator-prover --txs 0 --batches 1 --block-time "${LOCAL_P0_P2_BLOCK_TIME:-1000}"
      TXS_PER_BATCH="${LOCAL_P0_P2_TXS:-2}" NUM_BATCHES="${LOCAL_P0_P2_BATCHES:-2}" \
        WAIT_BLOCKS="${LOCAL_P0_P2_WAIT_BLOCKS:-4}" BLOCK_TIME="${LOCAL_P0_P2_BLOCK_TIME:-1000}" \
        run_profile validator-prover \
          --txs "${LOCAL_P0_P2_TXS:-2}" \
          --batches "${LOCAL_P0_P2_BATCHES:-2}" \
          --block-time "${LOCAL_P0_P2_BLOCK_TIME:-1000}"
      run_profile non-authority-validator-negative
      ;;
    single-validator-testnet)
      run_profile sync "$@"
      ;;
    two-validator-devnet)
      run_profile restart-recovery "$@"
      ;;
    two-validator-testnet-profile)
      run_profile validator-prover "$@"
      ;;
    non-authority-validator-negative)
      local out="/tmp/shell-node-start-negative.out"
      local err="/tmp/shell-node-start-negative.err"
      rm -f "$out" "$err"
      if SHELL_NODE_ROLE=validator \
        SHELL_KEYSTORE=/tmp/shell-chain-missing-validator.json \
        SHELL_PASSWORD_FILE=/tmp/shell-chain-missing-validator.pw \
        "$PROJECT_DIR/infra/testnet/systemd/shell-node-start.sh" >"$out" 2>"$err"; then
        echo "non-authority validator guard unexpectedly allowed startup" >&2
        return 1
      fi
      if ! grep -q 'SHELL_KEYSTORE is not readable' "$err"; then
        echo "non-authority validator guard failed for an unexpected reason" >&2
        cat "$err" >&2
        return 1
      fi
      if ! grep -q 'configured validator authority mismatch: expected .* got ' "$PROJECT_DIR/infra/testnet/systemd/shell-node-start.sh"; then
        echo "systemd validator authority mismatch log lost expected/derived comparison" >&2
        return 1
      fi
      echo "non-authority-validator-negative passed"
      ;;
    *)
      echo "unknown multinode regression profile: $profile" >&2
      usage >&2
      exit 64
      ;;
  esac
}

case "$PROFILE" in
  --help|-h)
    usage
    exit 0
    ;;
  all)
    run_profile sync
    run_profile restart-recovery
    run_profile validator-prover "$@"
    run_profile non-authority-validator-negative "$@"
    ;;
  sync|restart-recovery|chaos-docker|validator-prover|local-p0-p2|single-validator-testnet|two-validator-devnet|two-validator-testnet-profile|non-authority-validator-negative)
    run_profile "$PROFILE" "$@"
    ;;
  *)
    echo "unknown multinode regression profile: $PROFILE" >&2
    usage >&2
    exit 64
    ;;
esac
