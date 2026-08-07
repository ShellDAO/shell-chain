#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
watchdog="$script_dir/shell-cluster-watchdog.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
touch "$tmp/missing-env"

cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
endpoint="${*: -1}"
if [[ -s "${WATCHDOG_TEST_RESTARTED:-/dev/null}" ]]; then
  restarted=1
else
  restarted=0
fi
case "$endpoint" in
  http://ready/health)
    printf '%s\n' '{"block_height":10,"production_ready":true,"syncing":false}'
    ;;
  http://other/health)
    printf '%s\n' '{"block_height":11,"production_ready":true,"syncing":false}'
    ;;
  http://unready/health)
    if (( restarted == 1 )); then
      printf '%s\n' '{"block_height":10,"production_ready":true,"syncing":false}'
    else
      printf '%s\n' '{"block_height":10,"production_ready":false,"syncing":false}'
    fi
    ;;
  http://syncing/health)
    if (( restarted == 1 )); then
      printf '%s\n' '{"block_height":10,"production_ready":true,"syncing":false}'
    else
      printf '%s\n' '{"block_height":10,"production_ready":false,"syncing":true}'
    fi
    ;;
  http://missing/health)
    if (( restarted == 1 )); then
      printf '%s\n' '{"block_height":10,"production_ready":true,"syncing":false}'
    else
      exit 22
    fi
    ;;
  */metrics)
    printf '%s\n' "${WATCHDOG_TEST_METRICS:-shell_block_height 10}"
    ;;
  *) exit 22 ;;
esac
EOF

cat >"$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$WATCHDOG_TEST_ACTIONS"
if [[ "$1" == "is-active" ]]; then
  service="${*: -1}"
  case ",${WATCHDOG_TEST_INACTIVE:-}," in
    *",${service},"*) exit 3 ;;
  esac
  exit 0
fi
if [[ "$1" == "restart" || "$1" == "start" ]]; then
  if [[ "$1" == "start" && "${*: -1}" == "tx-worker.service" \
    && -n "${WATCHDOG_TEST_FAIL_TX_START_ONCE:-}" \
    && ! -e "$WATCHDOG_TEST_FAIL_TX_START_ONCE" ]]; then
    touch "$WATCHDOG_TEST_FAIL_TX_START_ONCE"
    exit 1
  fi
  printf '%s\n' "$*" >"$WATCHDOG_TEST_RESTARTED"
fi
EOF

for command in logger flock sleep chmod chown; do
  cat >"$tmp/bin/$command" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
done

chmod +x "$tmp/bin/"*

run_watchdog() {
  local endpoints="$1" services="$2" state_dir="$3" actions="$4"
  local inactive="${5:-}" conflicting="${6:-}" env_file="${7:-$tmp/missing-env}"
  local metrics="${8:-shell_block_height 10}"
  local fail_tx_start_once="${9:-}"
  local failure_threshold="${10:-1}"
  local stark_unreachable_threshold="${11:-3}"
  local restarted="$state_dir/restarted"
  mkdir -p "$state_dir"
  rm -f "$restarted"
  PATH="$tmp/bin:$PATH" \
    WATCHDOG_TEST_ACTIONS="$actions" \
    WATCHDOG_TEST_INACTIVE="$inactive" \
    WATCHDOG_TEST_METRICS="$metrics" \
    WATCHDOG_TEST_RESTARTED="$restarted" \
    WATCHDOG_TEST_FAIL_TX_START_ONCE="$fail_tx_start_once" \
    SHELL_WATCHDOG_ENDPOINTS="$endpoints" \
    SHELL_WATCHDOG_SERVICES="$services" \
    SHELL_WATCHDOG_FAILURE_THRESHOLD="$failure_threshold" \
    SHELL_WATCHDOG_INACTIVE_FAILURE_THRESHOLD=1 \
    SHELL_WATCHDOG_STALL_THRESHOLD=5 \
    SHELL_WATCHDOG_CONFLICTING_SERVICES="$conflicting" \
    SHELL_WATCHDOG_STATE_DIR="$state_dir" \
    SHELL_STARK_GUARD_SERVICE="${services%%,*}" \
    SHELL_STARK_GUARD_ENV_FILE="$env_file" \
    SHELL_STARK_MAX_PENDING=2 \
    SHELL_STARK_MAX_REJECTIONS_PER_INTERVAL=4 \
    SHELL_STARK_UNREACHABLE_THRESHOLD="$stark_unreachable_threshold" \
    SHELL_WATCHDOG_TX_SERVICE=tx-worker.service \
    SHELL_WATCHDOG_QUIESCE_SECONDS=1 \
    SHELL_WATCHDOG_RESTART_READY_TIMEOUT=2 \
    bash "$watchdog"
}

actions="$tmp/actions"
run_watchdog "http://ready,http://ready" "ready-a.service,ready-b.service" "$tmp/all-ready" "$actions"
if grep -Eq '^(start|restart|stop) ' "$actions"; then
  echo "watchdog changed services while every validator was ready" >&2
  exit 1
fi

run_watchdog "http://ready,http://missing" "ready.service,unreachable.service" "$tmp/one-unreachable" "$actions"
grep -qx 'restart unreachable.service' "$actions"
grep -qx 'stop tx-worker.service' "$actions"
grep -qx 'start tx-worker.service' "$actions"
if grep -qx 'restart ready.service' "$actions"; then
  echo "watchdog restarted a production-ready service" >&2
  exit 1
fi

: >"$actions"
run_watchdog "http://syncing,http://unready" "syncing.service,unready.service" "$tmp/syncing" "$actions"
if grep -Eq '^(start|restart|stop) ' "$actions"; then
  echo "watchdog disrupted active synchronization" >&2
  exit 1
fi

: >"$actions"
run_watchdog \
  "http://syncing,http://ready" \
  "inactive.service,ready.service" \
  "$tmp/inactive" \
  "$actions" \
  "inactive.service"
grep -qx 'reset-failed inactive.service' "$actions"
grep -qx 'start inactive.service' "$actions"

: >"$actions"
run_watchdog \
  "http://ready,http://ready" \
  "ready-a.service,ready-b.service" \
  "$tmp/conflict" \
  "$actions" \
  "" \
  "legacy.service"
grep -qx 'stop legacy.service' "$actions"

healthy_env="$tmp/healthy-stark.env"
cat >"$healthy_env" <<'EOF'
SHELL_NODE_ROLE=validator-prover
SHELL_ENABLE_STARK_AGGREGATION=true
EOF
: >"$actions"
healthy_metrics=$'shell_block_height 10\nshell_stark_pending_settlements 2\nshell_stark_proofs_generated_total 100\nshell_stark_settlements_accepted_total 1\nshell_stark_settlements_rejected_total 0'
run_watchdog \
  "http://ready,http://ready" \
  "prover.service,validator.service" \
  "$tmp/healthy-stark" \
  "$actions" \
  "" \
  "" \
  "$healthy_env" \
  "$healthy_metrics"
grep -qx 'SHELL_NODE_ROLE=validator-prover' "$healthy_env"
grep -qx 'SHELL_ENABLE_STARK_AGGREGATION=true' "$healthy_env"
if grep -Eq '^(start|restart|stop) ' "$actions"; then
  echo "watchdog treated independent STARK counters as an in-flight gauge" >&2
  exit 1
fi

tripped_env="$tmp/tripped-stark.env"
cp "$healthy_env" "$tripped_env"
: >"$actions"
pending_metrics=$'shell_block_height 10\nshell_stark_pending_settlements 3\nshell_stark_settlements_rejected_total 0'
run_watchdog \
  "http://ready,http://ready" \
  "prover.service,validator.service" \
  "$tmp/tripped-stark" \
  "$actions" \
  "" \
  "" \
  "$tripped_env" \
  "$pending_metrics"
grep -qx 'SHELL_NODE_ROLE=validator' "$tripped_env"
grep -qx 'SHELL_ENABLE_STARK_AGGREGATION=false' "$tripped_env"
grep -qx 'stop tx-worker.service' "$actions"
grep -qx 'restart prover.service' "$actions"
grep -qx 'start tx-worker.service' "$actions"

unreachable_env="$tmp/unreachable-stark.env"
cp "$healthy_env" "$unreachable_env"
: >"$actions"
for _ in 1 2 3; do
  run_watchdog \
    "http://missing,http://ready" \
    "prover.service,validator.service" \
    "$tmp/unreachable-stark" \
    "$actions" \
    "" \
    "" \
    "$unreachable_env" \
    $'shell_block_height 10' \
    "" \
    15 \
    3
done
grep -qx 'SHELL_NODE_ROLE=validator' "$unreachable_env"
grep -qx 'SHELL_ENABLE_STARK_AGGREGATION=false' "$unreachable_env"
grep -qx 'restart prover.service' "$actions"
grep -qx 'stop tx-worker.service' "$actions"
grep -qx 'start tx-worker.service' "$actions"

deferred_env="$tmp/deferred-stark.env"
cp "$healthy_env" "$deferred_env"
: >"$actions"
run_watchdog \
  "http://ready,http://other" \
  "prover.service,validator.service" \
  "$tmp/deferred-stark" \
  "$actions" \
  "" \
  "" \
  "$deferred_env" \
  "$pending_metrics"
grep -qx 'SHELL_NODE_ROLE=validator-prover' "$deferred_env"
grep -qx 'SHELL_ENABLE_STARK_AGGREGATION=true' "$deferred_env"
if grep -Eq '^(start|restart|stop) ' "$actions"; then
  echo "watchdog changed services before validator heights converged" >&2
  exit 1
fi

: >"$actions"
tx_start_failed_once="$tmp/tx-start-failed-once"
run_watchdog \
  "http://ready,http://missing" \
  "ready.service,unreachable.service" \
  "$tmp/tx-resume-retry" \
  "$actions" \
  "" \
  "" \
  "$tmp/missing-env" \
  $'shell_block_height 10' \
  "$tx_start_failed_once" || true
[[ "$(grep -c '^start tx-worker.service$' "$actions")" == 2 ]]

printf '%s\n' "shell cluster watchdog tests passed"
