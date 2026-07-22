#!/usr/bin/env bash
set -euo pipefail

: "${SHELL_WATCHDOG_ENDPOINTS:=http://127.0.0.1:9090,http://127.0.0.1:9091}"
: "${SHELL_WATCHDOG_SERVICES:=shell-node2.service,shell-node1.service}"
: "${SHELL_WATCHDOG_FAILURE_THRESHOLD:=15}"
: "${SHELL_WATCHDOG_STATE_DIR:=/var/lib/shell-chain/watchdog}"

IFS=',' read -r -a endpoints <<<"$SHELL_WATCHDOG_ENDPOINTS"
IFS=',' read -r -a services <<<"$SHELL_WATCHDOG_SERVICES"

if (( ${#endpoints[@]} == 0 || ${#endpoints[@]} != ${#services[@]} )); then
  echo "SHELL_WATCHDOG_ENDPOINTS and SHELL_WATCHDOG_SERVICES must have equal non-zero lengths" >&2
  exit 64
fi
if [[ ! "$SHELL_WATCHDOG_FAILURE_THRESHOLD" =~ ^[1-9][0-9]*$ ]]; then
  echo "SHELL_WATCHDOG_FAILURE_THRESHOLD must be a positive integer" >&2
  exit 64
fi

install -d -m 0750 "$SHELL_WATCHDOG_STATE_DIR"
exec 9>"$SHELL_WATCHDOG_STATE_DIR/lock"
flock -n 9 || exit 0

failure_file="$SHELL_WATCHDOG_STATE_DIR/consecutive-failures"
next_file="$SHELL_WATCHDOG_STATE_DIR/next-service-index"

read_state() {
  local file="$1" default="$2" value
  value="$(cat "$file" 2>/dev/null || true)"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s' "$value"
  else
    printf '%s' "$default"
  fi
}

write_state() {
  local file="$1" value="$2" tmp
  tmp="${file}.tmp"
  printf '%s\n' "$value" >"$tmp"
  mv "$tmp" "$file"
}

reset_failures() {
  write_state "$failure_file" 0
}

ready_count=0
syncing_count=0
reachable_count=0

for endpoint in "${endpoints[@]}"; do
  health="$(curl --fail --silent --show-error --max-time 5 "${endpoint%/}/health" 2>/dev/null || true)"
  if [[ -n "$health" ]]; then
    ((reachable_count += 1))
  fi
  if [[ "$health" == *'"production_ready":true'* ]]; then
    ((ready_count += 1))
  fi
  if [[ "$health" == *'"syncing":true'* ]]; then
    ((syncing_count += 1))
  fi
done

if (( ready_count > 0 )); then
  reset_failures
  exit 0
fi

# Catch-up sync can legitimately close the production gate for a long time.
# Never restart a node while any reachable peer reports active synchronization.
if (( syncing_count > 0 )); then
  reset_failures
  logger -t shell-cluster-watchdog "production unavailable while synchronization is active; recovery suppressed"
  exit 0
fi

failures="$(read_state "$failure_file" 0)"
((failures += 1))
write_state "$failure_file" "$failures"

logger -t shell-cluster-watchdog \
  "production unavailable: failures=${failures}/${SHELL_WATCHDOG_FAILURE_THRESHOLD} reachable=${reachable_count}/${#endpoints[@]}"

if (( failures < SHELL_WATCHDOG_FAILURE_THRESHOLD )); then
  exit 0
fi

index="$(read_state "$next_file" 0)"
index=$((index % ${#services[@]}))
service="${services[$index]}"

if systemctl is-active --quiet "$service"; then
  logger -t shell-cluster-watchdog "restarting ${service} after sustained production unavailability"
  systemctl restart "$service"
else
  logger -t shell-cluster-watchdog "starting inactive ${service} after sustained production unavailability"
  systemctl start "$service"
fi

write_state "$next_file" "$(((index + 1) % ${#services[@]}))"
reset_failures
