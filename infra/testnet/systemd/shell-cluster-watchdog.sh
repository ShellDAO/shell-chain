#!/usr/bin/env bash
set -euo pipefail

: "${SHELL_WATCHDOG_ENDPOINTS:=http://127.0.0.1:9090,http://127.0.0.1:9091}"
: "${SHELL_WATCHDOG_SERVICES:=shell-node2.service,shell-node1.service}"
: "${SHELL_WATCHDOG_FAILURE_THRESHOLD:=15}"
: "${SHELL_WATCHDOG_INACTIVE_FAILURE_THRESHOLD:=3}"
: "${SHELL_WATCHDOG_STALL_THRESHOLD:=5}"
: "${SHELL_WATCHDOG_CONFLICTING_SERVICES:=}"
: "${SHELL_WATCHDOG_STATE_DIR:=/var/lib/shell-chain/watchdog}"
: "${SHELL_STARK_GUARD_SERVICE:=shell-node2.service}"
: "${SHELL_STARK_GUARD_ENV_FILE:=/etc/default/shell-node2}"
: "${SHELL_STARK_MAX_PENDING:=2}"
: "${SHELL_STARK_MAX_REJECTIONS_PER_INTERVAL:=4}"
: "${SHELL_STARK_UNREACHABLE_THRESHOLD:=3}"
: "${SHELL_WATCHDOG_TX_SERVICE:=tx-worker.service}"
: "${SHELL_WATCHDOG_QUIESCE_SECONDS:=5}"
: "${SHELL_WATCHDOG_RESTART_READY_TIMEOUT:=180}"

IFS=',' read -r -a endpoints <<<"$SHELL_WATCHDOG_ENDPOINTS"
IFS=',' read -r -a services <<<"$SHELL_WATCHDOG_SERVICES"
conflicting_services=()
if [[ -n "$SHELL_WATCHDOG_CONFLICTING_SERVICES" ]]; then
  IFS=',' read -r -a conflicting_services <<<"$SHELL_WATCHDOG_CONFLICTING_SERVICES"
fi

for value in "$SHELL_WATCHDOG_FAILURE_THRESHOLD" \
  "$SHELL_WATCHDOG_INACTIVE_FAILURE_THRESHOLD" \
  "$SHELL_WATCHDOG_STALL_THRESHOLD" \
  "$SHELL_STARK_MAX_PENDING" \
  "$SHELL_STARK_MAX_REJECTIONS_PER_INTERVAL" \
  "$SHELL_STARK_UNREACHABLE_THRESHOLD" \
  "$SHELL_WATCHDOG_QUIESCE_SECONDS" \
  "$SHELL_WATCHDOG_RESTART_READY_TIMEOUT"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    echo "watchdog thresholds must be positive integers" >&2
    exit 64
  }
done
if (( ${#endpoints[@]} == 0 || ${#endpoints[@]} != ${#services[@]} )); then
  echo "SHELL_WATCHDOG_ENDPOINTS and SHELL_WATCHDOG_SERVICES must have equal non-zero lengths" >&2
  exit 64
fi

install -d -m 0750 "$SHELL_WATCHDOG_STATE_DIR"
exec 9>"$SHELL_WATCHDOG_STATE_DIR/lock"
flock -n 9 || exit 0

failure_file="$SHELL_WATCHDOG_STATE_DIR/consecutive-failures"
next_file="$SHELL_WATCHDOG_STATE_DIR/next-service-index"
height_file="$SHELL_WATCHDOG_STATE_DIR/last-block-height"
stall_file="$SHELL_WATCHDOG_STATE_DIR/stalled-checks"
rejected_file="$SHELL_WATCHDOG_STATE_DIR/stark-rejected-total"
stark_enabled_file="$SHELL_WATCHDOG_STATE_DIR/stark-enabled-last"
stark_unreachable_file="$SHELL_WATCHDOG_STATE_DIR/stark-unreachable-checks"
tx_resume_required=0

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

metric_value() {
  local body="$1" metric="$2"
  awk -v metric="$metric" '$1 == metric { print int($2); exit }' <<<"$body"
}

service_endpoint() {
  local requested="$1" index
  for ((index = 0; index < ${#services[@]}; index += 1)); do
    if [[ "${services[$index]}" == "$requested" ]]; then
      printf '%s' "${endpoints[$index]}"
      return 0
    fi
  done
  return 1
}

cluster_heights_equal() {
  local endpoint health height expected=""
  for endpoint in "${endpoints[@]}"; do
    health="$(curl --fail --silent --show-error --max-time 5 "${endpoint%/}/health" 2>/dev/null || true)"
    height="$(sed -n 's/.*"block_height":\([0-9][0-9]*\).*/\1/p' <<<"$health")"
    [[ "$height" =~ ^[0-9]+$ ]] || return 1
    if [[ -z "$expected" ]]; then
      expected="$height"
    elif [[ "$height" != "$expected" ]]; then
      return 1
    fi
  done
}

resume_tx_worker() {
  if (( tx_resume_required == 1 )); then
    systemctl start "$SHELL_WATCHDOG_TX_SERVICE" || return 1
    tx_resume_required=0
  fi
}
trap resume_tx_worker EXIT INT TERM

restart_service_guarded() {
  local service="$1" action="${2:-restart}" endpoint target_was_reachable=0
  local result=0 elapsed=0 health
  endpoint="$(service_endpoint "$service")" || return 1
  if curl --fail --silent --max-time 5 "${endpoint%/}/health" >/dev/null 2>&1; then
    target_was_reachable=1
  fi
  if systemctl is-active --quiet "$SHELL_WATCHDOG_TX_SERVICE"; then
    systemctl stop "$SHELL_WATCHDOG_TX_SERVICE" || return 1
    tx_resume_required=1
  fi

  sleep "$SHELL_WATCHDOG_QUIESCE_SECONDS"
  if (( target_was_reachable == 1 )) && ! cluster_heights_equal; then
    logger -t shell-cluster-watchdog \
      "deferring ${service} restart because validator heights are not converged"
    result=1
  elif [[ "$action" == "start" ]]; then
    systemctl reset-failed "$service" || result=1
    (( result != 0 )) || systemctl start "$service" || result=1
  else
    systemctl restart "$service" || result=1
  fi

  if (( result == 0 )); then
    while (( elapsed < SHELL_WATCHDOG_RESTART_READY_TIMEOUT )); do
      health="$(curl --fail --silent --show-error --max-time 5 "${endpoint%/}/health" 2>/dev/null || true)"
      if [[ "$health" == *'"production_ready":true'* && "$health" == *'"syncing":false'* ]]; then
        break
      fi
      sleep 2
      ((elapsed += 2))
    done
    if (( elapsed >= SHELL_WATCHDOG_RESTART_READY_TIMEOUT )); then
      logger -t shell-cluster-watchdog \
        "${service} did not become production-ready within ${SHELL_WATCHDOG_RESTART_READY_TIMEOUT}s"
      result=1
    fi
  fi

  resume_tx_worker || result=1
  return "$result"
}

trip_stark_circuit() {
  local reason="$1" tmp stamp endpoint
  [[ -f "$SHELL_STARK_GUARD_ENV_FILE" ]] || return 1
  if ! grep -q '^SHELL_NODE_ROLE=validator-prover$' "$SHELL_STARK_GUARD_ENV_FILE" \
    && ! grep -q '^SHELL_ENABLE_STARK_AGGREGATION=true$' "$SHELL_STARK_GUARD_ENV_FILE"; then
    return 1
  fi
  endpoint="$(service_endpoint "$SHELL_STARK_GUARD_SERVICE")" || return 1
  if curl --fail --silent --max-time 5 "${endpoint%/}/health" >/dev/null 2>&1 \
    && ! cluster_heights_equal; then
    logger -t shell-cluster-watchdog \
      "deferring STARK circuit breaker because validator heights are not converged"
    return 1
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if ! cp -a "$SHELL_STARK_GUARD_ENV_FILE" "${SHELL_STARK_GUARD_ENV_FILE}.stark-trip.${stamp}"; then
    logger -t shell-cluster-watchdog "STARK circuit breaker failed to create config backup"
    return 1
  fi
  tmp="${SHELL_STARK_GUARD_ENV_FILE}.tmp"
  if ! sed -E \
    -e 's/^SHELL_NODE_ROLE=.*/SHELL_NODE_ROLE=validator/' \
    -e 's/^SHELL_ENABLE_STARK_AGGREGATION=.*/SHELL_ENABLE_STARK_AGGREGATION=false/' \
    "$SHELL_STARK_GUARD_ENV_FILE" >"$tmp"; then
    logger -t shell-cluster-watchdog "STARK circuit breaker failed to render disabled config"
    return 1
  fi
  chmod --reference="$SHELL_STARK_GUARD_ENV_FILE" "$tmp" || return 1
  chown --reference="$SHELL_STARK_GUARD_ENV_FILE" "$tmp" || return 1
  mv "$tmp" "$SHELL_STARK_GUARD_ENV_FILE" || return 1
  if grep -q '^SHELL_NODE_ROLE=validator-prover$' "$SHELL_STARK_GUARD_ENV_FILE" \
    || grep -q '^SHELL_ENABLE_STARK_AGGREGATION=true$' "$SHELL_STARK_GUARD_ENV_FILE"; then
    logger -t shell-cluster-watchdog "STARK circuit breaker config verification failed"
    return 1
  fi
  logger -t shell-cluster-watchdog \
    "STARK circuit breaker tripped: ${reason}; disabling prover on ${SHELL_STARK_GUARD_SERVICE}"
  restart_service_guarded "$SHELL_STARK_GUARD_SERVICE" restart || return 1
  write_state "$stall_file" 0
  write_state "$failure_file" 0
  write_state "$stark_unreachable_file" 0
  return 0
}

if (( ${#conflicting_services[@]} > 0 )); then
  for service in "${conflicting_services[@]}"; do
    if systemctl is-active --quiet "$service"; then
      logger -t shell-cluster-watchdog "stopping configured conflicting service ${service}"
      systemctl stop "$service"
    fi
  done
fi

ready_count=0
syncing_count=0
reachable_count=0
inactive_count=0
max_height=0
max_pending=0
max_rejected=0
guard_reachable=0
ready=()
active=()

for ((index = 0; index < ${#endpoints[@]}; index += 1)); do
  endpoint="${endpoints[$index]}"
  service="${services[$index]}"
  if systemctl is-active --quiet "$service"; then
    active+=(1)
  else
    active+=(0)
    ((inactive_count += 1))
  fi
  health="$(curl --fail --silent --show-error --max-time 5 "${endpoint%/}/health" 2>/dev/null || true)"
  metrics="$(curl --fail --silent --show-error --max-time 5 "${endpoint%/}/metrics" 2>/dev/null || true)"
  if [[ -n "$health" ]]; then
    ((reachable_count += 1))
  fi
  if [[ "$service" == "$SHELL_STARK_GUARD_SERVICE" \
    && -n "$health" && -n "$metrics" ]]; then
    guard_reachable=1
  fi
  if (( active[index] == 1 )) && [[ "$health" == *'"production_ready":true'* ]]; then
    ((ready_count += 1))
    ready+=(1)
  else
    ready+=(0)
  fi
  if (( active[index] == 1 )) && [[ "$health" == *'"syncing":true'* ]]; then
    ((syncing_count += 1))
  fi
  height="$(metric_value "$metrics" shell_block_height)"
  pending="$(metric_value "$metrics" shell_stark_pending_settlements)"
  rejected="$(metric_value "$metrics" shell_stark_settlements_rejected_total)"
  [[ "$height" =~ ^[0-9]+$ ]] && (( height > max_height )) && max_height="$height"
  [[ "$pending" =~ ^[0-9]+$ ]] && (( pending > max_pending )) && max_pending="$pending"
  [[ "$rejected" =~ ^[0-9]+$ ]] && (( rejected > max_rejected )) && max_rejected="$rejected"
done

stark_enabled=0
if grep -q '^SHELL_NODE_ROLE=validator-prover$' "$SHELL_STARK_GUARD_ENV_FILE" \
  && grep -q '^SHELL_ENABLE_STARK_AGGREGATION=true$' "$SHELL_STARK_GUARD_ENV_FILE"; then
  stark_enabled=1
fi
was_stark_enabled="$(read_state "$stark_enabled_file" 0)"
rejection_delta=0
if (( stark_enabled == 1 && was_stark_enabled == 1 )) && [[ -f "$rejected_file" ]]; then
  previous_rejected="$(read_state "$rejected_file" "$max_rejected")"
  (( max_rejected >= previous_rejected )) && rejection_delta=$((max_rejected - previous_rejected))
fi
write_state "$rejected_file" "$max_rejected"
write_state "$stark_enabled_file" "$stark_enabled"

stark_unreachable_checks=0
if (( stark_enabled == 1 && guard_reachable == 0 )) \
  && systemctl is-active --quiet "$SHELL_STARK_GUARD_SERVICE"; then
  stark_unreachable_checks="$(read_state "$stark_unreachable_file" 0)"
  ((stark_unreachable_checks += 1))
fi
write_state "$stark_unreachable_file" "$stark_unreachable_checks"

last_height="$(read_state "$height_file" 0)"
stalled="$(read_state "$stall_file" 0)"
if (( max_height > last_height )); then
  write_state "$height_file" "$max_height"
  write_state "$stall_file" 0
  stalled=0
elif (( inactive_count == 0 && reachable_count == ${#endpoints[@]} )); then
  ((stalled += 1))
  write_state "$stall_file" "$stalled"
fi

# Generated and accepted are independent process-local counters, not an
# in-flight gauge. During canonical catch-up, proof generation can legitimately
# run ahead while the bounded settlement queue remains healthy.
if (( stark_enabled == 1 && stark_unreachable_checks >= SHELL_STARK_UNREACHABLE_THRESHOLD )); then
  trip_stark_circuit \
    "guarded prover endpoint was unreachable for ${stark_unreachable_checks} watchdog intervals" \
    && exit 0
fi
if (( stark_enabled == 1 && max_pending > SHELL_STARK_MAX_PENDING )); then
  trip_stark_circuit "pending settlements ${max_pending} exceeded limit ${SHELL_STARK_MAX_PENDING}" && exit 0
fi
if (( stark_enabled == 1 && rejection_delta > SHELL_STARK_MAX_REJECTIONS_PER_INTERVAL )); then
  trip_stark_circuit \
    "STARK rejections increased by ${rejection_delta}, exceeding interval limit ${SHELL_STARK_MAX_REJECTIONS_PER_INTERVAL}" \
    && exit 0
fi
if (( stalled >= SHELL_WATCHDOG_STALL_THRESHOLD )); then
  trip_stark_circuit "chain head stalled for ${stalled} watchdog intervals" && exit 0
fi

if (( ready_count == ${#endpoints[@]} && stalled < SHELL_WATCHDOG_STALL_THRESHOLD )); then
  write_state "$failure_file" 0
  exit 0
fi
if (( inactive_count == 0 && syncing_count > 0 && stalled < SHELL_WATCHDOG_STALL_THRESHOLD )); then
  write_state "$failure_file" 0
  logger -t shell-cluster-watchdog \
    "production unavailable while synchronization is active; recovery suppressed"
  exit 0
fi

failures="$(read_state "$failure_file" 0)"
((failures += 1))
write_state "$failure_file" "$failures"
logger -t shell-cluster-watchdog \
  "production unavailable: failures=${failures} stalled=${stalled} height=${max_height} reachable=${reachable_count}/${#endpoints[@]} inactive=${inactive_count}"

failure_threshold="$SHELL_WATCHDOG_FAILURE_THRESHOLD"
(( inactive_count > 0 )) && failure_threshold="$SHELL_WATCHDOG_INACTIVE_FAILURE_THRESHOLD"
(( failures < failure_threshold )) && exit 0

start_index="$(read_state "$next_file" 0)"
start_index=$((start_index % ${#services[@]}))
index=-1
for ((offset = 0; offset < ${#services[@]}; offset += 1)); do
  candidate=$(((start_index + offset) % ${#services[@]}))
  if (( active[candidate] == 0 )); then
    index="$candidate"
    break
  fi
done
if (( index < 0 )); then
  for ((offset = 0; offset < ${#services[@]}; offset += 1)); do
    candidate=$(((start_index + offset) % ${#services[@]}))
    if (( ready[candidate] == 0 )); then
      index="$candidate"
      break
    fi
  done
fi
(( index < 0 )) && index="$start_index"

service="${services[$index]}"
if systemctl is-active --quiet "$service"; then
  logger -t shell-cluster-watchdog "restarting ${service} after sustained production unavailability"
  restart_service_guarded "$service" restart
else
  logger -t shell-cluster-watchdog "starting inactive ${service} after sustained production unavailability"
  restart_service_guarded "$service" start
fi
write_state "$next_file" "$(((index + 1) % ${#services[@]}))"
write_state "$failure_file" 0
write_state "$stall_file" 0
