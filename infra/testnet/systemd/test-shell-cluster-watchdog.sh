#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
watchdog="$script_dir/shell-cluster-watchdog.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"

cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
endpoint="${*: -1}"
case "$endpoint" in
  http://ready/health) printf '%s\n' '{"production_ready":true,"syncing":false}' ;;
  http://unready/health) printf '%s\n' '{"production_ready":false,"syncing":false}' ;;
  http://syncing/health) printf '%s\n' '{"production_ready":false,"syncing":true}' ;;
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
EOF

cat >"$tmp/bin/logger" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$tmp/bin/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

chmod +x "$tmp/bin/curl" "$tmp/bin/systemctl" "$tmp/bin/logger" "$tmp/bin/flock"

run_watchdog() {
  local endpoints="$1" services="$2" state_dir="$3" actions="$4"
  local inactive="${5:-}" conflicting="${6:-}"
  PATH="$tmp/bin:$PATH" \
    WATCHDOG_TEST_ACTIONS="$actions" \
    WATCHDOG_TEST_INACTIVE="$inactive" \
    SHELL_WATCHDOG_ENDPOINTS="$endpoints" \
    SHELL_WATCHDOG_SERVICES="$services" \
    SHELL_WATCHDOG_FAILURE_THRESHOLD=1 \
    SHELL_WATCHDOG_INACTIVE_FAILURE_THRESHOLD=1 \
    SHELL_WATCHDOG_CONFLICTING_SERVICES="$conflicting" \
    SHELL_WATCHDOG_STATE_DIR="$state_dir" \
    bash "$watchdog"
}

actions="$tmp/actions"
run_watchdog "http://ready,http://ready" "ready-a.service,ready-b.service" "$tmp/all-ready" "$actions"
[[ ! -e "$actions" ]]

run_watchdog "http://ready,http://missing" "ready.service,unreachable.service" "$tmp/one-unreachable" "$actions"
grep -qx 'restart unreachable.service' "$actions"
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

printf '%s\n' "shell cluster watchdog tests passed"
