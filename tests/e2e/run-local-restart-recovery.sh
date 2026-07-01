#!/usr/bin/env bash
# Local two-validator restart recovery smoke test.
#
# This test does not require Docker. It creates two fresh validator keystores,
# writes a shared wPoA genesis, starts node1 with node2 as its configured
# bootnode while node2 is offline, then verifies that node1 redials node2 after
# node2 restarts and finality resumes without restarting node1. Validators use
# persistent storage so a process restart keeps the local canonical chain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass()  { echo -e "${GREEN}✓ $1${NC}"; }
fail()  { echo -e "${RED}✗ $1${NC}"; FAILURES=$((FAILURES+1)); }
info()  { echo -e "${YELLOW}→ $1${NC}"; }
header(){ echo -e "${CYAN}══ $1 ══${NC}"; }
FAILURES=0

NODE_BIN="${NODE_BIN:-./target/release/shell-node}"
CHAIN_ID="${CHAIN_ID:-31337}"
BLOCK_TIME="${BLOCK_TIME:-1000}"
MAX_IDLE_INTERVAL="${MAX_IDLE_INTERVAL:-0}"

NODE1_RPC="${NODE1_RPC:-19545}"; NODE1_P2P="${NODE1_P2P:-31313}"; NODE1_METRICS="${NODE1_METRICS:-19190}"
NODE2_RPC="${NODE2_RPC:-19546}"; NODE2_P2P="${NODE2_P2P:-31314}"; NODE2_METRICS="${NODE2_METRICS:-19191}"

TESTDIR=$(mktemp -d /tmp/shell-restart-recovery-XXXXXX)
NODE1_DATA="$TESTDIR/node1"
NODE2_DATA="$TESTDIR/node2"
KEY1="$TESTDIR/node1-validator.json"
KEY2="$TESTDIR/node2-validator.json"
PW="$TESTDIR/password.txt"
GENESIS="$TESTDIR/genesis.json"
LOG1="$TESTDIR/node1.log"
LOG2="$TESTDIR/node2.log"
REPORT="$TESTDIR/restart-recovery-report.txt"
mkdir -p "$NODE1_DATA" "$NODE2_DATA"
printf 'dev-password\n' > "$PW"
chmod 600 "$PW"

NODE1_PID=""; NODE2_PID=""

cleanup() {
  info "Shutting down local nodes..."
  [[ -n "$NODE1_PID" ]] && kill "$NODE1_PID" 2>/dev/null || true
  [[ -n "$NODE2_PID" ]] && kill "$NODE2_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  info "Artifacts saved to: $TESTDIR"
  if [[ $FAILURES -gt 0 ]]; then
    echo -e "${RED}FAILED ($FAILURES failures)${NC}"
    exit 1
  fi
  echo -e "${GREEN}ALL CHECKS PASSED${NC}"
}
trap cleanup EXIT

rpc() {
  local port=$1 method=$2 params=${3:-[]}
  curl -sf --max-time 5 -X POST "http://127.0.0.1:$port" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" 2>/dev/null
}

result_hex_to_dec() {
  python3 -c 'import json,sys; v=json.load(sys.stdin).get("result","0x0"); print(int(v,16) if isinstance(v,str) and v.startswith("0x") else int(v or 0))'
}

get_block_number() {
  rpc "$1" eth_blockNumber | result_hex_to_dec 2>/dev/null || echo 0
}

get_peer_count() {
  rpc "$1" net_peerCount | result_hex_to_dec 2>/dev/null || echo 0
}

get_finalized_number() {
  rpc "$1" shell_getFinalityInfo | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["result"]["lastFinalizedBlock"],16))' 2>/dev/null || echo 0
}

get_head_hash() {
  rpc "$1" eth_getBlockByNumber '["latest",false]' \
    | python3 -c 'import json,sys; r=json.load(sys.stdin).get("result") or {}; print(r.get("hash",""))' 2>/dev/null || echo ""
}

wait_rpc() {
  local port=$1 label=$2
  for _ in $(seq 1 60); do
    if rpc "$port" eth_chainId | grep -q '"result"'; then
      pass "$label RPC up"
      return 0
    fi
    sleep 1
  done
  fail "$label RPC did not start"
  return 1
}

wait_peer_count() {
  local port=$1 min_count=$2 label=$3
  for _ in $(seq 1 90); do
    local peers
    peers=$(get_peer_count "$port")
    if [[ "$peers" -ge "$min_count" ]]; then
      pass "$label peerCount=$peers"
      return 0
    fi
    sleep 1
  done
  fail "$label peerCount did not reach $min_count"
  return 1
}

wait_finality_above() {
  local port=$1 baseline=$2 label=$3
  for _ in $(seq 1 90); do
    local finalized
    finalized=$(get_finalized_number "$port")
    if [[ "$finalized" -gt "$baseline" ]]; then
      pass "$label finalized advanced $baseline -> $finalized"
      return 0
    fi
    sleep 1
  done
  fail "$label finality did not advance beyond $baseline"
  return 1
}

wait_same_head() {
  for _ in $(seq 1 60); do
    local h1 h2 hash1 hash2
    h1=$(get_block_number "$NODE1_RPC")
    h2=$(get_block_number "$NODE2_RPC")
    hash1=$(get_head_hash "$NODE1_RPC")
    hash2=$(get_head_hash "$NODE2_RPC")
    if [[ "$h1" == "$h2" && -n "$hash1" && "$hash1" == "$hash2" ]]; then
      pass "Heads match at block $h1 ($hash1)"
      return 0
    fi
    sleep 1
  done
  fail "Node heads did not converge"
  return 1
}

extract_bootnode() {
  local log=$1
  grep -Eo '/ip4/127\.[^ ]+/tcp/[0-9]+/p2p/[A-Za-z0-9]+' "$log" | tail -n1 || true
}

wait_bootnode() {
  local log=$1 label=$2
  for _ in $(seq 1 30); do
    local addr
    addr=$(extract_bootnode "$log")
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return 0
    fi
    sleep 1
  done
  fail "Could not determine $label bootnode multiaddr"
  return 1
}

start_node1() {
  "$NODE_BIN" run \
    --datadir "$NODE1_DATA" \
    --keystore "$KEY1" \
    --password-file "$PW" \
    --rpc-addr "127.0.0.1:$NODE1_RPC" \
    --rpc-api "eth,net,web3,shell" \
    --metrics-addr "127.0.0.1:$NODE1_METRICS" \
    --p2p --p2p-addr "0.0.0.0:$NODE1_P2P" \
    --bootnode "$NODE2_BOOTNODE" \
    --chain-id "$CHAIN_ID" \
    --block-time "$BLOCK_TIME" \
    --max-idle-interval "$MAX_IDLE_INTERVAL" \
    --db rocksdb \
    --consensus-engine wpoa \
    --node-role validator \
    --log-level info \
    > "$LOG1" 2>&1 &
  NODE1_PID=$!
}

start_node2() {
  "$NODE_BIN" run \
    --datadir "$NODE2_DATA" \
    --keystore "$KEY2" \
    --password-file "$PW" \
    --rpc-addr "127.0.0.1:$NODE2_RPC" \
    --rpc-api "eth,net,web3,shell" \
    --metrics-addr "127.0.0.1:$NODE2_METRICS" \
    --p2p --p2p-addr "0.0.0.0:$NODE2_P2P" \
    --chain-id "$CHAIN_ID" \
    --block-time "$BLOCK_TIME" \
    --max-idle-interval "$MAX_IDLE_INTERVAL" \
    --db rocksdb \
    --consensus-engine wpoa \
    --node-role validator \
    --log-level info \
    > "$LOG2" 2>&1 &
  NODE2_PID=$!
}

stop_node2() {
  [[ -n "$NODE2_PID" ]] && kill "$NODE2_PID" 2>/dev/null || true
  wait "$NODE2_PID" 2>/dev/null || true
  NODE2_PID=""
}

header "Preflight"
if [[ ! -x "$NODE_BIN" ]]; then
  fail "Node binary not found: $NODE_BIN"
  exit 1
fi
pass "Node binary: $NODE_BIN"

header "Generating validator keys and shared genesis"
"$NODE_BIN" --password-file "$PW" key generate --output "$KEY1" >/dev/null 2>"$TESTDIR/key1.log"
"$NODE_BIN" --password-file "$PW" key generate --output "$KEY2" >/dev/null 2>"$TESTDIR/key2.log"

python3 - "$KEY1" "$KEY2" "$GENESIS" "$CHAIN_ID" <<'PY'
import json, sys, time
key1, key2, genesis, chain_id = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
keys = [json.load(open(key1)), json.load(open(key2))]
authorities = [k["address"] for k in keys]
pubkeys = ["0x" + k["public_key"].removeprefix("0x") for k in keys]
alloc = {
    addr: {"balance": "0xd3c21bcecceda1000000", "nonce": 0}
    for addr in authorities
}
doc = {
    "chain_id": chain_id,
    "chain_name": "shell-local-restart-recovery",
    "network_type": "Dev",
    "timestamp": int(time.time()),
    "gas_limit": 30000000,
    "extra_data": "local-restart-recovery",
    "consensus": {
        "engine": "wpoa",
        "authorities": authorities,
        "authority_pubkeys": pubkeys,
        "block_time_secs": 1,
        "max_future_secs": 60,
        "epoch_length": 0,
        "weights": [1, 1],
    },
    "alloc": alloc,
    "boot_nodes": [],
}
json.dump(doc, open(genesis, "w"), indent=2)
PY
cp "$GENESIS" "$NODE1_DATA/genesis.json"
cp "$GENESIS" "$NODE2_DATA/genesis.json"
pass "Genesis written with two validators"

header "Priming node2 identity"
start_node2
wait_rpc "$NODE2_RPC" "node2 identity primer"
NODE2_BOOTNODE=$(wait_bootnode "$LOG2" "node2")
pass "Node2 bootnode: $NODE2_BOOTNODE"
stop_node2
pass "Node2 stopped before node1 starts"

header "Starting node1 with offline node2 bootnode"
start_node1
wait_rpc "$NODE1_RPC" "node1"
sleep 5
if [[ "$(get_peer_count "$NODE1_RPC")" -ne 0 ]]; then
  fail "node1 unexpectedly has peers before node2 restart"
  exit 1
fi
pass "node1 has no peers while bootnode is offline"

header "Restarting node2 and waiting for redial recovery"
start_node2
wait_rpc "$NODE2_RPC" "node2"
wait_peer_count "$NODE1_RPC" 1 "node1"
wait_peer_count "$NODE2_RPC" 1 "node2"
wait_finality_above "$NODE1_RPC" 0 "node1"
wait_finality_above "$NODE2_RPC" 0 "node2"
wait_same_head
BASE_FINALIZED=$(get_finalized_number "$NODE1_RPC")

if grep -q 'reason="redial"' "$LOG1"; then
  pass "node1 log includes bootnode redial"
else
  fail "node1 log did not include bootnode redial"
fi

header "Stopping only node2"
stop_node2
for _ in $(seq 1 45); do
  if [[ "$(get_peer_count "$NODE1_RPC")" -eq 0 ]]; then
    pass "node1 peerCount dropped to 0 after node2 stopped"
    break
  fi
  sleep 1
done
PEERS_AFTER_STOP=$(get_peer_count "$NODE1_RPC")
if [[ "$PEERS_AFTER_STOP" -ne 0 ]]; then
  fail "node1 peerCount did not drop after node2 stopped"
  exit 1
fi
sleep 3
STOP_FINALIZED=$(get_finalized_number "$NODE1_RPC")
if [[ "$STOP_FINALIZED" -lt "$BASE_FINALIZED" ]]; then
  fail "finality regressed after node2 stopped"
  exit 1
fi
pass "finality did not regress while quorum was lost"

header "Restarting node2 without restarting node1"
start_node2
wait_rpc "$NODE2_RPC" "node2 restarted"
wait_peer_count "$NODE1_RPC" 1 "node1 after node2 restart"
wait_peer_count "$NODE2_RPC" 1 "node2 after restart"
wait_finality_above "$NODE1_RPC" "$STOP_FINALIZED" "node1 after node2 restart"
wait_finality_above "$NODE2_RPC" "$STOP_FINALIZED" "node2 after restart"
wait_same_head

FINAL1=$(get_finalized_number "$NODE1_RPC")
FINAL2=$(get_finalized_number "$NODE2_RPC")
HEAD1=$(get_block_number "$NODE1_RPC")
HEAD2=$(get_block_number "$NODE2_RPC")
HASH1=$(get_head_hash "$NODE1_RPC")
HASH2=$(get_head_hash "$NODE2_RPC")

{
  echo "=== Local Restart Recovery Report ==="
  echo "Date: $(date -u)"
  echo "Node1 bootnode target: $NODE2_BOOTNODE"
  echo "Finalized before stop: $BASE_FINALIZED"
  echo "Finalized after stop:  $STOP_FINALIZED"
  echo "Finalized final:       node1=$FINAL1 node2=$FINAL2"
  echo "Head final:            node1=$HEAD1/$HASH1 node2=$HEAD2/$HASH2"
} > "$REPORT"
echo "Report: $REPORT"
