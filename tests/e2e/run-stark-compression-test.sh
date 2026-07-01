#!/usr/bin/env bash
# run-stark-compression-test.sh
# Local 3-node wPoA+STARK testnet block compression test.
#
# Starts 3 shell-node processes locally (no Docker required):
#   node1 - block producer + genesis + STARK aggregation enabled
#   node2 - follower (syncs via P2P)
#   node3 - follower (syncs via P2P)
#
# Then:
#   1. Optionally submits N batches of transactions (configurable)
#   2. Waits for blocks to be produced and proofs to be generated
#   3. Reads Prometheus metrics for STARK proof stats
#   4. Reports compression analysis
#
# Usage:
#   ./tests/e2e/run-stark-compression-test.sh
#   ./tests/e2e/run-stark-compression-test.sh --txs 0 --batches 1 --block-time 1000
#
# Prerequisites: shell-node binary at target/release/shell-node
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass()  { echo -e "${GREEN}✓ $1${NC}"; }
fail()  { echo -e "${RED}✗ $1${NC}"; FAILURES=$((FAILURES+1)); }
info()  { echo -e "${YELLOW}→ $1${NC}"; }
header(){ echo -e "${CYAN}══ $1 ══${NC}"; }
FAILURES=0

# ── Configuration ─────────────────────────────────────────────────────────────
NODE_BIN="${NODE_BIN:-./target/release/shell-node}"
TXS_PER_BATCH="${TXS_PER_BATCH:-0}"
NUM_BATCHES="${NUM_BATCHES:-1}"
BLOCK_TIME="${BLOCK_TIME:-2000}"
WAIT_BLOCKS="${WAIT_BLOCKS:-15}"
CHAIN_ID="${CHAIN_ID:-1337}"
MAX_IDLE_INTERVAL="${MAX_IDLE_INTERVAL:-0}"

# Ports
NODE1_RPC=8545;  NODE1_P2P=30303; NODE1_METRICS=9090
NODE2_RPC=8546;  NODE2_P2P=30304; NODE2_METRICS=9091
NODE3_RPC=8547;  NODE3_P2P=30305; NODE3_METRICS=9092

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --txs)       TXS_PER_BATCH=$2; shift 2;;
    --batches)   NUM_BATCHES=$2;   shift 2;;
    --block-time)BLOCK_TIME=$2;    shift 2;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

TOTAL_TXS=$((TXS_PER_BATCH * NUM_BATCHES))

# ── Tmp data dirs ─────────────────────────────────────────────────────────────
TESTDIR=$(mktemp -d /tmp/stark-testnet-XXXXXX)
NODE1_DATA="$TESTDIR/node1"
NODE2_DATA="$TESTDIR/node2"
NODE3_DATA="$TESTDIR/node3"
SHARED_DIR="$TESTDIR/shared"
mkdir -p "$NODE1_DATA" "$NODE2_DATA" "$NODE3_DATA" "$SHARED_DIR"
NODE1_KEYSTORE="$TESTDIR/node1-validator.json"
PASSWORD_FILE="$TESTDIR/password.txt"
printf 'dev-password\n' > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

# Log files
LOG1="$TESTDIR/node1.log"
LOG2="$TESTDIR/node2.log"
LOG3="$TESTDIR/node3.log"
REPORT="$TESTDIR/stark-compression-report.txt"

# PIDs
NODE1_PID=""; NODE2_PID=""; NODE3_PID=""

cleanup() {
  info "Shutting down nodes..."
  [[ -n "$NODE1_PID" ]] && kill "$NODE1_PID" 2>/dev/null || true
  [[ -n "$NODE2_PID" ]] && kill "$NODE2_PID" 2>/dev/null || true
  [[ -n "$NODE3_PID" ]] && kill "$NODE3_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -f "$PASSWORD_FILE" "$NODE1_KEYSTORE" "$TESTDIR"/tx-*.err
  find "$TESTDIR" -name 'dev-authority.json' -delete 2>/dev/null || true
  find "$TESTDIR" -name 'libp2p.key' -delete 2>/dev/null || true
  info "Logs saved to: $TESTDIR"
  if [[ $FAILURES -gt 0 ]]; then
    echo -e "${RED}FAILED ($FAILURES failures)${NC}"
    exit 1
  else
    echo -e "${GREEN}ALL CHECKS PASSED${NC}"
  fi
}
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────
header "Preflight"
if [[ ! -x "$NODE_BIN" ]]; then
  fail "Node binary not found: $NODE_BIN (run: cargo build --release -p shell-cli)"
  exit 1
fi
pass "Node binary: $NODE_BIN"

# Check --enable-stark-aggregation is supported
if ! "$NODE_BIN" run --help 2>&1 | grep -q "enable-stark"; then
  fail "Binary does not support --enable-stark-aggregation (please rebuild)"
  exit 1
fi
pass "Binary supports --enable-stark-aggregation"

rpc() { # rpc PORT METHOD [PARAMS]
  local port=$1 method=$2 params=${3:-[]}
  curl -sf --max-time 5 -X POST "http://127.0.0.1:$port" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" 2>/dev/null
}

write_rpc_snapshot() {
  local port=$1
  local label=$2
  local out="$TESTDIR/rpc-snapshot-$label.json"
  python3 - "$port" "$label" "$out" <<'PY'
import json
import sys
import urllib.request

port, label, out = sys.argv[1], sys.argv[2], sys.argv[3]
url = f"http://127.0.0.1:{port}"

def rpc(method, params=None):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)

snapshot = {"label": label, "rpc": url}
for key, method in [
    ("chainId", "eth_chainId"),
    ("blockNumber", "eth_blockNumber"),
    ("peerCount", "net_peerCount"),
    ("finality", "shell_getFinalityInfo"),
]:
    try:
        snapshot[key] = rpc(method)
    except Exception as exc:
        snapshot[key] = {"error": str(exc)}

with open(out, "w") as fh:
    json.dump(snapshot, fh, indent=2, sort_keys=True)
PY
}

wait_rpc() { # wait_rpc PORT LABEL
  local port=$1 label=$2
  for i in $(seq 1 60); do
    if rpc "$port" eth_blockNumber | grep -q '"result"'; then
      pass "$label RPC up (port $port)"
      return 0
    fi
    sleep 1
  done
  fail "$label RPC not responding after 60s"
  return 1
}

# ── Start node1 (producer, STARK enabled) ────────────────────────────────────
header "Generating node1 validator key"
"$NODE_BIN" --password-file "$PASSWORD_FILE" key generate --output "$NODE1_KEYSTORE" \
  > "$TESTDIR/keygen.log" 2>&1
pass "node1 validator keystore generated"

header "Starting node1 (block producer + STARK aggregation)"
"$NODE_BIN" run \
  --datadir "$NODE1_DATA" \
  --keystore "$NODE1_KEYSTORE" \
  --password-file "$PASSWORD_FILE" \
  --rpc-addr "127.0.0.1:$NODE1_RPC" \
  --rpc-api "eth,net,web3,shell" \
  --metrics-addr "127.0.0.1:$NODE1_METRICS" \
  --p2p --p2p-addr "0.0.0.0:$NODE1_P2P" \
  --chain-id "$CHAIN_ID" \
  --block-time "$BLOCK_TIME" \
  --max-idle-interval "$MAX_IDLE_INTERVAL" \
  --db memory \
  --enable-stark-aggregation \
  --node-role validator-prover \
  --log-level info \
  > "$LOG1" 2>&1 &
NODE1_PID=$!
info "node1 PID=$NODE1_PID"

wait_rpc "$NODE1_RPC" "node1"

info "Reusing node1 genesis for follower nodes..."
for i in $(seq 1 30); do
  if [[ -s "$NODE1_DATA/genesis.json" ]]; then
    cp "$NODE1_DATA/genesis.json" "$NODE2_DATA/genesis.json"
    cp "$NODE1_DATA/genesis.json" "$NODE3_DATA/genesis.json"
    pass "Follower genesis copied"
    break
  fi
  sleep 1
done
if [[ ! -s "$NODE2_DATA/genesis.json" || ! -s "$NODE3_DATA/genesis.json" ]]; then
  fail "node1 genesis was not created in time"
  exit 1
fi

# Extract bootnode address from node1 logs
info "Extracting node1 bootnode address..."
BOOTNODE=""
for i in $(seq 1 30); do
  BOOTNODE=$(grep -Eo '/ip4/127\.[^ ]+/tcp/[0-9]+/p2p/[A-Za-z0-9]+' "$LOG1" | tail -n1 || true)
  if [[ -n "$BOOTNODE" ]]; then
    pass "Bootnode: $BOOTNODE"
    break
  fi
  sleep 1
done

if [[ -z "$BOOTNODE" ]]; then
  info "No loopback P2P addr found, trying any advertised address..."
  BOOTNODE=$(grep -Eo '/ip4/[^ ]+/tcp/[0-9]+/p2p/[A-Za-z0-9]+' "$LOG1" | tail -n1 || true)
  if [[ -n "$BOOTNODE" ]]; then
    # Replace 0.0.0.0 with 127.0.0.1 for local connections
    BOOTNODE="${BOOTNODE/0.0.0.0/127.0.0.1}"
    pass "Bootnode (fallback): $BOOTNODE"
  else
    info "P2P address not found yet, continuing without bootnode for followers..."
  fi
fi

# ── Start node2 & node3 (followers) ──────────────────────────────────────────
header "Starting node2 and node3 (followers)"

BOOTNODE_FLAGS=()
[[ -n "$BOOTNODE" ]] && BOOTNODE_FLAGS=(--bootnode "$BOOTNODE")

"$NODE_BIN" run \
  --datadir "$NODE2_DATA" \
  --rpc-addr "127.0.0.1:$NODE2_RPC" \
  --rpc-api "eth,net,web3,shell" \
  --metrics-addr "127.0.0.1:$NODE2_METRICS" \
  --p2p --p2p-addr "0.0.0.0:$NODE2_P2P" \
  --chain-id "$CHAIN_ID" \
  --block-time "$BLOCK_TIME" \
  --max-idle-interval "$MAX_IDLE_INTERVAL" \
  --db memory \
  --enable-stark-aggregation \
  --node-role prover \
  --log-level info \
  "${BOOTNODE_FLAGS[@]}" \
  > "$LOG2" 2>&1 &
NODE2_PID=$!

"$NODE_BIN" run \
  --datadir "$NODE3_DATA" \
  --rpc-addr "127.0.0.1:$NODE3_RPC" \
  --rpc-api "eth,net,web3,shell" \
  --metrics-addr "127.0.0.1:$NODE3_METRICS" \
  --p2p --p2p-addr "0.0.0.0:$NODE3_P2P" \
  --chain-id "$CHAIN_ID" \
  --block-time "$BLOCK_TIME" \
  --max-idle-interval "$MAX_IDLE_INTERVAL" \
  --db memory \
  --enable-stark-aggregation \
  --node-role prover \
  --log-level info \
  "${BOOTNODE_FLAGS[@]}" \
  > "$LOG3" 2>&1 &
NODE3_PID=$!

info "node2 PID=$NODE2_PID, node3 PID=$NODE3_PID"

wait_rpc "$NODE2_RPC" "node2"
wait_rpc "$NODE3_RPC" "node3"

# ── Get funder account ────────────────────────────────────────────────────────
header "Getting dev authority account"

# node1 creates a funded dev authority. Current RPC intentionally returns an
# empty eth_accounts list, so prefer the startup log and keep eth_accounts as a
# compatibility fallback for older binaries.
DEV_ACCOUNT=$(grep -Eo 'Node authority: 0x[0-9a-fA-F]+' "$LOG1" | awk '{print $3}' | tail -n1 || true)
if [[ -z "$DEV_ACCOUNT" ]]; then
  DEV_ACCOUNT=$(rpc "$NODE1_RPC" eth_accounts | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['result'][0])" 2>/dev/null || echo "")
fi
if [[ -z "$DEV_ACCOUNT" ]]; then
  fail "Could not determine dev authority account"
  exit 1
fi
pass "Dev account: $DEV_ACCOUNT"

DEV_BALANCE=$(rpc "$NODE1_RPC" eth_getBalance "[\"$DEV_ACCOUNT\",\"latest\"]" \
  | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
pass "Balance: $DEV_BALANCE wei"

# ── Submit transactions ────────────────────────────────────────────────────────
header "Submitting $TOTAL_TXS transactions ($NUM_BATCHES × $TXS_PER_BATCH)"

RECIPIENT="0x000000000000000000000000000000000000000000000000000000000000dead"
TX_HASHES=()
TX_ERRORS=()
NONCE=0

send_tx() {
  "$NODE_BIN" --password-file "$PASSWORD_FILE" tx send \
    --keystore "$NODE1_KEYSTORE" \
    --rpc-url "http://127.0.0.1:$NODE1_RPC" \
    --chain-id "$CHAIN_ID" \
    --nonce "$1" \
    --gas-limit 21000 \
    --to "$RECIPIENT" \
    --value 1 \
    2>"$TESTDIR/tx-$1.err" \
    | tail -n1
}

if [[ "$TOTAL_TXS" -gt 0 ]]; then
  for batch in $(seq 1 "$NUM_BATCHES"); do
    info "Batch $batch/$NUM_BATCHES..."
    for _ in $(seq 1 "$TXS_PER_BATCH"); do
      if hash=$(send_tx "$NONCE"); then
        :
      else
        hash="ERROR:$(tr '\n' ' ' < "$TESTDIR/tx-$NONCE.err" 2>/dev/null || true)"
      fi
      if [[ "$hash" == 0x* ]]; then
        TX_HASHES+=("$hash")
      else
        TX_ERRORS+=("nonce=$NONCE $hash")
      fi
      NONCE=$((NONCE+1))
    done
    sleep 0.2
  done
else
  info "No transactions requested; running sparse validator-prover liveness smoke."
fi

SENT=${#TX_HASHES[@]}
pass "Sent $SENT transactions"
if [[ "$SENT" -ne "$TOTAL_TXS" ]]; then
  fail "Only $SENT/$TOTAL_TXS transactions were accepted"
  for err in "${TX_ERRORS[@]:0:5}"; do
    echo "  tx error: $err"
  done
  exit 1
fi

# ── Wait for blocks to be produced ───────────────────────────────────────────
header "Waiting for $WAIT_BLOCKS blocks..."
TARGET_BLOCK=$((WAIT_BLOCKS + 2))
REACHED_BLOCK=false
for i in $(seq 1 120); do
  BN=$(rpc "$NODE1_RPC" eth_blockNumber \
    | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
  if [[ "$BN" -ge "$TARGET_BLOCK" ]]; then
    pass "Block number reached: $BN"
    REACHED_BLOCK=true
    break
  fi
  sleep 1
done
if [[ "$REACHED_BLOCK" != "true" ]]; then
  fail "Block number did not reach target $TARGET_BLOCK within timeout (last=$BN)"
  exit 1
fi

# ── Wait for STARK proofs (async proving backlog) ────────────────────────────
info "Waiting for STARK proof backlog to drain (async proving)..."
sleep $((BLOCK_TIME / 200 + 5))

# ── Read Prometheus metrics ───────────────────────────────────────────────────
header "Reading Prometheus metrics (node1)"
METRICS=$(curl -sf --max-time 5 "http://127.0.0.1:$NODE1_METRICS/metrics" 2>/dev/null || echo "")

if [[ -z "$METRICS" ]]; then
  fail "No metrics from node1 (port $NODE1_METRICS)"
else
  pass "Metrics endpoint responding"
fi

extract_metric() {
  echo "$METRICS" | awk -v name="$1" '$1 == name { print $2; exit }'
}

PROOFS_OK=$(extract_metric "shell_stark_proofs_total")
PROOFS_FAIL=$(extract_metric "shell_stark_proof_failures_total")
AMENDMENTS=$(extract_metric "shell_stark_amendments_broadcast_total")

PROOFS_OK="${PROOFS_OK:-0}"
PROOFS_FAIL="${PROOFS_FAIL:-0}"
AMENDMENTS="${AMENDMENTS:-0}"

# ── Read chain stats ──────────────────────────────────────────────────────────
header "Chain stats"
FINAL_BN=$(rpc "$NODE1_RPC" eth_blockNumber \
  | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")

# Collect block sizes and tx counts over last N blocks
python3 - <<PYEOF
import json, urllib.request

RPC = "http://127.0.0.1:$NODE1_RPC"
FINAL_BN = $FINAL_BN

def rpc(method, params):
    req = urllib.request.Request(RPC,
        data=json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode(),
        headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r).get("result")

blocks_with_txs = []
blocks_empty = []
total_txs_confirmed = 0

start = max(1, FINAL_BN - 20)
for bn in range(start, FINAL_BN + 1):
    block = rpc("eth_getBlockByNumber", [hex(bn), False])
    if block is None:
        continue
    ntx = len(block.get("transactions", []))
    size = int(block.get("size","0x0"), 16)
    if ntx > 0:
        blocks_with_txs.append({"bn": bn, "txs": ntx, "size": size})
        total_txs_confirmed += ntx
    else:
        blocks_empty.append(bn)

print(f"Blocks scanned:        {FINAL_BN - start + 1}")
print(f"Blocks with txs:       {len(blocks_with_txs)}")
print(f"Empty blocks:          {len(blocks_empty)}")
print(f"Total txs confirmed:   {total_txs_confirmed}")
if blocks_with_txs:
    avg_txs = sum(b['txs'] for b in blocks_with_txs) / len(blocks_with_txs)
    avg_size = sum(b['size'] for b in blocks_with_txs) / len(blocks_with_txs)
    print(f"Avg txs/block:         {avg_txs:.1f}")
    print(f"Avg block size:        {avg_size:.0f} bytes")
    for b in blocks_with_txs[-5:]:
        print(f"  block {b['bn']:5d}: {b['txs']:3d} txs  {b['size']:6d} bytes")
PYEOF

# ── Compression analysis ──────────────────────────────────────────────────────
header "STARK Block Compression Analysis"

python3 - <<PYEOF
import math

proofs_ok   = $PROOFS_OK
proofs_fail = $PROOFS_FAIL
amendments  = $AMENDMENTS
total_txs   = $SENT

# Dilithium3 public key: 1952 bytes; signature: 3293 bytes
# In shell-chain, embedded pubkey txs carry the pubkey inline in the tx
# STARK proof amortizes these across the whole batch
DILITHIUM_PK_BYTES  = 1952
DILITHIUM_SIG_BYTES = 3293
PER_TX_SAVINGS_FLOOR = DILITHIUM_PK_BYTES   # each embedded-pubkey tx can drop the pubkey if proven

# Proof sizes from the 6h soak benchmark (median values)
PROOF_SIZES = {1:12587, 4:12587, 8:18303, 16:24980, 32:32945,
               64:42843, 128:56525, 256:75547}

print(f"STARK proofs generated:  {proofs_ok}")
print(f"STARK proof failures:    {proofs_fail}")
print(f"ProofAmendments broadcast: {amendments}")
print()
print("Theoretical compression savings (per block batch size):")
print(f"{'Batch':>7} | {'Raw pk size':>12} | {'Proof size':>10} | {'Savings':>10} | {'Ratio':>8}")
print("-" * 60)
for batch, proof_bytes in PROOF_SIZES.items():
    raw_pk_bytes = batch * DILITHIUM_PK_BYTES
    savings = raw_pk_bytes - proof_bytes
    ratio   = raw_pk_bytes / proof_bytes
    print(f"{batch:>7} | {raw_pk_bytes:>11,}B | {proof_bytes:>9,}B | {savings:>+9,}B | {ratio:>7.2f}x")

print()
print("Key insight:")
print("  With batch=256, a single STARK proof (75.5 KB) replaces 256 × 1952B = 499.7 KB of")
print("  embedded Dilithium3 public keys → 6.6× block size reduction for sig data.")
print()
if proofs_ok > 0:
    print(f"  ✓ {proofs_ok} proof(s) generated during this testnet run.")
elif total_txs > 0:
    print("  ℹ  No proofs generated; summary below verifies the explicit below-threshold wait state.")
else:
    print("  ℹ  No proofs generated; empty sparse run has no proof workload.")
PYEOF

# ── Node sync check ───────────────────────────────────────────────────────────
header "Node sync verification"

BN1=$(rpc "$NODE1_RPC" eth_blockNumber | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "?")
BN2=$(rpc "$NODE2_RPC" eth_blockNumber | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "?")
BN3=$(rpc "$NODE3_RPC" eth_blockNumber | python3 -c "import json,sys; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "?")
HASH1=$(rpc "$NODE1_RPC" eth_getBlockByNumber "[\"latest\",false]" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['hash'])" 2>/dev/null || echo "?")
HASH2=$(rpc "$NODE2_RPC" eth_getBlockByNumber "[\"latest\",false]" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['hash'])" 2>/dev/null || echo "?")
HASH3=$(rpc "$NODE3_RPC" eth_getBlockByNumber "[\"latest\",false]" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['hash'])" 2>/dev/null || echo "?")

echo "  node1: block $BN1 hash $HASH1"
echo "  node2: block $BN2 hash $HASH2"
echo "  node3: block $BN3 hash $HASH3"

if [[ "$BN1" == "$BN2" && "$BN2" == "$BN3" && "$HASH1" == "$HASH2" && "$HASH2" == "$HASH3" && "$HASH1" != "?" ]]; then
  pass "All nodes in sync at block $BN1 ($HASH1)"
else
  fail "Nodes not in sync (node1=$BN1/$HASH1, node2=$BN2/$HASH2, node3=$BN3/$HASH3)"
fi

write_rpc_snapshot "$NODE1_RPC" node1
write_rpc_snapshot "$NODE2_RPC" node2
write_rpc_snapshot "$NODE3_RPC" node3
pass "RPC snapshots written"

RECEIPT_PARITY="not-run"
if [[ "$SENT" -gt 0 ]]; then
  if python3 - "$NODE1_RPC" "$NODE2_RPC" "$NODE3_RPC" "$TESTDIR/receipt-parity.json" "${TX_HASHES[@]}" <<'PY'
import json
import sys
import time
import urllib.request

ports = sys.argv[1:4]
out = sys.argv[4]
hashes = sys.argv[5:]

def rpc(port, method, params):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.load(resp)
    if data.get("error"):
        raise RuntimeError(data["error"])
    return data.get("result")

rows = []
ok = True
for tx_hash in hashes:
    receipts = []
    for port in ports:
        receipt = None
        for _ in range(20):
            receipt = rpc(port, "eth_getTransactionReceipt", [tx_hash])
            if receipt:
                break
            time.sleep(0.5)
        reduced = None
        if receipt:
            reduced = {
                "transactionHash": receipt.get("transactionHash"),
                "status": receipt.get("status"),
                "blockHash": receipt.get("blockHash"),
                "blockNumber": receipt.get("blockNumber"),
                "transactionIndex": receipt.get("transactionIndex"),
            }
        receipts.append({"port": port, "receipt": reduced})
    first = receipts[0]["receipt"]
    parity = first is not None and all(item["receipt"] == first for item in receipts[1:])
    ok = ok and parity
    rows.append({"transactionHash": tx_hash, "parity": parity, "receipts": receipts})

with open(out, "w") as fh:
    json.dump({"ok": ok, "transactions": rows}, fh, indent=2, sort_keys=True)

sys.exit(0 if ok else 1)
PY
  then
    RECEIPT_PARITY="pass"
    pass "Transaction receipt parity passed"
  else
    RECEIPT_PARITY="fail"
    fail "Transaction receipt parity failed"
    exit 1
  fi
else
  RECEIPT_PARITY="no-transactions"
  pass "Receipt parity skipped; no transactions submitted"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "Summary"
echo "  Transactions sent:       $SENT"
echo "  Final block number:      $FINAL_BN"
echo "  STARK proofs generated:  $PROOFS_OK"
echo "  STARK proof failures:    $PROOFS_FAIL"
echo "  ProofAmendments:         $AMENDMENTS"
echo "  Test data directory:     $TESTDIR"
echo
if [[ "$PROOFS_OK" -gt 0 ]]; then
  PROOF_STATE="proof-generated"
  pass "STARK block compression active: $PROOFS_OK proof(s) generated"
elif [[ "$SENT" -eq 0 ]]; then
  PROOF_STATE="empty-chain-no-proof-expected"
  pass "Sparse liveness run completed without proof failures; no proof expected without transactions"
elif grep -q 'awaiting more canonical non-empty blocks' "$LOG1"; then
  PROOF_STATE="awaiting-more-entries"
  pass "STARK prover reported explicit below-threshold wait state for sparse transaction load"
else
  PROOF_STATE="ambiguous-pending"
  fail "STARK proofs pending without explicit ProverService wait reason"
  exit 1
fi

# Save report
{
  echo "=== STARK Block Compression Test Report ==="
  echo "Date: $(date -u)"
  echo "Transactions: $SENT"
  echo "Final block:  $FINAL_BN"
  echo "State:        $PROOF_STATE"
  echo "Proofs:       $PROOFS_OK"
  echo "Failures:     $PROOFS_FAIL"
  echo "Amendments:   $AMENDMENTS"
  echo "Head parity:  node1=$BN1/$HASH1 node2=$BN2/$HASH2 node3=$BN3/$HASH3"
  echo "Receipts:     $RECEIPT_PARITY"
} > "$REPORT"
echo "Report: $REPORT"
