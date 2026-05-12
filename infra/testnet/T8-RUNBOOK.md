# Testnet T.8 Bring-Up Runbook

## Goal
Bring up the 3-validator wPoA testnet (chain_id=10) and observe stable block production for 24 hours.

## Pre-flight Checklist

- [ ] 3 cloud VMs provisioned (recommend: 4 vCPU / 8GB RAM / 200 GB NVMe each)
- [ ] Docker + Docker Compose v2 installed on each VM
- [ ] Ports open: 30303/tcp (P2P), 8545/tcp (RPC), 9090/tcp (metrics)
- [ ] DNS configured: `rpc.testnet.shell.network` → node1 IP
- [ ] Keystores for all 3 validators generated and backed up
- [ ] `SHELL_IMAGE=ghcr.io/shelldao/shell-chain:0.21.0` available or built locally

## Step-by-Step Bring-Up

### Node1 (Primary + Boot Node)

```bash
# SSH to node1
ssh user@<node1-ip>

# Clone infra
git clone https://github.com/LucienSong/shell-chain.git
cd shell-chain/infra/testnet

# Copy genesis
cp ../../examples/genesis-testnet-wpoa.json .

# Set up keystore
mkdir keys
cp /path/to/node1-validator.key keys/node1.key

# Configure
cat > .env << 'EOF'
SHELL_IMAGE=ghcr.io/shelldao/shell-chain:0.21.0
NODE1_KEY_PATH=./keys/node1.key
KEY_PASSWORD=<secure-password>
EXTERNAL_IP=<node1-public-ip>
GRAFANA_ADMIN_PASSWORD=<grafana-password>
EOF

# Start only node1 first
docker compose up -d node1 prometheus grafana

# Wait ~30s, get peer ID
docker compose logs node1 2>&1 | grep -E "peer_id|PeerId|listening"
# Note: PEER_ID=<12D3Koo...>
```

### Node2 + Node3

```bash
# On each: update docker-compose.yml boot-nodes line with node1's peer ID
# Replace REPLACE_WITH_NODE1_PEER_ID → actual peer ID

docker compose up -d node2   # on node2 VM
docker compose up -d node3   # on node3 VM
```

### Faucet

The faucet service is deployed separately from this repository. Configure
its environment as follows once cloned:

```bash
cd /path/to/your/faucet/checkout
cp .env.example .env
# Edit .env: FAUCET_PRIVATE_KEY=<funded-key>, RPC_URL=http://rpc.testnet.shell.network:8545
npm install && npm run build
npm start &
```

## 24h Stability Checklist

Check every 2h during the first 24h:

```bash
# Block production still advancing?
curl -s http://rpc.testnet.shell.network:8545 \
  -d '{"jsonrpc":"2.0","method":"shell_blockNumber","params":[],"id":1}' \
  -H 'Content-Type: application/json' | jq .result

# All 3 nodes healthy?
docker compose ps

# Any view-changes (round > 0)?
docker compose logs node1 | grep "view.change\|WPoA" | tail -20

# Peer counts
curl -s http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"shell_peerCount","params":[],"id":1}' \
  -H 'Content-Type: application/json'
```

## Pass Criteria for T.8

- [ ] Block production continuous for 24h (no gaps > 30s)
- [ ] 0 unplanned view-changes
- [ ] All 3 nodes maintain ≥ 2 peers
- [ ] Finalized block advances (shell_getFinalizedBlock)
- [ ] Grafana dashboard green for all 24h
- [ ] Faucet successfully funded test accounts

## Escalation

If block production stalls > 5 min:
1. Check if ≥ 2 validators are online (`docker compose ps`)
2. Check for network partition (`docker compose logs nodeX | grep "peer disconnected"`)
3. If needed: restart affected node (`docker compose restart nodeX`)
4. If consensus stuck after restart: check wPoA round state in logs

After T.8 passes → update `v20-t8-bringup-24h` todo to done → start `v20-testnet-announce`.
