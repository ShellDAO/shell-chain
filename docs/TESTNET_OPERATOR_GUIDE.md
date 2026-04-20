# Shell-Chain Testnet Operator Guide

This guide covers everything you need to run a shell-chain testnet node — from system requirements to monitoring and maintenance.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md) · [Prover Guide](PROVER_GUIDE.md) · [Consensus Details](CONSENSUS_DETAILS.md) · [Block Pruning & Compression](BLOCK_PRUNING_AND_COMPRESSION.md)

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation from Source](#installation-from-source)
3. [Docker Deployment](#docker-deployment)
4. [Alpha Testnet Deployment](#alpha-testnet-deployment)
5. [Configuration](#configuration)
6. [Key Generation](#key-generation)
7. [Genesis Initialization](#genesis-initialization)
8. [Starting a Node](#starting-a-node)
9. [Health & Readiness Endpoints](#health--readiness-endpoints)
10. [Nginx Reverse Proxy](#nginx-reverse-proxy)
11. [JSON Logging](#json-logging)
12. [Monitoring Setup](#monitoring-setup)
13. [Upgrading and Maintenance](#upgrading-and-maintenance)
14. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum (single validator)

| Resource | Requirement |
|----------|-------------|
| **OS** | Linux (Ubuntu 22.04+), macOS 13+, or Windows with WSL2 |
| **CPU** | 2 cores (x86_64 or ARM64) |
| **RAM** | 4 GB |
| **Disk** | 40 GB SSD (archive mode requires more over time) |
| **Network** | 10 Mbps, port 30303/tcp open for P2P |

### Recommended (production validator)

| Resource | Recommendation |
|----------|----------------|
| **CPU** | 4+ cores |
| **RAM** | 8 GB |
| **Disk** | 200 GB NVMe SSD |
| **Network** | 100 Mbps, static IP, ports 30303/tcp (P2P), 8545/tcp (RPC), 9090/tcp (metrics) |

### Software Prerequisites

- **Rust** 1.75+ (with `cargo`)
- **Git**
- **Docker** & **Docker Compose** (for containerized deployment)
- **RocksDB** system library (for persistent storage backend)

---

## Installation from Source

### 1. Install the Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update stable
```

### 2. Clone the repository

```bash
git clone https://github.com/LucienSong/shell-chain.git
cd shell-chain
```

### 3. Build the release binary

```bash
cargo build --release
```

The binary is produced at `target/release/shell-node`.

Optionally install it system-wide:

```bash
cp target/release/shell-node /usr/local/bin/
```

### 4. Verify the installation

```bash
shell-node version
```

---

## Docker Deployment

Shell-chain ships with a production-ready Docker Compose file (`docker-compose.prod.yml`) that deploys:

- **3 validator nodes** (node1, node2, node3)
- **1 RPC-only node** (rpc-node)
- **Prometheus** metrics collector
- **Grafana** dashboard

### Quick start with Docker

```bash
# Copy and edit environment variables
cp .env.example .env
# Edit .env to set GF_ADMIN_PASSWORD for Grafana

# Start the full stack
docker compose -f docker-compose.prod.yml up -d
```

### Service details

| Service | Ports | Role |
|---------|-------|------|
| `node1` | 8545 (RPC), 8546 (WS), 30303 (P2P) | Genesis-creating validator |
| `node2` | 8555 (RPC), 8556 (WS), 30304 (P2P) | Validator |
| `node3` | 8565 (RPC), 8566 (WS), 30305 (P2P) | Validator |
| `rpc-node` | 8548 (RPC), 8549 (WS), 30306 (P2P) | Read-only RPC with debug/trace APIs |
| `prometheus` | 127.0.0.1:9090 | Metrics collection |
| `grafana` | 3000 | Dashboards (default password: `changeme`) |

### Resource limits

Each node container is limited to **2 CPUs** and **2 GB RAM**. Adjust in `docker-compose.prod.yml` if needed.

### Health checks

All nodes use an `eth_blockNumber` JSON-RPC health check (10s interval, 5s timeout, 3 retries).

### Networks

- **`internal`** — Private bridge for inter-node and monitoring traffic.
- **`frontend`** — Public-facing bridge; only `rpc-node` and `grafana` are attached.

### Persistent volumes

`node1-data`, `node2-data`, `node3-data`, `rpc-data`, `prometheus-data`, `grafana-data`, and a shared `genesis` volume.

---

## Alpha Testnet Deployment

Shell-Chain provides a dedicated `docker-compose.alpha.yml` for joining the public alpha testnet.

### Quick start

```bash
# Copy the environment template and configure
cp .env.example .env
# Edit .env to set your node name, RPC settings, etc.

# Start the alpha testnet node
docker compose -f docker-compose.alpha.yml up -d
```

The `.env.example` file contains all configurable environment variables with sensible defaults. Review and adjust before starting:

```bash
cat .env.example
```

### Verify the node is running

```bash
# Check container status
docker compose -f docker-compose.alpha.yml ps

# Check block height
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Upgrading

```bash
git pull origin main
docker compose -f docker-compose.alpha.yml build
docker compose -f docker-compose.alpha.yml up -d
```

---

## Health & Readiness Endpoints

Shell-Chain exposes HTTP health and readiness probes on the metrics port (default: 9090). These are designed for use with container orchestrators (Docker, Kubernetes) and load balancers.

### GET /health — Liveness Probe

Returns node liveness status. Use this for Docker `HEALTHCHECK` or Kubernetes `livenessProbe`.

```bash
curl http://localhost:9090/health
```

**Response (200 OK):**

```json
{"status":"ok","version":"0.6.0","block_height":1234}
```

The node is considered alive if the process is running and can respond to HTTP requests.

### GET /ready — Readiness Probe

Returns whether the node is ready to serve traffic. Use this for Kubernetes `readinessProbe` or load balancer health checks.

```bash
curl http://localhost:9090/ready
```

**Response (200 OK) — Ready:**

```json
{"ready":true}
```

**Response (503 Service Unavailable) — Not Ready:**

```json
{"ready":false,"reason":"no blocks produced yet"}
```

The node reports not-ready if it has not yet imported or produced any blocks. This prevents routing traffic to nodes that are still syncing.

### Using with Docker Compose

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:9090/health"]
  interval: 10s
  timeout: 5s
  retries: 3
```

---

## Nginx Reverse Proxy

For production deployments, place an nginx reverse proxy in front of the RPC endpoint. Shell-Chain includes a reference configuration at `docker/nginx.conf`.

### Reference configuration

The provided `docker/nginx.conf` handles:

- TLS termination (configure your certificates)
- Rate limiting for RPC requests
- Proxy headers (`X-Real-IP`, `X-Forwarded-For`)
- WebSocket upgrade for `ws://` connections
- CORS headers

### Example setup

```bash
# The alpha testnet docker-compose includes nginx
docker compose -f docker-compose.alpha.yml up -d

# Verify the proxy is working
curl http://testnet.shell.xyz \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Manual nginx setup

If running nginx outside Docker, point it at the RPC endpoint:

```nginx
upstream shell_rpc {
    server 127.0.0.1:8545;
}

server {
    listen 80;
    server_name testnet.shell.xyz;

    location / {
        proxy_pass http://shell_rpc;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## JSON Logging

Shell-Chain supports structured JSON logging for integration with log aggregation systems (ELK, Loki, Datadog, etc.).

### Enable JSON logging

```bash
shell-node run --log-format json --log-level info ...
```

Or in TOML config:

```toml
[logging]
format = "json"
level = "info"
```

### JSON log format

Each log line is a JSON object:

```json
{"timestamp":"2025-01-15T10:30:00Z","level":"INFO","target":"shell_node::consensus","message":"Block produced","block_number":1234,"block_hash":"0xabc...","tx_count":5}
```

### Log rotation

When writing logs to a file, use `logrotate` or a similar tool:

```bash
shell-node run --config config.toml --log-format json 2>&1 | \
  tee -a /var/log/shell-chain/node.log
```

---

## Configuration

Shell-chain is configured via a TOML file, CLI flags, or both. **CLI flags always override config file values.**

Reference configs are provided in `examples/`:

- `examples/config-validator.toml` — Full validator node
- `examples/config-rpc.toml` — Read-only RPC node

### TOML config structure

```toml
[node]
datadir = "/data"               # Data directory for chain storage and keystore
chain_id = 31337                # Chain ID
block_time = 2000               # Block production interval (milliseconds)
keystore = "/data/keystore.json" # Path to encrypted keystore file (validators only)
db = "rocksdb"                  # Storage backend: "memory" or "rocksdb"
pruning = 0                     # State roots to retain (0 = archive mode)
# Storage profile is set via CLI flag: --storage-profile archive|full|light (default: full)
# Individual overrides: --body-retention N, --witness-retention N
node_role = "validator"         # Node role: "validator", "validator-prover", or "prover"

[rpc]
listen_addr = "0.0.0.0:8545"   # JSON-RPC HTTP listen address
ws_enabled = true               # Enable WebSocket RPC
ws_port = 8546                  # WebSocket listen port
cors_origins = ["*"]            # CORS allowed origins (⚠️ restrict in production!)
rate_limit = 100                # Max RPC requests per second per connection
api_modules = ["eth", "net", "web3", "shell"]  # Enabled API namespaces

[p2p]
enabled = true                  # Enable libp2p networking
listen_addr = "0.0.0.0:30303"  # P2P listen address
bootnodes = []                  # Bootstrap peer multiaddrs
enable_mdns = true              # mDNS local peer discovery (disable in cloud)

[consensus]
engine = "poa"                  # Consensus engine (Proof of Authority)
enable_stark_aggregation = false  # Enable async STARK proof generation (see PROVER_GUIDE.md)

[prover]
max_concurrent_proofs = 1       # Parallel proof jobs (validator-prover / prover roles only)
proving_priority = "sequential" # "sequential" or "latest-first"

[metrics]
enabled = true                  # Enable Prometheus metrics
listen_addr = "0.0.0.0:9090"   # Metrics HTTP endpoint

[logging]
level = "info"                  # Log level (trace, debug, info, warn, error)
format = "json"                 # Log format: "text" or "json"
```

### Node roles

Shell-Chain supports three operational roles, set via `node.node_role` or `--node-role`:

| Role | Block production | Proves blocks | Use case |
|------|-----------------|---------------|----------|
| `validator` *(default)* | ✅ | ❌ | Standard block-producing authority node |
| `validator-prover` | ✅ | ✅ (idle slots) | Validator that also contributes proof work |
| `prover` | ❌ | ✅ (full time) | Standalone prover — no keys needed |

A `prover` node syncs the chain, generates `ProofAmendment` proofs, and propagates them via P2P without producing blocks. See [PROVER_GUIDE.md](PROVER_GUIDE.md) for details.

### Validator vs RPC configuration differences

| Setting | Validator | RPC Node |
|---------|-----------|----------|
| `node.keystore` | **Required** (path to keystore) | Omit (no block production) |
| `node.block_time` | Set (e.g., `2000`) | Not needed |
| `rpc.api_modules` | `["eth", "net", "web3", "shell"]` | `["eth", "net", "web3", "shell", "debug", "trace"]` |
| `rpc.rate_limit` | `100` | `50` (lower to protect from abuse) |

### CLI flag reference (for `shell-node run`)

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | — | Path to TOML config file |
| `--datadir <PATH>` | `shell-data` | Data directory |
| `--rpc-addr <ADDR>` | `127.0.0.1:8545` | RPC listen address |
| `--block-time <MS>` | `2000` | Block interval (ms) |
| `--keystore <PATH>` | — | Keystore file path |
| `--chain-id <ID>` | `1337` | Chain ID |
| `--db <BACKEND>` | `memory` | `memory` or `rocksdb` |
| `--ws` | disabled | Enable WebSocket RPC |
| `--ws-port <PORT>` | `8546` | WebSocket port |
| `--p2p` | disabled | Enable P2P networking |
| `--p2p-addr <ADDR>` | `0.0.0.0:30303` | P2P listen address |
| `--bootnode <MULTIADDR>` | — | Bootstrap peer (repeatable) |
| `--bootnodes <ADDRS>` | — | Comma-separated bootstrap peers |
| `--enable-mdns` | disabled | Enable mDNS discovery |
| `--pruning <N>` | `0` | State roots retained (0 = archive) |
| `--storage-profile <PROFILE>` | `full` | Data retention profile: `archive`, `full`, or `light` (see [Block Pruning](BLOCK_PRUNING_AND_COMPRESSION.md)) |
| `--body-retention <N>` | profile default | Override block body retention window (blocks; 0 = forever) |
| `--witness-retention <N>` | profile default | Override PQ witness retention window (blocks; 0 = forever) |
| `--node-role <ROLE>` | `validator` | `validator`, `validator-prover`, or `prover` |
| `--stark` | disabled | Enable STARK proof aggregation |
| `--max-concurrent-proofs <N>` | `1` | Parallel proof jobs (prover roles only) |
| `--checkpoint-url <URL>` | — | Checkpoint sync URL |
| `--rpc-cors <ORIGINS>` | — | CORS allowed origins |
| `--rpc-rate-limit <N>` | — | Rate limit (req/s) |
| `--rpc-api <NS>` | — | API namespaces (comma-separated) |
| `--metrics-addr <ADDR>` | — | Metrics listen address |
| `--log-format <FMT>` | `text` | `text` or `json` |
| `--log-level <LEVEL>` | `info` | Log level (overrides `RUST_LOG`) |

---

## Key Generation

Shell-chain uses **CRYSTALS-Dilithium3** post-quantum signatures (see [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md)). Generate a keypair:

```bash
shell-node key generate --output my-validator-key.json
```

You will be prompted for an encryption password. The command creates an encrypted keystore file containing:

- Dilithium3 public key (1,952 bytes)
- Encrypted secret key (4,032 bytes, encrypted with XChaCha20-Poly1305)
- Derived 20-byte address

### Inspect a keystore

```bash
shell-node key inspect my-validator-key.json
```

This displays the address associated with the keystore without requiring the password.

> **Important:** Back up your keystore file and password securely. There is no key recovery mechanism.

---

## Genesis Initialization

### 1. Create a genesis.json

```json
{
  "chain_id": 1337,
  "chain_name": "shell-testnet",
  "timestamp": 1700000000,
  "gas_limit": 30000000,
  "extra_data": "shell-genesis",
  "consensus": {
    "engine": "poa",
    "authorities": [
      "pq1YOUR_VALIDATOR_ADDRESS_HERE"
    ],
    "block_time_secs": 2,
    "epoch_length": 0
  },
  "alloc": {
    "pq1YOUR_VALIDATOR_ADDRESS_HERE": {
      "balance": "0x3635c9adc5dea00000"
    }
  },
  "boot_nodes": []
}
```

The `authorities` array lists the initial validator addresses (derived from keystores). The `alloc` section pre-funds accounts with an initial balance (in wei, hex-encoded).

### 2. Initialize the data directory

```bash
shell-node init --genesis genesis.json --chain-id 1337 --datadir shell-data
```

This creates the data directory structure and writes the genesis block.

---

## Starting a Node

### Validator node

A validator requires a keystore and produces blocks:

```bash
shell-node run \
  --config examples/config-validator.toml \
  --keystore my-validator-key.json \
  --datadir shell-data \
  --db rocksdb \
  --p2p \
  --p2p-addr 0.0.0.0:30303 \
  --rpc-addr 0.0.0.0:8545 \
  --ws --ws-port 8546 \
  --rpc-api eth,net,web3,shell \
  --metrics-addr 0.0.0.0:9090 \
  --log-format json
```

You will be prompted for the keystore password on startup.

> ⚠️ **Security**: Binding to `0.0.0.0` exposes RPC to all network interfaces. In production, use a reverse proxy (nginx/caddy) with TLS and firewall rules to restrict access. For local-only access, use `127.0.0.1:8545`.

### RPC-only node

An RPC node syncs the chain but does not produce blocks. Omit `--keystore`:

```bash
shell-node run \
  --config examples/config-rpc.toml \
  --datadir shell-data \
  --db rocksdb \
  --p2p \
  --p2p-addr 0.0.0.0:30303 \
  --bootnode /dns4/validator1.example.com/tcp/30303 \
  --rpc-addr 0.0.0.0:8545 \
  --ws --ws-port 8546 \
  --rpc-api eth,net,web3,shell,debug,trace \
  --rpc-cors "*" \
  --rpc-rate-limit 50 \
  --metrics-addr 0.0.0.0:9090
```

### Running as a systemd service

Create `/etc/systemd/system/shell-node.service`:

```ini
[Unit]
Description=Shell-Chain Node
After=network.target

[Service]
Type=simple
User=shellchain
ExecStart=/usr/local/bin/shell-node run \
  --config /etc/shell-chain/config.toml \
  --datadir /var/lib/shell-chain
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shell-node
```

---

## Monitoring Setup

Shell-chain exposes Prometheus metrics when started with `--metrics-addr`. The `monitoring/` directory provides a ready-to-use stack.

### Prometheus

Scrape config (`monitoring/prometheus.yml`):

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "shell-chain"
    static_configs:
      - targets:
          - "node1:9090"
          - "node2:9090"
          - "node3:9090"
          - "rpc-node:9090"
        labels:
          network: "shell-prod"
    metrics_path: "/metrics"
```

### Grafana dashboard

The pre-built **Shell Chain Overview** dashboard (`monitoring/grafana/dashboards/shell-chain.json`) includes 6 panels:

| Panel | Metric | Description |
|-------|--------|-------------|
| Block Height | `shell_block_height` | Current block number per node |
| Blocks Imported | `rate(shell_blocks_imported_total[1m])` | Blocks/sec import rate |
| Transactions Received | `rate(shell_txs_received_total[1m])` | Tx/sec receive rate |
| Peer Count | `shell_peer_count` | Connected peers per node |
| Mempool Size | `shell_tx_pool_size` | Pending transactions |
| Block Production Latency | `shell_block_production_duration_seconds` | Avg and p95 latency |

### Access

- **Prometheus:** `http://localhost:9090`
- **Grafana:** `http://localhost:3000` (default login: `admin` / password from `GF_ADMIN_PASSWORD` env var, default `changeme`)

### Key metrics to alert on

- `shell_block_height` not increasing → block production stalled
- `shell_peer_count == 0` → network isolation
- `shell_tx_pool_size` growing unboundedly → mempool congestion
- `shell_block_production_duration_seconds` p95 > block_time → node falling behind

---

## Upgrading and Maintenance

### Upgrading from source

```bash
cd shell-chain
git pull origin main
cargo build --release
# Stop the running node, replace the binary, restart
sudo systemctl restart shell-node
```

### Upgrading Docker deployment

```bash
cd shell-chain
git pull origin main
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

### Database management

**Export state snapshot:**

```bash
shell-node export-state --datadir shell-data --output snapshot.jsonl
# Export at a specific block:
shell-node export-state --datadir shell-data --block 1000 --output snapshot.jsonl
```

**Import state snapshot:**

```bash
shell-node import-state --datadir shell-data --snapshot snapshot.jsonl
```

**Remove the database:**

```bash
shell-node removedb --datadir shell-data --force
```

### Log rotation

When using `--log-format json`, pipe logs to a file and use `logrotate` or similar:

```bash
shell-node run --config config.toml --log-format json 2>&1 | \
  tee -a /var/log/shell-chain/node.log
```

---

## Troubleshooting

### Node won't start

| Symptom | Cause | Solution |
|---------|-------|----------|
| "genesis not initialized" | Missing `init` step | Run `shell-node init --genesis genesis.json` |
| "keystore not found" | Wrong `--keystore` path | Verify the path to your keystore file |
| "address in use" | Port already bound | Check for conflicting processes on 8545, 30303, or 9090 |
| "wrong password" | Incorrect keystore password | Re-enter password; check for leading/trailing whitespace |

### No blocks produced

- Verify your address is in the `authorities` list in genesis.json.
- Check that `--keystore` is provided and the password is correct.
- Confirm `shell_mining` returns `true` via `eth_mining` RPC call:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_mining","params":[],"id":1}'
```

### Peers not connecting

- Ensure port 30303/tcp is open and reachable.
- Verify `--p2p` flag is enabled.
- Check `--bootnode` multiaddr is correct (format: `/dns4/<host>/tcp/30303` or `/ip4/<ip>/tcp/30303`).
- In cloud environments, disable mDNS (`enable_mdns = false`) and use explicit bootnodes.

### RPC not responding

- Confirm `--rpc-addr` is bound to `0.0.0.0` (not `127.0.0.1`) if accessing remotely.
- Check CORS settings with `--rpc-cors` if calling from a browser.
- Verify the requested API namespace is enabled via `--rpc-api`.

### High memory usage

- Switch from `--db memory` to `--db rocksdb` for production.
- Choose a storage profile: `--storage-profile light` uses a fixed ~1 GB rolling window; `--storage-profile full` (default) keeps TX history forever but replaces PQ witnesses with compact STARK proofs.
- Enable state-root pruning: `--pruning 1000` retains only the last 1,000 state roots. Note: the `light` profile sets its own `keep_recent` default (4096) only when `--pruning` is omitted; pass `--pruning N` explicitly to override.
- Check mempool size via `shell_pendingCount` RPC.

### Metrics not appearing in Grafana

- Verify `--metrics-addr` is set and the port is reachable from Prometheus.
- Check Prometheus targets at `http://localhost:9090/targets`.
- Ensure the `monitoring/prometheus.yml` targets list matches your node addresses.

---

*Last updated: 2026-04-20*
