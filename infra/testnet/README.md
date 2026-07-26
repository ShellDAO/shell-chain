# Shell-Chain Public Testnet Infrastructure

Deployment manifests for the **Shell-Chain wPoA public testnet** (chain_id=10).

## Network Parameters

| Parameter        | Value                                     |
|-----------------|-------------------------------------------|
| Chain ID        | 10                                        |
| Engine          | wPoA (Weighted Proof of Authority)        |
| Block time      | 2 s                                       |
| Validators      | 3 (stake-derived weights: 2, 1, 1)        |
| Currency        | SHELL                                     |
| Native decimals | 18                                        |

## Quick Start

```bash
# 1. Copy genesis file
cp ../../examples/genesis-testnet-wpoa.json ./genesis-testnet-wpoa.json

# 2. Create key directory and generate/copy validator keystores
mkdir -p keys
# … copy node1.key, node2.key, node3.key here

# 3. Set environment
export SHELL_IMAGE=ghcr.io/shelldao/shell-chain:0.27.3
export NODE1_KEY_PATH=./keys/node1.key
export NODE2_KEY_PATH=./keys/node2.key
export NODE3_KEY_PATH=./keys/node3.key
export KEY_PASSWORD=<your-password>
export EXTERNAL_IP=<your-public-ip>

# 4. Launch
docker compose up -d

# 5. Check health
docker compose ps
curl http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  -H 'Content-Type: application/json'
```

## Boot Node Setup

After starting node1, obtain its peer ID:
```bash
docker compose logs node1 | grep "peer_id\|listening"
```

Replace `REPLACE_WITH_NODE1_PEER_ID` in `docker-compose.yml` with the actual peer ID
before starting node2 and node3.

## Monitoring

Prometheus metrics are exposed on ports 9090/9091/9092.
Use `infra/testnet/prometheus.yml` and `infra/testnet/grafana/` for dashboards.

## Kubernetes

For production deployments see `infra/testnet/k8s/`.
