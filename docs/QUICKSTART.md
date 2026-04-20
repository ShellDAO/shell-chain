# Shell-Chain Quickstart Guide

Get a local shell-chain node running in 5 minutes.

> **See also:** [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md) · [Smart Contract Guide](SMART_CONTRACT_GUIDE.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md)

---

## Prerequisites

- **Rust** 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Git**

---

## 1. Clone and build

```bash
git clone https://github.com/LucienSong/shell-chain.git
cd shell-chain
cargo build --release
```

The binary is at `target/release/shell-node`.

For convenience, add it to your PATH:

```bash
export PATH="$PWD/target/release:$PATH"
```

---

## 2. Generate a key

Shell-chain uses post-quantum Dilithium3 signatures (see [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md)). Generate a validator keypair:

```bash
shell-node key generate --output my-key.json
```

You will be prompted to set an encryption password. Save it — you'll need it to start the node.

View the derived address:

```bash
shell-node key inspect my-key.json
```

Note the displayed address (e.g., `pq1...`). You'll use it in the genesis file.

---

## 3. Initialize genesis

Create a `genesis.json` with your address as the sole validator and pre-fund it:

```json
{
  "chain_id": 1337,
  "chain_name": "shell-local",
  "timestamp": 1700000000,
  "gas_limit": 30000000,
  "extra_data": "shell-genesis",
  "consensus": {
    "engine": "poa",
    "authorities": [
      "pq1YOUR_ADDRESS_HERE"
    ],
    "block_time_secs": 2,
    "epoch_length": 0
  },
  "alloc": {
    "pq1YOUR_ADDRESS_HERE": {
      "balance": "0x3635c9adc5dea00000"
    }
  },
  "boot_nodes": []
}
```

Replace `pq1YOUR_ADDRESS_HERE` with the address from Step 2. The balance `0x3635c9adc5dea00000` is 1,000 ETH in wei.

Initialize the data directory:

```bash
shell-node init --genesis genesis.json --chain-id 1337 --datadir shell-data
```

---

## 4. Start a single node

```bash
shell-node run \
  --datadir shell-data \
  --keystore my-key.json \
  --rpc-addr 127.0.0.1:8545 \
  --block-time 2000 \
  --chain-id 1337 \
  --db memory \
  --rpc-api eth,net,web3,shell \
  --storage-profile full
```

Enter your keystore password when prompted. You should see log output showing blocks being produced every 2 seconds.

---

## 5. Check block height

Open a new terminal and query the node:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Expected response:

```json
{"jsonrpc":"2.0","id":1,"result":"0x5"}
```

The block number should increase every 2 seconds.

---

## 6. Check your balance

Using the CLI:

```bash
shell-node account balance pq1YOUR_ADDRESS_HERE --rpc-url http://127.0.0.1:8545
```

Or via curl:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["pq1YOUR_ADDRESS_HERE","latest"],"id":1}'
```

Expected result: `"0x3635c9adc5dea00000"` (1,000 ETH).

---

## 7. Send a test transaction

Generate a second key to use as the recipient:

```bash
shell-node key generate --output recipient-key.json
shell-node key inspect recipient-key.json
# Note the recipient address
```

Send 1 ETH (1000000000000000000 wei) from your funded account:

```bash
shell-node tx send \
  --to pq1RECIPIENT_ADDRESS \
  --value 1000000000000000000 \
  --keystore my-key.json \
  --rpc-url http://127.0.0.1:8545
```

Enter your keystore password when prompted. The command outputs the transaction hash.

Verify the recipient received the funds:

```bash
shell-node account balance pq1RECIPIENT_ADDRESS --rpc-url http://127.0.0.1:8545
```

---

## 8. Explore the API

Query node information:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getNodeInfo","params":[],"id":1}' | python3 -m json.tool
```

List validators:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getValidators","params":[],"id":1}'
```

Check client version:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
```

---

## Alpha Testnet

Join the public alpha testnet:

### Using Docker

```bash
cp .env.example .env
docker compose -f docker-compose.alpha.yml up -d
```

### Health Check

```bash
curl http://localhost:9090/health
# {"status":"ok","version":"0.6.0","block_height":...}

curl http://localhost:9090/ready
# {"ready":true} or {"ready":false,"reason":"..."}
```

For more details on alpha testnet operations, see the [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md).

---

## Next Steps

- **Run a multi-node testnet:** See the [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) for Docker deployment with 3 validators + monitoring.
- **Choose a storage profile:** `--storage-profile archive` (full history), `full` (default — TX history forever, STARK replaces PQ witnesses), or `light` (~2 h rolling window). See [Block Pruning & Compression](BLOCK_PRUNING_AND_COMPRESSION.md).
- **Deploy smart contracts:** See [Smart Contract Guide](SMART_CONTRACT_GUIDE.md) for deploying Solidity/Vyper contracts with Hardhat or Foundry.
- **Full API reference:** See [JSON-RPC API Reference](JSON_RPC_API.md) for all 61 RPC methods.
- **Understand the cryptography:** See [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) for details on Dilithium3, key formats, and quantum resistance.
- **Deploy a contract:** Use `shell-node tx deploy --code 0x... --keystore my-key.json`.
- **Make a read-only call:** Use `shell-node tx call --to pq1CONTRACT_ADDRESS --data 0x...`.
- **Monitor with Grafana:** Start the full stack with `docker compose -f docker-compose.prod.yml up -d` and open `http://localhost:3000`.

---

*Last updated: 2026-04-20*
