# Shell Chain Quickstart Guide

Get a local Shell Chain node running from source and verify it with JSON-RPC.

> **See also:** [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md) · [Smart Contract Guide](SMART_CONTRACT_GUIDE.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md)

---

## Prerequisites

- **Rust** 1.75+ from the official installer: <https://www.rust-lang.org/tools/install>
- **Git**
- **curl** and **python3** for the verification commands

---

## 1. Clone and build

```bash
git clone https://github.com/ShellDAO/shell-chain.git
cd shell-chain
cargo build --release -p shell-cli --bin shell-node
```

The binary is at `target/release/shell-node`.

For convenience, add it to your PATH:

```bash
export PATH="$PWD/target/release:$PATH"
```

---

## 2. Generate a validator key

Shell Chain uses ML-DSA-65 as its primary post-quantum signature scheme (see [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md)). Generate a validator keypair:

```bash
printf 'dev-password\n' > .quickstart-password
shell-node --password-file .quickstart-password key generate \
  --algorithm mldsa65 \
  --output my-key.json
chmod 600 my-key.json
```

For an interactive run, omit `--password-file` and enter the password at the prompt. Keep the password and keystore; both are required to start the node.

View the derived address:

```bash
shell-node key inspect my-key.json
```

Note the displayed address. Shell Chain user-facing addresses are canonical `0x` + 64 lowercase hex strings.

---

## 3. Initialize genesis

Set a shell variable to the inspected address and create a `genesis.json` with that address as the sole validator and pre-funded account:

```bash
ADDR=$(shell-node key inspect my-key.json | awk '/Address:/ {print $2}')
```

```bash
cat > genesis.json <<EOF
{
  "chain_id": 1337,
  "chain_name": "shell-local",
  "network_type": "Dev",
  "timestamp": $(date +%s),
  "gas_limit": 30000000,
  "extra_data": "shell-genesis",
  "consensus": {
    "engine": "poa",
    "authorities": [
      "$ADDR"
    ],
    "block_time_secs": 2,
    "epoch_length": 0
  },
  "alloc": {
    "$ADDR": {
      "balance": "0x3635c9adc5dea00000"
    }
  },
  "boot_nodes": []
}
EOF
```

The balance `0x3635c9adc5dea00000` is 1,000 SHELL in wei.

The same file with placeholders looks like this:

```json
{
  "chain_id": 1337,
  "chain_name": "shell-local",
  "network_type": "Dev",
  "timestamp": 1735689600,
  "gas_limit": 30000000,
  "extra_data": "shell-genesis",
  "consensus": {
    "engine": "poa",
    "authorities": [
      "0x<YOUR_ADDRESS_64_HEX>"
    ],
    "block_time_secs": 2,
    "epoch_length": 0
  },
  "alloc": {
    "0x<YOUR_ADDRESS_64_HEX>": {
      "balance": "0x3635c9adc5dea00000"
    }
  },
  "boot_nodes": []
}
```

Initialize the data directory:

```bash
shell-node --datadir shell-data init --genesis genesis.json --chain-id 1337 --network dev
```

---

## 4. Start a single node

```bash
shell-node run \
  --datadir shell-data \
  --keystore my-key.json \
  --password-file .quickstart-password \
  --rpc-addr 127.0.0.1:8545 \
  --block-time 2000 \
  --max-idle-interval 0 \
  --network dev \
  --chain-id 1337 \
  --db memory \
  --rpc-api eth,net,web3,shell \
  --storage-profile full
```

You should see log output showing blocks being produced every 2 seconds. `--max-idle-interval 0` keeps empty-block production enabled for the tutorial; omit it in normal development if you prefer the default idle-skip behavior.

> **Storage backend:** `--network dev` defaults to in-memory storage. This guide passes `--db memory` explicitly so the local tutorial leaves no database behind. For persistent local development, use `--db rocksdb`.

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
shell-node account balance "$ADDR" --rpc-url http://127.0.0.1:8545
```

Or via curl:

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}"
```

Expected result: `"0x3635c9adc5dea00000"` (1,000 ETH).

---

## 7. Send a test transaction

Generate a second key to use as the recipient:

```bash
shell-node --password-file .quickstart-password key generate \
  --algorithm mldsa65 \
  --output recipient-key.json
chmod 600 recipient-key.json
RECIPIENT=$(shell-node key inspect recipient-key.json | awk '/Address:/ {print $2}')
```

Send 1 ETH (1000000000000000000 wei) from your funded account:

```bash
TX_HASH=$(shell-node tx send \
  --to "$RECIPIENT" \
  --value 1000000000000000000 \
  --keystore my-key.json \
  --password-file .quickstart-password \
  --rpc-url http://127.0.0.1:8545)
```

The password file unlocks the keystore. The command stores the submitted
transaction hash in `TX_HASH`.

Query its receipt to check inclusion and execution:

```bash
shell-node tx receipt "$TX_HASH" --rpc-url http://127.0.0.1:8545
```

If the result is `null`, wait for a block and repeat the receipt query. A receipt
with `status: "0x1"` confirms successful execution; `status: "0x0"` means execution
failed. Receipt queries are read-only and can be repeated with the same hash.

After a successful receipt, verify the recipient received the funds:

```bash
shell-node account balance "$RECIPIENT" --rpc-url http://127.0.0.1:8545
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

## Public Testnet

Public testnet parameters:

| Parameter | Value |
|-----------|-------|
| Chain ID | `10` |
| RPC | `https://testnet-rpc.shell.org` |
| WebSocket | `wss://testnet-rpc.shell.org/ws` |
| Explorer | `https://explorer.shell.org` |
| Faucet | `https://faucet.shell.org` |

For validator or read-only node operations, see the [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md).

---

## Next Steps

- **Run a multi-node testnet:** See the [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) for systemd-based validator setup with monitoring.
- **Choose a storage profile:** `--storage-profile archive` (full history), `full` (default — TX history forever, STARK replaces PQ witnesses), or `light` (~2 h rolling window). See [Block Pruning & Compression](BLOCK_PRUNING_AND_COMPRESSION.md).
- **Deploy smart contracts:** See [Smart Contract Guide](SMART_CONTRACT_GUIDE.md) for deploying Solidity/Vyper contracts with Hardhat or Foundry.
- **Full API reference:** See [JSON-RPC API Reference](JSON_RPC_API.md) for all 79 RPC methods.
- **Understand the cryptography:** See [PQ Crypto Guide](PQ_CRYPTO_GUIDE.md) for details on ML-DSA-65, key formats, and quantum resistance.
- **Deploy a contract:** Use `shell-node tx deploy --code 0x... --keystore my-key.json`.
- **Make a read-only call:** Use `shell-node tx call --to 0x<CONTRACT_ADDRESS_64_HEX> --data 0x...`.
- **Monitor with Grafana:** Start the full stack with `docker compose -f docker-compose.prod.yml up -d` and open `http://localhost:3000`.

---

*Last updated: 2026-06-17*
