# Genesis File Format

> Shell Chain — Genesis JSON specification (F-PQ1-ONLY)

---

## Overview

The genesis file defines the initial chain state: chain identity, consensus parameters,
pre-funded accounts (`alloc`), and boot node addresses. It is passed to `shell-node init`
before the first block is produced.

**Key requirement (F-PQ1-ONLY):** All addresses in the genesis file must use the canonical
`pq1...` bech32m format. Legacy `0x` hex addresses are rejected by the parser.

---

## Full Schema

```json
{
  "chain_id": <u64>,
  "chain_name": "<string>",
  "network_type": "Mainnet" | "Testnet" | "Devnet",
  "timestamp": <u64 — Unix seconds for block 0>,
  "gas_limit": <u64>,
  "extra_data": "<string — arbitrary label, max 32 bytes>",
  "consensus": { ... },
  "alloc": { "<pq1-address>": { "balance": "<hex-wei>", "nonce": <u64> }, ... },
  "boot_nodes": [ "<multiaddr>", ... ]
}
```

---

## Field Reference

### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chain_id` | `u64` | ✅ | EIP-155 chain ID. Testnet: `10`. Devnet: `1337`. |
| `chain_name` | `string` | ✅ | Human-readable chain name (e.g. `"shell-testnet-wpoa"`). |
| `network_type` | enum | ✅ | `"Mainnet"`, `"Testnet"`, or `"Devnet"`. |
| `timestamp` | `u64` | ✅ | Genesis block timestamp (Unix seconds). |
| `gas_limit` | `u64` | ✅ | Block gas limit for block 0. Recommend `30_000_000`. |
| `extra_data` | `string` | ✅ | Arbitrary genesis label, stored in block 0 `extra_data`. |
| `consensus` | object | ✅ | Consensus engine configuration (see below). |
| `alloc` | object | ✅ | Initial account balances. Keys are `pq1...` addresses. |
| `boot_nodes` | array | ✅ | P2P multiaddrs for bootstrap nodes. |

### `consensus` — PoA

```json
{
  "engine": "poa",
  "authorities": ["pq1...", "pq1...", ...],
  "block_time_secs": 2,
  "max_future_secs": 60
}
```

### `consensus` — PoA / wPoA (Proof of Authority)

```json
{
  "engine": "poa",
  "authorities": ["pq1...", "pq1...", "pq1..."],
  "block_time_secs": 2,
  "max_future_secs": 60,
  "epoch_length": 0
}
```

To enable the optional Weighted PoA extension:

```json
{
  "engine": "wpoa",
  "authorities": ["pq1...", "pq1...", "pq1..."],
  "weights": [2, 1, 1],
  "block_time_secs": 2,
  "max_future_secs": 60,
  "epoch_length": 0
}
```

| Field | Description |
|-------|-------------|
| `engine` | `"poa"` or `"wpoa"`. |
| `authorities` | Array of `pq1...` validator addresses (must match keystore addresses). |
| `weights` | (wPoA only) Integer vote weights, one per authority. Must sum ≥ 2/3 for quorum. |
| `block_time_secs` | Target block time in seconds. |
| `max_future_secs` | Maximum allowed clock skew for incoming blocks. |
| `epoch_length` | Blocks per epoch for weight recalculation. `0` = disabled (fixed weights). |

### `alloc`

```json
"alloc": {
  "pq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqy0vusna": {
    "balance": "0x3635c9adc5dea00000",
    "nonce": 0
  }
}
```

| Field | Description |
|-------|-------------|
| key | `pq1...` bech32m address (canonical format). **`0x` addresses are rejected.** |
| `balance` | Initial balance in wei, hex-encoded with `0x` prefix. |
| `nonce` | Initial account nonce (almost always `0`). |

**Common balances:**

| Balance | Wei (hex) |
|---------|-----------|
| 1 SHELL | `0xde0b6b3a7640000` |
| 1,000 SHELL | `0x3635c9adc5dea00000` |
| 1,000,000 SHELL | `0xd3c21bcecceda1000000` |

### `boot_nodes`

Standard libp2p multiaddrs with the `/p2p/<PeerId>` suffix:

```
/dns4/node1.example.com/tcp/30303/p2p/12D3KooW...
/ip4/1.2.3.4/tcp/30303/p2p/12D3KooW...
```

---

## Full Example (testnet wPoA)

```json
{
  "chain_id": 10,
  "chain_name": "shell-testnet-wpoa",
  "network_type": "Testnet",
  "timestamp": 1700000000,
  "gas_limit": 30000000,
  "extra_data": "shell-testnet-wpoa-genesis",
  "consensus": {
    "engine": "wpoa",
    "authorities": [
      "pq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqy0vusna",
      "pq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg7j66z6",
      "pq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv3ccudq"
    ],
    "weights": [2, 1, 1],
    "block_time_secs": 2,
    "max_future_secs": 60,
    "epoch_length": 0
  },
  "alloc": {
    "pq1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqy0vusna": {
      "balance": "0x3635c9adc5dea00000",
      "nonce": 0
    },
    "pq1q8eel4h9r2kc3ah5ee4t3qnj088llwfzvc2lgdcq": {
      "balance": "0xde0b6b3a7640000",
      "nonce": 0
    },
    "pq1q9cfj7tsc5vp9hp6qyx86qd4pcx30hreeqdqsp8a": {
      "balance": "0xde0b6b3a7640000",
      "nonce": 0
    }
  },
  "boot_nodes": [
    "/dns4/node1.shell-testnet.example.com/tcp/30303/p2p/REPLACE_WITH_NODE1_PEER_ID"
  ]
}
```

---

## Creating a Genesis File

### 1. Manual

Write or copy an example from `examples/genesis-testnet-wpoa.json`.

### 2. CLI (`genesis add-alloc`)

```bash
# Start from a template
cp examples/genesis-testnet-wpoa.json my-genesis.json

# Add a faucet account
shell-node genesis add-alloc \
    --genesis my-genesis.json \
    --address pq1<faucet-address> \
    --balance 1000000000000000000000000
```

### 3. genesis-builder agent

```bash
node agents/genesis-builder/genesis-builder.mjs \
    --keystores /opt/shell/test-accounts \
    --genesis   examples/genesis-testnet-wpoa.json \
    --balance   1000000000000000000 \
    --output    my-genesis.json
```

### 4. Initialize the node

```bash
shell-node init --genesis my-genesis.json --data-dir /var/lib/shell
```

---

## Validation Rules

The node enforces these rules when loading a genesis file (F-082):

1. File size ≤ 10 MB.
2. All `alloc` addresses are valid `pq1...` bech32m addresses.
3. `chain_id` is non-zero.
4. `consensus.authorities` are non-empty and all valid `pq1...` addresses.
5. `consensus.weights` (wPoA) has the same length as `authorities`.
6. `timestamp` is reasonable (not zero, not far in the future).

---

## References

- `crates/cli/src/commands/genesis.rs` — `genesis add-alloc` subcommand
- `crates/core/src/genesis.rs` — Genesis struct and parser
- `examples/genesis-testnet-wpoa.json` — Production testnet template
- `agents/genesis-builder/` — Batch alloc generator
- `docs/TESTNET_OPERATOR_GUIDE.md` — Full testnet setup guide
