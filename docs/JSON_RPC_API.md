# Shell-Chain JSON-RPC API Reference

Complete reference for the shell-chain JSON-RPC API. All methods follow the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) specification.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md) · [System Contracts](SYSTEM_CONTRACTS.md) · [Prover Guide](PROVER_GUIDE.md)

---

## Table of Contents

- [Connection](#connection)
- [CORS Configuration](#cors-configuration)
- [API Namespace Whitelist](#api-namespace-whitelist)
- [Rate Limiting](#rate-limiting)
- [WebSocket Support](#websocket-support)
- [eth\_ Namespace](#eth_-namespace)
- [net\_ Namespace](#net_-namespace)
- [web3\_ Namespace](#web3_-namespace)
- [shell\_ Namespace](#shell_-namespace)
- [debug\_ Namespace](#debug_-namespace)
- [trace\_ Namespace](#trace_-namespace)

---

## Connection

**HTTP endpoint** (default):
```
http://127.0.0.1:8545
```

**WebSocket endpoint** (when `--ws` is enabled):
```
ws://127.0.0.1:8546
```

All requests use POST with `Content-Type: application/json`.

**Address note:** RPC input and output addresses use canonical 32-byte `0x` + 64 lowercase hex throughout the current codebase.

## CORS Configuration

Control cross-origin access with `--rpc-cors`:

```bash
# Allow all origins
shell-node run --rpc-cors "*"

# Allow specific origins (comma-separated)
shell-node run --rpc-cors "http://localhost:3000,https://app.example.com"
```

Or in TOML config:
```toml
[rpc]
cors_origins = ["http://localhost:3000", "https://app.example.com"]
```

## API Namespace Whitelist

Control which API namespaces are exposed with `--rpc-api`:

```bash
# Validators (minimal surface)
shell-node run --rpc-api eth,net,web3,shell

# RPC nodes (full API)
shell-node run --rpc-api eth,net,web3,shell,debug,trace
```

Available namespaces: `eth`, `net`, `web3`, `shell`, `debug`, `trace`

If `--rpc-api` is not specified, all namespaces registered by the node are available.

## Rate Limiting

Per-connection rate limiting is available via `--rpc-rate-limit`:

```bash
shell-node run --rpc-rate-limit 100  # 100 requests/sec per connection
```

Or in TOML config:
```toml
[rpc]
rate_limit = 100
```

When the limit is exceeded, the server returns an HTTP 429 response.

## WebSocket Support

Enable the WebSocket server with `--ws`:

```bash
shell-node run --ws --ws-port 8546
```

The WebSocket endpoint supports all the same JSON-RPC methods as HTTP, plus real-time PubSub subscriptions and filter-based polling via `eth_newFilter`, `eth_newBlockFilter`, and `eth_getFilterChanges`.

### eth_subscribe (WebSocket only)

Subscribe to live events. Returns a subscription ID.

**Subscription types:**

| Type | Description |
|------|-------------|
| `newHeads` | Pushes new block headers when blocks are produced or imported |
| `logs` | Pushes log events matching a filter (address, topics) |
| `newPendingTransactions` | Pushes transaction hashes as they enter the mempool |
| `syncing` | Pushes sync status changes (syncing/not syncing) |

**Example — newHeads:**

```bash
wscat -c ws://127.0.0.1:8546

> {"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}
< {"jsonrpc":"2.0","id":1,"result":"0x1"}
< {"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"0x1","result":{"number":"0xa","hash":"0x...","parentHash":"0x...","timestamp":"0x..."}}}
```

**Example — logs with filter:**

```bash
> {"jsonrpc":"2.0","id":2,"method":"eth_subscribe","params":["logs",{"address":"0x...","topics":["0xddf2..."]}]}
< {"jsonrpc":"2.0","id":2,"result":"0x2"}
```

**Example — newPendingTransactions:**

```bash
> {"jsonrpc":"2.0","id":3,"method":"eth_subscribe","params":["newPendingTransactions"]}
< {"jsonrpc":"2.0","id":3,"result":"0x3"}
< {"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"0x3","result":"0xabc123..."}}
```

### eth_unsubscribe (WebSocket only)

Cancel an active subscription.

```bash
> {"jsonrpc":"2.0","id":4,"method":"eth_unsubscribe","params":["0x1"]}
< {"jsonrpc":"2.0","id":4,"result":true}
```

**Limits:** Maximum 1024 global subscriptions, 16 per connection. Connections are auto-disconnected after repeated lag events.

---

## eth_ Namespace

Standard Ethereum-compatible JSON-RPC methods.

### eth_blockNumber

Returns the current block height.

**Parameters:** None

**Returns:** `String` — Hex-encoded block number.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x1a"}
```

---

### eth_chainId

Returns the chain ID.

**Parameters:** None

**Returns:** `String` — Hex-encoded chain ID.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x539"}
```

---

### eth_syncing

Returns sync status. A node may temporarily report syncing while block range catch-up is in flight; otherwise it returns `false`.

**Parameters:** None

**Returns:** `Boolean | Object` — `false` when not syncing, or a sync progress object when the node is catching up.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":false}
```

---

### eth_mining

Returns whether the node is producing blocks.

**Parameters:** None

**Returns:** `Boolean` — `true` if the node has a validator keystore loaded.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_mining","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":true}
```

---

### eth_hashrate

Returns mining hashrate. Always `"0x0"` (PoA consensus, no mining).

**Parameters:** None

**Returns:** `String` — Always `"0x0"`.

---

### eth_accounts

Returns managed accounts. Always empty — the node does not hold user private keys.

**Parameters:** None

**Returns:** `Array` — Always `[]`.

---

### eth_protocolVersion

Returns the protocol version.

**Parameters:** None

**Returns:** `String` — `"0x45"` (Cancun-compatible).

---

### eth_gasPrice

Returns the current base fee.

**Parameters:** None

**Returns:** `String` — Hex-encoded base fee in wei for the latest chain state.
The exact value changes over time as blocks are produced.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x5f7609"}
```

---

### eth_maxPriorityFeePerGas

Returns the suggested priority fee. Always `"0x0"` on this PoA chain.

**Parameters:** None

**Returns:** `String` — `"0x0"`.

---

### eth_feeHistory

Returns historical base fee and gas usage data.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block count (hex) — max 1024 |
| 2 | `String` | Yes | Newest block (block tag or hex number) |
| 3 | `Array<Number>` | No | Reward percentiles |

**Returns:** Object with `oldestBlock`, `baseFeePerGas`, `gasUsedRatio`, `reward`.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_feeHistory","params":["0x5","latest",[]],"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "oldestBlock": "0x15",
    "baseFeePerGas": ["0x8e4f6f","0x7c4681","0x6c1761","0x5f7609","0x53a8d3","0x48c470"],
    "gasUsedRatio": [0.0, 0.0, 0.0, 0.0, 0.0],
    "reward": []
  }
}
```

---

### eth_getBalance

Returns the balance of an address.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address (`0x...` canonical) |
| 2 | `String` | No | Block tag (`"latest"`, `"earliest"`, `"pending"`, `"safe"`, `"finalized"`, or hex number) |

**Returns:** `String` — Hex-encoded balance in wei.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xYOUR_ADDRESS_HERE","latest"],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x3635c9adc5dea00000"}
```

---

### eth_getTransactionCount

Returns the nonce (transaction count) for an address.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address (`0x...` canonical) |
| 2 | `String` | No | Block tag |

**Returns:** `String` — Hex-encoded nonce.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["0xYOUR_ADDRESS_HERE","latest"],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x0"}
```

---

### eth_getBlockByNumber

Returns a block by number.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block tag or hex number |
| 2 | `Boolean` | Yes | `true` for full transaction objects, `false` for hashes only |

Supported block tags: `"latest"`, `"earliest"`, `"pending"`, `"safe"`, `"finalized"`.

When `"pending"` is requested, a pseudo-block is constructed from the current mempool.

**Returns:** `Object|null` — Block object or `null` if not found.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "number": "0x1a",
    "hash": "0xabc...",
    "parentHash": "0xdef...",
    "timestamp": "0x65a5f200",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x0",
    "compressionLayer": 1,
    "pruningStatus": "pruned",
    "transactions": []
  }
}
```

Shell block responses include STARK storage metadata in addition to Ethereum
compatibility fields. `compressionLayer` is the highest accepted compression
layer currently known for the block, including pointer blocks in a contiguous
range. `pruningStatus` reports the local witness state (`unpruned`,
`compressedWitnessRetained`, `pruned`, `notWitnessed`, `pending`, or `unknown`).
STARK proof bytes are no longer carried in block header `extraData`; canonical
settlements use a `StarkReward` system transaction whose `input` contains the
proof payload, while source blocks expose full-proof or pointer metadata.

---

### eth_getBlockByHash

Returns a block by hash.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block hash (0x-prefixed, 32 bytes) |
| 2 | `Boolean` | Yes | `true` for full tx objects, `false` for hashes |

**Returns:** `Object|null` — Block object or `null`.

---

### eth_getTransactionByHash

Returns a transaction by hash. Checks the mempool first, then on-chain storage.
Shell reward records are first-class system transactions, so block gas rewards
and STARK rewards are also discoverable by deterministic transaction hash.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Transaction hash (0x-prefixed, 32 bytes) |

**Returns:** `Object|null` — Transaction object or `null`.

Shell-specific transaction metadata:

| Field | Description |
|---|---|
| `shellType` | Product-readable type: `transfer`, `contractCreate`, `contractCall`, `aaBatch`, `blockGasReward`, or `starkReward` |
| `rewardKind` | Present for reward system transactions: `blockGasReward` or `starkReward` |
| `rewardLayer` | STARK layer for prover rewards, hex encoded |
| `rewardSourceHash` | Parent block, source range, or artifact hash used to derive the reward |
| `originalSize` / `compressedSize` | STARK compression accounting, hex byte counts |

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0xabc123..."],"id":1}'
```

---

### eth_getTransactionReceipt

Returns the receipt of a mined transaction.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Transaction hash |

**Returns:** `Object|null` — Receipt object (includes `status`, `gasUsed`, `logs`, `blockNumber`, `shellType`, `rewardKind`, etc.) or `null` if not yet mined.

---

### eth_sendRawTransaction

Submits a signed transaction. Accepts RLP-encoded or JSON-encoded transaction bytes.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Hex-encoded signed transaction data |

**Returns:** `String` — Transaction hash.

**Validation:** The transaction's `max_fee_per_gas` must be ≥ the current base fee.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x...signed_tx_bytes..."],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0xabc123..."}
```

---

### eth_call

Executes a read-only call against the EVM (no state changes).

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Call request: `{from?, to, data?, value?, gas?}` |
| 2 | `String` | No | Block tag |

**Returns:** `String` — Hex-encoded return data.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xCONTRACT_ADDRESS","data":"0x..."},"latest"],"id":1}'
```

---

### eth_estimateGas

Estimates gas for a transaction. Returns `gas_used × 1.2` with a minimum of 21,000.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Call request: `{from?, to?, data?, value?}` |

**Returns:** `String` — Hex-encoded gas estimate.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_estimateGas","params":[{"to":"0xRECIPIENT_ADDRESS","value":"0xde0b6b3a7640000"}],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x5208"}
```

---

### eth_createAccessList

Creates an EIP-2930 access list for a transaction.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Call request |
| 2 | `String` | No | Block tag |

**Returns:** Object with `accessList` and `gasUsed`.

---

### eth_getCode

Returns the bytecode at an address.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address |
| 2 | `String` | No | Block tag |

**Returns:** `String` — Hex-encoded bytecode, or `"0x"` for accounts without
runtime code.

---

### eth_getStorageAt

Returns a storage slot value.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address |
| 2 | `String` | Yes | Storage position (hex-encoded, 32-byte key) |
| 3 | `String` | No | Block tag |

**Returns:** `String` — Zero-padded 32-byte hex value.

---

### eth_getLogs

Returns logs matching a filter.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Filter: `{address?, topics?, fromBlock?, toBlock?}` |

**Returns:** `Array` — Log objects with `address`, `topics`, `data`, `blockNumber`, `blockHash`, `transactionHash`, `transactionIndex`, `logIndex`, `removed`.

Uses bloom filters for fast block-level filtering. The block range is capped at `MAX_BLOCK_RANGE` to prevent DoS.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getLogs","params":[{"fromBlock":"0x0","toBlock":"latest"}],"id":1}'
```

---

### eth_newFilter

Creates a poll-based log filter.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Filter: `{address?, topics?, fromBlock?, toBlock?}` |

**Returns:** `String` — Filter ID.

---

### eth_newBlockFilter

Creates a poll-based block filter.

**Parameters:** None

**Returns:** `String` — Filter ID.

---

### eth_getFilterChanges

Returns changes since last poll for a filter.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Filter ID |

**Returns:** `Array` — Logs (for log filters) or block hashes (for block filters).

---

### eth_getFilterLogs

Re-queries all logs matching a filter's criteria.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Filter ID |

**Returns:** `Array` — Log objects.

---

### eth_uninstallFilter

Removes a filter.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Filter ID |

**Returns:** `Boolean` — `true` if the filter was removed.

---

### eth_blobBaseFee

Returns the current blob gas price (EIP-4844).

**Parameters:** None

**Returns:** `String` — Hex-encoded blob gas price, calculated from `excess_blob_gas`.

---

### eth_sign *(not supported)*

Returns error code `-32601`. The node does not hold private keys — sign transactions client-side with the CLI or SDK.

### eth_signTransaction *(not supported)*

Returns error code `-32601`. Same reason as `eth_sign`.

### eth_getCompilers

Returns `[]`. This legacy Ethereum method is retained for compatibility.

---

## net_ Namespace

### net_version

Returns the network/chain ID as a decimal string.

**Parameters:** None

**Returns:** `String` — Chain ID (e.g., `"1337"`).

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"1337"}
```

---

### net_listening

Returns whether the node is accepting connections. Always `true`.

**Parameters:** None

**Returns:** `Boolean` — `true`.

---

### net_peerCount

Returns the number of connected peers.

**Parameters:** None

**Returns:** `String` — Hex-encoded peer count (e.g., `"0x3"`).

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

---

## web3_ Namespace

### web3_clientVersion

Returns the client identifier string.

**Parameters:** None

**Returns:** `String` — `"shell-chain/0.22.2"`.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"shell-chain/0.22.2"}
```

---

### web3_sha3

Returns the Keccak-256 hash of the given data.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Hex-encoded data (max 32 KB) |

**Returns:** `String` — Hex-encoded Keccak-256 hash.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_sha3","params":["0x68656c6c6f"],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"}
```

---

## shell_ Namespace

Shell-chain custom extensions for post-quantum features, validator governance, and node information.

### shell_getPqPubkey

Returns the post-quantum public key associated with an address.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address (`0x...` canonical) |

**Returns:** `String|null` — Hex-encoded PQ public key, or `null` if not found.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getPqPubkey","params":["0xYOUR_ADDRESS_HERE"],"id":1}'
```

---

### shell_pendingCount

Returns the number of pending transactions in the mempool.

**Parameters:** None

**Returns:** `String` — Hex-encoded count.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_pendingCount","params":[],"id":1}'
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x0"}
```

---

### shell_sendTransaction

Submits a pre-signed shell-chain transaction.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Signed transaction object |

**Returns:** `String` — Transaction hash.

---

### shell_getValidators

Returns the current validator set.

**Parameters:** None

**Returns:** `Array<String>` — List of validator addresses.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getValidators","params":[],"id":1}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002"
  ]
}
```

---

### shell_getValidatorStatus

Returns whether an address is a validator.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address |

**Returns:** Object:
```json
{
  "address": "0x...",
  "isValidator": true
}
```

---

### shell_proposeAddValidator

Submits a governance transaction to add a validator (requires the node to have a proposer keystore).

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address to add |

**Returns:** `String` — Transaction hash.

---

### shell_proposeRemoveValidator

Submits a governance transaction to remove a validator.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address to remove |

**Returns:** `String` — Transaction hash.

---

### shell_encodeAddValidator

Generates calldata for the validator management system contract (does not submit a transaction).

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address to add |

**Returns:** `String` — Hex-encoded calldata.

---

### shell_encodeRemoveValidator

Generates calldata for validator removal.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Address to remove |

**Returns:** `String` — Hex-encoded calldata.

---

### shell_estimateGovernanceGas

Estimates gas for a governance operation.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Operation: `"addValidator"`, `"removeValidator"`, `"getValidators"`, or `"isValidator"` |

**Returns:** `String` — Hex-encoded gas estimate.

---

### shell_getGovernanceInfo

Returns governance configuration.

**Parameters:** None

**Returns:**
```json
{
  "validatorCount": 3,
  "validators": ["0x...", "0x...", "0x..."],
  "systemContractAddress": "0x0000000000000000000000000000000000000001",
  "proposalGasLimit": 100000
}
```

---

### shell_getNodeInfo

Returns node status information.

**Parameters:** None

**Returns:**
```json
{
  "version": "ShellChain/v0.22.2/rust",
  "chainId": 1337,
  "blockHeight": 42,
  "peerCount": 0,
  "txPoolSize": 5,
  "isMining": true,
  "uptime": 3600,
  "baseFee": "0x5f7609"
}
```

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getNodeInfo","params":[],"id":1}'
```

---

### shell_getNetworkStats

Returns P2P network statistics.

**Parameters:** None

**Returns:**
```json
{
  "peerCount": 0,
  "protocolVersion": "shell/1.0.0",
  "listeningAddress": "/ip4/0.0.0.0/tcp/30303",
  "protocols": ["gossipsub", "kademlia", "mdns"]
}
```

---

### shell_getChainStats

Returns aggregate chain statistics. `totalTransactions` and `gasUsedTotal`
cover the canonical chain from block 0 through the current head; `avgBlockTime`
is computed from the most recent block-time window.

**Parameters:** None

**Returns:**
```json
{
  "blockHeight": 1500,
  "totalTransactions": 3200,
  "avgBlockTime": 2.01,
  "gasUsedTotal": "0x...",
  "latestBaseFee": "0x5f7609"
}
```

---

### shell_getFinalityInfo

Returns finality status for the connected node.

**Parameters:** None

**Returns:**
```json
{
  "currentHead": "0x1a",
  "finalityLag": 2,
  "lastFinalizedBlock": "0x18",
  "lastFinalizedHash": "0xabc...",
  "pendingAttestations": 2
}
```

---

### shell_finalityProof

Returns a wrapper object for a finalized block hash. The `certificate` field
maps validator addresses to post-quantum signatures and is `null` when the
local node has no certificate for the requested hash.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block hash |

**Returns:**
```json
{
  "blockHash": "0xabc...",
  "certificate": {
    "0x...": {
      "sig_type": "Dilithium3",
      "data": [1, 2, 3]
    }
  }
}
```

---

### shell_getBlockSigners

Returns the post-quantum signature details for validators who signed a specific block.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block number (hex) or block tag |

**Returns:**
```json
{
  "blockNumber": "0x1a",
  "signers": [
    {
      "address": "0x...",
      "pqPubkey": "0x...",
      "signatureValid": true
    }
  ]
}
```

---

### shell_verifyPqSignature

Verifies a Dilithium3 post-quantum signature against a message and public key.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Hex-encoded message |
| 2 | `String` | Yes | Hex-encoded Dilithium3 signature |
| 3 | `String` | Yes | Hex-encoded Dilithium3 public key |

**Returns:** `Boolean` — `true` if the signature is valid.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_verifyPqSignature","params":["0xmessage...","0xsignature...","0xpubkey..."],"id":1}'
```

---

### shell_getEpochInfo

Returns information about the current consensus epoch.

**Parameters:** None

**Returns:**
```json
{
  "currentEpoch": 5,
  "epochLength": 0,
  "blocksInEpoch": 1500,
  "currentBlockTime": 2.01,
  "activeValidators": 3
}
```

---

### shell_getValidatorVotes

Returns voting activity statistics for validators in recent blocks.

**Parameters:** None

**Returns:**
```json
{
  "validators": [
    {
      "address": "0x...",
      "blocksProduced": 500,
      "lastBlockProduced": "0x1a",
      "uptime": 99.8
    }
  ]
}
```

---

### shell_getPendingGovernanceProposals

Returns pending governance proposals that have not yet been finalized.

**Parameters:** None

**Returns:**
```json
{
  "proposals": [
    {
      "type": "addValidator",
      "target": "0x...",
      "proposer": "0x...",
      "proposedAt": "0x18",
      "status": "pending"
    }
  ]
}
```

---

### shell_addValidator / shell_removeValidator *(disabled)*

These methods return error `-32601`. Direct validator set mutation is disabled to prevent split-brain issues. Use `shell_proposeAddValidator` and `shell_proposeRemoveValidator` instead, which go through the governance transaction flow.

### shell_transactionCount

Returns the total number of transactions stored across all blocks (chain-wide counter, not per-address nonce).

**Parameters:** none

**Response:** `"0x<hex>"` — total transaction count as a hex string.

```bash
curl -s http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_transactionCount","params":[],"id":1}'
# → {"result":"0x1a4f"}
```

### shell_getTransactionsByAddress

Returns transactions sent from or received by an address. Supports pagination
and inclusive block-range filters. There is no artificial deep-offset cap; under
live load, clients should pin `toBlock` from the first page and reuse it for
older pages to avoid gaps or duplicates while new blocks arrive.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `address` | string | `0x...` address |
| `fromBlock` | number \| null | Start block (inclusive, default 0) |
| `toBlock` | number \| null | End block (inclusive, default latest) |
| `page` | number \| null | Page index, 0-based (default 0) |
| `limit` | number \| null | Results per page (default 20) |

**Response:** paginated object:

| Field | Type | Description |
|------|------|-------------|
| `address` | string | Queried `0x...` address |
| `fromBlock` | string | Effective inclusive lower block bound, hex encoded |
| `toBlock` | string | Effective inclusive upper block snapshot, hex encoded |
| `page` | number | Page index, 0-based |
| `limit` | number | Page size |
| `total` | number | Total matches in the requested range |
| `transactions` | array | Transaction summaries, including `shellType`/reward metadata when present |

```bash
curl -s http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getTransactionsByAddress","params":["0xabc...",0,null,0,20],"id":1}'
```

### shell_getBlockWitnesses

Returns the PQ witness bundle for a block — the individual Dilithium3 signatures stored separately from TX bodies. Returns `null` when witnesses have been pruned (STARK proof received) or the block predates B3 storage.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `block` | string | Block hash (`0x...`) or block number (`"0x<hex>"` / `"latest"`) |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `blockHash` | string | Block hash |
| `witnessRoot` | string | `witness_root` from block header |
| `witnessCount` | number | Number of witnesses in bundle |
| `witnesses` | array | `[{ txIndex, sigType, signature, pubkey? }, ...]` |

Returns `null` when no witness bundle is stored (pruned or not applicable).

```bash
curl -s http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_getBlockWitnesses","params":["latest"],"id":1}'
```

### shell_setBalance *(dev/testnet only)*

Directly sets the balance of an address. **Only available when `api_modules` includes `dev`.** Returns `-32601` on production nodes.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `address` | string | Target `0x...` address |
| `balance` | string | New balance in wei as decimal string |

**Response:** `true` on success.

```bash
curl -s http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"shell_setBalance","params":["0xabc...","1000000000000000000"],"id":1}'
```

---

## debug_ Namespace

> **Note:** The `debug` namespace must be explicitly enabled via `--rpc-api eth,net,web3,shell,debug`. It is not enabled by default on validator nodes.

### debug_traceTransaction

Replays a transaction and returns an execution trace.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Transaction hash |
| 2 | `Object` | No | Trace options |

**Returns:**
```json
{
  "frame": {
    "type": "CALL",
    "from": "0x...",
    "to": "0x...",
    "gas": 21000,
    "gasUsed": 21000,
    "input": "0x",
    "output": "0x",
    "value": "0xde0b6b3a7640000",
    "error": null
  },
  "failed": false
}
```

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0xabc123..."],"id":1}'
```

---

### debug_traceBlockByNumber

Traces all transactions in a block.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block number (hex) or block tag |
| 2 | `Object` | No | Trace options |

**Returns:** `Array` — Array of trace result objects (one per transaction).

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["0x1a"],"id":1}'
```

---

## trace_ Namespace

OpenEthereum-compatible trace format.

> **Note:** Like `debug`, the `trace` namespace must be explicitly enabled via `--rpc-api`.

### trace_block

Returns traces for all transactions in a block.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block number (hex) or block tag |

**Returns:** `Array` — OpenEthereum-format trace objects.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"trace_block","params":["latest"],"id":1}'
```

---

### trace_oeTransaction

Returns the trace for a specific transaction in OpenEthereum format.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Transaction hash |

**Returns:** `Array` — Single-element array with the transaction trace.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"trace_oeTransaction","params":["0xabc123..."],"id":1}'
```

---

### trace_transaction

Returns the trace for a specific transaction in standard format.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Transaction hash |

**Returns:** `Array` — Trace objects for the transaction.

```bash
curl -s http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"trace_transaction","params":["0xabc123..."],"id":1}'
```

### shell_getAlgorithmRegistry

Returns the live algorithm registry as an array of objects: `{ algo, status, description }`.

**Parameters:** None

**Returns:** `Array` — one entry per registered signature algorithm.

```json
[
  {
    "algo": "MlDsa65",
    "description": "FIPS 204 ML-DSA-65 (NIST post-quantum standard; primary algorithm)",
    "status": "active"
  },
  {
    "algo": "Dilithium3",
    "description": "CRYSTALS-Dilithium3 (Round-3 pre-FIPS; active for legacy compatibility)",
    "status": "active"
  }
]
```

---

### shell_getProofAmendment

Returns the STARK proof amendment for a block if one has been generated asynchronously. See [stark-aggregation.md](stark-aggregation.md) for the full response schema.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Block hash (`0x...`) |

**Returns:** `Object|null` — Proof amendment object or `null` if not yet generated.

---

### shell_estimateBatch

Estimates gas for an AA batch transaction.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Batch transaction object |

**Returns:** `String` — Hex-encoded gas estimate.

---

### shell_getPaymasterPolicy

Returns the paymaster policy for a given paymaster address.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `String` | Yes | Paymaster address (`0x...`, 32 bytes) |

**Returns:** `Object|null` — Policy object or `null` if no policy registered.

---

### shell_isSponsored

Returns whether a transaction would be sponsored by a paymaster.

**Parameters:**
| # | Type | Required | Description |
|---|------|----------|-------------|
| 1 | `Object` | Yes | Transaction object |

**Returns:** `Boolean` — `true` if the transaction would be sponsored.

---

### shell_consensusInfo

Returns current consensus engine state.

**Parameters:** None

**Returns:**
```json
{
  "engine": "wpoa",
  "currentProposer": "0x...",
  "epochNumber": 5,
  "validatorCount": 3,
  "finalizedHeight": "0x18"
}
```

---

## Method Summary

For the canonical method list (currently 79 methods across `web3_`, `net_`, `eth_`, `debug_`, `trace_`, `evm_`, `shell_` namespaces), see `docs/rpc-reference.md`, which is auto-generated from `crates/rpc/src/api.rs`.

---

*Last updated: 2026-05-22*
