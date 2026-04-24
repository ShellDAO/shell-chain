# RPC Reference

shell-chain exposes five JSON-RPC namespaces:

- **`eth_`** — Ethereum-compatible methods
- **`shell_`** — shell-chain extension methods (PQ, AA, governance, ops)
- **`net_`** / **`web3_`** — standard net/web3 info methods
- **`admin_`** — node administration (authenticated)
- **`debug_`** / **`trace_`** — debugging (dev nodes only)

All methods use JSON-RPC 2.0. Hex quantities are `0x`-prefixed strings.

Error codes are defined in `crates/rpc/src/error.rs`:

| Code    | Constant            | Meaning                                     |
|---------|---------------------|---------------------------------------------|
| `-32601`| `METHOD_NOT_FOUND`  | Method not found or not enabled             |
| `-32602`| `INVALID_PARAMS`    | Invalid parameters                          |
| `-32603`| `INTERNAL_ERROR`    | Internal server error                       |
| `-32000`| `SERVER_ERROR`      | Generic server / precondition failure       |
| `-32001`| `NOT_FOUND`         | Resource (block, filter, tx) not found      |
| `-32002`| `DEV_MODE_REQUIRED` | Operation requires dev mode                 |
| `-32003`| `FEATURE_NOT_ENABLED`| Feature not enabled on this node           |
| `-32005`| `LIMIT_EXCEEDED`    | Result limit exceeded (eth_getLogs)         |

---

## eth_ namespace

### eth_blockNumber
Returns the current chain tip block number.
```
→ "0x1a4"    (hex-encoded block number)
```

### eth_chainId
Returns the chain ID.
```
→ "0x1"
```

### eth_getBlockByNumber(blockNumber, fullTxs)
Returns a block by number or tag (`"latest"`, `"earliest"`, `"pending"`).
- `fullTxs`: if `true`, returns full transaction objects; otherwise tx hashes.
```
→ RpcBlock | null
```

### eth_getBlockByHash(blockHash, fullTxs)
Returns a block by hash.
```
→ RpcBlock | null
```

### eth_getTransactionByHash(txHash)
Returns a transaction by hash.
```
→ RpcTransaction | null
```

### eth_getTransactionReceipt(txHash)
Returns a receipt by transaction hash.
```
→ RpcReceipt | null
```

### eth_getBlockReceipts(blockNumber)
Returns all receipts for a block.
```
→ RpcReceipt[]
```

### eth_getBalance(address, blockTag)
Returns the account balance in wei (hex).
```
→ "0xde0b6b3a7640000"
```

### eth_getTransactionCount(address, blockTag)
Returns the account nonce.
```
→ "0x5"
```

### eth_getCode(address, blockTag)
Returns the contract bytecode at address.
```
→ "0x608060..."
```

### eth_call(callObject, blockTag)
Executes a message call without creating a transaction.
```
callObject: { from?, to, data?, value?, gas? }
→ "0x..."    (return data hex)
```

### eth_estimateGas(callObject)
Estimates gas for a call.
```
→ "0x5208"
```

### eth_sendRawTransaction(rawTx)
Submits a signed, RLP-encoded transaction.
```
→ txHash
```

### eth_gasPrice
Returns the current base gas price in wei.
```
→ "0x3b9aca00"
```

### eth_maxPriorityFeePerGas
Returns the suggested miner tip in wei.
```
→ "0x3b9aca00"
```

### eth_feeHistory(blockCount, newestBlock, rewardPercentiles)
Returns fee history for EIP-1559 fee estimation.
```
→ { oldestBlock, baseFeePerGas[], gasUsedRatio[], reward[][] }
```

### eth_getLogs(filter)
Returns logs matching filter. Capped at `MAX_BLOCK_RANGE` blocks.
```
filter: { fromBlock?, toBlock?, address?, topics? }
→ RpcLogWithMeta[]
errors: -32005 if range > MAX_BLOCK_RANGE
```

### eth_newFilter(filter) / eth_newBlockFilter() / eth_newPendingTransactionFilter()
Creates a log / block / pending-tx filter. Returns a filter ID hex string.

### eth_getFilterChanges(filterId) / eth_getFilterLogs(filterId)
Polls or fetches accumulated filter results.
```
errors: -32001 if filter not found
```

### eth_uninstallFilter(filterId)
Removes a filter. Returns `true` if found and removed.

### eth_syncing
Returns `false` (shell-chain has no sync protocol yet).

### eth_blobBaseFee
Returns `"0x0"` (EIP-4844 placeholder).

---

## shell_ namespace

### shell_getPqPubkey(address)
Returns the stored ML-DSA-65 public key for an address (hex-encoded).
```
→ "0x..." | null
```

### shell_getNodeInfo()
Returns comprehensive node metadata.
```json
{
  "nodeId": "0x...",
  "version": "0.18.0",
  "chainId": 1,
  "blockHeight": 12345,
  "peerCount": 4,
  "validatorCount": 3,
  "isSyncing": false,
  "uptime": 3600
}
```

### shell_getNetworkStats()
Returns network-level statistics (peer topology, message rates).

### shell_getChainStats()
Returns chain-level statistics (TPS, block times, mempool depth).

### shell_getFinalityInfo()
Returns current finality state (epoch, finalized height, validator set hash).

### shell_transactionCount()
Returns the total number of transactions processed (hex).

### shell_pendingCount()
Returns the number of pending mempool transactions (hex).

### shell_sendTransaction(signedTx)
Submits a decoded `SignedTransaction` object.
```
→ txHash
```

### shell_getTransactionsByAddress(address, options)
Returns paginated transaction history for an address.
```
options: { page?, pageSize?, direction? }
→ { txs: RpcTransaction[], total: number, page: number }
```

### shell_getValidators()
Returns the current active validator set (array of addresses).

### shell_addValidator(address) / shell_removeValidator(address)
**Disabled** — use `shell_proposeAddValidator` / `shell_proposeRemoveValidator`.
```
errors: -32601
```

### shell_proposeAddValidator(address) / shell_proposeRemoveValidator(address)
Submits a governance transaction to add/remove a validator.
```
→ txHash
```

### shell_getValidatorStatus(address)
Returns validator status for an address.

### shell_getGovernanceInfo()
Returns current governance parameters and pending proposals.

### shell_estimateGovernanceGas(operation)
Estimates gas for a governance operation.
```
operation: "addValidator" | "removeValidator" | "getValidators" | "isValidator"
→ "0x..." (gas estimate hex)
errors: -32602 for unknown operation
```

### shell_encodeAddValidator(address) / shell_encodeRemoveValidator(address)
Returns ABI-encoded calldata for governance system calls.
```
→ "0x..."
```

---

## shell_ — Witness & Verification (OPS-2)

### shell_getBlockWitnesses(blockHash)
Returns the PQ witness bundle for a block.
```json
{
  "blockHash": "0x...",
  "witnesses": [...],
  "count": 3,
  "witnessRootVerified": true    // null if header has no witness_root
}
```

### shell_getWitness(blockHash, txIndex)
Returns the PQ witness for a specific transaction.
```json
{
  "blockHash": "0x...",
  "txIndex": 0,
  "publicKey": "0x...",
  "signature": "0x...",
  "state_root": "0x...",
  "timestamp": 1700000000,
  "witness_root": "0x...",
  "witness_root_verified": true
}
→ null if block/witness not found
```

### shell_verifyWitnessRoot(block)
Light-client verifier — recomputes the Merkle root over stored witnesses and
compares against the block header's `witness_root` field.
```
block: hex block number | "latest" | "earliest" | block hash
```
```json
{
  "blockHash": "0x...",
  "expectedRoot": "0x...",
  "computedRoot": "0x...",
  "verified": true
}
```
When information is unavailable:
```json
{ "verified": null, "reason": "block header has no witness_root (pre-B2 block or genesis)" }
```
Possible `reason` values:
- `"block not found"`
- `"block header has no witness_root (pre-B2 block or genesis)"`
- `"witness store not available on this node"`
- `"witness bundle not stored (pruned or never written)"`

---

## shell_ — Account Abstraction (v0.18.0)

### shell_estimateBatch(request)
Estimates gas for a batch (AA) transaction.
```json
{
  "from": "0x...",           // optional
  "inner_calls": [
    { "to": "0x...", "value": "0x0", "data": "0x", "gas_limit": "0x5208" }
  ]
}
```
```json
{
  "totalGas": "0x...",
  "outerIntrinsic": "0x...",
  "innerSum": "0x...",
  "intrinsicSurcharge": "0x...",
  "perInner": [
    { "gasLimit": "0x5208", "simulated": true },
    { "gasLimit": "0x7530", "simulated": false }
  ]
}
```
Errors:
- `-32602` if `inner_calls` is empty or exceeds `MAX_INNER_CALLS` (16)
- `-32602` if any `inner[n].gas_limit` is 0
- `-32000` if EVM simulation fails

### shell_getPaymasterPolicy(address)
Returns the paymaster policy for an address. Always returns a policy object
(never `null`); unregistered addresses receive the default `"eoa-open"` policy.
```json
{
  "address": "0x...",
  "hasPqPubkey": false,
  "pubkeyBytes": null,
  "balance": "0x...",
  "policy": "eoa-open",
  "maxGasSponsorship": null
}
```

### shell_isSponsored(txHash)
Returns whether a transaction was sponsored by a paymaster.
For unknown transactions, returns a normal object with `found: false` (no error).
```json
{
  "found": true,
  "location": "chain",
  "isAaBundle": true,
  "sponsored": true,
  "paymaster": "0x...",
  "sender": "0x...",
  "innerCallCount": 2
}
```
When not found:
```json
{ "found": false, "sponsored": false }
```

---

## shell_ — Ops (v0.18.0)

### shell_getStorageProfile()
Returns the node's current storage profile configuration.
```json
{
  "profile": "full",
  "body_retention": 0,
  "witness_retention": 128,
  "keep_recent": 0,
  "proof_replacement_grace": 0,
  "state_pruning_experimental": false
}
errors: -32003 if storage profile is not configured
```

---

## net_ namespace

### net_version
Returns the network ID string.

### net_listening
Returns `true` if the node is accepting P2P connections.

### net_peerCount
Returns the number of connected peers (hex).

---

## web3_ namespace

### web3_clientVersion
Returns the node client version string (e.g. `"shell-chain/0.18.0"`).

### web3_sha3(data)
Returns `keccak256(data)`.

---

## admin_ namespace

> Requires authentication. Connect to the admin RPC port (default `:8546`).

### admin_nodeInfo
Returns the full node identity: enode URL, protocol versions, ports.

### admin_peers
Returns connected peer details: enode, network, protocols.

### admin_addPeer(multiaddr)
**Stub** — not yet implemented. Use `--bootnodes` at startup.
```
errors: -32601
```

---

## debug_ namespace (dev mode)

### debug_traceTransaction(txHash, options)
Returns an execution trace for a transaction.

### debug_traceBlockByNumber(blockNumber, options)
Returns traces for all transactions in a block.

---

## evm_ namespace (dev mode)

> Only available when node is started with `--dev`.

### evm_mine(options)
Forces production of a new block.

### evm_setNextBlockTimestamp(timestamp)
Sets the timestamp for the next block.

### evm_increaseTime(seconds)
Advances the chain clock by N seconds.

### evm_snapshot()
Takes a chain snapshot. Returns a snapshot ID.

### evm_revert(snapshotId)
Reverts to a snapshot.

---

## shell_ — Dev only

### shell_setBalance(address, balance)
Sets the balance for an address. Dev mode required.
```
errors: -32002 if not in dev mode
```
