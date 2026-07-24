# RPC Reference

> **Auto-generated** by `tools/rpc-docgen` from `crates/rpc/src/api.rs`.
> Run `cargo run -p rpc-docgen` to regenerate.

shell-chain exposes the following JSON-RPC namespaces:

- **`web3_`** (2 methods)
- **`net_`** (3 methods)
- **`eth_`** (33 methods)
- **`debug_`** (2 methods)
- **`trace_`** (2 methods)
- **`evm_`** (5 methods)
- **`shell_`** (44 methods)

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

## web3_  namespace

### web3_clientVersion
```
client_version() → String
```

Returns the current client version string.

### web3_sha3
```
sha3(data: String) → String
```

Returns the Keccak-256 hash of the given data.


## net_  namespace

### net_version
```
version() → String
```

Returns the chain ID as a decimal string.

### net_listening
```
listening() → bool
```

Returns true if the node is listening for connections.

### net_peerCount
```
peer_count() → String
```

Returns the number of connected peers as a hex string.


## eth_  namespace

### eth_blockNumber
```
block_number() → String
```

Returns the current block number.

### eth_chainId
```
chain_id() → String
```

Returns the chain ID.

### eth_syncing
```
syncing() → serde_json::Value
```

Returns false when not syncing; will return sync status object later.

### eth_mining
```
mining() → bool
```

Returns true if the node is actively mining (validating).

### eth_hashrate
```
hashrate() → String
```

Returns the current hashrate (always 0 for PoA).

### eth_accounts
```
accounts() → Vec<Address>
```

Returns a list of accounts owned by the node (always empty).

### eth_sign
```
sign(address: Address, data: String, ) → String
```

Signs data with a local account (unsupported — node holds no private keys).

### eth_signTransaction
```
sign_transaction(tx: serde_json::Value, ) → String
```

Signs a transaction with a local account (unsupported).

### eth_getCompilers
```
get_compilers() → Vec<String>
```

Returns a list of available compilers (always empty).

### eth_protocolVersion
```
protocol_version() → String
```

Returns the current Ethereum protocol version.

### eth_getBlockByNumber
```
get_block_by_number(number: String, full_txs: bool, ) → Option<RpcBlock>
```

Returns a block by number (hex-encoded or "latest").

### eth_getBlockByHash
```
get_block_by_hash(hash: ShellHash, full_txs: bool, ) → Option<RpcBlock>
```

Returns a block by hash.

### eth_getTransactionByHash
```
get_transaction_by_hash(hash: ShellHash, ) → Option<RpcTransaction>
```

Returns a transaction by hash.

### eth_getTransactionReceipt
```
get_transaction_receipt(hash: ShellHash, ) → Option<RpcReceipt>
```

Returns the receipt of a transaction by hash.

### eth_getBlockReceipts
```
get_block_receipts(block: String, ) → Vec<RpcReceipt>
```

Returns all receipts for a given block by number or hash.

### eth_getBalance
```
get_balance(address: Address, block: Option<String>, ) → String
```

Returns the balance of an address.

### eth_getTransactionCount
```
get_transaction_count(address: Address, block: Option<String>, ) → String
```

Returns the nonce (transaction count) of an address.

### eth_gasPrice
```
gas_price() → String
```

Returns the current gas price suggestion.

### eth_maxPriorityFeePerGas
```
max_priority_fee_per_gas() → String
```

Returns a suggested max priority fee per gas (EIP-1559).

### eth_feeHistory
```
fee_history(block_count: String, newest_block: String, reward_percentiles: Option<Vec<f64>>, ) → serde_json::Value
```

Returns base fee history for a range of blocks (EIP-1559).

### eth_sendRawTransaction
```
send_raw_transaction(data: String, ) → ShellHash
```

Submits a signed transaction to the mempool.

### eth_call
```
call(tx: CallRequest, block: Option<String>, ) → String
```

Executes a call without creating a transaction (read-only).

### eth_estimateGas
```
estimate_gas(tx: CallRequest, ) → String
```

Estimates gas needed for a transaction.

### eth_createAccessList
```
create_access_list(tx: CallRequest, block: Option<String>, ) → serde_json::Value
```

Creates an EIP-2930 access list for a transaction.

### eth_getCode
```
get_code(address: Address, block: Option<String>, ) → String
```

Returns the bytecode at a given address.

### eth_getStorageAt
```
get_storage_at(address: Address, position: String, block: Option<String>, ) → String
```

Returns the value from a storage position at a given address.

### eth_getLogs
```
get_logs(filter: RawLogFilter, ) → Vec<RpcLogWithMeta>
```

Returns logs matching the given filter object.

### eth_newFilter
```
new_filter(filter: RawLogFilter, ) → String
```

Creates a log filter, returning a filter ID for polling via `eth_getFilterChanges`.

### eth_newBlockFilter
```
new_block_filter() → String
```

Creates a block filter that tracks new block hashes.

### eth_getFilterChanges
```
get_filter_changes(id: String, ) → serde_json::Value
```

Returns changes since the last poll for the given filter. After a chain
reorganization, log filters return matching orphaned logs with
`removed: true` before replacement-chain logs, while block filters
return canonical replacement block hashes.

### eth_getFilterLogs
```
get_filter_logs(id: String, ) → Vec<RpcLogWithMeta>
```

Returns all logs matching the filter criteria (for log filters only).

### eth_uninstallFilter
```
uninstall_filter(id: String, ) → bool
```

Removes a filter. Returns `true` if the filter existed.

### eth_blobBaseFee
```
blob_base_fee() → String
```

Returns the current blob base fee per gas (EIP-4844).


## debug_  namespace

### debug_traceTransaction
```
trace_transaction(tx_hash: String, opts: Option<serde_json::Value>, ) → serde_json::Value
```

Traces the execution of a transaction, returning call frames.
The optional tracer must be `callTracer`; unsupported or unknown options
are rejected as invalid parameters.

### debug_traceBlockByNumber
```
trace_block_by_number(block_number: String, opts: Option<serde_json::Value>, ) → serde_json::Value
```

Traces all transactions in a block by number, returning an array of call traces.
The optional tracer must be `callTracer`; unsupported or unknown options
are rejected as invalid parameters.


## trace_  namespace

### trace_block
```
trace_block(block_number: String, ) → serde_json::Value
```

Returns traces for all transactions in a block (OpenEthereum format).

### trace_transaction
```
trace_oe_transaction(tx_hash: String, ) → serde_json::Value
```

Returns traces for a single transaction (OpenEthereum format).


## evm_  namespace

### evm_mine
```
mine(blocks: Option<u64>, ) → serde_json::Value
```

Mine one or more blocks immediately. The block count defaults to 1 and
is capped at 256 per request.

### evm_setNextBlockTimestamp
```
set_next_block_timestamp(timestamp: u64, ) → serde_json::Value
```

Set the timestamp for the next block to be produced.

### evm_increaseTime
```
increase_time(seconds: u64, ) → serde_json::Value
```

Increase the virtual clock used for future blocks.

### evm_snapshot
```
snapshot() → String
```

Capture a snapshot of the current execution state. A node retains at most
128 active development snapshots.

### evm_revert
```
revert(snapshot_id: String) → bool
```

Revert to a previously captured snapshot. A successful revert consumes
the selected snapshot and any snapshots created after it.


## shell_  namespace

### shell_getPqPubkey
```
get_pq_pubkey(address: Address, ) → Option<String>
```

Returns the registered PQ public key for an address.

### shell_pendingCount
```
pending_count() → String
```

Returns the number of pending transactions in the mempool.

### shell_getBlockByNumber
```
shell_get_block_by_number(number: String, tx_detail: Option<String>, ) → Option<RpcBlock>
```

Returns a block by number with Shell transaction detail modes.

`tx_detail` accepts:
- `"hashes"` / `null`: transaction hashes only
- `"summary"`: row-ready tx metadata without signatures, calldata, or proofs
- `"full"`: full Ethereum-compatible transaction objects

### shell_getBlockByHash
```
shell_get_block_by_hash(hash: ShellHash, tx_detail: Option<String>, ) → Option<RpcBlock>
```

Returns a block by hash with Shell transaction detail modes.

See `shell_getBlockByNumber` for supported `tx_detail` values.

### shell_rpcCapabilities
```
rpc_capabilities() → crate::types::RpcCapabilities
```

Returns Shell RPC extension capabilities and server limits.

### shell_getChainSnapshot
```
get_chain_snapshot(options: Option<serde_json::Value>, ) → crate::types::RpcChainSnapshot
```

Returns a compact chain/node/consensus snapshot for dashboards.

### shell_getBlocksRange
```
get_blocks_range(start: String, options: Option<crate::types::RpcBlocksRangeOptions>, ) → crate::types::RpcBlocksRange
```

Returns a range of compact block responses in one call.

### shell_getAddressSummary
```
get_address_summary(address: Address, options: Option<crate::types::RpcAddressSummaryOptions>, ) → crate::types::RpcAddressSummary
```

Returns account state plus a small cursor-paginated transaction page.

### shell_getTransactionsByAddressV2
```
get_transactions_by_address_v2(address: Address, options: Option<crate::types::RpcAddressTransactionsV2Options>, ) → crate::types::RpcAddressTransactionsV2Page
```

Returns cursor-paginated transaction history for an address.

### shell_getTransactionSummary
```
get_transaction_summary(hash: ShellHash, options: Option<crate::types::RpcTransactionSummaryOptions>, ) → crate::types::RpcTransactionSummaryResult
```

Returns a compact transaction view with optional receipt.

### shell_getValidatorSnapshot
```
get_validator_snapshot(options: Option<crate::types::RpcValidatorSnapshotOptions>, ) → crate::types::RpcValidatorSnapshot
```

Returns validator set, proposer, and recent proposer stats.
`proposerWindow` defaults to 200, is capped at 1000, and must be at least 1.

### shell_sendTransaction
```
send_transaction(tx: shell_core::SignedTransaction, ) → ShellHash
```

Submit a signed transaction as structured JSON (developer-friendly).

### shell_getValidators
```
get_validators() → Vec<Address>
```

Returns the current validator set from world state.

### shell_addValidator
```
add_validator(address: String, ) → bool
```

Add a validator to the active set. Unauthenticated until M3.

### shell_removeValidator
```
remove_validator(address: String, ) → bool
```

Remove a validator from the active set. Unauthenticated until M3.

### shell_encodeAddValidator
```
encode_add_validator(address: String, ) → String
```

Encode calldata for `addValidator(address)` system contract call.

### shell_encodeRemoveValidator
```
encode_remove_validator(address: String, ) → String
```

Encode calldata for `removeValidator(address)` system contract call.

### shell_encodeSetValidatorStake
```
encode_set_validator_stake(address: String, stake: String, ) → String
```

Encode calldata for `setValidatorStake(address,uint256)` system contract call.

### shell_proposeAddValidator
```
propose_add_validator(address: String, ) → String
```

Propose adding a validator via system contract transaction.
Requires the node to be configured as a validator.
Returns the transaction hash on success.

### shell_proposeRemoveValidator
```
propose_remove_validator(address: String, ) → String
```

Propose removing a validator via system contract transaction.
Requires the node to be configured as a validator.
Returns the transaction hash on success.

### shell_proposeSetValidatorWeight
```
propose_set_validator_weight(address: String, weight: u64, ) → String
```

Propose updating a validator's governance weight via system contract transaction.
Requires the node to be configured as a validator.
Takes effect when a weighted quorum (>2/3 of total weight) supports the change.
Returns the transaction hash on success.

### shell_proposeSetValidatorStake
```
propose_set_validator_stake(address: String, stake: String, ) → String
```

Propose updating a validator's locked stake via system contract transaction.
In staking mode, consensus weight is derived from this stake.

### shell_getValidatorStatus
```
get_validator_status(address: Address, ) → serde_json::Value
```

Returns whether an address is currently a validator.

### shell_getGovernanceInfo
```
get_governance_info() → serde_json::Value
```

Returns governance-related information (validator count, list, system contract address, gas limit).

### shell_estimateGovernanceGas
```
estimate_governance_gas(operation: String, ) → String
```

Returns estimated gas for a governance operation ("addValidator" or "removeValidator").

### shell_getNodeInfo
```
get_node_info() → serde_json::Value
```

Returns comprehensive node status information for the performance dashboard.

### shell_getNetworkStats
```
get_network_stats() → serde_json::Value
```

Returns network statistics for the performance dashboard.

### shell_getChainStats
```
get_chain_stats() → serde_json::Value
```

Returns chain performance statistics for the performance dashboard.

### shell_getFinalityInfo
```
get_finality_info() → serde_json::Value
```

Returns finality information: last finalized block, current head, and pending attestations.

### shell_finalityProof
```
finality_proof(block_hash: ShellHash, ) → serde_json::Value
```

Returns the commit certificate (quorum signatures) for a finalized block.

The certificate is a JSON object mapping validator address → signature hex.
Returns the wrapper with `certificate: null` if no certificate is stored
for the given block hash.

Response fields:
- `blockHash`   — the queried block hash
- `certificate` — `{ "<address>": "<sig_hex>", ... }` or `null`

### shell_consensusInfo
```
consensus_info() → serde_json::Value
```

Returns consensus engine information: engine type, validator set, weights,
current proposer for the next block, and epoch progress.

Response fields:
- `engine`          — `"poa"` or `"wpoa"`
- `validators`      — array of `{ address, weight }` for active validators
- `current_proposer`— hex address of the validator expected to propose next
- `block_number`    — head block number (proposer is for `block_number + 1`)
- `epoch`           — current epoch index
- `epoch_length`    — blocks per epoch
- `epoch_progress`  — blocks elapsed in the current epoch

### shell_setBalance
```
set_balance(address: Address, balance: String, ) → bool
```

Set the balance of an address directly (dev/testnet only).

### shell_transactionCount
```
transaction_count() → String
```

Returns the total number of transactions across all blocks.

### shell_getTransactionsByAddress
```
get_transactions_by_address(address: Address, from_block: Option<u64>, to_block: Option<u64>, page: Option<u64>, limit: Option<u64>, ) → serde_json::Value
```

Returns transactions involving a given address (sender or recipient).
Supports pagination: `from_block`, `to_block`, `page` (0-based), `limit` (default 20).

### shell_getBlockWitnesses
```
get_block_witnesses(block: String, ) → serde_json::Value
```

Returns the witness bundle for a block (PQ signatures separated from tx bodies).

`block` can be a block hash (0x-prefixed 32-byte hex) or a block tag
("latest", "0x<number>").  Returns `null` when no witness bundle has
been stored for the block (pre-B3 blocks or pruned witnesses).

Response fields:
- `blockHash`    — canonical block hash
- `witnessRoot`  — `witness_root` field from the block header
- `witnessCount` — number of witnesses in the bundle
- `witnesses`    — array of `{ txIndex, sigType, signature, pubkey? }`

### shell_getWitness
```
get_witness(block: String, ) → serde_json::Value
```

SDK-facing witness endpoint.

Returns `null` when the node does not expose a witness store or when the
requested block's raw witness bundle has been pruned.

Response fields (OPS-2 enriched):
- `block_hash`     — `"0x..."` canonical block hash
- `block_number`   — u64 block height
- `state_root`     — `"0x..."` state root from the block header
- `timestamp`      — u64 block timestamp (Unix seconds)
- `witness_root`   — `"0x..."` expected witness Merkle root from header
- `witness_root_verified` — `bool`: `true` when the computed bundle root
  matches the header's `witness_root`; `false` on mismatch (tampered or
  corrupt bundle); `null` when the header carries no witness_root.
- `witness_count`  — number of witnesses
- `witnesses`      — array of `{ tx_index, sig_type, signature, public_key? }`

### shell_verifyWitnessRoot
```
verify_witness_root(block: String, ) → serde_json::Value
```

Verify that a stored witness bundle's Merkle root matches the block
header's `witness_root` field.

This is the primary light-client verifier: after downloading a
`shell_getWitness` response, the client can call this to confirm the
bundle has not been tampered with.

Returns:
- `{ blockHash, expectedRoot, computedRoot, verified: true }`  on match.
- `{ blockHash, expectedRoot, computedRoot, verified: false }` on mismatch.
- `{ blockHash, verified: null, reason: "..." }` when the block is
  unknown, the header has no `witness_root`, or no bundle is stored.

### shell_estimateBatch
```
estimate_batch(req: crate::types::BatchEstimateRequest, ) → serde_json::Value
```

Estimates gas for a Native-AA bundle (tx_type = `0x7E`).

Returns a JSON object:
- `total_gas` — hex: `outer_intrinsic + inner_sum + intrinsic_surcharge`
- `outer_intrinsic` — hex: 21,000 (standard tx base cost; access list
  is not supported in the admission AA path yet)
- `inner_sum` — hex: Σ per-inner gas (explicit or simulated)
- `intrinsic_surcharge` — hex: `(n - 1) × AA_INNER_CALL_INTRINSIC_GAS`
- `per_inner` — array of `{ gas_limit, simulated }` where `simulated`
  is `true` iff the request omitted `gas_limit` and the server filled it
  in via `eth_call`-style simulation (+ 20% buffer, min 21,000).

Does NOT require signatures; is a pure estimator. Errors
(`-32602`) if the bundle is structurally invalid (empty inner_calls,
> 16 inner calls, zero-gas inners); (`-32000`) if EVM simulation fails.

### shell_estimatePaymasterGas
```
estimate_paymaster_gas(req: crate::types::PaymasterGasEstimateRequest, ) → serde_json::Value
```

Reports paymaster validation gas capability for contract paymasters.

Current node builds return a versioned cap-only response for the
protocol `validatePaymasterOp` gas limit. They do not perform a full EVM
staticcall dry-run from this RPC path yet. Clients must inspect
`simulation_status` and only enable contract-paymaster UX when it is
upgraded from `"cap_only"`.

**Input** (`paymaster_context` is the opaque bytes forwarded to the contract):
```json
{
  "paymaster": "0x…",
  "sender": "0x…",
  "inner_calls_data": "0x…",
  "max_fee_per_gas": "0x…",
  "paymaster_context": "0x…"
}
```

**Response**:
- `validation_gas` — `null` while `simulation_status` is `"cap_only"`
- `paymaster_gas_cap` — hard cap enforced by the node (50 000)
- `within_cap` — `null` while no staticcall simulation has run
- `paymaster` — the paymaster address queried
- `simulation_status` — currently `"cap_only"`
- `simulation_version` — response contract version
- `capability` — current node capability string

**Future error** (`-32000`): EVM simulation failed or paymaster contract reverted.

### shell_getPaymasterPolicy
```
get_paymaster_policy(address: Address, ) → serde_json::Value
```

Returns Native-AA paymaster policy for an address.

In v0.18.0 Phase 1, paymasters are plain EOAs; the "policy" is
"sponsor any bundle that carries a valid paymaster signature over the
bundle's signing hash, as long as balance covers `gas_used × max_fee`".

Response:
- `address` — queried address
- `hasPqPubkey` — whether a PQ public key is registered (prerequisite
  to act as a paymaster on Native AA)
- `balance` — hex wei balance (available to sponsor gas)
- `policy` — constant string `"eoa-open"` (Phase 1)
- `maxGasSponsorship` — `null` (no per-tx cap in Phase 1; bounded only
  by balance)
- `pubkeyBytes` — hex length of the registered pubkey (sanity only),
  or `null`

### shell_isSponsored
```
is_sponsored(tx_hash: ShellHash, ) → serde_json::Value
```

Returns whether a transaction is (or would be) sponsored by a
paymaster.

Looks the transaction up first in the mempool, then in on-chain
storage. Response:
- `found` — whether the tx was located
- `location` — `"mempool"` | `"chain"` | `null`
- `is_aa_bundle` — whether tx_type is `0x7E` with a valid bundle
- `sponsored` — `true` iff `is_aa_bundle` and `paymaster` is set to a
  non-sender address
- `paymaster` — paymaster address (or `null`)
- `sender` — tx sender (or `null` when not found)
- `inner_call_count` — number of inner calls in the bundle (or `null`)

### shell_getStorageProfile
```
get_storage_profile() → serde_json::Value
```

Returns the active storage profile and the effective pruning parameters.

Profile is one of `"archive" | "full" | "pruned"`. The `"pruned"`
value corresponds to the rolling-window profile accepted as `"light"`
by CLI/config inputs. The numeric fields reflect the resolved
`PruningConfig` (after applying any per-field overrides such as
`--body-retention` / `--witness-retention`).
A value of `0` means "keep forever" for retention/keep_recent;
`proof_replacement_grace = u64::MAX` means "never delete witness even
after STARK proof arrives" (archive mode behavior).

Returns an error when the node has not been configured with a profile
(e.g. legacy startup paths). Stable consumers should treat such an
error as `"profile: unknown"`.

### shell_getProofAmendment
```
get_proof_amendment(block_hash: String, ) → serde_json::Value
```

Returns the STARK proof amendment for a block if one has been generated.

`block_hash` must be a `0x`-prefixed 32-byte hex hash.

Response when proof exists:
- `block_hash`     — the block hash
- `block_number`   — the block height
- `start_block`    — first source block covered by the proof
- `end_block`      — final source block covered by the proof
- `source_count`   — number of source blocks covered by the proof
- `layer`          — STARK compression layer
- `proof_entries`  — number of PQ signature entries aggregated
- `proof_version`  — amendment protocol version
- `prover`         — address of the prover
- `proof`          — hex-encoded STARK batch proof bytes

Pointer responses for non-final source blocks include `target_hash` and
`target_block`, with `proof: null`; query the target hash for full proof
bytes and proof entry counts.

Returns `null` when no proof amendment has been generated for the block.

### shell_getAlgorithmRegistry
```
get_algorithm_registry() → serde_json::Value
```

Returns the algorithm registry — the set of PQ signing algorithms
that are accepted, deprecated, or pending activation on this node.

This is the RPC exposure of the white-paper §6 algorithm registry.
The returned array reflects the node's live in-memory view of on-chain
governance transitions.

Response fields per entry:
- `algo`        — algorithm name (`"MlDsa65"`, `"Dilithium3"`, `"SphincsSha2256f"`)
- `status`      — `"active"`, `"deprecated"`, or `"pending_activation"`
- `description` — human-readable description / NIST reference

