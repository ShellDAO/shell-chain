//! JSON-RPC API trait definitions using jsonrpsee proc macros.

use jsonrpsee::proc_macros::rpc;
use shell_primitives::{Address, ShellHash};

use crate::filter::RawLogFilter;
use crate::types::{CallRequest, RpcBlock, RpcLogWithMeta, RpcReceipt, RpcTransaction};

/// Web3 namespace RPCs (client metadata and utility).
#[rpc(server, namespace = "web3")]
pub trait Web3Api {
    /// Returns the current client version string.
    #[method(name = "clientVersion")]
    async fn client_version(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the Keccak-256 hash of the given data.
    #[method(name = "sha3")]
    async fn sha3(&self, data: String) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;
}

/// Net namespace RPCs (network status).
#[rpc(server, namespace = "net")]
pub trait NetApi {
    /// Returns the chain ID as a decimal string.
    #[method(name = "version")]
    async fn version(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns true if the node is listening for connections.
    #[method(name = "listening")]
    async fn listening(&self) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the number of connected peers as a hex string.
    #[method(name = "peerCount")]
    async fn peer_count(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;
}

/// Ethereum-compatible JSON-RPC API.
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    /// Returns the current block number.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the chain ID.
    #[method(name = "chainId")]
    async fn chain_id(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns false when not syncing; will return sync status object later.
    #[method(name = "syncing")]
    async fn syncing(&self) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns true if the node is actively mining (validating).
    #[method(name = "mining")]
    async fn mining(&self) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the current hashrate (always 0 for PoA).
    #[method(name = "hashrate")]
    async fn hashrate(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a list of accounts owned by the node (always empty).
    #[method(name = "accounts")]
    async fn accounts(&self) -> Result<Vec<Address>, jsonrpsee::types::ErrorObjectOwned>;

    /// Signs data with a local account (unsupported — node holds no private keys).
    #[method(name = "sign")]
    async fn sign(
        &self,
        address: Address,
        data: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Signs a transaction with a local account (unsupported).
    #[method(name = "signTransaction")]
    async fn sign_transaction(
        &self,
        tx: serde_json::Value,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a list of available compilers (always empty).
    #[method(name = "getCompilers")]
    async fn get_compilers(&self) -> Result<Vec<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the current Ethereum protocol version.
    #[method(name = "protocolVersion")]
    async fn protocol_version(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a block by number (hex-encoded or "latest").
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        number: String,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a block by hash.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        hash: ShellHash,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a transaction by hash.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcTransaction>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the receipt of a transaction by hash.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcReceipt>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns all receipts for a given block by number or hash.
    #[method(name = "getBlockReceipts")]
    async fn get_block_receipts(
        &self,
        block: String,
    ) -> Result<Vec<RpcReceipt>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the balance of an address.
    #[method(name = "getBalance")]
    async fn get_balance(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the nonce (transaction count) of an address.
    #[method(name = "getTransactionCount")]
    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the current gas price suggestion.
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a suggested max priority fee per gas (EIP-1559).
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns base fee history for a range of blocks (EIP-1559).
    #[method(name = "feeHistory")]
    async fn fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Submits a signed transaction to the mempool.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(
        &self,
        data: String,
    ) -> Result<ShellHash, jsonrpsee::types::ErrorObjectOwned>;

    /// Executes a call without creating a transaction (read-only).
    #[method(name = "call")]
    async fn call(
        &self,
        tx: CallRequest,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Estimates gas needed for a transaction.
    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        tx: CallRequest,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Creates an EIP-2930 access list for a transaction.
    #[method(name = "createAccessList")]
    async fn create_access_list(
        &self,
        tx: CallRequest,
        block: Option<String>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the bytecode at a given address.
    #[method(name = "getCode")]
    async fn get_code(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the value from a storage position at a given address.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        address: Address,
        position: String,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns logs matching the given filter object.
    #[method(name = "getLogs")]
    async fn get_logs(
        &self,
        filter: RawLogFilter,
    ) -> Result<Vec<RpcLogWithMeta>, jsonrpsee::types::ErrorObjectOwned>;

    /// Creates a log filter, returning a filter ID for polling via `eth_getFilterChanges`.
    #[method(name = "newFilter")]
    async fn new_filter(
        &self,
        filter: RawLogFilter,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Creates a block filter that tracks new block hashes.
    #[method(name = "newBlockFilter")]
    async fn new_block_filter(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns changes since the last poll for the given filter.
    #[method(name = "getFilterChanges")]
    async fn get_filter_changes(
        &self,
        id: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns all logs matching the filter criteria (for log filters only).
    #[method(name = "getFilterLogs")]
    async fn get_filter_logs(
        &self,
        id: String,
    ) -> Result<Vec<RpcLogWithMeta>, jsonrpsee::types::ErrorObjectOwned>;

    /// Removes a filter. Returns `true` if the filter existed.
    #[method(name = "uninstallFilter")]
    async fn uninstall_filter(
        &self,
        id: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the current blob base fee per gas (EIP-4844).
    #[method(name = "blobBaseFee")]
    async fn blob_base_fee(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;
}

/// Debug namespace RPCs (transaction tracing).
#[rpc(server, namespace = "debug")]
pub trait DebugApi {
    /// Traces the execution of a transaction, returning call frames.
    #[method(name = "traceTransaction")]
    async fn trace_transaction(
        &self,
        tx_hash: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Traces all transactions in a block by number, returning an array of call traces.
    #[method(name = "traceBlockByNumber")]
    async fn trace_block_by_number(
        &self,
        block_number: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;
}

/// OpenEthereum-compatible trace namespace RPCs.
#[rpc(server, namespace = "trace")]
pub trait TraceApi {
    /// Returns traces for all transactions in a block (OpenEthereum format).
    #[method(name = "block")]
    async fn trace_block(
        &self,
        block_number: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns traces for a single transaction (OpenEthereum format).
    #[method(name = "transaction")]
    async fn trace_oe_transaction(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;
}

/// Hardhat/Foundry-compatible dev RPCs.
///
/// The `evm` namespace name is retained as an Ethereum tooling compatibility
/// surface; it is not the Shell-Chain execution model name.
#[rpc(server, namespace = "evm")]
pub trait LegacyEvmApi {
    /// Mine one or more blocks immediately.
    #[method(name = "mine")]
    async fn mine(
        &self,
        blocks: Option<u64>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Set the timestamp for the next block to be produced.
    #[method(name = "setNextBlockTimestamp")]
    async fn set_next_block_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Increase the virtual clock used for future blocks.
    #[method(name = "increaseTime")]
    async fn increase_time(
        &self,
        seconds: u64,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Capture a snapshot of the current execution state.
    #[method(name = "snapshot")]
    async fn snapshot(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Revert to a previously captured snapshot.
    #[method(name = "revert")]
    async fn revert(&self, snapshot_id: String)
        -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;
}

/// Shell-chain extension API for PQ-specific features.
#[rpc(server, namespace = "shell")]
pub trait ShellApi {
    /// Returns the registered PQ public key for an address.
    #[method(name = "getPqPubkey")]
    async fn get_pq_pubkey(
        &self,
        address: Address,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the number of pending transactions in the mempool.
    #[method(name = "pendingCount")]
    async fn pending_count(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a block by number with Shell transaction detail modes.
    ///
    /// `tx_detail` accepts:
    /// - `"hashes"` / `null`: transaction hashes only
    /// - `"summary"`: row-ready tx metadata without signatures, calldata, or proofs
    /// - `"full"`: full Ethereum-compatible transaction objects
    #[method(name = "getBlockByNumber")]
    async fn shell_get_block_by_number(
        &self,
        number: String,
        tx_detail: Option<String>,
    ) -> Result<Option<RpcBlock>, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns a block by hash with Shell transaction detail modes.
    ///
    /// See `shell_getBlockByNumber` for supported `tx_detail` values.
    #[method(name = "getBlockByHash")]
    async fn shell_get_block_by_hash(
        &self,
        hash: ShellHash,
        tx_detail: Option<String>,
    ) -> Result<Option<RpcBlock>, jsonrpsee::types::ErrorObjectOwned>;

    /// Submit a signed transaction as structured JSON (developer-friendly).
    #[method(name = "sendTransaction")]
    async fn send_transaction(
        &self,
        tx: shell_core::SignedTransaction,
    ) -> Result<ShellHash, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the current validator set from world state.
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> Result<Vec<Address>, jsonrpsee::types::ErrorObjectOwned>;

    /// Add a validator to the active set. Unauthenticated until M3.
    #[method(name = "addValidator")]
    async fn add_validator(
        &self,
        address: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Remove a validator from the active set. Unauthenticated until M3.
    #[method(name = "removeValidator")]
    async fn remove_validator(
        &self,
        address: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Encode calldata for `addValidator(address)` system contract call.
    #[method(name = "encodeAddValidator")]
    async fn encode_add_validator(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Encode calldata for `removeValidator(address)` system contract call.
    #[method(name = "encodeRemoveValidator")]
    async fn encode_remove_validator(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Propose adding a validator via system contract transaction.
    /// Requires the node to be configured as a validator.
    /// Returns the transaction hash on success.
    #[method(name = "proposeAddValidator")]
    async fn propose_add_validator(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Propose removing a validator via system contract transaction.
    /// Requires the node to be configured as a validator.
    /// Returns the transaction hash on success.
    #[method(name = "proposeRemoveValidator")]
    async fn propose_remove_validator(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Propose updating a validator's governance weight via system contract transaction.
    /// Requires the node to be configured as a validator.
    /// Takes effect when a weighted quorum (>2/3 of total weight) supports the change.
    /// Returns the transaction hash on success.
    #[method(name = "proposeSetValidatorWeight")]
    async fn propose_set_validator_weight(
        &self,
        address: String,
        weight: u64,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns whether an address is currently a validator.
    #[method(name = "getValidatorStatus")]
    async fn get_validator_status(
        &self,
        address: Address,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns governance-related information (validator count, list, system contract address, gas limit).
    #[method(name = "getGovernanceInfo")]
    async fn get_governance_info(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns estimated gas for a governance operation ("addValidator" or "removeValidator").
    #[method(name = "estimateGovernanceGas")]
    async fn estimate_governance_gas(
        &self,
        operation: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns comprehensive node status information for the performance dashboard.
    #[method(name = "getNodeInfo")]
    async fn get_node_info(&self) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns network statistics for the performance dashboard.
    #[method(name = "getNetworkStats")]
    async fn get_network_stats(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns chain performance statistics for the performance dashboard.
    #[method(name = "getChainStats")]
    async fn get_chain_stats(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns finality information: last finalized block, current head, and pending attestations.
    #[method(name = "getFinalityInfo")]
    async fn get_finality_info(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the commit certificate (quorum signatures) for a finalized block.
    ///
    /// The certificate is a JSON object mapping validator address → signature hex.
    /// Returns the wrapper with `certificate: null` if no certificate is stored
    /// for the given block hash.
    ///
    /// Response fields:
    /// - `blockHash`   — the queried block hash
    /// - `certificate` — `{ "<address>": "<sig_hex>", ... }` or `null`
    #[method(name = "finalityProof")]
    async fn finality_proof(
        &self,
        block_hash: ShellHash,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns consensus engine information: engine type, validator set, weights,
    /// current proposer for the next block, and epoch progress.
    ///
    /// Response fields:
    /// - `engine`          — `"poa"` or `"wpoa"`
    /// - `validators`      — array of `{ address, weight }` for active validators
    /// - `current_proposer`— hex address of the validator expected to propose next
    /// - `block_number`    — head block number (proposer is for `block_number + 1`)
    /// - `epoch`           — current epoch index
    /// - `epoch_length`    — blocks per epoch
    /// - `epoch_progress`  — blocks elapsed in the current epoch
    #[method(name = "consensusInfo")]
    async fn consensus_info(&self)
        -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Set the balance of an address directly (dev/testnet only).
    #[method(name = "setBalance")]
    async fn set_balance(
        &self,
        address: Address,
        balance: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the total number of transactions across all blocks.
    #[method(name = "transactionCount")]
    async fn transaction_count(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns transactions involving a given address (sender or recipient).
    /// Supports pagination: `from_block`, `to_block`, `page` (0-based), `limit` (default 20).
    #[method(name = "getTransactionsByAddress")]
    async fn get_transactions_by_address(
        &self,
        address: Address,
        from_block: Option<u64>,
        to_block: Option<u64>,
        page: Option<u64>,
        limit: Option<u64>,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the witness bundle for a block (PQ signatures separated from tx bodies).
    ///
    /// `block` can be a block hash (0x-prefixed 32-byte hex) or a block tag
    /// ("latest", "0x<number>").  Returns `null` when no witness bundle has
    /// been stored for the block (pre-B3 blocks or pruned witnesses).
    ///
    /// Response fields:
    /// - `blockHash`    — canonical block hash
    /// - `witnessRoot`  — `witness_root` field from the block header
    /// - `witnessCount` — number of witnesses in the bundle
    /// - `witnesses`    — array of `{ txIndex, sigType, signature, pubkey? }`
    #[method(name = "getBlockWitnesses")]
    async fn get_block_witnesses(
        &self,
        block: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// SDK-facing witness endpoint.
    ///
    /// Returns `null` when the node does not expose a witness store or when the
    /// requested block's raw witness bundle has been pruned.
    ///
    /// Response fields (OPS-2 enriched):
    /// - `block_hash`     — `"0x..."` canonical block hash
    /// - `block_number`   — u64 block height
    /// - `state_root`     — `"0x..."` state root from the block header
    /// - `timestamp`      — u64 block timestamp (Unix seconds)
    /// - `witness_root`   — `"0x..."` expected witness Merkle root from header
    /// - `witness_root_verified` — `bool`: `true` when the computed bundle root
    ///   matches the header's `witness_root`; `false` on mismatch (tampered or
    ///   corrupt bundle); `null` when the header carries no witness_root.
    /// - `witness_count`  — number of witnesses
    /// - `witnesses`      — array of `{ tx_index, sig_type, signature, public_key? }`
    #[method(name = "getWitness")]
    async fn get_witness(
        &self,
        block: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Verify that a stored witness bundle's Merkle root matches the block
    /// header's `witness_root` field.
    ///
    /// This is the primary light-client verifier: after downloading a
    /// `shell_getWitness` response, the client can call this to confirm the
    /// bundle has not been tampered with.
    ///
    /// Returns:
    /// - `{ blockHash, expectedRoot, computedRoot, verified: true }`  on match.
    /// - `{ blockHash, expectedRoot, computedRoot, verified: false }` on mismatch.
    /// - `{ blockHash, verified: null, reason: "..." }` when the block is
    ///   unknown, the header has no `witness_root`, or no bundle is stored.
    #[method(name = "verifyWitnessRoot")]
    async fn verify_witness_root(
        &self,
        block: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Estimates gas for a Native-AA bundle (tx_type = `0x7E`).
    ///
    /// Returns a JSON object:
    /// - `total_gas` — hex: `outer_intrinsic + inner_sum + intrinsic_surcharge`
    /// - `outer_intrinsic` — hex: 21,000 (standard tx base cost; access list
    ///   is not supported in the admission AA path yet)
    /// - `inner_sum` — hex: Σ per-inner gas (explicit or simulated)
    /// - `intrinsic_surcharge` — hex: `(n - 1) × AA_INNER_CALL_INTRINSIC_GAS`
    /// - `per_inner` — array of `{ gas_limit, simulated }` where `simulated`
    ///   is `true` iff the request omitted `gas_limit` and the server filled it
    ///   in via `eth_call`-style simulation (+ 20% buffer, min 21,000).
    ///
    /// Does NOT require signatures; is a pure estimator. Errors
    /// (`-32602`) if the bundle is structurally invalid (empty inner_calls,
    /// > 16 inner calls, zero-gas inners); (`-32000`) if EVM simulation fails.
    #[method(name = "estimateBatch")]
    async fn estimate_batch(
        &self,
        req: crate::types::BatchEstimateRequest,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns Native-AA paymaster policy for an address.
    ///
    /// In v0.18.0 Phase 1, paymasters are plain EOAs; the "policy" is
    /// "sponsor any bundle that carries a valid paymaster signature over the
    /// bundle's signing hash, as long as balance covers `gas_used × max_fee`".
    ///
    /// Response:
    /// - `address` — queried address
    /// - `hasPqPubkey` — whether a PQ public key is registered (prerequisite
    ///   to act as a paymaster on Native AA)
    /// - `balance` — hex wei balance (available to sponsor gas)
    /// - `policy` — constant string `"eoa-open"` (Phase 1)
    /// - `maxGasSponsorship` — `null` (no per-tx cap in Phase 1; bounded only
    ///   by balance)
    /// - `pubkeyBytes` — hex length of the registered pubkey (sanity only),
    ///   or `null`
    #[method(name = "getPaymasterPolicy")]
    async fn get_paymaster_policy(
        &self,
        address: Address,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns whether a transaction is (or would be) sponsored by a
    /// paymaster.
    ///
    /// Looks the transaction up first in the mempool, then in on-chain
    /// storage. Response:
    /// - `found` — whether the tx was located
    /// - `location` — `"mempool"` | `"chain"` | `null`
    /// - `is_aa_bundle` — whether tx_type is `0x7E` with a valid bundle
    /// - `sponsored` — `true` iff `is_aa_bundle` and `paymaster` is set to a
    ///   non-sender address
    /// - `paymaster` — paymaster address (or `null`)
    /// - `sender` — tx sender (or `null` when not found)
    /// - `inner_call_count` — number of inner calls in the bundle (or `null`)
    #[method(name = "isSponsored")]
    async fn is_sponsored(
        &self,
        tx_hash: ShellHash,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the active storage profile and the effective pruning parameters.
    ///
    /// Profile is one of `"archive" | "full" | "light"`. The numeric fields
    /// reflect the resolved `PruningConfig` (after applying any per-field
    /// overrides such as `--body-retention` / `--witness-retention`).
    /// A value of `0` means "keep forever" for retention/keep_recent;
    /// `proof_replacement_grace = u64::MAX` means "never delete witness even
    /// after STARK proof arrives" (archive mode behavior).
    ///
    /// Returns an error when the node has not been configured with a profile
    /// (e.g. legacy startup paths). Stable consumers should treat such an
    /// error as `"profile: unknown"`.
    #[method(name = "getStorageProfile")]
    async fn get_storage_profile(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the STARK proof amendment for a block if one has been generated.
    ///
    /// `block_hash` must be a `0x`-prefixed 32-byte hex hash.
    ///
    /// Response when proof exists:
    /// - `block_hash`     — the block hash
    /// - `block_number`   — the block height
    /// - `start_block`    — first source block covered by the proof
    /// - `end_block`      — final source block covered by the proof
    /// - `source_count`   — number of source blocks covered by the proof
    /// - `layer`          — STARK compression layer
    /// - `proof_entries`  — number of PQ signature entries aggregated
    /// - `proof_version`  — amendment protocol version
    /// - `prover`         — address of the prover
    /// - `proof`          — hex-encoded STARK batch proof bytes
    ///
    /// Pointer responses for non-final source blocks include `target_hash` and
    /// `target_block`, with `proof: null`; query the target hash for full proof
    /// bytes and proof entry counts.
    ///
    /// Returns `null` when no proof amendment has been generated for the block.
    #[method(name = "getProofAmendment")]
    async fn get_proof_amendment(
        &self,
        block_hash: String,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the algorithm registry — the set of PQ signing algorithms
    /// that are accepted, deprecated, or pending activation on this node.
    ///
    /// This is the RPC exposure of the white-paper §6 algorithm registry.
    /// The returned array reflects the node's live in-memory view of on-chain
    /// governance transitions.
    ///
    /// Response fields per entry:
    /// - `algo`        — algorithm name (`"MlDsa65"`, `"Dilithium3"`, `"SphincsSha2256f"`)
    /// - `status`      — `"active"`, `"deprecated"`, or `"pending_activation"`
    /// - `description` — human-readable description / NIST reference
    #[method(name = "getAlgorithmRegistry")]
    async fn get_algorithm_registry(
        &self,
    ) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned>;
}
