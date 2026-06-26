//! JSON-RPC types with Ethereum-compatible hex numerics and `0x` addresses.

use serde::{Deserialize, Serialize};
use shell_primitives::{Address, ShellHash, U256};

/// keccak256 of RLP-encoded empty list (`0xc0`).
/// Standard Ethereum constant for blocks with no ommers.
pub const EMPTY_OMMER_HASH: &str =
    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

/// Hex-encoded block response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    pub hash: ShellHash,
    pub parent_hash: ShellHash,
    pub number: String,
    pub timestamp: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub miner: Address,
    pub state_root: ShellHash,
    pub transactions_root: ShellHash,
    pub receipts_root: ShellHash,
    pub transactions: serde_json::Value,
    pub size: String,
    pub base_fee_per_gas: String,
    // F-072: standard Ethereum compatibility fields
    pub total_difficulty: String,
    #[serde(rename = "sha3Uncles")]
    pub sha3_uncles: String,
    pub uncles: Vec<ShellHash>,
    /// PoA block nonce — always zero (no mining).
    pub nonce: String,
    pub difficulty: String,
    pub mix_hash: ShellHash,
    pub extra_data: String,
    pub logs_bloom: String,
    pub withdrawals_root: String,
    pub parent_beacon_block_root: String,
    pub blob_gas_used: String,
    pub excess_blob_gas: String,
    /// STARK aggregate proof over the block's PoA signatures (hex-encoded).
    /// `null` when the block has no aggregate proof (genesis or pre-proof blocks).
    #[serde(rename = "sigAggregateProof", skip_serializing_if = "Option::is_none")]
    pub sig_aggregate_proof: Option<String>,
    /// Byte length of the STARK aggregate proof. `null` when no proof exists.
    #[serde(
        rename = "sigAggregateProofSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub sig_aggregate_proof_size: Option<u64>,
    /// Highest STARK compression layer currently known for this block.
    pub compression_layer: u32,
    /// Current local witness/pruning state for this block.
    pub pruning_status: String,
}

/// Hex-encoded transaction response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    pub hash: ShellHash,
    pub block_hash: Option<ShellHash>,
    pub block_number: Option<String>,
    pub transaction_index: Option<String>,
    pub from: Address,
    pub to: Option<Address>,
    pub value: String,
    pub gas: String,
    pub gas_price: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub nonce: String,
    pub input: String,
    pub chain_id: String,
    /// EIP-2718 transaction type (0x2=EIP-1559, 0x3=blob).
    #[serde(rename = "type")]
    pub tx_type: String,
    /// Legacy ECDSA compat stub — always "0x0" (PQ chain has no ECDSA).
    pub v: String,
    /// Legacy ECDSA compat stub — always "0x0".
    pub r: String,
    /// Legacy ECDSA compat stub — always "0x0".
    pub s: String,
    /// EIP-2930 access list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<RpcAccessListItem>>,
    /// EIP-4844 max fee per blob gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_blob_gas: Option<String>,
    /// EIP-4844 blob versioned hashes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<ShellHash>>,
    /// Shell product-level transaction type (`transfer`, `blockReward`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_source_hash: Option<ShellHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<String>,
    /// Decoded proof amendment input for `StarkReward` transactions.
    /// `None` for all other transaction types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_input: Option<serde_json::Value>,
}

/// Lightweight transaction response for explorer block rows.
///
/// This intentionally excludes signature compatibility fields (`v/r/s`), full
/// calldata, access lists, blob fields, and other heavy data. `hasInput` lets
/// clients distinguish simple transfers from contract calls without receiving
/// the full input payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionSummary {
    pub hash: ShellHash,
    pub block_hash: Option<ShellHash>,
    pub block_number: Option<String>,
    pub transaction_index: Option<String>,
    pub from: Address,
    pub to: Option<Address>,
    pub value: String,
    #[serde(rename = "type")]
    pub tx_type: String,
    pub has_input: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_source_hash: Option<ShellHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RpcListDirection {
    Asc,
    Desc,
}

impl Default for RpcListDirection {
    fn default() -> Self {
        Self::Desc
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RpcV2TxDetail {
    None,
    Hashes,
    Summary,
    Full,
}

impl Default for RpcV2TxDetail {
    fn default() -> Self {
        Self::Summary
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlocksRangeOptions {
    #[serde(default)]
    pub direction: RpcListDirection,
    pub limit: Option<u64>,
    #[serde(default)]
    pub tx_detail: RpcV2TxDetail,
    pub tx_limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcAddressSummaryOptions {
    pub recent_limit: Option<u64>,
    pub include_total: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcAddressTransactionsV2Options {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub cursor: Option<String>,
    pub limit: Option<u64>,
    #[serde(default)]
    pub direction: RpcListDirection,
    #[serde(default)]
    pub detail: RpcV2TxDetail,
    pub include_total: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionSummaryOptions {
    pub include_receipt: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RpcValidatorSnapshotOptions {
    pub proposer_window: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcCapabilities {
    pub rpc_version: String,
    pub methods: Vec<String>,
    pub max_page_size: u64,
    pub max_blocks_range: u64,
    pub max_tx_summary_per_block: u64,
    pub supports_cursor_pagination: bool,
    pub supports_address_history_index: bool,
    pub witness_store: bool,
    pub storage_profile: Option<StorageProfileInfo>,
    pub fallback_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlocksRange {
    pub start: String,
    pub direction: RpcListDirection,
    pub limit: u64,
    pub blocks: Vec<RpcBlock>,
    pub next_start: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAddressTransactionsV2Page {
    pub address: Address,
    pub from_block: String,
    pub to_block: String,
    pub limit: u64,
    pub direction: RpcListDirection,
    pub total: Option<u64>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub items: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAddressSummary {
    pub address: Address,
    pub balance: String,
    pub nonce: String,
    pub exists: bool,
    pub has_code: bool,
    pub code_hash: Option<ShellHash>,
    pub pq_pubkey_registered: bool,
    pub total_transactions: Option<u64>,
    pub recent_transactions: RpcAddressTransactionsV2Page,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionSummaryResult {
    pub transaction: Option<serde_json::Value>,
    pub receipt: Option<RpcReceipt>,
    pub status: Option<String>,
    pub gas_used: Option<String>,
    pub log_count: Option<u64>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcChainSnapshot {
    pub chain_id: String,
    pub head: Option<RpcBlock>,
    pub finalized: Option<RpcBlock>,
    pub finality_lag: u64,
    pub pending_transactions: String,
    pub peer_count: u64,
    pub is_mining: bool,
    pub uptime: u64,
    pub base_fee: String,
    pub gas_price: String,
    pub total_transactions: u64,
    pub gas_used_total: String,
    pub avg_block_time: f64,
    pub consensus: serde_json::Value,
    pub validators: serde_json::Value,
    pub storage_profile: Option<StorageProfileInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcValidatorSnapshot {
    pub validators: serde_json::Value,
    pub current_proposer: serde_json::Value,
    pub block_number: u64,
    pub epoch: serde_json::Value,
    pub epoch_length: serde_json::Value,
    pub epoch_progress: serde_json::Value,
    pub proposer_window: u64,
    pub proposer_stats: Vec<serde_json::Value>,
}

/// EIP-2930 access list item for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccessListItem {
    pub address: Address,
    pub storage_keys: Vec<String>,
}

/// Hex-encoded transaction receipt response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceipt {
    pub transaction_hash: ShellHash,
    pub block_hash: ShellHash,
    pub block_number: String,
    pub transaction_index: String,
    pub from: Address,
    pub to: Option<Address>,
    pub status: String,
    pub gas_used: String,
    pub cumulative_gas_used: String,
    pub effective_gas_price: String,
    pub contract_address: Option<Address>,
    pub logs: Vec<RpcLog>,
    pub logs_bloom: String,
    #[serde(rename = "type")]
    pub tx_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_kind: Option<String>,
}

/// Hex-encoded log response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcLog {
    pub address: Address,
    pub topics: Vec<ShellHash>,
    pub data: String,
}

/// Full log object returned by `eth_getLogs` with block/tx metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcLogWithMeta {
    pub address: Address,
    pub topics: Vec<ShellHash>,
    pub data: String,
    pub block_number: String,
    pub block_hash: ShellHash,
    pub transaction_hash: ShellHash,
    pub transaction_index: String,
    pub log_index: String,
    /// Always `false` for a non-reorg chain.
    pub removed: bool,
}

/// Ethereum `eth_call` / `eth_estimateGas` request object.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
    /// Sender address (defaults to zero address if absent).
    pub from: Option<Address>,
    /// Destination address (required for calls, absent for contract creation).
    pub to: Option<Address>,
    /// Hex-encoded call data.
    pub data: Option<String>,
    /// Hex-encoded value in wei.
    pub value: Option<String>,
    /// Hex-encoded gas limit.
    pub gas: Option<String>,
    /// EIP-2930 access list.
    pub access_list: Option<Vec<RpcAccessListItem>>,
}

/// Request object for `shell_estimateBatch`.
///
/// Estimates gas for a Native-AA bundle (tx_type = `0x7E`) without requiring
/// the caller to sign or assemble the full `AaBundle`. Structural only: the
/// return value reflects admission-layer arithmetic
/// (`outer_intrinsic + Σ inner.gas_limit + (n-1) × AA_INNER_CALL_INTRINSIC_GAS`)
/// plus, when an inner call's `gas_limit` is omitted, a per-inner simulation
/// using `eth_call`-style execution (with a 20% buffer, minimum 21,000).
#[derive(Debug, Clone, Deserialize)]
pub struct BatchEstimateRequest {
    /// Nominal sender (caller) for per-inner simulation. Defaults to zero.
    pub from: Option<Address>,
    /// Optional paymaster address. Purely informational for the estimate; the
    /// returned gas bound does not change based on paymaster presence.
    pub paymaster: Option<Address>,
    /// List of inner calls to estimate.
    pub inner_calls: Vec<BatchInnerCallRequest>,
}

/// Single inner call in a `shell_estimateBatch` request.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchInnerCallRequest {
    /// Destination address. `None` means contract creation.
    pub to: Option<Address>,
    /// Hex-encoded wei value (e.g., `"0x1"`). Defaults to `0`.
    pub value: Option<String>,
    /// Hex-encoded call data.
    pub data: Option<String>,
    /// Hex-encoded advisory gas cap for this inner call. When omitted, the
    /// server simulates the call and uses `max(gas_used × 1.2, 21_000)`.
    pub gas_limit: Option<String>,
}

/// Request body for `shell_estimatePaymasterGas` (AA Phase 2).
///
/// Reports the protocol gas cap for contract-paymaster validation.
///
/// Current node builds return a versioned `cap_only` response instead of a
/// real `validatePaymasterOp` staticcall simulation. Clients must inspect the
/// response `simulation_status` before enabling contract-paymaster UX.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymasterGasEstimateRequest {
    /// Paymaster contract address to query.
    pub paymaster: Address,
    /// Bundle sender address.
    pub sender: Address,
    /// Inner calls as raw hex bytes (forwarded to `validatePaymasterOp`).
    pub inner_calls_data: Option<String>,
    /// Max fee per gas (hex wei). Used to compute `max_gas_cost`.
    pub max_fee_per_gas: Option<String>,
    /// Opaque context bytes forwarded to `validatePaymasterOp`.
    pub paymaster_context: Option<String>,
}

/// Active storage profile descriptor returned by `shell_getStorageProfile`.
///
/// Active storage profile descriptor returned by `shell_getStorageProfile`.
///
/// `profile` uses white-paper canonical names: `"archive"`, `"full"`, `"pruned"`.
/// (`"pruned"` corresponds to the legacy `"light"` alias in CLI / config files.)
/// `body_retention`, `witness_retention`, `keep_recent`, `proof_replacement_grace`
/// reflect the effective `PruningConfig` after applying any per-field overrides
/// (a value of `0` means "keep forever" except for `proof_replacement_grace`
/// where `u64::MAX` means "never delete witness even after STARK proof").
#[derive(Debug, Clone, Serialize)]
pub struct StorageProfileInfo {
    pub profile: String,
    pub body_retention: u64,
    pub witness_retention: u64,
    pub keep_recent: u64,
    pub proof_replacement_grace: u64,
    pub state_pruning_experimental: bool,
}

/// Format a u64 as "0x..." hex string.
pub fn hex_u64(v: u64) -> String {
    format!("{:#x}", v)
}

/// Format a U256 as "0x..." hex string.
pub fn hex_u256(v: U256) -> String {
    format!("{:#x}", v)
}

/// Format bytes as "0x..." hex string.
pub fn hex_bytes(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

// ── Debug / Trace RPC types ────────────────────────────────────

/// Options accepted by `debug_traceTransaction` and `debug_traceBlockByNumber`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceOptions {
    /// Tracer type (only "callTracer" is supported).
    #[serde(default)]
    pub tracer: Option<String>,
    /// Whether to include only the top-level call (no nested calls).
    #[serde(default)]
    pub disable_stack: Option<bool>,
    /// Whether to exclude memory from the result.
    #[serde(default)]
    pub disable_memory: Option<bool>,
    /// Whether to exclude storage from the result.
    #[serde(default)]
    pub disable_storage: Option<bool>,
}

/// OpenEthereum-compatible trace action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OeTraceAction {
    /// Call type: "call", "create", "staticcall", "delegatecall"
    pub call_type: Option<String>,
    pub from: Address,
    pub to: Option<Address>,
    pub gas: String,
    pub value: String,
    pub input: String,
}

/// OpenEthereum-compatible trace result (return data + gas).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OeTraceOutput {
    pub gas_used: String,
    pub output: String,
}

/// Single OpenEthereum-compatible trace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OeTrace {
    pub action: OeTraceAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<OeTraceOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub subtraces: u64,
    pub trace_address: Vec<u64>,
    /// "call" | "create"
    #[serde(rename = "type")]
    pub trace_type: String,
    pub block_number: u64,
    pub block_hash: ShellHash,
    pub transaction_hash: ShellHash,
    pub transaction_position: u64,
}

// ════════════════════════════════════════════════════════════════
//  M5-A6: RPC type compatibility tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn hex_u64_formats_correctly() {
        assert_eq!(hex_u64(0), "0x0");
        assert_eq!(hex_u64(1), "0x1");
        assert_eq!(hex_u64(255), "0xff");
        assert_eq!(hex_u64(256), "0x100");
        assert_eq!(hex_u64(21_000), "0x5208");
        assert_eq!(hex_u64(30_000_000), "0x1c9c380");
        assert_eq!(hex_u64(u64::MAX), "0xffffffffffffffff");
    }

    #[test]
    fn hex_u256_formats_correctly() {
        assert_eq!(hex_u256(U256::ZERO), "0x0");
        assert_eq!(hex_u256(U256::from(1)), "0x1");
        assert_eq!(hex_u256(U256::from(1000)), "0x3e8");
        assert_eq!(hex_u256(U256::from(u64::MAX)), "0xffffffffffffffff");
    }

    #[test]
    fn hex_bytes_formats_correctly() {
        assert_eq!(hex_bytes(&[]), "0x");
        assert_eq!(hex_bytes(&[0x00]), "0x00");
        assert_eq!(hex_bytes(&[0xAA, 0xBB, 0xCC]), "0xaabbcc");
        assert_eq!(hex_bytes(&[0xFF]), "0xff");
    }

    #[test]
    fn rpc_block_json_camel_case_keys() {
        let block = RpcBlock {
            hash: ShellHash::ZERO,
            parent_hash: ShellHash::ZERO,
            number: "0x0".into(),
            timestamp: "0x0".into(),
            gas_limit: "0x1c9c380".into(),
            gas_used: "0x0".into(),
            miner: Address::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            transactions: serde_json::json!([]),
            size: "0x0".into(),
            base_fee_per_gas: "0x0".into(),
            total_difficulty: "0x1".into(),
            sha3_uncles: EMPTY_OMMER_HASH.into(),
            uncles: vec![],
            nonce: "0x0000000000000000".into(),
            difficulty: "0x1".into(),
            mix_hash: ShellHash::ZERO,
            extra_data: "0x".into(),
            logs_bloom: format!("0x{}", "00".repeat(256)),
            withdrawals_root: format!("{:?}", ShellHash::ZERO),
            parent_beacon_block_root: format!("{:?}", ShellHash::ZERO),
            blob_gas_used: "0x0".into(),
            excess_blob_gas: "0x0".into(),
            sig_aggregate_proof: None,
            sig_aggregate_proof_size: None,
            compression_layer: 0,
            pruning_status: "unknown".into(),
        };

        let json = serde_json::to_value(&block).unwrap();

        // Verify camelCase JSON keys per Ethereum spec
        assert!(json.get("parentHash").is_some(), "missing parentHash");
        assert!(json.get("gasLimit").is_some(), "missing gasLimit");
        assert!(json.get("gasUsed").is_some(), "missing gasUsed");
        assert!(json.get("stateRoot").is_some(), "missing stateRoot");
        assert!(
            json.get("transactionsRoot").is_some(),
            "missing transactionsRoot"
        );
        assert!(json.get("receiptsRoot").is_some(), "missing receiptsRoot");
        assert!(json.get("baseFeePerGas").is_some(), "missing baseFeePerGas");
        assert!(
            json.get("totalDifficulty").is_some(),
            "missing totalDifficulty"
        );
        assert!(json.get("sha3Uncles").is_some(), "missing sha3Uncles");
        assert!(json.get("mixHash").is_some(), "missing mixHash");
        assert!(json.get("extraData").is_some(), "missing extraData");
        assert!(json.get("logsBloom").is_some(), "missing logsBloom");
        assert!(
            json.get("withdrawalsRoot").is_some(),
            "missing withdrawalsRoot"
        );
        assert!(
            json.get("parentBeaconBlockRoot").is_some(),
            "missing parentBeaconBlockRoot"
        );
        assert!(json.get("blobGasUsed").is_some(), "missing blobGasUsed");
        assert!(json.get("excessBlobGas").is_some(), "missing excessBlobGas");
    }

    #[test]
    fn rpc_block_numbers_are_hex_strings() {
        let block = RpcBlock {
            hash: ShellHash::ZERO,
            parent_hash: ShellHash::ZERO,
            number: hex_u64(42),
            timestamp: hex_u64(1_700_000_000),
            gas_limit: hex_u64(30_000_000),
            gas_used: hex_u64(21_000),
            miner: Address::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            transactions: serde_json::json!([]),
            size: hex_u64(1000),
            base_fee_per_gas: hex_u64(1_000_000_000),
            total_difficulty: "0x1".into(),
            sha3_uncles: EMPTY_OMMER_HASH.into(),
            uncles: vec![],
            nonce: "0x0000000000000000".into(),
            difficulty: "0x1".into(),
            mix_hash: ShellHash::ZERO,
            extra_data: "0x".into(),
            logs_bloom: format!("0x{}", "00".repeat(256)),
            withdrawals_root: format!("{:?}", ShellHash::ZERO),
            parent_beacon_block_root: format!("{:?}", ShellHash::ZERO),
            blob_gas_used: hex_u64(0),
            excess_blob_gas: hex_u64(0),
            sig_aggregate_proof: None,
            sig_aggregate_proof_size: None,
            compression_layer: 0,
            pruning_status: "unknown".into(),
        };

        let json = serde_json::to_value(&block).unwrap();

        for key in &[
            "number",
            "timestamp",
            "gasLimit",
            "gasUsed",
            "size",
            "baseFeePerGas",
            "totalDifficulty",
            "nonce",
            "difficulty",
            "blobGasUsed",
            "excessBlobGas",
        ] {
            let val = json.get(key).unwrap();
            assert!(val.is_string(), "{key} should be a string");
            let s = val.as_str().unwrap();
            assert!(s.starts_with("0x"), "{key} = '{s}' should start with 0x");
        }
    }

    #[test]
    fn rpc_transaction_json_has_required_fields() {
        let tx = RpcTransaction {
            hash: ShellHash::ZERO,
            block_hash: Some(ShellHash::ZERO),
            block_number: Some("0x1".into()),
            transaction_index: Some("0x0".into()),
            from: Address::ZERO,
            to: Some(Address::from([0x01; 20])),
            value: "0x3e8".into(),
            gas: "0x5208".into(),
            gas_price: "0x14".into(),
            max_fee_per_gas: "0x14".into(),
            max_priority_fee_per_gas: "0x1".into(),
            nonce: "0x0".into(),
            input: "0x".into(),
            chain_id: "0x539".into(),
            tx_type: "0x2".into(),
            v: "0x0".into(),
            r: "0x0".into(),
            s: "0x0".into(),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            shell_type: Some("transfer".into()),
            reward_kind: None,
            reward_layer: None,
            reward_source_hash: None,
            original_size: None,
            compressed_size: None,
            decoded_input: None,
        };

        let json = serde_json::to_value(&tx).unwrap();

        for key in &[
            "hash",
            "blockHash",
            "blockNumber",
            "transactionIndex",
            "from",
            "to",
            "value",
            "gas",
            "gasPrice",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "nonce",
            "input",
            "chainId",
            "type",
            "v",
            "r",
            "s",
        ] {
            assert!(json.get(key).is_some(), "missing field: {key}");
        }
        assert_eq!(json.get("from").unwrap(), &serde_json::json!(Address::ZERO));
        assert_eq!(
            json.get("to").unwrap(),
            &serde_json::json!(Address::from([0x01; 20]))
        );
    }

    #[test]
    fn rpc_transaction_null_to_for_contract_creation() {
        let tx = RpcTransaction {
            hash: ShellHash::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: None,
            value: "0x0".into(),
            gas: "0x5208".into(),
            gas_price: "0x0".into(),
            max_fee_per_gas: "0x0".into(),
            max_priority_fee_per_gas: "0x0".into(),
            nonce: "0x0".into(),
            input: "0x6080".into(),
            chain_id: "0x539".into(),
            tx_type: "0x2".into(),
            v: "0x0".into(),
            r: "0x0".into(),
            s: "0x0".into(),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            shell_type: Some("contractCreate".into()),
            reward_kind: None,
            reward_layer: None,
            reward_source_hash: None,
            original_size: None,
            compressed_size: None,
            decoded_input: None,
        };

        let json = serde_json::to_value(&tx).unwrap();
        assert!(
            json.get("to").unwrap().is_null(),
            "to must be null for contract creation"
        );
        assert!(
            json.get("blockHash").unwrap().is_null(),
            "pending tx should have null blockHash"
        );
        assert!(
            json.get("blockNumber").unwrap().is_null(),
            "pending tx should have null blockNumber"
        );
        assert!(
            json.get("transactionIndex").unwrap().is_null(),
            "pending tx should have null transactionIndex"
        );
    }

    #[test]
    fn rpc_transaction_optional_eip4844_fields_absent_when_none() {
        let tx = RpcTransaction {
            hash: ShellHash::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: Some(Address::from([0x01; 20])),
            value: "0x0".into(),
            gas: "0x5208".into(),
            gas_price: "0x0".into(),
            max_fee_per_gas: "0x0".into(),
            max_priority_fee_per_gas: "0x0".into(),
            nonce: "0x0".into(),
            input: "0x".into(),
            chain_id: "0x539".into(),
            tx_type: "0x2".into(),
            v: "0x0".into(),
            r: "0x0".into(),
            s: "0x0".into(),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            shell_type: Some("transfer".into()),
            reward_kind: None,
            reward_layer: None,
            reward_source_hash: None,
            original_size: None,
            compressed_size: None,
            decoded_input: None,
        };

        let json = serde_json::to_string(&tx).unwrap();
        assert!(!json.contains("maxFeePerBlobGas"), "absent for non-blob tx");
        assert!(
            !json.contains("blobVersionedHashes"),
            "absent for non-blob tx"
        );
        assert!(!json.contains("accessList"), "absent when None");
    }

    #[test]
    fn rpc_transaction_eip4844_fields_present_when_some() {
        let tx = RpcTransaction {
            hash: ShellHash::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: Some(Address::from([0x01; 20])),
            value: "0x0".into(),
            gas: "0x5208".into(),
            gas_price: "0x0".into(),
            max_fee_per_gas: "0x0".into(),
            max_priority_fee_per_gas: "0x0".into(),
            nonce: "0x0".into(),
            input: "0x".into(),
            chain_id: "0x539".into(),
            tx_type: "0x3".into(),
            v: "0x0".into(),
            r: "0x0".into(),
            s: "0x0".into(),
            access_list: Some(vec![]),
            max_fee_per_blob_gas: Some("0xf4240".into()),
            blob_versioned_hashes: Some(vec![ShellHash::ZERO]),
            shell_type: Some("transfer".into()),
            reward_kind: None,
            reward_layer: None,
            reward_source_hash: None,
            original_size: None,
            compressed_size: None,
            decoded_input: None,
        };

        let json = serde_json::to_value(&tx).unwrap();
        assert!(json.get("maxFeePerBlobGas").is_some());
        assert!(json.get("blobVersionedHashes").is_some());
        assert!(json.get("accessList").is_some());
    }

    #[test]
    fn rpc_receipt_json_has_required_fields() {
        let receipt = RpcReceipt {
            transaction_hash: ShellHash::ZERO,
            block_hash: ShellHash::ZERO,
            block_number: "0x1".into(),
            transaction_index: "0x0".into(),
            from: Address::ZERO,
            to: Some(Address::from([0x01; 20])),
            status: "0x1".into(),
            gas_used: "0x5208".into(),
            cumulative_gas_used: "0x5208".into(),
            effective_gas_price: "0x14".into(),
            contract_address: None,
            logs: vec![],
            logs_bloom: format!("0x{}", "00".repeat(256)),
            tx_type: "0x2".into(),
            shell_type: Some("transfer".into()),
            reward_kind: None,
        };

        let json = serde_json::to_value(&receipt).unwrap();

        for key in &[
            "transactionHash",
            "blockHash",
            "blockNumber",
            "transactionIndex",
            "from",
            "to",
            "status",
            "gasUsed",
            "cumulativeGasUsed",
            "effectiveGasPrice",
            "contractAddress",
            "logs",
            "logsBloom",
            "type",
        ] {
            assert!(json.get(key).is_some(), "missing field: {key}");
        }
        assert_eq!(json.get("from").unwrap(), &serde_json::json!(Address::ZERO));
        assert_eq!(
            json.get("to").unwrap(),
            &serde_json::json!(Address::from([0x01; 20]))
        );
    }

    #[test]
    fn rpc_receipt_contract_address_null_for_non_creation() {
        let receipt = RpcReceipt {
            transaction_hash: ShellHash::ZERO,
            block_hash: ShellHash::ZERO,
            block_number: "0x1".into(),
            transaction_index: "0x0".into(),
            from: Address::ZERO,
            to: Some(Address::from([0x01; 20])),
            status: "0x1".into(),
            gas_used: "0x5208".into(),
            cumulative_gas_used: "0x5208".into(),
            effective_gas_price: "0x14".into(),
            contract_address: None,
            logs: vec![],
            logs_bloom: format!("0x{}", "00".repeat(256)),
            tx_type: "0x2".into(),
            shell_type: Some("transfer".into()),
            reward_kind: None,
        };

        let json = serde_json::to_value(&receipt).unwrap();
        assert!(json.get("contractAddress").unwrap().is_null());
    }

    #[test]
    fn rpc_log_with_meta_json_fields() {
        let log = RpcLogWithMeta {
            address: Address::from([0xAA; 20]),
            topics: vec![ShellHash::from([0xBB; 32])],
            data: "0x1234".into(),
            block_number: "0x1".into(),
            block_hash: ShellHash::ZERO,
            transaction_hash: ShellHash::ZERO,
            transaction_index: "0x0".into(),
            log_index: "0x0".into(),
            removed: false,
        };

        let json = serde_json::to_value(&log).unwrap();

        for key in &[
            "address",
            "topics",
            "data",
            "blockNumber",
            "blockHash",
            "transactionHash",
            "transactionIndex",
            "logIndex",
            "removed",
        ] {
            assert!(json.get(key).is_some(), "missing field: {key}");
        }
        assert_eq!(json.get("removed").unwrap(), false);
        assert_eq!(
            json.get("address").unwrap(),
            &serde_json::json!(Address::from([0xAA; 20]))
        );
    }

    #[test]
    fn rpc_block_serde_roundtrip() {
        let block = RpcBlock {
            hash: ShellHash::ZERO,
            parent_hash: ShellHash::ZERO,
            number: "0x2a".into(),
            timestamp: "0x65612340".into(),
            gas_limit: "0x1c9c380".into(),
            gas_used: "0x5208".into(),
            miner: Address::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            transactions: serde_json::json!([]),
            size: "0x3e8".into(),
            base_fee_per_gas: "0x3b9aca00".into(),
            total_difficulty: "0x1".into(),
            sha3_uncles: EMPTY_OMMER_HASH.into(),
            uncles: vec![],
            nonce: "0x0000000000000000".into(),
            difficulty: "0x1".into(),
            mix_hash: ShellHash::ZERO,
            extra_data: "0x".into(),
            logs_bloom: format!("0x{}", "00".repeat(256)),
            withdrawals_root: format!("{:?}", ShellHash::ZERO),
            parent_beacon_block_root: format!("{:?}", ShellHash::ZERO),
            blob_gas_used: "0x0".into(),
            excess_blob_gas: "0x0".into(),
            sig_aggregate_proof: None,
            sig_aggregate_proof_size: None,
            compression_layer: 0,
            pruning_status: "unknown".into(),
        };

        let json = serde_json::to_string(&block).unwrap();
        let decoded: RpcBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block.hash, decoded.hash);
        assert_eq!(block.number, decoded.number);
        assert_eq!(block.gas_limit, decoded.gas_limit);
        assert_eq!(block.blob_gas_used, decoded.blob_gas_used);
    }

    #[test]
    fn empty_ommer_hash_is_standard_ethereum() {
        assert_eq!(
            EMPTY_OMMER_HASH,
            "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
        );
    }

    #[test]
    fn call_request_deserializes_all_fields() {
        let from = Address::from([0x01; 20]);
        let to = Address::from([0x02; 20]);
        let access_addr = Address::from([0x03; 20]);
        let json = serde_json::json!({
            "from": from,
            "to": to,
            "data": "0xabcd",
            "value": "0x3e8",
            "gas": "0x5208",
            "accessList": [
                {
                    "address": access_addr,
                    "storageKeys": ["0x0000000000000000000000000000000000000000000000000000000000000001"]
                }
            ]
        });
        let req: CallRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.from, Some(from));
        assert_eq!(req.to, Some(to));
        assert_eq!(req.data.as_ref().unwrap(), "0xabcd");
        assert_eq!(req.value.as_ref().unwrap(), "0x3e8");
        assert_eq!(req.gas.as_ref().unwrap(), "0x5208");
        assert_eq!(req.access_list.as_ref().unwrap().len(), 1);
        assert_eq!(req.access_list.as_ref().unwrap()[0].address, access_addr);
    }

    #[test]
    fn call_request_rejects_hex_addresses() {
        let result: Result<CallRequest, _> = serde_json::from_value(serde_json::json!({
            "from": "0x0000000000000000000000000000000000000001",
            "to": "0x0000000000000000000000000000000000000002",
        }));
        assert!(result.is_err(), "hex addresses must be rejected");
    }

    #[test]
    fn call_request_optional_fields_default_to_none() {
        let json = r#"{}"#;
        let req: CallRequest = serde_json::from_str(json).unwrap();
        assert!(req.from.is_none());
        assert!(req.to.is_none());
        assert!(req.data.is_none());
        assert!(req.value.is_none());
        assert!(req.gas.is_none());
        assert!(req.access_list.is_none());
    }
}
