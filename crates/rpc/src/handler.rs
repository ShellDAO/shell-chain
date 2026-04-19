//! RPC handler implementation backed by chain storage, world state, and mempool.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use jsonrpsee::types::ErrorObjectOwned;

use alloy_rlp::Encodable;
use shell_consensus::FinalityState;
use shell_core::{Block, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{MultiVerifier, Signer};
use shell_evm::bloom::BLOOM_SIZE;
use shell_evm::{ShellEvm, ShellStateDb};
use shell_mempool::TxPool;
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_storage::{ChainStore, KvStore, WitnessStore, WorldState, MAX_ADDRESS_TX_HISTORY_OFFSET};

use crate::admin::{AdminApiServer, NodeInfo, PeerInfo};
use crate::api::{
    DebugApiServer, EthApiServer, EvmApiServer, NetApiServer, ShellApiServer, TraceApiServer,
    Web3ApiServer,
};
use crate::dev_control::DynDevRpcControl;
use crate::filter::{RawLogFilter, MAX_BLOCK_RANGE};
use crate::filter_registry::{FilterKind, FilterRegistry};
use crate::subscriptions::{BlockEvent, SubscriptionTracker, SyncStatus};
use crate::types::*;

/// JSON-RPC handler wired to storage and mempool backends.
///
/// All methods are read-only against storage (no state mutation).
/// `send_raw_transaction` is a stub that returns an error until
/// full tx deserialization from raw bytes is implemented.
pub struct RpcHandler<S: KvStore + 'static> {
    chain_store: Arc<ChainStore<S>>,
    world_state: Arc<parking_lot::RwLock<WorldState<S>>>,
    tx_pool: Arc<TxPool>,
    chain_id: u64,
    /// Optional channel for broadcasting new transactions to the network layer.
    tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<SignedTransaction>>,
    /// Broadcast sender for block events (used by eth_subscribe).
    block_events: tokio::sync::broadcast::Sender<BlockEvent>,
    /// Broadcast sender for pending transaction hashes (eth_subscribe newPendingTransactions).
    pending_tx_events: tokio::sync::broadcast::Sender<ShellHash>,
    /// Broadcast sender for sync status changes (eth_subscribe syncing).
    sync_events: tokio::sync::broadcast::Sender<SyncStatus>,
    /// Tracks active subscriptions and enforces a global limit.
    subscription_tracker: SubscriptionTracker,
    /// Optional signer for governance proposals (set when node is a validator).
    proposer_signer: Option<Arc<dyn Signer>>,
    /// Address of the proposer (derived from the signer's public key).
    proposer_address: Option<Address>,
    /// Timestamp when the RPC handler was created, used for uptime calculation.
    start_time: Instant,
    /// F-073: counter for bloom filter false positives in eth_getLogs.
    bloom_false_positives: Arc<AtomicU64>,
    /// Last finalized block number, shared with the node's attestation handler.
    finalized_number: Arc<parking_lot::RwLock<u64>>,
    /// Finality state for pending attestation queries.
    finality: Arc<parking_lot::RwLock<FinalityState>>,
    /// Registry for poll-based filters (eth_newFilter, eth_newBlockFilter, etc.).
    filter_registry: Arc<FilterRegistry>,
    /// Live peer count from the P2P network layer.
    peer_count: Arc<std::sync::atomic::AtomicUsize>,
    /// Optional runtime dev-control handle for Hardhat/Foundry compatibility.
    dev_control: Option<DynDevRpcControl>,
    /// Admin context: RPC listen address and local P2P identity strings.
    /// Used by `admin_nodeInfo` and `admin_peers`.
    /// `admin_rpc_addr`   — HTTP/RPC listen address (e.g. "127.0.0.1:8545").
    /// `admin_peer_id`    — libp2p PeerId (base58).
    /// `admin_p2p_listen` — P2P multiaddr the node listens on.
    admin_rpc_addr: String,
    admin_peer_id: String,
    admin_p2p_listen: String,
    /// Optional witness store for Phase B witness bundle queries (B4).
    witness_store: Option<Arc<WitnessStore<S>>>,
}

impl<S: KvStore + 'static> Clone for RpcHandler<S> {
    fn clone(&self) -> Self {
        Self {
            chain_store: Arc::clone(&self.chain_store),
            world_state: Arc::clone(&self.world_state),
            tx_pool: Arc::clone(&self.tx_pool),
            chain_id: self.chain_id,
            tx_broadcast: self.tx_broadcast.clone(),
            block_events: self.block_events.clone(),
            pending_tx_events: self.pending_tx_events.clone(),
            sync_events: self.sync_events.clone(),
            subscription_tracker: self.subscription_tracker.clone(),
            proposer_signer: self.proposer_signer.clone(),
            proposer_address: self.proposer_address,
            start_time: self.start_time,
            bloom_false_positives: Arc::clone(&self.bloom_false_positives),
            finalized_number: Arc::clone(&self.finalized_number),
            finality: Arc::clone(&self.finality),
            filter_registry: Arc::clone(&self.filter_registry),
            peer_count: Arc::clone(&self.peer_count),
            dev_control: self.dev_control.clone(),
            admin_rpc_addr: self.admin_rpc_addr.clone(),
            admin_peer_id: self.admin_peer_id.clone(),
            admin_p2p_listen: self.admin_p2p_listen.clone(),
            witness_store: self.witness_store.clone(),
        }
    }
}

impl<S: KvStore + 'static> RpcHandler<S> {
    /// Create a new RPC handler with access to chain data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_store: Arc<ChainStore<S>>,
        world_state: Arc<parking_lot::RwLock<WorldState<S>>>,
        tx_pool: Arc<TxPool>,
        chain_id: u64,
        tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<SignedTransaction>>,
        block_events: tokio::sync::broadcast::Sender<BlockEvent>,
        finalized_number: Arc<parking_lot::RwLock<u64>>,
        finality: Arc<parking_lot::RwLock<FinalityState>>,
    ) -> Self {
        // F-139: use larger capacity to reduce dropped events under load.
        let (pending_tx_events, _) = tokio::sync::broadcast::channel(512);
        let (sync_events, _) = tokio::sync::broadcast::channel(16);
        let handler = Self {
            chain_store,
            world_state,
            tx_pool,
            chain_id,
            tx_broadcast,
            block_events,
            pending_tx_events,
            sync_events,
            subscription_tracker: SubscriptionTracker::default(),
            proposer_signer: None,
            proposer_address: None,
            start_time: Instant::now(),
            bloom_false_positives: Arc::new(AtomicU64::new(0)),
            finalized_number,
            finality,
            filter_registry: Arc::new(FilterRegistry::new()),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            dev_control: None,
            admin_rpc_addr: String::new(),
            admin_peer_id: String::new(),
            admin_p2p_listen: String::new(),
            witness_store: None,
        };
        FilterRegistry::start_cleanup(Arc::clone(&handler.filter_registry));
        handler
    }

    /// Attach a witness store for `shell_getBlockWitnesses` (Phase B4).
    pub fn with_witness_store(mut self, ws: Arc<WitnessStore<S>>) -> Self {
        self.witness_store = Some(ws);
        self
    }

    /// Set the proposer signer for governance RPCs.
    /// When set, enables `shell_proposeAddValidator` and `shell_proposeRemoveValidator`.
    pub fn with_proposer(mut self, signer: Arc<dyn Signer>, address: Address) -> Self {
        self.proposer_signer = Some(signer);
        self.proposer_address = Some(address);
        self
    }

    /// Set the live peer count handle from the P2P network layer.
    pub fn with_peer_count(mut self, peer_count: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.peer_count = peer_count;
        self
    }

    /// Set the runtime dev-control surface for `evm_*` RPC methods.
    pub fn with_dev_control(mut self, dev_control: DynDevRpcControl) -> Self {
        self.dev_control = Some(dev_control);
        self
    }

    /// Set the admin context for `admin_nodeInfo` and `admin_peers`.
    ///
    /// - `peer_id`      — libp2p PeerId in base58 format.
    /// - `p2p_listen`   — P2P multiaddr the node is listening on.
    ///
    /// The RPC listen address is populated separately from the bound server
    /// address after `start_rpc_server` returns.
    pub fn with_admin_context(mut self, peer_id: String, p2p_listen: String) -> Self {
        self.admin_peer_id = peer_id;
        self.admin_p2p_listen = p2p_listen;
        self
    }

    /// Set the RPC listen address used in `admin_nodeInfo` responses.
    /// Called internally by `start_rpc_server` after the address is bound.
    pub fn with_admin_rpc_addr(mut self, rpc_addr: String) -> Self {
        self.admin_rpc_addr = rpc_addr;
        self
    }

    /// Returns a reference to the block event broadcast sender.
    pub fn block_event_sender(&self) -> &tokio::sync::broadcast::Sender<BlockEvent> {
        &self.block_events
    }

    /// Returns a reference to the pending transaction hash broadcast sender.
    pub fn pending_tx_event_sender(&self) -> &tokio::sync::broadcast::Sender<ShellHash> {
        &self.pending_tx_events
    }

    /// Returns a reference to the sync status broadcast sender.
    pub fn sync_event_sender(&self) -> &tokio::sync::broadcast::Sender<SyncStatus> {
        &self.sync_events
    }

    /// Returns a reference to the subscription tracker.
    pub fn subscription_tracker(&self) -> &SubscriptionTracker {
        &self.subscription_tracker
    }

    /// F-073: returns the total number of bloom filter false positives detected
    /// during `eth_getLogs` calls (blocks that passed bloom but had no matching logs).
    pub fn bloom_false_positives(&self) -> u64 {
        self.bloom_false_positives.load(Ordering::Relaxed)
    }

    /// Validate and submit a signed transaction to the mempool.
    /// On success, also forwards the transaction to the network broadcast channel
    /// (if one was provided) so peers can include it in their mempools.
    fn submit_tx(&self, signed_tx: SignedTransaction) -> Result<ShellHash, ErrorObjectOwned> {
        // EIP-1559: warn (and reject) if max_fee below current base_fee.
        if let Ok(Some(head)) = self.chain_store.get_head_block() {
            let current_base_fee = head.header.base_fee_per_gas;
            if current_base_fee > 0 && signed_tx.tx.max_fee_per_gas < current_base_fee {
                return Err(ErrorObjectOwned::owned(
                    -32000,
                    format!(
                        "max fee per gas ({}) below current base fee ({})",
                        signed_tx.tx.max_fee_per_gas, current_base_fee
                    ),
                    None::<()>,
                ));
            }
        }

        let chain_store = &self.chain_store;
        let mut ws = self.world_state.write();

        // Clone before insert (which consumes the value) so we can broadcast on success.
        let tx_for_broadcast = self.tx_broadcast.as_ref().map(|_| signed_tx.clone());

        let verifier = MultiVerifier;
        let hash = self
            .tx_pool
            .insert(signed_tx, &mut ws, chain_store, &verifier)
            .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))?;

        // Broadcast to peers via the network channel.
        if let (Some(sender), Some(tx)) = (&self.tx_broadcast, tx_for_broadcast) {
            let _ = sender.send(tx);
        }

        // Notify pending-tx subscribers about the new transaction hash.
        let _ = self.pending_tx_events.send(hash);

        Ok(hash)
    }

    /// Build, sign, and submit a governance transaction to the ValidatorRegistry.
    /// Returns the transaction hash on success.
    fn propose_validator_tx(&self, calldata: Vec<u8>) -> Result<ShellHash, ErrorObjectOwned> {
        let signer = self.proposer_signer.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "node is not configured as a validator", None::<()>)
        })?;
        let proposer_addr = self.proposer_address.ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "node is not configured as a validator", None::<()>)
        })?;

        let nonce = {
            let ws = self.world_state.read();
            ws.get_nonce(&proposer_addr).map_err(internal_err)?
        };

        let tx = Transaction {
            chain_id: self.chain_id,
            nonce,
            to: Some(shell_evm::registry_address()),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(&calldata),
            gas_limit: 100_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let tx_hash = tx.hash();
        let signature = signer
            .sign(tx_hash.0.as_slice())
            .map_err(|e| internal_err(format!("signing failed: {e}")))?;

        let pubkey = signer.public_key().to_vec();
        let signed_tx = SignedTransaction::with_pubkey(proposer_addr, tx, signature, pubkey);

        self.submit_tx(signed_tx)
    }

    /// Execute a call against a temporary EVM and return (output_bytes, gas_used).
    fn execute_call(
        &self,
        req: &crate::types::CallRequest,
    ) -> Result<(Vec<u8>, u64), ErrorObjectOwned> {
        let store = self.chain_store.store().clone();

        // Snapshot current state root so the temp WorldState sees committed data.
        let state_root = {
            let mut ws = self.world_state.write();
            ws.state_root().map_err(internal_err)?
        };

        let world_state = WorldState::at_root(store.clone(), &state_root).map_err(internal_err)?;
        let chain_store = ChainStore::new(store);
        let state_db = ShellStateDb::new(world_state, chain_store);
        let mut evm = ShellEvm::new(state_db, self.chain_id);

        let from = req.from.unwrap_or(Address::ZERO);
        let gas_limit = req
            .gas
            .as_deref()
            .map(|s| parse_hex_u64(s))
            .transpose()?
            .unwrap_or(30_000_000);
        let value = req
            .value
            .as_deref()
            .map(|s| parse_hex_u256(s))
            .transpose()?
            .unwrap_or(U256::ZERO);
        let data = req
            .data
            .as_deref()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                hex::decode(s).map(Bytes::from)
            })
            .transpose()
            .map_err(|e| internal_err(format!("invalid call data hex: {e}")))?
            .unwrap_or_default();

        let access_list = req
            .access_list
            .as_ref()
            .map(|list| {
                list.iter()
                    .map(|item| {
                        let storage_keys = item
                            .storage_keys
                            .iter()
                            .map(|k| parse_hex_hash(k))
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok(shell_core::AccessListItem {
                            address: item.address,
                            storage_keys,
                        })
                    })
                    .collect::<Result<Vec<_>, ErrorObjectOwned>>()
            })
            .transpose()?;

        let tx = Transaction {
            chain_id: self.chain_id,
            nonce: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            gas_limit,
            to: req.to,
            value,
            data,
            access_list,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]);
        let signed = SignedTransaction::new(from, tx, sig);

        let header = BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Bytes::default(),
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::default(),
            proposer: Address::ZERO,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        };

        let result = evm
            .execute_tx(&signed, &header, 0, 0)
            .map_err(|e| internal_err(format!("EVM execution failed: {e}")))?;

        Ok((result.output.clone(), result.gas_used))
    }

    /// Parse a block number string with finality awareness.
    /// Returns `None` for "latest"/"pending" (= head), `Some(n)` for specific numbers.
    /// "finalized" and "safe" resolve to the shared finalized block number.
    fn parse_block_number(&self, s: &str) -> Result<Option<u64>, ErrorObjectOwned> {
        match parse_block_tag(s)? {
            BlockTag::Latest | BlockTag::Pending => Ok(None),
            BlockTag::Finalized => {
                let num = *self.finalized_number.read();
                Ok(Some(num))
            }
            BlockTag::Number(n) => Ok(Some(n)),
        }
    }

    /// Look up a transaction and its containing block by hex-encoded hash.
    /// Returns (block, signed_tx, receipt, tx_index).
    fn lookup_tx_with_block(
        &self,
        tx_hash: &str,
    ) -> Result<
        (
            Block,
            SignedTransaction,
            shell_core::TransactionReceipt,
            u32,
        ),
        ErrorObjectOwned,
    > {
        let hex_str = tx_hash.strip_prefix("0x").unwrap_or(tx_hash);
        let hash_bytes =
            hex::decode(hex_str).map_err(|e| internal_err(format!("invalid tx hash hex: {e}")))?;
        let hash = ShellHash::try_from_slice(&hash_bytes)
            .map_err(|e| internal_err(format!("invalid tx hash length: {e}")))?;

        let (block_hash, tx_index) = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?
            .ok_or_else(|| internal_err("transaction not found"))?;

        let block = self
            .chain_store
            .get_block_by_hash(&block_hash)
            .map_err(internal_err)?
            .ok_or_else(|| internal_err("block not found"))?;

        let tx = block
            .transactions
            .get(tx_index as usize)
            .ok_or_else(|| internal_err("transaction not in block"))?
            .clone();

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .ok_or_else(|| internal_err("receipts not found"))?;

        let receipt = receipts
            .get(tx_index as usize)
            .ok_or_else(|| internal_err("receipt not found"))?
            .clone();

        Ok((block, tx, receipt, tx_index))
    }

    /// Resolve a block number string ("latest", "0x...", etc.) to a Block.
    fn resolve_block(&self, block_number: &str) -> Result<Block, ErrorObjectOwned> {
        let num_opt = self.parse_block_number(block_number)?;
        match num_opt {
            Some(n) => self
                .chain_store
                .get_block_by_number(n)
                .map_err(internal_err)?
                .ok_or_else(|| internal_err(format!("block {n} not found"))),
            None => {
                // "latest" — resolve head
                let head = self.chain_store.get_head_block().map_err(internal_err)?;
                head.ok_or_else(|| internal_err("chain has no blocks"))
            }
        }
    }

    /// Build an OpenEthereum-compatible trace entry for a single transaction.
    fn build_oe_trace(
        &self,
        tx: &SignedTransaction,
        receipt: Option<&shell_core::TransactionReceipt>,
        block_number: u64,
        block_hash: ShellHash,
        tx_position: u64,
    ) -> OeTrace {
        let is_create = tx.tx.to.is_none();
        let trace_type = if is_create { "create" } else { "call" };
        let call_type = if is_create {
            None
        } else {
            Some("call".to_string())
        };

        let action = OeTraceAction {
            call_type,
            from: tx.sender(),
            to: tx.tx.to,
            gas: hex_u64(tx.tx.gas_limit),
            value: hex_u256(tx.tx.value),
            input: hex_bytes(tx.tx.data.as_ref()),
        };

        let (result, error) = match receipt {
            Some(r) if r.succeeded() => {
                let output = OeTraceOutput {
                    gas_used: hex_u64(r.gas_used),
                    output: "0x".to_string(),
                };
                (Some(output), None)
            }
            Some(r) => {
                let output = OeTraceOutput {
                    gas_used: hex_u64(r.gas_used),
                    output: "0x".to_string(),
                };
                (Some(output), Some("execution reverted".to_string()))
            }
            None => (None, Some("receipt not available".to_string())),
        };

        OeTrace {
            action,
            result,
            error,
            subtraces: 0,
            trace_address: vec![],
            trace_type: trace_type.to_string(),
            block_number,
            block_hash,
            transaction_hash: tx.hash(),
            transaction_position: tx_position,
        }
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> EvmApiServer for RpcHandler<S> {
    async fn mine(&self, blocks: Option<u64>) -> Result<serde_json::Value, ErrorObjectOwned> {
        let count = blocks.unwrap_or(1).max(1);
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "evm namespace not enabled on this node", None::<()>)
        })?;
        dev.mine_blocks(count).map_err(internal_err)?;
        Ok(serde_json::json!({
            "blocksMined": hex_u64(count),
        }))
    }

    async fn set_next_block_timestamp(
        &self,
        timestamp: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "evm namespace not enabled on this node", None::<()>)
        })?;
        let applied = dev
            .set_next_block_timestamp(timestamp)
            .map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(applied)))
    }

    async fn increase_time(&self, seconds: u64) -> Result<serde_json::Value, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "evm namespace not enabled on this node", None::<()>)
        })?;
        let total = dev.increase_time(seconds).map_err(internal_err)?;
        Ok(serde_json::json!(hex_u64(total)))
    }

    async fn snapshot(&self) -> Result<String, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "evm namespace not enabled on this node", None::<()>)
        })?;
        dev.snapshot().map_err(internal_err)
    }

    async fn revert(&self, snapshot_id: String) -> Result<bool, ErrorObjectOwned> {
        let dev = self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "evm namespace not enabled on this node", None::<()>)
        })?;
        dev.revert(&snapshot_id).map_err(internal_err)
    }
}

/// Convert a storage error into a JSON-RPC internal error.
fn internal_err(msg: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg.to_string(), None::<()>)
}

/// Convert a user input problem into a JSON-RPC invalid params error.
fn invalid_params_err(msg: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.to_string(), None::<()>)
}

/// Parse a user-facing address string (`pq1...` or legacy hex).
fn parse_address(s: &str) -> Result<Address, ErrorObjectOwned> {
    Address::parse(s).map_err(|e| internal_err(format!("invalid address: {e}")))
}

/// Parse a 32-byte hex string into `ShellHash`.
fn parse_hex_hash(s: &str) -> Result<ShellHash, ErrorObjectOwned> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| internal_err(format!("invalid hash hex: {e}")))?;
    ShellHash::try_from_slice(&bytes).map_err(|e| internal_err(format!("invalid hash length: {e}")))
}

/// Parse a hex string "0x..." into u64.
fn parse_hex_u64(s: &str) -> Result<u64, ErrorObjectOwned> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|_| internal_err(format!("invalid hex u64: 0x{s}")))
}

/// Parse a hex string "0x..." into U256.
fn parse_hex_u256(s: &str) -> Result<U256, ErrorObjectOwned> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // F-066: reject oversized input to prevent silent truncation.
    if s.len() > 64 {
        return Err(internal_err(format!(
            "hex string too long for U256: {} chars (max 64)",
            s.len()
        )));
    }
    let bytes = hex::decode(if s.len() < 64 {
        format!("{:0>64}", s)
    } else {
        s.to_string()
    })
    .map_err(|_| internal_err(format!("invalid hex U256: 0x{s}")))?;
    Ok(U256::from_be_slice(&bytes))
}

/// Parsed block number tag.
enum BlockTag {
    /// Resolve to the current head block.
    Latest,
    /// Construct a pending pseudo-block from mempool.
    Pending,
    /// Resolve to the last finalized (or "safe") block.
    Finalized,
    /// A specific block number.
    Number(u64),
}

/// Parse a block number string: "latest", "pending", "earliest",
/// "finalized", "safe", or "0x..." hex.
fn parse_block_tag(s: &str) -> Result<BlockTag, ErrorObjectOwned> {
    match s {
        "latest" => Ok(BlockTag::Latest),
        "safe" | "finalized" => Ok(BlockTag::Finalized),
        "pending" => Ok(BlockTag::Pending),
        "earliest" => Ok(BlockTag::Number(0)),
        hex if hex.starts_with("0x") => u64::from_str_radix(&hex[2..], 16)
            .map(BlockTag::Number)
            .map_err(|_| internal_err(format!("invalid block number: {hex}"))),
        _ => Err(internal_err(format!("invalid block number: {s}"))),
    }
}

/// Legacy helper used by callers that don't need pending semantics.
/// `Finalized` is treated the same as `Latest` (resolves to head) because
/// the caller has no access to the shared finalized-number state.
#[allow(dead_code)]
fn parse_block_number(s: &str) -> Result<Option<u64>, ErrorObjectOwned> {
    match parse_block_tag(s)? {
        BlockTag::Latest | BlockTag::Pending | BlockTag::Finalized => Ok(None),
        BlockTag::Number(n) => Ok(Some(n)),
    }
}

/// F-100: validate that a block tag is well-formed.
/// Returns an error for malformed block parameters.
fn validate_block_is_latest(s: &str) -> Result<(), ErrorObjectOwned> {
    match s {
        "latest" | "pending" | "safe" | "finalized" | "earliest" => Ok(()),
        hex if hex.starts_with("0x") => {
            let _ = u64::from_str_radix(&hex[2..], 16)
                .map_err(|_| internal_err(format!("invalid block number: {hex}")))?;
            Ok(())
        }
        _ => Err(internal_err(format!("invalid block tag: {s}"))),
    }
}

/// Convert a core Block to an RpcBlock response.
///
/// When `full_txs` is true the `transactions` array contains full
/// [`RpcTransaction`] objects (as required by `eth_getBlockByNumber` /
/// `eth_getBlockByHash`).  When false it contains only transaction hashes.
fn block_to_rpc(block: &Block, full_txs: bool) -> RpcBlock {
    // F-074: approximate block size from RLP-encoded lengths.
    let header_size = block.header.length();
    let tx_size: usize = block.transactions.iter().map(|tx| tx.length()).sum();
    let size = header_size + tx_size;

    // F-072: logsBloom — hex-encode the 256-byte bloom or emit zero bloom.
    let logs_bloom = if block.header.logs_bloom.len() == BLOOM_SIZE {
        hex_bytes(block.header.logs_bloom.as_ref())
    } else {
        format!("0x{}", "00".repeat(BLOOM_SIZE))
    };

    let transactions = if full_txs {
        serde_json::to_value(
            block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    tx_to_rpc(
                        tx,
                        Some(block.hash()),
                        Some(block.header.number),
                        Some(i as u32),
                        Some(block.header.base_fee_per_gas),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default()
    } else {
        serde_json::to_value(
            block
                .transactions
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<ShellHash>>(),
        )
        .unwrap_or_default()
    };

    RpcBlock {
        hash: block.hash(),
        parent_hash: block.header.parent_hash,
        number: hex_u64(block.header.number),
        timestamp: hex_u64(block.header.timestamp),
        gas_limit: hex_u64(block.header.gas_limit),
        gas_used: hex_u64(block.header.gas_used),
        miner: block.header.proposer,
        state_root: block.header.state_root,
        transactions_root: block.header.transactions_root,
        receipts_root: block.header.receipts_root,
        transactions,
        size: hex_u64(size as u64),
        base_fee_per_gas: hex_u64(block.header.base_fee_per_gas),
        // F-072: standard Ethereum compatibility fields
        total_difficulty: "0x1".into(),
        sha3_uncles: crate::types::EMPTY_OMMER_HASH.into(),
        uncles: vec![],
        nonce: "0x0000000000000000".into(),
        difficulty: "0x1".into(),
        mix_hash: ShellHash::ZERO,
        extra_data: hex_bytes(block.header.extra_data.as_ref()),
        logs_bloom,
        withdrawals_root: format!("{:?}", block.header.withdrawals_root),
        parent_beacon_block_root: format!("{:?}", block.header.parent_beacon_block_root),
        blob_gas_used: hex_u64(block.header.blob_gas_used),
        excess_blob_gas: hex_u64(block.header.excess_blob_gas),
        sig_aggregate_proof_size: block
            .header
            .sig_aggregate_proof
            .as_ref()
            .map(|p| p.len() as u64),
        sig_aggregate_proof: block
            .header
            .sig_aggregate_proof
            .as_ref()
            .map(|p| hex_bytes(p.as_ref())),
    }
}

/// Convert a SignedTransaction to an RpcTransaction response.
fn tx_to_rpc(
    tx: &SignedTransaction,
    block_hash: Option<ShellHash>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
    base_fee: Option<u64>,
) -> RpcTransaction {
    // EIP-1559: mined txs report effective gas price; pending txs report max_fee
    let gas_price = match base_fee {
        Some(base) => shell_core::effective_gas_price(
            tx.tx.max_fee_per_gas,
            tx.tx.max_priority_fee_per_gas,
            base,
        ),
        None => tx.tx.max_fee_per_gas,
    };
    RpcTransaction {
        hash: tx.hash(),
        block_hash,
        block_number: block_number.map(hex_u64),
        transaction_index: tx_index.map(|i| hex_u64(i as u64)),
        from: tx.sender(),
        to: tx.tx.to,
        value: hex_u256(tx.tx.value),
        gas: hex_u64(tx.tx.gas_limit),
        gas_price: hex_u64(gas_price),
        max_fee_per_gas: hex_u64(tx.tx.max_fee_per_gas),
        max_priority_fee_per_gas: hex_u64(tx.tx.max_priority_fee_per_gas),
        nonce: hex_u64(tx.tx.nonce),
        input: hex_bytes(tx.tx.data.as_ref()),
        chain_id: hex_u64(tx.tx.chain_id),
        tx_type: format!("{:#x}", tx.tx.tx_type),
        v: "0x0".into(),
        r: "0x0".into(),
        s: "0x0".into(),
        access_list: tx.tx.access_list.as_ref().map(|list| {
            list.iter()
                .map(|item| RpcAccessListItem {
                    address: item.address,
                    storage_keys: item.storage_keys.iter().map(|k| format!("{}", k)).collect(),
                })
                .collect()
        }),
        max_fee_per_blob_gas: tx.tx.max_fee_per_blob_gas.map(hex_u64),
        blob_versioned_hashes: tx.tx.blob_versioned_hashes.clone(),
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> EthApiServer for RpcHandler<S> {
    async fn block_number(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let num = head.map(|b| b.number()).unwrap_or(0);
        Ok(hex_u64(num))
    }

    async fn chain_id(&self) -> Result<String, ErrorObjectOwned> {
        Ok(hex_u64(self.chain_id))
    }

    async fn syncing(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Shell-chain has no sync protocol yet; always report "not syncing".
        Ok(serde_json::Value::Bool(false))
    }

    async fn mining(&self) -> Result<bool, ErrorObjectOwned> {
        // Return true if the node is configured as a validator.
        Ok(self.proposer_signer.is_some())
    }

    async fn hashrate(&self) -> Result<String, ErrorObjectOwned> {
        // PoA consensus — no mining, hashrate is always zero.
        Ok("0x0".to_string())
    }

    async fn accounts(&self) -> Result<Vec<Address>, ErrorObjectOwned> {
        // Node does not manage user accounts.
        Ok(vec![])
    }

    async fn sign(&self, _address: Address, _data: String) -> Result<String, ErrorObjectOwned> {
        Err(ErrorObjectOwned::owned(
            -32601,
            "eth_sign is not supported: node does not hold private keys",
            None::<()>,
        ))
    }

    async fn sign_transaction(&self, _tx: serde_json::Value) -> Result<String, ErrorObjectOwned> {
        Err(ErrorObjectOwned::owned(
            -32601,
            "eth_signTransaction is not supported: node does not hold private keys",
            None::<()>,
        ))
    }

    async fn get_compilers(&self) -> Result<Vec<String>, ErrorObjectOwned> {
        // Deprecated method; always returns an empty array.
        Ok(vec![])
    }

    async fn protocol_version(&self) -> Result<String, ErrorObjectOwned> {
        // Protocol version 69 (Cancun-compatible).
        Ok("0x45".to_string())
    }

    async fn get_block_by_number(
        &self,
        number: String,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let tag = parse_block_tag(&number)?;
        match tag {
            BlockTag::Finalized => {
                let n = *self.finalized_number.read();
                let block = self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?;
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Number(n) => {
                let block = self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?;
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Latest => {
                let block = self.chain_store.get_head_block().map_err(internal_err)?;
                Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
            }
            BlockTag::Pending => {
                // F-075: construct a pseudo-block from the mempool.
                let head = self.chain_store.get_head_block().map_err(internal_err)?;
                let head = match head {
                    Some(b) => b,
                    None => return Ok(None),
                };
                let all_pending = self.tx_pool.pending(1000);
                // F-101: cap pending txs by gas_limit to prevent oversized pseudo-blocks.
                let gas_limit = head.header.gas_limit;
                let mut cumulative_gas: u64 = 0;
                let pending_txs: Vec<_> = all_pending
                    .into_iter()
                    .take_while(|tx| {
                        cumulative_gas = cumulative_gas.saturating_add(tx.tx.gas_limit);
                        cumulative_gas <= gas_limit
                    })
                    .collect();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let tx_size: usize = pending_txs.iter().map(|tx| tx.length()).sum();
                let header_size = head.header.length();
                let size = header_size + tx_size;

                let transactions = if full_txs {
                    serde_json::to_value(
                        pending_txs
                            .iter()
                            .map(|tx| tx_to_rpc(tx, None, Some(head.header.number + 1), None, None))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default()
                } else {
                    serde_json::to_value(
                        pending_txs
                            .iter()
                            .map(|tx| tx.hash())
                            .collect::<Vec<ShellHash>>(),
                    )
                    .unwrap_or_default()
                };

                let pending_block = RpcBlock {
                    hash: ShellHash::ZERO,
                    parent_hash: head.hash(),
                    number: hex_u64(head.header.number + 1),
                    timestamp: hex_u64(now),
                    gas_limit: hex_u64(head.header.gas_limit),
                    gas_used: hex_u64(0),
                    miner: head.header.proposer,
                    state_root: head.header.state_root,
                    transactions_root: ShellHash::ZERO,
                    receipts_root: ShellHash::ZERO,
                    transactions,
                    size: hex_u64(size as u64),
                    base_fee_per_gas: hex_u64(head.header.base_fee_per_gas),
                    total_difficulty: "0x1".into(),
                    sha3_uncles: crate::types::EMPTY_OMMER_HASH.into(),
                    uncles: vec![],
                    nonce: "0x0000000000000000".into(),
                    difficulty: "0x1".into(),
                    mix_hash: ShellHash::ZERO,
                    extra_data: "0x".into(),
                    logs_bloom: format!("0x{}", "00".repeat(BLOOM_SIZE)),
                    withdrawals_root: format!("{:?}", ShellHash::ZERO),
                    parent_beacon_block_root: format!("{:?}", ShellHash::ZERO),
                    blob_gas_used: hex_u64(0),
                    excess_blob_gas: hex_u64(0),
                    sig_aggregate_proof: None,
                    sig_aggregate_proof_size: None,
                };
                Ok(Some(pending_block))
            }
        }
    }

    async fn get_block_by_hash(
        &self,
        hash: ShellHash,
        full_txs: bool,
    ) -> Result<Option<RpcBlock>, ErrorObjectOwned> {
        let block = self
            .chain_store
            .get_block_by_hash(&hash)
            .map_err(internal_err)?;
        Ok(block.as_ref().map(|b| block_to_rpc(b, full_txs)))
    }

    async fn get_transaction_by_hash(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcTransaction>, ErrorObjectOwned> {
        // Check mempool first
        if let Some(pending_tx) = self.tx_pool.get(&hash) {
            return Ok(Some(tx_to_rpc(&pending_tx, None, None, None, None)));
        }

        // Then check on-chain index
        let location = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?;

        if let Some((block_hash, tx_index)) = location {
            let block = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?;
            if let Some(block) = block {
                if let Some(tx) = block.transactions.get(tx_index as usize) {
                    return Ok(Some(tx_to_rpc(
                        tx,
                        Some(block_hash),
                        Some(block.number()),
                        Some(tx_index),
                        Some(block.header.base_fee_per_gas),
                    )));
                }
            }
        }

        Ok(None)
    }

    async fn get_transaction_receipt(
        &self,
        hash: ShellHash,
    ) -> Result<Option<RpcReceipt>, ErrorObjectOwned> {
        let location = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?;

        if let Some((block_hash, tx_index)) = location {
            let block = self
                .chain_store
                .get_block_by_hash(&block_hash)
                .map_err(internal_err)?;
            let receipts = self
                .chain_store
                .get_receipts(&block_hash)
                .map_err(internal_err)?;
            if let (Some(block), Some(receipts)) = (block, receipts) {
                if let Some(receipt) = receipts.get(tx_index as usize) {
                    // F-067: populate from/to/effective_gas_price from the transaction.
                    let (from, to, eff_gas_price, tx_type_val) =
                        if let Some(tx) = block.transactions.get(tx_index as usize) {
                            let price = shell_core::effective_gas_price(
                                tx.tx.max_fee_per_gas,
                                tx.tx.max_priority_fee_per_gas,
                                block.header.base_fee_per_gas,
                            );
                            (tx.sender(), tx.tx.to, price, tx.tx.tx_type)
                        } else {
                            (Address::ZERO, None, 0, 2u8)
                        };

                    return Ok(Some(RpcReceipt {
                        transaction_hash: receipt.tx_hash,
                        block_hash,
                        block_number: hex_u64(receipt.block_number),
                        transaction_index: hex_u64(tx_index as u64),
                        from,
                        to,
                        status: hex_u64(receipt.status as u64),
                        gas_used: hex_u64(receipt.gas_used),
                        cumulative_gas_used: hex_u64(receipt.cumulative_gas_used),
                        effective_gas_price: hex_u64(eff_gas_price),
                        contract_address: receipt.contract_address,
                        logs: receipt
                            .logs
                            .iter()
                            .map(|log| RpcLog {
                                address: log.address,
                                topics: log.topics.clone(),
                                data: hex_bytes(log.data.as_ref()),
                            })
                            .collect(),
                        logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                        tx_type: format!("{:#x}", tx_type_val),
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn get_block_receipts(&self, block: String) -> Result<Vec<RpcReceipt>, ErrorObjectOwned> {
        // Resolve block identifier (number, tag, or hash)
        let block_obj = if block.starts_with("0x") && block.len() == 66 {
            let hex_str = block.strip_prefix("0x").unwrap_or(&block);
            let hash_bytes = hex::decode(hex_str)
                .map_err(|e| internal_err(format!("invalid block hash hex: {e}")))?;
            let hash = ShellHash::try_from_slice(&hash_bytes)
                .map_err(|e| internal_err(format!("invalid block hash: {e}")))?;
            self.chain_store
                .get_block_by_hash(&hash)
                .map_err(internal_err)?
        } else {
            match self.parse_block_number(&block)? {
                Some(num) => self
                    .chain_store
                    .get_block_by_number(num)
                    .map_err(internal_err)?,
                None => self.chain_store.get_head_block().map_err(internal_err)?,
            }
        };

        let block_obj = match block_obj {
            Some(b) => b,
            None => return Ok(vec![]),
        };

        let block_hash = block_obj.hash();
        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();

        let mut rpc_receipts = Vec::with_capacity(receipts.len());
        for (i, receipt) in receipts.iter().enumerate() {
            let (from, to, eff_gas_price, tx_type_val) =
                if let Some(tx) = block_obj.transactions.get(i) {
                    let price = shell_core::effective_gas_price(
                        tx.tx.max_fee_per_gas,
                        tx.tx.max_priority_fee_per_gas,
                        block_obj.header.base_fee_per_gas,
                    );
                    (tx.sender(), tx.tx.to, price, tx.tx.tx_type)
                } else {
                    (Address::ZERO, None, 0, 2u8)
                };

            rpc_receipts.push(RpcReceipt {
                transaction_hash: receipt.tx_hash,
                block_hash,
                block_number: hex_u64(receipt.block_number),
                transaction_index: hex_u64(i as u64),
                from,
                to,
                status: hex_u64(receipt.status as u64),
                gas_used: hex_u64(receipt.gas_used),
                cumulative_gas_used: hex_u64(receipt.cumulative_gas_used),
                effective_gas_price: hex_u64(eff_gas_price),
                contract_address: receipt.contract_address,
                logs: receipt
                    .logs
                    .iter()
                    .map(|log| RpcLog {
                        address: log.address,
                        topics: log.topics.clone(),
                        data: hex_bytes(log.data.as_ref()),
                    })
                    .collect(),
                logs_bloom: hex_bytes(receipt.logs_bloom.as_ref()),
                tx_type: format!("{:#x}", tx_type_val),
            });
        }

        Ok(rpc_receipts)
    }

    async fn get_balance(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        // F-100: validate block parameter — reject malformed block tags.
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let balance = ws.get_balance(&address).map_err(internal_err)?;
        Ok(hex_u256(balance))
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let nonce = ws.get_nonce(&address).map_err(internal_err)?;
        Ok(hex_u64(nonce))
    }

    async fn gas_price(&self) -> Result<String, ErrorObjectOwned> {
        // Return the base fee from the latest block, or INITIAL_BASE_FEE if no blocks exist.
        let base_fee = match self.chain_store.get_head_block() {
            Ok(Some(head)) if head.header.base_fee_per_gas > 0 => head.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };
        Ok(hex_u64(base_fee))
    }

    async fn max_priority_fee_per_gas(&self) -> Result<String, ErrorObjectOwned> {
        // PoA chain: no fee market competition, priority fee is always 0.
        Ok(hex_u64(0))
    }

    async fn fee_history(
        &self,
        block_count: String,
        newest_block: String,
        _reward_percentiles: Option<Vec<f64>>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let latest = match self.parse_block_number(&newest_block)? {
            Some(n) => n,
            None => {
                // "latest" — get head block number
                match self.chain_store.get_head_block() {
                    Ok(Some(head)) => head.header.number,
                    _ => 0,
                }
            }
        };

        let count = parse_hex_u64(&block_count)?.min(1024);

        let oldest = latest.saturating_sub(count.saturating_sub(1));

        let mut base_fee_per_gas = Vec::new();
        let mut gas_used_ratio = Vec::new();

        for num in oldest..=latest {
            match self.chain_store.get_block_by_number(num) {
                Ok(Some(block)) => {
                    let h = &block.header;
                    base_fee_per_gas.push(hex_u64(h.base_fee_per_gas));
                    let ratio = if h.gas_limit > 0 {
                        h.gas_used as f64 / h.gas_limit as f64
                    } else {
                        0.0
                    };
                    gas_used_ratio.push(ratio);
                }
                _ => {
                    base_fee_per_gas.push(hex_u64(0));
                    gas_used_ratio.push(0.0);
                }
            }
        }

        // Append next block's predicted base fee (one more entry than gas_used_ratio).
        if let Ok(Some(head)) = self.chain_store.get_block_by_number(latest) {
            let next = shell_core::fee::calculate_base_fee(
                head.header.gas_used,
                head.header.gas_limit,
                head.header.base_fee_per_gas,
            );
            base_fee_per_gas.push(hex_u64(next));
        } else {
            base_fee_per_gas.push(hex_u64(shell_core::INITIAL_BASE_FEE));
        }

        Ok(serde_json::json!({
            "oldestBlock": hex_u64(oldest),
            "baseFeePerGas": base_fee_per_gas,
            "gasUsedRatio": gas_used_ratio,
            "reward": []
        }))
    }

    async fn send_raw_transaction(&self, data: String) -> Result<ShellHash, ErrorObjectOwned> {
        // Decode hex payload: "0x" + hex-encoded transaction bytes.
        let raw = data.strip_prefix("0x").unwrap_or(&data);
        let bytes = hex::decode(raw).map_err(|e| internal_err(format!("invalid hex: {e}")))?;

        // Try RLP decoding first (standard Ethereum format), then JSON (legacy).
        let signed_tx: SignedTransaction = {
            let mut slice = bytes.as_slice();
            match alloy_rlp::Decodable::decode(&mut slice) {
                Ok(tx) if slice.is_empty() => tx,
                Ok(_) => {
                    // RLP decoded but trailing bytes remain — reject per Geth behavior.
                    return Err(internal_err(
                        "invalid transaction: RLP has trailing bytes".to_string(),
                    ));
                }
                Err(_) => serde_json::from_slice::<SignedTransaction>(&bytes).map_err(|e| {
                    internal_err(format!("invalid transaction: not valid RLP or JSON ({e})"))
                })?,
            }
        };

        self.submit_tx(signed_tx)
    }

    async fn call(
        &self,
        tx: crate::types::CallRequest,
        _block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        let (output, _gas_used) = self.execute_call(&tx)?;
        Ok(hex_bytes(&output))
    }

    async fn estimate_gas(
        &self,
        tx: crate::types::CallRequest,
    ) -> Result<String, ErrorObjectOwned> {
        let (_output, gas_used) = self.execute_call(&tx)?;
        // Add a 20% buffer to the estimated gas, with a minimum of 21000.
        let estimate = std::cmp::max((gas_used as f64 * 1.2) as u64, 21_000);
        Ok(hex_u64(estimate))
    }

    async fn create_access_list(
        &self,
        tx: crate::types::CallRequest,
        _block: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (_output, gas_used) = self.execute_call(&tx)?;
        // Simplified implementation: return the provided access list (or empty)
        // and the estimated gas.
        let access_list = tx
            .access_list
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "address": item.address,
                    "storageKeys": item.storage_keys,
                })
            })
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "accessList": access_list,
            "gasUsed": hex_u64(gas_used),
        }))
    }

    async fn get_code(
        &self,
        address: Address,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
        }
        let ws = self.world_state.read();
        let code_hash = ws.get_code_hash(&address).map_err(internal_err)?;
        match code_hash {
            Some(hash) => {
                let code = self.chain_store.get_code(&hash).map_err(internal_err)?;
                match code {
                    Some(bytes) => Ok(hex_bytes(&bytes)),
                    None => Ok("0x".into()),
                }
            }
            None => Ok("0x".into()),
        }
    }

    async fn get_storage_at(
        &self,
        address: Address,
        position: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        if let Some(ref tag) = block {
            validate_block_is_latest(tag)?;
        }
        let key_u256 = parse_hex_u256(&position)?;
        let key = ShellHash::from(alloy_primitives::B256::from(key_u256));
        let ws = self.world_state.read();
        let value = ws.get_storage(&address, &key).map_err(internal_err)?;
        // Return as zero-padded 32-byte hex string.
        Ok(format!("0x{}", hex::encode(value.as_bytes())))
    }

    async fn get_logs(
        &self,
        raw_filter: RawLogFilter,
    ) -> Result<Vec<RpcLogWithMeta>, ErrorObjectOwned> {
        // Resolve "latest" block number.
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);

        let filter = raw_filter.into_filter(latest);

        let from = filter.from_block.unwrap_or(latest);
        let to = filter.to_block.unwrap_or(latest);

        if from > to {
            return Ok(vec![]);
        }

        // Cap range to prevent DoS.
        if to - from + 1 > MAX_BLOCK_RANGE {
            return Err(ErrorObjectOwned::owned(
                -32005,
                format!(
                    "query returned more than {} blocks; cap the range",
                    MAX_BLOCK_RANGE
                ),
                None::<()>,
            ));
        }

        let mut results = Vec::new();

        for block_num in from..=to {
            let block = match self
                .chain_store
                .get_block_by_number(block_num)
                .map_err(internal_err)?
            {
                Some(b) => b,
                None => continue,
            };

            // Fast path: check block-level bloom filter.
            if !filter.matches_bloom(block.header.logs_bloom.as_ref()) {
                continue;
            }

            let block_hash = block.hash();

            let receipts = self
                .chain_store
                .get_receipts(&block_hash)
                .map_err(internal_err)?
                .unwrap_or_default();

            // F-073: track bloom false positives — count results before this block.
            let results_before = results.len();

            // Global log index across all receipts in this block.
            let mut global_log_index: u64 = 0;

            for (tx_idx, receipt) in receipts.iter().enumerate() {
                // Per-receipt bloom fast path.
                if receipt.logs_bloom.len() == BLOOM_SIZE
                    && !filter.matches_bloom(receipt.logs_bloom.as_ref())
                {
                    global_log_index += receipt.logs.len() as u64;
                    continue;
                }

                for log in &receipt.logs {
                    if filter.matches_log(log) {
                        results.push(RpcLogWithMeta {
                            address: log.address,
                            topics: log.topics.clone(),
                            data: hex_bytes(log.data.as_ref()),
                            block_number: hex_u64(block_num),
                            block_hash,
                            transaction_hash: receipt.tx_hash,
                            transaction_index: hex_u64(tx_idx as u64),
                            log_index: hex_u64(global_log_index),
                            removed: false,
                        });
                    }
                    global_log_index += 1;
                }
            }

            // F-073: bloom passed but no logs matched → false positive.
            if results.len() == results_before {
                self.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(results)
    }

    async fn new_filter(&self, mut filter: RawLogFilter) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);
        // F-125: resolve from_block at creation time so get_filter_logs
        // does not re-scan from block 0 on every call.
        if filter.from_block.is_none() {
            filter.from_block = Some(format!("0x{:x}", latest));
        }
        let id = self
            .filter_registry
            .new_filter(FilterKind::Log(filter), latest)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn new_block_filter(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);
        let id = self
            .filter_registry
            .new_filter(FilterKind::Block, latest)
            .ok_or_else(|| internal_err("filter limit reached"))?;
        Ok(id)
    }

    async fn get_filter_changes(&self, id: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Determine filter type and last polled block.
        let (is_log, last_poll_block) = self
            .filter_registry
            .get_filter_info(&id)
            .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;

        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let latest = head.map(|b| b.number()).unwrap_or(0);

        if is_log {
            // Log filter: query logs from (last_poll_block + 1) to latest.
            let from = last_poll_block.saturating_add(1);
            if from > latest {
                self.filter_registry.update_last_poll(&id, latest);
                return Ok(serde_json::json!([]));
            }

            // Retrieve the original filter criteria.
            let raw = self
                .filter_registry
                .get_log_filter(&id)
                .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;
            let filter = raw.into_filter(latest);

            let mut results = Vec::new();
            let actual_to = latest.min(from + MAX_BLOCK_RANGE - 1);

            for block_num in from..=actual_to {
                let block = match self
                    .chain_store
                    .get_block_by_number(block_num)
                    .map_err(internal_err)?
                {
                    Some(b) => b,
                    None => continue,
                };

                if !filter.matches_bloom(block.header.logs_bloom.as_ref()) {
                    continue;
                }

                let block_hash = block.hash();
                let receipts = self
                    .chain_store
                    .get_receipts(&block_hash)
                    .map_err(internal_err)?
                    .unwrap_or_default();

                let mut global_log_index: u64 = 0;
                for (tx_idx, receipt) in receipts.iter().enumerate() {
                    for log in &receipt.logs {
                        if filter.matches_log(log) {
                            results.push(RpcLogWithMeta {
                                address: log.address,
                                topics: log.topics.clone(),
                                data: hex_bytes(log.data.as_ref()),
                                block_number: hex_u64(block_num),
                                block_hash,
                                transaction_hash: receipt.tx_hash,
                                transaction_index: hex_u64(tx_idx as u64),
                                log_index: hex_u64(global_log_index),
                                removed: false,
                            });
                        }
                        global_log_index += 1;
                    }
                }
            }

            self.filter_registry.update_last_poll(&id, actual_to);
            Ok(serde_json::to_value(&results).unwrap_or(serde_json::json!([])))
        } else {
            // Block filter: collect hashes of blocks since last poll.
            let from = last_poll_block.saturating_add(1);
            if from > latest {
                self.filter_registry.update_last_poll(&id, latest);
                return Ok(serde_json::json!([]));
            }

            let mut hashes = Vec::new();
            for block_num in from..=latest {
                if let Some(block) = self
                    .chain_store
                    .get_block_by_number(block_num)
                    .map_err(internal_err)?
                {
                    hashes.push(block.hash());
                }
            }

            self.filter_registry.update_last_poll(&id, latest);
            Ok(serde_json::to_value(&hashes).unwrap_or(serde_json::json!([])))
        }
    }

    async fn get_filter_logs(&self, id: String) -> Result<Vec<RpcLogWithMeta>, ErrorObjectOwned> {
        // Only valid for log filters — re-query all matching logs.
        let raw = self
            .filter_registry
            .get_log_filter(&id)
            .ok_or_else(|| ErrorObjectOwned::owned(-32000, "filter not found", None::<()>))?;
        self.get_logs(raw).await
    }

    async fn uninstall_filter(&self, id: String) -> Result<bool, ErrorObjectOwned> {
        Ok(self.filter_registry.uninstall(&id))
    }

    async fn blob_base_fee(&self) -> Result<String, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let excess = head.map(|b| b.header.excess_blob_gas).unwrap_or(0);
        let price = shell_core::calc_blob_gas_price(excess);
        Ok(hex_u64(price))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> ShellApiServer for RpcHandler<S> {
    async fn get_pq_pubkey(&self, address: Address) -> Result<Option<String>, ErrorObjectOwned> {
        let pk = self
            .chain_store
            .get_pubkey(&address)
            .map_err(internal_err)?;
        Ok(pk.map(|bytes| hex_bytes(&bytes)))
    }

    async fn pending_count(&self) -> Result<String, ErrorObjectOwned> {
        Ok(hex_u64(self.tx_pool.len() as u64))
    }

    async fn send_transaction(&self, tx: SignedTransaction) -> Result<ShellHash, ErrorObjectOwned> {
        self.submit_tx(tx)
    }

    async fn get_validators(&self) -> Result<Vec<Address>, ErrorObjectOwned> {
        let ws = self.world_state.read();
        ws.get_validators().map_err(internal_err)
    }

    async fn add_validator(&self, _address: String) -> Result<bool, ErrorObjectOwned> {
        // DISABLED (F-039/F-040): Direct WorldState mutation via RPC causes
        // split-brain — validator changes must go through a system contract
        // transaction so all nodes compute the same state_root deterministically.
        // Use shell_proposeAddValidator instead.
        Err(ErrorObjectOwned::owned(
            -32601,
            "shell_addValidator is disabled: use shell_proposeAddValidator instead",
            None::<()>,
        ))
    }

    async fn remove_validator(&self, _address: String) -> Result<bool, ErrorObjectOwned> {
        // DISABLED (F-039/F-040): See add_validator rationale.
        // Use shell_proposeRemoveValidator instead.
        Err(ErrorObjectOwned::owned(
            -32601,
            "shell_removeValidator is disabled: use shell_proposeRemoveValidator instead",
            None::<()>,
        ))
    }

    async fn encode_add_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_add_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn encode_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_remove_validator_calldata(&addr);
        Ok(format!("0x{}", hex::encode(calldata)))
    }

    async fn propose_add_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_add_validator_calldata(&addr);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn propose_remove_validator(&self, address: String) -> Result<String, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let calldata = shell_evm::encode_remove_validator_calldata(&addr);
        let hash = self.propose_validator_tx(calldata)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    async fn get_validator_status(
        &self,
        address: Address,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ws = self.world_state.read();
        let validators = ws.get_validators().map_err(internal_err)?;
        let is_validator = validators.contains(&address);
        Ok(serde_json::json!({
            "address": address,
            "isValidator": is_validator,
        }))
    }

    async fn get_governance_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let ws = self.world_state.read();
        let validators = ws.get_validators().map_err(internal_err)?;
        Ok(serde_json::json!({
            "validatorCount": validators.len(),
            "validators": validators,
            "systemContractAddress": shell_evm::registry_address(),
            "proposalGasLimit": 100_000,
        }))
    }

    async fn estimate_governance_gas(&self, operation: String) -> Result<String, ErrorObjectOwned> {
        let gas = match operation.as_str() {
            "addValidator" | "removeValidator" => {
                shell_evm::SYSTEM_CALL_BASE_GAS + shell_evm::SYSTEM_CALL_OP_GAS
            }
            "getValidators" | "isValidator" => shell_evm::SYSTEM_CALL_BASE_GAS,
            _ => {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    format!("unknown governance operation: {operation}"),
                    None::<()>,
                ));
            }
        };
        Ok(hex_u64(gas))
    }

    async fn get_node_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let block_height = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let base_fee = match &head {
            Some(h) if h.header.base_fee_per_gas > 0 => h.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };

        Ok(serde_json::json!({
            "version": "ShellChain/v0.6.0/rust",
            "chainId": self.chain_id,
            "blockHeight": block_height,
            "peerCount": 0,
            "txPoolSize": self.tx_pool.len(),
            "isMining": self.proposer_signer.is_some(),
            "uptime": self.start_time.elapsed().as_secs(),
            "baseFee": hex_u64(base_fee),
        }))
    }

    async fn get_network_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        Ok(serde_json::json!({
            "peerCount": 0,
            "protocolVersion": "shell/1.0.0",
            "listeningAddress": "/ip4/0.0.0.0/tcp/30303",
            "protocols": ["gossipsub", "kademlia", "mdns"],
        }))
    }

    async fn get_chain_stats(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let head = self.chain_store.get_head_block().map_err(internal_err)?;
        let block_height = head.as_ref().map(|b| b.number()).unwrap_or(0);
        let base_fee = match &head {
            Some(h) if h.header.base_fee_per_gas > 0 => h.header.base_fee_per_gas,
            _ => shell_core::INITIAL_BASE_FEE,
        };

        let mut total_txs: u64 = 0;
        let mut gas_used_total = U256::ZERO;
        let mut avg_block_time: f64 = 0.0;

        // Cap scan to last 1000 blocks to prevent O(N) DoS on large chains.
        const MAX_SCAN: u64 = 1000;
        let scan_start = block_height.saturating_sub(MAX_SCAN);

        if block_height > 0 {
            for n in scan_start..=block_height {
                if let Ok(Some(blk)) = self.chain_store.get_block_by_number(n) {
                    total_txs = total_txs.saturating_add(blk.transactions.len() as u64);
                    gas_used_total = gas_used_total.saturating_add(U256::from(blk.header.gas_used));
                }
            }

            let window = std::cmp::min(block_height, 10);
            if window >= 1 {
                if let (Ok(Some(recent)), Ok(Some(older))) = (
                    self.chain_store.get_block_by_number(block_height),
                    self.chain_store.get_block_by_number(block_height - window),
                ) {
                    let dt = recent
                        .header
                        .timestamp
                        .saturating_sub(older.header.timestamp);
                    avg_block_time = dt as f64 / window as f64;
                }
            }
        }

        Ok(serde_json::json!({
            "blockHeight": block_height,
            "totalTransactions": total_txs,
            "avgBlockTime": avg_block_time,
            "gasUsedTotal": hex_u256(gas_used_total),
            "latestBaseFee": hex_u64(base_fee),
        }))
    }

    async fn get_finality_info(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let finalized = *self.finalized_number.read();
        let current_head = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|b| b.number())
            .unwrap_or(0);
        let pending = self.finality.read().total_pending_attestations();

        Ok(serde_json::json!({
            "lastFinalizedBlock": hex_u64(finalized),
            "currentHead": hex_u64(current_head),
            "pendingAttestations": pending,
        }))
    }

    async fn set_balance(
        &self,
        address: Address,
        balance: String,
    ) -> Result<bool, ErrorObjectOwned> {
        // Require dev mode — shell_setBalance is a state-mutation endpoint.
        self.dev_control.as_ref().ok_or_else(|| {
            ErrorObjectOwned::owned(-32601, "shell_setBalance requires dev mode", None::<()>)
        })?;
        let value = if let Some(hex_str) = balance.strip_prefix("0x") {
            U256::from_str_radix(hex_str, 16)
                .map_err(|e| internal_err(format!("invalid hex balance: {e}")))?
        } else {
            balance
                .parse::<U256>()
                .map_err(|e| internal_err(format!("invalid balance: {e}")))?
        };
        let mut ws = self.world_state.write();
        ws.set_balance(&address, value).map_err(internal_err)?;
        Ok(true)
    }

    async fn transaction_count(&self) -> Result<String, ErrorObjectOwned> {
        let count = self
            .chain_store
            .get_total_tx_count()
            .map_err(internal_err)?;
        Ok(hex_u64(count))
    }

    async fn get_transactions_by_address(
        &self,
        address: Address,
        from_block: Option<u64>,
        to_block: Option<u64>,
        page: Option<u64>,
        limit: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let from = from_block.unwrap_or(0);
        let to = to_block.unwrap_or_else(|| {
            self.chain_store
                .get_head_block()
                .ok()
                .flatten()
                .map(|b| b.number())
                .unwrap_or(0)
        });
        let page = page.unwrap_or(0);
        let limit = limit.unwrap_or(20).min(100);
        let offset = page
            .checked_mul(limit)
            .ok_or_else(|| invalid_params_err("page * limit overflow"))?;
        if offset > MAX_ADDRESS_TX_HISTORY_OFFSET as u64 {
            return Err(invalid_params_err(format!(
                "page/limit offset {} exceeds max {} entries",
                offset, MAX_ADDRESS_TX_HISTORY_OFFSET
            )));
        }

        let tx_hashes = self
            .chain_store
            .get_txs_by_address(&address, from, to, offset as usize, limit as usize)
            .map_err(internal_err)?;

        // Resolve each tx hash to a full RPC transaction
        let mut txs = Vec::with_capacity(tx_hashes.len());
        for hash in &tx_hashes {
            let location = self
                .chain_store
                .get_tx_location(hash)
                .map_err(internal_err)?;
            if let Some((block_hash, tx_index)) = location {
                let block = self
                    .chain_store
                    .get_block_by_hash(&block_hash)
                    .map_err(internal_err)?;
                if let Some(block) = block {
                    if let Some(tx) = block.transactions.get(tx_index as usize) {
                        txs.push(serde_json::json!({
                            "hash": hash,
                            "blockNumber": hex_u64(block.number()),
                            "blockHash": block_hash,
                            "transactionIndex": hex_u64(tx_index as u64),
                            "from": tx.sender(),
                            "to": tx.tx.to,
                            "value": hex_u256(tx.tx.value),
                            "gasLimit": hex_u64(tx.tx.gas_limit),
                            "nonce": hex_u64(tx.tx.nonce),
                        }));
                    }
                }
            }
        }

        Ok(serde_json::json!({
            "address": address,
            "fromBlock": hex_u64(from),
            "toBlock": hex_u64(to),
            "page": page,
            "limit": limit,
            "total": txs.len(),
            "transactions": txs,
        }))
    }

    async fn get_block_witnesses(
        &self,
        block: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Resolve block hash from tag or hash string.
        let block_hash = if block.starts_with("0x") && block.len() == 66 {
            // 32-byte hex hash
            let bytes = hex::decode(&block[2..])
                .map_err(|e| internal_err(format!("invalid block hash hex: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| internal_err("block hash must be 32 bytes"))?;
            ShellHash::from(arr)
        } else {
            // Block number / tag → look up canonical hash
            let tag = parse_block_tag(&block)?;
            let blk = match tag {
                BlockTag::Latest | BlockTag::Finalized | BlockTag::Pending => {
                    self.chain_store.get_head_block().map_err(internal_err)?
                }
                BlockTag::Number(n) => self
                    .chain_store
                    .get_block_by_number(n)
                    .map_err(internal_err)?,
            };
            match blk {
                None => return Ok(serde_json::Value::Null),
                Some(b) => b.hash(),
            }
        };

        // Retrieve the block header for witness_root.
        let header = self
            .chain_store
            .get_header_by_hash(&block_hash)
            .map_err(internal_err)?;
        let witness_root = header
            .as_ref()
            .and_then(|h| h.witness_root)
            .map(|r| format!("0x{}", hex::encode(r.as_bytes())))
            .unwrap_or_else(|| "null".into());

        // Look up the witness bundle if a store is wired.
        let Some(ws) = &self.witness_store else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "witnessRoot": witness_root,
                "witnessCount": null,
                "witnesses": null,
                "error": "witness store not available on this node",
            }));
        };

        let bundle = ws.get_bundle(&block_hash).map_err(internal_err)?;
        let Some(bundle) = bundle else {
            return Ok(serde_json::json!({
                "blockHash": block_hash,
                "witnessRoot": witness_root,
                "witnessCount": 0,
                "witnesses": [],
            }));
        };

        let witnesses: Vec<serde_json::Value> = bundle
            .witnesses
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let sig_type = format!("{:?}", w.signature.sig_type);
                let mut obj = serde_json::json!({
                    "txIndex": i,
                    "sigType": sig_type,
                    "signature": format!("0x{}", hex::encode(&w.signature.data)),
                });
                if let Some(pk) = &w.pubkey {
                    obj["pubkey"] = serde_json::Value::String(format!("0x{}", hex::encode(pk)));
                }
                obj
            })
            .collect();

        Ok(serde_json::json!({
            "blockHash": block_hash,
            "witnessRoot": witness_root,
            "witnessCount": witnesses.len(),
            "witnesses": witnesses,
        }))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> Web3ApiServer for RpcHandler<S> {
    async fn client_version(&self) -> Result<String, ErrorObjectOwned> {
        Ok("shell-chain/0.6.0".to_string())
    }

    async fn sha3(&self, data: String) -> Result<String, ErrorObjectOwned> {
        let raw = data.strip_prefix("0x").unwrap_or(&data);
        // Limit input to 32 KB to prevent DoS via large allocations.
        const MAX_HEX_LEN: usize = 32 * 1024 * 2; // 32 KB decoded = 64 KB hex
        if raw.len() > MAX_HEX_LEN {
            return Err(internal_err("input too large (max 32 KB)"));
        }
        let bytes = hex::decode(raw).map_err(|e| internal_err(format!("invalid hex: {e}")))?;
        let hash = shell_primitives::keccak256(&bytes);
        Ok(format!("0x{}", hex::encode(hash.0)))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> NetApiServer for RpcHandler<S> {
    async fn version(&self) -> Result<String, ErrorObjectOwned> {
        Ok(self.chain_id.to_string())
    }

    async fn listening(&self) -> Result<bool, ErrorObjectOwned> {
        Ok(true)
    }

    async fn peer_count(&self) -> Result<String, ErrorObjectOwned> {
        let count = self.peer_count.load(std::sync::atomic::Ordering::Relaxed);
        Ok(hex_u64(count as u64))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> DebugApiServer for RpcHandler<S> {
    async fn trace_transaction(
        &self,
        tx_hash: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let _trace_opts: TraceOptions = opts
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        let (_block, tx, receipt, _tx_index) = self.lookup_tx_with_block(&tx_hash)?;

        let to_addr = tx.tx.to.unwrap_or(Address::ZERO);
        let call_type = if tx.tx.to.is_none() { "CREATE" } else { "CALL" };

        let mut frame = shell_evm::CallFrame::new(
            call_type,
            tx.sender(),
            to_addr,
            tx.tx.gas_limit,
            tx.tx.data.clone(),
        );
        if !tx.tx.value.is_zero() {
            frame = frame.with_value(tx.tx.value);
        }
        frame.gas_used = receipt.gas_used;

        if receipt.succeeded() {
            frame.output = Some(Bytes::default());
        } else {
            frame.error = Some("execution reverted".to_string());
        }

        // Populate output/revert_reason from contract address if CREATE
        if tx.tx.to.is_none() {
            if let Some(addr) = receipt.contract_address {
                frame.to = addr;
            }
        }

        let trace = shell_evm::TraceResult {
            frame,
            failed: !receipt.succeeded(),
        };

        serde_json::to_value(&trace).map_err(|e| internal_err(format!("serialization error: {e}")))
    }

    async fn trace_block_by_number(
        &self,
        block_number: String,
        opts: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let _trace_opts: TraceOptions = opts
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        let block = self.resolve_block(&block_number)?;
        let block_hash = block.hash();

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();

        let mut traces = Vec::with_capacity(block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            let receipt = receipts.get(i);
            let to_addr = tx.tx.to.unwrap_or(Address::ZERO);
            let call_type = if tx.tx.to.is_none() { "CREATE" } else { "CALL" };

            let mut frame = shell_evm::CallFrame::new(
                call_type,
                tx.sender(),
                to_addr,
                tx.tx.gas_limit,
                tx.tx.data.clone(),
            );
            if !tx.tx.value.is_zero() {
                frame = frame.with_value(tx.tx.value);
            }

            if let Some(r) = receipt {
                frame.gas_used = r.gas_used;
                if r.succeeded() {
                    frame.output = Some(Bytes::default());
                } else {
                    frame.error = Some("execution reverted".to_string());
                }
                if tx.tx.to.is_none() {
                    if let Some(addr) = r.contract_address {
                        frame.to = addr;
                    }
                }
            }

            let failed = receipt.map(|r| !r.succeeded()).unwrap_or(true);
            let trace = shell_evm::TraceResult { frame, failed };
            traces.push(trace);
        }

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }
}

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> TraceApiServer for RpcHandler<S> {
    async fn trace_block(
        &self,
        block_number: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let block = self.resolve_block(&block_number)?;
        let block_hash = block.hash();
        let block_num = block.header.number;

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .unwrap_or_default();

        let mut traces = Vec::with_capacity(block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            let receipt = receipts.get(i);
            let trace = self.build_oe_trace(tx, receipt, block_num, block_hash, i as u64);
            traces.push(trace);
        }

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }

    async fn trace_oe_transaction(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (block, tx, receipt, tx_index) = self.lookup_tx_with_block(&tx_hash)?;
        let block_hash = block.hash();
        let block_num = block.header.number;

        let trace =
            self.build_oe_trace(&tx, Some(&receipt), block_num, block_hash, tx_index as u64);
        let traces = vec![trace];

        serde_json::to_value(&traces).map_err(|e| internal_err(format!("serialization error: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Admin namespace
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> AdminApiServer for RpcHandler<S> {
    async fn node_info(&self) -> Result<NodeInfo, ErrorObjectOwned> {
        let block_height = self
            .chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.header.number)
            .unwrap_or(0);

        let uptime_seconds = self.start_time.elapsed().as_secs();
        let peer_count = self.peer_count.load(Ordering::Relaxed);
        let tx_pool_size = self.tx_pool.len() as u64;

        let name = format!("shell-node/{}", env!("CARGO_PKG_VERSION"));

        Ok(NodeInfo {
            name,
            id: self.admin_peer_id.clone(),
            listen_addr: self.admin_p2p_listen.clone(),
            rpc_addr: self.admin_rpc_addr.clone(),
            chain_id: self.chain_id,
            uptime_seconds,
            block_height,
            tx_pool_size,
            peer_count,
        })
    }

    async fn peers(&self) -> Result<Vec<PeerInfo>, ErrorObjectOwned> {
        // The RPC handler receives only an atomic peer count from the network
        // layer; full per-peer detail (remote addr, client version) requires
        // a richer channel which is wired in Batch 5 network observability.
        // For now, return a count-accurate summary with placeholder per-peer
        // data so `admin_peers` is callable and returns valid JSON.
        let count = self.peer_count.load(Ordering::Relaxed);
        let peers = (0..count)
            .map(|i| PeerInfo {
                id: format!("peer-{i}"),
                remote_addr: String::new(),
                client_version: String::new(),
                block_height: 0,
                connected_seconds: 0,
            })
            .collect();
        Ok(peers)
    }

    async fn add_peer(&self, _multiaddr: String) -> Result<bool, ErrorObjectOwned> {
        // Dynamic peer dialling requires a command channel to the network layer.
        // Stubbed for Batch 4; full implementation in Batch 5 (P2P observability).
        Err(ErrorObjectOwned::owned(
            jsonrpsee::types::error::METHOD_NOT_FOUND_CODE,
            "admin_addPeer not yet implemented; use --bootnodes at startup",
            None::<()>,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ShellApiServer;
    use crate::dev_control::DevRpcControl;
    use shell_core::{Block, BlockHeader, Transaction, TransactionReceipt};
    use shell_crypto::{DilithiumSigner, Signer};
    use shell_primitives::Bytes;
    use shell_storage::{MemoryDb, WitnessStore};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct MockDevControl {
        mined: AtomicU64,
        increased: AtomicU64,
    }

    impl DevRpcControl for MockDevControl {
        fn mine_blocks(&self, blocks: u64) -> Result<(), String> {
            self.mined.fetch_add(blocks, Ordering::Relaxed);
            Ok(())
        }

        fn set_next_block_timestamp(&self, timestamp: u64) -> Result<u64, String> {
            Ok(timestamp)
        }

        fn increase_time(&self, seconds: u64) -> Result<u64, String> {
            Ok(self.increased.fetch_add(seconds, Ordering::Relaxed) + seconds)
        }

        fn snapshot(&self) -> Result<String, String> {
            Ok("0x1".into())
        }

        fn revert(&self, snapshot_id: &str) -> Result<bool, String> {
            Ok(snapshot_id == "0x1")
        }
    }

    fn setup() -> RpcHandler<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(parking_lot::RwLock::new(WorldState::new(db)));
        let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
            chain_id: 42,
            ..shell_mempool::MempoolConfig::default()
        }));
        let (block_events, _) = tokio::sync::broadcast::channel(16);
        let finalized_number = Arc::new(parking_lot::RwLock::new(0u64));
        let finality = Arc::new(parking_lot::RwLock::new(FinalityState::new()));
        RpcHandler::new(
            chain_store,
            world_state,
            tx_pool,
            42,
            None,
            block_events,
            finalized_number,
            finality,
        )
    }

    fn test_address(seed: &[u8]) -> Address {
        Address::from_public_key(seed, 0)
    }

    fn signer_address(signer: &DilithiumSigner) -> Address {
        Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
    }

    fn make_genesis_block() -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 0,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-key-data"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        }
    }

    #[tokio::test]
    async fn block_number_empty_chain() {
        let handler = setup();
        let result = EthApiServer::block_number(&handler).await.unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn evm_rpc_methods_delegate_to_dev_control() {
        let dev = Arc::new(MockDevControl::default());
        let handler = setup().with_dev_control(dev.clone());

        let mined = EvmApiServer::mine(&handler, Some(2)).await.unwrap();
        assert_eq!(mined["blocksMined"], "0x2");
        assert_eq!(dev.mined.load(Ordering::Relaxed), 2);

        let next = EvmApiServer::set_next_block_timestamp(&handler, 1_700_000_123)
            .await
            .unwrap();
        assert_eq!(next, serde_json::json!("0x6553f17b"));

        let increased = EvmApiServer::increase_time(&handler, 30).await.unwrap();
        assert_eq!(increased, serde_json::json!("0x1e"));

        let snapshot = EvmApiServer::snapshot(&handler).await.unwrap();
        assert_eq!(snapshot, "0x1");
        assert!(EvmApiServer::revert(&handler, "0x1".into()).await.unwrap());
        assert!(!EvmApiServer::revert(&handler, "0x2".into()).await.unwrap());
    }

    #[tokio::test]
    async fn chain_id() {
        let handler = setup();
        let result = EthApiServer::chain_id(&handler).await.unwrap();
        assert_eq!(result, "0x2a"); // 42
    }

    #[tokio::test]
    async fn get_transactions_by_address_rejects_deep_pagination() {
        let handler = setup();
        let err = ShellApiServer::get_transactions_by_address(
            &handler,
            Address::from([0x33; 20]),
            None,
            None,
            Some((MAX_ADDRESS_TX_HISTORY_OFFSET as u64) + 1),
            Some(1),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("exceeds max"));
    }

    #[tokio::test]
    async fn get_block_after_store() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();

        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        // By number
        let rpc_block = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap();
        assert!(rpc_block.is_some());
        assert_eq!(rpc_block.as_ref().unwrap().number, "0x0");

        // By hash
        let rpc_block = EthApiServer::get_block_by_hash(&handler, hash, false)
            .await
            .unwrap();
        assert!(rpc_block.is_some());

        // Latest
        let rpc_block = EthApiServer::get_block_by_number(&handler, "latest".into(), false)
            .await
            .unwrap();
        assert!(rpc_block.is_some());
        assert_eq!(rpc_block.unwrap().number, "0x0");
    }

    #[tokio::test]
    async fn get_balance_default_zero() {
        let handler = setup();
        let addr = test_address(b"test-address-key");
        let result = EthApiServer::get_balance(&handler, addr, None)
            .await
            .unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn get_nonce_default_zero() {
        let handler = setup();
        let addr = test_address(b"test-address-key");
        let result = EthApiServer::get_transaction_count(&handler, addr, None)
            .await
            .unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn gas_price_returns_default() {
        let handler = setup();
        let result = EthApiServer::gas_price(&handler).await.unwrap();
        // No blocks stored → returns INITIAL_BASE_FEE (1 gwei)
        assert_eq!(result, "0x3b9aca00");
    }

    #[tokio::test]
    async fn gas_price_returns_latest_base_fee() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.base_fee_per_gas = 2_000_000_000; // 2 gwei
        block.header.number = 1;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(1, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = EthApiServer::gas_price(&handler).await.unwrap();
        assert_eq!(result, "0x77359400"); // 2 gwei
    }

    #[tokio::test]
    async fn max_priority_fee_per_gas_returns_zero() {
        let handler = setup();
        let result = EthApiServer::max_priority_fee_per_gas(&handler)
            .await
            .unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn fee_history_returns_base_fees() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.base_fee_per_gas = 1_000_000_000;
        block.header.number = 0;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = EthApiServer::fee_history(&handler, "0x1".into(), "latest".into(), None)
            .await
            .unwrap();
        let base_fees = result["baseFeePerGas"].as_array().unwrap();
        // Should have 2 entries: block 0 + predicted next block
        assert_eq!(base_fees.len(), 2);
        assert_eq!(base_fees[0].as_str().unwrap(), "0x3b9aca00");
    }

    #[tokio::test]
    async fn get_nonexistent_tx_returns_none() {
        let handler = setup();
        let result = EthApiServer::get_transaction_by_hash(&handler, ShellHash::default())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_nonexistent_receipt_returns_none() {
        let handler = setup();
        let result = EthApiServer::get_transaction_receipt(&handler, ShellHash::default())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn shell_pending_count_empty() {
        let handler = setup();
        let result = ShellApiServer::pending_count(&handler).await.unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn shell_get_pq_pubkey_not_found() {
        let handler = setup();
        let addr = test_address(b"unknown");
        let result = ShellApiServer::get_pq_pubkey(&handler, addr).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn shell_get_pq_pubkey_found() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);

        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let result = ShellApiServer::get_pq_pubkey(&handler, addr).await.unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("0x"));
    }

    // ── shell_getBlockWitnesses tests ──────────────────────────────────────

    fn setup_with_witness() -> RpcHandler<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(parking_lot::RwLock::new(WorldState::new(db.clone())));
        let witness_store = Arc::new(WitnessStore::new(db));
        let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
            chain_id: 42,
            ..shell_mempool::MempoolConfig::default()
        }));
        let (block_events, _) = tokio::sync::broadcast::channel(16);
        let finalized_number = Arc::new(parking_lot::RwLock::new(0u64));
        let finality = Arc::new(parking_lot::RwLock::new(FinalityState::new()));
        RpcHandler::new(
            chain_store,
            world_state,
            tx_pool,
            42,
            None,
            block_events,
            finalized_number,
            finality,
        )
        .with_witness_store(witness_store)
    }

    #[tokio::test]
    async fn shell_get_block_witnesses_no_store() {
        // Without a witness store wired in, returns an error field.
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = ShellApiServer::get_block_witnesses(&handler, "latest".to_string())
            .await
            .unwrap();
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("witness store not available"));
    }

    #[tokio::test]
    async fn shell_get_block_witnesses_empty_bundle() {
        // Block exists, witness store is wired, but no bundle stored → empty array.
        let handler = setup_with_witness();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = ShellApiServer::get_block_witnesses(&handler, "latest".to_string())
            .await
            .unwrap();
        assert_eq!(result["witnessCount"], 0);
        assert!(result["witnesses"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn shell_get_block_witnesses_with_bundle() {
        use shell_core::{TxWitness, WitnessBundle};

        let handler = setup_with_witness();
        let block = make_genesis_block();
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

        // Build and store a witness bundle.
        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"tx0").unwrap();
        let bundle = WitnessBundle::new(vec![TxWitness::new_embedded(sig, pk)]);
        handler
            .witness_store
            .as_ref()
            .unwrap()
            .put_bundle(&block_hash, &bundle)
            .unwrap();

        let result = ShellApiServer::get_block_witnesses(
            &handler,
            format!("0x{}", hex::encode(block_hash.as_bytes())),
        )
        .await
        .unwrap();

        assert_eq!(result["witnessCount"], 1);
        let witnesses = result["witnesses"].as_array().unwrap();
        assert_eq!(witnesses[0]["txIndex"], 0);
        assert_eq!(witnesses[0]["sigType"], "Dilithium3");
        assert!(witnesses[0]["signature"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert!(witnesses[0]["pubkey"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn shell_get_block_witnesses_null_for_unknown_hash() {
        let handler = setup_with_witness();
        let fake_hash = format!("0x{}", "ab".repeat(32));
        let result = ShellApiServer::get_block_witnesses(&handler, fake_hash)
            .await
            .unwrap();
        // Block header not found, but no bundle stored → empty witnesses.
        assert_eq!(result["witnessCount"], 0);
    }

    #[tokio::test]
    async fn tx_response_includes_vrs_compat_fields() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        // Verify block is stored, then check RpcTransaction v/r/s fields.
        let _block = EthApiServer::get_block_by_number(&handler, "latest".into(), false)
            .await
            .unwrap()
            .unwrap();
        // Directly construct an RpcTransaction to check compat fields.
        let rpc_tx = tx_to_rpc(
            &shell_core::SignedTransaction::new(
                test_address(b"test"),
                Transaction {
                    chain_id: 42,
                    nonce: 0,
                    max_fee_per_gas: 1_000_000_000,
                    max_priority_fee_per_gas: 100_000_000,
                    gas_limit: 21_000,
                    to: None,
                    value: U256::ZERO,
                    data: Bytes::default(),
                    access_list: None,
                    tx_type: 2,
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                },
                shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
            ),
            None,
            None,
            None,
            None,
        );
        assert_eq!(rpc_tx.v, "0x0");
        assert_eq!(rpc_tx.r, "0x0");
        assert_eq!(rpc_tx.s, "0x0");
        assert_eq!(rpc_tx.tx_type, "0x2");
    }

    #[tokio::test]
    async fn send_raw_transaction_decodes_hex_json() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);
        let gas_limit = shell_evm::compute_intrinsic_gas(&[], true, &None);

        // Fund the sender so balance check passes.
        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        // Register pubkey so mempool can verify.
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            gas_limit,
            to: None,
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let signature = signer.sign(tx.hash().0.as_slice()).unwrap();
        let signed = SignedTransaction::new(addr, tx, signature);

        let json_bytes = serde_json::to_vec(&signed).unwrap();
        let hex_payload = format!("0x{}", hex::encode(&json_bytes));

        let result = EthApiServer::send_raw_transaction(&handler, hex_payload).await;
        assert!(
            result.is_ok(),
            "send_raw_transaction failed: {:?}",
            result.err()
        );

        assert_eq!(handler.tx_pool.len(), 1);
    }

    #[tokio::test]
    async fn shell_send_transaction() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);
        let gas_limit = shell_evm::compute_intrinsic_gas(&[], true, &None);

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            gas_limit,
            to: None,
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signature = signer.sign(tx.hash().0.as_slice()).unwrap();
        let signed = SignedTransaction::new(addr, tx, signature);

        let result = ShellApiServer::send_transaction(&handler, signed).await;
        assert!(result.is_ok());
        assert_eq!(handler.tx_pool.len(), 1);
    }

    #[tokio::test]
    async fn send_raw_transaction_rejects_invalid_hex() {
        let handler = setup();
        let result = EthApiServer::send_raw_transaction(&handler, "not-hex".into()).await;
        assert!(result.is_err());
    }

    // ── New RPC methods ──────────────────────────────────────────

    #[tokio::test]
    async fn get_code_no_contract_returns_0x() {
        let handler = setup();
        let addr = test_address(b"test-address");
        let result = EthApiServer::get_code(&handler, addr, None).await.unwrap();
        assert_eq!(result, "0x");
    }

    #[tokio::test]
    async fn get_code_returns_stored_bytecode() {
        let handler = setup();
        let addr = test_address(b"contract-addr");
        let code = b"\x60\x00\x60\x00\xf3"; // PUSH1 0 PUSH1 0 RETURN
        let code_hash = shell_primitives::keccak256(code);

        // Store code and set code hash on the account.
        handler.chain_store.put_code(&code_hash, code).unwrap();
        {
            let mut ws = handler.world_state.write();
            ws.set_account(
                &addr,
                &shell_core::Account {
                    pq_pubkey_hash: ShellHash::default(),
                    nonce: 0,
                    balance: U256::ZERO,
                    validation_code_hash: None,
                    code_hash: Some(code_hash),
                    storage_root: ShellHash::ZERO,
                },
            )
            .unwrap();
        }

        let result = EthApiServer::get_code(&handler, addr, None).await.unwrap();
        assert_eq!(result, format!("0x{}", hex::encode(code)));
    }

    #[tokio::test]
    async fn get_storage_at_empty_returns_zero() {
        let handler = setup();
        let addr = test_address(b"test-address");
        let result = EthApiServer::get_storage_at(&handler, addr, "0x0".into(), None)
            .await
            .unwrap();
        // 32 zero bytes, hex-encoded.
        assert_eq!(
            result,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[tokio::test]
    async fn get_storage_at_returns_stored_value() {
        let handler = setup();
        let addr = test_address(b"storage-test");
        let slot = ShellHash::from(alloy_primitives::B256::from(U256::from(1)));
        let value = ShellHash::from(alloy_primitives::B256::from(U256::from(42)));

        {
            let mut ws = handler.world_state.write();
            ws.set_account(
                &addr,
                &shell_core::Account {
                    pq_pubkey_hash: ShellHash::default(),
                    nonce: 0,
                    balance: U256::ZERO,
                    validation_code_hash: None,
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                },
            )
            .unwrap();
            ws.set_storage(&addr, &slot, &value).unwrap();
        }

        let result = EthApiServer::get_storage_at(&handler, addr, "0x1".into(), None)
            .await
            .unwrap();
        assert_eq!(
            result,
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
    }

    #[tokio::test]
    async fn eth_call_simple_transfer() {
        let handler = setup();
        let from = test_address(b"caller-key");

        // Fund the caller.
        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&from, U256::from(10_000_000_000u64))
                .unwrap();
        }

        let req = crate::types::CallRequest {
            from: Some(from),
            to: Some(Address::from([0x01; 20])),
            data: None,
            value: Some("0x3e8".into()), // 1000
            gas: Some("0x5208".into()),  // 21000
            access_list: None,
        };
        let result = EthApiServer::call(&handler, req, None).await;
        assert!(result.is_ok(), "eth_call failed: {:?}", result.err());
        // Transfer returns empty data.
        assert_eq!(result.unwrap(), "0x");
    }

    #[tokio::test]
    async fn eth_estimate_gas_simple_transfer() {
        let handler = setup();
        let from = test_address(b"caller-key");

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&from, U256::from(10_000_000_000u64))
                .unwrap();
        }

        let req = crate::types::CallRequest {
            from: Some(from),
            to: Some(Address::from([0x01; 20])),
            data: None,
            value: Some("0x3e8".into()),
            gas: None,
            access_list: None,
        };
        let result = EthApiServer::estimate_gas(&handler, req).await;
        assert!(result.is_ok(), "estimateGas failed: {:?}", result.err());
        let gas_hex = result.unwrap();
        let gas = u64::from_str_radix(gas_hex.strip_prefix("0x").unwrap(), 16).unwrap();
        assert!(gas >= 21_000, "estimated gas too low: {gas}");
    }

    // ── eth_getLogs tests ────────────────────────────────────────

    /// Helper: store a block with receipts that contain logs and return the block hash.
    fn store_block_with_logs(
        handler: &RpcHandler<MemoryDb>,
        number: u64,
        logs_per_receipt: Vec<Vec<shell_core::Log>>,
    ) -> ShellHash {
        let bloom = shell_evm::bloom::logs_bloom(
            &logs_per_receipt
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>(),
        );

        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::copy_from_slice(&bloom),
                number,
                gas_limit: 30_000_000,
                gas_used: 21_000 * logs_per_receipt.len() as u64,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-key-data"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(number, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let mut cumulative_gas = 0u64;
        let receipts: Vec<TransactionReceipt> = logs_per_receipt
            .into_iter()
            .enumerate()
            .map(|(i, logs)| {
                let receipt_bloom = shell_evm::bloom::logs_bloom(&logs);
                cumulative_gas += 21_000;
                TransactionReceipt {
                    tx_hash: ShellHash::from_slice(&[i as u8 + 1; 32]),
                    block_number: number,
                    tx_index: i as u32,
                    status: 1,
                    gas_used: 21_000,
                    cumulative_gas_used: cumulative_gas,
                    contract_address: None,
                    logs_bloom: Bytes::copy_from_slice(&receipt_bloom),
                    logs,
                }
            })
            .collect();

        handler.chain_store.put_receipts(&hash, &receipts).unwrap();
        hash
    }

    #[tokio::test]
    async fn get_logs_empty_range_returns_empty() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x5","toBlock":"0x1"}"#).unwrap();
        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn get_logs_no_blocks_returns_empty() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x0","toBlock":"0x0"}"#).unwrap();
        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn get_logs_matches_specific_address() {
        let handler = setup();
        let target = Address::from([0xAA; 20]);
        let other = Address::from([0xBB; 20]);

        let log_target = shell_core::Log::new(target, vec![], Bytes::new()).unwrap();
        let log_other = shell_core::Log::new(other, vec![], Bytes::new()).unwrap();

        store_block_with_logs(&handler, 0, vec![vec![log_target, log_other]]);

        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x0","address":"{}"}}"#,
            target,
        ))
        .unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, target);
        assert!(!result[0].removed);
    }

    #[tokio::test]
    async fn get_logs_topic_filtering() {
        let handler = setup();
        let topic_a = ShellHash::from_slice(&[0x11; 32]);
        let topic_b = ShellHash::from_slice(&[0x22; 32]);

        let log_a =
            shell_core::Log::new(Address::from([0x01; 20]), vec![topic_a], Bytes::new()).unwrap();
        let log_b =
            shell_core::Log::new(Address::from([0x01; 20]), vec![topic_b], Bytes::new()).unwrap();

        store_block_with_logs(&handler, 0, vec![vec![log_a, log_b]]);

        // Filter for topic_a only
        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x0","topics":["{}"]}}"#,
            topic_a,
        ))
        .unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].topics[0], topic_a);
    }

    #[tokio::test]
    async fn get_logs_bloom_fast_path_skips_block() {
        let handler = setup();
        // Block contains log from address 0xBB only.
        let other = Address::from([0xBB; 20]);
        let log = shell_core::Log::new(other, vec![], Bytes::new()).unwrap();
        store_block_with_logs(&handler, 0, vec![vec![log]]);

        // Query for address 0xAA — bloom should reject the block.
        let target = Address::from([0xAA; 20]);
        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x0","address":"{}"}}"#,
            target,
        ))
        .unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn get_logs_range_too_large_returns_error() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter = serde_json::from_str(
            r#"{"fromBlock":"0x0","toBlock":"0x2711"}"#, // 0..10001 = 10002 blocks > 10_000
        )
        .unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("cap the range"));
    }

    #[tokio::test]
    async fn get_logs_metadata_fields_are_correct() {
        let handler = setup();
        let addr = Address::from([0xCC; 20]);
        let topic = ShellHash::from_slice(&[0xDD; 32]);
        let log =
            shell_core::Log::new(addr, vec![topic], Bytes::copy_from_slice(b"\x01\x02")).unwrap();
        let block_hash = store_block_with_logs(&handler, 1, vec![vec![log]]);

        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x1","toBlock":"0x1"}"#).unwrap();
        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert_eq!(result.len(), 1);
        let entry = &result[0];
        assert_eq!(entry.block_number, "0x1");
        assert_eq!(entry.block_hash, block_hash);
        assert_eq!(entry.transaction_index, "0x0");
        assert_eq!(entry.log_index, "0x0");
        assert_eq!(entry.data, "0x0102");
        assert!(!entry.removed);
    }

    #[tokio::test]
    async fn shell_get_validators_empty() {
        let handler = setup();
        let result = ShellApiServer::get_validators(&handler).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn shell_get_validators_with_data() {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let ws = Arc::new(parking_lot::RwLock::new(WorldState::new(db)));
        let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
            chain_id: 42,
            ..shell_mempool::MempoolConfig::default()
        }));
        let (block_events, _) = tokio::sync::broadcast::channel(16);
        let handler = RpcHandler::new(
            chain_store,
            Arc::clone(&ws),
            tx_pool,
            42,
            None,
            block_events,
            Arc::new(parking_lot::RwLock::new(0u64)),
            Arc::new(parking_lot::RwLock::new(FinalityState::new())),
        );

        let v1 = Address::from([0x11; 20]);
        let v2 = Address::from([0x22; 20]);
        {
            let mut w = ws.write();
            w.set_validators(&[v1, v2]).unwrap();
        }
        let result = ShellApiServer::get_validators(&handler).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], v1);
        assert_eq!(result[1], v2);
    }

    #[tokio::test]
    async fn shell_add_validator_disabled() {
        let handler = setup();
        let addr_hex = format!("0x{}", "ab".repeat(20));

        let err = ShellApiServer::add_validator(&handler, addr_hex)
            .await
            .unwrap_err();
        assert!(err.message().contains("disabled"));
    }

    #[tokio::test]
    async fn shell_remove_validator_disabled() {
        let handler = setup();
        let addr_hex = format!("0x{}", "cc".repeat(20));

        let err = ShellApiServer::remove_validator(&handler, addr_hex)
            .await
            .unwrap_err();
        assert!(err.message().contains("disabled"));
    }

    // ── Governance proposal RPCs ─────────────────────────────────

    fn setup_with_proposer() -> (RpcHandler<MemoryDb>, DilithiumSigner, Address) {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(parking_lot::RwLock::new(WorldState::new(db)));
        let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
            chain_id: 42,
            ..shell_mempool::MempoolConfig::default()
        }));
        let (block_events, _) = tokio::sync::broadcast::channel(16);

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);

        let handler = RpcHandler::new(
            chain_store.clone(),
            world_state,
            tx_pool,
            42,
            None,
            block_events,
            Arc::new(parking_lot::RwLock::new(0u64)),
            Arc::new(parking_lot::RwLock::new(FinalityState::new())),
        )
        .with_proposer(
            Arc::new(
                DilithiumSigner::from_bytes(signer.public_key(), signer.secret_key_bytes())
                    .unwrap(),
            ),
            addr,
        );

        // Register pubkey so mempool signature verification passes.
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        (handler, signer, addr)
    }

    #[tokio::test]
    async fn propose_add_validator_no_signer_returns_error() {
        let handler = setup();
        let target = format!("0x{}", "ab".repeat(20));
        let err = ShellApiServer::propose_add_validator(&handler, target)
            .await
            .unwrap_err();
        assert!(err.message().contains("not configured as a validator"));
    }

    #[tokio::test]
    async fn propose_remove_validator_no_signer_returns_error() {
        let handler = setup();
        let target = format!("0x{}", "ab".repeat(20));
        let err = ShellApiServer::propose_remove_validator(&handler, target)
            .await
            .unwrap_err();
        assert!(err.message().contains("not configured as a validator"));
    }

    #[tokio::test]
    async fn propose_add_validator_creates_correct_tx() {
        let (handler, _signer, _addr) = setup_with_proposer();
        let target = Address::from([0xAB; 20]).to_string();
        let result = ShellApiServer::propose_add_validator(&handler, target.clone()).await;
        assert!(
            result.is_ok(),
            "proposeAddValidator failed: {:?}",
            result.err()
        );

        // Verify a transaction was inserted into the mempool.
        assert_eq!(handler.tx_pool.len(), 1);

        // Verify the transaction has the correct calldata.
        let target_addr = parse_address(&target).unwrap();
        let expected_calldata = shell_evm::encode_add_validator_calldata(&target_addr);
        let pending = handler.tx_pool.pending(100);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx.data.as_ref(), expected_calldata.as_slice());
        assert_eq!(pending[0].tx.to, Some(shell_evm::registry_address()));
        assert_eq!(pending[0].tx.value, U256::ZERO);
        assert_eq!(pending[0].tx.chain_id, 42);
        assert_eq!(pending[0].tx.nonce, 0);
    }

    #[tokio::test]
    async fn propose_remove_validator_creates_correct_tx() {
        let (handler, _signer, _addr) = setup_with_proposer();
        let target = Address::from([0xCC; 20]).to_string();
        let result = ShellApiServer::propose_remove_validator(&handler, target.clone()).await;
        assert!(
            result.is_ok(),
            "proposeRemoveValidator failed: {:?}",
            result.err()
        );

        assert_eq!(handler.tx_pool.len(), 1);

        let target_addr = parse_address(&target).unwrap();
        let expected_calldata = shell_evm::encode_remove_validator_calldata(&target_addr);
        let pending = handler.tx_pool.pending(100);
        assert_eq!(pending[0].tx.data.as_ref(), expected_calldata.as_slice());
    }

    #[tokio::test]
    async fn propose_add_validator_uses_correct_nonce() {
        let (handler, _signer, addr) = setup_with_proposer();

        // Set the proposer nonce to 5.
        {
            let mut ws = handler.world_state.write();
            for _ in 0..5 {
                ws.increment_nonce(&addr).unwrap();
            }
        }

        let target = Address::from([0xAB; 20]).to_string();
        let result = ShellApiServer::propose_add_validator(&handler, target).await;
        assert!(
            result.is_ok(),
            "proposeAddValidator failed: {:?}",
            result.err()
        );

        let pending = handler.tx_pool.pending(100);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx.nonce, 5);
    }

    #[tokio::test]
    async fn propose_add_validator_returns_tx_hash_hex() {
        let (handler, _signer, _addr) = setup_with_proposer();
        let target = format!("0x{}", "ab".repeat(20));
        let result = ShellApiServer::propose_add_validator(&handler, target)
            .await
            .unwrap();
        // Must be a hex string starting with 0x, 32 bytes = 66 chars.
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 66);
    }

    // ── web3_* tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn web3_client_version() {
        let handler = setup();
        let result = Web3ApiServer::client_version(&handler).await.unwrap();
        assert_eq!(result, "shell-chain/0.6.0");
    }

    #[tokio::test]
    async fn web3_sha3_known_vector() {
        let handler = setup();
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let result = Web3ApiServer::sha3(&handler, "0x".to_string())
            .await
            .unwrap();
        assert_eq!(
            result,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[tokio::test]
    async fn web3_sha3_hello() {
        let handler = setup();
        let input = format!("0x{}", hex::encode(b"hello"));
        let result = Web3ApiServer::sha3(&handler, input).await.unwrap();
        let expected = shell_primitives::keccak256(b"hello");
        assert_eq!(result, format!("0x{}", hex::encode(expected.0)));
    }

    // ── net_* tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn net_version_returns_chain_id_decimal() {
        let handler = setup();
        // setup() uses chain_id = 42
        let result = NetApiServer::version(&handler).await.unwrap();
        assert_eq!(result, "42");
    }

    #[tokio::test]
    async fn net_listening_returns_true() {
        let handler = setup();
        let result = NetApiServer::listening(&handler).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn net_peer_count_returns_hex() {
        let handler = setup();
        let result = NetApiServer::peer_count(&handler).await.unwrap();
        assert_eq!(result, "0x0");
    }

    // ── eth_syncing test ──────────────────────────────────────────────

    #[tokio::test]
    async fn eth_syncing_returns_false() {
        let handler = setup();
        let result = EthApiServer::syncing(&handler).await.unwrap();
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    // ── eth_mining / eth_hashrate / eth_accounts tests ───────────────

    #[tokio::test]
    async fn eth_mining_returns_false_without_signer() {
        let handler = setup();
        let result = EthApiServer::mining(&handler).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn eth_mining_returns_true_with_signer() {
        let mut handler = setup();
        let signer = DilithiumSigner::generate();
        handler.proposer_signer = Some(Arc::new(signer));
        let result = EthApiServer::mining(&handler).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn eth_hashrate_returns_zero() {
        let handler = setup();
        let result = EthApiServer::hashrate(&handler).await.unwrap();
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn eth_accounts_returns_empty() {
        let handler = setup();
        let result = EthApiServer::accounts(&handler).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn eth_sign_returns_error() {
        let handler = setup();
        let addr = test_address(b"test-key");
        let result = EthApiServer::sign(&handler, addr, "0xdeadbeef".into()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("not supported"));
    }

    #[tokio::test]
    async fn eth_sign_transaction_returns_error() {
        let handler = setup();
        let result = EthApiServer::sign_transaction(&handler, serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("not supported"));
    }

    #[tokio::test]
    async fn eth_get_compilers_returns_empty() {
        let handler = setup();
        let result = EthApiServer::get_compilers(&handler).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn eth_protocol_version_returns_cancun() {
        let handler = setup();
        let result = EthApiServer::protocol_version(&handler).await.unwrap();
        assert_eq!(result, "0x45");
    }

    // ── shell_getValidatorStatus tests ────────────────────────────────

    #[tokio::test]
    async fn get_validator_status_not_validator() {
        let handler = setup();
        let addr = test_address(b"some-random-key");
        let result = ShellApiServer::get_validator_status(&handler, addr)
            .await
            .unwrap();
        assert_eq!(result["isValidator"], false);
        assert!(result["address"].is_string());
    }

    #[tokio::test]
    async fn get_validator_status_is_validator() {
        let handler = setup();
        let addr = test_address(b"validator-key-1");
        {
            let mut ws = handler.world_state.write();
            ws.set_validators(&[addr]).unwrap();
        }
        let result = ShellApiServer::get_validator_status(&handler, addr)
            .await
            .unwrap();
        assert_eq!(result["isValidator"], true);
    }

    // ── shell_getGovernanceInfo tests ─────────────────────────────────

    #[tokio::test]
    async fn get_governance_info_empty() {
        let handler = setup();
        let result = ShellApiServer::get_governance_info(&handler).await.unwrap();
        assert_eq!(result["validatorCount"], 0);
        assert_eq!(result["validators"], serde_json::json!([]));
        assert_eq!(result["proposalGasLimit"], 100_000);
        assert!(result["systemContractAddress"].is_string());
    }

    #[tokio::test]
    async fn get_governance_info_with_validators() {
        let handler = setup();
        let v1 = test_address(b"validator-key-1");
        let v2 = test_address(b"validator-key-2");
        {
            let mut ws = handler.world_state.write();
            ws.set_validators(&[v1, v2]).unwrap();
        }
        let result = ShellApiServer::get_governance_info(&handler).await.unwrap();
        assert_eq!(result["validatorCount"], 2);
        assert_eq!(result["validators"].as_array().unwrap().len(), 2);
    }

    // ── shell_estimateGovernanceGas tests ─────────────────────────────

    #[tokio::test]
    async fn estimate_governance_gas_add_validator() {
        let handler = setup();
        let result = ShellApiServer::estimate_governance_gas(&handler, "addValidator".into())
            .await
            .unwrap();
        // 21000 + 5000 = 26000 = 0x6590
        assert_eq!(result, "0x6590");
    }

    #[tokio::test]
    async fn estimate_governance_gas_remove_validator() {
        let handler = setup();
        let result = ShellApiServer::estimate_governance_gas(&handler, "removeValidator".into())
            .await
            .unwrap();
        assert_eq!(result, "0x6590");
    }

    #[tokio::test]
    async fn estimate_governance_gas_view_ops() {
        let handler = setup();
        let result = ShellApiServer::estimate_governance_gas(&handler, "getValidators".into())
            .await
            .unwrap();
        // 21000 = 0x5208
        assert_eq!(result, "0x5208");

        let result = ShellApiServer::estimate_governance_gas(&handler, "isValidator".into())
            .await
            .unwrap();
        assert_eq!(result, "0x5208");
    }

    #[tokio::test]
    async fn estimate_governance_gas_unknown_op() {
        let handler = setup();
        let result = ShellApiServer::estimate_governance_gas(&handler, "badOp".into()).await;
        assert!(result.is_err());
    }

    // ── shell_encodeAddValidator / encodeRemoveValidator tests ────────

    #[tokio::test]
    async fn encode_add_validator_returns_correct_hex() {
        let handler = setup();
        let target = Address::from([0xAB; 20]);
        let bech32_addr = target.to_string();

        let result = ShellApiServer::encode_add_validator(&handler, bech32_addr)
            .await
            .unwrap();

        let expected = shell_evm::encode_add_validator_calldata(&target);
        assert_eq!(result, format!("0x{}", hex::encode(expected)));
        // Must start with the selector
        assert!(result.starts_with("0x"));
        // 4-byte selector + 32-byte param = 36 bytes = 72 hex chars + "0x"
        assert_eq!(result.len(), 74);
    }

    #[tokio::test]
    async fn encode_remove_validator_returns_correct_hex() {
        let handler = setup();
        let target = Address::from([0xCD; 20]);
        let bech32_addr = target.to_string();

        let result = ShellApiServer::encode_remove_validator(&handler, bech32_addr)
            .await
            .unwrap();

        let expected = shell_evm::encode_remove_validator_calldata(&target);
        assert_eq!(result, format!("0x{}", hex::encode(expected)));
        assert_eq!(result.len(), 74);
    }

    #[tokio::test]
    async fn get_governance_info_has_system_contract_address() {
        let handler = setup();
        let result = ShellApiServer::get_governance_info(&handler).await.unwrap();
        let addr_str = result["systemContractAddress"].as_str().unwrap();
        let expected = format!("{}", shell_evm::registry_address());
        assert_eq!(addr_str, expected);
    }

    #[tokio::test]
    async fn get_validator_status_reflects_changes() {
        let handler = setup();
        let addr = test_address(b"dynamic-val");

        // Initially not a validator
        let result = ShellApiServer::get_validator_status(&handler, addr)
            .await
            .unwrap();
        assert_eq!(result["isValidator"], false);

        // Set as validator
        {
            let mut ws = handler.world_state.write();
            ws.set_validators(&[addr]).unwrap();
        }

        let result = ShellApiServer::get_validator_status(&handler, addr)
            .await
            .unwrap();
        assert_eq!(result["isValidator"], true);
    }

    #[tokio::test]
    async fn encode_add_validator_rejects_bad_address() {
        let handler = setup();
        let result = ShellApiServer::encode_add_validator(&handler, "not-hex".into()).await;
        assert!(result.is_err());
    }

    // ── shell_getNodeInfo ──────────────────────────────────────────

    #[tokio::test]
    async fn get_node_info_returns_all_fields() {
        let handler = setup();
        let result = ShellApiServer::get_node_info(&handler).await.unwrap();

        assert_eq!(result["version"], "ShellChain/v0.6.0/rust");
        assert_eq!(result["chainId"], 42);
        assert_eq!(result["blockHeight"], 0);
        assert_eq!(result["peerCount"], 0);
        assert!(result["txPoolSize"].is_u64());
        assert_eq!(result["isMining"], false);
        assert!(result["uptime"].is_u64());
        assert!(result["baseFee"].is_string());
    }

    #[tokio::test]
    async fn get_node_info_reflects_block_height() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = ShellApiServer::get_node_info(&handler).await.unwrap();
        assert_eq!(result["blockHeight"], 0);
        assert_eq!(result["chainId"], 42);
    }

    #[tokio::test]
    async fn get_node_info_mining_true_with_proposer() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let addr = signer_address(&signer);
        let handler = handler.with_proposer(Arc::new(signer), addr);

        let result = ShellApiServer::get_node_info(&handler).await.unwrap();
        assert_eq!(result["isMining"], true);
    }

    // ── shell_getNetworkStats ──────────────────────────────────────

    #[tokio::test]
    async fn get_network_stats_returns_all_fields() {
        let handler = setup();
        let result = ShellApiServer::get_network_stats(&handler).await.unwrap();

        assert_eq!(result["peerCount"], 0);
        assert_eq!(result["protocolVersion"], "shell/1.0.0");
        assert_eq!(result["listeningAddress"], "/ip4/0.0.0.0/tcp/30303");
        let protocols = result["protocols"].as_array().unwrap();
        assert_eq!(protocols.len(), 3);
        assert!(protocols.contains(&serde_json::json!("gossipsub")));
        assert!(protocols.contains(&serde_json::json!("kademlia")));
        assert!(protocols.contains(&serde_json::json!("mdns")));
    }

    // ── shell_getChainStats ────────────────────────────────────────

    #[tokio::test]
    async fn get_chain_stats_empty_chain() {
        let handler = setup();
        let result = ShellApiServer::get_chain_stats(&handler).await.unwrap();

        assert_eq!(result["blockHeight"], 0);
        assert_eq!(result["totalTransactions"], 0);
        assert_eq!(result["avgBlockTime"], 0.0);
        assert!(result["gasUsedTotal"].is_string());
        assert!(result["latestBaseFee"].is_string());
    }

    #[tokio::test]
    async fn get_chain_stats_with_blocks() {
        let handler = setup();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_003,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-key-data"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 1_000_000_000,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        };
        let hash1 = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &hash1).unwrap();
        handler.chain_store.set_head(&hash1).unwrap();

        let result = ShellApiServer::get_chain_stats(&handler).await.unwrap();
        assert_eq!(result["blockHeight"], 1);
        assert_eq!(result["totalTransactions"], 0);
        assert_eq!(result["avgBlockTime"], 3.0);
        assert_eq!(result["gasUsedTotal"], "0x5208"); // 21000
        assert!(result["latestBaseFee"].is_string());
    }

    // ── F-072: RpcBlock new Ethereum fields ──────────────────────────

    #[tokio::test]
    async fn rpc_block_has_standard_eth_fields() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(rpc.total_difficulty, "0x1");
        assert_eq!(
            rpc.sha3_uncles,
            "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
        );
        assert!(rpc.uncles.is_empty());
        assert_eq!(rpc.nonce, "0x0000000000000000");
        assert_eq!(rpc.difficulty, "0x1");
        assert_eq!(rpc.mix_hash, ShellHash::ZERO);
        assert_eq!(rpc.extra_data, "0x");
        // logs_bloom should be 256 zero bytes hex-encoded (514 chars = "0x" + 512 hex chars)
        assert_eq!(rpc.logs_bloom.len(), 514);
        assert!(rpc.logs_bloom.starts_with("0x"));
    }

    #[tokio::test]
    async fn rpc_block_logs_bloom_reflects_header() {
        let handler = setup();
        let mut bloom_bytes = [0u8; 256];
        bloom_bytes[0] = 0xFF;
        bloom_bytes[255] = 0xAA;

        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::copy_from_slice(&bloom_bytes),
                number: 0,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-key-data"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "latest".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert!(rpc.logs_bloom.starts_with("0xff"));
        assert!(rpc.logs_bloom.ends_with("aa"));
    }

    #[tokio::test]
    async fn rpc_block_json_has_sha3uncles_key() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap()
            .unwrap();
        let json = serde_json::to_value(&rpc).unwrap();
        // The JSON key must be "sha3Uncles" (not "sha3_uncles")
        assert!(json.get("sha3Uncles").is_some());
        assert!(json.get("totalDifficulty").is_some());
        assert!(json.get("logsBloom").is_some());
        assert!(json.get("mixHash").is_some());
    }

    // ── F-073: bloom false positive metric ──────────────────────────

    #[tokio::test]
    async fn bloom_false_positive_counter_increments() {
        let handler = setup();
        let addr = Address::from([0xBB; 20]);
        let log = shell_core::Log::new(addr, vec![], Bytes::new()).unwrap();
        store_block_with_logs(&handler, 0, vec![vec![log]]);

        assert_eq!(handler.bloom_false_positives(), 0);

        // Query for address 0xBB — bloom matches and logs match → no FP.
        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x0","address":"{}"}}"#,
            addr,
        ))
        .unwrap();
        let _ = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert_eq!(handler.bloom_false_positives(), 0);
    }

    // ── F-074: non-zero block size ──────────────────────────────────

    #[tokio::test]
    async fn block_size_is_non_zero() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap()
            .unwrap();

        let size = u64::from_str_radix(rpc.size.strip_prefix("0x").unwrap(), 16).unwrap();
        assert!(size > 0, "block size should be non-zero, got: {}", rpc.size);
    }

    // ── F-075: pending block support ────────────────────────────────

    #[tokio::test]
    async fn pending_block_returns_next_number() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "pending".into(), false)
            .await
            .unwrap()
            .unwrap();

        // Pending block number = head + 1.
        assert_eq!(rpc.number, "0x1");
        // Parent hash = head's hash.
        assert_eq!(rpc.parent_hash, hash);
        // Hash = zero (not yet mined).
        assert_eq!(rpc.hash, ShellHash::ZERO);
        // Empty mempool → no transactions.
        assert_eq!(rpc.transactions, serde_json::json!([]));
        // Still has standard Ethereum fields.
        assert_eq!(rpc.total_difficulty, "0x1");
        assert_eq!(rpc.nonce, "0x0000000000000000");
    }

    #[tokio::test]
    async fn pending_block_no_head_returns_none() {
        let handler = setup();
        let rpc = EthApiServer::get_block_by_number(&handler, "pending".into(), false)
            .await
            .unwrap();
        assert!(rpc.is_none());
    }

    // ── Finality RPC tests ─────────────────────────────────────

    #[tokio::test]
    async fn parse_block_number_finalized_and_safe() {
        let handler = setup();
        // Default finalized_number is 0.
        assert_eq!(handler.parse_block_number("finalized").unwrap(), Some(0));
        assert_eq!(handler.parse_block_number("safe").unwrap(), Some(0));

        // Update the shared finalized number.
        *handler.finalized_number.write() = 42;
        assert_eq!(handler.parse_block_number("finalized").unwrap(), Some(42));
        assert_eq!(handler.parse_block_number("safe").unwrap(), Some(42));

        // Existing tags still work.
        assert_eq!(handler.parse_block_number("latest").unwrap(), None);
        assert_eq!(handler.parse_block_number("pending").unwrap(), None);
        assert_eq!(handler.parse_block_number("earliest").unwrap(), Some(0));
        assert_eq!(handler.parse_block_number("0xa").unwrap(), Some(10));
    }

    #[tokio::test]
    async fn get_finality_info_returns_valid_json() {
        let handler = setup();

        // Store a genesis block as head.
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = ShellApiServer::get_finality_info(&handler).await.unwrap();
        assert_eq!(result["lastFinalizedBlock"], "0x0");
        assert_eq!(result["currentHead"], "0x0");
        assert_eq!(result["pendingAttestations"], 0);
    }

    #[tokio::test]
    async fn finalized_number_propagates_to_rpc() {
        let finalized_number = Arc::new(parking_lot::RwLock::new(0u64));
        let finality = Arc::new(parking_lot::RwLock::new(FinalityState::new()));

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(parking_lot::RwLock::new(WorldState::new(db)));
        let tx_pool = Arc::new(TxPool::new(shell_mempool::MempoolConfig {
            chain_id: 42,
            ..shell_mempool::MempoolConfig::default()
        }));
        let (block_events, _) = tokio::sync::broadcast::channel(16);

        let handler = RpcHandler::new(
            chain_store,
            world_state,
            tx_pool,
            42,
            None,
            block_events,
            finalized_number.clone(),
            finality.clone(),
        );

        // Initially 0.
        assert_eq!(handler.parse_block_number("finalized").unwrap(), Some(0));

        // Simulate finalization by updating the shared number.
        *finalized_number.write() = 100;
        assert_eq!(handler.parse_block_number("finalized").unwrap(), Some(100));

        // Verify get_finality_info reflects the update.
        let result = ShellApiServer::get_finality_info(&handler).await.unwrap();
        assert_eq!(result["lastFinalizedBlock"], "0x64"); // 100 in hex
    }

    // ── Filter RPC tests ────────────────────────────────────────

    #[tokio::test]
    async fn new_block_filter_returns_hex_id() {
        let handler = setup();
        let id = EthApiServer::new_block_filter(&handler).await.unwrap();
        assert!(id.starts_with("0x"));
    }

    #[tokio::test]
    async fn new_filter_returns_hex_id() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter = serde_json::from_str(r#"{}"#).unwrap();
        let id = EthApiServer::new_filter(&handler, raw).await.unwrap();
        assert!(id.starts_with("0x"));
    }

    #[tokio::test]
    async fn block_filter_tracks_new_blocks() {
        let handler = setup();

        // Store genesis block first so the filter starts at block 0.
        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        // Install a block filter.
        let filter_id = EthApiServer::new_block_filter(&handler).await.unwrap();

        // No new blocks yet — should return empty.
        let changes = EthApiServer::get_filter_changes(&handler, filter_id.clone())
            .await
            .unwrap();
        assert_eq!(changes, serde_json::json!([]));

        // Store block 1.
        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                number: 1,
                ..make_genesis_block().header
            },
            transactions: vec![],
            proposer_seal: None,
        };
        let hash1 = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &hash1).unwrap();
        handler.chain_store.set_head(&hash1).unwrap();

        // Now getFilterChanges should return block 1's hash.
        let changes = EthApiServer::get_filter_changes(&handler, filter_id.clone())
            .await
            .unwrap();
        let arr = changes.as_array().unwrap();
        assert_eq!(arr.len(), 1);

        // Polling again should return empty (already drained).
        let changes = EthApiServer::get_filter_changes(&handler, filter_id)
            .await
            .unwrap();
        assert_eq!(changes, serde_json::json!([]));
    }

    #[tokio::test]
    async fn log_filter_returns_matching_logs() {
        let handler = setup();
        let addr = Address::from([0xEE; 20]);
        let topic = ShellHash::from_slice(&[0xFF; 32]);
        let log = shell_core::Log::new(addr, vec![topic], Bytes::new()).unwrap();

        // Store a block with a log.
        store_block_with_logs(&handler, 0, vec![vec![log]]);

        // Install a log filter starting from block 0.
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(&format!(r#"{{"fromBlock":"0x0","address":"{}"}}"#, addr,))
                .unwrap();
        let filter_id = EthApiServer::new_filter(&handler, raw).await.unwrap();

        // Store block 1 with another matching log.
        let log2 = shell_core::Log::new(addr, vec![topic], Bytes::new()).unwrap();
        store_block_with_logs(&handler, 1, vec![vec![log2]]);

        // getFilterChanges should return logs from block 1 only (after the install point).
        let changes = EthApiServer::get_filter_changes(&handler, filter_id.clone())
            .await
            .unwrap();
        let arr = changes.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["blockNumber"], "0x1");
    }

    #[tokio::test]
    async fn get_filter_logs_returns_all_matching_logs() {
        let handler = setup();
        let addr = Address::from([0xDD; 20]);
        let log = shell_core::Log::new(addr, vec![], Bytes::new()).unwrap();
        store_block_with_logs(&handler, 0, vec![vec![log]]);

        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x0","address":"{}"}}"#,
            addr,
        ))
        .unwrap();
        let filter_id = EthApiServer::new_filter(&handler, raw).await.unwrap();

        let logs = EthApiServer::get_filter_logs(&handler, filter_id)
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, addr);
    }

    #[tokio::test]
    async fn uninstall_filter_removes_filter() {
        let handler = setup();
        let filter_id = EthApiServer::new_block_filter(&handler).await.unwrap();

        // Uninstall should succeed.
        let removed = EthApiServer::uninstall_filter(&handler, filter_id.clone())
            .await
            .unwrap();
        assert!(removed);

        // Second uninstall should return false.
        let removed = EthApiServer::uninstall_filter(&handler, filter_id.clone())
            .await
            .unwrap();
        assert!(!removed);

        // getFilterChanges on uninstalled filter should fail.
        let result = EthApiServer::get_filter_changes(&handler, filter_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_filter_changes_nonexistent_returns_error() {
        let handler = setup();
        let result = EthApiServer::get_filter_changes(&handler, "0xdead".into()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("filter not found"));
    }

    #[tokio::test]
    async fn get_filter_logs_on_block_filter_returns_error() {
        let handler = setup();
        let filter_id = EthApiServer::new_block_filter(&handler).await.unwrap();
        let result = EthApiServer::get_filter_logs(&handler, filter_id).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("filter not found"));
    }

    // ── Debug / Trace API tests ────────────────────────────────

    /// Helper: create a block with one transaction and store it along with receipts.
    /// Returns (block_hash, tx_hash).
    fn store_block_with_tx(
        handler: &RpcHandler<MemoryDb>,
        number: u64,
        succeeded: bool,
    ) -> (ShellHash, ShellHash) {
        let signer = DilithiumSigner::generate();
        let from = signer_address(&signer);
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            gas_limit: 21_000,
            to: Some(Address::from([0xBB; 20])),
            value: U256::from(1000),
            data: Bytes::from(vec![0xaa, 0xbb]),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]);
        let signed = SignedTransaction::new(from, tx, sig);
        let tx_hash = signed.hash();

        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-key-data"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![signed],
            proposer_seal: None,
        };
        let block_hash = block.hash();

        handler.chain_store.put_block(&block).unwrap();
        handler
            .chain_store
            .set_canonical(number, &block_hash)
            .unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

        let receipt = TransactionReceipt {
            tx_hash,
            block_number: number,
            tx_index: 0,
            status: if succeeded { 1 } else { 0 },
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            contract_address: None,
            logs_bloom: Bytes::default(),
            logs: vec![],
        };
        handler
            .chain_store
            .put_receipts(&block_hash, &[receipt])
            .unwrap();

        (block_hash, tx_hash)
    }

    #[tokio::test]
    async fn debug_trace_transaction_returns_call_frame() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let result = DebugApiServer::trace_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
            None,
        )
        .await
        .unwrap();

        assert_eq!(result["type"], "CALL");
        assert_eq!(result["failed"], false);
        assert_eq!(result["gasUsed"], 21_000);
        assert!(result["error"].is_null());
    }

    #[tokio::test]
    async fn debug_trace_transaction_reverted() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, false);

        let result = DebugApiServer::trace_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
            None,
        )
        .await
        .unwrap();

        assert_eq!(result["type"], "CALL");
        assert_eq!(result["failed"], true);
        assert_eq!(result["error"], "execution reverted");
    }

    #[tokio::test]
    async fn debug_trace_transaction_not_found() {
        let handler = setup();
        let fake_hash = "0x".to_string() + &"aa".repeat(32);
        let result = DebugApiServer::trace_transaction(&handler, fake_hash, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("not found"));
    }

    #[tokio::test]
    async fn debug_trace_block_by_number_returns_traces() {
        let handler = setup();
        store_block_with_tx(&handler, 0, true);

        let result = DebugApiServer::trace_block_by_number(&handler, "0x0".into(), None)
            .await
            .unwrap();

        let traces = result.as_array().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0]["type"], "CALL");
        assert_eq!(traces[0]["failed"], false);
    }

    #[tokio::test]
    async fn debug_trace_block_by_number_empty_block() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = DebugApiServer::trace_block_by_number(&handler, "0x0".into(), None)
            .await
            .unwrap();

        let traces = result.as_array().unwrap();
        assert!(traces.is_empty());
    }

    #[tokio::test]
    async fn trace_block_returns_oe_format() {
        let handler = setup();
        let (block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let result = TraceApiServer::trace_block(&handler, "0x0".into())
            .await
            .unwrap();

        let traces = result.as_array().unwrap();
        assert_eq!(traces.len(), 1);

        let t = &traces[0];
        assert_eq!(t["type"], "call");
        assert_eq!(t["subtraces"], 0);
        assert_eq!(t["traceAddress"], serde_json::json!([]));
        assert_eq!(t["blockNumber"], 0);
        assert_eq!(t["transactionPosition"], 0);
        assert_eq!(t["blockHash"], serde_json::to_value(block_hash).unwrap());
        assert_eq!(t["transactionHash"], serde_json::to_value(tx_hash).unwrap());
        // Action fields
        assert!(t["action"]["from"].is_string());
        assert!(t["action"]["gas"].is_string());
        // Result fields
        assert!(t["result"]["gasUsed"].is_string());
    }

    #[tokio::test]
    async fn trace_oe_transaction_returns_oe_format() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let result = TraceApiServer::trace_oe_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
        )
        .await
        .unwrap();

        let traces = result.as_array().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0]["type"], "call");
        assert!(traces[0]["error"].is_null());
    }

    #[tokio::test]
    async fn trace_oe_transaction_reverted_has_error() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, false);

        let result = TraceApiServer::trace_oe_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
        )
        .await
        .unwrap();

        let traces = result.as_array().unwrap();
        assert_eq!(traces[0]["error"], "execution reverted");
    }

    #[tokio::test]
    async fn trace_oe_transaction_not_found() {
        let handler = setup();
        let fake_hash = "0x".to_string() + &"cc".repeat(32);
        let result = TraceApiServer::trace_oe_transaction(&handler, fake_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("not found"));
    }

    #[tokio::test]
    async fn debug_trace_transaction_with_options() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let opts = serde_json::json!({ "tracer": "callTracer" });
        let result = DebugApiServer::trace_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
            Some(opts),
        )
        .await
        .unwrap();

        assert_eq!(result["type"], "CALL");
        assert_eq!(result["failed"], false);
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: RPC eth_* response format compatibility tests
    // ════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn m5a6_eth_chain_id_returns_hex_string() {
        let handler = setup();
        let result = EthApiServer::chain_id(&handler).await.unwrap();
        assert!(result.starts_with("0x"), "chain_id should be hex: {result}");
        assert_eq!(result, "0x2a");
    }

    #[tokio::test]
    async fn m5a6_eth_block_number_returns_hex_string() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = EthApiServer::block_number(&handler).await.unwrap();
        assert!(
            result.starts_with("0x"),
            "blockNumber should be hex: {result}"
        );
        assert_eq!(result, "0x0");
    }

    #[tokio::test]
    async fn m5a6_eth_gas_price_returns_hex_string() {
        let handler = setup();
        let result = EthApiServer::gas_price(&handler).await.unwrap();
        assert!(result.starts_with("0x"), "gasPrice should be hex: {result}");
    }

    #[tokio::test]
    async fn m5a6_eth_get_block_not_found_returns_none() {
        let handler = setup();
        let result = EthApiServer::get_block_by_number(&handler, "0xff".into(), false)
            .await
            .unwrap();
        assert!(result.is_none(), "non-existent block should return None");

        let fake_hash = ShellHash::from([0xAA; 32]);
        let result2 = EthApiServer::get_block_by_hash(&handler, fake_hash, false)
            .await
            .unwrap();
        assert!(
            result2.is_none(),
            "non-existent block by hash should return None"
        );
    }

    #[tokio::test]
    async fn m5a6_eth_get_block_tx_hashes_vs_full_txs() {
        let handler = setup();
        let (block_hash, _tx_hash) = store_block_with_tx(&handler, 0, true);

        let rpc_hashes = EthApiServer::get_block_by_hash(&handler, block_hash, false)
            .await
            .unwrap()
            .unwrap();
        let txs = rpc_hashes.transactions.as_array().unwrap();
        assert_eq!(txs.len(), 1);
        assert!(
            txs[0].is_string(),
            "with full=false, tx should be hash string"
        );

        let rpc_full = EthApiServer::get_block_by_hash(&handler, block_hash, true)
            .await
            .unwrap()
            .unwrap();
        let txs_full = rpc_full.transactions.as_array().unwrap();
        assert_eq!(txs_full.len(), 1);
        assert!(
            txs_full[0].is_object(),
            "with full=true, tx should be object"
        );
        assert!(txs_full[0].get("hash").is_some());
        assert!(txs_full[0].get("from").is_some());
    }

    #[tokio::test]
    async fn m5a6_eth_get_transaction_by_hash_format() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let result = EthApiServer::get_transaction_by_hash(&handler, tx_hash)
            .await
            .unwrap();
        assert!(result.is_some());
        let rpc_tx = result.unwrap();

        assert!(rpc_tx.value.starts_with("0x"));
        assert!(rpc_tx.gas.starts_with("0x"));
        assert!(rpc_tx.nonce.starts_with("0x"));
        assert!(rpc_tx.chain_id.starts_with("0x"));
        assert!(rpc_tx.tx_type.starts_with("0x"));
        assert!(rpc_tx.input.starts_with("0x"));
        assert_eq!(rpc_tx.v, "0x0");
        assert_eq!(rpc_tx.r, "0x0");
        assert_eq!(rpc_tx.s, "0x0");
    }

    #[tokio::test]
    async fn m5a6_eth_get_transaction_by_hash_not_found() {
        let handler = setup();
        let fake_hash = ShellHash::from([0xBB; 32]);
        let result = EthApiServer::get_transaction_by_hash(&handler, fake_hash)
            .await
            .unwrap();
        assert!(result.is_none(), "non-existent tx should return None");
    }

    #[tokio::test]
    async fn m5a6_eth_get_transaction_receipt_format() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let result = EthApiServer::get_transaction_receipt(&handler, tx_hash)
            .await
            .unwrap();
        assert!(result.is_some());
        let receipt = result.unwrap();

        assert!(receipt.block_number.starts_with("0x"));
        assert!(receipt.transaction_index.starts_with("0x"));
        assert!(receipt.gas_used.starts_with("0x"));
        assert!(receipt.cumulative_gas_used.starts_with("0x"));
        assert!(receipt.status.starts_with("0x"));
        assert_eq!(receipt.status, "0x1");
        assert!(receipt.tx_type.starts_with("0x"));
    }

    #[tokio::test]
    async fn m5a6_eth_get_transaction_receipt_not_found() {
        let handler = setup();
        let fake_hash = ShellHash::from([0xCC; 32]);
        let result = EthApiServer::get_transaction_receipt(&handler, fake_hash)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn m5a6_rpc_block_blob_gas_fields_are_hex() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.blob_gas_used = 131_072;
        block.header.excess_blob_gas = 393_216;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(rpc.blob_gas_used, "0x20000");
        assert_eq!(rpc.excess_blob_gas, "0x60000");
    }

    #[tokio::test]
    async fn m5a6_eth_get_balance_returns_hex_string() {
        let handler = setup();
        let addr = Address::from([0xAA; 20]);

        {
            let mut ws = handler.world_state.write();
            let account =
                shell_core::Account::new_user_account(ShellHash::ZERO, U256::from(1_000_000));
            ws.set_account(&addr, &account).unwrap();
        }

        let result = EthApiServer::get_balance(&handler, addr, None)
            .await
            .unwrap();
        assert!(result.starts_with("0x"), "balance should be hex: {result}");
        assert_eq!(result, "0xf4240");
    }

    #[tokio::test]
    async fn m5a6_eth_get_transaction_count_returns_hex_nonce() {
        let handler = setup();
        let addr = Address::from([0xBB; 20]);

        {
            let mut ws = handler.world_state.write();
            let mut account = shell_core::Account::new_user_account(ShellHash::ZERO, U256::ZERO);
            account.nonce = 42;
            ws.set_account(&addr, &account).unwrap();
        }

        let result = EthApiServer::get_transaction_count(&handler, addr, None)
            .await
            .unwrap();
        assert_eq!(result, "0x2a");
    }

    #[tokio::test]
    async fn m6b1_send_raw_transaction_rlp_format() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);
        let gas_limit = shell_evm::compute_intrinsic_gas(&[], true, &None);

        // Fund the sender and register pubkey so mempool can verify.
        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_priority_fee_per_gas: 100_000_000,
            max_fee_per_gas: 1_000_000_000,
            gas_limit,
            to: None,
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let signature = signer.sign(tx.hash().0.as_slice()).unwrap();
        let signed = SignedTransaction::new(addr, tx, signature);

        // Encode as RLP.
        let mut rlp_buf = Vec::new();
        alloy_rlp::Encodable::encode(&signed, &mut rlp_buf);
        let hex_payload = format!("0x{}", hex::encode(&rlp_buf));

        let result = EthApiServer::send_raw_transaction(&handler, hex_payload).await;
        assert!(
            result.is_ok(),
            "RLP send_raw_transaction failed: {:?}",
            result.err()
        );
        assert_eq!(handler.tx_pool.len(), 1);
    }

    #[tokio::test]
    async fn m6b1_send_raw_transaction_json_format() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);
        let gas_limit = shell_evm::compute_intrinsic_gas(&[], true, &None);

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_priority_fee_per_gas: 100_000_000,
            max_fee_per_gas: 1_000_000_000,
            gas_limit,
            to: None,
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let signature = signer.sign(tx.hash().0.as_slice()).unwrap();
        let signed = SignedTransaction::new(addr, tx, signature);

        // Encode as JSON (legacy format).
        let json_bytes = serde_json::to_vec(&signed).unwrap();
        let hex_payload = format!("0x{}", hex::encode(&json_bytes));

        let result = EthApiServer::send_raw_transaction(&handler, hex_payload).await;
        assert!(
            result.is_ok(),
            "JSON send_raw_transaction failed: {:?}",
            result.err()
        );
        assert_eq!(handler.tx_pool.len(), 1);
    }

    #[tokio::test]
    async fn m6b1_send_raw_transaction_invalid_format_rejected() {
        // Both RLP and JSON decode should fail for random garbage.
        let handler = setup();
        let garbage = format!("0x{}", hex::encode(b"this is not valid rlp or json"));
        let result = EthApiServer::send_raw_transaction(&handler, garbage).await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("not valid RLP or JSON"),
            "unexpected error: {err_msg}"
        );
    }
}
