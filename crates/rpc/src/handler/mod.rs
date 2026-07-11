//! RPC handler implementation backed by chain storage, world state, and mempool.

pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::sync::Arc;
pub(crate) use std::time::Instant;

pub(crate) use jsonrpsee::types::ErrorObjectOwned;

pub(crate) use alloy_rlp::Encodable;
pub(crate) use shell_consensus::{ConsensusEngine, FinalityState};
pub(crate) use shell_core::{
    Block, BlockHeader, SignedTransaction, SystemTransaction, Transaction, INITIAL_BASE_FEE,
};
pub(crate) use shell_crypto::{MultiVerifier, Signer};
pub(crate) use shell_mempool::TxPool;
pub(crate) use shell_pqvm::bloom::BLOOM_SIZE;
pub(crate) use shell_pqvm::{ShellPqvm, ShellStateDb};
pub(crate) use shell_primitives::{Address, Bytes, ShellHash, U256};
pub(crate) use shell_storage::{ChainStore, KvStore, WitnessStore, WorldState};

pub(crate) use crate::admin::{AdminApiServer, NodeInfo, PeerInfo};
pub(crate) use crate::api::{
    DebugApiServer, EthApiServer, LegacyEvmApiServer, NetApiServer, ShellApiServer, TraceApiServer,
    Web3ApiServer,
};
pub(crate) use crate::dev_control::DynDevRpcControl;
pub(crate) use crate::error::{
    dev_mode_required, feature_not_enabled, invalid_params, limit_exceeded, method_not_found,
    not_found, server_error,
};
pub(crate) use crate::filter::{RawLogFilter, MAX_BLOCK_RANGE, MAX_LOG_RESULTS};
pub(crate) use crate::filter_registry::{FilterKind, FilterRegistry};
pub(crate) use crate::subscriptions::{BlockEvent, SubscriptionTracker, SyncStatus};
pub(crate) use crate::types::*;

mod admin;
mod debug;
mod eth;
mod evm;
mod net;
mod shell_api;

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
    tx_broadcast: Option<tokio::sync::mpsc::Sender<SignedTransaction>>,
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
    /// Optional active storage profile descriptor surfaced via
    /// `shell_getStorageProfile`. Set by the node at startup; absent in pure
    /// in-memory test setups.
    storage_profile: Option<crate::types::StorageProfileInfo>,
    /// Optional consensus engine reference for `shell_consensusInfo` (W.6).
    consensus_engine: Option<Arc<parking_lot::RwLock<dyn ConsensusEngine>>>,
    /// Optional proof amendment store for STARK proof fallback (STK.2).
    proof_amendment_store: Option<Arc<shell_storage::ProofAmendmentStore<S>>>,
    /// STK.5: counter for STARK proof amendment queries.
    stark_amendments_queried_total: Arc<AtomicU64>,
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
            storage_profile: self.storage_profile.clone(),
            consensus_engine: self.consensus_engine.clone(),
            proof_amendment_store: self.proof_amendment_store.clone(),
            stark_amendments_queried_total: Arc::clone(&self.stark_amendments_queried_total),
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
        tx_broadcast: Option<tokio::sync::mpsc::Sender<SignedTransaction>>,
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
            storage_profile: None,
            consensus_engine: None,
            proof_amendment_store: None,
            stark_amendments_queried_total: Arc::new(AtomicU64::new(0)),
        };
        FilterRegistry::start_cleanup(Arc::clone(&handler.filter_registry));
        handler
    }

    /// Attach the active storage profile descriptor for `shell_getStorageProfile`.
    /// Set by the node at startup; absent in pure in-memory test setups.
    pub fn with_storage_profile(mut self, info: crate::types::StorageProfileInfo) -> Self {
        self.storage_profile = Some(info);
        self
    }

    /// Attach the consensus engine for `shell_consensusInfo` (W.6).
    pub fn with_consensus_engine(
        mut self,
        engine: Arc<parking_lot::RwLock<dyn ConsensusEngine>>,
    ) -> Self {
        self.consensus_engine = Some(engine);
        self
    }

    /// Attach a proof amendment store for STARK proof fallback (STK.2/STK.3).
    pub fn with_proof_amendment_store(
        mut self,
        store: Arc<shell_storage::ProofAmendmentStore<S>>,
    ) -> Self {
        self.proof_amendment_store = Some(store);
        self
    }

    /// STK.2: Annotate the block with local compression/pruning state and proof
    /// size metadata without attaching the full proof bytes.
    pub(crate) fn fill_stark_metadata(&self, block_hash: &ShellHash, rpc_block: &mut RpcBlock) {
        self.fill_block_compression_metadata(block_hash, rpc_block);
        if rpc_block.sig_aggregate_proof_size.is_some() {
            return;
        }
        let store = match &self.proof_amendment_store {
            Some(s) => s,
            None => return,
        };
        let bytes = match store.get_amendment(block_hash) {
            Ok(Some(b)) => b,
            _ => return,
        };
        match shell_stark_prover::StoredProofArtifact::from_json(&bytes) {
            Ok(shell_stark_prover::StoredProofArtifact::Amendment(amendment)) => {
                rpc_block.sig_aggregate_proof_size = Some(amendment.proof.proof_bytes.len() as u64);
            }
            Ok(shell_stark_prover::StoredProofArtifact::Pointer(_)) | Err(_) => {}
        }
    }

    /// STK.2: If the block's `sig_aggregate_proof` is None and a proof amendment
    /// store is configured, attempt to fill it from stored async proofs. Also
    /// annotates the block with the local compression/pruning state.
    pub(crate) fn fill_stark_proof(&self, block_hash: &ShellHash, rpc_block: &mut RpcBlock) {
        self.fill_stark_metadata(block_hash, rpc_block);
        if rpc_block.sig_aggregate_proof.is_some() {
            return;
        }
        let store = match &self.proof_amendment_store {
            Some(s) => s,
            None => return,
        };
        let bytes = match store.get_amendment(block_hash) {
            Ok(Some(b)) => b,
            _ => return,
        };
        match shell_stark_prover::StoredProofArtifact::from_json(&bytes) {
            Ok(shell_stark_prover::StoredProofArtifact::Amendment(amendment)) => {
                rpc_block.sig_aggregate_proof_size = Some(amendment.proof.proof_bytes.len() as u64);
                rpc_block.sig_aggregate_proof = Some(hex_bytes(&amendment.proof.proof_bytes));
            }
            Ok(shell_stark_prover::StoredProofArtifact::Pointer(_)) | Err(_) => {}
        }
    }

    fn fill_block_compression_metadata(&self, block_hash: &ShellHash, rpc_block: &mut RpcBlock) {
        let mut layer = 0u32;
        let mut has_proof = false;
        if let Some(store) = &self.proof_amendment_store {
            if let Ok(Some(bytes)) = store.get_amendment(block_hash) {
                if let Ok(artifact) = shell_stark_prover::StoredProofArtifact::from_json(&bytes) {
                    layer = artifact.layer();
                    has_proof = true;
                }
            }
        }

        let has_witness = self
            .witness_store
            .as_ref()
            .and_then(|store| store.has_bundle(block_hash).ok())
            .unwrap_or(false);

        rpc_block.compression_layer = layer;
        rpc_block.pruning_status = match (has_proof, has_witness) {
            (true, true) => "compressedWitnessRetained",
            (true, false) => "pruned",
            (false, true) => "unpruned",
            (false, false) => "notWitnessed",
        }
        .to_string();
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
                return Err(server_error(format!(
                    "max fee per gas ({}) below current base fee ({})",
                    signed_tx.tx.max_fee_per_gas, current_base_fee
                )));
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
            .map_err(|e| server_error(e.to_string()))?;

        // Broadcast to peers via the network channel.
        if let (Some(sender), Some(tx)) = (&self.tx_broadcast, tx_for_broadcast) {
            // Use try_send (non-blocking) to avoid blocking the RPC handler.
            // If the channel is full, the tx is already in the mempool and will be
            // included in a block — dropping the broadcast here is safe.
            let _ = sender.try_send(tx);
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
        let max_fee_per_gas = self
            .chain_store
            .get_head_block()
            .map_err(internal_err)?
            .map(|head| head.header.base_fee_per_gas)
            .filter(|fee| *fee > 0)
            .unwrap_or(INITIAL_BASE_FEE);

        let tx = Transaction {
            chain_id: self.chain_id,
            nonce,
            to: Some(shell_pqvm::registry_address()),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(&calldata),
            gas_limit: 100_000,
            max_fee_per_gas,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let tx_hash = tx.signing_hash(signer.sig_type().as_u8());
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
        let mut evm = ShellPqvm::new(state_db, self.chain_id);

        let from = req.from.unwrap_or(Address::ZERO);
        // Cap gas to prevent DoS via unbounded simulated execution.
        const RPC_GAS_CAP: u64 = 50_000_000;
        let gas_limit = req
            .gas
            .as_deref()
            .map(|s| parse_hex_u64(s))
            .transpose()?
            .unwrap_or(30_000_000)
            .min(RPC_GAS_CAP);
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
                let Some(s) = s.strip_prefix("0x") else {
                    return Err(invalid_params_err("call data must be 0x-prefixed"));
                };
                if s.len() > shell_mempool::MAX_TX_SIZE.saturating_mul(2) {
                    return Err(invalid_params_err(format!(
                        "call data exceeds maximum size of {} bytes",
                        shell_mempool::MAX_TX_SIZE
                    )));
                }
                hex::decode(s)
                    .map(Bytes::from)
                    .map_err(|e| invalid_params_err(format!("invalid call data hex: {e}")))
            })
            .transpose()?
            .unwrap_or_default();

        let access_list = req
            .access_list
            .as_ref()
            .map(|list| {
                if list.len() > shell_core::MAX_ACCESS_LIST_ENTRIES {
                    return Err(invalid_params_err(format!(
                        "access list supports at most {} entries",
                        shell_core::MAX_ACCESS_LIST_ENTRIES
                    )));
                }
                list.iter()
                    .map(|item| {
                        if item.storage_keys.len() > shell_core::MAX_ACCESS_LIST_STORAGE_KEYS {
                            return Err(invalid_params_err(format!(
                                "access list storage keys support at most {} entries per address",
                                shell_core::MAX_ACCESS_LIST_STORAGE_KEYS
                            )));
                        }
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
            nonce: u64::default(),
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
            .map_err(|e| internal_err(format!("PQVM execution failed: {e}")))?;

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
        let Some(hex_str) = tx_hash.strip_prefix("0x") else {
            return Err(invalid_params_err("tx hash must be 0x-prefixed"));
        };
        if hex_str.len() != 64 {
            return Err(invalid_params_err("tx hash must be 32 bytes"));
        }
        let hash_bytes = hex::decode(hex_str)
            .map_err(|e| invalid_params_err(format!("invalid tx hash hex: {e}")))?;
        let hash = ShellHash::try_from_slice(&hash_bytes)
            .map_err(|e| invalid_params_err(format!("invalid tx hash length: {e}")))?;

        let (block_hash, tx_index) = self
            .chain_store
            .get_tx_location(&hash)
            .map_err(internal_err)?
            .ok_or_else(|| not_found_err("transaction not found"))?;

        let block = self
            .chain_store
            .get_block_by_hash(&block_hash)
            .map_err(internal_err)?
            .ok_or_else(|| not_found_err("block not found"))?;

        let tx = block
            .transactions
            .get(tx_index as usize)
            .ok_or_else(|| not_found_err("transaction not in block"))?
            .clone();

        let receipts = self
            .chain_store
            .get_receipts(&block_hash)
            .map_err(internal_err)?
            .ok_or_else(|| not_found_err("receipts not found"))?;

        let receipt = receipts
            .get(tx_index as usize)
            .ok_or_else(|| not_found_err("receipt not found"))?
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
                .ok_or_else(|| not_found_err(format!("block {n} not found"))),
            None => {
                // "latest" — resolve head
                let head = self.chain_store.get_head_block().map_err(internal_err)?;
                head.ok_or_else(|| not_found_err("chain has no blocks"))
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

/// Convert a storage error into a JSON-RPC internal error.
/// The raw error details are logged server-side but NOT returned to callers
/// to prevent leaking internal implementation details.
pub(crate) fn internal_err(msg: impl std::fmt::Display) -> ErrorObjectOwned {
    tracing::error!(rpc_internal_error = %msg, "RPC internal error");
    ErrorObjectOwned::owned(-32603, "Internal server error", None::<()>)
}

/// Resource not found — a valid user-facing response, exposed to the caller.
pub(crate) fn not_found_err(msg: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, msg.to_string(), None::<()>)
}

/// Convert a user input problem into a JSON-RPC invalid params error.
pub(crate) fn invalid_params_err(msg: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.to_string(), None::<()>)
}

pub(crate) fn buffered_gas_estimate(gas_used: u64, minimum: u64) -> u64 {
    let buffered = gas_used.saturating_add(gas_used / 5);
    buffered.max(minimum)
}

/// Parse a user-facing address string. Only `0x` + 64 lowercase hex is accepted.
pub(crate) fn parse_address(s: &str) -> Result<Address, ErrorObjectOwned> {
    Address::parse(s).map_err(|e| invalid_params_err(format!("invalid address: {e}")))
}

/// Parse a 32-byte hex string into `ShellHash`.
pub(crate) fn parse_hex_hash(s: &str) -> Result<ShellHash, ErrorObjectOwned> {
    let Some(hex_str) = s.strip_prefix("0x") else {
        return Err(invalid_params_err("hash must be 0x-prefixed"));
    };
    if hex_str.len() != 64 {
        return Err(invalid_params_err("hash must be 32 bytes"));
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| invalid_params_err(format!("invalid hash hex: {e}")))?;
    ShellHash::try_from_slice(&bytes)
        .map_err(|e| invalid_params_err(format!("invalid hash length: {e}")))
}

/// Parse a hex string "0x..." into u64.
pub(crate) fn parse_hex_u64(s: &str) -> Result<u64, ErrorObjectOwned> {
    let s = canonical_hex_quantity_digits(s, "u64")?;
    if s.len() > 16 {
        return Err(invalid_params_err(format!(
            "hex string too long for u64: {} chars (max 16)",
            s.len()
        )));
    }
    u64::from_str_radix(s, 16).map_err(|_| invalid_params_err(format!("invalid hex u64: 0x{s}")))
}

/// Parse a hex string "0x..." into U256.
pub(crate) fn parse_hex_u256(s: &str) -> Result<U256, ErrorObjectOwned> {
    let s = canonical_hex_quantity_digits(s, "U256")?;
    // F-066: reject oversized input to prevent silent truncation.
    if s.len() > 64 {
        return Err(invalid_params_err(format!(
            "hex string too long for U256: {} chars (max 64)",
            s.len()
        )));
    }
    let bytes = hex::decode(if s.len() < 64 {
        format!("{:0>64}", s)
    } else {
        s.to_string()
    })
    .map_err(|_| invalid_params_err(format!("invalid hex U256: 0x{s}")))?;
    Ok(U256::from_be_slice(&bytes))
}

fn canonical_hex_quantity_digits<'a>(
    value: &'a str,
    type_name: &str,
) -> Result<&'a str, ErrorObjectOwned> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(invalid_params_err(format!(
            "invalid hex {type_name}: missing 0x prefix"
        )));
    };
    if hex.is_empty() {
        return Err(invalid_params_err(format!(
            "invalid hex {type_name}: empty quantity"
        )));
    }
    if hex.len() > 1 && hex.starts_with('0') {
        return Err(invalid_params_err(format!(
            "invalid hex {type_name}: quantity has leading zeroes"
        )));
    }
    if !hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid_params_err(format!(
            "invalid hex {type_name}: contains non-hex characters"
        )));
    }
    Ok(hex)
}

/// Parsed block number tag.
pub(crate) enum BlockTag {
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
pub(crate) fn parse_block_tag(s: &str) -> Result<BlockTag, ErrorObjectOwned> {
    match s {
        "latest" => Ok(BlockTag::Latest),
        "safe" | "finalized" => Ok(BlockTag::Finalized),
        "pending" => Ok(BlockTag::Pending),
        "earliest" => Ok(BlockTag::Number(0)),
        hex if hex.starts_with("0x") => parse_hex_u64(hex).map(BlockTag::Number),
        _ => Err(invalid_block_tag_err()),
    }
}

/// Current state backend only exposes the live world state. Reject historical
/// state tags instead of returning latest-state data for a historical request.
pub(crate) fn validate_state_block_is_latest(s: &str) -> Result<(), ErrorObjectOwned> {
    match s {
        "latest" | "pending" => Ok(()),
        "safe" | "finalized" | "earliest" => Err(invalid_params_err(
            "historical state queries are not supported; use latest or pending",
        )),
        hex if hex.starts_with("0x") => {
            let _ = parse_hex_u64(hex)?;
            Err(invalid_params_err(
                "historical state queries are not supported; use latest or pending",
            ))
        }
        _ => Err(invalid_block_tag_err()),
    }
}

fn invalid_block_tag_err() -> ErrorObjectOwned {
    invalid_params_err("invalid block tag: expected latest, pending, earliest, safe, finalized, or 0x-prefixed quantity")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockTxDetail {
    Hashes,
    Summary,
    Full,
}

impl BlockTxDetail {
    fn include_stark_proof(self) -> bool {
        matches!(self, Self::Hashes | Self::Full)
    }
}

impl<S: KvStore + 'static> RpcHandler<S> {
    pub(crate) fn attach_system_txs(
        &self,
        block: &Block,
        rpc: &mut RpcBlock,
        detail: BlockTxDetail,
    ) {
        let block_hash = block.hash();
        let Ok(system_txs) = self.chain_store.get_system_transactions(&block_hash) else {
            return;
        };
        if system_txs.is_empty() {
            return;
        }

        let Ok(mut existing) =
            serde_json::from_value::<Vec<serde_json::Value>>(rpc.transactions.clone())
        else {
            return;
        };
        let ordered_system_txs = ordered_system_txs(&system_txs);
        match detail {
            BlockTxDetail::Full => {
                let mut merged: Vec<serde_json::Value> = ordered_system_txs
                    .into_iter()
                    .filter_map(|tx| {
                        serde_json::to_value(system_tx_to_rpc(tx, Some(block_hash))).ok()
                    })
                    .collect();
                merged.extend(existing);
                existing = merged;
            }
            BlockTxDetail::Summary => {
                let mut merged: Vec<serde_json::Value> = ordered_system_txs
                    .into_iter()
                    .filter_map(|tx| {
                        serde_json::to_value(system_tx_to_rpc_summary(tx, Some(block_hash))).ok()
                    })
                    .collect();
                merged.extend(existing);
                existing = merged;
            }
            BlockTxDetail::Hashes => {
                let mut merged: Vec<serde_json::Value> = ordered_system_txs
                    .into_iter()
                    .map(|tx| serde_json::json!(tx.hash()))
                    .collect();
                merged.extend(existing);
                existing = merged;
            }
        }
        rpc.transactions = serde_json::Value::Array(existing);
    }
}

fn ordered_system_txs(system_txs: &[SystemTransaction]) -> Vec<&SystemTransaction> {
    let mut ordered = system_txs.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|tx| {
        let priority = match tx.kind {
            shell_core::SystemTxKind::BlockGasReward => 0u8,
            shell_core::SystemTxKind::StarkReward => 1u8,
        };
        (priority, tx.tx_index)
    });
    ordered
}

fn system_tx_type_hex(kind: shell_core::SystemTxKind) -> &'static str {
    match kind {
        shell_core::SystemTxKind::BlockGasReward => "0x80",
        shell_core::SystemTxKind::StarkReward => "0x81",
    }
}

pub(crate) fn parse_block_tx_detail(
    tx_detail: Option<&str>,
) -> Result<BlockTxDetail, ErrorObjectOwned> {
    match tx_detail.unwrap_or("hashes") {
        "hashes" | "hash" | "false" => Ok(BlockTxDetail::Hashes),
        "summary" | "light" | "lite" => Ok(BlockTxDetail::Summary),
        "full" | "true" => Ok(BlockTxDetail::Full),
        other => Err(invalid_params_err(format!(
            "invalid tx detail mode '{other}', expected hashes, summary, or full"
        ))),
    }
}

/// Convert a core Block to an RpcBlock response.
///
/// `Hashes` and `Full` match Ethereum-compatible `eth_getBlockByNumber` /
/// `eth_getBlockByHash` semantics. `Summary` is a Shell extension for explorers:
/// it includes row-ready transaction metadata but strips signatures, full input
/// data, and STARK aggregate proof bytes.
pub(crate) fn block_to_rpc_with_detail(block: &Block, detail: BlockTxDetail) -> RpcBlock {
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

    let transactions = match detail {
        BlockTxDetail::Full => serde_json::to_value(
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
        .unwrap_or_default(),
        BlockTxDetail::Summary => serde_json::to_value(
            block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    tx_to_rpc_summary(
                        tx,
                        Some(block.hash()),
                        Some(block.header.number),
                        Some(i as u32),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default(),
        BlockTxDetail::Hashes => serde_json::to_value(
            block
                .transactions
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<ShellHash>>(),
        )
        .unwrap_or_default(),
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
        withdrawals_root: block.header.withdrawals_root.to_string(),
        parent_beacon_block_root: block.header.parent_beacon_block_root.to_string(),
        blob_gas_used: hex_u64(block.header.blob_gas_used),
        excess_blob_gas: hex_u64(block.header.excess_blob_gas),
        sig_aggregate_proof_size: block
            .header
            .sig_aggregate_proof
            .as_ref()
            .map(|p| p.len() as u64),
        sig_aggregate_proof: if detail.include_stark_proof() {
            block
                .header
                .sig_aggregate_proof
                .as_ref()
                .map(|p| hex_bytes(p.as_ref()))
        } else {
            None
        },
        compression_layer: 0,
        pruning_status: "unknown".into(),
    }
}

pub(crate) fn block_to_rpc(block: &Block, full_txs: bool) -> RpcBlock {
    block_to_rpc_with_detail(
        block,
        if full_txs {
            BlockTxDetail::Full
        } else {
            BlockTxDetail::Hashes
        },
    )
}

/// Convert a SignedTransaction to an RpcTransaction response.
pub(crate) fn tx_to_rpc(
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
        shell_type: Some(
            if tx.is_aa_bundle() {
                "aaBatch"
            } else if tx.tx.to.is_none() {
                "contractCreate"
            } else if !tx.tx.data.is_empty() {
                "contractCall"
            } else {
                "transfer"
            }
            .into(),
        ),
        reward_kind: None,
        reward_layer: None,
        reward_source_hash: None,
        original_size: None,
        compressed_size: None,
        decoded_input: None,
    }
}

/// Attempt to decode a proof payload as a JSON-structured `ProofAmendment`.
///
/// Returns `Some(serde_json::Value)` when the payload is valid JSON; `None` otherwise.
/// Used to populate the `decoded_input` field on `StarkReward` RPC transactions.
pub(crate) fn decode_proof_amendment_input(payload: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(payload).ok()
}

pub(crate) fn system_tx_to_rpc(
    tx: &SystemTransaction,
    block_hash: Option<ShellHash>,
) -> RpcTransaction {
    let decoded_input = tx
        .proof_payload
        .as_ref()
        .filter(|_| tx.kind == shell_core::SystemTxKind::StarkReward)
        .and_then(|payload| decode_proof_amendment_input(payload.as_ref()));
    RpcTransaction {
        hash: tx.hash(),
        block_hash,
        block_number: Some(hex_u64(tx.block_number)),
        transaction_index: Some(hex_u64(tx.tx_index as u64)),
        from: tx.from,
        to: Some(tx.to),
        value: hex_u256(tx.value),
        gas: hex_u64(0),
        gas_price: hex_u64(0),
        max_fee_per_gas: hex_u64(0),
        max_priority_fee_per_gas: hex_u64(0),
        nonce: hex_u64(0),
        input: tx
            .proof_payload
            .as_ref()
            .map(|payload| hex_bytes(payload.as_ref()))
            .unwrap_or_else(|| "0x".into()),
        chain_id: hex_u64(tx.chain_id),
        tx_type: system_tx_type_hex(tx.kind).into(),
        v: "0x0".into(),
        r: "0x0".into(),
        s: "0x0".into(),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        shell_type: Some(tx.kind.as_str().into()),
        reward_kind: Some(tx.kind.as_str().into()),
        reward_layer: tx.layer.map(|l| hex_u64(l as u64)),
        reward_source_hash: Some(tx.source_hash),
        original_size: tx.original_size.map(hex_u64),
        compressed_size: tx.compressed_size.map(hex_u64),
        decoded_input,
    }
}

pub(crate) fn tx_to_rpc_summary(
    tx: &SignedTransaction,
    block_hash: Option<ShellHash>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
) -> RpcTransactionSummary {
    RpcTransactionSummary {
        hash: tx.hash(),
        block_hash,
        block_number: block_number.map(hex_u64),
        transaction_index: tx_index.map(|i| hex_u64(i as u64)),
        from: tx.sender(),
        to: tx.tx.to,
        value: hex_u256(tx.tx.value),
        tx_type: format!("{:#x}", tx.tx.tx_type),
        has_input: !tx.tx.data.is_empty(),
        shell_type: Some(
            if tx.is_aa_bundle() {
                "aaBatch"
            } else if tx.tx.to.is_none() {
                "contractCreate"
            } else if !tx.tx.data.is_empty() {
                "contractCall"
            } else {
                "transfer"
            }
            .into(),
        ),
        reward_kind: None,
        reward_layer: None,
        reward_source_hash: None,
        original_size: None,
        compressed_size: None,
    }
}

pub(crate) fn system_tx_to_rpc_summary(
    tx: &SystemTransaction,
    block_hash: Option<ShellHash>,
) -> RpcTransactionSummary {
    RpcTransactionSummary {
        hash: tx.hash(),
        block_hash,
        block_number: Some(hex_u64(tx.block_number)),
        transaction_index: Some(hex_u64(tx.tx_index as u64)),
        from: tx.from,
        to: Some(tx.to),
        value: hex_u256(tx.value),
        tx_type: system_tx_type_hex(tx.kind).into(),
        has_input: tx.proof_payload.as_ref().is_some_and(|p| !p.is_empty()),
        shell_type: Some(tx.kind.as_str().into()),
        reward_kind: Some(tx.kind.as_str().into()),
        reward_layer: tx.layer.map(|l| hex_u64(l as u64)),
        reward_source_hash: Some(tx.source_hash),
        original_size: tx.original_size.map(hex_u64),
        compressed_size: tx.compressed_size.map(hex_u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ShellApiServer;
    use crate::dev_control::DevRpcControl;
    use shell_consensus::{PoaConfig, PoaEngine};
    use shell_core::{Block, BlockHeader, SystemTransaction, Transaction, TransactionReceipt};
    use shell_crypto::{DilithiumSigner, Signer};
    use shell_primitives::Bytes;
    use shell_storage::{MemoryDb, ProofAmendmentStore, WitnessStore};
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
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    #[tokio::test]
    async fn block_number_empty_chain() {
        let handler = setup();
        let result = EthApiServer::block_number(&handler).await.unwrap();
        assert_eq!(result, "0x0");
    }

    #[test]
    fn buffered_gas_estimate_uses_integer_math_and_saturates() {
        assert_eq!(buffered_gas_estimate(0, 21_000), 21_000);
        assert_eq!(buffered_gas_estimate(21_000, 21_000), 25_200);
        assert_eq!(buffered_gas_estimate(21_001, 21_000), 25_201);
        assert_eq!(buffered_gas_estimate(u64::MAX, 21_000), u64::MAX);
    }

    #[test]
    fn rpc_quantity_parsers_reject_non_canonical_hex() {
        for value in ["42", "0x", "0x00", "0x01", "0x-1", "0xgg"] {
            assert!(
                parse_hex_u64(value).is_err(),
                "u64 quantity should reject {value}"
            );
            assert!(
                parse_hex_u256(value).is_err(),
                "U256 quantity should reject {value}"
            );
        }
    }

    #[test]
    fn rpc_quantity_parsers_accept_canonical_hex() {
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("0xa").unwrap(), 10);
        assert_eq!(parse_hex_u64("0xA").unwrap(), 10);
        assert_eq!(parse_hex_u256("0x0").unwrap(), U256::ZERO);
        assert_eq!(parse_hex_u256("0x2a").unwrap(), U256::from(42u64));
        assert_eq!(
            parse_hex_u256("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap(),
            U256::from_be_slice(&[0xff; 32])
        );
    }

    #[test]
    fn rpc_hash_parser_requires_exact_hash_length_before_decode() {
        let valid = format!("0x{}", "11".repeat(32));
        assert_eq!(parse_hex_hash(&valid).unwrap(), ShellHash::from([0x11; 32]));

        let short = parse_hex_hash("0x11").unwrap_err();
        assert_eq!(short.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(short.message().contains("32 bytes"));

        let oversized = format!("0x{}", "aa".repeat(512));
        let err = parse_hex_hash(&oversized).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("32 bytes"));
        assert!(
            !err.message().contains(&"aa".repeat(64)),
            "error should not reflect large hash inputs"
        );

        let invalid_hex = format!("0x{}zz", "00".repeat(31));
        let err = parse_hex_hash(&invalid_hex).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("invalid hash hex"));
    }

    #[test]
    fn block_tag_parser_rejects_non_canonical_quantities() {
        assert!(matches!(
            parse_block_tag("0xa").unwrap(),
            BlockTag::Number(10)
        ));
        assert!(matches!(
            parse_block_tag("0xffffffffffffffff").unwrap(),
            BlockTag::Number(u64::MAX)
        ));
        assert!(matches!(
            parse_block_tag("latest").unwrap(),
            BlockTag::Latest
        ));

        for value in ["10", "0x", "0x00", "0x01", "0xzz", "0x10000000000000000"] {
            assert!(
                parse_block_tag(value).is_err(),
                "block tag should reject {value}"
            );
        }
    }

    #[test]
    fn hex_quantity_errors_do_not_echo_large_invalid_input() {
        let value = format!("0x{}z", "f".repeat(512));
        let err = match parse_block_tag(&value) {
            Ok(_) => panic!("oversized invalid quantity should be rejected"),
            Err(err) => err,
        };
        assert!(err.message().contains("non-hex characters"));
        assert!(
            !err.message().contains(&"f".repeat(128)),
            "error should not reflect large invalid quantities"
        );
    }

    #[test]
    fn block_tag_errors_do_not_echo_large_invalid_input() {
        let value = "not-a-block-tag".repeat(128);
        let err = match parse_block_tag(&value) {
            Ok(_) => panic!("large invalid block tag should be rejected"),
            Err(err) => err,
        };
        assert!(err.message().contains("invalid block tag"));
        assert!(
            !err.message().contains("not-a-block-tag"),
            "block tag errors should not reflect caller input"
        );

        let err = validate_state_block_is_latest(&value).unwrap_err();
        assert!(err.message().contains("invalid block tag"));
        assert!(
            !err.message().contains("not-a-block-tag"),
            "state block validation errors should not reflect caller input"
        );
    }

    #[test]
    fn state_block_validation_rejects_invalid_quantities_before_history_error() {
        assert!(validate_state_block_is_latest("latest").is_ok());
        assert!(validate_state_block_is_latest("pending").is_ok());

        let historical = validate_state_block_is_latest("0x1").unwrap_err();
        assert!(historical.message().contains("historical state"));

        for value in ["1", "0x", "0x00", "0x01"] {
            let err = validate_state_block_is_latest(value).unwrap_err();
            assert!(
                !err.message().contains("historical state"),
                "invalid tag {value} should fail before historical-state handling"
            );
        }
    }

    #[tokio::test]
    async fn evm_rpc_methods_delegate_to_dev_control() {
        let dev = Arc::new(MockDevControl::default());
        let handler = setup().with_dev_control(dev.clone());

        let mined = LegacyEvmApiServer::mine(&handler, Some(2)).await.unwrap();
        assert_eq!(mined["blocksMined"], "0x2");
        assert_eq!(dev.mined.load(Ordering::Relaxed), 2);

        let next = LegacyEvmApiServer::set_next_block_timestamp(&handler, 1_700_000_123)
            .await
            .unwrap();
        assert_eq!(next, serde_json::json!("0x6553f17b"));

        let increased = LegacyEvmApiServer::increase_time(&handler, 30)
            .await
            .unwrap();
        assert_eq!(increased, serde_json::json!("0x1e"));

        let snapshot = LegacyEvmApiServer::snapshot(&handler).await.unwrap();
        assert_eq!(snapshot, "0x1");
        assert!(LegacyEvmApiServer::revert(&handler, "0x1".into())
            .await
            .unwrap());
        assert!(!LegacyEvmApiServer::revert(&handler, "0x2".into())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn evm_mine_rejects_excessive_block_count() {
        let dev = Arc::new(MockDevControl::default());
        let handler = setup().with_dev_control(dev.clone());

        let err = LegacyEvmApiServer::mine(&handler, Some(257))
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at most 256"));
        assert_eq!(dev.mined.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn set_balance_requires_dev_control() {
        let handler = setup();
        let addr = test_address(b"set-balance-no-dev");

        let err = ShellApiServer::set_balance(&handler, addr, "0x1".into())
            .await
            .unwrap_err();

        assert_eq!(err.code(), -32002);
        assert!(err.message().contains("dev mode"));
    }

    #[tokio::test]
    async fn set_balance_accepts_canonical_hex_quantity() {
        let handler = setup().with_dev_control(Arc::new(MockDevControl::default()));
        let addr = test_address(b"set-balance-canonical");

        assert!(ShellApiServer::set_balance(&handler, addr, "0x2a".into())
            .await
            .unwrap());

        let balance = handler.world_state.read().get_balance(&addr).unwrap();
        assert_eq!(balance, U256::from(42u64));
    }

    #[tokio::test]
    async fn set_balance_rejects_non_canonical_quantities() {
        let handler = setup().with_dev_control(Arc::new(MockDevControl::default()));
        let addr = test_address(b"set-balance-invalid");

        for value in ["42", "0x", "0x00", "0x01", "0xgg"] {
            let err = ShellApiServer::set_balance(&handler, addr, value.into())
                .await
                .unwrap_err();
            assert_eq!(err.code(), -32602, "setBalance should reject {value}");
        }
    }

    #[tokio::test]
    async fn chain_id() {
        let handler = setup();
        let result = EthApiServer::chain_id(&handler).await.unwrap();
        assert_eq!(result, "0x2a"); // 42
    }

    #[tokio::test]
    async fn rpc_capabilities_exposes_v2_methods() {
        let handler = setup();
        let result = ShellApiServer::rpc_capabilities(&handler).await.unwrap();
        assert!(result.supports_cursor_pagination);
        assert!(result
            .methods
            .contains(&"shell_getTransactionsByAddressV2".to_string()));
        assert_eq!(result.max_page_size, 100);
    }

    #[tokio::test]
    async fn chain_snapshot_empty_chain_is_compact() {
        let handler = setup();
        let result = ShellApiServer::get_chain_snapshot(&handler, None)
            .await
            .unwrap();
        assert_eq!(result.chain_id, "0x2a");
        assert!(result.head.is_none());
        assert_eq!(result.pending_transactions, "0x0");
        assert_eq!(result.finality_lag, 0);
    }

    #[tokio::test]
    async fn transaction_summary_not_found_is_null_shaped() {
        let handler = setup();
        let result =
            ShellApiServer::get_transaction_summary(&handler, ShellHash::from([0x77; 32]), None)
                .await
                .unwrap();
        assert!(result.transaction.is_none());
        assert!(result.receipt.is_none());
        assert!(result.status.is_none());
    }

    #[tokio::test]
    async fn validator_snapshot_rejects_zero_proposer_window_as_invalid_params() {
        let handler = setup();
        let err = ShellApiServer::get_validator_snapshot(
            &handler,
            Some(RpcValidatorSnapshotOptions {
                proposer_window: Some(0),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at least 1"));
    }

    #[tokio::test]
    async fn validator_snapshot_caps_oversized_proposer_window() {
        let handler = setup();
        let result = ShellApiServer::get_validator_snapshot(
            &handler,
            Some(RpcValidatorSnapshotOptions {
                proposer_window: Some(1001),
            }),
        )
        .await
        .unwrap();

        assert_eq!(result.proposer_window, 1000);
    }

    #[tokio::test]
    async fn get_transactions_by_address_total_counts_all_matches() {
        let handler = setup();
        let sender = DilithiumSigner::generate();
        let from = signer_address(&sender);
        let to = Address::from([0x44; 20]);

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&from, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler
            .chain_store
            .put_pubkey(&from, sender.public_key())
            .unwrap();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler
            .chain_store
            .set_canonical(genesis.number(), &genesis_hash)
            .unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let tx1 = SignedTransaction::new(
            from,
            Transaction {
                chain_id: 42,
                nonce: 0,
                max_priority_fee_per_gas: 100_000_000,
                max_fee_per_gas: 1_000_000_000,
                gas_limit: 21_000,
                to: Some(to),
                value: U256::from(1u64),
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            sender.sign(b"tx-1").unwrap(),
        );
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
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-1"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![tx1],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block1_hash = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &block1_hash).unwrap();
        handler.chain_store.set_head(&block1_hash).unwrap();

        let tx2 = SignedTransaction::new(
            from,
            Transaction {
                chain_id: 42,
                nonce: 1,
                max_priority_fee_per_gas: 100_000_000,
                max_fee_per_gas: 1_000_000_000,
                gas_limit: 21_000,
                to: Some(to),
                value: U256::from(2u64),
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            sender.sign(b"tx-2").unwrap(),
        );
        let block2 = Block {
            header: BlockHeader {
                parent_hash: block1_hash,
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 2,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_002,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-2"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![tx2],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block2_hash = block2.hash();
        handler.chain_store.put_block(&block2).unwrap();
        handler.chain_store.set_canonical(2, &block2_hash).unwrap();
        handler.chain_store.set_head(&block2_hash).unwrap();

        let result = ShellApiServer::get_transactions_by_address(
            &handler,
            from,
            Some(0),
            Some(2),
            Some(0),
            Some(1),
        )
        .await
        .unwrap();

        assert_eq!(result["total"], 2);
        assert_eq!(result["transactions"].as_array().unwrap().len(), 1);
        assert_eq!(result["transactions"][0]["blockNumber"], "0x2");

        let v2 = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(2),
                limit: Some(1),
                include_total: Some(true),
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(v2.total, Some(2));
        assert!(v2.has_more);
        assert!(v2.next_cursor.is_some());
        assert_eq!(v2.items.len(), 1);
        assert_eq!(v2.items[0]["blockNumber"], "0x2");
        assert!(v2.items[0].get("input").is_none());
        assert!(v2.items[0].get("signature").is_none());

        let second_page = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(2),
                cursor: v2.next_cursor.clone(),
                limit: Some(1),
                include_total: Some(false),
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(second_page.total, None);
        assert!(!second_page.has_more);
        assert_eq!(second_page.next_cursor, None);
        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0]["blockNumber"], "0x1");

        let asc = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(2),
                limit: Some(1),
                direction: RpcListDirection::Asc,
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap();
        assert!(asc.has_more);
        assert!(asc.next_cursor.is_some());
        assert_eq!(asc.items.len(), 1);
        assert_eq!(asc.items[0]["blockNumber"], "0x1");

        let asc_second_page = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(2),
                cursor: asc.next_cursor,
                limit: Some(1),
                direction: RpcListDirection::Asc,
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap();
        assert!(!asc_second_page.has_more);
        assert_eq!(asc_second_page.next_cursor, None);
        assert_eq!(asc_second_page.items.len(), 1);
        assert_eq!(asc_second_page.items[0]["blockNumber"], "0x2");
    }

    #[tokio::test]
    async fn get_transactions_by_address_rejects_deep_legacy_offset() {
        let handler = setup();
        let address = test_address(b"legacy-deep-offset");

        let err = ShellApiServer::get_transactions_by_address(
            &handler,
            address,
            Some(0),
            Some(10),
            Some(101),
            Some(100),
        )
        .await
        .unwrap_err();

        assert!(
            err.message()
                .contains("legacy address transaction pagination offset"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_transactions_by_address_v2_rejects_wide_exact_total() {
        let handler = setup();
        let address = test_address(b"v2-wide-total");

        let err = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            address,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(10_001),
                include_total: Some(true),
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap_err();

        assert!(
            err.message().contains("exact address transaction totals"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_transactions_by_address_v2_rejects_invalid_cursor_as_invalid_params() {
        let handler = setup();
        let address = test_address(b"v2-bad-cursor");

        for cursor in ["0xzz", "0x0102"] {
            let err = ShellApiServer::get_transactions_by_address_v2(
                &handler,
                address,
                Some(RpcAddressTransactionsV2Options {
                    cursor: Some(cursor.into()),
                    ..RpcAddressTransactionsV2Options::default()
                }),
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), -32602);
        }
    }

    #[tokio::test]
    async fn get_transactions_by_address_v2_rejects_out_of_range_cursor_as_invalid_params() {
        let handler = setup();
        let from = test_address(b"v2-cursor-range-from");
        let to = Address::from([0x42; 20]);
        let signer = shell_crypto::DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler
            .chain_store
            .set_canonical(genesis.number(), &genesis_hash)
            .unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let tx = SignedTransaction::with_pubkey(
            from,
            Transaction {
                chain_id: 1,
                nonce: 0,
                to: Some(to),
                value: U256::from(1u64),
                data: Bytes::default(),
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            signer.sign(b"v2-cursor-range").unwrap(),
            pubkey,
        );
        let block = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: test_address(b"v2-cursor-range-proposer"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![tx],
            system_transactions: vec![],
            proposer_seal: None,
        };
        handler
            .chain_store
            .commit_canonical_block(&block, None)
            .unwrap();

        let first_page = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(0),
                to_block: Some(1),
                limit: Some(1),
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap();
        let cursor = first_page.items[0]["cursor"].as_str().unwrap().to_string();

        let err = ShellApiServer::get_transactions_by_address_v2(
            &handler,
            from,
            Some(RpcAddressTransactionsV2Options {
                from_block: Some(2),
                to_block: Some(3),
                cursor: Some(cursor),
                limit: Some(1),
                ..RpcAddressTransactionsV2Options::default()
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("outside requested block range"));
    }

    #[tokio::test]
    async fn blocks_range_clamps_limits_and_supports_direction() {
        let handler = setup();
        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler
            .chain_store
            .set_canonical(genesis.number(), &genesis_hash)
            .unwrap();

        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: test_address(b"proposer-range"),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block1_hash = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &block1_hash).unwrap();
        handler.chain_store.set_head(&block1_hash).unwrap();

        let desc = ShellApiServer::get_blocks_range(
            &handler,
            "latest".into(),
            Some(RpcBlocksRangeOptions {
                direction: RpcListDirection::Desc,
                limit: Some(250),
                tx_detail: RpcV2TxDetail::None,
                tx_limit: Some(250),
            }),
        )
        .await
        .unwrap();
        assert_eq!(desc.limit, 100);
        assert_eq!(desc.blocks.len(), 2);
        assert_eq!(desc.blocks[0].number, "0x1");
        assert_eq!(desc.blocks[1].number, "0x0");
        assert_eq!(desc.next_start, None);
        assert!(desc.blocks[0].transactions.as_array().unwrap().is_empty());

        let genesis_only = ShellApiServer::get_blocks_range(
            &handler,
            "0x0".into(),
            Some(RpcBlocksRangeOptions {
                direction: RpcListDirection::Desc,
                limit: Some(1),
                tx_detail: RpcV2TxDetail::None,
                tx_limit: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(genesis_only.blocks.len(), 1);
        assert_eq!(genesis_only.blocks[0].number, "0x0");
        assert_eq!(genesis_only.next_start, None);

        let asc = ShellApiServer::get_blocks_range(
            &handler,
            "0x0".into(),
            Some(RpcBlocksRangeOptions {
                direction: RpcListDirection::Asc,
                limit: Some(2),
                tx_detail: RpcV2TxDetail::Summary,
                tx_limit: Some(1),
            }),
        )
        .await
        .unwrap();
        assert_eq!(asc.blocks[0].number, "0x0");
        assert_eq!(asc.blocks[1].number, "0x1");
        assert_eq!(asc.next_start, None);
    }

    #[tokio::test]
    async fn blocks_range_finality_tags_start_at_finalized_block() {
        let handler = setup();
        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();

        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                number: 1,
                ..make_genesis_block().header
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block1_hash = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &block1_hash).unwrap();
        handler.chain_store.set_head(&block1_hash).unwrap();
        *handler.finalized_number.write() = 0;

        for tag in ["safe", "finalized"] {
            let page = ShellApiServer::get_blocks_range(
                &handler,
                tag.into(),
                Some(RpcBlocksRangeOptions {
                    direction: RpcListDirection::Desc,
                    limit: Some(10),
                    tx_detail: RpcV2TxDetail::Summary,
                    tx_limit: None,
                }),
            )
            .await
            .unwrap();

            assert_eq!(page.start, tag);
            assert_eq!(page.blocks.len(), 1);
            assert_eq!(page.blocks[0].number, "0x0");
            assert_eq!(page.next_start, None);
        }
    }

    #[tokio::test]
    async fn blocks_range_ascending_stops_at_max_height() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.number = u64::MAX;
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler
            .chain_store
            .set_canonical(u64::MAX, &block_hash)
            .unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

        let page = ShellApiServer::get_blocks_range(
            &handler,
            format!("0x{:x}", u64::MAX),
            Some(RpcBlocksRangeOptions {
                direction: RpcListDirection::Asc,
                limit: Some(1),
                tx_detail: RpcV2TxDetail::Summary,
                tx_limit: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(page.blocks.len(), 1);
        assert_eq!(page.blocks[0].number, format!("0x{:x}", u64::MAX));
        assert_eq!(page.next_start, None);
    }

    #[tokio::test]
    async fn get_transactions_by_address_returns_system_rewards_with_type() {
        let handler = setup();
        let reward_to = test_address(b"address-history-reward");
        let mut block = make_genesis_block();
        block.header.proposer = reward_to;
        let block_hash = block.hash();
        let reward = SystemTransaction::block_gas_reward(
            42,
            block.number(),
            0,
            reward_to,
            U256::from(10u64),
            block.header.parent_hash,
        );

        handler.chain_store.put_block(&block).unwrap();
        handler
            .chain_store
            .set_canonical(block.number(), &block_hash)
            .unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();
        handler
            .chain_store
            .put_system_transactions(&block_hash, block.number(), std::slice::from_ref(&reward))
            .unwrap();

        let result = ShellApiServer::get_transactions_by_address(
            &handler,
            reward_to,
            None,
            None,
            Some(0),
            Some(50),
        )
        .await
        .unwrap();

        assert_eq!(result["total"], 1);
        assert_eq!(
            result["transactions"][0]["hash"],
            serde_json::json!(reward.hash())
        );
        assert_eq!(result["transactions"][0]["type"], "0x80");
        assert_eq!(result["transactions"][0]["shellType"], "blockGasReward");
        assert_eq!(result["transactions"][0]["rewardKind"], "blockGasReward");
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
    async fn block_by_number_finality_tags_resolve_finalized_block() {
        let handler = setup();
        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                number: 1,
                ..make_genesis_block().header
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block1_hash = block1.hash();

        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &block1_hash).unwrap();
        handler.chain_store.set_head(&block1_hash).unwrap();
        *handler.finalized_number.write() = 0;

        for tag in ["safe", "finalized"] {
            let eth_block = EthApiServer::get_block_by_number(&handler, tag.into(), false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(eth_block.number, "0x0");

            let shell_block = ShellApiServer::shell_get_block_by_number(
                &handler,
                tag.into(),
                Some("summary".into()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(shell_block.number, "0x0");
        }
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
    async fn get_balance_rejects_historical_state_block() {
        let handler = setup();
        let addr = test_address(b"test-address-key");
        let err = EthApiServer::get_balance(&handler, addr, Some("0x0".into()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("historical state queries"));
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
    async fn get_transaction_count_pending_includes_contiguous_mempool_nonces() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);

        {
            let mut ws = handler.world_state.write();
            let mut account = shell_core::Account::new_user_account(
                ShellHash::ZERO,
                U256::from(100_000_000_000_000u64),
            );
            account.nonce = 5;
            ws.set_account(&addr, &account).unwrap();
        }
        handler.chain_store.put_pubkey(&addr, &pubkey).unwrap();

        let make_tx = |nonce| {
            let tx = Transaction {
                chain_id: 42,
                nonce,
                to: Some(test_address(b"pending-nonce-recipient")),
                value: U256::ZERO,
                data: Bytes::default(),
                gas_limit: 21_000,
                max_fee_per_gas: 1_000_000,
                max_priority_fee_per_gas: 1,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let sig = signer.sign(tx.hash().0.as_slice()).unwrap();
            SignedTransaction::new(addr, tx, sig)
        };

        {
            let mut ws = handler.world_state.write();
            handler
                .tx_pool
                .insert(
                    make_tx(5),
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
            handler
                .tx_pool
                .insert(
                    make_tx(6),
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
        }

        let latest = EthApiServer::get_transaction_count(&handler, addr, Some("latest".into()))
            .await
            .unwrap();
        let pending = EthApiServer::get_transaction_count(&handler, addr, Some("pending".into()))
            .await
            .unwrap();

        assert_eq!(latest, "0x5");
        assert_eq!(pending, "0x7");
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
    async fn fee_history_returns_zero_priority_rewards_when_requested() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.base_fee_per_gas = 1_000_000_000;
        block.header.number = 0;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = EthApiServer::fee_history(
            &handler,
            "0x1".into(),
            "latest".into(),
            Some(vec![25.0, 75.0]),
        )
        .await
        .unwrap();

        assert_eq!(result["reward"], serde_json::json!([["0x0", "0x0"]]));
    }

    #[tokio::test]
    async fn fee_history_empty_reward_percentiles_keeps_empty_reward() {
        let handler = setup();
        let result =
            EthApiServer::fee_history(&handler, "0x1".into(), "latest".into(), Some(Vec::new()))
                .await
                .unwrap();

        assert_eq!(result["reward"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn fee_history_rejects_zero_block_count_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::fee_history(&handler, "0x0".into(), "latest".into(), None)
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at least 1"));
    }

    #[tokio::test]
    async fn fee_history_rejects_oversized_block_count_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::fee_history(&handler, "0x401".into(), "latest".into(), None)
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at most 1024"));
    }

    #[tokio::test]
    async fn fee_history_rejects_invalid_reward_percentiles_as_invalid_params() {
        let handler = setup();

        for percentiles in [vec![-1.0], vec![101.0], vec![90.0, 50.0], vec![f64::NAN]] {
            let err = EthApiServer::fee_history(
                &handler,
                "0x1".into(),
                "latest".into(),
                Some(percentiles),
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        }
    }

    #[tokio::test]
    async fn fee_history_rejects_too_many_reward_percentiles() {
        let handler = setup();
        let percentiles = (0..101).map(|value| value as f64).collect();

        let err =
            EthApiServer::fee_history(&handler, "0x1".into(), "latest".into(), Some(percentiles))
                .await
                .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at most 100 entries"));
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

    fn setup_with_proof_amendment() -> RpcHandler<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(parking_lot::RwLock::new(WorldState::new(db.clone())));
        let proof_store = Arc::new(ProofAmendmentStore::new(db));
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
        .with_proof_amendment_store(proof_store)
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
    async fn witness_queries_resolve_finality_tags_to_finalized_block() {
        let handler = setup_with_witness();
        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();

        let block1 = Block {
            header: BlockHeader {
                parent_hash: genesis_hash,
                number: 1,
                ..make_genesis_block().header
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block1_hash = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler.chain_store.set_canonical(1, &block1_hash).unwrap();
        handler.chain_store.set_head(&block1_hash).unwrap();
        *handler.finalized_number.write() = 0;

        let latest = ShellApiServer::get_block_witnesses(&handler, "latest".to_string())
            .await
            .unwrap();
        assert_eq!(
            latest["blockHash"],
            serde_json::to_value(block1_hash).unwrap()
        );

        for tag in ["safe", "finalized"] {
            let result = ShellApiServer::get_block_witnesses(&handler, tag.to_string())
                .await
                .unwrap();
            assert_eq!(
                result["blockHash"],
                serde_json::to_value(genesis_hash).unwrap()
            );
            assert_eq!(result["witnessCount"], 0);
        }
    }

    #[tokio::test]
    async fn shell_get_block_summary_includes_stark_metadata_without_proof_bytes() {
        let handler = setup_with_proof_amendment();
        let block = make_genesis_block();
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

        let amendment = shell_stark_prover::ProofAmendment {
            version: shell_stark_prover::PROOF_AMENDMENT_VERSION,
            block_hash,
            block_number: 0,
            start_block: Some(0),
            proof: shell_stark_prover::SigBatchProof {
                version: shell_stark_prover::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [7; 32],
                n_sigs: 1,
                proof_bytes: vec![1, 2, 3, 4, 5],
            },
            prover: test_address(b"summary-prover"),
            prover_signature: Bytes::from_static(b"sig"),
            layer: 2,
            source_hashes: vec![block_hash],
            original_size: Some(100),
            compressed_size: Some(5),
            settlement_tx_hash: None,
        };
        handler
            .proof_amendment_store
            .as_ref()
            .unwrap()
            .put_amendment(&block_hash, &amendment.to_json().unwrap())
            .unwrap();

        let rpc = ShellApiServer::shell_get_block_by_number(
            &handler,
            "0x0".into(),
            Some("summary".into()),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(rpc.compression_layer, 2);
        assert_eq!(rpc.pruning_status, "pruned");
        assert_eq!(rpc.sig_aggregate_proof_size, Some(5));
        assert!(rpc.sig_aggregate_proof.is_none());
    }

    #[tokio::test]
    async fn shell_get_proof_amendment_exposes_stark_proof_stats() {
        let handler = setup_with_proof_amendment();
        let block = make_genesis_block();
        let block_hash = block.hash();
        let amendment = shell_stark_prover::ProofAmendment {
            version: shell_stark_prover::PROOF_AMENDMENT_VERSION,
            block_hash,
            block_number: 0,
            start_block: Some(0),
            proof: shell_stark_prover::SigBatchProof {
                version: shell_stark_prover::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [7; 32],
                n_sigs: 512,
                proof_bytes: vec![1, 2, 3, 4, 5],
            },
            prover: test_address(b"proof-stats-prover"),
            prover_signature: Bytes::from_static(b"sig"),
            layer: 1,
            source_hashes: vec![block_hash],
            original_size: Some(100),
            compressed_size: Some(5),
            settlement_tx_hash: None,
        };
        handler
            .proof_amendment_store
            .as_ref()
            .unwrap()
            .put_amendment(&block_hash, &amendment.to_json().unwrap())
            .unwrap();

        let rpc = ShellApiServer::get_proof_amendment(&handler, block_hash.to_string())
            .await
            .unwrap();

        assert_eq!(rpc["source_count"], 1);
        assert_eq!(rpc["layer"], 1);
        assert_eq!(rpc["proof_entries"], 512);
        assert_eq!(rpc["original_size"], 100);
        assert_eq!(rpc["compressed_size"], 5);
        assert_eq!(rpc["proof"], "0x0102030405");
    }

    #[tokio::test]
    async fn shell_get_block_summary_places_reward_txs_first_with_distinct_types() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let from = signer_address(&signer);
        let to = test_address(b"reward-order-to");
        let user_tx = SignedTransaction::new(
            from,
            Transaction {
                chain_id: 42,
                nonce: 0,
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 1_000_000_000,
                gas_limit: 21_000,
                to: Some(to),
                value: U256::from(7u64),
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            signer.sign(b"reward-order-user-tx").unwrap(),
        );
        let mut block = make_genesis_block();
        block.transactions = vec![user_tx.clone()];
        let block_hash = block.hash();
        let block_reward = SystemTransaction::block_gas_reward(
            42,
            block.number(),
            block.transactions.len() as u32,
            block.header.proposer,
            U256::from(10u64),
            block.header.parent_hash,
        );
        let stark_reward = SystemTransaction::stark_reward(shell_core::StarkRewardParams {
            chain_id: 42,
            block_number: block.number(),
            tx_index: block.transactions.len() as u32 + 1,
            recipient: test_address(b"stark-reward-to"),
            value: U256::from(20u64),
            source_hash: ShellHash::from([0x44; 32]),
            layer: 1,
            original_size: 100,
            compressed_size: 40,
            proof_payload: Bytes::from_static(b"proof"),
        });

        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();
        handler
            .chain_store
            .put_system_transactions(
                &block_hash,
                block.number(),
                &[stark_reward.clone(), block_reward.clone()],
            )
            .unwrap();

        let rpc = ShellApiServer::shell_get_block_by_number(
            &handler,
            "0x0".into(),
            Some("summary".into()),
        )
        .await
        .unwrap()
        .unwrap();
        let txs = rpc.transactions.as_array().unwrap();

        assert_eq!(txs[0]["hash"], serde_json::json!(block_reward.hash()));
        assert_eq!(txs[0]["type"], "0x80");
        assert_eq!(txs[0]["rewardKind"], "blockGasReward");
        assert_eq!(txs[1]["hash"], serde_json::json!(stark_reward.hash()));
        assert_eq!(txs[1]["type"], "0x81");
        assert_eq!(txs[1]["rewardKind"], "starkReward");
        assert_eq!(txs[2]["hash"], serde_json::json!(user_tx.hash()));
    }

    #[tokio::test]
    async fn shell_get_witness_returns_null_without_store() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let result = ShellApiServer::get_witness(&handler, "latest".to_string())
            .await
            .unwrap();
        assert!(result.is_null());
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
    async fn shell_get_witness_returns_sdk_shape() {
        use shell_core::{TxWitness, WitnessBundle};

        let handler = setup_with_witness();
        let block = make_genesis_block();
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

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

        let result = ShellApiServer::get_witness(&handler, "latest".to_string())
            .await
            .unwrap();

        assert_eq!(
            result["block_hash"],
            format!("0x{}", hex::encode(block_hash.as_bytes()))
        );
        assert_eq!(result["block_number"], 0);
        assert_eq!(result["witness_count"], 1);
        // OPS-2: enriched fields
        assert!(result["state_root"].as_str().unwrap().starts_with("0x"));
        assert!(result["timestamp"].is_u64());
        // genesis block has no witness_root → verified is null
        assert!(result["witness_root_verified"].is_null());
        let witnesses = result["witnesses"].as_array().unwrap();
        assert_eq!(witnesses[0]["tx_index"], 0);
        assert_eq!(witnesses[0]["sig_type"], "Dilithium3");
        assert!(witnesses[0]["signature"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert!(witnesses[0]["public_key"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
    }

    #[tokio::test]
    async fn get_block_witnesses_includes_root_verified_flag() {
        use shell_core::{TxWitness, WitnessBundle};

        let handler = setup_with_witness();
        let block = make_genesis_block();
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

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

        let result = ShellApiServer::get_block_witnesses(&handler, "latest".to_string())
            .await
            .unwrap();

        // genesis block carries no witness_root → verified is null
        assert!(result["witnessRootVerified"].is_null());
        assert_eq!(result["witnessCount"], 1);
    }

    // ── shell_verifyWitnessRoot ────────────────────────────────────

    #[tokio::test]
    async fn verify_witness_root_block_not_found() {
        let handler = setup_with_witness();
        let fake = format!("0x{}", "aa".repeat(32));
        let res = ShellApiServer::verify_witness_root(&handler, fake)
            .await
            .unwrap();
        assert!(res["verified"].is_null());
        assert!(res["reason"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn verify_witness_root_no_witness_root_in_header() {
        let handler = setup_with_witness();
        let block = make_genesis_block(); // genesis has no witness_root
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let res = ShellApiServer::verify_witness_root(&handler, "latest".to_string())
            .await
            .unwrap();
        assert!(res["verified"].is_null());
        assert!(res["reason"].as_str().unwrap().contains("no witness_root"));
    }

    #[tokio::test]
    async fn verify_witness_root_no_bundle_stored() {
        use shell_primitives::ShellHash;
        // Manufacture a block header with a witness_root set but no bundle stored.
        let handler = setup_with_witness();
        let mut block = make_genesis_block();
        block.header.witness_root = Some(ShellHash::from([0xab; 32]));
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let res = ShellApiServer::verify_witness_root(&handler, "latest".to_string())
            .await
            .unwrap();
        assert!(res["verified"].is_null());
        assert!(res["reason"].as_str().unwrap().contains("not stored"));
    }

    #[tokio::test]
    async fn verify_witness_root_match_and_mismatch() {
        use shell_core::{TxWitness, WitnessBundle};
        use shell_primitives::ShellHash;

        let handler = setup_with_witness();
        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"tx0").unwrap();
        let bundle = WitnessBundle::new(vec![TxWitness::new_embedded(sig, pk)]);
        let correct_root = bundle.compute_root();

        // --- match case: header.witness_root == bundle.compute_root() ---
        let mut block_match = make_genesis_block();
        block_match.header.witness_root = Some(correct_root);
        let hash_match = block_match.hash();
        handler.chain_store.put_block(&block_match).unwrap();
        handler.chain_store.set_canonical(0, &hash_match).unwrap();
        handler.chain_store.set_head(&hash_match).unwrap();
        handler
            .witness_store
            .as_ref()
            .unwrap()
            .put_bundle(&hash_match, &bundle)
            .unwrap();

        let res = ShellApiServer::verify_witness_root(&handler, "latest".to_string())
            .await
            .unwrap();
        assert_eq!(res["verified"], true);
        assert_eq!(
            res["expectedRoot"],
            serde_json::to_value(correct_root).unwrap()
        );

        // --- mismatch case: wrong root in header ---
        let wrong_root = ShellHash::from([0xff; 32]);
        let mut block_bad = make_genesis_block();
        block_bad.header.witness_root = Some(wrong_root);
        block_bad.header.number = 1; // different block so different hash
        let hash_bad = block_bad.hash();
        handler.chain_store.put_block(&block_bad).unwrap();
        handler.chain_store.set_canonical(1, &hash_bad).unwrap();
        handler.chain_store.set_head(&hash_bad).unwrap();

        let signer2 = DilithiumSigner::generate();
        let pk2 = signer2.public_key().to_vec();
        let sig2 = signer2.sign(b"tx0").unwrap();
        let bundle2 = WitnessBundle::new(vec![TxWitness::new_embedded(sig2, pk2)]);
        handler
            .witness_store
            .as_ref()
            .unwrap()
            .put_bundle(&hash_bad, &bundle2)
            .unwrap();

        let res2 = ShellApiServer::verify_witness_root(&handler, "latest".to_string())
            .await
            .unwrap();
        assert_eq!(res2["verified"], false);
        assert_eq!(
            res2["expectedRoot"],
            serde_json::to_value(wrong_root).unwrap()
        );
    }

    #[tokio::test]
    async fn shell_get_block_witnesses_null_for_unknown_hash() {
        let handler = setup_with_witness();
        let fake_hash = format!("0x{}", "ab".repeat(32));
        let result = ShellApiServer::get_block_witnesses(&handler, fake_hash)
            .await
            .unwrap();
        assert_eq!(result, serde_json::Value::Null);
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
        let gas_limit = shell_pqvm::compute_intrinsic_gas(&[], true, &None);

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
        let gas_limit = shell_pqvm::compute_intrinsic_gas(&[], true, &None);

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
        let result = EthApiServer::send_raw_transaction(&handler, "0xnot-hex".into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_raw_transaction_rejects_unprefixed_data_as_invalid_params() {
        let handler = setup();

        let err = EthApiServer::send_raw_transaction(&handler, "00".into())
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[tokio::test]
    async fn send_raw_transaction_rejects_oversized_payload_before_decode() {
        let handler = setup();
        let oversized = format!("0x{}", "00".repeat(shell_mempool::MAX_TX_SIZE + 1));
        let result = EthApiServer::send_raw_transaction(&handler, oversized).await;
        let err = result.unwrap_err();
        assert!(err.message().contains("maximum size"));
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

    #[tokio::test]
    async fn eth_call_rejects_invalid_data_hex_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::call(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some("0xzz".into()),
                value: None,
                gas: None,
                access_list: None,
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid call data hex"));
    }

    #[tokio::test]
    async fn eth_call_rejects_unprefixed_data_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::call(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some("00".into()),
                value: None,
                gas: None,
                access_list: None,
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[tokio::test]
    async fn eth_call_rejects_oversized_data_as_invalid_params() {
        let handler = setup();
        let oversized = format!("0x{}", "00".repeat(shell_mempool::MAX_TX_SIZE + 1));
        let err = EthApiServer::call(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some(oversized),
                value: None,
                gas: None,
                access_list: None,
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("maximum size"));
        assert!(
            !err.message().contains(&"00".repeat(128)),
            "error should not reflect large call data"
        );
    }

    #[tokio::test]
    async fn eth_call_rejects_unprefixed_access_list_storage_key_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::call(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: None,
                value: None,
                gas: None,
                access_list: Some(vec![crate::types::RpcAccessListItem {
                    address: Address::ZERO,
                    storage_keys: vec!["00".repeat(32)],
                }]),
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[tokio::test]
    async fn eth_call_rejects_oversized_access_list_as_invalid_params() {
        let handler = setup();
        let access_list = (0..=shell_core::MAX_ACCESS_LIST_ENTRIES)
            .map(|_| crate::types::RpcAccessListItem {
                address: Address::ZERO,
                storage_keys: vec![],
            })
            .collect();
        let err = EthApiServer::call(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: None,
                value: None,
                gas: None,
                access_list: Some(access_list),
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("access list"));
        assert!(err.message().contains("at most"));
    }

    #[tokio::test]
    async fn eth_estimate_gas_rejects_invalid_data_hex_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::estimate_gas(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some("0xzz".into()),
                value: None,
                gas: None,
                access_list: None,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid call data hex"));
    }

    #[tokio::test]
    async fn eth_estimate_gas_rejects_unprefixed_data_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::estimate_gas(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some("00".into()),
                value: None,
                gas: None,
                access_list: None,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[tokio::test]
    async fn eth_estimate_gas_rejects_oversized_data_as_invalid_params() {
        let handler = setup();
        let oversized = format!("0x{}", "00".repeat(shell_mempool::MAX_TX_SIZE + 1));
        let err = EthApiServer::estimate_gas(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: Some(oversized),
                value: None,
                gas: None,
                access_list: None,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("maximum size"));
        assert!(
            !err.message().contains(&"00".repeat(128)),
            "error should not reflect large call data"
        );
    }

    #[tokio::test]
    async fn eth_estimate_gas_rejects_unprefixed_access_list_storage_key_as_invalid_params() {
        let handler = setup();
        let err = EthApiServer::estimate_gas(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: None,
                value: None,
                gas: None,
                access_list: Some(vec![crate::types::RpcAccessListItem {
                    address: Address::ZERO,
                    storage_keys: vec!["00".repeat(32)],
                }]),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[tokio::test]
    async fn eth_estimate_gas_rejects_oversized_access_list_storage_keys_as_invalid_params() {
        let handler = setup();
        let storage_keys =
            vec![format!("0x{}", "11".repeat(32)); shell_core::MAX_ACCESS_LIST_STORAGE_KEYS + 1];
        let err = EthApiServer::estimate_gas(
            &handler,
            crate::types::CallRequest {
                from: None,
                to: None,
                data: None,
                value: None,
                gas: None,
                access_list: Some(vec![crate::types::RpcAccessListItem {
                    address: Address::ZERO,
                    storage_keys,
                }]),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("storage keys"));
        assert!(err.message().contains("at most"));
    }

    // ── eth_getLogs tests ────────────────────────────────────────

    /// Helper: store a block with receipts that contain logs and return the block hash.
    fn store_block_with_logs(
        handler: &RpcHandler<MemoryDb>,
        number: u64,
        logs_per_receipt: Vec<Vec<shell_core::Log>>,
    ) -> ShellHash {
        let bloom = shell_pqvm::bloom::logs_bloom(
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
            system_transactions: vec![],
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
                let receipt_bloom = shell_pqvm::bloom::logs_bloom(&logs);
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
    async fn get_logs_rejects_invalid_block_tag_as_invalid_params() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"not-a-block","toBlock":"0x1"}"#).unwrap();

        let err = EthApiServer::get_logs(&handler, raw).await.unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("fromBlock"));
    }

    #[tokio::test]
    async fn get_logs_rejects_noncanonical_block_quantity_as_invalid_params() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x01","toBlock":"0x1"}"#).unwrap();

        let err = EthApiServer::get_logs(&handler, raw).await.unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("fromBlock"));
    }

    #[tokio::test]
    async fn get_logs_rejects_oversized_block_quantity_as_invalid_params() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x10000000000000000","toBlock":"0x1"}"#).unwrap();

        let err = EthApiServer::get_logs(&handler, raw).await.unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("fromBlock"));
        assert!(err.message().contains("too long"));
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
    async fn get_logs_empty_address_array_returns_empty() {
        let handler = setup();
        let log = shell_core::Log::new(Address::from([0xAA; 20]), vec![], Bytes::new()).unwrap();
        store_block_with_logs(&handler, 0, vec![vec![log]]);

        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x0","toBlock":"0x0","address":[]}"#).unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert!(result.is_empty());
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
    async fn get_logs_empty_topic_alternative_array_returns_empty() {
        let handler = setup();
        let topic = ShellHash::from_slice(&[0x11; 32]);
        let log =
            shell_core::Log::new(Address::from([0x01; 20]), vec![topic], Bytes::new()).unwrap();

        store_block_with_logs(&handler, 0, vec![vec![log]]);

        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x0","toBlock":"0x0","topics":[[]]}"#).unwrap();

        let result = EthApiServer::get_logs(&handler, raw).await.unwrap();
        assert!(result.is_empty());
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
    async fn get_logs_rejects_too_many_matching_logs() {
        let handler = setup();
        let logs = (0..MAX_LOG_RESULTS + 1)
            .map(|_| shell_core::Log::new(Address::from([0xAA; 20]), vec![], Bytes::new()).unwrap())
            .collect();
        store_block_with_logs(&handler, 0, vec![logs]);

        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x0","toBlock":"0x0"}"#).unwrap();

        let err = EthApiServer::get_logs(&handler, raw).await.unwrap_err();

        assert!(err.message().contains("more than 10000 logs"));
    }

    #[tokio::test]
    async fn get_logs_max_range_too_large_returns_error_without_overflow() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter = serde_json::from_str(&format!(
            r#"{{"fromBlock":"0x0","toBlock":"0x{:x}"}}"#,
            u64::MAX
        ))
        .unwrap();

        let err = EthApiServer::get_logs(&handler, raw).await.unwrap_err();

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
        handler
            .world_state
            .write()
            .add_balance(&addr, U256::from(1_000_000_000_000_000_000u64))
            .unwrap();

        (handler, signer, addr)
    }

    #[tokio::test]
    async fn propose_add_validator_no_signer_returns_error() {
        let handler = setup();
        let target = Address::from([0xAB; 20]).to_string();
        let err = ShellApiServer::propose_add_validator(&handler, target)
            .await
            .unwrap_err();
        assert!(err.message().contains("not configured as a validator"));
    }

    #[tokio::test]
    async fn propose_remove_validator_no_signer_returns_error() {
        let handler = setup();
        let target = Address::from([0xAB; 20]).to_string();
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
        let expected_calldata = shell_pqvm::encode_add_validator_calldata(&target_addr);
        let pending = handler.tx_pool.pending(100);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx.data.as_ref(), expected_calldata.as_slice());
        assert_eq!(pending[0].tx.to, Some(shell_pqvm::registry_address()));
        assert_eq!(pending[0].tx.value, U256::ZERO);
        assert_eq!(pending[0].tx.chain_id, 42);
        assert_eq!(pending[0].tx.nonce, 0);
        assert_eq!(pending[0].tx.max_fee_per_gas, INITIAL_BASE_FEE);
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
        let expected_calldata = shell_pqvm::encode_remove_validator_calldata(&target_addr);
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
        let target = Address::from([0xAB; 20]).to_string();
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
        assert_eq!(result, format!("shell-chain/{}", env!("CARGO_PKG_VERSION")));
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

    #[tokio::test]
    async fn web3_sha3_rejects_unprefixed_data_as_invalid_params() {
        let handler = setup();

        let err = Web3ApiServer::sha3(&handler, hex::encode(b"hello"))
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
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
        let hex_addr = target.to_string();

        let result = ShellApiServer::encode_add_validator(&handler, hex_addr)
            .await
            .unwrap();

        let expected = shell_pqvm::encode_add_validator_calldata(&target);
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
        let hex_addr = target.to_string();

        let result = ShellApiServer::encode_remove_validator(&handler, hex_addr)
            .await
            .unwrap();

        let expected = shell_pqvm::encode_remove_validator_calldata(&target);
        assert_eq!(result, format!("0x{}", hex::encode(expected)));
        assert_eq!(result.len(), 74);
    }

    #[tokio::test]
    async fn get_governance_info_has_system_contract_address() {
        let handler = setup();
        let result = ShellApiServer::get_governance_info(&handler).await.unwrap();
        let addr_str = result["systemContractAddress"].as_str().unwrap();
        let expected = format!("{}", shell_pqvm::registry_address());
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

        assert_eq!(
            result["version"],
            format!("ShellChain/v{}/rust", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(result["chain_id"], "42");
        assert_eq!(result["block_height"], 0);
        assert!(result["peer_id"].is_string());
        assert_eq!(result["peer_count"], 0);
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
        assert_eq!(result["block_height"], 0);
        assert_eq!(result["chain_id"], "42");
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

    #[tokio::test]
    async fn consensus_info_omits_next_block_fields_at_terminal_head() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.number = u64::MAX;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(u64::MAX, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let authority = test_address(b"consensus-info-authority");
        let engine = Arc::new(parking_lot::RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1).with_epoch_length(10),
        )));
        let handler = handler.with_consensus_engine(engine);

        let result = ShellApiServer::consensus_info(&handler).await.unwrap();

        assert_eq!(result["block_number"], u64::MAX);
        assert_eq!(result["current_proposer"], serde_json::Value::Null);
        assert_eq!(result["epoch"], serde_json::Value::Null);
        assert_eq!(result["epoch_progress"], serde_json::Value::Null);
        assert_eq!(result["epoch_length"], 10);
    }

    // ── shell_getNetworkStats ──────────────────────────────────────

    #[tokio::test]
    async fn get_network_stats_returns_all_fields() {
        let handler = setup();
        let result = ShellApiServer::get_network_stats(&handler).await.unwrap();

        // peerCount reflects the live AtomicUsize (0 in the default test setup).
        assert_eq!(result["peerCount"], 0);
        assert_eq!(result["protocolVersion"], "shell/1.0.0");
        // listeningAddress falls back to the default multiaddr when unset.
        assert_eq!(result["listeningAddress"], "/ip4/0.0.0.0/tcp/30303");
        let protocols = result["protocols"].as_array().unwrap();
        assert_eq!(protocols.len(), 3);
        assert!(protocols.contains(&serde_json::json!("gossipsub")));
        assert!(protocols.contains(&serde_json::json!("kademlia")));
        assert!(protocols.contains(&serde_json::json!("mdns")));
    }

    #[tokio::test]
    async fn get_network_stats_reflects_live_peer_count() {
        use std::sync::atomic::Ordering;
        let handler = setup();
        handler.peer_count.store(7, Ordering::Relaxed);
        let result = ShellApiServer::get_network_stats(&handler).await.unwrap();
        assert_eq!(result["peerCount"], 7);
    }

    #[tokio::test]
    async fn get_network_stats_reflects_configured_listen_addr() {
        let handler = setup().with_admin_context("peer-id".into(), "/ip4/10.0.0.1/tcp/9000".into());
        let result = ShellApiServer::get_network_stats(&handler).await.unwrap();
        assert_eq!(result["listeningAddress"], "/ip4/10.0.0.1/tcp/9000");
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
            system_transactions: vec![],
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

    #[tokio::test]
    async fn get_chain_stats_rebuilds_full_chain_totals() {
        let handler = setup();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let from = test_address(b"chain-stats-from");
        let tx = SignedTransaction::new(
            from,
            Transaction {
                chain_id: 42,
                nonce: 0,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                gas_limit: 21_000,
                to: Some(test_address(b"chain-stats-to")),
                value: U256::from(1u64),
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
        );

        let mut parent_hash = genesis_hash;
        for number in 1..=1002u64 {
            let block = Block {
                header: BlockHeader {
                    parent_hash,
                    state_root: ShellHash::default(),
                    transactions_root: ShellHash::default(),
                    receipts_root: ShellHash::default(),
                    logs_bloom: Bytes::default(),
                    number,
                    gas_limit: 30_000_000,
                    gas_used: 1,
                    timestamp: genesis.header.timestamp + number,
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
                transactions: if number == 1 {
                    vec![tx.clone()]
                } else {
                    vec![]
                },
                system_transactions: vec![],
                proposer_seal: None,
            };
            let block_hash = block.hash();
            handler.chain_store.put_block(&block).unwrap();
            handler
                .chain_store
                .set_canonical(number, &block_hash)
                .unwrap();
            handler.chain_store.set_head(&block_hash).unwrap();
            parent_hash = block_hash;
        }

        let result = ShellApiServer::get_chain_stats(&handler).await.unwrap();
        assert_eq!(result["blockHeight"], 1002);
        assert_eq!(result["totalTransactions"], 1);
        assert_eq!(result["gasUsedTotal"], "0x3ea");
    }

    #[tokio::test]
    async fn get_chain_stats_counts_explorer_visible_system_transactions() {
        let handler = setup();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let from = test_address(b"chain-stats-visible-from");
        let tx = SignedTransaction::new(
            from,
            Transaction {
                chain_id: 42,
                nonce: 0,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                gas_limit: 21_000,
                to: Some(test_address(b"chain-stats-visible-to")),
                value: U256::from(1u64),
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
        );
        let reward = SystemTransaction::block_gas_reward(
            42,
            1,
            0,
            test_address(b"chain-stats-visible-reward"),
            U256::from(10u64),
            genesis_hash,
        );
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
            transactions: vec![tx],
            system_transactions: vec![reward],
            proposer_seal: None,
        };
        let hash1 = block1.hash();
        handler.chain_store.put_block(&block1).unwrap();
        handler
            .chain_store
            .put_system_transactions(&hash1, 1, &block1.system_transactions)
            .unwrap();
        handler.chain_store.set_canonical(1, &hash1).unwrap();
        handler.chain_store.set_head(&hash1).unwrap();

        let stats = ShellApiServer::get_chain_stats(&handler).await.unwrap();
        assert_eq!(stats["totalTransactions"], 2);

        let block = ShellApiServer::shell_get_block_by_number(
            &handler,
            "0x1".into(),
            Some("summary".into()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(block.transactions.as_array().unwrap().len(), 2);
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
            system_transactions: vec![],
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
    async fn rpc_block_roots_are_plain_hex_strings() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.withdrawals_root = ShellHash::from([0x11; 32]);
        block.header.parent_beacon_block_root = ShellHash::from([0x22; 32]);
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "0x0".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(rpc.withdrawals_root, format!("0x{}", "11".repeat(32)));
        assert_eq!(
            rpc.parent_beacon_block_root,
            format!("0x{}", "22".repeat(32))
        );
        assert!(!rpc.withdrawals_root.contains("ShellHash"));
        assert!(!rpc.parent_beacon_block_root.contains("ShellHash"));
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

    #[tokio::test]
    async fn get_block_receipts_rejects_invalid_hash_as_invalid_params() {
        let handler = setup();
        let invalid_hash = format!("0x{}zz", "00".repeat(31));

        let err = EthApiServer::get_block_receipts(&handler, invalid_hash)
            .await
            .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid block hash hex"));
    }

    #[tokio::test]
    async fn get_block_receipts_pending_returns_no_latest_receipts() {
        let handler = setup();
        store_block_with_logs(&handler, 0, vec![vec![]]);

        let latest = EthApiServer::get_block_receipts(&handler, "latest".into())
            .await
            .unwrap();
        let pending = EthApiServer::get_block_receipts(&handler, "pending".into())
            .await
            .unwrap();

        assert_eq!(latest.len(), 1);
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn witness_queries_reject_invalid_hash_as_invalid_params() {
        let handler = setup();
        let invalid_hash = format!("0x{}zz", "00".repeat(31));

        let err = ShellApiServer::get_witness(&handler, invalid_hash)
            .await
            .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid block hash hex"));
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
        assert_eq!(rpc.gas_used, "0x0");
        // Still has standard Ethereum fields.
        assert_eq!(rpc.total_difficulty, "0x1");
        assert_eq!(rpc.nonce, "0x0000000000000000");
    }

    #[tokio::test]
    async fn pending_block_skips_oversized_candidates_and_keeps_later_fit_txs() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.gas_limit = 42_000;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let oversized_signer = DilithiumSigner::generate();
        let oversized_addr = signer_address(&oversized_signer);
        let fit_signer = DilithiumSigner::generate();
        let fit_addr = signer_address(&fit_signer);
        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&oversized_addr, U256::from(100_000_000_000_000u64))
                .unwrap();
            ws.add_balance(&fit_addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler
            .chain_store
            .put_pubkey(&oversized_addr, oversized_signer.public_key())
            .unwrap();
        handler
            .chain_store
            .put_pubkey(&fit_addr, fit_signer.public_key())
            .unwrap();

        let oversized_tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_priority_fee_per_gas: 100_000_000,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 42_001,
            to: Some(test_address(b"pending-oversized-to")),
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let oversized_sig = oversized_signer
            .sign(oversized_tx.hash().0.as_slice())
            .unwrap();
        let oversized = SignedTransaction::new(oversized_addr, oversized_tx, oversized_sig);

        let fit_tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_priority_fee_per_gas: 100_000_000,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 21_000,
            to: Some(test_address(b"pending-fit-to")),
            value: U256::ZERO,
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let fit_sig = fit_signer.sign(fit_tx.hash().0.as_slice()).unwrap();
        let fit = SignedTransaction::new(fit_addr, fit_tx, fit_sig);
        let fit_hash = fit.hash();

        {
            let mut ws = handler.world_state.write();
            handler
                .tx_pool
                .insert(
                    oversized,
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
            handler
                .tx_pool
                .insert(fit, &mut ws, handler.chain_store.as_ref(), &MultiVerifier)
                .unwrap();
        }

        let rpc = EthApiServer::get_block_by_number(&handler, "pending".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(rpc.transactions, serde_json::json!([fit_hash]));
        assert_eq!(rpc.gas_used, "0x5208");
    }

    #[tokio::test]
    async fn pending_block_uses_block_candidate_nonce_order() {
        let handler = setup();
        let block = make_genesis_block();
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(0, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let sender_signer = DilithiumSigner::generate();
        let sender_addr = signer_address(&sender_signer);
        let other_signer = DilithiumSigner::generate();
        let other_addr = signer_address(&other_signer);
        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&sender_addr, U256::from(100_000_000_000_000u64))
                .unwrap();
            ws.add_balance(&other_addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }
        handler
            .chain_store
            .put_pubkey(&sender_addr, sender_signer.public_key())
            .unwrap();
        handler
            .chain_store
            .put_pubkey(&other_addr, other_signer.public_key())
            .unwrap();

        let make_tx = |signer: &DilithiumSigner,
                       from: Address,
                       nonce: u64,
                       priority_fee: u64,
                       seed: &[u8]| {
            let tx = Transaction {
                chain_id: 42,
                nonce,
                max_priority_fee_per_gas: priority_fee,
                max_fee_per_gas: 1_000_000_000,
                gas_limit: 21_000,
                to: Some(test_address(seed)),
                value: U256::ZERO,
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let sig = signer.sign(tx.hash().0.as_slice()).unwrap();
            SignedTransaction::new(from, tx, sig)
        };

        let sender_tx0 = make_tx(
            &sender_signer,
            sender_addr,
            0,
            10,
            b"pending-sender-nonce-0",
        );
        let sender_tx1 = make_tx(
            &sender_signer,
            sender_addr,
            1,
            100,
            b"pending-sender-nonce-1",
        );
        let other_tx = make_tx(&other_signer, other_addr, 0, 50, b"pending-other-nonce-0");

        let sender_tx0_hash = sender_tx0.hash();
        let sender_tx1_hash = sender_tx1.hash();
        let other_hash = other_tx.hash();

        {
            let mut ws = handler.world_state.write();
            handler
                .tx_pool
                .insert(
                    sender_tx0,
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
            handler
                .tx_pool
                .insert(
                    sender_tx1,
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
            handler
                .tx_pool
                .insert(
                    other_tx,
                    &mut ws,
                    handler.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
        }

        let rpc = EthApiServer::get_block_by_number(&handler, "pending".into(), false)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            rpc.transactions,
            serde_json::json!([other_hash, sender_tx0_hash, sender_tx1_hash])
        );
        assert_eq!(rpc.gas_used, "0xf618");
    }

    #[tokio::test]
    async fn pending_block_returns_none_at_terminal_height() {
        let handler = setup();
        let mut block = make_genesis_block();
        block.header.number = u64::MAX;
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(u64::MAX, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let rpc = EthApiServer::get_block_by_number(&handler, "pending".into(), false)
            .await
            .unwrap();

        assert!(rpc.is_none());
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

        // Verify get_finality_info reflects the full finality state.
        finality
            .write()
            .set_finalized_direct(100, ShellHash::from([0x64; 32]));
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
    async fn new_filter_accepts_finality_block_tags() {
        let handler = setup();
        *handler.finalized_number.write() = 7;
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"safe","toBlock":"finalized"}"#).unwrap();

        let id = EthApiServer::new_filter(&handler, raw).await.unwrap();

        assert!(id.starts_with("0x"));
    }

    #[tokio::test]
    async fn new_filter_rejects_invalid_block_tag_as_invalid_params() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"not-a-block","toBlock":"0x1"}"#).unwrap();

        let err = EthApiServer::new_filter(&handler, raw).await.unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("fromBlock"));
    }

    #[tokio::test]
    async fn new_filter_rejects_more_than_four_topic_slots() {
        let handler = setup();
        let raw: crate::filter::RawLogFilter = serde_json::from_str(
            r#"{
                "topics": [
                    null,
                    null,
                    null,
                    null,
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                ]
            }"#,
        )
        .unwrap();

        let err = EthApiServer::new_filter(&handler, raw).await.unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("at most 4"));
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
            system_transactions: vec![],
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
    async fn block_filter_changes_are_range_capped() {
        let handler = setup();

        let genesis = make_genesis_block();
        let genesis_hash = genesis.hash();
        handler.chain_store.put_block(&genesis).unwrap();
        handler.chain_store.set_canonical(0, &genesis_hash).unwrap();
        handler.chain_store.set_head(&genesis_hash).unwrap();

        let filter_id = EthApiServer::new_block_filter(&handler).await.unwrap();
        let mut parent_hash = genesis_hash;
        for number in 1..=(MAX_BLOCK_RANGE + 1) {
            let block = Block {
                header: BlockHeader {
                    parent_hash,
                    number,
                    ..make_genesis_block().header
                },
                transactions: vec![],
                system_transactions: vec![],
                proposer_seal: None,
            };
            let hash = block.hash();
            handler.chain_store.put_block(&block).unwrap();
            handler.chain_store.set_canonical(number, &hash).unwrap();
            handler.chain_store.set_head(&hash).unwrap();
            parent_hash = hash;
        }

        let first = EthApiServer::get_filter_changes(&handler, filter_id.clone())
            .await
            .unwrap();
        assert_eq!(first.as_array().unwrap().len(), MAX_BLOCK_RANGE as usize);

        let second = EthApiServer::get_filter_changes(&handler, filter_id)
            .await
            .unwrap();
        assert_eq!(second.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn filter_changes_caps_range_without_overflow_near_u64_max() {
        let handler = setup();
        let block = Block {
            header: BlockHeader {
                number: u64::MAX,
                ..make_genesis_block().header
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(u64::MAX, &hash).unwrap();
        handler.chain_store.set_head(&hash).unwrap();

        let block_filter = handler
            .filter_registry
            .new_filter(FilterKind::Block, u64::MAX - 1)
            .unwrap();
        let block_changes = EthApiServer::get_filter_changes(&handler, block_filter.clone())
            .await
            .unwrap();
        assert_eq!(block_changes.as_array().unwrap().len(), 1);
        let (_, last_poll) = handler
            .filter_registry
            .get_filter_info(&block_filter)
            .unwrap();
        assert_eq!(last_poll, u64::MAX);
        let block_changes = EthApiServer::get_filter_changes(&handler, block_filter.clone())
            .await
            .unwrap();
        assert!(block_changes.as_array().unwrap().is_empty());
        let (_, last_poll) = handler
            .filter_registry
            .get_filter_info(&block_filter)
            .unwrap();
        assert_eq!(last_poll, u64::MAX);

        let raw: RawLogFilter = serde_json::from_str(r#"{}"#).unwrap();
        let log_filter = handler
            .filter_registry
            .new_filter(FilterKind::Log(raw), u64::MAX - 1)
            .unwrap();
        let log_changes = EthApiServer::get_filter_changes(&handler, log_filter.clone())
            .await
            .unwrap();
        assert!(log_changes.as_array().unwrap().is_empty());
        let (_, last_poll) = handler
            .filter_registry
            .get_filter_info(&log_filter)
            .unwrap();
        assert_eq!(last_poll, u64::MAX);
        let log_changes = EthApiServer::get_filter_changes(&handler, log_filter.clone())
            .await
            .unwrap();
        assert!(log_changes.as_array().unwrap().is_empty());
        let (_, last_poll) = handler
            .filter_registry
            .get_filter_info(&log_filter)
            .unwrap();
        assert_eq!(last_poll, u64::MAX);
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
            system_transactions: vec![],
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
    async fn debug_trace_transaction_rejects_unprefixed_hash_as_invalid_params() {
        let handler = setup();
        let fake_hash = "aa".repeat(32);

        let err = DebugApiServer::trace_transaction(&handler, fake_hash, None)
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
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
    async fn trace_oe_transaction_rejects_unprefixed_hash_as_invalid_params() {
        let handler = setup();
        let fake_hash = "cc".repeat(32);

        let err = TraceApiServer::trace_oe_transaction(&handler, fake_hash)
            .await
            .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
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

    #[tokio::test]
    async fn debug_trace_transaction_rejects_invalid_options_as_invalid_params() {
        let handler = setup();
        let (_block_hash, tx_hash) = store_block_with_tx(&handler, 0, true);

        let err = DebugApiServer::trace_transaction(
            &handler,
            format!("0x{}", hex::encode(tx_hash.as_bytes())),
            Some(serde_json::json!({ "disableStack": "yes" })),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("invalid trace options"));
    }

    #[tokio::test]
    async fn debug_trace_block_by_number_rejects_invalid_options_as_invalid_params() {
        let handler = setup();
        store_block_with_tx(&handler, 0, true);

        let err = DebugApiServer::trace_block_by_number(
            &handler,
            "0x0".into(),
            Some(serde_json::json!({ "disableMemory": "no" })),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("invalid trace options"));
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
        let gas_limit = shell_pqvm::compute_intrinsic_gas(&[], true, &None);

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
        let gas_limit = shell_pqvm::compute_intrinsic_gas(&[], true, &None);

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
    async fn m6b1_send_raw_transaction_json_sdk_sender_pubkey_first_tx() {
        let handler = setup();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let addr = signer_address(&signer);
        let gas_limit = shell_pqvm::compute_intrinsic_gas(&[], true, &None);

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }

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
        let payload = serde_json::json!({
            "from": addr,
            "tx": tx,
            "signature": signature,
            "sender_pubkey": pubkey,
        });

        let json_bytes = serde_json::to_vec(&payload).unwrap();
        let hex_payload = format!("0x{}", hex::encode(&json_bytes));

        let result = EthApiServer::send_raw_transaction(&handler, hex_payload).await;
        assert!(
            result.is_ok(),
            "JSON send_raw_transaction with sender_pubkey failed: {:?}",
            result.err()
        );
        assert_eq!(handler.tx_pool.len(), 1);
        assert!(handler.chain_store.get_pubkey(&addr).unwrap().is_some());
    }

    #[tokio::test]
    async fn m6b2_send_raw_transaction_json_sdk_dilithium3_fixture_first_tx() {
        let handler = setup();
        let pubkey =
            hex::decode(include_str!("../../tests/fixtures/sdk_dilithium3_tx_pubkey.hex").trim())
                .unwrap();
        let signature_bytes = hex::decode(
            include_str!("../../tests/fixtures/sdk_dilithium3_tx_signature.hex").trim(),
        )
        .unwrap();
        let expected_hash =
            hex::decode(include_str!("../../tests/fixtures/sdk_dilithium3_tx_hash.hex").trim())
                .unwrap();
        let addr = Address::from_public_key(&pubkey, 0);

        assert_eq!(
            addr.to_string(),
            "0x68a08f38c46375c23149daffcc2081a193e3ada25a90ad6f0e77bc0647375ead"
        );

        {
            let mut ws = handler.world_state.write();
            ws.add_balance(&addr, U256::from(100_000_000_000_000u64))
                .unwrap();
        }

        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            max_priority_fee_per_gas: 100_000_000,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 21_000,
            to: Some(addr),
            value: U256::from(1u64),
            data: Bytes::default(),
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        assert_eq!(tx.hash().0.as_slice(), expected_hash.as_slice());

        let signature = shell_crypto::PQSignature::new(
            shell_crypto::SignatureType::Dilithium3,
            signature_bytes,
        );
        let payload = serde_json::json!({
            "from": addr,
            "tx": tx,
            "signature": signature,
            "sender_pubkey": pubkey,
        });

        let json_bytes = serde_json::to_vec(&payload).unwrap();
        let hex_payload = format!("0x{}", hex::encode(&json_bytes));

        let result = EthApiServer::send_raw_transaction(&handler, hex_payload).await;
        assert!(
            result.is_ok(),
            "JSON send_raw_transaction with sdk Dilithium3 fixture failed: {:?}",
            result.err()
        );
        assert_eq!(handler.tx_pool.len(), 1);
        assert!(handler.chain_store.get_pubkey(&addr).unwrap().is_some());
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

    // ── v0.18.0 M3 · Native-AA RPC surface ────────────────────────────

    fn make_inner_call_req(
        to: Address,
        value: u64,
        gas_limit: Option<u64>,
    ) -> crate::types::BatchInnerCallRequest {
        crate::types::BatchInnerCallRequest {
            to: Some(to),
            value: Some(format!("{:#x}", value)),
            data: None,
            gas_limit: gas_limit.map(|g| format!("{:#x}", g)),
        }
    }

    #[tokio::test]
    async fn estimate_batch_rejects_empty_inner_calls() {
        let handler = setup();
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: None,
                paymaster: None,
                inner_calls: vec![],
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.message().contains("inner_calls must not be empty"),
            "unexpected err: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn estimate_batch_rejects_too_many_inner_calls() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let calls: Vec<_> = (0..shell_core::MAX_INNER_CALLS + 1)
            .map(|_| make_inner_call_req(dst, 0, Some(21_000)))
            .collect();
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: None,
                paymaster: None,
                inner_calls: calls,
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.message().contains("exceeds MAX_INNER_CALLS"),
            "unexpected err: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn estimate_batch_explicit_gas_limits_computes_structural_total() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let res = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: None,
                paymaster: None,
                inner_calls: vec![
                    make_inner_call_req(dst, 0, Some(21_000)),
                    make_inner_call_req(dst, 0, Some(21_000)),
                    make_inner_call_req(dst, 0, Some(21_000)),
                ],
            },
        )
        .await
        .unwrap();

        // outer_intrinsic = 21_000
        // inner_sum = 3 × 21_000 = 63_000
        // intrinsic_surcharge = 2 × AA_INNER_CALL_INTRINSIC_GAS = 8_000
        // total_gas = 21_000 + 63_000 + 8_000 = 92_000
        assert_eq!(res["outer_intrinsic"], format!("{:#x}", 21_000));
        assert_eq!(res["inner_sum"], format!("{:#x}", 63_000));
        assert_eq!(
            res["intrinsic_surcharge"],
            format!("{:#x}", 2 * shell_core::AA_INNER_CALL_INTRINSIC_GAS)
        );
        assert_eq!(res["total_gas"], format!("{:#x}", 92_000));
        let per = res["per_inner"].as_array().unwrap();
        assert_eq!(per.len(), 3);
        assert_eq!(per[0]["simulated"], false);
    }

    #[tokio::test]
    async fn estimate_batch_rejects_gas_total_overflow_as_invalid_params() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);

        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: None,
                paymaster: None,
                inner_calls: vec![make_inner_call_req(dst, 0, Some(u64::MAX))],
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("total gas overflow"));
    }

    #[tokio::test]
    async fn estimate_batch_simulates_when_gas_limit_missing() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        // Omit gas_limit for the first inner call — the server must simulate it
        // via execute_call and return simulated = true with a gas ≥ 21_000.
        let res = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: Some(Address::ZERO),
                paymaster: None,
                inner_calls: vec![make_inner_call_req(dst, 0, None)],
            },
        )
        .await
        .unwrap();
        let per = res["per_inner"].as_array().unwrap();
        assert_eq!(per.len(), 1);
        assert_eq!(per[0]["simulated"], true);
        let gas = u64::from_str_radix(
            per[0]["gas_limit"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert!(gas >= 21_000, "expected simulated gas ≥ 21_000, got {gas}");
    }

    #[tokio::test]
    async fn estimate_batch_rejects_invalid_inner_data_hex_as_invalid_params() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: Some(Address::ZERO),
                paymaster: None,
                inner_calls: vec![crate::types::BatchInnerCallRequest {
                    to: Some(dst),
                    value: Some("0x0".into()),
                    data: Some("0xzz".into()),
                    gas_limit: None,
                }],
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid hex"));
    }

    #[tokio::test]
    async fn estimate_batch_validates_inner_data_with_explicit_gas_limit() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: Some(Address::ZERO),
                paymaster: None,
                inner_calls: vec![crate::types::BatchInnerCallRequest {
                    to: Some(dst),
                    value: Some("0x0".into()),
                    data: Some("0xzz".into()),
                    gas_limit: Some("0x5208".into()),
                }],
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("invalid hex"));
    }

    #[tokio::test]
    async fn estimate_batch_rejects_oversized_inner_data_with_explicit_gas_limit() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let oversized = format!("0x{}", "00".repeat(shell_mempool::MAX_TX_SIZE + 1));
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: Some(Address::ZERO),
                paymaster: None,
                inner_calls: vec![crate::types::BatchInnerCallRequest {
                    to: Some(dst),
                    value: Some("0x0".into()),
                    data: Some(oversized),
                    gas_limit: Some("0x5208".into()),
                }],
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("maximum size"));
        assert!(
            !err.message().contains(&"00".repeat(128)),
            "error should not reflect large inner call data"
        );
    }

    #[tokio::test]
    async fn estimate_batch_validates_inner_value_with_explicit_gas_limit() {
        let handler = setup();
        let dst = Address::from([0xAA; 20]);
        let err = ShellApiServer::estimate_batch(
            &handler,
            crate::types::BatchEstimateRequest {
                from: Some(Address::ZERO),
                paymaster: None,
                inner_calls: vec![crate::types::BatchInnerCallRequest {
                    to: Some(dst),
                    value: Some("1".into()),
                    data: Some("0x".into()),
                    gas_limit: Some("0x5208".into()),
                }],
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains("missing 0x prefix"));
    }

    #[tokio::test]
    async fn get_paymaster_policy_returns_unregistered_for_bare_address() {
        let handler = setup();
        let addr = Address::from([0xCC; 20]);
        let res = ShellApiServer::get_paymaster_policy(&handler, addr)
            .await
            .unwrap();
        assert_eq!(res["has_pq_pubkey"], false);
        assert_eq!(res["pubkey_bytes"], serde_json::Value::Null);
        assert_eq!(res["policy"], "eoa-open");
        assert_eq!(res["max_gas_sponsorship"], serde_json::Value::Null);
        assert_eq!(res["balance"], "0x0");
    }

    #[tokio::test]
    async fn get_paymaster_policy_surfaces_balance_and_pubkey() {
        let handler = setup();
        let addr = Address::from([0xCD; 20]);
        handler
            .chain_store
            .put_pubkey(&addr, &[0xAB; 1_952])
            .unwrap();
        {
            let mut ws = handler.world_state.write();
            ws.set_balance(&addr, U256::from(123_456_u64)).unwrap();
        }

        let res = ShellApiServer::get_paymaster_policy(&handler, addr)
            .await
            .unwrap();
        assert_eq!(res["has_pq_pubkey"], true);
        assert_eq!(res["pubkey_bytes"], 1_952u64);
        assert_eq!(res["balance"], format!("{:#x}", 123_456_u64));
        assert_eq!(res["policy"], "eoa-open");
    }

    #[tokio::test]
    async fn estimate_paymaster_gas_reports_versioned_cap_only_status() {
        let handler = setup();
        let paymaster = Address::from([0xAA; 20]);
        let sender = Address::from([0xBB; 20]);

        let res = ShellApiServer::estimate_paymaster_gas(
            &handler,
            PaymasterGasEstimateRequest {
                paymaster,
                sender,
                inner_calls_data: Some("0x".into()),
                max_fee_per_gas: Some("0x3b9aca00".into()),
                paymaster_context: Some("0x01".into()),
            },
        )
        .await
        .unwrap();

        assert_eq!(res["paymaster"], serde_json::to_value(paymaster).unwrap());
        assert_eq!(res["sender"], serde_json::to_value(sender).unwrap());
        assert_eq!(res["validation_gas"], serde_json::Value::Null);
        assert_eq!(res["within_cap"], serde_json::Value::Null);
        assert_eq!(res["paymaster_gas_cap"], "0xc350");
        assert_eq!(res["simulation_status"], "cap_only");
        assert_eq!(res["simulation_version"], 1u64);
        assert_eq!(res["capability"], "paymaster_cap_only");
    }

    #[tokio::test]
    async fn estimate_paymaster_gas_rejects_unprefixed_byte_fields() {
        let handler = setup();
        let paymaster = Address::from([0xAA; 20]);
        let sender = Address::from([0xBB; 20]);

        for (inner_calls_data, paymaster_context, expected) in [
            (
                Some("".into()),
                None,
                "inner_calls_data must be 0x-prefixed",
            ),
            (
                Some("01".into()),
                None,
                "inner_calls_data must be 0x-prefixed",
            ),
            (
                None,
                Some("".into()),
                "paymaster_context must be 0x-prefixed",
            ),
            (
                None,
                Some("01".into()),
                "paymaster_context must be 0x-prefixed",
            ),
        ] {
            let err = ShellApiServer::estimate_paymaster_gas(
                &handler,
                PaymasterGasEstimateRequest {
                    paymaster,
                    sender,
                    inner_calls_data,
                    max_fee_per_gas: Some("0x1".into()),
                    paymaster_context,
                },
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), -32602);
            assert!(err.message().contains(expected));
        }
    }

    #[tokio::test]
    async fn estimate_paymaster_gas_rejects_invalid_byte_fields() {
        let handler = setup();
        let paymaster = Address::from([0xAA; 20]);
        let sender = Address::from([0xBB; 20]);

        for (inner_calls_data, paymaster_context, expected) in [
            (Some("0xzz".into()), None, "inner_calls_data invalid hex"),
            (None, Some("0xzz".into()), "paymaster_context invalid hex"),
        ] {
            let err = ShellApiServer::estimate_paymaster_gas(
                &handler,
                PaymasterGasEstimateRequest {
                    paymaster,
                    sender,
                    inner_calls_data,
                    max_fee_per_gas: Some("0x1".into()),
                    paymaster_context,
                },
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), -32602);
            assert!(err.message().contains(expected));
        }
    }

    #[tokio::test]
    async fn estimate_paymaster_gas_rejects_oversized_byte_fields_before_decode() {
        let handler = setup();
        let paymaster = Address::from([0xAA; 20]);
        let sender = Address::from([0xBB; 20]);
        let oversized = format!("0x{}", "aa".repeat(32 * 1024 + 1));

        for (inner_calls_data, paymaster_context, expected) in [
            (
                Some(oversized.clone()),
                None,
                "inner_calls_data exceeds maximum size",
            ),
            (
                None,
                Some(oversized.clone()),
                "paymaster_context exceeds maximum size",
            ),
        ] {
            let err = ShellApiServer::estimate_paymaster_gas(
                &handler,
                PaymasterGasEstimateRequest {
                    paymaster,
                    sender,
                    inner_calls_data,
                    max_fee_per_gas: Some("0x1".into()),
                    paymaster_context,
                },
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), -32602);
            assert!(err.message().contains(expected));
            assert!(
                !err.message().contains(&"aa".repeat(64)),
                "error should not reflect large byte fields"
            );
        }
    }

    #[tokio::test]
    async fn estimate_paymaster_gas_rejects_context_above_protocol_cap() {
        let handler = setup();
        let paymaster = Address::from([0xAA; 20]);
        let sender = Address::from([0xBB; 20]);
        let oversized_context = format!("0x{}", "aa".repeat(shell_core::MAX_PAYMASTER_CONTEXT + 1));

        let err = ShellApiServer::estimate_paymaster_gas(
            &handler,
            PaymasterGasEstimateRequest {
                paymaster,
                sender,
                inner_calls_data: None,
                max_fee_per_gas: Some("0x1".into()),
                paymaster_context: Some(oversized_context),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), -32602);
        assert!(err.message().contains(&format!(
            "paymaster_context exceeds maximum size of {} bytes",
            shell_core::MAX_PAYMASTER_CONTEXT
        )));
    }

    #[tokio::test]
    async fn is_sponsored_returns_not_found_for_unknown_hash() {
        let handler = setup();
        let res = ShellApiServer::is_sponsored(&handler, ShellHash::from_slice(&[0u8; 32]))
            .await
            .unwrap();
        assert_eq!(res["found"], false);
        assert_eq!(res["location"], serde_json::Value::Null);
        assert_eq!(res["sponsored"], false);
    }

    #[tokio::test]
    async fn is_sponsored_detects_chain_stored_sponsored_bundle() {
        use shell_core::{AaBundle, InnerCall, PubkeyMode, AA_BUNDLE_TX_TYPE};
        use shell_crypto::{PQSignature, SignatureType};

        let handler = setup();
        let sender = Address::from([0x11; 20]);
        let payer = Address::from([0x22; 20]);

        let inner = InnerCall {
            to: Some(Address::from([0xFF; 20])),
            value: U256::from(1u64),
            data: Bytes::new(),
            gas_limit: 21_000,
        };
        let bundle = AaBundle {
            inner_calls: vec![inner.clone(), inner],
            paymaster: Some(payer),
            paymaster_signature: Some(Bytes::from(vec![0xAB; 64])),
            ..Default::default()
        };
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: None,
            value: U256::from(2u64),
            data: Bytes::new(),
            gas_limit: 200_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let placeholder_sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        let signed = SignedTransaction::with_aa_bundle(
            sender,
            tx,
            placeholder_sig,
            PubkeyMode::Reference,
            bundle,
        )
        .unwrap();
        let tx_hash = signed.hash();

        // Build a minimal block carrying this tx and index it.
        let genesis = make_genesis_block();
        handler.chain_store.put_block(&genesis).unwrap();
        handler
            .chain_store
            .set_canonical(0, &genesis.hash())
            .unwrap();

        let mut header = genesis.header.clone();
        header.parent_hash = genesis.hash();
        header.number = 1;
        let block = Block {
            header,
            transactions: vec![signed],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let block_hash = block.hash();
        handler.chain_store.put_block(&block).unwrap();
        handler.chain_store.set_canonical(1, &block_hash).unwrap();
        handler.chain_store.set_head(&block_hash).unwrap();

        let res = ShellApiServer::is_sponsored(&handler, tx_hash)
            .await
            .unwrap();
        assert_eq!(res["found"], true);
        assert_eq!(res["location"], "chain");
        assert_eq!(res["is_aa_bundle"], true);
        assert_eq!(res["sponsored"], true);
        assert_eq!(res["paymaster"], serde_json::to_value(payer).unwrap());
        assert_eq!(res["sender"], serde_json::to_value(sender).unwrap());
        assert_eq!(res["inner_call_count"], 2u64);
    }

    // ── shell_getStorageProfile ────────────────────────────────────

    #[tokio::test]
    async fn get_storage_profile_returns_pruned_descriptor() {
        let handler = setup().with_storage_profile(crate::types::StorageProfileInfo {
            profile: "pruned".into(),
            body_retention: 4096,
            witness_retention: 64,
            keep_recent: 4096,
            proof_replacement_grace: 128,
            state_pruning_experimental: false,
        });
        let res = ShellApiServer::get_storage_profile(&handler).await.unwrap();
        assert_eq!(res["profile"], "pruned");
        assert_eq!(res["body_retention"], 4096u64);
        assert_eq!(res["witness_retention"], 64u64);
        assert_eq!(res["keep_recent"], 4096u64);
        assert_eq!(res["proof_replacement_grace"], 128u64);
        assert_eq!(res["state_pruning_experimental"], false);
    }

    #[tokio::test]
    async fn get_storage_profile_archive_descriptor_round_trip() {
        let handler = setup().with_storage_profile(crate::types::StorageProfileInfo {
            profile: "archive".into(),
            body_retention: 0,
            witness_retention: 0,
            keep_recent: 0,
            proof_replacement_grace: u64::MAX,
            state_pruning_experimental: false,
        });
        let res = ShellApiServer::get_storage_profile(&handler).await.unwrap();
        assert_eq!(res["profile"], "archive");
        assert_eq!(res["proof_replacement_grace"], u64::MAX);
    }

    #[tokio::test]
    async fn get_storage_profile_returns_error_when_unconfigured() {
        let handler = setup();
        let err = ShellApiServer::get_storage_profile(&handler)
            .await
            .unwrap_err();
        assert_eq!(err.code(), crate::error::FEATURE_NOT_ENABLED);
        assert!(err.message().contains("storage profile"));
    }
}
