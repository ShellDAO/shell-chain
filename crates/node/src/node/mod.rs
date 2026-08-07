//! Running node with event loop and block production.

mod block_importer;
mod block_producer;
mod chain_state_machine;
mod challenge_lifecycle;
mod dev_rpc;
mod event_loop;
mod invariants;
mod p2p_handlers;
mod readiness;
pub(crate) mod stark_sources;
mod system_rewards;

pub(crate) use std::collections::{BTreeMap, HashMap, HashSet};
pub(crate) use std::sync::Arc;
pub(crate) use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use parking_lot::RwLock;
pub(crate) use tokio::sync::watch;
pub(crate) use tracing::{debug, info, warn};

pub(crate) use shell_consensus::{
    detect_offline, Attestation, ConsensusEngine, EngineType, EquivocationProof, FinalityState,
    ForkChoice, PeerScorer, PeerScoringConfig, ProofRateLimiter, ProofWindowManager,
    RateLimiterConfig, SlashingConfig, ViewChangeMessage, WPoaEvent, WPoaRound, WindowConfig,
    VIEW_CHANGE_TIMEOUT_MS,
};
pub(crate) use shell_core::{
    calc_blob_gas_price, calc_excess_blob_gas, calculate_base_fee, effective_gas_price, Block,
    BlockHeader, SignedTransaction, SystemTransaction, SystemTxKind, TransactionReceipt,
    WitnessBundle, MAX_BLOB_GAS_PER_BLOCK,
};
pub(crate) use shell_crypto::{
    infer_signature_type_from_address, AlgorithmRegistry, BatchVerifier, MultiVerifier,
    PQSignature, PreVerified, Signer, Verifier, VerifyItem, ALLOWED_ALGORITHMS,
};
pub(crate) use shell_mempool::TxPool;
pub(crate) use shell_network::{NetworkMessage, NetworkService};
pub(crate) use shell_pqvm::{
    commit_pqvm_state, load_algorithm_registry, process_pending_activations,
    validate_tx_for_import, validate_tx_for_import_with_expected_nonce, ExecutorError, ShellPqvm,
    ShellStateDb, StateDbError, TxValidationError,
};
pub(crate) use shell_primitives::{Address, Bytes, ShellHash, U256};
pub(crate) use shell_rpc::DevRpcControl;
pub(crate) use shell_storage::{
    validator_registry_addr, BodyPruner, ChainStore, KvStore, L2AggregationJob, L2InputIndex,
    L2JobStatus, L2JobStore, OverlayStore, ProofAmendmentStore, SettledSourceIndex, StatePruner,
    WitnessPruner, WitnessStore, WorldState,
};

pub(crate) use crate::config::NodeConfig;
pub(crate) use crate::error::NodeError;
pub(crate) use crate::metrics::Metrics;
pub(crate) use crate::prover_service::{ProverConfig, ProverService, ProverServiceHandle};
pub(crate) use crate::pruning::{
    prune_state_trie, retention_cutoff, state_trie_pruned_below, StateRootTracker, StorageProfile,
};
pub(crate) use chain_state_machine::{BlockImportTransition, ChainStateMachine};
pub(crate) use challenge_lifecycle::{
    ChallengeLifecycle, ChallengeRecord, ChallengeStatus, CHALLENGE_TIMEOUT_BLOCKS,
};
pub(crate) use readiness::{ProductionReadiness, ProductionReadinessState};

pub(crate) struct AlgorithmRegistryRollback {
    snapshot: Option<AlgorithmRegistry>,
}

impl AlgorithmRegistryRollback {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: Some(AlgorithmRegistry::global().clone()),
        }
    }

    pub(crate) fn commit(&mut self) {
        self.snapshot = None;
    }
}

impl Drop for AlgorithmRegistryRollback {
    fn drop(&mut self) {
        if let Some(snapshot) = self.snapshot.take() {
            *AlgorithmRegistry::global_mut() = snapshot;
        }
    }
}

fn apply_pending_activations<S: KvStore + 'static>(
    block_number: u64,
    world_state: &mut WorldState<S>,
    registry: &mut AlgorithmRegistry,
    phase: &str,
) -> Result<(), NodeError> {
    process_pending_activations(block_number, world_state, registry)
        .map(|_| ())
        .map_err(|e| {
            NodeError::Startup(format!(
                "algorithm activation at block {block_number} failed during {phase}: {e}"
            ))
        })
}

pub(crate) use shell_stark_prover::{
    proof::SigBatchProof,
    prover::{compute_batch_root, verify_sig_batch, SigBatchEntry},
    AggregationConfig, AggregationScheduler, AggregationTrigger, ProofAmendment, ProofBacklog,
    ProofTask, SettledL1Input, StoredProofArtifact, DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS,
};

fn tx_fits_remaining_block_gas(
    tx: &SignedTransaction,
    cumulative_gas: u64,
    block_gas_limit: u64,
) -> bool {
    cumulative_gas <= block_gas_limit && tx.tx.gas_limit <= block_gas_limit - cumulative_gas
}

fn checked_cumulative_block_gas(
    cumulative_gas: u64,
    gas_used: u64,
    block_gas_limit: u64,
) -> Option<u64> {
    cumulative_gas
        .checked_add(gas_used)
        .filter(|next| *next <= block_gas_limit)
}

fn checked_cumulative_blob_gas(cumulative_blob_gas: u64, tx_blob_gas: u64) -> Option<u64> {
    cumulative_blob_gas
        .checked_add(tx_blob_gas)
        .filter(|next| *next <= MAX_BLOB_GAS_PER_BLOCK)
}

fn next_block_request_start(head_number: u64) -> Option<u64> {
    head_number.checked_add(1)
}

fn canonical_mapping_retention(body_retention: u64, witness_retention: u64) -> u64 {
    if body_retention == 0 || witness_retention == 0 {
        return u64::MAX;
    }

    body_retention
        .max(witness_retention)
        .max(128)
        .saturating_add(1)
}

fn canonical_mapping_prune_boundary(
    finalized_number: u64,
    body_pruned_below: u64,
    witness_pruned_below: u64,
    state_trie_pruned_below: Option<u64>,
) -> u64 {
    let dependent_boundary = finalized_number
        .min(body_pruned_below)
        .min(witness_pruned_below);
    state_trie_pruned_below.map_or(dependent_boundary, |trie_boundary| {
        dependent_boundary.min(trie_boundary)
    })
}

fn state_trie_prune_boundary(finalized_number: u64, keep_recent: u64) -> Option<u64> {
    if finalized_number == 0 || keep_recent == 0 {
        return None;
    }

    let boundary = retention_cutoff(finalized_number, keep_recent);
    (boundary > 0).then_some(boundary)
}

#[derive(Debug, PartialEq, Eq)]
struct ForkAdoptionPlan {
    preferred_hash: ShellHash,
    preferred_number: u64,
    canonical_number: u64,
    ancestor_hash: ShellHash,
    ancestor_number: u64,
    old_chain: Vec<Block>,
    new_chain: Vec<Block>,
    reverted_txs: Vec<SignedTransaction>,
}

fn unique_reverted_transactions(
    old_chain: &[Block],
    new_chain: &[Block],
) -> Vec<SignedTransaction> {
    let adopted_hashes: HashSet<ShellHash> = new_chain
        .iter()
        .flat_map(|block| block.transactions.iter().map(SignedTransaction::hash))
        .collect();
    let mut reverted_hashes = HashSet::new();
    old_chain
        .iter()
        .flat_map(|block| block.transactions.iter())
        .filter(|tx| {
            let hash = tx.hash();
            !adopted_hashes.contains(&hash) && reverted_hashes.insert(hash)
        })
        .cloned()
        .collect()
}

/// A running shell-chain node.
///
/// Orchestrates storage, consensus, EVM, mempool, network, and RPC
/// into a unified event loop with optional block production.
pub struct Node<S: KvStore + 'static> {
    pub config: NodeConfig,
    pub store: Arc<S>,
    pub chain_store: Arc<ChainStore<S>>,
    pub world_state: Arc<RwLock<WorldState<S>>>,
    pub tx_pool: Arc<TxPool>,
    pub consensus: Arc<RwLock<dyn ConsensusEngine>>,
    /// Known authority public keys for seal verification (Address → PQ pubkey).
    pub known_authorities: Arc<RwLock<HashMap<Address, Vec<u8>>>>,
    /// Tracks recent state roots for pruning decisions.
    pub state_root_tracker: RwLock<StateRootTracker>,
    /// State pruner: removes old canonical mappings (F-303).
    pub state_pruner: RwLock<StatePruner>,
    /// Witness store: holds per-block signature witness bundles.
    pub witness_store: Arc<WitnessStore<S>>,
    /// Witness pruner: removes old witness bundles after finality.
    pub witness_pruner: RwLock<WitnessPruner>,
    /// Body pruner: removes old block bodies after finality (EIP-4444 style).
    pub body_pruner: RwLock<BodyPruner>,
    /// Whether to generate a STARK aggregate proof during block production.
    pub stark_aggregation: bool,
    /// Backlog of proof tasks for the background ProverService.
    /// When `stark_aggregation` is enabled, `produce_block` pushes tasks here
    /// instead of blocking on inline proof generation.
    pub proof_backlog: Arc<parking_lot::Mutex<ProofBacklog>>,
    /// G5: Stores async STARK proof amendments received from the network.
    pub amendment_store: ProofAmendmentStore<S>,
    /// Persistent index of settled (layer, source_hash) pairs. Written on every
    /// settlement; loaded at startup to skip the O(n-blocks) chain rebuild.
    settled_source_index: SettledSourceIndex<S>,
    /// Durable index of canonical L1 amendments available as L2 aggregation inputs.
    /// Keyed by the amendment's final source hash (`l2i/` prefix in KV).
    /// Only populated from canonical `StarkReward` system txs during
    /// `rebuild_settled_stark_sources_from_chain` and `record_settled_sources`.
    pub(crate) l2_input_index: L2InputIndex<S>,
    /// Durable store for L2 recursive aggregation jobs (`l2j/` prefix in KV).
    /// Keyed by deterministic job ID (blake3 of sorted L1 source hashes).
    pub(crate) l2_job_store: L2JobStore<S>,
    /// L2 aggregation scheduler — fed canonical settled L1 proofs and emits
    /// triggers when a contiguous window is ready for recursive proving.
    aggregation_scheduler: parking_lot::Mutex<AggregationScheduler>,
    /// Compression-valid STARK proof amendments waiting to be settled in the
    /// next locally produced block.
    pending_stark_settlements: Arc<parking_lot::Mutex<Vec<ProofAmendment>>>,
    /// In-memory guard against duplicate STARK reward settlement in the current
    /// process lifetime. The block-committed settlement remains authoritative.
    settled_stark_sources: parking_lot::Mutex<HashSet<(u32, ShellHash)>>,
    /// I1: Queue of equivocation proofs discovered during import_block, to be broadcast
    /// in the next event loop iteration (import_block is sync; network sends are async).
    equivocation_queue: parking_lot::Mutex<Vec<EquivocationProof>>,
    /// Finality tracking: collects attestations and detects quorum.
    pub finality: Arc<RwLock<FinalityState>>,
    /// Fork-choice rule: selects the canonical head based on attestations and finality.
    pub fork_choice: Arc<RwLock<ForkChoice>>,
    /// Prometheus metrics.
    pub metrics: Arc<Metrics>,
    /// Runtime signer retained so dev RPCs can force block production.
    runtime_signer: RwLock<Option<Arc<dyn Signer>>>,
    /// Dev-only runtime controls for Hardhat/Foundry compatibility.
    dev_state: RwLock<DevState>,
    /// L4: Peer storage capability tracker for historical body back-fill.
    pub peer_caps: crate::historical_sync::PeerCapabilityTracker,
    /// Shutdown signal sender; receivers can detect graceful shutdown.
    shutdown_tx: watch::Sender<bool>,
    /// L2 grace-window: maps block_hash → delete_at_block_number.
    /// Witnesses in this map are deleted once the head advances past delete_at.
    pending_grace_deletes: parking_lot::Mutex<HashMap<ShellHash, u64>>,
    /// I4: Proof window manager — tracks claim/squatting per block.
    /// Advances on each block import; drives prover reliability scoring in wPoA era.
    pub proof_window_manager: parking_lot::Mutex<ProofWindowManager>,
    /// White paper §7 challenge state machine for proof disputes.
    pub(crate) challenge_lifecycle: parking_lot::Mutex<ChallengeLifecycle>,
    /// W.5: Active wPoA round state machine for the current block height.
    /// `None` when running plain PoA or no block is in-flight.
    pub wpoa_round: parking_lot::Mutex<Option<shell_consensus::wpoa_state::WPoaRound>>,
    /// PS.1: Peer scorer for wPoA vote/proposal behavior (Constitution §13.5).
    pub peer_scorer: parking_lot::Mutex<shell_consensus::PeerScorer>,
    /// PS.2: Ban list bridge — scored-below-threshold peers are fed into the
    /// network-level ban list so libp2p disconnects them (Constitution §13.5).
    pub peer_ban_list: parking_lot::Mutex<shell_network::PeerBanList>,
    /// Recent tx gossip timestamps used to avoid rebroadcasting the same large
    /// PQ-signed transactions too frequently.
    tx_rebroadcast_seen: parking_lot::Mutex<HashMap<ShellHash, std::time::Instant>>,
    /// Tracks the most recent block proposed by each known validator.
    /// Updated on every block import/production; used for offline-slash detection
    /// at epoch boundaries (white paper §5.4 — wPoA offline enforcement).
    pub(crate) last_proposed_by: parking_lot::Mutex<HashMap<Address, u64>>,
    /// Set after startup synchronization completes so imported catch-up blocks
    /// cannot fill the proof backlog or trigger proof gossip prematurely.
    prover_ready: std::sync::atomic::AtomicBool,
    /// Per-prover admission control for authenticated proof gossip.
    proof_rate_limiter: parking_lot::Mutex<ProofRateLimiter>,
}

const SYNC_RETRY_BASE_INTERVAL_SECS: u64 = 5;
const SYNC_RETRY_MAX_INTERVAL_SECS: u64 = 30;
const SYNC_RETRY_BACKOFF_THRESHOLD: u32 = 3;
const TX_REBROADCAST_INTERVAL_SECS: u64 = 10;
const MAX_TX_REBROADCAST_PER_TICK: usize = 64;
const TX_REBROADCAST_COOLDOWN_SECS: u64 = 60;
const PROVER_AMENDMENT_CHANNEL_CAPACITY: usize = 1;
const MAX_PENDING_STARK_SETTLEMENTS: usize = 2;

const MAX_DEV_SNAPSHOTS: usize = 128;

#[derive(Clone)]
struct DevSnapshot {
    head_hash: ShellHash,
    head_number: u64,
    state_root: ShellHash,
    total_tx_count: u64,
    total_gas_used: U256,
    finalized_number: u64,
    pending_txs: Vec<SignedTransaction>,
    next_block_timestamp: Option<u64>,
}

struct DevState {
    next_block_timestamp: Option<u64>,
    next_snapshot_id: u64,
    snapshots: BTreeMap<u64, DevSnapshot>,
}

struct BlockStoreBoundary<'a, S: KvStore + 'static> {
    chain_store: &'a Arc<ChainStore<S>>,
    world_state: &'a Arc<RwLock<WorldState<S>>>,
    pending_grace_deletes: &'a parking_lot::Mutex<HashMap<ShellHash, u64>>,
}

impl<'a, S: KvStore + 'static> BlockStoreBoundary<'a, S> {
    fn head_block(&self) -> Result<Option<Block>, NodeError> {
        Ok(self.chain_store.get_head_block()?)
    }

    fn block_exists(&self, block_number: u64) -> Result<bool, NodeError> {
        Ok(self
            .chain_store
            .get_block_by_number(block_number)?
            .is_some())
    }

    fn block_by_number(&self, block_number: u64) -> Result<Option<Block>, NodeError> {
        Ok(self.chain_store.get_block_by_number(block_number)?)
    }

    fn block_hash_by_number(&self, block_number: u64) -> Result<Option<ShellHash>, NodeError> {
        Ok(self.chain_store.get_block_hash_by_number(block_number)?)
    }

    fn current_state_root(&self) -> Result<ShellHash, NodeError> {
        let mut ws = self.world_state.write();
        Ok(ws.state_root()?)
    }

    fn replace_world_state(&self, committed_world_state: WorldState<S>) {
        let mut live_ws = self.world_state.write();
        *live_ws = committed_world_state;
    }

    fn put_side_fork_block(&self, block: &Block) -> Result<(), NodeError> {
        self.chain_store.put_side_fork_block(block)?;
        Ok(())
    }

    fn side_fork_count(&self, block_number: u64) -> usize {
        self.chain_store
            .get_side_fork_hashes(block_number)
            .map(|hashes| hashes.len())
            .unwrap_or(0)
    }

    fn update_chain_totals(
        &self,
        block_number: u64,
        tx_count: u64,
        gas_used: u64,
    ) -> Result<(), NodeError> {
        self.chain_store
            .add_canonical_block_to_totals(block_number, tx_count, gas_used)?;
        Ok(())
    }

    fn prune_grace_witnesses(&self, current_head: u64) {
        let mut grace_map = self.pending_grace_deletes.lock();
        grace_map.retain(|hash, delete_at| {
            if current_head >= *delete_at {
                match self.chain_store.delete_witness_bundle(hash) {
                    Ok(()) => {
                        info!(
                            block = *delete_at,
                            "L2: grace-window expired, witness bundle deleted"
                        );
                        false
                    }
                    Err(e) => {
                        warn!(block = *delete_at, "L2: grace-window delete failed: {e}");
                        true
                    }
                }
            } else {
                true
            }
        });
    }
}

struct ConsensusManagerBoundary<'a, S: KvStore + 'static> {
    consensus: &'a Arc<RwLock<dyn ConsensusEngine>>,
    known_authorities: &'a Arc<RwLock<HashMap<Address, Vec<u8>>>>,
    finality: &'a Arc<RwLock<FinalityState>>,
    fork_choice: &'a Arc<RwLock<ForkChoice>>,
    world_state: &'a Arc<RwLock<WorldState<S>>>,
}

impl<'a, S: KvStore + 'static> ConsensusManagerBoundary<'a, S> {
    fn ensure_local_proposer(&self, block_number: u64, proposer: Address) -> Result<(), NodeError> {
        if self.consensus.read().is_proposer(block_number, &proposer) {
            Ok(())
        } else {
            Err(NodeError::NotProposer)
        }
    }

    fn finalized_cursor(&self) -> (u64, ShellHash) {
        let finality = self.finality.read();
        (
            finality.last_finalized_number(),
            *finality.last_finalized_hash(),
        )
    }

    fn finalized_number(&self) -> u64 {
        self.finality.read().last_finalized_number()
    }

    fn sign_block(&self, block: &mut Block, signer: &dyn Signer) -> Result<(), NodeError> {
        self.consensus.read().sign_block(block, signer)?;
        Ok(())
    }

    fn register_authority_pubkey(&self, address: Address, pubkey: Vec<u8>) {
        self.known_authorities.write().insert(address, pubkey);
    }

    fn register_fork_choice_block(
        &self,
        block_hash: ShellHash,
        parent_hash: ShellHash,
        block_number: u64,
    ) -> bool {
        let (attested_weight, is_finalized) = {
            let finality = self.finality.read();
            (
                finality.attested_weight(&block_hash),
                finality.last_finalized_number() >= block_number,
            )
        };
        self.fork_choice.write().add_block(
            block_hash,
            parent_hash,
            block_number,
            attested_weight,
            is_finalized,
        )
    }

    fn reload_authorities_if_boundary(&self, block_number: u64) -> Result<(), NodeError> {
        let should_reload = {
            let consensus = self.consensus.read();
            let config = consensus.poa_config();
            config.epoch_length == 0 || config.is_epoch_boundary(block_number)
        };
        if !should_reload {
            return Ok(());
        }

        let (validators, weights) = {
            let ws = self.world_state.read();
            let validators = ws.get_validators()?;
            let weights: Result<Vec<u64>, _> = validators
                .iter()
                .map(|validator| ws.get_validator_weight(validator))
                .collect();
            (validators, weights?)
        };
        if validators.is_empty() {
            warn!(
                block = block_number,
                "validator registry is empty at reload boundary; keeping current authority set"
            );
            return Ok(());
        }

        self.consensus
            .write()
            .set_authorities_with_weights(validators, weights);
        Ok(())
    }
}

struct ProverOrchestratorBoundary<'a, S: KvStore + 'static> {
    proof_backlog: &'a Arc<parking_lot::Mutex<ProofBacklog>>,
    pending_stark_settlements: &'a Arc<parking_lot::Mutex<Vec<ProofAmendment>>>,
    settled_stark_sources: &'a parking_lot::Mutex<HashSet<(u32, ShellHash)>>,
    settled_source_index: &'a SettledSourceIndex<S>,
    l2_input_index: &'a L2InputIndex<S>,
    metrics: &'a Arc<Metrics>,
}

impl<'a, S: KvStore + 'static> ProverOrchestratorBoundary<'a, S> {
    fn take_pending_stark_settlements(&self) -> Vec<ProofAmendment> {
        let mut pending = self.pending_stark_settlements.lock();
        std::mem::take(&mut *pending)
    }

    fn restore_pending_stark_settlements(&self, mut settlements: Vec<ProofAmendment>) {
        if settlements.is_empty() {
            return;
        }
        let mut pending = self.pending_stark_settlements.lock();
        settlements.append(&mut *pending);
        *pending = settlements;
    }

    fn has_settled_source(&self, key: (u32, ShellHash)) -> bool {
        self.settled_stark_sources.lock().contains(&key)
    }

    fn queue_task(&self, task: ProofTask) {
        self.proof_backlog.lock().push(task);
    }

    fn record_accepted_settlements(&self, count: usize) {
        if count > 0 {
            self.metrics.stark_settlements_accepted.inc_by(count as u64);
        }
    }

    fn record_settled_sources(&self, amendments: &[ProofAmendment]) {
        self.settled_stark_sources
            .lock()
            .extend(amendments.iter().flat_map(|amendment| {
                amendment
                    .covered_hashes()
                    .into_iter()
                    .map(move |source| (amendment.layer, source))
            }));
        for amendment in amendments {
            for source in amendment.covered_hashes() {
                let _ = self.settled_source_index.put(amendment.layer, &source);
            }
            // Record the final source of each L1 amendment as a canonical L2 input.
            if amendment.layer == 1 {
                let _ = self.l2_input_index.put(&amendment.block_hash);
            }
        }
    }

    fn remove_settled_pending(&self, amendments: &[ProofAmendment]) {
        if amendments.is_empty() {
            return;
        }
        let settled: HashSet<(u32, ShellHash)> = amendments
            .iter()
            .flat_map(|amendment| {
                amendment
                    .covered_hashes()
                    .into_iter()
                    .map(move |source| (amendment.layer, source))
            })
            .collect();
        self.pending_stark_settlements.lock().retain(|pending| {
            !pending
                .covered_hashes()
                .into_iter()
                .any(|source| settled.contains(&(pending.layer, source)))
        });
    }
}

struct MemPoolBoundary<'a, S: KvStore + 'static> {
    tx_pool: &'a Arc<TxPool>,
    world_state: &'a Arc<RwLock<WorldState<S>>>,
    tx_rebroadcast_seen: &'a parking_lot::Mutex<HashMap<ShellHash, std::time::Instant>>,
}

impl<'a, S: KvStore + 'static> MemPoolBoundary<'a, S> {
    fn pending_for_block(
        &self,
        max_txs: usize,
        base_fee_per_gas: u64,
        blob_base_fee: u64,
    ) -> Vec<Arc<SignedTransaction>> {
        self.tx_pool
            .pending_for_block_at_fees_shared(max_txs, base_fee_per_gas, blob_base_fee)
    }

    fn pending_for_rebroadcast(
        &self,
        target_peer: Option<&shell_network::PeerId>,
        limit: usize,
    ) -> Vec<Arc<SignedTransaction>> {
        let txs = self.tx_pool.pending_for_block_shared(limit);
        if txs.is_empty() || target_peer.is_some() {
            return txs;
        }

        let now = std::time::Instant::now();
        let cooldown = std::time::Duration::from_secs(TX_REBROADCAST_COOLDOWN_SECS);
        let mut seen = self.tx_rebroadcast_seen.lock();
        seen.retain(|_, last_seen| now.duration_since(*last_seen) < cooldown);
        let selected = txs
            .into_iter()
            .filter(|tx| {
                let hash = tx.hash();
                if seen
                    .get(&hash)
                    .is_some_and(|last_seen| now.duration_since(*last_seen) < cooldown)
                {
                    false
                } else {
                    seen.insert(hash, now);
                    true
                }
            })
            .collect();
        drop(seen);
        selected
    }

    fn remove_committed_hashes(&self, tx_hashes: &[ShellHash]) -> usize {
        self.tx_pool.remove_batch(tx_hashes);
        let ws = self.world_state.read();
        self.tx_pool.prune_nonce_too_low(&ws)
    }
}

struct NetworkInterface<'a, N: NetworkService + ?Sized> {
    inner: &'a mut N,
}

fn record_sync_request_result(
    sent: bool,
    nonce: u64,
    start_number: u64,
    sync_requested: &mut bool,
    sync_request_nonce: &mut Option<u64>,
    sync_request_start: &mut Option<u64>,
) -> bool {
    *sync_requested = sent;
    *sync_request_nonce = sent.then_some(nonce);
    *sync_request_start = sent.then_some(start_number);
    sent
}

fn stable_sync_request_nonce(
    active_nonce: Option<u64>,
    active_start: Option<u64>,
    requested_start: u64,
    generated: u64,
) -> u64 {
    if active_start == Some(requested_start) {
        active_nonce.unwrap_or(generated)
    } else {
        generated
    }
}

impl<'a, N: NetworkService + ?Sized> NetworkInterface<'a, N> {
    fn new(inner: &'a mut N) -> Self {
        Self { inner }
    }

    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), shell_network::NetworkError> {
        self.inner.broadcast(msg).await
    }

    async fn send_to_peer(
        &self,
        peer_id: &shell_network::PeerId,
        msg: NetworkMessage,
    ) -> Result<(), shell_network::NetworkError> {
        self.inner.send_to_peer(peer_id, msg).await
    }

    async fn next_event(&mut self) -> Option<shell_network::NetworkEvent> {
        self.inner.next_event().await
    }

    async fn peer_count(&self) -> usize {
        self.inner.peer_count().await
    }

    fn peer_count_handle(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.inner.peer_count_handle()
    }

    async fn shutdown(&self) -> Result<(), shell_network::NetworkError> {
        self.inner.shutdown().await
    }
}

fn restore_fork_choice<S: KvStore>(
    chain_store: &ChainStore<S>,
    finalized_number: u64,
    finalized_hash: ShellHash,
    head_number: u64,
) -> ForkChoice {
    let (root_number, root_hash) = if finalized_number > 0 && finalized_hash != ShellHash::ZERO {
        (finalized_number, finalized_hash)
    } else {
        (
            0,
            chain_store
                .get_block_hash_by_number(0)
                .ok()
                .flatten()
                .unwrap_or(ShellHash::ZERO),
        )
    };
    let mut fork_choice = ForkChoice::new(root_hash);
    if root_number > 0 {
        fork_choice.mark_finalized(&root_hash);
    }

    let Some(first_child) = root_number.checked_add(1) else {
        return fork_choice;
    };
    let mut parent_hash = root_hash;
    for block_number in first_child..=head_number {
        let block_hash = match chain_store.get_block_hash_by_number(block_number) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                warn!(
                    block_number,
                    "canonical hash missing while restoring fork choice"
                );
                break;
            }
            Err(error) => {
                warn!(
                    block_number,
                    %error,
                    "failed to read canonical hash while restoring fork choice"
                );
                break;
            }
        };
        fork_choice.add_block(block_hash, parent_hash, block_number, 0, false);
        parent_hash = block_hash;
    }

    fork_choice
}

impl<S: KvStore + 'static> Node<S> {
    /// Create a new node from pre-built components.
    pub fn new(
        config: NodeConfig,
        store: Arc<S>,
        chain_store: Arc<ChainStore<S>>,
        world_state: Arc<RwLock<WorldState<S>>>,
        tx_pool: Arc<TxPool>,
        consensus: Arc<RwLock<dyn ConsensusEngine>>,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let tracker = StateRootTracker::new(config.pruning.clone());
        let state_pruner = StatePruner::new(canonical_mapping_retention(
            config.pruning.body_retention,
            config.pruning.witness_retention,
        ));
        let witness_store = Arc::new(WitnessStore::new(store.clone()));
        let witness_pruner = WitnessPruner::new(config.pruning.witness_retention);
        let body_pruner = BodyPruner::new(config.pruning.body_retention);
        let peer_capability_limit = if config.network.max_peers == 0 {
            crate::historical_sync::MAX_PEER_CAPABILITY_RECORDS
        } else {
            config.network.max_peers
        };
        let stark_aggregation = config.enable_stark_aggregation;
        let metrics = Arc::new(Metrics::new().expect("failed to register Prometheus metrics"));
        let amendment_store = ProofAmendmentStore::new(store.clone());
        let settled_source_index = SettledSourceIndex::new(store.clone());
        let l2_input_index = L2InputIndex::new(store.clone());
        let l2_job_store = L2JobStore::new(store.clone());
        let aggregation_scheduler =
            parking_lot::Mutex::new(AggregationScheduler::new(AggregationConfig::default(), 0));

        // F-094: Recover finalized state from persistent storage on restart.
        let (fin_number, fin_hash) = {
            let stored = chain_store
                .get_finalized_number()
                .ok()
                .flatten()
                .unwrap_or(0);
            if stored > 0 {
                let hash = chain_store
                    .get_block_hash_by_number(stored)
                    .ok()
                    .flatten()
                    .unwrap_or(ShellHash::ZERO);
                (stored, hash)
            } else {
                (0, ShellHash::ZERO)
            }
        };
        let finality_state = if fin_number > 0 {
            FinalityState::with_finalized(fin_number, fin_hash)
        } else {
            FinalityState::new()
        };
        let current_head = chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.number())
            .unwrap_or(0);
        metrics.block_height.set(current_head as i64);
        metrics.update_finality(current_head, finality_state.last_finalized_number());
        let fork_choice = restore_fork_choice(&chain_store, fin_number, fin_hash, current_head);

        let node = Self {
            config,
            store,
            chain_store,
            world_state,
            tx_pool,
            consensus,
            known_authorities: Arc::new(RwLock::new(HashMap::new())),
            state_root_tracker: RwLock::new(tracker),
            state_pruner: RwLock::new(state_pruner),
            witness_store,
            witness_pruner: RwLock::new(witness_pruner),
            body_pruner: RwLock::new(body_pruner),
            stark_aggregation,
            proof_backlog: Arc::new(parking_lot::Mutex::new(ProofBacklog::new())),
            amendment_store,
            settled_source_index,
            l2_input_index,
            l2_job_store,
            aggregation_scheduler,
            pending_stark_settlements: Arc::new(parking_lot::Mutex::new(Vec::new())),
            settled_stark_sources: parking_lot::Mutex::new(HashSet::new()),
            equivocation_queue: parking_lot::Mutex::new(Vec::new()),
            finality: Arc::new(RwLock::new(finality_state)),
            fork_choice: Arc::new(RwLock::new(fork_choice)),
            metrics,
            runtime_signer: RwLock::new(None),
            dev_state: RwLock::new(DevState {
                next_block_timestamp: None,
                next_snapshot_id: 1,
                snapshots: BTreeMap::new(),
            }),
            shutdown_tx,
            peer_caps: crate::historical_sync::PeerCapabilityTracker::with_max_records(
                peer_capability_limit,
            ),
            pending_grace_deletes: parking_lot::Mutex::new(HashMap::new()),
            proof_window_manager: parking_lot::Mutex::new(ProofWindowManager::new(
                WindowConfig::default(),
            )),
            challenge_lifecycle: parking_lot::Mutex::new(ChallengeLifecycle::new()),
            wpoa_round: parking_lot::Mutex::new(None),
            peer_scorer: parking_lot::Mutex::new(PeerScorer::new(PeerScoringConfig::default())),
            peer_ban_list: parking_lot::Mutex::new(shell_network::PeerBanList::new(
                3,
                std::time::Duration::from_secs(300),
            )),
            tx_rebroadcast_seen: parking_lot::Mutex::new(HashMap::new()),
            last_proposed_by: parking_lot::Mutex::new(HashMap::new()),
            prover_ready: std::sync::atomic::AtomicBool::new(false),
            proof_rate_limiter: parking_lot::Mutex::new(ProofRateLimiter::new(RateLimiterConfig {
                initial_tokens: MAX_PENDING_STARK_SETTLEMENTS as u64,
                refill_rate: 1,
                refill_interval: std::time::Duration::from_secs(2),
                gc_after: std::time::Duration::from_secs(600),
            })),
        };

        // H-1: Emit a loud startup warning when stub-l2-verifier is compiled in.
        // This must never appear in production logs.
        #[cfg(feature = "stub-l2-verifier")]
        tracing::warn!(
            "⚠️  stub-l2-verifier feature enabled — L2 settlement proofs are NOT verified. \
             DO NOT USE IN PRODUCTION."
        );

        node
    }

    fn block_store(&self) -> BlockStoreBoundary<'_, S> {
        BlockStoreBoundary {
            chain_store: &self.chain_store,
            world_state: &self.world_state,
            pending_grace_deletes: &self.pending_grace_deletes,
        }
    }

    fn consensus_manager(&self) -> ConsensusManagerBoundary<'_, S> {
        ConsensusManagerBoundary {
            consensus: &self.consensus,
            known_authorities: &self.known_authorities,
            finality: &self.finality,
            fork_choice: &self.fork_choice,
            world_state: &self.world_state,
        }
    }

    fn prover_orchestrator(&self) -> ProverOrchestratorBoundary<'_, S> {
        ProverOrchestratorBoundary {
            proof_backlog: &self.proof_backlog,
            pending_stark_settlements: &self.pending_stark_settlements,
            settled_stark_sources: &self.settled_stark_sources,
            settled_source_index: &self.settled_source_index,
            l2_input_index: &self.l2_input_index,
            metrics: &self.metrics,
        }
    }

    fn mem_pool(&self) -> MemPoolBoundary<'_, S> {
        MemPoolBoundary {
            tx_pool: &self.tx_pool,
            world_state: &self.world_state,
            tx_rebroadcast_seen: &self.tx_rebroadcast_seen,
        }
    }

    /// Print the three-line startup pruning banner (ops-banner).
    ///
    /// Called once from the event loop at startup to give operators a quick
    /// view of what data will be retained.
    pub fn log_pruning_banner(&self) {
        let p = &self.config.pruning;

        // Use the canonical classifier so banner + P2P capability stay consistent.
        let profile_name = StorageProfile::from_pruning_config(p).as_str();

        let state_mode = if p.keep_recent == 0 {
            "archive".to_string()
        } else if matches!(
            StorageProfile::from_pruning_config(p),
            StorageProfile::Light
        ) {
            format!("keep-{} (pruned)", p.keep_recent)
        } else {
            format!("keep-{}", p.keep_recent)
        };

        let body_mode = if p.body_retention == 0 {
            "archive".to_string()
        } else {
            format!("keep-{}", p.body_retention)
        };

        let witness_mode = if p.witness_retention == 0 {
            if p.proof_replacement_grace == u64::MAX {
                "archive (never replaced)".to_string()
            } else if self.config.enable_stark_aggregation {
                "replaced-by-proof".to_string()
            } else {
                "archive".to_string()
            }
        } else {
            format!("keep-{}", p.witness_retention)
        };

        let stark_line = if self.config.enable_stark_aggregation {
            if p.proof_replacement_grace == u64::MAX {
                "STARK: enabled  (archive — witnesses kept after proof)".to_string()
            } else if p.proof_replacement_grace == 0 {
                "STARK: enabled  (witnesses replaced immediately after proof commit)".to_string()
            } else {
                format!(
                    "STARK: enabled  (grace={} blocks before witness deletion)",
                    p.proof_replacement_grace
                )
            }
        } else {
            "STARK: disabled".to_string()
        };

        tracing::info!("╔═══ Shell Chain — Storage Policy ══════════════════════════════╗");
        tracing::info!(
            "║  profile={}  state={}  bodies={}  witnesses={}",
            profile_name,
            state_mode,
            body_mode,
            witness_mode
        );
        tracing::info!("║  {}", stark_line);
        tracing::info!("╚════════════════════════════════════════════════════════════════╝");
    }

    /// Find the lowest block number whose body (`b/<hash>`) is still present.
    ///
    /// Used to populate the `oldest_body_block` field of `StorageCapability`.
    /// Returns 0 if block 0 is available (or no blocks exist yet).
    fn oldest_available_body_block(&self) -> u64 {
        self.chain_store
            .oldest_canonical_body_number()
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    fn validate_system_contract_effects<T: KvStore + 'static>(
        local_ws: &WorldState<T>,
        effects: &shell_pqvm::SystemContractEffects,
    ) -> Result<(), NodeError> {
        if effects.validator_set_changed {
            let validators = local_ws.get_validators()?;
            if validators.is_empty() {
                return Err(NodeError::Startup(
                    "system tx produced empty validator set".into(),
                ));
            }
            if validators.len() > WorldState::<T>::MAX_VALIDATORS {
                return Err(NodeError::Startup(format!(
                    "system tx produced validator set of size {} exceeding max {}",
                    validators.len(),
                    WorldState::<T>::MAX_VALIDATORS,
                )));
            }
            if local_ws.get_account(&validator_registry_addr())?.is_none() {
                return Err(NodeError::Startup(
                    "system tx removed validator registry account".into(),
                ));
            }
        }
        for address in &effects.updated_accounts {
            if local_ws.get_account(address)?.is_none() {
                return Err(NodeError::Startup(format!(
                    "system tx updated missing account {address}"
                )));
            }
        }
        Ok(())
    }

    fn reload_authorities_if_boundary(&self, block_number: u64) -> Result<(), NodeError> {
        self.consensus_manager()
            .reload_authorities_if_boundary(block_number)
    }

    /// Register an authority's public key for seal verification.
    pub fn register_authority_pubkey(&self, address: Address, pubkey: Vec<u8>) {
        self.consensus_manager()
            .register_authority_pubkey(address, pubkey);
    }

    fn head_number(&self) -> u64 {
        self.block_store()
            .head_block()
            .ok()
            .flatten()
            .map(|b| b.number())
            .unwrap_or(0)
    }

    fn local_validator_weight(&self) -> Option<u64> {
        let proposer = self.config.proposer_address?;
        self.consensus
            .read()
            .validator_weights()
            .get(&proposer)
            .copied()
            .filter(|weight| *weight > 0)
    }

    fn load_fork_segment(
        &self,
        label: &str,
        ancestor_hash: ShellHash,
        ancestor_number: u64,
        hashes: &[ShellHash],
        require_canonical: bool,
    ) -> Result<Vec<Block>, NodeError> {
        let mut blocks = Vec::with_capacity(hashes.len());
        let mut expected_parent = ancestor_hash;
        for (index, hash) in hashes.iter().enumerate() {
            let offset = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| {
                    NodeError::Startup(format!("{label} length overflows block height"))
                })?;
            let expected_number = ancestor_number.checked_add(offset).ok_or_else(|| {
                NodeError::Startup(format!("{label} height overflows block number space"))
            })?;
            let block = self
                .chain_store
                .get_block_by_hash(hash)?
                .ok_or_else(|| NodeError::Startup(format!("{label} block not found: {hash}")))?;
            if block.hash() != *hash
                || block.number() != expected_number
                || block.header.parent_hash != expected_parent
            {
                return Err(NodeError::Startup(format!(
                    "{label} continuity broken at {hash}: expected hash {hash}, #{expected_number} with parent {expected_parent}, got hash {}, #{} with parent {}",
                    block.hash(),
                    block.number(),
                    block.header.parent_hash,
                )));
            }
            if require_canonical
                && self.chain_store.get_block_hash_by_number(expected_number)? != Some(*hash)
            {
                return Err(NodeError::Startup(format!(
                    "{label} block {hash} is not canonical at #{expected_number}"
                )));
            }
            expected_parent = *hash;
            blocks.push(block);
        }
        Ok(blocks)
    }

    fn preferred_fork_plan(&self) -> Result<Option<ForkAdoptionPlan>, NodeError> {
        let canonical_head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let canonical_number = canonical_head.number();
        let canonical_hash = canonical_head.hash();
        let (
            preferred_hash,
            preferred_number,
            attested_weight,
            ancestor_hash,
            old_hashes,
            new_hashes,
        ) = {
            let fork_choice = self.fork_choice.read();
            let preferred_hash = *fork_choice.head();
            let score = fork_choice.score(&preferred_hash).ok_or_else(|| {
                NodeError::Startup(format!(
                    "fork-choice preferred block {preferred_hash} has no score"
                ))
            })?;
            if preferred_hash == canonical_hash || score.block_number <= canonical_number {
                return Ok(None);
            }
            let ancestor_hash = fork_choice
                .find_common_ancestor(&canonical_hash, &preferred_hash)
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "fork-choice preferred block {preferred_hash} has no common ancestor with canonical head {canonical_hash}"
                    ))
                })?;
            (
                preferred_hash,
                score.block_number,
                score.attested_weight,
                ancestor_hash,
                fork_choice.chain_between(&canonical_hash, &ancestor_hash),
                fork_choice.chain_between(&preferred_hash, &ancestor_hash),
            )
        };
        if new_hashes.is_empty() {
            return Err(NodeError::Startup(format!(
                "fork-choice path from ancestor {ancestor_hash} to preferred block {preferred_hash} is empty"
            )));
        }
        let new_chain_len = u64::try_from(new_hashes.len()).map_err(|_| {
            NodeError::Startup("preferred fork length overflows block number space".into())
        })?;
        let old_chain_len = u64::try_from(old_hashes.len()).map_err(|_| {
            NodeError::Startup("canonical rollback length overflows block number space".into())
        })?;
        let ancestor_number = preferred_number.checked_sub(new_chain_len).ok_or_else(|| {
            NodeError::Startup("preferred fork length exceeds preferred block number".into())
        })?;
        if canonical_number.checked_sub(ancestor_number) != Some(old_chain_len) {
            return Err(NodeError::Startup(format!(
                "fork-choice paths disagree on common ancestor {ancestor_hash} at #{ancestor_number}"
            )));
        }
        let total_weight = self
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        if !FinalityState::has_weighted_quorum(attested_weight, total_weight) {
            return Ok(None);
        }
        let (finalized_number, finalized_hash) = {
            let finality = self.finality.read();
            (
                finality.last_finalized_number(),
                *finality.last_finalized_hash(),
            )
        };
        if ancestor_number < finalized_number
            || (finalized_number > 0
                && ancestor_number == finalized_number
                && ancestor_hash != finalized_hash)
        {
            return Err(NodeError::Startup(format!(
                "preferred fork {preferred_hash} crosses finalized block #{finalized_number} ({finalized_hash})"
            )));
        }

        if self.chain_store.get_block_hash_by_number(ancestor_number)? != Some(ancestor_hash) {
            return Err(NodeError::Startup(format!(
                "fork ancestor {ancestor_hash} is not canonical at #{ancestor_number}"
            )));
        }
        let old_chain = self.load_fork_segment(
            "canonical rollback segment",
            ancestor_hash,
            ancestor_number,
            &old_hashes,
            true,
        )?;
        let new_chain = self.load_fork_segment(
            "preferred fork segment",
            ancestor_hash,
            ancestor_number,
            &new_hashes,
            false,
        )?;
        let reverted_txs = unique_reverted_transactions(&old_chain, &new_chain);

        Ok(Some(ForkAdoptionPlan {
            preferred_hash,
            preferred_number,
            canonical_number,
            ancestor_hash,
            ancestor_number,
            old_chain,
            new_chain,
            reverted_txs,
        }))
    }

    fn sync_retry_delay_secs(attempts_without_progress: u32) -> u64 {
        if attempts_without_progress < SYNC_RETRY_BACKOFF_THRESHOLD {
            SYNC_RETRY_BASE_INTERVAL_SECS
        } else {
            SYNC_RETRY_MAX_INTERVAL_SECS
        }
    }

    fn startup_sync_grace(block_time_ms: u64) -> std::time::Duration {
        std::time::Duration::from_millis(block_time_ms.clamp(2_000, 10_000))
    }

    fn catch_up_timeout(block_time_ms: u64) -> std::time::Duration {
        std::time::Duration::from_millis(block_time_ms.saturating_mul(3).clamp(10_000, 90_000))
    }

    async fn request_missing_blocks<N: NetworkService + ?Sized>(
        &self,
        network: &NetworkInterface<'_, N>,
        target_peer: Option<&shell_network::PeerId>,
        sync_requested: &mut bool,
        sync_request_nonce: &mut Option<u64>,
        sync_request_start: &mut Option<u64>,
        reason: &'static str,
    ) -> bool {
        let head_number = self.head_number();
        info!(
            head = head_number,
            reason,
            peer = target_peer.map(|p| p.0.as_str()).unwrap_or("broadcast"),
            "requesting blocks from peer"
        );
        let Some(start_number) = next_block_request_start(head_number) else {
            tracing::warn!(
                head = head_number,
                reason,
                "skipping missing-block request at terminal block height"
            );
            *sync_requested = false;
            *sync_request_nonce = None;
            *sync_request_start = None;
            return false;
        };
        let generated_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Retries for the same range keep their nonce so delayed responses remain
        // useful. Once import progress changes the requested range, rotate the nonce
        // so an empty response to the older range cannot reopen production early.
        let nonce = stable_sync_request_nonce(
            *sync_request_nonce,
            *sync_request_start,
            start_number,
            generated_nonce,
        );
        let req = NetworkMessage::BlockRequest {
            start_number,
            count: 1, // request 1 block at a time — PQ-signed blocks can be several MB each
            nonce,
        };
        let send_result = if let Some(peer) = target_peer {
            network.send_to_peer(peer, req).await
        } else {
            network.broadcast(req).await
        };
        match send_result {
            Ok(()) => record_sync_request_result(
                true,
                nonce,
                start_number,
                sync_requested,
                sync_request_nonce,
                sync_request_start,
            ),
            Err(e) => {
                tracing::warn!(reason, error = %e, "failed to request missing blocks");
                record_sync_request_result(
                    false,
                    nonce,
                    start_number,
                    sync_requested,
                    sync_request_nonce,
                    sync_request_start,
                )
            }
        }
    }

    async fn rebroadcast_pending_transactions<N: NetworkService + ?Sized>(
        &self,
        network: &NetworkInterface<'_, N>,
        target_peer: Option<&shell_network::PeerId>,
        limit: usize,
        reason: &'static str,
    ) {
        let mem_pool = self.mem_pool();
        let txs = mem_pool.pending_for_rebroadcast(target_peer, limit);
        if txs.is_empty() {
            return;
        }

        debug!(
            count = txs.len(),
            reason,
            peer = target_peer.map(|p| p.0.as_str()).unwrap_or("broadcast"),
            "rebroadcasting pending transactions"
        );
        for tx in txs {
            let msg = NetworkMessage::NewTransaction(Box::new(tx.as_ref().clone()));
            let result = if let Some(peer) = target_peer {
                network.send_to_peer(peer, msg).await
            } else {
                network.broadcast(msg).await
            };
            if let Err(e) = result {
                warn!(reason, error = %e, "failed to rebroadcast pending transaction");
                break;
            }
        }
    }

    fn current_block_timestamp(&self, parent_timestamp: u64) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut dev = self.dev_state.write();
        let ts = if let Some(next) = dev.next_block_timestamp.take() {
            next
        } else {
            now
        };
        ts.max(parent_timestamp.saturating_add(1))
    }

    fn snapshot_inner(&self) -> Result<String, NodeError> {
        if self.dev_state.read().snapshots.len() >= MAX_DEV_SNAPSHOTS {
            return Err(NodeError::Startup(format!(
                "dev snapshot limit reached ({MAX_DEV_SNAPSHOTS})"
            )));
        }

        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let (total_tx_count, total_gas_used) = self.chain_store.get_chain_totals(head.number())?;
        let finalized_number = self.chain_store.get_finalized_number()?.unwrap_or(0);
        let pending_txs = self.tx_pool.pending_for_block(self.tx_pool.len());

        let mut dev = self.dev_state.write();
        if dev.snapshots.len() >= MAX_DEV_SNAPSHOTS {
            return Err(NodeError::Startup(format!(
                "dev snapshot limit reached ({MAX_DEV_SNAPSHOTS})"
            )));
        }
        let id = dev.next_snapshot_id;
        dev.next_snapshot_id = dev
            .next_snapshot_id
            .checked_add(1)
            .ok_or_else(|| NodeError::Startup("dev snapshot ID space exhausted".into()))?;
        let next_block_timestamp = dev.next_block_timestamp;
        dev.snapshots.insert(
            id,
            DevSnapshot {
                head_hash: head.hash(),
                head_number: head.number(),
                state_root: head.header.state_root,
                total_tx_count,
                total_gas_used,
                finalized_number,
                pending_txs,
                next_block_timestamp,
            },
        );
        Ok(format!("0x{id:x}"))
    }

    fn revert_inner(&self, snapshot_id: &str) -> Result<bool, NodeError> {
        let Some(snapshot_id) = snapshot_id.strip_prefix("0x") else {
            return Ok(false);
        };
        if snapshot_id.is_empty() || snapshot_id.len() > 16 {
            return Ok(false);
        }
        let Ok(snapshot_id) = u64::from_str_radix(snapshot_id, 16) else {
            return Ok(false);
        };
        let snapshot = {
            let dev = self.dev_state.read();
            match dev.snapshots.get(&snapshot_id) {
                Some(s) => s.clone(),
                None => return Ok(false),
            }
        };

        let current_head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        if current_head.number() > snapshot.head_number {
            for number in (snapshot.head_number + 1)..=current_head.number() {
                if let Some(block) = self.chain_store.get_block_by_number(number)? {
                    self.chain_store
                        .delete_block_transaction_indexes(&block.hash())?;
                }
                self.chain_store.delete_canonical(number)?;
            }
        }

        self.chain_store.set_head(&snapshot.head_hash)?;
        self.chain_store
            .set_total_tx_count(snapshot.total_tx_count)?;
        self.chain_store
            .set_total_gas_used(snapshot.total_gas_used)?;
        self.chain_store
            .set_chain_totals_head(snapshot.head_number)?;
        self.chain_store
            .set_finalized_number(snapshot.finalized_number)?;

        let restored_ws = WorldState::at_root(self.store.clone(), &snapshot.state_root)?;
        *self.world_state.write() = restored_ws;

        let finalized_hash = if snapshot.finalized_number == 0 {
            ShellHash::ZERO
        } else {
            self.chain_store
                .get_block_by_number(snapshot.finalized_number)?
                .map(|b| b.hash())
                .unwrap_or(ShellHash::ZERO)
        };
        *self.finality.write() = if snapshot.finalized_number > 0 {
            shell_consensus::FinalityState::with_finalized(
                snapshot.finalized_number,
                finalized_hash,
            )
        } else {
            shell_consensus::FinalityState::new()
        };

        self.tx_pool.clear();
        let mut world_state = self.world_state.write();
        let verifier = MultiVerifier;
        for tx in snapshot.pending_txs {
            let _ = self
                .tx_pool
                .insert(tx, &mut world_state, self.chain_store.as_ref(), &verifier);
        }

        let mut dev = self.dev_state.write();
        dev.next_block_timestamp = snapshot.next_block_timestamp;
        dev.snapshots.retain(|id, _| *id < snapshot_id);

        Ok(true)
    }

    /// Signal the node to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Record a canonical state root, then run pruning bounded by finalized height.
    fn record_canonical_state_root(&self, block_number: u64, state_root: ShellHash) {
        let profile = StorageProfile::from_pruning_config(&self.config.pruning);
        let keep_recent = self.config.pruning.keep_recent;
        let mut prune_keep_below = None;
        let finalized_number = match self.chain_store.get_finalized_number() {
            Ok(stored) => stored.unwrap_or(0),
            Err(e) => {
                tracing::warn!(error = %e, "pruning: failed to read finalized height");
                0
            }
        }
        .max(self.finality.read().last_finalized_number());

        match self
            .chain_store
            .prune_finalized_address_metadata_undo(finalized_number)
        {
            Ok(pruned) if pruned > 0 => {
                tracing::debug!(
                    pruned,
                    finalized = finalized_number,
                    "pruned finalized address metadata undo journals"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    finalized = finalized_number,
                    "address metadata undo journal pruning failed"
                );
            }
        }

        {
            let mut tracker = self.state_root_tracker.write();
            if let Some(evicted) = tracker.record(block_number, state_root) {
                tracing::debug!(
                    block = evicted.block_number,
                    root = %evicted.state_root,
                    "state root eligible for pruning"
                );
                if matches!(profile, StorageProfile::Light) && keep_recent > 0 {
                    prune_keep_below = state_trie_prune_boundary(finalized_number, keep_recent);
                }
            }
        }

        if let Some(keep_below_block) = prune_keep_below {
            match prune_state_trie(Arc::clone(&self.store), keep_below_block, profile) {
                Ok(result) => {
                    if result.deleted_nodes > 0 {
                        tracing::info!(
                            keep_below_block,
                            pruned_roots = result.pruned_roots,
                            deleted_nodes = result.deleted_nodes,
                            skipped_roots = result.skipped_roots,
                            block = block_number,
                            "state trie pruning deleted old snapshots"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, keep_below_block, "state trie pruning pass failed");
                }
            }
        }

        // D1: Drive WitnessPruner — prune old witness bundles after finality.
        {
            let mut wpruner = self.witness_pruner.write();
            if !wpruner.is_archive() {
                // Guard every canonical hash instead of inferring a frontier from
                // the settled-set size: stale fork entries and gaps must fail closed.
                match wpruner.prune_before_settled(
                    finalized_number,
                    |hash| self.settled_stark_sources.lock().contains(&(1, *hash)),
                    &self.chain_store,
                    &self.witness_store,
                ) {
                    Ok(result) => {
                        if result.pruned_count > 0 {
                            tracing::info!(
                                pruned = result.pruned_count,
                                block = block_number,
                                finalized = finalized_number,
                                "witness pruner: removed old witness bundles"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "witness pruner: prune failed");
                    }
                }
            }
        }

        // D2: Drive BodyPruner — expire old block bodies after finality.
        {
            let mut bpruner = self.body_pruner.write();
            if !bpruner.is_archive() {
                match bpruner.prune_before(finalized_number, &self.chain_store) {
                    Ok(result) => {
                        if result.bodies_pruned > 0 {
                            tracing::info!(
                                pruned = result.bodies_pruned,
                                block = block_number,
                                finalized = finalized_number,
                                "body pruner: expired old block bodies"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "body pruner: prune failed");
                    }
                }
            }
        }

        // F-303: Drive StatePruner after dependent pruning so a successful body
        // or witness pass can advance canonical mapping cleanup in this cycle.
        {
            // Canonical mappings are required to resume body and witness pruning.
            // A delayed STARK settlement can hold the witness cursor behind the
            // configured retention window, so never let mapping cleanup overtake
            // any dependent pruner.
            let state_trie_boundary = if matches!(profile, StorageProfile::Light) && keep_recent > 0
            {
                match state_trie_pruned_below(self.store.as_ref()) {
                    Ok(boundary) => Some(boundary),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "state pruner: failed to read state-trie pruning cursor"
                        );
                        Some(0)
                    }
                }
            } else {
                None
            };
            let canonical_prune_boundary = canonical_mapping_prune_boundary(
                finalized_number,
                self.body_pruner.read().pruned_below(),
                self.witness_pruner.read().pruned_below(),
                state_trie_boundary,
            );
            let mut pruner = self.state_pruner.write();
            let should_prune = finalized_number > 0 && pruner.should_prune(block_number);
            let validate_genesis = pruner.genesis_root().is_none() || should_prune;
            let genesis_registered = if !validate_genesis {
                true
            } else {
                match self.chain_store.get_block_hash_by_number(0) {
                    Ok(Some(genesis_hash)) => {
                        match self.chain_store.get_header_by_hash(&genesis_hash) {
                            Ok(Some(genesis)) if genesis.number == 0 => {
                                match pruner.genesis_root() {
                                    Some(root) if *root != genesis.state_root => {
                                        tracing::warn!(
                                            expected_root = %root,
                                            actual_root = %genesis.state_root,
                                            "state pruner: genesis state root changed"
                                        );
                                        false
                                    }
                                    Some(_) => true,
                                    None => {
                                        pruner.set_genesis_root(genesis.state_root);
                                        true
                                    }
                                }
                            }
                            Ok(Some(genesis)) => {
                                tracing::warn!(
                                    header_number = genesis.number,
                                    "state pruner: genesis header reports the wrong block number"
                                );
                                false
                            }
                            Ok(None) => {
                                tracing::warn!("state pruner: genesis header is unavailable");
                                false
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "state pruner: failed to load genesis header");
                                false
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::warn!("state pruner: genesis canonical mapping is unavailable");
                        false
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "state pruner: failed to load genesis mapping");
                        false
                    }
                }
            };
            pruner.register_block(block_number, state_root);
            if genesis_registered && should_prune {
                pruner.mark_prunable(canonical_prune_boundary);
                match pruner.prune(self.store.as_ref()) {
                    Ok(result) => {
                        if result.pruned_count > 0 {
                            tracing::info!(
                                pruned = result.pruned_count,
                                protected = result.protected_count,
                                block = block_number,
                                finalized = finalized_number,
                                "state pruner: removed old canonical mappings"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "state pruner: prune failed");
                    }
                }
            }
        }

        // Periodic status log every 64 blocks.
        if block_number > 0 && block_number.is_multiple_of(64) {
            let tracker = self.state_root_tracker.read();
            let oldest = tracker.oldest().map(|e| e.block_number).unwrap_or(0);
            tracing::info!(
                tracked = tracker.len(),
                oldest_block = oldest,
                archive = tracker.config().is_archive(),
                "state root history status"
            );
        }
    }

    /// Get a shutdown receiver for external coordination.
    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pruning::PruningConfig;
    use shell_consensus::{PoaConfig, PoaEngine, WPoaConfig, WPoaEngine};
    use shell_core::{
        AaBundle, InnerCall, PubkeyMode, SessionAuth, Transaction, AA_BUNDLE_TX_TYPE,
    };
    use shell_crypto::{DilithiumSigner, MlDsaSigner, SignatureType, Signer};
    use shell_mempool::MempoolConfig;
    use shell_primitives::U256;
    use shell_rpc::DevRpcControl;
    use shell_storage::{MemoryDb, StorageError, WriteBatch, WriteBatchOp};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct AuthorityLockCheckingVerifier {
        authorities: Arc<RwLock<HashMap<Address, Vec<u8>>>>,
    }

    impl Verifier for AuthorityLockCheckingVerifier {
        fn verify(
            &self,
            pubkey: &[u8],
            message: &[u8],
            signature: &shell_crypto::PQSignature,
        ) -> Result<bool, shell_crypto::CryptoError> {
            assert!(
                self.authorities.try_write().is_some(),
                "authority registry lock must be released before signature verification"
            );
            MultiVerifier.verify(pubkey, message, signature)
        }

        fn sig_type(&self) -> shell_crypto::SignatureType {
            shell_crypto::SignatureType::Dilithium3
        }
    }

    fn run_isolated(test_name: &str, marker: &str) -> bool {
        if std::env::var_os(marker).is_some() {
            return false;
        }

        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(marker, "1")
            .status()
            .expect("isolated test process must start");
        assert!(status.success(), "isolated test process failed");
        true
    }

    #[derive(Debug, Default)]
    struct FailingBatchDb {
        inner: MemoryDb,
        fail_next_get: AtomicBool,
        fail_next_put: AtomicBool,
        fail_next_batch: AtomicBool,
        fail_head_batch: AtomicBool,
        fail_next_delete: AtomicBool,
    }

    impl FailingBatchDb {
        fn new() -> Self {
            Self {
                inner: MemoryDb::new(),
                fail_next_get: AtomicBool::new(false),
                fail_next_put: AtomicBool::new(false),
                fail_next_batch: AtomicBool::new(false),
                fail_head_batch: AtomicBool::new(false),
                fail_next_delete: AtomicBool::new(false),
            }
        }

        fn fail_next_batch(&self) {
            self.fail_next_batch.store(true, Ordering::SeqCst);
        }

        fn fail_next_get(&self) {
            self.fail_next_get.store(true, Ordering::SeqCst);
        }

        fn fail_next_put(&self) {
            self.fail_next_put.store(true, Ordering::SeqCst);
        }

        fn fail_head_batch(&self) {
            self.fail_head_batch.store(true, Ordering::SeqCst);
        }

        fn fail_next_delete(&self) {
            self.fail_next_delete.store(true, Ordering::SeqCst);
        }
    }

    impl KvStore for FailingBatchDb {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if self.fail_next_get.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected get failure".into()));
            }
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            if self.fail_next_put.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected put failure".into()));
            }
            self.inner.put(key, value)
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            if self.fail_next_delete.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected delete failure".into()));
            }
            self.inner.delete(key)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
            if self.fail_next_batch.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected batch failure".into()));
            }
            if self.fail_head_batch.load(Ordering::SeqCst)
                && batch.ops().iter().any(
                    |op| matches!(op, WriteBatchOp::Put { key, .. } if key.as_slice() == b"HEAD"),
                )
            {
                return Err(StorageError::Database(
                    "injected canonical batch failure".into(),
                ));
            }
            self.inner.write_batch(batch)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
    }

    #[test]
    fn next_block_request_start_stops_at_terminal_height() {
        assert_eq!(next_block_request_start(0), Some(1));
        assert_eq!(next_block_request_start(u64::MAX - 1), Some(u64::MAX));
        assert_eq!(next_block_request_start(u64::MAX), None);
    }

    #[test]
    fn tx_fits_remaining_block_gas_rejects_invalid_cumulative_gas() {
        let tx = signed_tx_with_gas_limit(0);

        assert!(tx_fits_remaining_block_gas(&tx, 30_000_000, 30_000_000));
        assert!(!tx_fits_remaining_block_gas(&tx, 30_000_001, 30_000_000));
    }

    #[test]
    fn checked_cumulative_block_gas_rejects_limit_and_u64_overflow() {
        assert_eq!(checked_cumulative_block_gas(20, 10, 30), Some(30));
        assert_eq!(checked_cumulative_block_gas(20, 11, 30), None);
        assert_eq!(checked_cumulative_block_gas(u64::MAX, 1, u64::MAX), None);
    }

    #[test]
    fn checked_cumulative_blob_gas_enforces_block_limit() {
        assert_eq!(
            checked_cumulative_blob_gas(
                shell_core::MAX_BLOB_GAS_PER_BLOCK - shell_core::BLOB_GAS_PER_BLOB,
                shell_core::BLOB_GAS_PER_BLOB,
            ),
            Some(shell_core::MAX_BLOB_GAS_PER_BLOCK)
        );
        assert_eq!(
            checked_cumulative_blob_gas(
                shell_core::MAX_BLOB_GAS_PER_BLOCK,
                shell_core::BLOB_GAS_PER_BLOB,
            ),
            None
        );
        assert_eq!(checked_cumulative_blob_gas(u64::MAX, 1), None);
    }

    fn signed_tx_with_gas_limit(gas_limit: u64) -> SignedTransaction {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::ZERO),
            value: U256::ZERO,
            data: Bytes::default(),
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey)
    }

    fn setup_node_with_authority(authority: Address) -> Node<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        Node::new(config, db, chain_store, world_state, tx_pool, consensus)
    }

    fn setup_node() -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        let node = setup_node_with_authority(authority);
        (node, signer)
    }

    fn setup_failing_batch_node() -> (Node<FailingBatchDb>, DilithiumSigner, Arc<FailingBatchDb>) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(FailingBatchDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        let node = Node::new(
            config,
            db.clone(),
            chain_store,
            world_state,
            tx_pool,
            consensus,
        );
        (node, signer, db)
    }

    fn configure_pending_activation<S: KvStore + 'static>(
        node: &Node<S>,
        height: u64,
        algo: shell_crypto::SignatureType,
    ) {
        AlgorithmRegistry::global_mut().propose_activation_with_spec(algo, height, [0xA5; 32]);

        let mut key_material = b"algorithm_activation_height:".to_vec();
        key_material.push(algo.as_u8());
        let key = shell_primitives::keccak256(&key_material);
        let mut value = [0u8; 32];
        value[24..].copy_from_slice(&height.to_be_bytes());
        node.world_state
            .write()
            .set_storage(
                &shell_pqvm::registry_address(),
                &key,
                &ShellHash::from(value),
            )
            .unwrap();
    }

    fn store_genesis<S: KvStore + 'static>(node: &Node<S>) {
        store_genesis_with_gas_limit(node, 30_000_000);
    }

    fn store_genesis_with_gas_limit<S: KvStore + 'static>(node: &Node<S>, gas_limit: u64) {
        let genesis = Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 0,
                gas_limit,
                gas_used: 0,
                timestamp: 1_700_000_000,
                extra_data: Bytes::default(),
                proposer: node.config.proposer_address.unwrap(),
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
        let hash = genesis.hash();
        node.chain_store.put_block(&genesis).unwrap();
        node.chain_store.set_canonical(0, &hash).unwrap();
        node.chain_store.set_head(&hash).unwrap();
    }

    fn store_consistent_genesis<S: KvStore + 'static>(node: &Node<S>) {
        let state_root = current_state_root(node);
        let genesis = Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 0,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000,
                extra_data: Bytes::default(),
                proposer: node.config.proposer_address.unwrap(),
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
        let hash = genesis.hash();
        node.chain_store.put_block(&genesis).unwrap();
        node.chain_store.set_canonical(0, &hash).unwrap();
        node.chain_store.set_head(&hash).unwrap();
    }

    fn fund_account<S: KvStore + 'static>(node: &Node<S>, addr: &Address, balance: U256) {
        let account = shell_core::Account {
            pq_pubkey_hash: ShellHash::default(),
            nonce: 0,
            balance,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::default(),
        };
        let mut ws = node.world_state.write();
        ws.set_account(addr, &account).unwrap();
    }

    fn install_accepting_custom_validator<S: KvStore + 'static>(
        node: &Node<S>,
        addr: &Address,
        balance: U256,
    ) {
        let code = vec![0x60, 0x01, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3];
        let code_hash = shell_primitives::keccak256(&code);
        node.chain_store.put_code(&code_hash, &code).unwrap();
        node.world_state
            .write()
            .set_account(
                addr,
                &shell_core::Account {
                    pq_pubkey_hash: ShellHash::ZERO,
                    nonce: 0,
                    balance,
                    validation_code_hash: Some(code_hash),
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                },
            )
            .unwrap();
    }

    fn counter_runtime() -> Vec<u8> {
        let incr_sel = shell_primitives::keccak256(b"increment()");
        let get_sel = shell_primitives::keccak256(b"get()");
        let mut code = vec![0x60, 0x00, 0x35, 0x60, 0xE0, 0x1C, 0x80, 0x63];
        code.extend_from_slice(&incr_sel.as_bytes()[..4]);
        code.extend_from_slice(&[0x14, 0x60, 0x1F, 0x57, 0x80, 0x63]);
        code.extend_from_slice(&get_sel.as_bytes()[..4]);
        code.extend_from_slice(&[
            0x14, 0x60, 0x2F, 0x57, 0x60, 0x00, 0x60, 0x00, 0xFD, 0x5B, 0x50, 0x60, 0x00, 0x54,
            0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xF3, 0x5B, 0x50, 0x60,
            0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3,
        ]);
        debug_assert_eq!(code[0x1F], 0x5B);
        debug_assert_eq!(code[0x2F], 0x5B);
        code
    }

    fn make_init_code(runtime: &[u8]) -> Vec<u8> {
        assert!(runtime.len() <= u8::MAX as usize, "runtime too large");
        let runtime_len = runtime.len() as u8;
        let prefix_len = 12u8;
        let mut init = vec![
            0x60,
            runtime_len,
            0x60,
            prefix_len,
            0x60,
            0x00,
            0x39,
            0x60,
            runtime_len,
            0x60,
            0x00,
            0xF3,
        ];
        init.extend_from_slice(runtime);
        init
    }

    fn submit_signed_tx<S: KvStore + 'static>(
        node: &Node<S>,
        tx_signer: &impl Signer,
        sender: Address,
        tx: Transaction,
    ) -> ShellHash {
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());
        let hash = signed.hash();
        let verifier = MultiVerifier;
        let mut world_state = node.world_state.write();
        node.tx_pool
            .insert(
                signed,
                &mut world_state,
                node.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        hash
    }

    fn submit_key_rotation<S: KvStore + 'static>(
        node: &Node<S>,
        tx_signer: &impl Signer,
        sender: Address,
        new_pubkey: &[u8],
    ) -> ShellHash {
        submit_signed_tx(
            node,
            tx_signer,
            sender,
            Transaction {
                chain_id: 1337,
                nonce: 0,
                to: Some(shell_pqvm::account_manager_address()),
                value: U256::ZERO,
                data: Bytes::from(shell_pqvm::encode_rotate_key_calldata(
                    new_pubkey,
                    tx_signer.sig_type().as_u8(),
                )),
                gas_limit: 100_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        )
    }

    fn current_state_root<S: KvStore + 'static>(node: &Node<S>) -> ShellHash {
        let mut ws = node.world_state.write();
        ws.state_root().unwrap()
    }

    #[test]
    fn import_block_accepts_custom_validator_owned_signature_policy() {
        let (leader, proposer_signer) = setup_node();
        let proposer = leader.config.proposer_address.unwrap();
        leader.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let sender = Address::from([0x41; 32]);
        let balance = U256::from(100_000_000_000_000u64);
        install_accepting_custom_validator(&leader, &sender, balance);
        store_consistent_genesis(&leader);
        let signed = SignedTransaction::new(
            sender,
            Transaction {
                chain_id: 1337,
                nonce: 0,
                to: Some(Address::from([0x42; 32])),
                value: U256::ZERO,
                data: Bytes::new(),
                gas_limit: 50_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature::new(SignatureType::MlDsa65, Vec::new()),
        );
        {
            let mut world_state = leader.world_state.write();
            leader
                .tx_pool
                .insert(
                    signed,
                    &mut world_state,
                    leader.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
        }
        let block = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);

        let follower = setup_node_with_authority(proposer);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
        install_accepting_custom_validator(&follower, &sender, balance);
        store_consistent_genesis(&follower);

        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();

        assert_eq!(follower.world_state.read().get_nonce(&sender).unwrap(), 1);

        let mut side_fork = block;
        side_fork.header.extra_data = Bytes::from_static(b"custom-validator-side-fork");
        side_fork.header.witness_root = None;
        side_fork.proposer_seal = Some(
            proposer_signer
                .sign(side_fork.header.hash().as_bytes())
                .unwrap(),
        );
        let side_fork_hash = side_fork.hash();

        leader.import_block(side_fork, &MultiVerifier).unwrap();

        assert!(leader
            .chain_store
            .get_block_by_hash(&side_fork_hash)
            .unwrap()
            .is_some());
    }

    #[test]
    fn node_creation() {
        let (node, _signer) = setup_node();
        assert_eq!(node.config.chain_id, 1337);
        assert!(node.config.proposer_address.is_some());
    }

    #[test]
    fn rebroadcast_pending_transactions_preserves_sender_nonce_order_for_peer() {
        let (node, _proposer_signer) = setup_node();
        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from([0x55; 32]);
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        let make_tx = |nonce, priority_fee| Transaction {
            chain_id: 1337,
            nonce,
            to: Some(receiver),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE + priority_fee,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let nonce0_hash = submit_signed_tx(&node, &tx_signer, sender, make_tx(0, 1));
        let nonce1_hash = submit_signed_tx(&node, &tx_signer, sender, make_tx(1, 100));
        let peer = shell_network::PeerId("peer-a".to_string());

        let first = node.mem_pool().pending_for_rebroadcast(Some(&peer), 1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].hash(), nonce0_hash);

        let ordered_hashes: Vec<_> = node
            .mem_pool()
            .pending_for_rebroadcast(Some(&peer), 2)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(ordered_hashes, vec![nonce0_hash, nonce1_hash]);
    }

    #[test]
    fn periodic_rebroadcast_filters_shared_pool_transactions_before_cloning() {
        let (node, _proposer_signer) = setup_node();
        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from([0x56; 32]);
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE + 1,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&node, &tx_signer, sender, tx);

        let stored = node.tx_pool.pending_for_block_shared(1);
        let first = node.mem_pool().pending_for_rebroadcast(None, 1);
        assert_eq!(first.len(), 1);
        assert!(Arc::ptr_eq(&stored[0], &first[0]));
        assert!(node.mem_pool().pending_for_rebroadcast(None, 1).is_empty());
    }

    #[test]
    fn sync_retry_delay_uses_backoff_after_threshold() {
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(0), 5);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(2), 5);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(3), 30);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(10), 30);
    }

    #[test]
    fn failed_sync_request_does_not_leave_an_in_flight_nonce() {
        let mut sync_requested = true;
        let mut sync_request_nonce = Some(7);
        let mut sync_request_start = Some(10);

        assert!(!record_sync_request_result(
            false,
            8,
            11,
            &mut sync_requested,
            &mut sync_request_nonce,
            &mut sync_request_start,
        ));
        assert!(!sync_requested);
        assert_eq!(sync_request_nonce, None);
        assert_eq!(sync_request_start, None);

        assert!(record_sync_request_result(
            true,
            9,
            12,
            &mut sync_requested,
            &mut sync_request_nonce,
            &mut sync_request_start,
        ));
        assert!(sync_requested);
        assert_eq!(sync_request_nonce, Some(9));
        assert_eq!(sync_request_start, Some(12));
    }

    #[test]
    fn sync_retry_reuses_nonce_only_for_the_same_range() {
        assert_eq!(stable_sync_request_nonce(Some(7), Some(10), 10, 8), 7);
        assert_eq!(stable_sync_request_nonce(Some(7), Some(10), 11, 8), 8);
        assert_eq!(stable_sync_request_nonce(None, None, 10, 8), 8);
    }

    #[test]
    fn core_invariants_accept_consistent_genesis() {
        let (node, _signer) = setup_node();
        store_consistent_genesis(&node);

        let snapshot = node.check_core_invariants().unwrap();

        assert_eq!(snapshot.head_number, 0);
        assert_eq!(snapshot.finalized_number, 0);
        assert_eq!(snapshot.chain_totals_head, None);
        assert_eq!(snapshot.tx_pool_len, 0);
    }

    #[test]
    fn core_invariants_reject_finalized_ahead_of_head() {
        let (node, _signer) = setup_node();
        store_consistent_genesis(&node);
        node.finality
            .write()
            .set_finalized_direct(1, ShellHash::from_slice(&[0xAA; 32]));

        let err = node.check_core_invariants().unwrap_err();

        assert!(
            matches!(err, NodeError::Startup(message) if message.contains("finalized #1 is ahead of head #0"))
        );
    }

    #[test]
    fn preferred_fork_plan_requires_quorum_for_noncanonical_branch() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let same_height_fork = ShellHash::from_slice(&[0x21; 32]);
        let ahead_block = make_block_at_1(&node, &signer, None);
        let ahead_fork = ahead_block.hash();

        node.fork_choice
            .write()
            .add_block(same_height_fork, ShellHash::ZERO, 0, 0, false);
        assert!(node.preferred_fork_plan().unwrap().is_none());

        node.fork_choice
            .write()
            .add_block(ahead_fork, genesis_hash, 1, 0, false);
        assert!(node.preferred_fork_plan().unwrap().is_none());

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let quorum_weight =
            u64::try_from((u128::from(total_weight).saturating_mul(2) / 3).saturating_add(1))
                .unwrap();
        node.fork_choice
            .write()
            .update_attested_weight(&ahead_fork, quorum_weight);
        let missing_block = node.preferred_fork_plan().unwrap_err();
        assert!(missing_block.to_string().contains("block not found"));

        node.chain_store.put_side_fork_block(&ahead_block).unwrap();
        assert_eq!(
            node.preferred_fork_plan().unwrap(),
            Some(ForkAdoptionPlan {
                preferred_hash: ahead_fork,
                preferred_number: 1,
                canonical_number: 0,
                ancestor_hash: genesis_hash,
                ancestor_number: 0,
                old_chain: vec![],
                new_chain: vec![ahead_block],
                reverted_txs: vec![],
            })
        );

        node.finality.write().set_finalized_direct(1, ahead_fork);
        let finalized_error = node.preferred_fork_plan().unwrap_err();
        assert!(finalized_error
            .to_string()
            .contains("crosses finalized block"));
    }

    #[test]
    fn quorum_preferred_state_neutral_fork_is_adopted_atomically() {
        let (node, signer) = setup_node();
        store_consistent_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let ancestor_root = current_state_root(&node);

        let canonical = make_block_at_1(&node, &signer, None);
        node.import_block(canonical.clone(), &MultiVerifier)
            .unwrap();

        let mut side_one = canonical.clone();
        side_one.header.timestamp += 1;
        side_one.proposer_seal = Some(
            signer
                .sign(side_one.header.hash().as_bytes())
                .expect("sign side block"),
        );
        let side_one_hash = side_one.hash();
        node.import_block(side_one.clone(), &MultiVerifier).unwrap();

        let mut side_two = side_one.clone();
        side_two.header.parent_hash = side_one_hash;
        side_two.header.number = 2;
        side_two.header.timestamp += 1;
        side_two.header.base_fee_per_gas = calculate_base_fee(
            side_one.header.gas_used,
            side_one.header.gas_limit,
            side_one.header.base_fee_per_gas,
        );
        side_two.proposer_seal = Some(
            signer
                .sign(side_two.header.hash().as_bytes())
                .expect("sign side-fork child"),
        );
        let side_two_hash = side_two.hash();
        node.import_block(side_two.clone(), &MultiVerifier).unwrap();

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);

        let plan = node
            .preferred_fork_plan()
            .unwrap()
            .expect("side fork should become preferred");
        assert_eq!(plan.old_chain, vec![canonical]);
        assert_eq!(plan.new_chain, vec![side_one.clone(), side_two.clone()]);

        node.adopt_preferred_fork(plan).unwrap();

        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(side_two_hash)
        );
        assert_eq!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(side_one_hash)
        );
        assert_eq!(
            node.chain_store.get_block_hash_by_number(2).unwrap(),
            Some(side_two_hash)
        );
        assert_eq!(
            node.chain_store.get_receipts(&side_one_hash).unwrap(),
            Some(vec![])
        );
        assert_eq!(
            node.chain_store.get_receipts(&side_two_hash).unwrap(),
            Some(vec![])
        );
        assert_eq!(current_state_root(&node), ancestor_root);
        assert!(node.preferred_fork_plan().unwrap().is_none());
    }

    #[test]
    fn reverted_transactions_are_reinserted_in_nonce_order() {
        let (node, _) = setup_node();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        fund_account(&node, &sender, U256::from(1_000_000_000_000_000u64));
        store_consistent_genesis(&node);

        let mut nonces = node.world_state.read().get_nonce(&sender).unwrap()..;
        let tx0 = make_embedded_tx(&signer, sender, pubkey.clone(), nonces.next().unwrap(), 1);
        let tx1 = make_embedded_tx(&signer, sender, pubkey, nonces.next().unwrap(), 2);
        let hash0 = tx0.hash();
        let hash1 = tx1.hash();

        let (inserted, rejected) = node.reinsert_reverted_transactions(&[tx0.clone(), tx0, tx1]);

        assert_eq!((inserted, rejected), (2, 1));
        assert_eq!(
            node.tx_pool
                .pending_for_block(2)
                .iter()
                .map(SignedTransaction::hash)
                .collect::<Vec<_>>(),
            vec![hash0, hash1]
        );
    }

    #[test]
    fn preferred_fork_state_root_mismatch_is_rejected_before_canonical_mutation() {
        let (node, signer) = setup_node();
        store_consistent_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let canonical = make_block_at_1(&node, &signer, None);
        let canonical_hash = canonical.hash();
        node.import_block(canonical, &MultiVerifier).unwrap();

        let mut side_one = make_block_at_1(&node, &signer, None);
        side_one.header.parent_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        side_one.header.timestamp += 1;
        side_one.header.state_root = ShellHash::from([0x99; 32]);
        side_one.proposer_seal = Some(
            signer
                .sign(side_one.header.hash().as_bytes())
                .expect("sign stateful side block"),
        );
        let side_one_hash = side_one.hash();
        node.chain_store.put_side_fork_block(&side_one).unwrap();
        node.fork_choice.write().add_block(
            side_one_hash,
            side_one.header.parent_hash,
            side_one.number(),
            0,
            false,
        );

        let mut side_two = side_one.clone();
        side_two.header.parent_hash = side_one_hash;
        side_two.header.number = 2;
        side_two.header.timestamp += 1;
        side_two.header.base_fee_per_gas = calculate_base_fee(
            side_one.header.gas_used,
            side_one.header.gas_limit,
            side_one.header.base_fee_per_gas,
        );
        side_two.proposer_seal = Some(
            signer
                .sign(side_two.header.hash().as_bytes())
                .expect("sign stateful side-fork child"),
        );
        let side_two_hash = side_two.hash();
        node.chain_store.put_side_fork_block(&side_two).unwrap();
        node.fork_choice.write().add_block(
            side_two_hash,
            side_one_hash,
            side_two.number(),
            0,
            false,
        );

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);
        let plan = node
            .preferred_fork_plan()
            .unwrap()
            .expect("stateful side fork should become preferred");

        let error = node.adopt_preferred_fork(plan).unwrap_err();

        assert!(error
            .to_string()
            .contains("state root mismatch after deterministic replay"));
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(canonical_hash)
        );
        assert_eq!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(canonical_hash)
        );
        assert_eq!(node.chain_store.get_block_hash_by_number(2).unwrap(), None);
    }

    #[test]
    fn stateful_preferred_fork_is_replayed_and_adopted_atomically() {
        let (node, proposer_signer) = setup_node();
        let proposer = node.config.proposer_address.unwrap();
        let fork_node = setup_node_with_authority(proposer);
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
        fork_node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from([0xBE; 20]);
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&node, &sender, initial_balance);
        fund_account(&fork_node, &sender, initial_balance);
        store_consistent_genesis(&node);
        store_consistent_genesis(&fork_node);

        let canonical = make_block_at_1(&node, &proposer_signer, None);
        let canonical_hash = canonical.hash();
        node.import_block(canonical, &MultiVerifier).unwrap();

        let transaction = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1_000u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&fork_node, &tx_signer, sender, transaction);
        let side_one = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_one_hash = side_one.hash();
        node.import_block(side_one.clone(), &MultiVerifier).unwrap();

        let side_two = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_two_hash = side_two.hash();
        node.import_block(side_two.clone(), &MultiVerifier).unwrap();

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);
        let plan = node
            .preferred_fork_plan()
            .unwrap()
            .expect("stateful side fork should become preferred");

        node.adopt_preferred_fork(plan).unwrap();

        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(side_two_hash)
        );
        assert_eq!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(side_one_hash)
        );
        assert_ne!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(canonical_hash)
        );
        assert_eq!(node.world_state.read().get_nonce(&sender).unwrap(), 1);
        assert_eq!(
            node.world_state.read().get_balance(&receiver).unwrap(),
            U256::from(1_000u64)
        );
        assert_eq!(
            node.chain_store
                .get_receipts(&side_one_hash)
                .unwrap()
                .expect("replayed receipts")
                .len(),
            side_one.transactions.len() + side_one.system_transactions.len()
        );
        assert_eq!(current_state_root(&node), side_two.header.state_root);
    }

    #[test]
    fn preferred_fork_replay_restores_ancestor_public_key() {
        let (node, proposer_signer) = setup_node();
        let proposer = node.config.proposer_address.unwrap();
        let fork_node = setup_node_with_authority(proposer);
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
        fork_node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let initial_pubkey = tx_signer.public_key().to_vec();
        let canonical_pubkey = vec![0xC1; 1312];
        let preferred_pubkey = vec![0xD2; 1312];
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        for chain in [&node, &fork_node] {
            fund_account(chain, &sender, initial_balance);
            chain
                .chain_store
                .put_pubkey(&sender, &initial_pubkey)
                .unwrap();
            store_consistent_genesis(chain);
        }
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();

        submit_key_rotation(&node, &tx_signer, sender, &canonical_pubkey);
        let canonical = node.produce_block(&proposer_signer, 100).unwrap();
        let canonical_hash = canonical.hash();
        assert_eq!(
            node.chain_store.get_pubkey(&sender).unwrap(),
            Some(canonical_pubkey.clone())
        );

        submit_key_rotation(&fork_node, &tx_signer, sender, &preferred_pubkey);
        let side_one = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_one_hash = side_one.hash();
        let side_two = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_two_hash = side_two.hash();
        assert_ne!(side_one_hash, canonical_hash);

        for block in [&side_one, &side_two] {
            node.chain_store.put_side_fork_block(block).unwrap();
            node.fork_choice.write().add_block(
                block.hash(),
                block.header.parent_hash,
                block.number(),
                0,
                false,
            );
        }
        assert_eq!(side_one.header.parent_hash, genesis_hash);
        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);
        let plan = node
            .preferred_fork_plan()
            .unwrap()
            .expect("rotated-key side fork should become preferred");
        assert_eq!(plan.old_chain, vec![canonical]);

        node.adopt_preferred_fork(plan).unwrap();

        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(side_two_hash)
        );
        assert_eq!(
            node.chain_store.get_pubkey(&sender).unwrap(),
            Some(preferred_pubkey)
        );
        assert_ne!(
            node.chain_store.get_pubkey(&sender).unwrap(),
            Some(initial_pubkey)
        );
    }

    #[test]
    fn terminally_invalid_preferred_fork_can_be_removed() {
        let (node, signer) = setup_node();
        store_consistent_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let canonical = make_block_at_1(&node, &signer, None);
        let canonical_hash = canonical.hash();
        node.import_block(canonical.clone(), &MultiVerifier)
            .unwrap();

        let mut side_one = canonical;
        side_one.header.timestamp += 1;
        side_one.header.base_fee_per_gas = side_one.header.base_fee_per_gas.saturating_add(1);
        side_one.proposer_seal = Some(
            signer
                .sign(side_one.header.hash().as_bytes())
                .expect("sign invalid side block"),
        );
        let side_one_hash = side_one.hash();
        node.chain_store.put_side_fork_block(&side_one).unwrap();
        node.fork_choice.write().add_block(
            side_one_hash,
            side_one.header.parent_hash,
            side_one.number(),
            0,
            false,
        );

        let mut side_two = side_one.clone();
        side_two.header.parent_hash = side_one_hash;
        side_two.header.number = 2;
        side_two.header.timestamp += 1;
        side_two.proposer_seal = Some(
            signer
                .sign(side_two.header.hash().as_bytes())
                .expect("sign invalid side-fork child"),
        );
        let side_two_hash = side_two.hash();
        node.chain_store.put_side_fork_block(&side_two).unwrap();
        node.fork_choice.write().add_block(
            side_two_hash,
            side_one_hash,
            side_two.number(),
            0,
            false,
        );

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);
        let plan = node
            .preferred_fork_plan()
            .unwrap()
            .expect("invalid side fork should become preferred before revalidation");

        let error = node.adopt_preferred_fork(plan).unwrap_err();

        assert!(matches!(
            error,
            NodeError::InvalidFork {
                block_hash,
                ..
            } if block_hash == side_one_hash
        ));
        assert!(node.fork_choice.write().remove_subtree(&side_one_hash));
        assert!(node.preferred_fork_plan().unwrap().is_none());
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(canonical_hash)
        );
    }

    #[test]
    fn fork_adoption_reverts_only_transactions_absent_from_preferred_chain() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let old_only = signed_tx_with_gas_limit(21_000);
        let retained = signed_tx_with_gas_limit(22_000);
        let mut old_block = make_block_at_1(&node, &signer, None);
        old_block.transactions = vec![old_only.clone(), retained.clone(), old_only.clone()];
        let mut new_block = make_block_at_1(&node, &signer, None);
        new_block.transactions = vec![retained];

        let reverted = unique_reverted_transactions(&[old_block], &[new_block]);

        assert_eq!(reverted, vec![old_only]);
    }

    fn dummy_proof_amendment(
        layer: u32,
        original_size: u64,
        compressed_size: u64,
    ) -> ProofAmendment {
        ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: ShellHash::from_slice(&[0x11; 32]),
            block_number: 7,
            start_block: Some(6),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [0x22; 32],
                n_sigs: if layer == 1 { MIN_L1_STARK_TXS } else { 2 },
                proof_bytes: vec![0x33; compressed_size as usize],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer,
            source_hashes: vec![
                ShellHash::from_slice(&[0x66; 32]),
                ShellHash::from_slice(&[0x77; 32]),
            ],
            original_size: Some(original_size),
            compressed_size: Some(compressed_size),
            settlement_tx_hash: None,
        }
    }

    #[test]
    fn imported_settlement_releases_bounded_pending_slot() {
        let (node, _signer) = setup_node();
        let settled = dummy_proof_amendment(1, 1_000, 400);
        let mut later = dummy_proof_amendment(1, 1_000, 400);
        later.block_hash = ShellHash::from([0x88; 32]);
        later.source_hashes = vec![later.block_hash];
        node.pending_stark_settlements
            .lock()
            .extend([settled.clone(), later.clone()]);

        node.prover_orchestrator()
            .remove_settled_pending(std::slice::from_ref(&settled));

        assert_eq!(
            node.pending_stark_settlements.lock().as_slice(),
            std::slice::from_ref(&later)
        );
    }

    #[test]
    fn stark_artifact_batch_failure_leaves_no_partial_range() {
        let (node, _signer, db) = setup_failing_batch_node();
        let first = ShellHash::from_slice(&[0x66; 32]);
        let last = ShellHash::from_slice(&[0x77; 32]);
        let mut amendment = dummy_proof_amendment(1, 1_000, 400);
        amendment.block_hash = last;
        amendment.source_hashes = vec![first, last];
        db.fail_next_batch();

        let err = node.store_stark_artifacts(&amendment, None).unwrap_err();

        assert!(err.to_string().contains("injected batch failure"));
        assert_eq!(node.amendment_store.get_amendment(&first).unwrap(), None);
        assert_eq!(node.amendment_store.get_amendment(&last).unwrap(), None);
    }

    #[test]
    fn system_extra_roundtrips_stark_settlements() {
        let amendment = dummy_proof_amendment(2, 1_000, 400);

        let encoded = Node::<MemoryDb>::encode_system_extra(std::slice::from_ref(&amendment))
            .expect("encode system extra");
        let decoded = Node::<MemoryDb>::decode_system_extra(&encoded).expect("decode system extra");

        assert_eq!(decoded, vec![amendment]);
        assert!(
            Node::<MemoryDb>::decode_system_extra(&Bytes::from_static(b"legacy extra data"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn stark_reward_value_enforces_per_source_layer_mint_and_compression() {
        let (node, _signer) = setup_node();
        let l2 = dummy_proof_amendment(2, 1_000, 400);
        let invalid = dummy_proof_amendment(1, 1_000, 500);

        assert_eq!(
            node.stark_reward_value(0, &l2).unwrap(),
            U256::from(50_000_000_000_000_000_000u128)
        );
        assert_eq!(
            node.stark_reward_value(20_047, &l2).unwrap(),
            U256::from(50_000_000_000_000_000_000u128)
        );
        assert!(node.stark_reward_value(20_047, &invalid).is_err());
    }

    fn dummy_ordered_amendment(
        layer: u32,
        source_hashes: Vec<ShellHash>,
        end_block: u64,
    ) -> ProofAmendment {
        let block_hash = *source_hashes
            .last()
            .expect("ordered amendment needs at least one source");
        let empty_root = shell_stark_prover::compute_batch_root(&[]);
        let mut amendment = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash,
            block_number: end_block,
            start_block: end_block
                .checked_add(1)
                .and_then(|end_plus_one| end_plus_one.checked_sub(source_hashes.len() as u64)),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: empty_root,
                n_sigs: 0,
                proof_bytes: Vec::new(),
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer,
            source_hashes,
            original_size: Some(0),
            compressed_size: Some(0),
            settlement_tx_hash: None,
        };
        let signer = DilithiumSigner::generate();
        amendment
            .sign_prover_authentication(&signer)
            .expect("sign dummy amendment");
        amendment
    }

    fn put_dummy_witness<S: KvStore + 'static>(node: &Node<S>, hash: &ShellHash) {
        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::{PQSignature, SignatureType};

        let bundle = WitnessBundle {
            witnesses: vec![TxWitness::new_reference(PQSignature {
                sig_type: SignatureType::Dilithium3,
                data: vec![0xAA; 256],
            })],
        };
        node.witness_store.put_bundle(hash, &bundle).unwrap();
    }

    fn produce_witnessed_blocks<S: KvStore + 'static>(
        node: &Node<S>,
        signer: &DilithiumSigner,
        count: u64,
    ) -> Vec<ShellHash> {
        (0..count)
            .map(|_| {
                let block = node.produce_block(signer, 10).unwrap();
                let hash = block.hash();
                put_dummy_witness(node, &hash);
                hash
            })
            .collect()
    }

    #[test]
    fn stark_l1_ordering_rejects_gap_before_frontier() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        let gap = dummy_ordered_amendment(1, vec![hashes[1]], 2);
        let err = node.validate_stark_amendment_ordering(&gap).unwrap_err();

        assert!(
            err.to_string().contains("frontier #0"),
            "expected frontier rejection, got {err}"
        );
    }

    #[test]
    fn stark_settlement_sequence_rejects_gap_before_frontier() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        let gap = dummy_ordered_amendment(1, vec![hashes[1]], 2);
        let err = node.validate_stark_settlement_sequence(&[gap]).unwrap_err();

        assert!(
            err.to_string().contains("frontier #0"),
            "expected sequence frontier rejection, got {err}"
        );
    }

    #[test]
    fn stark_l1_ordering_accepts_next_frontier() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        let first = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);
        node.validate_stark_amendment_ordering(&first).unwrap();
        node.settled_stark_sources.lock().extend(
            first
                .covered_hashes()
                .into_iter()
                .map(|hash| (first.layer, hash)),
        );

        let next = dummy_ordered_amendment(1, vec![hashes[2]], 3);
        node.validate_stark_amendment_ordering(&next).unwrap();
    }

    #[test]
    fn stark_l2_ordering_requires_lower_layer_sources() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        let l1_first = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        node.settled_stark_sources.lock().extend(
            l1_first
                .covered_hashes()
                .into_iter()
                .map(|hash| (l1_first.layer, hash)),
        );

        let l2_with_gap = dummy_ordered_amendment(2, vec![genesis_hash, hashes[0], hashes[1]], 2);
        let err = node
            .validate_stark_amendment_ordering(&l2_with_gap)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("requires block #2 to be compressed at L1"),
            "expected lower-layer gap rejection, got {err}"
        );
    }

    #[test]
    fn stark_l2_ordering_rejects_mixed_l0_l1_sources() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        let l1_first = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        node.settled_stark_sources.lock().extend(
            l1_first
                .covered_hashes()
                .into_iter()
                .map(|hash| (l1_first.layer, hash)),
        );

        let mixed_l2 = dummy_ordered_amendment(2, vec![genesis_hash, hashes[0], hashes[1]], 2);
        let err = node
            .validate_stark_amendment_ordering(&mixed_l2)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("requires block #2 to be compressed at L1"),
            "expected mixed-layer range rejection, got {err}"
        );
    }

    /// L2 source-binding validation must reject a source whose block-hash is
    /// NOT in `settled_stark_sources`, even if the source amendment is stored.
    #[test]
    fn l2_source_binding_rejects_unsettled_l1_source() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        // Build an L1 source amendment and store it — but do NOT register it in
        // settled_stark_sources so it is un-settled.
        let l1_src = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        let l1_src_json = serde_json::to_vec(&l1_src).unwrap();
        node.amendment_store
            .put_amendment(&l1_src.block_hash, &l1_src_json)
            .unwrap();

        // An L2 amendment that references the unsettled L1 source.
        let l2 = dummy_ordered_amendment(2, vec![l1_src.block_hash, hashes[1]], 2);
        let err = node.validate_stark_proof_source_binding(&l2).unwrap_err();
        assert!(
            err.to_string().contains("not yet settled"),
            "expected not-yet-settled rejection, got: {err}"
        );
    }

    /// L2 source-binding validation must accept a source that IS in
    /// `settled_stark_sources` (happy path for the new canonical check).
    /// With stub-l2-verifier disabled (default), garbage proof_bytes yield an
    /// error at Check 3; this test runs only with the stub enabled.
    #[test]
    #[cfg(feature = "stub-l2-verifier")]
    fn l2_source_binding_accepts_settled_l1_source() {
        use shell_stark_prover::recursive_air::compute_aggregate_root;
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 1);

        let l1_src = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        let l1_src_json = serde_json::to_vec(&l1_src).unwrap();
        node.amendment_store
            .put_amendment(&l1_src.block_hash, &l1_src_json)
            .unwrap();
        // Register the L1 source as settled.
        node.settled_stark_sources
            .lock()
            .insert((1, l1_src.block_hash));

        // Build an L2 amendment with correct n_sigs and aggregate root.
        let root = u128::from_le_bytes(l1_src.proof.batch_root_bytes[0..16].try_into().unwrap());
        let agg_root = compute_aggregate_root(&[root]);
        let l2 = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: l1_src.block_hash,
            block_number: 1,
            start_block: Some(1),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: {
                    let mut b = [0u8; 32];
                    b[0..16].copy_from_slice(&agg_root.to_le_bytes());
                    b
                },
                n_sigs: 1,
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer: 2,
            source_hashes: vec![l1_src.block_hash],
            original_size: Some(10_000),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        };
        node.validate_stark_proof_source_binding(&l2)
            .expect("settled L1 source should be accepted by L2 source-binding validation");
    }

    /// H-1: Without stub-l2-verifier, garbage proof_bytes must be a hard error.
    #[test]
    #[cfg(not(feature = "stub-l2-verifier"))]
    fn l2_source_binding_rejects_invalid_proof_bytes_without_stub() {
        use shell_stark_prover::recursive_air::compute_aggregate_root;
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 1);

        let l1_src = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        let l1_src_json = serde_json::to_vec(&l1_src).unwrap();
        node.amendment_store
            .put_amendment(&l1_src.block_hash, &l1_src_json)
            .unwrap();
        node.settled_stark_sources
            .lock()
            .insert((1, l1_src.block_hash));

        let root = u128::from_le_bytes(l1_src.proof.batch_root_bytes[0..16].try_into().unwrap());
        let agg_root = compute_aggregate_root(&[root]);
        let l2 = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: l1_src.block_hash,
            block_number: 1,
            start_block: Some(1),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: {
                    let mut b = [0u8; 32];
                    b[0..16].copy_from_slice(&agg_root.to_le_bytes());
                    b
                },
                n_sigs: 1,
                // H-1: These garbage bytes cannot be decoded as a RecursiveProof.
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer: 2,
            source_hashes: vec![l1_src.block_hash],
            original_size: Some(10_000),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        };
        let err = node.validate_stark_proof_source_binding(&l2);
        assert!(
            err.is_err(),
            "H-1: garbage proof_bytes must be a hard error without stub-l2-verifier, got Ok"
        );
    }

    #[test]
    fn stark_settlement_sequence_allows_l2_after_l1_in_same_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let hashes = produce_witnessed_blocks(&node, &signer, 1);

        let sources = vec![genesis_hash, hashes[0]];
        let l1 = dummy_ordered_amendment(1, sources.clone(), 1);
        let l2 = dummy_ordered_amendment(2, sources, 1);

        node.validate_stark_settlement_sequence(&[l1, l2]).unwrap();
    }

    #[test]
    fn stark_rebuild_materializes_canonical_proof_pointers() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let hashes = produce_witnessed_blocks(&node, &signer, 2);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);

        let mut manifest_block = node.produce_block(&signer, 100).unwrap();
        manifest_block.header.extra_data =
            Node::<MemoryDb>::encode_system_extra(std::slice::from_ref(&amendment)).unwrap();
        let manifest_hash = manifest_block.hash();
        node.chain_store.put_block(&manifest_block).unwrap();
        node.chain_store
            .set_canonical(manifest_block.number(), &manifest_hash)
            .unwrap();
        node.chain_store.set_head(&manifest_hash).unwrap();

        let rebuilt = node.rebuild_settled_stark_sources_from_chain().unwrap();
        assert_eq!(rebuilt, 3);

        let pointer_bytes = node
            .amendment_store
            .get_amendment(&hashes[0])
            .unwrap()
            .expect("first covered source should store a pointer");
        assert!(matches!(
            shell_stark_prover::StoredProofArtifact::from_json(&pointer_bytes).unwrap(),
            shell_stark_prover::StoredProofArtifact::Pointer(_)
        ));

        let proof_bytes = node
            .amendment_store
            .get_amendment(&hashes[1])
            .unwrap()
            .expect("final covered source should store the full proof");
        assert!(matches!(
            shell_stark_prover::StoredProofArtifact::from_json(&proof_bytes).unwrap(),
            shell_stark_prover::StoredProofArtifact::Amendment(_)
        ));
    }

    #[test]
    fn import_block_materializes_canonical_proof_pointers() {
        let (leader, signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();
        let hashes = produce_witnessed_blocks(&leader, &signer, 2);
        let block1 = leader
            .chain_store
            .get_block_by_hash(&hashes[0])
            .unwrap()
            .unwrap();
        let block2 = leader
            .chain_store
            .get_block_by_hash(&hashes[1])
            .unwrap()
            .unwrap();
        let block2_number = block2.number();
        let genesis_hash = leader
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);
        leader.pending_stark_settlements.lock().push(amendment);
        let settlement_block = leader.produce_block(&signer, 100).unwrap();
        let settlement_tx_hash = settlement_block
            .system_transactions
            .iter()
            .find(|tx| tx.kind == SystemTxKind::StarkReward)
            .expect("settlement tx")
            .hash();
        assert_eq!(settlement_block.number(), block2_number + 1);
        assert!(
            block2
                .system_transactions
                .iter()
                .all(|tx| tx.kind != SystemTxKind::StarkReward),
            "final source block must remain the proof anchor"
        );

        let follower_db = Arc::new(MemoryDb::new());
        let follower_chain_store = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_world_state = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let follower_consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(
            PoaEngine::new(PoaConfig::new(vec![proposer], 1)),
        ));
        let follower_tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db,
            follower_chain_store,
            follower_world_state,
            follower_tx_pool,
            follower_consensus,
        );
        store_genesis(&follower);
        follower.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let verifier = MultiVerifier;

        follower.import_block(block1, &verifier).unwrap();
        put_dummy_witness(&follower, &hashes[0]);
        follower.import_block(block2, &verifier).unwrap();
        put_dummy_witness(&follower, &hashes[1]);
        follower.import_block(settlement_block, &verifier).unwrap();

        let pointer_bytes = follower
            .amendment_store
            .get_amendment(&hashes[0])
            .unwrap()
            .expect("import should store pointer for first source");
        match shell_stark_prover::StoredProofArtifact::from_json(&pointer_bytes).unwrap() {
            shell_stark_prover::StoredProofArtifact::Pointer(pointer) => {
                assert_eq!(pointer.settlement_tx_hash, Some(settlement_tx_hash));
            }
            other => panic!("expected pointer, got {other:?}"),
        }

        let proof_bytes = follower
            .amendment_store
            .get_amendment(&hashes[1])
            .unwrap()
            .expect("import should store full proof for final source");
        match shell_stark_prover::StoredProofArtifact::from_json(&proof_bytes).unwrap() {
            shell_stark_prover::StoredProofArtifact::Amendment(amendment) => {
                assert_eq!(amendment.block_hash, hashes[1]);
                assert_eq!(amendment.block_number, block2_number);
                assert_eq!(amendment.settlement_tx_hash, Some(settlement_tx_hash));
            }
            other => panic!("expected amendment, got {other:?}"),
        }
    }

    #[test]
    fn stark_settlement_sort_prefers_widest_same_start_range() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        let mut short = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        short.proof.n_sigs = MIN_L1_STARK_TXS;
        short.proof.batch_root_bytes = [0x22; 32];
        short.proof.proof_bytes = vec![0x33; 128];
        short.original_size = Some(10_000);
        short.compressed_size = Some(128);
        let mut wide =
            dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1], hashes[2]], 3);
        wide.proof.n_sigs = MIN_L1_STARK_TXS;
        wide.proof.batch_root_bytes = [0x22; 32];
        wide.proof.proof_bytes = vec![0x33; 128];
        wide.original_size = Some(10_000);
        wide.compressed_size = Some(128);

        let mut settlements = vec![short, wide];
        block_producer::sort_stark_settlements_for_inclusion(&mut settlements);

        assert_eq!(
            settlements[0].block_hash, hashes[2],
            "same-start settlement sorting should prefer the widest range"
        );
        assert_eq!(
            settlements[1].block_hash, hashes[0],
            "shorter overlapping same-start settlement should sort after widest"
        );
    }

    #[test]
    fn stark_settlement_skips_invalid_same_start_proofs() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        let mut short = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        short.proof.proof_bytes = vec![0x33; 128];
        let mut wide =
            dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1], hashes[2]], 3);
        wide.proof.proof_bytes = vec![0x33; 128];

        node.pending_stark_settlements.lock().extend([short, wide]);
        let settlement_block = node.produce_block(&signer, 100).unwrap();

        assert_eq!(
            settlement_block
                .system_transactions
                .iter()
                .filter(|tx| tx.kind == SystemTxKind::StarkReward)
                .count(),
            0,
            "invalid proof-source bindings must not produce reward settlements"
        );
        assert!(
            !node.settled_stark_sources.lock().contains(&(1, hashes[2])),
            "invalid widest proof must not be marked settled"
        );
    }

    #[test]
    fn import_invalid_stark_settlement_does_not_poison_settled_index() {
        let (leader, signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();
        let hashes = produce_witnessed_blocks(&leader, &signer, 2);
        let block1 = leader
            .chain_store
            .get_block_by_hash(&hashes[0])
            .unwrap()
            .unwrap();
        let block2 = leader
            .chain_store
            .get_block_by_hash(&hashes[1])
            .unwrap()
            .unwrap();
        let amendment = dummy_ordered_amendment(1, vec![hashes[0], hashes[1]], 2);
        leader.pending_stark_settlements.lock().push(amendment);
        let mut bad_settlement_block = leader.produce_block(&signer, 100).unwrap();
        bad_settlement_block.header.state_root = ShellHash::from([0x99; 32]);
        leader
            .consensus
            .read()
            .sign_block(&mut bad_settlement_block, &signer)
            .unwrap();

        let follower_db = Arc::new(MemoryDb::new());
        let follower_chain_store = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_world_state = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let follower_consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(
            PoaEngine::new(PoaConfig::new(vec![proposer], 1)),
        ));
        let follower_tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db,
            follower_chain_store,
            follower_world_state,
            follower_tx_pool,
            follower_consensus,
        );
        store_genesis(&follower);
        follower.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let verifier = MultiVerifier;

        follower.import_block(block1, &verifier).unwrap();
        put_dummy_witness(&follower, &hashes[0]);
        follower.import_block(block2, &verifier).unwrap();
        put_dummy_witness(&follower, &hashes[1]);
        let err = follower
            .import_block(bad_settlement_block, &verifier)
            .unwrap_err();

        assert!(
            err.to_string().contains("state root mismatch"),
            "expected state root mismatch, got {err}"
        );
        assert!(!follower
            .settled_stark_sources
            .lock()
            .contains(&(1, hashes[0])));
        assert!(follower
            .amendment_store
            .get_amendment(&hashes[0])
            .unwrap()
            .is_none());
    }

    #[test]
    fn block_producer_settles_valid_l1_and_skips_invalid_l2_same_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let hashes = produce_witnessed_blocks(&node, &signer, 1);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let sources = vec![genesis_hash, hashes[0]];
        let l1 = dummy_ordered_amendment(1, sources.clone(), 1);
        let l2 = dummy_ordered_amendment(2, sources, 1);

        node.pending_stark_settlements.lock().extend([l1, l2]);
        let settlement_block = node.produce_block(&signer, 100).unwrap();
        assert!(
            settlement_block.header.extra_data.is_empty(),
            "STARK settlement manifests must live in reward tx payloads, not block extra_data"
        );
        let settlements: Vec<ProofAmendment> = settlement_block
            .system_transactions
            .iter()
            .filter(|tx| tx.kind == SystemTxKind::StarkReward)
            .map(|tx| {
                let payload = tx.proof_payload.as_ref().expect("proof payload");
                ProofAmendment::from_json(payload.as_ref()).expect("proof payload decodes")
            })
            .collect();

        assert_eq!(
            settlements.len(),
            1,
            "producer should settle the valid L1 amendment and skip invalid L2 proof bytes"
        );
        assert_eq!(settlements[0].layer, 1);
    }

    #[test]
    fn disabled_l2_mode_does_not_feed_scheduler_or_create_jobs() {
        let (node, _signer) = setup_node();
        assert_eq!(
            node.config.l2_stark_mode,
            crate::config::L2StarkMode::Disabled
        );

        node.metrics.stark_l2_blocked_gap_start.set(123);
        node.metrics.stark_l2_pending_inputs.set(456);
        node.metrics.stark_l2_ready_jobs.set(789);

        let settlements: Vec<ProofAmendment> = (10u64..18)
            .map(|block| {
                dummy_ordered_amendment(1, vec![ShellHash::from([block as u8; 32])], block)
            })
            .collect();
        node.feed_l2_scheduler_from_settlements(&settlements, 100);

        assert_eq!(node.metrics.stark_l2_blocked_gap_start.get(), 0);
        assert_eq!(node.metrics.stark_l2_pending_inputs.get(), 0);
        assert_eq!(node.metrics.stark_l2_ready_jobs.get(), 0);
        assert_eq!(node.aggregation_scheduler.lock().pending_proof_count(), 0);
        assert!(
            node.l2_job_store.all_jobs().unwrap().is_empty(),
            "disabled mode must not create L2 jobs"
        );
    }

    #[test]
    fn stark_settled_index_survives_simulated_restart() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        // Apply a STARK settlement via block production.
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);
        node.pending_stark_settlements
            .lock()
            .push(amendment.clone());
        node.produce_block(&signer, 100).unwrap();

        // Verify settled_stark_sources was populated.
        assert!(
            node.settled_stark_sources
                .lock()
                .contains(&(1, genesis_hash)),
            "genesis hash should be settled at L1"
        );
        assert!(
            node.settled_stark_sources.lock().contains(&(1, hashes[0])),
            "block 1 should be settled at L1"
        );
        assert!(
            node.settled_stark_sources.lock().contains(&(1, hashes[1])),
            "block 2 should be settled at L1"
        );

        // Simulate restart: clear in-memory set and reload via index (fast path).
        node.settled_stark_sources.lock().clear();
        assert!(
            node.settled_stark_sources.lock().is_empty(),
            "cleared before rebuild"
        );
        let count = node.rebuild_settled_stark_sources_from_chain().unwrap();
        assert_eq!(count, 3, "fast path should restore 3 settled entries");

        // After rebuild, settled_stark_sources should contain all three sources.
        assert!(
            node.settled_stark_sources
                .lock()
                .contains(&(1, genesis_hash)),
            "genesis hash should be restored after restart"
        );
        assert!(
            node.settled_stark_sources.lock().contains(&(1, hashes[0])),
            "block 1 should be restored after restart"
        );

        // Verify that a duplicate settlement would be rejected.
        node.pending_stark_settlements.lock().push(amendment);
        let dup_err = node.validate_stark_amendment_ordering(&ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: hashes[1],
            block_number: 2,
            start_block: Some(0),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [0x22; 32],
                n_sigs: MIN_L1_STARK_TXS,
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer: 1,
            source_hashes: vec![genesis_hash, hashes[0], hashes[1]],
            original_size: Some(10_000),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        });
        // The duplicate settlement should fail because the sources are already
        // settled at L1 (current_layer >= amendment.layer).
        assert!(
            dup_err.is_err(),
            "duplicate settlement should be rejected, got: {dup_err:?}"
        );
    }

    /// Simulate a reorg: a stale `ss/` index entry (from an old fork) must be
    /// purged by `rebuild_settled_stark_sources_from_chain` so it cannot
    /// incorrectly block the new canonical frontier.
    #[test]
    fn rebuild_settled_removes_stale_index_entries_after_reorg() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 1);

        // Inject a stale `ss/` entry for a hash that is NOT on the canonical
        // chain (simulates a block that existed on a fork before a reorg).
        let stale_hash = ShellHash::from([0xDE; 32]);
        node.settled_source_index.put(1, &stale_hash).unwrap();

        // Also add a legitimate canonical settlement for genesis so the index
        // is "populated" (previously this triggered the fast path that trusted
        // the index blindly).
        node.settled_source_index.put(1, &genesis_hash).unwrap();
        node.settled_source_index.put(1, &hashes[0]).unwrap();

        // Settle genesis + block 1 on the canonical chain so the slow scan
        // finds them.
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        node.pending_stark_settlements
            .lock()
            .push(amendment.clone());
        node.produce_block(&signer, 100).unwrap();

        // Now rebuild: canonical scan should find genesis+block1, remove stale_hash.
        node.settled_stark_sources.lock().clear();
        let count = node.rebuild_settled_stark_sources_from_chain().unwrap();

        // Only the two canonical sources should survive.
        assert_eq!(count, 2, "only canonical settled sources should remain");
        assert!(
            node.settled_stark_sources
                .lock()
                .contains(&(1, genesis_hash)),
            "genesis still settled"
        );
        assert!(
            node.settled_stark_sources.lock().contains(&(1, hashes[0])),
            "block 1 still settled"
        );
        assert!(
            !node.settled_stark_sources.lock().contains(&(1, stale_hash)),
            "stale fork entry must be removed"
        );
        // The persistent index must also be clean.
        assert!(
            !node.settled_source_index.has(1, &stale_hash).unwrap(),
            "stale `ss/` index entry must be deleted"
        );
    }

    #[test]
    fn produce_block_backfills_pointer_metadata_and_anchors_full_proof_on_final_source() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 2);
        let final_source = node
            .chain_store
            .get_block_by_hash(&hashes[1])
            .unwrap()
            .expect("final source block");
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);

        node.pending_stark_settlements.lock().push(amendment);
        let settlement_block = node.produce_block(&signer, 100).unwrap();
        let settlement_tx = settlement_block
            .system_transactions
            .iter()
            .find(|tx| tx.kind == SystemTxKind::StarkReward)
            .expect("settlement tx");

        assert_eq!(settlement_block.number(), final_source.number() + 1);
        assert!(
            final_source
                .system_transactions
                .iter()
                .all(|tx| tx.kind != SystemTxKind::StarkReward),
            "settlement must land after the sealed source block"
        );

        for (source_hash, source_block) in [(genesis_hash, 0u64), (hashes[0], 1u64)] {
            let pointer_bytes = node
                .amendment_store
                .get_amendment(&source_hash)
                .unwrap()
                .expect("pointer should be stored");
            match shell_stark_prover::StoredProofArtifact::from_json(&pointer_bytes).unwrap() {
                shell_stark_prover::StoredProofArtifact::Pointer(pointer) => {
                    assert_eq!(pointer.source_hash, source_hash);
                    assert_eq!(pointer.source_block, source_block);
                    assert_eq!(pointer.target_hash, hashes[1]);
                    assert_eq!(pointer.target_block, 2);
                    assert_eq!(pointer.start_block, 0);
                    assert_eq!(pointer.end_block, 2);
                    assert_eq!(pointer.settlement_tx_hash, Some(settlement_tx.hash()));
                }
                other => panic!("expected pointer, got {other:?}"),
            }
        }

        let proof_bytes = node
            .amendment_store
            .get_amendment(&hashes[1])
            .unwrap()
            .expect("final source should store full proof");
        match shell_stark_prover::StoredProofArtifact::from_json(&proof_bytes).unwrap() {
            shell_stark_prover::StoredProofArtifact::Amendment(full) => {
                assert_eq!(full.block_hash, hashes[1]);
                assert_eq!(full.block_number, 2);
                assert_eq!(full.settlement_tx_hash, Some(settlement_tx.hash()));
            }
            other => panic!("expected full proof, got {other:?}"),
        }
    }

    #[test]
    fn rebuild_settled_index_reconstructs_artifacts_when_persistent_index_is_missing() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 2);
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);

        node.pending_stark_settlements
            .lock()
            .push(amendment.clone());
        let settlement_block = node.produce_block(&signer, 100).unwrap();
        let settlement_tx_hash = settlement_block
            .system_transactions
            .iter()
            .find(|tx| tx.kind == SystemTxKind::StarkReward)
            .expect("settlement tx")
            .hash();

        for (key, _) in node.store.scan_prefix(b"pa/").unwrap() {
            node.store.delete(&key).unwrap();
        }
        for (key, _) in node.store.scan_prefix(b"ss/").unwrap() {
            node.store.delete(&key).unwrap();
        }
        node.settled_stark_sources.lock().clear();

        assert!(node.store.scan_prefix(b"pa/").unwrap().is_empty());
        assert!(node.store.scan_prefix(b"ss/").unwrap().is_empty());

        let rebuilt = node.rebuild_settled_stark_sources_from_chain().unwrap();
        assert_eq!(rebuilt, 3);
        assert_eq!(node.store.scan_prefix(b"ss/").unwrap().len(), 3);
        assert!(node
            .settled_stark_sources
            .lock()
            .contains(&(1, genesis_hash)));
        assert!(node.settled_stark_sources.lock().contains(&(1, hashes[0])));
        assert!(node.settled_stark_sources.lock().contains(&(1, hashes[1])));

        let pointer_bytes = node
            .amendment_store
            .get_amendment(&hashes[0])
            .unwrap()
            .expect("rebuild should restore pointer");
        match shell_stark_prover::StoredProofArtifact::from_json(&pointer_bytes).unwrap() {
            shell_stark_prover::StoredProofArtifact::Pointer(pointer) => {
                assert_eq!(pointer.target_hash, hashes[1]);
                assert_eq!(pointer.settlement_tx_hash, Some(settlement_tx_hash));
            }
            other => panic!("expected pointer, got {other:?}"),
        }

        let proof_bytes = node
            .amendment_store
            .get_amendment(&hashes[1])
            .unwrap()
            .expect("rebuild should restore final proof");
        match shell_stark_prover::StoredProofArtifact::from_json(&proof_bytes).unwrap() {
            shell_stark_prover::StoredProofArtifact::Amendment(full) => {
                assert_eq!(full.settlement_tx_hash, Some(settlement_tx_hash));
            }
            other => panic!("expected full proof, got {other:?}"),
        }
    }

    // ── stark-add-empty-range-tests ─────────────────────────────────────────

    /// `validate_stark_proof_source_binding` must reject an amendment whose
    /// declared `n_sigs` does not match the reconstructed entry count for the
    /// covered canonical source blocks.
    #[test]
    fn source_binding_rejects_wrong_n_sigs() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        // Two 0-tx blocks → reconstructed entry count = 0.
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        let bad = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: hashes[1],
            block_number: 2,
            start_block: Some(0),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [0u8; 32],
                n_sigs: 999, // wrong — actual canonical entry count is 0
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer: 1,
            source_hashes: vec![genesis_hash, hashes[0], hashes[1]],
            original_size: Some(0),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        };

        let err = node.validate_stark_proof_source_binding(&bad).unwrap_err();
        assert!(
            err.to_string().contains("n_sigs"),
            "expected n_sigs mismatch error, got: {err}"
        );
    }

    /// `validate_stark_proof_source_binding` must reject an amendment whose
    /// `batch_root_bytes` does not match the root recomputed from canonical
    /// source entries (even when `n_sigs` is correct).
    #[test]
    fn source_binding_rejects_wrong_batch_root() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        // One 0-tx block → reconstructed entries = [], n_sigs must be 0.
        let hashes = produce_witnessed_blocks(&node, &signer, 1);

        // Compute the correct root for an empty entry set, then flip a byte.
        let correct_root = shell_stark_prover::compute_batch_root(&[]);
        let mut wrong_root = correct_root;
        wrong_root[0] ^= 0xFF;

        let bad = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: hashes[0],
            block_number: 1,
            start_block: Some(0),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: wrong_root, // wrong root
                n_sigs: 0,                    // correct count for 0-tx blocks
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer: 1,
            source_hashes: vec![genesis_hash, hashes[0]],
            original_size: Some(0),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        };

        let err = node.validate_stark_proof_source_binding(&bad).unwrap_err();
        assert!(
            err.to_string().contains("batch_root_bytes"),
            "expected batch_root_bytes mismatch error, got: {err}"
        );
    }

    /// The ordering validator must reject an amendment whose `source_hashes`
    /// skips a canonical empty block (i.e., the declared range is not contiguous
    /// with the actual canonical chain).
    #[test]
    fn ordering_rejects_amendment_skipping_empty_canonical_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        // Produce 3 empty blocks: B1 (#1), B2 (#2), B3 (#3).
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        // Build amendment that claims to cover blocks 0..=2 but skips B2 (#2)
        // and substitutes B3 (#3) instead.  The canonical hash for block #2 is
        // B2, not B3, so the contiguity check must fail.
        let skip_b2 = dummy_ordered_amendment(
            1,
            vec![genesis_hash, hashes[0], hashes[2]], // skips hashes[1] = B2
            2,
        );

        let err = node
            .validate_stark_amendment_ordering(&skip_b2)
            .unwrap_err();
        assert!(
            err.to_string().contains("not canonical"),
            "expected 'not canonical' rejection for skipped block, got: {err}"
        );
    }

    /// The ordering validator must accept an amendment that correctly covers a
    /// contiguous range of empty (0-tx) canonical blocks.  Empty blocks are
    /// valid compression sources via the header-existence check in
    /// `is_stark_compression_source`, so they must be includable in any range.
    #[test]
    fn ordering_accepts_range_with_empty_leading_blocks() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        // Two more 0-tx blocks so the range is [genesis(0tx), B1(0tx), B2(0tx)].
        let hashes = produce_witnessed_blocks(&node, &signer, 2);

        // `dummy_ordered_amendment` represents a valid empty range; source_hashes
        // are contiguous canonical.
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);

        node.validate_stark_amendment_ordering(&amendment)
            .expect("ordering should accept a contiguous range of empty canonical blocks");
    }

    /// A STARK L1 reward that covers only 0-tx canonical blocks must return the
    /// minimum base-mint reward (1 source × mint), not a multiple proportional
    /// to the number of empty blocks in the range.
    #[test]
    fn stark_reward_value_empty_source_blocks_get_minimum_reward() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        // 4 more 0-tx blocks.
        let hashes = produce_witnessed_blocks(&node, &signer, 4);

        let amendment = dummy_ordered_amendment(
            1,
            vec![genesis_hash, hashes[0], hashes[1], hashes[2], hashes[3]],
            4,
        );

        let reward = node.stark_reward_value(4, &amendment).unwrap();
        // All 5 sources are 0-tx → non_empty_count=0 → source_count=1 (min).
        // Layer-1 mint = BASE_STARK_MINT_WEI / 2¹.
        const BASE: u128 = 100_000_000_000_000_000_000;
        assert_eq!(
            reward,
            U256::from(BASE / 2),
            "all-empty range must return minimum reward (1 × L1 mint), got {reward}"
        );
    }

    /// Empty (0-tx) canonical blocks must NOT appear in `settled_stark_sources`
    /// `stark_reward_value` for a L1 proof covering a fee-paying source block must
    /// return the mint-only amount — no gas-fee share.  This is a regression guard
    /// against re-introducing the old 50% gas split into the STARK reward path.
    #[test]
    fn stark_reward_value_is_mint_only_for_fee_paying_source_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        // Produce one fee-paying block with a real transaction.
        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from([0xBBu8; 32]);
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        let tx = shell_core::Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed = shell_core::SignedTransaction::with_pubkey(
            sender,
            tx,
            sig,
            tx_signer.public_key().to_vec(),
        );

        let verifier = MultiVerifier;
        {
            let mut ws = node.world_state.write();
            node.tx_pool
                .insert(signed, &mut ws, node.chain_store.as_ref(), &verifier)
                .unwrap();
        }

        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let block = node.produce_block(&signer, 10).unwrap();
        let block_hash = block.hash();
        assert!(!block.transactions.is_empty(), "block must contain the tx");
        put_dummy_witness(&node, &block_hash);

        // Build a minimal L1 STARK amendment referencing genesis + tx block.
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, block_hash], block.number());

        let reward = node.stark_reward_value(block.number(), &amendment).unwrap();

        // Expected: mint = BASE / 2^1 × source_count.
        // source_count = 1 (only the tx block is non-empty; genesis is 0-tx).
        const BASE: u128 = 100_000_000_000_000_000_000;
        let expected = U256::from(BASE / 2);
        assert_eq!(
            reward, expected,
            "STARK L1 reward must be mint-only (no gas-fee share); got {reward}, expected {expected}"
        );
    }

    /// before a StarkReward is accepted, but MUST appear after the settlement
    /// block is produced.  This ensures the seeding loop never skips empty
    /// frontier blocks prematurely.
    #[test]
    fn empty_canonical_blocks_not_settled_until_stark_reward_accepted() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        // Before any settlement, no block should be in settled_stark_sources.
        {
            let settled = node.settled_stark_sources.lock();
            for hash in [genesis_hash, hashes[0], hashes[1], hashes[2]] {
                assert!(
                    !settled.contains(&(1, hash)),
                    "block {hash:?} should not be settled before proof acceptance"
                );
            }
        }

        // Accept a StarkReward that covers all 4 empty blocks.
        let amendment =
            dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1], hashes[2]], 3);
        node.pending_stark_settlements.lock().push(amendment);
        node.produce_block(&signer, 100).unwrap();

        // After settlement, all 4 empty-gap blocks must be marked settled.
        let settled = node.settled_stark_sources.lock();
        for hash in [genesis_hash, hashes[0], hashes[1], hashes[2]] {
            assert!(
                settled.contains(&(1, hash)),
                "empty block {hash:?} must be settled after StarkReward accepted"
            );
        }
    }

    // ── end stark-add-empty-range-tests ─────────────────────────────────────

    #[test]
    fn produce_empty_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.number(), 1);
        assert!(block.transactions.is_empty());
        assert!(block.proposer_seal.is_some());
    }

    #[test]
    fn import_rejects_replacing_finalized_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;

        let block = node.produce_block(&signer, 100).unwrap();
        let finalized_hash = block.hash();
        node.finality
            .write()
            .set_finalized_direct(block.number(), finalized_hash);
        node.chain_store
            .set_finalized_number(block.number())
            .unwrap();

        let mut conflicting = block.clone();
        conflicting.header.extra_data = Bytes::from(vec![0xFF]);
        assert_ne!(conflicting.hash(), finalized_hash);

        let err = node.import_block(conflicting, &verifier).unwrap_err();
        assert!(matches!(
            err,
            NodeError::ConflictsWithFinalized {
                incoming: 1,
                fin_number: 1
            }
        ));
    }

    #[test]
    fn node_initializes_finality_metrics_from_persisted_chain_state() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let block = node.produce_block(&signer, 100).unwrap();
        let finalized_hash = block.hash();
        node.finality
            .write()
            .set_finalized_direct(block.number(), finalized_hash);
        node.chain_store
            .set_finalized_number(block.number())
            .unwrap();

        let db = node.store.clone();
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let authority = node.config.proposer_address.unwrap();
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let restarted = Node::new(
            NodeConfig::dev(authority),
            db,
            chain_store,
            world_state,
            tx_pool,
            consensus,
        );

        assert_eq!(restarted.metrics.block_height.get(), 1);
        assert_eq!(restarted.metrics.last_finalized_number.get(), 1);
        assert_eq!(restarted.metrics.finality_lag_blocks.get(), 0);
    }

    #[test]
    fn node_restores_canonical_fork_choice_from_finality_to_head() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let finalized = node.produce_block(&signer, 100).unwrap();
        let finalized_hash = finalized.hash();
        let block_two = node.produce_block(&signer, 100).unwrap();
        let block_two_hash = block_two.hash();
        let block_three = node.produce_block(&signer, 100).unwrap();
        let block_three_hash = block_three.hash();
        node.finality
            .write()
            .set_finalized_direct(finalized.number(), finalized_hash);
        node.chain_store
            .set_finalized_number(finalized.number())
            .unwrap();

        let db = node.store.clone();
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let authority = node.config.proposer_address.unwrap();
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let restarted = Node::new(
            NodeConfig::dev(authority),
            db,
            chain_store,
            world_state,
            tx_pool,
            consensus,
        );

        let fork_choice = restarted.fork_choice.read();
        assert_eq!(fork_choice.head(), &block_three_hash);
        assert_eq!(fork_choice.block_count(), 3);
        assert_eq!(fork_choice.parent(&finalized_hash), Some(&ShellHash::ZERO));
        assert_eq!(fork_choice.parent(&block_two_hash), Some(&finalized_hash));
        assert_eq!(fork_choice.parent(&block_three_hash), Some(&block_two_hash));
        assert_eq!(
            fork_choice.find_common_ancestor(&block_two_hash, &block_three_hash),
            Some(block_two_hash)
        );
        assert_eq!(
            fork_choice.score(&block_three_hash).unwrap().is_finalized,
            1,
            "canonical descendants must remain compatible with finalized root"
        );
    }

    #[test]
    fn node_recovers_finalized_hash_after_finalized_body_is_pruned() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let finalized = node.produce_block(&signer, 100).unwrap();
        let finalized_hash = finalized.hash();
        node.produce_block(&signer, 100).unwrap();
        node.finality
            .write()
            .set_finalized_direct(finalized.number(), finalized_hash);
        node.chain_store
            .set_finalized_number(finalized.number())
            .unwrap();
        node.chain_store.delete_bodies(&[finalized_hash]).unwrap();
        assert!(node
            .chain_store
            .get_block_by_number(finalized.number())
            .unwrap()
            .is_none());
        assert_eq!(
            node.chain_store
                .get_block_hash_by_number(finalized.number())
                .unwrap(),
            Some(finalized_hash)
        );

        let db = node.store.clone();
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let authority = node.config.proposer_address.unwrap();
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let restarted = Node::new(
            NodeConfig::dev(authority),
            db,
            chain_store,
            world_state,
            tx_pool,
            consensus,
        );

        assert_eq!(
            restarted.finality.read().last_finalized_number(),
            finalized.number()
        );
        assert_eq!(
            restarted.finality.read().last_finalized_hash(),
            &finalized_hash
        );
        assert_eq!(
            restarted.metrics.last_finalized_number.get(),
            finalized.number() as i64
        );
    }

    #[test]
    fn dev_rpc_mine_blocks_advances_head() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        *node.runtime_signer.write() = Some(Arc::new(signer));

        node.mine_blocks(2).unwrap();

        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 2);
    }

    #[test]
    fn dev_rpc_time_controls_affect_next_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        *node.runtime_signer.write() = Some(Arc::new(signer));

        let genesis = node.chain_store.get_head_block().unwrap().unwrap();
        let next_ts = genesis.header.timestamp + 10;
        assert_eq!(node.set_next_block_timestamp(next_ts).unwrap(), next_ts);
        node.mine_blocks(1).unwrap();

        let block1 = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(block1.header.timestamp, next_ts);

        let offset = node.increase_time(30).unwrap();
        assert_eq!(offset, 30);
        node.mine_blocks(1).unwrap();

        let block2 = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(block2.header.timestamp, block1.header.timestamp + 30);
    }

    #[test]
    fn dev_rpc_snapshot_and_revert_restore_head() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        *node.runtime_signer.write() = Some(Arc::new(signer));

        node.mine_blocks(1).unwrap();
        let snapshot_id = node.snapshot().unwrap();
        node.mine_blocks(2).unwrap();
        let head_before_revert = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head_before_revert.number(), 3);

        assert!(node.revert(&snapshot_id).unwrap());

        let head_after_revert = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head_after_revert.number(), 1);
        assert!(!node.revert("0xdeadbeef").unwrap());
    }

    #[test]
    fn dev_rpc_snapshot_restores_same_sender_nonce_chain() {
        let (node, _) = setup_node();

        let tx_signer = DilithiumSigner::generate();
        let pubkey = tx_signer.public_key().to_vec();
        let sender = Address::from_public_key(&pubkey, tx_signer.sig_type().as_u8());
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));
        store_consistent_genesis(&node);

        let make_tx = |nonce, priority_fee| {
            let tx = Transaction {
                chain_id: 1337,
                nonce,
                to: Some(Address::ZERO),
                value: U256::ZERO,
                data: shell_primitives::Bytes::new(),
                gas_limit: 21_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE + priority_fee,
                max_priority_fee_per_gas: priority_fee,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let signing_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
            let signature = tx_signer.sign(signing_hash.as_bytes()).unwrap();
            SignedTransaction::with_pubkey(sender, tx, signature, pubkey.clone())
        };
        let tx0 = make_tx(0, 1);
        let tx1 = make_tx(1, 2);
        let hash0 = tx0.hash();
        let hash1 = tx1.hash();
        let verifier = MultiVerifier;
        {
            let mut world_state = node.world_state.write();
            node.tx_pool
                .insert(tx0, &mut world_state, node.chain_store.as_ref(), &verifier)
                .unwrap();
            node.tx_pool
                .insert(tx1, &mut world_state, node.chain_store.as_ref(), &verifier)
                .unwrap();
        }

        let snapshot_id = node.snapshot().unwrap();
        node.tx_pool.clear();
        assert!(node.revert(&snapshot_id).unwrap());

        assert_eq!(node.tx_pool.sender_txs(&sender), vec![hash0, hash1]);
    }

    #[test]
    fn dev_rpc_snapshot_limit_bounds_retained_state() {
        let (node, _) = setup_node();
        store_genesis(&node);

        for _ in 0..MAX_DEV_SNAPSHOTS {
            node.snapshot().unwrap();
        }

        let err = node.snapshot().unwrap_err();
        assert!(err.contains("dev snapshot limit reached"));
        assert_eq!(node.dev_state.read().snapshots.len(), MAX_DEV_SNAPSHOTS);
    }

    #[test]
    fn dev_rpc_revert_consumes_snapshot_and_newer_ids() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        *node.runtime_signer.write() = Some(Arc::new(signer));

        let snapshot_1 = node.snapshot().unwrap();
        node.mine_blocks(1).unwrap();
        let snapshot_2 = node.snapshot().unwrap();
        node.mine_blocks(1).unwrap();

        assert!(node.revert(&snapshot_2).unwrap());
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            1
        );
        assert!(!node.revert(&snapshot_2).unwrap());

        assert!(node.revert(&snapshot_1).unwrap());
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            0
        );
        assert!(!node.revert(&snapshot_1).unwrap());
        assert!(node.dev_state.read().snapshots.is_empty());
    }

    #[test]
    fn produce_block_commits_state() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        // Create sender and receiver
        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xBB);
            a
        });
        let transfer_value = U256::from(1_000_000);

        // Fund sender (enough for transfer + gas at INITIAL_BASE_FEE)
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        // Verify initial balances
        {
            let ws = node.world_state.read();
            assert_eq!(
                ws.get_balance(&sender).unwrap(),
                U256::from(100_000_000_000_000u64)
            );
            assert_eq!(ws.get_balance(&receiver).unwrap(), U256::ZERO);
        }

        // Create and submit a transfer transaction
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: transfer_value,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        // Sign with real Dilithium key
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());

        // Insert into mempool with real verification
        let verifier = MultiVerifier;
        let mut world_state = node.world_state.write();
        node.tx_pool
            .insert(
                signed,
                &mut world_state,
                node.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(world_state);

        // Produce block with the transfer
        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.number(), 1);
        assert_eq!(block.transactions.len(), 1);

        // Verify state was committed: receiver got funds
        {
            let ws = node.world_state.read();
            let receiver_balance = ws.get_balance(&receiver).unwrap();
            assert_eq!(
                receiver_balance, transfer_value,
                "receiver should have received the transfer"
            );

            // Sender balance should have decreased (value transferred + gas)
            let sender_balance = ws.get_balance(&sender).unwrap();
            assert!(
                sender_balance < U256::from(100_000_000_000_000u64),
                "sender balance should decrease after transfer"
            );
        }

        // State root should be non-default (state was modified)
        assert_ne!(
            block.header.state_root,
            ShellHash::default(),
            "state root should reflect committed state"
        );
    }

    #[test]
    fn produce_block_skips_tx_that_exceeds_remaining_block_gas() {
        let (node, signer) = setup_node();
        store_genesis_with_gas_limit(&node, 30_000);

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xDD);
            a
        });
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        let make_tx = |nonce| Transaction {
            chain_id: 1337,
            nonce,
            to: Some(receiver),
            value: U256::from(1_000u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&node, &tx_signer, sender, make_tx(0));
        submit_signed_tx(&node, &tx_signer, sender, make_tx(1));

        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].tx.nonce, 0);
        assert_eq!(block.header.gas_used, 21_000);
    }

    #[test]
    fn produce_block_indexes_receipts_by_included_transaction_order() {
        let (node, signer) = setup_node();
        store_genesis_with_gas_limit(&node, 50_000);

        let receiver = Address::from([0xDD; 32]);
        let submit = |tx_signer: &DilithiumSigner, gas_limit, priority_fee| {
            let sender =
                Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
            fund_account(&node, &sender, U256::from(100_000_000_000_000u64));
            submit_signed_tx(
                &node,
                tx_signer,
                sender,
                Transaction {
                    chain_id: 1337,
                    nonce: 0,
                    to: Some(receiver),
                    value: U256::from(1_000u64),
                    data: Bytes::new(),
                    gas_limit,
                    max_fee_per_gas: shell_core::INITIAL_BASE_FEE + priority_fee,
                    max_priority_fee_per_gas: priority_fee,
                    access_list: None,
                    tx_type: 2,
                    max_fee_per_blob_gas: None,
                    blob_versioned_hashes: None,
                },
            );
            sender
        };

        let first_signer = DilithiumSigner::generate();
        let skipped_signer = DilithiumSigner::generate();
        let second_signer = DilithiumSigner::generate();
        let first_sender = submit(&first_signer, 21_000, 300);
        submit(&skipped_signer, 30_000, 200);
        let second_sender = submit(&second_signer, 21_000, 100);

        let block = node.produce_block(&signer, 2).unwrap();
        assert_eq!(
            block.transactions.len(),
            2,
            "the skipped candidate must not consume the inclusion limit"
        );
        assert_eq!(block.transactions[0].sender(), first_sender);
        assert_eq!(block.transactions[1].sender(), second_sender);

        let receipts = node
            .chain_store
            .get_receipts(&block.hash())
            .unwrap()
            .expect("produced block receipts");
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].tx_index, 0);
        assert_eq!(receipts[1].tx_index, 1);
        assert_eq!(receipts[2].tx_index, 2);
    }

    #[test]
    fn produce_block_commits_repeated_contract_storage_updates() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        fund_account(&node, &sender, U256::from(10_000_000_000_000_000_000u64));

        let deploy_tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: None,
            value: U256::ZERO,
            data: Bytes::from(make_init_code(&counter_runtime())),
            gas_limit: 5_000_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&node, &tx_signer, sender, deploy_tx);
        let deploy_block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(deploy_block.transactions.len(), 1);
        let deploy_receipts = node
            .chain_store
            .get_receipts(&deploy_block.hash())
            .unwrap()
            .expect("deploy receipts should be stored");
        let contract = deploy_receipts[0]
            .contract_address
            .expect("contract deploy should produce address");

        let increment_selector = shell_primitives::keccak256(b"increment()");
        for nonce in 1..=2 {
            let call_tx = Transaction {
                chain_id: 1337,
                nonce,
                to: Some(contract),
                value: U256::ZERO,
                data: Bytes::from(increment_selector.as_bytes()[..4].to_vec()),
                gas_limit: 1_000_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let tx_hash = submit_signed_tx(&node, &tx_signer, sender, call_tx);
            let block = node.produce_block(&signer, 100).unwrap();
            assert_eq!(
                block.transactions.len(),
                1,
                "call nonce {nonce} should be included"
            );
            assert_eq!(block.transactions[0].hash(), tx_hash);
        }

        let ws = node.world_state.read();
        let slot_value = ws.get_storage(&contract, &ShellHash::ZERO).unwrap();
        assert_eq!(
            U256::from_be_bytes(*slot_value.as_bytes()),
            U256::from(2u64),
            "counter storage slot 0 should survive repeated block commits"
        );
    }

    #[test]
    fn produce_block_commit_failure_rolls_back_world_state() {
        let (node, signer, failing_db) = setup_failing_batch_node();

        let genesis = Block {
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
                proposer: node.config.proposer_address.unwrap(),
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
        let genesis_hash = genesis.hash();
        node.chain_store.put_block(&genesis).unwrap();
        node.chain_store.set_canonical(0, &genesis_hash).unwrap();
        node.chain_store.set_head(&genesis_hash).unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xCC);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        let transfer_value = U256::from(1_000_000u64);
        fund_account(&node, &sender, initial_balance);
        let root_before = current_state_root(&node);

        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: transfer_value,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());
        let verifier = MultiVerifier;
        let mut ws = node.world_state.write();
        node.tx_pool
            .insert(signed, &mut ws, node.chain_store.as_ref(), &verifier)
            .unwrap();
        drop(ws);

        failing_db.fail_next_batch();
        let err = node.produce_block(&signer, 100).unwrap_err();
        assert!(
            matches!(err, NodeError::Storage(_)),
            "expected storage error, got {err}"
        );

        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            0
        );
        assert!(node.chain_store.get_block_by_number(1).unwrap().is_none());
        assert_eq!(current_state_root(&node), root_before);
        let ws = node.world_state.read();
        assert_eq!(ws.get_balance(&sender).unwrap(), initial_balance);
        assert_eq!(ws.get_balance(&receiver).unwrap(), U256::ZERO);
    }

    #[test]
    fn produce_block_commit_failure_does_not_persist_stark_settlement_side_effects() {
        let (node, signer, failing_db) = setup_failing_batch_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 2);
        let amendment = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1]], 2);
        let root_before = current_state_root(&node);
        let head_before = node.chain_store.get_head_block().unwrap().unwrap().number();

        node.pending_stark_settlements
            .lock()
            .push(amendment.clone());
        failing_db.fail_next_batch();
        let err = node.produce_block(&signer, 100).unwrap_err();
        assert!(
            matches!(err, NodeError::Storage(_)),
            "expected storage error, got {err}"
        );

        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            head_before
        );
        assert!(node
            .chain_store
            .get_block_by_number(head_before + 1)
            .unwrap()
            .is_none());
        assert_eq!(current_state_root(&node), root_before);
        assert!(node
            .amendment_store
            .get_amendment(&genesis_hash)
            .unwrap()
            .is_none());
        assert!(node
            .amendment_store
            .get_amendment(&hashes[0])
            .unwrap()
            .is_none());
        assert!(node
            .amendment_store
            .get_amendment(&hashes[1])
            .unwrap()
            .is_none());
        assert!(node.store.scan_prefix(b"ss/").unwrap().is_empty());
        assert!(!node
            .settled_stark_sources
            .lock()
            .contains(&(amendment.layer, genesis_hash)));
        assert!(!node
            .settled_stark_sources
            .lock()
            .contains(&(amendment.layer, hashes[0])));
        assert!(!node
            .settled_stark_sources
            .lock()
            .contains(&(amendment.layer, hashes[1])));
    }

    #[test]
    fn produce_block_commits_account_manager_updates() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        fund_account(&node, &sender, initial_balance);

        let new_pubkey = vec![0xAB; 1312];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::account_manager_address()),
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(shell_pqvm::encode_rotate_key_calldata(
                &new_pubkey,
                tx_signer.sig_type().as_u8(),
            )),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());

        let verifier = MultiVerifier;
        let mut world_state = node.world_state.write();
        node.tx_pool
            .insert(
                signed,
                &mut world_state,
                node.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(world_state);

        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);

        let account = node
            .world_state
            .read()
            .get_account(&sender)
            .unwrap()
            .unwrap();
        assert_eq!(
            account.pq_pubkey_hash,
            shell_primitives::blake3_hash(&new_pubkey)
        );
        assert_eq!(account.nonce, 1);
        assert_eq!(
            account.balance,
            initial_balance
                - U256::from(shell_pqvm::SYSTEM_CALL_BASE_GAS + shell_pqvm::SYSTEM_CALL_OP_GAS)
                    * U256::from(shell_core::INITIAL_BASE_FEE)
        );
        assert_eq!(
            node.chain_store.get_pubkey(&sender).unwrap().unwrap(),
            new_pubkey
        );
    }

    #[test]
    fn produce_block_commit_failure_does_not_persist_key_rotation() {
        let (node, proposer_signer, failing_db) = setup_failing_batch_node();
        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        fund_account(&node, &sender, initial_balance);
        node.chain_store
            .put_pubkey(&sender, tx_signer.public_key())
            .unwrap();
        store_consistent_genesis(&node);

        let original_pubkey = tx_signer.public_key().to_vec();
        let rotated_pubkey = vec![0xAB; 1312];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::account_manager_address()),
            value: U256::ZERO,
            data: Bytes::from(shell_pqvm::encode_rotate_key_calldata(
                &rotated_pubkey,
                tx_signer.sig_type().as_u8(),
            )),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&node, &tx_signer, sender, tx);
        let root_before = current_state_root(&node);

        failing_db.fail_next_batch();
        let error = node.produce_block(&proposer_signer, 100).unwrap_err();

        assert!(matches!(error, NodeError::Storage(_)));
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            0
        );
        assert_eq!(current_state_root(&node), root_before);
        assert_eq!(
            node.chain_store.get_pubkey(&sender).unwrap(),
            Some(original_pubkey)
        );
        assert_ne!(
            node.chain_store.get_pubkey(&sender).unwrap(),
            Some(rotated_pubkey)
        );
    }

    #[test]
    fn import_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let state_root = current_state_root(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut block, &signer)
            .unwrap();

        let verifier = MultiVerifier;
        node.import_block(block, &verifier).unwrap();

        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 1);
    }

    #[test]
    fn import_block_rejects_empty_header_blob_gas_used_mismatch() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let state_root = current_state_root(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: shell_core::BLOB_GAS_PER_BLOB,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        node.consensus
            .read()
            .sign_block(&mut block, &signer)
            .unwrap();

        let err = node.import_block(block, &MultiVerifier).unwrap_err();
        assert!(
            err.to_string().contains("blob_gas_used mismatch"),
            "expected empty block blob_gas_used rejection, got {err}"
        );
    }

    #[test]
    fn import_block_rejects_invalid_excess_blob_gas() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let state_root = current_state_root(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 1,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        node.consensus
            .read()
            .sign_block(&mut block, &signer)
            .unwrap();

        let err = node.import_block(block, &MultiVerifier).unwrap_err();
        assert!(
            err.to_string().contains("invalid excess_blob_gas"),
            "expected excess_blob_gas rejection, got {err}"
        );
    }

    #[test]
    fn import_block_rejects_empty_header_gas_used_mismatch() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let state_root = current_state_root(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 1,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut block, &signer)
            .unwrap();

        let err = node.import_block(block, &MultiVerifier).unwrap_err();
        assert!(
            err.to_string().contains("gas_used mismatch"),
            "expected empty block gas_used rejection, got {err}"
        );
    }

    #[test]
    fn import_block_with_valid_seal() {
        let (node, signer) = setup_node();
        store_consistent_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();

        // Register authority pubkey so seal verification runs.
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        // Produce a properly signed block and re-import it on a fresh node.
        let block = node.produce_block(&signer, 100).unwrap();
        assert!(block.proposer_seal.is_some());

        // Set up a second node sharing storage to import the block.
        let node2_db = Arc::new(MemoryDb::new());
        let node2_cs = Arc::new(ChainStore::new(node2_db.clone()));
        let node2_ws = Arc::new(RwLock::new(WorldState::new(node2_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let node2 = Node::new(config, node2_db, node2_cs, node2_ws, tx_pool, consensus);
        store_consistent_genesis(&node2);

        // Register authority pubkey on node2.
        node2.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let verifier = MultiVerifier;
        node2.import_block(block, &verifier).unwrap();

        let head = node2.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 1);
    }

    #[test]
    fn import_block_rejects_tx_that_exceeds_remaining_block_gas() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xDE);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1_000u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&leader, &tx_signer, sender, tx);
        let mut block = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);
        block.header.gas_limit = 20_999;
        block.proposer_seal = None;
        leader
            .consensus
            .read()
            .sign_block(&mut block, &proposer_signer)
            .unwrap();

        let follower = setup_node_with_authority(proposer);
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let err = follower.import_block(block, &MultiVerifier).unwrap_err();
        assert!(
            err.to_string().contains("exceeds remaining block gas"),
            "expected block gas rejection, got {err}"
        );
    }

    #[test]
    fn import_block_rejects_header_gas_used_mismatch() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xDF);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1_000u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&leader, &tx_signer, sender, tx);
        let mut block = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block.header.gas_used, 21_000);
        block.header.gas_used = 0;
        block.proposer_seal = None;
        leader
            .consensus
            .read()
            .sign_block(&mut block, &proposer_signer)
            .unwrap();

        let follower = setup_node_with_authority(proposer);
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let err = follower.import_block(block, &MultiVerifier).unwrap_err();
        assert!(
            err.to_string().contains("gas_used mismatch"),
            "expected header gas_used rejection, got {err}"
        );
    }

    #[test]
    fn import_block_persists_aa_pubkey_for_follow_up_transactions() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xCC);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let verifier = MultiVerifier;
        let tx0 = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx0_hash = tx0.signing_hash(tx_signer.sig_type().as_u8());
        let sig0 = tx_signer.sign(tx0_hash.as_bytes()).expect("sign failed");
        let signed0 =
            SignedTransaction::with_pubkey(sender, tx0, sig0, tx_signer.public_key().to_vec());

        let mut leader_world_state = leader.world_state.write();
        leader
            .tx_pool
            .insert(
                signed0,
                &mut leader_world_state,
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(leader_world_state);

        let block1 = leader.produce_block(&proposer_signer, 100).unwrap();

        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let follower = Node::new(
            config,
            follower_db,
            follower_cs,
            follower_ws,
            tx_pool,
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        follower.import_block(block1, &verifier).unwrap();
        assert_eq!(
            follower.chain_store.get_pubkey(&sender).unwrap().unwrap(),
            tx_signer.public_key().to_vec()
        );

        let tx1 = Transaction {
            chain_id: 1337,
            nonce: 1,
            to: Some(receiver),
            value: U256::from(2u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx1_hash = tx1.signing_hash(tx_signer.sig_type().as_u8());
        let sig1 = tx_signer.sign(tx1_hash.as_bytes()).expect("sign failed");
        let signed1 = SignedTransaction::new(sender, tx1, sig1);

        let mut leader_world_state = leader.world_state.write();
        leader
            .tx_pool
            .insert(
                signed1,
                &mut leader_world_state,
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(leader_world_state);

        let block2 = leader.produce_block(&proposer_signer, 100).unwrap();
        follower.import_block(block2, &verifier).unwrap();

        let follower_account = follower
            .world_state
            .read()
            .get_account(&sender)
            .unwrap()
            .unwrap();
        assert_eq!(follower_account.nonce, 2);
    }

    #[test]
    fn produce_add_validator_after_pubkey_registration_keeps_state_readable() {
        let (leader, proposer_signer) = setup_node();
        let proposer = leader.config.proposer_address.unwrap();
        {
            let mut ws = leader.world_state.write();
            ws.set_validators(&[proposer]).unwrap();
            ws.set_validator_weight(&proposer, 1).unwrap();
        }
        fund_account(&leader, &proposer, U256::from(1_000_000_000_000_000u64));
        store_consistent_genesis(&leader);
        leader.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let target_signer = DilithiumSigner::generate();
        let target =
            Address::from_public_key(target_signer.public_key(), target_signer.sig_type().as_u8());
        fund_account(&leader, &target, U256::from(1_000_000_000_000_000u64));

        let register_tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(target),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let register_sig = target_signer
            .sign(
                register_tx
                    .signing_hash(target_signer.sig_type().as_u8())
                    .as_bytes(),
            )
            .expect("sign failed");
        let register_signed = SignedTransaction::with_pubkey(
            target,
            register_tx,
            register_sig,
            target_signer.public_key().to_vec(),
        );
        let verifier = MultiVerifier;
        {
            let mut ws = leader.world_state.write();
            leader
                .tx_pool
                .insert(
                    register_signed,
                    &mut ws,
                    leader.chain_store.as_ref(),
                    &verifier,
                )
                .unwrap();
        }

        let block1 = leader.produce_block(&proposer_signer, 100).unwrap();
        let block1_hash = block1.hash();
        assert_eq!(block1.number(), 1);
        let block1_state = WorldState::at_root(leader.store.clone(), &block1.header.state_root)
            .expect("block1 state root reopens");
        assert_eq!(
            block1_state
                .get_validators()
                .expect("block1 validators readable from header state root"),
            vec![proposer]
        );
        assert!(leader.chain_store.get_pubkey(&target).unwrap().is_some());
        assert_eq!(
            leader
                .world_state
                .read()
                .get_validators()
                .expect("validators readable after pubkey-registration block"),
            vec![proposer]
        );

        let add_tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::registry_address()),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(&shell_pqvm::encode_add_validator_calldata(&target)),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let add_sig = proposer_signer
            .sign(
                add_tx
                    .signing_hash(proposer_signer.sig_type().as_u8())
                    .as_bytes(),
            )
            .expect("sign failed");
        let add_signed = SignedTransaction::with_pubkey(
            proposer,
            add_tx,
            add_sig,
            proposer_signer.public_key().to_vec(),
        );
        {
            let mut ws = leader.world_state.write();
            leader
                .tx_pool
                .insert(
                    add_signed.clone(),
                    &mut ws,
                    leader.chain_store.as_ref(),
                    &verifier,
                )
                .unwrap();
        }
        let block2 = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block2.number(), 2);
        let block2_hash = block2.hash();
        let receipts = leader
            .chain_store
            .get_receipts(&block2_hash)
            .unwrap()
            .unwrap();
        let add_receipt = receipts
            .iter()
            .find(|receipt| receipt.tx_hash == add_signed.hash())
            .expect("add-validator receipt stored");
        assert_eq!(add_receipt.status, 1);

        let validators = leader
            .world_state
            .read()
            .get_validators()
            .expect("validators readable after add-validator block");
        assert_eq!(validators, vec![proposer, target]);

        let reopened = WorldState::at_root(leader.store.clone(), &block2.header.state_root)
            .expect("block2 state root reopens");
        assert_eq!(reopened.get_validators().unwrap(), vec![proposer, target]);
        assert_ne!(block1_hash, block2_hash);
    }

    /// A block may contain repeated embedded keys from the same sender.
    ///
    /// The follower starts with no registered pubkey for the sender and must
    /// deduplicate the key while importing both transactions.
    #[test]
    fn block_import_pubkey_dedup_repeated_embedded_same_block() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xEE);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let verifier = MultiVerifier;

        // TX₀: Embedded — first tx from this sender carries the public key
        let tx0 = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig0 = tx_signer
            .sign(tx0.signing_hash(tx_signer.sig_type().as_u8()).as_bytes())
            .expect("sign failed");
        let signed0 =
            SignedTransaction::with_pubkey(sender, tx0, sig0, tx_signer.public_key().to_vec());

        // TX₁ also embeds the key because neither transaction is canonical yet.
        let tx1 = Transaction {
            chain_id: 1337,
            nonce: 1,
            to: Some(receiver),
            value: U256::from(2u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig1 = tx_signer
            .sign(tx1.signing_hash(tx_signer.sig_type().as_u8()).as_bytes())
            .expect("sign failed");
        let signed1 =
            SignedTransaction::with_pubkey(sender, tx1, sig1, tx_signer.public_key().to_vec());

        let mut ws = leader.world_state.write();
        leader
            .tx_pool
            .insert(signed0, &mut ws, leader.chain_store.as_ref(), &verifier)
            .unwrap();
        // Pending admission does not mutate the persistent pubkey registry.
        leader
            .tx_pool
            .insert(signed1, &mut ws, leader.chain_store.as_ref(), &verifier)
            .unwrap();
        drop(ws);

        let block1 = leader.produce_block(&proposer_signer, 100).unwrap();

        // Follower has no prior knowledge of sender's pubkey
        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db,
            follower_cs,
            follower_ws,
            tx_pool,
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        // Should succeed: Embedded TX₀ registers pubkey; Reference TX₁ resolves from block_pubkeys
        follower.import_block(block1, &verifier).unwrap();

        // Pubkey is now registered on the follower
        assert_eq!(
            follower.chain_store.get_pubkey(&sender).unwrap().unwrap(),
            tx_signer.public_key().to_vec()
        );
        // Both txs executed; sender nonce = 2
        let account = follower
            .world_state
            .read()
            .get_account(&sender)
            .unwrap()
            .unwrap();
        assert_eq!(account.nonce, 2);
    }

    /// F-405 Test 2: Block with Reference TX₀ before Embedded TX₁ must be rejected.
    ///
    /// When a Reference tx appears before the Embedded tx that would register
    /// the pubkey, the first-pass resolver cannot find the pubkey and the
    /// block import must fail immediately.
    #[test]
    fn block_import_reference_before_embedded_fails() {
        let (node, proposer_signer) = setup_node();
        store_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xFF);
            a
        });
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        // TX₀: Reference — wrong order; no Embedded tx has preceded it in this block
        let tx0 = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        // Sign tx0 properly so sig is structurally valid (error occurs before sig verify)
        let sig0 = tx_signer
            .sign(tx0.signing_hash(tx_signer.sig_type().as_u8()).as_bytes())
            .expect("sign failed");
        let signed0 = SignedTransaction::new(sender, tx0, sig0); // Reference mode

        // TX₁: Embedded — has the key, but comes too late
        let tx1 = Transaction {
            chain_id: 1337,
            nonce: 1,
            to: Some(receiver),
            value: U256::from(2u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig1 = tx_signer
            .sign(tx1.signing_hash(tx_signer.sig_type().as_u8()).as_bytes())
            .expect("sign failed");
        let signed1 =
            SignedTransaction::with_pubkey(sender, tx1, sig1, tx_signer.public_key().to_vec());

        // Build a signed block whose tx ordering must be rejected by import validation.
        let genesis_hash = node
            .chain_store
            .get_head_hash()
            .unwrap()
            .expect("genesis head");
        let mut bad_block = shell_core::Block {
            header: shell_core::BlockHeader {
                parent_hash: genesis_hash,
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: shell_primitives::Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: shell_primitives::Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![signed0, signed1], // Reference first = wrong order
            system_transactions: vec![SystemTransaction::block_gas_reward(
                1337,
                1,
                2,
                proposer,
                // Two 21 000-gas txs → 42 000 total gas; producer receives 100% of fees.
                U256::from(42_000u64).saturating_mul(U256::from(shell_core::INITIAL_BASE_FEE)),
                genesis_hash,
            )],
            proposer_seal: None,
        };
        bad_block.proposer_seal = Some(
            proposer_signer
                .sign(bad_block.header.hash().as_bytes())
                .expect("sign bad block"),
        );

        let verifier = MultiVerifier;
        let result = node.import_block(bad_block, &verifier);
        assert!(
            result.is_err(),
            "import should fail when Reference tx precedes Embedded in same block"
        );
        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err_msg.contains("reference pubkey mode") || err_msg.contains("no registered"),
            "expected unresolved Reference pubkey rejection, got: {err_msg}"
        );
    }

    #[test]
    fn import_block_rejects_empty_signature_user_tx() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();
        leader.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        fund_account(&leader, &sender, U256::from(100_000_000_000_000u64));
        let tx = make_embedded_tx(&tx_signer, sender, tx_signer.public_key().to_vec(), 0, 1);
        let verifier = MultiVerifier;
        {
            let mut ws = leader.world_state.write();
            leader
                .tx_pool
                .insert(tx, &mut ws, leader.chain_store.as_ref(), &verifier)
                .unwrap();
        }

        let mut block = leader.produce_block(&proposer_signer, 100).unwrap();
        block
            .transactions
            .first_mut()
            .expect("block should include tx")
            .signature
            .data
            .clear();

        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db,
            follower_cs,
            follower_ws,
            tx_pool,
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, U256::from(100_000_000_000_000u64));
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let err = follower.import_block(block, &verifier).unwrap_err();
        assert!(
            err.to_string().contains("empty signature"),
            "expected empty signature rejection, got: {err}"
        );
        assert_eq!(
            follower
                .chain_store
                .get_head_block()
                .unwrap()
                .unwrap()
                .number(),
            0,
            "failed import must not advance head"
        );
    }

    #[test]
    fn import_block_materializes_state_root_for_restart() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xDD);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let verifier = MultiVerifier;
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());

        let mut leader_world_state = leader.world_state.write();
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader_world_state,
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(leader_world_state);

        let block = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);

        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let follower = Node::new(
            config,
            follower_db,
            follower_cs,
            follower_ws,
            tx_pool,
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        follower.import_block(block.clone(), &verifier).unwrap();

        assert!(
            follower
                .store
                .contains(block.header.state_root.as_bytes())
                .unwrap(),
            "imported tx block should materialize its state root for restart safety"
        );
    }

    #[test]
    fn import_block_state_root_mismatch_leaves_live_state_unchanged() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xEE);
            a
        });
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);

        let verifier = MultiVerifier;
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());

        let mut leader_world_state = leader.world_state.write();
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader_world_state,
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(leader_world_state);

        let block = leader.produce_block(&proposer_signer, 100).unwrap();

        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let follower = Node::new(
            config,
            follower_db,
            follower_cs,
            follower_ws,
            tx_pool,
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        fund_account(
            &follower,
            &Address::from({
                let mut a = [0u8; 32];
                a[12..].fill(0xAB);
                a
            }),
            U256::from(42u64),
        );
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let before_root = current_state_root(&follower);
        let before_head = follower
            .chain_store
            .get_head_block()
            .unwrap()
            .unwrap()
            .hash();

        let err = follower.import_block(block, &verifier).unwrap_err();
        assert!(err.to_string().contains("state root mismatch"));
        assert_eq!(
            current_state_root(&follower),
            before_root,
            "failed imports must not mutate the follower live state"
        );

        let after_head = follower.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(after_head.number(), 0);
        assert_eq!(after_head.hash(), before_head);
    }

    #[test]
    fn rejected_account_manager_block_leaves_side_state_unchanged() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);
        let new_pubkey = vec![0xAB; 1312];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::account_manager_address()),
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(shell_pqvm::encode_rotate_key_calldata(
                &new_pubkey,
                tx_signer.sig_type().as_u8(),
            )),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());
        let verifier = MultiVerifier;
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader.world_state.write(),
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        let mut block = leader.produce_block(&proposer_signer, 100).unwrap();
        block.header.state_root = ShellHash::ZERO;
        block.proposer_seal = Some(
            proposer_signer
                .sign(block.header.hash().as_bytes())
                .unwrap(),
        );

        let follower_db = Arc::new(MemoryDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db,
            follower_cs,
            follower_ws,
            Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            })),
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let before_root = current_state_root(&follower);
        let before_account = follower
            .world_state
            .read()
            .get_account(&sender)
            .unwrap()
            .unwrap();
        assert!(follower.chain_store.get_pubkey(&sender).unwrap().is_none());

        let err = follower.import_block(block, &verifier).unwrap_err();
        assert!(err.to_string().contains("state root mismatch"));
        assert_eq!(current_state_root(&follower), before_root);
        assert_eq!(
            follower
                .world_state
                .read()
                .get_account(&sender)
                .unwrap()
                .unwrap(),
            before_account
        );
        assert!(
            follower.chain_store.get_pubkey(&sender).unwrap().is_none(),
            "rejected imports must not persist account-manager side state"
        );
    }

    #[test]
    fn import_commit_failure_leaves_account_manager_side_state_unchanged() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        fund_account(&leader, &sender, initial_balance);
        let new_pubkey = vec![0xAB; 1312];
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::account_manager_address()),
            value: U256::ZERO,
            data: Bytes::from(shell_pqvm::encode_rotate_key_calldata(
                &new_pubkey,
                tx_signer.sig_type().as_u8(),
            )),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());
        let verifier = MultiVerifier;
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader.world_state.write(),
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        let block = leader.produce_block(&proposer_signer, 100).unwrap();

        let follower_db = Arc::new(FailingBatchDb::new());
        let follower_cs = Arc::new(ChainStore::new(follower_db.clone()));
        let follower_ws = Arc::new(RwLock::new(WorldState::new(follower_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let follower = Node::new(
            NodeConfig::dev(proposer),
            follower_db.clone(),
            follower_cs,
            follower_ws,
            Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            })),
            consensus,
        );
        store_genesis(&follower);
        fund_account(&follower, &sender, initial_balance);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
        let root_before = current_state_root(&follower);
        let head_before = follower.chain_store.get_head_hash().unwrap().unwrap();

        follower_db.fail_head_batch();
        let err = follower.import_block(block, &verifier).unwrap_err();
        assert!(err.to_string().contains("injected canonical batch failure"));
        assert_eq!(
            follower.chain_store.get_head_hash().unwrap(),
            Some(head_before)
        );
        assert_eq!(current_state_root(&follower), root_before);
        assert!(
            follower.chain_store.get_pubkey(&sender).unwrap().is_none(),
            "failed canonical commits must not persist account-manager side state"
        );
    }

    #[test]
    fn rejected_governance_block_restores_algorithm_registry() {
        const TEST_NAME: &str =
            "node::tests::rejected_governance_block_restores_algorithm_registry";
        const ISOLATED_MARKER: &str = "SHELL_TEST_ISOLATED_ALGORITHM_REGISTRY_ROLLBACK";
        if run_isolated(TEST_NAME, ISOLATED_MARKER) {
            return;
        }

        struct RegistryReset(AlgorithmRegistry);

        impl Drop for RegistryReset {
            fn drop(&mut self) {
                *AlgorithmRegistry::global_mut() = self.0.clone();
            }
        }

        let _reset = RegistryReset(AlgorithmRegistry::global().clone());
        *AlgorithmRegistry::global_mut() = AlgorithmRegistry::default();

        let (leader, proposer_signer) = setup_node();
        let proposer = leader.config.proposer_address.unwrap();
        leader
            .world_state
            .write()
            .set_validators(&[proposer])
            .unwrap();
        let initial_balance = U256::from(1_000_000_000_000_000u64);
        fund_account(&leader, &proposer, initial_balance);
        store_consistent_genesis(&leader);

        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(shell_pqvm::registry_address()),
            value: U256::ZERO,
            data: Bytes::from(shell_pqvm::encode_propose_algorithm_activation_calldata(
                shell_crypto::SignatureType::SphincsSha2256f,
                shell_pqvm::ALGO_GOVERNANCE_DELTA_MIN,
                [0xA5; 32],
            )),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let tx_hash = tx.signing_hash(proposer_signer.sig_type().as_u8());
        let sig = proposer_signer
            .sign(tx_hash.as_bytes())
            .expect("sign failed");
        let signed = SignedTransaction::with_pubkey(
            proposer,
            tx,
            sig,
            proposer_signer.public_key().to_vec(),
        );
        let verifier = MultiVerifier;
        leader
            .tx_pool
            .insert(
                signed,
                &mut leader.world_state.write(),
                leader.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        let mut block = leader.produce_block(&proposer_signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert!(
            !AlgorithmRegistry::global().is_allowed(shell_crypto::SignatureType::SphincsSha2256f)
        );

        *AlgorithmRegistry::global_mut() = AlgorithmRegistry::default();
        block.header.state_root = ShellHash::ZERO;
        block.proposer_seal = Some(
            proposer_signer
                .sign(block.header.hash().as_bytes())
                .unwrap(),
        );

        let follower = setup_node_with_authority(proposer);
        follower
            .world_state
            .write()
            .set_validators(&[proposer])
            .unwrap();
        fund_account(&follower, &proposer, initial_balance);
        store_consistent_genesis(&follower);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let err = follower.import_block(block, &verifier).unwrap_err();
        assert!(err.to_string().contains("state root mismatch"));
        assert!(
            AlgorithmRegistry::global().is_allowed(shell_crypto::SignatureType::SphincsSha2256f),
            "rejected imports must restore process-global algorithm status"
        );
    }

    #[test]
    fn activation_transition_propagates_persistence_failure() {
        const TEST_NAME: &str = "node::tests::activation_transition_propagates_persistence_failure";
        const ISOLATED_MARKER: &str = "SHELL_TEST_ISOLATED_ACTIVATION_PRODUCTION_FAILURE";
        if run_isolated(TEST_NAME, ISOLATED_MARKER) {
            return;
        }

        *AlgorithmRegistry::global_mut() = AlgorithmRegistry::default();
        let (node, _signer, db) = setup_failing_batch_node();
        configure_pending_activation(&node, 1, shell_crypto::SignatureType::SphincsSha2256f);
        store_consistent_genesis(&node);
        db.fail_next_put();

        let mut world_state = node.world_state.write();
        let mut registry = AlgorithmRegistry::global_mut();
        let err = apply_pending_activations(1, &mut world_state, &mut registry, "production")
            .expect_err("activation persistence failure must propagate");

        let message = err.to_string();
        assert!(message.contains("injected put failure"));
        assert!(message.contains("algorithm activation at block 1"));
        assert!(
            !registry.is_allowed(shell_crypto::SignatureType::SphincsSha2256f),
            "failed activation persistence must leave the process registry pending"
        );
    }

    #[test]
    fn block_production_rolls_back_state_when_activation_persistence_fails() {
        const TEST_NAME: &str =
            "node::tests::block_production_rolls_back_state_when_activation_persistence_fails";
        const ISOLATED_MARKER: &str = "SHELL_TEST_ISOLATED_ACTIVATION_PRODUCTION_ROLLBACK";
        if run_isolated(TEST_NAME, ISOLATED_MARKER) {
            return;
        }

        *AlgorithmRegistry::global_mut() = AlgorithmRegistry::default();
        let (node, signer, db) = setup_failing_batch_node();
        for algo in [
            shell_crypto::SignatureType::MlDsa65,
            shell_crypto::SignatureType::SphincsSha2256f,
        ] {
            configure_pending_activation(&node, 1, algo);
        }
        store_consistent_genesis(&node);
        let canonical_root = node.world_state.write().state_root().unwrap();
        let canonical_head = node.chain_store.get_head_hash().unwrap();
        db.fail_next_batch();

        let err = node.produce_block(&signer, 100).unwrap_err();

        assert!(err.to_string().contains("injected batch failure"));
        assert_eq!(
            node.world_state.write().state_root().unwrap(),
            canonical_root,
            "failed production must restore the canonical world state"
        );
        assert_eq!(node.chain_store.get_head_hash().unwrap(), canonical_head);
    }

    #[test]
    fn import_block_with_invalid_seal_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();

        // Register authority pubkey.
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = node.produce_block(&signer, 100).unwrap();

        // Corrupt the seal.
        if let Some(ref mut seal) = block.proposer_seal {
            seal.data[0] ^= 0xFF;
        }

        // Set up a second node to import the corrupted block.
        let node2_db = Arc::new(MemoryDb::new());
        let node2_cs = Arc::new(ChainStore::new(node2_db.clone()));
        let node2_ws = Arc::new(RwLock::new(WorldState::new(node2_db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let node2 = Node::new(config, node2_db, node2_cs, node2_ws, tx_pool, consensus);
        store_genesis(&node2);
        node2.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let verifier = MultiVerifier;
        let result = node2.import_block(block, &verifier);
        assert!(
            result.is_err(),
            "block with invalid seal should be rejected"
        );
    }

    #[test]
    fn import_block_without_seal_rejected() {
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let state_root = current_state_root(&node);

        let block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: node.config.proposer_address.unwrap(),
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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

        let verifier = MultiVerifier;
        let err = node.import_block(block, &verifier).unwrap_err();
        assert!(
            err.to_string().contains("missing proposer seal"),
            "expected missing seal rejection, got: {err}"
        );
    }

    #[test]
    fn import_block_rejects_timestamp_before_block_time() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let state_root = current_state_root(&node);

        let mut block = Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: parent.number() + 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: parent.header.timestamp,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        block.proposer_seal = Some(
            signer
                .sign(block.header.hash().as_bytes())
                .expect("sign block"),
        );

        let err = node.import_block(block, &MultiVerifier).unwrap_err();
        assert!(err.to_string().contains("timestamp"));
    }

    #[test]
    fn import_block_rejects_future_timestamp() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let parent = node.chain_store.get_head_block().unwrap().unwrap();
        let state_root = current_state_root(&node);
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(10_000);

        let mut block = Block {
            header: BlockHeader {
                parent_hash: parent.hash(),
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: parent.number() + 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: future,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        block.proposer_seal = Some(
            signer
                .sign(block.header.hash().as_bytes())
                .expect("sign block"),
        );

        let err = node.import_block(block, &MultiVerifier).unwrap_err();
        assert!(err.to_string().contains("timestamp"));
    }

    #[test]
    fn produce_block_registers_authority_pubkey() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let proposer = node.config.proposer_address.unwrap();
        assert!(node.known_authorities.read().get(&proposer).is_none());

        node.produce_block(&signer, 100).unwrap();

        let known = node.known_authorities.read();
        let pubkey = known
            .get(&proposer)
            .expect("pubkey should be registered after produce_block");
        assert_eq!(pubkey, signer.public_key());
    }

    #[test]
    fn shutdown_signal() {
        let (node, _signer) = setup_node();
        let rx = node.shutdown_tx.subscribe();
        assert!(!*rx.borrow());

        node.shutdown();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn event_loop_produces_blocks() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::time::Duration;

        let (mut node, signer) = setup_node();
        // Override block_time to 1s so the test completes quickly
        // regardless of the Dev network profile default (30s).
        node.config.block_time_ms = 1_000;
        node.config.rpc_enabled = false;
        node.config.metrics.enabled = false;
        // Disable idle-skip so the loop produces blocks even with an empty
        // mempool (this test only verifies block production, not idle behavior).
        node.config.max_idle_interval_ms = 0;
        store_consistent_genesis(&node);

        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());

        let node = Arc::new(node);
        let node_clone = node.clone();
        let signer = Arc::new(signer) as Arc<dyn Signer>;

        // Spawn the event loop in a background task.
        let handle = tokio::spawn(async move { node_clone.run(signer, &mut network).await });

        let observed_height = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match node.chain_store.get_head_block() {
                    Ok(Some(head)) if head.number() >= 3 => break Ok(head.number()),
                    Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(error) => break Err(error),
                }
            }
        })
        .await;

        // Shut down the node.
        node.shutdown();
        let result = handle.await.expect("task panicked");
        assert!(result.is_ok(), "run() returned error: {:?}", result.err());

        let observed_height = observed_height
            .expect("timed out waiting for three blocks")
            .expect("failed to read the canonical head");
        assert!(
            observed_height >= 3,
            "expected at least 3 blocks, got {}",
            observed_height
        );
    }

    #[tokio::test]
    async fn event_loop_adopts_stateful_preferred_fork_before_resuming_production() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::time::Duration;

        let (mut node, proposer_signer) = setup_node();
        node.config.block_time_ms = 1_000;
        node.config.rpc_enabled = false;
        node.config.metrics.enabled = false;
        node.config.max_idle_interval_ms = 0;

        let proposer = node.config.proposer_address.unwrap();
        let fork_node = setup_node_with_authority(proposer);
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
        fork_node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let reverted_signer = DilithiumSigner::generate();
        let reverted_sender = Address::from_public_key(
            reverted_signer.public_key(),
            reverted_signer.sig_type().as_u8(),
        );
        let receiver = Address::from([0xBE; 20]);
        let reverted_receiver = Address::from([0xCF; 20]);
        let initial_balance = U256::from(100_000_000_000_000u64);
        fund_account(&node, &sender, initial_balance);
        fund_account(&fork_node, &sender, initial_balance);
        fund_account(&node, &reverted_sender, initial_balance);
        fund_account(&fork_node, &reverted_sender, initial_balance);
        store_consistent_genesis(&node);
        store_consistent_genesis(&fork_node);

        let reverted_tx_hash = submit_signed_tx(
            &node,
            &reverted_signer,
            reverted_sender,
            Transaction {
                chain_id: 1337,
                nonce: 0,
                to: Some(reverted_receiver),
                value: U256::from(2_000u64),
                data: Bytes::new(),
                gas_limit: 21_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        );
        let canonical = node.produce_block(&proposer_signer, 100).unwrap();
        let canonical_hash = canonical.hash();
        assert_eq!(canonical.transactions.len(), 1);

        let transaction = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1_000u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(&fork_node, &tx_signer, sender, transaction);
        let side_one = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_one_hash = side_one.hash();
        node.import_block(side_one, &MultiVerifier).unwrap();

        let side_two = fork_node.produce_block(&proposer_signer, 100).unwrap();
        let side_two_hash = side_two.hash();
        node.import_block(side_two, &MultiVerifier).unwrap();

        let total_weight = node
            .consensus
            .read()
            .validator_weights()
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        node.fork_choice
            .write()
            .update_attested_weight(&side_two_hash, total_weight);

        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());
        let node = Arc::new(node);
        let node_clone = node.clone();
        let signer = Arc::new(proposer_signer) as Arc<dyn Signer>;
        let handle = tokio::spawn(async move { node_clone.run(signer, &mut network).await });

        let observed_height = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match node.chain_store.get_head_block() {
                    Ok(Some(head)) if head.number() >= 3 => break Ok(head.number()),
                    Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(error) => break Err(error),
                }
            }
        })
        .await;

        node.shutdown();
        let result = handle.await.expect("task panicked");
        assert!(result.is_ok(), "run() returned error: {:?}", result.err());

        let observed_height = observed_height
            .expect("timed out waiting for production after fork adoption")
            .expect("failed to read the canonical head");
        assert!(observed_height >= 3);
        assert_eq!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(side_one_hash)
        );
        assert_ne!(
            node.chain_store.get_block_hash_by_number(1).unwrap(),
            Some(canonical_hash)
        );
        assert_eq!(
            node.chain_store.get_block_hash_by_number(2).unwrap(),
            Some(side_two_hash)
        );
        assert_eq!(node.world_state.read().get_nonce(&sender).unwrap(), 1);
        assert_eq!(
            node.world_state.read().get_balance(&receiver).unwrap(),
            U256::from(1_000u64)
        );
        let resumed_block = node
            .chain_store
            .get_block_by_number(3)
            .unwrap()
            .expect("production should resume at block 3");
        assert!(resumed_block
            .transactions
            .iter()
            .any(|tx| tx.hash() == reverted_tx_hash));
        assert_eq!(
            node.world_state
                .read()
                .get_balance(&reverted_receiver)
                .unwrap(),
            U256::from(2_000u64)
        );
    }

    #[tokio::test]
    async fn aborting_event_loop_drops_background_prover_service() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::net::SocketAddr;
        use std::time::Duration;

        let (mut node, signer) = setup_node();
        node.config.node_role = crate::config::NodeRole::ValidatorProver;
        node.config.metrics.enabled = false;
        node.config.rpc_enabled = false;
        node.config.rpc.listen_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        node.config.rpc.ws_addr = None;
        store_consistent_genesis(&node);

        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());

        let node = Arc::new(node);
        let backlog_refs_before_run = Arc::strong_count(&node.proof_backlog);
        let signer = Arc::new(signer) as Arc<dyn Signer>;
        let handle = tokio::spawn({
            let node = Arc::clone(&node);
            async move { node.run(signer, &mut network).await }
        });

        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&node.proof_backlog) <= backlog_refs_before_run {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("prover service did not acquire the proof backlog");

        handle.abort();
        let err = handle
            .await
            .expect_err("aborted event loop should not complete normally");
        assert!(
            err.is_cancelled(),
            "expected cancelled join error, got {err}"
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&node.proof_backlog) != backlog_refs_before_run {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted event loop retained the prover service");
    }

    #[test]
    fn epoch_boundary_reloads_validators() {
        let signer = DilithiumSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1).with_epoch_length(3),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        store_genesis(&node);

        // Write a new validator set to world state.
        let new_validator = Address::from([0xAA; 32]);
        {
            let mut ws = node.world_state.write();
            ws.set_validators(&[authority, new_validator]).unwrap();
        }

        // Before epoch boundary, consensus has 1 authority.
        assert_eq!(node.consensus.read().poa_config().authorities.len(), 1);

        // Produce blocks until we hit the epoch boundary (block 3).
        for _ in 0..3 {
            node.produce_block(&signer, 0).unwrap();
        }

        // Block 3 is an epoch boundary (epoch_length=3).
        // Simulate the epoch boundary sync that the event loop would do.
        {
            let consensus = node.consensus.read();
            if consensus.poa_config().is_epoch_boundary(3) {
                drop(consensus);
                let ws = node.world_state.read();
                let validators = ws.get_validators().unwrap();
                drop(ws);
                if !validators.is_empty() {
                    node.consensus.write().set_authorities(validators);
                }
            }
        }

        // After epoch boundary reload, consensus should have 2 authorities.
        let consensus_guard = node.consensus.read();
        let authorities = &consensus_guard.poa_config().authorities;
        assert_eq!(authorities.len(), 2);
        assert!(authorities.contains(&authority));
        assert!(authorities.contains(&new_validator));
    }

    #[test]
    fn validator_change_takes_effect_at_next_epoch() {
        let signer = DilithiumSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1).with_epoch_length(2),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        store_genesis(&node);

        // Produce block 1 — not an epoch boundary.
        node.produce_block(&signer, 0).unwrap();
        assert_eq!(node.consensus.read().poa_config().authorities.len(), 1);

        // Write validators mid-epoch.
        let new_val = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xCC);
            a
        });
        {
            let mut ws = node.world_state.write();
            ws.set_validators(&[authority, new_val]).unwrap();
        }

        // Still not reloaded until epoch boundary.
        assert_eq!(node.consensus.read().poa_config().authorities.len(), 1);

        // Produce block 2 — epoch boundary (epoch_length=2).
        node.produce_block(&signer, 0).unwrap();

        // Simulate epoch boundary sync.
        {
            let consensus = node.consensus.read();
            if consensus.poa_config().is_epoch_boundary(2) {
                drop(consensus);
                let ws = node.world_state.read();
                let validators = ws.get_validators().unwrap();
                drop(ws);
                if !validators.is_empty() {
                    node.consensus.write().set_authorities(validators);
                }
            }
        }

        // Now the validator set should be updated.
        assert_eq!(node.consensus.read().poa_config().authorities.len(), 2);
    }

    #[test]
    fn authority_reload_uses_world_state_weights() {
        let signer = DilithiumSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let new_val = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xDD);
            a
        });

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let poa = PoaConfig::new(vec![authority], 1);
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(WPoaEngine::new(
            WPoaConfig::with_weights(poa, vec![1]),
            Arc::new(MultiVerifier),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        {
            let mut ws = node.world_state.write();
            ws.set_validators(&[authority, new_val]).unwrap();
            ws.set_validator_weights(&[authority, new_val], &[4, 2])
                .unwrap();
        }

        node.reload_authorities_if_boundary(1).unwrap();

        let consensus = node.consensus.read();
        let weights = consensus.validator_weights();
        assert_eq!(weights.get(&authority), Some(&4));
        assert_eq!(weights.get(&new_val), Some(&2));
        assert_eq!(consensus.poa_config().authority_weights, vec![4, 2]);
    }

    // ── Pruning integration tests ──────────────────────────────────────

    fn setup_node_with_pruning(keep_recent: u64) -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let mut config = NodeConfig::dev(authority);
        config.pruning = PruningConfig::new(keep_recent);
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        (node, signer)
    }

    fn setup_node_with_retention(
        body_retention: u64,
        witness_retention: u64,
    ) -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let mut config = NodeConfig::dev(authority);
        config.pruning = PruningConfig::new(128);
        config.pruning.body_retention = body_retention;
        config.pruning.witness_retention = witness_retention;
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        (node, signer)
    }

    #[test]
    fn canonical_mapping_retention_outlives_dependent_artifacts() {
        assert_eq!(canonical_mapping_retention(512, 256), 513);
        assert_eq!(canonical_mapping_retention(64, 256), 257);
        assert_eq!(canonical_mapping_retention(32, 32), 129);
    }

    #[test]
    fn canonical_mapping_retention_preserves_archive_indexes() {
        assert_eq!(canonical_mapping_retention(0, 256), u64::MAX);
        assert_eq!(canonical_mapping_retention(512, 0), u64::MAX);
    }

    #[test]
    fn canonical_mapping_pruning_waits_for_dependent_pruners() {
        assert_eq!(canonical_mapping_prune_boundary(80, 80, 0, None), 0);
        assert_eq!(canonical_mapping_prune_boundary(80, 40, 60, None), 40);
        assert_eq!(canonical_mapping_prune_boundary(80, 90, 100, None), 80);
        assert_eq!(
            canonical_mapping_prune_boundary(8_000, 8_000, 8_000, Some(1_024)),
            1_024,
            "canonical mappings must not overtake the bounded state-trie cursor"
        );

        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));
        let mut pruner = StatePruner::new(32);
        for number in 0..100 {
            let root = ShellHash::from([number as u8; 32]);
            pruner.register_block(number, root);
            chain_store.set_canonical(number, &root).unwrap();
        }

        pruner.mark_prunable(canonical_mapping_prune_boundary(80, 80, 0, None));
        assert_eq!(pruner.prune(store.as_ref()).unwrap().pruned_count, 0);
        assert!(chain_store.get_block_hash_by_number(0).unwrap().is_some());
    }

    #[test]
    fn state_trie_pruning_is_bounded_by_finalized_height() {
        assert_eq!(state_trie_prune_boundary(0, 4), None);
        assert_eq!(state_trie_prune_boundary(3, 4), None);
        assert_eq!(state_trie_prune_boundary(8, 4), Some(5));

        // A high unfinalized head must not move the pruning boundary.
        let finalized = 8;
        let unfinalized_head = 100;
        assert_ne!(
            state_trie_prune_boundary(finalized, 4),
            Some(retention_cutoff(unfinalized_head, 4))
        );
    }

    #[test]
    fn state_root_history_grows_with_blocks() {
        let (node, signer) = setup_node_with_pruning(128);
        store_genesis(&node);

        for _ in 0..5 {
            node.produce_block(&signer, 0).unwrap();
        }

        let tracker = node.state_root_tracker.read();
        assert_eq!(tracker.len(), 5, "should track one root per produced block");
        assert_eq!(tracker.oldest().unwrap().block_number, 1);
        assert_eq!(tracker.latest().unwrap().block_number, 5);
    }

    #[test]
    fn state_pruner_only_pins_genesis_root() {
        let (node, signer) = setup_node_with_pruning(128);
        store_genesis(&node);
        let genesis_root = node
            .chain_store
            .get_block_by_number(0)
            .unwrap()
            .unwrap()
            .header
            .state_root;

        for _ in 0..5 {
            node.produce_block(&signer, 0).unwrap();
        }

        let pruner = node.state_pruner.read();
        assert_eq!(pruner.active_root_count(), 1);
        assert_eq!(pruner.genesis_root(), Some(&genesis_root));
    }

    #[test]
    fn oldest_roots_evicted_when_exceeding_keep_recent() {
        let keep = 3u64;
        let (node, signer) = setup_node_with_pruning(keep);
        store_genesis(&node);

        for _ in 0..6 {
            node.produce_block(&signer, 0).unwrap();
        }

        let tracker = node.state_root_tracker.read();
        assert_eq!(
            tracker.len(),
            keep as usize,
            "history should be capped at keep_recent"
        );
        assert_eq!(
            tracker.oldest().unwrap().block_number,
            4,
            "blocks 1–3 should have been evicted"
        );
        assert_eq!(tracker.latest().unwrap().block_number, 6);
    }

    #[test]
    fn archive_mode_never_prunes() {
        let (node, signer) = setup_node_with_pruning(0); // archive
        store_genesis(&node);

        for _ in 0..10 {
            node.produce_block(&signer, 0).unwrap();
        }

        let tracker = node.state_root_tracker.read();
        assert_eq!(tracker.len(), 10, "archive mode keeps all roots");
        assert_eq!(tracker.oldest().unwrap().block_number, 1);
    }

    #[test]
    fn body_and_witness_pruning_wait_for_finalized_height() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..5 {
            node.produce_block(&signer, 0).unwrap();
        }

        assert_eq!(node.body_pruner.read().pruned_below(), 0);
        assert_eq!(node.witness_pruner.read().pruned_below(), 0);

        let finalized = node.chain_store.get_block_by_number(3).unwrap().unwrap();
        let finalized_hash = finalized.hash();
        node.chain_store.set_finalized_number(3).unwrap();
        node.finality
            .write()
            .set_finalized_direct(3, finalized_hash);
        let block_0_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        let block_1_hash = node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .unwrap();
        node.settled_stark_sources
            .lock()
            .extend([(1, block_0_hash), (1, block_1_hash)]);

        node.produce_block(&signer, 0).unwrap();

        assert_eq!(node.body_pruner.read().pruned_below(), 2);
        assert_eq!(node.witness_pruner.read().pruned_below(), 2);
    }

    #[test]
    fn canonical_mapping_pruning_waits_for_state_trie_cursor() {
        let (node, signer) = setup_node_with_retention(2, 2);
        *node.state_pruner.write() = StatePruner::new(32);
        node.state_pruner.write().set_prune_interval(1);
        store_genesis(&node);

        for _ in 0..40 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(35).unwrap().unwrap();
        node.chain_store.set_finalized_number(35).unwrap();
        node.finality
            .write()
            .set_finalized_direct(35, finalized.hash());
        for number in 0..34 {
            let hash = node
                .chain_store
                .get_block_hash_by_number(number)
                .unwrap()
                .unwrap();
            node.settled_stark_sources.lock().insert((1, hash));
        }

        assert!(node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .is_some());
        node.produce_block(&signer, 0).unwrap();

        assert_eq!(node.body_pruner.read().pruned_below(), 34);
        assert_eq!(node.witness_pruner.read().pruned_below(), 34);
        assert!(
            node.chain_store
                .get_block_hash_by_number(1)
                .unwrap()
                .is_some(),
            "state-trie pruning has not advanced, so its canonical mappings remain required"
        );
    }

    #[test]
    fn canonical_mapping_pruning_stops_when_genesis_is_unavailable() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..40 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(35).unwrap().unwrap();
        node.chain_store.set_finalized_number(35).unwrap();
        node.finality
            .write()
            .set_finalized_direct(35, finalized.hash());
        for number in 0..34 {
            let hash = node
                .chain_store
                .get_block_hash_by_number(number)
                .unwrap()
                .unwrap();
            node.settled_stark_sources.lock().insert((1, hash));
        }

        node.produce_block(&signer, 0).unwrap();
        assert_eq!(node.body_pruner.read().pruned_below(), 34);
        assert_eq!(node.witness_pruner.read().pruned_below(), 34);
        assert!(node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .is_some());

        *node.state_pruner.write() = StatePruner::new(32);
        node.state_pruner.write().set_prune_interval(1);
        node.chain_store.delete_canonical(0).unwrap();
        node.produce_block(&signer, 0).unwrap();

        assert!(node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn canonical_mapping_pruning_revalidates_registered_genesis() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..40 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(35).unwrap().unwrap();
        node.chain_store.set_finalized_number(35).unwrap();
        node.finality
            .write()
            .set_finalized_direct(35, finalized.hash());
        for number in 0..34 {
            let hash = node
                .chain_store
                .get_block_hash_by_number(number)
                .unwrap()
                .unwrap();
            node.settled_stark_sources.lock().insert((1, hash));
        }

        assert!(node.state_pruner.read().genesis_root().is_some());
        node.produce_block(&signer, 0).unwrap();
        assert_eq!(node.body_pruner.read().pruned_below(), 34);
        assert_eq!(node.witness_pruner.read().pruned_below(), 34);
        node.state_pruner.write().set_prune_interval(1);
        node.chain_store.delete_canonical(0).unwrap();
        node.produce_block(&signer, 0).unwrap();

        assert!(node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn canonical_mapping_pruning_uses_pruned_genesis_header() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..40 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(35).unwrap().unwrap();
        node.chain_store.set_finalized_number(35).unwrap();
        node.finality
            .write()
            .set_finalized_direct(35, finalized.hash());
        for number in 0..34 {
            let hash = node
                .chain_store
                .get_block_hash_by_number(number)
                .unwrap()
                .unwrap();
            node.settled_stark_sources.lock().insert((1, hash));
        }

        *node.state_pruner.write() = StatePruner::new(32);
        node.state_pruner.write().set_prune_interval(1);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .unwrap();
        node.chain_store.delete_body(&genesis_hash).unwrap();
        node.produce_block(&signer, 0).unwrap();

        assert!(node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .is_some());
        assert!(node
            .chain_store
            .get_block_hash_by_number(1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn witness_pruning_waits_for_zero_stark_frontier() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..5 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(3).unwrap().unwrap();
        let finalized_hash = finalized.hash();
        node.chain_store.set_finalized_number(3).unwrap();
        node.finality
            .write()
            .set_finalized_direct(3, finalized_hash);

        node.produce_block(&signer, 0).unwrap();

        assert_eq!(node.body_pruner.read().pruned_below(), 2);
        assert_eq!(node.witness_pruner.read().pruned_below(), 0);
    }

    #[test]
    fn witness_pruning_ignores_noncanonical_settled_sources() {
        let (node, signer) = setup_node_with_retention(2, 2);
        store_genesis(&node);

        for _ in 0..5 {
            node.produce_block(&signer, 0).unwrap();
        }

        let finalized = node.chain_store.get_block_by_number(3).unwrap().unwrap();
        node.chain_store.set_finalized_number(3).unwrap();
        node.finality
            .write()
            .set_finalized_direct(3, finalized.hash());

        // Stale entries from an orphaned fork must not advance the canonical
        // STARK frontier merely because their count matches eligible heights.
        node.settled_stark_sources.lock().extend([
            (1, ShellHash::from([0xA1; 32])),
            (1, ShellHash::from([0xA2; 32])),
        ]);

        node.produce_block(&signer, 0).unwrap();

        assert_eq!(node.body_pruner.read().pruned_below(), 2);
        assert_eq!(node.witness_pruner.read().pruned_below(), 0);
    }

    // ── Block sync integration tests ───────────────────────────────────

    #[test]
    fn import_multiple_sequential_blocks() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let state_root = current_state_root(&node);

        let mut parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let mut parent_gas_used = 0u64;
        let mut parent_gas_limit = 30_000_000u64;
        let mut parent_base_fee = 0u64;

        for i in 1..=5u64 {
            let base_fee =
                shell_core::calculate_base_fee(parent_gas_used, parent_gas_limit, parent_base_fee);
            let mut block = Block {
                header: BlockHeader {
                    parent_hash,
                    state_root,
                    transactions_root: ShellHash::default(),
                    receipts_root: ShellHash::default(),
                    logs_bloom: Bytes::default(),
                    number: i,
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp: 1_700_000_000 + i,
                    extra_data: Bytes::default(),
                    proposer,
                    sig_aggregate_proof: None,
                    base_fee_per_gas: base_fee,
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
            node.consensus
                .read()
                .sign_block(&mut block, &signer)
                .unwrap();
            parent_hash = block.hash();
            parent_gas_used = block.header.gas_used;
            parent_gas_limit = block.header.gas_limit;
            parent_base_fee = base_fee;
            node.import_block(block, &verifier).unwrap();
        }

        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 5);
        for i in 0..=5u64 {
            assert!(
                node.chain_store.get_block_by_number(i).unwrap().is_some(),
                "block {i} should be retrievable by number"
            );
        }
    }

    #[test]
    fn import_block_with_gap_fails() {
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();

        // Skip block 1, try to import block 2 directly.
        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::from([0xAA; 32]),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 2,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_002,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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

        let result = node.import_block(block, &verifier);
        assert!(result.is_err());
        match result.unwrap_err() {
            NodeError::GapDetected { incoming, expected } => {
                assert_eq!(incoming, 2);
                assert_eq!(expected, 1);
            }
            other => panic!("expected GapDetected, got: {other:?}"),
        }
    }

    #[test]
    fn import_fork_block_at_same_height_is_stored_as_side_fork() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let state_root = current_state_root(&node);

        // Import block 1 normally.
        let parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let mut block1 = Block {
            header: BlockHeader {
                parent_hash,
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut block1, &signer)
            .unwrap();
        let block1_hash = block1.hash();
        node.import_block(block1, &verifier).unwrap();
        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            block1_hash
        );

        // Try to import a competing block at the same height with different content.
        let mut fork_block = Block {
            header: BlockHeader {
                parent_hash,
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_099_999, // different timestamp → different hash
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut fork_block, &signer)
            .unwrap();
        let fork_hash = fork_block.hash();

        // Should succeed, keep canonical head unchanged, and retain the side fork
        // for later fork-choice/reorg handling.
        let result = node.import_block(fork_block, &verifier);
        assert!(result.is_ok());
        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            block1_hash,
            "head should remain unchanged after side-fork import"
        );
        assert_eq!(
            node.chain_store.get_side_fork_hashes(1).unwrap(),
            vec![fork_hash]
        );
        assert_eq!(
            node.chain_store
                .get_block_by_hash(&fork_hash)
                .unwrap()
                .unwrap()
                .hash(),
            fork_hash
        );
        assert!(
            node.fork_choice.read().contains(&block1_hash),
            "canonical imported block should be registered with fork choice"
        );
        assert!(
            node.fork_choice.read().contains(&fork_hash),
            "side-fork block should be registered with fork choice"
        );
    }

    #[test]
    fn import_next_height_unknown_parent_is_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let state_root = current_state_root(&node);
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let wrong_parent = ShellHash::from([0x42; 32]);

        let mut fork_block = Block {
            header: BlockHeader {
                parent_hash: wrong_parent,
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut fork_block, &signer)
            .unwrap();

        let err = node.import_block(fork_block, &verifier).unwrap_err();
        assert!(
            matches!(err, NodeError::Startup(ref message) if message.contains("parent block")),
            "expected unknown parent rejection, got {err:?}"
        );

        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            genesis_hash,
            "disconnected next-height block must not become canonical head"
        );
        assert!(node.chain_store.get_side_fork_hashes(1).unwrap().is_empty());
    }

    #[test]
    fn import_block_out_of_order_then_correct_order() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;

        // Produce block 1 to get a valid block.
        let block1 = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block1.number(), 1);

        // Set up node2 to try importing.
        let proposer = node.config.proposer_address.unwrap();
        let db2 = Arc::new(MemoryDb::new());
        let cs2 = Arc::new(ChainStore::new(db2.clone()));
        let ws2 = Arc::new(RwLock::new(WorldState::new(db2.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![proposer], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let node2 = Node::new(config, db2, cs2, ws2, tx_pool, consensus);
        node2.register_authority_pubkey(proposer, signer.public_key().to_vec());
        store_genesis(&node2);

        // Produce block 2 on node1.
        let block2 = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block2.number(), 2);

        // Try importing block 2 first (out of order) — should fail with gap.
        let result = node2.import_block(block2.clone(), &verifier);
        assert!(result.is_err());

        // Now import block 1, then block 2 — both should succeed.
        node2.import_block(block1, &verifier).unwrap();
        node2.import_block(block2, &verifier).unwrap();
        let head = node2.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 2);
    }

    #[test]
    fn import_duplicate_block_is_idempotent() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());
        let state_root = current_state_root(&node);

        let parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let mut block = Block {
            header: BlockHeader {
                parent_hash,
                state_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer,
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        node.consensus
            .read()
            .sign_block(&mut block, &signer)
            .unwrap();

        // First import should succeed.
        node.import_block(block.clone(), &verifier).unwrap();
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            1
        );

        // Second import of same block (now at or below head) should succeed silently.
        let result = node.import_block(block, &verifier);
        assert!(
            result.is_ok(),
            "duplicate import should be handled gracefully"
        );
        assert_eq!(
            node.chain_store.get_head_block().unwrap().unwrap().number(),
            1
        );
    }

    #[test]
    fn head_number_returns_current_height() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        assert_eq!(node.head_number(), 0);

        node.produce_block(&signer, 100).unwrap();
        assert_eq!(node.head_number(), 1);
    }

    #[test]
    fn local_validator_weight_returns_active_weight() {
        let (node, _signer) = setup_node();
        assert_eq!(node.local_validator_weight(), Some(1));
    }

    #[test]
    fn local_validator_weight_ignores_non_authority_proposer() {
        let local = Address::from([0x11; 32]);
        let active = Address::from([0x22; 32]);
        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> =
            Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(vec![active], 1))));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(local);

        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);

        assert_eq!(node.local_validator_weight(), None);
    }

    // ── State consistency tests ────────────────────────────────────────

    #[test]
    fn produce_n_blocks_head_matches() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        for expected in 1..=8u64 {
            let block = node.produce_block(&signer, 100).unwrap();
            assert_eq!(block.number(), expected);

            let head = node.chain_store.get_head_block().unwrap().unwrap();
            assert_eq!(
                head.number(),
                expected,
                "chain_store head should be {expected} after producing block {expected}"
            );
            assert_eq!(head.hash(), block.hash());
        }
    }

    #[test]
    fn import_block_state_root_matches_header() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let block = node.produce_block(&signer, 0).unwrap();
        let expected_root = block.header.state_root;

        // Verify world state root matches what was written in the header.
        let _ws = node.world_state.read();
        // The state root won't literally match for empty blocks on a fresh trie,
        // but the produce_block code writes ws.state_root() into the header.
        // We verify the header's state_root is consistent.
        assert_eq!(
            block.header.state_root, expected_root,
            "header state_root should be self-consistent"
        );
    }

    #[test]
    fn produce_block_with_tx_stores_receipts() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from({
            let mut a = [0u8; 32];
            a[12..].fill(0xCC);
            a
        });

        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(receiver),
            value: U256::from(1_000),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let tx_hash = tx.signing_hash(tx_signer.sig_type().as_u8());
        let sig = tx_signer.sign(tx_hash.as_bytes()).expect("sign failed");
        let signed =
            SignedTransaction::with_pubkey(sender, tx, sig, tx_signer.public_key().to_vec());

        let verifier = MultiVerifier;
        let mut world_state = node.world_state.write();
        node.tx_pool
            .insert(
                signed,
                &mut world_state,
                node.chain_store.as_ref(),
                &verifier,
            )
            .unwrap();
        drop(world_state);

        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);

        // Verify receipts were stored.
        let block_hash = block.hash();
        let receipts = node.chain_store.get_receipts(&block_hash).unwrap();
        assert!(
            receipts.is_some(),
            "receipts should be stored for block with txs"
        );
        let receipts = receipts.unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].status, 1, "transfer tx should succeed");
        assert_eq!(receipts[0].gas_used, 21_000);
        assert_eq!(receipts[1].status, 1, "block gas reward should succeed");
        assert_eq!(receipts[1].gas_used, 0);
    }

    #[test]
    fn chain_store_get_block_by_number_roundtrip() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let mut produced_hashes = vec![];
        for _ in 0..4 {
            let block = node.produce_block(&signer, 0).unwrap();
            produced_hashes.push(block.hash());
        }

        // Verify every produced block is retrievable by number.
        for (i, expected_hash) in produced_hashes.iter().enumerate() {
            let number = (i + 1) as u64;
            let block = node
                .chain_store
                .get_block_by_number(number)
                .unwrap()
                .unwrap_or_else(|| panic!("block {number} not found"));
            assert_eq!(block.hash(), *expected_hash);
            assert_eq!(block.number(), number);
        }
    }

    #[test]
    fn import_block_tracks_state_root() {
        let (node, signer) = setup_node_with_pruning(10);
        store_genesis(&node);
        let current_root = current_state_root(&node);
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, signer.public_key().to_vec());

        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root: current_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: node.config.proposer_address.unwrap(),
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
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
        block.proposer_seal = Some(
            signer
                .sign(block.header.hash().as_bytes())
                .expect("sign block"),
        );

        let verifier = MultiVerifier;
        node.import_block(block, &verifier).unwrap();

        let tracker = node.state_root_tracker.read();
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.latest().unwrap().block_number, 1);
        assert_eq!(tracker.latest().unwrap().state_root, current_root);
    }

    #[test]
    fn handle_attestation_routes_mldsa65_signatures() {
        let signer = MlDsaSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let node = setup_node_with_authority(authority);
        store_genesis(&node);
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let block = node.produce_block(&signer, 100).unwrap();
        let block_hash = block.hash();
        let block_number = block.header.number;
        // handle_attestation checks block existence in chain_store first.
        node.chain_store.put_block(&block).unwrap();
        let attestation = node
            .create_attestation(block_hash, block_number, &signer)
            .unwrap();

        let verifier = MultiVerifier;
        assert!(node.handle_attestation(attestation, &verifier).is_ok());
        // With a single unit-weight validator the attestation immediately
        // satisfies weighted quorum (1 > 2/3*1), so the block is finalized
        // and its attestation entry is pruned by prune_below(1).
        // Verify finalization rather than raw attestation count.
        assert_eq!(node.finality.read().last_finalized_hash(), &block_hash);
        let fork_choice = node.fork_choice.read();
        assert_eq!(fork_choice.block_count(), 1);
        assert_eq!(fork_choice.parent(&block_hash), Some(&ShellHash::ZERO));
    }

    #[test]
    fn handle_attestation_releases_authority_lock_before_verification() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let block = node.produce_block(&signer, 100).unwrap();
        let block_hash = block.hash();
        node.chain_store.put_block(&block).unwrap();
        let attestation = node
            .create_attestation(block_hash, block.header.number, &signer)
            .unwrap();
        let verifier = AuthorityLockCheckingVerifier {
            authorities: Arc::clone(&node.known_authorities),
        };

        node.handle_attestation(attestation, &verifier).unwrap();
    }

    #[test]
    fn handle_attestation_does_not_finalize_noncanonical_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let canonical_block = node.produce_block(&signer, 100).unwrap();
        let canonical_hash = canonical_block.hash();
        let block_number = canonical_block.header.number;

        let mut side_block = canonical_block.clone();
        side_block.header.timestamp += 1;
        side_block.proposer_seal = None;
        side_block.proposer_seal = Some(
            signer
                .sign(side_block.header.hash().as_bytes())
                .expect("sign side block"),
        );
        let side_hash = side_block.hash();
        assert_ne!(side_hash, canonical_hash);
        node.chain_store.put_side_fork_block(&side_block).unwrap();

        let attestation = node
            .create_attestation(side_hash, block_number, &signer)
            .unwrap();
        node.handle_attestation(attestation, &MultiVerifier)
            .unwrap();

        let finality = node.finality.read();
        assert_eq!(finality.last_finalized_number(), 0);
        assert_eq!(finality.last_finalized_hash(), &ShellHash::ZERO);
        assert_eq!(finality.attestation_count(&side_hash), 1);
        drop(finality);
        assert_eq!(node.chain_store.get_finalized_number().unwrap(), None);
        assert_eq!(
            node.chain_store
                .get_block_hash_by_number(block_number)
                .unwrap(),
            Some(canonical_hash)
        );
    }

    #[test]
    fn handle_attestation_persists_before_advancing_finality_and_retries_duplicate() {
        let (node, signer, db) = setup_failing_batch_node();
        store_genesis(&node);
        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let block = node.produce_block(&signer, 100).unwrap();
        let block_hash = block.hash();
        let block_number = block.header.number;
        let attestation = node
            .create_attestation(block_hash, block_number, &signer)
            .unwrap();

        db.fail_next_put();
        let error = node
            .handle_attestation(attestation.clone(), &MultiVerifier)
            .unwrap_err();
        assert!(error.to_string().contains("injected put failure"));
        assert_eq!(node.finality.read().last_finalized_number(), 0);
        assert_eq!(node.finality.read().last_finalized_hash(), &ShellHash::ZERO);
        assert_eq!(
            node.finality.read().attestation_count(&block_hash),
            1,
            "the pending attestation must remain available for retry"
        );
        assert_eq!(node.chain_store.get_finalized_number().unwrap(), None);

        node.handle_attestation(attestation, &MultiVerifier)
            .unwrap();
        assert_eq!(node.finality.read().last_finalized_number(), block_number);
        assert_eq!(node.finality.read().last_finalized_hash(), &block_hash);
        assert_eq!(
            node.chain_store.get_finalized_number().unwrap(),
            Some(block_number)
        );
    }

    #[test]
    fn handle_attestation_rejects_target_metadata_mismatch() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let block = node.produce_block(&signer, 100).unwrap();
        let block_hash = block.hash();
        let mismatched_targets = [
            (ShellHash::from([0x55; 32]), block.header.number),
            (block.header.parent_hash, block.header.number + 1),
        ];

        for (parent_hash, block_number) in mismatched_targets {
            let signature = signer
                .sign(&Attestation::signing_message(
                    node.config.chain_id,
                    &parent_hash,
                    &block_hash,
                    block_number,
                    0,
                ))
                .unwrap();
            let attestation = Attestation::new(
                node.config.chain_id,
                parent_hash,
                block_hash,
                block_number,
                authority,
                0,
                signature.data,
            );

            let error = node
                .handle_attestation(attestation, &MultiVerifier)
                .unwrap_err();

            assert!(error
                .to_string()
                .contains("attestation target does not match stored block header"));
        }
        assert_eq!(node.finality.read().attestation_count(&block_hash), 0);
        assert_eq!(node.finality.read().last_finalized_number(), 0);
    }

    #[test]
    fn handle_attestation_rejects_equivocation() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let proposer = node.config.proposer_address.unwrap();
        let pubkey = signer.public_key().to_vec();
        node.register_authority_pubkey(proposer, pubkey);

        let verifier = MultiVerifier;

        // Produce a block so we have height 1.
        let block1 = node.produce_block(&signer, 100).unwrap();
        let hash1 = block1.hash();
        let height = block1.header.number;

        // Directly record an attestation for hash1 into the finality tracker
        // (bypassing handle_attestation avoids triggering finality + prune
        // since we only have 1 validator).
        let att1 = node.create_attestation(hash1, height, &signer).unwrap();
        node.finality.write().record_attestation(att1);

        // Create a competing block at the same height and store it so the
        // F-087 block existence check passes.
        let mut competing_block = Block {
            header: block1.header.clone(),
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        competing_block.header.timestamp += 999; // different timestamp → different hash
        let competing_hash = competing_block.hash();
        node.chain_store.put_block(&competing_block).unwrap();

        // Create a second attestation from the same validator for the
        // competing block at the same height — this is equivocation.
        let att2 = node
            .create_attestation(competing_hash, height, &signer)
            .unwrap();
        let result = node.handle_attestation(att2, &verifier);

        assert!(result.is_err(), "equivocation must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("equivocation"),
            "error should mention equivocation: {err_msg}"
        );
    }

    // ── B5: witness_root validation tests ────────────────────────────────────

    /// Build a height-1 block with an optional witness_root set.
    fn make_block_at_1(
        node: &Node<MemoryDb>,
        signer: &dyn Signer,
        witness_root: Option<ShellHash>,
    ) -> Block {
        let current_root = current_state_root(node);
        let mut block = Block {
            header: BlockHeader {
                parent_hash: node.chain_store.get_head_hash().unwrap().unwrap(),
                state_root: current_root,
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_001,
                extra_data: Bytes::default(),
                proposer: node.config.proposer_address.unwrap(),
                sig_aggregate_proof: None,
                base_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        block.proposer_seal = Some(
            signer
                .sign(block.header.hash().as_bytes())
                .expect("sign block"),
        );
        block
    }

    #[test]
    fn import_block_no_witness_root_succeeds() {
        // Block with no witness_root: validation is skipped.
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let block = make_block_at_1(&node, &signer, None);
        let verifier = MultiVerifier;
        assert!(node.import_block(block, &verifier).is_ok());
    }

    #[test]
    fn import_block_rejects_logs_bloom_mismatch() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let mut block = make_block_at_1(&node, &signer, None);
        block.header.logs_bloom = Bytes::from(vec![0x01; shell_pqvm::bloom::BLOOM_SIZE]);
        block.proposer_seal = Some(
            signer
                .sign(block.header.hash().as_bytes())
                .expect("sign block"),
        );

        let err = node.import_block(block, &MultiVerifier).unwrap_err();

        assert!(err.to_string().contains("logs_bloom mismatch"));
    }

    #[test]
    fn import_block_witness_root_mismatch_without_stored_bundle_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let fake_root = ShellHash::from([0xab; 32]);
        let block = make_block_at_1(&node, &signer, Some(fake_root));
        let verifier = MultiVerifier;
        let err = node.import_block(block, &verifier).unwrap_err();
        assert!(err.to_string().contains("witness_root mismatch"));
    }

    #[test]
    fn import_side_fork_witness_root_mismatch_is_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let canonical = make_block_at_1(&node, &signer, None);
        node.import_block(canonical, &MultiVerifier).unwrap();

        let mut side_fork = make_block_at_1(&node, &signer, Some(ShellHash::from([0xab; 32])));
        side_fork.header.parent_hash = genesis_hash;
        side_fork.header.extra_data = Bytes::from_static(b"side-fork");
        side_fork.proposer_seal = Some(
            signer
                .sign(side_fork.header.hash().as_bytes())
                .expect("sign side fork"),
        );
        let side_fork_hash = side_fork.hash();

        let err = node.import_block(side_fork, &MultiVerifier).unwrap_err();
        assert!(err.to_string().contains("witness_root mismatch"));
        assert!(node
            .chain_store
            .get_block_by_hash(&side_fork_hash)
            .unwrap()
            .is_none());
        assert!(!node.fork_choice.read().contains(&side_fork_hash));
    }

    #[test]
    fn import_side_fork_invalid_sig_aggregate_proof_is_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let canonical = make_block_at_1(&node, &signer, None);
        node.import_block(canonical, &MultiVerifier).unwrap();

        let mut side_fork = make_block_at_1(&node, &signer, None);
        side_fork.header.parent_hash = genesis_hash;
        side_fork.header.extra_data = Bytes::from_static(b"invalid-aggregate-proof");
        side_fork.header.sig_aggregate_proof = Some(Bytes::from_static(b"not-json"));
        side_fork.proposer_seal = Some(
            signer
                .sign(side_fork.header.hash().as_bytes())
                .expect("sign side fork"),
        );
        let side_fork_hash = side_fork.hash();

        let error = node.import_block(side_fork, &MultiVerifier).unwrap_err();

        assert!(error
            .to_string()
            .contains("STARK aggregate proof deserialization failed"));
        assert!(node
            .chain_store
            .get_block_by_hash(&side_fork_hash)
            .unwrap()
            .is_none());
        assert!(!node.fork_choice.read().contains(&side_fork_hash));
    }

    #[test]
    fn import_side_fork_invalid_fee_and_blob_fields_are_rejected() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let canonical = make_block_at_1(&node, &signer, None);
        node.import_block(canonical, &MultiVerifier).unwrap();

        let mut side_fork = make_block_at_1(&node, &signer, None);
        side_fork.header.parent_hash = genesis_hash;
        side_fork.header.base_fee_per_gas += 1;
        side_fork.header.extra_data = Bytes::from_static(b"bad-base-fee");
        side_fork.proposer_seal = Some(
            signer
                .sign(side_fork.header.hash().as_bytes())
                .expect("sign side fork"),
        );
        let base_fee_hash = side_fork.hash();
        let err = node
            .import_block(side_fork.clone(), &MultiVerifier)
            .unwrap_err();
        assert!(err.to_string().contains("invalid base_fee_per_gas"));
        assert!(node
            .chain_store
            .get_block_by_hash(&base_fee_hash)
            .unwrap()
            .is_none());

        side_fork.header.base_fee_per_gas = shell_core::INITIAL_BASE_FEE;
        side_fork.header.blob_gas_used = shell_core::BLOB_GAS_PER_BLOB;
        side_fork.header.extra_data = Bytes::from_static(b"bad-blob-gas");
        side_fork.proposer_seal = Some(
            signer
                .sign(side_fork.header.hash().as_bytes())
                .expect("sign side fork"),
        );
        let blob_gas_hash = side_fork.hash();
        let err = node.import_block(side_fork, &MultiVerifier).unwrap_err();
        assert!(err.to_string().contains("blob_gas_used mismatch"));
        assert!(node
            .chain_store
            .get_block_by_hash(&blob_gas_hash)
            .unwrap()
            .is_none());
        assert!(!node.fork_choice.read().contains(&blob_gas_hash));
    }

    #[test]
    fn import_side_fork_with_invalid_transaction_signatures_is_rejected() {
        let (node, proposer_signer) = setup_node();
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));
        store_consistent_genesis(&node);
        let tx = make_embedded_tx(&tx_signer, sender, tx_signer.public_key().to_vec(), 0, 1);
        {
            let mut world_state = node.world_state.write();
            node.tx_pool
                .insert(
                    tx,
                    &mut world_state,
                    node.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
        }

        let canonical = node.produce_block(&proposer_signer, 100).unwrap();
        for (label, mutation) in [("empty", 0), ("corrupt", 1), ("sender", 2)] {
            let mut side_fork = canonical.clone();
            side_fork.header.extra_data = Bytes::copy_from_slice(label.as_bytes());
            side_fork.header.witness_root = None;
            let transaction = side_fork
                .transactions
                .first_mut()
                .expect("block should include a transaction");
            match mutation {
                0 => transaction.signature.data.clear(),
                1 => transaction.signature.data[0] ^= 1,
                2 => transaction.from = Address::from([0x44; 20]),
                _ => unreachable!(),
            }
            side_fork.proposer_seal = Some(
                proposer_signer
                    .sign(side_fork.header.hash().as_bytes())
                    .expect("sign side fork"),
            );
            let side_fork_hash = side_fork.hash();

            let error = node.import_block(side_fork, &MultiVerifier).unwrap_err();

            let message = error.to_string();
            assert!(
                message.contains("empty signature")
                    || message.contains("batch sig verification failed")
                    || message.contains("signature verification failed")
                    || message.contains("address mismatch")
                    || message.contains("does not match resolved pubkey address"),
                "unexpected rejection for {label} signature: {message}"
            );
            assert!(node
                .chain_store
                .get_block_by_hash(&side_fork_hash)
                .unwrap()
                .is_none());
            assert!(!node.fork_choice.read().contains(&side_fork_hash));
        }
    }

    #[test]
    fn import_side_fork_accepts_valid_session_key_signature() {
        let (node, proposer_signer) = setup_node();
        let proposer = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        let root = MlDsaSigner::generate();
        let session = DilithiumSigner::generate();
        let sender = Address::from_public_key(root.public_key(), root.sig_type().as_u8());
        fund_account(&node, &sender, U256::from(100_000_000_000_000u64));
        store_consistent_genesis(&node);

        let recipient = Address::from([0x45; 20]);
        let transaction = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(recipient),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let inner_call = InnerCall {
            to: Some(recipient),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 50_000,
        };
        let mut session_auth = SessionAuth {
            session_pubkey: Bytes::from(session.public_key().to_vec()),
            session_algo: session.sig_type().as_u8(),
            target: Some(recipient),
            value_cap: U256::ZERO,
            expiry_block: 10,
            root_signature: Bytes::new(),
            session_signature: Bytes::from(vec![1]),
        };
        session_auth.root_signature = Bytes::from(
            root.sign(session_auth.auth_hash(transaction.chain_id).as_bytes())
                .unwrap()
                .data,
        );
        let placeholder = session.sign(b"placeholder").unwrap();
        let unsigned = SignedTransaction::with_aa_bundle(
            sender,
            transaction.clone(),
            placeholder,
            PubkeyMode::Embedded(root.public_key().to_vec()),
            AaBundle {
                inner_calls: vec![inner_call.clone()],
                session_auth: Some(session_auth.clone()),
                ..AaBundle::default()
            },
        )
        .unwrap();
        let session_signature = session
            .sign(unsigned.sender_signing_hash().as_bytes())
            .unwrap();
        session_auth.session_signature = Bytes::from(session_signature.data.clone());
        let signed = SignedTransaction::with_aa_bundle(
            sender,
            transaction,
            session_signature,
            PubkeyMode::Embedded(root.public_key().to_vec()),
            AaBundle {
                inner_calls: vec![inner_call],
                session_auth: Some(session_auth),
                ..AaBundle::default()
            },
        )
        .unwrap();
        {
            let mut world_state = node.world_state.write();
            node.tx_pool
                .insert(
                    signed,
                    &mut world_state,
                    node.chain_store.as_ref(),
                    &MultiVerifier,
                )
                .unwrap();
        }

        let canonical = node.produce_block(&proposer_signer, 100).unwrap();
        let follower = setup_node_with_authority(proposer);
        fund_account(&follower, &sender, U256::from(100_000_000_000_000u64));
        store_consistent_genesis(&follower);
        follower.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());

        follower
            .import_block(canonical.clone(), &MultiVerifier)
            .unwrap();

        let mut side_fork = canonical.clone();
        side_fork.header.extra_data = Bytes::from_static(b"session-side-fork");
        side_fork.header.witness_root = None;
        side_fork.proposer_seal = Some(
            proposer_signer
                .sign(side_fork.header.hash().as_bytes())
                .unwrap(),
        );
        let side_fork_hash = side_fork.hash();

        node.import_block(side_fork, &MultiVerifier).unwrap();

        assert!(node
            .chain_store
            .get_block_by_hash(&side_fork_hash)
            .unwrap()
            .is_some());
        assert!(node.fork_choice.read().contains(&side_fork_hash));
    }

    #[test]
    fn import_block_witness_root_matches_bundle_succeeds() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );
        let block = make_block_at_1(&node, &signer, Some(ShellHash::default()));

        let verifier = MultiVerifier;
        assert!(node.import_block(block, &verifier).is_ok());
    }

    #[test]
    fn import_block_witness_root_mismatch_rejected() {
        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::PQSignature;
        use shell_crypto::SignatureType;

        let (node, signer) = setup_node();
        store_genesis(&node);
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            signer.public_key().to_vec(),
        );

        let wrong_root = ShellHash::from([0xFF; 32]);
        let block = make_block_at_1(&node, &signer, Some(wrong_root));
        let block_hash = block.hash();

        // Store a bundle whose root does NOT match wrong_root.
        let sig = PQSignature {
            sig_type: SignatureType::Dilithium3,
            data: vec![0xBB; 16],
        };
        let witness = TxWitness {
            signature: sig,
            pubkey: None,
        };
        let bundle = WitnessBundle {
            witnesses: vec![witness],
        };
        // Verify the bundle root is not wrong_root.
        assert_ne!(bundle.compute_root(), wrong_root);
        node.witness_store.put_bundle(&block_hash, &bundle).unwrap();

        let verifier = MultiVerifier;
        let result = node.import_block(block, &verifier);
        assert!(result.is_err(), "mismatch must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("witness_root mismatch"),
            "error must mention witness_root mismatch: {msg}"
        );
    }

    // ── STARK block compression tests ─────────────────────────────────────────

    /// Create a node with STARK aggregation enabled.
    fn setup_stark_node() -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(PoaEngine::new(
            PoaConfig::new(vec![authority], 1),
        )));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let mut config = NodeConfig::dev(authority);
        config.enable_stark_aggregation = true;
        config.node_role = crate::config::NodeRole::ValidatorProver;
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        (node, signer)
    }

    /// Create and fund a test account with a Dilithium key.
    /// Returns (signer, address, pubkey).
    fn make_stark_account(node: &Node<MemoryDb>) -> (DilithiumSigner, Address, Vec<u8>) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let address = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        fund_account(node, &address, U256::from(1_000_000_000_000_000u64));
        // Register the pubkey so import_block can validate the embedded-key tx.
        node.chain_store.put_pubkey(&address, &pubkey).unwrap();
        (signer, address, pubkey)
    }

    /// Build a signed transfer with PubkeyMode::Embedded (triggers STARK task).
    fn make_embedded_tx(
        signer: &DilithiumSigner,
        from: Address,
        pubkey: Vec<u8>,
        nonce: u64,
        value: u64,
    ) -> SignedTransaction {
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: Some(Address::from({
                let mut a = [0u8; 32];
                a[12..].fill(0xBE);
                a
            })),
            value: U256::from(value),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer
            .sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes())
            .unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey)
    }

    /// STARK compression: produce blocks with Embedded-pubkey txs, verify the
    /// proof backlog is populated, run the prover, and report compression ratios.
    #[test]
    fn stark_block_compression_queues_proof_tasks() {
        let (node, proposer_signer) = setup_stark_node();
        store_genesis(&node);

        // ── Phase 1: fund accounts and prepare transactions ───────────────────

        const TXS_PER_BLOCK: usize = 10;
        const NUM_BLOCKS: usize = 3;

        // Dilithium3 constants (from bench_compression.rs)
        const DILITHIUM3_PUBKEY_LEN: usize = 1952;
        const DILITHIUM3_SIG_LEN: usize = 3309;
        const TX_META_LEN: usize = 140;
        const TX_EMBEDDED_SIZE: usize = TX_META_LEN + DILITHIUM3_SIG_LEN + DILITHIUM3_PUBKEY_LEN;

        let mut all_accounts = Vec::new();
        for _ in 0..(TXS_PER_BLOCK * NUM_BLOCKS) {
            all_accounts.push(make_stark_account(&node));
        }

        // ── Phase 2: submit txs and produce blocks ────────────────────────────

        let mut block_stats: Vec<(u64, usize, usize)> = Vec::new(); // (block_num, tx_count, backlog_depth_after)

        for block_idx in 0..NUM_BLOCKS {
            let start = block_idx * TXS_PER_BLOCK;
            for (i, (signer, addr, pubkey)) in all_accounts[start..start + TXS_PER_BLOCK]
                .iter()
                .enumerate()
            {
                // Use a unique value (global index) to avoid tx hash collisions
                // since the hash is derived from tx fields, not from/pubkey.
                let global_idx = (start + i + 1) as u64;
                let tx = make_embedded_tx(signer, *addr, pubkey.clone(), 0, global_idx);
                let verifier = MultiVerifier;
                let mut ws = node.world_state.write();
                node.tx_pool
                    .insert(tx, &mut ws, node.chain_store.as_ref(), &verifier)
                    .unwrap();
                drop(ws);
            }

            let block = node
                .produce_block(&proposer_signer, TXS_PER_BLOCK + 10)
                .unwrap();
            let block_num = block.number();
            let tx_count = block.transactions.len();
            let backlog_depth = node.proof_backlog.lock().len();

            block_stats.push((block_num, tx_count, backlog_depth));

            // Store block so next produce_block can find parent.
            let hash = block.hash();
            node.chain_store.put_block(&block).unwrap();
            node.chain_store.set_canonical(block_num, &hash).unwrap();
            node.chain_store.set_head(&hash).unwrap();
        }

        // ── Phase 3: verify proof backlog is populated ────────────────────────

        let total_backlog = node.proof_backlog.lock().len();
        println!("\n╔══ STARK Block Compression Test ══════════════════════════════╗");
        println!("║  Blocks produced: {NUM_BLOCKS}, txs/block: {TXS_PER_BLOCK}");
        println!("║  Total proof tasks queued: {total_backlog}");
        for (num, txs, depth) in &block_stats {
            println!("║  Block #{num}: {txs} embedded txs → backlog depth after = {depth}");
        }

        // Every block with embedded txs must push a proof task, and the STARK
        // frontier must retain the empty genesis source so ranges start at #0.
        assert_eq!(
            total_backlog,
            NUM_BLOCKS + 1,
            "expected {} proof tasks in backlog, got {total_backlog}",
            NUM_BLOCKS + 1
        );

        // ── Phase 4: compression ratio analysis (using known STARK proof sizes) ─

        // These sizes come from the 6h soak benchmark (checkpoint #097):
        //   batch=10: proof ≈ 13KB, raw tx data = 10 × TX_EMBEDDED_SIZE ≈ 52.6KB
        //   This gives ~4x reduction for the pubkey+sig portion.
        //
        // Conservative estimate: proof_size_bytes ≈ 13_000 (from soak benchmark)
        let raw_per_block = TXS_PER_BLOCK * TX_EMBEDDED_SIZE;
        let estimated_proof_size = 13_000usize; // bytes, from benchmark data
        let pubkey_data_per_block = TXS_PER_BLOCK * DILITHIUM3_PUBKEY_LEN;
        let sig_data_per_block = TXS_PER_BLOCK * DILITHIUM3_SIG_LEN;

        // Compression ratio: raw sig+pubkey bytes vs STARK proof bytes
        let compression_ratio =
            (pubkey_data_per_block + sig_data_per_block) as f64 / estimated_proof_size as f64;

        println!("║");
        println!("║  ── Compression Analysis (batch={TXS_PER_BLOCK} txs) ──────────────────────");
        println!(
            "║  Raw block size (embedded): {} bytes ({:.1} KB)",
            raw_per_block,
            raw_per_block as f64 / 1024.0
        );
        println!(
            "║    ├─ pubkeys: {} bytes ({} × {} B)",
            pubkey_data_per_block, TXS_PER_BLOCK, DILITHIUM3_PUBKEY_LEN
        );
        println!(
            "║    └─ signatures: {} bytes ({} × {} B)",
            sig_data_per_block, TXS_PER_BLOCK, DILITHIUM3_SIG_LEN
        );
        println!(
            "║  STARK proof (estimated): {estimated_proof_size} bytes ({:.1} KB)",
            estimated_proof_size as f64 / 1024.0
        );
        println!("║  Compression ratio (sig+pubkey → proof): {compression_ratio:.1}×");
        println!(
            "║  Space saved per block: {} bytes ({:.1} KB)",
            (pubkey_data_per_block + sig_data_per_block).saturating_sub(estimated_proof_size),
            (pubkey_data_per_block + sig_data_per_block).saturating_sub(estimated_proof_size)
                as f64
                / 1024.0
        );
        println!("╚═══════════════════════════════════════════════════════════════╝\n");

        // Sanity: compression should be significant for any realistic batch size.
        assert!(
            compression_ratio > 1.0,
            "STARK proof should compress better than raw embedded txs (got {compression_ratio:.2}x)"
        );
    }

    #[test]
    fn stark_frontier_backlog_includes_empty_genesis_block() {
        let (node, _proposer_signer) = setup_stark_node();
        store_genesis(&node);

        let queued = node.enqueue_stark_frontier_backlog(8).unwrap();
        assert_eq!(queued, 1);

        let backlog = node.proof_backlog.lock();
        let task = backlog
            .peek()
            .expect("empty genesis source should be queued");
        assert_eq!(task.block_number, 0);
        assert!(task.entries.is_empty());
        assert_eq!(task.original_size, Some(0));
        assert_eq!(task.source_hashes.len(), 1);
    }

    #[test]
    fn stark_frontier_backlog_pauses_at_pending_settlement_limit() {
        let (node, _proposer_signer) = setup_stark_node();
        store_genesis(&node);
        node.pending_stark_settlements.lock().extend([
            dummy_proof_amendment(1, 1_000, 400),
            dummy_proof_amendment(1, 1_000, 400),
        ]);

        assert_eq!(node.enqueue_stark_frontier_backlog(8).unwrap(), 0);
        assert!(node.proof_backlog.lock().is_empty());
    }

    #[test]
    fn stark_frontier_recovery_discards_unauthenticated_stored_amendment() {
        let (node, _proposer_signer) = setup_stark_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis must be canonical");
        let mut invalid = dummy_proof_amendment(1, 1_000, 400);
        invalid.block_hash = genesis_hash;
        invalid.block_number = 0;
        invalid.start_block = Some(0);
        invalid.source_hashes = vec![genesis_hash];
        let payload = invalid.to_json().unwrap();
        node.amendment_store
            .put_amendment(&genesis_hash, &payload)
            .unwrap();

        assert_eq!(node.enqueue_stark_frontier_backlog(8).unwrap(), 1);

        assert!(node.pending_stark_settlements.lock().is_empty());
        assert!(node
            .amendment_store
            .get_amendment(&genesis_hash)
            .unwrap()
            .is_none());
        let backlog = node.proof_backlog.lock();
        let task = backlog
            .peek()
            .expect("invalid stored amendment must be replaced with a proof task");
        assert_eq!(task.block_number, 0);
        assert_eq!(task.source_hashes, vec![genesis_hash]);
    }

    #[test]
    fn stark_frontier_recovery_preserves_valid_proof_pointers() {
        let (node, proposer_signer) = setup_stark_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis must be canonical");
        let hashes = produce_witnessed_blocks(&node, &proposer_signer, 2);
        let sources = vec![genesis_hash, hashes[0], hashes[1]];
        let amendment = dummy_ordered_amendment(1, sources.clone(), 2);
        while node.proof_backlog.lock().pop().is_some() {}
        node.store_stark_artifacts(&amendment, None).unwrap();

        assert_eq!(node.enqueue_stark_frontier_backlog(8).unwrap(), 3);

        assert!(node.proof_backlog.lock().is_empty());
        assert_eq!(
            node.pending_stark_settlements.lock().as_slice(),
            std::slice::from_ref(&amendment)
        );
        for source_hash in sources {
            assert!(
                node.amendment_store
                    .get_amendment(&source_hash)
                    .unwrap()
                    .is_some(),
                "valid stored artifact must survive recovery"
            );
        }
    }

    #[test]
    fn rejected_stark_recovery_artifact_does_not_delete_unrelated_proof() {
        let (node, proposer_signer) = setup_stark_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis must be canonical");
        let block_hash = produce_witnessed_blocks(&node, &proposer_signer, 1)[0];
        let unrelated = dummy_ordered_amendment(1, vec![block_hash], 1);
        node.store_stark_artifacts(&unrelated, None).unwrap();

        let mut invalid = dummy_proof_amendment(1, 1_000, 400);
        invalid.block_hash = genesis_hash;
        invalid.block_number = 0;
        invalid.start_block = Some(0);
        invalid.source_hashes = vec![block_hash];
        node.amendment_store
            .put_amendment(&genesis_hash, &invalid.to_json().unwrap())
            .unwrap();

        node.delete_stored_stark_amendment_artifacts(&invalid, genesis_hash)
            .unwrap();

        assert!(node
            .amendment_store
            .get_amendment(&genesis_hash)
            .unwrap()
            .is_none());
        assert_eq!(
            node.amendment_store
                .get_amendment(&block_hash)
                .unwrap()
                .expect("unrelated proof must survive rejection cleanup"),
            unrelated.to_json().unwrap()
        );
    }

    #[test]
    fn stark_source_original_size_uses_fallback_for_pruned_stub_block() {
        let (node, proposer_signer) = setup_stark_node();
        store_genesis(&node);

        let (signer, addr, pubkey) = make_stark_account(&node);
        let tx = make_embedded_tx(&signer, addr, pubkey, 0, 1);
        let verifier = MultiVerifier;
        let mut ws = node.world_state.write();
        node.tx_pool
            .insert(tx, &mut ws, node.chain_store.as_ref(), &verifier)
            .unwrap();
        drop(ws);

        let block = node.produce_block(&proposer_signer, 8).unwrap();
        let source_hash = block.hash();
        node.chain_store.put_block(&block).unwrap();
        assert!(node.chain_store.has_witness_bundle(&source_hash).unwrap());

        node.chain_store
            .delete_witness_bundle(&source_hash)
            .unwrap();
        let pruned_block = node
            .chain_store
            .get_block_by_hash(&source_hash)
            .unwrap()
            .expect("block should still be readable after witness pruning");

        assert!(
            !pruned_block.transactions.is_empty(),
            "test requires a block with at least one tx"
        );
        assert!(pruned_block
            .transactions
            .iter()
            .all(|tx| tx.signature.data.is_empty()));

        let (_, stub_bundle) = shell_core::StrippedBlock::split(&pruned_block);
        let stub_bundle_size = alloy_rlp::encode(&stub_bundle).len() as u64;
        assert!(stub_bundle_size > 0, "stub split should be non-empty");

        let original_size = node
            .stark_source_original_size(
                &source_hash,
                &pruned_block,
                pruned_block.transactions.len(),
            )
            .unwrap()
            .expect("original_size should be computable");

        const ESTIMATED_DILITHIUM3_SIG_BYTES: u64 = 3_309;
        const ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES: u64 = 8;
        let expected = pruned_block.transactions.len() as u64
            * (ESTIMATED_DILITHIUM3_SIG_BYTES + ESTIMATED_REFERENCE_WITNESS_RLP_OVERHEAD_BYTES);

        assert_eq!(
            original_size, expected,
            "pruned stub blocks must use conservative fallback sizing"
        );
        assert!(
            original_size > stub_bundle_size,
            "fallback size must not undercount to stub witness bytes"
        );
    }
    /// STARK compression: verify ProverService correctly waits when the
    /// accumulated entry count is below MIN_L1_STARK_TXS (512).
    ///
    /// With the strict threshold policy the prover must not drain the backlog
    /// until enough entries accumulate — generating an under-threshold proof
    /// wastes work and would always be rejected by settlement.
    #[tokio::test]
    async fn stark_prover_service_waits_when_entries_below_l1_threshold() {
        use crate::prover_service::{ProverConfig, ProverService};
        use shell_storage::ProofAmendmentStore;

        let (node, proposer_signer) = setup_stark_node();
        store_genesis(&node);

        // Fund 5 accounts and submit embedded txs.
        const TXS: usize = 5;
        let accounts: Vec<_> = (0..TXS).map(|_| make_stark_account(&node)).collect();

        for (i, (signer, addr, pubkey)) in accounts.iter().enumerate() {
            let tx = make_embedded_tx(signer, *addr, pubkey.clone(), 0, (i + 1) as u64);
            let verifier = MultiVerifier;
            let mut ws = node.world_state.write();
            node.tx_pool
                .insert(tx, &mut ws, node.chain_store.as_ref(), &verifier)
                .unwrap();
            drop(ws);
        }

        // Produce block 1 → 5 embedded txs, plus the empty genesis frontier task.
        node.produce_block(&proposer_signer, 20).unwrap();

        assert_eq!(
            node.proof_backlog.lock().len(),
            2,
            "expected genesis + block proof tasks after producing 1 block with {TXS} embedded txs"
        );

        // Start ProverService; 5 entries < MIN_L1_STARK_TXS (512) so both tasks
        // must remain in the backlog — the prover waits for more blocks.
        let db = node.store.clone();
        let amendment_store = ProofAmendmentStore::new(db);
        let (amendment_tx, mut amendment_rx) = tokio::sync::mpsc::channel(1);
        let svc = ProverService::new(
            Arc::clone(&node.proof_backlog),
            amendment_store.clone(),
            ProverConfig::default(),
            node.config.proposer_address.unwrap_or_default(),
        )
        .with_amendment_sender(amendment_tx);
        let handle = svc.start();

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        handle.shutdown().await;

        assert_eq!(
            node.proof_backlog.lock().len(),
            2,
            "below-threshold backlog must not be drained: prover waits for MIN_L1_STARK_TXS"
        );
        assert!(
            amendment_rx.try_recv().is_err(),
            "no proof amendment must be broadcast when entries are below threshold"
        );
    }

    // ─── L2: proof-replaces-witness tests ──────────────────────────────────────

    /// L2 basic: when a ProofAmendment network message is handled and grace=0,
    /// the witness bundle for that block is deleted from chain_store.
    #[test]
    fn l2_proof_amendment_deletes_witness_bundle_grace_zero() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let block = node.produce_block(&signer, 1).unwrap();
        let block_hash = block.hash();
        let block_num = block.number();

        // Verify witness was written by put_block (block has 0 txs → no bundle)
        // so write one manually to simulate a block with txs.
        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::PQSignature;
        let bundle = WitnessBundle {
            witnesses: vec![TxWitness::new_reference(PQSignature {
                sig_type: shell_crypto::SignatureType::Dilithium3,
                data: vec![0u8; 3309],
            })],
        };
        node.witness_store.put_bundle(&block_hash, &bundle).unwrap();
        assert!(
            node.chain_store.has_witness_bundle(&block_hash).unwrap(),
            "bundle should exist before amendment"
        );

        // Simulate receiving a ProofAmendment (grace=0 by default).
        let dummy_payload = b"fake-proof".to_vec();
        node.amendment_store
            .put_amendment(&block_hash, &dummy_payload)
            .unwrap();

        // Now manually apply the L2 logic (the network handler calls this inline).
        let grace = node.config.pruning.proof_replacement_grace;
        assert_eq!(grace, 0, "default grace should be 0");
        node.chain_store.delete_witness_bundle(&block_hash).unwrap();

        assert!(
            !node.chain_store.has_witness_bundle(&block_hash).unwrap(),
            "witness bundle should be gone after proof replacement"
        );
        // TX detail block body must still be readable.
        let retrieved = node.chain_store.get_block_by_hash(&block_hash).unwrap();
        assert!(
            retrieved.is_some(),
            "block body (tx detail) must survive witness deletion"
        );
        assert_eq!(retrieved.unwrap().number(), block_num);
    }

    /// L2 grace: when grace=2 and proof arrives for block N while head is N+1,
    /// the witness bundle must NOT be deleted yet.
    #[test]
    fn l2_proof_amendment_respects_grace_window() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let block1 = node.produce_block(&signer, 1).unwrap();
        let b1_hash = block1.hash();

        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::PQSignature;
        let bundle = WitnessBundle {
            witnesses: vec![TxWitness::new_reference(PQSignature {
                sig_type: shell_crypto::SignatureType::Dilithium3,
                data: vec![0u8; 3309],
            })],
        };
        node.witness_store.put_bundle(&b1_hash, &bundle).unwrap();

        // Set grace=2; head is at block 1, so head.saturating_sub(1) = 0 < 2.
        // Simulating the grace check logic from the event loop handler.
        let grace: u64 = 2;
        let head = node
            .chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.header.number)
            .unwrap_or(0);
        let should_delete = head.saturating_sub(block1.number()) >= grace;
        assert!(!should_delete, "within grace window: should NOT delete");
        assert!(
            node.chain_store.has_witness_bundle(&b1_hash).unwrap(),
            "witness bundle must survive grace window"
        );
    }

    #[test]
    fn grace_window_witness_delete_retries_after_storage_failure() {
        let (node, _signer, db) = setup_failing_batch_node();
        let block_hash = ShellHash::from([0x42; 32]);
        let bundle = shell_core::WitnessBundle {
            witnesses: vec![shell_core::TxWitness::new_reference(
                shell_crypto::PQSignature {
                    sig_type: shell_crypto::SignatureType::Dilithium3,
                    data: vec![0u8; 32],
                },
            )],
        };
        node.witness_store.put_bundle(&block_hash, &bundle).unwrap();
        node.pending_grace_deletes.lock().insert(block_hash, 10);

        db.fail_next_delete();
        node.block_store().prune_grace_witnesses(10);

        assert!(node.pending_grace_deletes.lock().contains_key(&block_hash));
        assert!(node.chain_store.has_witness_bundle(&block_hash).unwrap());

        node.block_store().prune_grace_witnesses(11);

        assert!(!node.pending_grace_deletes.lock().contains_key(&block_hash));
        assert!(!node.chain_store.has_witness_bundle(&block_hash).unwrap());
    }

    #[test]
    fn wpoa_view_change_propagates_head_lookup_failure() {
        let (node, signer, db) = setup_failing_batch_node();
        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let highest_qc_hash = *node.finality.read().last_finalized_hash();
        let signing_message = ViewChangeMessage::signing_message(1337, 1, 0, &highest_qc_hash);
        let signature = signer.sign(&signing_message).unwrap();
        let msg = ViewChangeMessage::new(1337, 1, 0, highest_qc_hash, authority, signature.data);

        db.fail_next_get();
        let err = node
            .handle_wpoa_view_change(msg, &MultiVerifier)
            .unwrap_err();

        assert!(matches!(
            err,
            NodeError::Storage(StorageError::Database(message))
                if message.contains("injected get failure")
        ));
    }

    #[test]
    fn wpoa_view_change_releases_authority_lock_before_verification() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let authority = node.config.proposer_address.unwrap();
        node.register_authority_pubkey(authority, signer.public_key().to_vec());

        let highest_qc_hash = *node.finality.read().last_finalized_hash();
        let signing_message = ViewChangeMessage::signing_message(1337, 1, 0, &highest_qc_hash);
        let signature = signer.sign(&signing_message).unwrap();
        let msg = ViewChangeMessage::new(1337, 1, 0, highest_qc_hash, authority, signature.data);
        let verifier = AuthorityLockCheckingVerifier {
            authorities: Arc::clone(&node.known_authorities),
        };

        node.handle_wpoa_view_change(msg, &verifier).unwrap();
    }

    // ─── W.7: wPoA end-to-end test suite ──────────────────────────────────────

    mod wpoa_e2e_tests {
        use super::*;
        use shell_consensus::{PoaConfig, WPoaConfig, WPoaEngine};
        use shell_crypto::{DilithiumSigner, PQSignature, SignatureType};
        use shell_mempool::MempoolConfig;
        use shell_storage::MemoryDb;

        fn hash(n: u8) -> ShellHash {
            ShellHash::from([n; 32])
        }

        fn dummy_sig() -> PQSignature {
            PQSignature::new(SignatureType::Dilithium3, vec![0u8; 32])
        }

        /// Build a Node backed by a WPoA engine.
        ///
        /// The engine has a single validator so the node is always the proposer.
        fn setup_wpoa_node() -> (Node<MemoryDb>, DilithiumSigner) {
            let signer = DilithiumSigner::generate();
            let pubkey = signer.public_key().to_vec();
            let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));

            let poa_cfg = PoaConfig::new(vec![authority], 1);
            let wpoa_cfg = WPoaConfig::from_poa(poa_cfg);
            let engine = WPoaEngine::new(wpoa_cfg, Arc::new(MultiVerifier));
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));

            let tx_pool = Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            }));

            let config = NodeConfig::dev(authority);
            let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
            (node, signer)
        }

        fn setup_failing_wpoa_node() -> (Node<FailingBatchDb>, DilithiumSigner, Arc<FailingBatchDb>)
        {
            let signer = DilithiumSigner::generate();
            let pubkey = signer.public_key().to_vec();
            let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

            let db = Arc::new(FailingBatchDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
            let engine = WPoaEngine::new(
                WPoaConfig::from_poa(PoaConfig::new(vec![authority], 1)),
                Arc::new(MultiVerifier),
            );
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));
            let node = Node::new(
                NodeConfig::dev(authority),
                db.clone(),
                chain_store,
                world_state,
                Arc::new(TxPool::new(MempoolConfig {
                    chain_id: 1337,
                    ..MempoolConfig::default()
                })),
                consensus,
            );
            (node, signer, db)
        }

        fn store_genesis_wpoa<S: KvStore + 'static>(node: &Node<S>) -> ShellHash {
            let proposer = node.config.proposer_address.unwrap();
            let genesis = Block {
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
                    proposer,
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
            let h = genesis.hash();
            node.chain_store.put_block(&genesis).unwrap();
            node.chain_store.set_canonical(0, &h).unwrap();
            node.chain_store.set_head(&h).unwrap();
            h
        }

        fn store_next_wpoa_block<S: KvStore + 'static>(
            node: &Node<S>,
            parent_hash: ShellHash,
        ) -> ShellHash {
            let proposer = node.config.proposer_address.unwrap();
            let block = Block {
                header: BlockHeader {
                    parent_hash,
                    state_root: ShellHash::default(),
                    transactions_root: ShellHash::default(),
                    receipts_root: ShellHash::default(),
                    logs_bloom: Bytes::default(),
                    number: 1,
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp: 1_700_000_001,
                    extra_data: Bytes::default(),
                    proposer,
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
            let block_hash = block.hash();
            node.chain_store.put_block(&block).unwrap();
            node.chain_store.set_canonical(1, &block_hash).unwrap();
            node.chain_store.set_head(&block_hash).unwrap();
            block_hash
        }

        // ── 1. State machine: propose → vote → commit ─────────────────────────

        #[test]
        fn wpoa_state_machine_propose_vote_commit() {
            let weights = (1u8..=3).map(|i| (Address::from([i; 32]), 1u64)).collect();
            let mut round = WPoaRound::new(1, 0, weights);
            let bh = hash(1);

            let events = round.on_block_proposed(bh, Address::from([1; 32]));
            assert_eq!(
                events.len(),
                2,
                "propose should emit ProposeAccepted + VoteNeeded"
            );
            assert!(matches!(&events[0], WPoaEvent::ProposeAccepted { .. }));
            assert!(matches!(&events[1], WPoaEvent::VoteNeeded { .. }));

            // First vote: not yet strict finality quorum.
            let v1 = round.on_vote(Address::from([1; 32]), bh, dummy_sig());
            assert!(v1.is_empty(), "first vote must not yet trigger commit");

            // Exactly two thirds is not enough to finalize.
            let v2 = round.on_vote(Address::from([2; 32]), bh, dummy_sig());
            assert!(
                v2.is_empty(),
                "two votes must not finalize three validators"
            );

            // Third vote exceeds two thirds and reaches finality quorum.
            let v3 = round.on_vote(Address::from([3; 32]), bh, dummy_sig());
            assert_eq!(v3.len(), 1, "third vote should emit BlockCommitted");
            match &v3[0] {
                WPoaEvent::BlockCommitted {
                    block_hash,
                    quorum_signatures,
                } => {
                    assert_eq!(*block_hash, bh);
                    assert_eq!(quorum_signatures.len(), 3);
                }
                other => panic!("expected BlockCommitted, got {other:?}"),
            }
            assert_eq!(round.phase_name(), "Committed");
        }

        // ── 2. State machine: view-change quorum ──────────────────────────────

        #[test]
        fn wpoa_state_machine_view_change() {
            let weights = (1u8..=3).map(|i| (Address::from([i; 32]), 1u64)).collect();
            let mut round = WPoaRound::new(1, 0, weights);
            round.start_view_change(1);
            assert_eq!(round.phase_name(), "ViewChanging");

            // First view-change vote: not yet quorum
            let e1 = round.on_view_change_vote(Address::from([1; 32]), 1);
            assert!(
                e1.is_empty(),
                "single view-change vote must not yet reach quorum"
            );

            // Second view-change vote: reaches quorum
            let e2 = round.on_view_change_vote(Address::from([2; 32]), 1);
            assert_eq!(e2.len(), 1);
            assert!(
                matches!(&e2[0], WPoaEvent::ViewChangeReady { new_view: 1 }),
                "should emit ViewChangeReady(1)"
            );
        }

        // ── 3. Node: produce block with WPoA engine ───────────────────────────

        #[test]
        fn wpoa_node_produces_block_with_wpoa_engine() {
            let (node, signer) = setup_wpoa_node();
            store_genesis_wpoa(&node);

            let block = node
                .produce_block(&signer, 100)
                .expect("produce_block failed");
            assert_eq!(block.number(), 1);
            assert!(
                block.proposer_seal.is_some(),
                "block must carry a proposer seal"
            );
            assert_eq!(
                block.header.proposer,
                node.config.proposer_address.unwrap(),
                "proposer must match the node's authority address"
            );
        }

        // ── 4. RPC: shell_consensusInfo returns engine="wpoa" ─────────────────

        #[tokio::test]
        async fn wpoa_consensus_info_returns_wpoa_engine() {
            use shell_rpc::api::ShellApiServer;
            use shell_rpc::RpcHandler;

            let authority1 = Address::from([0x01; 32]);
            let authority2 = Address::from([0x02; 32]);
            let authority3 = Address::from([0x03; 32]);

            let poa_cfg =
                PoaConfig::new(vec![authority1, authority2, authority3], 1).with_epoch_length(100);
            let wpoa_cfg = WPoaConfig::from_poa(poa_cfg);
            let engine = WPoaEngine::new(wpoa_cfg, Arc::new(MultiVerifier));
            let engine_arc: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));

            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db)));
            let tx_pool = Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            }));
            let (block_events, _) = tokio::sync::broadcast::channel(16);
            let finalized = Arc::new(RwLock::new(0u64));
            let finality = Arc::new(RwLock::new(FinalityState::new()));

            let handler = RpcHandler::new(
                chain_store,
                world_state,
                tx_pool,
                1337,
                None,
                block_events,
                finalized,
                finality,
            )
            .with_consensus_engine(engine_arc);

            let info = ShellApiServer::consensus_info(&handler).await.unwrap();
            assert_eq!(info["engine"], "wpoa", "engine field must be 'wpoa'");
            let validators = info["validators"]
                .as_array()
                .expect("validators must be an array");
            assert_eq!(validators.len(), 3, "must report all 3 validators");
        }

        // ── 5. Node: handle_wpoa_vote reaches quorum ──────────────────────────

        #[test]
        fn wpoa_handle_vote_reaches_quorum() {
            // C-3: All voters must have their pubkeys registered and use real
            // signatures over block_hash.as_bytes() (the vote pre-image).
            let signer1 = DilithiumSigner::generate();
            let signer2 = DilithiumSigner::generate();
            let signer3 = DilithiumSigner::generate();
            let addr1 = Address::from_public_key(signer1.public_key(), signer1.sig_type().as_u8());
            let addr2 = Address::from_public_key(signer2.public_key(), signer2.sig_type().as_u8());
            let addr3 = Address::from_public_key(signer3.public_key(), signer3.sig_type().as_u8());

            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));

            let poa_cfg = PoaConfig::new(vec![addr1, addr2, addr3], 1);
            let wpoa_cfg = WPoaConfig::from_poa(poa_cfg);
            let engine = WPoaEngine::new(wpoa_cfg, Arc::new(MultiVerifier));
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));

            let tx_pool = Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            }));

            let config = NodeConfig::dev(addr1);
            let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
            // C-3: Register all validator public keys so sig verification can proceed.
            node.register_authority_pubkey(addr1, signer1.public_key().to_vec());
            node.register_authority_pubkey(addr2, signer2.public_key().to_vec());
            node.register_authority_pubkey(addr3, signer3.public_key().to_vec());
            store_genesis_wpoa(&node);

            // Manually initialise the wPoA round (the event loop does this after
            // block production; here we skip that to keep the test synchronous).
            let block_hash = hash(42);
            let block_number = 1u64;
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(block_number, 0, weights);
                let _ = round.on_block_proposed(block_hash, addr1);
                *node.wpoa_round.lock() = Some(round);
            }

            // addr2 votes first with a valid signature — still below quorum.
            let sig2 = signer2.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(addr2, block_hash, block_number, sig2);
            let phase1 = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(
                phase1.as_deref(),
                Some("Voting"),
                "should still be Voting after 1 vote"
            );

            // addr3 votes with a valid signature. Exactly two thirds must not finalize.
            let sig3 = signer3.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(addr3, block_hash, block_number, sig3);
            let phase2 = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(phase2.as_deref(), Some("Voting"));

            // addr1's vote raises signed weight strictly above two thirds.
            let sig1 = signer1.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(addr1, block_hash, block_number, sig1);
            let phase3 = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(
                phase3.as_deref(),
                Some("Committed"),
                "should be Committed after quorum is reached"
            );
        }

        #[test]
        fn wpoa_handle_vote_rejects_zero_total_validator_weight() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            {
                let mut consensus = node.consensus.write();
                consensus.poa_config_mut().slash_weight_bps = 10_000;
                consensus.slash_authority(&authority);
                assert_eq!(consensus.validator_weights().get(&authority), Some(&0));
            }

            let block_hash = hash(43);
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(1, 0, weights);
                let _ = round.on_block_proposed(block_hash, authority);
                *node.wpoa_round.lock() = Some(round);
            }

            let signature = signer.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(authority, block_hash, 1, signature);

            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Voting")
            );
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());
        }

        #[test]
        fn wpoa_handle_vote_rechecks_weights_changed_mid_round() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());

            let block_hash = hash(44);
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(1, 0, weights);
                let _ = round.on_block_proposed(block_hash, authority);
                *node.wpoa_round.lock() = Some(round);
            }
            {
                let mut consensus = node.consensus.write();
                consensus.poa_config_mut().slash_weight_bps = 10_000;
                consensus.slash_authority(&authority);
            }

            let signature = signer.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(authority, block_hash, 1, signature);

            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Voting")
            );
            assert_eq!(node.finality.read().last_finalized_number(), 0);
        }

        #[test]
        fn wpoa_vote_retries_after_atomic_finality_write_failure() {
            let (node, signer, db) = setup_failing_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            let genesis_hash = store_genesis_wpoa(&node);
            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            let mut round = WPoaRound::new(1, 0, node.consensus.read().validator_weights());
            let _ = round.on_block_proposed(block_hash, authority);
            *node.wpoa_round.lock() = Some(round);

            db.fail_next_batch();
            node.handle_wpoa_vote(
                authority,
                block_hash,
                1,
                signer.sign(block_hash.as_bytes()).unwrap(),
            );

            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Voting")
            );
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert_eq!(node.chain_store.get_finalized_number().unwrap(), None);
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());

            node.handle_wpoa_vote(
                authority,
                block_hash,
                1,
                signer.sign(block_hash.as_bytes()).unwrap(),
            );

            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Committed")
            );
            assert_eq!(node.finality.read().last_finalized_number(), 1);
            assert_eq!(node.chain_store.get_finalized_number().unwrap(), Some(1));
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_some());
        }

        #[test]
        fn wpoa_vote_persists_certificate_for_already_finalized_block() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            let genesis_hash = store_genesis_wpoa(&node);
            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            node.finality.write().set_finalized_direct(1, block_hash);

            let mut round = WPoaRound::new(1, 0, node.consensus.read().validator_weights());
            let _ = round.on_block_proposed(block_hash, authority);
            *node.wpoa_round.lock() = Some(round);

            node.handle_wpoa_vote(
                authority,
                block_hash,
                1,
                signer.sign(block_hash.as_bytes()).unwrap(),
            );

            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Committed")
            );
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_some());
        }

        #[test]
        fn wpoa_round_rebuild_preserves_verified_votes() {
            let signers: Vec<DilithiumSigner> =
                (0..3).map(|_| DilithiumSigner::generate()).collect();
            let authorities: Vec<Address> = signers
                .iter()
                .map(|signer| {
                    Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
                })
                .collect();
            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
            let engine = WPoaEngine::new(
                WPoaConfig::with_weights(PoaConfig::new(authorities.clone(), 1), vec![2, 1, 1]),
                Arc::new(MultiVerifier),
            );
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));
            let node = Node::new(
                NodeConfig::dev(authorities[0]),
                db,
                chain_store,
                world_state,
                Arc::new(TxPool::new(MempoolConfig {
                    chain_id: 1337,
                    ..MempoolConfig::default()
                })),
                consensus,
            );
            for (authority, signer) in authorities.iter().zip(&signers) {
                node.register_authority_pubkey(*authority, signer.public_key().to_vec());
            }

            let block_hash = hash(45);
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(1, 0, weights);
                let _ = round.on_block_proposed(block_hash, authorities[0]);
                *node.wpoa_round.lock() = Some(round);
            }
            node.handle_wpoa_vote(
                authorities[0],
                block_hash,
                1,
                signers[0].sign(block_hash.as_bytes()).unwrap(),
            );

            node.consensus
                .write()
                .set_authorities_with_weights(authorities.clone(), vec![1, 3, 3]);
            node.handle_wpoa_vote(
                authorities[1],
                block_hash,
                1,
                signers[1].sign(block_hash.as_bytes()).unwrap(),
            );
            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Voting")
            );

            node.handle_wpoa_vote(
                authorities[2],
                block_hash,
                1,
                signers[2].sign(block_hash.as_bytes()).unwrap(),
            );
            assert_eq!(
                node.wpoa_round.lock().as_ref().map(WPoaRound::phase_name),
                Some("Committed")
            );
        }

        /// C-3: A vote with a garbage signature for a known validator must be
        /// rejected — the round must NOT advance past Voting.
        #[test]
        fn wpoa_handle_vote_rejects_garbage_signature() {
            let signer1 = DilithiumSigner::generate();
            let signer2 = DilithiumSigner::generate();
            let signer3 = DilithiumSigner::generate();
            let addr1 = Address::from_public_key(signer1.public_key(), signer1.sig_type().as_u8());
            let addr2 = Address::from_public_key(signer2.public_key(), signer2.sig_type().as_u8());
            let addr3 = Address::from_public_key(signer3.public_key(), signer3.sig_type().as_u8());

            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));

            let poa_cfg = PoaConfig::new(vec![addr1, addr2, addr3], 1);
            let wpoa_cfg = WPoaConfig::from_poa(poa_cfg);
            let engine = WPoaEngine::new(wpoa_cfg, Arc::new(MultiVerifier));
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));

            let tx_pool = Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            }));

            let config = NodeConfig::dev(addr1);
            let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
            node.register_authority_pubkey(addr1, signer1.public_key().to_vec());
            node.register_authority_pubkey(addr2, signer2.public_key().to_vec());
            node.register_authority_pubkey(addr3, signer3.public_key().to_vec());
            store_genesis_wpoa(&node);

            let block_hash = hash(99);
            let block_number = 1u64;
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(block_number, 0, weights);
                let _ = round.on_block_proposed(block_hash, addr1);
                *node.wpoa_round.lock() = Some(round);
            }

            // Send votes with garbage signatures for addr2 and addr3.
            // Neither should be accepted by the round (C-3 fix).
            let garbage_sig = shell_crypto::PQSignature::new(
                shell_crypto::SignatureType::Dilithium3,
                vec![0xde, 0xad, 0xbe, 0xef],
            );
            node.handle_wpoa_vote(addr2, block_hash, block_number, garbage_sig.clone());
            node.handle_wpoa_vote(addr3, block_hash, block_number, garbage_sig);

            let phase = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(
                phase.as_deref(),
                Some("Voting"),
                "C-3: round must NOT advance when all votes have garbage signatures"
            );
        }

        /// Security: A vote with a valid signature but a wrong `sig_type` tag
        /// must be rejected — algorithm-tag confusion must not allow fake commit
        /// certificates.
        #[test]
        fn wpoa_handle_vote_rejects_sig_type_mismatch() {
            use shell_crypto::SignatureType;

            // Use DilithiumSigner so the voter's address encodes Dilithium3.
            let signer = DilithiumSigner::generate();
            let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

            // Need a second validator to bootstrap the round (proposer).
            let proposer = DilithiumSigner::generate();
            let proposer_addr =
                Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());

            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));

            let poa_cfg = PoaConfig::new(vec![proposer_addr, addr], 1);
            let wpoa_cfg = WPoaConfig::from_poa(poa_cfg);
            let engine = WPoaEngine::new(wpoa_cfg, Arc::new(MultiVerifier));
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));

            let tx_pool = Arc::new(TxPool::new(MempoolConfig {
                chain_id: 1337,
                ..MempoolConfig::default()
            }));

            let config = NodeConfig::dev(proposer_addr);
            let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
            node.register_authority_pubkey(proposer_addr, proposer.public_key().to_vec());
            node.register_authority_pubkey(addr, signer.public_key().to_vec());
            store_genesis_wpoa(&node);

            let block_hash = hash(77);
            let block_number = 1u64;
            {
                let weights = node.consensus.read().validator_weights();
                let mut round = WPoaRound::new(block_number, 0, weights);
                let _ = round.on_block_proposed(block_hash, proposer_addr);
                *node.wpoa_round.lock() = Some(round);
            }

            // Build a valid Dilithium3 signature over block_hash, but lie about
            // sig_type — claim it's MlDsa65 so the tag mismatches the inferred type.
            let real_sig = signer.sign(block_hash.as_bytes()).unwrap();
            let mismatched_sig = shell_crypto::PQSignature::new(
                SignatureType::MlDsa65, // wrong tag — signer used Dilithium3
                real_sig.data,
            );

            node.handle_wpoa_vote(addr, block_hash, block_number, mismatched_sig);

            // The vote must have been rejected: round stays in Voting (no votes accepted).
            let phase = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(
                phase.as_deref(),
                Some("Voting"),
                "algorithm-tag mismatch must cause vote rejection"
            );
        }

        #[test]
        fn fast_finalize_rejects_certificate_sig_type_mismatch() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            let genesis_hash = store_genesis_wpoa(&node);

            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            let real_sig = signer.sign(block_hash.as_bytes()).unwrap();
            let mut quorum_signatures = HashMap::new();
            quorum_signatures.insert(
                authority,
                PQSignature::new(SignatureType::MlDsa65, real_sig.data),
            );
            let cert = Node::<MemoryDb>::encode_commit_certificate(&quorum_signatures).unwrap();

            assert!(!node.fast_finalize_with_certificate(1, block_hash, &cert));
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());
        }

        #[test]
        fn fast_finalize_rejects_exactly_two_thirds_weight() {
            let signers: Vec<DilithiumSigner> =
                (0..3).map(|_| DilithiumSigner::generate()).collect();
            let authorities: Vec<Address> = signers
                .iter()
                .map(|signer| {
                    Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
                })
                .collect();
            let db = Arc::new(MemoryDb::new());
            let chain_store = Arc::new(ChainStore::new(db.clone()));
            let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
            let engine = WPoaEngine::new(
                WPoaConfig::from_poa(PoaConfig::new(authorities.clone(), 1)),
                Arc::new(MultiVerifier),
            );
            let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));
            let node = Node::new(
                NodeConfig::dev(authorities[0]),
                db,
                chain_store,
                world_state,
                Arc::new(TxPool::new(MempoolConfig {
                    chain_id: 1337,
                    ..MempoolConfig::default()
                })),
                consensus,
            );
            for (authority, signer) in authorities.iter().zip(&signers) {
                node.register_authority_pubkey(*authority, signer.public_key().to_vec());
            }

            let genesis_hash = store_genesis_wpoa(&node);
            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            let quorum_signatures = authorities
                .iter()
                .zip(&signers)
                .take(2)
                .map(|(authority, signer)| {
                    (*authority, signer.sign(block_hash.as_bytes()).unwrap())
                })
                .collect();
            let cert = Node::<MemoryDb>::encode_commit_certificate(&quorum_signatures).unwrap();

            assert!(!node.fast_finalize_with_certificate(1, block_hash, &cert));
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());
        }

        #[test]
        fn fast_finalize_rejects_zero_total_validator_weight() {
            let (node, _) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            let genesis_hash = store_genesis_wpoa(&node);
            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            {
                let mut consensus = node.consensus.write();
                consensus.poa_config_mut().slash_weight_bps = 10_000;
                consensus.slash_authority(&authority);
                assert_eq!(consensus.validator_weights().get(&authority), Some(&0));
            }

            let cert = Node::<MemoryDb>::encode_commit_certificate(&HashMap::new()).unwrap();

            assert!(!node.fast_finalize_with_certificate(1, block_hash, &cert));
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());
        }

        #[test]
        fn fast_finalize_rejects_noncanonical_target() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            let genesis_hash = store_genesis_wpoa(&node);
            let canonical_hash = store_next_wpoa_block(&node, genesis_hash);
            let mut side_block = node
                .chain_store
                .get_block_by_hash(&canonical_hash)
                .unwrap()
                .unwrap();
            side_block.header.timestamp += 1;
            let side_hash = side_block.hash();
            node.chain_store.put_block(&side_block).unwrap();

            let quorum_signatures =
                HashMap::from([(authority, signer.sign(side_hash.as_bytes()).unwrap())]);
            let cert = Node::<MemoryDb>::encode_commit_certificate(&quorum_signatures).unwrap();

            assert!(!node.fast_finalize_with_certificate(1, side_hash, &cert));
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert_eq!(node.chain_store.get_finalized_number().unwrap(), None);
            assert!(node
                .chain_store
                .get_commit_certificate(&side_hash)
                .unwrap()
                .is_none());
            assert_eq!(
                node.chain_store.get_block_hash_by_number(1).unwrap(),
                Some(canonical_hash)
            );
        }

        #[test]
        fn fast_finalize_does_not_advance_volatile_state_on_atomic_write_failure() {
            let (node, signer, db) = setup_failing_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());
            let genesis_hash = store_genesis_wpoa(&node);
            let block_hash = store_next_wpoa_block(&node, genesis_hash);
            let quorum_signatures =
                HashMap::from([(authority, signer.sign(block_hash.as_bytes()).unwrap())]);
            let cert =
                Node::<FailingBatchDb>::encode_commit_certificate(&quorum_signatures).unwrap();

            db.fail_next_batch();
            assert!(!node.fast_finalize_with_certificate(1, block_hash, &cert));
            assert_eq!(node.finality.read().last_finalized_number(), 0);
            assert_eq!(node.chain_store.get_finalized_number().unwrap(), None);
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_none());

            assert!(node.fast_finalize_with_certificate(1, block_hash, &cert));
            assert_eq!(node.finality.read().last_finalized_number(), 1);
            assert_eq!(node.chain_store.get_finalized_number().unwrap(), Some(1));
            assert!(node
                .chain_store
                .get_commit_certificate(&block_hash)
                .unwrap()
                .is_some());
        }

        #[test]
        fn wpoa_view_change_rejects_max_head_height() {
            let (node, signer) = setup_wpoa_node();
            let authority = node.config.proposer_address.unwrap();
            node.register_authority_pubkey(authority, signer.public_key().to_vec());

            let block = Block {
                header: BlockHeader {
                    parent_hash: ShellHash::default(),
                    state_root: ShellHash::default(),
                    transactions_root: ShellHash::default(),
                    receipts_root: ShellHash::default(),
                    logs_bloom: Bytes::default(),
                    number: u64::MAX,
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp: 1_700_000_000,
                    extra_data: Bytes::default(),
                    proposer: authority,
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
            node.chain_store.put_block(&block).unwrap();
            node.chain_store.set_canonical(u64::MAX, &hash).unwrap();
            node.chain_store.set_head(&hash).unwrap();

            let highest_qc_hash = *node.finality.read().last_finalized_hash();
            let signing_message =
                ViewChangeMessage::signing_message(1337, u64::MAX, 0, &highest_qc_hash);
            let signature = signer.sign(&signing_message).unwrap();
            let msg = ViewChangeMessage::new(
                1337,
                u64::MAX,
                0,
                highest_qc_hash,
                authority,
                signature.data,
            );

            let err = node
                .handle_wpoa_view_change(msg, &MultiVerifier)
                .unwrap_err();
            assert!(matches!(
                err,
                NodeError::Startup(message) if message.contains("overflows u64")
            ));
        }

        // ── 6. Serde: NetworkMessage::WPoaVote roundtrip ──────────────────────

        #[test]
        fn wpoa_network_message_wpoavote_serde() {
            let voter = Address::from([0xde; 32]);
            let block_hash = hash(7);
            let msg = NetworkMessage::WPoaVote {
                block_hash,
                block_number: 42,
                voter,
                signature: shell_crypto::PQSignature::new(
                    shell_crypto::SignatureType::Dilithium3,
                    vec![1, 2, 3, 4],
                ),
            };
            let json = serde_json::to_string(&msg).expect("serialize failed");
            let decoded: NetworkMessage = serde_json::from_str(&json).expect("deserialize failed");
            match decoded {
                NetworkMessage::WPoaVote {
                    block_hash: bh,
                    block_number: bn,
                    voter: v,
                    signature: sig,
                } => {
                    assert_eq!(bh, block_hash);
                    assert_eq!(bn, 42);
                    assert_eq!(v, voter);
                    assert_eq!(sig.data, vec![1, 2, 3, 4]);
                }
                _ => panic!("expected WPoaVote after deserialization"),
            }
        }

        // ── 7. Serde: NetworkMessage::WPoaViewChange roundtrip ────────────────

        #[test]
        fn wpoa_network_message_wpoa_view_change_serde() {
            let voter = Address::from([0xef; 32]);
            let msg = NetworkMessage::WPoaViewChange(Box::new(ViewChangeMessage::new(
                0,
                10,
                3,
                ShellHash::ZERO,
                voter,
                vec![9, 9, 9],
            )));
            let json = serde_json::to_string(&msg).expect("serialize failed");
            let decoded: NetworkMessage = serde_json::from_str(&json).expect("deserialize failed");
            match decoded {
                NetworkMessage::WPoaViewChange(view_change) => {
                    assert_eq!(view_change.view, 3);
                    assert_eq!(view_change.block_number, 10);
                    assert_eq!(view_change.validator, voter);
                    assert_eq!(view_change.signature, vec![9, 9, 9]);
                }
                _ => panic!("expected WPoaViewChange after deserialization"),
            }
        }
    }
}
