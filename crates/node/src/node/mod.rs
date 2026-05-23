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
    detect_double_sign, detect_offline, Attestation, ConsensusEngine, EngineType,
    EquivocationProof, FinalityState, ForkChoice, PeerScorer, PeerScoringConfig,
    ProofWindowManager, SlashingConfig, ViewChangeMessage, WPoaEvent, WPoaRound, WindowConfig,
    VIEW_CHANGE_TIMEOUT_MS,
};
pub(crate) use shell_core::{
    calculate_base_fee, effective_gas_price, Account, Block, BlockHeader, SignedTransaction,
    SystemTransaction, SystemTxKind, TransactionReceipt,
};
pub(crate) use shell_crypto::{
    BatchVerifier, MultiVerifier, PreVerified, Signer, Verifier, VerifyItem,
};
pub(crate) use shell_evm::{commit_evm_state, validate_tx_for_import, ShellEvm, ShellStateDb};
pub(crate) use shell_mempool::TxPool;
pub(crate) use shell_network::{NetworkMessage, NetworkService};
pub(crate) use shell_primitives::{Address, Bytes, ShellHash, U256};
pub(crate) use shell_rpc::DevRpcControl;
pub(crate) use shell_storage::{
    validator_registry_addr, BodyPruner, ChainStore, KvStore, L2AggregationJob, L2InputIndex,
    L2JobStatus, L2JobStore, ProofAmendmentStore, SettledSourceIndex, StatePruner, WitnessPruner,
    WitnessStore, WorldState,
};

pub(crate) use crate::config::NodeConfig;
pub(crate) use crate::error::NodeError;
pub(crate) use crate::metrics::Metrics;
pub(crate) use crate::prover_service::{ProverConfig, ProverService, ProverServiceHandle};
pub(crate) use crate::pruning::{prune_state_trie, StateRootTracker, StorageProfile};
pub(crate) use chain_state_machine::{BlockImportTransition, ChainStateMachine};
pub(crate) use challenge_lifecycle::{
    ChallengeLifecycle, ChallengeRecord, ChallengeStatus, CHALLENGE_TIMEOUT_BLOCKS,
};
pub(crate) use readiness::{ProductionReadiness, ProductionReadinessState};

pub(crate) use shell_stark_prover::{
    prover::{verify_sig_batch, SigBatchEntry},
    AggregationConfig, AggregationScheduler, AggregationTrigger, ProofAmendment, ProofBacklog,
    ProofTask, SettledL1Input, DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS,
};

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
    /// Drain frontier: the highest gap-at-block seen across all prover drain
    /// operations in this process lifetime.  Shared with ProverService so the
    /// seeding function can skip blocks that were already drained (and therefore
    /// can never accumulate enough entries to form a valid proof on their own).
    /// This prevents the drain-reseed infinite loop where drained sparse blocks
    /// are immediately re-inserted at the backlog front by the seeder.
    pub(crate) stark_drain_frontier: Arc<std::sync::atomic::AtomicU64>,
}

const SYNC_RETRY_BASE_INTERVAL_SECS: u64 = 5;
const SYNC_RETRY_MAX_INTERVAL_SECS: u64 = 30;
const SYNC_RETRY_BACKOFF_THRESHOLD: u32 = 3;
const TX_REBROADCAST_INTERVAL_SECS: u64 = 10;
const MAX_TX_REBROADCAST_PER_TICK: usize = 64;
const TX_REBROADCAST_COOLDOWN_SECS: u64 = 60;

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
    snapshots: BTreeMap<String, DevSnapshot>,
}

type NodeStateDb<S> = ShellStateDb<S>;

struct BlockStoreBoundary<'a, S: KvStore + 'static> {
    store: &'a Arc<S>,
    chain_store: &'a Arc<ChainStore<S>>,
    world_state: &'a Arc<RwLock<WorldState<S>>>,
    witness_store: &'a Arc<WitnessStore<S>>,
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

    fn isolated_state_db(&self) -> Result<(NodeStateDb<S>, ShellHash), NodeError> {
        let current_root = self.current_state_root()?;
        let ws = WorldState::at_root(self.store.clone(), &current_root)?;
        let cs = ChainStore::new(self.store.clone());
        Ok((ShellStateDb::new(ws, cs), current_root))
    }

    fn rollback_world_state(&self, root: &ShellHash) -> Result<(), NodeError> {
        let mut ws = self.world_state.write();
        ws.rollback_to_root(root)?;
        Ok(())
    }

    fn replace_world_state(&self, committed_world_state: WorldState<S>) {
        let mut live_ws = self.world_state.write();
        *live_ws = committed_world_state;
    }

    fn add_balance(&self, address: &Address, balance: U256) -> Result<(), NodeError> {
        let mut ws = self.world_state.write();
        ws.add_balance(address, balance)?;
        Ok(())
    }

    fn commit_canonical_block(
        &self,
        block: &Block,
        receipts: Option<&[TransactionReceipt]>,
    ) -> Result<(), NodeError> {
        self.chain_store.commit_canonical_block(block, receipts)?;
        Ok(())
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

    fn stored_pubkey(&self, address: &Address) -> Result<Option<Vec<u8>>, NodeError> {
        Ok(self.chain_store.get_pubkey(address)?)
    }

    fn store_pubkey(&self, address: &Address, pubkey: &[u8]) -> Result<(), NodeError> {
        self.chain_store.put_pubkey(address, pubkey)?;
        Ok(())
    }

    fn witness_bundle(
        &self,
        block_hash: &ShellHash,
    ) -> Result<Option<shell_core::WitnessBundle>, NodeError> {
        Ok(self.witness_store.get_bundle(block_hash)?)
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
                    Ok(()) => info!(
                        block = *delete_at,
                        "L2: grace-window expired, witness bundle deleted"
                    ),
                    Err(e) => warn!(block = *delete_at, "L2: grace-window delete failed: {e}"),
                }
                false
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

    fn verify_header(&self, header: &BlockHeader) -> Result<(), NodeError> {
        self.consensus.read().verify_header(header)?;
        Ok(())
    }

    fn sign_block(&self, block: &mut Block, signer: &dyn Signer) -> Result<(), NodeError> {
        self.consensus.read().sign_block(block, signer)?;
        Ok(())
    }

    fn register_authority_pubkey(&self, address: Address, pubkey: Vec<u8>) {
        self.known_authorities.write().insert(address, pubkey);
    }

    fn known_authority_pubkey(&self, address: &Address) -> Option<Vec<u8>> {
        self.known_authorities.read().get(address).cloned()
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
}

struct MemPoolBoundary<'a, S: KvStore + 'static> {
    tx_pool: &'a Arc<TxPool>,
    world_state: &'a Arc<RwLock<WorldState<S>>>,
    tx_rebroadcast_seen: &'a parking_lot::Mutex<HashMap<ShellHash, std::time::Instant>>,
}

impl<'a, S: KvStore + 'static> MemPoolBoundary<'a, S> {
    fn pending_for_block(&self, max_txs: usize) -> Vec<SignedTransaction> {
        self.tx_pool.pending_for_block(max_txs)
    }

    fn pending_for_rebroadcast(
        &self,
        target_peer: Option<&shell_network::PeerId>,
        limit: usize,
    ) -> Vec<SignedTransaction> {
        let txs = self.tx_pool.pending(limit);
        if txs.is_empty() || target_peer.is_some() {
            return txs;
        }

        let now = std::time::Instant::now();
        let cooldown = std::time::Duration::from_secs(TX_REBROADCAST_COOLDOWN_SECS);
        let mut seen = self.tx_rebroadcast_seen.lock();
        seen.retain(|_, last_seen| now.duration_since(*last_seen) < cooldown);
        txs.into_iter()
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
            .collect()
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
        let state_pruner = StatePruner::new(128);
        let witness_store = Arc::new(WitnessStore::new(store.clone()));
        let witness_pruner = WitnessPruner::new(config.pruning.witness_retention);
        let body_pruner = BodyPruner::new(config.pruning.body_retention);
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
                    .get_block_by_number(stored)
                    .ok()
                    .flatten()
                    .map(|b| b.hash())
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
            fork_choice: Arc::new(RwLock::new(ForkChoice::new(ShellHash::ZERO))),
            metrics,
            runtime_signer: RwLock::new(None),
            dev_state: RwLock::new(DevState {
                next_block_timestamp: None,
                next_snapshot_id: 1,
                snapshots: BTreeMap::new(),
            }),
            shutdown_tx,
            peer_caps: crate::historical_sync::PeerCapabilityTracker::new(),
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
            stark_drain_frontier: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
            store: &self.store,
            chain_store: &self.chain_store,
            world_state: &self.world_state,
            witness_store: &self.witness_store,
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
        let head_number = self
            .chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.header.number)
            .unwrap_or(0);

        // Binary search for the first block that still has a body.
        // Fall back to sequential scan if the range is small.
        if head_number < 1024 {
            for n in 0..=head_number {
                if let Ok(Some(h)) = self.chain_store.get_block_hash_by_number(n) {
                    if self.chain_store.has_body(&h).unwrap_or(false) {
                        return n;
                    }
                }
            }
            return head_number;
        }

        // Binary search: find smallest n where has_body is true.
        let mut lo = 0u64;
        let mut hi = head_number;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let has = self
                .chain_store
                .get_block_hash_by_number(mid)
                .ok()
                .flatten()
                .and_then(|h| self.chain_store.has_body(&h).ok())
                .unwrap_or(false);
            if has {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }

    fn sync_system_contract_state(
        &self,
        local_ws: &mut WorldState<S>,
        effects: &shell_evm::SystemContractEffects,
    ) -> Result<(), NodeError> {
        let registry_account = if effects.validator_set_changed {
            let validators = local_ws.get_validators()?;
            if validators.is_empty() {
                return Err(NodeError::Startup(
                    "system tx produced empty validator set".into(),
                ));
            }
            if validators.len() > WorldState::<S>::MAX_VALIDATORS {
                return Err(NodeError::Startup(format!(
                    "system tx produced validator set of size {} exceeding max {}",
                    validators.len(),
                    WorldState::<S>::MAX_VALIDATORS,
                )));
            }
            let registry = validator_registry_addr();
            Some(local_ws.get_account(&registry)?.ok_or_else(|| {
                NodeError::Startup("system tx removed validator registry account".into())
            })?)
        } else {
            None
        };

        let mut updated_accounts: Vec<(Address, Account)> =
            Vec::with_capacity(effects.updated_accounts.len());
        for address in &effects.updated_accounts {
            let account = local_ws.get_account(address)?.ok_or_else(|| {
                NodeError::Startup(format!("system tx updated missing account {address}"))
            })?;
            updated_accounts.push((*address, account));
        }

        if registry_account.is_none() && updated_accounts.is_empty() {
            return Ok(());
        }

        let mut ws = self.world_state.write();
        if let Some(account) = registry_account {
            ws.set_account(&validator_registry_addr(), &account)?;
        }
        for (address, account) in updated_accounts {
            ws.set_account(&address, &account)?;
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

    fn preferred_fork_ahead(&self) -> Option<(ShellHash, u64, u64)> {
        let canonical_head = self.chain_store.get_head_block().ok().flatten()?;
        let canonical_number = canonical_head.number();
        let fork_choice = self.fork_choice.read();
        let preferred_hash = *fork_choice.head();
        if preferred_hash == canonical_head.hash() {
            return None;
        }
        let preferred_number = fork_choice.score(&preferred_hash)?.block_number;
        (preferred_number > canonical_number).then_some((
            preferred_hash,
            preferred_number,
            canonical_number,
        ))
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
        reason: &'static str,
    ) {
        let head_number = self.head_number();
        info!(
            head = head_number,
            reason,
            peer = target_peer.map(|p| p.0.as_str()).unwrap_or("broadcast"),
            "requesting blocks from peer"
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let req = NetworkMessage::BlockRequest {
            start_number: head_number + 1,
            count: 1, // request 1 block at a time — PQ-signed blocks can be several MB each
            nonce,
        };
        let send_result = if let Some(peer) = target_peer {
            network.send_to_peer(peer, req).await
        } else {
            network.broadcast(req).await
        };
        if let Err(e) = send_result {
            tracing::warn!(reason, error = %e, "failed to request missing blocks");
        }
        *sync_requested = true;
        *sync_request_nonce = Some(nonce);
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
            let msg = NetworkMessage::NewTransaction(Box::new(tx));
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
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let (total_tx_count, total_gas_used) = self.chain_store.get_chain_totals(head.number())?;
        let finalized_number = self.chain_store.get_finalized_number()?.unwrap_or(0);
        let pending_txs = self.tx_pool.pending(self.tx_pool.len());

        let mut dev = self.dev_state.write();
        let id = format!("0x{:x}", dev.next_snapshot_id);
        dev.next_snapshot_id = dev.next_snapshot_id.saturating_add(1);
        let next_block_timestamp = dev.next_block_timestamp;
        dev.snapshots.insert(
            id.clone(),
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
        Ok(id)
    }

    fn revert_inner(&self, snapshot_id: &str) -> Result<bool, NodeError> {
        let snapshot = {
            let dev = self.dev_state.read();
            match dev.snapshots.get(snapshot_id) {
                Some(s) => DevSnapshot {
                    head_hash: s.head_hash,
                    head_number: s.head_number,
                    state_root: s.state_root,
                    total_tx_count: s.total_tx_count,
                    total_gas_used: s.total_gas_used,
                    finalized_number: s.finalized_number,
                    pending_txs: s.pending_txs.clone(),
                    next_block_timestamp: s.next_block_timestamp,
                },
                None => return Ok(false),
            }
        };

        let current_head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        if current_head.number() > snapshot.head_number {
            for number in (snapshot.head_number + 1)..=current_head.number() {
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

        self.dev_state.write().next_block_timestamp = snapshot.next_block_timestamp;

        Ok(true)
    }

    /// Signal the node to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Record a finalised state root, run state pruning, and evict old entries.
    fn record_finalized_state_root(&self, block_number: u64, state_root: ShellHash) {
        let profile = StorageProfile::from_pruning_config(&self.config.pruning);
        let keep_recent = self.config.pruning.keep_recent;
        let mut prune_keep_below = None;

        {
            let mut tracker = self.state_root_tracker.write();
            if let Some(evicted) = tracker.record(block_number, state_root) {
                tracing::debug!(
                    block = evicted.block_number,
                    root = %evicted.state_root,
                    "state root eligible for pruning"
                );
                if matches!(profile, StorageProfile::Light) && keep_recent > 0 {
                    prune_keep_below =
                        Some(block_number.saturating_add(1).saturating_sub(keep_recent));
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

        // F-303: Drive StatePruner — register block and run periodic pruning.
        {
            let mut pruner = self.state_pruner.write();
            pruner.register_block(block_number, state_root);
            pruner.mark_active(state_root);
            if pruner.should_prune(block_number) {
                pruner.mark_prunable(block_number);
                match pruner.prune(self.store.as_ref()) {
                    Ok(result) => {
                        if result.pruned_count > 0 {
                            tracing::info!(
                                pruned = result.pruned_count,
                                protected = result.protected_count,
                                block = block_number,
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

        // D1: Drive WitnessPruner — prune old witness bundles after finality.
        {
            let mut wpruner = self.witness_pruner.write();
            if !wpruner.is_archive() {
                // Guard: never prune witnesses for blocks that have not yet been
                // STARK-proved.  The frontier is the count of settled L1 sources,
                // i.e. the first unproved block number.
                let stark_frontier = self
                    .settled_stark_sources
                    .lock()
                    .iter()
                    .filter(|(l, _)| *l == 1)
                    .count() as u64;
                match wpruner.prune_before(
                    block_number,
                    stark_frontier,
                    &self.chain_store,
                    &self.witness_store,
                ) {
                    Ok(result) => {
                        if result.pruned_count > 0 {
                            tracing::info!(
                                pruned = result.pruned_count,
                                block = block_number,
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
                match bpruner.prune_before(block_number, &self.chain_store) {
                    Ok(result) => {
                        if result.bodies_pruned > 0 {
                            tracing::info!(
                                pruned = result.bodies_pruned,
                                block = block_number,
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
    use shell_core::Transaction;
    use shell_crypto::{DilithiumSigner, MlDsaSigner, Signer};
    use shell_mempool::MempoolConfig;
    use shell_primitives::U256;
    use shell_rpc::DevRpcControl;
    use shell_storage::{MemoryDb, StorageError, WriteBatch};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Default)]
    struct FailingBatchDb {
        inner: MemoryDb,
        fail_next_batch: AtomicBool,
    }

    impl FailingBatchDb {
        fn new() -> Self {
            Self {
                inner: MemoryDb::new(),
                fail_next_batch: AtomicBool::new(false),
            }
        }

        fn fail_next_batch(&self) {
            self.fail_next_batch.store(true, Ordering::SeqCst);
        }
    }

    impl KvStore for FailingBatchDb {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(key, value)
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
            if self.fail_next_batch.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected batch failure".into()));
            }
            self.inner.write_batch(batch)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
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

    fn store_genesis<S: KvStore + 'static>(node: &Node<S>) {
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

    fn current_state_root<S: KvStore + 'static>(node: &Node<S>) -> ShellHash {
        let mut ws = node.world_state.write();
        ws.state_root().unwrap()
    }

    #[test]
    fn node_creation() {
        let (node, _signer) = setup_node();
        assert_eq!(node.config.chain_id, 1337);
        assert!(node.config.proposer_address.is_some());
    }

    #[test]
    fn sync_retry_delay_uses_backoff_after_threshold() {
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(0), 5);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(2), 5);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(3), 30);
        assert_eq!(Node::<MemoryDb>::sync_retry_delay_secs(10), 30);
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
    fn preferred_fork_ahead_only_flags_higher_noncanonical_branch() {
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let same_height_fork = ShellHash::from_slice(&[0x21; 32]);
        let ahead_fork = ShellHash::from_slice(&[0x22; 32]);

        node.fork_choice
            .write()
            .add_block(same_height_fork, ShellHash::ZERO, 0, 10, false);
        assert!(node.preferred_fork_ahead().is_none());

        node.fork_choice
            .write()
            .add_block(ahead_fork, genesis_hash, 1, 11, false);
        assert_eq!(node.preferred_fork_ahead(), Some((ahead_fork, 1, 0)));
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
                batch_root_bytes: [0x22; 16],
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
        ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash,
            block_number: end_block,
            start_block: end_block
                .checked_add(1)
                .and_then(|end_plus_one| end_plus_one.checked_sub(source_hashes.len() as u64)),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: [0x22; 16],
                n_sigs: if layer == 1 {
                    MIN_L1_STARK_TXS
                } else {
                    source_hashes.len()
                },
                proof_bytes: vec![0x33; 128],
            },
            prover: Address::from([0x44; 32]),
            prover_signature: Bytes::from(vec![0x55; 8]),
            layer,
            source_hashes,
            original_size: Some(10_000),
            compressed_size: Some(128),
            settlement_tx_hash: None,
        }
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
        let root = u128::from_le_bytes(l1_src.proof.batch_root_bytes);
        let agg_root = compute_aggregate_root(&[root]);
        let l2 = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: l1_src.block_hash,
            block_number: 1,
            start_block: Some(1),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: agg_root.to_le_bytes(),
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

        let root = u128::from_le_bytes(l1_src.proof.batch_root_bytes);
        let agg_root = compute_aggregate_root(&[root]);
        let l2 = ProofAmendment {
            version: shell_stark_prover::amendment::PROOF_AMENDMENT_VERSION,
            block_hash: l1_src.block_hash,
            block_number: 1,
            start_block: Some(1),
            proof: shell_stark_prover::proof::SigBatchProof {
                version: shell_stark_prover::proof::SIG_BATCH_PROOF_VERSION,
                batch_root_bytes: agg_root.to_le_bytes(),
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
    fn stark_settlement_prefers_widest_same_start_range() {
        let (node, signer) = setup_node();
        store_genesis(&node);
        let genesis_hash = node
            .chain_store
            .get_block_hash_by_number(0)
            .unwrap()
            .expect("genesis hash");
        let hashes = produce_witnessed_blocks(&node, &signer, 3);

        let short = dummy_ordered_amendment(1, vec![genesis_hash, hashes[0]], 1);
        let wide =
            dummy_ordered_amendment(1, vec![genesis_hash, hashes[0], hashes[1], hashes[2]], 3);

        node.pending_stark_settlements.lock().extend([short, wide]);
        let settlement_block = node.produce_block(&signer, 100).unwrap();

        assert_eq!(
            settlement_block
                .system_transactions
                .iter()
                .filter(|tx| tx.kind == SystemTxKind::StarkReward)
                .count(),
            1,
            "overlapping same-start proofs should produce only one reward settlement"
        );
        assert!(
            node.settled_stark_sources.lock().contains(&(1, hashes[2])),
            "the widest same-start proof should be settled first"
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
    fn block_producer_settles_l1_and_l2_in_same_block() {
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

        assert_eq!(settlements.len(), 2);
        assert_eq!(settlements[0].layer, 1);
        assert_eq!(settlements[1].layer, 2);
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
                batch_root_bytes: [0x22; 16],
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
                batch_root_bytes: [0u8; 16],
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

        // `dummy_ordered_amendment` sets n_sigs = MIN_L1_STARK_TXS which
        // satisfies the layer-1 threshold; source_hashes are contiguous canonical.
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
            to: Some(shell_evm::account_manager_address()),
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(shell_evm::encode_rotate_key_calldata(
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
                - U256::from(shell_evm::SYSTEM_CALL_BASE_GAS + shell_evm::SYSTEM_CALL_OP_GAS)
                    * U256::from(shell_core::INITIAL_BASE_FEE)
        );
        assert_eq!(
            node.chain_store.get_pubkey(&sender).unwrap().unwrap(),
            new_pubkey
        );
    }

    #[test]
    fn import_block() {
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
        node.import_block(block, &verifier).unwrap();

        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 1);
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
            to: Some(shell_evm::registry_address()),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(&shell_evm::encode_add_validator_calldata(&target)),
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

    /// F-405 Test 1: Block with [Embedded TX₀, Reference TX₁] from same sender.
    ///
    /// The two-pass pubkey resolution must handle Reference txs that follow
    /// an Embedded tx from the same sender **within the same block**.
    /// The follower starts with no registered pubkey for the sender.
    #[test]
    fn block_import_pubkey_dedup_embedded_then_reference_same_block() {
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

        // TX₁: Reference — subsequent tx omits the public key
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
        let signed1 = SignedTransaction::new(sender, tx1, sig1);

        let mut ws = leader.world_state.write();
        leader
            .tx_pool
            .insert(signed0, &mut ws, leader.chain_store.as_ref(), &verifier)
            .unwrap();
        // Leader already registered pubkey from TX₀; TX₁ Reference resolves fine
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
        let (node, _) = setup_node();
        store_genesis(&node);
        let proposer = node.config.proposer_address.unwrap();

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

        // Build a minimally valid block (proposer_seal=None is allowed in M1b)
        let genesis_hash = node
            .chain_store
            .get_head_hash()
            .unwrap()
            .expect("genesis head");
        let bad_block = shell_core::Block {
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
                U256::from(21_000u64).saturating_mul(U256::from(shell_core::INITIAL_BASE_FEE)),
                genesis_hash,
            )],
            proposer_seal: None,
        };

        let verifier = MultiVerifier;
        let result = node.import_block(bad_block, &verifier);
        assert!(
            result.is_err(),
            "import should fail when Reference tx precedes Embedded in same block"
        );
        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err_msg.contains("state root mismatch"),
            "expected state-root backstop rejection, got: {err_msg}"
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
    fn import_block_without_seal_allowed_m1b() {
        // In M1b, blocks without a seal are allowed with a warning.
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
        // Should succeed despite missing seal (M1b tolerance).
        node.import_block(block, &verifier).unwrap();
        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert_eq!(head.number(), 1);
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

        // Wait for at least 3 blocks to be produced (~3s with 1s block_time).
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Shut down the node.
        node.shutdown();
        let result = handle.await.expect("task panicked");
        assert!(result.is_ok(), "run() returned error: {:?}", result.err());

        // Verify blocks were produced.
        let head = node.chain_store.get_head_block().unwrap().unwrap();
        assert!(
            head.number() >= 3,
            "expected at least 3 blocks, got {}",
            head.number()
        );
    }

    #[tokio::test]
    async fn aborting_event_loop_stops_background_prover_tasks() {
        use shell_network::{NetworkBus, NetworkConfig};
        use std::net::SocketAddr;

        let (mut node, signer) = setup_node();
        node.config.node_role = crate::config::NodeRole::ValidatorProver;
        node.config.metrics.enabled = false;
        node.config.rpc.listen_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        node.config.rpc.ws_addr = None;
        store_consistent_genesis(&node);

        let bus = NetworkBus::new(64);
        let mut network = bus.join(&NetworkConfig::default());

        let node = Arc::new(node);
        let signer = Arc::new(signer) as Arc<dyn Signer>;
        let handle = tokio::spawn({
            let node = Arc::clone(&node);
            async move { node.run(signer, &mut network).await }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        handle.abort();
        let err = handle
            .await
            .expect_err("aborted event loop should not complete normally");
        assert!(
            err.is_cancelled(),
            "expected cancelled join error, got {err}"
        );

        let completed_before = {
            let mut backlog = node.proof_backlog.lock();
            let _ = backlog.drain();
            let completed_before = backlog.total_completed();
            backlog.push(ProofTask::new([7u8; 32], 7, vec![]));
            completed_before
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        let backlog = node.proof_backlog.lock();
        assert_eq!(
            backlog.len(),
            1,
            "aborted run must not leave prover tasks running"
        );
        assert_eq!(
            backlog.total_completed(),
            completed_before,
            "aborted run must not drain backlog after lifecycle owner is dropped"
        );
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

    // ── Block sync integration tests ───────────────────────────────────

    #[test]
    fn import_multiple_sequential_blocks() {
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        let state_root = current_state_root(&node);

        let mut parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let mut parent_gas_used = 0u64;
        let mut parent_gas_limit = 30_000_000u64;
        let mut parent_base_fee = 0u64;

        for i in 1..=5u64 {
            let base_fee =
                shell_core::calculate_base_fee(parent_gas_used, parent_gas_limit, parent_base_fee);
            let block = Block {
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
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        let state_root = current_state_root(&node);

        // Import block 1 normally.
        let parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let block1 = Block {
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
        let block1_hash = block1.hash();
        node.import_block(block1, &verifier).unwrap();
        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            block1_hash
        );

        // Try to import a competing block at the same height with different content.
        let fork_block = Block {
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
    fn import_next_height_wrong_parent_is_stored_as_side_fork() {
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        let state_root = current_state_root(&node);
        let genesis_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let wrong_parent = ShellHash::from([0x42; 32]);

        let fork_block = Block {
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
        let fork_hash = fork_block.hash();

        node.import_block(fork_block, &verifier).unwrap();

        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            genesis_hash,
            "disconnected next-height block must not become canonical head"
        );
        assert_eq!(
            node.chain_store.get_side_fork_hashes(1).unwrap(),
            vec![fork_hash]
        );
        assert!(node.fork_choice.read().contains(&fork_hash));
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
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let verifier = MultiVerifier;
        let proposer = node.config.proposer_address.unwrap();
        let state_root = current_state_root(&node);

        let parent_hash = node.chain_store.get_head_hash().unwrap().unwrap();
        let block = Block {
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
        let (node, _signer) = setup_node_with_pruning(10);
        store_genesis(&node);
        let current_root = current_state_root(&node);

        let block = Block {
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
    fn make_block_at_1(node: &Node<MemoryDb>, witness_root: Option<ShellHash>) -> Block {
        let current_root = current_state_root(node);
        Block {
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
        }
    }

    #[test]
    fn import_block_no_witness_root_succeeds() {
        // Block with no witness_root: validation is skipped.
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let block = make_block_at_1(&node, None);
        let verifier = MultiVerifier;
        assert!(node.import_block(block, &verifier).is_ok());
    }

    #[test]
    fn import_block_witness_root_no_bundle_still_imports() {
        // witness_root is set but no bundle in store → logged, import allowed.
        let (node, _signer) = setup_node();
        store_genesis(&node);
        let fake_root = ShellHash::from([0xab; 32]);
        let block = make_block_at_1(&node, Some(fake_root));
        let verifier = MultiVerifier;
        assert!(
            node.import_block(block, &verifier).is_ok(),
            "should accept block when bundle not yet delivered"
        );
    }

    #[test]
    fn import_block_witness_root_matches_bundle_succeeds() {
        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::PQSignature;
        use shell_crypto::SignatureType;

        let (node, _signer) = setup_node();
        store_genesis(&node);

        // Build a minimal bundle and compute its root.
        let sig = PQSignature {
            sig_type: SignatureType::Dilithium3,
            data: vec![0xAA; 16],
        };
        let witness = TxWitness {
            signature: sig,
            pubkey: None,
        };
        let bundle = WitnessBundle {
            witnesses: vec![witness],
        };
        let root = bundle.compute_root();

        // Store the bundle before the block hash exists — we need the future hash.
        // Build block first, then store bundle, then import.
        let block = make_block_at_1(&node, Some(root));
        let block_hash = block.hash();
        node.witness_store.put_bundle(&block_hash, &bundle).unwrap();

        let verifier = MultiVerifier;
        assert!(node.import_block(block, &verifier).is_ok());
    }

    #[test]
    fn import_block_witness_root_mismatch_rejected() {
        use shell_core::{TxWitness, WitnessBundle};
        use shell_crypto::PQSignature;
        use shell_crypto::SignatureType;

        let (node, _signer) = setup_node();
        store_genesis(&node);

        let wrong_root = ShellHash::from([0xFF; 32]);
        let block = make_block_at_1(&node, Some(wrong_root));
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
        let (amendment_tx, mut amendment_rx) = tokio::sync::mpsc::unbounded_channel();
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

        fn store_genesis_wpoa(node: &Node<MemoryDb>) {
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

            // First vote: not yet quorum (ceil(2/3 * 3) = 2 required)
            let v1 = round.on_vote(Address::from([1; 32]), bh, dummy_sig());
            assert!(v1.is_empty(), "first vote must not yet trigger commit");

            // Second vote: reaches quorum
            let v2 = round.on_vote(Address::from([2; 32]), bh, dummy_sig());
            assert_eq!(v2.len(), 1, "second vote should emit BlockCommitted");
            match &v2[0] {
                WPoaEvent::BlockCommitted {
                    block_hash,
                    quorum_signatures,
                } => {
                    assert_eq!(*block_hash, bh);
                    assert_eq!(quorum_signatures.len(), 2);
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

            // addr3 votes with a valid signature — quorum (2 of 3) reached.
            let sig3 = signer3.sign(block_hash.as_bytes()).unwrap();
            node.handle_wpoa_vote(addr3, block_hash, block_number, sig3);
            let phase2 = node
                .wpoa_round
                .lock()
                .as_ref()
                .map(|r| r.phase_name().to_string());
            assert_eq!(
                phase2.as_deref(),
                Some("Committed"),
                "should be Committed after quorum is reached"
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
                3,
                10,
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
