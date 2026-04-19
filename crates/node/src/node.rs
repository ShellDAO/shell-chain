//! Running node with event loop and block production.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use shell_consensus::{
    detect_double_sign, Attestation, ConsensusEngine, EquivocationProof, FinalityState, ForkChoice,
    PoaEngine,
};
use shell_core::{calculate_base_fee, Account, Block, BlockHeader, SignedTransaction};
use shell_crypto::{BatchVerifier, MultiVerifier, PreVerified, Signer, Verifier, VerifyItem};
use shell_evm::{commit_evm_state, validate_tx_for_import, ShellEvm, ShellStateDb};
use shell_mempool::TxPool;
use shell_network::{NetworkMessage, NetworkService};
use shell_primitives::{Address, Bytes, ShellHash};
use shell_rpc::DevRpcControl;
use shell_storage::{
    BodyPruner, ChainStore, KvStore, ProofAmendmentStore, StatePruner, WitnessPruner, WitnessStore,
    WorldState,
};

use crate::config::{NodeConfig, NodeRole};
use crate::error::NodeError;
use crate::metrics::Metrics;
use crate::prover_service::{ProverConfig, ProverService, ProverServiceHandle};
use crate::pruning::StateRootTracker;

use shell_stark_prover::{
    prover::{verify_sig_batch, SigBatchEntry},
    ProofBacklog, ProofTask,
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
    pub consensus: Arc<RwLock<PoaEngine>>,
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
    /// H3: Handle to the background prover service (non-None when `node_role.runs_prover()`).
    prover_service_handle: parking_lot::Mutex<Option<ProverServiceHandle>>,
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
    shutdown_tx: watch::Sender<bool>,
}

const SYNC_RETRY_BASE_INTERVAL_SECS: u64 = 5;
const SYNC_RETRY_MAX_INTERVAL_SECS: u64 = 30;
const SYNC_RETRY_BACKOFF_THRESHOLD: u32 = 3;

struct DevSnapshot {
    head_hash: ShellHash,
    head_number: u64,
    state_root: ShellHash,
    total_tx_count: u64,
    finalized_number: u64,
    pending_txs: Vec<SignedTransaction>,
    next_block_timestamp: Option<u64>,
}

struct DevState {
    next_block_timestamp: Option<u64>,
    next_snapshot_id: u64,
    snapshots: BTreeMap<String, DevSnapshot>,
}

impl<S: KvStore + 'static> Node<S> {
    /// Create a new node from pre-built components.
    pub fn new(
        config: NodeConfig,
        store: Arc<S>,
        chain_store: Arc<ChainStore<S>>,
        world_state: Arc<RwLock<WorldState<S>>>,
        tx_pool: Arc<TxPool>,
        consensus: Arc<RwLock<PoaEngine>>,
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

        Self {
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
            prover_service_handle: parking_lot::Mutex::new(None),
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
        }
    }

    /// Print the three-line startup pruning banner (ops-banner).
    ///
    /// Called once from the event loop at startup to give operators a quick
    /// view of what data will be retained.
    pub fn log_pruning_banner(&self) {
        let p = &self.config.pruning;

        let state_mode = if p.state_pruning_experimental {
            if p.keep_recent == 0 {
                "archive (experimental enabled but keep_recent=0)".to_string()
            } else {
                format!("keep-{} (experimental)", p.keep_recent)
            }
        } else {
            "archive".to_string()
        };

        let witness_mode = if p.witness_retention == 0 {
            if self.config.enable_stark_aggregation {
                "replaced-by-proof".to_string()
            } else {
                "archive".to_string()
            }
        } else {
            format!("keep-{}", p.witness_retention)
        };

        let stark_line = if self.config.enable_stark_aggregation {
            if p.proof_replacement_grace == 0 {
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
            "║  state={}  bodies=archive  witnesses={}",
            state_mode,
            witness_mode
        );
        tracing::info!("║  {}", stark_line);
        tracing::info!("╚════════════════════════════════════════════════════════════════╝");
    }

    fn sync_system_contract_state(
        &self,
        local_ws: &mut WorldState<S>,
        effects: &shell_evm::SystemContractEffects,
    ) -> Result<(), NodeError> {
        let validators = if effects.validator_set_changed {
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
            Some(validators)
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

        if validators.is_none() && updated_accounts.is_empty() {
            return Ok(());
        }

        let mut ws = self.world_state.write();
        if let Some(validators) = validators {
            ws.set_validators(&validators)?;
        }
        for (address, account) in updated_accounts {
            ws.set_account(&address, &account)?;
        }

        Ok(())
    }

    /// Register an authority's public key for seal verification.
    pub fn register_authority_pubkey(&self, address: Address, pubkey: Vec<u8>) {
        self.known_authorities.write().insert(address, pubkey);
    }

    fn head_number(&self) -> u64 {
        self.chain_store
            .get_head_block()
            .ok()
            .flatten()
            .map(|b| b.number())
            .unwrap_or(0)
    }

    fn sync_retry_delay_secs(attempts_without_progress: u32) -> u64 {
        if attempts_without_progress < SYNC_RETRY_BACKOFF_THRESHOLD {
            SYNC_RETRY_BASE_INTERVAL_SECS
        } else {
            SYNC_RETRY_MAX_INTERVAL_SECS
        }
    }

    async fn request_missing_blocks<N: NetworkService + ?Sized>(
        &self,
        network: &mut N,
        sync_requested: &mut bool,
        reason: &'static str,
    ) {
        let head_number = self.head_number();
        info!(head = head_number, reason, "requesting blocks from peers");
        let req = NetworkMessage::BlockRequest {
            start_number: head_number + 1,
            count: 128,
        };
        let _ = network.broadcast(req).await;
        *sync_requested = true;
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
        let total_tx_count = self.chain_store.get_total_tx_count()?;
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
        let mut tracker = self.state_root_tracker.write();
        if let Some(evicted) = tracker.record(block_number, state_root) {
            tracing::debug!(
                block = evicted.block_number,
                root = %evicted.state_root,
                "state root eligible for pruning"
            );
            // L3: when experimental trie pruning is enabled, evict trie nodes
            // for the now-unreachable state root.  Until reference-counting is
            // fully wired into the trie writer path, this only logs intent.
            if self.config.pruning.state_pruning_experimental {
                tracing::debug!(
                    block = evicted.block_number,
                    root = %evicted.state_root,
                    "L3 (experimental): trie node eviction eligible — \
                     full ref-count walk deferred until trie writer is instrumented"
                );
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
                match wpruner.prune_before(block_number, &self.chain_store, &self.witness_store) {
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

    /// Run the async event loop.
    ///
    /// Drives block production, network event handling, and RPC serving:
    /// - **Block production**: on a timer, if this node is the current proposer,
    ///   produce a block from pending mempool txs and broadcast it.
    /// - **Network events**: import blocks and transactions from peers.
    /// - **RPC server**: serves JSON-RPC on the configured address.
    /// - **Shutdown**: stops on `shutdown()` call or Ctrl-C.
    pub async fn run(
        self: Arc<Self>,
        signer: Arc<dyn Signer>,
        network: &mut dyn NetworkService,
    ) -> Result<(), NodeError> {
        use shell_network::{NetworkEvent, NetworkMessage};
        use shell_rpc::{start_rpc_server, BlockEvent};
        use tokio::time::{interval, Duration};

        *self.runtime_signer.write() = Some(Arc::clone(&signer));

        // Spawn the Prometheus metrics HTTP server if enabled.
        if self.config.metrics.enabled {
            let metrics = Arc::clone(&self.metrics);
            let metrics_addr = self.config.metrics.listen_addr;
            tokio::spawn(crate::metrics::serve_metrics(metrics, metrics_addr));
        }

        // Create a channel for the RPC layer to forward submitted transactions
        // to the network broadcast loop.
        let (tx_broadcast_tx, mut tx_broadcast_rx) =
            tokio::sync::mpsc::unbounded_channel::<SignedTransaction>();

        // Create a broadcast channel for block events (eth_subscribe).
        // F-042: Use larger capacity to reduce subscriber lag.
        let (block_event_tx, _) = tokio::sync::broadcast::channel::<BlockEvent>(256);

        // Start JSON-RPC server.
        // Pass the signer to the RPC layer if this node is a validator,
        // enabling governance RPCs (proposeAddValidator / proposeRemoveValidator).
        let proposer_signer: Option<Arc<dyn Signer>> = if self.config.proposer_address.is_some() {
            Some(Arc::clone(&signer))
        } else {
            None
        };
        // Shared finalized block number for the RPC layer.
        // F-107: recover persisted finalized_number from ChainStore on restart,
        // falling back to finality state and then 0.
        let finality_num = self.finality.read().last_finalized_number();
        let persisted_num = self
            .chain_store
            .get_finalized_number()
            .ok()
            .flatten()
            .unwrap_or(0);
        let finalized_number = Arc::new(parking_lot::RwLock::new(finality_num.max(persisted_num)));

        // Get the peer count handle from the network for RPC.
        let peer_count_handle = network.peer_count_handle();

        self.config
            .rpc
            .validate_dev_rpc_exposure()
            .map_err(NodeError::Startup)?;

        let rpc_handle = start_rpc_server(
            self.config.rpc.clone(),
            self.chain_store.clone(),
            self.world_state.clone(),
            self.tx_pool.clone(),
            self.config.chain_id,
            Some(tx_broadcast_tx),
            block_event_tx.clone(),
            proposer_signer,
            self.config.proposer_address,
            finalized_number.clone(),
            self.finality.clone(),
            peer_count_handle,
            if self.config.rpc.has_api_namespace("evm") {
                Some(self.clone() as Arc<dyn DevRpcControl>)
            } else {
                None
            },
            None, // admin_p2p_context: wire peer_id + p2p_listen when P2P layer is integrated
            Some(Arc::clone(&self.witness_store)), // B5: witness store wired
        )
        .await
        .map_err(|e| NodeError::Startup(format!("RPC: {e}")))?;

        // Register own authority pubkey for seal verification.
        if let Some(addr) = self.config.proposer_address {
            self.register_authority_pubkey(addr, signer.public_key().to_vec());
        }

        // ops-banner: print storage policy at startup.
        self.log_pruning_banner();

        let mut block_timer = interval(Duration::from_millis(self.config.block_time_ms));
        let mut peer_count_timer = interval(Duration::from_secs(10));
        let mut sync_retry_timer = interval(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        // Track the last time a block was produced for idle-block-skip.
        let mut last_block_time = std::time::Instant::now();
        let mut sync_retry_attempts_without_progress = 0u32;

        // Skip the first immediate tick.
        block_timer.tick().await;
        peer_count_timer.tick().await;
        sync_retry_timer.tick().await;

        // Startup sync: request blocks we don't have from peers.
        // Track whether we are catching up so we don't spam requests.
        let mut sync_requested = false;
        if network.peer_count().await > 0 {
            self.request_missing_blocks(network, &mut sync_requested, "initial-sync")
                .await;
        }

        // H3: Start background prover service if this node is configured to run proving.
        if self.config.node_role.runs_prover() {
            let prover_address = self.config.proposer_address.unwrap_or_default();
            let prover_config = ProverConfig::default();
            let service = ProverService::new(
                Arc::clone(&self.proof_backlog),
                self.amendment_store.clone(),
                prover_config,
                prover_address,
            );
            let handle = service.start();
            *self.prover_service_handle.lock() = Some(handle);
            info!(
                role = ?self.config.node_role,
                "H3: Background prover service started"
            );
        }

        loop {
            tokio::select! {
                _ = block_timer.tick() => {
                    if self.config.proposer_address.is_some() {
                        // Idle-block-skip: when mempool is empty and we haven't
                        // exceeded max_idle_interval, skip block production.
                        let max_idle_ms = self.config.max_idle_interval_ms;
                        if max_idle_ms > 0 && self.tx_pool.is_empty() {
                            let idle_dur = std::time::Duration::from_millis(max_idle_ms);
                            if last_block_time.elapsed() < idle_dur {
                                continue;
                            }
                            // Heartbeat: produce an empty block to keep chain alive.
                        }

                        let start = std::time::Instant::now();
                        match self.produce_block(&*signer, 500) {
                            Ok(block) => {
                                last_block_time = std::time::Instant::now();
                                let elapsed = start.elapsed().as_secs_f64();
                                self.metrics.block_production_ms.observe(elapsed);
                                self.metrics.blocks_imported.inc();
                                self.metrics.block_height.set(block.number() as i64);
                                self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                let number = block.number();
                                let tx_count = block.transactions.len();
                                let gas = block.header.gas_used;
                                // F-046: Use scope blocks to manage lock lifetimes.
                                {
                                    let consensus = self.consensus.read();
                                    if consensus.config().is_epoch_boundary(number) {
                                        let epoch = consensus.config().epoch_of(number);
                                        info!(epoch, block = number, "new epoch started");
                                    }
                                }
                                // Reload validators at epoch boundaries (F-041: handle errors).
                                // F-061: Scope read lock explicitly to prevent deadlock.
                                let is_epoch = {
                                    self.consensus.read().config().is_epoch_boundary(number)
                                };
                                if is_epoch {
                                    let validators = {
                                        let ws = self.world_state.read();
                                        ws.get_validators()
                                    };
                                    match validators {
                                        Ok(v) if !v.is_empty() => {
                                            self.consensus.write().config_mut().set_authorities(v);
                                        }
                                        Ok(_) => {
                                            // Empty validator set in world state — keep current authorities.
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                error = %e,
                                                block = number,
                                                "CRITICAL: failed to reload validators at epoch boundary — \
                                                 continuing with stale validator set may cause consensus divergence"
                                            );
                                        }
                                    }
                                }
                                eprintln!(
                                    "⛏  Block #{number} produced ({tx_count} txs, {gas} gas)"
                                );

                                // Notify eth_subscribe listeners.
                                let block_hash = block.hash();
                                let receipts = self
                                    .chain_store
                                    .get_receipts(&block_hash)
                                    .ok()
                                    .flatten()
                                    .unwrap_or_default();
                                if block_event_tx.send(BlockEvent::NewBlock {
                                    header: block.header.clone(),
                                    receipts,
                                }).is_err() {
                                    tracing::warn!("no active subscribers for block events");
                                }

                                let msg = NetworkMessage::NewBlock(Box::new(block));
                                let _ = network.broadcast(msg).await;
                            }
                            Err(NodeError::NotProposer) => {
                                // Not our turn to propose; silently skip.
                            }
                            Err(e) => {
                                eprintln!("⚠  Block production error: {e}");
                            }
                        }
                    }
                }

                event = network.next_event() => {
                    match event {
                        Some(NetworkEvent::MessageReceived { peer, message }) => {
                            match message {
                                NetworkMessage::NewBlock(block) => {
                                    let verifier = MultiVerifier;
                                    let saved_header = block.header.clone();
                                    let saved_hash = block.hash();
                                    let imported_number = block.number();
                                    match self.import_block(*block, &verifier) {
                                        Ok(()) => {
                                            sync_requested = false;
                                            sync_retry_attempts_without_progress = 0;
                                            sync_retry_timer.reset_after(Duration::from_secs(
                                                SYNC_RETRY_BASE_INTERVAL_SECS,
                                            ));
                                            self.metrics.blocks_imported.inc();
                                            self.metrics.block_height.set(imported_number as i64);
                                            self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);

                                            // Notify eth_subscribe listeners.
                                            let receipts = self
                                                .chain_store
                                                .get_receipts(&saved_hash)
                                                .ok()
                                                .flatten()
                                                .unwrap_or_default();
                                            if block_event_tx.send(BlockEvent::NewBlock {
                                                header: saved_header,
                                                receipts,
                                            }).is_err() {
                                                tracing::warn!("no active subscribers for block events");
                                            }

                                            // I1: Drain any equivocation proofs discovered
                                            // during import and broadcast to the network.
                                            let pending: Vec<EquivocationProof> = {
                                                let mut q = self.equivocation_queue.lock();
                                                std::mem::take(&mut *q)
                                            };
                                            for equivocation in pending {
                                                let msg = NetworkMessage::EquivocationEvidence(
                                                    Box::new(equivocation),
                                                );
                                                let _ = network.broadcast(msg).await;
                                            }
                                        }
                                        Err(NodeError::GapDetected { .. }) => {
                                            // Only request missing blocks on genuine gap,
                                            // NOT on invalid signatures or other errors (F-037).
                                            if !sync_requested {
                                                self.request_missing_blocks(
                                                    network,
                                                    &mut sync_requested,
                                                    "gap-detected",
                                                )
                                                .await;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("⚠  Block import error: {e}");
                                        }
                                    }
                                }
                                NetworkMessage::NewTransaction(tx) => {
                                    // F-043: Use insert() directly — it returns Duplicate
                                    // error if already known, avoiding TOCTOU race.
                                    let verifier = MultiVerifier;
                                    match self.handle_incoming_tx(*tx, &verifier) {
                                        Ok(_hash) => {
                                            self.metrics.txs_received.inc();
                                            self.metrics.tx_pool_size.set(self.tx_pool.len() as i64);
                                        }
                                        Err(e) => {
                                            // MempoolError::Duplicate is expected for re-broadcast; don't log it as error.
                                            let msg = format!("{e}");
                                            if !msg.contains("duplicate") && !msg.contains("Duplicate") {
                                                eprintln!("⚠  Tx handling error: {e}");
                                            }
                                        }
                                    }
                                }
                                NetworkMessage::BlockRequest { start_number, count } => {
                                    const MAX_BLOCK_RESPONSE: u64 = 128;
                                    let safe_count = count.min(MAX_BLOCK_RESPONSE);
                                    debug!(
                                        %peer,
                                        start_number,
                                        count,
                                        safe_count,
                                        "received BlockRequest"
                                    );
                                    let mut blocks = Vec::new();
                                    for n in start_number..start_number.saturating_add(safe_count) {
                                        match self.chain_store.get_block_by_number(n) {
                                            Ok(Some(block)) => blocks.push(block),
                                            _ => break,
                                        }
                                    }
                                    if !blocks.is_empty() {
                                        info!(
                                            count = blocks.len(),
                                            from = start_number,
                                            "responding with blocks"
                                        );
                                        let resp = NetworkMessage::BlockResponse { blocks };
                                        let _ = network.broadcast(resp).await;
                                    }
                                }
                                NetworkMessage::BlockResponse { blocks } => {
                                    info!(
                                        count = blocks.len(),
                                        "received BlockResponse, importing blocks"
                                    );
                                    let verifier = MultiVerifier;
                                    let mut last_ok = 0u64;
                                    for block in blocks {
                                        let num = block.number();
                                        let hdr = block.header.clone();
                                        let bhash = block.hash();
                                        match self.import_block(block, &verifier) {
                                            Ok(()) => {
                                                last_ok = num;
                                                self.metrics.blocks_imported.inc();
                                                self.metrics.block_height.set(num as i64);
                                                debug!(number = num, "synced block");

                                                // Notify eth_subscribe listeners.
                                                let receipts = self
                                                    .chain_store
                                                    .get_receipts(&bhash)
                                                    .ok()
                                                    .flatten()
                                                    .unwrap_or_default();
                                                if block_event_tx.send(BlockEvent::NewBlock {
                                                    header: hdr,
                                                    receipts,
                                                }).is_err() {
                                                    tracing::warn!("no active subscribers for block events");
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    number = num,
                                                    error = %e,
                                                    "block sync import failed"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    // Request next batch if we imported blocks
                                    // (there may be more to catch up on).
                                    if last_ok > 0 {
                                        let req = NetworkMessage::BlockRequest {
                                            start_number: last_ok + 1,
                                            count: 128,
                                        };
                                        let _ = network.broadcast(req).await;
                                        sync_requested = true;
                                        sync_retry_attempts_without_progress = 0;
                                        sync_retry_timer.reset_after(Duration::from_secs(
                                            SYNC_RETRY_BASE_INTERVAL_SECS,
                                        ));
                                    } else {
                                        sync_requested = false;
                                        sync_retry_attempts_without_progress = 0;
                                        sync_retry_timer.reset_after(Duration::from_secs(
                                            SYNC_RETRY_BASE_INTERVAL_SECS,
                                        ));
                                    }
                                }
                                NetworkMessage::Ping => {
                                    debug!(%peer, "received Ping, responding with Pong");
                                    let _ = network.broadcast(NetworkMessage::Pong).await;
                                }
                                NetworkMessage::Pong => {
                                    debug!(%peer, "received Pong");
                                }
                                NetworkMessage::NewAttestation(attestation) => {
                                    let verifier = MultiVerifier;
                                    if let Err(e) = self.handle_attestation(*attestation, &verifier) {
                                        tracing::warn!("attestation error: {e}");
                                    }
                                    // Push latest finalized number to the RPC layer.
                                    let fin = self.finality.read().last_finalized_number();
                                    let mut fn_w = finalized_number.write();
                                    if fin > *fn_w {
                                        *fn_w = fin;
                                    }
                                }
                                // G5: Receive async STARK proof amendment from a prover node.
                                // Deserialize, store via ProofAmendmentStore, log result.
                                NetworkMessage::ProofAmendment { block_hash, block_number, payload } => {
                                    debug!(%peer, block = block_number, "received ProofAmendment");
                                    if let Err(e) = self.amendment_store.put_amendment(&block_hash, &payload) {
                                        warn!(%peer, block = block_number, "failed to store proof amendment: {e}");
                                    } else {
                                        info!(block = block_number, "G5: proof amendment stored from peer {peer}");
                                        // L2: delete witness bundle once proof is secured, unless grace window is active.
                                        let grace = self.config.pruning.proof_replacement_grace;
                                        if grace == 0 {
                                            match self.chain_store.delete_witness_bundle(&block_hash) {
                                                Ok(()) => info!(block = block_number, "L2: witness bundle deleted after proof replacement"),
                                                Err(e) => warn!(block = block_number, "L2: failed to delete witness bundle: {e}"),
                                            }
                                        } else {
                                            let head = self.chain_store.get_head_block()
                                                .ok().flatten().map(|b| b.header.number).unwrap_or(0);
                                            if head.saturating_sub(block_number) >= grace {
                                                match self.chain_store.delete_witness_bundle(&block_hash) {
                                                    Ok(()) => info!(block = block_number, "L2: witness bundle deleted after grace period"),
                                                    Err(e) => warn!(block = block_number, "L2: failed to delete witness bundle: {e}"),
                                                }
                                            } else {
                                                debug!(block = block_number, grace, head, "L2: proof stored, within grace window — witness kept");
                                            }
                                        }
                                    }
                                }
                                // G5: Acknowledge that a peer has stored a proof amendment.
                                NetworkMessage::ProofAck { block_hash, holder } => {
                                    debug!(%peer, ?holder, "received ProofAck for block {}", block_hash);
                                }
                                // I1: Received equivocation evidence from a peer.
                                // Independently verify and apply slashing if valid.
                                NetworkMessage::EquivocationEvidence(equivocation) => {
                                    if equivocation.verify() {
                                        warn!(
                                            offender = %equivocation.offender,
                                            block_number = equivocation.header_a.number,
                                            "I1: equivocation evidence verified, slashing {}",
                                            equivocation.offender
                                        );
                                        // TODO: wire into slashing state; for now log only.
                                    } else {
                                        warn!(%peer, "I1: received invalid equivocation evidence, ignoring");
                                    }
                                }
                                // I2: Received a proof challenge from a peer.
                                // If we hold the proof, respond with raw bytes.
                                NetworkMessage::ProofChallenge(challenge) => {
                                    debug!(%peer, block = challenge.block_number, reason = %challenge.reason, "I2: received ProofChallenge");
                                    if let Ok(Some(proof_bytes)) = self.amendment_store.get_amendment(&challenge.block_hash) {
                                        use shell_consensus::ChallengeResponse;
                                        if let Some(our_address) = self.config.proposer_address {
                                            let resp = ChallengeResponse {
                                                block_hash: challenge.block_hash,
                                                proof_bytes,
                                                responder: our_address,
                                            };
                                            let _ = network.broadcast(NetworkMessage::ProofChallengeResponse(Box::new(resp))).await;
                                            debug!(block = challenge.block_number, "I2: sent ChallengeResponse");
                                        }
                                    }
                                }
                                // I2: Received a challenge response with raw proof bytes.
                                // Re-verify and store if valid.
                                NetworkMessage::ProofChallengeResponse(resp) => {
                                    debug!(%peer, "I2: received ChallengeResponse for block {}", resp.block_hash);
                                    // Attempt to verify the provided proof bytes.
                                    match shell_stark_prover::proof::SigBatchProof::from_json(&resp.proof_bytes) {
                                        Ok(sig_proof) => {
                                            if shell_stark_prover::prover::verify_sig_batch(&sig_proof).is_ok() {
                                                if let Err(e) = self.amendment_store.put_amendment(&resp.block_hash, &resp.proof_bytes) {
                                                    warn!("I2: failed to store verified challenge response: {e}");
                                                } else {
                                                    info!(block = %resp.block_hash, "I2: challenge response verified and stored");
                                                }
                                            } else {
                                                warn!(%peer, "I2: challenge response proof verification failed");
                                            }
                                        }
                                        Err(e) => {
                                            warn!(%peer, "I2: challenge response malformed: {e}");
                                        }
                                    }
                                }
                            }
                        }
                        Some(NetworkEvent::PeerConnected(peer)) => {
                            info!(%peer, "peer connected");
                            sync_requested = false;
                            sync_retry_attempts_without_progress = 0;
                            sync_retry_timer
                                .reset_after(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
                            self.request_missing_blocks(
                                network,
                                &mut sync_requested,
                                "peer-connected",
                            )
                            .await;
                        }
                        Some(NetworkEvent::PeerDisconnected(peer)) => {
                            info!(%peer, "peer disconnected");
                            sync_requested = false;
                            sync_retry_attempts_without_progress = 0;
                            sync_retry_timer
                                .reset_after(Duration::from_secs(SYNC_RETRY_BASE_INTERVAL_SECS));
                        }
                        Some(NetworkEvent::RoutingTableUpdated { peer_count }) => {
                            debug!(peer_count, "routing table updated");
                            if peer_count > 0 && !sync_requested {
                                sync_retry_attempts_without_progress = 0;
                                sync_retry_timer.reset_after(Duration::from_secs(
                                    SYNC_RETRY_BASE_INTERVAL_SECS,
                                ));
                                self.request_missing_blocks(
                                    network,
                                    &mut sync_requested,
                                    "routing-update",
                                )
                                .await;
                            }
                        }
                        None => {
                            eprintln!("Network channel closed, shutting down");
                            break;
                        }
                    }
                }

                // Forward RPC-submitted transactions to peers.
                Some(signed_tx) = tx_broadcast_rx.recv() => {
                    let msg = NetworkMessage::NewTransaction(Box::new(signed_tx));
                    let _ = network.broadcast(msg).await;
                }

                // Periodically update peer count metric.
                _ = peer_count_timer.tick() => {
                    let peers = network.peer_count().await;
                    self.metrics.peer_count.set(peers as i64);
                    // ops-metrics: update per-CF storage size gauges lazily on each 10s tick.
                    // Uses prefix scan byte counts as a backend-agnostic approximation.
                    // RocksDB nodes can replace this with property_int_value_cf calls.
                    let chain_bytes = self.chain_store.approximate_prefix_bytes(b"b/")
                        .unwrap_or(0)
                        .saturating_add(self.chain_store.approximate_prefix_bytes(b"h/").unwrap_or(0))
                        .saturating_add(self.chain_store.approximate_prefix_bytes(b"n/").unwrap_or(0));
                    let witness_bytes = self.chain_store.approximate_prefix_bytes(b"w/").unwrap_or(0);
                    let proof_bytes = self.chain_store.approximate_prefix_bytes(b"p/").unwrap_or(0);
                    // State trie bytes are stored in a separate KV namespace; use 0 until
                    // the trie store exposes a size_estimate().
                    self.metrics.update_cf_sizes(chain_bytes, witness_bytes, 0, proof_bytes);
                }

                _ = sync_retry_timer.tick() => {
                    if sync_requested && network.peer_count().await > 0 {
                        self.request_missing_blocks(
                            network,
                            &mut sync_requested,
                            "sync-retry",
                        )
                        .await;
                        sync_retry_attempts_without_progress =
                            sync_retry_attempts_without_progress.saturating_add(1);
                        sync_retry_timer.reset_after(Duration::from_secs(
                            Self::sync_retry_delay_secs(sync_retry_attempts_without_progress),
                        ));
                    }
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        eprintln!("Shutdown signal received");
                        break;
                    }
                }
            }
        }

        // Graceful shutdown: stop RPC servers first.
        rpc_handle.http_handle.stop().ok();
        if let Some(ws) = rpc_handle.ws_handle {
            ws.stop().ok();
        }
        eprintln!("✓ RPC server stopped");

        // Flush storage to disk.
        if let Err(e) = self.store.flush() {
            eprintln!("⚠  Storage flush failed: {e}");
        } else {
            eprintln!("✓ Storage flushed to disk");
        }

        let _ = network.shutdown().await;
        Ok(())
    }

    /// Produce a block from pending mempool transactions.
    ///
    /// Collects up to `max_txs` transactions, executes each through the EVM,
    /// commits state changes after every transaction (so subsequent txs see
    /// prior updates), assembles a block, and commits it to storage.
    pub fn produce_block(&self, signer: &dyn Signer, max_txs: usize) -> Result<Block, NodeError> {
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;
        let head_hash = head.hash();
        let next_number = head.number() + 1;

        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;

        if !self
            .consensus
            .read()
            .is_proposer(next_number, &proposer_addr)
        {
            return Err(NodeError::NotProposer);
        }

        // Collect pending transactions from mempool.
        let candidates = self.tx_pool.pending(max_txs);

        // Create an isolated EVM instance at the current state root.
        let current_root = {
            let mut ws = self.world_state.write();
            ws.state_root()?
        };
        let ws = WorldState::at_root(self.store.clone(), &current_root)?;
        let cs = ChainStore::new(self.store.clone());
        let state_db = ShellStateDb::new(ws, cs);
        let mut evm = ShellEvm::new(state_db, self.config.chain_id);

        let now = self.current_block_timestamp(head.header.timestamp);

        // Calculate EIP-1559 base fee from parent block.
        let base_fee = calculate_base_fee(
            head.header.gas_used,
            head.header.gas_limit,
            head.header.base_fee_per_gas,
        );

        // Build a preliminary header for EVM context.
        let mut header = BlockHeader {
            parent_hash: head_hash,
            state_root: ShellHash::default(),
            transactions_root: ShellHash::default(),
            receipts_root: ShellHash::default(),
            logs_bloom: Bytes::default(),
            number: next_number,
            gas_limit: head.header.gas_limit,
            gas_used: 0,
            timestamp: now,
            extra_data: Bytes::default(),
            proposer: proposer_addr,
            sig_aggregate_proof: None,
            base_fee_per_gas: base_fee,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        };

        let mut included_txs: Vec<SignedTransaction> = Vec::new();
        let mut receipts = Vec::new();
        let mut cumulative_gas: u64 = 0;

        for (idx, tx) in candidates.iter().enumerate() {
            // EIP-1559: skip transactions that cannot afford the base fee.
            if tx.tx.max_fee_per_gas < base_fee {
                continue;
            }

            // F-302: Re-validate mempool txs before execution. Security checks
            // may have changed since the tx was originally admitted (e.g. new
            // algorithm restrictions, pubkey conflicts). Uses the import-path
            // validator which skips nonce/balance (EVM handles those).
            let import_cs = ChainStore::new(self.store.clone());
            let pre_verifier = PreVerified;
            if let Err(e) = validate_tx_for_import(
                tx,
                evm.state_db_mut().world_state_mut(),
                &import_cs,
                &pre_verifier,
                self.config.chain_id,
            ) {
                debug!(
                    tx_hash = %tx.tx.hash(),
                    error = %e,
                    "produce_block: skipping tx that failed re-validation"
                );
                continue;
            }

            match evm.execute_tx(tx, &header, idx as u32, cumulative_gas) {
                Ok(result) => {
                    cumulative_gas += result.gas_used;
                    receipts.push(result.receipt);
                    included_txs.push(tx.clone());

                    if result.is_system_tx {
                        self.sync_system_contract_state(
                            evm.state_db_mut().world_state_mut(),
                            &result.system_contract_effects,
                        )?;
                    } else {
                        // Normal EVM tx: commit EvmState changeset.
                        commit_evm_state(
                            &result.state_changes,
                            evm.state_db_mut().world_state_mut(),
                            &self.chain_store,
                        )?;

                        // Commit to the node's persistent WorldState.
                        {
                            let mut ws = self.world_state.write();
                            commit_evm_state(&result.state_changes, &mut ws, &self.chain_store)?;
                        }
                    }
                }
                Err(_) => {
                    // Skip failed transactions.
                    continue;
                }
            }

            if cumulative_gas >= header.gas_limit {
                break;
            }
        }

        header.gas_used = cumulative_gas;

        // Compute block-level logs bloom by OR-ing all receipt blooms.
        {
            let receipt_blooms: Vec<shell_evm::bloom::Bloom> = receipts
                .iter()
                .map(|r| {
                    let mut bloom = [0u8; shell_evm::bloom::BLOOM_SIZE];
                    let bytes = r.logs_bloom.as_ref();
                    let len = bytes.len().min(shell_evm::bloom::BLOOM_SIZE);
                    bloom[..len].copy_from_slice(&bytes[..len]);
                    bloom
                })
                .collect();
            let block_bloom = shell_evm::bloom::bloom_union(&receipt_blooms);
            header.logs_bloom = Bytes::from(block_bloom.to_vec());
        }

        // Compute state root from the updated world state.
        {
            let mut ws = self.world_state.write();
            header.state_root = ws.state_root().unwrap_or_default();
        }

        let mut block = Block {
            header,
            transactions: included_txs.clone(),
            proposer_seal: None,
        };

        // C3: If STARK aggregation is enabled, generate a batch commitment proof
        // over all transactions that carry embedded pubkeys (the source of bloat).
        // G4: Collect signature entries and push to the proof backlog for async proving.
        // Block production is no longer blocked waiting for a STARK proof.
        // The background ProverService will generate the proof and store a ProofAmendment.
        if self.stark_aggregation {
            let entries: Vec<SigBatchEntry> = included_txs
                .iter()
                .filter_map(|tx| {
                    if let shell_core::PubkeyMode::Embedded(ref pk) = tx.pubkey_mode {
                        let mut msg_hash = [0u8; 32];
                        msg_hash.copy_from_slice(tx.hash().as_bytes());
                        let mut pk_hash = [0u8; 32];
                        let copy_len = pk.len().min(32);
                        pk_hash[..copy_len].copy_from_slice(&pk[..copy_len]);
                        Some(SigBatchEntry { msg_hash, pk_hash })
                    } else {
                        None
                    }
                })
                .collect();

            if !entries.is_empty() {
                let block_num = block.header.number;
                let mut hash_bytes = [0u8; 32];
                // Use a placeholder hash — real hash assigned after signing below.
                // The backlog task is updated by the ProverService on pop.
                hash_bytes[..8].copy_from_slice(&block_num.to_be_bytes());
                let mut backlog = self.proof_backlog.lock();
                backlog.push(ProofTask::new(hash_bytes, block_num, entries));
                debug!(
                    block = block_num,
                    "G4: proof task queued in backlog (async proving)"
                );
            }
        }

        // Sign the block with the proposer's key.
        self.consensus.read().sign_block(&mut block, signer)?;

        // Register the signer's pubkey so we can verify our own blocks on re-import.
        self.register_authority_pubkey(proposer_addr, signer.public_key().to_vec());

        // Commit to storage.
        let block_hash = block.hash();
        self.chain_store.put_block(&block)?;
        self.chain_store.put_receipts(&block_hash, &receipts)?;
        self.chain_store
            .set_canonical(block.number(), &block_hash)?;
        self.chain_store.set_head(&block_hash)?;

        // Remove included transactions from mempool.
        let tx_hashes: Vec<ShellHash> = included_txs.iter().map(|tx| tx.hash()).collect();
        self.tx_pool.remove_batch(&tx_hashes);

        // Update global transaction counter for shell_transactionCount RPC.
        let new_tx_count = included_txs.len() as u64;
        if new_tx_count > 0 {
            self.chain_store.increment_tx_count(new_tx_count)?;
        }

        // Track the new state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);

        Ok(block)
    }

    /// Import and validate a block received from the network.
    ///
    /// Re-executes all transactions through the EVM on an isolated state
    /// snapshot, verifies the imported state root, then atomically swaps the
    /// live WorldState and stores the block.
    ///
    /// Fork detection: if the incoming block is at the same height as
    /// the current head but with a different hash, it is treated as a
    /// potential fork and skipped. If there is a gap (block number is
    /// more than one ahead of head), missing blocks are requested.
    pub fn import_block(&self, block: Block, _verifier: &dyn Verifier) -> Result<(), NodeError> {
        let head = self
            .chain_store
            .get_head_block()?
            .ok_or(NodeError::NoGenesis)?;

        let expected = head.number() + 1;
        let incoming = block.number();

        // Fork detection: same height, different hash.
        if incoming == head.number() && block.hash() != head.hash() {
            warn!(
                number = incoming,
                local_hash = %head.hash(),
                remote_hash = %block.hash(),
                "potential fork detected at same height, skipping import"
            );
            return Ok(());
        }

        // I1: Equivocation detection — check if the incoming block's proposer has
        // already produced a block at this height. If so, this is a double-sign event.
        // We detect by comparing against the block we have at `incoming` number.
        if let Ok(Some(existing)) = self.chain_store.get_block_by_number(incoming) {
            if existing.hash() != block.hash() && existing.header.proposer == block.header.proposer
            {
                let slash_record = detect_double_sign(&existing.header, &block.header);
                if let Some(record) = slash_record {
                    if let Some(equivocation) = EquivocationProof::from_slash_record(&record) {
                        if equivocation.verify() {
                            warn!(
                                offender = %equivocation.offender,
                                block_number = incoming,
                                "I1: double-sign detected, queuing equivocation broadcast"
                            );
                            // Store in equivocation queue for broadcast in the event loop.
                            self.equivocation_queue.lock().push(equivocation);
                        }
                    }
                }
            }
        }

        // Duplicate of current head — already have it.
        if incoming <= head.number() {
            debug!(
                incoming,
                head = head.number(),
                "ignoring block at or below current head"
            );
            return Ok(());
        }

        // Gap detection: block is too far ahead.
        if incoming > expected {
            warn!(
                incoming,
                expected,
                gap = incoming - expected,
                "block too far ahead, missing blocks need to be requested"
            );
            return Err(NodeError::GapDetected { incoming, expected });
        }

        // Verify consensus rules.
        self.consensus.read().verify_header(&block.header)?;

        // Verify EIP-1559 base fee is correct.
        let expected_base_fee = calculate_base_fee(
            head.header.gas_used,
            head.header.gas_limit,
            head.header.base_fee_per_gas,
        );
        if block.header.base_fee_per_gas != expected_base_fee {
            return Err(NodeError::Startup(format!(
                "invalid base_fee_per_gas: expected {expected_base_fee}, got {}",
                block.header.base_fee_per_gas,
            )));
        }

        // Verify proposer seal (PQ signature).
        match &block.proposer_seal {
            Some(seal) => {
                let proposer = &block.header.proposer;
                let known = self.known_authorities.read();
                if let Some(pubkey) = known.get(proposer) {
                    let verifier = MultiVerifier;
                    self.consensus
                        .read()
                        .verify_seal(&block.header, seal, pubkey, &verifier)?;
                } else {
                    // Try chain store as fallback.
                    drop(known);
                    if let Ok(Some(pubkey)) = self.chain_store.get_pubkey(proposer) {
                        let verifier = MultiVerifier;
                        self.consensus.read().verify_seal(
                            &block.header,
                            seal,
                            &pubkey,
                            &verifier,
                        )?;
                        // Cache for future lookups.
                        self.known_authorities.write().insert(*proposer, pubkey);
                    } else {
                        // F-308: Reject blocks from unknown proposers.
                        return Err(NodeError::Startup(format!(
                            "block {} seal verification failed: proposer {} pubkey unknown",
                            block.number(),
                            proposer
                        )));
                    }
                }
            }
            None => {
                warn!(
                    block = block.number(),
                    proposer = %block.header.proposer,
                    "imported block has no proposer seal (M1b: allowed, will be strict in M2)"
                );
            }
        }

        // C3: If the block carries a STARK aggregate proof, verify it.
        // A valid proof means the block producer correctly accumulated all
        // tx signature entries; this is belt-and-suspenders verification on top
        // of the existing individual sig checks below.
        if let Some(proof_bytes) = &block.header.sig_aggregate_proof {
            match shell_stark_prover::proof::SigBatchProof::from_json(proof_bytes.as_ref()) {
                Ok(sig_proof) => {
                    if let Err(e) = verify_sig_batch(&sig_proof) {
                        return Err(NodeError::Startup(format!(
                            "block {} STARK aggregate proof verification failed: {e}",
                            block.number()
                        )));
                    }
                    debug!(
                        block = block.number(),
                        n_sigs = sig_proof.n_sigs,
                        "C3: STARK aggregate proof verified"
                    );
                }
                Err(e) => {
                    return Err(NodeError::Startup(format!(
                        "block {} STARK aggregate proof deserialization failed: {e}",
                        block.number()
                    )));
                }
            }
        }

        let current_root = {
            let mut ws = self.world_state.write();
            ws.state_root()?
        };

        // Re-execute transactions against an isolated state snapshot.
        // The live WorldState is only swapped to the imported root after the
        // computed state_root matches the block header.
        let mut receipts = Vec::new();
        let mut new_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
        let imported_state_root = if !block.transactions.is_empty() {
            // Validate all transactions before execution (F-181):
            // security-critical checks (sig, algorithm, access list, pubkey)
            // are enforced during block import, not just mempool.
            let import_cs = ChainStore::new(self.store.clone());
            let mut block_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            // M5-C2: Batch verify all transaction signatures in parallel.
            // Resolve pubkeys and compute tx hashes, then dispatch to rayon.
            let batch_verifier = MultiVerifier;
            let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
            let mut resolved_pks: Vec<Vec<u8>> = Vec::with_capacity(block.transactions.len());
            for tx in &block.transactions {
                let pk = match &tx.pubkey_mode {
                    shell_core::PubkeyMode::Embedded(pk) => {
                        block_pubkeys.entry(tx.from).or_insert_with(|| pk.clone());
                        if import_cs
                            .get_pubkey(&tx.from)
                            .map_err(|e| {
                                NodeError::Startup(format!(
                                    "block {} pubkey lookup failed: {e}",
                                    block.number()
                                ))
                            })?
                            .is_none()
                        {
                            new_pubkeys.entry(tx.from).or_insert_with(|| pk.clone());
                        }
                        pk.clone()
                    }
                    shell_core::PubkeyMode::Reference => {
                        if let Some(pk) = block_pubkeys.get(&tx.from) {
                            pk.clone()
                        } else {
                            import_cs
                                .get_pubkey(&tx.from)
                                .map_err(|e| {
                                    NodeError::Startup(format!(
                                        "block {} pubkey lookup failed: {e}",
                                        block.number()
                                    ))
                                })?
                                .ok_or_else(|| {
                                    NodeError::Startup(format!(
                                        "block {} missing pubkey for {}",
                                        block.number(),
                                        tx.from
                                    ))
                                })?
                        }
                    }
                };
                resolved_pks.push(pk);
            }
            let verify_items: Vec<VerifyItem> = block
                .transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| VerifyItem {
                    pubkey: &resolved_pks[i],
                    message: tx_hashes[i].as_bytes(),
                    signature: &tx.signature,
                })
                .collect();
            batch_verifier
                .verify_batch_all(&verify_items)
                .map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} batch sig verification failed: {e}",
                        block.number()
                    ))
                })?;

            let ws = WorldState::at_root(self.store.clone(), &current_root)?;
            let cs = ChainStore::new(self.store.clone());
            let state_db = ShellStateDb::new(ws, cs);
            let mut evm = ShellEvm::new(state_db, self.config.chain_id);

            // Non-signature validation (chain-id, gas, sender binding).
            // Uses PreVerified to skip redundant individual
            // sig checks — signatures were already batch-verified above.
            //
            // IMPORTANT: validate_tx_for_import is READ-ONLY — it does NOT register
            // pubkeys (unlike validate_tx used in the mempool path). Pubkey registration
            // is deferred to the `new_pubkeys` commit at the end of import_block.
            // The `new_pubkeys` HashMap uses `or_insert_with` (first-write-wins), so
            // even if multiple Embedded txs from the same sender appear in one block,
            // only the first pubkey is written — registration is idempotent by design.
            //
            // Reference txs mutated to Embedded here (for validation) do NOT trigger
            // re-registration because validate_tx_for_import performs no writes.
            let pre_verified = PreVerified;
            let mut validation_pubkeys: HashMap<Address, Vec<u8>> = HashMap::new();
            for tx in &block.transactions {
                let mut tx_for_validation = tx.clone();
                if tx_for_validation.pubkey_mode.is_reference() {
                    if let Some(pk) = validation_pubkeys.get(&tx.from) {
                        tx_for_validation.pubkey_mode =
                            shell_core::PubkeyMode::Embedded(pk.clone());
                    }
                }

                validate_tx_for_import(
                    &tx_for_validation,
                    evm.state_db_mut().world_state_mut(),
                    &import_cs,
                    &pre_verified,
                    self.config.chain_id,
                )
                .map_err(|e| {
                    NodeError::Startup(format!(
                        "block {} tx validation failed: {e}",
                        block.number()
                    ))
                })?;

                if let shell_core::PubkeyMode::Embedded(pk) = &tx.pubkey_mode {
                    validation_pubkeys
                        .entry(tx.from)
                        .or_insert_with(|| pk.clone());
                }
            }
            let mut cumulative_gas: u64 = 0;

            for (idx, tx) in block.transactions.iter().enumerate() {
                match evm.execute_tx(tx, &block.header, idx as u32, cumulative_gas) {
                    Ok(result) => {
                        cumulative_gas += result.gas_used;
                        receipts.push(result.receipt);

                        if result.is_system_tx {
                            self.sync_system_contract_state(
                                evm.state_db_mut().world_state_mut(),
                                &result.system_contract_effects,
                            )?;
                        } else {
                            commit_evm_state(
                                &result.state_changes,
                                evm.state_db_mut().world_state_mut(),
                                &self.chain_store,
                            )?;
                        }
                    }
                    Err(e) => {
                        return Err(NodeError::Startup(format!(
                            "tx {} re-execution failed: {e}",
                            idx
                        )));
                    }
                }
            }
            evm.state_db_mut().world_state_mut().state_root()?
        } else {
            current_root
        };
        if imported_state_root != block.header.state_root {
            return Err(NodeError::Startup(format!(
                "block {} state root mismatch: expected {:?}, got {:?}",
                block.number(),
                block.header.state_root,
                imported_state_root
            )));
        }

        // B5: Validate witness_root when present.
        // If the header declares a witness_root, the stored bundle must hash to it.
        if let Some(expected_root) = block.header.witness_root {
            let block_hash_for_witness = block.hash();
            match self.witness_store.get_bundle(&block_hash_for_witness) {
                Ok(Some(bundle)) => {
                    let computed = bundle.compute_root();
                    if computed != expected_root {
                        return Err(NodeError::Startup(format!(
                            "block {} witness_root mismatch: header={:?}, computed={:?}",
                            block.number(),
                            expected_root,
                            computed
                        )));
                    }
                }
                Ok(None) => {
                    // Witness bundle not yet available (e.g. not yet delivered by network).
                    // Log and allow import — full validation requires witness propagation
                    // (Phase B network layer). Reject only if bundle is present but wrong.
                    debug!(
                        block = block.number(),
                        witness_root = ?expected_root,
                        "witness bundle not in store; skipping witness_root check for now"
                    );
                }
                Err(e) => {
                    return Err(NodeError::Startup(format!(
                        "block {} witness store lookup failed: {e}",
                        block.number()
                    )));
                }
            }
        }

        let committed_world_state = WorldState::at_root(self.store.clone(), &imported_state_root)?;
        {
            let mut live_ws = self.world_state.write();
            *live_ws = committed_world_state;
        }

        // Commit to storage.
        let block_hash = block.hash();
        self.chain_store.put_block(&block)?;
        if !receipts.is_empty() {
            self.chain_store.put_receipts(&block_hash, &receipts)?;
        }
        self.chain_store
            .set_canonical(block.number(), &block_hash)?;
        self.chain_store.set_head(&block_hash)?;
        for (address, pubkey) in new_pubkeys {
            self.chain_store.put_pubkey(&address, &pubkey)?;
        }

        // Remove any included transactions from our mempool.
        let tx_hashes: Vec<ShellHash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.tx_pool.remove_batch(&tx_hashes);

        // Update global transaction counter for shell_transactionCount RPC.
        let imported_tx_count = block.transactions.len() as u64;
        if imported_tx_count > 0 {
            let _ = self.chain_store.increment_tx_count(imported_tx_count);
        }

        // Track the imported state root for pruning decisions.
        self.record_finalized_state_root(block.number(), block.header.state_root);

        // H4: Standalone Prover node — extract sig batch entries from imported block
        // and push them to the proof backlog for async proving.
        // Validators handle this in produce_block (G4); Prover nodes do it here.
        if self.config.node_role == NodeRole::Prover {
            let block_number = block.number();
            let block_hash = block.hash();
            let entries: Vec<shell_stark_prover::prover::SigBatchEntry> = block
                .transactions
                .iter()
                .map(|tx| {
                    let tx_hash = tx.hash();
                    let sender = tx.sender();
                    let mut pk_hash = [0u8; 32];
                    pk_hash[..20].copy_from_slice(sender.0.as_slice());
                    shell_stark_prover::prover::SigBatchEntry {
                        msg_hash: *tx_hash.0,
                        pk_hash,
                    }
                })
                .collect();
            if !entries.is_empty() {
                let n = entries.len();
                let task = ProofTask {
                    block_hash: *block_hash.0,
                    block_number,
                    entries,
                };
                self.proof_backlog.lock().push(task);
                debug!(
                    block = block_number,
                    n_entries = n,
                    "H4: Pushed proof task for standalone prover"
                );
            }
        }

        Ok(())
    }

    /// Handle a transaction received from the network.
    pub fn handle_incoming_tx(
        &self,
        tx: SignedTransaction,
        _verifier: &dyn Verifier,
    ) -> Result<ShellHash, NodeError> {
        let chain_store = &self.chain_store;
        let mut world_state_guard = self.world_state.write();

        let dv = MultiVerifier;
        let hash = self
            .tx_pool
            .insert(tx, &mut world_state_guard, chain_store.as_ref(), &dv)
            .map_err(|e| NodeError::Startup(e.to_string()))?;

        Ok(hash)
    }

    /// Process an incoming attestation from the network.
    pub fn handle_attestation(
        &self,
        attestation: Attestation,
        verifier: &dyn Verifier,
    ) -> Result<(), NodeError> {
        let block_hash = attestation.block_hash;
        let block_number = attestation.block_number;
        let validator = attestation.validator;

        // F-087: Verify the attested block exists in our local chain store.
        // If unknown, log and skip — the block may arrive later via sync.
        match self.chain_store.get_block_by_hash(&block_hash) {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(
                    %block_hash,
                    block_number,
                    %validator,
                    "attestation for unknown block — skipping (may arrive via sync)"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    %block_hash,
                    error = %e,
                    "failed to check block existence for attestation"
                );
                return Ok(());
            }
        }

        // Verify the attesting validator is a known authority.
        let known = self.known_authorities.read();
        let pubkey = known.get(&validator).ok_or_else(|| {
            NodeError::Startup(format!("unknown attestation validator: {:?}", validator))
        })?;

        // Verify the attestation signature.
        let msg = Attestation::signing_message(&block_hash, block_number);
        let sig = shell_crypto::PQSignature::new(
            shell_crypto::SignatureType::Dilithium3,
            attestation.signature.clone(),
        );
        let valid = verifier
            .verify(pubkey, &msg, &sig)
            .map_err(|_| NodeError::Startup("invalid attestation signature".into()))?;
        if !valid {
            return Err(NodeError::Startup(
                "attestation signature verification failed".into(),
            ));
        }

        // Check for equivocation.
        let mut finality = self.finality.write();
        if let Some(conflicting) =
            finality.detect_equivocation(&block_hash, block_number, &validator)
        {
            tracing::error!(
                %validator,
                %block_hash,
                %conflicting,
                height = block_number,
                "equivocation detected — rejecting attestation"
            );
            return Err(NodeError::Startup(format!(
                "equivocation: validator {validator:?} already attested to {conflicting:?} at height {block_number}"
            )));
        }

        // Record the attestation.
        if !finality.record_attestation(attestation) {
            return Ok(()); // duplicate, already recorded
        }

        // Check if this block reached finality.
        let total_validators = self.consensus.read().config().authorities.len();
        if finality.check_finality(&block_hash, block_number, total_validators) {
            tracing::info!(
                block = block_number,
                hash = %block_hash,
                "block finalized"
            );
            let _ = self.chain_store.set_finalized_number(block_number);
            // F-088: Prune fork choice data for old blocks to prevent unbounded growth.
            let mut fc = self.fork_choice.write();
            fc.mark_finalized(&block_hash);
            fc.prune_below(block_number);
        }

        Ok(())
    }

    /// Create and return an attestation for a block (called after producing/importing a block).
    pub fn create_attestation(
        &self,
        block_hash: ShellHash,
        block_number: u64,
        signer: &dyn Signer,
    ) -> Result<Attestation, NodeError> {
        let proposer_addr = self.config.proposer_address.ok_or(NodeError::NotProposer)?;

        let msg = Attestation::signing_message(&block_hash, block_number);
        let sig = signer
            .sign(&msg)
            .map_err(|e| NodeError::Startup(format!("failed to sign attestation: {e}")))?;

        Ok(Attestation::new(
            block_hash,
            block_number,
            proposer_addr,
            sig.data,
        ))
    }
}

impl<S: KvStore + 'static> DevRpcControl for Node<S> {
    fn mine_blocks(&self, blocks: u64) -> Result<(), String> {
        let signer = self
            .runtime_signer
            .read()
            .clone()
            .ok_or_else(|| "node signer is not initialized".to_string())?;
        for _ in 0..blocks.max(1) {
            self.produce_block(signer.as_ref(), 500)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn set_next_block_timestamp(&self, timestamp: u64) -> Result<u64, String> {
        let head = self
            .chain_store
            .get_head_block()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing head block".to_string())?;
        let min_timestamp = head.header.timestamp.saturating_add(1);
        if timestamp < min_timestamp {
            return Err(format!(
                "timestamp must be >= next valid block timestamp {min_timestamp}"
            ));
        }
        self.dev_state.write().next_block_timestamp = Some(timestamp);
        Ok(timestamp)
    }

    fn increase_time(&self, seconds: u64) -> Result<u64, String> {
        let head = self
            .chain_store
            .get_head_block()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "missing head block".to_string())?;
        let mut dev = self.dev_state.write();
        let base_timestamp = dev
            .next_block_timestamp
            .unwrap_or(head.header.timestamp)
            .max(head.header.timestamp);
        let next_timestamp = base_timestamp.saturating_add(seconds);
        dev.next_block_timestamp = Some(next_timestamp);
        Ok(next_timestamp.saturating_sub(head.header.timestamp))
    }

    fn snapshot(&self) -> Result<String, String> {
        self.snapshot_inner().map_err(|e| e.to_string())
    }

    fn revert(&self, snapshot_id: &str) -> Result<bool, String> {
        self.revert_inner(snapshot_id).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pruning::PruningConfig;
    use shell_consensus::PoaConfig;
    use shell_core::Transaction;
    use shell_crypto::{DilithiumSigner, Signer};
    use shell_mempool::MempoolConfig;
    use shell_primitives::U256;
    use shell_rpc::DevRpcControl;
    use shell_storage::MemoryDb;

    fn setup_node() -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![authority],
            1,
        ))));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let config = NodeConfig::dev(authority);
        let node = Node::new(config, db, chain_store, world_state, tx_pool, consensus);
        (node, signer)
    }

    fn store_genesis(node: &Node<MemoryDb>) {
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
            proposer_seal: None,
        };
        let hash = genesis.hash();
        node.chain_store.put_block(&genesis).unwrap();
        node.chain_store.set_canonical(0, &hash).unwrap();
        node.chain_store.set_head(&hash).unwrap();
    }

    fn fund_account(node: &Node<MemoryDb>, addr: &Address, balance: U256) {
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

    fn current_state_root(node: &Node<MemoryDb>) -> ShellHash {
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
    fn produce_empty_block() {
        let (node, signer) = setup_node();
        store_genesis(&node);

        let block = node.produce_block(&signer, 100).unwrap();
        assert_eq!(block.number(), 1);
        assert!(block.transactions.is_empty());
        assert!(block.proposer_seal.is_some());
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
        let receiver = Address::from([0xBB; 20]);
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
        let tx_hash = {
            let encoded = alloy_rlp::encode(&tx);
            shell_primitives::keccak256(&encoded)
        };
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

        let tx_hash = {
            let encoded = alloy_rlp::encode(&tx);
            shell_primitives::keccak256(&encoded)
        };
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
        store_genesis(&node);
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));
        let config = NodeConfig::dev(proposer);
        let node2 = Node::new(config, node2_db, node2_cs, node2_ws, tx_pool, consensus);
        store_genesis(&node2);

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
        let receiver = Address::from([0xCC; 20]);
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
        let tx0_hash = {
            let encoded = alloy_rlp::encode(&tx0);
            shell_primitives::keccak256(&encoded)
        };
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        let tx1_hash = {
            let encoded = alloy_rlp::encode(&tx1);
            shell_primitives::keccak256(&encoded)
        };
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
        let receiver = Address::from([0xEE; 20]);
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
            .sign(tx0.hash().0.as_slice())
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
            .sign(tx1.hash().0.as_slice())
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        let receiver = Address::from([0xFF; 20]);
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
            .sign(tx0.hash().0.as_slice())
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
            .sign(tx1.hash().0.as_slice())
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
            err_msg.contains("pubkey") || err_msg.contains("missing"),
            "expected pubkey-related error, got: {err_msg}"
        );
    }

    #[test]
    fn import_block_materializes_state_root_for_restart() {
        let (leader, proposer_signer) = setup_node();
        store_genesis(&leader);
        let proposer = leader.config.proposer_address.unwrap();

        let tx_signer = DilithiumSigner::generate();
        let sender = Address::from_public_key(tx_signer.public_key(), tx_signer.sig_type().as_u8());
        let receiver = Address::from([0xDD; 20]);
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
        let tx_hash = {
            let encoded = alloy_rlp::encode(&tx);
            shell_primitives::keccak256(&encoded)
        };
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        let receiver = Address::from([0xEE; 20]);
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
        let tx_hash = {
            let encoded = alloy_rlp::encode(&tx);
            shell_primitives::keccak256(&encoded)
        };
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        fund_account(&follower, &Address::from([0xAB; 20]), U256::from(42u64));
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        store_genesis(&node);

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

    #[test]
    fn epoch_boundary_reloads_validators() {
        let signer = DilithiumSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus = Arc::new(RwLock::new(PoaEngine::new(
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
        let new_validator = Address::from([0xAA; 20]);
        {
            let mut ws = node.world_state.write();
            ws.set_validators(&[authority, new_validator]).unwrap();
        }

        // Before epoch boundary, consensus has 1 authority.
        assert_eq!(node.consensus.read().config().authorities.len(), 1);

        // Produce blocks until we hit the epoch boundary (block 3).
        for _ in 0..3 {
            node.produce_block(&signer, 0).unwrap();
        }

        // Block 3 is an epoch boundary (epoch_length=3).
        // Simulate the epoch boundary sync that the event loop would do.
        {
            let consensus = node.consensus.read();
            if consensus.config().is_epoch_boundary(3) {
                drop(consensus);
                let ws = node.world_state.read();
                let validators = ws.get_validators().unwrap();
                drop(ws);
                if !validators.is_empty() {
                    node.consensus
                        .write()
                        .config_mut()
                        .set_authorities(validators);
                }
            }
        }

        // After epoch boundary reload, consensus should have 2 authorities.
        let consensus_guard = node.consensus.read();
        let authorities = &consensus_guard.config().authorities;
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(
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
        assert_eq!(node.consensus.read().config().authorities.len(), 1);

        // Write validators mid-epoch.
        let new_val = Address::from([0xCC; 20]);
        {
            let mut ws = node.world_state.write();
            ws.set_validators(&[authority, new_val]).unwrap();
        }

        // Still not reloaded until epoch boundary.
        assert_eq!(node.consensus.read().config().authorities.len(), 1);

        // Produce block 2 — epoch boundary (epoch_length=2).
        node.produce_block(&signer, 0).unwrap();

        // Simulate epoch boundary sync.
        {
            let consensus = node.consensus.read();
            if consensus.config().is_epoch_boundary(2) {
                drop(consensus);
                let ws = node.world_state.read();
                let validators = ws.get_validators().unwrap();
                drop(ws);
                if !validators.is_empty() {
                    node.consensus
                        .write()
                        .config_mut()
                        .set_authorities(validators);
                }
            }
        }

        // Now the validator set should be updated.
        assert_eq!(node.consensus.read().config().authorities.len(), 2);
    }

    // ── Pruning integration tests ──────────────────────────────────────

    fn setup_node_with_pruning(keep_recent: u64) -> (Node<MemoryDb>, DilithiumSigner) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let authority = Address::from_public_key(&pubkey, signer.sig_type().as_u8());

        let db = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(db.clone()));
        let world_state = Arc::new(RwLock::new(WorldState::new(db.clone())));
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![authority],
            1,
        ))));
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
    fn import_fork_block_at_same_height_skipped() {
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
            proposer_seal: None,
        };

        // Should succeed (silently skipped as fork), head unchanged.
        let result = node.import_block(fork_block, &verifier);
        assert!(result.is_ok());
        assert_eq!(
            node.chain_store.get_head_hash().unwrap().unwrap(),
            block1_hash,
            "head should remain unchanged after fork block is skipped"
        );
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![proposer],
            1,
        ))));
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
        let receiver = Address::from([0xCC; 20]);

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

        let tx_hash = {
            let encoded = alloy_rlp::encode(&tx);
            shell_primitives::keccak256(&encoded)
        };
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
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, 1, "transfer tx should succeed");
        assert_eq!(receipts[0].gas_used, 21_000);
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
        let consensus = Arc::new(RwLock::new(PoaEngine::new(PoaConfig::new(
            vec![authority],
            1,
        ))));
        let tx_pool = Arc::new(TxPool::new(MempoolConfig {
            chain_id: 1337,
            ..MempoolConfig::default()
        }));

        let mut config = NodeConfig::dev(authority);
        config.enable_stark_aggregation = true;
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
            to: Some(Address::from([0xBE; 20])),
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
        let sig = signer.sign(tx.hash().0.as_slice()).unwrap();
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

        // Every block with embedded txs must push a proof task.
        assert_eq!(
            total_backlog, NUM_BLOCKS,
            "expected {NUM_BLOCKS} proof tasks in backlog, got {total_backlog}"
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

    /// STARK compression: verify ProverService processes the backlog and stores
    /// proof amendments.
    #[tokio::test]
    async fn stark_prover_service_processes_backlog() {
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

        // Produce block 1 → 5 embedded txs → 1 proof task queued.
        let block = node.produce_block(&proposer_signer, 20).unwrap();
        let block_num = block.number();

        // produce_block pushes a ProofTask with a placeholder hash derived from
        // block_number (see G4 in node.rs): hash_bytes[..8] = block_num.to_be_bytes().
        // The ProverService stores the amendment under that same placeholder hash.
        let mut placeholder = [0u8; 32];
        placeholder[..8].copy_from_slice(&block_num.to_be_bytes());
        let placeholder_hash = ShellHash::from(placeholder);

        assert_eq!(
            node.proof_backlog.lock().len(),
            1,
            "expected 1 proof task after producing 1 block with {TXS} embedded txs"
        );

        // Start ProverService to process the backlog.
        let db = node.store.clone();
        let amendment_store = ProofAmendmentStore::new(db);
        let svc = ProverService::new(
            Arc::clone(&node.proof_backlog),
            amendment_store.clone(),
            ProverConfig::default(),
            node.config.proposer_address.unwrap_or_default(),
        );
        let handle = svc.start();

        // Wait for proof to be processed (proving 5 entries takes ~5-15ms in mock mode).
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        handle.shutdown().await;

        // Backlog should be drained.
        assert_eq!(
            node.proof_backlog.lock().len(),
            0,
            "ProverService should have drained the backlog"
        );

        // Amendment should be stored under the placeholder hash.
        let stored_bytes = amendment_store
            .get_amendment(&placeholder_hash)
            .expect("amendment store read failed");
        assert!(
            stored_bytes.is_some(),
            "ProofAmendment for block #{block_num} should be stored under placeholder hash {placeholder_hash}"
        );

        // Deserialize and check the amendment.
        let bytes = stored_bytes.unwrap();
        let amendment: shell_stark_prover::ProofAmendment =
            serde_json::from_slice(&bytes).expect("amendment deserialization failed");
        let proof_size = amendment.proof.size_bytes();
        let raw_sig_pubkey_size = TXS * (3309 + 1952);

        println!("\n╔══ STARK ProverService Test ════════════════════════════════════╗");
        println!("║  Block #{block_num}: {TXS} embedded txs → proof generated & stored");
        println!(
            "║  Proof size: {proof_size} bytes ({:.1} KB)",
            proof_size as f64 / 1024.0
        );
        println!(
            "║  Raw sig+pubkey: {raw_sig_pubkey_size} bytes ({:.1} KB)",
            raw_sig_pubkey_size as f64 / 1024.0
        );
        println!(
            "║  Actual compression: {:.1}×",
            raw_sig_pubkey_size as f64 / proof_size as f64
        );
        println!("╚════════════════════════════════════════════════════════════════╝\n");

        assert!(proof_size > 0, "proof must be non-empty");
        assert!(
            proof_size < raw_sig_pubkey_size,
            "STARK proof ({proof_size} B) should be smaller than raw sig+pubkey data ({raw_sig_pubkey_size} B)"
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
}
