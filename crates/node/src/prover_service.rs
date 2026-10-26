//! Background STARK prover service — decouples proving from block production.
//!
//! `ProverService` runs as a `tokio::spawn`-ed background task. It continuously
//! drains the [`ProofBacklog`], calls [`prove_sig_batch`] for each task, and
//! stores the resulting [`ProofAmendment`] in the chain store.  Block production
//! is never blocked waiting for a proof.
//!
//! ## Lifecycle
//!
//! ```text
//! ProverService::start()
//!   └─► tokio::spawn(run_loop)
//!         └─► loop { pop task → prove → store amendment → broadcast }
//!               └─► shutdown_rx changed → break
//! ```
//!
//! ## Shutdown
//!
//! The owner sends `true` on the `shutdown_tx` watch channel.  The service
//! loop checks the channel on each iteration and exits gracefully, allowing
//! in-flight proofs to complete before stopping.
//!
//! Dropping the handle also aborts the async service loop to avoid leaving an
//! orphaned task. This does **not** hard-cancel CPU work already running inside
//! `spawn_blocking`; those proof jobs may run to completion.

use std::{collections::VecDeque, sync::Arc, time::Instant};

use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use parking_lot::Mutex;
use shell_crypto::Signer;
use shell_primitives::{Address, ShellHash};
use shell_stark_prover::{
    prove_sig_batch, L1StallDiagnosis, L2ProverTask, ProofAmendment, ProofBacklog, ProofTask,
    DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS, PROOF_AMENDMENT_VERSION,
};
use shell_storage::{ChainStore, KvStore, ProofAmendmentStore, StorageError};

use crate::{config::L2StarkMode, metrics::Metrics};

/// Bound local reservations while an explicitly configured cohort member is offline.
const MAX_WORKER_COHORT: usize = 64;
const MAX_DEFERRED_COHORT_RANGES: usize = 64;

/// Opt-in L1 assignment from canonical sources and coordinated membership.
/// Membership is independent of peer arrival timing and does not change proof
/// validity, rewards, validator membership, or consensus state.
pub(crate) struct WorkerCohort<S: KvStore> {
    epochs: Vec<(u64, Vec<Address>)>,
    local: Address,
    chain: ChainStore<S>,
    deferred: VecDeque<ProofTask>,
    registry_mode: bool,
    fallback_after_blocks: u64,
}

impl<S: KvStore + 'static> WorkerCohort<S> {
    #[cfg(test)]
    pub(crate) fn open(
        store: Arc<S>,
        workers: Vec<Address>,
        local: Address,
    ) -> Result<Option<Self>, StorageError> {
        Self::open_scheduled(store, workers, Vec::new(), local)
    }

    #[cfg(test)]
    pub(crate) fn open_scheduled(
        store: Arc<S>,
        workers: Vec<Address>,
        schedule: Vec<crate::config::ProverWorkerEpoch>,
        local: Address,
    ) -> Result<Option<Self>, StorageError> {
        Self::open_scheduled_with_fallback(store, workers, schedule, local, 0)
    }

    pub(crate) fn open_scheduled_with_fallback(
        store: Arc<S>,
        workers: Vec<Address>,
        schedule: Vec<crate::config::ProverWorkerEpoch>,
        local: Address,
        fallback_after_blocks: u64,
    ) -> Result<Option<Self>, StorageError> {
        if store.get(b"prover-worker-cohort/v1")?.as_deref() == Some(b"registry:v3") {
            return Err(StorageError::InvalidInput("registry-derived worker cohort cannot be disabled or replaced by a static schedule".into()));
        }
        let mut epochs = vec![(0, workers)];
        epochs.extend(
            schedule
                .into_iter()
                .map(|epoch| (epoch.from_block, epoch.workers)),
        );
        let enabled = !epochs[0].1.is_empty();
        if epochs.len() > MAX_WORKER_COHORT
            || (!enabled && epochs.len() != 1)
            || epochs.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(StorageError::InvalidInput(
                "worker_cohort_schedule requires an initial cohort and at most 63 strictly increasing future epochs".into(),
            ));
        }
        for (_, workers) in &mut epochs {
            workers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            if workers.len() > MAX_WORKER_COHORT
                || (enabled && workers.is_empty())
                || workers.windows(2).any(|pair| pair[0] == pair[1])
            {
                return Err(StorageError::InvalidInput(
                    "each worker cohort must contain 1 to 64 distinct addresses".into(),
                ));
            }
        }
        if enabled && !epochs.iter().any(|(_, workers)| workers.contains(&local)) {
            return Err(StorageError::InvalidInput(
                "worker cohort schedule must contain the local prover".into(),
            ));
        }
        let chain = ChainStore::new(Arc::clone(&store));
        let height = chain
            .get_head_block()?
            .map_or(0, |block| block.header.number);
        ProofAmendmentStore::new(store).bind_worker_cohort_schedule_with_fallback(
            &epochs,
            height,
            fallback_after_blocks,
        )?;
        Ok(enabled.then(|| Self {
            epochs,
            local,
            chain,
            deferred: VecDeque::new(),
            registry_mode: false,
            fallback_after_blocks,
        }))
    }

    pub(crate) fn open_registry(store: Arc<S>, local: Address) -> Result<Self, StorageError> {
        let chain = ChainStore::new(Arc::clone(&store));
        if chain
            .get_chain_config()?
            .and_then(|config| config.prover_registry_height)
            .is_none()
        {
            return Err(StorageError::InvalidInput(
                "registry-derived cohort requires configured prover_registry_height".into(),
            ));
        }
        let genesis = chain.get_block_hash_by_number(0)?.ok_or_else(|| {
            StorageError::State("missing canonical genesis for prover discovery".into())
        })?;
        let head = chain.get_head_block()?.ok_or_else(|| {
            StorageError::State("missing canonical head for prover discovery".into())
        })?;
        shell_storage::WorldState::at_root_with_cache_mb(
            Arc::clone(&store),
            &head.header.state_root,
            0,
        )?
        .registered_prover_members(genesis)?;
        let key = b"prover-worker-cohort/v1";
        match store.get(key)? {
            Some(bytes) if bytes != b"registry:v3" => {
                return Err(StorageError::InvalidInput(
                    "registry-derived cohort conflicts with persisted static assignments".into(),
                ))
            }
            Some(_) => {}
            None => store.put(key, b"registry:v3")?,
        }
        Ok(Self {
            epochs: Vec::new(),
            local,
            chain,
            deferred: VecDeque::new(),
            registry_mode: true,
            fallback_after_blocks: 0,
        })
    }

    fn assigned_owner(&self, task: &ProofTask) -> Result<Option<Address>, StorageError> {
        if !self.registry_mode {
            return Ok(Some(self.owner(task)));
        }
        let finalized = self.chain.get_finalized_number()?.unwrap_or(0);
        if task.block_number > finalized {
            return Ok(None);
        }
        let genesis = self
            .chain
            .get_block_hash_by_number(0)?
            .ok_or_else(|| StorageError::State("missing canonical genesis".into()))?;
        let tip_hash = self
            .chain
            .get_block_hash_by_number(finalized)?
            .ok_or_else(|| StorageError::State("missing finalized block".into()))?;
        let tip = self
            .chain
            .get_header_by_hash(&tip_hash)?
            .ok_or_else(|| StorageError::State("missing finalized header".into()))?;
        let store = Arc::clone(self.chain.store());
        let current = shell_storage::WorldState::at_root_with_cache_mb(
            Arc::clone(&store),
            &tip.state_root,
            0,
        )?
        .registered_prover_members(genesis)?;
        let Some(first) = current.iter().map(|(_, height)| *height).min() else {
            return Ok(None);
        };
        // A source range predating the first prover uses that first canonical
        // registration, so old backlog cannot remain permanently unassigned.
        let reference = task.block_number.max(first);
        if reference > finalized {
            return Ok(None);
        }
        // The current registry is append-only and its registration height is
        // immutable. Filter finalized records by the range's reference height;
        // no old state root or body must survive for historical assignment.
        let members: Vec<_> = current
            .into_iter()
            .filter(|(_, height)| *height <= reference)
            .collect();
        if members.is_empty() {
            return Ok(None);
        }
        if members.len() > MAX_WORKER_COHORT {
            return Err(StorageError::InvalidInput(
                "registry-derived cohort exceeds 64 workers".into(),
            ));
        }
        let source = task
            .source_hashes
            .first()
            .copied()
            .unwrap_or_else(|| ShellHash::from(task.block_hash));
        let prefix = u64::from_be_bytes(source.as_bytes()[..8].try_into().expect("hash prefix"));
        Ok(Some(members[(prefix % members.len() as u64) as usize].0))
    }

    fn members_for_task(&self, task: &ProofTask) -> &[Address] {
        let start = task
            .block_number
            .saturating_sub(task.source_hashes.len().saturating_sub(1) as u64);
        &self
            .epochs
            .iter()
            .rev()
            .find(|(from, _)| *from <= start)
            .expect("initial epoch at zero")
            .1
    }

    fn owner(&self, task: &ProofTask) -> Address {
        let source = task
            .source_hashes
            .first()
            .copied()
            .unwrap_or_else(|| ShellHash::from(task.block_hash));
        let workers = self.members_for_task(task);
        let prefix = u64::from_be_bytes(source.as_bytes()[..8].try_into().expect("hash prefix"));
        workers[(prefix % workers.len() as u64) as usize]
    }

    fn fallback_eligible(&self, task: &ProofTask) -> Result<bool, StorageError> {
        if self.fallback_after_blocks == 0 || self.registry_mode {
            return Ok(false);
        }
        let workers = self.members_for_task(task);
        let Some(local) = workers.iter().position(|worker| *worker == self.local) else {
            return Ok(false);
        };
        let primary = workers
            .iter()
            .position(|worker| *worker == self.owner(task))
            .expect("owner belongs to the selected epoch");
        let rank = (local + workers.len() - primary) % workers.len();
        if rank == 0 {
            return Ok(false);
        }
        let Some(wait) = self.fallback_after_blocks.checked_mul(rank as u64) else {
            return Ok(false);
        };
        let finalized = self.chain.get_finalized_number()?.unwrap_or(0);
        Ok(finalized
            .checked_sub(task.block_number)
            .is_some_and(|age| age >= wait))
    }

    fn reap(
        &mut self,
        amendments: &ProofAmendmentStore<S>,
        backlog: &Mutex<ProofBacklog>,
    ) -> Result<(), StorageError> {
        for _ in 0..self.deferred.len() {
            // Observe before removing metadata, retaining reservations on I/O errors.
            let task = self.deferred.front().expect("bounded deferred range");
            let done = amendments.has_amendment(&ShellHash::from(task.block_hash))?
                || self.chain.get_block_hash_by_number(task.block_number)?
                    != Some(ShellHash::from(task.block_hash))
                || (self.registry_mode && self.assigned_owner(task)? == Some(self.local))
                || self.fallback_eligible(task)?;
            let task = self.deferred.pop_front().expect("observed deferred range");
            if done {
                backlog.lock().complete_in_flight(
                    task.layer,
                    task.block_number,
                    &task.source_hashes,
                );
            } else {
                self.deferred.push_back(task);
            }
        }
        Ok(())
    }
}

// ── ProverConfig ──────────────────────────────────────────────────────────────

/// Configuration for the background prover service.
#[derive(Debug, Clone)]
pub struct ProverConfig {
    /// Maximum number of proof tasks to process concurrently.
    ///
    /// Set to 1 for sequential proving (safest, lowest memory).
    /// Higher values use more CPU/memory but reduce backlog latency.
    pub max_concurrent_proofs: usize,
    /// Priority mode controlling how the service schedules proving work.
    pub proving_priority: ProvingPriority,
    /// Minimum milliseconds to sleep between backlog polls when idle.
    pub idle_poll_ms: u64,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            max_concurrent_proofs: 1,
            proving_priority: ProvingPriority::Sequential,
            idle_poll_ms: 200,
        }
    }
}

/// Scheduling priority for the prover service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvingPriority {
    /// Prove blocks strictly in block-number order. Safest for chain consistency.
    Sequential,
    /// Prove newer eligible ranges first within a bounded contiguous window.
    /// Persistence and handoff still follow canonical source order.
    LatestFirst,
}

// ── ProverServiceHandle ───────────────────────────────────────────────────────

/// Handle returned by [`ProverService::start`].
///
/// Call [`shutdown`] for graceful termination.
///
/// Dropping the handle sends shutdown and aborts the async service loop to
/// avoid leaving an orphaned prover task. This is best-effort: proof generation
/// already running in `spawn_blocking` cannot be forcibly interrupted.
///
/// [`shutdown`]: ProverServiceHandle::shutdown
pub struct ProverServiceHandle {
    shutdown_tx: Option<watch::Sender<bool>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProverServiceHandle {
    /// Signal the prover service to stop and wait for it to finish.
    pub async fn shutdown(mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn shutdown_cleanly(mut self) {
        self.shutdown_tx
            .take()
            .expect("started service must own its shutdown sender")
            .send(true)
            .expect("prover service must be listening for shutdown");
        self.join_handle
            .take()
            .expect("started service must own its task")
            .await
            .expect("prover service task must exit cleanly");
    }
}

impl Drop for ProverServiceHandle {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = &self.shutdown_tx {
            let _ = shutdown_tx.send(true);
        }
        if let Some(join_handle) = &self.join_handle {
            join_handle.abort();
        }
    }
}

// ── ProverService ─────────────────────────────────────────────────────────────

/// Background STARK prover service.
pub struct ProverService<S: KvStore + Send + Sync + 'static> {
    backlog: Arc<Mutex<ProofBacklog>>,
    amendment_store: ProofAmendmentStore<S>,
    amendment_tx: Option<mpsc::Sender<ProofAmendment>>,
    config: ProverConfig,
    worker_cohort: Option<WorkerCohort<S>>,
    metrics: Option<Arc<Metrics>>,
    /// The node's own address, used as `prover` field in [`ProofAmendment`].
    prover_address: shell_primitives::Address,
    /// The node key that authenticates generated proof amendments.
    prover_signer: Option<Arc<dyn Signer>>,
    /// Readiness gate controlled by the node event loop. Proving must not
    /// compete with startup sync or publish amendments from a stale head.
    readiness_rx: Option<watch::Receiver<bool>>,
    /// L2 STARK mode — controls whether recursive L2 proving is attempted.
    l2_mode: L2StarkMode,
    #[cfg(test)]
    test_event_tx: Option<mpsc::UnboundedSender<ProverServiceTestEvent>>,
    #[cfg(test)]
    test_proof_hook: Option<Arc<dyn Fn(u64, bool) + Send + Sync>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProverServiceTestEvent {
    Started,
    BacklogPolled,
}

impl<S: KvStore + Send + Sync + 'static> ProverService<S> {
    /// Create a new prover service.
    pub fn new(
        backlog: Arc<Mutex<ProofBacklog>>,
        amendment_store: ProofAmendmentStore<S>,
        config: ProverConfig,
        prover_address: shell_primitives::Address,
    ) -> Self {
        Self {
            backlog,
            amendment_store,
            amendment_tx: None,
            config,
            worker_cohort: None,
            metrics: None,
            prover_address,
            prover_signer: None,
            readiness_rx: None,
            l2_mode: L2StarkMode::Disabled,
            #[cfg(test)]
            test_event_tx: None,
            #[cfg(test)]
            test_proof_hook: None,
        }
    }

    /// Record actual CPU proof attempts in the node's metrics registry.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn prove_timed(
        entries: &[shell_stark_prover::SigBatchEntry],
        metrics: Option<&Metrics>,
    ) -> Result<shell_stark_prover::SigBatchProof, String> {
        // Start inside the worker: queueing and ordered handoff are not CPU proving time.
        let _timer = metrics.map(|m| m.stark_proof_duration_seconds.start_timer());
        let started = Instant::now();
        info!(entries = entries.len(), "STARK CPU proof started");
        let result = prove_sig_batch(entries);
        info!(
            entries = entries.len(),
            elapsed_seconds = started.elapsed().as_secs_f64(),
            success = result.is_ok(),
            "STARK CPU proof finished"
        );
        result
    }

    /// Set the signer used to authenticate locally generated amendments.
    pub fn with_signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.prover_signer = Some(signer);
        self
    }

    /// Pause proof generation until the node has completed startup sync.
    pub fn with_readiness(mut self, readiness_rx: watch::Receiver<bool>) -> Self {
        self.readiness_rx = Some(readiness_rx);
        self
    }

    pub(crate) fn with_worker_cohort(mut self, cohort: Option<WorkerCohort<S>>) -> Self {
        self.worker_cohort = cohort;
        self
    }

    /// Set the L2 STARK mode for this service.
    pub fn with_l2_mode(mut self, mode: L2StarkMode) -> Self {
        self.l2_mode = mode;
        self
    }

    /// Send locally generated amendments back to the node event loop for P2P
    /// settlement ordering, reward queueing, and P2P broadcast after they are
    /// durably stored.
    pub fn with_amendment_sender(mut self, amendment_tx: mpsc::Sender<ProofAmendment>) -> Self {
        self.amendment_tx = Some(amendment_tx);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_event_sender(
        mut self,
        test_event_tx: mpsc::UnboundedSender<ProverServiceTestEvent>,
    ) -> Self {
        self.test_event_tx = Some(test_event_tx);
        self
    }

    /// Spawn the prover service as a background tokio task.
    ///
    /// Returns a [`ProverServiceHandle`] for graceful shutdown.
    pub fn start(self) -> ProverServiceHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join_handle = tokio::spawn(self.run_loop(shutdown_rx));
        ProverServiceHandle {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        }
    }

    async fn run_loop(mut self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            "ProverService started (max_concurrent={}, priority={:?})",
            self.config.max_concurrent_proofs, self.config.proving_priority
        );
        #[cfg(test)]
        if let Some(tx) = &self.test_event_tx {
            let _ = tx.send(ProverServiceTestEvent::Started);
        }
        let idle_sleep = tokio::time::Duration::from_millis(self.config.idle_poll_ms);
        let mut last_stall_log = Instant::now()
            .checked_sub(std::time::Duration::from_secs(300))
            .unwrap_or_else(Instant::now);
        let mut jobs: VecDeque<(ProofTask, _)> = VecDeque::new();
        let limit = self.config.max_concurrent_proofs.max(1);
        let mut latest_workers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut admission_failed = false;
        loop {
            if jobs.is_empty() {
                for worker in latest_workers.drain(..) {
                    if let Err(error) = worker.await {
                        error!(%error, "latest-first proof worker terminated");
                    }
                }
            }
            // Stop admission on shutdown, but drain all reserved CPU jobs.
            // Persist and hand off results in canonical admission order.
            // Check shutdown signal.
            if (*shutdown_rx.borrow() || admission_failed) && jobs.is_empty() {
                info!("ProverService received shutdown signal, stopping");
                break;
            }

            if jobs.is_empty() && self.readiness_rx.as_ref().is_some_and(|rx| !*rx.borrow()) {
                let readiness_rx = self
                    .readiness_rx
                    .as_mut()
                    .expect("readiness receiver checked above");
                tokio::select! {
                    changed = readiness_rx.changed() => {
                        if changed.is_err() {
                            info!("ProverService readiness channel closed, stopping");
                            break;
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            info!("ProverService received shutdown signal while paused");
                            break;
                        }
                    }
                }
                continue;
            }

            if !admission_failed {
                if let Some(cohort) = self.worker_cohort.as_mut() {
                    if let Err(error) = cohort.reap(&self.amendment_store, &self.backlog) {
                        error!(%error, "cannot observe deferred prover ranges; stopping admission");
                        admission_failed = true;
                        if jobs.is_empty() {
                            break;
                        }
                    }
                }
            }

            // Reserve contiguous source ranges before starting independent CPU work.
            // Results may finish in any order; only the front job can be persisted
            // and published, so later ranges never overtake their predecessor.
            // Latest-first reserves a finite window, then drains it before
            // admitting more work. Continuous arrivals cannot starve its frontier.
            let latest_first = self.config.proving_priority == ProvingPriority::LatestFirst;
            let capacity = if latest_first {
                limit.saturating_mul(2)
            } else {
                limit
            };
            let admit = !latest_first || jobs.is_empty();
            let mut reserved: Vec<ProofTask> = Vec::new();
            while admit
                && !admission_failed
                && jobs.len() + reserved.len() < capacity
                && !*shutdown_rx.borrow()
                && self.readiness_rx.as_ref().is_none_or(|rx| *rx.borrow())
                && self
                    .worker_cohort
                    .as_ref()
                    .is_none_or(|cohort| cohort.deferred.len() < MAX_DEFERRED_COHORT_RANGES)
            {
                let task = {
                    let mut backlog = self.backlog.lock();
                    let previous = reserved
                        .last()
                        .or_else(|| jobs.back().map(|(task, _)| task));
                    if let (Some(previous), Some(next)) = (previous, backlog.peek()) {
                        let next_start = next.block_number.checked_add(1).and_then(|end| {
                            end.checked_sub(next.source_hashes.len().max(1) as u64)
                        });
                        if previous.layer != next.layer
                            || previous.block_number.checked_add(1) != next_start
                        {
                            break;
                        }
                    }
                    backlog
                        .pop_contiguous_for_proving(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
                };
                #[cfg(test)]
                if let Some(tx) = &self.test_event_tx {
                    let _ = tx.send(ProverServiceTestEvent::BacklogPolled);
                }
                let Some(task) = task else { break };
                if task.layer == 1 {
                    if let Some(cohort) = self.worker_cohort.as_mut() {
                        let canonical = cohort.chain.get_block_hash_by_number(task.block_number);
                        let existing = self
                            .amendment_store
                            .has_amendment(&ShellHash::from(task.block_hash));
                        match (canonical, existing) {
                            (Ok(Some(hash)), Ok(false))
                                if hash == ShellHash::from(task.block_hash) => {}
                            (Ok(_), Ok(_)) => {
                                self.backlog.lock().complete_in_flight(
                                    task.layer,
                                    task.block_number,
                                    &task.source_hashes,
                                );
                                continue;
                            }
                            (Err(error), _) | (_, Err(error)) => {
                                error!(%error, "cannot inspect assigned prover range; preserving reservation");
                                cohort.deferred.push_back(task);
                                admission_failed = true;
                                break;
                            }
                        }
                        let owner = match cohort.assigned_owner(&task) {
                            Ok(Some(owner)) => owner,
                            Ok(None) => {
                                let mut task = task;
                                task.entries.clear();
                                cohort.deferred.push_back(task);
                                continue;
                            }
                            Err(error) => {
                                error!(%error, "cannot discover canonical prover membership; preserving reservation");
                                cohort.deferred.push_back(task);
                                admission_failed = true;
                                break;
                            }
                        };
                        let fallback = if owner != cohort.local {
                            match cohort.fallback_eligible(&task) {
                                Ok(eligible) => eligible,
                                Err(error) => {
                                    error!(%error, "cannot inspect finalized worker fallback; preserving reservation");
                                    cohort.deferred.push_back(task);
                                    admission_failed = true;
                                    break;
                                }
                            }
                        } else {
                            false
                        };
                        if owner != cohort.local && !fallback {
                            info!(%owner, block = task.block_number, "deferring L1 proof range to cohort owner");
                            let mut task = task;
                            task.entries.clear();
                            cohort.deferred.push_back(task);
                            continue;
                        }
                        info!(%owner, prover = %cohort.local, fallback, block = task.block_number, "admitting L1 proof range for cohort worker");
                    }
                }
                reserved.push(task);
            }
            if latest_first && !reserved.is_empty() {
                let worker_count = limit.min(reserved.len());
                let mut queue = Vec::with_capacity(reserved.len());
                for mut task in reserved {
                    let entries = std::mem::take(&mut task.entries);
                    let (sender, receiver) = oneshot::channel();
                    queue.push((entries, sender, task.block_number));
                    let result = tokio::spawn(async move {
                        receiver
                            .await
                            .unwrap_or_else(|_| Err("proof worker terminated".into()))
                    });
                    jobs.push_back((task, result));
                }
                let queue = Arc::new(Mutex::new(queue));
                for _ in 0..worker_count {
                    let queue = queue.clone();
                    let metrics = self.metrics.clone();
                    #[cfg(test)]
                    let hook = self.test_proof_hook.clone();
                    latest_workers.push(tokio::task::spawn_blocking(move || loop {
                        let work = queue.lock().pop();
                        let Some((entries, sender, _block_number)) = work else {
                            break;
                        };
                        #[cfg(test)]
                        if let Some(hook) = &hook {
                            hook(_block_number, false);
                        }
                        let result = Self::prove_timed(&entries, metrics.as_deref());
                        #[cfg(test)]
                        if let Some(hook) = &hook {
                            hook(_block_number, true);
                        }
                        let _ = sender.send(result);
                    }));
                }
            } else {
                for mut task in reserved {
                    let entries = std::mem::take(&mut task.entries);
                    #[cfg(test)]
                    let hook = self.test_proof_hook.clone();
                    #[cfg(test)]
                    let block_number = task.block_number;
                    let metrics = self.metrics.clone();
                    let proof = tokio::task::spawn_blocking(move || {
                        #[cfg(test)]
                        if let Some(hook) = &hook {
                            hook(block_number, false);
                        }
                        let result = Self::prove_timed(&entries, metrics.as_deref());
                        #[cfg(test)]
                        if let Some(hook) = hook {
                            hook(block_number, true);
                        }
                        result
                    });
                    jobs.push_back((task, proof));
                }
            }
            let task = jobs.pop_front();
            match task {
                None => {
                    // If the backlog is non-empty but pop returns None, log a stall
                    // warning at most once per 60 seconds so it doesn't spam the log.
                    {
                        let backlog = self.backlog.lock();
                        let depth = backlog.len();
                        if depth > 0 && last_stall_log.elapsed().as_secs() >= 60 {
                            last_stall_log = Instant::now();
                            let first_block = backlog.min_block_number_for_layer(1).unwrap_or(0);
                            let last_block = backlog.max_block_number_for_layer(1).unwrap_or(0);
                            let stall_info = backlog
                                .diagnose_l1_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
                            match stall_info {
                                Some(L1StallDiagnosis::GapBeforeThreshold {
                                    entries,
                                    gap_at_block: gap,
                                    contiguous_take: take,
                                }) => {
                                    warn!(
                                        depth,
                                        first_block,
                                        last_block,
                                        entries,
                                        gap_at_block = gap,
                                        contiguous_take = take,
                                        "STARK prover stalled: gap in backlog prevents reaching min_entries threshold"
                                    );
                                    // A strict L1 settlement must start at the
                                    // canonical frontier. Skipping a sparse or
                                    // unavailable range only creates a proof that
                                    // ordering validation will reject, so retain
                                    // the tasks until the seeder fills the gap.
                                    warn!(
                                        contiguous_tasks = take,
                                        entries,
                                        gap_at_block = gap,
                                        "STARK prover waiting for missing canonical frontier task"
                                    );
                                }
                                Some(L1StallDiagnosis::AwaitingMoreEntries {
                                    entries,
                                    contiguous_take: take,
                                }) => {
                                    info!(
                                        depth,
                                        first_block,
                                        last_block,
                                        entries,
                                        contiguous_take = take,
                                        min_entries = MIN_L1_STARK_TXS,
                                        "STARK prover waiting: L1 backlog tail is below proof threshold; awaiting more canonical non-empty blocks"
                                    );
                                }
                                None => {
                                    warn!(
                                        depth,
                                        first_block,
                                        last_block,
                                        "STARK prover stalled: pop returned None with non-empty backlog (diagnose_stall says OK?)"
                                    );
                                }
                            }
                        }
                    }
                    // Backlog empty (or insufficient entries) — sleep briefly before polling again.
                    tokio::select! {
                        _ = tokio::time::sleep(idle_sleep) => {}
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                    }
                }
                Some((task, proof)) => {
                    let layer = task.layer;
                    let block_number = task.block_number;
                    let source_hashes = if task.source_hashes.is_empty() {
                        vec![ShellHash::from(task.block_hash)]
                    } else {
                        task.source_hashes.clone()
                    };
                    let handed_off = self
                        .process_proof(task, proof.await, Some(&mut shutdown_rx))
                        .await;
                    if !handed_off {
                        self.backlog
                            .lock()
                            .complete_in_flight(layer, block_number, &source_hashes);
                    }
                }
            }
        }

        if let Some(cohort) = self.worker_cohort.as_mut() {
            for task in cohort.deferred.drain(..) {
                self.backlog.lock().complete_in_flight(
                    task.layer,
                    task.block_number,
                    &task.source_hashes,
                );
            }
        }
        info!("ProverService stopped");
    }

    #[cfg(test)]
    async fn process_task(
        &self,
        mut task: ProofTask,
        shutdown_rx: Option<&mut watch::Receiver<bool>>,
    ) -> bool {
        if task.layer == 1 && task.entries.is_empty() {
            return false;
        }
        let entries = std::mem::take(&mut task.entries);
        let metrics = self.metrics.clone();
        let proof =
            tokio::task::spawn_blocking(move || Self::prove_timed(&entries, metrics.as_deref()))
                .await;
        self.process_proof(task, proof, shutdown_rx).await
    }

    async fn process_proof(
        &self,
        task: ProofTask,
        proof_result: Result<
            Result<shell_stark_prover::SigBatchProof, String>,
            tokio::task::JoinError,
        >,
        mut shutdown_rx: Option<&mut watch::Receiver<bool>>,
    ) -> bool {
        let ProofTask {
            block_hash,
            block_number,
            source_hashes,
            layer,
            original_size,
            ..
        } = task;
        let mut handed_off = false;
        if !matches!(&proof_result, Ok(Ok(_))) {
            if let Some(metrics) = &self.metrics {
                metrics.stark_proof_failures.inc();
            }
        }
        match proof_result {
            Err(join_err) => {
                error!("ProverService: proof task panicked for block #{block_number}: {join_err}");
            }
            Ok(Err(prove_err)) => {
                warn!(
                    "ProverService: proof generation failed for block #{block_number}: {prove_err}"
                );
            }
            Ok(Ok(proof)) => {
                let block_hash_shell: ShellHash = block_hash.into();
                let mut amendment = ProofAmendment {
                    version: PROOF_AMENDMENT_VERSION,
                    block_hash: block_hash_shell,
                    block_number,
                    start_block: block_number.checked_add(1).and_then(|end_plus_one| {
                        end_plus_one.checked_sub(source_hashes.len().max(1) as u64)
                    }),
                    proof,
                    prover_signature: Default::default(),
                    prover: self.prover_address,
                    layer,
                    source_hashes: if source_hashes.is_empty() {
                        vec![block_hash_shell]
                    } else {
                        source_hashes
                    },
                    original_size,
                    compressed_size: None,
                    settlement_tx_hash: None,
                };
                let Some(signer) = self.prover_signer.as_deref() else {
                    error!(
                        "ProverService: refusing to persist unauthenticated amendment for block #{block_number}"
                    );
                    return false;
                };
                if let Err(e) = amendment.sign_prover_authentication(signer) {
                    error!(
                        "ProverService: failed to authenticate amendment for block #{block_number}: {e}"
                    );
                    return false;
                }
                if amendment.prover != self.prover_address {
                    error!(
                        configured = %self.prover_address,
                        signer = %amendment.prover,
                        "ProverService: configured prover address does not match signer for block #{block_number}"
                    );
                    return false;
                }

                // Serialize and persist the amendment artifacts.
                match amendment.storage_artifacts() {
                    Err(e) => {
                        error!(
                            "ProverService: failed to serialize amendment artifacts for block #{block_number}: {e}"
                        );
                    }
                    Ok(artifacts) => {
                        let artifact_count = artifacts.len();
                        match self.amendment_store.put_amendments_atomic(artifacts) {
                            Ok(()) => {
                                info!(
                                    "ProverService: proof amendment stored for range ending at block #{block_number} ({artifact_count} source hashes)"
                                );
                                if let Some(tx) = &self.amendment_tx {
                                    let sent = if let Some(shutdown_rx) = shutdown_rx.as_mut() {
                                        if *shutdown_rx.borrow() {
                                            false
                                        } else {
                                            tokio::select! {
                                                result = tx.send(amendment) => result.is_ok(),
                                                _ = shutdown_rx.changed() => false,
                                            }
                                        }
                                    } else {
                                        tx.send(amendment).await.is_ok()
                                    };
                                    if !sent {
                                        warn!(
                                            "ProverService: proof amendment channel closed or shutting down for block #{block_number}"
                                        );
                                    } else {
                                        handed_off = true;
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "ProverService: failed to atomically store amendment range ending at block #{block_number}: {e}"
                                );
                            }
                        }
                    }
                }
            }
        }
        handed_off
    }

    /// Handle an L2 recursive aggregation task.
    ///
    /// When `L2StarkMode::Active` is configured (and the `recursive` cargo
    /// feature is enabled), this would call a real recursive prover.
    ///
    /// Currently all L2 tasks are deferred: the job remains in `L2JobStore`
    /// with `Ready` status and a clear log explains why no proof was generated.
    pub async fn process_l2_task(&self, task: &L2ProverTask) {
        if !self.l2_mode.is_active() {
            info!(
                job_id = %shell_primitives::ShellHash::from(*task.job_id.as_bytes()),
                start_block = task.start_block,
                end_block = task.end_block,
                n_inputs = task.l1_source_hashes.len(),
                mode = %self.l2_mode,
                "ProverService: L2 recursive proving not active — job remains Ready; \
                 set l2_stark_mode=Active to enable"
            );
            return;
        }

        // Gated path: recursive proving implementation goes here when available.
        // For now, log that the prover is active but not yet implemented.
        warn!(
            job_id = %shell_primitives::ShellHash::from(*task.job_id.as_bytes()),
            start_block = task.start_block,
            end_block = task.end_block,
            "ProverService: L2StarkMode::Active set but recursive prover is not \
             yet implemented; no L2 proof generated"
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use shell_crypto::DilithiumSigner;
    use shell_primitives::Address;
    use shell_stark_prover::{ProofBacklog, ProofTask};
    use shell_storage::{MemoryDb, ProofAmendmentStore};

    fn make_service() -> (ProverService<MemoryDb>, Arc<Mutex<ProofBacklog>>) {
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        let db = Arc::new(MemoryDb::new());
        let amendment_store = ProofAmendmentStore::new(db);
        let config = ProverConfig::default();
        let signer = Arc::new(DilithiumSigner::generate());
        let prover_address =
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let service = ProverService::new(backlog.clone(), amendment_store, config, prover_address)
            .with_signer(signer);
        (service, backlog)
    }

    fn observe_service(
        service: ProverService<MemoryDb>,
    ) -> (
        ProverServiceHandle,
        mpsc::UnboundedReceiver<ProverServiceTestEvent>,
    ) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        (service.with_test_event_sender(event_tx).start(), event_rx)
    }

    async fn expect_service_event(
        event_rx: &mut mpsc::UnboundedReceiver<ProverServiceTestEvent>,
        expected: ProverServiceTestEvent,
    ) {
        let actual = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("prover service event timed out")
            .expect("prover service event channel closed");
        assert_eq!(actual, expected);
    }

    async fn shutdown_cleanly(handle: ProverServiceHandle) {
        handle.shutdown_cleanly().await;
    }

    fn registry_cohort_fixture(
        store: Arc<MemoryDb>,
        signers: &[Arc<DilithiumSigner>; 2],
    ) -> [shell_core::Block; 3] {
        let authority =
            Address::from_public_key(signers[0].public_key(), signers[0].sig_type().as_u8());
        let config = shell_genesis::GenesisConfig::from_json(&serde_json::json!({
            "chain_id":1337, "chain_name":"registry-cohort", "network_type":"Dev", "timestamp":1,
            "gas_limit":30000000, "extra_data":"registry-cohort", "alloc":{}, "boot_nodes":[], "prover_registry_height":0,
            "consensus":{"engine":"poa", "authorities":[authority], "block_time_secs":1, "max_future_secs":60}
        }).to_string()).unwrap();
        let genesis = shell_genesis::initialize_genesis(&config, store.clone()).unwrap();
        let chain = ChainStore::new(store.clone());
        let mut state =
            shell_storage::WorldState::at_root(store.clone(), &genesis.header.state_root).unwrap();
        let mut blocks = vec![genesis];
        for (i, signer) in signers.iter().enumerate() {
            let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
            state
                .set_registered_prover(
                    &address,
                    &shell_storage::RegisteredProver {
                        public_key: signer.public_key().to_vec(),
                        algorithm: signer.sig_type().as_u8(),
                        registered_at: i as u64 + 1,
                        proofs_submitted: 0,
                        last_proof_block: 0,
                    },
                )
                .unwrap();
            let mut block = blocks.last().unwrap().clone();
            block.header.parent_hash = blocks.last().unwrap().hash();
            block.header.number = i as u64 + 1;
            block.header.state_root = state.state_root().unwrap();
            block.header.timestamp += 1;
            if i == 1 {
                let mut members = signers
                    .each_ref()
                    .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()))
                    .to_vec();
                members.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                while members[(u64::from_be_bytes(block.hash().as_bytes()[..8].try_into().unwrap())
                    % 2) as usize]
                    != address
                {
                    block.header.timestamp += 1;
                }
            }
            chain.commit_canonical_block(&block, None).unwrap();
            blocks.push(block);
        }
        chain.set_finalized_number(2).unwrap();
        blocks.try_into().unwrap()
    }

    #[tokio::test]
    async fn registry_cohort_discovers_real_jobs_and_preserves_historical_membership() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let addresses = signers
            .each_ref()
            .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()));
        let stores = [Arc::new(MemoryDb::new()), Arc::new(MemoryDb::new())];
        let entries = vec![
            shell_stark_prover::SigBatchEntry {
                msg_hash: [7; 32],
                pk_hash: [9; 32]
            };
            MIN_L1_STARK_TXS
        ];
        let mut handles = Vec::new();
        let mut receivers = Vec::new();
        for i in 0..2 {
            let blocks = registry_cohort_fixture(stores[i].clone(), &signers);
            let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
            for block in &blocks[1..] {
                backlog.lock().push(ProofTask::new(
                    *block.hash().as_bytes(),
                    block.number(),
                    entries.clone(),
                ));
            }
            let cohort = WorkerCohort::open_registry(stores[i].clone(), addresses[i]).unwrap();
            let first = ProofTask::new(*blocks[1].hash().as_bytes(), 1, entries.clone());
            assert_eq!(
                cohort.assigned_owner(&first).unwrap(),
                Some(addresses[0]),
                "later registration cannot steal old canonical work"
            );
            let (tx, rx) = mpsc::channel(2);
            handles.push(
                ProverService::new(
                    backlog,
                    ProofAmendmentStore::new(stores[i].clone()),
                    ProverConfig::default(),
                    addresses[i],
                )
                .with_worker_cohort(Some(cohort))
                .with_signer(signers[i].clone())
                .with_amendment_sender(tx)
                .start(),
            );
            receivers.push(rx);
        }
        let mut proofs = Vec::new();
        for i in 0..2 {
            let proof = tokio::time::timeout(Duration::from_secs(5), receivers[i].recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.prover, addresses[i]);
            assert_eq!(proof.block_number, i as u64 + 1);
            shell_stark_prover::verify_sig_batch(&proof.proof).unwrap();
            proof.verify_prover_authentication().unwrap();
            proofs.push(proof);
        }
        assert_ne!(proofs[0].covered_hashes(), proofs[1].covered_hashes());
        for handle in handles {
            handle.shutdown_cleanly().await;
        }
        for i in 0..2 {
            let reopened = WorkerCohort::open_registry(stores[i].clone(), addresses[i]).unwrap();
            let task = ProofTask::new(*proofs[0].block_hash.as_bytes(), 1, entries.clone());
            assert_eq!(reopened.assigned_owner(&task).unwrap(), Some(addresses[0]));
            assert!(WorkerCohort::open(stores[i].clone(), vec![], addresses[i]).is_err());
            assert!(
                WorkerCohort::open(stores[i].clone(), addresses.to_vec(), addresses[i]).is_err()
            );
        }
    }

    #[test]
    fn registry_cohort_rejects_writer_gap_without_blessing_later_blocks() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let address =
            Address::from_public_key(signers[0].public_key(), signers[0].sig_type().as_u8());
        let db = Arc::new(MemoryDb::new());
        let blocks = registry_cohort_fixture(db.clone(), &signers);
        let chain = ChainStore::new(db.clone());
        let mut unsupported = blocks[2].clone();
        unsupported.header.number = 3;
        unsupported.header.parent_hash = blocks[2].hash();
        chain.put_block(&unsupported).unwrap();
        chain.set_canonical(3, &unsupported.hash()).unwrap();
        chain.set_head(&unsupported.hash()).unwrap();
        assert!(WorkerCohort::open_registry(db.clone(), address).is_err());
        let mut later = unsupported.clone();
        later.header.number = 4;
        later.header.parent_hash = unsupported.hash();
        chain.commit_canonical_block(&later, None).unwrap();
        assert!(
            WorkerCohort::open_registry(db, address).is_err(),
            "a capturing writer cannot certify an earlier unsupported gap"
        );
    }

    #[test]
    fn registry_cohort_rewind_filters_orphaned_members_and_rejects_no_activation() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let address =
            Address::from_public_key(signers[0].public_key(), signers[0].sig_type().as_u8());
        let db = Arc::new(MemoryDb::new());
        let blocks = registry_cohort_fixture(db.clone(), &signers);
        let chain = ChainStore::new(db.clone());
        chain
            .commit_canonical_rewind(
                &blocks[2..],
                &[2],
                &blocks[1].hash(),
                0,
                shell_primitives::U256::ZERO,
                1,
            )
            .unwrap();
        let cohort = WorkerCohort::open_registry(db.clone(), address).unwrap();
        let members = shell_storage::WorldState::at_root(db.clone(), &blocks[1].header.state_root)
            .unwrap()
            .registered_prover_members(blocks[0].hash())
            .unwrap();
        assert_eq!(
            members,
            vec![(address, 1)],
            "orphaned registration hints are not membership"
        );
        assert_eq!(
            cohort
                .assigned_owner(&ProofTask::new(*blocks[1].hash().as_bytes(), 1, vec![]))
                .unwrap(),
            Some(address)
        );
        let mut config = chain.get_chain_config().unwrap().unwrap();
        config.prover_registry_height = None;
        let no_activation = Arc::new(MemoryDb::new());
        ChainStore::new(no_activation.clone())
            .put_chain_config(&config)
            .unwrap();
        assert!(WorkerCohort::open_registry(no_activation, address).is_err());
    }

    #[test]
    fn registry_cohort_waits_for_finality_and_releases_local_deferred_work() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let address =
            Address::from_public_key(signers[0].public_key(), signers[0].sig_type().as_u8());
        let db = Arc::new(MemoryDb::new());
        let blocks = registry_cohort_fixture(db.clone(), &signers);
        let chain = ChainStore::new(db.clone());
        chain.set_finalized_number(0).unwrap();
        let mut cohort = WorkerCohort::open_registry(db.clone(), address).unwrap();
        let task = ProofTask::new(*blocks[1].hash().as_bytes(), 1, vec![]);
        assert!(cohort.assigned_owner(&task).unwrap().is_none());
        cohort.deferred.push_back(task.clone());
        chain.set_finalized_number(2).unwrap();
        cohort
            .reap(
                &ProofAmendmentStore::new(db.clone()),
                &Mutex::new(ProofBacklog::new()),
            )
            .unwrap();
        assert!(
            cohort.deferred.is_empty(),
            "normal canonical seeding can recover newly eligible local work"
        );
        let old = ProofTask::new(*blocks[0].hash().as_bytes(), 0, vec![]);
        assert_eq!(cohort.assigned_owner(&old).unwrap(), Some(address));
        let unindexed = Arc::new(MemoryDb::new());
        assert!(WorkerCohort::open_registry(unindexed, address).is_err());
    }

    #[tokio::test]
    async fn worker_cohort_assigns_real_proofs_once_and_retains_assignment_on_reopen() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let addresses = signers
            .each_ref()
            .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()));
        let mut sorted = addresses.to_vec();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let stores = [Arc::new(MemoryDb::new()), Arc::new(MemoryDb::new())];
        // Independent canonical source IDs choose opposite owners; these are
        // queue-level inputs. Native acceptance separately uses actual block hashes.
        let mut hashes = [[0u8; 32]; 2];
        hashes[0][31] = 1;
        hashes[1][7] = 1;
        hashes[1][31] = 2;
        let entries = vec![
            shell_stark_prover::SigBatchEntry {
                msg_hash: [7; 32],
                pk_hash: [9; 32]
            };
            MIN_L1_STARK_TXS
        ];
        let mut handles = Vec::new();
        let mut receivers = Vec::new();
        for i in 0..2 {
            let chain = ChainStore::new(stores[i].clone());
            let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
            for (n, h) in hashes.iter().enumerate() {
                chain
                    .set_canonical(n as u64 + 1, &ShellHash::from(*h))
                    .unwrap();
                backlog
                    .lock()
                    .push(ProofTask::new(*h, n as u64 + 1, entries.clone()));
            }
            let mut configured = addresses.to_vec();
            if i == 1 {
                configured.reverse();
            }
            let cohort = WorkerCohort::open(stores[i].clone(), configured, addresses[i]).unwrap();
            let (tx, rx) = mpsc::channel(2);
            handles.push(
                ProverService::new(
                    backlog,
                    ProofAmendmentStore::new(stores[i].clone()),
                    ProverConfig::default(),
                    addresses[i],
                )
                .with_worker_cohort(cohort)
                .with_signer(signers[i].clone())
                .with_amendment_sender(tx)
                .start(),
            );
            receivers.push(rx);
        }
        let mut proofs = Vec::new();
        for i in 0..2 {
            let a = tokio::time::timeout(Duration::from_secs(5), receivers[i].recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(a.prover, addresses[i]);
            assert_eq!(a.prover, sorted[(a.block_number - 1) as usize]);
            shell_stark_prover::verify_sig_batch(&a.proof).unwrap();
            a.verify_prover_authentication().unwrap();
            proofs.push(a);
        }
        assert_ne!(proofs[0].covered_hashes(), proofs[1].covered_hashes());
        for handle in handles {
            handle.shutdown().await;
        }
        for i in 0..2 {
            let store = ProofAmendmentStore::new(stores[i].clone());
            for a in &proofs {
                store
                    .put_amendments_atomic(a.storage_artifacts().unwrap())
                    .unwrap();
            }
            let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
            for (n, h) in hashes.iter().enumerate() {
                backlog
                    .lock()
                    .push(ProofTask::new(*h, n as u64 + 1, entries.clone()));
            }
            let cohort =
                WorkerCohort::open(stores[i].clone(), addresses.to_vec(), addresses[i]).unwrap();
            let (tx, mut rx) = mpsc::channel(2);
            let handle = ProverService::new(backlog, store, ProverConfig::default(), addresses[i])
                .with_worker_cohort(cohort)
                .with_signer(signers[i].clone())
                .with_amendment_sender(tx)
                .start();
            assert!(
                tokio::time::timeout(Duration::from_millis(250), rx.recv())
                    .await
                    .is_err(),
                "no cached proof recomputation"
            );
            handle.shutdown().await;
            assert!(
                WorkerCohort::open(stores[i].clone(), vec![], addresses[i]).is_err(),
                "cannot silently disable persisted cohort"
            );
            assert!(
                WorkerCohort::open(stores[i].clone(), vec![addresses[i]], addresses[i]).is_err(),
                "cannot silently reassign persisted cohort"
            );
        }
        let fresh = Arc::new(MemoryDb::new());
        assert!(WorkerCohort::open(
            fresh.clone(),
            vec![addresses[0], addresses[0]],
            addresses[0]
        )
        .is_err());
        assert!(WorkerCohort::open(fresh, vec![addresses[1]], addresses[0]).is_err());
    }

    #[tokio::test]
    async fn worker_cohort_schedule_preserves_crossing_ranges_and_moves_later_work() {
        use crate::config::ProverWorkerEpoch;
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let addresses = signers
            .each_ref()
            .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()));
        let epoch = ProverWorkerEpoch {
            from_block: 10,
            workers: vec![addresses[1]],
        };
        let entries = vec![
            shell_stark_prover::SigBatchEntry {
                msg_hash: [7; 32],
                pk_hash: [9; 32]
            };
            MIN_L1_STARK_TXS
        ];
        let sources: Vec<ShellHash> = (9..=14).map(|n| ShellHash::from([n; 32])).collect();
        let tasks = [
            ProofTask::with_sources(
                *sources[2].0,
                11,
                entries.clone(),
                1,
                sources[..3].to_vec(),
                None,
            ),
            ProofTask::with_sources(*sources[5].0, 14, entries, 1, sources[3..].to_vec(), None),
        ];
        for i in 0..2 {
            let store = Arc::new(MemoryDb::new());
            let chain = ChainStore::new(store.clone());
            let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
            for task in &tasks {
                chain
                    .set_canonical(task.block_number, &ShellHash::from(task.block_hash))
                    .unwrap();
                backlog.lock().push(task.clone());
            }
            let cohort = WorkerCohort::open_scheduled(
                store.clone(),
                vec![addresses[0]],
                vec![epoch.clone()],
                addresses[i],
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                cohort.owner(&tasks[0]),
                addresses[0],
                "crossing window belongs to its first-source epoch"
            );
            assert_eq!(
                cohort.owner(&tasks[1]),
                addresses[1],
                "new member owns the later window"
            );
            let (tx, mut rx) = mpsc::channel(2);
            let handle = ProverService::new(
                backlog,
                ProofAmendmentStore::new(store.clone()),
                ProverConfig::default(),
                addresses[i],
            )
            .with_worker_cohort(Some(cohort))
            .with_signer(signers[i].clone())
            .with_amendment_sender(tx)
            .start();
            let proof = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.block_number, [11, 14][i]);
            assert_eq!(proof.prover, addresses[i]);
            shell_stark_prover::verify_sig_batch(&proof.proof).unwrap();
            proof.verify_prover_authentication().unwrap();
            handle.shutdown().await;
            let reopened = WorkerCohort::open_scheduled(
                store.clone(),
                vec![addresses[0]],
                vec![epoch.clone()],
                addresses[i],
            )
            .unwrap()
            .unwrap();
            assert_eq!(reopened.owner(&tasks[0]), addresses[0]);
            assert_eq!(reopened.owner(&tasks[1]), addresses[1]);
            assert!(
                WorkerCohort::open(store.clone(), vec![addresses[0]], addresses[0]).is_err(),
                "scheduled database rejects static downgrade"
            );
            let amendments = ProofAmendmentStore::new(store.clone());
            let old = vec![(0, vec![addresses[0]]), (10, vec![addresses[1]])];
            let mut appended = old.clone();
            appended.push((20, addresses.to_vec()));
            assert!(
                amendments
                    .bind_worker_cohort_schedule(&appended, 20)
                    .is_err(),
                "backdated append rejected"
            );
            amendments.bind_worker_cohort_schedule(&old, 20).unwrap();
            amendments
                .bind_worker_cohort_schedule(&appended, 19)
                .unwrap();
            assert!(
                amendments.bind_worker_cohort_schedule(&old, 20).is_err(),
                "cannot remove an announced future epoch"
            );
            appended[1].1 = vec![addresses[0]];
            assert!(
                amendments
                    .bind_worker_cohort_schedule(&appended, 0)
                    .is_err(),
                "cannot rewrite history"
            );
            assert_eq!(
                store.get(b"prover-worker-cohort/v1").unwrap().unwrap(),
                b"scheduled:v2",
                "static-only binaries must fail their old equality check"
            );
        }
        let store = Arc::new(MemoryDb::new());
        for schedule in [
            vec![ProverWorkerEpoch {
                from_block: 0,
                workers: vec![addresses[1]],
            }],
            vec![ProverWorkerEpoch {
                from_block: 1,
                workers: vec![],
            }],
            vec![ProverWorkerEpoch {
                from_block: 1,
                workers: vec![addresses[1], addresses[1]],
            }],
        ] {
            assert!(WorkerCohort::open_scheduled(
                store.clone(),
                vec![addresses[0]],
                schedule,
                addresses[0]
            )
            .is_err());
        }
        assert!(
            store.get(b"prover-worker-cohort/v1").unwrap().is_none(),
            "invalid input must not bind the database"
        );
    }

    #[test]
    fn worker_cohort_releases_orphans_but_retains_reservations_on_storage_error() {
        struct FaultStore {
            db: MemoryDb,
            fail: std::sync::atomic::AtomicBool,
        }
        impl KvStore for FaultStore {
            fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(StorageError::Database("read fault".into()));
                }
                self.db.get(k)
            }
            fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
                self.db.put(k, v)
            }
            fn delete(&self, k: &[u8]) -> Result<(), StorageError> {
                self.db.delete(k)
            }
            fn flush(&self) -> Result<(), StorageError> {
                self.db.flush()
            }
            fn write_batch(&self, b: shell_storage::WriteBatch) -> Result<(), StorageError> {
                self.db.write_batch(b)
            }
            fn scan_prefix(&self, p: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
                self.db.scan_prefix(p)
            }
        }
        let store = Arc::new(FaultStore {
            db: MemoryDb::new(),
            fail: std::sync::atomic::AtomicBool::new(false),
        });
        let local = Address::from([1; 32]);
        let other = Address::from([2; 32]);
        let mut cohort = WorkerCohort::open(store.clone(), vec![other, local], local)
            .unwrap()
            .unwrap();
        let hash = ShellHash::from([7; 32]);
        cohort.chain.set_canonical(1, &hash).unwrap();
        let backlog = Mutex::new(ProofBacklog::new());
        backlog.lock().push(ProofTask::new([7; 32], 1, vec![]));
        let task = backlog.lock().pop_contiguous_for_proving(1, 0).unwrap();
        cohort.deferred.push_back(task);
        let amendments = ProofAmendmentStore::new(store.clone());
        cohort.reap(&amendments, &backlog).unwrap();
        assert_eq!(cohort.deferred.len(), 1);
        store.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(cohort.reap(&amendments, &backlog).is_err());
        assert_eq!(cohort.deferred.len(), 1);
        assert!(backlog.lock().contains_source(1, &hash));
        store
            .fail
            .store(false, std::sync::atomic::Ordering::Relaxed);
        cohort
            .chain
            .set_canonical(1, &ShellHash::from([8; 32]))
            .unwrap();
        cohort.reap(&amendments, &backlog).unwrap();
        assert!(cohort.deferred.is_empty());
        assert!(!backlog.lock().contains_source(1, &hash));
        assert_eq!(
            backlog.lock().first_uncovered_block_for_layer(1, 1, 1),
            Some(1)
        );
    }

    #[tokio::test]
    async fn worker_cohort_bounds_offline_owner_reservations_and_releases_on_shutdown() {
        let store = Arc::new(MemoryDb::new());
        let local = Address::from([1; 32]);
        let other = Address::from([2; 32]);
        let chain = ChainStore::new(store.clone());
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        for n in 0..=MAX_DEFERRED_COHORT_RANGES {
            let mut hash = [0u8; 32];
            hash[7] = 1;
            hash[31] = n as u8;
            chain
                .set_canonical(n as u64 + 1, &ShellHash::from(hash))
                .unwrap();
            backlog.lock().push(ProofTask::new(
                hash,
                n as u64 + 1,
                vec![
                    shell_stark_prover::SigBatchEntry {
                        msg_hash: [3; 32],
                        pk_hash: [4; 32]
                    };
                    MIN_L1_STARK_TXS
                ],
            ));
        }
        let cohort = WorkerCohort::open(store.clone(), vec![local, other], local).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let handle = ProverService::new(
            backlog.clone(),
            ProofAmendmentStore::new(store),
            ProverConfig::default(),
            local,
        )
        .with_worker_cohort(cohort)
        .with_amendment_sender(tx)
        .start();
        tokio::time::timeout(Duration::from_secs(1), async {
            while backlog.lock().len() > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            backlog.lock().len(),
            1,
            "bounded deferred slots leave later ranges queued"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), rx.recv())
                .await
                .is_err(),
            "offline ownership must not silently transfer"
        );
        handle.shutdown().await;
        assert_eq!(
            backlog.lock().covered_block_count_for_layer(1),
            1,
            "shutdown releases only deferred reservations"
        );
    }

    #[test]
    fn worker_fallback_uses_finalized_age_and_persists_policy() {
        let store = Arc::new(MemoryDb::new());
        let members = vec![
            Address::from([1; 32]),
            Address::from([2; 32]),
            Address::from([3; 32]),
        ];
        let task = ProofTask::new([0; 32], 10, vec![]);
        let chain = ChainStore::new(store.clone());
        let first = WorkerCohort::open_scheduled_with_fallback(
            store.clone(),
            members.clone(),
            vec![],
            members[1],
            3,
        )
        .unwrap()
        .unwrap();
        let second = WorkerCohort::open_scheduled_with_fallback(
            store.clone(),
            members.clone(),
            vec![],
            members[2],
            3,
        )
        .unwrap()
        .unwrap();
        for (height, a, b) in [
            (9, false, false),
            (10, false, false),
            (12, false, false),
            (13, true, false),
            (15, true, false),
            (16, true, true),
            (100, true, true),
        ] {
            chain.set_finalized_number(height).unwrap();
            assert_eq!(
                first.fallback_eligible(&task).unwrap(),
                a,
                "height {height}"
            );
            assert_eq!(
                second.fallback_eligible(&task).unwrap(),
                b,
                "height {height}"
            );
            assert_eq!(
                first.owner(&task),
                members[0],
                "fallback never revokes the primary"
            );
        }
        let before = store.scan_prefix(b"").unwrap();
        assert!(WorkerCohort::open(store.clone(), members.clone(), members[1]).is_err());
        assert!(WorkerCohort::open_scheduled_with_fallback(
            store.clone(),
            members.clone(),
            vec![],
            members[1],
            4
        )
        .is_err());
        assert!(
            ProofAmendmentStore::new(store.clone())
                .bind_worker_cohort_schedule(&[(0, members.clone())], 0)
                .is_err(),
            "older writer rejects recovery marker"
        );
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let mut reordered = members.clone();
        reordered.reverse();
        let reopened = WorkerCohort::open_scheduled_with_fallback(
            store.clone(),
            reordered,
            vec![],
            members[1],
            3,
        )
        .unwrap()
        .unwrap();
        assert!(reopened.fallback_eligible(&task).unwrap());
        let overflow_store = Arc::new(MemoryDb::new());
        let overflow = WorkerCohort::open_scheduled_with_fallback(
            overflow_store.clone(),
            members.clone(),
            vec![],
            members[2],
            u64::MAX,
        )
        .unwrap()
        .unwrap();
        ChainStore::new(overflow_store)
            .set_finalized_number(u64::MAX)
            .unwrap();
        assert!(
            !overflow.fallback_eligible(&task).unwrap(),
            "rank multiplication cannot wrap"
        );
        let future = Arc::new(MemoryDb::new());
        let cohort = WorkerCohort::open_scheduled_with_fallback(
            future.clone(),
            members[..2].to_vec(),
            vec![crate::config::ProverWorkerEpoch {
                from_block: 20,
                workers: members.clone(),
            }],
            members[2],
            3,
        )
        .unwrap()
        .unwrap();
        ChainStore::new(future).set_finalized_number(100).unwrap();
        assert!(
            !cohort.fallback_eligible(&task).unwrap(),
            "future members cannot take historical ranges"
        );
        assert!(WorkerCohort::open_scheduled_with_fallback(
            Arc::new(MemoryDb::new()),
            vec![],
            vec![],
            members[0],
            3
        )
        .is_err());
    }

    #[tokio::test]
    async fn worker_fallback_proves_after_boundary_and_reopen_keeps_original_artifact() {
        let signers = [
            Arc::new(DilithiumSigner::generate()),
            Arc::new(DilithiumSigner::generate()),
        ];
        let mut members: Vec<_> = signers
            .iter()
            .map(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()))
            .collect();
        members.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let backup = members[1];
        let signer = signers
            .into_iter()
            .find(|s| Address::from_public_key(s.public_key(), s.sig_type().as_u8()) == backup)
            .unwrap();
        let store = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(store.clone());
        let hash = ShellHash::from([0; 32]);
        chain.set_canonical(10, &hash).unwrap();
        chain.set_finalized_number(12).unwrap();
        let task = ProofTask::new(
            *hash.as_bytes(),
            10,
            vec![
                shell_stark_prover::SigBatchEntry {
                    msg_hash: [7; 32],
                    pk_hash: [9; 32]
                };
                MIN_L1_STARK_TXS
            ],
        );
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        backlog.lock().push(task.clone());
        let cohort = WorkerCohort::open_scheduled_with_fallback(
            store.clone(),
            members.clone(),
            vec![],
            backup,
            3,
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        let handle = ProverService::new(
            backlog.clone(),
            ProofAmendmentStore::new(store.clone()),
            ProverConfig::default(),
            backup,
        )
        .with_worker_cohort(cohort)
        .with_signer(signer.clone())
        .with_amendment_sender(tx)
        .start();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !backlog.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .is_err());
        chain.set_finalized_number(13).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while backlog.lock().first_uncovered_block_for_layer(1, 10, 10) != Some(10) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // The native acceptance exercises the node's actual witness reseeding.
        backlog.lock().push(task.clone());
        let amendment = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(amendment.prover, backup);
        assert_eq!(amendment.block_hash, hash);
        shell_stark_prover::verify_sig_batch(&amendment.proof).unwrap();
        amendment.verify_prover_authentication().unwrap();
        handle.shutdown().await;
        let original = ProofAmendmentStore::new(store.clone())
            .get_amendment(&hash)
            .unwrap()
            .unwrap();
        let reopened_backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        reopened_backlog.lock().push(task);
        let cohort =
            WorkerCohort::open_scheduled_with_fallback(store.clone(), members, vec![], backup, 3)
                .unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        let reopened = ProverService::new(
            reopened_backlog,
            ProofAmendmentStore::new(store.clone()),
            ProverConfig::default(),
            backup,
        )
        .with_worker_cohort(cohort)
        .with_signer(signer)
        .with_amendment_sender(tx)
        .start();
        assert!(tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err());
        reopened.shutdown().await;
        assert_eq!(
            ProofAmendmentStore::new(store)
                .get_amendment(&hash)
                .unwrap()
                .unwrap(),
            original
        );
    }

    #[test]
    fn prover_config_defaults() {
        let cfg = ProverConfig::default();
        assert_eq!(cfg.max_concurrent_proofs, 1);
        assert_eq!(cfg.proving_priority, ProvingPriority::Sequential);
        assert_eq!(cfg.idle_poll_ms, 200);
    }

    #[test]
    fn prover_config_custom() {
        let cfg = ProverConfig {
            max_concurrent_proofs: 4,
            proving_priority: ProvingPriority::LatestFirst,
            idle_poll_ms: 50,
        };
        assert_eq!(cfg.max_concurrent_proofs, 4);
        assert_eq!(cfg.proving_priority, ProvingPriority::LatestFirst);
    }

    #[tokio::test]
    async fn service_starts_and_shuts_down_cleanly() {
        let (service, _backlog) = make_service();
        let (handle, mut event_rx) = observe_service(service);
        expect_service_event(&mut event_rx, ProverServiceTestEvent::Started).await;
        shutdown_cleanly(handle).await;
    }

    #[tokio::test]
    async fn service_drains_empty_backlog_without_panic() {
        let (service, _backlog) = make_service();
        let (handle, mut event_rx) = observe_service(service);
        expect_service_event(&mut event_rx, ProverServiceTestEvent::Started).await;
        expect_service_event(&mut event_rx, ProverServiceTestEvent::BacklogPolled).await;
        shutdown_cleanly(handle).await;
    }

    #[tokio::test]
    async fn dropping_handle_stops_service_loop() {
        let (service, _backlog) = make_service();
        let handle = service.start();
        let abort_handle = handle
            .join_handle
            .as_ref()
            .expect("started service must own its task")
            .abort_handle();

        drop(handle);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !abort_handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped handle must stop the service task");
    }

    #[tokio::test]
    async fn service_waits_when_isolated_l1_run_is_below_threshold() {
        // With the strict L1 threshold policy a task with fewer than
        // MIN_L1_STARK_TXS entries must NEVER be dispatched to the prover,
        // even when it sits alone at the queue tail with no contiguous
        // successor.  Generating an under-threshold proof wastes work and
        // produces a proof that settlement always rejects (n_sigs check).
        let (service, backlog) = make_service();
        {
            let mut b = backlog.lock();
            b.push(ProofTask::new([0u8; 32], 1, vec![]));
        }
        let (handle, mut event_rx) = observe_service(service);
        expect_service_event(&mut event_rx, ProverServiceTestEvent::Started).await;
        expect_service_event(&mut event_rx, ProverServiceTestEvent::BacklogPolled).await;
        shutdown_cleanly(handle).await;
        let b = backlog.lock();
        assert_eq!(b.len(), 1, "below-threshold run must remain in backlog");
        assert_eq!(b.total_completed(), 0, "no proof must be generated");
    }

    #[tokio::test]
    async fn service_waits_for_node_readiness_before_proving() {
        let (service, backlog) = make_service();
        let entry = shell_stark_prover::SigBatchEntry {
            msg_hash: [1u8; 32],
            pk_hash: [2u8; 32],
        };
        backlog.lock().push(ProofTask::with_sources(
            [3u8; 32],
            1,
            vec![entry; MIN_L1_STARK_TXS],
            1,
            vec![ShellHash::from([3u8; 32])],
            Some(1_000_000),
        ));
        let (readiness_tx, readiness_rx) = watch::channel(false);
        let (amendment_tx, mut amendment_rx) = mpsc::channel(1);
        let (handle, mut event_rx) = observe_service(
            service
                .with_readiness(readiness_rx)
                .with_amendment_sender(amendment_tx),
        );

        expect_service_event(&mut event_rx, ProverServiceTestEvent::Started).await;
        assert_eq!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty),
            "syncing prover must not poll the backlog"
        );
        assert_eq!(backlog.lock().len(), 1, "syncing prover must stay paused");

        readiness_tx.send(true).expect("service is listening");
        let amendment = tokio::time::timeout(Duration::from_secs(5), amendment_rx.recv())
            .await
            .expect("proof generation timed out")
            .expect("amendment channel closed");
        assert_eq!(amendment.block_number, 1);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn bounded_cpu_jobs_overlap_but_handoff_stays_in_source_order() {
        for priority in [ProvingPriority::Sequential, ProvingPriority::LatestFirst] {
            let (mut service, backlog) = make_service();
            service.config.max_concurrent_proofs = 2;
            service.config.proving_priority = priority;
            let metrics = Arc::new(Metrics::new().unwrap().with_proof_backlog(backlog.clone()));
            service = service.with_metrics(metrics.clone());
            for number in 1..=6u64 {
                backlog.lock().push(ProofTask::with_sources(
                    [number as u8; 32],
                    number,
                    vec![
                        shell_stark_prover::SigBatchEntry {
                            msg_hash: [number as u8; 32],
                            pk_hash: [9; 32],
                        };
                        MIN_L1_STARK_TXS / 2
                    ],
                    1,
                    vec![ShellHash::from([number as u8; 32])],
                    Some(1_000_000),
                ));
            }
            assert!(metrics.gather().contains("shell_stark_backlog_depth 6\n"));
            let gate = Arc::new((Mutex::new(0u64), parking_lot::Condvar::new()));
            let (events, mut observed) = mpsc::unbounded_channel();
            let worker_gate = gate.clone();
            service.test_proof_hook = Some(Arc::new(move |number, completed| {
                events.send((number, completed)).unwrap();
                if !completed {
                    let (mask, wake) = &*worker_gate;
                    let mut mask = mask.lock();
                    while *mask & (1 << number) == 0 {
                        assert!(
                            !wake
                                .wait_for(&mut mask, Duration::from_secs(10))
                                .timed_out(),
                            "proof gate timed out"
                        );
                    }
                }
            }));
            let (tx, mut rx) = mpsc::channel(1);
            let store = service.amendment_store.clone();
            let handle = service.with_amendment_sender(tx).start();
            let mut starts = vec![];
            for _ in 0..2 {
                let (number, completed) =
                    tokio::time::timeout(Duration::from_secs(5), observed.recv())
                        .await
                        .unwrap()
                        .unwrap();
                assert!(!completed);
                starts.push(number);
            }
            starts.sort();
            assert_eq!(
                starts,
                if priority == ProvingPriority::Sequential {
                    vec![2, 4]
                } else {
                    vec![4, 6]
                }
            );
            assert_eq!(
                backlog.lock().len(),
                if priority == ProvingPriority::Sequential {
                    2
                } else {
                    0
                },
                "reservation count follows the bounded scheduling window"
            );
            metrics.gather();
            assert_eq!(
                metrics.stark_backlog_depth.get(),
                backlog.lock().len() as i64
            );
            assert_eq!(metrics.stark_proof_duration_seconds.get_sample_count(), 0);
            *gate.0.lock() |= 1 << 4;
            gate.1.notify_all();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), observed.recv())
                    .await
                    .unwrap(),
                Some((4, true))
            );
            assert!(
                rx.try_recv().is_err(),
                "later proof must not overtake blocked predecessor"
            );
            assert!(store
                .get_amendment(&ShellHash::from([4; 32]))
                .unwrap()
                .is_none());
            *gate.0.lock() = u64::MAX;
            gate.1.notify_all();
            for end in [2u64, 4, 6] {
                let amendment = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(amendment.block_number, end);
                shell_stark_prover::verify_sig_batch(&amendment.proof).unwrap();
                amendment.verify_prover_authentication().unwrap();
                assert!(store
                    .get_amendment(&amendment.block_hash)
                    .unwrap()
                    .is_some());
                let mut b = backlog.lock();
                assert!(
                    b.contains_source(1, &amendment.block_hash),
                    "handoff retains reservation until consumer acknowledges"
                );
                b.complete_in_flight(1, end, &amendment.covered_hashes());
            }
            handle.shutdown().await;
            assert!(backlog.lock().is_empty());
            assert!(metrics.gather().contains("shell_stark_backlog_depth 0\n"));
            assert_eq!(metrics.stark_proof_duration_seconds.get_sample_count(), 3);
            assert!(metrics.stark_proof_duration_seconds.get_sample_sum() > 0.0);
            assert_eq!(metrics.stark_proof_failures.get(), 0);
        }
    }

    #[tokio::test]
    async fn latest_first_computes_newer_range_before_frontier_but_publishes_in_order() {
        let (mut service, backlog) = make_service();
        service.config.proving_priority = ProvingPriority::LatestFirst;
        for number in 1..=6u64 {
            backlog.lock().push(ProofTask::with_sources(
                [number as u8; 32],
                number,
                vec![
                    shell_stark_prover::SigBatchEntry {
                        msg_hash: [number as u8; 32],
                        pk_hash: [9; 32],
                    };
                    MIN_L1_STARK_TXS / 2
                ],
                1,
                vec![ShellHash::from([number as u8; 32])],
                Some(1_000_000),
            ));
        }
        let (events, mut observed) = mpsc::unbounded_channel();
        service.test_proof_hook = Some(Arc::new(move |number, completed| {
            let _ = events.send((number, completed));
        }));
        let (tx, mut rx) = mpsc::channel(3);
        let store = service.amendment_store.clone();
        let handle = service.with_amendment_sender(tx).start();
        let first = tokio::time::timeout(Duration::from_secs(5), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, (4, false), "newest eligible range must start first");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), observed.recv())
                .await
                .unwrap()
                .unwrap(),
            (4, true)
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), observed.recv())
                .await
                .unwrap()
                .unwrap(),
            (2, false)
        );
        for end in [2u64, 4, 6] {
            let amendment = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(amendment.block_number, end);
            shell_stark_prover::verify_sig_batch(&amendment.proof).unwrap();
            amendment.verify_prover_authentication().unwrap();
            assert!(store
                .get_amendment(&amendment.block_hash)
                .unwrap()
                .is_some());
            backlog
                .lock()
                .complete_in_flight(1, end, &amendment.covered_hashes());
        }
        handle.shutdown().await;
        assert!(backlog.lock().is_empty());
    }

    #[tokio::test]
    async fn default_limit_keeps_successor_queued_while_first_job_runs() {
        let (mut service, backlog) = make_service();
        for number in 1..=4u64 {
            backlog.lock().push(ProofTask::with_sources(
                [number as u8; 32],
                number,
                vec![
                    shell_stark_prover::SigBatchEntry {
                        msg_hash: [1; 32],
                        pk_hash: [2; 32]
                    };
                    MIN_L1_STARK_TXS / 2
                ],
                1,
                vec![ShellHash::from([number as u8; 32])],
                Some(1_000_000),
            ));
        }
        let gate = Arc::new((Mutex::new(false), parking_lot::Condvar::new()));
        let worker_gate = gate.clone();
        let (events, mut observed) = mpsc::unbounded_channel();
        service.test_proof_hook = Some(Arc::new(move |number, completed| {
            if !completed {
                events.send(number).unwrap();
                let mut open = worker_gate.0.lock();
                while !*open {
                    assert!(!worker_gate
                        .1
                        .wait_for(&mut open, Duration::from_secs(10))
                        .timed_out());
                }
            }
        }));
        let (tx, mut rx) = mpsc::channel(2);
        let handle = service.with_amendment_sender(tx).start();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), observed.recv())
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(backlog.lock().len(), 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), observed.recv())
                .await
                .is_err()
        );
        *gate.0.lock() = true;
        gate.1.notify_all();
        for end in [2, 4] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .block_number,
                end
            );
        }
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_drains_concurrent_proofs_without_waiting_for_handoff_capacity() {
        for priority in [ProvingPriority::Sequential, ProvingPriority::LatestFirst] {
            let (mut service, backlog) = make_service();
            service.config.max_concurrent_proofs = 2;
            service.config.proving_priority = priority;
            let last = if priority == ProvingPriority::LatestFirst {
                6
            } else {
                4
            };
            for number in 1..=last {
                backlog.lock().push(ProofTask::with_sources(
                    [number as u8; 32],
                    number,
                    vec![
                        shell_stark_prover::SigBatchEntry {
                            msg_hash: [1; 32],
                            pk_hash: [2; 32]
                        };
                        MIN_L1_STARK_TXS / 2
                    ],
                    1,
                    vec![ShellHash::from([number as u8; 32])],
                    Some(1_000_000),
                ));
            }
            let gate = Arc::new((Mutex::new(false), parking_lot::Condvar::new()));
            let worker_gate = gate.clone();
            let (events, mut observed) = mpsc::unbounded_channel();
            service.test_proof_hook = Some(Arc::new(move |number, completed| {
                if !completed {
                    events.send(number).unwrap();
                    let mut open = worker_gate.0.lock();
                    while !*open {
                        assert!(!worker_gate
                            .1
                            .wait_for(&mut open, Duration::from_secs(10))
                            .timed_out());
                    }
                }
            }));
            let (tx, _rx) = mpsc::channel(1);
            let store = service.amendment_store.clone();
            let handle = service.with_amendment_sender(tx).start();
            for _ in 0..2 {
                tokio::time::timeout(Duration::from_secs(5), observed.recv())
                    .await
                    .unwrap()
                    .unwrap();
            }
            // The receiver stays alive but never drains the bounded handoff channel.
            let stopping = tokio::spawn(handle.shutdown());
            tokio::task::yield_now().await;
            *gate.0.lock() = true;
            gate.1.notify_all();
            tokio::time::timeout(Duration::from_secs(5), stopping)
                .await
                .unwrap()
                .unwrap();
            for end in (2..=last as u8).step_by(2) {
                let hash = ShellHash::from([end; 32]);
                let bytes = store.get_amendment(&hash).unwrap().unwrap();
                let amendment = ProofAmendment::from_json(&bytes).unwrap();
                shell_stark_prover::verify_sig_batch(&amendment.proof).unwrap();
                assert!(
                    !backlog.lock().contains_source(1, &hash),
                    "unpublished job must release reservation"
                );
            }
        }
    }

    #[tokio::test]
    async fn service_stores_full_proof_only_at_range_end() {
        let (service, _backlog) = make_service();
        let first_hash = ShellHash::from([1u8; 32]);
        let end_hash = ShellHash::from([2u8; 32]);
        let task = ProofTask::with_sources(
            [2u8; 32],
            11,
            vec![shell_stark_prover::SigBatchEntry {
                msg_hash: [3u8; 32],
                pk_hash: [4u8; 32],
            }],
            2,
            vec![first_hash, end_hash],
            Some(10_000),
        );

        service.process_task(task, None).await;

        let pointer_bytes = service
            .amendment_store
            .get_amendment(&first_hash)
            .expect("pointer read")
            .expect("pointer stored");
        assert!(matches!(
            shell_stark_prover::StoredProofArtifact::from_json(&pointer_bytes).expect("pointer"),
            shell_stark_prover::StoredProofArtifact::Pointer(_)
        ));

        let full_bytes = service
            .amendment_store
            .get_amendment(&end_hash)
            .expect("amendment read")
            .expect("full amendment stored");
        let shell_stark_prover::StoredProofArtifact::Amendment(amendment) =
            shell_stark_prover::StoredProofArtifact::from_json(&full_bytes).expect("amendment")
        else {
            panic!("expected full amendment")
        };
        amendment
            .verify_prover_authentication()
            .expect("generated amendment is authenticated");
    }

    #[tokio::test]
    async fn failed_proof_attempts_are_observed_without_success_or_persistence() {
        let (service, _) = make_service();
        let metrics = Arc::new(Metrics::new().unwrap());
        let service = service.with_metrics(metrics.clone());
        let task = ProofTask::new([7; 32], 1, vec![]);
        let result = ProverService::<MemoryDb>::prove_timed(&[], Some(&metrics));
        assert!(result.is_err());
        assert!(!service.process_proof(task.clone(), Ok(result), None).await);
        assert_eq!(metrics.stark_proof_duration_seconds.get_sample_count(), 1);
        assert!(metrics.stark_proof_duration_seconds.get_sample_sum() > 0.0);
        assert_eq!(metrics.stark_proof_failures.get(), 1);

        let panicked = tokio::task::spawn_blocking(|| panic!("worker failure")).await;
        assert!(!service.process_proof(task, panicked, None).await);
        assert_eq!(metrics.stark_proof_failures.get(), 2);
        assert_eq!(metrics.stark_proofs_generated.get(), 0);
        assert!(service
            .amendment_store
            .get_amendment(&ShellHash::from([7; 32]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn proving_priority_variants() {
        assert_ne!(ProvingPriority::Sequential, ProvingPriority::LatestFirst);
    }

    // ── STARK boundary guard tests ────────────────────────────────────────────
    // Verify that L2StarkMode::Active cannot produce a recursive settlement
    // when the real recursive prover is unavailable (scaffold only).

    #[tokio::test]
    async fn active_l2_mode_does_not_store_recursive_proof() {
        // Build a service with L2StarkMode::Active and a real amendment store.
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        let db = Arc::new(MemoryDb::new());
        let amendment_store = ProofAmendmentStore::new(db.clone());
        let service = ProverService::new(
            backlog.clone(),
            amendment_store.clone(),
            ProverConfig::default(),
            Address::default(),
        )
        .with_l2_mode(crate::config::L2StarkMode::Active);

        let task = shell_stark_prover::L2ProverTask {
            job_id: ShellHash::from([0xAA; 32]),
            l1_source_hashes: vec![ShellHash::from([0x01; 32]), ShellHash::from([0x02; 32])],
            l1_batch_roots: vec![42u128, 84u128],
            start_block: 10,
            end_block: 11,
            original_size: Some(1024),
        };

        service.process_l2_task(&task).await;

        // The amendment store must remain empty — scaffold prover must not
        // store any success-shaped recursive proof.
        let stored = amendment_store
            .get_amendment(&task.job_id)
            .expect("store read must not fail");
        assert!(
            stored.is_none(),
            "L2StarkMode::Active with scaffold prover must NOT store a recursive proof"
        );
    }

    #[tokio::test]
    async fn scaffold_l2_mode_does_not_store_recursive_proof() {
        // L2StarkMode::Scaffold also must not produce recursive settlements —
        // it provides observability only.
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        let db = Arc::new(MemoryDb::new());
        let amendment_store = ProofAmendmentStore::new(db.clone());
        let service = ProverService::new(
            backlog,
            amendment_store.clone(),
            ProverConfig::default(),
            Address::default(),
        )
        .with_l2_mode(crate::config::L2StarkMode::Scaffold);

        let task = shell_stark_prover::L2ProverTask {
            job_id: ShellHash::from([0xBB; 32]),
            l1_source_hashes: vec![ShellHash::from([0x03; 32])],
            l1_batch_roots: vec![99u128],
            start_block: 5,
            end_block: 5,
            original_size: None,
        };

        service.process_l2_task(&task).await;

        let stored = amendment_store
            .get_amendment(&task.job_id)
            .expect("store read must not fail");
        assert!(
            stored.is_none(),
            "L2StarkMode::Scaffold must not store any recursive proof"
        );
    }
}
