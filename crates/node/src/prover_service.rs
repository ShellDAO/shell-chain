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
use shell_primitives::ShellHash;
use shell_stark_prover::{
    prove_sig_batch, L1StallDiagnosis, L2ProverTask, ProofAmendment, ProofBacklog, ProofTask,
    DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS, PROOF_AMENDMENT_VERSION,
};
use shell_storage::{KvStore, ProofAmendmentStore};

use crate::{config::L2StarkMode, metrics::Metrics};

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
        prove_sig_batch(entries)
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
            if *shutdown_rx.borrow() && jobs.is_empty() {
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
                && jobs.len() + reserved.len() < capacity
                && !*shutdown_rx.borrow()
                && self.readiness_rx.as_ref().is_none_or(|rx| *rx.borrow())
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
