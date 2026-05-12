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

use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use parking_lot::Mutex;
use shell_primitives::{Bytes, ShellHash};
use shell_stark_prover::{
    prove_sig_batch, L2ProverTask, ProofAmendment, ProofBacklog, ProofTask,
    DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS, PROOF_AMENDMENT_VERSION,
};
use shell_storage::{KvStore, ProofAmendmentStore};

use crate::config::L2StarkMode;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvingPriority {
    /// Prove blocks strictly in block-number order. Safest for chain consistency.
    Sequential,
    /// Prove the most recently arrived block first (LIFO). Lower latency for
    /// the chain head, but older blocks take longer.
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
    amendment_tx: Option<mpsc::UnboundedSender<ProofAmendment>>,
    config: ProverConfig,
    /// The node's own address, used as `prover` field in [`ProofAmendment`].
    prover_address: shell_primitives::Address,
    /// L2 STARK mode — controls whether recursive L2 proving is attempted.
    l2_mode: L2StarkMode,
    /// Shared drain frontier: updated after each drain_front so the seeder
    /// knows not to re-seed blocks before the gap that caused the drain.
    drain_frontier: Arc<std::sync::atomic::AtomicU64>,
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
            prover_address,
            l2_mode: L2StarkMode::Disabled,
            drain_frontier: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Set the L2 STARK mode for this service.
    pub fn with_l2_mode(mut self, mode: L2StarkMode) -> Self {
        self.l2_mode = mode;
        self
    }

    /// Send locally generated amendments back to the node event loop for P2P
    /// settlement ordering, reward queueing, and P2P broadcast after they are
    /// durably stored.
    pub fn with_amendment_sender(
        mut self,
        amendment_tx: mpsc::UnboundedSender<ProofAmendment>,
    ) -> Self {
        self.amendment_tx = Some(amendment_tx);
        self
    }

    /// Share the drain-frontier atomic with the node's event loop so the
    /// seeder can skip blocks below the last drained gap.
    pub fn with_drain_frontier(
        mut self,
        drain_frontier: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.drain_frontier = drain_frontier;
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

    async fn run_loop(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            "ProverService started (max_concurrent={})",
            self.config.max_concurrent_proofs
        );
        let idle_sleep = tokio::time::Duration::from_millis(self.config.idle_poll_ms);
        let mut last_stall_log = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(300))
            .unwrap_or_else(std::time::Instant::now);
        // Track consecutive stall observations at the same gap block before
        // draining. We require the same gap_at_block to appear on 2+ consecutive
        // 60-second stall checks (≥ 120 s) before treating it as permanent.
        let mut consecutive_gap: Option<(u64, u32)> = None; // (gap_block, count)

        loop {
            // Check shutdown signal.
            if *shutdown_rx.borrow() {
                info!("ProverService received shutdown signal, stopping");
                break;
            }

            // Pop next task from the backlog.
            let task = {
                let mut backlog = self.backlog.lock();
                if self.config.proving_priority == ProvingPriority::LatestFirst {
                    // For LatestFirst, drain and re-push all but the last task,
                    // effectively processing in reverse arrival order.
                    // For now, pop from front (sequential) — LatestFirst
                    // reordering requires a more complex priority queue and is
                    // deferred to a future optimization pass.
                    backlog.pop_contiguous_with_min_entries(
                        DEFAULT_MAX_L1_RANGE_SOURCES,
                        MIN_L1_STARK_TXS,
                    )
                } else {
                    backlog.pop_contiguous_with_min_entries(
                        DEFAULT_MAX_L1_RANGE_SOURCES,
                        MIN_L1_STARK_TXS,
                    )
                }
            };

            match task {
                None => {
                    // If the backlog is non-empty but pop returns None, log a stall
                    // warning at most once per 60 seconds so it doesn't spam the log.
                    {
                        let mut backlog = self.backlog.lock();
                        let depth = backlog.len();
                        if depth > 0 && last_stall_log.elapsed().as_secs() >= 60 {
                            last_stall_log = std::time::Instant::now();
                            let first_block = backlog.min_block_number_for_layer(1).unwrap_or(0);
                            let last_block = backlog.max_block_number_for_layer(1).unwrap_or(0);
                            let stall_info = backlog
                                .diagnose_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
                            match stall_info {
                                Some((entries, Some(gap), take)) => {
                                    warn!(
                                        depth,
                                        first_block,
                                        last_block,
                                        entries,
                                        gap_at_block = gap,
                                        contiguous_take = take,
                                        "STARK prover stalled: gap in backlog prevents reaching min_entries threshold"
                                    );
                                    // Guard against transient gaps: require the same
                                    // gap_at_block to appear on 2 consecutive stall
                                    // checks (≥ 120 s) before treating it as permanent.
                                    let count = match consecutive_gap {
                                        Some((prev_gap, n)) if prev_gap == gap as u64 => {
                                            consecutive_gap = Some((gap as u64, n + 1));
                                            n + 1
                                        }
                                        _ => {
                                            consecutive_gap = Some((gap as u64, 1));
                                            1
                                        }
                                    };
                                    if count >= 2 {
                                        // The gap block's witness is permanently missing (pruned).
                                        // The pre-gap range can never accumulate enough entries.
                                        // Drain those tasks so the prover can advance past the gap.
                                        warn!(
                                            draining = take,
                                            entries_lost = entries,
                                            gap_at_block = gap,
                                            consecutive_checks = count,
                                            "STARK prover: draining {} stuck tasks before confirmed permanent gap at block {}",
                                            take, gap
                                        );
                                        backlog.drain_front(take);
                                        consecutive_gap = None;
                                        // Advance the drain frontier so the seeder
                                        // won't re-insert blocks below this gap on
                                        // the very next seeding pass.
                                        let prev = self
                                            .drain_frontier
                                            .fetch_max(gap, std::sync::atomic::Ordering::Release);
                                        if gap > prev {
                                            info!(
                                                gap_at_block = gap,
                                                "STARK drain frontier advanced"
                                            );
                                        }
                                    } else {
                                        info!(
                                            gap_at_block = gap,
                                            consecutive_checks = count,
                                            "STARK prover: gap observed, waiting for confirmation before drain"
                                        );
                                    }
                                }
                                Some((entries, None, take)) => {
                                    warn!(
                                        depth,
                                        first_block,
                                        last_block,
                                        entries,
                                        contiguous_take = take,
                                        "STARK prover stalled: not enough entries in full backlog range (all 0-tx blocks?)"
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
                Some(task) => {
                    self.process_task(task).await;
                }
            }
        }

        info!("ProverService stopped");
    }

    async fn process_task(&self, task: ProofTask) {
        let block_hash = task.block_hash;
        let block_number = task.block_number;
        debug!(
            "ProverService: proving range ending at block #{} ({} entries, {} source hashes)",
            block_number,
            task.entries.len(),
            task.source_hashes.len()
        );

        // Destructure task so entries can be moved into spawn_blocking while the
        // remaining fields remain available after the await point.
        let ProofTask {
            entries,
            source_hashes,
            layer,
            original_size,
            ..
        } = task;

        // Defense-in-depth: the backlog should never dispatch an all-empty L1
        // task (pop_contiguous_with_min_entries returns None for zero entries),
        // but guard here too so we never call prove_sig_batch with an empty
        // batch. This avoids a panic/error cycle if the guard is ever bypassed.
        if layer == 1 && entries.is_empty() {
            warn!(
                "ProverService: skipping empty L1 task for block #{block_number} \
                 ({} source hashes) — waiting for non-empty successor",
                source_hashes.len()
            );
            return;
        }

        // Run the CPU-intensive proof generation on a blocking thread so the
        // tokio executor is not starved. Note: once started, this blocking job
        // is not hard-cancelable via JoinHandle::abort.
        let proof_result = tokio::task::spawn_blocking(move || prove_sig_batch(&entries)).await;

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
                    prover_signature: Bytes::new(),
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
                if amendment.compressed_size.is_none() {
                    amendment.compressed_size = Some(amendment.size_bytes() as u64);
                }

                // Serialize and persist the amendment artifacts.
                match amendment.storage_artifacts() {
                    Err(e) => {
                        error!(
                            "ProverService: failed to serialize amendment artifacts for block #{block_number}: {e}"
                        );
                    }
                    Ok(artifacts) => {
                        let mut stored = 0usize;
                        for (source_hash, artifact) in artifacts {
                            match self.amendment_store.put_amendment(&source_hash, &artifact) {
                                Ok(()) => {
                                    stored += 1;
                                }
                                Err(e) => {
                                    error!(
                                        "ProverService: failed to store amendment for source {source_hash}: {e}"
                                    );
                                }
                            }
                        }
                        if stored > 0 {
                            info!(
                                "ProverService: proof amendment stored for range ending at block #{block_number} ({stored} source hashes)"
                            );
                            if let Some(tx) = &self.amendment_tx {
                                if tx.send(amendment).is_err() {
                                    warn!(
                                        "ProverService: proof amendment broadcast channel closed for block #{block_number}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle an L2 recursive aggregation task.
    ///
    /// When `L2StarkMode::Active` is configured (and the `recursive` cargo
    /// feature is enabled), this would call a real recursive prover.
    ///
    /// Currently all L2 tasks are deferred: the job remains in `L2JobStore`
    /// with `Ready` status and a clear log explains why no proof was generated.
    #[allow(dead_code)] // scaffolded for future L2 proving
    pub(crate) async fn process_l2_task(&self, task: &L2ProverTask) {
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
    use shell_primitives::Address;
    use shell_stark_prover::{ProofBacklog, ProofTask};
    use shell_storage::{MemoryDb, ProofAmendmentStore};

    fn make_service() -> (ProverService<MemoryDb>, Arc<Mutex<ProofBacklog>>) {
        let backlog = Arc::new(Mutex::new(ProofBacklog::new()));
        let db = Arc::new(MemoryDb::new());
        let amendment_store = ProofAmendmentStore::new(db);
        let config = ProverConfig::default();
        let service =
            ProverService::new(backlog.clone(), amendment_store, config, Address::default());
        (service, backlog)
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
        let handle = service.start();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn service_drains_empty_backlog_without_panic() {
        let (service, _backlog) = make_service();
        let handle = service.start();
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn dropping_handle_stops_service_loop() {
        let (service, backlog) = make_service();
        let handle = service.start();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        drop(handle);

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        {
            let mut backlog = backlog.lock();
            backlog.push(ProofTask::new([9u8; 32], 9, vec![]));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        let backlog = backlog.lock();
        assert_eq!(
            backlog.len(),
            1,
            "dropped handle must stop the service task"
        );
        assert_eq!(
            backlog.total_completed(),
            0,
            "dropped handle must not leave the async prover loop running"
        );
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
        let handle = service.start();
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        handle.shutdown().await;
        let b = backlog.lock();
        assert_eq!(b.len(), 1, "below-threshold run must remain in backlog");
        assert_eq!(b.total_completed(), 0, "no proof must be generated");
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

        service.process_task(task).await;

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
        assert!(matches!(
            shell_stark_prover::StoredProofArtifact::from_json(&full_bytes).expect("amendment"),
            shell_stark_prover::StoredProofArtifact::Amendment(_)
        ));
    }

    #[test]
    fn proving_priority_variants() {
        assert_ne!(ProvingPriority::Sequential, ProvingPriority::LatestFirst);
    }
}
