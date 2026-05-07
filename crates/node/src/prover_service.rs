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

use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use parking_lot::Mutex;
use shell_primitives::{Bytes, ShellHash};
use shell_stark_prover::{
    prove_sig_batch, ProofAmendment, ProofBacklog, ProofTask, DEFAULT_MAX_L1_RANGE_SOURCES,
    MIN_L1_STARK_TXS, PROOF_AMENDMENT_VERSION,
};
use shell_storage::{KvStore, ProofAmendmentStore};

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
/// Dropping this handle does **not** stop the service — call [`shutdown`]
/// explicitly for graceful termination.
///
/// [`shutdown`]: ProverServiceHandle::shutdown
pub struct ProverServiceHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl ProverServiceHandle {
    /// Signal the prover service to stop and wait for it to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join_handle.await;
    }
}

// ── ProverService ─────────────────────────────────────────────────────────────

/// Background STARK prover service.
pub struct ProverService<S: KvStore + Send + Sync + 'static> {
    backlog: Arc<Mutex<ProofBacklog>>,
    amendment_store: ProofAmendmentStore<S>,
    settlement_queue: Option<Arc<Mutex<Vec<ProofAmendment>>>>,
    amendment_tx: Option<mpsc::UnboundedSender<ProofAmendment>>,
    config: ProverConfig,
    /// The node's own address, used as `prover` field in [`ProofAmendment`].
    prover_address: shell_primitives::Address,
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
            settlement_queue: None,
            amendment_tx: None,
            config,
            prover_address,
        }
    }

    /// Queue locally generated amendments for settlement by validator-prover
    /// nodes. Pure prover nodes may omit this and only persist/broadcast proofs.
    pub fn with_settlement_queue(
        mut self,
        settlement_queue: Arc<Mutex<Vec<ProofAmendment>>>,
    ) -> Self {
        self.settlement_queue = Some(settlement_queue);
        self
    }

    /// Send locally generated amendments back to the node event loop for P2P
    /// broadcast after they are durably stored.
    pub fn with_amendment_sender(
        mut self,
        amendment_tx: mpsc::UnboundedSender<ProofAmendment>,
    ) -> Self {
        self.amendment_tx = Some(amendment_tx);
        self
    }

    /// Spawn the prover service as a background tokio task.
    ///
    /// Returns a [`ProverServiceHandle`] for graceful shutdown.
    pub fn start(self) -> ProverServiceHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join_handle = tokio::spawn(self.run_loop(shutdown_rx));
        ProverServiceHandle {
            shutdown_tx,
            join_handle,
        }
    }

    async fn run_loop(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            "ProverService started (max_concurrent={})",
            self.config.max_concurrent_proofs
        );
        let idle_sleep = tokio::time::Duration::from_millis(self.config.idle_poll_ms);

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
                    // Backlog empty — sleep briefly before polling again.
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
        let ProofTask { entries, source_hashes, layer, original_size, .. } = task;

        // Run the CPU-intensive proof generation on a blocking thread so the
        // tokio executor is not starved.
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
                            if let Some(queue) = &self.settlement_queue {
                                queue.lock().push(amendment.clone());
                                info!(
                                    "ProverService: proof amendment queued for STARK reward settlement at block #{block_number}"
                                );
                            }
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
    async fn service_waits_for_l1_minimum_entries() {
        let (service, backlog) = make_service();
        {
            let mut b = backlog.lock();
            b.push(ProofTask::new([0u8; 32], 1, vec![]));
        }
        let handle = service.start();
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        handle.shutdown().await;
        let b = backlog.lock();
        assert_eq!(b.len(), 1);
        assert_eq!(b.total_completed(), 0);
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
