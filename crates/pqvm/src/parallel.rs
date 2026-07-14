//! Parallel PQVM PoC scheduling primitives.
//!
//! This module intentionally stays additive: it builds conflict graphs and
//! execution waves from transaction read/write sets without changing the
//! production executor path. Callers can opt in via [`ParallelPqvmConfig`]
//! and either inspect the plan or execute wave-local work with rayon.

use rayon::prelude::*;
use shell_core::SignedTransaction;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use crate::rwset::{ReadWriteSetExtractor, TxAccessPath, TxReadWriteSet};

/// Feature flag and scheduler knobs for the parallel-PQVM PoC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelPqvmConfig {
    /// Enables conflict-graph scheduling.
    pub enabled: bool,
    /// Maximum worker threads used for parallelizable waves.
    pub max_workers: usize,
    /// Fall back to a single serial wave when any rw-set is incomplete.
    pub fallback_on_incomplete: bool,
}

impl Default for ParallelPqvmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_workers: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            fallback_on_incomplete: true,
        }
    }
}

/// Why two transactions are considered conflicting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictReason {
    ReadWrite,
    WriteWrite,
    Incomplete,
}

/// A single conflict edge between two transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxConflict {
    pub left: usize,
    pub right: usize,
    pub reason: ConflictReason,
    pub shared_paths: Vec<TxAccessPath>,
}

/// Pairwise conflict graph over a transaction batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxConflictGraph {
    pub rwsets: Vec<TxReadWriteSet>,
    pub conflicts: Vec<TxConflict>,
}

impl TxConflictGraph {
    pub fn build(rwsets: Vec<TxReadWriteSet>) -> Self {
        let mut conflicts = Vec::new();

        for left in 0..rwsets.len() {
            for right in (left.saturating_add(1))..rwsets.len() {
                if let Some(conflict) = detect_conflict(
                    left,
                    right,
                    rwsets
                        .get(left)
                        .unwrap_or_else(|| unreachable!("left < rwsets.len()")),
                    rwsets
                        .get(right)
                        .unwrap_or_else(|| unreachable!("right < rwsets.len()")),
                ) {
                    conflicts.push(conflict);
                }
            }
        }

        Self { rwsets, conflicts }
    }

    pub fn has_conflict(&self, left: usize, right: usize) -> bool {
        self.conflicts.iter().any(|edge| {
            (edge.left == left && edge.right == right) || (edge.left == right && edge.right == left)
        })
    }
}

/// One execution wave containing mutually non-conflicting transaction indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWave {
    pub tx_indices: Vec<usize>,
    pub parallelizable: bool,
}

/// Greedy execution plan built from the conflict graph.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParallelExecutionPlan {
    pub waves: Vec<ExecutionWave>,
    pub fallback_serial: bool,
}

/// Conflict-aware scheduler for the parallel-PQVM PoC.
#[derive(Debug, Clone)]
pub struct ParallelScheduler {
    config: ParallelPqvmConfig,
    worker_pool: Arc<OnceLock<rayon::ThreadPool>>,
}

impl ParallelScheduler {
    pub fn new(config: ParallelPqvmConfig) -> Self {
        Self {
            config,
            worker_pool: Arc::new(OnceLock::new()),
        }
    }

    pub fn config(&self) -> &ParallelPqvmConfig {
        &self.config
    }

    pub fn build_graph<E: ReadWriteSetExtractor>(
        &self,
        txs: &[SignedTransaction],
        extractor: &E,
    ) -> TxConflictGraph {
        let rwsets = txs.iter().map(|tx| extractor.extract(tx)).collect();
        TxConflictGraph::build(rwsets)
    }

    pub fn plan<E: ReadWriteSetExtractor>(
        &self,
        txs: &[SignedTransaction],
        extractor: &E,
    ) -> (TxConflictGraph, ParallelExecutionPlan) {
        let graph = self.build_graph(txs, extractor);
        let plan = self.plan_from_graph(&graph);
        (graph, plan)
    }

    /// Like [`plan`], but also returns a [`ConflictMetric`] for the batch.
    pub fn plan_with_metrics<E: ReadWriteSetExtractor>(
        &self,
        txs: &[SignedTransaction],
        extractor: &E,
    ) -> (TxConflictGraph, ParallelExecutionPlan, ConflictMetric) {
        let graph = self.build_graph(txs, extractor);
        let mut metric = ConflictMetric::from(&graph);
        metric.finalize(txs.len());
        let plan = self.plan_from_graph(&graph);
        (graph, plan, metric)
    }

    pub fn plan_from_graph(&self, graph: &TxConflictGraph) -> ParallelExecutionPlan {
        if graph.rwsets.is_empty() {
            return ParallelExecutionPlan::default();
        }

        if !self.config.enabled {
            return serial_plan(graph.rwsets.len());
        }

        if self.config.fallback_on_incomplete && graph.rwsets.iter().any(|rwset| !rwset.complete) {
            return ParallelExecutionPlan {
                waves: vec![ExecutionWave {
                    tx_indices: (0..graph.rwsets.len()).collect(),
                    parallelizable: false,
                }],
                fallback_serial: true,
            };
        }

        let mut conflicts_by_tx = vec![HashSet::new(); graph.rwsets.len()];
        for conflict in &graph.conflicts {
            if conflict.left < conflicts_by_tx.len() && conflict.right < conflicts_by_tx.len() {
                conflicts_by_tx[conflict.left].insert(conflict.right);
                conflicts_by_tx[conflict.right].insert(conflict.left);
            }
        }

        let mut waves: Vec<ExecutionWave> = Vec::new();
        for (tx_index, tx_conflicts) in conflicts_by_tx.iter().enumerate() {
            let can_join_last_wave = waves
                .last()
                .map(|wave| {
                    wave.tx_indices
                        .iter()
                        .all(|existing| !tx_conflicts.contains(existing))
                })
                .unwrap_or(false);

            if can_join_last_wave {
                if let Some(wave) = waves.last_mut() {
                    wave.tx_indices.push(tx_index);
                }
            } else {
                waves.push(ExecutionWave {
                    tx_indices: vec![tx_index],
                    parallelizable: false,
                });
            }
        }

        for wave in &mut waves {
            wave.parallelizable = wave.tx_indices.len() > 1;
        }

        ParallelExecutionPlan {
            waves,
            fallback_serial: false,
        }
    }

    pub fn execute<T, E, F>(
        &self,
        txs: &[SignedTransaction],
        plan: &ParallelExecutionPlan,
        execute_tx: F,
    ) -> Result<Vec<T>, E>
    where
        T: Send,
        E: Send,
        F: Fn(&SignedTransaction) -> Result<T, E> + Sync + Send,
    {
        // This PoC helper assumes `execute_tx` is side-effect free with respect to
        // shared mutable state. Parallel waves may evaluate jobs concurrently and
        // only preserve deterministic ordering in the collected return values.
        let mut outputs = Vec::new();
        for wave in &plan.waves {
            if wave.parallelizable {
                let wave_results = self.worker_pool().install(|| {
                    wave.tx_indices
                        .par_iter()
                        .map(|index| {
                            execute_tx(
                                txs.get(*index)
                                    .unwrap_or_else(|| unreachable!("index < txs.len()")),
                            )
                        })
                        .collect::<Vec<_>>()
                });
                for result in wave_results {
                    outputs.push(result?);
                }
            } else {
                for index in &wave.tx_indices {
                    outputs.push(execute_tx(
                        txs.get(*index)
                            .unwrap_or_else(|| unreachable!("index < txs.len()")),
                    )?);
                }
            }
        }

        Ok(outputs)
    }

    fn worker_pool(&self) -> &rayon::ThreadPool {
        self.worker_pool.get_or_init(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.config.max_workers.max(1))
                .build()
                .unwrap_or_else(|_| unreachable!("thread pool creation should succeed"))
        })
    }
}

/// Tracks conflict statistics over a single scheduling run.
///
/// Use [`ConflictMetric::record_conflict`] to accumulate individual conflict
/// events, then call [`ConflictMetric::finalize`] with the total transaction
/// count to compute `conflict_ratio`.
#[derive(Debug, Clone, Default)]
pub struct ConflictMetric {
    /// Total number of conflict edges detected.
    pub total_conflicts: usize,
    /// Cumulative count of transactions flagged for re-execution due to conflicts.
    pub reexecuted_txs: usize,
    /// Fraction of detected conflicts relative to total transactions (0.0 – 1.0+).
    pub conflict_ratio: f64,
}

impl ConflictMetric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one conflict event involving `reexecuted` additional transactions.
    pub fn record_conflict(&mut self, reexecuted: usize) {
        self.total_conflicts = self.total_conflicts.saturating_add(1);
        self.reexecuted_txs = self.reexecuted_txs.saturating_add(reexecuted);
    }

    /// Compute `conflict_ratio` given `total_txs` processed in the batch.
    pub fn finalize(&mut self, total_txs: usize) {
        self.conflict_ratio = if total_txs == 0 {
            0.0
        } else {
            self.total_conflicts as f64 / total_txs as f64
        };
    }

    /// Return a human-readable summary of the conflict statistics.
    pub fn summary(&self) -> String {
        format!(
            "ConflictMetric {{ total_conflicts: {}, reexecuted_txs: {}, conflict_ratio: {:.4} }}",
            self.total_conflicts, self.reexecuted_txs, self.conflict_ratio
        )
    }
}

impl From<&TxConflictGraph> for ConflictMetric {
    /// Derive metrics directly from an already-built conflict graph.
    fn from(graph: &TxConflictGraph) -> Self {
        let mut metric = ConflictMetric::new();
        for _ in &graph.conflicts {
            metric.record_conflict(1);
        }
        metric.finalize(graph.rwsets.len());
        metric
    }
}

fn serial_plan(len: usize) -> ParallelExecutionPlan {
    ParallelExecutionPlan {
        waves: vec![ExecutionWave {
            tx_indices: (0..len).collect(),
            parallelizable: false,
        }],
        fallback_serial: true,
    }
}

fn detect_conflict(
    left_index: usize,
    right_index: usize,
    left: &TxReadWriteSet,
    right: &TxReadWriteSet,
) -> Option<TxConflict> {
    let mut shared_paths = Vec::new();

    for left_path in &left.writes {
        for right_path in right.reads.iter().chain(right.writes.iter()) {
            if access_paths_conflict(left_path, right_path) {
                push_unique(&mut shared_paths, left_path.clone());
            }
        }
    }

    for right_path in &right.writes {
        for left_path in left.reads.iter().chain(left.writes.iter()) {
            if access_paths_conflict(right_path, left_path) {
                push_unique(&mut shared_paths, right_path.clone());
            }
        }
    }

    let reason = if !shared_paths.is_empty() {
        if !left.complete || !right.complete {
            ConflictReason::Incomplete
        } else if left.writes.iter().any(|left_path| {
            right
                .writes
                .iter()
                .any(|right_path| access_paths_conflict(left_path, right_path))
        }) {
            ConflictReason::WriteWrite
        } else {
            ConflictReason::ReadWrite
        }
    } else if !left.complete || !right.complete {
        return Some(TxConflict {
            left: left_index,
            right: right_index,
            reason: ConflictReason::Incomplete,
            shared_paths: vec![TxAccessPath::GlobalState],
        });
    } else {
        return None;
    };

    Some(TxConflict {
        left: left_index,
        right: right_index,
        reason,
        shared_paths,
    })
}

fn push_unique(paths: &mut Vec<TxAccessPath>, candidate: TxAccessPath) {
    if !paths.contains(&candidate) {
        paths.push(candidate);
    }
}

fn access_paths_conflict(left: &TxAccessPath, right: &TxAccessPath) -> bool {
    use TxAccessPath::{
        ContractStorageAny, Erc20Balance, GlobalState, NativeBalance, NativeNonce, PqPublicKey,
        ValidationCode, ValidatorSet,
    };

    if matches!(left, GlobalState) || matches!(right, GlobalState) {
        return true;
    }

    match (left, right) {
        (NativeBalance(a), NativeBalance(b))
        | (NativeNonce(a), NativeNonce(b))
        | (PqPublicKey(a), PqPublicKey(b))
        | (ValidationCode(a), ValidationCode(b)) => a == b,
        (ValidatorSet, ValidatorSet) => true,
        (
            Erc20Balance {
                token: left_token,
                owner: left_owner,
            },
            Erc20Balance {
                token: right_token,
                owner: right_owner,
            },
        ) => left_token == right_token && left_owner == right_owner,
        (ContractStorageAny(left_addr), ContractStorageAny(right_addr)) => left_addr == right_addr,
        (ContractStorageAny(addr), Erc20Balance { token, .. })
        | (Erc20Balance { token, .. }, ContractStorageAny(addr)) => addr == token,
        _ => false,
    }
}

#[cfg(test)]
mod parallel_validation {
    use super::*;
    use shell_core::{SignedTransaction, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};

    use crate::rwset::{HeuristicRwSetExtractor, TxAccessPath, TxReadWriteSet};

    fn make_tx(to: Address, nonce: u64) -> SignedTransaction {
        let from = Address::from([0x20 + nonce as u8; 20]);
        let tx = Transaction {
            chain_id: 424242,
            nonce,
            to: Some(to),
            value: U256::from(nonce),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        SignedTransaction::new(
            from,
            tx,
            PQSignature::new(SignatureType::Dilithium3, vec![0x77; 32]),
        )
    }

    /// Test 1: sequential vs parallel produces identical read/write sets.
    #[test]
    fn sequential_and_parallel_rwsets_are_identical() {
        let txs = vec![
            make_tx(Address::from([0x31; 20]), 1),
            make_tx(Address::from([0x32; 20]), 2),
            make_tx(Address::from([0x33; 20]), 3),
        ];
        let extractor = HeuristicRwSetExtractor;

        // Sequential: extract rwsets one by one.
        let sequential_rwsets: Vec<TxReadWriteSet> =
            txs.iter().map(|tx| extractor.extract(tx)).collect();

        // Parallel: build graph, which extracts rwsets internally.
        let scheduler_parallel = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            ..ParallelPqvmConfig::default()
        });
        let graph = scheduler_parallel.build_graph(&txs, &extractor);

        assert_eq!(
            sequential_rwsets.len(),
            graph.rwsets.len(),
            "rwset count must match"
        );
        for (i, (seq, par)) in sequential_rwsets
            .iter()
            .zip(graph.rwsets.iter())
            .enumerate()
        {
            assert_eq!(seq.reads, par.reads, "reads differ at tx {i}");
            assert_eq!(seq.writes, par.writes, "writes differ at tx {i}");
            assert_eq!(seq.complete, par.complete, "completeness differs at tx {i}");
        }
    }

    /// Test 2: conflict detection correctly identifies overlapping storage slots.
    #[test]
    fn conflict_detection_identifies_overlapping_storage_slots() {
        let shared_addr = Address::from([0xAA; 20]);

        // Both txs write to the same native balance (shared_addr is recipient).
        let tx_a = make_tx(shared_addr, 1);
        let tx_b = make_tx(shared_addr, 2);
        let graph = TxConflictGraph::build(vec![
            HeuristicRwSetExtractor.extract(&tx_a),
            HeuristicRwSetExtractor.extract(&tx_b),
        ]);

        assert!(
            !graph.conflicts.is_empty(),
            "overlapping recipient should produce a conflict"
        );
        assert!(
            graph.has_conflict(0, 1),
            "tx 0 and tx 1 must be detected as conflicting"
        );

        // Two txs targeting different addresses should not conflict.
        let tx_c = make_tx(Address::from([0xBB; 20]), 3);
        let tx_d = make_tx(Address::from([0xCC; 20]), 4);
        let clean_graph = TxConflictGraph::build(vec![
            HeuristicRwSetExtractor.extract(&tx_c),
            HeuristicRwSetExtractor.extract(&tx_d),
        ]);
        assert!(
            clean_graph.conflicts.is_empty(),
            "non-overlapping txs should have no conflicts"
        );
    }

    /// Test 3: empty tx batch produces empty rwset.
    #[test]
    fn empty_batch_produces_empty_rwset() {
        let graph = TxConflictGraph::build(vec![]);
        assert!(graph.rwsets.is_empty(), "rwsets should be empty");
        assert!(graph.conflicts.is_empty(), "conflicts should be empty");

        let scheduler = ParallelScheduler::new(ParallelPqvmConfig::default());
        let plan = scheduler.plan_from_graph(&graph);
        assert!(
            plan.waves.is_empty(),
            "plan should have no waves for empty batch"
        );
    }

    /// Test 4: single tx produces correct read/write set entries.
    #[test]
    fn single_tx_produces_correct_rwset_entries() {
        let recipient = Address::from([0x55; 20]);
        let tx = make_tx(recipient, 7);
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.complete, "simple native transfer must be complete");
        assert!(
            rwset.reads.contains(&TxAccessPath::NativeBalance(tx.from)),
            "must read sender balance"
        );
        assert!(
            rwset.reads.contains(&TxAccessPath::NativeNonce(tx.from)),
            "must read sender nonce"
        );
        assert!(
            rwset.writes.contains(&TxAccessPath::NativeBalance(tx.from)),
            "must write sender balance"
        );
        assert!(
            rwset.writes.contains(&TxAccessPath::NativeNonce(tx.from)),
            "must write sender nonce"
        );
        assert!(
            rwset
                .reads
                .contains(&TxAccessPath::NativeBalance(recipient)),
            "must read recipient balance"
        );
        assert!(
            rwset
                .writes
                .contains(&TxAccessPath::NativeBalance(recipient)),
            "must write recipient balance"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{SignedTransaction, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};

    use crate::rwset::{HeuristicRwSetExtractor, TxAccessPath};

    fn signed_tx(to: Address, value: u64, data: Vec<u8>) -> SignedTransaction {
        let from = Address::from([0x10 + value as u8; 20]);
        let tx = Transaction {
            chain_id: 424242,
            nonce: value,
            to: Some(to),
            value: U256::from(value),
            data: Bytes::from(data),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        SignedTransaction::new(
            from,
            tx,
            PQSignature::new(SignatureType::Dilithium3, vec![0x77; 32]),
        )
    }

    #[test]
    fn graph_detects_conflicting_native_balance_writes() {
        let shared = Address::from([0x22; 20]);
        let txs = vec![
            signed_tx(shared, 1, Vec::new()),
            signed_tx(shared, 2, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            ..ParallelPqvmConfig::default()
        });
        let graph = scheduler.build_graph(&txs, &HeuristicRwSetExtractor);

        assert_eq!(graph.conflicts.len(), 1);
        assert!(graph.conflicts[0]
            .shared_paths
            .contains(&TxAccessPath::NativeBalance(shared)));
    }

    #[test]
    fn scheduler_batches_independent_transfers_into_one_wave() {
        let txs = vec![
            signed_tx(Address::from([0x31; 20]), 1, Vec::new()),
            signed_tx(Address::from([0x32; 20]), 2, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            ..ParallelPqvmConfig::default()
        });
        let (_, plan) = scheduler.plan(&txs, &HeuristicRwSetExtractor);

        assert_eq!(plan.waves.len(), 1);
        assert_eq!(plan.waves[0].tx_indices, vec![0, 1]);
        assert!(plan.waves[0].parallelizable);
    }

    #[test]
    fn scheduler_falls_back_to_serial_when_incomplete_sets_exist() {
        let from = Address::from([0x44; 20]);
        let tx = Transaction {
            chain_id: 424242,
            nonce: 1,
            to: None,
            value: U256::ZERO,
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let txs = vec![SignedTransaction::new(
            from,
            tx,
            PQSignature::new(SignatureType::Dilithium3, vec![0x77; 32]),
        )];

        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            fallback_on_incomplete: true,
            ..ParallelPqvmConfig::default()
        });
        let (_, plan) = scheduler.plan(&txs, &HeuristicRwSetExtractor);

        assert!(plan.fallback_serial);
        assert_eq!(plan.waves.len(), 1);
        assert!(!plan.waves[0].parallelizable);
    }

    #[test]
    fn execute_preserves_wave_local_order() {
        let txs = vec![
            signed_tx(Address::from([0x51; 20]), 1, Vec::new()),
            signed_tx(Address::from([0x52; 20]), 2, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            max_workers: 2,
            ..ParallelPqvmConfig::default()
        });
        let (_, plan) = scheduler.plan(&txs, &HeuristicRwSetExtractor);
        let outputs = scheduler
            .execute(&txs, &plan, |tx| Ok::<u64, ()>(tx.tx.nonce))
            .unwrap();

        assert_eq!(outputs, vec![1, 2]);
    }

    #[test]
    fn execute_lazily_reuses_worker_pool() {
        let txs = vec![
            signed_tx(Address::from([0x61; 20]), 1, Vec::new()),
            signed_tx(Address::from([0x62; 20]), 2, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            max_workers: 2,
            ..ParallelPqvmConfig::default()
        });

        let serial_plan = ParallelExecutionPlan {
            waves: vec![ExecutionWave {
                tx_indices: vec![0],
                parallelizable: false,
            }],
            fallback_serial: true,
        };
        scheduler
            .execute(&txs, &serial_plan, |_| Ok::<(), ()>(()))
            .unwrap();
        assert!(scheduler.worker_pool.get().is_none());

        let parallel_plan = ParallelExecutionPlan {
            waves: vec![ExecutionWave {
                tx_indices: vec![0, 1],
                parallelizable: true,
            }],
            fallback_serial: false,
        };
        scheduler
            .execute(&txs, &parallel_plan, |_| Ok::<(), ()>(()))
            .unwrap();
        let first_pool = scheduler.worker_pool() as *const rayon::ThreadPool;

        scheduler
            .execute(&txs, &parallel_plan, |_| Ok::<(), ()>(()))
            .unwrap();
        assert_eq!(
            first_pool,
            scheduler.worker_pool() as *const rayon::ThreadPool
        );
    }

    #[test]
    fn scheduler_preserves_global_transaction_order_across_waves() {
        let shared = Address::from([0x99; 20]);
        let txs = vec![
            signed_tx(Address::from([0x31; 20]), 1, Vec::new()),
            signed_tx(Address::from([0x32; 20]), 2, Vec::new()),
            signed_tx(shared, 3, Vec::new()),
            signed_tx(shared, 4, Vec::new()),
            signed_tx(Address::from([0x33; 20]), 5, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            max_workers: 4,
            ..ParallelPqvmConfig::default()
        });
        let (_, plan) = scheduler.plan(&txs, &HeuristicRwSetExtractor);
        let outputs = scheduler
            .execute(&txs, &plan, |tx| Ok::<u64, ()>(tx.tx.nonce))
            .unwrap();

        assert_eq!(outputs, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn graph_detects_symmetric_read_after_write_conflicts() {
        let address_a = Address::from([0xaa; 20]);
        let address_b = Address::from([0xbb; 20]);
        let address_c = Address::from([0xcc; 20]);

        let left = TxReadWriteSet {
            reads: vec![TxAccessPath::NativeBalance(address_a)],
            writes: vec![TxAccessPath::NativeBalance(address_b)],
            complete: true,
        };
        let right = TxReadWriteSet {
            reads: vec![TxAccessPath::NativeBalance(address_c)],
            writes: vec![TxAccessPath::NativeBalance(address_a)],
            complete: true,
        };

        let graph = TxConflictGraph::build(vec![left, right]);
        assert_eq!(graph.conflicts.len(), 1);
        assert_eq!(graph.conflicts[0].reason, ConflictReason::ReadWrite);
    }

    #[test]
    fn conflict_metrics_track_correctly() {
        // Two conflicting txs (same recipient) → 1 conflict edge.
        let shared = Address::from([0x77; 20]);
        let txs_conflict = vec![
            signed_tx(shared, 1, Vec::new()),
            signed_tx(shared, 2, Vec::new()),
        ];
        let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
            enabled: true,
            ..ParallelPqvmConfig::default()
        });
        let (graph, _, metric) =
            scheduler.plan_with_metrics(&txs_conflict, &HeuristicRwSetExtractor);
        assert_eq!(graph.conflicts.len(), 1, "should detect one conflict");
        assert_eq!(metric.total_conflicts, 1);
        assert_eq!(metric.reexecuted_txs, 1);
        assert!(metric.conflict_ratio > 0.0, "ratio must be positive");

        let summary = metric.summary();
        assert!(summary.contains("total_conflicts: 1"));
        assert!(summary.contains("reexecuted_txs: 1"));

        // Two non-conflicting txs → 0 conflicts.
        let txs_clean = vec![
            signed_tx(Address::from([0x31; 20]), 3, Vec::new()),
            signed_tx(Address::from([0x32; 20]), 4, Vec::new()),
        ];
        let (_, _, clean_metric) =
            scheduler.plan_with_metrics(&txs_clean, &HeuristicRwSetExtractor);
        assert_eq!(clean_metric.total_conflicts, 0);
        assert_eq!(clean_metric.reexecuted_txs, 0);
        assert_eq!(clean_metric.conflict_ratio, 0.0);

        // Empty batch.
        let (_, _, empty_metric) = scheduler.plan_with_metrics(&[], &HeuristicRwSetExtractor);
        assert_eq!(empty_metric.total_conflicts, 0);
        assert_eq!(empty_metric.conflict_ratio, 0.0);
    }
}
