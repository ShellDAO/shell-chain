//! Parallel EVM PoC scheduling primitives.
//!
//! This module intentionally stays additive: it builds conflict graphs and
//! execution waves from transaction read/write sets without changing the
//! production executor path. Callers can opt in via [`ParallelEvmConfig`]
//! and either inspect the plan or execute wave-local work with rayon.

use rayon::prelude::*;
use shell_core::SignedTransaction;

use crate::rwset::{ReadWriteSetExtractor, TxAccessPath, TxReadWriteSet};

/// Feature flag and scheduler knobs for the parallel-EVM PoC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelEvmConfig {
    /// Enables conflict-graph scheduling.
    pub enabled: bool,
    /// Maximum worker threads used for parallelizable waves.
    pub max_workers: usize,
    /// Fall back to a single serial wave when any rw-set is incomplete.
    pub fallback_on_incomplete: bool,
}

impl Default for ParallelEvmConfig {
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
            for right in (left + 1)..rwsets.len() {
                if let Some(conflict) = detect_conflict(left, right, &rwsets[left], &rwsets[right])
                {
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

/// Conflict-aware scheduler for the parallel-EVM PoC.
#[derive(Debug, Clone)]
pub struct ParallelScheduler {
    config: ParallelEvmConfig,
}

impl ParallelScheduler {
    pub fn new(config: ParallelEvmConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ParallelEvmConfig {
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

        let mut waves: Vec<ExecutionWave> = Vec::new();
        for tx_index in 0..graph.rwsets.len() {
            let can_join_last_wave = waves
                .last()
                .map(|wave| {
                    wave.tx_indices
                        .iter()
                        .all(|existing| !graph.has_conflict(tx_index, *existing))
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
        let worker_count = self.config.max_workers.max(1);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .expect("thread pool creation should succeed");

        let mut outputs = Vec::new();
        for wave in &plan.waves {
            if wave.parallelizable {
                let wave_results = pool.install(|| {
                    wave.tx_indices
                        .par_iter()
                        .map(|index| execute_tx(&txs[*index]))
                        .collect::<Vec<_>>()
                });
                for result in wave_results {
                    outputs.push(result?);
                }
            } else {
                for index in &wave.tx_indices {
                    outputs.push(execute_tx(&txs[*index])?);
                }
            }
        }

        Ok(outputs)
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
        let scheduler = ParallelScheduler::new(ParallelEvmConfig {
            enabled: true,
            ..ParallelEvmConfig::default()
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
        let scheduler = ParallelScheduler::new(ParallelEvmConfig {
            enabled: true,
            ..ParallelEvmConfig::default()
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

        let scheduler = ParallelScheduler::new(ParallelEvmConfig {
            enabled: true,
            fallback_on_incomplete: true,
            ..ParallelEvmConfig::default()
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
        let scheduler = ParallelScheduler::new(ParallelEvmConfig {
            enabled: true,
            max_workers: 2,
            ..ParallelEvmConfig::default()
        });
        let (_, plan) = scheduler.plan(&txs, &HeuristicRwSetExtractor);
        let outputs = scheduler
            .execute(&txs, &plan, |tx| Ok::<u64, ()>(tx.tx.nonce))
            .unwrap();

        assert_eq!(outputs, vec![1, 2]);
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
        let scheduler = ParallelScheduler::new(ParallelEvmConfig {
            enabled: true,
            max_workers: 4,
            ..ParallelEvmConfig::default()
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
}
