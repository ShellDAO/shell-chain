//! Benchmarks for the parallel-PQVM scheduling and rwset layer.
//!
//! These benchmarks exercise the conflict-graph and wave-planning paths using
//! mock transactions — no real PQVM execution is required.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_pqvm::{HeuristicRwSetExtractor, ParallelPqvmConfig, ParallelScheduler};
use shell_primitives::{Address, Bytes, U256};

fn make_tx(nonce: u64, to: Address) -> SignedTransaction {
    let from = Address::from([(nonce % 200) as u8 + 1; 20]);
    let tx = Transaction {
        chain_id: 424242,
        nonce,
        to: Some(to),
        value: U256::from(1u64),
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
        PQSignature::new(SignatureType::Dilithium3, vec![0x55; 32]),
    )
}

fn scheduler() -> ParallelScheduler {
    ParallelScheduler::new(ParallelPqvmConfig {
        enabled: true,
        max_workers: 4,
        fallback_on_incomplete: true,
    })
}

/// Benchmark: parallel execution plan for an empty transaction batch.
fn bench_empty_batch(c: &mut Criterion) {
    let sched = scheduler();
    let txs: Vec<SignedTransaction> = vec![];

    c.bench_function("parallel/empty_batch", |b| {
        b.iter(|| {
            let (graph, plan) = sched.plan(black_box(&txs), &HeuristicRwSetExtractor);
            black_box((graph.conflicts.len(), plan.waves.len()))
        });
    });
}

/// Benchmark: 8 non-conflicting native transfers (all different recipients).
fn bench_small_batch_no_conflict(c: &mut Criterion) {
    let sched = scheduler();
    let txs: Vec<SignedTransaction> = (0..8u64)
        .map(|i| make_tx(i, Address::from([(i + 0x40) as u8; 20])))
        .collect();

    c.bench_function("parallel/small_batch_no_conflict", |b| {
        b.iter(|| {
            let (graph, plan) = sched.plan(black_box(&txs), &HeuristicRwSetExtractor);
            black_box((graph.conflicts.len(), plan.waves.len()))
        });
    });
}

/// Benchmark: 8 transfers all targeting the same address (maximum conflicts).
fn bench_small_batch_with_conflict(c: &mut Criterion) {
    let sched = scheduler();
    let shared = Address::from([0x99; 20]);
    let txs: Vec<SignedTransaction> = (0..8u64).map(|i| make_tx(i, shared)).collect();

    c.bench_function("parallel/small_batch_with_conflict", |b| {
        b.iter(|| {
            let (graph, plan) = sched.plan(black_box(&txs), &HeuristicRwSetExtractor);
            black_box((graph.conflicts.len(), plan.waves.len()))
        });
    });
}

/// Benchmark wave planning over an already-built dense conflict graph.
fn bench_dense_plan(c: &mut Criterion) {
    let sched = scheduler();
    let shared = Address::from([0x99; 20]);
    let txs: Vec<SignedTransaction> = (0..128u64).map(|i| make_tx(i, shared)).collect();
    let graph = sched.build_graph(&txs, &HeuristicRwSetExtractor);

    c.bench_function("parallel/dense_plan_128", |b| {
        b.iter(|| black_box(sched.plan_from_graph(black_box(&graph))))
    });
}

criterion_group!(
    benches,
    bench_empty_batch,
    bench_small_batch_no_conflict,
    bench_small_batch_with_conflict,
    bench_dense_plan
);
criterion_main!(benches);
