use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_pqvm::{HeuristicRwSetExtractor, ParallelPqvmConfig, ParallelScheduler};
use shell_primitives::{Address, Bytes, U256};

fn bench_parallel_poc(c: &mut Criterion) {
    let scheduler = ParallelScheduler::new(ParallelPqvmConfig {
        enabled: true,
        max_workers: 4,
        fallback_on_incomplete: true,
    });
    let independent = make_independent_transfers(128);
    let conflicting = make_conflicting_transfers(128);

    c.bench_function("parallel-poc/independent-plan", |b| {
        b.iter(|| {
            let (graph, plan) = scheduler.plan(black_box(&independent), &HeuristicRwSetExtractor);
            black_box((graph.conflicts.len(), plan.waves.len()))
        });
    });

    c.bench_function("parallel-poc/independent-execute", |b| {
        let (_, plan) = scheduler.plan(&independent, &HeuristicRwSetExtractor);
        b.iter(|| {
            let outputs = scheduler
                .execute(black_box(&independent), &plan, |tx| {
                    Ok::<u64, ()>(tx.tx.nonce + tx.tx.gas_limit)
                })
                .unwrap();
            black_box(outputs.len())
        });
    });

    c.bench_function("parallel-poc/conflicting-fallback", |b| {
        b.iter(|| {
            let (graph, plan) = scheduler.plan(black_box(&conflicting), &HeuristicRwSetExtractor);
            black_box((graph.conflicts.len(), plan.fallback_serial))
        });
    });
}

fn make_independent_transfers(count: usize) -> Vec<SignedTransaction> {
    (0..count)
        .map(|index| make_transfer_tx(index as u64, Address::from([(index % 200) as u8 + 1; 20])))
        .collect()
}

fn make_conflicting_transfers(count: usize) -> Vec<SignedTransaction> {
    let shared = Address::from([0x99; 20]);
    (0..count)
        .map(|index| make_transfer_tx(index as u64, shared))
        .collect()
}

fn make_transfer_tx(nonce: u64, to: Address) -> SignedTransaction {
    let from = Address::from([nonce as u8; 20]);
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

criterion_group!(benches, bench_parallel_poc);
criterion_main!(benches);
