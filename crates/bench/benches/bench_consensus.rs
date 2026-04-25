/// Criterion benchmarks for shell-chain consensus operations.
///
/// Covers PoA seal/verify header and proposer selection.
/// Run with: `cargo bench --package shell-bench --bench bench_consensus`
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use shell_consensus::{ConsensusEngine, PoaConfig, PoaEngine};
use shell_core::{Block, BlockHeader};
use shell_crypto::{DilithiumSigner, Signer};
use shell_primitives::{Address, Bytes, ShellHash};

fn make_block(number: u64, proposer: Address) -> Block {
    Block {
        header: BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Bytes::default(),
            number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_700_000_000 + number,
            extra_data: Bytes::default(),
            proposer,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            ..BlockHeader::default()
        },
        transactions: vec![],
        proposer_seal: None,
    }
}

fn bench_poa_sign(c: &mut Criterion) {
    let signer = DilithiumSigner::generate();
    let addr = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let engine = PoaEngine::new(PoaConfig::new(vec![addr], 2));

    let mut group = c.benchmark_group("poa");
    group.throughput(Throughput::Elements(1));

    group.bench_function("sign_block", |b| {
        b.iter(|| {
            let mut block = make_block(black_box(1), addr);
            engine.sign_block(&mut block, &signer).unwrap()
        })
    });

    let mut block = make_block(1, addr);
    engine.sign_block(&mut block, &signer).unwrap();

    group.bench_function("verify_header", |b| {
        b.iter(|| engine.verify_header(black_box(&block.header)).unwrap())
    });

    group.finish();
}

fn bench_poa_proposer_selection(c: &mut Criterion) {
    // Simulate round-robin proposer selection for 10 validators.
    let validators: Vec<Address> = (0u8..10)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            Address::from(bytes)
        })
        .collect();

    let mut group = c.benchmark_group("poa");
    group.throughput(Throughput::Elements(1));

    group.bench_function("proposer_for_block", |b| {
        let count = validators.len() as u64;
        b.iter(|| {
            let _proposer = validators[(black_box(1000_u64) % count) as usize];
        })
    });

    group.finish();
}

criterion_group!(benches, bench_poa_sign, bench_poa_proposer_selection);
criterion_main!(benches);
