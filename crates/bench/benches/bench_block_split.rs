/// Criterion benchmarks for 3-way block body split (L1 storage separation).
///
/// Measures the on-disk byte size of:
/// - (a) **legacy**: full [`Block`] RLP (pre-split baseline)
/// - (b) **split**: `StrippedBlock` + `WitnessBundle` (L1 split)
/// - (c) **post-proof**: `StrippedBlock` only (witness deleted after STARK proof)
///
/// Reports size ratios to show the storage benefit of the split and
/// the additional savings from proof-based witness replacement.
///
/// Run with: `cargo bench --package shell-bench --bench bench_block_split`
use alloy_rlp::Encodable;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use shell_core::{
    Block, BlockHeader, SignedTransaction, StrippedBlock, Transaction, TxWitness, WitnessBundle,
};
use shell_crypto::{DilithiumSigner, PQSignature, SignatureType, Signer};
use shell_primitives::{Address, Bytes, ShellHash, U256};

// ─── Constants ────────────────────────────────────────────────────────────────

const DILITHIUM3_SIG_LEN: usize = 3309;
const DILITHIUM3_PUBKEY_LEN: usize = 1952;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_transfer_tx(nonce: u64) -> Transaction {
    Transaction {
        chain_id: 1337,
        nonce,
        to: Some(Address::from([0xAB; 20])),
        value: U256::from(1u64),
        data: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 0,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

fn make_signed_tx(
    signer: &DilithiumSigner,
    from: Address,
    nonce: u64,
    first: bool,
) -> SignedTransaction {
    let tx = make_transfer_tx(nonce);
    let sig = signer.sign(tx.hash().0.as_slice()).unwrap();
    let pubkey = signer.public_key().to_vec();
    if first {
        SignedTransaction::with_pubkey(from, tx, sig, pubkey)
    } else {
        SignedTransaction::new(from, tx, sig)
    }
}

/// Build a [`Block`] with `tx_count` signed transactions.
fn make_block(tx_count: usize) -> Block {
    let signer = DilithiumSigner::generate();
    let from = Address::from([0x11; 20]);
    let txs: Vec<SignedTransaction> = (0..tx_count)
        .map(|i| make_signed_tx(&signer, from, i as u64, i == 0))
        .collect();

    Block {
        header: BlockHeader {
            parent_hash: ShellHash::default(),
            state_root: ShellHash::default(),
            transactions_root: ShellHash::default(),
            receipts_root: ShellHash::default(),
            logs_bloom: Bytes::default(),
            number: 1,
            gas_limit: 30_000_000,
            gas_used: tx_count as u64 * 21_000,
            timestamp: 1_700_000_000,
            extra_data: Bytes::default(),
            sig_aggregate_proof: None,
        },
        transactions: txs,
    }
}

// ─── Size measurement helpers ─────────────────────────────────────────────────

/// Byte size of the full block RLP (legacy single-blob encoding).
fn legacy_size(block: &Block) -> usize {
    let mut buf = Vec::new();
    block.encode(&mut buf);
    buf.len()
}

/// Byte size of StrippedBlock + WitnessBundle (L1 split encoding).
fn split_size(block: &Block) -> usize {
    let (stripped, bundle) = block.clone().split();
    let mut sbuf = Vec::new();
    stripped.encode(&mut sbuf);
    let mut wbuf = Vec::new();
    bundle.encode(&mut wbuf);
    sbuf.len() + wbuf.len()
}

/// Byte size of StrippedBlock only (post-proof: witness deleted).
fn post_proof_size(block: &Block) -> usize {
    let (stripped, _bundle) = block.clone().split();
    let mut sbuf = Vec::new();
    stripped.encode(&mut sbuf);
    sbuf.len()
}

// ─── Size report (run at benchmark startup) ───────────────────────────────────

fn print_size_table() {
    println!("\n╔══ Block Split Storage Sizes ═════════════════════════════════════╗");
    println!(
        "║  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "txs", "legacy", "split", "post-proof", "split%", "proof%", "saving%"
    );
    for tx_count in [1, 10, 50, 100] {
        let block = make_block(tx_count);
        let legacy = legacy_size(&block);
        let split = split_size(&block);
        let post = post_proof_size(&block);
        println!(
            "║  {:>6}  {:>8}  {:>8}  {:>8}  {:>7.1}%  {:>7.1}%  {:>7.1}%",
            tx_count,
            legacy,
            split,
            post,
            split as f64 / legacy as f64 * 100.0,
            post as f64 / legacy as f64 * 100.0,
            (1.0 - post as f64 / legacy as f64) * 100.0,
        );
    }
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    println!("  note: split ≈ legacy (same data, different keys)");
    println!(
        "  note: post-proof removes PQ signatures (~{} B/tx), retaining TX payloads\n",
        DILITHIUM3_SIG_LEN + DILITHIUM3_PUBKEY_LEN
    );
}

// ─── Benchmarks ──────────────────────────────────────────────────────────────

fn bench_encode_legacy(c: &mut Criterion) {
    print_size_table();

    let mut group = c.benchmark_group("block_split/encode");

    for tx_count in [10usize, 50, 100] {
        let block = make_block(tx_count);
        let bytes = tx_count * (DILITHIUM3_SIG_LEN + DILITHIUM3_PUBKEY_LEN + 140);
        group.throughput(Throughput::Bytes(bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("legacy_rlp", tx_count),
            &block,
            |b, block| b.iter(|| black_box(legacy_size(block))),
        );

        group.bench_with_input(
            BenchmarkId::new("split_stripped+witness", tx_count),
            &block,
            |b, block| b.iter(|| black_box(split_size(block))),
        );

        group.bench_with_input(
            BenchmarkId::new("post_proof_stripped_only", tx_count),
            &block,
            |b, block| b.iter(|| black_box(post_proof_size(block))),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_encode_legacy);
criterion_main!(benches);
