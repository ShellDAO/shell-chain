//! Benchmarks for shell-storage: Block/Header RLP, ChainStore, MerkleTrie.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use shell_core::{Block, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_storage::{ChainStore, MemoryDb, MerkleTrie};

fn sample_header() -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::from([0xAA; 32]),
        state_root: ShellHash::from([0xBB; 32]),
        transactions_root: ShellHash::from([0xCC; 32]),
        receipts_root: ShellHash::from([0xDD; 32]),
        logs_bloom: Bytes::from(vec![0u8; 256]),
        number: 42,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1_700_000_000,
        extra_data: Bytes::from(b"shell".to_vec()),
        proposer: Address::from([0x01; 20]),
        sig_aggregate_proof: None,
        base_fee_per_gas: 1_000_000_000,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        ..BlockHeader::default()
    }
}

fn sample_signed_tx(nonce: u64) -> SignedTransaction {
    let tx = Transaction {
        chain_id: 1337,
        nonce,
        to: Some(Address::from([0x42; 20])),
        value: U256::from(1_000_000u64),
        data: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAB; 3293]);
    SignedTransaction::new(Address::from([0x01; 20]), tx, sig)
}

fn sample_block() -> Block {
    let txs: Vec<SignedTransaction> = (0..5).map(sample_signed_tx).collect();
    Block {
        header: sample_header(),
        transactions: txs,
        proposer_seal: None,
    }
}

// ── RLP encode/decode ────────────────────────────────────────

fn bench_header_rlp(c: &mut Criterion) {
    let header = sample_header();
    let mut buf = Vec::new();
    header.encode(&mut buf);
    let encoded = buf.clone();

    let mut group = c.benchmark_group("header/rlp");
    group.bench_function("encode", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(512);
            black_box(&header).encode(&mut out);
            black_box(out);
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            let h = BlockHeader::decode(&mut black_box(encoded.as_slice())).unwrap();
            black_box(h);
        });
    });
    group.finish();
}

fn bench_block_rlp(c: &mut Criterion) {
    let block = sample_block();
    let mut buf = Vec::new();
    block.encode(&mut buf);
    let encoded = buf.clone();

    let mut group = c.benchmark_group("block/rlp");
    group.bench_function("encode", |b| {
        b.iter(|| {
            let mut out = Vec::with_capacity(32768);
            black_box(&block).encode(&mut out);
            black_box(out);
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            let blk = Block::decode(&mut black_box(encoded.as_slice())).unwrap();
            black_box(blk);
        });
    });
    group.finish();
}

// ── ChainStore put/get ───────────────────────────────────────

fn bench_chain_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_store");

    group.bench_function("put_block", |b| {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = sample_block();
        b.iter(|| {
            cs.put_block(black_box(&block)).unwrap();
        });
    });

    group.bench_function("get_block", |b| {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = sample_block();
        let hash = block.hash();
        cs.put_block(&block).unwrap();
        b.iter(|| {
            let loaded = cs.get_block_by_hash(black_box(&hash)).unwrap();
            black_box(loaded);
        });
    });
    group.finish();
}

// ── MerkleTrie ───────────────────────────────────────────────

fn bench_merkle_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_trie");

    group.bench_function("insert", |b| {
        let store = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(store);
        let mut i = 0u64;
        b.iter(|| {
            let key = i.to_be_bytes();
            trie.insert(&key, black_box(b"value")).unwrap();
            i += 1;
        });
    });

    group.bench_function("get", |b| {
        let store = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(store);
        // Pre-populate
        for i in 0u64..1000 {
            trie.insert(&i.to_be_bytes(), b"value").unwrap();
        }
        let mut i = 0u64;
        b.iter(|| {
            let key = (i % 1000).to_be_bytes();
            let v = trie.get(black_box(&key)).unwrap();
            black_box(v);
            i += 1;
        });
    });

    group.bench_function("root_hash", |b| {
        let store = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(store);
        for i in 0u64..100 {
            trie.insert(&i.to_be_bytes(), b"value").unwrap();
        }
        b.iter(|| {
            let root = trie.root_hash().unwrap();
            black_box(root);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_header_rlp,
    bench_block_rlp,
    bench_chain_store,
    bench_merkle_trie,
);
criterion_main!(benches);
