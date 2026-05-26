//! Benchmarks for shell-pqvm: transfer, contract creation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

use shell_core::{Account, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_pqvm::{ShellPqvm, ShellStateDb};
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_storage::{ChainStore, MemoryDb, WorldState};

fn setup_evm() -> ShellPqvm<MemoryDb> {
    let ws = WorldState::new(Arc::new(MemoryDb::new()));
    let cs = ChainStore::new(Arc::new(MemoryDb::new()));
    let state_db = ShellStateDb::new(ws, cs);
    ShellPqvm::new(state_db, 1337)
}

fn sample_header() -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: ShellHash::ZERO,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: Bytes::new(),
        number: 1,
        timestamp: 1_000_000,
        gas_limit: 30_000_000,
        gas_used: 0,
        extra_data: Bytes::new(),
        proposer: Address::ZERO,
        sig_aggregate_proof: None,
        base_fee_per_gas: 0,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        ..BlockHeader::default()
    }
}

fn fund_account(evm: &mut ShellPqvm<MemoryDb>, addr: &Address, balance: U256) {
    let account = Account {
        pq_pubkey_hash: ShellHash::ZERO,
        nonce: 0,
        balance,
        validation_code_hash: None,
        code_hash: None,
        storage_root: ShellHash::ZERO,
    };
    evm.state_db_mut()
        .world_state_mut()
        .set_account(addr, &account)
        .unwrap();
}

fn make_transfer(from: &Address, to: &Address, nonce: u64) -> SignedTransaction {
    let tx = Transaction {
        chain_id: 1337,
        nonce,
        to: Some(*to),
        value: U256::from(1_000u64),
        data: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
    SignedTransaction::new(*from, tx, sig)
}

/// Init code that deploys a minimal runtime (STOP opcode).
fn minimal_init_code() -> Vec<u8> {
    // Runtime: single STOP (0x00)
    let runtime = [0x00u8];
    let runtime_len = runtime.len() as u8;
    let prefix_len: u8 = 12;
    let mut init = Vec::new();
    init.extend_from_slice(&[
        0x60,
        runtime_len, // PUSH1 len
        0x60,
        prefix_len, // PUSH1 offset
        0x60,
        0x00, // PUSH1 0
        0x39, // CODECOPY
        0x60,
        runtime_len, // PUSH1 len
        0x60,
        0x00, // PUSH1 0
        0xF3, // RETURN
    ]);
    init.extend_from_slice(&runtime);
    init
}

// ── Simple transfer ──────────────────────────────────────────

fn bench_simple_transfer(c: &mut Criterion) {
    c.bench_function("pqvm/simple_transfer", |b| {
        let mut evm = setup_evm();
        let sender = Address::from([0x01; 20]);
        let receiver = Address::from([0x02; 20]);
        fund_account(&mut evm, &sender, U256::from(1_000_000_000_000u64));
        let header = sample_header();
        let mut nonce = 0u64;

        b.iter(|| {
            let signed = make_transfer(&sender, &receiver, nonce);
            let result = evm.execute_tx(black_box(&signed), &header, 0, 0).unwrap();
            black_box(&result);
            nonce += 1;
        });
    });
}

// ── Contract creation ────────────────────────────────────────

fn bench_contract_creation(c: &mut Criterion) {
    c.bench_function("pqvm/contract_creation", |b| {
        let mut evm = setup_evm();
        let deployer = Address::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(1_000_000_000_000u64));
        let header = sample_header();
        let init_code = minimal_init_code();
        let mut nonce = 0u64;

        b.iter(|| {
            let tx = Transaction {
                chain_id: 1337,
                nonce,
                to: None,
                value: U256::ZERO,
                data: Bytes::from(init_code.clone()),
                gas_limit: 5_000_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xCC; 100]);
            let signed = SignedTransaction::new(deployer, tx, sig);
            let result = evm.execute_tx(black_box(&signed), &header, 0, 0).unwrap();
            black_box(&result);
            nonce += 1;
        });
    });
}

criterion_group!(benches, bench_simple_transfer, bench_contract_creation);
criterion_main!(benches);
