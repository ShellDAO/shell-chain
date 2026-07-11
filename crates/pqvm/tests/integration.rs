//! End-to-end EVM integration tests.
//!
//! These tests exercise the full pipeline: tx validation → PQVM execution → receipt,
//! using real Dilithium3 signatures and the Shell PQ precompile suite (0x0001–0x0006).

use alloy_primitives::U256;
use shell_core::{Account, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, DilithiumVerifier, PQSignature, SignatureType, Signer};
use shell_pqvm::{validate_tx, ShellPqvm, ShellStateDb, TxValidationError};
use shell_primitives::{Address as ShellAddress, Bytes as ShellBytes, ShellHash};
use shell_storage::{ChainStore, MemoryDb, WorldState};
use std::sync::Arc;

// ── Helpers ──────────────────────────────────────────────────────

const CHAIN_ID: u64 = 1337;

fn setup() -> (ShellPqvm<MemoryDb>, ChainStore<MemoryDb>) {
    let ws = WorldState::new(Arc::new(MemoryDb::new()));
    let cs_db = Arc::new(MemoryDb::new());
    let cs_for_evm = ChainStore::new(cs_db.clone());
    let cs_for_test = ChainStore::new(cs_db);
    let state_db = ShellStateDb::new(ws, cs_for_evm);
    let evm = ShellPqvm::new(state_db, CHAIN_ID);
    (evm, cs_for_test)
}

fn sample_header(number: u64) -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: ShellHash::ZERO,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: ShellBytes::new(),
        number,
        timestamp: 1_700_000_000 + number * 12,
        gas_limit: 30_000_000,
        gas_used: 0,
        extra_data: ShellBytes::new(),
        proposer: ShellAddress::ZERO,
        sig_aggregate_proof: None,
        base_fee_per_gas: 0,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        witness_root: None,
    }
}

fn fund_account(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress, balance: U256) {
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

fn current_nonce(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress) -> u64 {
    evm.state_db_mut()
        .world_state_mut()
        .get_nonce(addr)
        .unwrap()
}

fn tx_signing_hash_for_signer<S: Signer>(tx: &Transaction, signer: &S) -> ShellHash {
    tx.signing_hash(signer.sig_type().as_u8())
}

// ── Test 1: Simple ETH transfer with real Dilithium3 sig ─────────

#[test]
fn e2e_transfer_with_real_dilithium_sig() {
    let (mut evm, cs) = setup();
    let verifier = DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let to = ShellAddress::from([0xBB; 20]);

    fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

    let tx = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(to),
        value: U256::from(1_000_000),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let hash = tx_signing_hash_for_signer(&tx, &signer);
    let sig = signer.sign(hash.as_bytes()).expect("sign failed");

    let signed = SignedTransaction::with_pubkey(from, tx, sig, signer.public_key().to_vec());

    let header = sample_header(1);

    // Validate: real sig verification + pubkey registration
    let validated = validate_tx(
        &signed,
        evm.state_db_mut().world_state_mut(),
        &cs,
        &verifier,
        CHAIN_ID,
    );
    assert!(
        validated.is_ok(),
        "validate_tx failed: {:?}",
        validated.err()
    );

    // Execute: runs the transfer through revm
    let result = evm.execute_tx(&signed, &header, 0, 0);
    assert!(result.is_ok(), "execute_tx failed: {:?}", result.err());

    let tx_result = result.unwrap();
    assert_eq!(tx_result.receipt.status, 1, "transfer should succeed");
    assert_eq!(tx_result.receipt.block_number, 1);
    assert_eq!(tx_result.receipt.tx_index, 0);
    assert!(tx_result.gas_used <= 21_000);
}

// ── Test 2: Validation rejects wrong signature ───────────────────

#[test]
fn e2e_reject_invalid_signature() {
    let (mut evm, cs) = setup();
    let verifier = DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

    let tx = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(ShellAddress::from([0xCC; 20])),
        value: U256::from(100),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let bad_sig = PQSignature::new(SignatureType::Dilithium3, vec![0xFF; 3293]);
    let signed = SignedTransaction::with_pubkey(from, tx, bad_sig, signer.public_key().to_vec());

    let result = validate_tx(
        &signed,
        evm.state_db_mut().world_state_mut(),
        &cs,
        &verifier,
        CHAIN_ID,
    );
    assert!(
        matches!(result, Err(TxValidationError::SignatureInvalid)),
        "should reject forged signature, got: {:?}",
        result
    );
}

// ── Test 3: Contract deployment ──────────────────────────────────

#[test]
fn e2e_contract_deployment() {
    let (mut evm, _cs) = setup();

    let from = ShellAddress::from([0x42; 20]);
    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    // Minimal init code: PUSH1 0x42 PUSH1 0 MSTORE PUSH1 1 PUSH1 31 RETURN
    let init_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];

    let tx = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: None,
        value: U256::ZERO,
        data: ShellBytes::from(init_code),
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
    let signed = SignedTransaction::new(from, tx, sig);

    let header = sample_header(1);
    let result = evm.execute_tx(&signed, &header, 0, 0);
    assert!(result.is_ok(), "contract deploy failed: {:?}", result.err());

    let tx_result = result.unwrap();
    assert_eq!(tx_result.receipt.status, 1);
    assert!(
        tx_result.receipt.contract_address.is_some(),
        "should have contract address"
    );
}

// ── Test 4: Hybrid pubkey: second tx reads from registry ─────────

#[test]
fn e2e_hybrid_pubkey_second_tx_from_registry() {
    let (mut evm, cs) = setup();
    let verifier = DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let to = ShellAddress::from([0xDD; 20]);

    fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

    // First tx: carries pubkey
    let tx1 = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(to),
        value: U256::from(100),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let hash1 = tx_signing_hash_for_signer(&tx1, &signer);
    let sig1 = signer.sign(hash1.as_bytes()).unwrap();
    let signed1 = SignedTransaction::with_pubkey(from, tx1, sig1, signer.public_key().to_vec());

    // Validate first tx — registers pubkey to chain store
    let v1 = validate_tx(
        &signed1,
        evm.state_db_mut().world_state_mut(),
        &cs,
        &verifier,
        CHAIN_ID,
    );
    assert!(v1.is_ok(), "first tx validation failed: {:?}", v1.err());

    // Execute first tx to increment nonce in world state
    let header = sample_header(1);
    let r1 = evm.execute_tx(&signed1, &header, 0, 0).unwrap();
    assert_eq!(r1.receipt.status, 1);

    // Commit the nonce change from execution using commit_pqvm_state so PQ
    // addresses are correctly resolved via the address_registry.
    shell_pqvm::commit_pqvm_state(&r1, evm.state_db_mut()).expect("commit r1 failed");

    // Second tx: NO pubkey attached — should read from registry
    let tx2 = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(to),
        value: U256::from(200),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let hash2 = tx_signing_hash_for_signer(&tx2, &signer);
    let sig2 = signer.sign(hash2.as_bytes()).unwrap();
    let signed2 = SignedTransaction::new(from, tx2, sig2);

    let v2 = validate_tx(
        &signed2,
        evm.state_db_mut().world_state_mut(),
        &cs,
        &verifier,
        CHAIN_ID,
    );
    assert!(
        v2.is_ok(),
        "second tx should pass with registered pubkey: {:?}",
        v2.err()
    );
}

// ── Test 5: Precompile addresses registered correctly ────────────

#[test]
fn e2e_precompile_addresses() {
    use alloy_primitives::address;
    use revm::primitives::hardfork::SpecId;
    use shell_pqvm::ShellPrecompiles;

    let sp = ShellPrecompiles::new(SpecId::CANCUN);

    // ML-DSA-65 verify at 0x0001 (replaces ecrecover)
    let pq_addr = address!("0x0000000000000000000000000000000000000001");
    assert!(
        sp.is_precompile(&pq_addr),
        "ML-DSA-65 verify precompile should be registered"
    );

    // SLH-DSA verify at 0x0002
    let slhdsa_addr = address!("0x0000000000000000000000000000000000000002");
    assert!(
        sp.is_precompile(&slhdsa_addr),
        "SLH-DSA verify precompile should be registered"
    );

    // PQ address derive at 0x0006
    let pqaddr_addr = address!("0x0000000000000000000000000000000000000006");
    assert!(
        sp.is_precompile(&pqaddr_addr),
        "PQ address derive precompile should be registered"
    );

    // Non-precompile address (old PQ addr 0x0100 no longer registered)
    let random_addr = address!("0x0000000000000000000000000000000000000100");
    assert!(
        !sp.is_precompile(&random_addr),
        "0x0100 should not be a precompile"
    );
}

// ── Test 6: Multiple transfers accumulate gas ────────────────────

#[test]
fn e2e_cumulative_gas_tracking() {
    let (mut evm, _cs) = setup();

    let from = ShellAddress::from([0x42; 20]);
    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let header = sample_header(1);

    let tx1 = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(ShellAddress::from([0x01; 20])),
        value: U256::from(100),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig1 = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
    let signed1 = SignedTransaction::new(from, tx1, sig1);

    let r1 = evm.execute_tx(&signed1, &header, 0, 0).unwrap();
    assert_eq!(r1.receipt.status, 1);
    let gas1 = r1.gas_used;

    let tx2 = Transaction {
        chain_id: CHAIN_ID,
        nonce: current_nonce(&mut evm, &from),
        to: Some(ShellAddress::from([0x02; 20])),
        value: U256::from(200),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig2 = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);
    let signed2 = SignedTransaction::new(from, tx2, sig2);

    let r2 = evm.execute_tx(&signed2, &header, 1, gas1).unwrap();
    assert_eq!(r2.receipt.status, 1);
    assert_eq!(
        r2.receipt.cumulative_gas_used,
        gas1 + r2.gas_used,
        "cumulative gas should accumulate"
    );
}
