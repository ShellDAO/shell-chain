use alloy_primitives::U256;
use shell_core::{Account, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType, Signer, Verifier};
use shell_pqvm::{commit_pqvm_state, validate_tx, ShellPqvm, ShellStateDb, TxExecutionResult};
use shell_primitives::{Address as ShellAddress, Bytes as ShellBytes, ShellHash};
use shell_storage::{ChainStore, MemoryDb, WorldState};
use std::sync::Arc;

pub const CHAIN_ID: u64 = 1337;

pub fn setup() -> (ShellPqvm<MemoryDb>, ChainStore<MemoryDb>) {
    let world_state = WorldState::new(Arc::new(MemoryDb::new()));
    let chain_store_db = Arc::new(MemoryDb::new());
    let chain_store_for_evm = ChainStore::new(chain_store_db.clone());
    let chain_store_for_tests = ChainStore::new(chain_store_db);
    let state_db = ShellStateDb::new(world_state, chain_store_for_evm);
    let evm = ShellPqvm::new(state_db, CHAIN_ID);
    (evm, chain_store_for_tests)
}

pub fn sample_header(number: u64) -> BlockHeader {
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

pub fn fund_account(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress, balance: U256) {
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

pub fn sign_tx<S: Signer>(
    from: ShellAddress,
    signer: &S,
    tx: Transaction,
    include_pubkey: bool,
) -> SignedTransaction {
    let hash = tx.signing_hash(signer.sig_type().as_u8());
    let sig = signer.sign(hash.as_bytes()).expect("sign failed");
    if include_pubkey {
        SignedTransaction::with_pubkey(from, tx, sig, signer.public_key().to_vec())
    } else {
        SignedTransaction::new(from, tx, sig)
    }
}

pub fn apply_tx<V: Verifier>(
    evm: &mut ShellPqvm<MemoryDb>,
    chain_store: &ChainStore<MemoryDb>,
    verifier: &V,
    signed_tx: &SignedTransaction,
    block_number: u64,
    tx_index: u32,
    cumulative_gas_used: u64,
) -> TxExecutionResult {
    validate_tx(
        signed_tx,
        evm.state_db_mut().world_state_mut(),
        chain_store,
        verifier,
        CHAIN_ID,
    )
    .expect("validate_tx failed");

    let result = evm
        .execute_tx(
            signed_tx,
            &sample_header(block_number),
            tx_index,
            cumulative_gas_used,
        )
        .expect("execute_tx failed");

    if !result.is_system_tx {
        commit_pqvm_state(&result, evm.state_db_mut()).expect("commit_pqvm_state failed");
    }

    result
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn deploy_runtime_contract<S: Signer, V: Verifier>(
    evm: &mut ShellPqvm<MemoryDb>,
    chain_store: &ChainStore<MemoryDb>,
    verifier: &V,
    signer: &S,
    from: ShellAddress,
    nonce: u64,
    block_number: u64,
    runtime: &[u8],
) -> (ShellAddress, ShellHash) {
    let tx = Transaction {
        chain_id: CHAIN_ID,
        nonce,
        to: None,
        value: U256::ZERO,
        data: ShellBytes::from(make_init_code(runtime)),
        gas_limit: 5_000_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let signed = sign_tx(from, signer, tx, true);
    let result = apply_tx(evm, chain_store, verifier, &signed, block_number, 0, 0);
    let contract_addr = result
        .receipt
        .contract_address
        .expect("contract deployment should return an address");
    let account = evm
        .state_db()
        .world_state()
        .get_account(&contract_addr)
        .unwrap()
        .unwrap();
    let code_hash = account
        .code_hash
        .expect("deployed contract should have code hash");
    (contract_addr, code_hash)
}

#[allow(dead_code)]
fn make_init_code(runtime: &[u8]) -> Vec<u8> {
    let runtime_len = runtime.len();
    assert!(runtime_len <= 0xFFFF, "runtime too large for PUSH2");

    let mut init = Vec::new();
    if runtime_len <= 0xFF {
        let prefix_len: u8 = 12;
        init.extend_from_slice(&[
            0x60,
            runtime_len as u8,
            0x60,
            prefix_len,
            0x60,
            0x00,
            0x39,
            0x60,
            runtime_len as u8,
            0x60,
            0x00,
            0xF3,
        ]);
    } else {
        let prefix_len: u16 = 15;
        init.extend_from_slice(&[
            0x61,
            (runtime_len >> 8) as u8,
            (runtime_len & 0xFF) as u8,
            0x61,
            (prefix_len >> 8) as u8,
            (prefix_len & 0xFF) as u8,
            0x60,
            0x00,
            0x39,
            0x61,
            (runtime_len >> 8) as u8,
            (runtime_len & 0xFF) as u8,
            0x60,
            0x00,
            0xF3,
        ]);
    }
    init.extend_from_slice(runtime);
    init
}

/// Call a deployed contract with arbitrary calldata using a dummy PQ signature.
///
/// Suitable for testing contract logic where signature validation is not the focus.
/// Returns the full `TxExecutionResult` (including `output` and `receipt`).
#[allow(dead_code)]
pub fn call_contract(
    evm: &mut ShellPqvm<MemoryDb>,
    from: ShellAddress,
    nonce: u64,
    contract: ShellAddress,
    calldata: Vec<u8>,
    block_number: u64,
) -> TxExecutionResult {
    let tx = Transaction {
        chain_id: CHAIN_ID,
        nonce,
        to: Some(contract),
        value: U256::ZERO,
        data: ShellBytes::from(calldata),
        gas_limit: 1_000_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
    let signed = SignedTransaction::new(from, tx, sig);
    let result = evm
        .execute_tx(&signed, &sample_header(block_number), 0, 0)
        .expect("call_contract: execute_tx failed");
    if !result.is_system_tx {
        commit_pqvm_state(&result, evm.state_db_mut()).expect("call_contract: commit failed");
    }
    result
}

/// ABI-encode a single uint256 value as 32 bytes big-endian.
#[allow(dead_code)]
pub fn abi_encode_u256(v: U256) -> Vec<u8> {
    v.to_be_bytes::<32>().to_vec()
}

/// Decode the first 32 bytes of raw output as a big-endian U256.
#[allow(dead_code)]
pub fn abi_decode_u256(output: &[u8]) -> U256 {
    assert!(output.len() >= 32, "output too short for U256 decode");
    U256::from_be_slice(&output[..32])
}
