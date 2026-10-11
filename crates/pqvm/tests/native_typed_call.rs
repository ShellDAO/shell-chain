use shell_core::{Account, BlockHeader, SignedTransaction, Transaction};
use shell_crypto::{PQSignature, SignatureType};
use shell_pqvm::{commit_pqvm_state, ShellPqvm, ShellStateDb};
use shell_primitives::{Address as ShellAddress, ShellHash, U256};
use shell_storage::{ChainStore, MemoryDb, WorldState};
use std::sync::Arc;
fn sample_header() -> BlockHeader {
    BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root: ShellHash::ZERO,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: shell_primitives::Bytes::new(),
        number: 1,
        timestamp: 1_000_000,
        gas_limit: 30_000_000,
        gas_used: 0,
        extra_data: shell_primitives::Bytes::new(),
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

fn make_system_tx_to(from: ShellAddress, to: ShellAddress, calldata: Vec<u8>) -> SignedTransaction {
    let tx = Transaction {
        chain_id: 1337,
        nonce: u64::default(),
        to: Some(to),
        value: U256::ZERO,
        data: shell_primitives::Bytes::from(calldata),
        gas_limit: 100_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDD; 100]);
    SignedTransaction::new(from, tx, sig)
}

// Regenerate with shell-sdk's compile-native-typed-call-fixture.mjs.
#[test]
fn native_typed_calls_preserve_original_selectors_full_addresses_and_rollback() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-typed-call.json")).unwrap();
    let store = Arc::new(MemoryDb::new());
    let mut evm = ShellPqvm::new(
        ShellStateDb::new(
            WorldState::new(store.clone()),
            ChainStore::new(store.clone()),
        ),
        1337,
    );
    let config=serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":ShellHash::ZERO,"native_address_context_height":2})).unwrap();
    evm.state_db()
        .chain_store()
        .put_chain_config(&config)
        .unwrap();
    let sender = ShellAddress::from([0x42; 32]);
    let contract = ShellAddress::from([0x43; 32]);
    let mut first = [0x12; 32];
    first[..12].fill(0x34);
    let mut second = first;
    second[..12].fill(0x56);
    let mut alias = first;
    alias[..12].fill(0);
    let first = ShellAddress::from(first);
    let second = ShellAddress::from(second);
    let alias = ShellAddress::from(alias);
    let short = ShellAddress::from([0x67; 32]);
    let missing = ShellAddress::from([0x68; 32]);
    let runtime = |name: &str| {
        hex::decode(
            fixture["artifacts"][name]["deployedBytecode"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
    };
    for (address, code) in [
        (contract, runtime("Typed")),
        (first, runtime("Echo")),
        (second, runtime("Echo")),
        (short, hex::decode("60015ff3").unwrap()),
        (alias, hex::decode("60ff5f5560ff5f5260205ff3").unwrap()),
    ] {
        let hash = shell_primitives::keccak256(&code);
        evm.state_db().chain_store().put_code(&hash, &code).unwrap();
        evm.state_db_mut()
            .world_state_mut()
            .set_account(
                &address,
                &Account {
                    code_hash: Some(hash),
                    ..Account::new_user_account(ShellHash::ZERO, U256::ZERO)
                },
            )
            .unwrap();
    }
    evm.state_db_mut()
        .world_state_mut()
        .set_account(
            &sender,
            &Account::new_user_account(ShellHash::ZERO, U256::from(10_000_000)),
        )
        .unwrap();
    // Original ABI selectors are independently computed in the fixture. The two
    // targets and arguments share low160 bits but differ in their upper96 bits.
    for (nonce, (method, target, value, success, counter)) in [
        ("invoke(address,address)", first, first, false, 0u64),
        ("invoke(address,address)", first, first, true, 1),
        (
            "invoke(address,address)",
            second,
            ShellAddress::ZERO,
            false,
            1,
        ),
        ("invoke(address,address)", second, second, true, 2),
        ("inspect(address,address)", first, second, false, 2),
        ("invoke(address,address)", short, first, false, 2),
        ("invoke(address,address)", missing, first, false, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let mut header = sample_header();
        header.number = nonce as u64 + 1;
        let mut data = hex::decode(
            fixture["selectors"][method]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(value.as_bytes());
        let mut tx = make_system_tx_to(sender, contract, data);
        tx.tx.nonce = nonce as u64;
        tx.tx.gas_limit = 500_000;
        let result = evm.execute_tx(&tx, &header, 0, 0).unwrap();
        assert_eq!(
            result.receipt.status,
            u8::from(success),
            "height {}",
            header.number
        );
        if success {
            assert_eq!(result.output, value.as_bytes());
        } else if header.number == 3 {
            let mut denied = hex::decode(
                fixture["selectors"]["Denied(address)"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            denied.extend_from_slice(ShellAddress::ZERO.as_bytes());
            assert_eq!(result.output, denied);
        } else {
            assert!(result.output.is_empty());
        }
        commit_pqvm_state(&result, evm.state_db_mut()).unwrap();
        let root = evm.state_db_mut().world_state_mut().state_root().unwrap();
        let recovered = WorldState::at_root(store.clone(), &root).unwrap();
        assert_eq!(
            recovered.get_storage(&contract, &ShellHash::ZERO).unwrap(),
            ShellHash::from(U256::from(counter).to_be_bytes::<32>())
        );
        assert_eq!(
            recovered.get_storage(&first, &ShellHash::ZERO).unwrap(),
            if header.number >= 2 {
                ShellHash::from(*first.as_bytes())
            } else {
                ShellHash::ZERO
            }
        );
        assert_eq!(
            recovered.get_storage(&second, &ShellHash::ZERO).unwrap(),
            if header.number >= 4 {
                ShellHash::from(*second.as_bytes())
            } else {
                ShellHash::ZERO
            }
        );
        assert_eq!(
            recovered.get_storage(&alias, &ShellHash::ZERO).unwrap(),
            ShellHash::ZERO
        );
        assert_eq!(recovered.get_nonce(&sender).unwrap(), nonce as u64 + 1);
    }
}
