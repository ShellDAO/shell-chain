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

// Regenerate with shell-sdk's compile-native-owner-fixture.mjs.
#[test]
fn native_uint256_interface_calls_preserve_selector_full_owner_and_static_mode() {
    check_owner_fixture(include_str!("fixtures/native-owner.json"));
}

#[test]
fn native_uint256_interface_calls_preserve_bytes32_owner_and_static_mode() {
    check_owner_fixture(include_str!("fixtures/native-owner-bytes32.json"));
}

fn check_owner_fixture(source: &str) {
    let fixture: serde_json::Value = serde_json::from_str(source).unwrap();
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
    let writer = ShellAddress::from([0x69; 32]);
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
        (contract, runtime("Reader")),
        (first, runtime("Owner")),
        (second, runtime("Owner")),
        (short, hex::decode("60015ff3").unwrap()),
        (writer, runtime("Writer")),
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
    for target in [first, second] {
        evm.state_db_mut()
            .world_state_mut()
            .set_storage(
                &target,
                &ShellHash::ZERO,
                &ShellHash::from(*target.as_bytes()),
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
    // Original ownerOf(uint256) selector and the maximum token ID must survive;
    // two distinct full-width destinations share their low 20 bytes.
    for (nonce, (target, token_id, success, counter)) in [
        (first, U256::MAX, false, 0u64),
        (first, U256::MAX, true, 1),
        (second, U256::ZERO, false, 1),
        (second, U256::MAX, true, 2),
        (writer, U256::MAX, false, 2),
        (short, U256::MAX, false, 2),
        (missing, U256::MAX, false, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let mut header = sample_header();
        header.number = nonce as u64 + 1;
        let mut data = hex::decode(
            fixture["selectors"]["lookup(address,uint256)"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(&token_id.to_be_bytes::<32>());
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
            assert_eq!(result.output, target.as_bytes());
        } else if header.number == 3 {
            let mut denied = hex::decode(
                fixture["selectors"]["Missing(uint256)"]
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
        for target in [first, second] {
            assert_eq!(
                recovered.get_storage(&target, &ShellHash::ZERO).unwrap(),
                ShellHash::from(*target.as_bytes())
            );
        }
        assert_eq!(
            recovered.get_storage(&writer, &ShellHash::ZERO).unwrap(),
            ShellHash::ZERO
        );
        assert!(recovered.get_account(&missing).unwrap().is_none());
        assert_eq!(
            recovered.get_storage(&alias, &ShellHash::ZERO).unwrap(),
            ShellHash::ZERO
        );
        assert_eq!(recovered.get_nonce(&sender).unwrap(), nonce as u64 + 1);
    }
}

// Regenerate with: compile-native-owner-fixture.mjs <output.json> bytes32 struct.
#[test]
fn native_struct_call_receivers_preserve_words_single_evaluation_and_history() {
    use shell_storage::KvStore;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-struct-call.json")).unwrap();
    for name in ["Ledger", "SelectingLedger"] {
        for activation in [None, Some(2u64)] {
            let store = Arc::new(MemoryDb::new());
            let mut vm = ShellPqvm::new(
                ShellStateDb::new(
                    WorldState::new(store.clone()),
                    ChainStore::new(store.clone()),
                ),
                1337,
            );
            let sender = ShellAddress::from([0x42; 32]);
            let ledger = ShellAddress::from([0x43; 32]);
            let wide = |high: u8| {
                let mut word = [0x12; 32];
                word[..12].fill(high);
                ShellAddress::from(word)
            };
            let first = wide(0x34);
            let second = wide(0x56);
            let alias = wide(0);
            let writer = ShellAddress::from([0x67; 32]);
            let short = ShellAddress::from([0x68; 32]);
            let missing = ShellAddress::from([0x69; 32]);
            let runtime = |contract: &str| {
                hex::decode(
                    fixture["artifacts"][contract]["deployedBytecode"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap()
            };
            for (address, code) in [
                (ledger, runtime(name)),
                (first, runtime("Owner")),
                (second, runtime("Owner")),
                (writer, runtime("Writer")),
                (short, hex::decode("60015ff3").unwrap()),
                (alias, hex::decode("60ff5f5560ff5f5260205ff3").unwrap()),
            ] {
                let hash = shell_primitives::keccak256(&code);
                vm.state_db().chain_store().put_code(&hash, &code).unwrap();
                vm.state_db_mut()
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
            // Independent callee storage is the oracle, not compiler-generated output.
            for target in [first, second] {
                vm.state_db_mut()
                    .world_state_mut()
                    .set_storage(
                        &target,
                        &ShellHash::ZERO,
                        &ShellHash::from(*target.as_bytes()),
                    )
                    .unwrap();
            }
            vm.state_db_mut()
                .world_state_mut()
                .set_account(
                    &sender,
                    &Account::new_user_account(ShellHash::ZERO, U256::from(10_000_000)),
                )
                .unwrap();
            vm.state_db().chain_store().put_chain_config(&serde_json::from_value(serde_json::json!({
                "chain_id":1337,"genesis_hash":ShellHash::ZERO,"native_address_context_height":activation
            })).unwrap()).unwrap();
            let slot = |id: usize| {
                let mut key = U256::from(id).to_be_bytes::<32>().to_vec();
                key.extend_from_slice(&[0u8; 32]);
                shell_primitives::keccak256(&key)
            };
            let input = |signature: &str, id: usize, target: Option<ShellAddress>| {
                let mut data = hex::decode(
                    fixture["selectors"][signature]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap();
                data.extend_from_slice(&U256::from(id).to_be_bytes::<32>());
                if let Some(target) = target {
                    data.extend_from_slice(target.as_bytes());
                }
                data
            };
            let selecting = name == "SelectingLedger";
            let mut owners = [ShellAddress::ZERO; 5];
            let mut selections = 0u64;
            let mut history = Vec::new();
            let mut nonce = 0u64;
            // Setup uses the public setter and therefore verifies the stored full target.
            for (id, target) in [first, second, writer, short, missing]
                .into_iter()
                .enumerate()
            {
                let mut tx = make_system_tx_to(
                    sender,
                    ledger,
                    input("set(uint256,address)", id, Some(target)),
                );
                tx.tx.nonce = nonce;
                tx.tx.gas_limit = 500_000;
                let result = vm.execute_tx(&tx, &sample_header(), 0, 0).unwrap();
                assert_eq!(result.receipt.status, 1);
                commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
                owners[id] = target;
                nonce += 1;
            }
            let initial = vm.state_db_mut().world_state_mut().state_root().unwrap();
            history.push((initial, owners, selections, nonce));
            let mut operations = vec![
                ("lookup(uint256)", 0usize, 1u64, false),
                ("lookup(uint256)", 0, 2, activation.is_some()),
                ("lookup(uint256)", 1, 3, activation.is_some()),
                ("lookup(uint256)", 2, 3, false), // STATICCALL must reject Writer's SSTORE.
                ("lookup(uint256)", 3, 3, false), // Short return must not decode.
                ("lookup(uint256)", 4, 3, false), // Missing code must not decode.
                ("lookup(uint256)", 5, 3, false), // Unset struct field has a zero target.
            ];
            if selecting {
                operations.push(("denied(uint256)", 0, 3, false));
            }
            for (signature, id, height, success) in operations {
                let mut tx = make_system_tx_to(sender, ledger, input(signature, id, None));
                tx.tx.nonce = nonce;
                tx.tx.gas_limit = 500_000;
                let mut header = sample_header();
                header.number = height;
                let before = vm.state_db_mut().world_state_mut().state_root().unwrap();
                let result = vm.execute_tx(&tx, &header, 0, 0).unwrap();
                assert_eq!(
                    vm.state_db_mut().world_state_mut().state_root().unwrap(),
                    before
                );
                assert_eq!(
                    result.receipt.status,
                    u8::from(success),
                    "{name} {signature} id{id} height{height} activation{activation:?}"
                );
                if success {
                    assert_eq!(result.output, owners[id].as_bytes());
                    if selecting {
                        selections += 1;
                    }
                } else if signature == "denied(uint256)" && activation.is_some() {
                    let mut error = hex::decode(
                        fixture["selectors"]["Missing(uint256)"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                    )
                    .unwrap();
                    error.extend_from_slice(&[0u8; 32]);
                    assert_eq!(result.output, error);
                } else {
                    assert!(result.output.is_empty());
                }
                commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
                nonce += 1;
                let root = vm.state_db_mut().world_state_mut().state_root().unwrap();
                let recovered = WorldState::at_root(store.clone(), &root).unwrap();
                assert_eq!(recovered.get_nonce(&sender).unwrap(), nonce);
                for (id, target) in owners.into_iter().enumerate() {
                    assert_eq!(
                        recovered.get_storage(&ledger, &slot(id)).unwrap(),
                        ShellHash::from(*target.as_bytes())
                    );
                }
                if selecting {
                    assert_eq!(
                        recovered
                            .get_storage(
                                &ledger,
                                &ShellHash::from(U256::from(1).to_be_bytes::<32>())
                            )
                            .unwrap(),
                        ShellHash::from(U256::from(selections).to_be_bytes::<32>())
                    );
                }
                assert_eq!(
                    recovered.get_storage(&writer, &ShellHash::ZERO).unwrap(),
                    ShellHash::ZERO
                );
                assert_eq!(
                    recovered.get_storage(&alias, &ShellHash::ZERO).unwrap(),
                    ShellHash::ZERO
                );
                assert!(recovered.get_account(&missing).unwrap().is_none());
                history.push((root, owners, selections, nonce));
            }
            // Change current receiver; historical calls must still select the old callee.
            let mut tx = make_system_tx_to(
                sender,
                ledger,
                input("set(uint256,address)", 0, Some(second)),
            );
            tx.tx.nonce = nonce;
            tx.tx.gas_limit = 500_000;
            let mut header = sample_header();
            header.number = 3;
            let result = vm.execute_tx(&tx, &header, 0, 0).unwrap();
            assert_eq!(result.receipt.status, 1);
            commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
            assert_eq!(
                vm.state_db()
                    .world_state()
                    .get_storage(&ledger, &slot(0))
                    .unwrap(),
                ShellHash::from(*second.as_bytes())
            );
            let current_root = vm.state_db_mut().world_state_mut().state_root().unwrap();
            let mut current = make_system_tx_to(sender, ledger, input("lookup(uint256)", 0, None));
            current.tx.nonce = nonce + 1;
            current.tx.gas_limit = 500_000;
            let result = vm.execute_tx(&current, &header, 0, 0).unwrap();
            assert_eq!(result.receipt.status, u8::from(activation.is_some()));
            if activation.is_some() {
                assert_eq!(result.output, second.as_bytes());
            }
            assert_eq!(
                vm.state_db_mut().world_state_mut().state_root().unwrap(),
                current_root
            );
            let before = store.scan_prefix(b"").unwrap();
            for (root, owners, count, nonce) in history.into_iter().rev() {
                let world = WorldState::at_root(store.clone(), &root).unwrap();
                assert_eq!(
                    world.get_storage(&ledger, &slot(0)).unwrap(),
                    ShellHash::from(*owners[0].as_bytes())
                );
                if selecting {
                    assert_eq!(
                        world
                            .get_storage(
                                &ledger,
                                &ShellHash::from(U256::from(1).to_be_bytes::<32>())
                            )
                            .unwrap(),
                        ShellHash::from(U256::from(count).to_be_bytes::<32>())
                    );
                }
                let mut historical = ShellPqvm::new(
                    ShellStateDb::new(world, ChainStore::new(store.clone())),
                    1337,
                );
                let mut query =
                    make_system_tx_to(sender, ledger, input("lookup(uint256)", 0, None));
                query.tx.nonce = nonce;
                query.tx.gas_limit = 500_000;
                let result = historical.execute_tx(&query, &header, 0, 0).unwrap();
                assert_eq!(result.receipt.status, u8::from(activation.is_some()));
                if activation.is_some() {
                    assert_eq!(result.output, first.as_bytes());
                }
            }
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
    }
}
