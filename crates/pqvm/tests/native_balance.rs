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

// Regenerate with shell-sdk's compile-native-balance-fixture.mjs after npm run build.
#[test]
fn native_typed_calls_preserve_full_word_results_identities_and_rollback() {
    for reader_contract in [
        "Reader",
        "PureReader",
        "PureAddressReader",
        "PureBytesReader",
    ] {
        check_native_balance_reader(reader_contract);
    }
}

fn check_native_balance_reader(reader_contract: &str) {
    for activation in [None, Some(2u64)] {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/native-balance.json")).unwrap();
        let store = Arc::new(MemoryDb::new());
        let mut vm = ShellPqvm::new(
            ShellStateDb::new(
                WorldState::new(store.clone()),
                ChainStore::new(store.clone()),
            ),
            1337,
        );
        let sender = ShellAddress::from([0x42; 32]);
        let reader = ShellAddress::from([0x43; 32]);
        let wide = |high: u8, low: u8| {
            let mut word = [low; 32];
            word[..12].fill(high);
            ShellAddress::from(word)
        };
        let first = wide(0x34, 0x12);
        let second = wide(0x56, 0x12);
        let alias = wide(0, 0x12);
        let owner = wide(0x78, 0x23);
        let other_owner = wide(0x9a, 0x23);
        let owner_alias = wide(0, 0x23);
        let writer = ShellAddress::from([0x67; 32]);
        let short = ShellAddress::from([0x68; 32]);
        let missing = ShellAddress::from([0x69; 32]);
        let slot = |key: ShellAddress| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.extend_from_slice(&[0u8; 32]);
            shell_primitives::keccak256(&bytes)
        };
        // Address/bytes32 results deliberately collide in their low 20 bytes.
        // Expected words come from independently initialized storage.
        let word_result = matches!(reader_contract, "PureAddressReader" | "PureBytesReader");
        let first_balance = if word_result {
            U256::from_be_bytes(*first.as_bytes())
        } else {
            U256::MAX
        };
        let large = if word_result {
            U256::from_be_bytes(*second.as_bytes())
        } else {
            U256::from(1u64) << 200usize | U256::from(73u64)
        };
        let balances = [
            (first, owner, first_balance),
            (first, other_owner, large),
            (second, owner, U256::from(19u64)),
            (second, other_owner, U256::ZERO),
            (first, owner_alias, U256::from(666u64)),
        ];
        for (address, code) in [
            (
                reader,
                hex::decode(
                    fixture["artifacts"][reader_contract]["deployedBytecode"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap(),
            ),
            (
                first,
                hex::decode(
                    fixture["artifacts"]["Token"]["deployedBytecode"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap(),
            ),
            (
                second,
                hex::decode(
                    fixture["artifacts"]["Token"]["deployedBytecode"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap(),
            ),
            (
                writer,
                hex::decode(
                    fixture["artifacts"]["Writer"]["deployedBytecode"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap(),
            ),
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
        for (token, account, balance) in balances {
            vm.state_db_mut()
                .world_state_mut()
                .set_storage(
                    &token,
                    &slot(account),
                    &ShellHash::from(balance.to_be_bytes::<32>()),
                )
                .unwrap();
        }
        vm.state_db_mut()
            .world_state_mut()
            .set_account(
                &sender,
                &Account::new_user_account(ShellHash::ZERO, U256::from(10_000_000u64)),
            )
            .unwrap();
        let config = serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":ShellHash::ZERO,"native_address_context_height":activation})).unwrap();
        vm.state_db()
            .chain_store()
            .put_chain_config(&config)
            .unwrap();
        let cases = [
            (1, first, owner, false, false, U256::ZERO, 0u64),
            (2, first, owner, false, true, first_balance, 0),
            (3, first, other_owner, false, true, large, 0),
            (4, second, owner, false, true, U256::from(19u64), 0),
            (5, second, other_owner, false, true, U256::ZERO, 0),
            (6, first, owner, true, true, first_balance, 1),
            (7, first, ShellAddress::ZERO, true, false, U256::ZERO, 1),
            (8, writer, owner_alias, true, false, U256::ZERO, 1),
            (9, short, owner, true, false, U256::ZERO, 1),
            (10, missing, owner, true, false, U256::ZERO, 1),
            (11, second, other_owner, true, true, U256::ZERO, 2),
            (12, first, owner_alias, false, true, U256::from(666u64), 2),
            (13, alias, owner, true, false, U256::ZERO, 2),
        ];
        for (nonce, (height, target, account, record, success, balance, counter)) in
            cases.into_iter().enumerate()
        {
            let mut header = sample_header();
            header.number = height;
            let signature = if record {
                "record(address,address)"
            } else {
                "lookup(address,address)"
            };
            let mut data = hex::decode(
                fixture["selectors"][signature]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            data.extend_from_slice(target.as_bytes());
            data.extend_from_slice(account.as_bytes());
            let mut tx = make_system_tx_to(sender, reader, data);
            tx.tx.nonce = nonce as u64;
            tx.tx.gas_limit = 500_000;
            let before = vm.state_db_mut().world_state_mut().state_root().unwrap();
            if activation.is_some() && height == 8 {
                // The identical calldata succeeds under CALL. Its failure below
                // therefore exercises STATICCALL's write rule, not ABI decoding.
                let mut input = hex::decode(
                    fixture["selectors"]["balanceOf(address)"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap();
                input.extend_from_slice(account.as_bytes());
                let mut direct = make_system_tx_to(sender, writer, input);
                direct.tx.nonce = nonce as u64;
                let control = vm.execute_tx(&direct, &header, 0, 0).unwrap();
                assert_eq!(control.receipt.status, 1);
                assert_eq!(control.output, U256::from(99u64).to_be_bytes::<32>());
                assert_eq!(
                    vm.state_db_mut().world_state_mut().state_root().unwrap(),
                    before
                );
            }
            let result = vm.execute_tx(&tx, &header, 0, 0).unwrap();
            assert_eq!(
                vm.state_db_mut().world_state_mut().state_root().unwrap(),
                before,
                "uncommitted simulation must not write live state"
            );
            let enabled = activation.is_some_and(|start| height >= start);
            assert_eq!(
                result.receipt.status,
                u8::from(enabled && success),
                "height{height} activation{activation:?}"
            );
            if enabled && success {
                assert_eq!(
                    result.output,
                    balance.to_be_bytes::<32>(),
                    "full-word result {reader_contract} height{height}"
                );
            } else if enabled && height == 7 {
                let mut denied = hex::decode(
                    fixture["selectors"]["Missing(address)"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap();
                denied.extend_from_slice(ShellAddress::ZERO.as_bytes());
                assert_eq!(result.output, denied);
            } else {
                assert!(result.output.is_empty(), "unexpected revert height{height}");
            }
            commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
            let root = vm.state_db_mut().world_state_mut().state_root().unwrap();
            let recovered = WorldState::at_root(store.clone(), &root).unwrap();
            assert_eq!(recovered.get_nonce(&sender).unwrap(), nonce as u64 + 1);
            assert_eq!(
                recovered.get_storage(&reader, &ShellHash::ZERO).unwrap(),
                ShellHash::from(
                    U256::from(if activation.is_some() { counter } else { 0 }).to_be_bytes::<32>()
                )
            );
            for (token, account, balance) in balances {
                assert_eq!(
                    recovered.get_storage(&token, &slot(account)).unwrap(),
                    ShellHash::from(balance.to_be_bytes::<32>())
                );
            }
            for untouched in [writer, alias] {
                assert_eq!(
                    recovered.get_storage(&untouched, &ShellHash::ZERO).unwrap(),
                    ShellHash::ZERO
                );
            }
            assert!(recovered.get_account(&missing).unwrap().is_none());
            assert!(recovered.get_account(&owner_alias).unwrap().is_none());
        }
    }
}

// Regenerate with shell-sdk's compile-native-struct-fixture.mjs after npm run build.
#[test]
fn native_struct_members_preserve_full_words_and_committed_history() {
    use shell_storage::KvStore;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-struct.json")).unwrap();
    for artifact in ["original", "nested"] {
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
            let mut first = [0x12; 32];
            first[..12].fill(0x34);
            let mut second = first;
            second[..12].fill(0x56);
            let first = U256::from_be_bytes(first);
            let second = U256::from_be_bytes(second);
            let nested = artifact == "nested";
            let max = if nested {
                (U256::from(1) << 96usize) - U256::from(1)
            } else {
                U256::MAX
            };
            let code = hex::decode(
                fixture["artifacts"][artifact]["deployedBytecode"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            vm.state_db_mut()
                .world_state_mut()
                .set_account(
                    &ledger,
                    &Account {
                        code_hash: Some(shell_primitives::keccak256(&code)),
                        ..Account::new_user_account(ShellHash::ZERO, U256::ZERO)
                    },
                )
                .unwrap();
            vm.state_db()
                .chain_store()
                .put_code(&shell_primitives::keccak256(&code), &code)
                .unwrap();
            vm.state_db_mut()
                .world_state_mut()
                .set_account(
                    &sender,
                    &Account::new_user_account(ShellHash::ZERO, U256::from(10_000_000u64)),
                )
                .unwrap();
            vm.state_db().chain_store().put_chain_config(&serde_json::from_value(serde_json::json!({
                "chain_id":1337,"genesis_hash":ShellHash::ZERO,"native_address_context_height":activation
            })).unwrap()).unwrap();
            let set = if nested {
                "set(uint256,address,uint96,address)"
            } else {
                "set(uint256,address,uint256)"
            };
            let words = |id, owner, amount, backup| {
                let mut values = vec![id, owner, amount];
                if nested {
                    values.push(backup);
                }
                values
            };
            let mut operations = vec![
                (set, words(U256::ZERO, first, max, second), false, true),
                (
                    set,
                    words(U256::from(1), second, U256::from(19), first),
                    false,
                    true,
                ),
                ("get(uint256)", vec![U256::ZERO], false, true),
                (
                    if nested {
                        "update(uint256,address,uint96)"
                    } else {
                        set
                    },
                    vec![U256::ZERO, second, U256::ZERO],
                    false,
                    true,
                ),
                ("get(uint256)", vec![U256::from(1)], false, true),
                (set, words(U256::ZERO, first, max, first), true, false),
            ];
            if nested {
                operations.push((
                    set,
                    words(U256::ZERO, first, U256::from(1) << 96usize, first),
                    false,
                    false,
                ));
            }
            operations.extend([
                ("get(uint256)", vec![U256::ZERO], false, true),
                ("get(uint256)", vec![U256::MAX], false, true),
            ]);
            let zero = [U256::ZERO; 3];
            let mut expected_zero = zero;
            let mut expected_one = zero;
            let mut history = Vec::new();
            let slot = |id: U256, offset: usize| {
                let mut key = id.to_be_bytes::<32>().to_vec();
                key.extend_from_slice(&[0u8; 32]);
                let base = U256::from_be_bytes(*shell_primitives::keccak256(&key).as_bytes());
                ShellHash::from((base + U256::from(offset)).to_be_bytes::<32>())
            };
            for (nonce, (signature, values, short, success)) in operations.into_iter().enumerate() {
                let mut input = hex::decode(
                    fixture["selectors"][signature]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap();
                for word in &values {
                    input.extend_from_slice(&word.to_be_bytes::<32>());
                }
                if short {
                    input.pop();
                }
                let mut tx = make_system_tx_to(sender, ledger, input);
                tx.tx.nonce = nonce as u64;
                tx.tx.gas_limit = 500_000;
                let mut header = sample_header();
                header.number = nonce as u64 + 1;
                let before = vm.state_db_mut().world_state_mut().state_root().unwrap();
                let result = vm.execute_tx(&tx, &header, 0, 0).unwrap();
                assert_eq!(
                    vm.state_db_mut().world_state_mut().state_root().unwrap(),
                    before
                );
                assert_eq!(
                    result.receipt.status,
                    u8::from(success),
                    "{artifact} nonce{nonce} activation{activation:?}"
                );
                if nonce == 0 {
                    expected_zero = [first, max, if nested { second } else { U256::ZERO }];
                }
                if nonce == 1 {
                    expected_one = [
                        second,
                        U256::from(19),
                        if nested { first } else { U256::ZERO },
                    ];
                }
                if nonce == 3 {
                    expected_zero = [second, U256::ZERO, if nested { second } else { U256::ZERO }];
                }
                if signature == "get(uint256)" {
                    let expected = if values[0] == U256::ZERO {
                        expected_zero
                    } else if values[0] == U256::from(1) {
                        expected_one
                    } else {
                        zero
                    };
                    let output = expected[..if nested { 3 } else { 2 }]
                        .iter()
                        .flat_map(|value| value.to_be_bytes::<32>())
                        .collect::<Vec<_>>();
                    assert_eq!(result.output, output);
                }
                commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
                let root = vm.state_db_mut().world_state_mut().state_root().unwrap();
                let recovered = WorldState::at_root(store.clone(), &root).unwrap();
                assert_eq!(recovered.get_nonce(&sender).unwrap(), nonce as u64 + 1);
                for (id, expected) in [(U256::ZERO, expected_zero), (U256::from(1), expected_one)] {
                    for (offset, value) in expected[..if nested { 3 } else { 2 }].iter().enumerate()
                    {
                        assert_eq!(
                            recovered.get_storage(&ledger, &slot(id, offset)).unwrap(),
                            ShellHash::from(value.to_be_bytes::<32>())
                        );
                    }
                }
                history.push((root, expected_zero, expected_one));
            }
            let before = store.scan_prefix(b"").unwrap();
            for (root, expected_zero, expected_one) in history.into_iter().rev() {
                let historical = WorldState::at_root(store.clone(), &root).unwrap();
                for (id, expected) in [(U256::ZERO, expected_zero), (U256::from(1), expected_one)] {
                    for (offset, value) in expected[..if nested { 3 } else { 2 }].iter().enumerate()
                    {
                        assert_eq!(
                            historical.get_storage(&ledger, &slot(id, offset)).unwrap(),
                            ShellHash::from(value.to_be_bytes::<32>())
                        );
                    }
                }
            }
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
    }
}

// Regenerate with: compile-native-balance-fixture.mjs <output.json> struct.
#[test]
fn native_struct_argument_preserves_full_identity_balance_and_history() {
    use shell_storage::KvStore;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-struct-argument.json")).unwrap();
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
            let wide = |high: u8, low: u8| {
                let mut word = [low; 32];
                word[..12].fill(high);
                ShellAddress::from(word)
            };
            let first = wide(0x34, 0x12);
            let second = wide(0x56, 0x12);
            let alias = wide(0, 0x12);
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
                (first, runtime("Token")),
                (second, runtime("Token")),
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
            let slot = |id: usize, offset: usize| {
                let mut key = U256::from(id).to_be_bytes::<32>().to_vec();
                key.extend_from_slice(&[0u8; 32]);
                ShellHash::from(
                    (U256::from_be_bytes(*shell_primitives::keccak256(&key).as_bytes())
                        + U256::from(offset))
                    .to_be_bytes::<32>(),
                )
            };
            let input =
                |signature: &str, id: usize, target: Option<(ShellAddress, ShellAddress)>| {
                    let mut data = hex::decode(
                        fixture["selectors"][signature]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                    )
                    .unwrap();
                    data.extend_from_slice(&U256::from(id).to_be_bytes::<32>());
                    if let Some((token, beneficiary)) = target {
                        data.extend_from_slice(token.as_bytes());
                        data.extend_from_slice(beneficiary.as_bytes());
                    }
                    data
                };
            let selecting = name == "SelectingLedger";
            let beneficiary = wide(0x78, 0x23);
            let other = wide(0x9a, 0x23);
            let beneficiary_alias = wide(0, 0x23);
            let large = (U256::from(1) << 200usize) | U256::from(73);
            let balance_slot = |owner: ShellAddress| {
                let mut key = owner.as_bytes().to_vec();
                key.extend_from_slice(&[0u8; 32]);
                shell_primitives::keccak256(&key)
            };
            for (token, owner, value) in [
                (first, beneficiary, U256::MAX),
                (first, other, large),
                (second, beneficiary, U256::from(19)),
                (second, other, U256::ZERO),
                (first, beneficiary_alias, U256::from(666)),
            ] {
                vm.state_db_mut()
                    .world_state_mut()
                    .set_storage(
                        &token,
                        &balance_slot(owner),
                        &ShellHash::from(value.to_be_bytes::<32>()),
                    )
                    .unwrap();
            }
            let mut owners = [(ShellAddress::ZERO, ShellAddress::ZERO); 8];
            let mut selections = 0u64;
            let mut history = Vec::new();
            let mut nonce = 0u64;
            // Setup uses the public setter and therefore verifies the stored full target.
            for (id, target) in [
                (first, beneficiary),
                (first, other),
                (second, beneficiary),
                (second, other),
                (writer, beneficiary),
                (short, beneficiary),
                (missing, beneficiary),
                (first, ShellAddress::ZERO),
            ]
            .into_iter()
            .enumerate()
            {
                let mut tx = make_system_tx_to(
                    sender,
                    ledger,
                    input("set(uint256,address,address)", id, Some(target)),
                );
                tx.tx.nonce = nonce;
                tx.tx.gas_limit = 500_000;
                let result = vm.execute_tx(&tx, &sample_header(), 0, 0).unwrap();
                assert_eq!(result.receipt.status, 1);
                commit_pqvm_state(&result, vm.state_db_mut()).unwrap();
                owners[id] = target;
                nonce += 1;
            }
            // Positive normal CALL control: Writer accepts the full-width word
            // and performs SSTORE. The following interface calls must be static.
            let mut data = hex::decode(
                fixture["selectors"]["balanceOf(address)"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            data.extend_from_slice(beneficiary.as_bytes());
            let mut control = make_system_tx_to(sender, writer, data);
            control.tx.nonce = nonce;
            control.tx.gas_limit = 500_000;
            let root = vm.state_db_mut().world_state_mut().state_root().unwrap();
            let result = vm.execute_tx(&control, &sample_header(), 0, 0).unwrap();
            assert_eq!(result.receipt.status, 1);
            assert_eq!(result.output, U256::from(99).to_be_bytes::<32>());
            assert!(result.state_changes.values().any(|account| account
                .storage
                .get(&U256::ZERO)
                .is_some_and(
                    |slot| slot.present_value.to_be_bytes::<32>() == *beneficiary.as_bytes()
                )));

            assert_eq!(
                vm.state_db_mut().world_state_mut().state_root().unwrap(),
                root
            );
            let initial = vm.state_db_mut().world_state_mut().state_root().unwrap();
            history.push((initial, owners, selections, nonce));
            let operations = [
                ("lookup(uint256)", 0usize, 1u64, false),
                ("lookup(uint256)", 0, 2, activation.is_some()),
                ("lookup(uint256)", 0, 3, activation.is_some()),
                ("lookup(uint256)", 1, 3, activation.is_some()),
                ("lookup(uint256)", 2, 3, activation.is_some()),
                ("lookup(uint256)", 3, 3, activation.is_some()),
                ("lookup(uint256)", 4, 3, false),
                ("lookup(uint256)", 5, 3, false),
                ("lookup(uint256)", 6, 3, false),
                ("lookup(uint256)", 7, 3, false),
                ("lookup(uint256)", 8, 3, false),
            ];
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
                    assert_eq!(
                        result.output,
                        [U256::MAX, large, U256::from(19), U256::ZERO][id].to_be_bytes::<32>()
                    );
                    if selecting {
                        selections += 1;
                    }
                } else if id == 7 && activation.is_some() {
                    let mut error = hex::decode(
                        fixture["selectors"]["Missing(address)"]
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
                for (id, (token, beneficiary)) in owners.into_iter().enumerate() {
                    assert_eq!(
                        recovered.get_storage(&ledger, &slot(id, 0)).unwrap(),
                        ShellHash::from(*token.as_bytes())
                    );
                    assert_eq!(
                        recovered.get_storage(&ledger, &slot(id, 1)).unwrap(),
                        ShellHash::from(*beneficiary.as_bytes())
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
            // Change the current argument; historical calls must retain the old balance.
            let mut tx = make_system_tx_to(
                sender,
                ledger,
                input("set(uint256,address,address)", 0, Some((first, other))),
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
                    .get_storage(&ledger, &slot(0, 1))
                    .unwrap(),
                ShellHash::from(*other.as_bytes())
            );
            let current_root = vm.state_db_mut().world_state_mut().state_root().unwrap();
            let mut current = make_system_tx_to(sender, ledger, input("lookup(uint256)", 0, None));
            current.tx.nonce = nonce + 1;
            current.tx.gas_limit = 500_000;
            let result = vm.execute_tx(&current, &header, 0, 0).unwrap();
            assert_eq!(result.receipt.status, u8::from(activation.is_some()));
            if activation.is_some() {
                assert_eq!(result.output, large.to_be_bytes::<32>());
            }
            assert_eq!(
                vm.state_db_mut().world_state_mut().state_root().unwrap(),
                current_root
            );
            let before = store.scan_prefix(b"").unwrap();
            for (root, owners, count, nonce) in history.into_iter().rev() {
                let world = WorldState::at_root(store.clone(), &root).unwrap();
                assert_eq!(
                    world.get_storage(&ledger, &slot(0, 1)).unwrap(),
                    ShellHash::from(*owners[0].1.as_bytes())
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
                    assert_eq!(result.output, U256::MAX.to_be_bytes::<32>());
                }
            }
            assert_eq!(store.scan_prefix(b"").unwrap(), before);
        }
    }
}
