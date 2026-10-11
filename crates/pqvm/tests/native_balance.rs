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
