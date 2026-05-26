mod common;

use alloy_primitives::U256;
use common::{apply_tx, deploy_runtime_contract, fund_account, setup, sign_tx, CHAIN_ID};
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, MultiVerifier, PQSignature, SignatureType, Signer};
use shell_pqvm::{
    account_manager_address, encode_clear_validation_code_calldata,
    encode_set_validation_code_calldata, validate_tx, TxValidationError,
};
use shell_primitives::{Address as ShellAddress, Bytes as ShellBytes};

fn transfer_tx(nonce: u64, to: ShellAddress, value: u64) -> Transaction {
    Transaction {
        chain_id: CHAIN_ID,
        nonce,
        to: Some(to),
        value: U256::from(value),
        data: ShellBytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

fn account_manager_tx(nonce: u64, calldata: Vec<u8>) -> Transaction {
    Transaction {
        chain_id: CHAIN_ID,
        nonce,
        to: Some(account_manager_address()),
        value: U256::ZERO,
        data: ShellBytes::from(calldata),
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

fn default_pq_validator_runtime() -> Vec<u8> {
    hex::decode(include_str!("../../../contracts/DefaultPQValidator.bin-runtime").trim())
        .expect("default validator runtime hex should decode")
}

fn validator_returns_false() -> Vec<u8> {
    vec![0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]
}

fn validator_loops_forever() -> Vec<u8> {
    vec![0x5B, 0x60, 0x00, 0x56]
}

#[test]
fn set_validation_code_allows_custom_validator_and_clear_restores_builtin_rules() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let owner = DilithiumSigner::generate();
    let owner_addr = ShellAddress::from_public_key(owner.public_key(), owner.sig_type().as_u8());
    let receiver = ShellAddress::from([0x33; 20]);

    fund_account(&mut evm, &owner_addr, U256::from(10_000_000_000u64));

    let (_validator_addr, validator_hash) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &owner,
        owner_addr,
        0,
        1,
        &default_pq_validator_runtime(),
    );

    let set_signed = sign_tx(
        owner_addr,
        &owner,
        account_manager_tx(1, encode_set_validation_code_calldata(&validator_hash)),
        false,
    );
    let set_result = apply_tx(&mut evm, &chain_store, &verifier, &set_signed, 2, 0, 0);
    assert_eq!(set_result.receipt.status, 1);
    assert_eq!(
        evm.state_db()
            .world_state()
            .get_account(&owner_addr)
            .unwrap()
            .unwrap()
            .validation_code_hash,
        Some(validator_hash)
    );

    let custom_signed = sign_tx(owner_addr, &owner, transfer_tx(2, receiver, 111), false);
    let custom_result = apply_tx(&mut evm, &chain_store, &verifier, &custom_signed, 3, 0, 0);
    assert_eq!(custom_result.receipt.status, 1);
    assert_eq!(
        evm.state_db().world_state().get_balance(&receiver).unwrap(),
        U256::from(111u64)
    );

    let clear_signed = sign_tx(
        owner_addr,
        &owner,
        account_manager_tx(3, encode_clear_validation_code_calldata()),
        false,
    );
    let clear_result = apply_tx(&mut evm, &chain_store, &verifier, &clear_signed, 4, 0, 0);
    assert_eq!(clear_result.receipt.status, 1);
    assert_eq!(
        evm.state_db()
            .world_state()
            .get_account(&owner_addr)
            .unwrap()
            .unwrap()
            .validation_code_hash,
        None
    );

    let rejected_after_clear = SignedTransaction::new(
        owner_addr,
        transfer_tx(4, receiver, 1),
        PQSignature::new(SignatureType::MlDsa65, vec![0xBB; 64]),
    );
    let rejected_err = validate_tx(
        &rejected_after_clear,
        evm.state_db_mut().world_state_mut(),
        &chain_store,
        &verifier,
        CHAIN_ID,
    )
    .unwrap_err();
    assert!(matches!(rejected_err, TxValidationError::SignatureInvalid));

    let builtin_signed = sign_tx(owner_addr, &owner, transfer_tx(4, receiver, 5), false);
    let builtin_result = apply_tx(&mut evm, &chain_store, &verifier, &builtin_signed, 5, 0, 0);
    assert_eq!(builtin_result.receipt.status, 1);
    assert_eq!(
        evm.state_db().world_state().get_balance(&receiver).unwrap(),
        U256::from(116u64)
    );
}

#[test]
fn custom_validator_false_return_rejects_transaction() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let owner = DilithiumSigner::generate();
    let owner_addr = ShellAddress::from_public_key(owner.public_key(), owner.sig_type().as_u8());
    let receiver = ShellAddress::from([0x44; 20]);

    fund_account(&mut evm, &owner_addr, U256::from(10_000_000_000u64));

    let (_validator_addr, validator_hash) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &owner,
        owner_addr,
        0,
        1,
        &validator_returns_false(),
    );

    let set_signed = sign_tx(
        owner_addr,
        &owner,
        account_manager_tx(1, encode_set_validation_code_calldata(&validator_hash)),
        false,
    );
    apply_tx(&mut evm, &chain_store, &verifier, &set_signed, 2, 0, 0);

    let failing_signed = SignedTransaction::new(
        owner_addr,
        transfer_tx(2, receiver, 1),
        PQSignature::new(SignatureType::MlDsa65, vec![0xCC; 64]),
    );
    let err = validate_tx(
        &failing_signed,
        evm.state_db_mut().world_state_mut(),
        &chain_store,
        &verifier,
        CHAIN_ID,
    )
    .unwrap_err();
    match err {
        TxValidationError::AaValidation(msg) => {
            assert!(msg.contains("unexpected return"), "unexpected error: {msg}");
        }
        other => panic!("expected AaValidation error, got {other:?}"),
    }
}

#[test]
fn custom_validator_gas_cap_rejects_transaction() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let owner = DilithiumSigner::generate();
    let owner_addr = ShellAddress::from_public_key(owner.public_key(), owner.sig_type().as_u8());
    let receiver = ShellAddress::from([0x55; 20]);

    fund_account(&mut evm, &owner_addr, U256::from(10_000_000_000u64));

    let (_validator_addr, validator_hash) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &owner,
        owner_addr,
        0,
        1,
        &validator_loops_forever(),
    );

    let set_signed = sign_tx(
        owner_addr,
        &owner,
        account_manager_tx(1, encode_set_validation_code_calldata(&validator_hash)),
        false,
    );
    apply_tx(&mut evm, &chain_store, &verifier, &set_signed, 2, 0, 0);

    let failing_signed = SignedTransaction::new(
        owner_addr,
        transfer_tx(2, receiver, 1),
        PQSignature::new(SignatureType::MlDsa65, vec![0xDD; 64]),
    );
    let err = validate_tx(
        &failing_signed,
        evm.state_db_mut().world_state_mut(),
        &chain_store,
        &verifier,
        CHAIN_ID,
    )
    .unwrap_err();
    match err {
        TxValidationError::AaValidation(msg) => {
            assert!(
                msg.contains("halted") || msg.contains("OutOfGas"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected AaValidation error, got {other:?}"),
    }
}
