mod common;

use alloy_primitives::U256;
use common::{apply_tx, fund_account, setup, sign_tx, CHAIN_ID};
use shell_core::Transaction;
use shell_crypto::{DilithiumSigner, MultiVerifier, Signer, SphincsSigner};
use shell_pqvm::{
    account_manager_address, encode_rotate_key_calldata, validate_tx, TxValidationError,
};
use shell_primitives::{blake3_hash, Address as ShellAddress, Bytes as ShellBytes};

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

fn rotate_key_tx(nonce: u64, pubkey: &[u8], algo_id: u8) -> Transaction {
    Transaction {
        chain_id: CHAIN_ID,
        nonce,
        to: Some(account_manager_address()),
        value: U256::ZERO,
        data: ShellBytes::from(encode_rotate_key_calldata(pubkey, algo_id)),
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

#[test]
fn rotate_key_same_algorithm_accepts_new_signer_and_rejects_old_one() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let old_signer = DilithiumSigner::generate();
    let new_signer = DilithiumSigner::generate();
    let from =
        ShellAddress::from_public_key(old_signer.public_key(), old_signer.sig_type().as_u8());
    let receiver = ShellAddress::from([0x11; 20]);

    fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

    let rotate_signed = sign_tx(
        from,
        &old_signer,
        rotate_key_tx(0, new_signer.public_key(), new_signer.sig_type().as_u8()),
        true,
    );
    let rotate_result = apply_tx(&mut evm, &chain_store, &verifier, &rotate_signed, 1, 0, 0);
    assert_eq!(rotate_result.receipt.status, 1);

    let account = evm
        .state_db()
        .world_state()
        .get_account(&from)
        .unwrap()
        .unwrap();
    assert_eq!(account.pq_pubkey_hash, blake3_hash(new_signer.public_key()));
    assert_eq!(account.nonce, 1);
    assert_eq!(
        chain_store.get_pubkey(&from).unwrap().unwrap(),
        new_signer.public_key()
    );

    let stale_signed = sign_tx(from, &old_signer, transfer_tx(1, receiver, 1), true);
    let stale_err = validate_tx(
        &stale_signed,
        evm.state_db_mut().world_state_mut(),
        &chain_store,
        &verifier,
        CHAIN_ID,
    )
    .unwrap_err();
    assert!(matches!(stale_err, TxValidationError::PubkeyConflict));

    let rotated_signed = sign_tx(from, &new_signer, transfer_tx(1, receiver, 7), false);
    let rotated_result = apply_tx(&mut evm, &chain_store, &verifier, &rotated_signed, 2, 0, 0);
    assert_eq!(rotated_result.receipt.status, 1);
    assert_eq!(
        evm.state_db().world_state().get_balance(&receiver).unwrap(),
        U256::from(7u64)
    );
}

#[test]
fn rotate_key_cross_algorithm_to_sphincs_preserves_address() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let old_signer = DilithiumSigner::generate();
    let new_signer = SphincsSigner::generate();
    let from =
        ShellAddress::from_public_key(old_signer.public_key(), old_signer.sig_type().as_u8());
    let receiver = ShellAddress::from([0x22; 20]);

    fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

    let rotate_signed = sign_tx(
        from,
        &old_signer,
        rotate_key_tx(0, new_signer.public_key(), new_signer.sig_type().as_u8()),
        true,
    );
    let rotate_result = apply_tx(&mut evm, &chain_store, &verifier, &rotate_signed, 1, 0, 0);
    assert_eq!(rotate_result.receipt.status, 1);

    let account = evm
        .state_db()
        .world_state()
        .get_account(&from)
        .unwrap()
        .unwrap();
    assert_eq!(account.pq_pubkey_hash, blake3_hash(new_signer.public_key()));
    assert_eq!(
        chain_store.get_pubkey(&from).unwrap().unwrap(),
        new_signer.public_key()
    );

    let stale_signed = sign_tx(from, &old_signer, transfer_tx(1, receiver, 1), true);
    let stale_err = validate_tx(
        &stale_signed,
        evm.state_db_mut().world_state_mut(),
        &chain_store,
        &verifier,
        CHAIN_ID,
    )
    .unwrap_err();
    assert!(matches!(stale_err, TxValidationError::PubkeyConflict));

    let rotated_signed = sign_tx(from, &new_signer, transfer_tx(1, receiver, 9), false);
    let rotated_result = apply_tx(&mut evm, &chain_store, &verifier, &rotated_signed, 2, 0, 0);
    assert_eq!(rotated_result.receipt.status, 1);
    assert_eq!(
        evm.state_db().world_state().get_balance(&receiver).unwrap(),
        U256::from(9u64)
    );
}

#[test]
fn rotate_key_cannot_mutate_other_accounts() {
    let (mut evm, chain_store) = setup();
    let verifier = MultiVerifier;

    let victim = DilithiumSigner::generate();
    let attacker = DilithiumSigner::generate();
    let replacement = DilithiumSigner::generate();
    let victim_addr = ShellAddress::from_public_key(victim.public_key(), victim.sig_type().as_u8());
    let attacker_addr =
        ShellAddress::from_public_key(attacker.public_key(), attacker.sig_type().as_u8());

    fund_account(&mut evm, &victim_addr, U256::from(10_000_000_000u64));
    fund_account(&mut evm, &attacker_addr, U256::from(10_000_000_000u64));

    let mut victim_account = evm
        .state_db()
        .world_state()
        .get_account(&victim_addr)
        .unwrap()
        .unwrap();
    victim_account.pq_pubkey_hash = blake3_hash(victim.public_key());
    evm.state_db_mut()
        .world_state_mut()
        .set_account(&victim_addr, &victim_account)
        .unwrap();
    chain_store
        .put_pubkey(&victim_addr, victim.public_key())
        .unwrap();

    let attack_signed = sign_tx(
        attacker_addr,
        &attacker,
        rotate_key_tx(0, replacement.public_key(), replacement.sig_type().as_u8()),
        true,
    );
    let attack_result = apply_tx(&mut evm, &chain_store, &verifier, &attack_signed, 1, 0, 0);
    assert_eq!(attack_result.receipt.status, 1);

    let victim_after = evm
        .state_db()
        .world_state()
        .get_account(&victim_addr)
        .unwrap()
        .unwrap();
    assert_eq!(
        victim_after.pq_pubkey_hash,
        blake3_hash(victim.public_key())
    );
    assert_eq!(
        chain_store.get_pubkey(&victim_addr).unwrap().unwrap(),
        victim.public_key()
    );

    let attacker_after = evm
        .state_db()
        .world_state()
        .get_account(&attacker_addr)
        .unwrap()
        .unwrap();
    assert_eq!(
        attacker_after.pq_pubkey_hash,
        blake3_hash(replacement.public_key())
    );
}
