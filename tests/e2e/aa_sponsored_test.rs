//! E2E tests for AA sponsored gas (paymaster) RPC surface.
//!
//! Tests exercise `shell_getPaymasterPolicy` and `shell_isSponsored`
//! against an in-memory node environment, verifying the complete
//! RPC → storage query path for paymaster-related functionality.

use shell_e2e::*;

use shell_core::{AaBundle, InnerCall, SignedTransaction, Transaction, AA_BUNDLE_TX_TYPE};
use shell_crypto::Signer;
use shell_primitives::{Address, Bytes, ShellHash, U256};
use shell_rpc::api::ShellApiServer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a sponsored `SignedTransaction` with a paymaster address set.
fn make_sponsored_tx(
    sender: &FundedAccount,
    nonce: u64,
    paymaster: Address,
    inner_calls: Vec<InnerCall>,
) -> SignedTransaction {
    let tx = Transaction {
        chain_id: TEST_CHAIN_ID,
        nonce,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        gas_limit: 200_000,
        to: None,
        value: U256::ZERO,
        data: Bytes::default(),
        access_list: None,
        tx_type: AA_BUNDLE_TX_TYPE,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let bundle = AaBundle {
        inner_calls,
        paymaster: Some(paymaster),
        paymaster_signature: Some(Bytes::from(vec![0xab; 32])),
        ..Default::default()
    };
    // Compute batch_signing_hash by building a placeholder, then sign the correct hash.
    let placeholder_sig = sender.signer.sign(b"placeholder").unwrap();
    let mut temp = SignedTransaction::new(sender.address, tx.clone(), placeholder_sig);
    temp.aa_bundle = Some(bundle.clone());
    let signing_hash = temp
        .batch_signing_hash()
        .expect("AA bundle tx must have batch_signing_hash");
    let sig = sender.signer.sign(signing_hash.0.as_slice()).unwrap();
    let mut signed = SignedTransaction::new(sender.address, tx, sig);
    signed.aa_bundle = Some(bundle);
    signed
}

/// Builds a minimal inner call.
fn inner_call(to: Address) -> InnerCall {
    InnerCall {
        to: Some(to),
        value: U256::ZERO,
        data: Bytes::default(),
        gas_limit: 21_000,
    }
}

// ---------------------------------------------------------------------------
// 1. shell_getPaymasterPolicy — no-policy case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_paymaster_policy_returns_default_eoa_open_when_not_registered() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let unknown_paymaster = Address::from([0x11; 20]);
    let result = ShellApiServer::get_paymaster_policy(&env.handler, unknown_paymaster)
        .await
        .unwrap();

    // Unregistered paymaster returns default EOA-open policy (not null).
    assert!(
        !result.is_null(),
        "unregistered paymaster should return default policy object"
    );
    assert_eq!(
        result["policy"], "eoa-open",
        "default policy should be eoa-open"
    );
    assert_eq!(result["has_pq_pubkey"], false, "no pubkey registered");
}

// ---------------------------------------------------------------------------
// 2. shell_isSponsored — tx not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_sponsored_returns_not_found_for_unknown_tx() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let unknown_hash = ShellHash::from([0xff; 32]);
    let result = ShellApiServer::is_sponsored(&env.handler, unknown_hash)
        .await
        .unwrap();

    assert_eq!(
        result["found"], false,
        "unknown tx should report found=false"
    );
    assert_eq!(result["sponsored"], false);
}

// ---------------------------------------------------------------------------
// 3. shell_isSponsored — non-sponsored tx
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_sponsored_returns_false_for_regular_tx() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let recipient = Address::from([0x12; 20]);

    // Regular (non-AA) transfer
    let tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(100u64));
    let signed = sign_tx(&sender.signer, sender.address, tx);
    let tx_hash = signed.hash();

    let genesis_hash = genesis.hash();
    mine_block(&env, 1, genesis_hash, vec![signed]);

    let result = ShellApiServer::is_sponsored(&env.handler, tx_hash)
        .await
        .unwrap();

    assert_eq!(result["found"], true, "mined tx should be found");
    assert_eq!(
        result["sponsored"], false,
        "regular tx should not be sponsored"
    );
    assert_eq!(result["is_aa_bundle"], false, "regular tx is not AA");
}

// ---------------------------------------------------------------------------
// 4. shell_isSponsored — sponsored AA tx
// ---------------------------------------------------------------------------

#[tokio::test]
async fn is_sponsored_detects_sponsored_aa_tx() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let paymaster = Address::from([0x13; 20]);
    let recipient = Address::from([0x14; 20]);

    let sponsored = make_sponsored_tx(&sender, 0, paymaster, vec![inner_call(recipient)]);
    let tx_hash = sponsored.hash();

    let genesis_hash = genesis.hash();
    mine_block(&env, 1, genesis_hash, vec![sponsored]);

    let result = ShellApiServer::is_sponsored(&env.handler, tx_hash)
        .await
        .unwrap();

    assert_eq!(result["found"], true);
    assert_eq!(
        result["sponsored"], true,
        "AA tx with paymaster should be sponsored"
    );
    assert_eq!(result["is_aa_bundle"], true);
    // paymaster field is present and non-null
    assert!(
        !result["paymaster"].is_null(),
        "paymaster address should be set"
    );
}

// ---------------------------------------------------------------------------
// 5. Sponsored tx survives block storage roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sponsored_tx_paymaster_survives_block_roundtrip() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let paymaster = Address::from([0x15; 20]);
    let recipient = Address::from([0x16; 20]);

    let sponsored = make_sponsored_tx(&sender, 0, paymaster, vec![inner_call(recipient)]);

    let genesis_hash = genesis.hash();
    let block_hash = mine_block(&env, 1, genesis_hash, vec![sponsored]);

    let block = env
        .chain_store
        .get_block_by_hash(&block_hash)
        .unwrap()
        .expect("block must be stored");

    let stored_tx = block.transactions.first().expect("block must have tx");
    let bundle = stored_tx
        .aa_bundle
        .as_ref()
        .expect("aa_bundle must be present");

    assert_eq!(
        bundle.paymaster,
        Some(paymaster),
        "paymaster must survive block storage roundtrip"
    );
}

// ---------------------------------------------------------------------------
// 6. Multiple sponsored txs in one block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiple_sponsored_txs_in_same_block() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender1 = make_funded_account(&env);
    let sender2 = make_funded_account(&env);
    let paymaster = Address::from([0x17; 20]);
    let recipient = Address::from([0x18; 20]);

    let tx1 = make_sponsored_tx(&sender1, 0, paymaster, vec![inner_call(recipient)]);
    let tx2 = make_sponsored_tx(&sender2, 0, paymaster, vec![inner_call(recipient)]);
    let hash1 = tx1.hash();
    let hash2 = tx2.hash();

    let genesis_hash = genesis.hash();
    mine_block(&env, 1, genesis_hash, vec![tx1, tx2]);

    // Both should be detectable as sponsored
    for hash in [hash1, hash2] {
        let result = ShellApiServer::is_sponsored(&env.handler, hash)
            .await
            .unwrap();
        assert_eq!(
            result["sponsored"], true,
            "tx {:?} should be sponsored",
            hash
        );
    }
}
