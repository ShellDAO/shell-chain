//! E2E tests for AA batch transaction RPC surface.
//!
//! Tests exercise `shell_estimateBatch` and `shell_sendTransaction` with
//! AA bundle payloads against an in-memory node environment. These are
//! integration tests that verify the complete RPC → mempool → storage path.

use shell_e2e::*;

use shell_core::{
    AaBundle, InnerCall, SignedTransaction, Transaction, AA_BUNDLE_TX_TYPE, MAX_INNER_CALLS,
};
use shell_crypto::Signer;
use shell_primitives::{Address, Bytes, U256};
use shell_rpc::api::ShellApiServer;
use shell_rpc::types::BatchEstimateRequest;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a batch `SignedTransaction` with the given inner calls.
fn make_batch_tx(
    sender: &FundedAccount,
    nonce: u64,
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
        paymaster: None,
        paymaster_signature: None,
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

/// Builds a minimal `InnerCall` transferring `value` to `to`.
fn inner_transfer(to: Address, value: U256) -> InnerCall {
    InnerCall {
        to: Some(to),
        value,
        data: Bytes::default(),
        gas_limit: 21_000,
    }
}

// ---------------------------------------------------------------------------
// 1. shell_estimateBatch — validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn estimate_batch_rejects_empty_inner_calls() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let req = BatchEstimateRequest {
        from: None,
        paymaster: None,
        inner_calls: vec![],
    };
    let err = ShellApiServer::estimate_batch(&env.handler, req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), shell_rpc::error::INVALID_PARAMS);
    assert!(err.message().contains("inner_calls must not be empty"));
}

#[tokio::test]
async fn estimate_batch_rejects_too_many_inner_calls() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let recipient = Address::from([0x02; 20]);
    let inner_calls = (0..=MAX_INNER_CALLS)
        .map(|_| shell_rpc::types::BatchInnerCallRequest {
            to: Some(recipient),
            value: Some("0x0".to_string()),
            data: None,
            gas_limit: Some("0x5208".to_string()),
        })
        .collect();

    let req = BatchEstimateRequest {
        from: None,
        paymaster: None,
        inner_calls,
    };
    let err = ShellApiServer::estimate_batch(&env.handler, req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), shell_rpc::error::INVALID_PARAMS);
    assert!(err.message().contains("MAX_INNER_CALLS"));
}

#[tokio::test]
async fn estimate_batch_rejects_zero_gas_limit() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let recipient = Address::from([0x03; 20]);
    let req = BatchEstimateRequest {
        from: None,
        paymaster: None,
        inner_calls: vec![shell_rpc::types::BatchInnerCallRequest {
            to: Some(recipient),
            value: Some("0x0".to_string()),
            data: None,
            gas_limit: Some("0x0".to_string()),
        }],
    };
    let err = ShellApiServer::estimate_batch(&env.handler, req)
        .await
        .unwrap_err();
    assert_eq!(err.code(), shell_rpc::error::INVALID_PARAMS);
    assert!(err.message().contains("gas_limit must be > 0"));
}

// ---------------------------------------------------------------------------
// 2. shell_estimateBatch — success path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn estimate_batch_single_transfer_returns_gas() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let recipient = Address::from([0x04; 20]);
    let req = BatchEstimateRequest {
        from: None,
        paymaster: None,
        inner_calls: vec![shell_rpc::types::BatchInnerCallRequest {
            to: Some(recipient),
            value: Some("0x0".to_string()),
            data: None,
            gas_limit: Some("0x5208".to_string()), // 21_000
        }],
    };
    let result = ShellApiServer::estimate_batch(&env.handler, req)
        .await
        .unwrap();

    let inner_gas = result["perInner"].as_array().unwrap();
    assert_eq!(inner_gas.len(), 1, "should return one inner_gas entry");

    let total_gas_hex = result["totalGas"].as_str().unwrap();
    let total_gas = u64::from_str_radix(total_gas_hex.trim_start_matches("0x"), 16).unwrap();
    assert!(total_gas >= 21_000, "total_gas should be at least base gas");
}

#[tokio::test]
async fn estimate_batch_multiple_calls_sums_gas() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let r1 = Address::from([0x05; 20]);
    let r2 = Address::from([0x06; 20]);
    let req = BatchEstimateRequest {
        from: None,
        paymaster: None,
        inner_calls: vec![
            shell_rpc::types::BatchInnerCallRequest {
                to: Some(r1),
                value: Some("0x0".to_string()),
                data: None,
                gas_limit: Some("0x5208".to_string()),
            },
            shell_rpc::types::BatchInnerCallRequest {
                to: Some(r2),
                value: Some("0x0".to_string()),
                data: None,
                gas_limit: Some("0x7530".to_string()), // 30_000
            },
        ],
    };
    let result = ShellApiServer::estimate_batch(&env.handler, req)
        .await
        .unwrap();

    let inner_gas = result["perInner"].as_array().unwrap();
    assert_eq!(inner_gas.len(), 2);

    let total_gas_hex = result["totalGas"].as_str().unwrap();
    let total_gas = u64::from_str_radix(total_gas_hex.trim_start_matches("0x"), 16).unwrap();
    // total = sum(inner) + AA_BUNDLE_TX_TYPE * count intrinsic overhead
    assert!(
        total_gas > 21_000 + 30_000,
        "total should exceed sum of inners"
    );
}

// ---------------------------------------------------------------------------
// 3. AA batch tx submission and retrieval
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_batch_tx_and_retrieve_from_mempool() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let recipient = Address::from([0x07; 20]);

    let batch = make_batch_tx(
        &sender,
        0,
        vec![inner_transfer(recipient, U256::from(1_000u64))],
    );
    let batch_hash = batch.hash();

    let hash = ShellApiServer::send_transaction(&env.handler, batch)
        .await
        .unwrap();
    assert_eq!(hash, batch_hash, "returned hash should match tx hash");

    // Tx should be in mempool
    let pool_count = ShellApiServer::pending_count(&env.handler).await.unwrap();
    let count = u64::from_str_radix(pool_count.trim_start_matches("0x"), 16).unwrap();
    assert_eq!(count, 1, "mempool should have 1 pending batch tx");
}

#[tokio::test]
async fn batch_tx_included_in_mined_block_is_retrievable() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let recipient = Address::from([0x08; 20]);

    let batch = make_batch_tx(
        &sender,
        0,
        vec![
            inner_transfer(recipient, U256::from(100u64)),
            inner_transfer(recipient, U256::from(200u64)),
        ],
    );
    let batch_hash = batch.hash();

    // Mine the batch tx into block 1
    let genesis_hash = genesis.hash();
    mine_block(&env, 1, genesis_hash, vec![batch]);

    // Retrieve by hash
    use shell_rpc::api::EthApiServer;
    let rpc_tx = EthApiServer::get_transaction_by_hash(&env.handler, batch_hash)
        .await
        .unwrap()
        .expect("batch tx should be retrievable after mining");

    assert_eq!(rpc_tx.hash, batch_hash, "hash should match");
    assert_eq!(rpc_tx.block_number, Some("0x1".to_string()), "in block 1");
}

#[tokio::test]
async fn batch_tx_receipt_has_correct_fields() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let recipient = Address::from([0x09; 20]);

    let batch = make_batch_tx(
        &sender,
        0,
        vec![inner_transfer(recipient, U256::from(50u64))],
    );
    let batch_hash = batch.hash();

    let genesis_hash = genesis.hash();
    mine_block(&env, 1, genesis_hash, vec![batch]);

    use shell_rpc::api::EthApiServer;
    let receipt = EthApiServer::get_transaction_receipt(&env.handler, batch_hash)
        .await
        .unwrap()
        .expect("receipt should exist");

    assert_eq!(receipt.transaction_hash, batch_hash);
    assert_eq!(receipt.status, "0x1", "should succeed");
    assert_eq!(receipt.block_number, "0x1");
}

// ---------------------------------------------------------------------------
// 4. AA bundle persistence through block storage roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aa_bundle_survives_block_storage_roundtrip() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let r1 = Address::from([0x0a; 20]);
    let r2 = Address::from([0x0b; 20]);

    let inner_calls = vec![
        inner_transfer(r1, U256::from(111u64)),
        inner_transfer(r2, U256::from(222u64)),
    ];
    let expected_count = inner_calls.len();
    let batch = make_batch_tx(&sender, 0, inner_calls);

    let genesis_hash = genesis.hash();
    let block_hash = mine_block(&env, 1, genesis_hash, vec![batch]);

    // Retrieve the block and verify AA bundle is preserved
    let block = env
        .chain_store
        .get_block_by_hash(&block_hash)
        .unwrap()
        .expect("block must be stored");

    let stored_tx = block.transactions.first().expect("block should have a tx");
    let bundle = stored_tx
        .aa_bundle
        .as_ref()
        .expect("aa_bundle must be present");
    assert_eq!(
        bundle.inner_calls.len(),
        expected_count,
        "inner_calls count must survive block storage roundtrip"
    );
}
