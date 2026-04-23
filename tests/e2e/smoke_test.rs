//! E2E Smoke Test — verifies core RPC operations against an in-memory node.
//!
//! Exercises: eth_blockNumber, net_version, web3_clientVersion,
//! transaction submission, receipt retrieval, balance queries,
//! and block production.

use shell_e2e::*;

use hex::FromHex;
use shell_primitives::{Address, U256};
use shell_rpc::api::{EthApiServer, NetApiServer, ShellApiServer, Web3ApiServer};

// ---------------------------------------------------------------------------
// 1. RPC liveness checks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rpc_block_number_starts_at_zero() {
    let env = setup();
    let result = EthApiServer::block_number(&env.handler).await.unwrap();
    assert_eq!(result, "0x0");
}

#[tokio::test]
async fn rpc_net_version_returns_chain_id() {
    let env = setup();
    let result = NetApiServer::version(&env.handler).await.unwrap();
    assert_eq!(result, TEST_CHAIN_ID.to_string());
}

#[tokio::test]
async fn rpc_web3_client_version() {
    let env = setup();
    let result = Web3ApiServer::client_version(&env.handler).await.unwrap();
    assert!(!result.is_empty(), "client version must not be empty");
    assert!(
        result.contains("shell"),
        "client version should contain 'shell', got: {result}"
    );
}

// ---------------------------------------------------------------------------
// 2. Transaction submission and inclusion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_transaction_and_verify_receipt() {
    let env = setup();

    // Store genesis so the handler has a head block
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    // Create and fund a sender account
    let sender = make_funded_account(&env);
    let recipient = Address::from([0x01; 20]);

    // Build, sign, and submit a transfer
    let tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(1_000u64));
    let signed = sign_tx(&sender.signer, sender.address, tx);
    let tx_hash = signed.hash();

    let returned_hash = ShellApiServer::send_transaction(&env.handler, signed.clone())
        .await
        .unwrap();
    assert_eq!(returned_hash, tx_hash);

    // Verify the transaction is in the mempool
    let pending = ShellApiServer::pending_count(&env.handler).await.unwrap();
    assert_eq!(pending, "0x1");

    // Mine a block containing the transaction
    let block_hash = mine_block(&env, 1, genesis.hash(), vec![signed]);

    // Verify receipt is retrievable
    let receipt = EthApiServer::get_transaction_receipt(&env.handler, tx_hash)
        .await
        .unwrap();
    assert!(receipt.is_some(), "receipt should exist after mining");

    let receipt = receipt.unwrap();
    assert_eq!(receipt.block_number, "0x1");
    assert_eq!(receipt.status, "0x1"); // success

    // Verify block is queryable by hash
    let block = EthApiServer::get_block_by_hash(&env.handler, block_hash, false)
        .await
        .unwrap();
    assert!(block.is_some(), "block should exist after mining");
}

#[tokio::test]
async fn submit_sdk_dilithium3_fixture_and_verify_receipt() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let pubkey = Vec::from_hex(
        include_str!("../../crates/rpc/tests/fixtures/sdk_dilithium3_tx_pubkey.hex").trim(),
    )
    .expect("failed to decode sdk_dilithium3_tx_pubkey.hex fixture");
    let signature_bytes = Vec::from_hex(
        include_str!("../../crates/rpc/tests/fixtures/sdk_dilithium3_tx_signature.hex").trim(),
    )
    .expect("failed to decode sdk_dilithium3_tx_signature.hex fixture");
    let from = Address::from_public_key(&pubkey, 0);

    {
        let mut ws = env.world_state.write();
        ws.add_balance(&from, U256::from(FUNDED_BALANCE)).unwrap();
    }

    let tx = shell_core::Transaction {
        chain_id: TEST_CHAIN_ID,
        nonce: 0,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        gas_limit: 21_000,
        to: Some(from),
        value: U256::from(1u64),
        data: shell_primitives::Bytes::default(),
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    let signature =
        shell_crypto::PQSignature::new(shell_crypto::SignatureType::Dilithium3, signature_bytes);
    let payload = serde_json::json!({
        "from": from,
        "tx": tx,
        "signature": signature,
        "sender_pubkey": pubkey,
    });
    let tx_hash = EthApiServer::send_raw_transaction(
        &env.handler,
        format!("0x{}", hex::encode(serde_json::to_vec(&payload).unwrap())),
    )
    .await
    .unwrap();

    assert_eq!(
        ShellApiServer::pending_count(&env.handler).await.unwrap(),
        "0x1"
    );

    let signed = env
        .tx_pool
        .get(&tx_hash)
        .expect("fixture transaction accepted into mempool");
    let block_hash = mine_block(&env, 1, genesis.hash(), vec![signed]);

    let receipt = EthApiServer::get_transaction_receipt(&env.handler, tx_hash)
        .await
        .unwrap()
        .expect("fixture transaction receipt should exist after mining");
    assert_eq!(receipt.block_number, "0x1");
    assert_eq!(receipt.status, "0x1");

    let block = EthApiServer::get_block_by_hash(&env.handler, block_hash, false)
        .await
        .unwrap()
        .expect("mined block should be queryable");
    assert_eq!(block.number, "0x1");
}

// ---------------------------------------------------------------------------
// 3. Balance queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_balance_unfunded_is_zero() {
    let env = setup();
    let addr = Address::from([0xAA; 20]);
    let bal = EthApiServer::get_balance(&env.handler, addr, None)
        .await
        .unwrap();
    assert_eq!(bal, "0x0");
}

#[tokio::test]
async fn query_balance_funded_account() {
    let env = setup();
    let account = make_funded_account(&env);
    let bal = EthApiServer::get_balance(&env.handler, account.address, None)
        .await
        .unwrap();

    let expected = format!("0x{:x}", FUNDED_BALANCE);
    assert_eq!(bal, expected);
}

// ---------------------------------------------------------------------------
// 4. Block production
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_number_increases_with_new_blocks() {
    let env = setup();

    // Build a chain of 5 blocks
    let genesis = make_genesis_block();
    store_block(&env, &genesis);
    let mut parent = genesis.hash();

    for i in 1..=5 {
        let block = make_block(i, parent);
        parent = block.hash();
        store_block(&env, &block);
    }

    let result = EthApiServer::block_number(&env.handler).await.unwrap();
    assert_eq!(result, "0x5");
}

#[tokio::test]
async fn get_block_by_number_latest() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let block = make_block(1, genesis.hash());
    store_block(&env, &block);

    let rpc_block = EthApiServer::get_block_by_number(&env.handler, "latest".into(), false)
        .await
        .unwrap();
    assert!(rpc_block.is_some());
    assert_eq!(rpc_block.unwrap().number, "0x1");
}

// ---------------------------------------------------------------------------
// 5. Clean shutdown (handler drops cleanly)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_shutdown() {
    let env = setup();

    // Perform a few operations
    let genesis = make_genesis_block();
    store_block(&env, &genesis);
    let _block_num = EthApiServer::block_number(&env.handler).await.unwrap();

    // Dropping env is the "shutdown" — no panics expected
    drop(env);
}

// ---------------------------------------------------------------------------
// 6. Negative-path tests — error & rejection scenarios
// ---------------------------------------------------------------------------

#[tokio::test]
async fn receipt_for_nonexistent_tx_returns_none() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let fake_hash = shell_primitives::ShellHash::from([0xDE; 32]);
    let receipt = EthApiServer::get_transaction_receipt(&env.handler, fake_hash)
        .await
        .unwrap();
    assert!(receipt.is_none(), "non-existent tx should return None");
}

#[tokio::test]
async fn block_by_future_number_returns_none() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let block = EthApiServer::get_block_by_number(&env.handler, "0xFFFF".into(), false)
        .await
        .unwrap();
    assert!(block.is_none(), "future block number should return None");
}

#[tokio::test]
async fn balance_of_unknown_address_is_zero() {
    let env = setup();
    let unknown = Address::from([0xBB; 20]);
    let bal = EthApiServer::get_balance(&env.handler, unknown, None)
        .await
        .unwrap();
    assert_eq!(bal, "0x0", "unknown address balance should be zero");
}

#[tokio::test]
async fn get_tx_by_hash_nonexistent_returns_none() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let fake_hash = shell_primitives::ShellHash::from([0xAB; 32]);
    let tx = EthApiServer::get_transaction_by_hash(&env.handler, fake_hash)
        .await
        .unwrap();
    assert!(tx.is_none(), "non-existent tx hash should return None");
}
