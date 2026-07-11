//! E2E Sync Test — verifies chain integrity, state consistency, and snapshot
//! export/import round-tripping.

use shell_e2e::*;

use shell_primitives::{Address, ShellHash, U256};
use shell_rpc::api::EthApiServer;
use shell_storage::{ChainStore, MemoryDb, SnapshotMetadata};
use std::io::Cursor;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// 1. Block hash chain integrity — parent_hash links
// ---------------------------------------------------------------------------

#[tokio::test]
async fn block_chain_parent_hash_integrity() {
    let env = setup();
    let chain_length = 10u64;

    let genesis = make_genesis_block();
    store_block(&env, &genesis);
    let mut hashes = vec![genesis.hash()];

    for i in 1..=chain_length {
        let parent = *hashes.last().unwrap();
        let block = make_block(i, parent);
        let hash = block.hash();
        store_block(&env, &block);
        hashes.push(hash);
    }

    // Walk the chain backwards and verify parent links
    for i in (1..=chain_length).rev() {
        let rpc_block =
            EthApiServer::get_block_by_number(&env.handler, format!("0x{:x}", i), false)
                .await
                .unwrap();
        let rpc_block = rpc_block.unwrap();

        // parent_hash in the RPC response should match the hash of block i-1
        assert_eq!(
            rpc_block.parent_hash,
            hashes[i as usize - 1],
            "parent hash mismatch at block {i}"
        );
    }

    // Head should be at the chain tip
    let head = EthApiServer::block_number(&env.handler).await.unwrap();
    assert_eq!(head, format!("0x{:x}", chain_length));
}

// ---------------------------------------------------------------------------
// 2. Account state consistency after multiple transfers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_consistency_after_transfers() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let sender = make_funded_account(&env);
    let recipient = Address::from([0x10; 20]);

    // Perform 5 transfers across 5 blocks
    let transfer_amount = 1_000u64;
    let num_transfers = 5u64;
    let mut parent = genesis.hash();

    for i in 0..num_transfers {
        let tx = make_transfer(TEST_CHAIN_ID, i, recipient, U256::from(transfer_amount));
        let signed = sign_tx(&sender.signer, sender.address, tx);

        // Manually debit/credit world state to simulate execution
        {
            let mut ws = env.world_state.write();
            let gas_cost = 21_000u64 * 1_000_000_000u64; // gas_limit * max_fee_per_gas
            let sender_balance = ws.get_balance(&sender.address).unwrap();
            let debit = U256::from(transfer_amount) + U256::from(gas_cost);
            if sender_balance >= debit {
                // Subtract (balance - debit)
                let new_bal = sender_balance - debit;
                ws.set_account(
                    &sender.address,
                    &shell_core::Account {
                        pq_pubkey_hash: ShellHash::default(),
                        nonce: (i + 1),
                        balance: new_bal,
                        validation_code_hash: None,
                        code_hash: None,
                        storage_root: ShellHash::default(),
                    },
                )
                .unwrap();
            }
            ws.add_balance(&recipient, U256::from(transfer_amount))
                .unwrap();
        }

        parent = mine_block(&env, i + 1, parent, vec![signed]);
    }

    // Verify recipient has accumulated the expected balance
    let recipient_balance = EthApiServer::get_balance(&env.handler, recipient, None)
        .await
        .unwrap();
    let expected = U256::from(transfer_amount * num_transfers);
    let expected_hex = format!("0x{:x}", expected);
    assert_eq!(recipient_balance, expected_hex);

    // Verify nonce advanced
    let nonce = EthApiServer::get_transaction_count(&env.handler, sender.address, None)
        .await
        .unwrap();
    let expected_nonce = format!("0x{:x}", num_transfers);
    assert_eq!(nonce, expected_nonce);
}

// ---------------------------------------------------------------------------
// 3. Multiple blocks with transactions — all receipts retrievable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_receipts_across_blocks() {
    let env = setup();
    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    let recipient = Address::from([0x20; 20]);
    let blocks = 5u64;
    let mut parent = genesis.hash();
    let mut all_tx_hashes = Vec::new();

    for blk in 1..=blocks {
        let sender = make_funded_account(&env);
        // Unique value per block to avoid duplicate tx hash
        let tx = make_transfer(TEST_CHAIN_ID, 0, recipient, U256::from(100 + blk));
        let signed = sign_tx(&sender.signer, sender.address, tx);
        all_tx_hashes.push(signed.hash());

        use shell_rpc::api::ShellApiServer;
        ShellApiServer::send_transaction(&env.handler, signed.clone())
            .await
            .unwrap();
        parent = mine_block(&env, blk, parent, vec![signed]);
    }

    // Every transaction should have a receipt
    for (i, tx_hash) in all_tx_hashes.iter().enumerate() {
        let receipt = EthApiServer::get_transaction_receipt(&env.handler, *tx_hash)
            .await
            .unwrap();
        assert!(
            receipt.is_some(),
            "receipt missing for tx {i} (hash {tx_hash})"
        );
        let r = receipt.unwrap();
        assert_eq!(r.status, "0x1");
        assert_eq!(
            r.block_number,
            format!("0x{:x}", i + 1),
            "wrong block for tx {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Snapshot export & import round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_export_import_roundtrip() {
    let env = setup();
    let state_root = env.world_state.write().state_root().unwrap_or_default();

    // Build a short chain
    let mut genesis = make_genesis_block();
    genesis.header.state_root = state_root;
    store_block(&env, &genesis);
    let mut block1 = make_block(1, genesis.hash());
    block1.header.state_root = state_root;
    store_block(&env, &block1);

    let genesis_hash = genesis.hash();

    // Export snapshot
    let metadata = SnapshotMetadata::new(TEST_CHAIN_ID, 1, block1.hash(), state_root, genesis_hash);
    let mut buf: Vec<u8> = Vec::new();
    let exported_meta = env.chain_store.export_snapshot(metadata, &mut buf).unwrap();
    assert_eq!(exported_meta.chain_id, TEST_CHAIN_ID);
    assert_eq!(exported_meta.block_number, 1);
    assert!(exported_meta.entry_count > 0);

    // Import into a fresh store
    let db2 = Arc::new(MemoryDb::new());
    let chain_store2 = ChainStore::new(db2.clone());
    let imported_meta = chain_store2
        .import_snapshot(Cursor::new(buf), TEST_CHAIN_ID, &genesis_hash)
        .unwrap();
    assert_eq!(imported_meta.chain_id, TEST_CHAIN_ID);
    assert_eq!(imported_meta.block_number, 1);

    let imported_head = chain_store2.get_head_block().unwrap().unwrap();
    assert_eq!(imported_head.hash(), block1.hash());
}

// ---------------------------------------------------------------------------
// 5. Chain reorg safety — canonical chain is consistent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn canonical_chain_consistency() {
    let env = setup();

    let genesis = make_genesis_block();
    store_block(&env, &genesis);

    // Build a 5-block canonical chain
    let mut parent = genesis.hash();
    for i in 1..=5 {
        let block = make_block(i, parent);
        parent = block.hash();
        store_block(&env, &block);
    }

    // Verify every canonical block is retrievable by number
    for i in 0..=5 {
        let rpc_block =
            EthApiServer::get_block_by_number(&env.handler, format!("0x{:x}", i), false)
                .await
                .unwrap();
        assert!(
            rpc_block.is_some(),
            "canonical block {i} should be retrievable"
        );
        assert_eq!(rpc_block.unwrap().number, format!("0x{:x}", i));
    }
}
