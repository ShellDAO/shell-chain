// Included inside node::tests to reuse the native signed execution fixtures.
fn configure_block_commitment_node<S: KvStore + 'static>(
    node: &Node<S>,
    proposer_signer: &DilithiumSigner,
    sender: Address,
    activation: Option<u64>,
) {
    let proposer = node.config.proposer_address.unwrap();
    node.register_authority_pubkey(proposer, proposer_signer.public_key().to_vec());
    fund_account(node, &sender, U256::from(1_000_000_000_000_000_000u64));
    store_consistent_genesis(node);
    let config = serde_json::from_value(serde_json::json!({
        "chain_id": 1337,
        "genesis_hash": node.chain_store.get_head_hash().unwrap().unwrap(),
        "block_commitment_height": activation,
        "fee_accounting_activation_height": 1,
    }))
    .unwrap();
    node.chain_store.put_chain_config(&config).unwrap();
}

fn block_commitment_roundtrip<S: KvStore + 'static>(
    leader: &Node<MemoryDb>,
    follower: &Node<S>,
    proposer_signer: &DilithiumSigner,
    activation: Option<u64>,
) -> (Address, Address, Vec<Block>) {
    use shell_crypto::MlDsaSigner;
    let signer = MlDsaSigner::generate();
    let sender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let receiver = Address::from([0xab; 32]);
    configure_block_commitment_node(leader, proposer_signer, sender, activation);
    configure_block_commitment_node(follower, proposer_signer, sender, activation);
    let mut blocks = Vec::new();
    let mut export = Vec::new();
    for nonce in 0..3 {
        let transaction = Transaction {
            chain_id: 1337,
            nonce,
            to: Some(receiver),
            value: U256::from(1),
            data: Bytes::new(),
            gas_limit: 100_000,
            max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        submit_signed_tx(leader, &signer, sender, transaction);
        let block = leader.produce_block(proposer_signer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert!(!block.system_transactions.is_empty());
        let receipts = leader
            .chain_store
            .get_receipts(&block.hash())
            .unwrap()
            .unwrap();
        let active = activation.is_some_and(|height| block.number() >= height);
        if active {
            assert_eq!(
                block.header.transactions_root,
                shell_core::block_body_root(&block.transactions, &block.system_transactions)
                    .unwrap()
            );
            assert_eq!(
                block.header.receipts_root,
                shell_core::block_receipts_root(&receipts)
            );
            let before = follower.store.scan_prefix(b"").unwrap();
            let old_root = current_state_root(follower);
            for mutation in 0..7 {
                let mut changed = block.clone();
                match mutation {
                    0 => changed.transactions[0].signature.data[0] ^= 1,
                    1 => changed.transactions[0].pubkey_mode = shell_core::PubkeyMode::Reference,
                    2 => changed.system_transactions[0].value += U256::from(1),
                    3 => {
                        changed.transactions.clear();
                    }
                    4 => {
                        changed.system_transactions.clear();
                    }
                    5 => changed.header.transactions_root = ShellHash::ZERO,
                    _ => changed.header.receipts_root = ShellHash::ZERO,
                }
                changed.proposer_seal = Some(
                    proposer_signer
                        .sign(changed.header.hash().as_bytes())
                        .unwrap(),
                );
                assert!(
                    follower.import_block(changed, &MultiVerifier).is_err(),
                    "mutation {mutation}"
                );
                assert_eq!(
                    follower.store.scan_prefix(b"").unwrap(),
                    before,
                    "mutation {mutation} wrote KV"
                );
                assert_eq!(current_state_root(follower), old_root);
            }
        } else {
            assert_eq!(block.header.transactions_root, ShellHash::ZERO);
            assert_eq!(block.header.receipts_root, ShellHash::ZERO);
        }
        follower
            .import_block(block.clone(), &MultiVerifier)
            .unwrap();
        assert_eq!(current_state_root(follower), block.header.state_root);
        assert_eq!(
            follower.chain_store.get_receipts(&block.hash()).unwrap(),
            Some(receipts.clone())
        );
        assert_eq!(
            follower.world_state.read().get_nonce(&sender).unwrap(),
            nonce + 1
        );
        assert_eq!(
            follower.world_state.read().get_balance(&receiver).unwrap(),
            U256::from(nonce + 1)
        );
        assert_eq!(
            receipts.len(),
            block.transactions.len() + block.system_transactions.len()
        );
        if active {
            let before = follower.store.scan_prefix(b"").unwrap();
            let mut stale = block.clone();
            stale.transactions[0].signature.data[0] ^= 1;
            assert!(
                follower.import_block(stale, &MultiVerifier).is_err(),
                "duplicate must not hide altered body"
            );
            let mut changed = receipts.clone();
            changed[0].status ^= 1;
            assert!(follower
                .chain_store
                .commit_canonical_block(&block, Some(&changed))
                .is_err());
            assert!(follower
                .chain_store
                .put_backfill_block(
                    &{
                        let mut altered = block.clone();
                        altered.transactions[0].tx.value += U256::from(1);
                        altered
                    },
                    false
                )
                .is_err());
            assert_eq!(follower.store.scan_prefix(b"").unwrap(), before);
        }
        let encode = |value: &dyn alloy_rlp::Encodable| {
            let mut bytes = Vec::new();
            value.encode(&mut bytes);
            hex::encode(bytes)
        };
        export.push(serde_json::json!({"block": &block, "receipts": &receipts,
            "transactions_rlp": block.transactions.iter().map(|tx| encode(tx)).collect::<Vec<_>>(),
            "system_rlp": block.system_transactions.iter().map(|tx| encode(&tx.to_wire_bytes().unwrap())).collect::<Vec<_>>(),
            "receipts_rlp": receipts.iter().map(|r| encode(r)).collect::<Vec<_>>() }));
        blocks.push(block);
    }
    // Empty production and import still require the two distinct empty commitments.
    let empty = leader.produce_block(proposer_signer, 100).unwrap();
    follower
        .import_block(empty.clone(), &MultiVerifier)
        .unwrap();
    if activation.is_some_and(|height| empty.number() >= height) {
        assert_eq!(
            empty.header.transactions_root,
            shell_core::block_body_root(&empty.transactions, &empty.system_transactions).unwrap()
        );
        assert_eq!(
            empty.header.receipts_root,
            shell_core::block_receipts_root(
                &follower
                    .chain_store
                    .get_receipts(&empty.hash())
                    .unwrap()
                    .unwrap()
            )
        );
    }
    blocks.push(empty);
    for block in &blocks[..3] {
        let before = follower.store.scan_prefix(b"").unwrap();
        follower.validate_legacy_backfill_witness(block).unwrap();
        assert_eq!(follower.store.scan_prefix(b"").unwrap(), before);
    }
    // Remove witness + historical undo: the retained genesis checkpoint is the replay anchor.
    for block in &blocks[..3] {
        assert_pruned_genesis_witness_recovery(follower, block);
    }
    // The child recovery writer has its own fixture; only the ordinary test
    // exports here, avoiding concurrent writes when tests run in parallel.
    if let (Some(2), None, Some(path)) = (
        activation,
        std::env::var_os("SHELL_TEST_BLOCK_COMMITMENT_DIRECTORY"),
        std::env::var_os("SHELL_BLOCK_COMMITMENT_FIXTURE"),
    ) {
        std::fs::write(path, serde_json::to_vec_pretty(&export).unwrap()).unwrap();
    }
    (sender, receiver, blocks)
}

#[test]
fn block_commitment_signed_production_import_and_history() {
    for activation in [None, Some(2)] {
        let (leader, proposer) = setup_node();
        let follower = setup_node_with_authority(leader.config.proposer_address.unwrap());
        block_commitment_roundtrip(&leader, &follower, &proposer, activation);
    }
}

#[cfg(feature = "rocksdb")]
#[test]
fn block_commitment_import_survives_process_exit() {
    const DIRECTORY: &str = "SHELL_TEST_BLOCK_COMMITMENT_DIRECTORY";
    if let Some(directory) = std::env::var_os(DIRECTORY) {
        let directory = std::path::PathBuf::from(directory);
        let (leader, proposer) = setup_node();
        let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
        let follower = setup_node_with_store(
            leader.config.proposer_address.unwrap(),
            Arc::new(stores.state),
        );
        let fixture = block_commitment_roundtrip(&leader, &follower, &proposer, Some(2));
        std::fs::write(
            directory.join("fixture.json"),
            serde_json::to_vec(&fixture).unwrap(),
        )
        .unwrap();
        std::process::exit(0);
    }
    let directory = std::env::var_os("SHELL_BLOCK_COMMITMENT_RECOVERY_DIRECTORY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "shell-block-commitment-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
        });
    std::fs::create_dir_all(&directory).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::tests::block_commitment_import_survives_process_exit",
            "--nocapture",
        ])
        .env(DIRECTORY, &directory)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "writer failed; retained {}",
        directory.display()
    );
    let (sender, receiver, blocks): (Address, Address, Vec<Block>) =
        serde_json::from_slice(&std::fs::read(directory.join("fixture.json")).unwrap()).unwrap();
    let tip = blocks.last().unwrap();
    let stores = shell_storage::RocksDbStore::open_all(directory.join("db"), None).unwrap();
    let store = Arc::new(stores.state);
    let chain = ChainStore::new(store.clone());
    assert_eq!(chain.get_head_hash().unwrap(), Some(tip.hash()));
    assert_eq!(
        chain
            .get_chain_config()
            .unwrap()
            .unwrap()
            .block_commitment_height,
        Some(2)
    );
    let state = WorldState::at_root(store, &tip.header.state_root).unwrap();
    assert_eq!(state.get_nonce(&sender).unwrap(), 3);
    assert_eq!(state.get_balance(&receiver).unwrap(), U256::from(3));
    for block in &blocks {
        assert_eq!(
            chain.get_block_by_hash(&block.hash()).unwrap(),
            Some(block.clone())
        );
        chain.verify_block_body_commitment(block).unwrap();
        chain
            .verify_block_receipts_commitment(
                block,
                &chain.get_receipts(&block.hash()).unwrap().unwrap(),
            )
            .unwrap();
    }
    eprintln!("retained recovery database: {}", directory.display());
}
