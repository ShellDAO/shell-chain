// Included inside node::tests to reuse real signed production/import fixtures.
fn header_batch_source_fixture<S: KvStore + 'static>(
    follower_store: Arc<S>,
) -> (Node<S>, DilithiumSigner, Block, Address, Address) {
    let (leader, proposer) = setup_stark_node();
    let follower = setup_node_with_store(leader.config.proposer_address.unwrap(), follower_store);
    let signer = shell_crypto::MlDsaSigner::generate();
    let sender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let recipient = Address::from([0xab; 32]);
    configure_block_commitment_node(&leader, &proposer, sender, Some(1));
    configure_block_commitment_node(&follower, &proposer, sender, Some(1));
    for nonce in 0..2 {
        submit_signed_tx(
            &leader,
            &signer,
            sender,
            Transaction {
                chain_id: 1337,
                nonce,
                to: Some(recipient),
                value: U256::from(1),
                data: Bytes::new(),
                gas_limit: 100_000,
                max_fee_per_gas: shell_core::INITIAL_BASE_FEE,
                max_priority_fee_per_gas: 1,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        );
    }
    let block = leader.produce_block(&proposer, 100).unwrap();
    assert_eq!(block.transactions.len(), 2);
    assert!(block.header.sig_aggregate_proof.is_some());
    (follower, proposer, block, sender, recipient)
}

fn header_batch_source_attach(
    block: &Block,
    proof: &SigBatchProof,
    signer: &DilithiumSigner,
) -> Block {
    let mut block = block.clone();
    block.header.sig_aggregate_proof = Some(proof.to_json().unwrap().into());
    block.proposer_seal = Some(signer.sign(block.header.hash().as_bytes()).unwrap());
    block
}

#[test]
fn header_batch_source_binding_rejects_foreign_claims_before_persistence() {
    for side_fork in [false, true] {
        let (node, proposer, block, _, _) = header_batch_source_fixture(Arc::new(MemoryDb::new()));
        let entries = stark_sources::block_to_sig_batch_entries(&block);
        let mut reversed = entries.clone();
        reversed.reverse();
        let foreign = shell_stark_prover::prove_sig_batch(&reversed).unwrap();
        // The rejection must bind the source, not mistake a valid proof for
        // invalid Winterfell bytes. Order is part of the expected source.
        shell_stark_prover::verify_sig_batch(&foreign).unwrap();
        let correct = shell_stark_prover::prove_sig_batch(&entries).unwrap();
        let mut claims = vec![("root", foreign)];
        for full in [false, true] {
            let base = if full {
                correct.clone()
            } else {
                SigBatchProof::commitment_only(correct.batch_root_bytes, correct.n_sigs)
            };
            let mut root = base.clone();
            root.batch_root_bytes[0] ^= 1;
            claims.push(("root", root));
            let mut count = base.clone();
            count.n_sigs += 1;
            claims.push(("count", count));
            for version in [0, 1, 3, 255] {
                let mut unknown = base.clone();
                unknown.version = version;
                claims.push(("version", unknown));
            }
        }
        if side_fork {
            node.import_block(block.clone(), &MultiVerifier).unwrap();
        }
        let before = node.store.scan_prefix(b"").unwrap();
        let head = node.chain_store.get_head_hash().unwrap();
        let state = current_state_root(&node);
        for (field, proof) in claims {
            let changed = header_batch_source_attach(&block, &proof, &proposer);
            let hash = changed.hash();
            let error = node.import_block(changed, &MultiVerifier).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("aggregate {field} mismatch")),
                "{error}"
            );
            assert_eq!(node.store.scan_prefix(b"").unwrap(), before);
            assert_eq!(node.chain_store.get_head_hash().unwrap(), head);
            assert_eq!(current_state_root(&node), state);
            assert!(!node.fork_choice.read().contains(&hash));
        }
    }
}

#[test]
fn header_batch_source_binding_valid_claims_keep_native_signature_validation() {
    for full in [false, true] {
        let (node, proposer, block, sender, recipient) =
            header_batch_source_fixture(Arc::new(MemoryDb::new()));
        let block = if full {
            let proof = shell_stark_prover::prove_sig_batch(
                &stark_sources::block_to_sig_batch_entries(&block),
            )
            .unwrap();
            header_batch_source_attach(&block, &proof, &proposer)
        } else {
            block
        };
        let before = node.store.scan_prefix(b"").unwrap();
        let mut invalid = block.clone();
        invalid.transactions[1].signature.data[0] ^= 1;
        invalid.header.transactions_root =
            shell_core::block_body_root(&invalid.transactions, &invalid.system_transactions)
                .unwrap();
        invalid.proposer_seal = Some(proposer.sign(invalid.header.hash().as_bytes()).unwrap());
        // Signature bytes are not part of this legacy accumulator. A matching
        // source proof must never bypass the separate native signature check.
        let error = node.import_block(invalid, &MultiVerifier).unwrap_err();
        assert!(
            error.to_string().contains("batch sig verification failed"),
            "{error}"
        );
        assert_eq!(node.store.scan_prefix(b"").unwrap(), before);
        node.import_block(block.clone(), &MultiVerifier).unwrap();
        assert_eq!(
            node.chain_store.get_head_hash().unwrap(),
            Some(block.hash())
        );
        assert_eq!(node.world_state.read().get_nonce(&sender).unwrap(), 2);
        assert_eq!(
            node.world_state.read().get_balance(&recipient).unwrap(),
            U256::from(2)
        );
        let receipts = node
            .chain_store
            .get_receipts(&block.hash())
            .unwrap()
            .unwrap();
        assert_eq!(
            receipts.len(),
            block.transactions.len() + block.system_transactions.len()
        );
        assert!(receipts.iter().all(|receipt| receipt.status == 1));
        assert_eq!(
            shell_core::block_receipts_root(&receipts),
            block.header.receipts_root
        );
    }
}

#[cfg(feature = "rocksdb")]
#[test]
fn header_batch_source_binding_native_reopen() {
    let directory = std::env::temp_dir().join(format!(
        "shell-header-batch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let stores = shell_storage::RocksDbStore::open_all(&directory, None).unwrap();
    let (node, proposer, block, sender, recipient) =
        header_batch_source_fixture(Arc::new(stores.state));
    let proof =
        shell_stark_prover::prove_sig_batch(&stark_sources::block_to_sig_batch_entries(&block))
            .unwrap();
    let block = header_batch_source_attach(&block, &proof, &proposer);
    node.import_block(block.clone(), &MultiVerifier).unwrap();
    let receipts = node
        .chain_store
        .get_receipts(&block.hash())
        .unwrap()
        .unwrap();
    drop(node);
    drop(stores.chain);
    drop(stores.witness);
    drop(stores.receipts);
    drop(stores.index);
    let stores = shell_storage::RocksDbStore::open_all(&directory, None).unwrap();
    let store = Arc::new(stores.state);
    let chain = ChainStore::new(store.clone());
    assert_eq!(chain.get_head_hash().unwrap(), Some(block.hash()));
    assert_eq!(
        chain.get_block_by_hash(&block.hash()).unwrap().unwrap(),
        block
    );
    assert_eq!(
        chain.get_receipts(&block.hash()).unwrap().unwrap(),
        receipts
    );
    let state = WorldState::at_root(store, &block.header.state_root).unwrap();
    assert_eq!(state.get_nonce(&sender).unwrap(), 2);
    assert_eq!(state.get_balance(&recipient).unwrap(), U256::from(2));
    println!(
        "native header batch data retained at {}",
        directory.display()
    );
}
