// Included inside node::tests to reuse real signed production/import fixtures.
#[test]
fn live_bound_and_first_use_slh_pairs_stage_before_native_import() {
    let proposer = shell_crypto::SphincsSigner::generate();
    let signer = shell_crypto::SphincsSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let sender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    for unbound in [false, true] {
      for activation in [None, Some(2), Some(1)] {
        let mut leader = setup_node_with_store(authority, Arc::new(MemoryDb::new()));
        leader.config.node_role = crate::config::NodeRole::ValidatorProver;
        let db = Arc::new(MemoryDb::new());
        let mut follower = setup_node_with_store(authority, db.clone());
        for (node, commitment_height) in [(&leader, Some(1)), (&follower, activation)] {
            node.register_authority_pubkey(authority, proposer.public_key().to_vec());
            node.chain_store.put_pubkey(&authority, proposer.public_key()).unwrap();
            fund_account(node, &sender, U256::from(1_000_000_000_000_000_000u64));
            let mut account = node.world_state.read().get_account(&sender).unwrap().unwrap();
            account.pq_pubkey_hash = if unbound { ShellHash::ZERO } else {
                shell_primitives::blake3_hash(signer.public_key())
            };
            node.world_state.write().set_account(&sender, &account).unwrap();
            if !unbound {
                node.chain_store.put_pubkey(&sender, signer.public_key()).unwrap();
            }
            store_consistent_genesis(node);
            let cfg = serde_json::from_value(serde_json::json!({
                "chain_id":1337,"genesis_hash":node.chain_store.get_head_hash().unwrap().unwrap(),
                "block_commitment_height":commitment_height,"fee_accounting_activation_height":1
            })).unwrap();
            node.chain_store.put_chain_config(&cfg).unwrap();
        }
        let tx = Transaction {
            chain_id:1337,nonce:0,to:Some(Address::from([0xab;32])),value:U256::from(1),
            data:Bytes::new(),gas_limit:100_000,max_fee_per_gas:shell_core::INITIAL_BASE_FEE,
            max_priority_fee_per_gas:1,access_list:None,tx_type:2,
            max_fee_per_blob_gas:None,blob_versioned_hashes:None,
        };
        let mut signed = shell_core::SignedTransaction::new(
            sender,
            tx.clone(),
            signer.sign(tx.signing_hash(signer.sig_type().as_u8()).as_bytes()).unwrap(),
        );
        if unbound {
            signed.pubkey_mode = shell_core::PubkeyMode::Embedded(signer.public_key().to_vec());
        }
        leader.handle_incoming_tx(signed, &MultiVerifier).unwrap();
        let block = leader.produce_block(&proposer, 100).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.proposer_seal.as_ref().unwrap().data.len(), 49856);
        let parent = follower.chain_store.get_head_hash().unwrap();
        let before = db.scan_all().unwrap();
        let peer = shell_network::PeerId("slh-provider".into());
        assert!(!follower.stage_live_candidate(&peer, &block).unwrap());
        assert_eq!(db.scan_all().unwrap(), before);
        follower.config.canonical_proof_admission = true;
        if activation != Some(1) {
            assert!(!follower.stage_live_candidate(&peer, &block).unwrap());
            assert_eq!(db.scan_all().unwrap(), before);
            continue;
        }
        let mut bad = block.clone();
        bad.proposer_seal.as_mut().unwrap().data[0] ^= 1;
        assert!(follower.stage_live_candidate(&peer, &bad).is_err());
        assert_eq!(db.scan_all().unwrap(), before);
        assert!(follower.stage_live_candidate(&peer, &block).unwrap());
        assert!(follower.canonical_admission_status(block.hash()).unwrap().is_some());
        assert_eq!(follower.chain_store.get_pubkey(&sender).unwrap().is_none(), unbound);
        assert_eq!(follower.chain_store.get_head_hash().unwrap(), parent);
        assert!(follower.chain_store.get_block_by_hash(&block.hash()).unwrap().is_none());
        assert!(follower.chain_store.get_receipts(&block.hash()).unwrap().is_none());
      }
    }
}

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

#[tokio::test]
async fn sender_proof_status_survives_publication_between_source_reads() {
    use http_body_util::BodyExt;
    use shell_storage::{CanonicalProofManifest, CanonicalProofUploadState};
    use std::sync::atomic::AtomicUsize;

    async fn status_request(
        address: std::net::SocketAddr,
        bearer: Option<&str>,
        id: ShellHash,
    ) -> (hyper::StatusCode, serde_json::Value) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let (mut client, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await.unwrap();
            let connection = tokio::spawn(connection);
            let payload = serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"admin_canonicalProofStatus","params":[id]
            })).unwrap();
            let mut request = hyper::Request::builder().method("POST")
                .uri(format!("http://{address}/"))
                .header("Host", address.to_string())
                .header("Content-Type", "application/json");
            if let Some(token) = bearer {
                request = request.header("Authorization", format!("Bearer {token}"));
            }
            let response = client.send_request(request.body(http_body_util::Full::new(
                hyper::body::Bytes::from(payload),
            )).unwrap()).await.unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            drop(client);
            connection.await.unwrap().unwrap();
            let value = if status == hyper::StatusCode::OK {
                serde_json::from_slice(&bytes).unwrap()
            } else { serde_json::Value::Null };
            (status, value)
        }).await.expect("sender status RPC timed out")
    }

    let db = Arc::new(FailingBatchDb::new());
    let (mut node, _, block, sender, recipient) = header_batch_source_fixture(db.clone());
    node.config.canonical_proof_admission = true;
    let funded = node.world_state.read().get_account(&sender).unwrap().unwrap();
    let peer = shell_network::PeerId("sender-status-provider".into());
    assert!(node.stage_live_candidate(&peer, &block).unwrap());
    let manifest = CanonicalProofManifest {
        version:1,chain_id:1337,
        genesis_hash:node.chain_store.get_head_hash().unwrap().unwrap(),
        block_hash:block.hash(),total_bytes:1,
        payload_hash:shell_primitives::blake3_hash(b"x"),
    };
    {
        // Only the retained-source metadata is needed. The byte is never verified
        // as a proof, and neither the network actor nor Node.run is started.
        let network = node.activate_canonical_proof_network(true);
        node.canonical_proof_peer_connected(peer.clone());
        node.accept_live_manifest(&peer, block.hash(), 0, Some(manifest.clone())).unwrap();
        node.canonical_proof_uploads.append(&manifest.id(), 0, b"x").unwrap();
        drop(network);
    }
    // Actual ordinary Native import supplies the already-published canonical child.
    // This test concerns its concurrent status read, not proof-backed authorization.
    node.import_block(block.clone(), &MultiVerifier).unwrap();
    let receipts = node.chain_store.get_receipts(&block.hash()).unwrap().unwrap();
    let fees = block.transactions.iter().fold(U256::ZERO, |sum, tx| {
        let receipt = receipts.iter().find(|r| r.tx_hash == tx.uncached_hash()).unwrap();
        assert!(receipt.succeeded());
        let price = tx.tx.max_fee_per_gas.min(block.header.base_fee_per_gas
            .saturating_add(tx.tx.max_priority_fee_per_gas));
        sum + U256::from(receipt.gas_used) * U256::from(price)
    });
    let account = node.world_state.read().get_account(&sender).unwrap().unwrap();
    assert_eq!(account.nonce, funded.nonce + 2);
    assert_eq!(account.balance, funded.balance - U256::from(2) - fees);
    assert_eq!(node.world_state.read().get_account(&recipient).unwrap().unwrap().balance, U256::from(2));
    assert_eq!(current_state_root(&node), block.header.state_root);
    let expected = node.canonical_proof_uploads.status(&manifest.id()).unwrap();
    assert_eq!(expected.state, CanonicalProofUploadState::Ready);
    assert!(expected.result.is_none());
    assert_eq!(expected.verification_attempts, 0);
    let node = Arc::new(node);
    let token = shell_primitives::blake3_hash(DilithiumSigner::generate().public_key()).to_string();
    let (events, _) = tokio::sync::broadcast::channel(16);
    let server = shell_rpc::start_rpc_server_with_proof_control(
        shell_rpc::RpcConfig {
            listen_addr:"127.0.0.1:0".parse().unwrap(),ws_addr:None,
            api_namespaces:vec!["admin".into()],api_key:Some(token.clone()),
            rate_limit_per_sec:None,..Default::default()
        },
        node.chain_store.clone(),node.world_state.clone(),node.tx_pool.clone(),
        node.config.chain_id,None,events,None,None,Arc::new(RwLock::new(0)),
        node.finality.clone(),Arc::new(AtomicUsize::new(0)),None,None,None,None,None,None,
        Some(node.clone() as Arc<dyn shell_rpc::CanonicalProofControl>),
    ).await.unwrap();
    let snapshot = db.scan_all().unwrap();
    let unauthorized = status_request(server.http_addr, None, manifest.id()).await;
    let ordinary = status_request(server.http_addr, Some(&token), manifest.id()).await;
    let initial_reads_unchanged = db.scan_all().unwrap() == snapshot;

    node.chain_store.set_canonical(1, &ShellHash::from([9;32])).unwrap();
    let different_rows = db.scan_all().unwrap();
    db.stale_child_mapping.store(true, Ordering::SeqCst);
    let different = status_request(server.http_addr, Some(&token), manifest.id()).await;
    let different_read_unchanged = db.scan_all().unwrap() == different_rows;
    node.chain_store.set_canonical(1, &block.hash()).unwrap();
    // Model persisted corruption below the validating ChainStore write boundary.
    let body_key = [b"b/".as_slice(), block.hash().as_bytes()].concat();
    let original_body = db.get(&body_key).unwrap().unwrap();
    assert_eq!(original_body[0], 2); // Current version-prefixed RLP storage.
    let (mut stripped, _) = shell_core::StrippedBlock::split(&block);
    stripped.transactions[0].tx.value += U256::from(1);
    let mut changed = vec![original_body[0]];
    alloy_rlp::Encodable::encode(&stripped, &mut changed);
    db.put(&body_key, &changed).unwrap();
    let changed_rows = db.scan_all().unwrap();
    db.stale_child_mapping.store(true, Ordering::SeqCst);
    let changed_body = status_request(server.http_addr, Some(&token), manifest.id()).await;
    let changed_read_unchanged = db.scan_all().unwrap() == changed_rows;
    db.put(&body_key, &original_body).unwrap();
    db.stale_child_mapping.store(true, Ordering::SeqCst);
    let crossing = status_request(server.http_addr, Some(&token), manifest.id()).await;
    server.http_handle.stop().unwrap();
    server.http_handle.clone().stopped().await;
    println!("{}",serde_json::json!({"method":"admin_canonicalProofStatus",
        "params":[manifest.id()],"publicationCrossingResponse":crossing.1,
        "nativeTransfers":2,"proofVerificationStarted":false,"RPCOnlyFixture":true}));
    assert_eq!(unauthorized.0, hyper::StatusCode::UNAUTHORIZED);
    assert_eq!(ordinary.0, hyper::StatusCode::OK);
    assert_eq!(ordinary.1["result"], serde_json::to_value(&expected).unwrap());
    assert!(initial_reads_unchanged && different_read_unchanged && changed_read_unchanged);
    assert!(different.1["error"]["message"].as_str().unwrap().contains("exact current canonical parent"));
    assert!(changed_body.1["error"]["message"].as_str().unwrap()
        .contains("block body commitment mismatch"));
    assert_eq!(db.scan_all().unwrap(), snapshot);
    assert_eq!(node.chain_store.get_head_hash().unwrap(), Some(block.hash()));
    assert_eq!(node.chain_store.get_receipts(&block.hash()).unwrap().unwrap(), receipts);
    assert_eq!(crossing.0, hyper::StatusCode::OK);
    assert_eq!(crossing.1["result"], serde_json::to_value(&expected).unwrap(),
        "publication changed the read-only sender status response");
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

#[test]
fn live_candidate_staging_preserves_native_state_and_checks_activation_seal_and_body() {
    let (leader, proposer) = setup_stark_node();
    let db = Arc::new(MemoryDb::new());
    let mut follower = setup_node_with_store(leader.config.proposer_address.unwrap(), db.clone());
    let signer = shell_crypto::MlDsaSigner::generate();
    let sender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let configure = |node: &Node<MemoryDb>, activation| {
        node.register_authority_pubkey(
            node.config.proposer_address.unwrap(),
            proposer.public_key().to_vec(),
        );
        fund_account(node, &sender, U256::from(1_000_000_000_000_000_000u64));
        let mut account = node
            .world_state
            .read()
            .get_account(&sender)
            .unwrap()
            .unwrap();
        account.pq_pubkey_hash = shell_primitives::blake3_hash(signer.public_key());
        node.world_state
            .write()
            .set_account(&sender, &account)
            .unwrap();
        node.chain_store
            .put_pubkey(&sender, signer.public_key())
            .unwrap();
        store_consistent_genesis(node);
        let cfg=serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":node.chain_store.get_head_hash().unwrap().unwrap(),"block_commitment_height":activation,"fee_accounting_activation_height":1})).unwrap();
        node.chain_store.put_chain_config(&cfg).unwrap();
    };
    configure(&leader, 1u64);
    configure(&follower, 1u64);
    submit_signed_tx(
        &leader,
        &signer,
        sender,
        Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(Address::from([0xab; 32])),
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
    let block = leader.produce_block(&proposer, 100).unwrap();
    let peer = shell_network::PeerId("provider".into());
    let before = db.scan_all().unwrap();
    assert!(!follower.stage_live_candidate(&peer, &block).unwrap());
    assert_eq!(db.scan_all().unwrap(), before);
    follower.config.canonical_proof_admission = true;
    let inactive_db = Arc::new(MemoryDb::new());
    let mut inactive =
        setup_node_with_store(leader.config.proposer_address.unwrap(), inactive_db.clone());
    configure(&inactive, 2u64);
    inactive.config.canonical_proof_admission = true;
    let before = inactive_db.scan_all().unwrap();
    assert!(!inactive.stage_live_candidate(&peer, &block).unwrap());
    assert_eq!(inactive_db.scan_all().unwrap(), before);
    let cfg = follower.chain_store.get_chain_config().unwrap().unwrap();
    let before = db.scan_all().unwrap();
    let mut bad_seal = block.clone();
    bad_seal.proposer_seal.as_mut().unwrap().data[0] ^= 1;
    let mut bad_body = block.clone();
    bad_body.transactions[0].tx.value = U256::from(2);
    for bad in [bad_seal, bad_body] {
        assert!(follower.stage_live_candidate(&peer, &bad).is_err());
        assert_eq!(db.scan_all().unwrap(), before);
    }
    assert!(follower.stage_live_candidate(&peer, &block).unwrap());
    assert_eq!(
        follower.chain_store.get_head_hash().unwrap(),
        Some(cfg.genesis_hash)
    );
    assert!(follower
        .chain_store
        .get_block_by_hash(&block.hash())
        .unwrap()
        .is_none());
    assert!(follower
        .chain_store
        .get_receipts(&block.hash())
        .unwrap()
        .is_none());
    assert!(follower
        .canonical_admission_status(block.hash())
        .unwrap()
        .is_some());
}
