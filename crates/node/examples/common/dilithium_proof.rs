//! Genuine locked Dilithium3 roles and retained native controls.
use super::*;
use shell_crypto::{DilithiumSigner, MlDsaSigner, Verifier};
use shell_storage::RocksDbStores;

fn genesis(
    path: &Path,
    sender: &dyn Signer,
    proposer: &dyn Signer,
) -> Result<RocksDbStores, Error> {
    let stores = RocksDbStore::open_all(path, None)?;
    let db = Arc::new(stores.state.clone());
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    let mut world = WorldState::new(db.clone());
    world.set_account(
        &address,
        &Account::new_user_account(blake3_hash(sender.public_key()), U256::from(1_000_000)),
    )?;
    let block = Block {
        header: BlockHeader {
            state_root: world.state_root()?,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: 1,
            proposer: authority,
            ..Default::default()
        },
        transactions: vec![],
        system_transactions: vec![],
        proposer_seal: None,
    };
    let chain = ChainStore::new(db);
    chain.put_pubkey(&address, sender.public_key())?;
    chain.put_pubkey(&authority, proposer.public_key())?;
    let config: ChainConfig = serde_json::from_value(
        json!({"chain_id":10,"genesis_hash":block.hash(),"fee_accounting_activation_height":1,"native_address_context_height":1,"block_commitment_height":1}),
    )?;
    chain.commit_genesis_block(&block, &config)?;
    stores.state.flush()?;
    Ok(stores)
}
fn signed(sender: &dyn Signer, nonce: u64) -> Result<SignedTransaction, Error> {
    let tx = Transaction {
        chain_id: 10,
        nonce,
        to: Some(Address::from([0x11; 32])),
        value: U256::from(1),
        data: Default::default(),
        gas_limit: 21_000,
        max_fee_per_gas: 2,
        max_priority_fee_per_gas: 1,
        tx_type: 0,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };
    Ok(SignedTransaction::new(
        Address::from_public_key(sender.public_key(), sender.sig_type().as_u8()),
        tx.clone(),
        sender.sign(tx.signing_hash(sender.sig_type().as_u8()).as_bytes())?,
    ))
}
fn control(node: &Node<RocksDbStore>, block: &Block) -> Result<Value, Error> {
    let receipts = node
        .chain_store
        .get_receipts(&block.hash())?
        .ok_or("legacy receipts absent")?;
    ensure(
        receipts.len() == 2
            && receipts[0].gas_used == 21_000
            && receipts[0].status == 1
            && receipts[1].gas_used == 0,
        "legacy native receipt mismatch",
    )?;
    Ok(
        json!({"head":block.hash(),"height":block.number(),"state_root":block.header.state_root,"receipts":receipts,"accounts":accounts(node.store.clone(),block)?}),
    )
}
pub(crate) fn prepare(out: &Path, legacy_sender: bool, legacy_proposer: bool) -> Result<(), Error> {
    if out.exists() {
        ensure(
            std::fs::read_dir(out)?.all(|e| e.is_ok_and(|e| e.file_name() == "commands")),
            "legacy output exists; refusing key replacement",
        )?;
    } else {
        std::fs::create_dir(out)?;
    }
    ensure(
        legacy_sender || legacy_proposer,
        "a genuine Dilithium role is required",
    )?;
    let sender: Box<dyn Signer> = if legacy_sender {
        Box::new(DilithiumSigner::generate())
    } else {
        Box::new(MlDsaSigner::generate())
    };
    let proposer: Box<dyn Signer> = if legacy_proposer {
        Box::new(DilithiumSigner::generate())
    } else {
        Box::new(MlDsaSigner::generate())
    };
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        address != authority && address != Address::from([0x11; 32]),
        "legacy actor collision",
    )?;
    let stores = genesis(
        &out.join("native-original/db"),
        sender.as_ref(),
        proposer.as_ref(),
    )?;
    let receiver = genesis(
        &out.join("network-dilithium/receiver/db"),
        sender.as_ref(),
        proposer.as_ref(),
    )?;
    let receiver_genesis = ChainStore::new(Arc::new(receiver.state.clone()))
        .get_head_hash()?
        .ok_or("legacy receiver genesis absent")?;
    let genesis_rows = receiver.state.scan_all()?;
    drop(receiver);
    let mut node = fixture::node(
        Arc::new(stores.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    // This ordinary Native proposer control precedes public source collection.
    // Avoid creating a sender-only job whose immutable inputs would be replaced.
    node.config.canonical_proof_production = !legacy_proposer;
    let tx = signed(sender.as_ref(), 0)?;
    ensure(
        MultiVerifier.verify(
            sender.public_key(),
            tx.sender_signing_hash().as_bytes(),
            &tx.signature,
        )?,
        "genuine legacy crypto refused",
    )?;
    node.handle_incoming_tx(tx, &MultiVerifier)?;
    let block = node.produce_block(proposer.as_ref(), 100)?;
    let vote = proposer.sign(block.hash().as_bytes())?;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        block.number(),
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(authority, block.hash(), block.number(), vote.clone())
        .ok_or("legacy quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == 1,
        "legacy native finality absent",
    )?;
    let context = fixture::Context {
        version: 1,
        authority,
        authority_key: proposer.public_key().to_vec(),
        genesis_root: node
            .chain_store
            .get_header_by_hash(&receiver_genesis)?
            .ok_or("legacy genesis header absent")?
            .state_root,
        block: block.hash(),
        tip: block.hash(),
    };
    ensure(
        block.header.parent_hash == receiver_genesis,
        "legacy independent genesis differs",
    )?;
    write(&out.join("context.json"), &context)?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("quorum-vote.json"), &vote)?;
    write(&out.join("control.json"), &control(&node, &block)?)?;
    let failed = Arc::new(shell_storage::MemoryDb::new());
    for (k, v) in genesis_rows {
        failed.put(&k, &v)?;
    }
    let failed_node = fixture::node(failed.clone(), authority, proposer.public_key())?;
    let mut bad = block.clone();
    bad.header.state_root = ShellHash::ZERO;
    bad.proposer_seal = Some(proposer.sign(bad.hash().as_bytes())?);
    let before = failed.scan_all()?;
    let error = failed_node
        .import_block(bad, &MultiVerifier)
        .err()
        .ok_or("legacy wrong root accepted")?
        .to_string();
    ensure(
        error.contains("state root mismatch")
            && error.contains(&format!("{:?}", block.header.state_root))
            && before == failed.scan_all()?,
        "legacy wrong-root refusal leaked writes or preceded execution",
    )?;
    write(
        &out.join("native-rollback.json"),
        &json!({"native_crypto_control_not_proof_admission":true,"all_kv_unchanged":true,"error":error}),
    )?;
    stores.state.flush()?;
    std::fs::create_dir(out.join("network-dilithium/provider"))?;
    stores.create_checkpoint(out.join("network-dilithium/provider/db"))?;
    node.config.canonical_proof_production = false;
    node.handle_incoming_tx(signed(sender.as_ref(), 1)?, &MultiVerifier)?;
    let successor = node.produce_block(proposer.as_ref(), 100)?;
    write(&out.join("successor.json"), &successor)?;
    write(
        &out.join("later-control.json"),
        &control(&node, &successor)?,
    )?;
    write(
        &out.join("actors.json"),
        &json!({"sender":address,"sender_key":sender.public_key(),"sender_algorithm":sender.sig_type(),"proposer_algorithm":proposer.sig_type(),"private_keys_persisted":false,"profile":if legacy_sender && legacy_proposer {"legacy-both"} else if legacy_proposer {"legacy-proposer"} else {"legacy-sender"},"initial_automatic_capture_disabled_native_control":legacy_proposer,"native_transcript":"locked pqcrypto-dilithium0.5.0 raw roles; FIPS only where explicitly selected"}),
    )?;
    node.store.flush()?;
    drop(node);
    drop(stores);
    drop(sender);
    drop(proposer);
    probe(out, false)
}
pub(crate) fn probe(out: &Path, recovered: bool) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-dilithium/provider/db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state.clone()));
    let context: fixture::Context = read(&out.join("context.json"))?;
    let before = digest(&stores.state)?;
    let result = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
        &chain,
        context.tip,
        context.block,
    );
    ensure(
        before == digest(&stores.state)?,
        "legacy source capture wrote native data",
    )?;
    let path = out.join(if recovered {
        "capture-recovered.json"
    } else {
        "capture-original.json"
    });
    ensure(!path.exists(), "retained legacy capture receipt exists")?;
    match result {
        Ok(source) => {
            let input: Value = serde_json::from_slice(source.identity())?;
            let full = input["version"] == 2 && input["proposer_key"].is_array();
            write(
                &path,
                &json!({"supported":full,"captured_version":input["version"],"proposer_captured":input["proposer_key"].is_array(),"identity_hash":blake3_hash(source.identity()),"all_kv_unchanged":true,"native_digest":before}),
            )?;
            ensure(full, "genuine proposer missing from full production source")
        }
        Err(error) => {
            write(
                &path,
                &json!({"supported":false,"error":error,"all_kv_unchanged":true,"native_digest":before}),
            )?;
            Err(error.into())
        }
    }
}

fn legacy_roles(out: &Path) -> Result<(bool, bool), Error> {
    let actors: Value = read(&out.join("actors.json"))?;
    match (
        actors["sender_algorithm"].as_str(),
        actors["proposer_algorithm"].as_str(),
    ) {
        (Some("Dilithium3"), Some("MlDsa65")) => Ok((true, false)),
        (Some("MlDsa65"), Some("Dilithium3")) => Ok((false, true)),
        (Some("Dilithium3"), Some("Dilithium3")) => Ok((true, true)),
        _ => Err("unsupported retained Dilithium role profile".into()),
    }
}
pub(crate) async fn run(out: &Path, pause: bool) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    ensure(
        !network.join("complete.json").exists(),
        "Dilithium proof complete; use verify",
    )?;
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let (legacy_sender, legacy_proposer) = legacy_roles(out)?;
    let expected: Value = read(&out.join("control.json"))?;
    let faults = Arc::new(Faults::default());
    let provider = Live::start(
        &network.join("provider/db"),
        &context,
        vec![],
        false,
        true,
        Some(faults.clone()),
    )
    .await?;
    let receiver = match Live::start(
        &network.join("receiver/db"),
        &context,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await
    {
        Ok(receiver) => receiver,
        Err(error) => {
            provider.stop().await?;
            return Err(error);
        }
    };
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12 * 60 * 60);
        let mut last_progress = tokio::time::Instant::now();
        let mut previous = None;
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(), "Dilithium live node exited")?;
            let production = provider.call("admin_canonicalProofProduction", json!([block.hash()])).await?;
            let admission = receiver.call("admin_canonicalProofAdmission", json!([block.hash()])).await?;
            ensure(production["status"]["state"] != "failed", &format!("Dilithium production failed: {production}"))?;
            ensure(admission["status"]["state"] != "failed", &format!("Dilithium admission failed: {admission}"))?;
            let count = checkpoint_components(provider.node.store.as_ref(), block.hash())?;
            let height = receiver.node.chain_store.get_head_block()?.ok_or("Dilithium receiver head absent")?.number();
            let finalized = receiver.node.finality.read().last_finalized_number();
            let progress = json!({"components":count,"production":production["status"],"admission":admission,"height":height,"finalized":finalized});
            if previous.as_ref() != Some(&progress) {
                previous = Some(progress.clone()); last_progress = tokio::time::Instant::now();
                let tmp = network.join("progress.tmp");
                std::fs::write(&tmp, serde_json::to_vec(&progress)?)?;
                std::fs::rename(tmp, network.join("progress.json"))?;
                println!("Dilithium components={count}; height={height}; finalized={finalized}");
            }
            if pause && count > 0 { ensure(height == 0 && finalized == 0, "partial Dilithium proof changed native head")?; break; }
            if height == 1 && finalized == 1 {
                ensure(production["status"]["state"] == "complete" && admission["nativeCanonical"] == true && admission["status"]["state"] == "complete", "Dilithium import did not consume its proof")?;
                ensure(receiver.node.chain_store.get_receipts(&block.hash())?.map(serde_json::to_value).transpose()? == Some(expected["receipts"].clone()) && accounts(receiver.node.store.clone(), &block)? == expected["accounts"], "Dilithium peer native outputs differ")?;
                let manifest: CanonicalProofManifest = serde_json::from_value(admission["status"]["manifest"].clone())?;
                let cache = shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|v|v["proved_sender_signatures"] == 1 && v["proved_proposer_signature"] == true), "Dilithium import omitted full AIR")?;
                let bytes = cache.payload(&manifest.id())?;
                let proof = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
                let sender = &proof.transactions.first().ok_or("Dilithium sender proof absent")?.signature;
                let equation = &sender.transaction.signature.equation;
                let (bound, inner, seed) = if legacy_sender {(3,2,32)} else {(1,1,48)};
                let prop = proof.proposer.as_ref().ok_or("full proposer proof absent")?;
                let (prop_version, prop_seed) = if legacy_proposer {(2,32)} else {(1,48)};
                ensure(proof.version == 2 && proof.transactions.len() == 1 && sender.version == bound && sender.transaction.version == inner && sender.transaction.signature.version == inner && equation.challenge.version == inner && equation.challenge.seed == equation.signature.decoded.challenge[..seed] && prop.version == prop_version && prop.signature.version == prop_version && prop.signature.equation.challenge.version == prop_version && prop.signature.equation.challenge.seed == prop.signature.equation.signature.decoded.challenge[..prop_seed], "Dilithium/FIPS full proof profile mismatch")?;
                let path = network.join("proof.bin");
                if path.exists() { ensure(std::fs::read(&path)? == bytes, "retained Dilithium proof changed")?; } else { std::fs::write(path, &bytes)?; }
                write(&network.join("manifest.json"), &manifest)?;
                write(&network.join("complete.json"), &json!({"production":production["status"],"admission":admission,"height":height,"finalized":finalized,"genuine_dilithium_sender_primary_proposer_full_proof_admitted":legacy_sender && !legacy_proposer,"genuine_dilithium_proposer_primary_sender_full_proof_admitted":legacy_proposer && !legacy_sender,"genuine_dilithium_both_roles_full_proof_admitted":legacy_sender && legacy_proposer,"native_outputs_match":true,"served_chunks":faults.chunks.load(Ordering::SeqCst)}))?;
                break;
            }
            ensure(tokio::time::Instant::now() < deadline && last_progress.elapsed() < Duration::from_secs(1800), "Dilithium progress bound exceeded")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_, Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    if pause {
        write(
            &network.join("paused.json"),
            &json!({"gracefully_stopped":true}),
        )?;
    }
    Ok(())
}

pub(crate) fn snapshot(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-dilithium/provider/db"), None)?;
    let rows = stores
        .state
        .scan_prefix(b"local/canonical-production/v1/")?;
    let bytes: usize = rows
        .iter()
        .filter(|(k, _)| k != b"local/canonical-production/v1/bytes")
        .map(|(k, v)| k.len() + v.len())
        .sum();
    let recorded = stores
        .state
        .get(b"local/canonical-production/v1/bytes")?
        .unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
    ensure(
        recorded.as_slice() == (bytes as u64).to_be_bytes() && bytes <= 256 * 1024 * 1024,
        "Dilithium checkpoint accounting mismatch",
    )?;
    println!(
        "{}",
        json!({"native_digest":canonical_digest(&stores.state)?,"physical_checkpoint_bytes":bytes,"rows":rows.into_iter().map(|(k,v)|json!({"key":hex::encode(k),"bytes":v.len(),"hash":blake3_hash(&v)})).collect::<Vec<_>>()})
    );
    Ok(())
}

pub(crate) fn verify(out: &Path, advance: bool) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    ensure(
        network.join("complete.json").exists(),
        "Dilithium proof admission incomplete",
    )?;
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let expected: Value = read(&out.join("control.json"))?;
    let later: Block = read(&out.join("successor.json"))?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    if advance
        && node
            .chain_store
            .get_head_block()?
            .ok_or("Dilithium head absent")?
            .number()
            == 1
    {
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    let current = node
        .chain_store
        .get_head_block()?
        .ok_or("Dilithium head absent")?;
    let changed = current.number() == 2;
    ensure(
        current.hash() == if changed { later.hash() } else { block.hash() },
        "Dilithium current native head differs",
    )?;
    let control: Value = read(&out.join(if changed {
        "later-control.json"
    } else {
        "control.json"
    }))?;
    ensure(
        accounts(node.store.clone(), &current)? == control["accounts"]
            && node
                .chain_store
                .get_receipts(&current.hash())?
                .map(serde_json::to_value)
                .transpose()?
                == Some(control["receipts"].clone()),
        "Dilithium current native state differs",
    )?;
    let before = digest(node.store.as_ref())?;
    let proof = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(
        network.join("proof.bin"),
    )?)?;
    let replay =
        node.replay_canonical_transactions_with_proof(current.hash(), block.hash(), &proof)?;
    ensure(
        replay.proved_sender_signatures == 1
            && replay.proved_proposer_signature
            && replay.state_root.to_string() == expected["state_root"].as_str().unwrap_or_default()
            && serde_json::to_value(&replay.receipts)? == expected["receipts"],
        "Dilithium cold historical replay differs",
    )?;
    ensure(
        before == digest(node.store.as_ref())?,
        "Dilithium historical replay wrote current native KV",
    )?;
    let stem = if changed {
        "history-verified"
    } else {
        "verified"
    };
    let mut path = network.join(format!("{stem}.json"));
    let mut index = 2;
    while path.exists() {
        path = network.join(format!("{stem}-{index}.json"));
        index += 1;
    }
    write(
        &path,
        &json!({"all_kv_unchanged":true,"current_head":current.hash(),"current_height":current.number(),"ordinary_successor_not_proof_admitted":changed,"replay":replay}),
    )?;
    node.store.flush()?;
    Ok(())
}

pub(crate) fn negative(out: &Path) -> Result<(), Error> {
    let network = out.join("network-dilithium");
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let raw = std::fs::read(network.join("proof.bin"))?;
    let original = shell_stark_prover::compact_canonical::decode_payload(&raw)?;
    let (legacy_sender, legacy_proposer) = legacy_roles(out)?;
    let foreign = if legacy_proposer {
        &original
            .transactions
            .first()
            .ok_or("foreign sender proof absent")?
            .signature
            .transaction
            .signature
    } else {
        &original
            .proposer
            .as_ref()
            .ok_or("foreign proposer proof absent")?
            .signature
    };
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state),
        context.authority,
        &context.authority_key,
    )?;
    let tip = node
        .chain_store
        .get_head_hash()?
        .ok_or("Dilithium negative tip absent")?;
    let before = digest(node.store.as_ref())?;
    let mut results = Vec::new();
    let both = legacy_sender && legacy_proposer;
    let cases = if both {
        [
            ("foreign-key", "public key"),
            ("foreign-challenge", "challenge"),
            ("foreign-commitment", "final commitment"),
            ("relabelled-fips-profile", "version"),
        ]
    } else {
        [
            ("primary-key", "public key"),
            ("fips-challenge", "challenge"),
            ("fips-commitment", "final commitment"),
            ("relabelled-fips-profile", "version"),
        ]
    };
    for (index, (name, edge)) in cases.into_iter().enumerate() {
        let mut proof = original.clone();
        let target = if legacy_proposer {
            &mut proof
                .proposer
                .as_mut()
                .ok_or("raw proposer proof absent")?
                .signature
        } else {
            &mut proof.transactions[0].signature.transaction.signature
        };
        match index {
            0 => target.equation.key = foreign.equation.key.clone(),
            1 => target.equation.challenge = foreign.equation.challenge.clone(),
            2 => target.completion.commitment = foreign.completion.commitment.clone(),
            3 => target.version = 1,
            _ => unreachable!(),
        }
        let bytes =
            shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
        let decoded = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
        let error = node
            .replay_canonical_transactions_with_proof(tip, block.hash(), &decoded)
            .err()
            .ok_or("foreign transcript/certificate accepted")?
            .to_string();
        ensure(
            error.contains(edge)
                && before == digest(node.store.as_ref())?
                && raw == std::fs::read(network.join("proof.bin"))?,
            "Dilithium refusal changed original data or failed at wrong edge",
        )?;
        std::fs::write(network.join(format!("{name}-refused.cbor")), &bytes)?;
        results.push(json!({"case":name,"correct_outer_hash":blake3_hash(&bytes),"error":error,"all_kv_unchanged":true,"original_proof_unchanged":true,"new_proofs_generated":0}));
    }
    write(
        &network.join("refusals.json"),
        &json!({"genuine_primary_certificates":!both,"genuine_foreign_raw_certificates":both,"cases":results,"scope":"full historical predicate refusals, not new native block imports"}),
    )?;
    Ok(())
}
