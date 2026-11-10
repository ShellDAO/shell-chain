//! Genuine Native SLH-DSA controls and immutable canonical source reproduction.
use super::*;
use shell_crypto::{SphincsSigner, Verifier};

pub(crate) fn prepare(out: &Path) -> Result<(), Error> {
    if out.exists() {
        ensure(
            std::fs::read_dir(out)?.all(|p| p.is_ok_and(|p| p.file_name() == "commands")),
            "retained SLH inputs exist; refusing key replacement",
        )?;
    } else {
        std::fs::create_dir(out)?;
    }
    let sender = SphincsSigner::generate();
    let proposer = MlDsaSigner::generate();
    let address = Address::from_public_key(sender.public_key(), sender.sig_type().as_u8());
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    ensure(
        sender.public_key().len() == 64 && address != authority,
        "SLH actor profile",
    )?;
    let stores = dilithium::genesis(&out.join("native-original/db"), &sender, &proposer, false)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, false)?;
    let genesis_rows = stores.state.scan_all()?;
    let mut node = fixture::node(
        Arc::new(stores.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    node.config.canonical_proof_production = false;
    let original = dilithium::signed(&sender, 0)?;
    ensure(
        original.signature.data.len() == 49_856
            && MultiVerifier.verify(
                sender.public_key(),
                original.sender_signing_hash().as_bytes(),
                &original.signature,
            )?,
        "genuine FIPS205 signature refused",
    )?;
    write(&out.join("signed-first.json"), &original)?;
    let other = SphincsSigner::generate();
    let mut cases = Vec::new();
    for name in ["modified-message", "wrong-owner-signature"] {
        let mut rejected = original.clone();
        if name == "modified-message" {
            rejected.tx.value = U256::from(2);
        } else {
            rejected.signature = other.sign(original.sender_signing_hash().as_bytes())?;
        }
        write(&out.join(format!("{name}.json")), &rejected)?;
        let before = digest(node.store.as_ref())?;
        let error = node
            .handle_incoming_tx(rejected, &MultiVerifier)
            .err()
            .ok_or("invalid SLH owner/message accepted")?
            .to_string();
        ensure(
            before == digest(node.store.as_ref())?,
            "SLH refusal wrote state",
        )?;
        cases.push(json!({"case":name,"error":error,"all_kv_unchanged":true}));
    }
    write(
        &out.join("native-intake-refusals.json"),
        &json!({"cases":cases,"wrong_owner_key":other.public_key(),"private_keys_persisted":false}),
    )?;
    node.handle_incoming_tx(original.clone(), &MultiVerifier)?;
    let block = node.produce_block(&proposer, 100)?;
    ensure(
        block.transactions == vec![original],
        "SLH Native changed original transaction",
    )?;
    let vote = proposer.sign(block.hash().as_bytes())?;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        1,
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(authority, block.hash(), 1, vote.clone())
        .ok_or("SLH Native quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == 1,
        "SLH Native finality absent",
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    peer.import_block(block.clone(), &MultiVerifier)?;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        1,
        0,
        peer.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *peer.wpoa_round.lock() = Some(round);
    peer.handle_wpoa_vote(authority, block.hash(), 1, vote.clone())
        .ok_or("SLH independent Native quorum absent")?;
    ensure(
        peer.finality.read().last_finalized_number() == 1,
        "SLH independent Native finality absent",
    )?;
    let result = dilithium::control(&node, &block)?;
    ensure(
        dilithium::control(&peer, &block)? == result,
        "SLH Native import output mismatch",
    )?;
    write(&out.join("control.json"), &result)?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("quorum-vote.json"), &vote)?;
    write(
        &out.join("context.json"),
        &fixture::Context {
            version: 1,
            authority,
            authority_key: proposer.public_key().to_vec(),
            genesis_root: node
                .chain_store
                .get_header_by_hash(&block.header.parent_hash)?
                .ok_or("SLH genesis header absent")?
                .state_root,
            block: block.hash(),
            tip: block.hash(),
        },
    )?;
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
        .ok_or("SLH wrong root accepted")?
        .to_string();
    ensure(
        error.contains("state root mismatch") && before == failed.scan_all()?,
        "SLH rollback failed",
    )?;
    write(
        &out.join("native-rollback.json"),
        &json!({"error":error,"all_kv_unchanged":true,"native_control_not_proof_admission":true}),
    )?;
    stores.state.flush()?;
    std::fs::create_dir(out.join("provider"))?;
    stores.create_checkpoint(out.join("provider/db"))?;
    node.handle_incoming_tx(dilithium::signed(&sender, 1)?, &MultiVerifier)?;
    let successor = node.produce_block(&proposer, 100)?;
    write(&out.join("successor.json"), &successor)?;
    write(
        &out.join("later-control.json"),
        &dilithium::control(&node, &successor)?,
    )?;
    write(
        &out.join("actors.json"),
        &json!({"sender":address,"sender_key":sender.public_key(),"sender_algorithm":sender.sig_type(),"proposer_algorithm":proposer.sig_type(),"signature_bytes":49856,"public_key_bytes":64,"private_keys_persisted":false,"parameter":"SLH-DSA-SHA2-256f","native_fips205_pure_empty_context":true}),
    )?;
    stores.state.flush()?;
    receiver.state.flush()?;
    drop(peer);
    drop(receiver);
    drop(node);
    drop(stores);
    drop(other);
    drop(sender);
    drop(proposer);
    write(
        &out.join("native-complete.json"),
        &json!({"native_admission_execution_finality_and_independent_db_import":true,"original_signature_preserved":true,"private_keys_persisted":false,"ordinary_successor_signed":true,"native_is_not_full_signature_proof_admission":true}),
    )?;
    Ok(())
}

/// Recover a retained first block without signing or replacing any original input.
pub(crate) fn recover_native(out: &Path) -> Result<(), Error> {
    ensure(
        !out.join("provider/db").exists(),
        "SLH checkpoint already exists",
    )?;
    ensure(
        !out.join("native-complete.json").exists(),
        "SLH Native completion already exists",
    )?;
    let context: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let original: SignedTransaction = read(&out.join("signed-first.json"))?;
    ensure(
        block.transactions == vec![original.clone()] && block.hash() == context.block,
        "retained SLH block/input mismatch",
    )?;
    let stores = RocksDbStore::open_all(out.join("native-original/db"), None)?;
    let receiver = RocksDbStore::open_all(out.join("receiver/db"), None)?;
    let node = fixture::node(
        Arc::new(stores.state.clone()),
        context.authority,
        &context.authority_key,
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        context.authority,
        &context.authority_key,
    )?;
    let key = node
        .chain_store
        .get_pubkey(&original.from)?
        .ok_or("retained SLH registry key absent")?;
    ensure(
        key.len() == 64
            && block.header.proposer == context.authority
            && block
                .proposer_seal
                .as_ref()
                .is_some_and(|seal| seal.sig_type == shell_crypto::SignatureType::MlDsa65)
            && original.signature.sig_type == shell_crypto::SignatureType::SphincsSha2256f
            && original.signature.data.len() == 49_856
            && MultiVerifier.verify(
                &key,
                original.sender_signing_hash().as_bytes(),
                &original.signature,
            )?
            && node.chain_store.get_head_hash()? == Some(block.hash())
            && peer.chain_store.get_head_hash()? == Some(block.hash())
            && node.finality.read().last_finalized_number() == 1
            && peer.finality.read().last_finalized_number() == 1,
        "retained SLH Native identity/signature/finality mismatch",
    )?;
    let result: Value = read(&out.join("control.json"))?;
    ensure(
        dilithium::control(&node, &block)? == result
            && dilithium::control(&peer, &block)? == result,
        "retained SLH Native outputs changed",
    )?;
    std::fs::create_dir_all(out.join("provider"))?;
    stores.create_checkpoint(out.join("provider/db"))?;
    write(
        &out.join("actors.json"),
        &json!({"sender":original.from,"sender_key":key,"sender_algorithm":original.signature.sig_type,"proposer_algorithm":block.proposer_seal.as_ref().ok_or("retained SLH proposer seal absent")?.sig_type,"signature_bytes":original.signature.data.len(),"public_key_bytes":64,"private_keys_persisted":false,"parameter":"SLH-DSA-SHA2-256f","native_fips205_pure_empty_context":true}),
    )?;
    write(
        &out.join("native-complete.json"),
        &json!({"native_admission_execution_finality_and_independent_db_import":true,"original_signature_preserved":true,"private_keys_persisted":false,"retained_recovery_without_private_keys":true,"ordinary_successor_signed":false,"native_is_not_full_signature_proof_admission":true}),
    )?;
    Ok(())
}

pub(crate) fn capture(out: &Path, recovered: bool) -> Result<(), Error> {
    let path = out.join(if recovered {
        "capture-recovered.json"
    } else {
        "capture-original.json"
    });
    ensure(!path.exists(), "retained SLH source receipt exists")?;
    let stores = RocksDbStore::open_all(out.join("provider/db"), None)?;
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
        "SLH source capture wrote Native data",
    )?;
    match result {
        Ok(source) => {
            write(
                &path,
                &json!({"supported":true,"all_kv_unchanged":true,"identity_hash":blake3_hash(source.identity()),"full_signature_proof_admitted":false}),
            )?;
            std::fs::write(out.join("captured-source.json"), source.identity())?;
            Ok(())
        }
        Err(error) => {
            write(
                &path,
                &json!({"supported":false,"all_kv_unchanged":true,"error":error,"native_complete":true,"full_signature_proof_admitted":false}),
            )?;
            Err(error.into())
        }
    }
}
