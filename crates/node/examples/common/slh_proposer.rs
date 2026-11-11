//! Genuine SLH proposer controls and complete canonical seal acceptance.
use super::*;
use shell_crypto::{MlDsaSigner, SphincsSigner};

fn finalize(node: &Node<RocksDbStore>, signer: &dyn Signer, block: &Block) -> Result<(), Error> {
    let authority = block.header.proposer;
    let mut round = shell_consensus::wpoa_state::WPoaRound::new(
        block.number(),
        0,
        node.consensus.read().validator_weights(),
    );
    let _ = round.on_block_proposed(block.hash(), authority);
    *node.wpoa_round.lock() = Some(round);
    node.handle_wpoa_vote(
        authority,
        block.hash(),
        block.number(),
        signer.sign(block.hash().as_bytes())?,
    )
    .ok_or("SLH proposer Native quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == block.number(),
        "SLH Native finality absent",
    )
}
pub(crate) fn prepare(out: &Path) -> Result<(), Error> {
    ensure(
        !out.exists(),
        "SLH proposer output exists; refusing replacement",
    )?;
    let sender = MlDsaSigner::generate();
    let proposer = SphincsSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    std::fs::create_dir(out)?;
    let native = dilithium::genesis(&out.join("native/db"), &sender, &proposer, false)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, false)?;
    let mut node = fixture::node(
        Arc::new(native.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    let first = dilithium::signed(&sender, 0)?;
    node.handle_incoming_tx(first.clone(), &MultiVerifier)?;
    let block = node.produce_block(&proposer, 100)?;
    ensure(
        block.transactions == vec![first.clone()]
            && block.proposer_seal.as_ref().is_some_and(|s| {
                s.sig_type == shell_crypto::SignatureType::SphincsSha2256f && s.data.len() == 49856
            })
            && proposer.public_key().len() == 64,
        "Native proposer/primary sender profile differs",
    )?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    let before = digest(&receiver.state)?;
    let mut refusals = Vec::new();
    for case in ["seal-byte", "selected-authority", "header-message"] {
        let mut bad = block.clone();
        match case {
            "seal-byte" => bad.proposer_seal.as_mut().ok_or("seal absent")?.data[0] ^= 1,
            "selected-authority" => bad.header.proposer = Address::from([0x44; 32]),
            _ => bad.header.timestamp += 1,
        }
        let error = peer
            .import_block(bad, &MultiVerifier)
            .err()
            .ok_or("invalid SLH proposer imported")?
            .to_string();
        ensure(
            before == digest(&receiver.state)?,
            "SLH proposer refusal wrote Native state",
        )?;
        refusals.push(json!({"case":case,"error":error,"native_unchanged":true}));
    }
    write(&out.join("native-refusals.json"), &refusals)?;
    peer.import_block(block.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &block)?;
    finalize(&peer, &proposer, &block)?;
    let control = dilithium::control(&node, &block)?;
    ensure(
        dilithium::control(&peer, &block)? == control,
        "SLH proposer Native controls differ",
    )?;
    std::fs::create_dir(out.join("provider"))?;
    native.create_checkpoint(out.join("provider/db"))?;
    write(
        &out.join("context.json"),
        &fixture::Context {
            version: 1,
            authority,
            authority_key: proposer.public_key().to_vec(),
            genesis_root: node
                .chain_store
                .get_header_by_hash(&block.header.parent_hash)?
                .ok_or("genesis absent")?
                .state_root,
            block: block.hash(),
            tip: block.hash(),
        },
    )?;
    write(&out.join("signed-first.json"), &first)?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("control.json"), &control)?;
    let next = dilithium::signed(&sender, 1)?;
    node.handle_incoming_tx(next.clone(), &MultiVerifier)?;
    let later = node.produce_block(&proposer, 100)?;
    ensure(
        later.number() == 2
            && later.header.state_root != block.header.state_root
            && later.transactions == vec![next.clone()],
        "SLH proposer later state did not change",
    )?;
    peer.import_block(later.clone(), &MultiVerifier)?;
    finalize(&node, &proposer, &later)?;
    finalize(&peer, &proposer, &later)?;
    ensure(
        dilithium::control(&node, &later)? == dilithium::control(&peer, &later)?,
        "later Native controls differ",
    )?;
    std::fs::create_dir(out.join("native-later"))?;
    native.create_checkpoint(out.join("native-later/db"))?;
    write(&out.join("later.json"), &later)?;
    write(&out.join("later-signed.json"), &next)?;
    write(
        &out.join("later-control.json"),
        &dilithium::control(&node, &later)?,
    )?;
    drop(sender);
    drop(proposer);
    write(
        &out.join("prepared.json"),
        &json!({"independent_new_native_control":true,"primary_MLDSA_sender":true,"SLH_proposer_key_bytes":64,"SLH_seal_bytes":49856,"first_native_import_and_finality":true,"later_native_state_changed":true,"private_keys_memory_only_dropped":true}),
    )
}
pub(crate) fn capture(out: &Path) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let db = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&db.state)?;
    let source = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(db.state.clone())),
        c.tip,
        c.block,
    )?;
    let value: Value = serde_json::from_slice(source.identity())?;
    ensure(
        before == digest(&db.state)?,
        "proposer capture wrote Native state",
    )?;
    if value["version"] != 8
        || value["proposer_key"]
            .as_array()
            .is_none_or(|v| v.len() != 64)
    {
        if !out.join("sender-only-source.json").exists() {
            write(&out.join("sender-only-source.json"), &value)?;
        }
        return Err("SLH proposer seal absent from captured source; Native fallback cannot qualify full proposer proof".into());
    }
    let path = out.join("source.json");
    if path.exists() {
        ensure(
            read::<Value>(&path)? == value,
            "retained proposer source differs; refusing replacement",
        )
    } else {
        write(&path, &value)
    }
}

pub(crate) fn prove(out: &Path, pause: bool) -> Result<(), Error> {
    use shell_stark_prover::{
        canonical_producer::CanonicalProductionSource,
        production_store::{ProductionError, ProductionStore},
    };
    let c: fixture::Context = read(&out.join("context.json"))?;
    let native = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&native.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(native.state.clone())),
        c.tip,
        c.block,
    )?;
    ensure(source.has_slh_proposer(), "full SLH proposer source absent")?;
    std::fs::create_dir_all(out.join("proof"))?;
    let mut kv = RocksDbStore::open_all(out.join("proof/db"), None)?.state;
    let mut job = ProductionStore::open_slh(
        &mut kv,
        source.identity(),
        if pause {
            std::num::NonZeroUsize::new(1)
        } else {
            None
        },
    )?;
    let result = source.produce(&mut job);
    write(
        &out.join(if pause {
            "proof-paused.json"
        } else {
            "proof-progress.json"
        }),
        &job.progress(),
    )?;
    drop(job);
    if pause {
        ensure(
            matches!(result, Err(ProductionError::Paused)),
            "proposer proof did not durably pause",
        )?;
        return Ok(());
    }
    let proof = result?;
    source.verify(&proof)?;
    let payload =
        shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
    let decoded = shell_stark_prover::compact_canonical::decode_payload(&payload)?;
    source.verify(&decoded)?;
    let path = out.join("proof.cbor");
    if path.exists() {
        ensure(
            std::fs::read(&path)? == payload,
            "immutable SLH proposer graph differs",
        )?;
    } else {
        std::fs::write(&path, &payload)?;
    }
    let manifest = shell_storage::CanonicalProofManifest {
        version: 1,
        chain_id: 10,
        genesis_hash: source.genesis_hash(),
        block_hash: c.block,
        total_bytes: payload.len() as u64,
        payload_hash: blake3_hash(&payload),
    };
    write(&out.join("manifest.json"), &manifest)?;
    ensure(
        before == digest(&native.state)?,
        "proving changed Native source",
    )?;
    write(
        &out.join("proof-complete.json"),
        &json!({"source_version":8,"batch_version":4,"frame_version":5,"proposer_full17_layers":true,"source_native_unchanged":true,"new_signing":false,"proof_bytes":payload.len()}),
    )
}
pub(crate) fn verify(out: &Path, refuse: bool) -> Result<(), Error> {
    use shell_stark_prover::canonical_producer::CanonicalProductionSource;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let payload = std::fs::read(out.join("proof.cbor"))?;
    let proof = shell_stark_prover::compact_canonical::decode_payload(&payload)?;
    let original = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let original_before = digest(&original.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(original.state.clone())),
        c.tip,
        c.block,
    )?;
    source.verify(&proof)?;
    let certificate = ChainStore::new(Arc::new(original.state.clone()))
        .get_commit_certificate(&c.block)?
        .ok_or("original SLH certificate absent")?;
    ensure(
        original_before == digest(&original.state)?,
        "proposer verification changed Native input",
    )?;
    // Parent reconstruction takes its own exclusive source handle.
    drop(original);
    let directory = if refuse {
        "refused-control"
    } else {
        "verified-control"
    };
    if !out.join(directory).exists() {
        super::prepare_from(out, directory, &out.join("provider/db"))?;
    }
    let fresh =
        Arc::new(RocksDbStore::open_all(out.join(directory).join("receiver/db"), None)?.state);
    let mut node = fixture::node(fresh.clone(), c.authority, &c.authority_key)?;
    if refuse {
        ensure(
            node.chain_store.get_head_hash()? == Some(block.header.parent_hash),
            "negative proposer receiver not at genesis",
        )?;
        let before = digest(fresh.as_ref())?;
        let mut results = Vec::new();
        for case in [
            "missing-proposer",
            "wrong-profile",
            "missing-layer",
            "changed-signature",
            "foreign-header-certificate",
        ] {
            let mut bad = proof.clone();
            match case {
                "missing-proposer" => bad.slh_proposer = None,
                "wrong-profile" => bad.version = 2,
                "missing-layer" => {
                    bad.slh_proposer.as_mut().ok_or("SLH absent")?.layers.pop();
                }
                "changed-signature" => {
                    bad.slh_proposer
                        .as_mut()
                        .ok_or("SLH absent")?
                        .fors
                        .inputs
                        .signature[0] ^= 1
                }
                _ => {
                    let valid = &bad.transactions[0].signature.transaction_id;
                    bad.slh_proposer
                        .as_mut()
                        .ok_or("SLH absent")?
                        .header
                        .canonical = valid.clone();
                }
            }
            let error = node
                .import_block_with_canonical_proof(block.header.parent_hash, block.clone(), &bad)
                .err()
                .ok_or("invalid SLH proposer graph imported")?
                .to_string();
            ensure(
                before == digest(fresh.as_ref())?,
                "proposer graph refusal wrote Native state",
            )?;
            results.push(json!({"case":case,"error":error,"native_unchanged":true}));
        }
        return write(&out.join("refused.json"), &results);
    }
    let control: Value = read(&out.join("control.json"))?;
    if node.chain_store.get_head_hash()? == Some(block.header.parent_hash) {
        let imported = node.import_block_with_canonical_proof(
            block.header.parent_hash,
            block.clone(),
            &proof,
        )?;
        ensure(
            imported.proved_proposer_signature
                && imported.proved_sender_signatures == 1
                && serde_json::to_value(&imported.receipts)? == control["receipts"]
                && accounts(fresh.clone(), &block)? == control["accounts"],
            "full SLH proposer import differs from Native",
        )?;
        ensure(
            node.fast_finalize_with_certificate(1, c.block, &certificate),
            "proof-backed SLH proposer child did not finalize",
        )?;
        write(
            &out.join("proof-import.json"),
            &json!({"actual_import":imported,"finalized_height":1,"native_controls_match":true}),
        )?;
    }
    let later: Block = read(&out.join("later.json"))?;
    if node.chain_store.get_head_hash()? == Some(c.block) {
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    ensure(
        node.chain_store.get_head_hash()? == Some(later.hash())
            && node.world_state.write().state_root()? == later.header.state_root
            && later.header.state_root != block.header.state_root,
        "proposer history did not advance",
    )?;
    let before = digest(fresh.as_ref())?;
    let replay = node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    let ordinary = Arc::new(RocksDbStore::open_all(out.join("native-later/db"), None)?.state);
    let ordinary_before = digest(ordinary.as_ref())?;
    let ordinary_node = fixture::node(ordinary.clone(), c.authority, &c.authority_key)?;
    let second =
        ordinary_node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    ensure(
        replay.proved_proposer_signature
            && second.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && second.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && serde_json::to_value(&second.receipts)? == control["receipts"]
            && before == digest(fresh.as_ref())?
            && ordinary_before == digest(ordinary.as_ref())?,
        "SLH proposer historical replay differs or writes back",
    )?;
    write(
        &out.join("verified.json"),
        &json!({"full_SLH_proposer_AIR":true,"actual_proof_import":true,"changed_current_height":2,"read_only_historical_replay":replay,"ordinary_Native_history_matches":true,"both_Native_databases_unchanged":true,"new_signing":false}),
    )
}

pub(crate) fn publish(out: &Path) -> Result<(), Error> {
    use shell_storage::{CanonicalProofUploadState, CanonicalProofUploadStore};
    let published = out.join("published");
    ensure(
        !published.exists(),
        "published output exists; refusing replacement",
    )?;
    let original = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    let manifest: CanonicalProofManifest = read(&out.join("manifest.json"))?;
    let payload = std::fs::read(out.join("proof.cbor"))?;
    ensure(
        payload.len() as u64 == manifest.total_bytes
            && blake3_hash(&payload) == manifest.payload_hash,
        "completed proposer frame/manifest mismatch",
    )?;
    std::fs::create_dir(&published)?;
    std::fs::create_dir(published.join("provider"))?;
    original.create_checkpoint(published.join("provider/db"))?;
    let db = RocksDbStore::open_all(published.join("provider/db"), None)?;
    let store = CanonicalProofUploadStore::new(Arc::new(db.state));
    let id = store.begin(manifest.clone())?.proof_id;
    for (index, chunk) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        store.append(&id, index as u32, chunk)?;
    }
    let status = store.status(&id)?;
    ensure(
        status.state == CanonicalProofUploadState::Ready
            && status.result.is_none()
            && store.payload(&id)? == payload
            && before == digest(&original.state)?,
        "proposer proof publication differs or changed Native input",
    )?;
    std::fs::write(published.join("proof.cbor"), &payload)?;
    write(&published.join("manifest.json"), &manifest)?;
    write(
        &published.join("published.json"),
        &json!({"availability_only":true,"outer_hash_checked":true,"native_original_unchanged":true,"payload_bytes":payload.len(),"new_math":0,"new_signing":false}),
    )
}
