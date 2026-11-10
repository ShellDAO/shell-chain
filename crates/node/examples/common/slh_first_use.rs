//! Retained genuine SLH signature in an independent funded first-use lifecycle.
use super::*;
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_stark_prover::canonical_producer::CanonicalProductionSource;
use shell_stark_prover::{
    compact_canonical::{decode_payload, encode_component, encode_payload},
    production_store::{ProductionError, ProductionStore},
};
use std::num::NonZeroUsize;

struct PublicSlh {
    key: Vec<u8>,
    calls: AtomicUsize,
}
impl Signer for PublicSlh {
    fn public_key(&self) -> &[u8] {
        &self.key
    }
    fn sig_type(&self) -> SignatureType {
        SignatureType::SphincsSha2256f
    }
    fn sign(&self, _: &[u8]) -> Result<PQSignature, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CryptoError::SigningFailed(
            "retained SLH actor has no private key".into(),
        ))
    }
}
fn finalize(node: &Node<RocksDbStore>, proposer: &dyn Signer, block: &Block) -> Result<(), Error> {
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
        proposer.sign(block.hash().as_bytes())?,
    )
    .ok_or("first-use native quorum absent")?;
    ensure(
        node.finality.read().last_finalized_number() == block.number(),
        "native certificate did not finalize",
    )
}
fn prepare(original: &Path, out: &Path) -> Result<(), Error> {
    ensure(
        !out.exists(),
        "first-use output exists; refusing replacement",
    )?;
    let context: fixture::Context = read(&original.join("context.json"))?;
    let old_block: Block = read(&original.join("candidate.json"))?;
    let reference: SignedTransaction = read(&original.join("signed-first.json"))?;
    let old = RocksDbStore::open_all(original.join("provider/db"), None)?;
    let before = digest(&old.state)?;
    let chain = ChainStore::new(Arc::new(old.state.clone()));
    let key = chain
        .canonical_parent_view(context.tip, old_block.header.parent_hash)?
        .registered_key(&reference.from)?
        .ok_or("original SLH public key absent")?;
    ensure(
        reference.signature.sig_type == SignatureType::SphincsSha2256f
            && key.len() == 64
            && reference.signature.data.len() == 49856
            && Address::from_public_key(&key, reference.signature.sig_type.as_u8())
                == reference.from
            && MultiVerifier.verify(
                &key,
                reference.sender_signing_hash().as_bytes(),
                &reference.signature,
            )?,
        "retained genuine SLH inputs mismatch",
    )?;
    let sender = PublicSlh {
        key,
        calls: AtomicUsize::new(0),
    };
    let proposer = MlDsaSigner::generate();
    let authority = Address::from_public_key(proposer.public_key(), proposer.sig_type().as_u8());
    std::fs::create_dir(out)?;
    let native = dilithium::genesis(&out.join("native/db"), &sender, &proposer, true)?;
    let receiver = dilithium::genesis(&out.join("receiver/db"), &sender, &proposer, true)?;
    let mut node = fixture::node(
        Arc::new(native.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    node.config.proposer_address = Some(authority);
    node.config.node_role = shell_node::NodeRole::ValidatorProver;
    ensure(
        node.chain_store.get_pubkey(&reference.from)?.is_none()
            && node
                .world_state
                .read()
                .get_account(&reference.from)?
                .is_some_and(|a| a.pq_pubkey_hash == ShellHash::ZERO),
        "first-use parent was bound or registered",
    )?;
    let mut first = reference.clone();
    first.pubkey_mode = shell_core::PubkeyMode::Embedded(sender.key.clone());
    ensure(
        first.tx == reference.tx
            && first.signature == reference.signature
            && first.sender_signing_hash() == reference.sender_signing_hash()
            && first.uncached_hash() == reference.uncached_hash(),
        "Embedded mode changed original signed identity",
    )?;
    let mut cases = Vec::new();
    for name in [
        "reference-without-key",
        "wrong-derived-address",
        "changed-message",
        "wrong-embedded-key",
    ] {
        let mut bad = first.clone();
        match name {
            "reference-without-key" => bad.pubkey_mode = shell_core::PubkeyMode::Reference,
            "wrong-derived-address" => bad.from = Address::from([0x12; 32]),
            "changed-message" => bad.tx.value = U256::from(2),
            _ => {
                let mut key = sender.key.clone();
                key[0] ^= 1;
                bad.pubkey_mode = shell_core::PubkeyMode::Embedded(key);
            }
        }
        let snapshot = digest(node.store.as_ref())?;
        let error = node
            .handle_incoming_tx(bad, &MultiVerifier)
            .err()
            .ok_or("invalid Native first-use accepted")?
            .to_string();
        ensure(
            snapshot == digest(node.store.as_ref())?
                && node.chain_store.get_pubkey(&first.from)?.is_none(),
            "Native first-use refusal wrote state or key",
        )?;
        cases.push(
            json!({"case":name,"error":error,"native_unchanged":true,"key_registered":false}),
        );
    }
    write(&out.join("native-refusals.json"), &cases)?;
    node.handle_incoming_tx(first.clone(), &MultiVerifier)?;
    ensure(
        node.chain_store.get_pubkey(&first.from)?.is_none(),
        "mempool registered key prematurely",
    )?;
    let block = node.produce_block(&proposer, 100)?;
    ensure(
        block.transactions == vec![first.clone()]
            && node.chain_store.get_pubkey(&first.from)?.as_deref() == Some(sender.public_key())
            && node
                .world_state
                .read()
                .get_account(&first.from)?
                .is_some_and(|a| a.nonce == 1),
        "first-use Native execution or key binding failed",
    )?;
    finalize(&node, &proposer, &block)?;
    let peer = fixture::node(
        Arc::new(receiver.state.clone()),
        authority,
        proposer.public_key(),
    )?;
    peer.import_block(block.clone(), &MultiVerifier)?;
    finalize(&peer, &proposer, &block)?;
    let control = dilithium::control(&node, &block)?;
    ensure(
        dilithium::control(&peer, &block)? == control,
        "independent Native first-use root/receipts/accounts differ",
    )?;
    std::fs::create_dir(out.join("provider"))?;
    native.create_checkpoint(out.join("provider/db"))?;
    write(&out.join("candidate.json"), &block)?;
    write(&out.join("signed-first.json"), &first)?;
    write(&out.join("original-signed-first.json"), &reference)?;
    write(&out.join("control.json"), &control)?;
    write(
        &out.join("context.json"),
        &fixture::Context {
            version: 1,
            authority,
            authority_key: proposer.public_key().to_vec(),
            genesis_root: node
                .chain_store
                .get_header_by_hash(&block.header.parent_hash)?
                .ok_or("genesis missing")?
                .state_root,
            block: block.hash(),
            tip: block.hash(),
        },
    )?;
    let mut tx = first.tx.clone();
    tx.nonce = 0;
    tx.max_fee_per_gas = 1;
    tx.max_priority_fee_per_gas = 0;
    let later_tx = SignedTransaction::new(
        authority,
        tx.clone(),
        proposer.sign(tx.signing_hash(proposer.sig_type().as_u8()).as_bytes())?,
    );
    write(&out.join("later-signed.json"), &later_tx)?;
    node.handle_incoming_tx(later_tx.clone(), &MultiVerifier)?;
    let later = node.produce_block(&proposer, 100)?;
    ensure(
        later.number() == 2
            && later.transactions == vec![later_tx]
            && later.header.state_root != block.header.state_root,
        "independent later state did not change",
    )?;
    finalize(&node, &proposer, &later)?;
    peer.import_block(later.clone(), &MultiVerifier)?;
    finalize(&peer, &proposer, &later)?;
    ensure(
        dilithium::control(&node, &later)? == dilithium::control(&peer, &later)?,
        "later Native control differs",
    )?;
    std::fs::create_dir(out.join("native-later"))?;
    native.create_checkpoint(out.join("native-later/db"))?;
    write(&out.join("later.json"), &later)?;
    write(
        &out.join("later-control.json"),
        &dilithium::control(&node, &later)?,
    )?;
    ensure(
        sender.calls.load(Ordering::SeqCst) == 0 && before == digest(&old.state)?,
        "original SLH signing or Native input mutation",
    )?;
    write(
        &out.join("prepared.json"),
        &json!({"independent_funded_unbound_profile":true,"same_original_transaction_signature_signing_hash_id":true,"original_native_unchanged":true,"new_slh_signatures":0,"original_successor2_signed":false,"new_proposer_memory_only":true,"native_first_use_and_key_registration":true,"mempool_does_not_register":true,"separate_later_state_changed":true,"original_bound_history_not_replaced":true,"original_native_digest":before}),
    )
}
fn capture(out: &Path) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let db = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&db.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(db.state.clone())),
        c.tip,
        c.block,
    );
    ensure(
        before == digest(&db.state)?,
        "source capture changed Native data",
    )?;
    match source {
        Ok(s) => {
            write(
                &out.join("source.json"),
                &serde_json::from_slice::<Value>(s.identity())?,
            )?;
            Ok(())
        }
        Err(error) => {
            write(
                &out.join("capture-error.json"),
                &json!({"error":error,"native_unchanged":true}),
            )?;
            Err(error.into())
        }
    }
}
fn source(out: &Path) -> Result<(fixture::Context, Block, CanonicalProductionSource), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let db = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let chain = ChainStore::new(Arc::new(db.state));
    ensure(
        chain
            .canonical_parent_view(c.tip, block.header.parent_hash)?
            .registered_key(&block.transactions[0].from)?
            .is_none(),
        "historical first-use parent contains a future key",
    )?;
    let source = CanonicalProductionSource::capture(&chain, c.tip, c.block)?;
    Ok((c, block, source))
}
fn prove(original: &Path, reference: &Path, out: &Path, pause: bool) -> Result<(), Error> {
    let (c, block, current) = source(out)?;
    let old_c: fixture::Context = read(&original.join("context.json"))?;
    let old_tx: SignedTransaction = read(&original.join("signed-first.json"))?;
    let old_db = RocksDbStore::open_all(original.join("provider/db"), None)?;
    let original_before = digest(&old_db.state)?;
    let reference_bytes = std::fs::read(reference.join("proof.cbor"))?;
    let bound = decode_payload(&reference_bytes)?;
    CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(old_db.state.clone())),
        old_c.tip,
        old_c.block,
    )?
    .verify(&bound)?;
    let old = bound
        .slh_transactions
        .as_ref()
        .and_then(|v| v.first())
        .ok_or("bound SLH reference absent")?;
    ensure(
        block.transactions[0].tx == old_tx.tx
            && block.transactions[0].signature == old_tx.signature
            && block.transactions[0].uncached_hash() == old_tx.uncached_hash(),
        "first-use changed original signature/transaction/identity",
    )?;
    let message = shell_core::block_body_leaf_message(&block.transactions[0], 0);
    let body_inputs = shell_stark_prover::blake3_hash::large_body_witness_inputs(&message)?;
    let reuse = |name: &str| -> Result<Option<Vec<u8>>, String> {
        macro_rules! component {
            ($v:expr) => {
                encode_component($v).map(Some)
            };
        }
        if let Some(at) = name.strip_prefix("sender-0-fors-") {
            return component!(old
                .fors
                .hashes
                .get(at.parse::<usize>().map_err(|e| e.to_string())?)
                .ok_or("FORS reference absent")?);
        }
        if name == "sender-0-seed-prefix" {
            return component!(&old.layers[0].prefix);
        }
        if let Some(at) = name.strip_prefix("sender-0-layer-") {
            let parts: Vec<_> = at.split('-').collect();
            if parts.len() != 3 {
                return Err("layer reference name invalid".into());
            }
            let layer = old
                .layers
                .get(parts[0].parse::<usize>().map_err(|e| e.to_string())?)
                .ok_or("layer reference absent")?;
            let at = parts[2].parse::<usize>().map_err(|e| e.to_string())?;
            return match parts[1] {
                "chain" => component!(layer
                    .chains
                    .get(at.checked_sub(1).ok_or("chain ordinal invalid")?)
                    .ok_or("chain reference absent")?),
                "hash" if at == 0 => component!(&layer.wots_public_key),
                "hash" => component!(layer
                    .authentication
                    .get(at - 1)
                    .ok_or("authentication reference absent")?),
                _ => Err("layer reference kind invalid".into()),
            };
        }
        if let Some(at) = name.strip_prefix("sender-0-body-group-") {
            let start = at.parse::<usize>().map_err(|e| e.to_string())? * 16;
            let end = (start + 16).min(body_inputs.len());
            let prior = old.envelope.body.leaf.compressions.get(start..end);
            if let Some(prior) = prior.filter(|p| {
                p.len() == end - start
                    && p.iter()
                        .zip(&body_inputs[start..end])
                        .all(|(p, input)| p.input == *input)
            }) {
                return component!(&prior.to_vec());
            }
            return Ok(None);
        }
        match name {
            "sender-0-key-hash" => component!(&old.public_key_hash),
            "sender-0-signing-hash" => component!(&old.envelope.signing_hash),
            "sender-0-id" => component!(&old.envelope.transaction_id),
            // Account, tagged address, Embedded entry leaf, changed envelope
            // routes and the independent proposer require their own statements.
            _ => Ok(None),
        }
    };
    std::fs::create_dir_all(out.join("proof"))?;
    let mut kv = RocksDbStore::open_all(out.join("proof/db"), None)?.state;
    let mut job = ProductionStore::open_slh(
        &mut kv,
        current.identity(),
        if pause { NonZeroUsize::new(1) } else { None },
    )?
    .with_reuse(&reuse);
    let result = current.produce(&mut job);
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
            "first-use component budget did not pause",
        )?;
        return Ok(());
    }
    let proof = result?;
    current.verify(&proof)?;
    ensure(
        proof
            .slh_transactions
            .as_ref()
            .is_some_and(|v| v.len() == 1 && v[0].version == 2 && v[0].tagged_key.is_some()),
        "unbound address proof profile absent",
    )?;
    let payload = encode_payload(&proof, 256 * 1024 * 1024, true)?;
    let manifest = CanonicalProofManifest {
        version: 1,
        chain_id: 10,
        genesis_hash: current.genesis_hash(),
        block_hash: c.block,
        total_bytes: payload.len() as u64,
        payload_hash: blake3_hash(&payload),
    };
    let published = out.join("published");
    std::fs::create_dir_all(published.join("provider"))?;
    for path in [out.join("proof.cbor"), published.join("proof.cbor")] {
        if path.exists() {
            ensure(
                std::fs::read(&path)? == payload,
                "immutable first-use proof differs",
            )?;
        } else {
            std::fs::write(path, &payload)?;
        }
    }
    write(&out.join("manifest.json"), &manifest)?;
    write(&published.join("manifest.json"), &manifest)?;
    let native = RocksDbStore::open_all(out.join("provider/db"), None)?;
    if !published.join("provider/db/CURRENT").exists() {
        native.create_checkpoint(published.join("provider/db"))?;
    }
    let provider = RocksDbStore::open_all(published.join("provider/db"), None)?;
    let native_before = canonical_digest(&provider.state)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(Arc::new(provider.state.clone()));
    let status = cache.begin(manifest)?;
    let id = status.proof_id;
    for (i, part) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        if i < (status.next_chunk as usize) {
            ensure(
                cache.chunk(&id, i as u32)? == part,
                "cached first-use chunk differs",
            )?;
        } else {
            cache.append(&id, i as u32, part)?;
        }
    }
    ensure(
        cache.payload(&id)? == payload
            && cache.status(&id)?.result.is_none()
            && native_before == canonical_digest(&provider.state)?
            && original_before == digest(&old_db.state)?
            && reference_bytes == std::fs::read(reference.join("proof.cbor"))?,
        "publication changed Native inputs or cached bytes",
    )?;
    write(
        &out.join("proof-complete.json"),
        &json!({"source_version":7,"sender_proof_version":2,"full_signature_and_address_AIR":true,"original_signature_unchanged":true,"original_reference_unchanged":true,"native_unchanged":true,"ready_cache_not_execution":true,"payload_bytes":payload.len(),"new_slh_signing":false}),
    )
}
fn verify(out: &Path, refuse: bool) -> Result<(), Error> {
    let (c, block, source) = source(out)?;
    let proof = decode_payload(&std::fs::read(out.join("proof.cbor"))?)?;
    source.verify(&proof)?;
    let path = out
        .parent()
        .ok_or("first-use output parent absent")?
        .join(format!(
            "{}-{}",
            out.file_name()
                .ok_or("output name absent")?
                .to_string_lossy(),
            if refuse { "refused" } else { "verified" }
        ));
    if !path.join("receiver/db/CURRENT").exists() {
        slh_peer::command("slh-peer-prepare", out, &out.join("published"), &path)?;
    }
    let fresh = Arc::new(RocksDbStore::open_all(path.join("receiver/db"), None)?.state);
    let mut node = fixture::node(fresh.clone(), c.authority, &c.authority_key)?;
    if refuse {
        ensure(
            node.chain_store.get_head_hash()? == Some(block.header.parent_hash)
                && node
                    .chain_store
                    .get_pubkey(&block.transactions[0].from)?
                    .is_none(),
            "negative receiver was not unregistered genesis",
        )?;
        let before = digest(fresh.as_ref())?;
        let mut cases = Vec::new();
        for name in [
            "bound-proof-version",
            "missing-address",
            "foreign-valid-address",
            "changed-signature",
            "changed-envelope",
        ] {
            let mut rejected = proof.clone();
            let entry = &mut rejected.slh_transactions.as_mut().ok_or("SLH absent")?[0];
            match name {
                "bound-proof-version" => entry.version = 1,
                "missing-address" => entry.tagged_key = None,
                "foreign-valid-address" => {
                    entry.tagged_key = Some(entry.envelope.signing_hash.clone())
                }
                "changed-signature" => entry.fors.inputs.signature[0] ^= 1,
                _ => {
                    entry.envelope.body.leaf.message[0] ^= 1;
                }
            }
            let error = source
                .verify(&rejected)
                .err()
                .ok_or("invalid first-use proof accepted")?;
            let import_error = node
                .import_block_with_canonical_proof(
                    block.header.parent_hash,
                    block.clone(),
                    &rejected,
                )
                .err()
                .ok_or("invalid first-use proof imported")?
                .to_string();
            ensure(
                before == digest(fresh.as_ref())?
                    && node
                        .chain_store
                        .get_pubkey(&block.transactions[0].from)?
                        .is_none(),
                "refused first-use import registered key or wrote Native state",
            )?;
            cases.push(json!({"case":name,"error":error,"import_error":import_error,"native_unchanged":true,"key_registered":false}));
        }
        return write(&out.join("refused.json"), &cases);
    }
    let native = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let control: Value = read(&out.join("control.json"))?;
    let later: Block = read(&out.join("later.json"))?;
    if node.chain_store.get_head_hash()? == Some(block.header.parent_hash) {
        let result = node.import_block_with_canonical_proof(
            block.header.parent_hash,
            block.clone(),
            &proof,
        )?;
        ensure(
            serde_json::to_value(
                node.chain_store
                    .get_receipts(&c.block)?
                    .ok_or("first-use receipts absent")?,
            )? == control["receipts"]
                && accounts(fresh.clone(), &block)? == control["accounts"]
                && node
                    .chain_store
                    .get_pubkey(&block.transactions[0].from)?
                    .as_deref()
                    == block.transactions[0].pubkey_mode.pubkey_bytes(),
            "proof-backed Native first-use output or key registration differs",
        )?;
        let cert = ChainStore::new(Arc::new(native.state.clone()))
            .get_commit_certificate(&c.block)?
            .ok_or("first-use signed certificate absent")?;
        ensure(
            node.fast_finalize_with_certificate(1, c.block, &cert),
            "first-use proof-backed import did not finalize",
        )?;
        write(
            &out.join("proof-import.json"),
            &json!({"imported":result,"native_control_matches":true,"key_registered_after_commit":true,"finalized_height":1}),
        )?;
    }
    if node.chain_store.get_head_hash()? == Some(c.block) {
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    ensure(
        node.chain_store.get_head_hash()? == Some(later.hash())
            && node.world_state.write().state_root()? == later.header.state_root,
        "later state did not advance proof receiver",
    )?;
    let current = Arc::new(RocksDbStore::open_all(out.join("native-later/db"), None)?.state);
    let before = digest(current.as_ref())?;
    let control_node = fixture::node(current.clone(), c.authority, &c.authority_key)?;
    ensure(
        control_node
            .chain_store
            .get_head_block()?
            .is_some_and(|b| b.number() == 2 && b.header.state_root != block.header.state_root)
            && control_node
                .chain_store
                .get_pubkey(&block.transactions[0].from)?
                .is_some(),
        "later Native state or registration absent",
    )?;
    let receiver_before = digest(fresh.as_ref())?;
    let replay = node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    let ordinary_replay =
        control_node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    ensure(
        replay.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && serde_json::to_value(&ordinary_replay.receipts)? == control["receipts"]
            && before == digest(current.as_ref())?
            && receiver_before == digest(fresh.as_ref())?,
        "historical first-use replay differs or wrote current state",
    )?;
    write(
        &out.join("verified.json"),
        &json!({"full_AIR_verified":true,"current_height":2,"current_state_changed":true,"historical_parent_key_absent":true,"current_key_present":true,"read_only_historical_replay":replay,"native_unchanged":true,"original_bound_successor2_not_replaced":true}),
    )
}
pub(crate) fn command(
    mode: &str,
    original: &Path,
    reference: &Path,
    out: &Path,
) -> Result<(), Error> {
    let input = original.canonicalize()?;
    let output = if out.exists() {
        out.canonicalize()?
    } else {
        out.parent()
            .unwrap_or(Path::new("."))
            .canonicalize()?
            .join(out.file_name().ok_or("output absent")?)
    };
    ensure(
        !output.starts_with(&input) && !input.starts_with(&output),
        "first-use output overlaps original Native inputs",
    )?;
    let reference_path = reference.canonicalize()?;
    ensure(
        !output.starts_with(&reference_path) && !reference_path.starts_with(&output),
        "first-use output overlaps reference",
    )?;
    match mode {
        "slh-first-use-prepare" => prepare(original, &output),
        "slh-first-use-capture" => capture(&output),
        "slh-first-use-pause" => prove(original, reference, &output, true),
        "slh-first-use-resume" => prove(original, reference, &output, false),
        "slh-first-use-verify" => verify(&output, false),
        "slh-first-use-refuse" => verify(&output, true),
        _ => Err("unsupported first-use mode".into()),
    }
}
