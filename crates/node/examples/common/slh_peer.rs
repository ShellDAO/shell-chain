//! Retained SLH sender or proposer through discovery and the dedicated proof channel.
use super::*;
use shell_crypto::{CryptoError, PQSignature, SignatureType};
use shell_storage::{CanonicalProofUploadState, CanonicalProofUploadStore};

struct PublicOnly {
    key: Vec<u8>,
    kind: SignatureType,
    calls: AtomicUsize,
}
impl Signer for PublicOnly {
    fn public_key(&self) -> &[u8] {
        &self.key
    }
    fn sig_type(&self) -> SignatureType {
        self.kind
    }
    fn sign(&self, _: &[u8]) -> Result<PQSignature, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CryptoError::SigningFailed(
            "public-only peer actor has no private key".into(),
        ))
    }
}
fn source(native: &Path) -> Result<(fixture::Context, Block, Value), Error> {
    let c: fixture::Context = read(&native.join("context.json"))?;
    let block: Block = read(&native.join("candidate.json"))?;
    let original: SignedTransaction = read(&native.join("signed-first.json"))?;
    ensure(
        block.hash() == c.block
            && matches!(block.number(), 1 | 2)
            && block.transactions == vec![original]
            && (block.transactions[0].signature.sig_type == SignatureType::SphincsSha2256f
                || (matches!(
                    block.transactions[0].signature.sig_type,
                    SignatureType::MlDsa65 | SignatureType::Dilithium3
                ) && block.proposer_seal.as_ref().is_some_and(|seal| {
                    seal.sig_type == SignatureType::SphincsSha2256f && c.authority_key.len() == 64
                }))),
        "retained SLH sender or supported-sender/SLH-proposer child required",
    )?;
    Ok((c, block, read(&native.join("control.json"))?))
}
fn prepare(native: &Path, cache: &Path, out: &Path) -> Result<(), Error> {
    ensure(!out.exists(), "peer output exists; refusing replacement")?;
    ensure(
        native.join("provider/db/CURRENT").is_file() && cache.join("provider/db/CURRENT").is_file(),
        "retained initialized native and automatic outputs required",
    )?;
    let (c, block, _) = source(native)?;
    let manifest: CanonicalProofManifest = read(&cache.join("manifest.json"))?;
    manifest.validate()?;
    let original = RocksDbStore::open_all(native.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    let original_cache = RocksDbStore::open_all(cache.join("provider/db"), None)?;
    let cache_before = digest(&original_cache.state)?;
    let cache_store = CanonicalProofUploadStore::new(Arc::new(original_cache.state.clone()));
    let status = cache_store.status(&manifest.id())?;
    ensure(
        manifest.block_hash == c.block
            && manifest.chain_id == 10
            && status.state == CanonicalProofUploadState::Ready
            && status.result.is_none(),
        "automatic source is not ready-only availability",
    )?;
    let payload = std::fs::read(cache.join("proof.cbor"))?;
    ensure(
        payload.len() as u64 == manifest.total_bytes
            && payload == cache_store.payload(&manifest.id())?
            && blake3_hash(&payload) == manifest.payload_hash,
        "retained automatic proof/cache bytes mismatch",
    )?;
    std::fs::create_dir(out)?;
    std::fs::create_dir(out.join("provider"))?;
    std::fs::create_dir(out.join("receiver"))?;
    original_cache.create_checkpoint(out.join("provider/db"))?;
    let chain = ChainStore::new(Arc::new(original.state.clone()));
    let certificate = chain
        .get_commit_certificate(&c.block)?
        .ok_or("original signed quorum certificate absent")?;
    let cache_had_certificate = ChainStore::new(Arc::new(original_cache.state.clone()))
        .get_commit_certificate(&c.block)?
        .is_some();
    let provider = Arc::new(RocksDbStore::open_all(out.join("provider/db"), None)?.state);
    let provider_node = fixture::node(provider.clone(), c.authority, &c.authority_key)?;
    provider_node.fast_finalize_with_certificate(block.number(), c.block, &certificate);
    ensure(
        provider_node.finality.read().last_finalized_number() == block.number()
            && provider_node
                .chain_store
                .get_commit_certificate(&c.block)?
                .as_ref()
                == Some(&certificate),
        "provider did not retain verified original quorum certificate",
    )?;
    provider.flush()?;
    let parent = chain
        .get_block_by_hash(&block.header.parent_hash)?
        .ok_or("original genesis absent")?;
    if parent.number() > 0 {
        fixture::restore_parent(native, &out.join("receiver/db"), &original.state)?;
    }
    let receiver = Arc::new(RocksDbStore::open_all(out.join("receiver/db"), None)?.state);
    if parent.number() == 0 {
        ensure(receiver.scan_all()?.is_empty(), "receiver was not fresh")?;
        WorldState::validate_snapshot_nodes(&original.state, parent.header.state_root)?;
        for hash in
            WorldState::collect_snapshot_node_hashes(&original.state, parent.header.state_root)?
        {
            let bytes = original
                .state
                .get(hash.as_bytes())?
                .ok_or("reachable genesis node absent")?;
            ensure(
                shell_primitives::keccak256(&bytes) == hash,
                "genesis trie content hash mismatch",
            )?;
            receiver.put(hash.as_bytes(), &bytes)?;
        }
        ensure(
            receiver.get(block.header.state_root.as_bytes())?.is_none(),
            "child root preloaded in receiver",
        )?;
        let target = ChainStore::new(receiver.clone());
        target.commit_genesis_block(
            &parent,
            &chain.get_chain_config()?.ok_or("chain config absent")?,
        )?;
        let view = chain.canonical_parent_view(c.tip, parent.hash())?;
        for address in [block.transactions[0].from, c.authority] {
            if let Some(key) = view.registered_key(&address)? {
                target.put_pubkey(&address, &key)?;
            } else {
                ensure(
                    address == block.transactions[0].from
                        && block.transactions[0]
                            .pubkey_mode
                            .pubkey_bytes()
                            .is_some_and(|key| {
                                (key.len() == 64
                                    && block.transactions[0].signature.sig_type
                                        == SignatureType::SphincsSha2256f
                                    || key.len() == 1952
                                        && matches!(
                                            block.transactions[0].signature.sig_type,
                                            SignatureType::MlDsa65 | SignatureType::Dilithium3
                                        )
                                        && block.proposer_seal.as_ref().is_some_and(|s| {
                                            s.sig_type == SignatureType::SphincsSha2256f
                                        }))
                                    && Address::from_public_key(
                                        key,
                                        block.transactions[0].signature.sig_type.as_u8(),
                                    ) == address
                            })
                        && view
                            .world_state()?
                            .get_account(&address)?
                            .is_some_and(|account| {
                                account.validation_code_hash.is_none()
                                    && account.pq_pubkey_hash == ShellHash::ZERO
                            }),
                    "historical key absent outside funded first-use profile",
                )?;
            }
        }
    }
    let target = ChainStore::new(receiver.clone());
    ensure(
        target.get_head_hash()? == Some(block.header.parent_hash)
            && target.get_block_by_hash(&c.block)?.is_none()
            && target.get_receipts(&c.block)?.is_none()
            && receiver.get(block.header.state_root.as_bytes())?.is_none(),
        "peer target state preloaded",
    )?;
    receiver.flush()?;
    write(&out.join("manifest.json"), &manifest)?;
    write(
        &out.join("initial.json"),
        &json!({"head":parent.hash(),"native_digest":canonical_digest(receiver.as_ref())?,"genesis_reachable_nodes_only":parent.number()==0,"genuine_native_parent_checkpoint":parent.number()>0,"parent_height":parent.number(),"child_root_not_preloaded":true,"native_original_digest":before,"cache_original_digest":cache_before,"original_signature_preserved":true,"provider_original_certificate_verified":true,"provider_finalized_height":block.number(),"automatic_cache_had_certificate":cache_had_certificate,"original_certificate_hash":blake3_hash(&certificate)}),
    )?;
    ensure(
        before == digest(&original.state)? && cache_before == digest(&original_cache.state)?,
        "retained input changed during peer preparation",
    )?;
    Ok(())
}
async fn run(native: &Path, out: &Path, pause: bool, negative: bool) -> Result<(), Error> {
    let (c, block, control) = source(native)?;
    let initial: Value = read(&out.join("initial.json"))?;
    let manifest: CanonicalProofManifest = read(&out.join(if negative {
        "negative-manifest.json"
    } else {
        "manifest.json"
    }))?;
    let actor = Arc::new(PublicOnly {
        key: c.authority_key.clone(),
        kind: block
            .proposer_seal
            .as_ref()
            .ok_or("proposer seal absent")?
            .sig_type,
        calls: AtomicUsize::new(0),
    });
    let faults = Arc::new(Faults::default());
    faults
        .attached_certificates_only
        .store(true, Ordering::SeqCst);
    faults.hold.store(!negative, Ordering::SeqCst);
    if negative {
        *faults.manifest_override.write().unwrap() = Some(manifest.clone());
    }
    let provider = Live::start_with_actor(
        &out.join("provider/db"),
        &c,
        vec![],
        false,
        false,
        Some(faults.clone()),
        Some(actor.clone()),
    )
    .await?;
    let receiver_result = Live::start_with_actor(
        &out.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
        Some(actor.clone()),
    )
    .await;
    let receiver = match receiver_result {
        Ok(v) => v,
        Err(e) => {
            provider.stop().await?;
            return Err(e);
        }
    };
    let result=async {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(1200);
        if !negative {
            let discovery_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            while !faults.seen.load(Ordering::SeqCst) {
                ensure(!provider.task.is_finished()&&!receiver.task.is_finished(),"peer Node.run exited")?;
                if receiver.node.chain_store.get_head_hash()?==Some(c.block) {
                    let status=receiver.call("admin_canonicalProofAdmission",json!([c.block])).await?;
                    write(&out.join("premature-native-import.json"),&json!({"head":c.block,"admission":status,"proof_chunks":faults.chunks.load(Ordering::SeqCst),"actual_TCP_Noise":true,"original_raw_signatures_genuine":true,"receipts":receiver.node.chain_store.get_receipts(&c.block)?,"state_root":receiver.node.world_state.write().state_root()?}))?;
                    return Err("SLH child imported natively before required peer proof staging".into());
                }
                ensure(tokio::time::Instant::now()<discovery_deadline,"ordinary SLH candidate/proof discovery timeout")?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let candidate=receiver.call("admin_canonicalProofAdmission",json!([c.block])).await?;
            let upload: shell_storage::CanonicalProofUploadStatus=serde_json::from_value(receiver.call("admin_canonicalProofStatus",json!([manifest.id()])).await?)?;
            let fetch: shell_storage::CanonicalProofFetchStatus=serde_json::from_value(receiver.call("admin_canonicalProofFetchStatus",json!([manifest.id()])).await?)?;
            ensure(candidate["nativeCanonical"]==false && upload.next_chunk==3 && upload.received_bytes==3*shell_storage::CANONICAL_PROOF_CHUNK_BYTES as u64 && json!(canonical_digest(receiver.node.store.as_ref())?)==initial["native_digest"],"partial proof changed canonical receiver")?;
            if pause {
                write(&out.join("paused.json"),&json!({"admission":candidate,"upload":upload,"fetch":fetch,"served_response_attempts":faults.chunks.load(Ordering::SeqCst),"native_unchanged":true}))?;
                return Ok(());
            }
            let prior:Value=read(&out.join("paused.json"))?;
            ensure(faults.chunks.load(Ordering::SeqCst)==1 && fetch.nonce>prior["fetch"]["nonce"].as_u64().ok_or("paused nonce absent")?,"cold peer resume restarted old chunks or reused nonce")?;
            write(&out.join("resumed.json"),&json!({"first_requested_index":3,"response_attempts":1,"fresh_nonce":true,"fetch":fetch,"native_unchanged":true}))?;
            faults.release.notify_one();
        }
        loop {
            ensure(!provider.task.is_finished()&&!receiver.task.is_finished(),"peer Node.run exited")?;
            let status=receiver.call("admin_canonicalProofAdmission",json!([c.block])).await?;
            if status["status"]["state"]=="failed" {
                ensure(negative,&format!("SLH peer candidate failed: {status}"))?;
                ensure(status["nativeCanonical"]==false && receiver.node.chain_store.get_head_hash()?==Some(serde_json::from_value(initial["head"].clone())?) && receiver.node.chain_store.get_receipts(&c.block)?.is_none() && json!(canonical_digest(receiver.node.store.as_ref())?)==initial["native_digest"],"invalid inner graph changed native parent")?;
                write(&out.join("refused.json"),&json!({"admission":status,"correct_outer_hash":true,"genuine_foreign_hash_certificate":true,"genuine_original_signatures":true,"native_parent_unchanged":true,"served_response_attempts":faults.chunks.load(Ordering::SeqCst)}))?;break;
            }
            if status["status"]["state"]=="complete" {
                ensure(!negative,"genuine foreign key-hash proof was accepted")?;
                ensure(status["nativeCanonical"]==true && receiver.node.chain_store.get_head_hash()?==Some(c.block) && receiver.node.chain_store.get_receipts(&c.block)?.is_some_and(|v|serde_json::to_value(v).is_ok_and(|v|v==control["receipts"])) && accounts(receiver.node.store.clone(),&block)?==control["accounts"],"peer native execution differs from original control")?;
                if let Some(key) = block.transactions[0].pubkey_mode.pubkey_bytes() {
                    ensure(receiver.node.chain_store.get_pubkey(&block.transactions[0].from)?.as_deref() == Some(key), "committed Embedded key registration absent")?;
                }
                if receiver.node.finality.read().last_finalized_number() < block.number() {
                    ensure(tokio::time::Instant::now()<deadline,"imported SLH child did not finalize")?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let received=receiver.node.store.clone(); let raw=CanonicalProofUploadStore::new(received).payload(&manifest.id())?;
                ensure(raw.len() as u64==manifest.total_bytes && blake3_hash(&raw)==manifest.payload_hash,"received graph bytes mismatch")?;
                write(&out.join("complete.json"),&json!({"admission":status,"served_response_attempts":faults.chunks.load(Ordering::SeqCst),"native_receipts_root_accounts_match_original":true,"finalized_height":block.number(),"ordinary_block_discovery":true,"actual_TCP_Noise":true,"operator_fetch_or_import":false,"no_signing":true}))?;break;
            }
            if receiver.node.chain_store.get_head_hash()?==Some(c.block) && status["nativeCanonical"]!=true {return Err("native fallback accepted a pending SLH candidate".into());}
            ensure(tokio::time::Instant::now()<deadline,&format!("SLH peer admission timeout: {status}"))?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_,Error>(())
    }.await;
    let rs = receiver.stop().await;
    faults.release.notify_one();
    let ps = provider.stop().await;
    result?;
    rs?;
    ps?;
    ensure(
        actor.calls.load(Ordering::SeqCst) == 0,
        "peer prover actor attempted signing",
    )?;
    ensure(
        faults.certificate_responses.load(Ordering::SeqCst) > 0,
        "original quorum certificate absent from ordinary block responses",
    )?;
    write(
        &out.join(if pause {
            "paused-transport.json"
        } else if negative {
            "refused-transport.json"
        } else {
            "complete-transport.json"
        }),
        &json!({"standalone_commit_certificates_suppressed":true,"block_responses_with_original_certificate":faults.certificate_responses.load(Ordering::SeqCst),"signing_calls":0,"both_Node_run_tasks_stopped":true}),
    )?;
    Ok(())
}
fn verify(native: &Path, out: &Path) -> Result<(), Error> {
    let (c, block, control) = source(native)?;
    let manifest: CanonicalProofManifest = read(&out.join("manifest.json"))?;
    let db = Arc::new(RocksDbStore::open_all(out.join("receiver/db"), None)?.state);
    let before = digest(db.as_ref())?;
    let proof = shell_stark_prover::compact_canonical::decode_payload(
        &CanonicalProofUploadStore::new(db.clone()).payload(&manifest.id())?,
    )?;
    let node = fixture::node(db.clone(), c.authority, &c.authority_key)?;
    ensure(
        node.chain_store.get_head_hash()? == Some(c.block)
            && node.finality.read().last_finalized_number() == block.number(),
        "cold peer head/finality missing",
    )?;
    if let Some(key) = block.transactions[0].pubkey_mode.pubkey_bytes() {
        ensure(
            node.chain_store
                .get_pubkey(&block.transactions[0].from)?
                .as_deref()
                == Some(key),
            "cold Embedded key registration absent",
        )?;
    }
    let replay = node.replay_canonical_transactions_with_proof(c.block, c.block, &proof)?;
    ensure(
        replay.proved_sender_signatures == 1
            && replay.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && node.chain_store.get_receipts(&c.block)?.as_ref() == Some(&replay.receipts)
            && accounts(db.clone(), &block)? == control["accounts"]
            && before == digest(db.as_ref())?,
        "cold received graph/native state mismatch or writeback",
    )?;
    write(
        &out.join("verified.json"),
        &json!({"actual_received_graph_cold_replay":replay,"native_unchanged":true,"finalized_height":block.number(),"original_accounts_match":true,"new_math":0,"new_signing":false}),
    )
}
fn inspect(native: &Path, out: &Path) -> Result<(), Error> {
    let (c, block, control) = source(native)?;
    let db = Arc::new(RocksDbStore::open_all(out.join("receiver/db"), None)?.state);
    let before = digest(db.as_ref())?;
    let node = fixture::node(db.clone(), c.authority, &c.authority_key)?;
    let observed = json!({"head":node.chain_store.get_head_hash()?,"receipts":node.chain_store.get_receipts(&c.block)?,"accounts":accounts(db.clone(),&block)?,"finalized_number":node.finality.read().last_finalized_number(),"state_root":node.world_state.write().state_root()?,"admission":node.canonical_admission_status(c.block)?,"expected":control});
    ensure(
        before == digest(db.as_ref())?,
        "inspection changed native data",
    )?;
    write(&out.join("observed.json"), &observed)?;
    println!("{}", observed);
    Ok(())
}
fn negative(native: &Path, cache: &Path, out: &Path) -> Result<std::path::PathBuf, Error> {
    let bad = out.join("foreign-key-certificate");
    prepare(native, cache, &bad)?;
    let mut proof = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(
        cache.join("proof.cbor"),
    )?)?;
    if let Some(proposer) = &mut proof.slh_proposer {
        let foreign = proof.transactions[0].signature.transaction_id.clone();
        shell_stark_prover::blake3_hash::verify_hash(&foreign, &foreign.message, &foreign.output)?;
        ensure(
            foreign.message != proposer.header.canonical.message,
            "foreign header certificate not distinct",
        )?;
        proposer.header.canonical = foreign;
    } else {
        let sender = proof
            .slh_transactions
            .as_mut()
            .and_then(|v| v.first_mut())
            .ok_or("SLH proof absent")?;
        let foreign = sender.envelope.signing_hash.clone();
        shell_stark_prover::blake3_hash::verify_hash(&foreign, &foreign.message, &foreign.output)?;
        ensure(
            foreign.message != sender.public_key_hash.message,
            "foreign certificate not distinct",
        )?;
        sender.public_key_hash = foreign;
    }
    let payload =
        shell_stark_prover::compact_canonical::encode_payload(&proof, 256 * 1024 * 1024, true)?;
    let mut manifest: CanonicalProofManifest = read(&bad.join("manifest.json"))?;
    manifest.total_bytes = payload.len() as u64;
    manifest.payload_hash = blake3_hash(&payload);
    let stores = RocksDbStore::open_all(bad.join("provider/db"), None)?;
    let store = CanonicalProofUploadStore::new(Arc::new(stores.state));
    let id = store.begin(manifest.clone())?.proof_id;
    for (index, chunk) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
    {
        store.append(&id, index as u32, chunk)?;
    }
    ensure(
        store.payload(&id)? == payload,
        "negative outer hash mismatch",
    )?;
    write(&bad.join("negative-manifest.json"), &manifest)?;
    Ok(bad)
}
pub(crate) fn command(mode: &str, native: &Path, cache: &Path, out: &Path) -> Result<(), Error> {
    ensure(
        matches!(
            mode,
            "slh-peer-prepare"
                | "slh-peer-pause"
                | "slh-peer-resume"
                | "slh-peer-verify"
                | "slh-peer-refuse"
                | "slh-peer-inspect"
        ),
        "unsupported SLH peer mode",
    )?;
    let output = if out.exists() {
        out.canonicalize()?
    } else {
        out.parent()
            .unwrap_or(Path::new("."))
            .canonicalize()?
            .join(out.file_name().ok_or("output name absent")?)
    };
    for p in [native, cache] {
        let input = p.canonicalize()?;
        ensure(
            !output.starts_with(&input) && !input.starts_with(&output),
            "peer output overlaps retained inputs",
        )?;
    }
    if mode == "slh-peer-prepare" {
        return prepare(native, cache, &output);
    }
    ensure(
        output.is_dir() && !output.symlink_metadata()?.file_type().is_symlink(),
        "real owned peer output required",
    )?;
    if mode == "slh-peer-verify" {
        return verify(native, &output);
    }
    if mode == "slh-peer-inspect" {
        return inspect(native, &output);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    if mode == "slh-peer-refuse" {
        let bad = negative(native, cache, &output)?;
        return runtime.block_on(run(native, &bad, false, true));
    }
    runtime.block_on(run(native, &output, mode == "slh-peer-pause", false))
}
