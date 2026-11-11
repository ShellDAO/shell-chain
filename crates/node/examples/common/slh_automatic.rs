//! Actual background production from fresh sources or explicit warm checkpoints.
use super::*;
use shell_crypto::{CryptoError, MultiVerifier, PQSignature, SignatureType, Signer};
use shell_network::{Libp2pNetwork, NetworkConfig};
use shell_primitives::Bytes;
use shell_storage::{
    CanonicalProofManifest, CanonicalProofUploadState, CanonicalProofUploadStatus, WriteBatch,
    CANONICAL_PROOF_CACHE_PREFIX, CANONICAL_PROOF_CHUNK_BYTES,
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PREFIX: &[u8] = b"local/canonical-production/v1/";
fn key(suffix: &[u8]) -> Vec<u8> {
    [PREFIX, suffix].concat()
}
fn job(hash: ShellHash, suffix: &[u8]) -> Vec<u8> {
    [PREFIX, b"certificates/", hash.as_bytes(), b"/", suffix].concat()
}
fn json_read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_slice(&read(path, 4 * 1024 * 1024)?)?)
}
fn save(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    write(path, &serde_json::to_vec_pretty(value)?)
}
fn native_digest(db: &impl KvStore) -> Result<ShellHash, Error> {
    let rows: Vec<_> = db
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| !k.starts_with(PREFIX) && !k.starts_with(CANONICAL_PROOF_CACHE_PREFIX))
        .collect();
    Ok(blake3_hash(&serde_json::to_vec(&rows)?))
}
fn reaccount(db: &impl KvStore, rows: BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), Error> {
    let mut batch = WriteBatch::new();
    let mut total = 0usize;
    for (k, v) in rows {
        if k != key(b"bytes") {
            total = total
                .checked_add(k.len() + v.len())
                .ok_or("quota overflow")?;
            batch.put(k, v);
        }
    }
    ensure(
        total <= 256 * 1024 * 1024 - 64 * 1024,
        "test checkpoint exceeds unchanged native quota",
    )?;
    batch.put(key(b"bytes"), (total as u64).to_be_bytes().to_vec());
    db.write_batch(batch)?;
    db.flush()?;
    Ok(())
}
struct PublicOnly {
    key: Vec<u8>,
    kind: SignatureType,
    calls: AtomicUsize,
}
impl Signer for PublicOnly {
    fn sign(&self, _: &[u8]) -> Result<PQSignature, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CryptoError::SigningFailed(
            "public-only regression actor has no secret key".into(),
        ))
    }
    fn public_key(&self) -> &[u8] {
        &self.key
    }
    fn sig_type(&self) -> SignatureType {
        self.kind
    }
}
struct Live {
    node: Arc<shell_node::Node<RocksDbStore>>,
    task: tokio::task::JoinHandle<Result<(), shell_node::NodeError>>,
    signer: Arc<PublicOnly>,
    address: SocketAddr,
    token: String,
}
impl Live {
    async fn start(
        out: &Path,
        c: &fixture::Context,
        block: &shell_core::Block,
        budget: Option<NonZeroUsize>,
    ) -> Result<Self, Error> {
        let db = Arc::new(RocksDbStore::open_all(out.join("provider/db"), None)?.state);
        let mut node = fixture::node(db, c.authority, &c.authority_key)?;
        node.config.canonical_proof_production = true;
        node.config.canonical_proof_component_budget = budget;
        node.config.metrics.enabled = false;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        drop(socket);
        // Ephemeral loopback test authentication; never saved or used for a public service.
        let token = blake3_hash(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_le_bytes(),
        )
        .to_string();
        node.config.rpc_enabled = true;
        node.config.rpc = shell_rpc::RpcConfig {
            listen_addr: address,
            ws_addr: None,
            api_namespaces: vec!["admin".into()],
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            ..Default::default()
        };
        let cfg = NetworkConfig {
            listen_addr: "127.0.0.1:0".parse()?,
            boot_nodes: vec![],
            enable_mdns: false,
            enable_kademlia: false,
            enable_relay: false,
            enable_relay_server: false,
            enable_dcutr: false,
            enable_autonat: false,
            identity_key_path: None,
            ..Default::default()
        };
        node.config.network = cfg.clone();
        let node = Arc::new(node);
        let signer = Arc::new(PublicOnly {
            key: c.authority_key.clone(),
            kind: block
                .proposer_seal
                .as_ref()
                .ok_or("proposer seal absent")?
                .sig_type,
            calls: AtomicUsize::new(0),
        });
        let runner = node.clone();
        let actor = signer.clone();
        let mut network = Libp2pNetwork::new(&cfg).await?;
        let task = tokio::spawn(async move { runner.run(actor, &mut network).await });
        Ok(Self {
            node,
            task,
            signer,
            address,
            token,
        })
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, v) = fixture::request(self.address, Some(&self.token), method, params).await?;
        ensure(
            status == 200 && v.get("error").is_none(),
            "authenticated RPC refused request",
        )?;
        v.get("result")
            .cloned()
            .ok_or_else(|| "RPC result absent".into())
    }
    async fn status(&self, hash: ShellHash) -> Result<Value, Error> {
        self.call("admin_canonicalProofProduction", json!([hash]))
            .await
    }
    async fn stop(self) -> Result<(), Error> {
        self.node.shutdown();
        tokio::time::timeout(Duration::from_secs(180), self.task).await???;
        ensure(
            self.signer.calls.load(Ordering::SeqCst) == 0,
            "prover attempted signing without a private key",
        )
    }
}
fn context(native: &Path) -> Result<(fixture::Context, shell_core::Block, Value), Error> {
    Ok((
        json_read(&native.join("context.json"))?,
        json_read(&native.join("candidate.json"))?,
        json_read(&native.join("control.json"))?,
    ))
}
fn prepare(native: &Path, prior: Option<&Path>, out: &Path, fresh: bool) -> Result<(), Error> {
    ensure(
        native.join("provider/db/CURRENT").is_file()
            && (fresh
                || prior.is_some_and(|p| {
                    p.join("db/CURRENT").is_file() && p.join("proof.cbor").is_file()
                })),
        "initialized Native input and required warm checkpoint missing",
    )?;
    ensure(
        !out.exists(),
        "automatic output exists; refusing replacement",
    )?;
    let (c, block, control) = context(native)?;
    let original = RocksDbStore::open_all(native.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    let chain = ChainStore::new(Arc::new(original.state.clone()));
    let source = CanonicalProductionSource::capture(&chain, c.tip, c.block)?;
    ensure(
        source.needs_slh_encoding() && source.block() == &block,
        "original SLH source mismatch",
    )?;
    let donor = if fresh {
        None
    } else {
        Some(RocksDbStore::open_all(
            prior.ok_or("warm checkpoint absent")?.join("db"),
            None,
        )?)
    };
    let donor_before = donor.as_ref().map(|d| digest(&d.state)).transpose()?;
    let component_count = if let Some(donor) = &donor {
        ensure(
            donor.state.get(b"production/source")?.as_deref() == Some(source.identity()),
            "checkpoint source is not the original source",
        )?;
        let index: Value = serde_json::from_slice(
            &donor
                .state
                .get(b"production/index")?
                .ok_or("checkpoint index absent")?,
        )?;
        ensure(
            index["version"] == 4
                && index["components"]
                    .as_object()
                    .is_some_and(|v| !v.is_empty()),
            "complete format4 checkpoint required",
        )?;
        index["components"]
            .as_object()
            .ok_or("component map absent")?
            .len()
    } else {
        0
    };
    std::fs::create_dir(out)?;
    std::fs::create_dir(out.join("provider"))?;
    let db = Arc::new(RocksDbStore::open_all(out.join("provider/db"), None)?.state);
    let target = ChainStore::new(db.clone());
    let parent = chain
        .get_block_by_hash(&block.header.parent_hash)?
        .ok_or("original parent absent")?;
    ensure(
        parent.number() == 0 && db.scan_all()?.is_empty(),
        "fresh original genesis receiver required",
    )?;
    shell_storage::WorldState::validate_snapshot_nodes(&original.state, parent.header.state_root)?;
    for hash in shell_storage::WorldState::collect_snapshot_node_hashes(
        &original.state,
        parent.header.state_root,
    )? {
        let value = original
            .state
            .get(hash.as_bytes())?
            .ok_or("genesis trie node absent")?;
        ensure(
            shell_primitives::keccak256(&value) == hash,
            "genesis node mismatch",
        )?;
        db.put(hash.as_bytes(), &value)?;
    }
    ensure(
        db.get(block.header.state_root.as_bytes())?.is_none(),
        "child state was preloaded",
    )?;
    target.commit_genesis_block(
        &parent,
        &chain.get_chain_config()?.ok_or("configuration absent")?,
    )?;
    let view = chain.canonical_parent_view(c.tip, parent.hash())?;
    let parent_sender_registered = view.registered_key(&block.transactions[0].from)?.is_some();
    for address in [block.transactions[0].from, c.authority] {
        if let Some(key) = view.registered_key(&address)? {
            target.put_pubkey(&address, &key)?;
        } else {
            ensure(
                address == block.transactions[0].from
                    && source.has_unbound_senders()
                    && block.transactions[0]
                        .pubkey_mode
                        .pubkey_bytes()
                        .is_some_and(|key| {
                            matches!(
                                (block.transactions[0].signature.sig_type, key.len()),
                                (SignatureType::SphincsSha2256f, 64)
                                    | (SignatureType::MlDsa65, 1952)
                            ) && shell_primitives::Address::from_public_key(
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
    ensure(
        target.get_pubkey(&block.transactions[0].from)?.is_some() == parent_sender_registered,
        "genesis restoration changed historical sender registration",
    )?;
    let mut node = fixture::node(db.clone(), c.authority, &c.authority_key)?;
    ensure(
        !node.config.canonical_proof_production && db.scan_prefix(PREFIX)?.is_empty(),
        "production must default off",
    )?;
    node.config.canonical_proof_production = true;
    node.import_block(block.clone(), &MultiVerifier)?;
    let queued = node
        .canonical_production_status(c.block)?
        .ok_or("ordinary import failed to capture source")?;
    ensure(
        queued["status"]["state"] == "queued"
            && queued["status"]["components"] == 0
            && queued["nativeExecutionVerified"] == false,
        "capture was not a fresh queued job",
    )?;
    ensure(
        target
            .get_receipts(&c.block)?
            .is_some_and(|v| serde_json::to_value(v).is_ok_and(|v| v == control["receipts"])),
        "fresh native receipts differ",
    )?;
    if !parent_sender_registered {
        ensure(
            target.get_pubkey(&block.transactions[0].from)?.as_deref()
                == block.transactions[0].pubkey_mode.pubkey_bytes(),
            "ordinary first-use import did not register its Embedded key",
        )?;
    }
    drop(node);
    let mut rows: BTreeMap<_, _> = db.scan_prefix(PREFIX)?.into_iter().collect();
    ensure(
        rows.get(&key(&[b"source/".as_slice(), c.block.as_bytes()].concat()))
            .is_some_and(|v| v == source.identity()),
        "captured source differs from retained checkpoint",
    )?;
    // Test-only transplant: preserve every exact mathematical component and index.
    // The actual worker must reverify them before it can publish any availability.
    if let Some(donor) = &donor {
        for (k, v) in donor.state.scan_prefix(b"production/")? {
            ensure(
                rows.insert(job(c.block, &k), v).is_none(),
                "native job already contains components",
            )?;
        }
    } else {
        ensure(
            db.scan_prefix(&job(c.block, b"production/"))?.is_empty()
                && db.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty(),
            "fresh source already contains mathematical checkpoints or availability",
        )?;
    }
    reaccount(db.as_ref(), rows)?;
    ensure(
        before == digest(&original.state)?
            && donor_before == donor.as_ref().map(|d| digest(&d.state)).transpose()?,
        "retained original inputs changed",
    )?;
    save(
        &out.join("prepared.json"),
        &json!({"ordinary_native_import_captured":queued,"parent_sender_registered":parent_sender_registered,"sender_registered_after_native_import":target.get_pubkey(&block.transactions[0].from)?.is_some(),"source_version":serde_json::from_slice::<Value>(source.identity())?["version"],"genesis_only_parent":true,"child_root_not_preloaded":true,"checkpoint_transplant":if fresh {"none; empty mathematical job"}else{"same-source test preparation; no complete flag"},"fresh_generation":fresh,"donor_opened":donor.is_some(),"checkpoint_digest":donor_before,"component_count":component_count,"native_digest":native_digest(db.as_ref())?,"new_math":0,"new_signing":false,"original_digest":before}),
    )
}
async fn exercise(
    native: &Path,
    prior: Option<&Path>,
    out: &Path,
    pause: bool,
    refuse: bool,
    fresh: bool,
) -> Result<(), Error> {
    let (c, block, _) = context(native)?;
    let live = Live::start(
        out,
        &c,
        &block,
        if fresh && !pause {
            None
        } else {
            NonZeroUsize::new(1)
        },
    )
    .await?;
    let result = async {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(if fresh { 86400 } else { 1800 });
        let mut authenticated = false;
        let terminal = loop {
            ensure(
                !live.task.is_finished(),
                "Node.run exited before producer result",
            )?;
            if let Ok(value) = live.status(c.block).await {
                if !authenticated {
                    let (status, _) = fixture::request(
                        live.address,
                        None,
                        "admin_canonicalProofProduction",
                        json!([c.block]),
                    )
                    .await?;
                    ensure(status == 401, "unauthenticated producer RPC accepted")?;
                    authenticated = true;
                }
                let state = value["status"]["state"].as_str();
                if pause
                    && if fresh {
                        state == Some("paused")
                            && value["status"]["components"]
                                .as_u64()
                                .is_some_and(|n| n > 0)
                    } else {
                        state == Some("proving")
                    }
                {
                    break value;
                }
                if !pause && state == Some(if refuse { "failed" } else { "complete" }) {
                    break value;
                }
                ensure(
                    state != Some("failed"),
                    &format!("automatic production failed: {value}"),
                )?;
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "automatic producer timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        ensure(
            terminal["nativeExecutionVerified"] == false,
            "availability claimed execution",
        )?;
        if pause {
            return Ok(terminal);
        }
        if refuse {
            let before = native_digest(live.node.store.as_ref())?;
            tokio::time::sleep(Duration::from_millis(600)).await;
            ensure(
                live.status(c.block).await?["status"]["error"] == terminal["status"]["error"]
                    && before == native_digest(live.node.store.as_ref())?,
                "failed job retried or changed canonical data",
            )?;
            return Ok(terminal);
        }
        if fresh {
            ensure(
                terminal["status"]["newlyProved"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
                    && terminal["status"]["components"]
                        .as_u64()
                        .is_some_and(|n| n > 0),
                "fresh worker generated no new mathematical certificates",
            )?;
        } else {
            ensure(
                terminal["status"]["newlyProved"] == 0
                    && terminal["status"]["components"]
                        == json_read::<Value>(&out.join("prepared.json"))?["component_count"]
                    && terminal["status"]["reused"].as_u64().is_some_and(|v| {
                        terminal["status"]["components"]
                            .as_u64()
                            .is_some_and(|count| v >= count)
                    }),
                "background worker regenerated or lost retained certificates",
            )?;
        }
        let manifest: CanonicalProofManifest =
            serde_json::from_value(terminal["status"]["manifest"].clone())?;
        let cache: CanonicalProofUploadStatus = serde_json::from_value(
            live.call("admin_canonicalProofStatus", json!([manifest.id()]))
                .await?,
        )?;
        ensure(
            cache.state == CanonicalProofUploadState::Ready && cache.result.is_none(),
            "cache readiness was treated as execution",
        )?;
        let mut payload = Vec::new();
        for i in 0..cache.next_chunk {
            let chunk: Bytes = serde_json::from_value(
                live.call("admin_getCanonicalProofChunk", json!([manifest.id(), i]))
                    .await?,
            )?;
            ensure(
                chunk.len() <= CANONICAL_PROOF_CHUNK_BYTES,
                "RPC chunk limit exceeded",
            )?;
            payload.extend_from_slice(chunk.as_ref());
        }
        ensure(
            payload.len() as u64 == manifest.total_bytes
                && blake3_hash(&payload) == manifest.payload_hash
                && prior
                    .map(|p| read(&p.join("proof.cbor"), 256 * 1024 * 1024))
                    .transpose()?
                    .is_none_or(|expected| payload == expected),
            "authenticated RPC did not reproduce exact original proof bytes",
        )?;
        write(&out.join("proof.cbor"), &payload)?;
        save(&out.join("manifest.json"), &manifest)?;
        save(&out.join("block.json"), &block)?;
        Ok::<_, Error>(terminal)
    }
    .await;
    let stopped = live.stop().await;
    let terminal = result?;
    stopped?;
    let db = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let saved: Value = serde_json::from_slice(
        &db.state
            .get(&key(&[b"record/".as_slice(), c.block.as_bytes()].concat()))?
            .ok_or("durable status missing")?,
    )?;
    ensure(
        saved["state"]
            == if pause {
                "paused"
            } else if refuse {
                "failed"
            } else {
                "complete"
            },
        "graceful shutdown did not retain expected state",
    )?;
    let prepared: Value = json_read(&out.join("prepared.json"))?;
    ensure(
        json!(native_digest(&db.state)?) == prepared["native_digest"],
        "automatic production changed native canonical data",
    )?;
    save(
        &out.join(if pause {
            "runtime-paused.json"
        } else if refuse {
            "runtime-refused.json"
        } else {
            "runtime-complete.json"
        }),
        &json!({"observed":terminal,"durable":saved,"native_unchanged":true,"new_signing":false,"graceful_Node_run_shutdown":true,"fresh_generation":fresh}),
    )
}
fn verify(native: &Path, prior: Option<&Path>, out: &Path, fresh: bool) -> Result<(), Error> {
    let (c, block, control) = context(native)?;
    let original = RocksDbStore::open_all(native.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    let source = CanonicalProductionSource::capture(
        &ChainStore::new(Arc::new(original.state.clone())),
        c.tip,
        c.block,
    )?;
    let bytes = read(&out.join("proof.cbor"), 256 * 1024 * 1024)?;
    ensure(
        prior
            .map(|p| read(&p.join("proof.cbor"), 256 * 1024 * 1024))
            .transpose()?
            .is_none_or(|expected| bytes == expected),
        "cold proof differs from original graph",
    )?;
    let proof = decode_payload(&bytes)?;
    source.verify(&proof)?;
    let stores = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let db = Arc::new(stores.state.clone());
    let native_before = native_digest(db.as_ref())?;
    let node = fixture::node(db.clone(), c.authority, &c.authority_key)?;
    let replay = node.replay_canonical_transactions_with_proof(c.block, c.block, &proof)?;
    ensure(
        replay.proved_sender_signatures == 1
            && replay.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && node.chain_store.get_receipts(&c.block)?.as_ref() == Some(&replay.receipts),
        "cold background proof replay differs from original native execution",
    )?;
    let world = shell_storage::WorldState::at_root(db.clone(), &block.header.state_root)?;
    let mut accounts = Vec::new();
    for row in control["accounts"].as_array().ok_or("accounts absent")? {
        let a = serde_json::from_value::<shell_primitives::Address>(row["address"].clone())?;
        accounts.push(
            json!({"address":a,"nonce":world.get_nonce(&a)?,"balance":world.get_balance(&a)?}),
        );
    }
    ensure(
        json!(accounts) == control["accounts"]
            && native_before == native_digest(db.as_ref())?
            && before == digest(&original.state)?,
        "cold replay altered canonical state or accounts differ",
    )?;
    let changed_history = if (source.has_unbound_senders() || source.has_slh_proposer())
        && native.join("later.json").is_file()
    {
        let later: shell_core::Block = json_read(&native.join("later.json"))?;
        ensure(
            later.header.parent_hash == c.block
                && later.number() == 2
                && later.header.state_root != block.header.state_root,
            "later control is not a changed child",
        )?;
        std::fs::create_dir_all(out.join("history"))?;
        if !out.join("history/db/CURRENT").is_file() {
            stores.create_checkpoint(out.join("history/db"))?;
        }
        let history = Arc::new(RocksDbStore::open_all(out.join("history/db"), None)?.state);
        let history_node = fixture::node(history.clone(), c.authority, &c.authority_key)?;
        ensure(
            !history_node.config.canonical_proof_production,
            "cold history enabled new jobs",
        )?;
        if history_node.chain_store.get_head_hash()? == Some(c.block) {
            history_node.import_block(later.clone(), &MultiVerifier)?;
        }
        ensure(
            history_node.chain_store.get_head_hash()? == Some(later.hash())
                && history_node.world_state.write().state_root()? == later.header.state_root
                && history_node
                    .chain_store
                    .get_pubkey(&block.transactions[0].from)?
                    .is_some(),
            "history did not advance with registered key",
        )?;
        let original_parent = ChainStore::new(Arc::new(original.state.clone()))
            .canonical_parent_view(c.tip, block.header.parent_hash)?;
        let parent_sender_key = original_parent.registered_key(&block.transactions[0].from)?;
        let parent_proposer_key = original_parent.registered_key(&c.authority)?;
        let sealed = history_node
            .chain_store
            .canonical_parent_view(later.hash(), block.header.parent_hash)?;
        ensure(
            sealed.registered_key(&block.transactions[0].from)? == parent_sender_key
                && sealed.registered_key(&c.authority)? == parent_proposer_key,
            "current key supplied different historical authority",
        )?;
        let history_before = digest(history.as_ref())?;
        let replay =
            history_node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
        let ordinary =
            Arc::new(RocksDbStore::open_all(native.join("native-later/db"), None)?.state);
        let ordinary_before = digest(ordinary.as_ref())?;
        let ordinary_node = fixture::node(ordinary.clone(), c.authority, &c.authority_key)?;
        ensure(
            ordinary_node.chain_store.get_head_hash()? == Some(later.hash()),
            "independent Native later control absent",
        )?;
        let ordinary_replay = ordinary_node.replay_canonical_transactions_with_proof(
            later.hash(),
            c.block,
            &proof,
        )?;
        ensure(
            replay.proved_sender_signatures == 1
                && replay.proved_proposer_signature
                && ordinary_replay.proved_sender_signatures == 1
                && ordinary_replay.proved_proposer_signature
                && replay.state_root == block.header.state_root
                && ordinary_replay.state_root == block.header.state_root
                && serde_json::to_value(&replay.receipts)? == control["receipts"]
                && serde_json::to_value(&ordinary_replay.receipts)? == control["receipts"]
                && history_before == digest(history.as_ref())?
                && ordinary_before == digest(ordinary.as_ref())?
                && native_before == native_digest(db.as_ref())?,
            "generated proof historical replay differs or writes current state",
        )?;
        Some(
            json!({"current_height":2,"current_state_changed":true,"current_key_present":true,"sealed_parent_key_absent":parent_sender_key.is_none(),"sealed_parent_keys_match_original":true,"proved_sender_signatures":replay.proved_sender_signatures,"proved_proposer_signature":replay.proved_proposer_signature,"generated_proof_replay_matches_independent_Native":true,"both_databases_unchanged":true}),
        )
    } else {
        None
    };
    println!(
        "{}",
        json!({"actual_Node_run_cold_proof_verified":true,"proof_bytes":bytes.len(),"byte_identical_original_graph":prior.map(|_|true),"receipts_state_accounts_match_original":true,"read_only":true,"new_signing":false,"fresh_generation":fresh,"peer_transport":false,"first_use_history":if source.has_unbound_senders(){changed_history.as_ref()}else{None},"slh_proposer_history":if source.has_slh_proposer(){changed_history.as_ref()}else{None},"original_successor2_signed":false})
    );
    Ok(())
}
fn corrupt(out: &Path, hash: ShellHash) -> Result<PathBuf, Error> {
    let mut bad = out.join("bad-certificate");
    let mut serial = 2;
    while bad.exists() {
        bad = out.join(format!("bad-certificate-{serial}"));
        serial += 1;
    }
    std::fs::create_dir(&bad)?;
    std::fs::create_dir(bad.join("provider"))?;
    let original = RocksDbStore::open_all(out.join("provider/db"), None)?;
    let before = digest(&original.state)?;
    original.create_checkpoint(bad.join("provider/db"))?;
    let db = RocksDbStore::open_all(bad.join("provider/db"), None)?;
    let mut rows: BTreeMap<_, _> = db.state.scan_prefix(PREFIX)?.into_iter().collect();
    let index_key = job(hash, b"production/index");
    let component_key = job(hash, b"production/component/sender-0-key-hash");
    let mut index: Value = serde_json::from_slice(rows.get(&index_key).ok_or("index absent")?)?;
    let mut proof: Blake3HashProof = shell_stark_prover::compact_canonical::decode_component(
        rows.get(&component_key).ok_or("key component absent")?,
    )?;
    ensure(
        !proof.compressions.is_empty() && !proof.compressions[0].proof_bytes.is_empty(),
        "genuine key AIR bytes absent",
    )?;
    proof.compressions[0].proof_bytes[0] ^= 1;
    let bytes = encode_component(&proof)?;
    index["components"]["sender-0-key-hash"]["bytes"] = json!(bytes.len());
    index["components"]["sender-0-key-hash"]["hash"] = json!(blake3_hash(&bytes));
    rows.insert(component_key, bytes);
    rows.insert(index_key, serde_json::to_vec(&index)?);
    let rk = key(&[b"record/".as_slice(), hash.as_bytes()].concat());
    let mut status: Value = serde_json::from_slice(rows.get(&rk).ok_or("status absent")?)?;
    status["state"] = json!("paused");
    status["manifest"] = Value::Null;
    status["error"] = Value::Null;
    rows.insert(rk, serde_json::to_vec(&status)?);
    reaccount(&db.state, rows)?;
    ensure(
        before == digest(&original.state)?,
        "corrupt copy changed valid source",
    )?;
    save(
        &bad.join("prepared.json"),
        &json!({"native_digest":native_digest(&db.state)?,"valid_original_unchanged":true,"proof_bytes_changed_with_correct_component_hash":true}),
    )?;
    Ok(bad)
}
pub(super) fn run(
    mode: &str,
    native: &Path,
    prior: Option<&Path>,
    out: &Path,
) -> Result<(), Error> {
    let fresh = mode.starts_with("automatic-fresh-");
    let mode = mode
        .strip_prefix(if fresh {
            "automatic-fresh-"
        } else {
            "automatic-"
        })
        .ok_or("unsupported automatic mode")?;
    ensure(
        matches!(mode, "prepare" | "pause" | "resume" | "verify" | "refuse"),
        "unsupported automatic mode",
    )?;
    for input in std::iter::once(native).chain(prior) {
        let input = input.canonicalize()?;
        let output = if out.exists() {
            out.canonicalize()?
        } else {
            out.parent()
                .unwrap_or(Path::new("."))
                .canonicalize()?
                .join(out.file_name().ok_or("output name absent")?)
        };
        ensure(
            !output.starts_with(&input) && !input.starts_with(&output),
            "automatic output overlaps retained input",
        )?;
    }
    if mode == "prepare" {
        return prepare(native, prior, out, fresh);
    }
    ensure(
        out.is_dir() && !out.symlink_metadata()?.file_type().is_symlink(),
        "real owned automatic output required",
    )?;
    if mode == "verify" {
        return verify(native, prior, out, fresh);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    if mode == "refuse" {
        let (c, _, _) = context(native)?;
        let bad = corrupt(out, c.block)?;
        return runtime.block_on(exercise(native, prior, &bad, false, true, fresh));
    }
    runtime.block_on(exercise(native, prior, out, mode == "pause", false, fresh))
}
