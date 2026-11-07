//! Real ordinary block sync and dedicated proof transfer, with a cold receiver.
use super::*;
use async_trait::async_trait;
use shell_network::{
    Libp2pNetwork, LocalNodeInfo, NetworkConfig, NetworkError, NetworkEvent, NetworkMessage,
    NetworkService, PeerId,
};
use shell_node::Node;
use shell_storage::{CanonicalProofManifest, CANONICAL_PROOF_CACHE_PREFIX};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        RwLock,
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};
#[derive(Default)]
struct Faults {
    hold: AtomicBool,
    seen: AtomicBool,
    release: Notify,
    chunks: AtomicUsize,
    manifest_override: RwLock<Option<CanonicalProofManifest>>,
    hold_suffix: AtomicBool,
    suffix_seen: AtomicBool,
    release_suffix: Notify,
    gossip_block: RwLock<Option<Block>>,
    gossip_attempts: AtomicUsize,
    suppressed_direct_bodies: AtomicUsize,
}
struct Provider {
    inner: Libp2pNetwork,
    faults: Arc<Faults>,
    gossip_timer: tokio::time::Interval,
}
#[async_trait]
impl NetworkService for Provider {
    async fn broadcast(&self, m: NetworkMessage) -> Result<(), NetworkError> {
        self.inner.broadcast(m).await
    }
    async fn send_to_peer(&self, p: &PeerId, mut m: NetworkMessage) -> Result<(), NetworkError> {
        if self.faults.gossip_block.read().unwrap().is_some()
            && matches!(
                &m,
                NetworkMessage::NewBlock(_) | NetworkMessage::BlockResponse { .. }
            )
        {
            self.faults
                .suppressed_direct_bodies
                .fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        if let NetworkMessage::CanonicalProofManifestResponse {
            block_hash,
            manifest,
            ..
        } = &mut m
        {
            if let Some(replacement) = self.faults.manifest_override.read().unwrap().as_ref() {
                if *block_hash == replacement.block_hash {
                    *manifest = Some(replacement.clone());
                }
            }
        }
        if (matches!(&m,NetworkMessage::BlockResponse{blocks,..} if blocks.first().is_some_and(|b|b.number()>=3))
            || matches!(&m,NetworkMessage::NewBlock(block) if block.number()>=3))
            && self.faults.hold_suffix.swap(false, Ordering::SeqCst)
        {
            self.faults.suffix_seen.store(true, Ordering::SeqCst);
            self.faults.release_suffix.notified().await;
        }
        if let NetworkMessage::CanonicalProofChunkResponse {
            index,
            data: Some(_),
            ..
        } = &m
        {
            self.faults.chunks.fetch_add(1, Ordering::SeqCst);
            if *index == 3 && self.faults.hold.swap(false, Ordering::SeqCst) {
                self.faults.seen.store(true, Ordering::SeqCst);
                self.faults.release.notified().await;
            }
        }
        self.inner.send_to_peer(p, m).await
    }
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        if self.faults.gossip_block.read().unwrap().is_none() {
            return self.inner.next_event().await;
        }
        loop {
            tokio::select! {
                event = self.inner.next_event() => return event,
                _ = self.gossip_timer.tick() => {
                    if self.inner.peer_count().await == 0 { continue; }
                    let block = self.faults.gossip_block.read().unwrap().clone()?;
                    if self.inner.broadcast(NetworkMessage::NewBlock(Box::new(block))).await.is_ok() {
                        self.faults.gossip_attempts.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
    }
    async fn peer_count(&self) -> usize {
        self.inner.peer_count().await
    }
    fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        self.inner.peer_count_handle()
    }
    fn local_node_info_handle(&self) -> Arc<RwLock<LocalNodeInfo>> {
        self.inner.local_node_info_handle()
    }
    fn supports_canonical_proof_transfer(&self) -> bool {
        self.inner.supports_canonical_proof_transfer()
    }
    async fn shutdown(&self) -> Result<(), NetworkError> {
        self.inner.shutdown().await
    }
}
struct Live {
    node: Arc<Node<RocksDbStore>>,
    task: JoinHandle<Result<(), shell_node::NodeError>>,
    address: SocketAddr,
    token: String,
    info: Arc<RwLock<LocalNodeInfo>>,
}
impl Live {
    async fn start(
        db: &Path,
        c: &fixture::Context,
        boot: Vec<String>,
        admission: bool,
        production: bool,
        faults: Option<Arc<Faults>>,
    ) -> Result<Self, Error> {
        let stores = RocksDbStore::open_all(db, None)?;
        let mut node = fixture::node(Arc::new(stores.state), c.authority, &c.authority_key)?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        drop(socket);
        let token = blake3_hash(DilithiumSigner::generate().public_key()).to_string();
        node.config.rpc_enabled = true;
        node.config.metrics.enabled = false;
        node.config.canonical_proof_admission = admission;
        node.config.canonical_proof_production = production;
        node.config.canonical_proof_component_budget = None;
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
            boot_nodes: boot,
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
        let mut network = Libp2pNetwork::new(&cfg).await?;
        let info = network.local_node_info_handle();
        let signer = Arc::new(DilithiumSigner::generate());
        ensure(
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8()) != c.authority,
            "duplicate canonical signer",
        )?;
        let node = Arc::new(node);
        let run = node.clone();
        let task = tokio::spawn(async move {
            if let Some(faults) = faults {
                run.run(
                    signer,
                    &mut Provider {
                        inner: network,
                        faults,
                        gossip_timer: tokio::time::interval(Duration::from_secs(3)),
                    },
                )
                .await
            } else {
                run.run(signer, &mut network).await
            }
        });
        let live = Self {
            node,
            task,
            address,
            token,
            info,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            ensure(!live.task.is_finished(), "Node.run exited during startup")?;
            if live.call("admin_nodeInfo", json!([])).await.is_ok()
                && !live.info.read().unwrap().listen_addresses.is_empty()
            {
                break;
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "node startup timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(live)
    }
    fn dial(&self) -> String {
        let i = self.info.read().unwrap();
        format!("{}/p2p/{}", i.listen_addresses[0], i.peer_id)
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, result) =
            fixture::request(self.address, Some(&self.token), method, params).await?;
        ensure(status == 200, "HTTP failure")?;
        if let Some(e) = result.get("error") {
            return Err(format!("RPC {method}: {e}").into());
        }
        result
            .get("result")
            .cloned()
            .ok_or_else(|| "RPC result absent".into())
    }
    async fn stop(self) -> Result<(), Error> {
        self.node.shutdown();
        tokio::time::timeout(Duration::from_secs(180), self.task).await???;
        Ok(())
    }
}
fn canonical_digest(store: &impl KvStore) -> Result<ShellHash, Error> {
    let rows: Vec<_> = store
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| {
            !k.starts_with(CANONICAL_PROOF_CACHE_PREFIX)
                && !k.starts_with(b"local/canonical-admission/v1/")
        })
        .collect();
    Ok(blake3_hash(&serde_json::to_vec(&rows)?))
}
pub(super) fn prepare(out: &Path) -> Result<(), Error> {
    prepare_at(out, "network")
}
fn prepare_at(out: &Path, directory: &str) -> Result<(), Error> {
    let network = out.join(directory);
    ensure(
        !network.exists(),
        "network data exists; refusing replacement",
    )?;
    std::fs::create_dir(&network)?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let source = RocksDbStore::open_all(out.join("native/db"), None)?;
    std::fs::create_dir(network.join("provider"))?;
    source.create_checkpoint(network.join("provider/db"))?;
    let chain = ChainStore::new(Arc::new(source.state));
    let config = chain
        .get_chain_config()?
        .ok_or("source configuration absent")?;
    let genesis = chain
        .get_block_by_hash(&config.genesis_hash)?
        .ok_or("source genesis absent")?;
    let key = chain
        .get_pubkey(&block.transactions[0].from)?
        .ok_or("parent key absent")?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let mut world = WorldState::new(store.clone());
    world.set_account(
        &block.transactions[0].from,
        &Account::new_user_account(blake3_hash(&key), U256::from(1_000_000)),
    )?;
    ensure(
        world.state_root()? == c.genesis_root && genesis.header.state_root == c.genesis_root,
        "independent receiver genesis mismatch",
    )?;
    let target = ChainStore::new(store.clone());
    target.put_pubkey(&block.transactions[0].from, &key)?;
    target.put_pubkey(&c.authority, &c.authority_key)?;
    target.commit_genesis_block(&genesis, &config)?;
    store.flush()?;
    write(
        &network.join("initial.json"),
        &json!({"head":genesis.hash(),"native_digest":canonical_digest(store.as_ref())?,"independent_genesis":true,"private_keys_persisted":false}),
    )?;
    Ok(())
}
pub(super) async fn run(
    out: &Path,
    pause: bool,
    negative: bool,
    recovery: bool,
) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let network = out.join(if negative {
        "network-bad-air"
    } else {
        "network"
    });
    let faults = Arc::new(Faults::default());
    if negative && recovery {
        // Fault-inject informational metadata in a stopped, isolated receiver.
        // The canonical body/state are unchanged; no verifier token is persisted.
        let prior: Value = read(&network.join("refused.json"))?;
        let manifest: CanonicalProofManifest =
            serde_json::from_value(prior["admission"]["status"]["manifest"].clone())?;
        let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
        let before = canonical_digest(&stores.state)?;
        let cache = shell_storage::CanonicalProofUploadStore::new(Arc::new(stores.state.clone()));
        cache.claim(&manifest.id(), true)?;
        cache.complete(&manifest.id(), Ok(json!({"forged_local_receipt":true})))?;
        let mut record = prior["admission"]["status"].clone();
        record["state"] = json!("verifying");
        let key = [
            b"local/canonical-admission/v1/record/".as_slice(),
            c.block.as_bytes(),
        ]
        .concat();
        stores.state.put(&key, &serde_json::to_vec(&record)?)?;
        stores.state.flush()?;
        ensure(
            canonical_digest(&stores.state)? == before,
            "metadata fault changed native state",
        )?;
        let mut forged_receipt = network.join("forged-status.json");
        let mut index = 2;
        while forged_receipt.exists() {
            forged_receipt = network.join(format!("forged-status-{index}.json"));
            index += 1;
        }
        write(
            &forged_receipt,
            &json!({"stale_verifying_record":record,"verified_cache_is_informational":true,"native_unchanged":true}),
        )?;
        *faults.manifest_override.write().unwrap() = Some(manifest);
    } else if negative {
        prepare_at(out, "network-bad-air")?;
        let mut proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
            read(&out.join("job/proof.json"))?;
        proof.transactions[0]
            .signature
            .transaction
            .signature
            .equation
            .key
            .proof_bytes[0] ^= 1;
        let bytes = serde_json::to_vec(&proof)?;
        let mut manifest: CanonicalProofManifest = read(&out.join("job/manifest.json"))?;
        manifest.total_bytes = bytes.len() as u64;
        manifest.payload_hash = blake3_hash(&bytes);
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        let cache = shell_storage::CanonicalProofUploadStore::new(Arc::new(stores.state));
        let id = cache.begin(manifest.clone())?.proof_id;
        for (index, chunk) in bytes
            .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
            .enumerate()
        {
            cache.append(&id, index as u32, chunk)?;
        }
        ensure(
            cache.payload(&id)? == bytes,
            "negative graph outer hash incorrect",
        )?;
        *faults.manifest_override.write().unwrap() = Some(manifest);
    }
    faults.hold.store(pause, Ordering::SeqCst);
    let provider = Live::start(
        &network.join("provider/db"),
        &c,
        vec![],
        false,
        false,
        Some(faults.clone()),
    )
    .await?;
    let receiver = Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await?;
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        if pause {
            while !faults.seen.load(Ordering::SeqCst) {
                ensure(!receiver.task.is_finished() && !provider.task.is_finished(), "network node exited")?;
                ensure(tokio::time::Instant::now() < deadline, "ordinary candidate/chunk discovery timeout")?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let status = receiver.call("admin_canonicalProofAdmission", json!([c.block])).await?;
            ensure(status["nativeCanonical"] == false, "partial chunks committed native state")?;
            let initial: Value = read(&network.join("initial.json"))?;
            ensure(json!(canonical_digest(receiver.node.store.as_ref())?) == initial["native_digest"], "pending candidate wrote canonical state")?;
            write(&network.join("paused.json"), &status)?;
        } else {
            loop {
                ensure(!receiver.task.is_finished() && !provider.task.is_finished(), "network node exited")?;
                let status = receiver.call("admin_canonicalProofAdmission", json!([c.block])).await?;
                if status["status"]["state"] == "failed" {
                    if !negative { return Err(format!("candidate failed: {status}").into()); }
                    let initial: Value = read(&network.join("initial.json"))?;
                    ensure(status["nativeCanonical"] == false && json!(canonical_digest(receiver.node.store.as_ref())?) == initial["native_digest"], "invalid AIR changed canonical state")?;
                    let error = status["status"]["error"].as_str().ok_or("missing AIR error")?;
                    ensure(error.contains("public-key") || error.contains("proof"), "unexpected proof refusal")?;
                    write(&network.join(if recovery {"refused-recheck.json"} else {"refused.json"}), &json!({"admission":status,"correct_outer_hash":true,"genuine_raw_signatures":true,"native_unchanged":true,"served_chunks":faults.chunks.load(Ordering::SeqCst)}))?;
                    break;
                }
                if status["status"]["state"] == "complete" {
                    ensure(!negative, "invalid AIR was accepted")?;
                    ensure(status["nativeCanonical"] == true, "completed candidate not canonical")?;
                    let control: Value = read(&out.join("control.json"))?;
                    let block: Block = read(&out.join("candidate.json"))?;
                    ensure(receiver.node.chain_store.get_head_hash()? == Some(c.block)
                        && receiver.node.chain_store.get_receipts(&c.block)?.map(|x| serde_json::to_value(x).unwrap()) == Some(control["receipts"].clone())
                        && accounts(receiver.node.store.clone(), &block)? == control["accounts"], "automatic native commit differs from independent execution")?;
                    write(&network.join("complete.json"), &json!({"admission":status,"served_chunks":faults.chunks.load(Ordering::SeqCst),"actual_normal_block_sync":true,"operator_fetch_or_import":false,"root_receipts_accounts_match":true}))?;
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("automatic admission timeout: {status}").into());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Ok::<_, Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    faults.release.notify_one();
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    Ok(())
}
pub(super) fn verify(out: &Path) -> Result<(), Error> {
    verify_at(out, "network")
}
fn verify_at(out: &Path, directory: &str) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let proof = read(&out.join("job/proof.json"))?;
    let control: Value = read(&out.join("control.json"))?;
    let network = out.join(directory);
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let before = digest(store.as_ref())?;
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    ensure(
        node.chain_store.get_head_hash()? == Some(c.block),
        "cold receiver head mismatch",
    )?;
    let result = node.replay_canonical_transactions_with_proof(c.block, c.block, &proof)?;
    ensure(
        result.state_root == block.header.state_root
            && serde_json::to_value(&result.receipts)? == control["receipts"]
            && accounts(store.clone(), &block)? == control["accounts"],
        "cold automatic proof-backed replay differs from native control",
    )?;
    ensure(
        digest(store.as_ref())? == before,
        "cold automatic verification wrote native state",
    )?;
    let mut receipt = network.join("verified.json");
    let mut i = 2;
    while receipt.exists() {
        receipt = network.join(format!("verified-{i}.json"));
        i += 1;
    }
    write(&receipt, &result)
}

pub(super) fn verify_gossip(out: &Path) -> Result<(), Error> {
    verify_at(out, "network-gossip")
}

pub(super) async fn gossip(out: &Path) -> Result<(), Error> {
    let network = out.join("network-gossip");
    ensure(
        !network.exists(),
        "gossip fixture exists; retain it and inspect receipts",
    )?;
    prepare_at(out, "network-gossip")?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let initial: Value = read(&network.join("initial.json"))?;
    {
        let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
        let chain = ChainStore::new(Arc::new(stores.state.clone()));
        ensure(
            chain.get_block_by_hash(&c.block)?.is_none()
                && stores
                    .state
                    .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                    .is_empty(),
            "gossip receiver already has source body or proof cache",
        )?;
        ensure(
            json!(canonical_digest(&stores.state)?) == initial["native_digest"],
            "gossip initial state changed",
        )?;
    }
    let faults = Arc::new(Faults::default());
    *faults.gossip_block.write().unwrap() = Some(block.clone());
    let provider = Live::start(
        &network.join("provider/db"),
        &c,
        vec![],
        false,
        false,
        Some(faults.clone()),
    )
    .await?;
    let provider_peer = provider.info.read().unwrap().peer_id.clone();
    let receiver = Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await?;
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(), "gossip node exited")?;
            let status = receiver.call("admin_canonicalProofAdmission", json!([c.block])).await?;
            ensure(status["status"]["state"] != "failed", &format!("gossip proof refused: {status}"))?;
            if status["status"]["state"] == "complete" {
                let control: Value = read(&out.join("control.json"))?;
                ensure(status["nativeCanonical"] == true
                    && status["status"]["peer"] == provider_peer
                    && receiver.node.chain_store.get_head_hash()? == Some(c.block)
                    && receiver.node.chain_store.get_receipts(&c.block)?.map(serde_json::to_value).transpose()? == Some(control["receipts"].clone())
                    && accounts(receiver.node.store.clone(), &block)? == control["accounts"],
                    "gossip native commit differs from independent control")?;
                let attempts = faults.gossip_attempts.load(Ordering::SeqCst);
                let suppressed = faults.suppressed_direct_bodies.load(Ordering::SeqCst);
                let chunks = faults.chunks.load(Ordering::SeqCst);
                ensure(attempts > 0 && suppressed > 0 && chunks > 0, "gossip-only transport condition not exercised")?;
                write(&network.join("complete.json"), &json!({"admission":status,"broadcast_attempts":attempts,"suppressed_direct_bodies":suppressed,"served_chunks":chunks,"actual_libp2p_gossip":true,"no_direct_source_body":true,"root_receipts_accounts_match":true}))?;
                break;
            }
            ensure(tokio::time::Instant::now() < deadline, &format!("gossip admission timeout: {status}"))?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    Ok(())
}

pub(super) fn snapshot(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network/receiver/db"), None)?;
    let rows: Vec<_> = stores
        .state
        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
        .iter()
        .filter(|(k, _)| k.starts_with(&[CANONICAL_PROOF_CACHE_PREFIX, b"data/"].concat()))
        .map(|(k, v)| json!({"key":hex::encode(k),"hash":blake3_hash(v),"bytes":v.len()}))
        .collect();
    println!(
        "{}",
        json!({"head":ChainStore::new(Arc::new(stores.state.clone())).get_head_hash()?,"canonical_digest":canonical_digest(&stores.state)?,"immutable_chunks":rows})
    );
    Ok(())
}

fn checkpoint_components(store: &impl KvStore, block: ShellHash) -> Result<usize, Error> {
    let key = [
        b"local/canonical-production/v1/certificates/".as_slice(),
        block.as_bytes(),
        b"/production/index",
    ]
    .concat();
    let index: Value =
        serde_json::from_slice(&store.get(&key)?.ok_or("source2 checkpoint index absent")?)?;
    Ok(index["components"]
        .as_object()
        .ok_or("source2 components absent")?
        .len())
}
fn sync_controls(
    out: &Path,
    receiver: Arc<RocksDbStore>,
    provider: Arc<RocksDbStore>,
) -> Result<Value, Error> {
    let control: Value = read(&out.join("advance-control.json"))?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let candidate: Block = read(&out.join("candidate.json"))?;
    let mut blocks = vec![candidate];
    blocks.extend(read::<Vec<Block>>(&out.join("advance-blocks.json"))?);
    let target = ChainStore::new(receiver.clone());
    let source = ChainStore::new(provider);
    let last = blocks.last().ok_or("empty native controls")?;
    ensure(
        source.get_head_hash()? == Some(last.hash()),
        "provider native head changed during proving",
    )?;
    ensure(
        target.get_head_hash()? == Some(last.hash())
            && json!(last.hash()) == control["head"]
            && json!(last.number()) == control["height"],
        "native sync head differs from independent control",
    )?;
    ensure(
        target.get_block_hash_by_number(0)? == source.get_block_hash_by_number(0)?,
        "native genesis differs",
    )?;
    for block in &blocks {
        ensure(
            target.get_block_hash_by_number(block.number())? == Some(block.hash())
                && target.get_block_by_hash(&block.hash())?.as_ref() == Some(block),
            "canonical synchronized body/hash mismatch",
        )?;
        ensure(
            target.get_receipts(&block.hash())? == source.get_receipts(&block.hash())?,
            "synchronized persisted receipts differ from native control",
        )?;
    }
    let mut current_view = blocks[0].clone();
    current_view.header.state_root = last.header.state_root;
    ensure(
        json!(last.header.state_root) == control["root"]
            && accounts(receiver.clone(), &current_view)? == control["accounts"],
        "native sync root/accounts differ from independent control",
    )?;
    let result = json!({"head":last.hash(),"height":last.number(),"root":last.header.state_root,"canonical_bodies_and_receipts":blocks.len(),"accounts":accounts(receiver,&current_view)?,"source1":c.block});
    Ok(result)
}
pub(super) async fn sustained_sync(out: &Path) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let blocks: Vec<Block> = read(&out.join("advance-blocks.json"))?;
    let second = blocks.first().ok_or("second native block absent")?.clone();
    let network = out.join("network");
    ensure(
        !network.join("sync-complete.json").exists(),
        "sync already complete; use verify",
    )?;
    let initial_components = {
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        checkpoint_components(&stores.state, second.hash())?
    };
    ensure(
        (1..=61).contains(&initial_components),
        "source2 captured checkpoint missing or invalid",
    )?;
    let faults = Arc::new(Faults::default());
    faults.hold_suffix.store(true, Ordering::SeqCst);
    let provider = Live::start(
        &network.join("provider/db"),
        &c,
        vec![],
        false,
        true,
        Some(faults.clone()),
    )
    .await?;
    let receiver = Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await?;
    let result=async {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(4*60*60);
        let mut last_progress=tokio::time::Instant::now();
        let mut previous=None;
        loop {
            ensure(!receiver.task.is_finished() && !provider.task.is_finished(),"sustained sync node exited")?;
            let production=provider.call("admin_canonicalProofProduction",json!([second.hash()])).await?;
            ensure(production["status"]["state"]!="failed",&format!("source2 producer failed: {production}"))?;
            let components=checkpoint_components(provider.node.store.as_ref(),second.hash())?;
            let head=receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?;
            let admission=receiver.call("admin_canonicalProofAdmission",json!([second.hash()])).await?;
            ensure(admission["status"]["state"]!="failed",&format!("source2 admission failed: {admission}"))?;
            let current=(components,head.number(),production["status"]["state"].clone(),admission["status"]["state"].clone());
            if previous.as_ref()!=Some(&current) {
                previous=Some(current);last_progress=tokio::time::Instant::now();
                let progress=json!({"admission":admission,"source2":second.hash(),"checkpoint_components":components,"follower_height":head.number(),"producer":production,"suffix_held":faults.suffix_seen.load(Ordering::SeqCst)});
                let temp=network.join("sync-progress.tmp");std::fs::write(&temp,serde_json::to_vec(&progress)?)?;std::fs::rename(temp,network.join("sync-progress.json"))?;
                println!("source2 components={components}; follower height={}",head.number());
            }
            if faults.suffix_seen.load(Ordering::SeqCst) {
                ensure(head.hash()==second.hash(),"suffix gate did not freeze independent parent2")?;
                ensure(production["status"]["state"]=="complete" && components==61,"source2 graph incomplete")?;
                let manifest:CanonicalProofManifest=serde_json::from_value(production["status"]["manifest"].clone())?;
                let first_manifest:CanonicalProofManifest=read(&out.join("job/manifest.json"))?;
                ensure(manifest.block_hash==second.hash() && manifest.payload_hash!=first_manifest.payload_hash,"source2 reused the first source graph")?;
                ensure(initial_components==61 || production["status"]["reused"].as_u64().is_some_and(|n|n>=initial_components as u64),"retained source2 certificates were not rechecked")?;
                let cache=shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                let bytes=cache.payload(&manifest.id())?;
                let proof:shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof=serde_json::from_slice(&bytes)?;
                let before=canonical_digest(receiver.node.store.as_ref())?;
                let node=receiver.node.clone();let hash=second.hash();
                let replay=tokio::task::spawn_blocking(move||node.replay_canonical_transactions_with_proof(hash,hash,&proof)).await??;
                ensure(canonical_digest(receiver.node.store.as_ref())?==before,"live source2 proof replay wrote native state")?;
                ensure(replay.state_root==second.header.state_root && receiver.node.chain_store.get_receipts(&hash)?.as_ref()==Some(&replay.receipts),"source2 full replay differs from persisted execution")?;
                {
                    use std::io::Write;
                    let path=network.join("source2-proof.json");
                    if path.exists() { ensure(std::fs::read(path)?==bytes,"retained source2 proof conflicts")?; }
                    else { let mut artifact=std::fs::OpenOptions::new().write(true).create_new(true).open(path)?; artifact.write_all(&bytes)?;artifact.sync_all()?; }
                }
                write(&network.join("source2-manifest.json"),&manifest)?;
                write(&network.join("sync-height2-proof-replay.json"),&json!({"replay":replay,"native_unchanged":true,"suffix_delay_is_explicit_test_condition":true,"production":production}))?;
                faults.release_suffix.notify_one();break;
            }
            ensure(tokio::time::Instant::now()<deadline && last_progress.elapsed()<Duration::from_secs(1800),"source2 proving/sync made no progress within its documented long-operation bound")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let deadline=tokio::time::Instant::now()+Duration::from_secs(180);
        while receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number()<130 {
            ensure(!receiver.task.is_finished() && !provider.task.is_finished(),"suffix sync node exited")?;
            ensure(tokio::time::Instant::now()<deadline,"ordinary suffix sync failed to reach130")?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let result=sync_controls(out,receiver.node.store.clone(),provider.node.store.clone())?;
        write(&network.join("sync-complete.json"),&result)?;
        Ok::<_,Error>(())
    }.await;
    // Release a blocked response even on refusal before joining either node.
    faults.release_suffix.notify_one();
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    Ok(())
}
pub(super) fn verify_sync(out: &Path) -> Result<(), Error> {
    let network = out.join("network");
    let receiver = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let provider = RocksDbStore::open_all(network.join("provider/db"), None)?;
    let before = digest(&receiver.state)?;
    let store = Arc::new(receiver.state);
    let result = sync_controls(out, store.clone(), Arc::new(provider.state))?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let blocks: Vec<Block> = read(&out.join("advance-blocks.json"))?;
    let second = blocks.first().ok_or("source2 absent")?;
    let proof = read(&network.join("source2-proof.json"))?;
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    let head = node
        .chain_store
        .get_head_hash()?
        .ok_or("cold head absent")?;
    let error = node
        .replay_canonical_transactions_with_proof(head, second.hash(), &proof)
        .unwrap_err()
        .to_string();
    ensure(
        error.contains("retention bound"),
        &format!("unexpected bounded historical result: {error}"),
    )?;
    ensure(
        digest(store.as_ref())? == before,
        "cold native sync verification wrote state",
    )?;
    let mut path = network.join("sync-verified.json");
    let mut i = 2;
    while path.exists() {
        path = network.join(format!("sync-verified-{i}.json"));
        i += 1;
    }
    write(
        &path,
        &json!({"native":result,"expected_historical_refusal":error,"native_unchanged":true}),
    )
}
