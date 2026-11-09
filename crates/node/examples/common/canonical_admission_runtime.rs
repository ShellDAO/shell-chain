//! Real ordinary block sync and dedicated proof transfer, with a cold receiver.
#[path = "rotation_proof.rs"]
pub(super) mod rotation;
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
    withheld_block: RwLock<Option<ShellHash>>,
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
impl Faults {
    fn withhold(&self, message: &mut NetworkMessage) -> bool {
        // Deliver the Byzantine child only after the valid parent has finalized.
        // Empty responses still reach the ordinary sync/certificate handlers.
        let Some(hash) = *self.withheld_block.read().unwrap() else {
            return false;
        };
        match message {
            NetworkMessage::NewBlock(block) if block.hash() == hash => return true,
            NetworkMessage::CommitCertificate { block_hash, .. } if *block_hash == hash => {
                return true
            }
            NetworkMessage::BlockResponse {
                blocks,
                commit_certificates,
                ..
            } => {
                blocks.retain(|b| b.hash() != hash);
                commit_certificates.retain(|(h, _)| *h != hash);
            }
            NetworkMessage::BodyResponse { blocks, .. } => blocks.retain(|b| b.hash() != hash),
            _ => {}
        }
        false
    }
}
struct Provider {
    inner: Libp2pNetwork,
    faults: Arc<Faults>,
    gossip_timer: tokio::time::Interval,
}
#[async_trait]
impl NetworkService for Provider {
    async fn broadcast(&self, mut m: NetworkMessage) -> Result<(), NetworkError> {
        if self.faults.withhold(&mut m) {
            return Ok(());
        }
        self.inner.broadcast(m).await
    }
    async fn send_to_peer(&self, p: &PeerId, mut m: NetworkMessage) -> Result<(), NetworkError> {
        if self.faults.withhold(&mut m) {
            return Ok(());
        }
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
                // RPC starts before retained producer checkpoints are prepared.
                // Wait for the event loop to publish actual producer readiness.
                && (!production || live.node.metrics.production_ready.get() != 0)
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
                && !k.starts_with(b"local/canonical-production/v1/")
        })
        .collect();
    Ok(blake3_hash(&serde_json::to_vec(&rows)?))
}
pub(super) fn prepare(out: &Path) -> Result<(), Error> {
    prepare_at(out, "network")
}
fn prepare_at(out: &Path, directory: &str) -> Result<(), Error> {
    prepare_from(out, directory, &out.join("native/db"))
}
fn prepare_from(out: &Path, directory: &str, source_path: &Path) -> Result<(), Error> {
    let network = out.join(directory);
    ensure(
        !network.exists(),
        "network data exists; refusing replacement",
    )?;
    std::fs::create_dir(&network)?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let source = RocksDbStore::open_all(source_path, None)?;
    std::fs::create_dir(network.join("provider"))?;
    source.create_checkpoint(network.join("provider/db"))?;
    let chain = ChainStore::new(Arc::new(source.state));
    let config = chain
        .get_chain_config()?
        .ok_or("source configuration absent")?;
    let genesis = chain
        .get_block_by_hash(&config.genesis_hash)?
        .ok_or("source genesis absent")?;
    let control: Value = read(&out.join("control.json"))?;
    let first_use = control["first_use_parent_unregistered"]
        .as_bool()
        .unwrap_or(false);
    let keys = sender_addresses(&block)
        .into_iter()
        .map(|address| {
            let transaction = block
                .transactions
                .iter()
                .find(|tx| tx.from == address)
                .ok_or("source transaction absent")?;
            let unbound = first_use && transaction.pubkey_mode.is_embedded();
            let key = if unbound {
                transaction
                    .pubkey_mode
                    .pubkey_bytes()
                    .ok_or("first-use Embedded source key absent")?
                    .to_vec()
            } else {
                chain.get_pubkey(&address)?.ok_or("parent key absent")?
            };
            Ok((address, key, unbound))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let mut world = WorldState::new(store.clone());
    let funding = if out.join("initial-funding.json").exists() {
        read::<u64>(&out.join("initial-funding.json"))?
    } else {
        1_000_000
    };
    for (address, key, unbound) in &keys {
        world.set_account(
            address,
            &Account::new_user_account(
                if *unbound {
                    ShellHash::ZERO
                } else {
                    blake3_hash(key)
                },
                U256::from(funding),
            ),
        )?;
    }
    ensure(
        world.state_root()? == c.genesis_root && genesis.header.state_root == c.genesis_root,
        "independent receiver genesis mismatch",
    )?;
    let target = ChainStore::new(store.clone());
    for (address, key, unbound) in &keys {
        if !unbound {
            target.put_pubkey(address, key)?;
        }
    }
    target.put_pubkey(&c.authority, &c.authority_key)?;
    target.commit_genesis_block(&genesis, &config)?;
    let initial_registered =
        keys.iter()
            .try_fold(0usize, |count, (address, _, _)| -> Result<usize, Error> {
                Ok(count + usize::from(target.get_pubkey(address)?.is_some()))
            })?;
    let initial_unbound = keys.iter().filter(|(_, _, unbound)| *unbound).count();
    ensure(
        initial_registered == keys.len() - initial_unbound,
        "independent receiver parent registry mismatch",
    )?;
    store.flush()?;
    write(
        &network.join("initial.json"),
        &json!({"head":genesis.hash(),"native_digest":canonical_digest(store.as_ref())?,"independent_genesis":true,"first_use_parent_unregistered":first_use,"initial_registered_sender_keys":initial_registered,"initial_unbound_sender_keys":initial_unbound,"private_keys_persisted":false}),
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
    let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
        read(&out.join("job/proof.json"))?;
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
        result.proved_proposer_signature == (proof.version == 2)
            && result.state_root == block.header.state_root
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

pub(super) fn verify_full(out: &Path) -> Result<(), Error> {
    let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
        read(&out.join("job/proof.json"))?;
    ensure(
        proof.version == 2 && proof.proposer.is_some(),
        "full proof envelope missing proposer",
    )?;
    verify_at(out, "network-full")
}

pub(super) fn snapshot_full(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("network-full/provider/db"), None)?;
    let rows: Vec<_> = stores.state.scan_prefix(b"local/canonical-production/v1/")?.into_iter()
        .map(|(key,value)|json!({"key":hex::encode(key),"hash":blake3_hash(&value),"bytes":value.len()})).collect();
    println!(
        "{}",
        json!({"native_digest":canonical_digest(&stores.state)?,"rows":rows})
    );
    Ok(())
}

pub(super) fn snapshot_consecutive(out: &Path) -> Result<(), Error> {
    snapshot_production(out, "network-consecutive")
}
pub(super) fn snapshot_batch(out: &Path) -> Result<(), Error> {
    snapshot_production(out, "network-batch")
}
pub(super) fn snapshot_wide(out: &Path) -> Result<(), Error> {
    snapshot_production(out, "network-wide")
}
fn snapshot_production(out: &Path, directory: &str) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join(directory).join("provider/db"), None)?;
    let rows = stores
        .state
        .scan_prefix(b"local/canonical-production/v1/")?;
    let bytes = rows
        .iter()
        .filter(|(k, _)| k != b"local/canonical-production/v1/bytes")
        .map(|(k, v)| (k.len() + v.len()) as u64)
        .sum::<u64>();
    let recorded = stores
        .state
        .get(b"local/canonical-production/v1/bytes")?
        .ok_or("missing global counter")?;
    ensure(
        recorded.as_slice() == bytes.to_be_bytes() && bytes <= 256 * 1024 * 1024,
        "consecutive global quota/accounting mismatch",
    )?;
    let rows: Vec<_> = rows
        .into_iter()
        .map(|(k, v)| json!({"key":hex::encode(k),"hash":blake3_hash(&v),"bytes":v.len()}))
        .collect();
    println!(
        "{}",
        json!({"native_digest":canonical_digest(&stores.state)?,"physical_checkpoint_bytes":bytes,"rows":rows})
    );
    Ok(())
}

pub(super) async fn consecutive(out: &Path, pause: bool) -> Result<(), Error> {
    let network = out.join("network-consecutive");
    let c: fixture::Context = read(&out.join("context.json"))?;
    let later: Block = read(&out.join("later-block.json"))?;
    if !network.exists() {
        ensure(
            pause && out.join("full-result.json").exists(),
            "completed full run required",
        )?;
        prepare_from(
            out,
            "network-consecutive",
            &out.join("network-full/provider/db"),
        )?;
        // The single-authority fixture's existing proposer signature covers exactly
        // the native vote message (the block hash). No new signing key is required.
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        let node = fixture::node(Arc::new(stores.state), c.authority, &c.authority_key)?;
        if node.chain_store.get_head_hash()? == Some(c.block) {
            node.import_block(later.clone(), &MultiVerifier)?;
        }
        ensure(
            node.chain_store.get_head_hash()? == Some(later.hash()),
            "retained successor did not become native source",
        )?;
        let mut round = shell_consensus::wpoa_state::WPoaRound::new(
            later.number(),
            0,
            node.consensus.read().validator_weights(),
        );
        let _ = round.on_block_proposed(later.hash(), c.authority);
        *node.wpoa_round.lock() = Some(round);
        node.handle_wpoa_vote(
            c.authority,
            later.hash(),
            later.number(),
            later
                .proposer_seal
                .clone()
                .ok_or("missing signed successor seal")?,
        )
        .ok_or("genuine successor quorum vote failed")?;
        ensure(
            node.finality.read().last_finalized_number() == 2,
            "genuine same-message successor vote failed",
        )?;
        write(
            &network.join("vote.json"),
            &json!({"existing_genuine_proposer_signature_used_as_same_hash_vote":true,"finalized":2}),
        )?;
    }
    {
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        let chain = ChainStore::new(Arc::new(stores.state));
        let source = shell_stark_prover::canonical_producer::CanonicalProductionSource::capture(
            &chain,
            later.hash(),
            later.hash(),
        )?;
        let path = network.join("source2-capture.json");
        if !path.exists() {
            write(&path, &serde_json::from_slice::<Value>(source.identity())?)?;
        }
    }
    ensure(
        !network.join("complete.json").exists(),
        "consecutive result exists; use verify",
    )?;
    if !pause {
        ensure(
            network.join("paused.json").exists(),
            "consecutive pause missing",
        )?;
    }
    let faults = Arc::new(Faults::default());
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
    let provider_node = provider.node.clone();
    let result=async {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(6*60*60);
        let mut last_progress=tokio::time::Instant::now();let mut prior=None;
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(),"consecutive node exited")?;
            let components=checkpoint_components(provider.node.store.as_ref(),later.hash())?;
            let production=provider.call("admin_canonicalProofProduction",json!([later.hash()])).await?;
            ensure(production["status"]["state"]!="failed",&format!("consecutive production failed: {production}"))?;
            let admission=receiver.call("admin_canonicalProofAdmission",json!([later.hash()])).await?;
            let receiver_height=receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number();
            let state=(components,production["status"]["state"].clone(),admission["status"]["state"].clone(),receiver_height,receiver.node.finality.read().last_finalized_number());
            if prior.as_ref()!=Some(&state) {
                prior=Some(state);last_progress=tokio::time::Instant::now();
                let progress=json!({"components":components,"production":production["status"],"admission":admission,"receiver_height":receiver_height,"finalized":receiver.node.finality.read().last_finalized_number()});
                let tmp=network.join("progress.tmp");std::fs::write(&tmp,serde_json::to_vec(&progress)?)?;std::fs::rename(tmp,network.join("progress.json"))?;
                println!("consecutive components={components}; admission={}",admission["status"]["state"]);
            }
            if pause && components>0 {ensure(receiver_height<2,"partial second graph imported")?;break;}
            ensure(admission["status"]["state"]!="failed",&format!("consecutive admission failed: {admission}"))?;
            if admission["status"]["state"]=="complete" && receiver.node.finality.read().last_finalized_number()==2 {
                let control:Value=read(&out.join("later-control.json"))?;
                ensure(components==118 && production["status"]["state"]=="complete" && production["status"]["reused"].as_u64().unwrap_or(0)>=77,"consecutive common certificates not reused")?;
                ensure(receiver.node.chain_store.get_head_hash()?==Some(later.hash()) && *receiver.node.finality.read().last_finalized_hash()==later.hash()
                    && accounts(receiver.node.store.clone(),&later)?==control["accounts"]
                    && receiver.node.chain_store.get_receipts(&later.hash())?.map(serde_json::to_value).transpose()?==Some(control["receipts"].clone()),"consecutive native outputs/finality mismatch")?;
                for block in [c.block,later.hash()] {
                    let status=receiver.call("admin_canonicalProofAdmission",json!([block])).await?;
                    ensure(status["nativeCanonical"]==true && status["status"]["state"]=="complete","both targets must be proof-admitted")?;
                    let manifest:CanonicalProofManifest=serde_json::from_value(status["status"]["manifest"].clone())?;
                    let cache=shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                    ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|r|r["proved_proposer_signature"]==true),"consecutive native import omitted proposer AIR")?;
                    if block==later.hash() {
                        let bytes=cache.payload(&manifest.id())?;
                        use std::io::Write;
                        let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(network.join("source2-proof.json"))?;file.write_all(&bytes)?;file.sync_all()?;
                        write(&network.join("source2-manifest.json"),&manifest)?;
                    }
                }
                write(&network.join("complete.json"),&json!({"production":production["status"],"admission":admission,"both_full_proof_admitted":true,"native_outputs_match":true,"finalized":2,"served_chunks":faults.chunks.load(Ordering::SeqCst)}))?;
                break;
            }
            ensure(tokio::time::Instant::now()<deadline && last_progress.elapsed()<Duration::from_secs(1800),"consecutive proof exceeded progress bound")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_,Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    if pause {
        let production = provider_node
            .canonical_production_status(later.hash())?
            .ok_or("second production status missing")?;
        ensure(
            production["status"]["state"] == "paused"
                && production["status"]["components"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 118),
            "second producer did not durably pause",
        )?;
        write(&network.join("paused.json"), &production)?;
    }
    Ok(())
}

pub(super) fn verify_consecutive(out: &Path) -> Result<(), Error> {
    let network = out.join("network-consecutive");
    ensure(
        network.join("complete.json").exists(),
        "consecutive import incomplete",
    )?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let later: Block = read(&out.join("later-block.json"))?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    let before = digest(store.as_ref())?;
    let mut replays = Vec::new();
    for (block, path, control) in [
        (
            c.block,
            out.join("job/proof.json"),
            out.join("control.json"),
        ),
        (
            later.hash(),
            network.join("source2-proof.json"),
            out.join("later-control.json"),
        ),
    ] {
        let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof = read(&path)?;
        let result = node.replay_canonical_transactions_with_proof(later.hash(), block, &proof)?;
        let control: Value = read(&control)?;
        ensure(
            result.proved_proposer_signature
                && result.proved_sender_signatures == 1
                && result.state_root.to_string()
                    == control["state_root"].as_str().unwrap_or_default()
                && serde_json::to_value(&result.receipts)? == control["receipts"],
            "consecutive cold replay output mismatch",
        )?;
        replays.push(result);
    }
    ensure(
        digest(store.as_ref())? == before,
        "consecutive cold replay wrote state",
    )?;
    let mut path = network.join("verified.json");
    let mut index = 2;
    while path.exists() {
        path = network.join(format!("verified-{index}.json"));
        index += 1;
    }
    write(
        &path,
        &json!({"replays":replays,"native_unchanged":true,"current_head":later.hash()}),
    )
}

pub(super) async fn bad_consecutive_reference(out: &Path) -> Result<(), Error> {
    let network = out.join("network-consecutive-bad");
    ensure(
        out.join("network-consecutive/complete.json").exists(),
        "consecutive result required",
    )?;
    prepare_from(
        out,
        "network-consecutive-bad",
        &out.join("network-consecutive/provider/db"),
    )?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let later: Block = read(&out.join("later-block.json"))?;
    let before = {
        let stores = RocksDbStore::open_all(network.join("provider/db"), None)?;
        let store = &stores.state;
        let prefix = b"local/canonical-production/v1/";
        let component = [
            prefix.as_slice(),
            b"certificates/",
            later.hash().as_bytes(),
            b"/production/component/sender-0-key",
        ]
        .concat();
        let raw = store.get(&component)?.ok_or("shared component absent")?;
        let marker = b"\0canonical-certificate/v1/";
        let mut reference: Value = serde_json::from_slice(
            raw.strip_prefix(marker)
                .ok_or("component not a shared reference")?,
        )?;
        let mut hash = reference["hash"]
            .as_str()
            .ok_or("reference hash missing")?
            .as_bytes()
            .to_vec();
        hash[2] = if hash[2] == b'0' { b'1' } else { b'0' };
        reference["hash"] = json!(String::from_utf8(hash)?);
        let damaged = [
            marker.as_slice(),
            serde_json::to_vec(&reference)?.as_slice(),
        ]
        .concat();
        let record = [prefix.as_slice(), b"record/", later.hash().as_bytes()].concat();
        let prior = store.get(&record)?.ok_or("second record missing")?;
        let mut status: Value = serde_json::from_slice(&prior)?;
        status["state"] = json!("paused");
        let changed = serde_json::to_vec(&status)?;
        let counter = [prefix.as_slice(), b"bytes"].concat();
        let bytes = u64::from_be_bytes(
            store
                .get(&counter)?
                .ok_or("counter absent")?
                .try_into()
                .map_err(|_| "counter width")?,
        );
        let total = bytes
            .checked_sub((raw.len() + prior.len()) as u64)
            .and_then(|n| n.checked_add((damaged.len() + changed.len()) as u64))
            .ok_or("fault accounting overflow")?;
        let native = canonical_digest(store)?;
        let mut batch = shell_storage::WriteBatch::new();
        batch.put(component, damaged);
        batch.put(record, changed);
        batch.put(counter, total.to_be_bytes().to_vec());
        store.write_batch(batch)?;
        store.flush()?;
        ensure(
            canonical_digest(store)? == native,
            "reference fault changed native data",
        )?;
        native
    };
    let provider = Live::start(&network.join("provider/db"), &c, vec![], false, true, None).await?;
    let observer = Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await?;
    let result=async {
        let deadline=tokio::time::Instant::now()+Duration::from_secs(180);
        loop {
            ensure(!provider.task.is_finished(),"damaged provider exited unexpectedly")?;
            let status=provider.call("admin_canonicalProofProduction",json!([later.hash()])).await?;
            if status["status"]["state"]=="failed" {
                ensure(status["status"]["error"].as_str().is_some_and(|e|e.contains("reference integrity mismatch")),"unexpected reference refusal")?;
                ensure(canonical_digest(provider.node.store.as_ref())?==before,"failed production changed native provider")?;
                write(&network.join("refused.json"),&json!({"production":status["status"],"failed_provider_native_unchanged":true,"ready_payloads_are_not_checkpoint_authorization":true}))?;break;
            }
            ensure(tokio::time::Instant::now()<deadline,"damaged reference did not refuse")?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_,Error>(())
    }.await;
    let observer_stop = observer.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    observer_stop?;
    provider_stop?;
    Ok(())
}

/// Advance through an explicitly separate ordinary native successor, then
/// replay the full proof at its historical parent without changing current state.
pub(super) fn history_full(out: &Path, advance: bool) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let later: Block = read(&out.join("later-block.json"))?;
    let control: Value = read(&out.join("later-control.json"))?;
    let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
        read(&out.join("job/proof.json"))?;
    let stores = RocksDbStore::open_all(out.join("network-full/receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    if advance {
        ensure(
            node.chain_store.get_head_hash()? == Some(c.block),
            "history advance requires full admitted child",
        )?;
        node.import_block(later.clone(), &MultiVerifier)?;
    }
    ensure(
        node.chain_store.get_head_hash()? == Some(later.hash())
            && later.header.state_root != block.header.state_root
            && node
                .chain_store
                .get_receipts(&later.hash())?
                .map(serde_json::to_value)
                .transpose()?
                == Some(control["receipts"].clone())
            && accounts(store.clone(), &later)? == control["accounts"],
        "ordinary native history control mismatch",
    )?;
    let before = digest(store.as_ref())?;
    let replay = node.replay_canonical_transactions_with_proof(later.hash(), c.block, &proof)?;
    let original: Value = read(&out.join("control.json"))?;
    ensure(
        replay.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == original["receipts"]
            && digest(store.as_ref())? == before,
        "full historical replay changed current state or output",
    )?;
    let network = out.join("network-full");
    let mut path = network.join("history-verified.json");
    let mut n = 2;
    while path.exists() {
        path = network.join(format!("history-verified-{n}.json"));
        n += 1;
    }
    write(
        &path,
        &json!({"replay":replay,"current_head":later.hash(),"current_state_root":later.header.state_root,"current_state_unchanged":true,"ordinary_successor_is_not_claimed_proof_admitted":true}),
    )
}

/// Real production, shutdown/checkpoint recovery, peer intake and native consensus.
pub(super) async fn full(out: &Path, phase: &str) -> Result<(), Error> {
    let pause = phase == "full-pause";
    let negative = phase == "full-bad-proposer";
    let directory = if negative {
        "network-full-bad"
    } else {
        "network-full"
    };
    let network = out.join(directory);
    if pause {
        prepare_at(out, directory)?;
    } else if negative {
        ensure(
            out.join("network-full/complete.json").exists(),
            "complete full flow required",
        )?;
        prepare_from(out, directory, &out.join("network-full/provider/db"))?;
    } else {
        ensure(
            network.join("paused.json").exists(),
            "full checkpoint pause evidence absent",
        )?;
        ensure(
            !network.join("complete.json").exists(),
            "full flow already complete; use verify",
        )?;
    }
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    ensure(
        block
            .proposer_seal
            .as_ref()
            .is_some_and(|s| s.sig_type == shell_crypto::SignatureType::MlDsa65),
        "full fixture proposer must use MLDSA65",
    )?;
    let initial: Value = read(&network.join("initial.json"))?;
    let faults = Arc::new(Faults::default());
    if negative {
        let mut proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
            read(&out.join("job/proof.json"))?;
        proof
            .proposer
            .as_mut()
            .ok_or("missing full proposer proof")?
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
            "bad proposer payload outer hash incorrect",
        )?;
        *faults.manifest_override.write().unwrap() = Some(manifest);
    }
    let provider = Live::start(
        &network.join("provider/db"),
        &c,
        vec![],
        false,
        !negative,
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
    let provider_node = provider.node.clone();
    let receiver_node = receiver.node.clone();
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6*60*60);
        let mut last_progress = tokio::time::Instant::now();
        let mut prior = None;
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(), "full proof node exited")?;
            let components = checkpoint_components(provider.node.store.as_ref(), c.block)?;
            let production = provider.call("admin_canonicalProofProduction", json!([c.block])).await?;
            ensure(production["status"]["state"] != "failed", &format!("full producer failed: {production}"))?;
            let admission = receiver.call("admin_canonicalProofAdmission", json!([c.block])).await?;
            let state = (components, production["status"]["state"].clone(), admission["status"]["state"].clone());
            if prior.as_ref() != Some(&state) {
                prior = Some(state); last_progress = tokio::time::Instant::now();
                let progress = json!({"components":components,"production":production["status"],"admission":admission,"receiver_head":receiver.node.chain_store.get_head_hash()?});
                let temporary = network.join("progress.tmp");std::fs::write(&temporary,serde_json::to_vec(&progress)?)?;std::fs::rename(temporary,network.join("progress.json"))?;
                println!("full proof components={components}; admission={}", admission["status"]["state"]);
            }
            if pause && components > 0 {
                ensure(admission["nativeCanonical"] == false && json!(canonical_digest(receiver.node.store.as_ref())?) == initial["native_digest"], "partial full graph changed native state")?;
                break;
            }
            if admission["status"]["state"] == "failed" {
                ensure(negative && admission["nativeCanonical"] == false && json!(canonical_digest(receiver.node.store.as_ref())?) == initial["native_digest"], &format!("full proof admission failed: {admission}"))?;
                let error = admission["status"]["error"].as_str().ok_or("missing full refusal reason")?;
                ensure(error.contains("public-key") || error.contains("proof"), "unexpected proposer proof refusal")?;
                write(&network.join("refused.json"),&json!({"admission":admission,"correct_outer_hash":true,"genuine_raw_seal_and_sender":true,"native_unchanged":true}))?;
                break;
            }
            if admission["status"]["state"] == "complete" {
                ensure(!pause && !negative && production["status"]["state"] == "complete" && components == 118, "full production component profile incomplete")?;
                let control: Value = read(&out.join("control.json"))?;
                ensure(receiver.node.chain_store.get_head_hash()? == Some(c.block)
                    && receiver.node.chain_store.get_receipts(&c.block)?.map(serde_json::to_value).transpose()? == Some(control["receipts"].clone())
                    && accounts(receiver.node.store.clone(), &block)? == control["accounts"], "full native output differs from independent execution")?;
                if receiver.node.finality.read().last_finalized_number() < block.number() {
                    ensure(tokio::time::Instant::now() < deadline && last_progress.elapsed() < Duration::from_secs(1800), "full import certificate did not finalize within documented bound")?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                ensure(*receiver.node.finality.read().last_finalized_hash() == c.block
                    && provider.node.finality.read().last_finalized_number() == block.number(), "full import finality differs from genuine native quorum")?;
                let manifest: CanonicalProofManifest = serde_json::from_value(admission["status"]["manifest"].clone())?;
                let cache = shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                let bytes = cache.payload(&manifest.id())?;
                let proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof = serde_json::from_slice(&bytes)?;
                ensure(proof.version == 2 && proof.proposer.is_some(), "full graph downgraded to sender-only")?;
                ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|r|r["proved_proposer_signature"] == true), "native import did not consume full proposer AIR")?;
                std::fs::create_dir(out.join("job"))?;
                {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(out.join("job/proof.json"))?;
                    file.write_all(&bytes)?;file.sync_all()?;
                }
                write(&out.join("job/manifest.json"), &manifest)?;
                let paused: Value = read(&network.join("paused.json"))?;
                ensure(production["status"]["reused"].as_u64().unwrap_or(0) >= paused["status"]["components"].as_u64().ok_or("paused count absent")?, "full checkpoint was not reverified")?;
                write(&network.join("complete.json"), &json!({"production":production["status"],"admission":admission,"served_chunks":faults.chunks.load(Ordering::SeqCst),"root_receipts_accounts_match":true,"full_native_proposer_AIR_consumed":true,"finalized_height":block.number()}))?;
                break;
            }
            ensure(tokio::time::Instant::now() < deadline && last_progress.elapsed() < Duration::from_secs(1800), "full proof made no progress within documented bound")?;
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
        let production = provider_node
            .canonical_production_status(c.block)?
            .ok_or("full paused job absent")?;
        ensure(
            production["status"]["state"] == "paused"
                && production["status"]["components"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 118),
            "full producer did not persist interrupted checkpoint",
        )?;
        ensure(
            json!(canonical_digest(receiver_node.store.as_ref())?) == initial["native_digest"],
            "paused full receiver changed canonical state",
        )?;
        write(&network.join("paused.json"), &production)?;
    }
    if negative {
        let mut offline =
            fixture::node(receiver_node.store.clone(), c.authority, &c.authority_key)?;
        let mut proof: shell_stark_prover::canonical_batch::CanonicalSignatureBatchProof =
            read(&out.join("job/proof.json"))?;
        let before = canonical_digest(offline.store.as_ref())?;
        proof.version = 1;
        ensure(
            offline
                .import_block_with_canonical_proof(block.header.parent_hash, block.clone(), &proof)
                .is_err(),
            "v1 accepted an unversioned proposer proof",
        )?;
        proof.version = 2;
        let seal = proof.proposer.take();
        ensure(
            offline
                .import_block_with_canonical_proof(block.header.parent_hash, block.clone(), &proof)
                .is_err(),
            "v2 missing proposer proof fell back to native crypto",
        )?;
        proof.proposer = seal;
        let mut unauthorized = block.clone();
        unauthorized.header.proposer = Address::from([0x77; 32]);
        ensure(
            offline
                .import_block_with_canonical_proof(block.header.parent_hash, unauthorized, &proof)
                .is_err(),
            "proof replaced native proposer authorization",
        )?;
        ensure(
            canonical_digest(offline.store.as_ref())? == before,
            "full envelope/authority refusal changed native state",
        )?;
        write(
            &network.join("envelope-refused.json"),
            &json!({"v1_with_seal":true,"v2_without_seal":true,"native_authority_retained":true,"native_unchanged":true}),
        )?;
    }
    Ok(())
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
    let Some(bytes) = store.get(&key)? else {
        return Ok(0);
    };
    let index: Value = serde_json::from_slice(&bytes)?;
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

/// Full ordered registered-key batch, followed by a genuinely signed wrong-root child.
/// The bad child's source is explicitly Byzantine storage, never native execution.
pub(super) async fn batch(out: &Path, pause: bool, wide: bool) -> Result<(), Error> {
    let directory = if wide {
        "network-wide"
    } else {
        "network-batch"
    };
    let network = out.join(directory);
    let count = if wide { 16 } else { 2 };
    let profile: Value = read(&out.join("batch-fixture.json"))?;
    let first_use = profile["first_use_parent_unregistered"]
        .as_bool()
        .unwrap_or(false);
    let unbound_senders = profile["unbound_sender_count"]
        .as_u64()
        .unwrap_or(u64::from(first_use)) as usize;
    let senders = profile["registered_sender_keys"].as_u64().unwrap_or(1) as usize;
    ensure(
        ((wide && matches!(senders, 1 | 2 | 8 | 16)) || !wide && senders == 1)
            && unbound_senders <= senders
            && first_use == (unbound_senders > 0),
        "unsupported fixture sender count",
    )?;
    let components = if senders == 16 {
        982
    } else if wide {
        433 + 40 * (senders - 1)
    } else {
        179
    };
    // This is an experiment observation bound, not a protocol/activation change.
    let idle_bound = if wide { 2 * 60 * 60 } else { 1800 };
    let c: fixture::Context = read(&out.join("context.json"))?;
    let good: Block = read(&out.join("candidate.json"))?;
    let bad: Block = read(&out.join("batch-bad-block.json"))?;
    let control2: Block = read(&out.join("later-block.json"))?;
    let addresses = sender_addresses(&good);
    let per_sender = count / senders;
    let ordered = |block: &Block, start: usize| {
        sender_addresses(block) == addresses
            && addresses.iter().all(|address| {
                let nonces: Vec<_> = block
                    .transactions
                    .iter()
                    .filter(|tx| tx.from == *address)
                    .map(|tx| tx.tx.nonce)
                    .collect();
                nonces == (start as u64..(start + per_sender) as u64).collect::<Vec<_>>()
            })
    };
    ensure(
        good.transactions.len() == count
            && bad.transactions.len() == count
            && addresses.len() == senders
            && !addresses.contains(&c.authority)
            && ordered(&good, 0)
            && ordered(&bad, per_sender)
            && bad.transactions == control2.transactions
            && bad.header.state_root != control2.header.state_root,
        "ordered batch fixture mismatch",
    )?;
    if !network.exists() {
        ensure(
            pause && out.join("batch-fixture.json").exists(),
            "batch preparation required",
        )?;
        prepare_from(out, directory, &out.join("batch-native/db"))?;
    }
    ensure(
        !network.join("complete.json").exists(),
        "batch already complete; use verify",
    )?;
    ensure(
        pause || network.join("paused.json").exists(),
        "batch pause evidence missing",
    )?;
    let initial: Value = read(&network.join("initial.json"))?;
    let faults = Arc::new(Faults::default());
    *faults.withheld_block.write().unwrap() = Some(bad.hash());
    let provider = Live::start(
        &network.join("provider/db"),
        &c,
        vec![],
        false,
        true,
        Some(faults.clone()),
    )
    .await?;
    let receiver = match Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
        false,
        None,
    )
    .await
    {
        Ok(live) => live,
        Err(error) => {
            provider.stop().await?;
            return Err(error);
        }
    };
    let provider_node = provider.node.clone();
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(if wide { 12 * 60 * 60 } else { 6 * 60 * 60 });
        let mut last_progress = tokio::time::Instant::now();
        let mut prior = None;
        let mut baseline = None;
        loop {
            ensure(!provider.task.is_finished() && !receiver.task.is_finished(), "batch node exited")?;
            let counts = [checkpoint_components(provider.node.store.as_ref(), c.block)?, checkpoint_components(provider.node.store.as_ref(), bad.hash())?];
            let production1 = provider.call("admin_canonicalProofProduction", json!([c.block])).await?;
            let production2 = provider.call("admin_canonicalProofProduction", json!([bad.hash()])).await?;
            for status in [&production1, &production2] {
                ensure(status["status"]["state"] != "failed", &format!("batch producer failed: {status}"))?;
            }
            let admission1 = receiver.call("admin_canonicalProofAdmission", json!([c.block])).await?;
            let admission2 = receiver.call("admin_canonicalProofAdmission", json!([bad.hash()])).await?;
            let head = receiver.node.chain_store.get_head_block()?.ok_or("batch receiver head missing")?;
            let finalized = receiver.node.finality.read().last_finalized_number();
            let state = json!({"components":counts,"production1":production1["status"],"production2":production2["status"],"admission1":admission1,"admission2":admission2,"head":head.hash(),"height":head.number(),"finalized":finalized});
            if prior.as_ref() != Some(&state) {
                prior = Some(state.clone()); last_progress = tokio::time::Instant::now();
                let tmp = network.join("progress.tmp"); std::fs::write(&tmp, serde_json::to_vec(&state)?)?; std::fs::rename(tmp, network.join("progress.json"))?;
                println!("batch components={counts:?}; height={}; finalized={finalized}; admission2={}", head.number(), admission2["status"]["state"]);
            }
            ensure(admission1["status"]["state"] != "failed", &format!("valid ordered batch refused: {admission1}"))?;
            if pause && counts[0] > 0 {
                ensure(head.number() == 0 && finalized == 0 && json!(canonical_digest(receiver.node.store.as_ref())?) == initial["native_digest"], "partial batch changed native state")?;
                break;
            }
            if baseline.is_none() && admission1["status"]["state"] == "complete" && finalized == 1 {
                let control: Value = read(&out.join("control.json"))?;
                ensure(head.hash() == c.block && *receiver.node.finality.read().last_finalized_hash() == c.block
                    && (if first_use { counts[0] > 0 } else if senders == 16 { counts[0] >= components } else { counts[0] == components }) && production1["status"]["state"] == "complete"
                    && receiver.node.chain_store.get_receipts(&c.block)?.map(serde_json::to_value).transpose()? == Some(control["receipts"].clone())
                    && accounts(receiver.node.store.clone(), &good)? == control["accounts"], "valid batch native outputs/finality mismatch")?;
                if first_use {
                    let parent = receiver.node.chain_store.canonical_parent_view(c.block, good.header.parent_hash)?;
                    for tx in &good.transactions {
                        let prior_key = parent.registered_key(&tx.from)?;
                        let current_key = receiver.node.chain_store.get_pubkey(&tx.from)?;
                        let account = parent.world_state()?.get_account(&tx.from)?.ok_or("historical sender absent")?;
                        let valid = if let Some(embedded) = tx.pubkey_mode.pubkey_bytes() {
                            prior_key.is_none() && account.pq_pubkey_hash == ShellHash::ZERO
                                && current_key.as_deref() == Some(embedded)
                        } else {
                            prior_key.as_ref().is_some_and(|key| account.pq_pubkey_hash == blake3_hash(key))
                                && current_key == prior_key
                        };
                        ensure(valid, "proof admission did not preserve the exact mixed parent/registered key bindings")?;
                    }
                }
                let before = canonical_digest(receiver.node.store.as_ref())?;
                let path = network.join("rollback-baseline.json");
                let record = json!({"native_digest":before,"head":head.hash(),"finalized":finalized,"accounts":control["accounts"],"receipts":control["receipts"]});
                if path.exists() { ensure(read::<Value>(&path)? == record, "persisted rollback baseline changed")?; }
                else { write(&path, &record)?; }
                baseline = Some(before);
                *faults.withheld_block.write().unwrap() = None;
            }
            if admission2["status"]["state"] == "failed" {
                let error = admission2["status"]["error"].as_str().ok_or("missing batch refusal")?;
                ensure(error.contains("state root mismatch") && error.contains(&format!("{:?}", control2.header.state_root)), &format!("batch failed before all ordered native transactions executed: {error}"))?;
                let before = baseline.ok_or("bad child delivered before finalized parent")?;
                ensure(head.hash() == c.block && finalized == 1 && admission2["nativeCanonical"] == false
                    && receiver.node.chain_store.get_block_by_hash(&bad.hash())?.is_none()
                    && receiver.node.chain_store.get_receipts(&bad.hash())?.is_none()
                    && canonical_digest(receiver.node.store.as_ref())? == before, "failed batch leaked native writes")?;
                ensure((if first_use { counts[0] > 0 && counts[1] > 0 } else if senders == 16 { counts[0] >= components && counts[0] == counts[1] } else { counts == [components,components] }) && production2["status"]["state"] == "complete", "batch full graph incomplete")?;
                let mut sender_profiles = Vec::new();
                for (hash, status, store, name) in [(c.block, &admission1, receiver.node.store.clone(), "good"), (bad.hash(), &production2, provider.node.store.clone(), "bad")] {
                    let manifest: CanonicalProofManifest = serde_json::from_value(status["status"]["manifest"].clone())?;
                    ensure(manifest.block_hash == hash, "batch manifest mismatch")?;
                    let cache = shell_storage::CanonicalProofUploadStore::new(store);
                    if hash == c.block {
                        ensure(cache.status(&manifest.id())?.result.as_ref().is_some_and(|r| r["proved_sender_signatures"] == count && r["proved_proposer_signature"] == true), "native batch did not consume all sender AIRs and proposer AIR")?;
                    }
                    let bytes = cache.payload(&manifest.id())?;
                    let proof = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
                    ensure(proof.version == 2 && proof.proposer.is_some() && proof.transactions.len() == count, "full batch profile downgraded")?;
                    let profiles: Vec<_> = proof.transactions.iter().map(|tx| tx.signature.version).collect();
                    let unbound_proofs = unbound_senders * per_sender;
                    ensure(profiles.iter().filter(|&&version| version == 2).count() == unbound_proofs
                        && profiles.iter().filter(|&&version| version == 1).count() == count - unbound_proofs,
                        "actual bound/unbound sender proof composition differs from genesis")?;
                    let body = if hash == c.block { &good } else { &bad };
                    let mut senders = Vec::new();
                    for (entry, transaction) in proof.transactions.iter().zip(&body.transactions) {
                        let address_certificate = if entry.signature.version == 2 {
                            let address = entry.signature.tagged_key.as_ref().ok_or("unbound address certificate absent")?;
                            let key = &entry.signature.transaction.public_key_hash.message;
                            ensure(key.len() == 1952 && address.message.len() == 1953
                                && address.message[0] == shell_crypto::SignatureType::MlDsa65.as_u8()
                                && address.message[1..] == *key
                                && &address.output == transaction.from.as_bytes(), "unbound proof does not bind the full sender/key")?;
                            Some(blake3_hash(&serde_json::to_vec(address)?))
                        } else { None };
                        senders.push(json!({"from":transaction.from,"version":entry.signature.version,"embedded":transaction.pubkey_mode.is_embedded(),"address_certificate_hash":address_certificate}));
                    }
                    sender_profiles.push(json!({"target":name,"profiles":profiles,"senders":senders}));
                    use std::io::Write;
                    let extension = if wide { "cbor" } else { "json" };
                    let path = network.join(format!("{name}-proof.{extension}"));
                    if path.exists() { ensure(std::fs::read(&path)? == bytes, "retained batch proof changed")?; }
                    else { let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?; file.write_all(&bytes)?; file.sync_all()?; }
                    let path = network.join(format!("{name}-manifest.json"));
                    if path.exists() { ensure(read::<CanonicalProofManifest>(&path)? == manifest, "retained batch manifest changed")?; }
                    else { write(&path, &manifest)?; }
                }
                write(&network.join("complete.json"), &json!({"production1":production1["status"],"production2":production2["status"],"admission1":admission1,"admission2":admission2,"native_digest":before,"served_chunks":faults.chunks.load(Ordering::SeqCst),"both_native_transactions_executed_before_wrong_root_refusal":count==2,"native_transactions_executed_before_wrong_root_refusal":count,"unbound_first_use_registration_verified":first_use,"sender_profiles":sender_profiles,"failed_batch_native_unchanged":true,"bad_source_is_storage_only_byzantine_fixture":true,"finalized":finalized}))?;
                break;
            }
            ensure(tokio::time::Instant::now() < deadline && last_progress.elapsed() < Duration::from_secs(idle_bound), "batch progress bound exceeded")?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok::<_,Error>(())
    }.await;
    let receiver_stop = receiver.stop().await;
    let provider_stop = provider.stop().await;
    result?;
    receiver_stop?;
    provider_stop?;
    if pause {
        let production = provider_node
            .canonical_production_status(c.block)?
            .ok_or("batch pause status missing")?;
        ensure(
            production["status"]["state"] == "paused"
                && production["status"]["components"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < components as u64),
            "batch producer did not durably pause",
        )?;
        write(&network.join("paused.json"), &production)?;
    }
    Ok(())
}

/// Cold replay before/after a separately labelled, ordinarily imported correct child.
pub(super) fn verify_batch(
    out: &Path,
    history: bool,
    advance: bool,
    wide: bool,
) -> Result<(), Error> {
    let network = out.join(if wide {
        "network-wide"
    } else {
        "network-batch"
    });
    let count = if wide { 16 } else { 2 };
    let completed: Value = read(&network.join("complete.json"))?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let bad: Block = read(&out.join("batch-bad-block.json"))?;
    let later: Block = read(&out.join("later-block.json"))?;
    let proof_path = network.join(if wide {
        "good-proof.cbor"
    } else {
        "good-proof.json"
    });
    let proof = shell_stark_prover::compact_canonical::decode_payload(&std::fs::read(proof_path)?)?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    if advance {
        ensure(history, "ordinary batch advance requires history mode")?;
        match node.chain_store.get_head_hash()? {
            Some(head) if head == c.block => node.import_block(later.clone(), &MultiVerifier)?,
            Some(head) if head == later.hash() => {}
            _ => {
                return Err(
                    "batch ordinary advance requires valid parent or retained control".into(),
                )
            }
        }
    }
    let tip = if history { later.hash() } else { c.block };
    let control: Value = read(&out.join(if history {
        "later-control.json"
    } else {
        "control.json"
    }))?;
    let current = if history { &later } else { &block };
    ensure(
        node.chain_store.get_head_hash()? == Some(tip)
            && node.chain_store.get_block_by_hash(&bad.hash())?.is_none()
            && accounts(store.clone(), current)? == control["accounts"]
            && node
                .chain_store
                .get_receipts(&tip)?
                .map(serde_json::to_value)
                .transpose()?
                == Some(control["receipts"].clone()),
        "cold batch native controls mismatch",
    )?;
    if !history {
        ensure(
            json!(canonical_digest(store.as_ref())?) == completed["native_digest"],
            "cold failed-batch state changed",
        )?;
    }
    let before = digest(store.as_ref())?;
    let replay = node.replay_canonical_transactions_with_proof(tip, c.block, &proof)?;
    let original: Value = read(&out.join("control.json"))?;
    ensure(
        replay.proved_sender_signatures == count
            && replay.proved_proposer_signature
            && replay.state_root == block.header.state_root
            && serde_json::to_value(&replay.receipts)? == original["receipts"]
            && digest(store.as_ref())? == before,
        "cold full batch replay wrote state or output mismatch",
    )?;
    let label = if history {
        "history-verified"
    } else {
        "verified"
    };
    let mut path = network.join(format!("{label}.json"));
    let mut n = 2;
    while path.exists() {
        path = network.join(format!("{label}-{n}.json"));
        n += 1;
    }
    write(
        &path,
        &json!({"replay":replay,"current_head":tip,"current_state_root":current.header.state_root,"all_kv_unchanged":true,"ordinary_correct_successor_not_proof_admitted":history}),
    )
}

/// A valid certificate for another registered key cannot authorize this sender.
pub(super) fn mixed_key_refusal(out: &Path) -> Result<(), Error> {
    certificate_refusal(out, CertificateFault::Key)
}
/// Changing an intermediate Keccak lane with a genuine aggregate proof and a
/// freshly computed availability hash must fail full AIR at the native reader.
pub(super) fn aggregate_refusal(out: &Path) -> Result<(), Error> {
    certificate_refusal(out, CertificateFault::Keccak)
}
/// A genuine raw-key hash cannot replace the algorithm-tagged address proof.
pub(super) fn unbound_address_refusal(out: &Path) -> Result<(), Error> {
    certificate_refusal(out, CertificateFault::Address)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CertificateFault {
    Key,
    Keccak,
    Address,
}
fn certificate_refusal(out: &Path, fault: CertificateFault) -> Result<(), Error> {
    let wide = out.join("network-wide/complete.json").exists();
    let network = out.join(if wide {
        "network-wide"
    } else {
        "network-batch"
    });
    let label = match fault {
        CertificateFault::Keccak => "aggregate-refused",
        CertificateFault::Key => "cross-key-refused",
        CertificateFault::Address => "address-refused",
    };
    ensure(
        !network.join(format!("{label}.json")).exists(),
        "certificate refusal already recorded",
    )?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let other = block
        .transactions
        .iter()
        .position(|tx| tx.from != block.transactions[0].from);
    let original_path = network.join(if wide {
        "good-proof.cbor"
    } else {
        "good-proof.json"
    });
    let original = std::fs::read(&original_path)?;
    let mut proof = shell_stark_prover::compact_canonical::decode_payload(&original)?;
    if fault == CertificateFault::Keccak {
        let xof = &mut proof.transactions[0]
            .signature
            .transaction
            .signature
            .equation
            .matrix
            .polynomials[0]
            .xof;
        ensure(
            (xof.version == 2 && !xof.permutation_batches.is_empty()) || xof.version == 3,
            "aggregate certificate missing",
        )?;
        xof.permutations[0].rounds[11].theta[24] ^= 1;
    } else if fault == CertificateFault::Address {
        let signature = &mut proof
            .transactions
            .iter_mut()
            .find(|tx| tx.signature.version == 2)
            .ok_or("unbound sender proof absent")?
            .signature;
        ensure(
            signature.version == 2 && signature.tagged_key.is_some(),
            "unbound address profile absent",
        )?;
        signature.tagged_key = Some(signature.transaction.public_key_hash.clone());
    } else {
        let certificate = if let Some(index) = other {
            proof.transactions[index]
                .signature
                .transaction
                .signature
                .equation
                .key
                .clone()
        } else {
            proof
                .proposer
                .as_ref()
                .ok_or("distinct proposer donor missing")?
                .signature
                .equation
                .key
                .clone()
        };
        ensure(
            certificate.proof_bytes
                != proof.transactions[0]
                    .signature
                    .transaction
                    .signature
                    .equation
                    .key
                    .proof_bytes,
            "distinct key certificates missing",
        )?;
        proof.transactions[0]
            .signature
            .transaction
            .signature
            .equation
            .key = certificate;
    }
    let payload = shell_stark_prover::compact_canonical::encode_payload(
        &proof,
        shell_storage::MAX_CANONICAL_PROOF_BYTES as usize,
        true,
    )?;
    let hash = blake3_hash(&payload);
    ensure(
        hash != blake3_hash(&original),
        "certificate replacement did not change payload",
    )?;
    let decoded = shell_stark_prover::compact_canonical::decode_payload(&payload)?;
    let stores = RocksDbStore::open_all(network.join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    let tip = node
        .chain_store
        .get_head_hash()?
        .ok_or("certificate refusal tip absent")?;
    let later: Value = read(&out.join("later-control.json"))?;
    ensure(
        json!(tip) == later["head"],
        "certificate refusal requires advanced native control",
    )?;
    let before = digest(store.as_ref())?;
    let error = node
        .replay_canonical_transactions_with_proof(tip, c.block, &decoded)
        .expect_err("altered certificate must not authorize the sender")
        .to_string();
    ensure(
        match fault {
            CertificateFault::Keccak => error.contains("Keccak aggregate verification"),
            CertificateFault::Address => error.contains("unbound sender address"),
            CertificateFault::Key => error.contains("key") || error.contains("proof"),
        },
        "unexpected certificate refusal",
    )?;
    ensure(
        digest(store.as_ref())? == before && std::fs::read(original_path)? == original,
        "certificate refusal changed native or original proof data",
    )?;
    let path = network.join(format!("{label}.cbor"));
    if path.exists() {
        ensure(
            std::fs::read(path)? == payload,
            "retained certificate refusal payload differs",
        )?;
    } else {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
    }
    write(
        &network.join(format!("{label}.json")),
        &json!({"correct_outer_hash":hash,"valid_other_registered_key_certificate":fault==CertificateFault::Key,"changed_intermediate_lane_with_genuine_aggregate":fault==CertificateFault::Keccak,"genuine_raw_key_hash_cannot_authorize_unbound_address":fault==CertificateFault::Address,"donor_transaction":other,"donor_proposer":fault==CertificateFault::Key && other.is_none(),"error":error,"all_kv_unchanged":true,"original_proof_unchanged":true,"new_proofs_generated":0,"current_head":tip}),
    )
}

/// Repack an existing genuine full graph and verify it at a cold native history.
/// Input/output are explicit fixture directories; no private key or proof generation.
pub(super) fn compact_roundtrip(source: &Path, output: &Path) -> Result<(), Error> {
    let network = if source.join("network-batch/complete.json").exists() {
        "network-batch"
    } else {
        "network-full"
    };
    let original = source.join(if network == "network-batch" {
        "network-batch/good-proof.json"
    } else {
        "job/proof.json"
    });
    let original_bytes = std::fs::read(&original)?;
    let mut proof = shell_stark_prover::compact_canonical::decode_payload(&original_bytes)?;
    let bytes = shell_stark_prover::compact_canonical::encode_payload(
        &proof,
        shell_storage::MAX_CANONICAL_PROOF_BYTES as usize,
        true,
    )?;
    ensure(
        bytes.len() < original_bytes.len(),
        "compact representation did not reduce real graph",
    )?;
    let c: fixture::Context = read(&source.join("context.json"))?;
    let control: Value = read(&source.join("control.json"))?;
    let stores = RocksDbStore::open_all(source.join(network).join("receiver/db"), None)?;
    let store = Arc::new(stores.state);
    let node = fixture::node(store.clone(), c.authority, &c.authority_key)?;
    let tip = node
        .chain_store
        .get_head_hash()?
        .ok_or("compact history tip missing")?;
    let before = digest(store.as_ref())?;
    let decoded = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
    let replay = node.replay_canonical_transactions_with_proof(tip, c.block, &decoded)?;
    ensure(
        replay.proved_sender_signatures == proof.transactions.len()
            && replay.proved_proposer_signature
            && replay.state_root.to_string() == control["state_root"].as_str().unwrap_or_default()
            && serde_json::to_value(&replay.receipts)? == control["receipts"]
            && digest(store.as_ref())? == before,
        "compact real AIR/native history output changed",
    )?;
    // Rebuild a valid outer frame and all content hashes around a bad AIR proof.
    // Framing integrity cannot authorize a changed mathematical certificate.
    proof.transactions[0]
        .signature
        .transaction
        .signature
        .equation
        .key
        .proof_bytes[0] ^= 1;
    let corrupt = shell_stark_prover::compact_canonical::encode_payload(
        &proof,
        shell_storage::MAX_CANONICAL_PROOF_BYTES as usize,
        true,
    )?;
    let corrupted = shell_stark_prover::compact_canonical::decode_payload(&corrupt)?;
    let error = node
        .replay_canonical_transactions_with_proof(tip, c.block, &corrupted)
        .unwrap_err()
        .to_string();
    ensure(
        error.contains("public-key") || error.contains("proof"),
        "unexpected compact corrupt AIR refusal",
    )?;
    ensure(
        digest(store.as_ref())? == before && std::fs::read(&original)? == original_bytes,
        "compact negative/replay changed retained data",
    )?;
    ensure(
        !output.exists(),
        "compact output already exists; retain it for inspection",
    )?;
    std::fs::create_dir_all(output)?;
    use std::io::Write;
    for (name, data) in [
        ("proof.cbor", bytes.as_slice()),
        ("bad-air.cbor", corrupt.as_slice()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    write(
        &output.join("complete.json"),
        &json!({"replay":replay,"original_bytes":original_bytes.len(),"compact_bytes":bytes.len(),"compact_payload_hash":blake3_hash(&bytes),"bad_air_correct_outer_hash":blake3_hash(&corrupt),"bad_air_error":error,"current_head":tip,"all_kv_unchanged":true,"original_bytes_unchanged":true,"new_proofs_generated":0,"scope":"Existing full2 graph compatibility only, not Native16 acceptance"}),
    )
}
