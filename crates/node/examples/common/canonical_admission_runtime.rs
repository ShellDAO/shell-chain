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
}
struct Provider {
    inner: Libp2pNetwork,
    faults: Arc<Faults>,
}
#[async_trait]
impl NetworkService for Provider {
    async fn broadcast(&self, m: NetworkMessage) -> Result<(), NetworkError> {
        self.inner.broadcast(m).await
    }
    async fn send_to_peer(&self, p: &PeerId, mut m: NetworkMessage) -> Result<(), NetworkError> {
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
        self.inner.next_event().await
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
        Some(faults.clone()),
    )
    .await?;
    let receiver = Live::start(
        &network.join("receiver/db"),
        &c,
        vec![provider.dial()],
        true,
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
    let c: fixture::Context = read(&out.join("context.json"))?;
    let block: Block = read(&out.join("candidate.json"))?;
    let proof = read(&out.join("job/proof.json"))?;
    let control: Value = read(&out.join("control.json"))?;
    let stores = RocksDbStore::open_all(out.join("network/receiver/db"), None)?;
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
    let mut receipt = out.join("network/verified.json");
    let mut i = 2;
    while receipt.exists() {
        receipt = out.join(format!("network/verified-{i}.json"));
        i += 1;
    }
    write(&receipt, &result)
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
