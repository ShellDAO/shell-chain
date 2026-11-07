//! Real retained-proof transfer over dedicated TCP/Noise peers and Node RPC.
#[path = "common/canonical_proof_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;
use async_trait::async_trait;
use fixture::{node, request, Context};
use serde_json::{json, Value};
use shell_crypto::{DilithiumSigner, Signer};
use shell_network::{
    Libp2pNetwork, LocalNodeInfo, NetworkConfig, NetworkError, NetworkEvent, NetworkMessage,
    NetworkService, PeerId,
};
use shell_node::{CanonicalProofReplay, Node};
use shell_primitives::{blake3_hash, Address, Bytes, ShellHash};
use shell_storage::{
    CanonicalProofFetchState as FetchState, CanonicalProofFetchStatus, CanonicalProofManifest,
    CanonicalProofUploadState as UploadState, CanonicalProofUploadStatus, KvStore, RocksDbStore,
    CANONICAL_PROOF_CACHE_PREFIX,
};
use source::{read, write, Error};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn network_config(boot_nodes: Vec<String>) -> NetworkConfig {
    NetworkConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        boot_nodes,
        enable_mdns: false,
        enable_kademlia: false,
        enable_relay: false,
        enable_relay_server: false,
        enable_dcutr: false,
        enable_autonat: false,
        identity_key_path: None,
        ..Default::default()
    }
}
#[derive(Default)]
struct Faults {
    corrupt: AtomicBool,
    control_once: AtomicBool,
    control_seen: AtomicBool,
    control_nonce: AtomicU64,
    control_release: Notify,
    partial_once: AtomicBool,
    partial_seen: AtomicBool,
    partial_release: Notify,
    frames: AtomicU64,
}
struct ProviderNetwork {
    inner: Libp2pNetwork,
    faults: Arc<Faults>,
}
#[async_trait]
impl NetworkService for ProviderNetwork {
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        self.inner.broadcast(msg).await
    }
    async fn send_to_peer(
        &self,
        peer: &PeerId,
        mut msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        if let NetworkMessage::CanonicalProofChunkResponse {
            index,
            nonce,
            data: Some(_),
            ..
        } = &msg
        {
            let (index, nonce) = (*index, *nonce);
            if index == 1 && self.faults.control_once.swap(false, Ordering::SeqCst) {
                let mut wrong = msg.clone();
                if let NetworkMessage::CanonicalProofChunkResponse { nonce, .. } = &mut wrong {
                    *nonce = nonce
                        .checked_add(1)
                        .ok_or_else(|| NetworkError::Transport("test nonce overflow".into()))?;
                }
                self.inner.send_to_peer(peer, wrong).await?;
                self.faults.control_nonce.store(nonce, Ordering::SeqCst);
                self.faults.control_seen.store(true, Ordering::SeqCst);
                tokio::time::timeout(
                    Duration::from_secs(20),
                    self.faults.control_release.notified(),
                )
                .await
                .map_err(|_| NetworkError::Transport("control gate timed out".into()))?;
            }
            if index == 4 && self.faults.partial_once.swap(false, Ordering::SeqCst) {
                self.faults.partial_seen.store(true, Ordering::SeqCst);
                tokio::time::timeout(
                    Duration::from_secs(20),
                    self.faults.partial_release.notified(),
                )
                .await
                .map_err(|_| NetworkError::Transport("partial gate timed out".into()))?;
            }
            if index == 0 && self.faults.corrupt.load(Ordering::SeqCst) {
                if let NetworkMessage::CanonicalProofChunkResponse {
                    data: Some(data), ..
                } = &mut msg
                {
                    let mut bad = data.as_ref().to_vec();
                    bad[0] ^= 1;
                    *data = Bytes::from(bad);
                }
            }
            self.faults.frames.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.send_to_peer(peer, msg).await
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
        dir: &Path,
        context: &Context,
        boot_nodes: Vec<String>,
        faults: Option<Arc<Faults>>,
    ) -> Result<Self, Error> {
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        let mut node = node(
            Arc::new(stores.state),
            context.authority,
            &context.authority_key,
        )?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        drop(socket);
        let token = blake3_hash(DilithiumSigner::generate().public_key()).to_string();
        node.config.rpc_enabled = true;
        node.config.metrics.enabled = false;
        node.config.rpc = shell_rpc::RpcConfig {
            listen_addr: address,
            ws_addr: None,
            api_namespaces: vec!["admin".into()],
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            max_request_body_size: 2 * 1024 * 1024,
            ..Default::default()
        };
        let config = network_config(boot_nodes);
        node.config.network = config.clone();
        let network = Libp2pNetwork::new(&config).await?;
        let info = network.local_node_info_handle();
        let signer = Arc::new(DilithiumSigner::generate());
        ensure(
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
                != context.authority,
            "temporary signer must not duplicate canonical authority",
        )?;
        let node = Arc::new(node);
        let runner = node.clone();
        let task = tokio::spawn(async move {
            if let Some(faults) = faults {
                runner
                    .run(
                        signer,
                        &mut ProviderNetwork {
                            inner: network,
                            faults,
                        },
                    )
                    .await
            } else {
                let mut network = network;
                runner.run(signer, &mut network).await
            }
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if task.is_finished() {
                return Err(format!("Node.run exited during startup: {:?}", task.await?).into());
            }
            if request(address, Some(&token), "admin_nodeInfo", json!([]))
                .await
                .is_ok_and(|(status, result)| status == 200 && result.get("result").is_some())
                && !info.read().unwrap().listen_addresses.is_empty()
            {
                break;
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "Node RPC/listener startup timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(Self {
            node,
            task,
            address,
            token,
            info,
        })
    }
    fn peer(&self) -> String {
        self.info.read().unwrap().peer_id.clone()
    }
    fn dial(&self) -> String {
        let info = self.info.read().unwrap();
        format!("{}/p2p/{}", info.listen_addresses[0], info.peer_id)
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, result) = request(self.address, Some(&self.token), method, params).await?;
        ensure(status == 200, "authenticated RPC HTTP failed")?;
        if let Some(error) = result.get("error") {
            return Err(format!("RPC {method}: {error}").into());
        }
        result
            .get("result")
            .cloned()
            .ok_or_else(|| "RPC result absent".into())
    }
    async fn status(&self, id: ShellHash) -> Result<CanonicalProofUploadStatus, Error> {
        Ok(serde_json::from_value(
            self.call("admin_canonicalProofStatus", json!([id])).await?,
        )?)
    }
    async fn fetch_status(&self, id: ShellHash) -> Result<CanonicalProofFetchStatus, Error> {
        let value = self
            .call("admin_canonicalProofFetchStatus", json!([id]))
            .await?;
        Ok(serde_json::from_value(value)?)
    }
    async fn connected(&self, peer: &str, manifest: &CanonicalProofManifest) -> Result<(), Error> {
        let mut foreign = manifest.clone();
        foreign.chain_id += 1;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match self
                .call("admin_fetchCanonicalProof", json!([peer, foreign]))
                .await
            {
                Err(error) if error.to_string().contains("identity mismatch") => return Ok(()),
                Err(error)
                    if error.to_string().contains("not running")
                        || error.to_string().contains("not connected") => {}
                other => {
                    return Err(format!("unexpected readiness/source refusal: {other:?}").into())
                }
            };
            ensure(
                tokio::time::Instant::now() < deadline,
                "dedicated peer readiness timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn begin(
        &self,
        peer: &str,
        manifest: &CanonicalProofManifest,
    ) -> Result<CanonicalProofFetchStatus, Error> {
        Ok(serde_json::from_value(
            self.call("admin_fetchCanonicalProof", json!([peer, manifest]))
                .await?,
        )?)
    }
    async fn terminal(&self, id: ShellHash) -> Result<CanonicalProofFetchStatus, Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        loop {
            let status = self.fetch_status(id).await?;
            if !matches!(status.state, FetchState::Receiving | FetchState::Verifying) {
                return Ok(status);
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "proof transfer/verification timeout; data retained",
            )?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn stop(self) -> Result<(), Error> {
        self.node.shutdown();
        tokio::time::timeout(Duration::from_secs(30), self.task).await???;
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&self.node) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "Node backend still retained after shutdown")?;
        drop(self.node);
        Ok(())
    }
}
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
fn native_rows(store: &RocksDbStore) -> Result<Rows, Error> {
    Ok(store
        .scan_all()?
        .into_iter()
        .filter(|(key, _)| !key.starts_with(CANONICAL_PROOF_CACHE_PREFIX))
        .collect())
}
fn clone_store(source: &Path, destination: &Path, include_cache: bool) -> Result<(), Error> {
    let original = RocksDbStore::open_all(source.join("native-db"), None)?;
    let before = original.state.scan_all()?;
    let cloned = RocksDbStore::open_all(destination.join("native-db"), None)?;
    for (key, value) in &before {
        if include_cache || !key.starts_with(CANONICAL_PROOF_CACHE_PREFIX) {
            cloned.state.put(key, value)?;
        }
    }
    ensure(
        original.state.scan_all()? == before,
        "source native DB changed",
    )
}
async fn flag(flag: &AtomicBool) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !flag.load(Ordering::SeqCst) {
        ensure(
            tokio::time::Instant::now() < deadline,
            "provider control gate not reached",
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}
async fn transfer(native: &Path, cache: &Path, dir: &Path) -> Result<(), Error> {
    ensure(
        !dir.try_exists()?,
        "output exists; retain it and use explicit admin resume or verify a completed run",
    )?;
    let context: Context = read(&native.join("context.json"))?;
    ensure(
        context == read::<Context>(&cache.join("context.json"))?,
        "native and proof-cache identities differ",
    )?;
    let saved: Value = read(&cache.join("rpc-result.json"))?;
    let manifest: CanonicalProofManifest =
        serde_json::from_value(saved["valid"]["manifest"].clone())?;
    manifest.validate()?;
    let expected: CanonicalProofReplay = read(&native.join("result.json"))?;
    ensure(
        manifest.total_bytes > 4 * 1024 * 1024,
        "fixture must exercise real multi-message proof transfer",
    )?;
    std::fs::create_dir(dir)?;
    std::fs::create_dir(dir.join("provider"))?;
    std::fs::create_dir(dir.join("receiver"))?;
    clone_store(cache, &dir.join("provider"), true)?;
    clone_store(native, &dir.join("receiver"), false)?;
    write(&dir.join("context.json"), &context)?;
    write(&dir.join("manifest.json"), &manifest)?;
    let id = manifest.id();
    let faults = Arc::new(Faults {
        corrupt: AtomicBool::new(true),
        control_once: AtomicBool::new(true),
        partial_once: AtomicBool::new(true),
        ..Default::default()
    });
    let provider = Live::start(
        &dir.join("provider"),
        &context,
        vec![],
        Some(faults.clone()),
    )
    .await?;
    let receiver =
        Live::start(&dir.join("receiver"), &context, vec![provider.dial()], None).await?;
    receiver.connected(&provider.peer(), &manifest).await?;
    ensure(
        receiver
            .node
            .store
            .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
            .is_empty(),
        "refused foreign-chain fetch allocated cache",
    )?;
    let (http, _) = request(
        receiver.address,
        None,
        "admin_fetchCanonicalProof",
        json!([provider.peer(), manifest]),
    )
    .await?;
    ensure(
        http == 401
            && receiver
                .node
                .store
                .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                .is_empty(),
        "unauthenticated fetch allocated cache",
    )?;
    let before = native_rows(&receiver.node.store)?;
    let provider_before = native_rows(&provider.node.store)?;
    receiver.begin(&provider.peer(), &manifest).await?;
    flag(&faults.control_seen).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let waiting = receiver.status(id).await?;
    let pending = receiver.fetch_status(id).await?;
    ensure(
        waiting.next_chunk == 1 && pending.nonce == faults.control_nonce.load(Ordering::SeqCst),
        "wrong nonce advanced upload",
    )?;
    let target = PeerId(receiver.peer());
    let attacker = Libp2pNetwork::new(&network_config(vec![receiver.dial()])).await?;
    let attacker_id = attacker
        .local_node_info_handle()
        .read()
        .unwrap()
        .peer_id
        .clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while attacker.peer_count().await == 0 {
        ensure(
            tokio::time::Instant::now() < deadline,
            "attacker transport did not connect",
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let data: Bytes = serde_json::from_value(
        provider
            .call("admin_getCanonicalProofChunk", json!([id, 1]))
            .await?,
    )?;
    attacker
        .send_to_peer(
            &target,
            NetworkMessage::CanonicalProofChunkResponse {
                version: 1,
                proof_id: id,
                index: 1,
                nonce: pending.nonce,
                data: Some(data),
                error: None,
            },
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    ensure(
        receiver.status(id).await? == waiting && receiver.fetch_status(id).await? == pending,
        "wrong authenticated peer advanced upload",
    )?;
    write(
        &dir.join("security-result.json"),
        &json!({"expected_peer":provider.peer(),"other_noise_peer":attacker_id,"exact_pending_nonce":pending.nonce,"wrong_nonce_and_peer_no_progress":true,"next_chunk":waiting.next_chunk,"bearer_401":true,"foreign_chain_no_allocation":true}),
    )?;
    attacker.shutdown().await?;
    faults.control_release.notify_one();
    flag(&faults.partial_seen).await?;
    let partial = receiver.status(id).await?;
    let partial_fetch = receiver.fetch_status(id).await?;
    ensure(
        partial.next_chunk == 4
            && partial.received_bytes < manifest.total_bytes
            && partial.state == UploadState::Uploading,
        "partial checkpoint not isolated",
    )?;
    ensure(
        native_rows(&receiver.node.store)? == before,
        "partial transfer changed native KV",
    )?;
    write(&dir.join("partial-status.json"), &partial)?;
    let first_receiver_peer = receiver.peer();
    receiver.stop().await?;
    faults.partial_release.notify_one();
    let receiver =
        Live::start(&dir.join("receiver"), &context, vec![provider.dial()], None).await?;
    receiver.connected(&provider.peer(), &manifest).await?;
    ensure(
        receiver.peer() != first_receiver_peer && receiver.status(id).await? == partial,
        "receiver restart did not preserve exact chunk progress",
    )?;
    let saved_cache = receiver
        .node
        .store
        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?;
    ensure(
        receiver.fetch_status(id).await?.state == FetchState::Paused,
        "interrupted transfer was not reported paused",
    )?;
    ensure(
        receiver
            .node
            .store
            .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
            == saved_cache,
        "status query wrote persisted history",
    )?;
    let resumed = receiver.begin(&provider.peer(), &manifest).await?;
    ensure(
        resumed.next_chunk == partial.next_chunk && resumed.nonce > partial_fetch.nonce,
        "resume lost progress or reused nonce",
    )?;
    let failed_fetch = receiver.terminal(id).await?;
    let rejected = receiver.status(id).await?;
    ensure(
        failed_fetch.state == FetchState::Failed
            && rejected.state == UploadState::Rejected
            && rejected
                .error
                .as_deref()
                .is_some_and(|e| e.contains("payload hash mismatch")),
        "malicious received bytes were not rejected before decode",
    )?;
    write(&dir.join("rejected-status.json"), &rejected)?;
    ensure(
        native_rows(&receiver.node.store)? == before,
        "hash refusal changed native KV",
    )?;
    faults.corrupt.store(false, Ordering::SeqCst);
    let retry = receiver.begin(&provider.peer(), &manifest).await?;
    ensure(
        retry.generation == 1 && retry.next_chunk == 0 && retry.nonce > failed_fetch.nonce,
        "retry did not reserve a fresh retained generation",
    )?;
    let complete = receiver.terminal(id).await?;
    let verified = receiver.status(id).await?;
    ensure(
        complete.state == FetchState::Complete
            && verified.state == UploadState::Verified
            && verified.generation == 1
            && verified.verification_attempts == 2
            && verified.result == Some(serde_json::to_value(&expected)?),
        &format!("actual proof-backed Node replay failed: {verified:?}"),
    )?;
    let archive: CanonicalProofUploadStatus = serde_json::from_value(
        receiver
            .call("admin_canonicalProofAttemptStatus", json!([id, 0]))
            .await?,
    )?;
    let archive_fetch: CanonicalProofFetchStatus = serde_json::from_value(
        receiver
            .call("admin_canonicalProofFetchStatus", json!([id, 0]))
            .await?,
    )?;
    ensure(
        archive == rejected && archive_fetch == failed_fetch,
        "failed generation metadata not retained",
    )?;
    let bad: Bytes = serde_json::from_value(
        receiver
            .call("admin_getCanonicalProofAttemptChunk", json!([id, 0, 0]))
            .await?,
    )?;
    let good: Bytes = serde_json::from_value(
        receiver
            .call("admin_getCanonicalProofChunk", json!([id, 0]))
            .await?,
    )?;
    ensure(
        bad.len() == good.len()
            && bad.as_ref()[0] == good.as_ref()[0] ^ 1
            && bad.as_ref()[1..] == good.as_ref()[1..],
        "archived bad bytes or current good bytes changed",
    )?;
    ensure(
        native_rows(&receiver.node.store)? == before
            && native_rows(&provider.node.store)? == provider_before,
        "peer transfer/replay changed native KV",
    )?;
    write(
        &dir.join("result.json"),
        &json!({"version":1,"manifest":manifest,"partial":partial,"resumed":resumed,"rejected":rejected,"failed_fetch":failed_fetch,"verified":verified,"complete_fetch":complete,"failed_archive_readable":true,"native_KV_unchanged":true,"expected_native":expected,"provider_data_frames":faults.frames.load(Ordering::SeqCst),"actual_Node_run_TCP_Noise":true,"sender_native_crypto_fallback":false}),
    )?;
    receiver.stop().await?;
    provider.stop().await?;
    println!(
        "{}",
        json!({"mode":"transfer","payload_bytes":manifest.total_bytes,"native_replay":true,"resume_and_poison_recovery":true,"bad_generation_retained":true,"actual_TCP_Noise":true,"native_KV_unchanged":true})
    );
    Ok(())
}
async fn verify(native: &Path, dir: &Path) -> Result<(), Error> {
    let context: Context = read(&dir.join("context.json"))?;
    ensure(
        context == read::<Context>(&native.join("context.json"))?,
        "native source identity changed",
    )?;
    let manifest: CanonicalProofManifest = read(&dir.join("manifest.json"))?;
    let saved: Value = read(&dir.join("result.json"))?;
    let expected: CanonicalProofReplay = read(&native.join("result.json"))?;
    let id = manifest.id();
    let receiver = Live::start(&dir.join("receiver"), &context, vec![], None).await?;
    let before = native_rows(&receiver.node.store)?;
    let cached = receiver.status(id).await?;
    ensure(
        cached.manifest == manifest && cached.result == saved["verified"].get("result").cloned(),
        "retained successful proof result changed",
    )?;
    let started: CanonicalProofUploadStatus = serde_json::from_value(
        receiver
            .call("admin_verifyCanonicalProof", json!([id, true]))
            .await?,
    )?;
    ensure(
        started.state == UploadState::Verifying
            && started.verification_attempts > cached.verification_attempts,
        "cold proof verification did not start",
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(900);
    let checked = loop {
        let status = receiver.status(id).await?;
        if status.state != UploadState::Verifying {
            break status;
        }
        ensure(
            tokio::time::Instant::now() < deadline,
            "cold verifier timed out; data retained",
        )?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    ensure(
        checked.state == UploadState::Verified
            && checked.generation == 1
            && checked.result == Some(serde_json::to_value(expected)?),
        "cold received-graph math/native replay failed",
    )?;
    let archive: CanonicalProofUploadStatus = serde_json::from_value(
        receiver
            .call("admin_canonicalProofAttemptStatus", json!([id, 0]))
            .await?,
    )?;
    ensure(
        archive.state == UploadState::Rejected
            && archive
                .error
                .as_deref()
                .is_some_and(|e| e.contains("payload hash mismatch")),
        "failed received data disappeared after restart",
    )?;
    ensure(
        native_rows(&receiver.node.store)? == before,
        "cold query changed native KV",
    )?;
    let first = dir.join("recheck-result.json");
    if first.try_exists()? {
        let prior: CanonicalProofUploadStatus = read(&first)?;
        ensure(
            prior.proof_id == checked.proof_id
                && prior.manifest == checked.manifest
                && prior.result == checked.result
                && prior.verification_attempts < checked.verification_attempts,
            "first recheck receipt differs",
        )?;
        write(
            &dir.join(format!("recheck-{}.json", checked.verification_attempts)),
            &checked,
        )?;
    } else {
        write(&first, &checked)?;
    }
    receiver.stop().await?;
    println!(
        "{}",
        json!({"mode":"verify","actual_received_graph_Node_rechecked":true,"verification_attempts":checked.verification_attempts,"both_generations_retained":true,"native_KV_unchanged":true})
    );
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(
        args.len() == 4,
        "usage: mldsa-p2p-proof transfer|verify native-node-fixture rpc-proof-fixture output",
    )?;
    let native = Path::new(&args[1]).canonicalize()?;
    let cache = Path::new(&args[2]).canonicalize()?;
    let output = std::path::absolute(&args[3])?;
    let parent = output
        .parent()
        .ok_or("missing output parent")?
        .canonicalize()?;
    let output = if output.try_exists()? {
        output.canonicalize()?
    } else {
        parent.join(output.file_name().ok_or("output filename absent")?)
    };
    for input in [&native, &cache] {
        ensure(
            !output.starts_with(input) && !input.starts_with(&output),
            "output overlaps immutable native/proof input",
        )?;
    }
    match args[0].as_str() {
        "transfer" => transfer(&native, &cache, &output).await,
        "verify" => verify(&native, &output).await,
        _ => Err("unknown P2P proof operation".into()),
    }
}
