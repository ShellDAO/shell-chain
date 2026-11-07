//! Fresh real Node.run producer regression; no cached graph or persisted signing keys.
use super::*;
use shell_network::{Libp2pNetwork, NetworkConfig};
use shell_primitives::Bytes;
use shell_storage::{
    CanonicalProofManifest, CanonicalProofUploadState, CanonicalProofUploadStatus,
    CANONICAL_PROOF_CACHE_PREFIX, CANONICAL_PROOF_CHUNK_BYTES,
};
use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};
const PREFIX: &[u8] = b"local/canonical-production/v1/";
fn native_digest(db: &impl KvStore) -> Result<ShellHash, Error> {
    let rows: Vec<_> = db
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| !k.starts_with(PREFIX) && !k.starts_with(CANONICAL_PROOF_CACHE_PREFIX))
        .collect();
    Ok(blake3_hash(&serde_json::to_vec(&rows)?))
}
pub(super) fn snapshot(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("native/db"), None)?;
    let rows: Vec<_> = stores
        .state
        .scan_prefix(PREFIX)?
        .iter()
        .map(|(k, v)| json!({"key":hex::encode(k),"hash":blake3_hash(v),"bytes":v.len()}))
        .collect();
    println!(
        "{}",
        json!({"native_digest":native_digest(&stores.state)?,"rows":rows})
    );
    Ok(())
}
struct Live {
    node: Arc<shell_node::Node<RocksDbStore>>,
    task: tokio::task::JoinHandle<Result<(), shell_node::NodeError>>,
    address: SocketAddr,
    token: String,
}
impl Live {
    async fn start(out: &Path, c: &fixture::Context, budget: usize) -> Result<Self, Error> {
        let stores = RocksDbStore::open_all(out.join("native/db"), None)?;
        let mut cfg = NodeConfig::dev(c.authority);
        cfg.node_role = shell_node::NodeRole::Prover;
        cfg.proposer_address = None;
        cfg.chain_id = 10;
        cfg.mempool.chain_id = 10;
        cfg.enable_stark_aggregation = false;
        cfg.canonical_proof_production = true;
        cfg.canonical_proof_component_budget = NonZeroUsize::new(budget);
        cfg.metrics.enabled = false;
        let mut consensus = shell_consensus::WPoaConfig::from_poa(
            shell_consensus::PoaConfig::new(vec![c.authority], 1).with_max_future_secs(86400),
        );
        consensus.chain_id = 10;
        cfg.consensus = ConsensusEngineConfig::WPoa(consensus);
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        drop(socket);
        let token = blake3_hash(DilithiumSigner::generate().public_key()).to_string();
        cfg.rpc_enabled = true;
        cfg.rpc = shell_rpc::RpcConfig {
            listen_addr: address,
            ws_addr: None,
            api_namespaces: vec!["admin".into()],
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            ..Default::default()
        };
        let network_cfg = NetworkConfig {
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
        cfg.network = network_cfg.clone();
        let (node, _) = NodeBuilder::new(cfg, Arc::new(stores.state)).build()?;
        let node = Arc::new(node);
        let runner = node.clone();
        let mut network = Libp2pNetwork::new(&network_cfg).await?;
        let signer = Arc::new(DilithiumSigner::generate());
        ensure(
            Address::from_public_key(signer.public_key(), signer.sig_type().as_u8()) != c.authority,
            "duplicate signer",
        )?;
        let task = tokio::spawn(async move { runner.run(signer, &mut network).await });
        let live = Self {
            node,
            task,
            address,
            token,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            ensure(!live.task.is_finished(), "Node.run exited at startup")?;
            if live.call("admin_nodeInfo", json!([])).await.is_ok() {
                break;
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "RPC startup timeout",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let (status, _) = fixture::request(
            address,
            None,
            "admin_canonicalProofProduction",
            json!([c.block]),
        )
        .await?;
        ensure(
            status == 401,
            "unauthenticated producer control was accepted",
        )?;
        Ok(live)
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, value) =
            fixture::request(self.address, Some(&self.token), method, params).await?;
        ensure(status == 200, "HTTP failed")?;
        if let Some(e) = value.get("error") {
            return Err(format!("{method}: {e}").into());
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| "RPC result missing".into())
    }
    async fn status(&self, hash: ShellHash) -> Result<Value, Error> {
        self.call("admin_canonicalProofProduction", json!([hash]))
            .await
    }
    async fn stop(self) -> Result<(), Error> {
        self.node.shutdown();
        tokio::time::timeout(Duration::from_secs(120), self.task).await???;
        Ok(())
    }
}
pub(super) async fn run(out: &Path, pause: bool) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let live = Live::start(out, &c, if pause { 3 } else { 58 }).await?;
    // Always join Node.run on test errors as well, so retained RocksDB/job bytes are durable.
    let result = exercise(out, &c, &live, pause).await;
    let stopped = live.stop().await;
    result?;
    stopped
}
async fn exercise(out: &Path, c: &fixture::Context, live: &Live, pause: bool) -> Result<(), Error> {
    let advance: Value = read(&out.join("advance-control.json"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(7200);
    let mut advanced = !pause;
    let complete = loop {
        ensure(
            !live.task.is_finished(),
            "Node.run exited during generation",
        )?;
        let value = live.status(c.block).await?;
        let state = value["status"]["state"].as_str();
        if !advanced && matches!(state, Some("proving" | "paused")) {
            let blocks: Vec<Block> = read(&out.join("advance-blocks.json"))?;
            for block in blocks {
                live.node.import_block(block, &MultiVerifier)?;
            }
            ensure(
                live.node
                    .chain_store
                    .get_head_block()?
                    .ok_or("head absent")?
                    .number()
                    == 130,
                "runtime did not advance beyond historical undo retention",
            )?;
            write(
                &out.join("advanced.json"),
                &json!({"head":live.node.chain_store.get_head_hash()?,"height":130,"root":live.node.world_state.write().state_root()?,"native_digest":native_digest(live.node.store.as_ref())?}),
            )?;
            advanced = true;
        }
        if state == Some("failed") {
            return Err(format!("background producer failed: {value}").into());
        }
        if state == Some(if pause { "paused" } else { "complete" }) {
            break value;
        }
        ensure(
            tokio::time::Instant::now() < deadline,
            "background proof production timed out",
        )?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    ensure(
        complete["block"] == serde_json::to_value(read::<Block>(&out.join("candidate.json"))?)?,
        "captured source block changed",
    )?;
    ensure(
        complete["nativeExecutionVerified"] == false,
        "status claims native execution",
    )?;
    let original: Block = read(&out.join("candidate.json"))?;
    let mut current_view = original.clone();
    current_view.header.state_root = live.node.world_state.write().state_root()?;
    ensure(
        json!(live
            .node
            .chain_store
            .get_head_hash()?
            .ok_or("head missing")?)
            == advance["head"]
            && json!(current_view.header.state_root) == advance["root"]
            && accounts(live.node.store.clone(), &current_view)? == advance["accounts"],
        "runtime advancement differs from independent native execution",
    )?;
    if pause {
        ensure(
            complete["status"]["components"] == 3 && complete["status"]["newlyProved"] == 3,
            "component budget not enforced",
        )?;
        write(&out.join("runtime-paused.json"), &complete)?;
    } else {
        ensure(
            complete["status"]["components"] == 61
                && complete["status"]["newlyProved"] == 58
                && complete["status"]["reused"] == 3,
            "cold resume failed to reuse exactly three certificates",
        )?;
        let manifest: CanonicalProofManifest =
            serde_json::from_value(complete["status"]["manifest"].clone())?;
        let cache: CanonicalProofUploadStatus = serde_json::from_value(
            live.call("admin_canonicalProofStatus", json!([manifest.id()]))
                .await?,
        )?;
        ensure(
            cache.state == CanonicalProofUploadState::Ready && cache.result.is_none(),
            "producer bytes incorrectly treated as executed block",
        )?;
        let mut payload = Vec::new();
        for index in 0..cache.next_chunk {
            let chunk: Bytes = serde_json::from_value(
                live.call(
                    "admin_getCanonicalProofChunk",
                    json!([manifest.id(), index]),
                )
                .await?,
            )?;
            ensure(chunk.len() <= CANONICAL_PROOF_CHUNK_BYTES, "oversize chunk")?;
            payload.extend_from_slice(chunk.as_ref());
        }
        ensure(
            payload.len() as u64 == manifest.total_bytes
                && blake3_hash(&payload) == manifest.payload_hash,
            "RPC payload hash/size mismatch",
        )?;
        let advanced: Value = read(&out.join("advanced.json"))?;
        ensure(
            json!(native_digest(live.node.store.as_ref())?) == advanced["native_digest"],
            "background proof generation changed native canonical data",
        )?;
        let job = out.join("job");
        std::fs::create_dir(&job)?;
        // write() is create_new + fsync; never replace an existing delivery file.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(job.join("proof.json"))?;
            file.write_all(&payload)?;
            file.sync_all()?;
        }
        write(&job.join("manifest.json"), &manifest)?;
        write(&job.join("block.json"), &original)?;
        write(&out.join("runtime-complete.json"), &complete)?;
    }
    Ok(())
}

/// Corrupt only independent checkpoint copies, preserving all native and valid cache bytes.
pub(super) async fn negative(out: &Path, mode: &str) -> Result<(), Error> {
    let c: fixture::Context = read(&out.join("context.json"))?;
    let copy = out.join(mode);
    ensure(
        !copy.exists(),
        "negative runtime copy exists; refusing replacement",
    )?;
    std::fs::create_dir(&copy)?;
    std::fs::create_dir(copy.join("native"))?;
    let original = RocksDbStore::open_all(out.join("native/db"), None)?;
    let genuine_before = digest(&original.state)?;
    original.create_checkpoint(copy.join("native/db"))?;
    let stores = RocksDbStore::open_all(copy.join("native/db"), None)?;
    let record_key = [PREFIX, b"record/", c.block.as_bytes()].concat();
    let source_key = [PREFIX, b"source/", c.block.as_bytes()].concat();
    let job_prefix = [PREFIX, b"certificates/", c.block.as_bytes(), b"/"].concat();
    let index_key = [job_prefix.as_slice(), b"production/index"].concat();
    let mut rows: std::collections::BTreeMap<_, _> =
        stores.state.scan_prefix(PREFIX)?.into_iter().collect();
    let mut status: Value = serde_json::from_slice(rows.get(&record_key).ok_or("record absent")?)?;
    status["state"] = json!("paused");
    status["manifest"] = Value::Null;
    status["error"] = Value::Null;
    // Isolate dispatch to the corrupt job; retain all other source/certificate bytes.
    rows.insert(
        [PREFIX, b"jobs"].concat(),
        serde_json::to_vec(&vec![c.block])?,
    );
    match mode {
        "runtime-bad-certificate" => {
            let key = [job_prefix.as_slice(), b"production/component/sender-0-key"].concat();
            let mut proof: Value =
                serde_json::from_slice(rows.get(&key).ok_or("key certificate absent")?)?;
            let first = proof["proof_bytes"][0]
                .as_u64()
                .ok_or("certificate byte absent")?;
            proof["proof_bytes"][0] = json!(first ^ 1);
            let bytes = serde_json::to_vec(&proof)?;
            let mut index: Value =
                serde_json::from_slice(rows.get(&index_key).ok_or("index absent")?)?;
            index["components"]["sender-0-key"]["hash"] = json!(blake3_hash(&bytes));
            index["components"]["sender-0-key"]["bytes"] = json!(bytes.len());
            rows.insert(key, bytes);
            rows.insert(index_key, serde_json::to_vec(&index)?);
        }
        "runtime-bad-source" => {
            let bytes = rows.get_mut(&source_key).ok_or("source absent")?;
            bytes.push(b' ');
            status["sourceHash"] = json!(blake3_hash(bytes));
        }
        _ => return Err("unknown runtime negative mode".into()),
    }
    rows.insert(record_key.clone(), serde_json::to_vec(&status)?);
    let counter = [PREFIX, b"bytes"].concat();
    let total: u64 = rows
        .iter()
        .filter(|(k, _)| **k != counter)
        .map(|(k, v)| (k.len() + v.len()) as u64)
        .sum();
    rows.insert(counter, total.to_be_bytes().to_vec());
    let mut batch = shell_storage::WriteBatch::new();
    for (k, v) in rows {
        batch.put(k, v);
    }
    stores.state.write_batch(batch)?;
    stores.state.flush()?;
    let before = native_digest(&stores.state)?;
    let certificates = stores.state.scan_prefix(&job_prefix)?;
    drop(stores);
    let live = Live::start(&copy, &c, 1).await?;
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let failed = loop {
            ensure(!live.task.is_finished(), "negative Node.run exited")?;
            let status: Value = serde_json::from_slice(
                &live.node.store.get(&record_key)?.ok_or("record absent")?
            )?;
            if status["state"] == "failed" { break status; }
            ensure(tokio::time::Instant::now() < deadline, "corrupt job was not refused")?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        ensure(failed["manifest"].is_null() && failed["newlyProved"] == 0 && failed["reused"] == 0,
            "failed job exposed completion or stale attempt counts")?;
        ensure(native_digest(live.node.store.as_ref())? == before, "corrupt producer wrote canonical state")?;
        ensure(live.node.store.scan_prefix(&job_prefix)? == certificates, "corrupt producer replaced or generated a certificate")?;
        write(&copy.join("refused.json"), &json!({"status":failed,"native_unchanged":true,"certificates_unchanged":true,"correct_outer_hashes_and_quota":true}))?;
        Ok::<_, Error>(())
    }.await;
    let stopped = live.stop().await;
    result?;
    stopped?;
    ensure(
        digest(&original.state)? == genuine_before,
        "negative checkpoint changed genuine source",
    )?;
    Ok(())
}

pub(super) fn verify_native(out: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(out.join("native/db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state.clone()));
    let head = chain.get_head_block()?.ok_or("advanced head absent")?;
    let control: Value = read(&out.join("advance-control.json"))?;
    let advanced: Value = read(&out.join("advanced.json"))?;
    let mut view: Block = read(&out.join("candidate.json"))?;
    view.header.state_root = head.header.state_root;
    let unavailable = chain
        .canonical_parent_view(head.hash(), view.header.parent_hash)
        .err()
        .ok_or("test did not exceed native historical-view retention")?;
    ensure(
        unavailable.to_string().contains("retention bound mismatch"),
        "historical-view refusal was unrelated to retention",
    )?;
    ensure(
        json!(head.hash()) == control["head"]
            && json!(head.number()) == control["height"]
            && json!(head.header.state_root) == control["root"]
            && accounts(Arc::new(stores.state.clone()), &view)? == control["accounts"]
            && json!(native_digest(&stores.state)?) == advanced["native_digest"],
        "cold advanced native state/control/digest mismatch",
    )
}

/// Prove that the ordinary import hook retained a second job before history expiry.
pub(super) async fn next_job(out: &Path) -> Result<(), Error> {
    verify_native(out)?;
    let c: fixture::Context = read(&out.join("context.json"))?;
    let blocks: Vec<Block> = read(&out.join("advance-blocks.json"))?;
    let target = blocks.first().ok_or("second native block absent")?;
    let live = Live::start(out, &c, 1).await?;
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let status = loop {
            let value = live.status(target.hash()).await?;
            if value["status"]["state"] == "paused" {
                break value;
            }
            ensure(
                value["status"]["state"] != "failed",
                "second imported job failed",
            )?;
            ensure(
                tokio::time::Instant::now() < deadline,
                "second job dispatch timed out",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        ensure(
            status["status"]["components"] == 1
                && status["status"]["newlyProved"] == 1
                && status["status"]["reused"] == 0
                && status["block"] == serde_json::to_value(target)?,
            "second import job did not dispatch independently",
        )?;
        write(&out.join("runtime-next-job-paused.json"), &status)?;
        Ok::<_, Error>(())
    }
    .await;
    let stopped = live.stop().await;
    result?;
    stopped?;
    verify_native(out)
}
