//! Actual authenticated, durable full-quorum proof availability checks.
use super::*;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shell_crypto::Verifier;
use shell_network::{Libp2pNetwork, LocalNodeInfo, NetworkConfig, NetworkService};
use shell_primitives::ShellHash;
use shell_storage::{
    CanonicalProofManifest, CanonicalProofUploadState, CanonicalProofUploadStatus,
    CANONICAL_PROOF_CACHE_PREFIX,
};
use std::{net::SocketAddr, time::Duration};
#[path = "quorum_fault.rs"]
mod batch_fault;

async fn request(
    address: SocketAddr,
    token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<(u16, Value), Error> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let stream = tokio::net::TcpStream::connect(address).await?;
        let (mut client, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        let connection = tokio::spawn(connection);
        let payload =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
        let mut req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{address}/"))
            .header("Host", address.to_string())
            .header("Content-Type", "application/json");
        if let Some(token) = token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let response = client
            .send_request(req.body(http_body_util::Full::new(hyper::body::Bytes::from(payload)))?)
            .await?;
        let status = response.status().as_u16();
        let body = response.into_body().collect().await?.to_bytes();
        drop(client);
        connection.await??;
        Ok::<_, Error>((
            status,
            if status == 200 {
                serde_json::from_slice(&body)?
            } else {
                Value::Null
            },
        ))
    })
    .await?
}
struct Live<S: KvStore + 'static = RocksDbStore> {
    node: Arc<Node<S>>,
    task: tokio::task::JoinHandle<Result<(), shell_node::NodeError>>,
    address: SocketAddr,
    token: String,
    info: Arc<std::sync::RwLock<LocalNodeInfo>>,
}
impl Live {
    async fn start(path: &Path, c: &Control, boot_nodes: Vec<String>) -> Result<Self, Error> {
        let live = Self::start_mode(path, c, boot_nodes, false, false).await?;
        if live.node.chain_store.get_head_hash()? != Some(c.blocks[2].hash())
            || live.node.chain_store.get_finalized_number()? != Some(3)
        {
            live.stop().await?;
            return Err("canonical state3 required".into());
        }
        Ok(live)
    }
    async fn start_mode(
        path: &Path,
        c: &Control,
        boot_nodes: Vec<String>,
        quorum: bool,
        initialize: bool,
    ) -> Result<Self, Error> {
        Self::start_production(path, c, boot_nodes, quorum, initialize, false).await
    }
    async fn start_production(
        path: &Path,
        c: &Control,
        boot_nodes: Vec<String>,
        quorum: bool,
        initialize: bool,
        production: bool,
    ) -> Result<Self, Error> {
        Self::start_on_node(
            node(path, c, initialize)?,
            c,
            boot_nodes,
            quorum,
            production,
        )
        .await
    }
}
impl<S: KvStore + 'static> Live<S> {
    async fn start_on_node(
        mut node: Node<S>,
        c: &Control,
        boot_nodes: Vec<String>,
        quorum: bool,
        production: bool,
    ) -> Result<Self, Error> {
        node.config.canonical_quorum_admission = quorum;
        node.config.canonical_quorum_production = production;
        if production {
            node.config.canonical_proof_component_budget = node
                .config
                .canonical_proof_component_budget
                .or(std::num::NonZeroUsize::new(1));
        }
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = socket.local_addr()?;
        drop(socket);
        let signer = Arc::new(DilithiumSigner::generate());
        ensure(
            !authority_weights(c).0.contains(&Address::from_public_key(
                signer.public_key(),
                signer.sig_type().as_u8(),
            )),
            "runtime signer cannot be authority",
        )?;
        let token = blake3_hash(signer.public_key()).to_string();
        node.config.node_role = shell_node::NodeRole::Prover;
        node.config.proposer_address = None;
        node.config.metrics.enabled = false;
        node.config.rpc_enabled = true;
        node.config.rpc = shell_rpc::RpcConfig {
            listen_addr: address,
            ws_addr: None,
            api_namespaces: vec!["admin".into()],
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            max_request_body_size: 2 * 1024 * 1024,
            ..Default::default()
        };
        let config = NetworkConfig {
            listen_addr: "127.0.0.1:0".parse()?,
            boot_nodes,
            enable_mdns: false,
            enable_kademlia: false,
            enable_relay: false,
            enable_relay_server: false,
            enable_dcutr: false,
            enable_autonat: false,
            identity_key_path: None,
            ..Default::default()
        };
        node.config.network = config.clone();
        let mut network = Libp2pNetwork::new(&config).await?;
        let info = network.local_node_info_handle();
        let node = Arc::new(node);
        let runner = node.clone();
        let task = tokio::spawn(async move { runner.run(signer, &mut network).await });
        let live = Self {
            node,
            task,
            address,
            token,
            info,
        };
        let startup = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if live.task.is_finished() {
                    return Err::<(), Error>("Node.run exited during RPC startup".into());
                }
                if request(address, Some(&live.token), "admin_nodeInfo", json!([]))
                    .await
                    .is_ok_and(|(s, v)| s == 200 && v.get("result").is_some())
                    && !live.info.read().unwrap().listen_addresses.is_empty()
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await;
        match startup {
            Ok(Ok(())) => Ok(live),
            other => {
                live.stop().await?;
                Err(format!("RPC startup failed: {other:?}").into())
            }
        }
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, value) = request(self.address, Some(&self.token), method, params).await?;
        ensure(status == 200, "authenticated RPC HTTP failure")?;
        if let Some(error) = value.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| "RPC result missing".into())
    }
    async fn status(&self, id: ShellHash) -> Result<CanonicalProofUploadStatus, Error> {
        Ok(serde_json::from_value(
            self.call("admin_canonicalProofStatus", json!([id])).await?,
        )?)
    }
    async fn verify(&self, id: ShellHash) -> Result<CanonicalProofUploadStatus, Error> {
        self.call("admin_verifyCanonicalProof", json!([id, true]))
            .await?;
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                let s = self.status(id).await?;
                if matches!(
                    s.state,
                    CanonicalProofUploadState::Verified | CanonicalProofUploadState::Rejected
                ) {
                    return Ok::<_, Error>(s);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?
    }
    fn peer(&self) -> String {
        self.info.read().unwrap().peer_id.clone()
    }
    fn dial(&self) -> String {
        let info = self.info.read().unwrap();
        format!("{}/p2p/{}", info.listen_addresses[0], info.peer_id)
    }
    async fn connected(&self, peer: &str, manifest: &CanonicalProofManifest) -> Result<(), Error> {
        let mut foreign = manifest.clone();
        foreign.chain_id += 1;
        for attempt in 0..3 {
            match self
                .call("admin_fetchCanonicalProof", json!([peer, foreign]))
                .await
            {
                Err(e) if e.to_string().contains("identity mismatch") => return Ok(()),
                Err(e)
                    if attempt < 2
                        && (e.to_string().contains("not connected")
                            || e.to_string().contains("not running")) =>
                {
                    tokio::time::sleep(Duration::from_secs(1)).await
                }
                other => {
                    return Err(format!(
                        "unexpected proof-peer readiness/source response: {other:?}"
                    )
                    .into())
                }
            }
        }
        Err("proof-peer readiness unavailable".into())
    }
    async fn upload(
        &self,
        m: &CanonicalProofManifest,
        payload: &[u8],
        pause: bool,
    ) -> Result<CanonicalProofUploadStatus, Error> {
        let mut s: CanonicalProofUploadStatus =
            serde_json::from_value(self.call("admin_beginCanonicalProof", json!([m])).await?)?;
        println!(
            "{}",
            json!({"manifestVersion":m.version,"proofId":s.proof_id,"state":s.state,"resumedChunk":s.next_chunk,"receivedBytes":s.received_bytes})
        );
        if !pause {
            ensure(s.next_chunk==3&&s.state==CanonicalProofUploadState::Uploading,"completion requires retained three-chunk pause; use rpc-recheck for a completed run")?;
        }
        for (index, chunk) in payload
            .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
            .enumerate()
            .skip(s.next_chunk as usize)
        {
            if pause && index >= 3 {
                break;
            }
            s = serde_json::from_value(
                self.call(
                    "admin_appendCanonicalProof",
                    json!([s.proof_id, index, format!("0x{}", hex::encode(chunk))]),
                )
                .await?,
            )?;
        }
        Ok(s)
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
        .map_err(|_| "RPC node backend retained after shutdown")?;
        self.node.store.flush()?;
        Ok(())
    }
}
fn native_rows(n: &Node<RocksDbStore>) -> Result<Rows, Error> {
    Ok(n.store
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| !k.starts_with(CANONICAL_PROOF_CACHE_PREFIX))
        .collect())
}
fn frame(proof_file: &Path) -> Result<Vec<u8>, Error> {
    let proof: CommitQuorumProof = read(proof_file)?;
    Ok(shell_stark_prover::commit_quorum::payload::encode(
        &proof,
        shell_core::MAX_CANONICAL_PROOF_BYTES as usize,
    )?)
}
fn manifest(c: &Control, payload: &[u8]) -> CanonicalProofManifest {
    CanonicalProofManifest {
        version: shell_core::COMMIT_QUORUM_ARTIFACT_VERSION,
        chain_id: 1337,
        genesis_hash: c.genesis.hash(),
        block_hash: c.blocks[0].hash(),
        total_bytes: payload.len() as u64,
        payload_hash: blake3_hash(payload),
    }
}
fn expected_result(live: &Live, c: &Control, s: &CanonicalProofUploadStatus) -> Result<(), Error> {
    ensure(
        s.state == CanonicalProofUploadState::Verified,
        "full quorum historical RPC rejected",
    )?;
    let result = s.result.as_ref().ok_or("verified result absent")?;
    let execution = &result["execution"];
    let signatures = if c.co_authority.is_some() { 2 } else { 1 };
    ensure(
        result["proved_commit_signatures"] == signatures
            && execution["tip"]
                == serde_json::to_value(c.blocks.last().ok_or("control tip absent")?.hash())?
            && execution["block"] == serde_json::to_value(c.blocks[0].hash())?
            && execution["parent"] == serde_json::to_value(c.genesis.hash())?
            && execution["state_root"] == serde_json::to_value(c.blocks[0].header.state_root)?
            && execution["receipts"]
                == serde_json::to_value(
                    live.node
                        .chain_store
                        .get_receipts(&c.blocks[0].hash())?
                        .ok_or("Native receipts missing")?,
                )?
            && execution["proved_sender_signatures"] == 0,
        "RPC proof count/root/receipt/canonical context mismatch",
    )?;
    Ok(())
}
async fn metadata_refusals(
    live: &Live,
    m: &CanonicalProofManifest,
    c: &Control,
) -> Result<(), Error> {
    let before = live.node.store.scan_all()?;
    for case in 0..6 {
        let mut wrong = m.clone();
        match case {
            0 => wrong.version = 3,
            1 => wrong.chain_id += 1,
            2 => wrong.genesis_hash = ShellHash::ZERO,
            3 => wrong.block_hash = ShellHash::ZERO,
            4 => wrong.total_bytes = shell_core::MAX_CANONICAL_PROOF_BYTES + 1,
            _ => wrong.block_hash = c.genesis.hash(),
        }
        ensure(
            live.call("admin_beginCanonicalProof", json!([wrong]))
                .await
                .is_err()
                && live.node.store.scan_all()? == before,
            "invalid/inactive source allocated bytes or changed rows",
        )?;
    }
    Ok(())
}
async fn rejected_payload(
    live: &Live,
    m: &CanonicalProofManifest,
    payload: &[u8],
) -> Result<(), Error> {
    let mut s: CanonicalProofUploadStatus =
        serde_json::from_value(live.call("admin_beginCanonicalProof", json!([m])).await?)?;
    for (index, chunk) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
        .skip(s.next_chunk as usize)
    {
        s = serde_json::from_value(
            live.call(
                "admin_appendCanonicalProof",
                json!([s.proof_id, index, format!("0x{}", hex::encode(chunk))]),
            )
            .await?,
        )?;
    }
    let s = live.verify(s.proof_id).await?;
    ensure(
        s.state == CanonicalProofUploadState::Rejected && s.result.is_none(),
        "invalid full proof or relabeled sender payload accepted",
    )?;
    println!(
        "{}",
        json!({"rejectedPayload":s.proof_id,"manifestVersion":m.version,"error":s.error})
    );
    Ok(())
}
async fn peer(
    live: &Live,
    c: &Control,
    m: &CanonicalProofManifest,
    path: &Path,
    recheck: bool,
) -> Result<Value, Error> {
    let receiver = Live::start(path, c, vec![live.dial()]).await?;
    let before = native_rows(&receiver.node)?;
    let outcome=async {
        receiver.connected(&live.peer(),m).await?;
        if !recheck {
            ensure(receiver.call("admin_canonicalProofStatus",json!([m.id()])).await.is_err(),"fresh peer target already has proof cache")?;
        }
        receiver.call("admin_fetchCanonicalProof",json!([live.peer(),m])).await?;
        let fetched=tokio::time::timeout(Duration::from_secs(240),async {
            loop {
                let status:shell_storage::CanonicalProofFetchStatus=serde_json::from_value(receiver.call("admin_canonicalProofFetchStatus",json!([m.id()])).await?)?;
                if !matches!(status.state,shell_storage::CanonicalProofFetchState::Receiving|shell_storage::CanonicalProofFetchState::Verifying){return Ok::<_,Error>(status);}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        ensure(fetched.state==shell_storage::CanonicalProofFetchState::Complete&&fetched.received_bytes==m.total_bytes,"explicit peer fetch incomplete")?;
        let s=if recheck {receiver.verify(m.id()).await?}else{receiver.status(m.id()).await?};expected_result(&receiver,c,&s)?;
        ensure(native_rows(&receiver.node)?==before,"peer proof verification wrote Native state")?;
        Ok::<_,Error>(json!({"explicitTCPNoiseFetch":true,"manifestVersion":m.version,"receivedBytes":fetched.received_bytes,"nextChunk":fetched.next_chunk,"nonce":fetched.nonce,"verificationAttempts":s.verification_attempts,"coldRecheck":recheck,"NativeRowsUnchanged":true}))
    }.await;
    let unchanged = native_rows(&receiver.node)? == before;
    receiver.stop().await?;
    ensure(unchanged, "failed peer path wrote Native state")?;
    outcome
}
async fn exercise(
    controls: &Path,
    proof_file: &Path,
    root: &Path,
    mode: &str,
) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    ensure(
        c.co_authority.is_some() && c.blocks.len() == 3,
        "two-authority controls required",
    )?;
    let payload = frame(proof_file)?;
    let output = root.join("quorum-payload.bin");
    if output.exists() {
        ensure(
            std::fs::read(&output)? == payload,
            "retained payload changed",
        )?;
    } else {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)?;
        std::io::Write::write_all(&mut f, &payload)?;
        f.sync_all()?;
    }
    let m = manifest(&c, &payload);
    let live = Live::start(&root.join("db"), &c, vec![]).await?;
    let before = native_rows(&live.node)?;
    let outcome=async {
        let(status,_)=request(live.address,None,"admin_beginCanonicalProof",json!([m])).await?;ensure(status==401,"admin authorization missing")?;
        metadata_refusals(&live,&m,&c).await?;
        if mode=="rpc-pause" {
            let s=live.upload(&m,&payload,true).await?;ensure(s.next_chunk==3&&s.state==CanonicalProofUploadState::Uploading,"durable three-chunk pause missing")?;
            println!("{}",json!({"partialUpload":true,"nextChunk":s.next_chunk,"receivedBytes":s.received_bytes,"manifestVersion":m.version}));
        }else {
            let attempts=if mode=="rpc-recheck" {let old=live.status(m.id()).await?;ensure(old.state==CanonicalProofUploadState::Verified,"cold recheck requires completed upload")?;old.verification_attempts}else{live.upload(&m,&payload,false).await?.verification_attempts};
            let verified=live.verify(m.id()).await?;expected_result(&live,&c,&verified)?;ensure(verified.verification_attempts>attempts,"cold recheck reused cached authorization")?;
            if mode=="rpc-verify" {
                let mut altered:CommitQuorumProof=read(proof_file)?;altered.weight.proof_bytes[0]^=1;
                let bad=shell_stark_prover::commit_quorum::payload::encode(&altered,shell_core::MAX_CANONICAL_PROOF_BYTES as usize)?;rejected_payload(&live,&manifest(&c,&bad),&bad).await?;
                let mut sender=m.clone();sender.version=1;
                rejected_payload(&live,&sender,&payload).await?;
            }
            let fetched=peer(&live,&c,&m,&root.join("control-db"),mode=="rpc-recheck").await?;
            println!("{}",json!({"fullQuorumRPCVerified":true,"currentHeight":3,"finalized":3,"provedCommitSignatures":2,"NativeRowsUnchanged":true,"partialUploadColdResumed":mode=="rpc-verify","coldRecheck":mode=="rpc-recheck","verificationAttempts":verified.verification_attempts,"peer":fetched,"result":verified.result,"metadataRefusals":6,"bearerRequired":true,"storedResultIsAuthorization":false,"newSigningOrProofGeneration":false}));
        }
        ensure(native_rows(&live.node)?==before,"read-only proof RPC wrote Native rows")?;Ok::<_,Error>(())
    }.await;
    let unchanged = native_rows(&live.node)? == before;
    live.stop().await?;
    ensure(unchanged, "failed proof RPC changed Native state")?;
    outcome
}
pub(super) fn run(
    controls: &Path,
    proof_file: &Path,
    root: &Path,
    mode: &str,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise(controls, proof_file, root, mode))
}

fn canonical_rows(live: &Live) -> Result<Rows, Error> {
    Ok(native_rows(&live.node)?
        .into_iter()
        .filter(|(k, _)| !k.starts_with(b"local/canonical-admission/v1/"))
        .collect())
}
async fn wait_pending<S: KvStore + 'static>(live: &Live<S>, c: &Control) -> Result<Value, Error> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let value = live
                .call("admin_canonicalProofAdmission", json!([c.blocks[0].hash()]))
                .await?;
            if !value.is_null() {
                ensure(value["status"]["version"] == 2, "wrong pending proof role")?;
                return Ok::<_, Error>(value);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
async fn upload_all(live: &Live, m: &CanonicalProofManifest, payload: &[u8]) -> Result<(), Error> {
    let mut s: CanonicalProofUploadStatus =
        serde_json::from_value(live.call("admin_beginCanonicalProof", json!([m])).await?)?;
    for (index, chunk) in payload
        .chunks(shell_storage::CANONICAL_PROOF_CHUNK_BYTES)
        .enumerate()
        .skip(s.next_chunk as usize)
    {
        s = serde_json::from_value(
            live.call(
                "admin_appendCanonicalProof",
                json!([s.proof_id, index, format!("0x{}", hex::encode(chunk))]),
            )
            .await?,
        )?;
    }
    Ok(())
}
async fn wait_upload(live: &Live, id: ShellHash) -> Result<CanonicalProofUploadStatus, Error> {
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let s = live.status(id).await?;
            if matches!(
                s.state,
                CanonicalProofUploadState::Verified | CanonicalProofUploadState::Rejected
            ) {
                return Ok::<_, Error>(s);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
fn certify_slh_history(controls: &Path, source: &Path, c: &Control) -> Result<(), Error> {
    let reference = controls.join("history-control-db");
    ensure(
        std::fs::canonicalize(source)? != std::fs::canonicalize(&reference)?,
        "independent Native3 stores required",
    )?;
    let mut expected = None;
    let mut certificate_checks = 0;
    let mut tamper_refusals = 0;
    let mut reimported = 0;
    for path in [source, reference.as_path()] {
        let n = node(path, c, false)?;
        let head = n
            .chain_store
            .get_head_block()?
            .ok_or("history head absent")?;
        ensure(
            (1..=3).contains(&head.number())
                && head.hash() == c.blocks[head.number() as usize - 1].hash(),
            "SLH history store must contain a matching signed prefix",
        )?;
        for (index, (block, certificate)) in c.blocks.iter().zip(&c.certificates).enumerate() {
            let number = index as u64 + 1;
            let hash = block.hash();
            ensure(
                block.number() == number,
                "SLH history control height mismatch",
            )?;
            let signatures: HashMap<String, shell_crypto::PQSignature> =
                serde_json::from_slice(certificate)?;
            let signature = signatures
                .get(&c.authority.to_string())
                .ok_or("SLH authority signature absent")?;
            ensure(
                signatures.len() == 1
                    && signature.sig_type == shell_crypto::SignatureType::SphincsSha2256f
                    && MultiVerifier.verify(&c.authority_key, hash.as_bytes(), signature)?,
                "retained SLH certificate signature failed",
            )?;
            certificate_checks += 1;
            let head = n
                .chain_store
                .get_head_block()?
                .ok_or("history head absent")?;
            if head.number() < number {
                ensure(
                    head.number() + 1 == number && block.header.parent_hash == head.hash(),
                    "signed history successor does not extend the retained prefix",
                )?;
                n.import_block(block.clone(), &MultiVerifier)?;
                reimported += 1;
            }
            ensure(
                n.chain_store.get_block_hash_by_number(number)? == Some(hash),
                "SLH history control is not canonical",
            )?;
            if number > 1 {
                let mut damaged = signature.clone();
                damaged.data[0] ^= 1;
                let bad = Node::<RocksDbStore>::encode_commit_certificate(&HashMap::from([(
                    c.authority,
                    damaged,
                )]))?;
                let before = n.store.scan_all()?;
                let before_finality = {
                    let f = n.finality.read();
                    (f.last_finalized_number(), *f.last_finalized_hash())
                };
                let refused = !n.fast_finalize_with_certificate(number, hash, &bad);
                let after_finality = {
                    let f = n.finality.read();
                    (f.last_finalized_number(), *f.last_finalized_hash())
                };
                ensure(
                    refused && n.store.scan_all()? == before && after_finality == before_finality,
                    "tampered successor certificate changed Native state",
                )?;
                balances(
                    &n,
                    c,
                    n.chain_store
                        .get_head_block()?
                        .ok_or("history head absent")?
                        .number() as usize,
                )?;
                tamper_refusals += 1;
            }
            let finalized = n.chain_store.get_finalized_number()?.unwrap_or(0);
            let retained = n.chain_store.get_commit_certificate(&hash)?;
            if number > finalized || retained.as_ref() != Some(certificate) {
                ensure(
                    n.fast_finalize_with_certificate(number, hash, certificate)
                        == (number > finalized),
                    "SLH successor certificate finalization failed",
                )?;
            }
            ensure(
                n.chain_store.get_commit_certificate(&hash)?.as_ref() == Some(certificate),
                "SLH successor certificate bytes not persisted",
            )?;
        }
        ensure(
            n.chain_store.get_finalized_number()? == Some(3)
                && n.finality.read().last_finalized_number() == 3
                && *n.finality.read().last_finalized_hash() == c.blocks[2].hash(),
            "SLH Native3 finality absent",
        )?;
        balances(&n, c, 3)?;
        let before = n.store.scan_all()?;
        ensure(
            n.commit_quorum_source(1, c.blocks[0].hash(), &c.certificates[0])?
                == read::<CommitQuorumSource>(&controls.join("source.cbor"))?
                && n.store.scan_all()? == before,
            "finalized Native3 historical source changed or wrote Native rows",
        )?;
        let digest = recovery_native_digest(&n)?;
        if let Some(prior) = expected {
            ensure(digest == prior, "independent certified Native3 rows differ")?;
        }
        expected = Some(digest);
        n.store.flush()?;
    }
    println!(
        "{}",
        json!({"SLHHistoryCertificatesCertified":true,"certificateChecks":certificate_checks,"reimportedSignedBlocks":reimported,
        "tamperedCertificateRefusals":tamper_refusals,"independentNative3Stores":2,
        "finalized":3,"historicalSourceUnchanged":true,"newSigningOrProving":false})
    );
    Ok(())
}

async fn exercise_live(
    controls: &Path,
    proof_file: &Path,
    root: &Path,
    source: &Path,
    mode: &str,
) -> Result<(), Error> {
    let slh = mode.starts_with("slh-");
    let mode = mode.strip_prefix("slh-").unwrap_or(mode);
    let c: Control = read(&controls.join(if slh && mode == "live-history3" {
        "history-control.cbor"
    } else {
        "control.cbor"
    }))?;
    if slh {
        let blocks = if mode == "live-history3" { 3 } else { 1 };
        ensure(
            c.co_authority.is_none()
                && c.blocks.len() == blocks
                && c.certificates.len() == blocks
                && c.authority_key.len() == 64,
            "one-authority SLH controls for the requested height required",
        )?;
    } else {
        ensure(
            c.co_authority.is_some() && c.blocks.len() == 3,
            "genuine two-authority controls required",
        )?;
    }
    if slh && mode == "live-history3" {
        certify_slh_history(controls, source, &c)?;
    }
    let proved_signatures = if slh { 1_u64 } else { 2 };
    let tip_number = c.blocks.len() as u64;
    let tip = c.blocks.last().ok_or("control tip absent")?.hash();
    if slh && mode == "live-persistent-batch-cold" {
        let m = manifest(&c, &frame(proof_file)?);
        return batch_fault::persistent_failure(None, &c, root, &m, true).await;
    }
    if slh
        && matches!(
            mode,
            "live-batch-fault" | "live-batch-recover" | "live-persistent-batch-fault"
        )
    {
        let provider = Live::start_mode(source, &c, vec![], false, false).await?;
        let provider_before = recovery_native_digest(&provider.node)?;
        let outcome = async {
            let payload = frame(proof_file)?;
            let m = manifest(&c, &payload);
            ensure(
                provider.node.chain_store.get_head_hash()? == Some(tip)
                    && provider.node.chain_store.get_finalized_number()? == Some(1),
                "independent Native1 provider required",
            )?;
            if matches!(mode, "live-batch-fault" | "live-persistent-batch-fault") {
                ensure(
                    provider
                        .node
                        .store
                        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                        .is_empty(),
                    "SLH batch fault needs a proof-empty provider, such as prepare-slh control-db",
                )?;
                upload_all(&provider, &m, &payload).await?;
                let checked = provider.verify(m.id()).await?;
                ensure(
                    checked.state == CanonicalProofUploadState::Verified
                        && checked
                            .result
                            .as_ref()
                            .is_some_and(|v| v["proved_commit_signatures"] == 1),
                    "provider original SLH verification failed",
                )?;
                if mode == "live-persistent-batch-fault" {
                    batch_fault::persistent_failure(Some(&provider), &c, root, &m, false).await?;
                } else {
                    batch_fault::exercise(&provider, &c, root, &m, false).await?;
                }
            } else {
                let cache =
                    shell_storage::CanonicalProofUploadStore::new(provider.node.store.clone());
                ensure(
                    cache.payload(&m.id())? == payload,
                    "recovery provider payload changed",
                )?;
                automatic_recovery(&provider, &c, root, &m, "producer-auto-recover").await?;
                let reopened = node(&root.join("db"), &c, false)?;
                ensure(
                    recovery_native_digest(&reopened)? == provider_before,
                    "recovered SLH canonical rows differ from independent Native",
                )?;
            }
            ensure(
                recovery_native_digest(&provider.node)? == provider_before,
                "SLH batch flow changed independent provider Native rows",
            )?;
            println!(
                "{}",
                json!({"SLHFinalBatchFlow":mode,"provedCommitSignatures":1,
                "manualProviderArtifactSupply":true,"noReceiverOperatorProofCalls":true,
                "providerNativeRowsUnchanged":true,"newAuthoritySigningOrProving":false})
            );
            Ok::<_, Error>(())
        }
        .await;
        provider.stop().await?;
        return outcome;
    }
    if matches!(mode, "live-pause" | "live-default" | "live-invalid-recheck") {
        std::fs::create_dir(root)?;
    }
    let initialize = matches!(mode, "live-pause" | "live-default" | "live-invalid-recheck");
    let receiver = Live::start_mode(
        &root.join("db"),
        &c,
        vec![],
        !matches!(mode, "live-default" | "live-history3"),
        initialize,
    )
    .await?;
    let before = canonical_rows(&receiver)?;
    if mode == "live-cold" {
        let outcome=async{
            ensure(receiver.node.chain_store.get_head_hash()?==Some(c.blocks[0].hash())&&receiver.node.chain_store.get_finalized_number()?==Some(1),"cold imported child absent")?;
            let payload=frame(proof_file)?;let m=manifest(&c,&payload);let old=receiver.status(m.id()).await?;let checked=receiver.verify(m.id()).await?;
            ensure(checked.state==CanonicalProofUploadState::Verified&&checked.verification_attempts>old.verification_attempts&&checked.result.as_ref().is_some_and(|v|v["proved_commit_signatures"]==proved_signatures),"cold quorum recheck reused cached authority")?;
            ensure(canonical_rows(&receiver)?==before,"cold quorum replay wrote Native state")?;
            println!("{}",json!({"coldLiveQuorumRecheck":true,"verificationAttempts":checked.verification_attempts,"NativeRowsUnchanged":true,"currentHeight":1,"finalized":1,"newSigningOrProving":false}));Ok::<_,Error>(())
        }.await;
        receiver.stop().await?;
        return outcome;
    }
    let provider = match Live::start_mode(source, &c, vec![receiver.dial()], false, false).await {
        Ok(v) => v,
        Err(e) => {
            receiver.stop().await?;
            return Err(e);
        }
    };
    let outcome=async{
        if mode=="live-history3" {
            tokio::time::timeout(Duration::from_secs(60),async{loop{if receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number()==tip_number&&receiver.node.chain_store.get_finalized_number()?==provider.node.chain_store.get_finalized_number()?{return Ok::<_,Error>(());}tokio::time::sleep(Duration::from_millis(100)).await;}}).await??;
            let snapshot=canonical_rows(&receiver)?;let payload=frame(proof_file)?;let m=manifest(&c,&payload);let prior=receiver.status(m.id()).await?;let checked=receiver.verify(m.id()).await?;
            ensure(prior.state==CanonicalProofUploadState::Verified&&checked.verification_attempts>prior.verification_attempts,"after3 full quorum history not reverified")?;
            expected_result(&receiver,&c,&checked)?;
            balances(&receiver.node,&c,tip_number as usize)?;
            ensure(canonical_rows(&receiver)?==snapshot&&canonical_rows(&provider)?==snapshot,"after3 historical writeback or independent Native row mismatch")?;
            println!("{}",json!({"freshLiveFirstThenNativeFollow3":true,"fullSLH":slh,"currentHeight":tip_number,"finalized":receiver.node.chain_store.get_finalized_number()?,"firstBlockFullAIRSigners":proved_signatures,"firstBlockRootReceiptsChecked":true,"successorQuorumCryptoNative":true,"historyRowsUnchanged":true,"independentNativeRowsEqual":true,"verificationAttempts":checked.verification_attempts,"newSigningOrProving":false}));return Ok::<_,Error>(());
        }
        if mode=="live-default" {
            tokio::time::timeout(Duration::from_secs(60),async{loop{if receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number()==tip_number{return Ok::<_,Error>(());}tokio::time::sleep(Duration::from_millis(100)).await;}}).await??;
            ensure(receiver.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty()&&receiver.node.canonical_admission_status(c.blocks[0].hash())?.is_none(),"default node entered quorum proof path")?;
            println!("{}",json!({"defaultQuorumAdmissionDisabled":true,"head":tip_number,"fullSLH":slh,"proofCacheEmpty":true,"pendingAbsent":true}));return Ok::<_,Error>(());
        }
        let pending=wait_pending(&receiver,&c).await?;
        ensure(receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number()==0&&canonical_rows(&receiver)?==before,"Native changed before full QC proof")?;
        if mode=="live-pause" {
            ensure(pending["status"]["state"]=="waiting"&&receiver.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty(),"pause requires untrusted source and no proof")?;
            if slh {
                let payload = frame(proof_file)?;
                let m = manifest(&c, &payload);
                let (status, _) = request(receiver.address, None, "admin_beginCanonicalProof", json!([m])).await?;
                ensure(status == 401, "SLH operator authorization absent")?;
                metadata_refusals(&receiver, &m, &c).await?;
                let partial = receiver.upload(&m, &payload, true).await?;
                ensure(partial.next_chunk == 3 && partial.state == CanonicalProofUploadState::Uploading
                    && receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number() == 0
                    && canonical_rows(&receiver)? == before,
                    "SLH partial upload changed Native state or missed durable pause")?;
                println!("{}",json!({"durableQuorumCandidate":true,"fullSLH":true,"head":0,"NativeRowsUnchanged":true,"pending":pending,"actualTCPNoiseBodyAndQC":true,"partialUpload":partial}));
            } else {
                println!("{}",json!({"durableQuorumCandidate":true,"head":0,"NativeRowsUnchanged":true,"proofCacheEmpty":true,"pending":pending,"actualTCPNoiseBodyAndQC":true}));
            }
            return Ok(());
        }
        ensure(matches!(mode,"live-import"|"live-invalid-recheck"),"unknown live mode")?;
        let payload=frame(proof_file)?;let m=manifest(&c,&payload);
        if slh && mode == "live-import" {
            let partial = receiver.status(m.id()).await?;
            ensure(partial.state == CanonicalProofUploadState::Uploading && partial.next_chunk == 3
                && partial.received_bytes == 3 * shell_storage::CANONICAL_PROOF_CHUNK_BYTES as u64,
                "SLH import requires the retained three-chunk pause")?;
        }
        let(status,_)=request(receiver.address,None,"admin_beginCanonicalProof",json!([m])).await?;ensure(status==401,"fresh quorum operator auth absent")?;
        let mut sender=m.clone();sender.version=1;
        ensure(receiver.call("admin_beginCanonicalProof",json!([sender])).await.is_err(),"sender role attached to quorum pending source")?;
        let mut foreign=m.clone();foreign.chain_id+=1;
        ensure(receiver.call("admin_beginCanonicalProof",json!([foreign])).await.is_err(),"foreign manifest attached to quorum source")?;
        let mut damaged:CommitQuorumProof=read(proof_file)?;
        if mode=="live-invalid-recheck" {
            // Preserve STARK layout and bytes; change a public AIR witness word
            // so rejection must reach the cryptographic verifier.
            if slh {
                let weight = serde_json::to_vec(&damaged.weight)?;
                let signature = damaged.slh_signatures.last_mut().ok_or("SLH proof absent")?;
                ensure(signature.layers.len() == 17, "complete SLH layers required")?;
                let prefix = &mut signature.layers.last_mut().ok_or("last SLH layer absent")?.prefix;
                let original_stark = prefix.proof_bytes.clone();
                let operation = prefix.operations.first_mut().ok_or("SLH prefix operation absent")?;
                *operation ^= 1;
                ensure(prefix.proof_bytes == original_stark && serde_json::to_vec(&damaged.weight)? == weight,
                    "SLH mutation changed STARK bytes or quorum weight")?;
                println!("{}", json!({"SLHLastLayerPublicOperationAltered":true,"layer":16,
                    "weightUnchanged":true,"originalStarkBytesPreserved":true,
                    "versionsCountsAndLayoutPreserved":true,"newSigningOrProving":false}));
            } else {
                let last=damaged.weight.prefixes.last_mut().ok_or("weight prefix absent")?;
                ensure(last[0]>1,"weight total must allow a bounded nonzero alteration")?;
                last[0]-=1;
            }
        } else { damaged.weight.proof_bytes[0]^=1; }
        let bad=shell_stark_prover::commit_quorum::payload::encode(&damaged,shell_core::MAX_CANONICAL_PROOF_BYTES as usize)?;let bad_manifest=manifest(&c,&bad);
        upload_all(&receiver,&bad_manifest,&bad).await?;
        let rejected=wait_upload(&receiver,bad_manifest.id()).await?;
        ensure(rejected.state==CanonicalProofUploadState::Rejected&&rejected.result.is_none()&&receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number()==0&&canonical_rows(&receiver)?==before,"damaged quorum graph changed Native head/state")?;
        if mode=="live-invalid-recheck" {
            batch_fault::invalid_recheck(&receiver,&c,&bad_manifest,&bad,root,if slh {"SHA2 compression verification:"} else {"quorum weight verification:"}).await?;
            return Ok(());
        }
        upload_all(&provider,&m,&payload).await?;
        let checked=provider.verify(m.id()).await?;
        ensure(checked.state==CanonicalProofUploadState::Verified&&checked.result.as_ref().is_some_and(|v|v["execution"]["tip"]==serde_json::to_value(tip).unwrap()),"provider historical proof verification failed")?;
        receiver.connected(&provider.peer(),&m).await?;
        match receiver.call("admin_fetchCanonicalProof",json!([provider.peer(),m])).await {Ok(_)=>{},Err(e) if e.to_string().contains("busy")=>{},Err(e)=>return Err(e),}
        let verified=wait_upload(&receiver,m.id()).await?;
        let value=verified.result.as_ref().ok_or("fresh quorum receipt absent")?;
        let stored=receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?.ok_or("fresh receipts missing")?;
        ensure(verified.state==CanonicalProofUploadState::Verified&&receiver.node.chain_store.get_head_hash()?==Some(c.blocks[0].hash())&&receiver.node.chain_store.get_finalized_number()?==Some(1)&&value["proved_commit_signatures"]==proved_signatures&&value["execution"]["state_root"]==serde_json::to_value(c.blocks[0].header.state_root)?&&value["execution"]["receipts"]==serde_json::to_value(&stored)?&&provider.node.chain_store.get_receipts(&c.blocks[0].hash())?==Some(stored),"fresh quorum head/finality/proof/independent receipts mismatch")?;
        balances(&receiver.node,&c,1)?;
        if slh {
            ensure(canonical_rows(&receiver)? == canonical_rows(&provider)?,
                "full SLH live import differs from independent Native rows")?;
        }
        let fetch=tokio::time::timeout(Duration::from_secs(15),async{loop{let v=receiver.call("admin_canonicalProofFetchStatus",json!([m.id()])).await?;if v["state"]=="complete"{return Ok::<_,Error>(v);}tokio::time::sleep(Duration::from_millis(100)).await;}}).await??;
        println!("{}",json!({"freshLiveQuorumImported":true,"actualTCPNoiseBodyAndProof":true,"resumedPendingSource":true,"damagedWeightRejectedBeforeMutation":true,"wrongRoleAndChainRejected":true,"head":1,"finalized":1,"provedCommitSignatures":proved_signatures,"fullSLH":slh,"independentReceiptsEqual":true,"balancesNonceFeesChecked":true,"fetch":fetch,"result":value,"newAuthoritySigningOrProving":false}));
        Ok::<_,Error>(())
    }.await;
    let a = provider.stop().await;
    let b = receiver.stop().await;
    a?;
    b?;
    outcome?;
    if mode == "live-invalid-recheck" {
        batch_fault::invalid_cold(&c, root)?;
    }
    Ok(())
}
pub(super) fn run_live(
    controls: &Path,
    proof: &Path,
    root: &Path,
    source: &Path,
    mode: &str,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise_live(controls, proof, root, source, mode))
}

fn production_native_rows<S: KvStore + 'static>(n: &Node<S>) -> Result<Rows, Error> {
    Ok(n.store
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| {
            !k.starts_with(b"local/quorum-production/v1/")
                && !k.starts_with(CANONICAL_PROOF_CACHE_PREFIX)
        })
        .collect())
}

fn recovery_native_digest<S: KvStore + 'static>(n: &Node<S>) -> Result<ShellHash, Error> {
    let rows: Rows = n
        .store
        .scan_all()?
        .into_iter()
        .filter(|(key, _)| !key.starts_with(b"local/"))
        .collect();
    Ok(blake3_hash(&serde_json::to_vec(&rows)?))
}

fn recovery_genesis_balances<S: KvStore + 'static>(n: &Node<S>, c: &Control) -> Result<(), Error> {
    let state = n.world_state.read();
    let sender = state
        .get_account(&c.sender)?
        .ok_or("genesis sender missing")?;
    let recipient = state.get_account(&c.recipient)?;
    ensure(
        sender.nonce == 0
            && sender.balance == U256::from(INITIAL)
            && recipient.is_none_or(|account| account.balance.is_zero() && account.nonce == 0),
        "genesis nonce/value/fee balance mismatch",
    )
}

fn recovery_chunks<S: KvStore>(
    cache: &shell_storage::CanonicalProofUploadStore<S>,
    upload: &CanonicalProofUploadStatus,
) -> Result<Vec<ShellHash>, Error> {
    (0..upload.next_chunk)
        .map(|index| Ok(blake3_hash(&cache.chunk(&upload.proof_id, index)?)))
        .collect()
}

/// Observe real persisted progress and stop through Node.shutdown; never inject bytes.
async fn automatic_recovery(
    provider: &Live,
    c: &Control,
    root: &Path,
    manifest: &CanonicalProofManifest,
    mode: &str,
) -> Result<(), Error> {
    let recover = mode == "producer-auto-recover";
    let slh = c.co_authority.is_none() && c.authority_key.len() == 64;
    let proved_signatures = if c.co_authority.is_some() {
        2_u64
    } else {
        1_u64
    };
    let checkpoint_path = root.join("recovery.json");
    let saved: Option<Value> = if recover {
        Some(serde_json::from_slice(&std::fs::read(&checkpoint_path)?)?)
    } else {
        std::fs::create_dir(root)?;
        None
    };
    let initial_digest;
    {
        let initial = node(&root.join("db"), c, !recover)?;
        ensure(
            initial.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && initial.chain_store.get_finalized_number()?.unwrap_or(0) == 0
                && initial
                    .chain_store
                    .get_receipts(&c.blocks[0].hash())?
                    .is_none(),
            "recovery receiver must retain genesis Native state",
        )?;
        recovery_genesis_balances(&initial, c)?;
        initial_digest = recovery_native_digest(&initial)?;
        if let Some(saved) = &saved {
            ensure(
                matches!(
                    saved["mode"].as_str(),
                    Some(
                        "producer-auto-partial"
                            | "producer-auto-worker"
                            | "producer-auto-batch-fault"
                    )
                ) && saved["nativeDigest"] == serde_json::to_value(initial_digest)?
                    && saved["manifest"] == serde_json::to_value(manifest)?,
                "cold recovery source or Native identity changed",
            )?;
            let cache = shell_storage::CanonicalProofUploadStore::new(initial.store.clone());
            let upload = cache.status(&manifest.id())?;
            let fetch = cache
                .fetch_status(&manifest.id(), None)?
                .ok_or("retained fetch absent")?;
            ensure(
                saved["upload"] == serde_json::to_value(&upload)?
                    && saved["fetch"] == serde_json::to_value(&fetch)?
                    && saved["chunkDigests"]
                        == serde_json::to_value(recovery_chunks(&cache, &upload)?)?
                    && fetch.peer != provider.peer(),
                "cold recovery cache, generation, nonce or peer identity changed",
            )?;
        } else {
            ensure(
                initial
                    .store
                    .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                    .is_empty(),
                "new recovery receiver already has proof bytes",
            )?;
        }
    }
    let receiver =
        Live::start_mode(&root.join("db"), c, vec![provider.dial()], true, false).await?;
    let outcome = async {
        wait_pending(&receiver, c).await?;
        let upload = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                match receiver.status(manifest.id()).await {
                    Ok(s) => {
                        let reached = match mode {
                            "producer-auto-partial" => {
                                s.state == CanonicalProofUploadState::Uploading
                                    && s.next_chunk >= 3
                                    && s.received_bytes < manifest.total_bytes
                            }
                            "producer-auto-worker" => {
                                s.state == CanonicalProofUploadState::Verifying
                                    && s.verification_attempts > 0
                            }
                            _ => matches!(
                                s.state,
                                CanonicalProofUploadState::Verified
                                    | CanonicalProofUploadState::Rejected
                            ),
                        };
                        if reached {
                            if !recover {
                                receiver.node.shutdown();
                            }
                            return Ok::<_, Error>(s);
                        }
                        ensure(
                            !matches!(
                                s.state,
                                CanonicalProofUploadState::Verified
                                    | CanonicalProofUploadState::Rejected
                            ),
                            "recovery observation missed the requested interruption",
                        )?;
                    }
                    Err(e) if e.to_string().contains("upload not found") => {}
                    Err(e) => return Err(e),
                }
                ensure(
                    !receiver.task.is_finished(),
                    "receiver stopped before requested recovery observation",
                )?;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await??;
        if recover {
            ensure(
                upload.state == CanonicalProofUploadState::Verified
                    && upload
                        .result
                        .as_ref()
                        .is_some_and(|v| v["proved_commit_signatures"] == proved_signatures)
                    && receiver.node.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
                    && receiver.node.chain_store.get_finalized_number()? == Some(1)
                    && receiver
                        .node
                        .chain_store
                        .get_receipts(&c.blocks[0].hash())?
                        == provider
                            .node
                            .chain_store
                            .get_receipts(&c.blocks[0].hash())?,
                "recovered proof did not reach independent atomic canonical/finality endpoint",
            )?;
            balances(&receiver.node, c, 1)?;
        }
        Ok::<_, Error>(upload)
    }
    .await;
    // Always close the actors before opening their physical store, including refusals.
    receiver.stop().await?;
    let observed = outcome?;
    let reopened = node(&root.join("db"), c, false)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(reopened.store.clone());
    let upload = cache.status(&manifest.id())?;
    let fetch = cache
        .fetch_status(&manifest.id(), None)?
        .ok_or("durable fetch absent")?;
    let chunks = recovery_chunks(&cache, &upload)?;
    if let Some(saved) = saved {
        let old_upload: CanonicalProofUploadStatus =
            serde_json::from_value(saved["upload"].clone())?;
        let old_fetch: shell_storage::CanonicalProofFetchStatus =
            serde_json::from_value(saved["fetch"].clone())?;
        let old_chunks: Vec<ShellHash> = serde_json::from_value(saved["chunkDigests"].clone())?;
        let partial = saved["mode"] == "producer-auto-partial";
        ensure(
            upload.generation == old_upload.generation
                && chunks.starts_with(&old_chunks)
                && (!partial
                    || (fetch.peer == provider.peer()
                        && fetch.peer != old_fetch.peer
                        && fetch.nonce > old_fetch.nonce))
                && fetch.generation == old_fetch.generation
                && upload.verification_attempts > old_upload.verification_attempts
                && reopened.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
                && reopened.chain_store.get_finalized_number()? == Some(1)
                && reopened.chain_store.get_receipts(&c.blocks[0].hash())?
                    == provider
                        .node
                        .chain_store
                        .get_receipts(&c.blocks[0].hash())?,
            "cold recovery lost retained chunks, peer/nonce binding or full recheck",
        )?;
        balances(&reopened, c, 1)?;
        println!(
            "{}",
            json!({"automaticQuorumRecoveryComplete":true,"interruptedMode":saved["mode"],"head":1,"finalized":1,"provedCommitSignatures":proved_signatures,"independentReceiptsBalancesNonceFeesChecked":true,"retainedChunkDigestsEqual":true,"retainedChunks":old_chunks.len(),"sameGeneration":true,"recoveryByteTransferRequired":partial,"differentAuthenticatedPeer":fetch.peer!=old_fetch.peer,"nonceIncreased":fetch.nonce>old_fetch.nonce,"verificationAttempts":upload.verification_attempts,"noOperatorProofCalls":!slh,"noReceiverOperatorProofCalls":true,"physicalColdReopen":true})
        );
    } else {
        ensure(
            recovery_native_digest(&reopened)? == initial_digest
                && reopened.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && reopened.chain_store.get_finalized_number()?.unwrap_or(0) == 0
                && reopened
                    .chain_store
                    .get_receipts(&c.blocks[0].hash())?
                    .is_none()
                && upload.result.is_none()
                && fetch.state == shell_storage::CanonicalProofFetchState::Paused,
            "interruption published canonical state or retained an active fetch",
        )?;
        recovery_genesis_balances(&reopened, c)?;
        ensure(
            match mode {
                "producer-auto-partial" => {
                    upload.state == CanonicalProofUploadState::Uploading
                        && upload.next_chunk >= observed.next_chunk
                        && upload.received_bytes < manifest.total_bytes
                        && upload.verification_attempts == 0
                }
                "producer-auto-worker" => {
                    upload.state == CanonicalProofUploadState::Ready
                        && upload.received_bytes == manifest.total_bytes
                        && upload.verification_attempts == observed.verification_attempts
                        && upload
                            .error
                            .as_ref()
                            .is_some_and(|e| e.contains("full recheck required"))
                }
                _ => false,
            },
            "durable interruption state inconsistent",
        )?;
        ensure(
            !checkpoint_path.exists(),
            "recovery checkpoint already exists",
        )?;
        let checkpoint = json!({"mode":mode,"manifest":manifest,"nativeDigest":initial_digest,"upload":upload,"fetch":fetch,"chunkDigests":chunks});
        std::fs::write(checkpoint_path, serde_json::to_vec_pretty(&checkpoint)?)?;
        println!(
            "{}",
            json!({"automaticQuorumInterrupted":true,"mode":mode,"head":0,"finalized":0,"canonicalRowsUnchanged":true,"noChildReceipts":true,"noCachedAuthorization":true,"receivedBytes":upload.received_bytes,"nextChunk":upload.next_chunk,"verificationAttempts":upload.verification_attempts,"noOperatorProofCalls":!slh,"noReceiverOperatorProofCalls":true,"actualTCPNoise":true,"gracefulNodeShutdown":true,"physicalColdReopen":true})
        );
    }
    Ok(())
}

pub(super) fn seed_producer(
    controls: &Path,
    job_root: &Path,
    provider_db: &Path,
) -> Result<(), Error> {
    use shell_stark_prover::{
        commit_quorum::prove_commit_quorum_persistent_interruptible,
        production_store::{ProductionError, ProductionProgress},
    };
    use shell_storage::MemoryDb;
    let c: Control = read(&controls.join("control.cbor"))?;
    let source: CommitQuorumSource = read(&job_root.join("source.cbor"))?;
    let mut provider = node(provider_db, &c, false)?;
    let before = provider.store.scan_all()?;
    ensure(
        !provider.config.canonical_quorum_production,
        "producer defaults enabled",
    )?;
    let stores = RocksDbStore::open_all(job_root.join("db"), None)?;
    let mut donor = stores.chain;
    let original = donor.scan_all()?;
    let mut progress = ProductionProgress {
        components: 0,
        checkpoint_bytes: 0,
        newly_proved: 0,
        reused: 0,
    };
    ensure(
        matches!(
            prove_commit_quorum_persistent_interruptible(
                &mut donor,
                &source,
                std::num::NonZeroUsize::new(1),
                &|| true,
                &mut progress
            ),
            Err(ProductionError::Paused)
        ) && progress.newly_proved == 0
            && progress.reused == 0
            && donor.scan_all()? == original,
        "cancelled quorum attempt proved or changed checkpoints",
    )?;
    let malformed = MemoryDb::new();
    for (k, v) in &original {
        malformed.put(k, v)?;
    }
    let key = b"production/component/commit-weight";
    let mut bytes = malformed.get(key)?.ok_or("weight checkpoint missing")?;
    bytes.push(0);
    malformed.put(key, &bytes)?;
    let mut index: Value =
        serde_json::from_slice(&malformed.get(b"production/index")?.ok_or("index absent")?)?;
    let expected_components = index["components"]
        .as_object()
        .ok_or("component index absent")?
        .len();
    ensure(expected_components > 0, "completed donor has no components")?;
    index["components"]["commit-weight"]["bytes"] = json!(bytes.len());
    index["components"]["commit-weight"]["hash"] = serde_json::to_value(blake3_hash(&bytes))?;
    malformed.put(b"production/index", &serde_json::to_vec(&index)?)?;
    let mut malformed = malformed;
    let rejected = provider
        .recover_quorum_production_job(c.blocks[0].hash(), &mut malformed)
        .err()
        .ok_or("damaged correct-hash donor accepted")?;
    ensure(
        provider.store.scan_all()? == before,
        "invalid donor wrote node rows",
    )?;
    let foreign = provider
        .recover_quorum_production_job(ShellHash::ZERO, &mut donor)
        .err()
        .ok_or("foreign source accepted")?;
    ensure(
        provider.store.scan_all()? == before,
        "foreign source wrote node rows",
    )?;
    let native_donor = MemoryDb::new();
    for (k, v) in &original {
        native_donor.put(k, v)?;
    }
    native_donor.put(b"HEAD", b"forbidden native key")?;
    let mut native_donor = native_donor;
    let namespace = provider
        .recover_quorum_production_job(c.blocks[0].hash(), &mut native_donor)
        .err()
        .ok_or("native donor namespace accepted")?;
    ensure(
        provider.store.scan_all()? == before,
        "foreign namespace wrote node rows",
    )?;
    let recovered = provider.recover_quorum_production_job(c.blocks[0].hash(), &mut donor)?;
    ensure(
        recovered.components == expected_components
            && recovered.newly_proved == 0
            && recovered.reused >= expected_components
            && donor.scan_all()? == original,
        "recovery changed original graph or proved new components",
    )?;
    ensure(
        production_native_rows(&provider)? == before
            && provider
                .store
                .scan_prefix(b"local/canonical-production/v1/")?
                .is_empty()
            && provider
                .canonical_production_status(c.blocks[0].hash())?
                .is_none(),
        "quorum recovery touched Native or sender production",
    )?;
    provider.store.flush()?;
    println!(
        "{}",
        json!({"nodeOwnedQuorumRecovered":true,"progress":recovered,"cancelledBeforeProving":true,"correctHashDamagedDonorRefusal":rejected,"foreignSourceRefusal":foreign,"NativeNamespaceRefusal":namespace,"NativeRowsUnchanged":true,"senderNamespaceUnchanged":true,"donorLogicalRowsUnchanged":true,"newAuthoritySigningOrProving":false,"status":provider.quorum_production_status(c.blocks[0].hash())?})
    );
    Ok(())
}
async fn wait_production(live: &Live, hash: ShellHash, was_complete: bool) -> Result<Value, Error> {
    tokio::time::timeout(Duration::from_secs(300), async {
        // RPC can start before cold startup requeues the persisted complete record.
        let mut rechecking = !was_complete;
        loop {
            let v = live
                .call("admin_quorumProofProduction", json!([hash]))
                .await?;
            if matches!(v["status"]["state"].as_str(), Some("queued" | "proving")) {
                rechecking = true;
            }
            if v["status"]["state"] == "failed"
                || (rechecking && v["status"]["state"] == "complete")
            {
                return Ok::<_, Error>(v);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
async fn exercise_producer(
    controls: &Path,
    provider_db: &Path,
    receiver_root: &Path,
    proof_file: &Path,
    mode: &str,
) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    if mode == "producer-manifest" {
        let n = node(provider_db, &c, false)?;
        let key = [
            b"local/quorum-production/v1/record/".as_slice(),
            c.blocks[0].hash().as_bytes(),
        ]
        .concat();
        let old = n
            .store
            .get(&key)?
            .ok_or("completed quorum metadata absent")?;
        let mut v: Value = serde_json::from_slice(&old)?;
        ensure(
            v["manifest"]["version"] == 2,
            "manifest fault requires completed producer",
        )?;
        v["manifest"]["version"] = json!(1);
        let bad = serde_json::to_vec(&v)?;
        ensure(
            old.len() == bad.len(),
            "manifest fault must retain quota width",
        )?;
        n.store.put(&key, &bad)?;
        n.store.flush()?;
    }
    if mode == "producer-corrupt" {
        let n = node(provider_db, &c, false)?;
        let key = [
            b"local/quorum-production/v1/certificates/".as_slice(),
            c.blocks[0].hash().as_bytes(),
            b"/production/component/commit-weight",
        ]
        .concat();
        let mut bytes = n.store.get(&key)?.ok_or("owned weight checkpoint absent")?;
        *bytes.last_mut().ok_or("weight checkpoint empty")? ^= 1;
        n.store.put(&key, &bytes)?;
        n.store.flush()?;
    }
    let (expected_components, was_complete, before) = {
        let offline = node(provider_db, &c, false)?;
        let status = if mode == "producer-manifest" {
            None
        } else {
            offline.quorum_production_status(c.blocks[0].hash())?
        };
        (
            status
                .as_ref()
                .and_then(|s| s["status"]["components"].as_u64()),
            status
                .as_ref()
                .is_some_and(|s| s["status"]["state"] == "complete"),
            production_native_rows(&offline)?,
        )
    };
    ensure(
        mode != "producer-cold" || was_complete,
        "cold producer requires a previously complete job",
    )?;
    let proved_signatures = 1 + usize::from(c.co_authority.is_some());
    let provider = Live::start_production(
        provider_db,
        &c,
        vec![],
        false,
        false,
        !matches!(mode, "producer-disabled" | "producer-auto-wait"),
    )
    .await?;
    let outcome=async{
        if mode=="producer-disabled" {
            let status=provider.call("admin_quorumProofProduction",json!([c.blocks[0].hash()])).await?;
            ensure(status["status"]["state"]=="paused"&&status["status"]["manifest"].is_null()&&provider.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty()&&production_native_rows(&provider.node)?==before,"disabled producer resumed or published")?;
            println!("{}",json!({"quorumProducerDefaultDisabled":true,"NativeRowsUnchanged":true,"proofCacheEmpty":true,"status":status}));return Ok::<_,Error>(());
        }
        if mode=="producer-manifest" {
            let key=[b"local/quorum-production/v1/record/".as_slice(),c.blocks[0].hash().as_bytes()].concat();
            tokio::time::timeout(Duration::from_secs(90),async{loop{let v:Value=serde_json::from_slice(&provider.node.store.get(&key)?.ok_or("metadata absent")?)?;if v["state"]=="failed"{return Ok::<_,Error>(());}tokio::time::sleep(Duration::from_millis(100)).await;}}).await??;
            ensure(provider.call("admin_quorumProofProduction",json!([c.blocks[0].hash()])).await.is_err()&&production_native_rows(&provider.node)?==before,"wrong-role completed metadata accepted or changed Native")?;
            println!("{}",json!({"wrongRoleProducerMetadataRejected":true,"NativeRowsUnchanged":true,"noCachedAuthorization":true}));return Ok(());
        }
        if mode=="producer-auto-wait" {
            ensure(provider.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty(),"wait provider already has proof bytes")?;
            std::fs::create_dir(receiver_root)?;
            let receiver=Live::start_mode(&receiver_root.join("db"),&c,vec![provider.dial()],true,true).await?;
            let outcome=async {
                let pending=wait_pending(&receiver,&c).await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                ensure(receiver.node.chain_store.get_head_hash()?==Some(c.genesis.hash())&&receiver.node.chain_store.get_finalized_number()?.unwrap_or(0)==0&&receiver.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty()&&pending["status"]["manifest"].is_null(),"missing availability imported child or allocated proof bytes")?;
                println!("{}",json!({"automaticQuorumWaitingPersisted":true,"head":0,"proofCacheEmpty":true,"pending":pending,"noOperatorProofCalls":true,"sourceNativeRowsUnchanged":production_native_rows(&provider.node)?==before}));Ok::<_,Error>(())
            }.await;
            receiver.stop().await?;return outcome;
        }
        let status=wait_production(&provider,c.blocks[0].hash(),was_complete).await?;
        if mode=="producer-corrupt" {
            ensure(status["status"]["state"]=="failed"&&status["status"]["error"].is_string()&&production_native_rows(&provider.node)?==before&&provider.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty(),"corrupt owned job healed, wrote Native, or published bytes")?;
            println!("{}",json!({"damagedOwnedGraphRejected":true,"NativeRowsUnchanged":true,"proofCacheEmpty":true,"status":status}));return Ok::<_,Error>(());
        }
        let expected_components=expected_components.filter(|n|*n>0).ok_or("seeded component count absent")?;
        ensure(status["status"]["state"]=="complete"&&status["status"]["components"]==expected_components&&status["status"]["newlyProved"]==0&&status["status"]["reused"].as_u64().is_some_and(|n|n>=expected_components)&&status["artifactVersion"]==2&&status["nativeExecutionVerified"]==false,"actual quorum producer did not fully reverify existing graph")?;
        let manifest:CanonicalProofManifest=serde_json::from_value(status["status"]["manifest"].clone())?;
        ensure(manifest.version==2&&provider.status(manifest.id()).await?.state==CanonicalProofUploadState::Ready&&production_native_rows(&provider.node)?==before,"producer availability or Native state incorrect")?;
        let expected=frame(proof_file)?;ensure(manifest==super::quorum_rpc::manifest(&c,&expected),"produced payload identity differs from original genuine graph")?;
        let cache=shell_storage::CanonicalProofUploadStore::new(provider.node.store.clone());
        ensure(cache.payload(&manifest.id())?==expected,"node-produced bytes differ from complete original proof")?;
        if mode=="producer-cold"{
            println!("{}",json!({"coldNodeQuorumProducerReverified":true,"observedColdRecheck":was_complete,"NativeRowsUnchanged":true,"status":status,"readyBytesNotNativeAuthorization":true}));return Ok(());
        }
        if matches!(mode,"producer-auto-batch-fault"|"producer-intact-rejection") {
            batch_fault::exercise(&provider,&c,receiver_root,&manifest,mode=="producer-intact-rejection").await?;
            ensure(production_native_rows(&provider.node)?==before,"fault flow changed provider Native rows")?;
            return Ok(());
        }
        if mode=="producer-auto-batch-recover" {
            automatic_recovery(&provider,&c,receiver_root,&manifest,"producer-auto-recover").await?;
            ensure(production_native_rows(&provider.node)?==before,"batch recovery changed provider Native rows")?;
            return Ok(());
        }
        if matches!(mode,"producer-auto-partial"|"producer-auto-worker"|"producer-auto-recover") {
            automatic_recovery(&provider,&c,receiver_root,&manifest,mode).await?;
            ensure(production_native_rows(&provider.node)?==before,"recovery changed provider Native rows")?;
            return Ok(());
        }
        ensure(matches!(mode,"producer-live"|"producer-auto"|"producer-auto-resume"),"unknown producer mode")?;
        let resume=mode=="producer-auto-resume";
        if resume {ensure(receiver_root.join("db/CURRENT").is_file(),"resume needs retained waiting receiver")?;}else{std::fs::create_dir(receiver_root)?;}
        let automatic=mode!="producer-live";
        if automatic {
            let initial=node(&receiver_root.join("db"),&c,!resume)?;
            ensure(initial.chain_store.get_head_hash()?==Some(c.genesis.hash())&&initial.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty(),"automatic receiver must start at genesis with no proof bytes")?;
        }
        let receiver=Live::start_mode(&receiver_root.join("db"),&c,vec![provider.dial()],true,!resume&&!automatic).await?;
        let transfer=async{
            wait_pending(&receiver,&c).await?;
            if mode=="producer-live" {
                receiver.connected(&provider.peer(),&manifest).await?;
                match receiver.call("admin_fetchCanonicalProof",json!([provider.peer(),manifest])).await {
                    Ok(_)=>{},Err(e) if e.to_string().contains("busy")=>{},Err(e)=>return Err(e),
                }
            }
            let verified=tokio::time::timeout(Duration::from_secs(180),async {
                loop {
                    match receiver.status(manifest.id()).await {
                        Ok(s) if matches!(s.state,CanonicalProofUploadState::Verified|CanonicalProofUploadState::Rejected)=>return Ok::<_,Error>(s),
                        Ok(_)=>{},Err(e) if e.to_string().contains("upload not found")=>{},Err(e)=>return Err(e),
                    }
                    if receiver.task.is_finished(){return Err("receiver stopped before automatic proof completion".into());}
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }).await??;
            let receipts=receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?.ok_or("receiver receipts absent")?;
            ensure(verified.state==CanonicalProofUploadState::Verified&&receiver.node.chain_store.get_head_hash()?==Some(c.blocks[0].hash())&&receiver.node.chain_store.get_finalized_number()?==Some(1)&&verified.result.as_ref().is_some_and(|v|v["proved_commit_signatures"]==proved_signatures)&&provider.node.chain_store.get_receipts(&c.blocks[0].hash())?==Some(receipts),"produced proof did not reach true atomic canonical/finality endpoint")?;
            balances(&receiver.node,&c,1)?;
            println!("{}",json!({"nodeQuorumProducerToFreshPeerComplete":true,"status":status,"actualTCPNoise":true,"head":1,"finalized":1,"provedCommitSignatures":proved_signatures,"independentNativeReceiptsEqual":true,"balancesNonceFeesChecked":true,"sourceNativeRowsUnchanged":production_native_rows(&provider.node)?==before,"manualProofUpload":false,"automaticDiscovery":mode!="producer-live","coldWaitingResumed":resume,"noOperatorProofCalls":mode!="producer-live","newAuthoritySigningOrProving":false}));Ok::<_,Error>(())
        }.await;
        receiver.stop().await?;
        transfer?;
        let reopened=node(&receiver_root.join("db"),&c,false)?;
        ensure(reopened.chain_store.get_head_hash()?==Some(c.blocks[0].hash())&&reopened.chain_store.get_finalized_number()?==Some(1)&&recovery_native_digest(&reopened)?==recovery_native_digest(&provider.node)?,"cold produced-proof Native rows differ from independent reference")?;
        balances(&reopened,&c,1)?;
        ensure(production_native_rows(&provider.node)?==before,"producer changed Native during automatic import")?;
        println!("{}",json!({"coldProducedProofCanonicalRowsEqual":true,"head":1,"finalized":1,"independentNativeReference":true,"balancesNonceFeesChecked":true,"sourceNativeRowsUnchanged":true}));
        Ok(())
    }.await;
    provider.stop().await?;
    outcome
}

async fn exercise_producer_step(
    controls: &Path,
    provider_db: &Path,
    receiver_root: &Path,
    budget: usize,
) -> Result<(), Error> {
    ensure(
        (1..=16).contains(&budget),
        "step budget must be between 1 and 16",
    )?;
    let c: Control = read(&controls.join("control.cbor"))?;
    ensure(
        c.co_authority.as_ref().is_none_or(|(address, key)| {
            shell_crypto::infer_signature_type_from_address(key, address)
                == Some(shell_crypto::SignatureType::MlDsa65)
        }) && c.authority_key.len() == 64
            && c.blocks.len() == 1
            && c.certificates.len() == 1,
        "step requires one-block SLH controls with optional ML-DSA coauthority",
    )?;
    let mut artifact = receiver_root.as_os_str().to_os_string();
    artifact.push(".proof.cbor");
    let artifact = std::path::PathBuf::from(artifact);
    ensure(
        !receiver_root.exists() && !artifact.exists(),
        "step receiver/output already exists",
    )?;
    let block = c.blocks[0].hash();
    let prefix = [
        b"local/quorum-production/v1/certificates/".as_slice(),
        block.as_bytes(),
        b"/production/component/",
    ]
    .concat();
    let (mut n, prior, before, old_rows) = {
        let n = node(provider_db, &c, false)?;
        ensure(
            n.chain_store.get_head_hash()? == Some(block)
                && n.chain_store.get_finalized_number()? == Some(1),
            "step needs finalized Native1 provider",
        )?;
        ensure(
            !n.config.canonical_quorum_production,
            "production defaults enabled",
        )?;
        let prior = n.quorum_production_status(block)?;
        ensure(
            prior
                .as_ref()
                .is_none_or(|s| s["status"]["state"] == "paused"),
            "step requires an absent or paused job; retain failed/completed jobs for diagnosis",
        )?;
        if prior.is_none() {
            ensure(
                n.store
                    .scan_prefix(b"local/quorum-production/v1/")?
                    .is_empty()
                    && n.store
                        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                        .is_empty(),
                "fresh step already has production or proof bytes",
            )?;
        }
        ensure(
            n.store
                .scan_prefix(b"local/canonical-production/v1/")?
                .is_empty(),
            "step provider has sender production rows",
        )?;
        let reference = node(&controls.join("control-db"), &c, false)?;
        ensure(
            recovery_native_digest(&n)? == recovery_native_digest(&reference)?,
            "step provider differs from independent Native1 reference",
        )?;
        let before = production_native_rows(&n)?;
        let rows = n.store.scan_prefix(&prefix)?;
        (n, prior, before, rows)
    };
    let previous_components = prior
        .as_ref()
        .and_then(|s| s["status"]["components"].as_u64())
        .unwrap_or(0);
    ensure(
        old_rows.len() as u64 == previous_components,
        "prior component count differs from owned rows",
    )?;
    n.config.canonical_proof_component_budget = std::num::NonZeroUsize::new(budget);
    let provider = Live::start_on_node(n, &c, vec![], false, true).await?;
    let outcome = async {
        let mut started = false;
        let status = tokio::time::timeout(Duration::from_secs(3600), async {
            loop {
                if provider.task.is_finished() {
                    return Err::<Value, Error>("step node stopped".into());
                }
                if provider.node.quorum_production_status(block)?.is_some() {
                    let v = provider
                        .call("admin_quorumProofProduction", json!([block]))
                        .await?;
                    let state = v["status"]["state"].as_str().unwrap_or("");
                    started |= matches!(state, "queued" | "proving");
                    let advanced = v["status"]["components"]
                        .as_u64()
                        .is_some_and(|n| n > previous_components);
                    if state == "failed"
                        || state == "complete"
                        || (state == "paused" && (started || advanced))
                    {
                        return Ok(v);
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        let state = status["status"]["state"]
            .as_str()
            .ok_or("step state absent")?;
        ensure(
            matches!(state, "paused" | "complete"),
            &format!("step failed: {status}"),
        )?;
        let count = status["status"]["components"]
            .as_u64()
            .ok_or("step count absent")?;
        let newly = status["status"]["newlyProved"]
            .as_u64()
            .ok_or("step new count absent")?;
        let reused = status["status"]["reused"]
            .as_u64()
            .ok_or("step reuse count absent")?;
        ensure(
            newly <= budget as u64
                && count == previous_components + newly
                && reused >= previous_components,
            "step budget/progress/reuse mismatch",
        )?;
        let rows = provider.node.store.scan_prefix(&prefix)?;
        ensure(
            rows.len() as u64 == count && old_rows.iter().all(|r| rows.contains(r)),
            "step removed or changed prior checkpoint bytes",
        )?;
        let job_prefix = prefix
            .strip_suffix(b"component/")
            .ok_or("step prefix shape")?;
        let index: Value = serde_json::from_slice(
            &provider
                .node
                .store
                .get(&[job_prefix, b"index"].concat())?
                .ok_or("step index absent")?,
        )?;
        let source = provider
            .node
            .store
            .get(&[job_prefix, b"source"].concat())?
            .ok_or("step source absent")?;
        let entries = index["components"]
            .as_object()
            .ok_or("step index components absent")?;
        let logical_bytes = entries
            .values()
            .try_fold(
                index["source_bytes"]
                    .as_u64()
                    .ok_or("step source bytes absent")?,
                |total, entry| total.checked_add(entry["bytes"].as_u64()?),
            )
            .ok_or("step logical size overflow")?;
        ensure(
            index["source_bytes"] == source.len() as u64
                && index["source_hash"] == serde_json::to_value(blake3_hash(&source))?
                && entries.len() as u64 == count
                && logical_bytes
                    == status["status"]["checkpointBytes"]
                        .as_u64()
                        .ok_or("step bytes absent")?
                && logical_bytes
                    <= shell_stark_prover::production_store::MAX_CHECKPOINT_BYTES as u64,
            "step source/index/logical byte binding mismatch",
        )?;
        ensure(
            production_native_rows(&provider.node)? == before,
            "step changed Native/sender rows",
        )?;
        let payload = if state == "paused" {
            ensure(
                newly > 0
                    && status["status"]["manifest"].is_null()
                    && provider
                        .node
                        .store
                        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                        .is_empty(),
                "paused step made no progress or exposed proof bytes",
            )?;
            None
        } else {
            let m: CanonicalProofManifest =
                serde_json::from_value(status["status"]["manifest"].clone())?;
            let cache = shell_storage::CanonicalProofUploadStore::new(provider.node.store.clone());
            let bytes = cache.payload(&m.id())?;
            ensure(
                m == manifest(&c, &bytes)
                    && cache.status(&m.id())?.state == CanonicalProofUploadState::Ready
                    && status["nativeExecutionVerified"] == false,
                "step completion is not bounded source-bound availability",
            )?;
            Some(bytes)
        };
        Ok::<_, Error>((status, rows, payload))
    }
    .await;
    provider.stop().await?;
    let (status, rows, payload) = outcome?;
    {
        let reopened = node(provider_db, &c, false)?;
        ensure(
            reopened.quorum_production_status(block)? == Some(status.clone())
                && reopened.store.scan_prefix(&prefix)? == rows
                && production_native_rows(&reopened)? == before,
            "step cold metadata/checkpoints/Native mismatch",
        )?;
    }
    println!(
        "{}",
        json!({"nodeOwnedQuorumProductionStep":true,"fromZero":prior.is_none(),
        "componentBudget":budget,"previousComponents":previous_components,"status":status,
        "priorCheckpointsUnchanged":true,"NativeRowsUnchanged":true,"physicalColdReopen":true,
        "partialProductionOnly":payload.is_none(),"newAuthoritySigning":false,
        "expectedCommitSignatures":1+usize::from(c.co_authority.is_some())})
    );
    if let Some(bytes) = payload {
        let proof = shell_stark_prover::commit_quorum::payload::decode(&bytes)?;
        write(&artifact, &proof)?;
        exercise_producer(
            controls,
            provider_db,
            receiver_root,
            &artifact,
            "producer-auto",
        )
        .await?;
        println!(
            "{}",
            json!({"nodeOwnedCompleteStepToFreshPeer":true,"proofFile":artifact,
            "head":1,"finalized":1,"independentColdNativeRowsChecked":true})
        );
    }
    Ok(())
}
pub(super) fn run_producer_step(
    controls: &Path,
    provider: &Path,
    receiver: &Path,
    budget: usize,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise_producer_step(controls, provider, receiver, budget))
}

pub(super) fn run_producer(
    controls: &Path,
    provider: &Path,
    receiver: &Path,
    proof: &Path,
    mode: &str,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise_producer(controls, provider, receiver, proof, mode))
}

pub(super) fn run_explicit_recheck(
    controls: &Path,
    proof: &Path,
    root: &Path,
    reference: &Path,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(batch_fault::explicit_recheck(
            controls, proof, root, reference,
        ))
}

pub(super) fn run_cold_intent_recheck(
    controls: &Path,
    proof: &Path,
    root: &Path,
    reference: &Path,
) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(batch_fault::cold_intent_recheck(
            controls, proof, root, reference,
        ))
}
