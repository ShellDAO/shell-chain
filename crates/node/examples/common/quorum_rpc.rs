//! Actual authenticated, durable full-quorum proof availability checks.
use super::*;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shell_network::{Libp2pNetwork, LocalNodeInfo, NetworkConfig, NetworkService};
use shell_primitives::ShellHash;
use shell_storage::{
    CanonicalProofManifest, CanonicalProofUploadState, CanonicalProofUploadStatus,
    CANONICAL_PROOF_CACHE_PREFIX,
};
use std::{net::SocketAddr, time::Duration};

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
struct Live {
    node: Arc<Node<RocksDbStore>>,
    task: tokio::task::JoinHandle<Result<(), shell_node::NodeError>>,
    address: SocketAddr,
    token: String,
    info: Arc<std::sync::RwLock<LocalNodeInfo>>,
}
impl Live {
    async fn start(path: &Path, c: &Control, boot_nodes: Vec<String>) -> Result<Self, Error> {
        let mut node = node(path, c, false)?;
        ensure(
            node.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
                && node.chain_store.get_finalized_number()? == Some(3),
            "canonical state3 required",
        )?;
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
    ensure(
        result["proved_commit_signatures"] == 2
            && execution["tip"] == serde_json::to_value(c.blocks[2].hash())?
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
