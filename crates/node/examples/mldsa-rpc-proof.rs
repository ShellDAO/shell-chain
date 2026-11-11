//! Real HTTP intake, interrupted upload recovery and complete native replay.
#[path = "common/canonical_proof_fixture.rs"]
mod fixture;
use fixture::{node, request, Context};
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_batch.rs"]
mod graph;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;

use graph::LoadedEntry;
use parking_lot::RwLock;
use shell_core::Block;
use shell_crypto::{DilithiumSigner, Signer};
use shell_node::{CanonicalProofReplay, Node};
use shell_primitives::ShellHash;
use shell_stark_prover::canonical_batch::{
    CanonicalSignatureBatchProof, CanonicalTransactionProof,
};
use shell_stark_prover::registered_signature::RegisteredSignatureProof;
use shell_storage::{ChainStore, KvStore, RocksDbStore};
use source::{read, write, Error};
use std::{path::Path, sync::Arc};

fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn block_proof(
    first: &LoadedEntry,
    second: &LoadedEntry,
    state: &Path,
    block: &Block,
) -> Result<CanonicalSignatureBatchProof, Error> {
    let mut transactions = Vec::new();
    for tx in &block.transactions {
        let (entry, name) = if tx == &first.expected {
            (first, "first-account.json")
        } else if tx == &second.expected {
            (second, "second-account.json")
        } else {
            return Err(
                "native source differs from the two independently expected graph inputs".into(),
            );
        };
        transactions.push(CanonicalTransactionProof {
            account: read(&state.join(name))?,
            signature: RegisteredSignatureProof {
                version: 1,
                transaction: entry.proof.identified.sender.transaction.clone(),
                transaction_id: entry.proof.identified.transaction_id.clone(),
                leaf: entry.proof.leaf.clone(),
                tagged_key: None,
            },
        });
    }
    Ok(CanonicalSignatureBatchProof {
        slh_proposer: None,
        slh_transactions: None,
        version: 1,
        proposer: None,
        transactions,
    })
}
use serde_json::{json, Value};
use shell_primitives::blake3_hash;
use shell_rpc::{start_rpc_server_with_proof_control, RpcConfig, RpcServerHandle};
use shell_storage::{
    CanonicalProofManifest, CanonicalProofUploadState, CanonicalProofUploadStatus,
    CANONICAL_PROOF_CACHE_PREFIX, CANONICAL_PROOF_CHUNK_BYTES, MAX_CANONICAL_PROOF_BYTES,
};
use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    time::Duration,
};

struct Receiver {
    node: Arc<Node<RocksDbStore>>,
    server: RpcServerHandle,
    token: String,
}
impl Receiver {
    async fn open(dir: &Path, context: &Context, admin: bool) -> Result<Self, Error> {
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        let node = Arc::new(node(
            Arc::new(stores.state),
            context.authority,
            &context.authority_key,
        )?);
        let token = blake3_hash(DilithiumSigner::generate().public_key()).to_string();
        let config = RpcConfig {
            listen_addr: "127.0.0.1:0".parse()?,
            ws_addr: None,
            api_namespaces: if admin {
                vec!["admin".into()]
            } else {
                RpcConfig::default().api_namespaces
            },
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            max_request_body_size: 2 * 1024 * 1024,
            ..Default::default()
        };
        let (events, _) = tokio::sync::broadcast::channel(16);
        let server = start_rpc_server_with_proof_control(
            config,
            node.chain_store.clone(),
            node.world_state.clone(),
            node.tx_pool.clone(),
            10,
            None,
            events,
            None,
            None,
            Arc::new(RwLock::new(2)),
            node.finality.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(node.clone()),
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(Self {
            node,
            server,
            token,
        })
    }
    async fn stop(self) -> Result<(), Error> {
        self.server.http_handle.stop()?;
        self.server.http_handle.stopped().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&self.node) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "HTTP backend still holds receiver after shutdown")?;
        drop(self.node);
        Ok(())
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let (status, result) =
            request(self.server.http_addr, Some(&self.token), method, params).await?;
        ensure(status == 200, "authenticated HTTP failed")?;
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
    async fn refused(&self, method: &str, params: Value) -> Result<(), Error> {
        let before = self.node.store.scan_all()?;
        let (status, result) =
            request(self.server.http_addr, Some(&self.token), method, params).await?;
        ensure(
            status == 200 && result["error"]["code"].is_i64(),
            "invalid request accepted",
        )?;
        ensure(
            self.node.store.scan_all()? == before,
            "refused request wrote KV",
        )
    }
    async fn append(
        &self,
        id: ShellHash,
        index: u32,
        chunk: &[u8],
    ) -> Result<CanonicalProofUploadStatus, Error> {
        Ok(serde_json::from_value(
            self.call(
                "admin_appendCanonicalProof",
                json!([id, index, shell_primitives::Bytes::copy_from_slice(chunk)]),
            )
            .await?,
        )?)
    }
    async fn upload(&self, path: &Path, id: ShellHash, stop: Option<u32>) -> Result<(), Error> {
        let next = self.status(id).await?.next_chunk;
        let mut file = File::open(path)?;
        let mut index = 0;
        let mut buffer = vec![0; CANONICAL_PROOF_CHUNK_BYTES];
        loop {
            let mut used = 0;
            while used < buffer.len() {
                let n = file.read(&mut buffer[used..])?;
                if n == 0 {
                    break;
                }
                used += n;
            }
            if used == 0 || stop.is_some_and(|n| index >= n) {
                break;
            }
            if index >= next {
                self.append(id, index, &buffer[..used]).await?;
            }
            index += 1;
        }
        Ok(())
    }
    async fn verify(
        &self,
        id: ShellHash,
        recheck: bool,
    ) -> Result<CanonicalProofUploadStatus, Error> {
        let started: CanonicalProofUploadStatus = serde_json::from_value(
            self.call("admin_verifyCanonicalProof", json!([id, recheck]))
                .await?,
        )?;
        ensure(
            started.state == CanonicalProofUploadState::Verifying,
            "verification did not start",
        )?;
        let duplicate: CanonicalProofUploadStatus =
            serde_json::from_value(self.call("admin_verifyCanonicalProof", json!([id])).await?)?;
        ensure(
            duplicate.verification_attempts == started.verification_attempts,
            "duplicate started another job",
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(900);
        loop {
            let status = self.status(id).await?;
            if status.state != CanonicalProofUploadState::Verifying {
                return Ok(status);
            }
            ensure(
                tokio::time::Instant::now() < deadline,
                "proof worker timed out; retained upload",
            )?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
fn non_cache(store: &RocksDbStore) -> Result<Rows, Error> {
    Ok(store
        .scan_all()?
        .into_iter()
        .filter(|(key, _)| !key.starts_with(CANONICAL_PROOF_CACHE_PREFIX))
        .collect())
}
fn manifest(
    chain: &ChainStore<RocksDbStore>,
    block: ShellHash,
    bytes: &[u8],
) -> Result<CanonicalProofManifest, Error> {
    let manifest = CanonicalProofManifest {
        version: 1,
        chain_id: 10,
        genesis_hash: chain.get_block_hash_by_number(0)?.ok_or("genesis absent")?,
        block_hash: block,
        total_bytes: bytes.len() as u64,
        payload_hash: blake3_hash(bytes),
    };
    manifest.validate()?;
    Ok(manifest)
}
fn save_payload(path: &Path, proof: &CanonicalSignatureBatchProof) -> Result<(), Error> {
    let mut file = BufWriter::new(File::options().write(true).create_new(true).open(path)?);
    serde_json::to_writer(&mut file, proof)?;
    file.flush()?;
    Ok(())
}
async fn produce(
    first: &LoadedEntry,
    second: &LoadedEntry,
    state: &Path,
    native: &Path,
    dir: &Path,
) -> Result<(), Error> {
    ensure(
        !dir.try_exists()?,
        "output exists; use verify to recheck retained artifacts",
    )?;
    std::fs::create_dir(dir)?;
    let context: Context = read(&native.join("context.json"))?;
    {
        let original = RocksDbStore::open_all(native.join("native-db"), None)?;
        let rows = original.state.scan_all()?;
        let stores = RocksDbStore::open_all(dir.join("native-db"), None)?;
        for (key, value) in &rows {
            stores.state.put(key, value)?;
        }
        let block = ChainStore::new(Arc::new(stores.state))
            .get_block_by_hash(&context.block)?
            .ok_or("source block absent")?;
        let mut proof = block_proof(first, second, state, &block)?;
        save_payload(&dir.join("payload.json"), &proof)?;
        proof.transactions[0]
            .signature
            .transaction
            .signature
            .equation
            .matrix
            .polynomials[0]
            .proof_bytes[0] ^= 1;
        save_payload(&dir.join("corrupt-payload.json"), &proof)?;
        ensure(original.state.scan_all()? == rows, "source DB modified")?;
    }
    write(&dir.join("context.json"), &context)?;
    intake(native, dir).await
}
async fn intake(native: &Path, dir: &Path) -> Result<(), Error> {
    let context: Context = read(&dir.join("context.json"))?;
    ensure(
        context == read::<Context>(&native.join("context.json"))?,
        "retained native context changed",
    )?;
    ensure(
        !dir.join("rpc-result.json").try_exists()?,
        "completed intake exists; use verify",
    )?;
    let receiver = Receiver::open(dir, &context, false).await?;
    let before = non_cache(&receiver.node.store)?;
    let bytes = std::fs::read(dir.join("payload.json"))?;
    let valid = manifest(&receiver.node.chain_store, context.block, &bytes)?;
    ensure(
        bytes.len() > CANONICAL_PROOF_CHUNK_BYTES * 2,
        "fixture must exercise chunked transfer",
    )?;
    let (status, result) = request(
        receiver.server.http_addr,
        Some(&receiver.token),
        "admin_beginCanonicalProof",
        json!([valid]),
    )
    .await?;
    ensure(
        status == 200 && result["error"]["code"] == -32601,
        "admin enabled by default",
    )?;
    ensure(
        non_cache(&receiver.node.store)? == before,
        "default RPC changed chain",
    )?;
    receiver.stop().await?;
    let receiver = Receiver::open(dir, &context, true).await?;
    for token in [None, Some("invalid")] {
        let (status, _) = request(
            receiver.server.http_addr,
            token,
            "admin_beginCanonicalProof",
            json!([valid]),
        )
        .await?;
        ensure(status == 401, "unauthenticated intake accepted")?;
    }
    for mut bad in [valid.clone(), valid.clone(), valid.clone(), valid.clone()]
        .into_iter()
        .enumerate()
    {
        match bad.0 {
            0 => bad.1.chain_id += 1,
            1 => bad.1.genesis_hash = ShellHash::ZERO,
            2 => bad.1.block_hash = context.tip,
            _ => bad.1.total_bytes = MAX_CANONICAL_PROOF_BYTES + 1,
        }
        receiver
            .refused("admin_beginCanonicalProof", json!([bad.1]))
            .await?;
    }
    let begun: CanonicalProofUploadStatus = serde_json::from_value(
        receiver
            .call("admin_beginCanonicalProof", json!([valid]))
            .await?,
    )?;
    let id = begun.proof_id;
    // Change only the disposable receiver's source selector, then restore it.
    receiver.node.chain_store.set_canonical(1, &context.tip)?;
    receiver
        .refused("admin_verifyCanonicalProof", json!([id]))
        .await?;
    receiver
        .refused("admin_getCanonicalProofChunk", json!([id, 0]))
        .await?;
    receiver.node.chain_store.set_canonical(1, &context.block)?;

    receiver
        .refused("admin_verifyCanonicalProof", json!([id]))
        .await?;
    receiver
        .append(id, 0, &bytes[..CANONICAL_PROOF_CHUNK_BYTES])
        .await?;
    receiver
        .append(id, 0, &bytes[..CANONICAL_PROOF_CHUNK_BYTES])
        .await?;
    let mut conflicting = bytes[..CANONICAL_PROOF_CHUNK_BYTES].to_vec();
    conflicting[0] ^= 1;
    receiver
        .refused(
            "admin_appendCanonicalProof",
            json!([id, 0, shell_primitives::Bytes::from(conflicting)]),
        )
        .await?;
    for (index, size) in [
        (2, CANONICAL_PROOF_CHUNK_BYTES),
        (1, 1),
        (1, CANONICAL_PROOF_CHUNK_BYTES + 1),
    ] {
        receiver
            .refused(
                "admin_appendCanonicalProof",
                json!([
                    id,
                    index,
                    shell_primitives::Bytes::copy_from_slice(&bytes[..size])
                ]),
            )
            .await?;
    }
    let half = (bytes.len().div_ceil(CANONICAL_PROOF_CHUNK_BYTES) / 2) as u32;
    receiver
        .upload(&dir.join("payload.json"), id, Some(half))
        .await?;
    ensure(
        receiver.status(id).await?.next_chunk == half,
        "partial upload mismatch",
    )?;
    receiver.stop().await?;
    let receiver = Receiver::open(dir, &context, true).await?;
    ensure(
        receiver.status(id).await?.next_chunk == half,
        "partial upload lost on reopen",
    )?;
    receiver.upload(&dir.join("payload.json"), id, None).await?;
    let verified = receiver.verify(id, false).await?;
    ensure(
        verified.state == CanonicalProofUploadState::Verified,
        &format!("full proof rejected: {:?}", verified.error),
    )?;
    let expected: CanonicalProofReplay = read(&native.join("result.json"))?;
    ensure(
        verified.result == Some(serde_json::to_value(&expected)?),
        "RPC replay differs from independent native result",
    )?;
    let corrupt = std::fs::read(dir.join("corrupt-payload.json"))?;
    let invalid = manifest(&receiver.node.chain_store, context.block, &corrupt)?;
    receiver
        .call("admin_beginCanonicalProof", json!([invalid]))
        .await?;
    receiver
        .upload(&dir.join("corrupt-payload.json"), invalid.id(), None)
        .await?;
    let rejected = receiver.verify(invalid.id(), false).await?;
    ensure(
        rejected.state == CanonicalProofUploadState::Rejected && rejected.result.is_none(),
        "corrupt AIR accepted through native fallback",
    )?;
    // Small malformed artifacts also exercise whole-payload hashing before decode.
    let mut mismatch = manifest(&receiver.node.chain_store, context.block, b"{}")?;
    mismatch.payload_hash = ShellHash::ZERO;
    receiver
        .call("admin_beginCanonicalProof", json!([mismatch]))
        .await?;
    receiver.append(mismatch.id(), 0, b"{}").await?;
    let hash_rejected = receiver.verify(mismatch.id(), false).await?;
    ensure(
        hash_rejected.error.as_deref()
            == Some("invalid input: canonical proof payload hash mismatch"),
        "payload hash refusal missing",
    )?;
    let malformed = manifest(&receiver.node.chain_store, context.block, b"{}")?;
    receiver
        .call("admin_beginCanonicalProof", json!([malformed]))
        .await?;
    receiver.append(malformed.id(), 0, b"{}").await?;
    let decode_rejected = receiver.verify(malformed.id(), false).await?;
    ensure(
        decode_rejected.state == CanonicalProofUploadState::Rejected
            && decode_rejected
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("canonical proof payload decode at ")),
        "malformed artifact accepted",
    )?;
    let trailing_bytes = br#"{"version":1,"transactions":[]} {}"#;
    let trailing = manifest(&receiver.node.chain_store, context.block, trailing_bytes)?;
    receiver
        .call("admin_beginCanonicalProof", json!([trailing]))
        .await?;
    receiver.append(trailing.id(), 0, trailing_bytes).await?;
    let trailing_rejected = receiver.verify(trailing.id(), false).await?;
    ensure(
        trailing_rejected.state == CanonicalProofUploadState::Rejected,
        "trailing artifact accepted",
    )?;
    ensure(
        non_cache(&receiver.node.store)? == before,
        "proof intake changed canonical KV",
    )?;
    receiver.stop().await?;
    let receiver = Receiver::open(dir, &context, true).await?;
    ensure(
        receiver.status(id).await? == verified && receiver.status(invalid.id()).await? == rejected,
        "results lost on reopen",
    )?;
    let chunk: shell_primitives::Bytes = serde_json::from_value(
        receiver
            .call("admin_getCanonicalProofChunk", json!([id, 0]))
            .await?,
    )?;
    ensure(
        chunk.as_ref() == &bytes[..CANONICAL_PROOF_CHUNK_BYTES],
        "retained proof chunk changed",
    )?;
    ensure(
        non_cache(&receiver.node.store)? == before,
        "reopen changed canonical KV",
    )?;
    write(
        &dir.join("rpc-result.json"),
        &json!({"version":1,"valid":verified,"corrupt":rejected,
        "hash_rejected":hash_rejected,"decode_rejected":decode_rejected,"trailing_rejected":trailing_rejected,"partial_reopen_chunk":half,
        "canonical_KV_unchanged":true,"admin_default_off":true,"bearer_required":true,"native_result":expected}),
    )?;
    receiver.stop().await?;
    println!(
        "{}",
        json!({"mode":"produce","payload_bytes":bytes.len(),"resumed":true,"real_HTTP":true,"actual_Node_replay":true,"corrupt_AIR_rejected":true,"canonical_KV_unchanged":true})
    );
    Ok(())
}
async fn verify(native: &Path, dir: &Path) -> Result<(), Error> {
    let context: Context = read(&dir.join("context.json"))?;
    let source: Context = read(&native.join("context.json"))?;
    ensure(
        context.block == source.block
            && context.tip == source.tip
            && context.authority_key == source.authority_key,
        "native context changed",
    )?;
    let saved: Value = read(&dir.join("rpc-result.json"))?;
    let id: ShellHash = serde_json::from_value(saved["valid"]["proofId"].clone())?;
    let receiver = Receiver::open(dir, &context, true).await?;
    let before = non_cache(&receiver.node.store)?;
    let bytes = std::fs::read(dir.join("payload.json"))?;
    let expected = manifest(&receiver.node.chain_store, context.block, &bytes)?;
    ensure(
        expected.id() == id && receiver.status(id).await?.manifest == expected,
        "retained payload identity changed",
    )?;
    let checked = receiver.verify(id, true).await?;
    let native_result: CanonicalProofReplay = read(&native.join("result.json"))?;
    ensure(
        checked.state == CanonicalProofUploadState::Verified
            && checked.result == Some(serde_json::to_value(native_result)?),
        "independent RPC recheck failed",
    )?;
    ensure(
        non_cache(&receiver.node.store)? == before,
        "independent recheck changed canonical KV",
    )?;
    let first_receipt = dir.join("recheck-result.json");
    if first_receipt.try_exists()? {
        let previous: CanonicalProofUploadStatus = read(&first_receipt)?;
        ensure(
            previous.proof_id == checked.proof_id
                && previous.manifest == checked.manifest
                && previous.state == CanonicalProofUploadState::Verified
                && previous.error.is_none()
                && previous.result == checked.result
                && previous.verification_attempts < checked.verification_attempts,
            "saved verification receipt differs from current verified result",
        )?;
        write(
            &dir.join(format!("recheck-{}.json", checked.verification_attempts)),
            &checked,
        )?;
    } else {
        write(&first_receipt, &checked)?;
    }
    receiver.stop().await?;
    println!(
        "{}",
        json!({"mode":"verify","actual_Node_reverified":true,"verification_attempts":checked.verification_attempts,"native_crypto_fallback":false,"canonical_KV_unchanged":true})
    );
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(args.len()==6,"usage: mldsa-rpc-proof produce|resume|verify first-graph second-graph account-state native-node output")?;
    let state = Path::new(&args[3]).canonicalize()?;
    let native = Path::new(&args[4]).canonicalize()?;
    let out = std::path::absolute(&args[5])?;
    let parent = out.parent().ok_or("output parent absent")?.canonicalize()?;
    let out = if out.try_exists()? {
        out.canonicalize()?
    } else {
        parent.join(out.file_name().ok_or("output filename absent")?)
    };
    let first_paths = graph::paths(Path::new(&args[1]))?;
    let second_paths = graph::paths(Path::new(&args[2]))?;
    for input in [
        &first_paths.source,
        &first_paths.equation,
        &first_paths.signature,
        &first_paths.sender,
        &first_paths.id,
        &first_paths.entry,
        &second_paths.source,
        &second_paths.equation,
        &second_paths.signature,
        &second_paths.sender,
        &second_paths.id,
        &second_paths.entry,
        &state,
        &native,
    ] {
        let input = input.canonicalize()?;
        ensure(
            !out.starts_with(&input) && !input.starts_with(&out),
            "output overlaps immutable proof or chain input",
        )?;
    }
    match args[0].as_str() {
        "produce" => {
            let (first, _, _) = graph::load(Path::new(&args[1]))?;
            let (second, _, _) = graph::load(Path::new(&args[2]))?;
            produce(&first, &second, &state, &native, &out).await
        }
        "resume" => intake(&native, &out).await,
        "verify" => verify(&native, &out).await,
        _ => Err("unknown RPC proof operation".into()),
    }
}
