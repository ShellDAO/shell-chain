//! A real Node.run peer import with one backend rejection of the canonical batch.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

/// Run the real HTTP proof control without starting the canonical event loop.
/// This gives an orderly, deterministic boundary before a queued request is claimed.
async fn queue_before_loop(
    c: &Control,
    root: &Path,
    manifest: &CanonicalProofManifest,
    old: &CanonicalProofUploadStatus,
    native: ShellHash,
) -> Result<Value, Error> {
    let mut n = node(&root.join("db"), c, false)?;
    n.config.canonical_quorum_admission = true;
    let n = Arc::new(n);
    let token = blake3_hash(DilithiumSigner::generate().public_key()).to_string();
    let (events, _) = tokio::sync::broadcast::channel(16);
    let server = shell_rpc::start_rpc_server_with_proof_control(
        shell_rpc::RpcConfig {
            listen_addr: "127.0.0.1:0".parse()?,
            ws_addr: None,
            api_namespaces: vec!["admin".into()],
            api_key: Some(token.clone()),
            rate_limit_per_sec: None,
            ..Default::default()
        },
        n.chain_store.clone(),
        n.world_state.clone(),
        n.tx_pool.clone(),
        n.config.chain_id,
        None,
        events,
        None,
        None,
        Arc::new(RwLock::new(0)),
        n.finality.clone(),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(n.clone() as Arc<dyn shell_rpc::CanonicalProofControl>),
    )
    .await
    .map_err(|e| e.to_string())?;
    let outcome = async {
        let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
        let rows = n.store.scan_all()?;
        let (http, _) = request(server.http_addr, None, "admin_verifyCanonicalProof", json!([manifest.id(), true])).await?;
        let (authorized, refused) = request(server.http_addr, Some(&token), "admin_verifyCanonicalProof", json!([manifest.id(), false])).await?;
        ensure(http == 401 && authorized == 200 && refused.get("error").is_some()
            && n.store.scan_all()? == rows, "queue-only bearer/false refusal changed retained state")?;
        let (http, response) = request(server.http_addr, Some(&token), "admin_verifyCanonicalProof", json!([manifest.id(), true])).await?;
        ensure(http == 200 && response.get("error").is_none()
            && serde_json::from_value::<CanonicalProofUploadStatus>(response["result"].clone())? == *old,
            "queue-only request started verification or returned a different cache status")?;
        let queued = n.canonical_admission_status(c.blocks[0].hash())?.ok_or("queued admission absent")?;
        ensure(queued["status"]["state"] == "paused"
            && queued["status"]["explicitRecheck"] == serde_json::to_value(manifest.id())?
            && queued["nativeCanonical"] == false && queued["statusIsAuthorization"] == false,
            "authenticated request did not durably queue its exact proof ID")?;
        let queued_rows = n.store.scan_all()?;
        let (http, duplicate) = request(server.http_addr, Some(&token), "admin_verifyCanonicalProof", json!([manifest.id(), true])).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure(http == 200 && duplicate.get("error").is_none()
            && serde_json::from_value::<CanonicalProofUploadStatus>(duplicate["result"].clone())? == *old
            && n.store.scan_all()? == queued_rows && cache.status(&manifest.id())? == *old
            && recovery_native_digest(&n)? == native,
            "duplicate request or RPC-only phase consumed intent or changed canonical state")?;
        recovery_genesis_balances(&n, c)?;
        println!("{}",json!({"explicitIntentQueuedBeforeLoop":true,"verificationAttempts":old.verification_attempts,"sameGeneration":true,"duplicateRequestIdempotent":true,"unauthenticatedAndNonExplicitRefused":true,"noVerifierStarted":true,"canonicalRowsUnchanged":true,"head":0,"finalized":0,"RPCOnlyPhase":true,"operatorProofRPC":true}));
        Ok::<_,Error>(queued)
    }.await;
    server.http_handle.stop()?;
    server.http_handle.clone().stopped().await;
    drop(server);
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&n) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "queue-only RPC retained the backend after orderly stop")?;
    n.store.flush()?;
    outcome
}

/// Preserve an actual authenticated intent across physical reopen, then let Node.run own it.
pub(super) async fn cold_intent_recheck(
    controls: &Path,
    proof: &Path,
    root: &Path,
    reference: &Path,
) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    let payload = frame(proof)?;
    let m = manifest(&c, &payload);
    let reference = node(reference, &c, false)?;
    ensure(
        reference.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && reference.chain_store.get_finalized_number()? == Some(1),
        "independent first-block reference required",
    )?;
    let reference_digest = recovery_native_digest(&reference)?;
    let (old, chunks, native) = {
        let n = node(&root.join("db"), &c, false)?;
        let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
        let old = cache.status(&m.id())?;
        let admission = n
            .canonical_admission_status(c.blocks[0].hash())?
            .ok_or("rejected admission absent")?;
        ensure(
            old.state == CanonicalProofUploadState::Rejected
                && old.result.is_none()
                && old.manifest == m
                && cache.payload(&m.id())? == payload
                && admission["status"]["state"] == "failed"
                && admission["status"]["explicitRecheck"].is_null()
                && n.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && n.chain_store.get_finalized_number()?.unwrap_or(0) == 0,
            "intact unrequested rejected source at genesis required",
        )?;
        recovery_genesis_balances(&n, &c)?;
        let chunks = recovery_chunks(&cache, &old)?;
        (old, chunks, recovery_native_digest(&n)?)
    };
    let unrequested = Live::start_mode(&root.join("db"), &c, vec![], true, false).await?;
    let held = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure(
            unrequested.status(m.id()).await? == old
                && recovery_native_digest(&unrequested.node)? == native,
            "unrequested rejection revived on a live cold start",
        )
    }
    .await;
    unrequested.stop().await?;
    held?;
    let queued = queue_before_loop(&c, root, &m, &old, native).await?;
    {
        let n = node(&root.join("db"), &c, false)?;
        let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
        ensure(
            n.canonical_admission_status(c.blocks[0].hash())? == Some(queued.clone())
                && cache.status(&m.id())? == old
                && cache.payload(&m.id())? == payload
                && recovery_chunks(&cache, &old)? == chunks
                && recovery_native_digest(&n)? == native
                && n.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && n.chain_store.get_finalized_number()?.unwrap_or(0) == 0
                && n.finality.read().last_finalized_number() == 0
                && n.chain_store.get_receipts(&c.blocks[0].hash())?.is_none(),
            "physical cold reopen lost queued intent or started verification/canonical writes",
        )?;
        recovery_genesis_balances(&n, &c)?;
        std::fs::write(
            root.join("queued-intent.json"),
            serde_json::to_vec_pretty(
                &json!({"manifest":m,"old":old,"chunks":chunks,"nativeDigest":native,"queued":queued}),
            )?,
        )?;
        println!(
            "{}",
            json!({"explicitIntentColdPreserved":true,"sameProofID":true,"sameGeneration":true,"allOriginalChunksEqual":true,"verificationAttempts":old.verification_attempts,"canonicalRowsUnchanged":true,"head":0,"finalized":0,"noChildReceipts":true,"physicalColdReopen":true,"orderlyStopOnly":true,"powerLossQualified":false})
        );
    }
    let receiver = Live::start_mode(&root.join("db"), &c, vec![], true, false).await?;
    let outcome = async {
        let checked = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                let status = receiver.status(m.id()).await?;
                if status.verification_attempts > old.verification_attempts
                    && matches!(
                        status.state,
                        CanonicalProofUploadState::Verified | CanonicalProofUploadState::Rejected
                    )
                {
                    return Ok::<_, Error>(status);
                }
                ensure(
                    !receiver.task.is_finished(),
                    "cold intent receiver stopped before consumption",
                )?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let admission = receiver
            .call("admin_canonicalProofAdmission", json!([c.blocks[0].hash()]))
            .await?;
        ensure(
            checked.state == CanonicalProofUploadState::Verified
                && checked.verification_attempts == old.verification_attempts + 1
                && checked.generation == old.generation
                && receiver.status(m.id()).await? == checked
                && checked
                    .result
                    .as_ref()
                    .is_some_and(|v| v["proved_commit_signatures"] == 2)
                && admission["status"]["state"] == "complete"
                && admission["status"]["explicitRecheck"].is_null()
                && recovery_native_digest(&receiver.node)? == reference_digest,
            "cold intent did not undergo one full verification before independent Native commit",
        )?;
        balances(&receiver.node, &c, 1)?;
        Ok::<_, Error>(checked)
    }
    .await;
    receiver.stop().await?;
    let checked = outcome?;
    let again = Live::start_mode(&root.join("db"), &c, vec![], true, false).await?;
    let held = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure(
            again.status(m.id()).await? == checked
                && recovery_native_digest(&again.node)? == reference_digest,
            "completed intent was consumed again on the next live cold start",
        )
    }
    .await;
    again.stop().await?;
    held?;
    let reopened = node(&root.join("db"), &c, false)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(reopened.store.clone());
    ensure(
        cache.status(&m.id())? == checked
            && cache.payload(&m.id())? == payload
            && recovery_chunks(&cache, &checked)? == chunks
            && recovery_native_digest(&reopened)? == reference_digest
            && recovery_native_digest(&reference)? == reference_digest
            && reopened.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && reopened.chain_store.get_finalized_number()? == Some(1)
            && reopened.chain_store.get_receipts(&c.blocks[0].hash())?
                == reference.chain_store.get_receipts(&c.blocks[0].hash())?,
        "persisted cold intent endpoint differs from independent Native receipts/state",
    )?;
    balances(&reopened, &c, 1)?;
    println!(
        "{}",
        json!({"explicitIntentColdConsumedOnce":true,"head":1,"finalized":1,"sameGeneration":true,"allOriginalChunkDigestsEqual":true,"retainedChunks":chunks.len(),"verificationAttempts":checked.verification_attempts,"provedCommitSignatures":2,"persistedIndependentReceiptsBalancesNonceFeesEqual":true,"noRequestDidNotRevive":true,"noThirdAttemptAfterCompletedLiveRestart":true,"canonicalEventLoopOwned":true,"operatorRequestBeforeLoopOnly":true,"noPeerFetch":true,"physicalColdReopen":true,"orderlyStopOnly":true,"powerLossQualified":false,"newAuthoritySigningOrProving":false})
    );
    Ok(())
}

/// An explicit retry must not launder an intact but cryptographically invalid proof.
pub(super) async fn invalid_recheck(
    receiver: &Live,
    c: &Control,
    manifest: &CanonicalProofManifest,
    payload: &[u8],
    root: &Path,
    expected_verifier_error: &str,
) -> Result<(), Error> {
    let old = receiver.status(manifest.id()).await?;
    let native_before = recovery_native_digest(&receiver.node)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
    ensure(
        old.state == CanonicalProofUploadState::Rejected
            && old.verification_attempts == 1
            && old.result.is_none()
            && old
                .error
                .as_ref()
                .is_some_and(|e| e.contains(expected_verifier_error))
            && cache.payload(&manifest.id())? == payload
            && blake3_hash(payload) == manifest.payload_hash,
        "initial refusal was not an intact correctly hashed cryptographic rejection",
    )?;
    let chunks = recovery_chunks(&cache, &old)?;
    let checkpoint = json!({"manifest":manifest,"nativeDigest":native_before,"firstStatus":old,"chunkDigests":chunks,"expectedVerifierError":expected_verifier_error});
    std::fs::write(
        root.join("invalid-recheck.json"),
        serde_json::to_vec_pretty(&checkpoint)?,
    )?;
    let (http, _) = request(
        receiver.address,
        None,
        "admin_verifyCanonicalProof",
        json!([manifest.id(), true]),
    )
    .await?;
    ensure(
        http == 401
            && receiver
                .call("admin_verifyCanonicalProof", json!([manifest.id(), false]))
                .await
                .is_err()
            && receiver.status(manifest.id()).await? == old,
        "unauthenticated or non-explicit request altered rejected proof",
    )?;
    receiver
        .call("admin_verifyCanonicalProof", json!([manifest.id(), true]))
        .await?;
    let checked = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let status = receiver.status(manifest.id()).await?;
            if status.verification_attempts > old.verification_attempts
                && matches!(
                    status.state,
                    CanonicalProofUploadState::Rejected | CanonicalProofUploadState::Verified
                )
            {
                return Ok::<_, Error>(status);
            }
            ensure(
                !receiver.task.is_finished(),
                "receiver stopped before invalid proof recheck",
            )?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let stable = receiver.status(manifest.id()).await?;
    let admission = receiver
        .call("admin_canonicalProofAdmission", json!([c.blocks[0].hash()]))
        .await?;
    ensure(checked.state==CanonicalProofUploadState::Rejected && stable==checked
        && checked.verification_attempts==2 && checked.generation==old.generation
        && checked.result.is_none() && checked.error.as_ref().is_some_and(|e|e.contains(expected_verifier_error))
        && recovery_chunks(&cache,&checked)?==chunks
        && recovery_native_digest(&receiver.node)?==native_before
        && receiver.node.chain_store.get_head_hash()?==Some(c.genesis.hash())
        && receiver.node.chain_store.get_finalized_number()?.unwrap_or(0)==0
        && receiver.node.finality.read().last_finalized_number()==0
        && receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?.is_none()
        && admission["status"]["state"]=="failed" && admission["status"]["explicitRecheck"].is_null()
        && admission["nativeCanonical"]==false && admission["statusIsAuthorization"]==false,
        "explicit retry accepted invalid crypto, wrote partial Native state or repeated automatically")?;
    recovery_genesis_balances(&receiver.node, c)?;
    println!(
        "{}",
        json!({"invalidCryptoExplicitRecheckRejected":true,"initialError":old.error,"recheckError":checked.error,"payloadHashCorrect":true,"completeProofBytes":payload.len(),"sameGeneration":true,"allChunkHashesEqual":true,"verificationAttempts":2,"initialAndExplicitAttemptRejected":true,"weightAIRVerifierReachedBothAttempts":expected_verifier_error=="quorum weight verification:","SLHAIRVerifierReachedBothAttempts":expected_verifier_error=="SHA2 compression verification:","originalWeightStarkBytesPreserved":true,"intentConsumed":true,"noAutomaticThirdAttempt":true,"canonicalRowsUnchanged":true,"head":0,"finalized":0,"inMemoryFinality":0,"noChildReceipts":true,"balancesNonceFeesUnchanged":true,"unauthenticatedAndNonExplicitRefused":true,"operatorProofRPC":true,"actualTCPNoiseBodyAndQC":true,"noNewOriginalSigningOrProving":true})
    );
    Ok(())
}

pub(super) fn invalid_cold(c: &Control, root: &Path) -> Result<(), Error> {
    let saved: Value = serde_json::from_slice(&std::fs::read(root.join("invalid-recheck.json"))?)?;
    let manifest: CanonicalProofManifest = serde_json::from_value(saved["manifest"].clone())?;
    let first: CanonicalProofUploadStatus = serde_json::from_value(saved["firstStatus"].clone())?;
    let chunks: Vec<ShellHash> = serde_json::from_value(saved["chunkDigests"].clone())?;
    let expected_verifier_error = saved["expectedVerifierError"]
        .as_str()
        .unwrap_or("quorum weight verification:");
    let n = node(&root.join("db"), c, false)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
    let status = cache.status(&manifest.id())?;
    let admission = n
        .canonical_admission_status(c.blocks[0].hash())?
        .ok_or("cold pending source absent")?;
    ensure(
        status.state == CanonicalProofUploadState::Rejected
            && status.verification_attempts == 2
            && status.generation == first.generation
            && status.result.is_none()
            && status
                .error
                .as_ref()
                .is_some_and(|e| e.contains(expected_verifier_error))
            && recovery_chunks(&cache, &status)? == chunks
            && saved["nativeDigest"] == serde_json::to_value(recovery_native_digest(&n)?)?
            && blake3_hash(&cache.payload(&manifest.id())?) == manifest.payload_hash
            && n.chain_store.get_head_hash()? == Some(c.genesis.hash())
            && n.chain_store.get_finalized_number()?.unwrap_or(0) == 0
            && n.chain_store.get_receipts(&c.blocks[0].hash())?.is_none()
            && admission["status"]["state"] == "failed"
            && admission["status"]["explicitRecheck"].is_null(),
        "physical cold reopen lost cryptographic refusal or changed Native state",
    )?;
    recovery_genesis_balances(&n, c)?;
    println!(
        "{}",
        json!({"invalidCryptoRecheckColdRefusal":true,"error":status.error,"head":0,"finalized":0,"canonicalRowsUnchanged":true,"sameGeneration":true,"allOriginalChunksPreserved":true,"payloadHashCorrect":true,"verificationAttempts":2,"noChildReceipts":true,"intentConsumed":true,"physicalColdReopen":true})
    );
    Ok(())
}

/// Recheck retained intact rejection through the authenticated operator entry.
pub(super) async fn explicit_recheck(
    controls: &Path,
    proof: &Path,
    root: &Path,
    reference: &Path,
) -> Result<(), Error> {
    let c: Control = read(&controls.join("control.cbor"))?;
    let m = manifest(&c, &frame(proof)?);
    let reference = node(reference, &c, false)?;
    ensure(
        reference.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && reference.chain_store.get_finalized_number()? == Some(1),
        "independent first-block reference required",
    )?;
    let reference_before = recovery_native_digest(&reference)?;
    let (old, old_chunks, native_before) = {
        let initial = node(&root.join("db"), &c, false)?;
        let cache = shell_storage::CanonicalProofUploadStore::new(initial.store.clone());
        let old = cache.status(&m.id())?;
        ensure(
            old.state == CanonicalProofUploadState::Rejected
                && old.manifest == m
                && cache.payload(&m.id())? == frame(proof)?
                && initial.chain_store.get_head_hash()? == Some(c.genesis.hash())
                && initial.chain_store.get_finalized_number()?.unwrap_or(0) == 0,
            "intact rejected source at genesis required",
        )?;
        recovery_genesis_balances(&initial, &c)?;
        let chunks = recovery_chunks(&cache, &old)?;
        (old, chunks, recovery_native_digest(&initial)?)
    };
    let receiver = Live::start_mode(&root.join("db"), &c, vec![], true, false).await?;
    let outcome = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure(receiver.status(m.id()).await? == old
            && recovery_native_digest(&receiver.node)? == native_before,
            "rejected object retried without explicit authorization")?;
        let (http, _) = request(receiver.address, None, "admin_verifyCanonicalProof", json!([m.id(),true])).await?;
        ensure(http == 401, "explicit recheck did not require bearer authorization")?;
        ensure(receiver.call("admin_verifyCanonicalProof",json!([m.id(),false])).await.is_err()
            && receiver.status(m.id()).await? == old
            && recovery_native_digest(&receiver.node)? == native_before,
            "non-explicit recheck changed rejection or Native state")?;
        let queued = receiver.call("admin_verifyCanonicalProof",json!([m.id(),true])).await;
        println!("{}",json!({"explicitIntactRecheckRequested":true,"accepted":queued.is_ok(),"error":queued.as_ref().err().map(|e|e.to_string()),"headBefore":0,"generation":old.generation,"attemptsBefore":old.verification_attempts,"operatorProofRPC":true,"noPeerFetch":true,"noAutomaticMigration":true}));
        queued?;
        let intent=receiver.call("admin_canonicalProofAdmission",json!([c.blocks[0].hash()])).await?;
        ensure(intent["status"]["explicitRecheck"]==serde_json::to_value(m.id())?
            || intent["status"]["state"]=="verifying",
            "operator recheck intent was not durably queued or consumed by event loop")?;
        let checked = tokio::time::timeout(Duration::from_secs(180),async {
            loop {
                let status=receiver.status(m.id()).await?;
                if status.verification_attempts>old.verification_attempts
                    && matches!(status.state,CanonicalProofUploadState::Verified|CanonicalProofUploadState::Rejected) {
                    return Ok::<_,Error>(status);
                }
                ensure(!receiver.task.is_finished(),"receiver stopped before explicit canonical recheck")?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        ensure(checked.state==CanonicalProofUploadState::Verified
            && checked.result.as_ref().is_some_and(|v|v["proved_commit_signatures"]==2)
            && receiver.node.chain_store.get_head_hash()?==Some(c.blocks[0].hash())
            && receiver.node.chain_store.get_finalized_number()?==Some(1)
            && receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?==reference.chain_store.get_receipts(&c.blocks[0].hash())?,
            "explicit recheck did not reach independent atomic canonical endpoint")?;
        balances(&receiver.node,&c,1)?;
        Ok::<_,Error>(())
    }.await;
    receiver.stop().await?;
    outcome?;
    let reopened = node(&root.join("db"), &c, false)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(reopened.store.clone());
    let checked = cache.status(&m.id())?;
    ensure(
        checked.generation == old.generation
            && checked.verification_attempts > old.verification_attempts
            && recovery_chunks(&cache, &checked)? == old_chunks
            && reopened.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
            && reopened.chain_store.get_finalized_number()? == Some(1)
            && reopened.chain_store.get_receipts(&c.blocks[0].hash())?
                == reference.chain_store.get_receipts(&c.blocks[0].hash())?
            && recovery_native_digest(&reference)? == reference_before,
        "cold explicit recheck changed bytes/generation or lost persisted independent result",
    )?;
    balances(&reopened, &c, 1)?;
    println!(
        "{}",
        json!({"explicitIntactRejectedRecheckComplete":true,"head":1,"finalized":1,"sameGeneration":true,"allOriginalChunkDigestsEqual":true,"retainedChunks":old_chunks.len(),"verificationAttempts":checked.verification_attempts,"provedCommitSignatures":2,"persistedIndependentReceiptsBalancesNonceFeesEqual":true,"unauthenticatedAndNonExplicitRefused":true,"noPeerFetch":true,"operatorProofRPC":true,"canonicalEventLoopOwned":true,"physicalColdReopen":true})
    );
    Ok(())
}

pub(super) async fn exercise(
    provider: &Live,
    c: &Control,
    root: &Path,
    manifest: &CanonicalProofManifest,
    state_error: bool,
) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    let store = Arc::new(FailingBatch {
        inner: RocksDbStore::open_all(root.join("db"), None)?.state,
        armed: AtomicBool::new(true),
        attempted: AtomicBool::new(false),
        complete_tuple: AtomicBool::new(false),
        certificate: c.certificates[0].clone(),
        canonical_only: true,
        state_error,
    });
    let initial = node_on_store(store.clone(), c, true)?;
    let digest = recovery_native_digest(&initial)?;
    let receiver = Live::start_on_node(initial, c, vec![provider.dial()], true, false).await?;
    let outcome = async {
        wait_pending(&receiver, c).await?;
        let upload = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                match receiver.status(manifest.id()).await {
                    Ok(s) if store.attempted.load(SeqCst) && matches!(s.state, CanonicalProofUploadState::Rejected | CanonicalProofUploadState::Ready) => return Ok::<_, Error>(s),
                    Ok(_) => {},
                    Err(e) if e.to_string().contains("upload not found") => {},
                    Err(e) => return Err(e),
                }
                ensure(!receiver.task.is_finished(), "receiver exited before final-batch observation")?;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await??;
        // A one-shot fault is now disarmed. A live retry would incorrectly commit here.
        tokio::time::sleep(Duration::from_secs(2)).await;
        ensure(receiver.status(manifest.id()).await?.verification_attempts == 1,
            "failed backend triggered repeated verification in the same process")?;
        let admission = receiver.call("admin_canonicalProofAdmission", json!([c.blocks[0].hash()])).await?;
        ensure(store.complete_tuple.load(SeqCst)
            && recovery_native_digest(&receiver.node)? == digest
            && receiver.node.chain_store.get_head_hash()? == Some(c.genesis.hash())
            && receiver.node.chain_store.get_finalized_number()?.unwrap_or(0) == 0
            && receiver.node.finality.read().last_finalized_number() == 0
            && receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?.is_none(), "final-batch rejection left partial durable or in-memory canonical state")?;
        recovery_genesis_balances(&receiver.node, c)?;
        println!("{}",json!({"observedLiveFinalBatchFailure":true,"completeCanonicalTupleRejected":true,"canonicalRowsUnchanged":true,"head":0,"finalized":0,"inMemoryFinality":0,"noChildReceipts":true,"uploadState":upload.state,"admission":admission,"verificationAttempts":upload.verification_attempts,"noOperatorProofCalls":true,"actualTCPNoise":true}));
        Ok::<_, Error>((upload, admission))
    }.await;
    receiver.stop().await?;
    drop(store);
    let (_, admission) = outcome?;
    let reopened = node(&root.join("db"), c, false)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(reopened.store.clone());
    let upload = cache.status(&manifest.id())?;
    let fetch = cache
        .fetch_status(&manifest.id(), None)?
        .ok_or("retained fetch absent")?;
    ensure(
        recovery_native_digest(&reopened)? == digest
            && upload.verification_attempts == 1
            && upload.received_bytes == manifest.total_bytes
            && upload.result.is_none(),
        "cold final-batch rejection state changed",
    )?;
    recovery_genesis_balances(&reopened, c)?;
    let checkpoint = json!({"mode":"producer-auto-batch-fault","manifest":manifest,"nativeDigest":digest,"upload":upload,"fetch":fetch,"chunkDigests":recovery_chunks(&cache,&upload)?});
    std::fs::write(
        root.join("recovery.json"),
        serde_json::to_vec_pretty(&checkpoint)?,
    )?;
    if state_error {
        ensure(
            upload.state == CanonicalProofUploadState::Rejected
                && admission["status"]["state"] == "failed",
            "non-database state failure did not retain intact rejected candidate",
        )?;
        println!(
            "{}",
            json!({"intactRejectedCandidatePrepared":true,"head":0,"finalized":0,"completeCryptographicVerificationBeforeBackendFailure":true,"verificationAttempts":1,"chunks":upload.next_chunk,"generation":upload.generation,"noCachedAuthorization":true,"physicalColdReopen":true})
        );
        return Ok(());
    }
    ensure(
        upload.state == CanonicalProofUploadState::Ready
            && admission["status"]["state"] == "paused",
        "backend rejection poisoned proof or prevented automatic cold recheck",
    )?;
    println!(
        "{}",
        json!({"liveFinalBatchRollbackRecoverable":true,"head":0,"finalized":0,"canonicalRowsUnchanged":true,"physicalColdReopen":true,"verificationAttempts":1,"noOperatorProofCalls":true,"cachedStatusIsAuthorization":false})
    );
    Ok(())
}
