//! A real Node.run peer import with one backend rejection of the canonical batch.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

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
