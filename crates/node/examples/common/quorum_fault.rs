//! A real Node.run peer import with one backend rejection of the canonical batch.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

pub(super) async fn exercise(
    provider: &Live,
    c: &Control,
    root: &Path,
    manifest: &CanonicalProofManifest,
) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    let store = Arc::new(FailingBatch {
        inner: RocksDbStore::open_all(root.join("db"), None)?.state,
        armed: AtomicBool::new(true),
        attempted: AtomicBool::new(false),
        complete_tuple: AtomicBool::new(false),
        certificate: c.certificates[0].clone(),
        canonical_only: true,
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
