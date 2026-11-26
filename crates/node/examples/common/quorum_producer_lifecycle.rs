//! Source-bound completed checkpoints through three real node-owned quorum jobs.
use super::*;
#[path = "quorum_fresh.rs"]
mod fresh;
#[path = "quorum_producer_fault.rs"]
mod owner_fault;

fn certificate_rows(n: &Node<RocksDbStore>, hash: ShellHash) -> Result<Rows, Error> {
    Ok(n.store.scan_prefix(
        &[
            b"local/quorum-production/v1/certificates/".as_slice(),
            hash.as_bytes(),
            b"/",
        ]
        .concat(),
    )?)
}
fn copy_native_snapshot(
    source: &Path,
    destination: &Path,
    c: &Control,
    number: usize,
) -> Result<(), Error> {
    ensure(
        !destination.exists(),
        "Native snapshot destination already exists",
    )?;
    let original = node(source, c, false)?;
    ensure(
        original.chain_store.get_head_hash()? == Some(c.blocks[number - 1].hash())
            && original.chain_store.get_finalized_number()? == Some(number as u64)
            && original.chain_store.get_block_hash_by_number(0)? == Some(c.genesis.hash()),
        "Native snapshot chain/prefix identity mismatch",
    )?;
    let rows: Rows = original
        .store
        .scan_all()?
        .into_iter()
        .filter(|(k, _)| !k.starts_with(b"local/"))
        .collect();
    let stores = RocksDbStore::open_all(destination, None)?;
    ensure(
        stores.state.scan_all()?.is_empty(),
        "Native snapshot destination not empty",
    )?;
    let mut batch = shell_storage::WriteBatch::new();
    for (key, value) in &rows {
        batch.put(key.clone(), value.clone());
    }
    stores.state.write_batch(batch)?;
    stores.state.flush()?;
    ensure(
        stores.state.scan_all()? == rows,
        "Native snapshot copy differs",
    )?;
    // Only a fresh Native-only destination is created. Original databases and
    // every local proof/checkpoint byte remain in their source stores.
    Ok(())
}
fn recover(n: &mut Node<RocksDbStore>, hash: ShellHash, donor: &Path) -> Result<(), Error> {
    let stores = RocksDbStore::open_all(donor.join("db"), None)?;
    let mut job = stores.chain;
    let before = job.scan_all()?;
    let result = n.recover_quorum_production_job(hash, &mut job)?;
    ensure(
        result.components > 0
            && result.newly_proved == 0
            && result.reused >= result.components
            && job.scan_all()? == before,
        "checkpoint recovery changed donor or generated proofs",
    )?;
    println!(
        "{}",
        json!({"checkpointRecovery":hash,"progress":result,"donorLogicalRowsUnchanged":true})
    );
    Ok(())
}
fn owner_index(n: &Node<RocksDbStore>, c: &Control) -> Result<(), Error> {
    let index: Value = serde_json::from_slice(
        &n.store
            .get(b"local/quorum-production/v1/jobs")?
            .ok_or("quorum owner index absent")?,
    )?;
    ensure(
        index["version"] == 2
            && index["active"]
                == serde_json::to_value(vec![c.blocks[1].hash(), c.blocks[2].hash()])?
            && index["completed"] == serde_json::to_value(vec![c.blocks[0].hash()])?,
        "active/history owner index mismatch",
    )
}
fn completed(status: &Value) -> Result<CanonicalProofManifest, Error> {
    ensure(
        status["status"]["state"] == "complete"
            && status["status"]["newlyProved"] == 0
            && status["status"]["components"].as_u64().is_some_and(|n| {
                n > 0 && status["status"]["reused"].as_u64().is_some_and(|r| r >= n)
            }),
        "node producer did not fully reverify the existing complete graph",
    )?;
    Ok(serde_json::from_value(
        status["status"]["manifest"].clone(),
    )?)
}
async fn prepare_prefix(
    c: &Control,
    controls: &Path,
    donors: &[String],
    root: &Path,
) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    let path = root.join("provider-db");
    copy_native_snapshot(
        &controls.join("control-db"),
        &root.join("reference-db"),
        c,
        3,
    )?;
    copy_native_snapshot(&controls.join("prefix2-db"), &path, c, 2)?;
    let mut provider = node(&path, c, false)?;
    for (index, donor) in donors.iter().take(2).enumerate() {
        recover(&mut provider, c.blocks[index].hash(), Path::new(donor))?;
    }
    let native = recovery_native_digest(&provider)?;
    let first = Live::start_on_node(provider, c, vec![], false, true).await?;
    let result = async {
        for block in &c.blocks[..2] {
            completed(&wait_production(&first, block.hash(), false).await?)?;
        }
        ensure(
            recovery_native_digest(&first.node)? == native
                && first.node.chain_store.get_head_hash()? == Some(c.blocks[1].hash()),
            "first two producer jobs changed Native2",
        )?;
        Ok::<_, Error>(())
    }
    .await;
    first.stop().await?;
    result?;
    let offline = node(&path, c, false)?;
    let old = [
        certificate_rows(&offline, c.blocks[0].hash())?,
        certificate_rows(&offline, c.blocks[1].hash())?,
    ];
    drop(offline);
    let reference = Live::start(&root.join("reference-db"), c, vec![]).await?;
    let synced = async {
        let follower = Live::start_mode(&path, c, vec![reference.dial()], false, false).await?;
        let result = async {
            successor::wait_head(&follower, c, 3).await?;
            ensure(
                recovery_native_digest(&follower.node)? == recovery_native_digest(&reference.node)?,
                "certified peer Native3 differs from independent reference",
            )?;
            Ok::<_, Error>(())
        }
        .await;
        follower.stop().await?;
        result
    }
    .await;
    reference.stop().await?;
    synced?;
    let provider = node(&path, c, false)?;
    ensure(
        certificate_rows(&provider, c.blocks[0].hash())? == old[0]
            && certificate_rows(&provider, c.blocks[1].hash())? == old[1],
        "ordinary certified sync changed original checkpoints",
    )?;
    drop(provider);
    println!(
        "{}",
        json!({"providerAdvancedViaActualCertifiedPeer":true,"NativeHeadAndFinality":3,"selectorAndTimeoutUnchanged":true})
    );
    Ok(())
}
async fn prepare_owned(
    c: &Control,
    controls: &Path,
    donors: &[String],
    root: &Path,
) -> Result<(), Error> {
    prepare_prefix(c, controls, donors, root).await?;
    queue_and_recover_third(c, Path::new(&donors[2]), root).await
}
async fn queue_and_recover_third(c: &Control, donor: &Path, root: &Path) -> Result<(), Error> {
    ensure(
        !root.join("receiver-db").exists(),
        "receiver already exists; use the completed cold flow",
    )?;
    let path = root.join("provider-db");
    let provider = node(&path, c, false)?;
    ensure(
        provider.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
            && provider.chain_store.get_finalized_number()? == Some(3),
        "Native3 provider required for third-source recovery",
    )?;
    let native = recovery_native_digest(&provider)?;
    let reference = node(&root.join("reference-db"), c, false)?;
    ensure(
        native == recovery_native_digest(&reference)?,
        "Native3 differs from independent reference",
    )?;
    drop(reference);
    let old = [
        certificate_rows(&provider, c.blocks[0].hash())?,
        certificate_rows(&provider, c.blocks[1].hash())?,
    ];
    println!(
        "{}",
        json!({"thirdStatusBeforeReadinessProbe":provider.quorum_production_status(c.blocks[2].hash())?,"Native3PrefixRetained":true})
    );
    drop(provider);
    // The normal multi-authority no-peer readiness gate holds the CPU worker.
    // Startup still captures the real third finalized source before readiness.
    let mut probe_node = node(&path, c, false)?;
    probe_node.config.network_type = shell_genesis::NetworkType::Testnet;
    let probe = Live::start_on_node(probe_node, c, vec![], false, true).await?;
    let result = async {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                ensure(
                    !probe.task.is_finished(),
                    "producer exited before capture completed",
                )?;
                let status = probe
                    .call("admin_quorumProofProduction", json!([c.blocks[2].hash()]))
                    .await?;
                if status["status"]["state"] == "queued" {
                    ensure(
                        status["status"]["components"] == 0,
                        "capture probe generated checkpoints before readiness",
                    )?;
                    return Ok::<_, Error>(());
                }
                ensure(
                    status.is_null(),
                    "third source entered unexpected state before readiness",
                )?;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await??;
        owner_index(&probe.node, c)?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        ensure(
            certificate_rows(&probe.node, c.blocks[2].hash())?.is_empty()
                && recovery_native_digest(&probe.node)? == native,
            "readiness probe generated third checkpoints or changed Native3",
        )?;
        Ok::<_, Error>(())
    }
    .await;
    probe.stop().await?;
    result?;
    let mut provider = node(&path, c, false)?;
    ensure(
        certificate_rows(&provider, c.blocks[0].hash())? == old[0]
            && certificate_rows(&provider, c.blocks[1].hash())? == old[1],
        "completed donor checkpoints changed during automatic index roll",
    )?;
    let status = provider
        .quorum_production_status(c.blocks[2].hash())?
        .ok_or("third source absent after readiness probe")?;
    ensure(
        status["status"]["components"] == 0 && status["status"]["newlyProved"] == 0,
        "probe did new third proof math",
    )?;
    recover(&mut provider, c.blocks[2].hash(), donor)?;
    owner_index(&provider, c)?;
    ensure(
        recovery_native_digest(&provider)? == native,
        "third job recovery changed Native",
    )?;
    provider.store.flush()?;
    println!(
        "{}",
        json!({"automaticThirdSourceCapturedBeforeReadiness":true,"noPeerMultiAuthorityProbe":true,"newProofMath":0,"oldCheckpointRowsPreserved":true,"NativeRowsUnchanged":true})
    );
    Ok(())
}
async fn exercise(args: &[String]) -> Result<(), Error> {
    let from_empty = args[0].starts_with("producer-fresh-");
    if from_empty
        && !matches!(
            args[0].as_str(),
            "producer-fresh-peer" | "producer-fresh-cold"
        )
    {
        return fresh::exercise(args).await;
    }
    if args[0].starts_with("producer-history-") {
        return owner_fault::exercise(args).await;
    }
    let cold = matches!(
        args[0].as_str(),
        "producer-successor-cold" | "producer-fresh-cold"
    );
    let resume = args[0] == "producer-successor-resume";
    let c = successor::controls(Path::new(&args[1]))?;
    ensure(
        c.co_authority.is_some(),
        "producer lifecycle requires genuine two-authority controls",
    )?;
    let root = Path::new(&args[if from_empty { 2 } else { 5 }]);
    ensure(
        root.exists() == (cold || resume || from_empty),
        "producer lifecycle destination ownership mismatch",
    )?;
    if resume {
        queue_and_recover_third(&c, Path::new(&args[4]), root).await?;
    } else if !cold && !from_empty {
        prepare_owned(&c, Path::new(&args[1]), &args[2..5], root).await?;
    }
    let path = root.join("provider-db");
    let offline = node(&path, &c, false)?;
    let native = recovery_native_digest(&offline)?;
    let mut original = Vec::new();
    for block in &c.blocks {
        original.push(certificate_rows(&offline, block.hash())?);
    }
    owner_index(&offline, &c)?;
    drop(offline);
    let provider = Live::start_production(&path, &c, vec![], false, false, true).await?;
    let result = async {
        let mut manifests = Vec::new();
        let mut production = Vec::new();
        for block in &c.blocks {
            let status = wait_production(&provider,block.hash(),cold || from_empty).await?;
            manifests.push(completed(&status)?);
            production.push(status);
        }
        owner_index(&provider.node,&c)?;
        let reference = node(&root.join("reference-db"),&c,false)?;
        ensure(recovery_native_digest(&provider.node)? == native && native == recovery_native_digest(&reference)?, "producer Native3 differs from independent execution")?;
        for (index, block) in c.blocks.iter().enumerate() {
            ensure(certificate_rows(&provider.node,block.hash())? == original[index], "cold/active producer rewrote original checkpoints")?;
        }
        let receiver_exists = root.join("receiver-db/CURRENT").is_file();
        let receiver = Live::start_mode(&root.join("receiver-db"),&c,vec![provider.dial()],true,!(cold||from_empty&&receiver_exists)).await?;
        let result = async {
            successor::wait_head(&receiver,&c,3).await?;
            ensure(recovery_native_digest(&receiver.node)? == native, "fresh peer Native3 differs from independent provider")?;
            balances(&receiver.node,&c,3)?;
            let before = canonical_rows(&receiver)?;
            let mut attempts=Vec::new();
            for (index, manifest) in manifests.iter().enumerate() {
                let old=receiver.status(manifest.id()).await?;
                ensure(if from_empty {old.verification_attempts>=1}else{old.verification_attempts == if cold {2}else{1}}, "unexpected history authorization attempts before explicit full check")?;
                let checked=receiver.verify(manifest.id()).await?;
                successor::expected(&receiver,&provider,&c,index,&checked,c.blocks[2].hash())?;
                ensure(checked.verification_attempts == old.verification_attempts+1, "historical proof did not run a new full check")?;
                ensure(shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone()).payload(&manifest.id())? == shell_storage::CanonicalProofUploadStore::new(provider.node.store.clone()).payload(&manifest.id())?, "node-owned availability bytes differ at peer")?;
                attempts.push(checked.verification_attempts);
            }
            ensure(canonical_rows(&receiver)? == before && recovery_native_digest(&receiver.node)? == native && receiver.node.chain_store.get_finalized_number()? == Some(3), "full historical recheck changed current Native3")?;
            println!("{}",json!({"nodeOwnedQuorumJobs":3,"activeJobs":2,"completedHistoryJobs":1,"productionEntry":args[0],"production":production,"newProofMath":0,"automaticThirdCaptureProbeThisProcess":!cold&&!from_empty,"actualTCPNoise":true,"freshPeerImportThisProcess":!cold&&!receiver_exists,"receiverManualUploadOrFetch":false,"NativeHeadAndFinality":3,"independentNative3RowsEqual":true,"originalCheckpointRowsPreserved":true,"historyVerificationAttempts":attempts,"historicalNativeRowsUnchanged":true,"coldProcess":cold,"senderOwnerUntouched":provider.node.store.scan_prefix(b"local/canonical-production/v1/")?.is_empty()}));
            Ok::<_, Error>(())
        }.await;
        receiver.stop().await?;
        result
    }.await;
    let unchanged = recovery_native_digest(&provider.node)? == native;
    provider.stop().await?;
    ensure(
        unchanged,
        "producer changed Native while serving historical proofs",
    )?;
    result
}
pub(super) fn run(args: &[String]) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise(args))
}
