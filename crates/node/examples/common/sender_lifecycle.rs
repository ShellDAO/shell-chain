//! Genuine sender-job continuation with disposable signed Native controls.
use super::*;
const OWNER: &[u8] = b"local/canonical-production/v1/";

fn controls(path: &Path) -> Result<Control, Error> {
    let c: Control = read(&path.join("control.cbor"))?;
    ensure(
        c.blocks.len() == 3 && c.certificates.len() == 3,
        "three signed controls required",
    )?;
    Ok(c)
}
fn initialize(path: &Path, c: &Control, count: usize, production: bool) -> Result<(), Error> {
    ensure(!path.exists(), "destination exists; refusing replacement")?;
    let mut n = node(path, c, true)?;
    n.config.canonical_proof_production = production;
    n.config.node_role = shell_node::NodeRole::Prover;
    for (block, cert) in c.blocks.iter().zip(&c.certificates).take(count) {
        n.import_block(block.clone(), &MultiVerifier)?;
        ensure(
            n.fast_finalize_with_certificate(block.number(), block.hash(), cert),
            "original Native certificate refused",
        )?;
    }
    balances(&n, c, count)?;
    n.store.flush()?;
    Ok(())
}
fn init(c: &Control, root: &Path) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    initialize(&root.join("owner-db"), c, 2, true)?;
    initialize(&root.join("reference2-db"), c, 2, false)?;
    initialize(&root.join("reference3-db"), c, 3, false)?;
    let owner = node(&root.join("owner-db"), c, false)?;
    let reference = node(&root.join("reference2-db"), c, false)?;
    ensure(
        recovery_native_digest(&owner)? == recovery_native_digest(&reference)?,
        "independent Native2 mismatch",
    )?;
    for b in &c.blocks[..2] {
        let s = owner
            .canonical_production_status(b.hash())?
            .ok_or("publication did not capture sender source")?;
        ensure(
            s["status"]["state"] == "queued" && s["status"]["components"] == 0,
            "initial sender job is not empty",
        )?;
    }
    println!(
        "{}",
        json!({"senderJobsInitialized":2,"NativeHeadAndFinality":2,"independentNativeRowsEqual":true,"seededComponents":0,"newProofMath":0,"privateKeysPersisted":false})
    );
    Ok(())
}
fn immutable_rows(n: &Node<RocksDbStore>) -> Result<Rows, Error> {
    Ok(n.store
        .scan_prefix(OWNER)?
        .into_iter()
        .filter(|(k, _)| {
            k.starts_with(&[OWNER, b"source/"].concat())
                || (k.starts_with(&[OWNER, b"certificates/"].concat())
                    && !k.ends_with(b"/production/index"))
        })
        .collect())
}
fn preserved(old: &Rows, n: &Node<RocksDbStore>) -> Result<(), Error> {
    for (k, v) in old {
        ensure(
            n.store.get(k)?.as_ref() == Some(v),
            "original source/checkpoint bytes changed",
        )?;
    }
    Ok(())
}
fn statuses(n: &Node<RocksDbStore>, c: &Control, count: usize) -> Result<Vec<Value>, Error> {
    c.blocks
        .iter()
        .take(count)
        .map(|b| {
            Ok(n.canonical_production_status(b.hash())?
                .unwrap_or(Value::Null))
        })
        .collect()
}
fn manifest(v: &Value) -> Result<CanonicalProofManifest, Error> {
    ensure(
        v["status"]["state"] == "complete" && v["status"]["error"].is_null(),
        "complete sender job required",
    )?;
    let m: CanonicalProofManifest = serde_json::from_value(v["status"]["manifest"].clone())?;
    ensure(m.version == 1, "sender artifact role required")?;
    Ok(m)
}
async fn step(c: &Control, root: &Path, budget: usize) -> Result<(), Error> {
    ensure((1..=16).contains(&budget), "component budget must be 1..16")?;
    let mut n = node(&root.join("owner-db"), c, false)?;
    let count = n
        .chain_store
        .get_head_block()?
        .ok_or("owner head absent")?
        .number() as usize;
    ensure(matches!(count, 2 | 3), "Native2 or Native3 owner required")?;
    let prior = statuses(&n, c, count)?;
    ensure(
        prior.iter().any(|s| s["status"]["state"] != "complete"),
        "all captured sources already complete; advance or verify history",
    )?;
    let original = immutable_rows(&n)?;
    let native = recovery_native_digest(&n)?;
    n.config.canonical_proof_production = true;
    n.config.canonical_proof_component_budget = std::num::NonZeroUsize::new(budget);
    let live = Live::start_on_node(n, c, vec![], false, false).await?;
    let outcome=async {
        let mut started=false;
        let observed=tokio::time::timeout(Duration::from_secs(10800),async {
            loop {
                ensure(!live.task.is_finished(),"sender node stopped during production")?;
                let s=statuses(&live.node,c,count)?;
                for (current,old) in s.iter().zip(&prior) {
                    let state=current["status"]["state"].as_str().unwrap_or("");
                    ensure(state!="failed",&format!("sender production failed: {current}"))?;
                    started |= matches!(state,"queued"|"proving") || current["status"]["components"].as_u64().unwrap_or(0)>old["status"]["components"].as_u64().unwrap_or(0);
                }
                let spent=s.iter().zip(&prior).filter(|(_,old)| old["status"]["state"]!="complete").map(|(v,_)| v["status"]["newlyProved"].as_u64().unwrap_or(0)).sum::<u64>();
                if s.iter().all(|v| v["status"]["state"]=="complete") || (started && spent>=budget as u64 && s.iter().any(|v|v["status"]["state"]=="paused") && s.iter().all(|v|v["status"]["state"]!="proving")) {
                    ensure(spent<=budget as u64,"sender session exceeded component budget")?;
                    return Ok::<_,Error>(s);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        preserved(&original,&live.node)?;
        ensure(recovery_native_digest(&live.node)?==native,"sender production changed Native rows")?;
        println!("{}",json!({"senderProductionStep":true,"budget":budget,"NativeRowsUnchanged":true,"originalSourceAndCheckpointRowsPreserved":true,"production":observed,"seededComponents":0}));
        Ok::<_,Error>(())
    }.await;
    live.stop().await?;
    outcome
}
async fn advance(c: &Control, root: &Path) -> Result<(), Error> {
    let mut n = node(&root.join("owner-db"), c, false)?;
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[1].hash()),
        "advance requires original Native2 owner",
    )?;
    for s in statuses(&n, c, 2)? {
        let m = manifest(&s)?;
        shell_storage::CanonicalProofUploadStore::new(n.store.clone()).payload(&m.id())?;
    }
    let old = immutable_rows(&n)?;
    n.config.canonical_proof_production = true;
    n.config.canonical_proof_component_budget = std::num::NonZeroUsize::new(1);
    let reference = Live::start(&root.join("reference3-db"), c, vec![]).await?;
    let result=async {
        let follower=Live::start_on_node(n,c,vec![reference.dial()],false,false).await?;
        let result=async {
            successor::wait_head(&follower,c,3).await?;
            ensure(recovery_native_digest(&follower.node)?==recovery_native_digest(&reference.node)?,"peer advance differs from independent Native3")?;
            preserved(&old,&follower.node)?;
            let third=follower.node.canonical_production_status(c.blocks[2].hash())?;
            println!("{}",json!({"senderOwnerAdvanced":true,"actualTCPNoise":true,"NativeHeadAndFinality":3,"independentNative3RowsEqual":true,"oldSourceAndCheckpointRowsPreserved":true,"thirdProduction":third}));
            ensure(third.is_some(),"third sender job absent after certified Native3 publication; owner data retained")
        }.await;
        follower.stop().await?;
        result
    }.await;
    reference.stop().await?;
    result
}
fn snapshot(c: &Control, root: &Path) -> Result<(), Error> {
    let n = node(&root.join("owner-db"), c, false)?;
    let fingerprint = |rows: Rows| -> Result<ShellHash, Error> {
        let entries: Vec<_> = rows
            .into_iter()
            .map(|(k, v)| (k, blake3_hash(&v)))
            .collect();
        Ok(blake3_hash(&serde_json::to_vec(&entries)?))
    };
    let before = fingerprint(n.store.scan_all()?)?;
    let count = n
        .chain_store
        .get_head_block()?
        .ok_or("owner head absent")?
        .number() as usize;
    let production = statuses(&n, c, count)?;
    let mut payloads = vec![];
    for s in &production {
        if s["status"]["state"] == "complete" {
            let m = manifest(s)?;
            let payload =
                shell_storage::CanonicalProofUploadStore::new(n.store.clone()).payload(&m.id())?;
            payloads.push(json!({"manifest":m,"hash":blake3_hash(&payload),"bytes":payload.len()}));
        }
    }
    ensure(
        before == fingerprint(n.store.scan_all()?)?,
        "snapshot query changed owner rows",
    )?;
    let index: Value = serde_json::from_slice(
        &n.store
            .get(&[OWNER, b"jobs"].concat())?
            .ok_or("owner index absent")?,
    )?;
    println!(
        "{}",
        json!({"senderOwnerSnapshot":true,"head":count,"finalized":n.chain_store.get_finalized_number()?,"production":production,"index":index,"payloads":payloads,"allRowsDigest":before,"logicalRowsUnchanged":true,"newProofMath":0})
    );
    Ok(())
}
fn admission_snapshot(c: &Control, root: &Path) -> Result<(), Error> {
    let saved: Value =
        serde_json::from_slice(&std::fs::read(root.join("sender-admission-crash.json"))?)?;
    let n = node(&root.join("receiver-db"), c, false)?;
    let manifest: CanonicalProofManifest = serde_json::from_value(saved["manifest"].clone())?;
    let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
    let upload = cache.status(&manifest.id())?;
    ensure(
        manifest.version == 1
            && manifest.block_hash == c.blocks[0].hash()
            && upload.state == CanonicalProofUploadState::Verifying
            && upload.verification_attempts == 1
            && upload.result.is_none()
            && upload.received_bytes == manifest.total_bytes
            && serde_json::to_value(&upload)? == saved["upload"]
            && serde_json::to_value(recovery_chunks(&cache, &upload)?)? == saved["chunkDigests"]
            && serde_json::to_value(recovery_native_digest(&n)?)? == saved["nativeDigest"]
            && n.chain_store.get_head_hash()? == Some(c.genesis.hash())
            && n.chain_store.get_finalized_number()?.unwrap_or(0) == 0
            && n.chain_store.get_receipts(&c.blocks[0].hash())?.is_none(),
        "sender crash claim/chunks or genesis Native rows changed",
    )?;
    recovery_genesis_balances(&n, c)?;
    println!(
        "{}",
        json!({"senderAdmissionCrashSnapshot":true,"verificationAttempts":1,"head":0,"finalized":0,"allChunksRetained":true,"NativeRowsUnchanged":true,"newProofMath":0})
    );
    Ok(())
}
async fn peer(
    c: &Control,
    root: &Path,
    receiver_directory: Option<&str>,
    crash: bool,
) -> Result<(), Error> {
    let owner = node(&root.join("owner-db"), c, false)?;
    let before = recovery_native_digest(&owner)?;
    let reference = node(&root.join("reference3-db"), c, false)?;
    ensure(
        before == recovery_native_digest(&reference)?,
        "producer differs from independent Native3",
    )?;
    drop(reference);
    let manifests = statuses(&owner, c, 3)?
        .iter()
        .map(manifest)
        .collect::<Result<Vec<_>, _>>()?;
    let original = immutable_rows(&owner)?;
    let provider = Live::start_on_node(owner, c, vec![], false, false).await?;
    let result=async {
        let path=root.join(receiver_directory.unwrap_or("receiver-db"));
        let fresh=!path.exists();
        ensure(!crash || fresh,"crash requires a new receiver; refusing existing data")?;
        let mut n=node(&path,c,fresh)?;
        let initial=recovery_native_digest(&n)?;
        n.config.canonical_proof_admission=true;
        let receiver=Live::start_on_node(n,c,vec![provider.dial()],false,false).await?;
        let result=async {
            if crash {
                let manifest=&manifests[0];
                let cache=shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone());
                let upload=tokio::time::timeout(Duration::from_secs(3600),async {
                    loop {
                        ensure(!receiver.task.is_finished(),"sender receiver stopped before crash claim")?;
                        match cache.status(&manifest.id()) {
                            Ok(s) if s.state==CanonicalProofUploadState::Verifying => return Ok::<_,Error>(s),
                            Ok(s) => ensure(!matches!(s.state,CanonicalProofUploadState::Verified|CanonicalProofUploadState::Rejected),"sender verification completed before crash observation")?,
                            Err(e) if e.to_string().contains("upload not found") => {},
                            Err(e) => return Err(e.into()),
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }).await??;
                let chunks=recovery_chunks(&cache,&upload)?;
                ensure(upload.verification_attempts==1 && upload.result.is_none()
                    && upload.received_bytes==manifest.total_bytes
                    && cache.status(&manifest.id())?==upload
                    && recovery_native_digest(&receiver.node)?==initial
                    && receiver.node.chain_store.get_head_hash()?==Some(c.genesis.hash())
                    && receiver.node.chain_store.get_finalized_number()?.unwrap_or(0)==0
                    && receiver.node.finality.read().last_finalized_number()==0
                    && receiver.node.chain_store.get_receipts(&c.blocks[0].hash())?.is_none(),
                    "sender crash boundary already published or changed")?;
                recovery_genesis_balances(&receiver.node,c)?;
                let checkpoint=json!({"manifest":manifest,"nativeDigest":initial,"upload":upload,"chunkDigests":chunks});
                let file=std::fs::OpenOptions::new().write(true).create_new(true).open(root.join("sender-admission-crash.json"))?;
                serde_json::to_writer_pretty(&file,&checkpoint)?;
                file.sync_all()?;
                println!("{}",json!({"senderAdmissionCrashReady":true,"pid":std::process::id(),"verificationAttempts":1,"head":0,"finalized":0,"actualTCPNoise":true,"allChunksRetained":true,"gracefulNodeShutdown":false,"newProofMath":0}));
                std::io::Write::flush(&mut std::io::stdout())?;
                // The external controller signals only its own child; keep actors running.
                return std::future::pending::<Result<(),Error>>().await;
            }
            let mut two_since=None;
            tokio::time::timeout(Duration::from_secs(3600),async {
                loop {
                    ensure(!receiver.task.is_finished(),"sender receiver stopped")?;
                    let head=receiver.node.chain_store.get_head_block()?.ok_or("receiver head absent")?.number();
                    let finalized=receiver.node.chain_store.get_finalized_number()?;
                    if head==3 && finalized==Some(3) {return Ok::<_,Error>(());}
                    let third=receiver.node.canonical_admission_status(c.blocks[2].hash())?;
                    if head==2 && third.is_none() {
                        let since=two_since.get_or_insert_with(tokio::time::Instant::now);
                        if since.elapsed()>Duration::from_secs(45) {
                            println!("{}",json!({"senderPeerThirdCandidateAbsent":true,"head":head,"finalized":finalized,"admission":c.blocks.iter().map(|b|receiver.node.canonical_admission_status(b.hash())).collect::<Result<Vec<_>,_>>()?,"providerManifests":manifests,"actualTCPNoise":true,"receiverPrefixRetained":true}));
                            return Err("third sender candidate absent while completed candidates remain; receiver prefix retained".into());
                        }
                    } else {two_since=None;}
                    if third.as_ref().is_some_and(|v|v["status"]["state"]=="failed") {
                        return Err(format!("sender third admission failed: {third:?}").into());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }).await??;
            ensure(recovery_native_digest(&receiver.node)?==before,"proof-backed peer differs from independent Native3")?;
            balances(&receiver.node,c,3)?;
            let native=recovery_native_digest(&receiver.node)?;
            let mut attempts=vec![];
            for (block,m) in c.blocks.iter().zip(&manifests) {
                metadata_refusals(&receiver,m,c).await?;
                let prior=receiver.status(m.id()).await?;
                let checked=receiver.verify(m.id()).await?;
                let v=checked.result.as_ref().ok_or("historical sender result absent")?;
                let receipts=receiver.node.chain_store.get_receipts(&block.hash())?.ok_or("historical receipts absent")?;
                ensure(checked.state==CanonicalProofUploadState::Verified
                    && checked.verification_attempts==prior.verification_attempts+1
                    && v["proved_sender_signatures"]==1 && v["proved_proposer_signature"]==true
                    && v["block"]==serde_json::to_value(block.hash())?
                    && v["parent"]==serde_json::to_value(block.header.parent_hash)?
                    && v["tip"]==serde_json::to_value(c.blocks[2].hash())?
                    && v["state_root"]==serde_json::to_value(block.header.state_root)?
                    && v["receipts"]==serde_json::to_value(&receipts)?
                    && provider.node.chain_store.get_receipts(&block.hash())?==Some(receipts),
                    "full historical sender proof differs from independent Native execution")?;
                ensure(shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone()).payload(&m.id())?==shell_storage::CanonicalProofUploadStore::new(provider.node.store.clone()).payload(&m.id())?,"peer proof bytes differ")?;
                attempts.push(checked.verification_attempts);
            }
            preserved(&original,&provider.node)?;
            ensure(recovery_native_digest(&receiver.node)?==native && recovery_native_digest(&provider.node)?==before,"history wrote current Native state")?;
            println!("{}",json!({"senderProducerToPeerComplete":true,"freshPeer":fresh,"actualTCPNoise":true,"automaticAdmission":true,"NativeHeadAndFinality":3,"independentNativeRowsReceiptsBalancesNonceFeesEqual":true,"historyVerificationAttempts":attempts,"historicalNativeRowsUnchanged":true,"producerCheckpointsPreserved":true,"newProofMath":0}));
            Ok::<_,Error>(())
        }.await;
        receiver.stop().await?;
        result
    }.await;
    provider.stop().await?;
    result
}
pub(super) fn run(args: &[String]) -> Result<(), Error> {
    let c = controls(Path::new(&args[1]))?;
    let root = Path::new(&args[2]);
    match args[0].as_str() {
        "sender-history-init" => init(&c, root),
        "sender-history-snapshot" => snapshot(&c, root),
        "sender-admission-snapshot" => admission_snapshot(&c, root),
        _ => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(async {
                match args[0].as_str() {
                    "sender-history-step" => step(&c, root, args[3].parse()?).await,
                    "sender-history-advance" => advance(&c, root).await,
                    "sender-history-peer" => {
                        peer(&c, root, args.get(3).map(String::as_str), false).await
                    }
                    "sender-admission-crash" => peer(&c, root, None, true).await,
                    _ => Err("unknown sender lifecycle command".into()),
                }
            }),
    }
}
