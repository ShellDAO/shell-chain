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
async fn peer(c: &Control, root: &Path, receiver_directory: Option<&str>) -> Result<(), Error> {
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
        let mut n=node(&path,c,fresh)?;
        n.config.canonical_proof_admission=true;
        let receiver=Live::start_on_node(n,c,vec![provider.dial()],false,false).await?;
        let result=async {
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
        _ => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(async {
                match args[0].as_str() {
                    "sender-history-step" => step(&c, root, args[3].parse()?).await,
                    "sender-history-advance" => advance(&c, root).await,
                    "sender-history-peer" => peer(&c, root, args.get(3).map(String::as_str)).await,
                    _ => Err("unknown sender lifecycle command".into()),
                }
            }),
    }
}
