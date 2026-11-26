//! Empty-checkpoint quorum production through the real bounded Node worker.
use super::*;
const OWNER: &[u8] = b"local/quorum-production/v1/";

fn immutable(n: &Node<RocksDbStore>) -> Result<Rows, Error> {
    Ok(n.store
        .scan_prefix(OWNER)?
        .into_iter()
        .filter(|(k, _)| {
            k.starts_with(&[OWNER, b"source/"].concat())
                || k.starts_with(&[OWNER, b"account-parts/"].concat())
                || (k.starts_with(&[OWNER, b"certificates/"].concat())
                    && !k.ends_with(b"/production/index"))
        })
        .collect())
}
fn preserve(old: &Rows, n: &Node<RocksDbStore>) -> Result<(), Error> {
    for (key, value) in old {
        ensure(
            n.store.get(key)?.as_ref() == Some(value),
            "existing quorum source/checkpoint bytes changed",
        )?;
    }
    Ok(())
}
fn statuses(n: &Node<RocksDbStore>, c: &Control, count: usize) -> Result<Vec<Value>, Error> {
    c.blocks
        .iter()
        .take(count)
        .map(|b| Ok(n.quorum_production_status(b.hash())?.unwrap_or(Value::Null)))
        .collect()
}
fn manifest(v: &Value) -> Result<CanonicalProofManifest, Error> {
    ensure(
        v["status"]["state"] == "complete" && v["status"]["error"].is_null(),
        "complete quorum source required",
    )?;
    let m: CanonicalProofManifest = serde_json::from_value(v["status"]["manifest"].clone())?;
    ensure(m.version == 2, "full quorum manifest required")?;
    Ok(m)
}
async fn init(c: &Control, controls: &Path, root: &Path, genesis: bool) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    if !genesis {
        copy_native_snapshot(
            &controls.join("prefix2-db"),
            &root.join("provider-db"),
            c,
            2,
        )?;
    }
    copy_native_snapshot(
        &controls.join("control-db"),
        &root.join("reference-db"),
        c,
        3,
    )?;
    let n = node(&root.join("provider-db"), c, genesis)?;
    let height = if genesis { 0 } else { 2 };
    ensure(
        n.chain_store
            .get_head_block()?
            .ok_or("head absent")?
            .number()
            == height
            && n.chain_store.get_finalized_number()?.unwrap_or(0) == height,
        "initial Native height mismatch",
    )?;
    ensure(
        n.store.scan_prefix(OWNER)?.is_empty()
            && n.store
                .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                .is_empty()
            && n.store
                .scan_prefix(b"local/canonical-production/v1/")?
                .is_empty(),
        "empty owner/cache/sender namespace required",
    )?;
    let native = recovery_native_digest(&n)?;
    let off = Live::start_on_node(n, c, vec![], false, false).await?;
    let result = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ensure(
            !off.task.is_finished()
                && off.node.store.scan_prefix(OWNER)?.is_empty()
                && off.node.store.scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?.is_empty()
                && recovery_native_digest(&off.node)? == native,
            "default-off Node captured/proved or changed Native",
        )?;
        println!("{}",json!({"freshQuorumInitialized":true,"NativeHeadAndFinality":height,"defaultOffObserved":true,"initialComponents":0,"initialSources":0,"proofCacheEmpty":true,"seededJobs":0,"privateKeysPersisted":false}));
        Ok::<_, Error>(())
    }.await;
    off.stop().await?;
    result
}
async fn follow(c: &Control, root: &Path) -> Result<(), Error> {
    let reference = Live::start(&root.join("reference-db"), c, vec![]).await?;
    let result = async {
        let off_path = root.join("default-off-db");
        let off = Live::start_mode(
            &off_path,
            c,
            vec![reference.dial()],
            false,
            !off_path.join("CURRENT").is_file(),
        )
        .await?;
        let result = async {
            successor::wait_head(&off, c, 3).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            ensure(
                off.node.store.scan_prefix(OWNER)?.is_empty()
                    && off
                        .node
                        .store
                        .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                        .is_empty()
                    && off
                        .node
                        .store
                        .scan_prefix(b"local/canonical-production/v1/")?
                        .is_empty()
                    && recovery_native_digest(&off.node)?
                        == recovery_native_digest(&reference.node)?,
                "default-off live arrival generated proofs or mismatched Native3",
            )?;
            Ok::<_, Error>(())
        }
        .await;
        off.stop().await?;
        result?;
        let mut n = node(&root.join("provider-db"), c, false)?;
        let starting = n
            .chain_store
            .get_head_block()?
            .ok_or("head absent")?
            .number();
        ensure(
            starting <= 3 && n.chain_store.get_block_hash_by_number(0)? == Some(c.genesis.hash()),
            "matching genesis provider required",
        )?;
        let old = immutable(&n)?;
        n.config.canonical_proof_component_budget = std::num::NonZeroUsize::new(2);
        let live = Live::start_on_node(n, c, vec![reference.dial()], false, true).await?;
        let result = async {
            successor::wait_head(&live, c, 3).await?;
            let observed = tokio::time::timeout(Duration::from_secs(10800), async {
                loop {
                    ensure(!live.task.is_finished(), "live genesis producer stopped")?;
                    let values = statuses(&live.node, c, 3)?;
                    ensure(
                        values.iter().all(|v| v["status"]["state"] != "failed"),
                        "live genesis source generation failed",
                    )?;
                    if values[0]["status"]["state"] == "paused"
                        && values[0]["status"]["components"].as_u64().unwrap_or(0) >= 2
                        && values[1]["status"]["state"] == "queued"
                    {
                        return Ok::<_, Error>(values);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await??;
            tokio::time::sleep(Duration::from_millis(500)).await;
            ensure(
                observed == statuses(&live.node, c, 3)?
                    && observed[2].is_null()
                    && observed[1]["status"]["components"] == 0
                    && observed[0]["status"]["newlyProved"].as_u64().unwrap_or(0) <= 2,
                "third source was not stably deferred behind two unfinished jobs",
            )?;
            let index: Value = serde_json::from_slice(
                &live
                    .node
                    .store
                    .get(&[OWNER, b"jobs"].concat())?
                    .ok_or("owner index absent")?,
            )?;
            let expected = serde_json::to_value(vec![c.blocks[0].hash(), c.blocks[1].hash()])?;
            ensure(
                index == expected
                    || (index["version"] == 2
                        && index["active"] == expected
                        && index["completed"] == json!([])),
                "deferred live source index mismatch",
            )?;
            preserve(&old, &live.node)?;
            ensure(
                live.node
                    .store
                    .scan_prefix(CANONICAL_PROOF_CACHE_PREFIX)?
                    .is_empty()
                    && recovery_native_digest(&live.node)?
                        == recovery_native_digest(&reference.node)?,
                "deferred production changed Native3 or published an incomplete proof",
            )?;
            println!(
                "{}",
                json!({"liveGenesisSourceCapture":true,"startingNativeHead":starting,
                "NativeHeadAndFinality":3,"actualTCPNoise":true,"defaultOffLiveArrivalEmpty":true,
                "production":observed,"index":index,"thirdSourceDeferred":true,
                "Native3RowsEqual":true,"originalSourceComponentRowsPreserved":true,
                "newlyProvedThisProcess":observed[0]["status"]["newlyProved"],"seededJobs":0})
            );
            Ok::<_, Error>(())
        }
        .await;
        live.stop().await?;
        result
    }
    .await;
    reference.stop().await?;
    result
}
async fn step(c: &Control, root: &Path, budget: usize) -> Result<(), Error> {
    ensure((1..=16).contains(&budget), "component budget must be 1..16")?;
    let mut n = node(&root.join("provider-db"), c, false)?;
    let count = n
        .chain_store
        .get_head_block()?
        .ok_or("head absent")?
        .number() as usize;
    ensure(
        matches!(count, 2 | 3),
        "Native2 or Native3 provider required",
    )?;
    let prior = statuses(&n, c, count)?;
    let target = prior
        .iter()
        .position(|v| v["status"]["state"] != "complete")
        .ok_or("all sources complete; use advance or peer")?;
    let native = recovery_native_digest(&n)?;
    let old = immutable(&n)?;
    n.config.canonical_proof_component_budget = std::num::NonZeroUsize::new(budget);
    let live = Live::start_on_node(n, c, vec![], false, true).await?;
    let result=async {
        let mut started=false;
        let observed=tokio::time::timeout(Duration::from_secs(10800),async {
            loop {
                ensure(!live.task.is_finished(),"quorum worker stopped")?;
                let values=statuses(&live.node,c,count)?;
                for v in &values {
                    let state=v["status"]["state"].as_str().unwrap_or("");
                    ensure(state!="failed",&format!("fresh quorum production failed: {v}"))?;
                }
                started |= values[target]["status"]["state"]=="proving"
                    || values[target]["status"]["components"].as_u64().unwrap_or(0)>prior[target]["status"]["components"].as_u64().unwrap_or(0);
                let spent=values.iter().map(|v|v["status"]["newlyProved"].as_u64().unwrap_or(0)).sum::<u64>();
                let complete=values.iter().all(|v|v["status"]["state"]=="complete");
                let stopped=started && spent>=budget as u64
                    && values.iter().any(|v|v["status"]["state"]=="paused")
                    && values.iter().all(|v|v["status"]["state"]!="proving");
                if complete || stopped {
                    ensure(spent<=budget as u64,"quorum session exceeded component budget")?;
                    return Ok::<_,Error>(values);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        preserve(&old,&live.node)?;
        ensure(recovery_native_digest(&live.node)?==native,"production changed Native")?;
        println!("{}",json!({"freshQuorumStep":true,"budget":budget,"newlyProvedThisProcess":observed.iter().map(|v|v["status"]["newlyProved"].as_u64().unwrap_or(0)).sum::<u64>(),"production":observed,"NativeRowsUnchanged":true,"existingSourceCheckpointRowsPreserved":true,"seededJobs":0}));
        Ok::<_,Error>(())
    }.await;
    live.stop().await?;
    result
}
async fn advance(c: &Control, root: &Path) -> Result<(), Error> {
    let n = node(&root.join("provider-db"), c, false)?;
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[1].hash()),
        "advance requires Native2",
    )?;
    let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
    for status in statuses(&n, c, 2)? {
        let m = manifest(&status)?;
        cache.payload(&m.id())?;
    }
    let old = immutable(&n)?;
    let reference = Live::start(&root.join("reference-db"), c, vec![]).await?;
    let result=async {
        let follower=Live::start_on_node(n,c,vec![reference.dial()],false,false).await?;
        let result=async {
            successor::wait_head(&follower,c,3).await?;
            preserve(&old,&follower.node)?;
            ensure(recovery_native_digest(&follower.node)?==recovery_native_digest(&reference.node)?,"certified peer Native3 differs from independent reference")?;
            println!("{}",json!({"freshQuorumAdvanced":true,"actualTCPNoise":true,"NativeHeadAndFinality":3,"oldSourceCheckpointRowsPreserved":true,"independentNative3RowsEqual":true,"newProofMath":0}));
            Ok::<_,Error>(())
        }.await;
        follower.stop().await?;
        result
    }.await;
    reference.stop().await?;
    result
}
fn snapshot(c: &Control, root: &Path) -> Result<(), Error> {
    let n = node(&root.join("provider-db"), c, false)?;
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
        .ok_or("head absent")?
        .number() as usize;
    ensure(matches!(count, 2 | 3), "Native2 or Native3 required")?;
    let production = statuses(&n, c, count)?;
    let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
    let mut payloads = vec![];
    for v in &production {
        if v["status"]["state"] == "complete" {
            let m = manifest(v)?;
            let bytes = cache.payload(&m.id())?;
            payloads.push(json!({"manifest":m,"hash":blake3_hash(&bytes),"bytes":bytes.len()}));
        }
    }
    if count == 3 && payloads.len() == 3 {
        owner_index(&n, c)?;
    }
    let index: Option<Value> = n
        .store
        .get(&[OWNER, b"jobs"].concat())?
        .map(|v| serde_json::from_slice(&v))
        .transpose()?;
    ensure(
        before == fingerprint(n.store.scan_all()?)?,
        "snapshot changed logical rows",
    )?;
    println!(
        "{}",
        json!({"freshQuorumSnapshot":true,"head":count,"finalized":n.chain_store.get_finalized_number()?,"production":production,"index":index,"payloads":payloads,"allRowsDigest":before,"immutableRowsDigest":fingerprint(immutable(&n)?)?,"NativeDigest":recovery_native_digest(&n)?,"logicalRowsUnchanged":true,"newProofMath":0})
    );
    Ok(())
}
pub(super) async fn exercise(args: &[String]) -> Result<(), Error> {
    let controls = Path::new(&args[1]);
    let c = successor::controls(controls)?;
    ensure(
        c.co_authority.is_some(),
        "genuine two-authority controls required",
    )?;
    let root = Path::new(&args[2]);
    match args[0].as_str() {
        "producer-fresh-init" => init(&c, controls, root, false).await,
        "producer-fresh-genesis-init" => init(&c, controls, root, true).await,
        "producer-fresh-follow" => follow(&c, root).await,
        "producer-fresh-step" => step(&c, root, args[3].parse()?).await,
        "producer-fresh-advance" => advance(&c, root).await,
        "producer-fresh-snapshot" => snapshot(&c, root),
        _ => Err("unknown fresh producer command".into()),
    }
}
