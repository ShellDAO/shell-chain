//! Two consecutive full-quorum admissions without switching to Native sync.
use super::*;

fn controls(path: &Path) -> Result<Control, Error> {
    let c: Control = read(&path.join("control.cbor"))?;
    ensure(
        c.blocks.len() == 3
            && c.certificates.len() == 3
            && c.blocks[0].number() == 1
            && c.blocks[1].number() == 2
            && c.blocks[1].header.parent_hash == c.blocks[0].hash(),
        "three genuine signed controls required",
    )?;
    Ok(c)
}

pub(super) fn capture(path: &Path, provider: &Path, output: &Path) -> Result<(), Error> {
    ensure(!output.exists(), "successor source output already exists")?;
    let c = controls(path)?;
    let n = node(provider, &c, false)?;
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
            && n.chain_store.get_finalized_number()? == Some(3),
        "independently finalized Native3 provider required",
    )?;
    let before = n.store.scan_all()?;
    let source = n.commit_quorum_source(2, c.blocks[1].hash(), &c.certificates[1])?;
    source.validate()?;
    ensure(
        source.signatures.len() == 1 + usize::from(c.co_authority.is_some()),
        "successor certificate omits an authority",
    )?;
    for signature in &source.signatures {
        ensure(
            MultiVerifier.verify(
                &signature.public_key,
                c.blocks[1].hash().as_bytes(),
                &signature.signature,
            )?,
            "successor authority signature invalid",
        )?;
    }
    ensure(
        n.store.scan_all()? == before,
        "successor certificate invalid or source query wrote state",
    )?;
    write(output, &source)?;
    println!(
        "{}",
        json!({"successorSourceCaptured":true,"number":2,"block":c.blocks[1].hash(),"signers":source.signatures.len(),"NativeRowsUnchanged":true,"newSigningOrProving":false})
    );
    Ok(())
}

fn expected(
    receiver: &Live,
    provider: &Live,
    c: &Control,
    index: usize,
    status: &CanonicalProofUploadStatus,
    tip: ShellHash,
) -> Result<(), Error> {
    let block = &c.blocks[index];
    let result = status
        .result
        .as_ref()
        .ok_or("full successor result absent")?;
    let receipts = receiver.node.chain_store.get_receipts(&block.hash())?;
    ensure(
        status.state == CanonicalProofUploadState::Verified
            && result["proved_commit_signatures"] == 1 + usize::from(c.co_authority.is_some())
            && result["execution"]["block"] == serde_json::to_value(block.hash())?
            && result["execution"]["parent"] == serde_json::to_value(block.header.parent_hash)?
            && result["execution"]["state_root"] == serde_json::to_value(block.header.state_root)?
            && result["execution"]["tip"] == serde_json::to_value(tip)?
            && receipts.is_some()
            && receipts == provider.node.chain_store.get_receipts(&block.hash())?
            && result["execution"]["receipts"] == serde_json::to_value(receipts.unwrap())?,
        "successor proof/result/independent receipts mismatch",
    )
}

async fn wait_head(live: &Live, c: &Control, number: usize) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            ensure(!live.task.is_finished(), "successor receiver exited")?;
            if live.node.chain_store.get_head_hash()? == Some(c.blocks[number - 1].hash())
                && live.node.chain_store.get_finalized_number()? == Some(number as u64)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}

async fn exercise(args: &[String]) -> Result<(), Error> {
    let cold = args[0] == "successor-cold";
    let c = controls(Path::new(&args[1]))?;
    let root = Path::new(&args[4]);
    ensure(
        root.exists() == cold,
        "successor receiver ownership mismatch",
    )?;
    let mut manifests = Vec::new();
    let mut payloads = Vec::new();
    for index in 0..2 {
        let payload = frame(Path::new(&args[2 + index]))?;
        let mut m = manifest(&c, &payload);
        m.block_hash = c.blocks[index].hash();
        manifests.push(m);
        payloads.push(payload);
    }
    let provider = Live::start(Path::new(&args[5]), &c, vec![]).await?;
    let provider_before = canonical_rows(&provider)?;
    let outcome = async {
        upload_all(&provider, &manifests[0], &payloads[0]).await?;
        let receiver = Live::start_mode(&root.join("db"), &c, vec![provider.dial()], true, !cold).await?;
        let outcome = async {
            if !cold {
                wait_head(&receiver, &c, 1).await?;
                let first = receiver.status(manifests[0].id()).await?;
                expected(&receiver, &provider, &c, 0, &first, c.blocks[0].hash())?;
                tokio::time::timeout(Duration::from_secs(60), async {
                    loop {
                        if receiver.node.canonical_admission_status(c.blocks[1].hash())?.is_some() {
                            return Ok::<_, Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }).await??;
                let before = canonical_rows(&receiver)?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                ensure(
                    canonical_rows(&receiver)? == before
                        && receiver.node.chain_store.get_head_hash()? == Some(c.blocks[0].hash())
                        && receiver.node.chain_store.get_receipts(&c.blocks[1].hash())?.is_none(),
                    "missing successor proof bypassed admission",
                )?;
                let source = provider.node.commit_quorum_source(2, c.blocks[1].hash(), &c.certificates[1])?;
                let wrong: CommitQuorumProof = read(Path::new(&args[2]))?;
                let mut damaged: CommitQuorumProof = read(Path::new(&args[3]))?;
                *damaged.weight.proof_bytes.first_mut().ok_or("empty successor weight proof")? ^= 1;
                ensure(
                    shell_stark_prover::commit_quorum::verify_commit_quorum(&wrong, &source).is_err()
                        && shell_stark_prover::commit_quorum::verify_commit_quorum(&damaged, &source).is_err()
                        && canonical_rows(&receiver)? == before,
                    "wrong-block or damaged successor proof accepted or changed state",
                )?;
                upload_all(&provider, &manifests[1], &payloads[1]).await?;
                wait_head(&receiver, &c, 2).await?;
                let second = receiver.status(manifests[1].id()).await?;
                expected(&receiver, &provider, &c, 1, &second, c.blocks[1].hash())?;
            } else {
                wait_head(&receiver, &c, 2).await?;
            }
            balances(&receiver.node, &c, 2)?;
            let reference = WorldState::at_root(provider.node.store.clone(), &c.blocks[1].header.state_root)?;
            for address in [c.sender, c.recipient, c.authority].into_iter().chain(c.co_authority.as_ref().map(|(a, _)| *a)) {
                ensure(
                    serde_json::to_value(receiver.node.world_state.read().get_account(&address)?)?
                        == serde_json::to_value(reference.get_account(&address)?)?,
                    "successor state differs from independently executed historical parent",
                )?;
            }
            let before = canonical_rows(&receiver)?;
            let mut attempts = Vec::new();
            for (index, m) in manifests.iter().enumerate() {
                let old = receiver.status(m.id()).await?;
                let checked = receiver.verify(m.id()).await?;
                expected(&receiver, &provider, &c, index, &checked, c.blocks[1].hash())?;
                ensure(checked.verification_attempts > old.verification_attempts, "successor history reused cached authorization")?;
                attempts.push(checked.verification_attempts);
            }
            ensure(
                canonical_rows(&receiver)? == before
                    && receiver.node.config.canonical_quorum_admission
                    && receiver.node.chain_store.get_head_hash()? == Some(c.blocks[1].hash())
                    && receiver.node.chain_store.get_finalized_number()? == Some(2)
                    && receiver.node.chain_store.get_receipts(&c.blocks[2].hash())?.is_none(),
                "historical verification wrote current state or unproved third block imported",
            )?;
            println!("{}",json!({"consecutiveFullQuorumAdmissions":2,"actualTCPNoise":true,"quorumAdmissionAlwaysEnabled":true,"currentHeight":2,"finalized":2,"coldProcess":cold,"historicalVerificationAttempts":attempts,"independentNativeHistoricalStateAndReceiptsEqual":true,"historicalRowsUnchanged":true,"unprovedThirdBlockAbsent":true,"receiverManualUploadFetchOrFreshVerify":false,"newSigningOrProving":false}));
            Ok::<_, Error>(())
        }.await;
        receiver.stop().await?;
        outcome
    }.await;
    let unchanged = canonical_rows(&provider)? == provider_before;
    provider.stop().await?;
    ensure(unchanged, "successor provider Native rows changed")?;
    outcome
}

pub(super) fn run(args: &[String]) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(exercise(args))
}
