//! Consecutive full-quorum admissions with bounded local intake metadata.
use super::*;

pub(super) fn controls(path: &Path) -> Result<Control, Error> {
    let c: Control = read(&path.join("control.cbor"))?;
    ensure(
        c.blocks.len() == 3
            && c.certificates.len() == 3
            && c.blocks[0].number() == 1
            && c.blocks[1].number() == 2
            && c.blocks[1].header.parent_hash == c.blocks[0].hash()
            && c.blocks[2].number() == 3
            && c.blocks[2].header.parent_hash == c.blocks[1].hash(),
        "three genuine signed controls required",
    )?;
    Ok(c)
}

pub(super) fn capture(
    path: &Path,
    provider: &Path,
    output: &Path,
    number: usize,
) -> Result<(), Error> {
    ensure(
        (2..=3).contains(&number),
        "successor source number must be 2 or 3",
    )?;
    let index = number - 1;
    ensure(!output.exists(), "successor source output already exists")?;
    let c = controls(path)?;
    let n = node(provider, &c, false)?;
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
            && n.chain_store.get_finalized_number()? == Some(3),
        "independently finalized Native3 provider required",
    )?;
    let before = n.store.scan_all()?;
    let certificate = n
        .chain_store
        .get_commit_certificate(&c.blocks[index].hash())?
        .ok_or("Native successor certificate absent")?;
    let source = n.commit_quorum_source(number as u64, c.blocks[index].hash(), &certificate)?;
    source.validate()?;
    ensure(
        source.signatures.len() == 1 + usize::from(c.co_authority.is_some()),
        "successor certificate omits an authority",
    )?;
    for signature in &source.signatures {
        ensure(
            MultiVerifier.verify(
                &signature.public_key,
                c.blocks[index].hash().as_bytes(),
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
        json!({"successorSourceCaptured":true,"number":number,"block":c.blocks[index].hash(),"signers":source.signatures.len(),"NativeRowsUnchanged":true,"newSigningOrProving":false})
    );
    Ok(())
}

pub(super) fn expected(
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

pub(super) async fn wait_head(live: &Live, c: &Control, number: usize) -> Result<(), Error> {
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

async fn completed(live: &Live, hash: ShellHash) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            ensure(
                !live.task.is_finished(),
                "receiver exited before completion status",
            )?;
            if let Some(record) = live.node.canonical_admission_status(hash)? {
                if record["status"]["state"] == "complete" {
                    return ensure(
                        record["status"]["attempts"] == 1,
                        "fresh child did not complete one automatic admission",
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}

async fn exercise(args: &[String]) -> Result<(), Error> {
    let cold = args[0] == "successor-cold";
    let count = args.len() - 4;
    ensure(
        (2..=3).contains(&count),
        "two or three successor proofs required",
    )?;
    let c = controls(Path::new(&args[1]))?;
    let root = Path::new(&args[2 + count]);
    ensure(
        root.exists() == cold,
        "successor receiver ownership mismatch",
    )?;
    let mut manifests = Vec::new();
    let mut payloads = Vec::new();
    for index in 0..count {
        let payload = frame(Path::new(&args[2 + index]))?;
        let mut m = manifest(&c, &payload);
        m.block_hash = c.blocks[index].hash();
        manifests.push(m);
        payloads.push(payload);
    }
    let provider = Live::start(Path::new(&args[3 + count]), &c, vec![]).await?;
    let provider_before = canonical_rows(&provider)?;
    let outcome = async {
        upload_all(&provider, &manifests[0], &payloads[0]).await?;
        let receiver = Live::start_mode(&root.join("db"), &c, vec![provider.dial()], true, !cold).await?;
        let outcome = async {
            if !cold {
                wait_head(&receiver, &c, 1).await?;
                completed(&receiver, c.blocks[0].hash()).await?;
                let first = receiver.status(manifests[0].id()).await?;
                expected(&receiver, &provider, &c, 0, &first, c.blocks[0].hash())?;
                for index in 1..count {
                    tokio::time::timeout(Duration::from_secs(60), async {
                        loop {
                            ensure(!receiver.task.is_finished(), "successor receiver exited while waiting")?;
                            if receiver.node.canonical_admission_status(c.blocks[index].hash())?.is_some() {
                                return Ok::<_, Error>(());
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }).await??;
                    let before = canonical_rows(&receiver)?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    ensure(
                        canonical_rows(&receiver)? == before
                            && receiver.node.chain_store.get_head_hash()? == Some(c.blocks[index - 1].hash())
                            && receiver.node.chain_store.get_receipts(&c.blocks[index].hash())?.is_none(),
                        "missing successor proof bypassed admission",
                    )?;
                    let certificate = provider.node.chain_store.get_commit_certificate(&c.blocks[index].hash())?.ok_or("Native successor certificate absent")?;
                    let source = provider.node.commit_quorum_source((index + 1) as u64, c.blocks[index].hash(), &certificate)?;
                    let wrong: CommitQuorumProof = read(Path::new(&args[1 + index]))?;
                    let mut damaged: CommitQuorumProof = read(Path::new(&args[2 + index]))?;
                    *damaged.weight.proof_bytes.first_mut().ok_or("empty successor weight proof")? ^= 1;
                    ensure(
                        shell_stark_prover::commit_quorum::verify_commit_quorum(&wrong, &source).is_err()
                            && shell_stark_prover::commit_quorum::verify_commit_quorum(&damaged, &source).is_err()
                            && canonical_rows(&receiver)? == before,
                        "wrong-block or damaged successor proof accepted or changed state",
                    )?;
                    upload_all(&provider, &manifests[index], &payloads[index]).await?;
                    wait_head(&receiver, &c, index + 1).await?;
                    completed(&receiver, c.blocks[index].hash()).await?;
                    let checked = receiver.status(manifests[index].id()).await?;
                    expected(&receiver, &provider, &c, index, &checked, c.blocks[index].hash())?;
                }
            } else {
                wait_head(&receiver, &c, count).await?;
            }
            let records = receiver.node.store.scan_prefix(b"local/canonical-admission/v1/record/")?;
            ensure(records.len() <= 2, "local admission record bound exceeded")?;
            if count == 3 {
                ensure(receiver.node.canonical_admission_status(c.blocks[0].hash())?.is_none(), "old completed intake record not retired")?;
                ensure(recovery_native_digest(&receiver.node)? == recovery_native_digest(&provider.node)?, "independently executed Native3 rows differ")?;
            }
            for index in 0..count {
                let hash = c.blocks[index].hash();
                ensure(
                    receiver.node.chain_store.get_block_by_hash(&hash)? == provider.node.chain_store.get_block_by_hash(&hash)?
                        && receiver.node.chain_store.get_commit_certificate(&hash)? == provider.node.chain_store.get_commit_certificate(&hash)?
                        && serde_json::to_value(receiver.node.chain_store.get_block_signers(&hash)?)? == serde_json::to_value(provider.node.chain_store.get_block_signers(&hash)?)?
                        && shell_storage::CanonicalProofUploadStore::new(receiver.node.store.clone()).payload(&manifests[index].id())? == payloads[index],
                    "retired target Native evidence or proof availability changed",
                )?;

            }
            balances(&receiver.node, &c, count)?;
            let tip = c.blocks[count - 1].hash();
            let reference = WorldState::at_root(provider.node.store.clone(), &c.blocks[count - 1].header.state_root)?;
            for address in [c.sender, c.recipient, c.authority].into_iter().chain(c.co_authority.as_ref().map(|(a, _)| *a)) {
                ensure(
                    serde_json::to_value(receiver.node.world_state.read().get_account(&address)?)?
                        == serde_json::to_value(reference.get_account(&address)?)?,
                    "successor state differs from independently executed historical state",
                )?;
            }
            let before = canonical_rows(&receiver)?;
            let mut attempts = Vec::new();
            for (index, m) in manifests.iter().enumerate() {
                let old = receiver.status(m.id()).await?;
                let checked = receiver.verify(m.id()).await?;
                expected(&receiver, &provider, &c, index, &checked, tip)?;
                ensure(checked.verification_attempts > old.verification_attempts, "successor history reused cached authorization")?;
                attempts.push(checked.verification_attempts);
            }
            ensure(
                canonical_rows(&receiver)? == before
                    && receiver.node.config.canonical_quorum_admission
                    && receiver.node.chain_store.get_head_hash()? == Some(tip)
                    && receiver.node.chain_store.get_finalized_number()? == Some(count as u64)
                    && (count == 3 || receiver.node.chain_store.get_receipts(&c.blocks[2].hash())?.is_none()),
                "historical verification wrote current state or imported an unproved child",
            )?;
            println!("{}",json!({"consecutiveFullQuorumAdmissions":count,"actualTCPNoise":true,"quorumAdmissionAlwaysEnabled":true,"currentHeight":count,"finalized":count,"retainedAdmissionRecords":records.len(),"oldestIntakeRetired":count==3,"allNativeEvidenceAndProofPayloadsRetained":true,"independentNative3RowsEqual":count==3,"coldProcess":cold,"historicalVerificationAttempts":attempts,"independentNativeHistoricalStateAndReceiptsEqual":true,"historicalRowsUnchanged":true,"unprovedThirdBlockAbsent":count==2,"receiverManualUploadFetchOrFreshVerify":false,"newSigningOrProving":false}));
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
