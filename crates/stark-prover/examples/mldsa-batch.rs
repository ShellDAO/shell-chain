//! Verify a real ordered native batch over complete authenticated entry graphs.
#[path = "common/mldsa_batch.rs"]
mod graph;
#[path = "common/mldsa_source.rs"]
mod source;
use graph::{load, paths};
use serde::{Deserialize, Serialize};
use shell_crypto::{MlDsaSigner, MlDsaVerifier, PQSignature, SignatureType, Signer, Verifier};
use shell_stark_prover::{
    blake3_hash::{verify_transaction_signing_hash, Blake3HashProof},
    compute_batch_root,
    mldsa_source::{verify_authenticated_sig_batch, verify_signature_entry},
    prove_sig_batch, verify_sig_batch, SigBatchEntry, SigBatchProof,
};
use source::{read, write, Error, Identity, Source};
use std::{io::Write, path::Path};

fn init_second(template: &Path, dir: &Path) -> Result<(), Error> {
    let p = paths(template)?;
    let original: Source = read(&p.source.join("source.json"))?;
    let first: Identity = read(&p.source.join("identity.json"))?;
    let tag = SignatureType::MlDsa65.as_u8();
    if original.version != 1
        || original.sig_type != tag
        || original.transaction.tx_type > 3
        || first.version != 1
        || first.public_key.len() != 1952
        || first.message.len() != 32
    {
        return Err("invalid canonical template identity/source".into());
    }
    let message = original.transaction.signing_hash(tag);
    if first.message.as_slice() != message.as_bytes() {
        return Err("template signing message mismatch".into());
    }
    let hash: Blake3HashProof = read(&p.source.join("transaction-hash.json"))?;
    verify_transaction_signing_hash(&hash, &original.transaction, tag, message.as_bytes())?;
    let mut generated = false;
    if !dir.try_exists()? {
        std::fs::create_dir_all(dir)?;
        let signer = MlDsaSigner::generate();
        let public_key = signer.public_key().to_vec();
        if public_key[..32] == first.public_key[..32] {
            return Err("second rho must be distinct".into());
        }
        let signature = signer.sign(message.as_bytes())?.data;
        write(
            &dir.join("identity.json"),
            &Identity {
                version: 1,
                public_key: public_key.clone(),
                message: message.as_bytes().to_vec(),
                signature,
            },
        )?;
        write(
            &dir.join("source.json"),
            &Source {
                version: 1,
                transaction: original.transaction.clone(),
                sig_type: tag,
                public_key_hash: *blake3::hash(&public_key).as_bytes(),
            },
        )?;
        generated = true;
    }
    let second: Identity = read(&dir.join("identity.json"))?;
    let s: Source = read(&dir.join("source.json"))?;
    if second.version != 1
        || s.version != 1
        || second.public_key.len() != 1952
        || second.signature.len() != 3309
        || second.message != first.message
        || second.public_key[..32] == first.public_key[..32]
        || s.transaction != original.transaction
        || s.sig_type != tag
        || s.public_key_hash != *blake3::hash(&second.public_key).as_bytes()
        || s.transaction.signing_payload(tag) != hash.message
    {
        return Err("second source is not a distinct equivalent-payload identity".into());
    }
    if !MlDsaVerifier.verify(
        &second.public_key,
        &second.message,
        &PQSignature::new(SignatureType::MlDsa65, second.signature),
    )? {
        return Err("second identity failed native signature control".into());
    }
    let old = std::fs::read(p.source.join("transaction-hash.json"))?;
    let destination = dir.join("transaction-hash.json");
    if !destination.try_exists()? {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        file.write_all(&old)?;
        file.sync_all()?;
    }
    if std::fs::read(&destination)? != old {
        return Err("transaction-hash checkpoint differs from equivalent template".into());
    }
    println!(
        "{}",
        serde_json::json!({"mode":"init-second","new_public_identity":generated,"distinct_rho":true,
        "canonical_payload_byte_equivalent":true,"transaction_hash_checkpoint_reused":true,"transaction_compressions_reused":hash.compressions.len(),
        "new_signature_native_control":true,"private_key_serialized":false,"proofs_generated":0})
    );
    Ok(())
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BatchSource {
    version: u8,
    transaction_ids: Vec<[u8; 32]>,
    batch_root: [u8; 32],
}
fn checkpoint(
    path: &Path,
    proving: bool,
    entries: &[SigBatchEntry],
    count: &mut usize,
) -> Result<SigBatchProof, Error> {
    if proving && !path.try_exists()? {
        write(path, &prove_sig_batch(entries)?)?;
        *count += 1;
    }
    let proof: SigBatchProof = read(path)?;
    if proof.version != 2
        || proof.n_sigs != entries.len()
        || proof.batch_root_bytes != compute_batch_root(entries)
    {
        return Err("native accumulator control inputs differ".into());
    }
    verify_sig_batch(&proof)?;
    Ok(proof)
}
fn reject(
    cases: &mut Vec<serde_json::Value>,
    name: &str,
    result: Result<(), String>,
    phase: &str,
) -> Result<(), Error> {
    let error = result
        .err()
        .ok_or_else(|| format!("{name}: invalid batch accepted"))?;
    if !error.starts_with(phase) {
        return Err(format!("{name}: {error}").into());
    }
    cases.push(serde_json::json!({"case":name,"error":error}));
    Ok(())
}
fn report(mode: &std::ffi::OsStr, source: &BatchSource, proof: &SigBatchProof, generated: usize) {
    let proving = mode == "prove";
    println!(
        "{}",
        serde_json::json!({"mode":mode.to_string_lossy(),"authenticated_ordered_batch_verified":true,"actual_distinct_signed_sources":2,"batch_count":proof.n_sigs,"batch_root":source.batch_root,"transaction_ids":source.transaction_ids,"native_accumulator_proof_bytes":proof.proof_bytes.len(),"newly_proved":generated,"native_producer_control":proving,"native_hash_or_signature_acceptance_fallback":false,"canonical_chain_membership_proved":false,"account_authority_proved":false,"Reference_proved":false,"private_witness":false,"node_integrated":false})
    );
}
fn run(mode: &std::ffi::OsStr, first: &Path, second: &Path, dir: &Path) -> Result<(), Error> {
    let (first, first_identity, first_paths) = load(first)?;
    let (second, second_identity, _) = load(second)?;
    let verified = vec![first.verify()?, second.verify()?];
    if first.id == second.id
        || first_identity.public_key[..32] == second_identity.public_key[..32]
        || first.leaf == second.leaf
    {
        return Err(
            "qualification requires two distinct actual canonical identities/rho/leaves".into(),
        );
    }
    if mode == "verify" {
        let source: BatchSource = read(&dir.join("batch-source.json"))?;
        if source.version != 1 {
            return Err("invalid expected batch source version".into());
        }
        let proof: SigBatchProof = read(&dir.join("batch-proof.json"))?;
        verify_authenticated_sig_batch(
            &proof,
            &verified,
            &source.transaction_ids,
            &source.batch_root,
        )?;
        report(mode, &source, &proof, 0);
        return Ok(());
    }
    let proving = mode == "prove";
    let mut generated = 0;
    let plain = vec![
        SigBatchEntry::from_signed_transaction(&first.expected),
        SigBatchEntry::from_signed_transaction(&second.expected),
    ];
    if proving {
        std::fs::create_dir_all(dir)?;
        let control = BatchSource {
            version: 1,
            transaction_ids: vec![
                *first.expected.hash().as_bytes(),
                *second.expected.hash().as_bytes(),
            ],
            batch_root: compute_batch_root(&plain),
        };
        let path = dir.join("batch-source.json");
        if !path.try_exists()? {
            write(&path, &control)?;
        }
        if read::<BatchSource>(&path)? != control {
            return Err("saved batch expectation differs from native producer control".into());
        }
    }
    let source: BatchSource = read(&dir.join("batch-source.json"))?;
    if source.version != 1 {
        return Err("invalid expected batch source version".into());
    }
    let proof = if proving {
        checkpoint(&dir.join("batch-proof.json"), true, &plain, &mut generated)?
    } else {
        read(&dir.join("batch-proof.json"))?
    };
    verify_authenticated_sig_batch(
        &proof,
        &verified,
        &source.transaction_ids,
        &source.batch_root,
    )?;
    let reverse = vec![plain[1].clone(), plain[0].clone()];
    let duplicate = vec![plain[0].clone(), plain[0].clone()];
    let mut foreign = plain.clone();
    foreign[1].pk_hash[31] ^= 1;
    if proving {
        for (name, entries) in [
            ("reverse", reverse.as_slice()),
            ("duplicate", duplicate.as_slice()),
            ("dropped", &plain[..1]),
            ("foreign", foreign.as_slice()),
        ] {
            checkpoint(
                &dir.join(format!("{name}-proof.json")),
                true,
                entries,
                &mut generated,
            )?;
        }
    }
    if mode == "check-rejections" {
        let reverse_proof = checkpoint(
            &dir.join("reverse-proof.json"),
            false,
            &reverse,
            &mut generated,
        )?;
        let duplicate_proof = checkpoint(
            &dir.join("duplicate-proof.json"),
            false,
            &duplicate,
            &mut generated,
        )?;
        let drop_proof = checkpoint(
            &dir.join("dropped-proof.json"),
            false,
            &plain[..1],
            &mut generated,
        )?;
        let foreign_proof = checkpoint(
            &dir.join("foreign-proof.json"),
            false,
            &foreign,
            &mut generated,
        )?;
        let mut reversed = verified.clone();
        reversed.reverse();
        let mut ids = source.transaction_ids.clone();
        ids.reverse();
        verify_authenticated_sig_batch(
            &reverse_proof,
            &reversed,
            &ids,
            &reverse_proof.batch_root_bytes,
        )?;
        let mut cases = Vec::new();
        reject(
            &mut cases,
            "honest_reverse_wrong_canonical_order",
            verify_authenticated_sig_batch(
                &reverse_proof,
                &reversed,
                &source.transaction_ids,
                &reverse_proof.batch_root_bytes,
            ),
            "authenticated batch source order",
        )?;
        reject(
            &mut cases,
            "reordered_verified_sources",
            verify_authenticated_sig_batch(
                &proof,
                &reversed,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "authenticated batch source order",
        )?;
        let dup = vec![verified[0].clone(), verified[0].clone()];
        let dupids = vec![first.id, first.id];
        reject(
            &mut cases,
            "honest_duplicate_even_with_duplicate_expected_IDs",
            verify_authenticated_sig_batch(
                &duplicate_proof,
                &dup,
                &dupids,
                &duplicate_proof.batch_root_bytes,
            ),
            "duplicate authenticated batch",
        )?;
        reject(
            &mut cases,
            "honest_dropped_source",
            verify_authenticated_sig_batch(
                &drop_proof,
                &verified[..1],
                &source.transaction_ids,
                &drop_proof.batch_root_bytes,
            ),
            "invalid authenticated batch source count",
        )?;
        reject(
            &mut cases,
            "honest_foreign_leaf_native_proof",
            verify_authenticated_sig_batch(
                &foreign_proof,
                &verified,
                &source.transaction_ids,
                &foreign_proof.batch_root_bytes,
            ),
            "authenticated batch root",
        )?;
        let empty = SigBatchProof::commitment_only([0; 32], 0);
        reject(
            &mut cases,
            "empty_batch",
            verify_authenticated_sig_batch(&empty, &[], &[], &[0; 32]),
            "invalid authenticated batch source count",
        )?;
        let mut changed = proof.clone();
        changed.version += 1;
        reject(
            &mut cases,
            "proof_version",
            verify_authenticated_sig_batch(
                &changed,
                &verified,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "invalid authenticated batch proof version",
        )?;
        let mut changed = proof.clone();
        changed.n_sigs += 1;
        reject(
            &mut cases,
            "claimed_count",
            verify_authenticated_sig_batch(
                &changed,
                &verified,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "invalid authenticated batch source count",
        )?;
        let mut changed = source.transaction_ids.clone();
        changed[1][31] ^= 1;
        reject(
            &mut cases,
            "expected_ID",
            verify_authenticated_sig_batch(&proof, &verified, &changed, &source.batch_root),
            "authenticated batch source order",
        )?;
        let mut changed = source.batch_root;
        changed[31] ^= 1;
        reject(
            &mut cases,
            "expected_root",
            verify_authenticated_sig_batch(&proof, &verified, &source.transaction_ids, &changed),
            "authenticated batch root",
        )?;
        let mut changed = proof.clone();
        changed.batch_root_bytes[31] ^= 1;
        reject(
            &mut cases,
            "proof_root",
            verify_authenticated_sig_batch(
                &changed,
                &verified,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "authenticated batch root",
        )?;
        let mut changed = proof.clone();
        let i = changed.proof_bytes.len() / 2;
        changed.proof_bytes[i] ^= 1;
        reject(
            &mut cases,
            "actual_proof_bytes",
            verify_authenticated_sig_batch(
                &changed,
                &verified,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "batch accumulator:",
        )?;
        let commitment = SigBatchProof::commitment_only(source.batch_root, 2);
        reject(
            &mut cases,
            "correct_commitment_without_STARK",
            verify_authenticated_sig_batch(
                &commitment,
                &verified,
                &source.transaction_ids,
                &source.batch_root,
            ),
            "batch accumulator:",
        )?;
        let bad: Identity = read(&first_paths.rejection.join("identity.json"))?;
        if bad.version != 1
            || bad.public_key != first_identity.public_key
            || bad.message != first_identity.message
            || bad.signature.len() != 3309
            || bad.signature == first_identity.signature
            || bad.signature[..3248] != first_identity.signature[..3248]
        {
            return Err("invalid honest altered-hint control".into());
        }
        let mut altered = first.expected.clone();
        altered.signature.data = bad.signature;
        if MlDsaVerifier
            .verify(&bad.public_key, &bad.message, &altered.signature)
            .unwrap_or(false)
        {
            return Err("invalid signature native control accepted".into());
        }
        let entry = SigBatchEntry::from_signed_transaction(&altered);
        if entry.msg_hash != first.entry.msg_hash
            || entry.pk_hash != first.entry.pk_hash
            || entry.to_leaf_bytes() != first.leaf
        {
            return Err("honest invalid signature changed native leaf".into());
        }
        let mut changed = first.proof.clone();
        changed
            .identified
            .sender
            .transaction
            .signature
            .equation
            .signature = read(&first_paths.rejection.join("signature.json"))?;
        changed
            .identified
            .sender
            .transaction
            .signature
            .completion
            .finish = read(&first_paths.rejection.join("finish.json"))?;
        changed
            .identified
            .sender
            .transaction
            .signature
            .completion
            .commitment = read(&first_paths.rejection.join("commitment.json"))?;
        reject(
            &mut cases,
            "honest_invalid_signature_preserves_valid_native_batch_root",
            verify_signature_entry(
                &changed,
                &altered,
                &first.key_hash,
                &first.id,
                &first.entry,
                &first.leaf,
            )
            .map(|_| ()),
            "signature: final commitment:",
        )?;
        println!(
            "{}",
            serde_json::json!({"mode":"check-rejections","actual_two_distinct_full_entry_graphs_verified":true,"honest_native_controls":4,"honest_reverse_positive_verified":true,"invalid_signature_native_control":true,"rejected":cases,"proofs_generated":0,"input_files_read_only":true})
        );
        return Ok(());
    }
    report(mode, &source, &proof, generated);
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = args.first().ok_or("missing mode")?;
    if mode == "verify-entry" && args.len() == 2 {
        let (loaded, _, _) = load(Path::new(&args[1]))?;
        let verified = loaded.verify()?;
        println!(
            "{}",
            serde_json::json!({"mode":"verify-entry","full_graph_verified":true,"transaction_id":verified.transaction_id(),"leaf":verified.leaf_bytes(),"proofs_generated":0,"native_acceptance_fallback":false})
        );
        return Ok(());
    }
    if mode == "init-second" && args.len() == 3 {
        return init_second(Path::new(&args[1]), Path::new(&args[2]));
    }
    if args.len() != 4 || (mode != "prove" && mode != "verify" && mode != "check-rejections") {
        return Err("usage: mldsa-batch verify-entry graph; mldsa-batch init-second template-graph second-source-dir; mldsa-batch prove|verify|check-rejections first-graph second-graph batch-dir (graph is a directory or version1 path manifest)".into());
    }
    run(
        mode,
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )
}
