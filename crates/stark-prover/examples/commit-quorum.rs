//! Separate source-bound RocksDB quorum proof jobs; never a Native chain store.
use serde::{de::DeserializeOwned, Serialize};
use shell_stark_prover::commit_quorum::{
    prove_commit_quorum_persistent, prove_commit_quorum_persistent_reusing,
    reverify_commit_quorum_persistent, verify_commit_quorum, CommitQuorumProof, CommitQuorumSource,
};
use shell_storage::{KvStore, MemoryDb, RocksDbStore, WriteBatch};
use std::{
    io::{Read, Write},
    num::NonZeroUsize,
    path::Path,
};

type Error = Box<dyn std::error::Error>;
type Rows = Vec<(Vec<u8>, Vec<u8>)>;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Err("quorum input exceeds artifact bound".into());
    }
    let mut reader = std::io::BufReader::new(file);
    let value = ciborium::de::from_reader(&mut reader)?;
    if reader.read(&mut [0])? != 0 {
        return Err("trailing quorum artifact bytes".into());
    }
    Ok(value)
}
fn encoded(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("quorum output exceeds artifact bound".into());
    }
    Ok(bytes)
}
fn write(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    if path.exists() {
        return check_output(path, value);
    }
    let bytes = encoded(value)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn check_output(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    let bytes = encoded(value)?;
    let mut existing = Vec::new();
    std::fs::File::open(path)?
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut existing)?;
    if existing != bytes {
        return Err("refusing conflicting quorum output".into());
    }
    Ok(())
}
fn new_root(root: &Path, source: &CommitQuorumSource) -> Result<(), Error> {
    std::fs::create_dir(root)?;
    write(&root.join("source.cbor"), source)
}
fn existing_root(root: &Path, source: &CommitQuorumSource) -> Result<(), Error> {
    if root.is_symlink()
        || root.join("source.cbor").is_symlink()
        || root.join("db").is_symlink()
        || !root.join("db/CURRENT").is_file()
        || read::<CommitQuorumSource>(&root.join("source.cbor"))? != *source
    {
        return Err("quorum job ownership/source mismatch".into());
    }
    Ok(())
}
fn output_preflight(output: &Path, source: &CommitQuorumSource) -> Result<(), Error> {
    if output.exists() {
        let proof: CommitQuorumProof = read(output)?;
        verify_commit_quorum(&proof, source)?;
        // Also reject a differently encoded existing output before opening a job.
        check_output(output, &proof)?;
    }
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify-wire") if args.len()==3 => {
            let source:CommitQuorumSource=read(Path::new(&args[1]))?;
            let proof:CommitQuorumProof=read(Path::new(&args[2]))?;
            verify_commit_quorum(&proof,&source)?;
            check_output(Path::new(&args[2]),&proof)?;
            let payload=shell_stark_prover::commit_quorum::payload::encode(&proof,shell_core::MAX_CANONICAL_PROOF_BYTES as usize)?;
            let restored=shell_stark_prover::commit_quorum::payload::decode(&payload)?;
            verify_commit_quorum(&restored,&source)?;
            if shell_stark_prover::commit_quorum::payload::encode(&restored,payload.len())?!=payload {return Err("quorum wire roundtrip changed bytes".into());}
            println!("{}",serde_json::json!({"fullWeightAndSignatureAIRVerified":true,"proofVersion":proof.version,"originalProofCBORUnchanged":true,"payloadRoundtripByteEqual":true,"signers":source.signatures.len(),"newSigningOrProving":false}));
        }
        Some("checkpoints") if args.len()==3 => {
            let source:CommitQuorumSource=read(Path::new(&args[1]))?;
            let root=Path::new(&args[2]);existing_root(root,&source)?;
            let stores=RocksDbStore::open_all(root.join("db"),None)?;let mut job=stores.chain;
            let before=job.scan_all()?;
            let result=reverify_commit_quorum_persistent(&mut job,&source);
            if job.scan_all()?!=before {return Err("read-only checkpoint verification changed logical rows".into());}
            let retained=before.iter().filter(|(key,_)|key.starts_with(b"production/component/")).count();
            println!("{}",serde_json::json!({"checkpointReplayReadOnly":true,"complete":result.is_ok(),"retainedComponents":retained,"nativeAuthorization":false,"firstRefusal":result.as_ref().err().map(ToString::to_string)}));
            let(proof,progress)=result?;verify_commit_quorum(&proof,&source)?;
            if progress.newly_proved!=0 {return Err("read-only checkpoint verification generated a component".into());}
        }
        Some("restore") if args.len() == 4 => {
            let source: CommitQuorumSource = read(Path::new(&args[1]))?;
            let root = Path::new(&args[3]);
            if root.exists() || root.is_symlink() { return Err("restore requires a new separate job directory".into()); }
            let rows: Rows = read(Path::new(&args[2]))?;
            let mut memory = MemoryDb::new();
            for (key, value) in &rows {
                if memory.get(key)?.is_some() { return Err("duplicate checkpoint key".into()); }
                memory.put(key, value)?;
            }
            // A damaged/incomplete donor refuses before any persistent job opens.
            let (_, checked) = reverify_commit_quorum_persistent(&mut memory, &source)?;
            if checked.newly_proved != 0 || memory.scan_all()? != rows { return Err("checkpoint preflight wrote rows".into()); }
            new_root(root, &source)?;
            let stores = RocksDbStore::open_all(root.join("db"), None)?;
            let mut job = stores.chain;
            let mut batch = WriteBatch::new();
            for (key, value) in &rows { batch.put(key.clone(), value.clone()); }
            job.write_batch(batch)?;
            job.flush()?;
            let (_, progress) = reverify_commit_quorum_persistent(&mut job, &source)?;
            if progress.newly_proved != 0 || job.scan_all()? != rows { return Err("RocksDB checkpoint differs from original rows".into()); }
            println!("{}", serde_json::json!({"checkpointMigrated":true,"freshGeneration":false,"nativeAuthorization":false,"progress":progress}));
        }
        Some("prove-reusing") if args.len() == 6 || args.len() == 7 => {
            let source: CommitQuorumSource = read(Path::new(&args[1]))?;
            let donor_source: CommitQuorumSource = read(Path::new(&args[4]))?;
            let root=Path::new(&args[2]);let output=Path::new(&args[3]);let donor_root=Path::new(&args[5]);
            let limit=args.get(6).map(|v|v.parse::<NonZeroUsize>()).transpose()?;
            output_preflight(output,&source)?;
            existing_root(donor_root,&donor_source)?;
            if root == donor_root { return Err("donor and destination must be separate".into()); }
            if root.exists() || root.is_symlink() { existing_root(root,&source)?; }
            else { new_root(root,&source)?; }
            let stores=RocksDbStore::open_all(root.join("db"),None)?;
            let donor_stores=RocksDbStore::open_all(donor_root.join("db"),None)?;
            let mut job=stores.chain;let mut donor=donor_stores.chain;
            let before=donor.scan_all()?;
            let result=prove_commit_quorum_persistent_reusing(&mut job,&source,limit,&mut donor,&donor_source);
            if donor.scan_all()? != before { return Err("donor logical rows changed".into()); }
            let (proof,progress)=result?;
            verify_commit_quorum(&proof,&source)?;
            write(output,&proof)?;
            println!("{}",serde_json::json!({"fullSignatureAndWeightAirVerified":true,"donorRowsUnchanged":true,"nativeAuthorization":false,"progress":progress}));
        }
        Some("prove" | "verify") if args.len() == 4 || (args[0] == "prove" && args.len() == 5) => {
            let source: CommitQuorumSource = read(Path::new(&args[1]))?;
            let limit = args.get(4).map(|v| v.parse::<NonZeroUsize>()).transpose()?;
            let root = Path::new(&args[2]);
            let output = Path::new(&args[3]);
            output_preflight(output, &source)?;
            let verify_only = args[0] == "verify";
            if verify_only && !output.is_file() { return Err("verification requires an existing proof output".into()); }
            if root.exists() || root.is_symlink() { existing_root(root, &source)?; }
            else if verify_only { return Err("verification requires an existing quorum job".into()); }
            else { new_root(root, &source)?; }
            let stores = RocksDbStore::open_all(root.join("db"), None)?;
            let mut job = stores.chain;
            let before = job.scan_all()?;
            let (proof, progress) = if verify_only {
                reverify_commit_quorum_persistent(&mut job, &source)?
            } else {
                prove_commit_quorum_persistent(&mut job, &source, limit)?
            };
            verify_commit_quorum(&proof, &source)?;
            if (verify_only || progress.newly_proved == 0) && job.scan_all()? != before {
                return Err("checkpoint reuse changed logical job rows".into());
            }
            if verify_only { check_output(output, &proof)?; }
            else { write(output, &proof)?; }
            println!("{}", serde_json::json!({"fullSignatureAndWeightAirVerified":true,"verificationOnly":verify_only,"nativeAuthorization":false,"progress":progress}));
        }
        _ => return Err("usage: commit-quorum checkpoints <source.cbor> <existing-job-directory> | verify-wire <source.cbor> <proof.cbor> | prove-reusing <source.cbor> <separate-job-directory> <proof.cbor> <donor-source.cbor> <donor-job-directory> [component-limit] | restore <source.cbor> <completed-job-rows.cbor> <new-job-directory> | prove <source.cbor> <separate-job-directory> <proof.cbor> [component-limit] | verify <source.cbor> <existing-job-directory> <proof.cbor>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn verification_output_comparison_never_initializes_missing_output() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("quorum-output-{}-{nonce}.cbor", std::process::id()));
        assert!(!path.exists());
        assert!(super::check_output(&path, &7u32).is_err());
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod quorum_payload_boundaries {
    use shell_primitives::ShellHash;
    use shell_stark_prover::{
        commit_quorum::{payload, CommitQuorumProof},
        weighted_quorum::{QuorumWeightContext, QuorumWeightProof},
    };
    fn untrusted_fixture() -> CommitQuorumProof {
        // Codec data only: empty signer/context lists cannot authenticate a quorum.
        CommitQuorumProof {
            version: 1,
            weight: QuorumWeightProof {
                version: 1,
                context: QuorumWeightContext {
                    chain_id: 1337,
                    parent_hash: ShellHash::ZERO,
                    block_hash: ShellHash::ZERO,
                    block_number: 1,
                    authorities: vec![],
                    signers: vec![],
                },
                prefixes: vec![[0, 0]],
                proof_bytes: vec![1, 2],
            },
            signatures: vec![],
            slh_signatures: vec![],
        }
    }
    #[test]
    fn slh_payload_domain_and_signer_bound_do_not_grant_cryptographic_authority() {
        use shell_stark_prover::{
            commit_quorum::slh::CommitSlhProof,
            slh_fors::{SlhForsInputs, SlhForsProof},
            slh_signature::SlhSignatureManifest,
        };
        let input = SlhForsInputs {
            public_seed: [1; 32],
            public_root: [2; 32],
            message: [3; 32],
            signature: vec![],
        };
        let raw = CommitSlhProof {
            version: 2,
            manifest: SlhSignatureManifest::new(input.clone()),
            fors: SlhForsProof {
                version: 1,
                inputs: input,
                hashes: vec![],
            },
            layers: vec![],
        };
        let mut proof = untrusted_fixture();
        proof.version = 2;
        proof.slh_signatures = vec![raw.clone()];
        let encoded = payload::encode(&proof, 16_384).unwrap();
        assert!(encoded.starts_with(b"\0commit-quorum/cbor/v2/"));
        assert_eq!(payload::decode(&encoded).unwrap().slh_signatures.len(), 1);
        let prefix = b"\0commit-quorum/cbor/v2/";
        let wrong = [
            b"\0commit-quorum/cbor/v1/".as_slice(),
            &encoded[prefix.len()..],
        ]
        .concat();
        assert!(payload::decode(&wrong).is_err());
        proof.version = 1;
        assert!(payload::encode(&proof, 16_384).is_err());
        proof.version = 2;
        proof.slh_signatures = vec![raw; 17];
        assert!(payload::encode(&proof, 16_384).is_err());
    }
    #[test]
    fn exact_budget_domain_trailer_and_noncanonical_map() {
        let proof = untrusted_fixture();
        let encoded = payload::encode(&proof, 4096).unwrap();
        assert!(payload::decode(&encoded).is_ok());
        assert_eq!(payload::encode(&proof, encoded.len()).unwrap(), encoded);
        assert!(payload::encode(&proof, encoded.len() - 1).is_err());
        let mut bad = encoded.clone();
        bad.push(0);
        assert!(payload::decode(&bad).is_err());
        let mut bad = encoded.clone();
        bad[1] ^= 1;
        assert!(payload::decode(&bad).is_err());
        let prefix = b"\0commit-quorum/cbor/v1/";
        let mut bad = encoded.clone();
        assert_eq!(bad[prefix.len()], 0xa3);
        bad[prefix.len()] = 0xbf;
        bad.push(0xff);
        assert!(payload::decode(&bad).unwrap_err().contains("noncanonical"));
    }
    #[test]
    fn declared_signer_count_refuses_before_elements_or_allocation() {
        let mut encoded = payload::encode(&untrusted_fixture(), 4096).unwrap();
        assert_eq!(encoded.pop(), Some(0x80));
        encoded.push(0x9b);
        encoded.extend(u64::MAX.to_be_bytes());
        assert!(payload::decode(&encoded)
            .unwrap_err()
            .contains("count limit"));
    }
}
