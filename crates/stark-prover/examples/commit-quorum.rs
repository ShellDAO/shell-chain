//! Separate source-bound RocksDB quorum proof jobs; never a Native chain store.
use serde::{de::DeserializeOwned, Serialize};
use shell_stark_prover::commit_quorum::{
    prove_commit_quorum_persistent, reverify_commit_quorum_persistent, verify_commit_quorum,
    CommitQuorumProof, CommitQuorumSource,
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
        _ => return Err("usage: commit-quorum restore <source.cbor> <completed-job-rows.cbor> <new-job-directory> | prove <source.cbor> <separate-job-directory> <proof.cbor> [component-limit] | verify <source.cbor> <existing-job-directory> <proof.cbor>".into()),
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
