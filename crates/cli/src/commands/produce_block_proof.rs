//! Offline raw native source to complete canonical proof artifact.
use std::{error::Error, num::NonZeroUsize, path::PathBuf};

pub fn produce_block_proof(
    datadir: PathBuf,
    block_hash: String,
    expected_tip: String,
    output: PathBuf,
    component_limit: Option<NonZeroUsize>,
) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "rocksdb")]
    {
        use shell_primitives::{blake3_hash, ShellHash};
        use shell_stark_prover::{
            canonical_producer::CanonicalProductionSource,
            production_store::{bounded_json, ProductionStore},
        };
        use shell_storage::{
            CanonicalProofManifest, ChainStore, RocksDbStore, MAX_CANONICAL_PROOF_BYTES,
        };
        use std::sync::Arc;
        let hash = |s: &str| -> Result<ShellHash, Box<dyn Error>> {
            Ok(ShellHash::try_from_slice(&hex::decode(
                s.trim_start_matches("0x"),
            )?)?)
        };
        let block_hash = hash(&block_hash)?;
        let expected_tip = hash(&expected_tip)?;
        let database = datadir.join("db");
        if !database.join("CURRENT").is_file() {
            return Err(
                "proof production requires an existing initialized RocksDB; stop the node first"
                    .into(),
            );
        }
        let database = database.canonicalize()?;
        // Establish exclusive native ownership before touching output artifacts.
        let native = Arc::new(RocksDbStore::open_all(&database, None)?.state);
        let chain = ChainStore::new(native);
        let source = CanonicalProductionSource::capture(&chain, expected_tip, block_hash)?;
        let block_bytes = bounded_json(source.block(), 2 * 1024 * 1024)?;
        let output = prepare_output(&database, &output)?;
        let mut db = RocksDbStore::open_all(output.join("db"), None)?.state;
        let compact = source.block().transactions.len() > 2 || source.needs_slh_encoding();
        let mut job = if source.needs_slh_encoding() {
            ProductionStore::open_slh(&mut db, source.identity(), component_limit)?
        } else if compact {
            ProductionStore::open_compact(&mut db, source.identity(), component_limit)?
        } else {
            ProductionStore::open(&mut db, source.identity(), component_limit)?
        };
        let produced = source.produce(&mut job);
        println!("{}", serde_json::to_string(&job.progress())?);
        let proof = produced?;
        let bytes = shell_stark_prover::compact_canonical::encode_payload(
            &proof,
            MAX_CANONICAL_PROOF_BYTES as usize,
            compact,
        )?;
        let manifest = CanonicalProofManifest {
            version: 1,
            chain_id: source.chain_id(),
            genesis_hash: source.genesis_hash(),
            block_hash,
            total_bytes: bytes.len() as u64,
            payload_hash: blake3_hash(&bytes),
        };
        manifest.validate()?;
        let proof_file = if compact { "proof.cbor" } else { "proof.json" };
        append_artifact(&output.join(proof_file), &bytes)?;
        append_artifact(&output.join("block.json"), &block_bytes)?;
        append_artifact(
            &output.join("manifest.json"),
            &serde_json::to_vec(&manifest)?,
        )?;
        let mut result = serde_json::json!({"complete":true,"manifest":manifest,"newly_proved":job.progress().newly_proved,"reused":job.progress().reused});
        if compact {
            result["proof_file"] = serde_json::json!(proof_file);
        }
        println!("{result}");
        Ok(())
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = (datadir, block_hash, expected_tip, output, component_limit);
        Err("this build does not include RocksDB support".into())
    }
}

#[cfg(any(feature = "rocksdb", test))]
fn prepare_output(
    database: &std::path::Path,
    output: &std::path::Path,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = if output.exists() {
        if output.symlink_metadata()?.file_type().is_symlink() || !output.is_dir() {
            return Err("production output must be a real directory".into());
        }
        output.canonicalize()?
    } else {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."))
            .canonicalize()?;
        parent.join(
            output
                .file_name()
                .ok_or("missing production directory name")?,
        )
    };
    if path.starts_with(database) || database.starts_with(&path) {
        return Err("production output overlaps the native database".into());
    }
    if path.exists() {
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid production output name")?;
            if ![
                "db",
                "proof.json",
                "proof.cbor",
                "manifest.json",
                "block.json",
            ]
            .contains(&name)
                || entry.file_type()?.is_symlink()
            {
                return Err("refusing unowned or linked production output".into());
            }
        }
        if std::fs::read_dir(&path)?.next().is_some() && !path.join("db/CURRENT").is_file() {
            return Err("nonempty production output has no job database".into());
        }
    } else {
        std::fs::create_dir(&path)?;
    }
    Ok(path)
}

#[cfg(any(feature = "rocksdb", test))]
fn append_artifact(path: &std::path::Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut options = std::fs::OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > bytes.len() as u64 {
        return Err("production artifact shape/size conflict".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("linked production artifact refused".into());
        }
    }
    let old_len = metadata.len() as usize;
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0;
    while offset < old_len {
        let count = (old_len - offset).min(buffer.len());
        file.read_exact(&mut buffer[..count])?;
        if buffer[..count] != bytes[offset..offset + count] {
            return Err("production artifact prefix conflict; retained unchanged".into());
        }
        offset += count;
    }
    file.write_all(&bytes[old_len..])?;
    file.sync_all()?;
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err("production artifact size changed".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0;
    while offset < bytes.len() {
        let count = (bytes.len() - offset).min(buffer.len());
        file.read_exact(&mut buffer[..count])?;
        if buffer[..count] != bytes[offset..offset + count] {
            return Err("production artifact readback mismatch".into());
        }
        offset += count;
    }
    std::fs::File::open(path.parent().ok_or("missing output parent")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_exact_prefix_and_refuse_conflict_and_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("proof.json");
        std::fs::write(&artifact, b"pre").unwrap();
        append_artifact(&artifact, b"prefix").unwrap();
        append_artifact(&artifact, b"prefix").unwrap();
        assert!(append_artifact(&artifact, b"different").is_err());
        assert_eq!(std::fs::read(&artifact).unwrap(), b"prefix");
        let base = dir.path().canonicalize().unwrap();
        assert!(prepare_output(&base, &base.join("job")).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&artifact, &link).unwrap();
            assert!(append_artifact(&link, b"prefix").is_err());
        }
    }
}
