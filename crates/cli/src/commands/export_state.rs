//! `shell-node export-state` — export chain state to a snapshot file.

use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};

fn replace_file_atomically<T>(
    output: &Path,
    write: impl FnOnce(&mut File) -> Result<T, Box<dyn Error>>,
) -> Result<(T, u64), Box<dyn Error>> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    let result = write(temp.as_file_mut())?;
    temp.as_file_mut().sync_all()?;
    let file_size = temp.as_file().metadata()?.len();
    temp.persist(output).map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok((result, file_size))
}

/// Export chain state at a given block to a snapshot file.
pub fn export_state(
    datadir: PathBuf,
    output: PathBuf,
    block: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // F-096: Validate output path — parent directory must exist and be writable.
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(format!(
                "output parent directory does not exist: {}",
                parent.display()
            )
            .into());
        }
    }
    #[cfg(feature = "rocksdb")]
    {
        use shell_storage::{ChainStore, RocksDbStore, SnapshotMetadata};
        use std::sync::Arc;

        let db_path = datadir.join("db");
        if !db_path.exists() {
            return Err(format!(
                "Database not found at {}. Run `shell-node init` first.",
                db_path.display()
            )
            .into());
        }

        let stores = RocksDbStore::open_all(&db_path, None)?;
        let store = Arc::new(stores.state);
        let chain_store = ChainStore::new(store);

        // Resolve block number: use provided value or latest head block.
        let target_block = match block {
            Some(n) => {
                let blk = chain_store
                    .get_block_by_number(n)?
                    .ok_or_else(|| format!("Block #{n} not found in chain store"))?;
                blk
            }
            None => chain_store
                .get_head_block()?
                .ok_or("No head block found. Is the chain initialized?")?,
        };

        let metadata = SnapshotMetadata::new(
            chain_store
                .get_chain_config()?
                .map(|c| c.chain_id)
                .unwrap_or(0),
            target_block.number(),
            target_block.hash(),
            target_block.header.state_root,
            chain_store
                .get_chain_config()?
                .map(|c| c.genesis_hash)
                .unwrap_or_default(),
        );

        let (final_meta, file_size) = replace_file_atomically(&output, |file| {
            let writer = std::io::BufWriter::new(file);
            chain_store
                .export_snapshot(metadata, writer)
                .map_err(Into::into)
        })?;
        eprintln!("✓ State exported successfully");
        eprintln!("  Block:   #{}", final_meta.block_number);
        eprintln!("  Entries: {}", final_meta.entry_count);
        eprintln!("  File:    {} ({} bytes)", output.display(), file_size);

        Ok(())
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = (datadir, output, block);
        Err("RocksDB support not compiled. Rebuild with: cargo build -p shell-cli --features rocksdb".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn failed_atomic_replace_preserves_existing_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("snapshot.jsonl");
        std::fs::write(&output, b"existing snapshot").unwrap();

        let result = replace_file_atomically(&output, |file| {
            file.write_all(b"partial replacement")?;
            Err::<(), Box<dyn Error>>("injected export failure".into())
        });

        assert!(result.is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"existing snapshot");
    }

    #[test]
    fn successful_atomic_replace_publishes_complete_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("snapshot.jsonl");
        std::fs::write(&output, b"existing snapshot").unwrap();

        let (value, size) = replace_file_atomically(&output, |file| {
            file.write_all(b"complete replacement")?;
            Ok(42)
        })
        .unwrap();

        assert_eq!(value, 42);
        assert_eq!(size, b"complete replacement".len() as u64);
        assert_eq!(std::fs::read(&output).unwrap(), b"complete replacement");
    }
}
