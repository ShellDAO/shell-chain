//! `shell-node import-state` — import chain state from a snapshot file.

use std::path::PathBuf;

use shell_storage::{ChainStore, KvStore, SnapshotReader};

fn ensure_no_canonical_head<S: KvStore>(
    chain_store: &ChainStore<S>,
) -> Result<(), Box<dyn std::error::Error>> {
    if chain_store.get_head_hash()?.is_some() {
        return Err(
            "cannot import a snapshot into a database with an existing canonical head".into(),
        );
    }
    Ok(())
}

/// Import chain state from a snapshot file.
pub fn import_state(datadir: PathBuf, snapshot: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !snapshot.exists() {
        return Err(format!("Snapshot file not found: {}", snapshot.display()).into());
    }
    // F-096: Canonicalize snapshot path.
    let snapshot = snapshot.canonicalize().map_err(|e| {
        format!(
            "failed to canonicalize snapshot path '{}': {e}",
            snapshot.display()
        )
    })?;

    // Validate snapshot file before opening the database.
    let validate_file = std::fs::File::open(&snapshot)?;
    let reader = std::io::BufReader::new(validate_file);
    let snap_reader = SnapshotReader::new(reader)?;
    let preview = snap_reader.metadata().clone();
    eprintln!(
        "Snapshot: block #{}, chain_id={}, entries={}",
        preview.block_number, preview.chain_id, preview.entry_count
    );

    #[cfg(feature = "rocksdb")]
    {
        use shell_storage::RocksDbStore;
        use std::sync::Arc;

        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path)?;
        let stores = RocksDbStore::open_all(&db_path, None)?;
        let store = Arc::new(stores.state);
        let chain_store = ChainStore::new(store);

        // Require a local chain configuration as the trust anchor. The
        // snapshot's own genesis hash is metadata, not authentication.
        let cfg = chain_store.get_chain_config()?.ok_or(
            "fresh database has no trusted chain config; initialize the chain before importing state",
        )?;
        ensure_no_canonical_head(&chain_store)?;

        let file = std::fs::File::open(&snapshot)?;
        let reader = std::io::BufReader::new(file);
        let metadata = chain_store.import_snapshot(reader, cfg.chain_id, &cfg.genesis_hash)?;

        eprintln!("✓ State imported successfully");
        eprintln!("  Block:   #{}", metadata.block_number);
        eprintln!("  Entries: {}", metadata.entry_count);
        eprintln!("  Data:    {} bytes (uncompressed)", metadata.data_size);

        Ok(())
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = (datadir, snapshot);
        Err("RocksDB support not compiled. Rebuild with: cargo build -p shell-cli --features rocksdb".into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use shell_primitives::ShellHash;
    use shell_storage::MemoryDb;

    use super::*;

    #[test]
    fn snapshot_import_requires_an_empty_canonical_chain() {
        let chain_store = ChainStore::new(Arc::new(MemoryDb::new()));
        ensure_no_canonical_head(&chain_store).unwrap();

        chain_store.set_head(&ShellHash::from([0xAA; 32])).unwrap();
        let error = ensure_no_canonical_head(&chain_store).unwrap_err();

        assert!(error.to_string().contains("existing canonical head"));
    }
}
