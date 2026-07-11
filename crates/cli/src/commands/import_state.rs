//! `shell-node import-state` — import chain state from a snapshot file.

use std::path::PathBuf;

use shell_storage::SnapshotReader;

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
        use shell_storage::{ChainStore, RocksDbStore};
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
