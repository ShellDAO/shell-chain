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

        ensure_no_canonical_head(&chain_store)?;

        // The trust anchor must come from local configuration, not the snapshot.
        // `init` writes genesis.json without opening the persistent database.
        let cfg = match chain_store.get_chain_config()? {
            Some(cfg) => cfg,
            None => {
                let genesis_path = datadir.join("genesis.json");
                if !genesis_path.is_file() {
                    return Err(
                        "fresh database has no trusted chain config; initialize the chain before importing state"
                            .into(),
                    );
                }
                let genesis = shell_genesis::GenesisConfig::from_file(&genesis_path)?;
                let block = shell_genesis::initialize_genesis(
                    &genesis,
                    Arc::new(shell_storage::MemoryDb::new()),
                )?;
                shell_storage::ChainConfig {
                    chain_id: genesis.chain_id,
                    genesis_hash: block.hash(),
                }
            }
        };

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

    #[cfg(feature = "rocksdb")]
    fn prepare_snapshot(
        datadir: &std::path::Path,
    ) -> (shell_genesis::GenesisConfig, ShellHash, PathBuf) {
        crate::commands::init(datadir.to_path_buf(), None, 1337, "dev".into()).unwrap();
        let genesis =
            shell_genesis::GenesisConfig::from_file(&datadir.join("genesis.json")).unwrap();
        let store = Arc::new(MemoryDb::new());
        let block = shell_genesis::initialize_genesis(&genesis, Arc::clone(&store)).unwrap();
        let hash = block.hash();
        let snapshot = datadir.join("snapshot.jsonl");
        ChainStore::new(store)
            .export_snapshot(
                shell_storage::SnapshotMetadata::new(
                    genesis.chain_id,
                    block.number(),
                    hash,
                    block.header.state_root,
                    hash,
                ),
                std::fs::File::create(&snapshot).unwrap(),
            )
            .unwrap();
        (genesis, hash, snapshot)
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn snapshot_import_works_after_init_without_starting_node() {
        let dir = tempfile::tempdir().unwrap();
        let (_, expected_head, snapshot) = prepare_snapshot(dir.path());

        import_state(dir.path().to_path_buf(), snapshot.clone()).unwrap();
        {
            let stores =
                shell_storage::RocksDbStore::open_all(dir.path().join("db"), None).unwrap();
            let chain_store = ChainStore::new(Arc::new(stores.state));
            assert_eq!(chain_store.get_head_hash().unwrap(), Some(expected_head));
        }

        let error = import_state(dir.path().to_path_buf(), snapshot).unwrap_err();
        assert!(error.to_string().contains("existing canonical head"));
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn fresh_snapshot_import_requires_matching_local_genesis() {
        let source = tempfile::tempdir().unwrap();
        let (mut genesis, _, snapshot) = prepare_snapshot(source.path());
        let destination = tempfile::tempdir().unwrap();

        let error = import_state(destination.path().to_path_buf(), snapshot.clone()).unwrap_err();
        assert!(error.to_string().contains("trusted chain config"));

        genesis.timestamp += 1;
        std::fs::write(
            destination.path().join("genesis.json"),
            genesis.to_json_pretty().unwrap(),
        )
        .unwrap();
        let error = import_state(destination.path().to_path_buf(), snapshot).unwrap_err();
        assert!(error.to_string().contains("genesis"));

        let stores =
            shell_storage::RocksDbStore::open_all(destination.path().join("db"), None).unwrap();
        let chain_store = ChainStore::new(Arc::new(stores.state));
        assert!(chain_store.get_head_hash().unwrap().is_none());
        assert!(chain_store.get_chain_config().unwrap().is_none());
    }
}
