//! Checkpoint sync: download and import a snapshot from a remote URL.
//!
//! This is a one-time operation at node startup. If the chain is empty
//! (no blocks beyond genesis), the node downloads a snapshot file from
//! the given URL, validates it, and imports it via `ChainStore::import_snapshot`.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use shell_storage::{ChainStore, KvStore, SnapshotReader};
use tracing::info;

use crate::error::NodeError;

struct DownloadedSnapshot {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl DownloadedSnapshot {
    fn create(datadir: &Path) -> Result<Self, NodeError> {
        static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

        for _ in 0..16 {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let file_id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
            let path = datadir.join(format!(
                "checkpoint_snapshot-{}-{timestamp}-{file_id}.jsonl",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);

            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(NodeError::Startup(format!(
                        "create checkpoint snapshot file: {error}"
                    )))
                }
            }
        }

        Err(NodeError::Startup(
            "could not allocate a unique checkpoint snapshot file".into(),
        ))
    }

    fn file(&self) -> Result<&std::fs::File, NodeError> {
        self.file
            .as_ref()
            .ok_or_else(|| NodeError::Startup("checkpoint snapshot file is closed".into()))
    }

    fn reader(&self) -> Result<std::fs::File, NodeError> {
        let mut file = self
            .file()?
            .try_clone()
            .map_err(|e| NodeError::Startup(format!("clone checkpoint snapshot file: {e}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| NodeError::Startup(format!("rewind checkpoint snapshot file: {e}")))?;
        Ok(file)
    }
}

impl Drop for DownloadedSnapshot {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Download a snapshot from a URL and import it into the chain store.
///
/// Returns the block number that was imported.
///
/// The snapshot is downloaded to a temporary file inside `datadir`, validated,
/// imported, and then cleaned up.
pub async fn checkpoint_sync<S: KvStore>(
    url: &str,
    chain_store: &ChainStore<S>,
    datadir: &Path,
    expected_chain_id: u64,
) -> Result<u64, NodeError> {
    let snapshot = DownloadedSnapshot::create(datadir)?;

    // Download the snapshot file using curl.
    info!("Downloading checkpoint snapshot...");
    download_snapshot(url, snapshot.file()?).await?;

    // Validate the snapshot format before importing.
    info!("Validating checkpoint snapshot...");
    let metadata = validate_snapshot(snapshot.reader()?)?;
    info!(
        "Checkpoint snapshot: block #{}, chain_id={}, entries={}",
        metadata.block_number, metadata.chain_id, metadata.entry_count
    );

    // Always validate chain_id against the expected value.
    if metadata.chain_id != expected_chain_id {
        return Err(NodeError::Startup(format!(
            "snapshot chain_id mismatch: expected {}, got {}",
            expected_chain_id, metadata.chain_id
        )));
    }

    // A checkpoint must be anchored to the local chain configuration. Never
    // accept the snapshot's own genesis hash as its trust anchor on a fresh
    // store; that would allow an arbitrary URL to bootstrap a fake chain.
    let config = chain_store
        .get_chain_config()
        .map_err(NodeError::Storage)?
        .ok_or_else(|| {
            NodeError::Startup(
                "checkpoint sync requires an initialized chain config with a trusted genesis hash"
                    .into(),
            )
        })?;
    if config.chain_id != expected_chain_id {
        return Err(NodeError::Startup(format!(
            "local chain config ID {} does not match expected {}",
            config.chain_id, expected_chain_id
        )));
    }

    // Import the snapshot into the chain store.
    info!("Importing checkpoint snapshot...");
    let imported = chain_store
        .import_snapshot(snapshot.reader()?, config.chain_id, &config.genesis_hash)
        .map_err(NodeError::Storage)?;

    // Verify the imported HEAD block's state_root matches the snapshot metadata.
    verify_imported_head(chain_store, imported.state_root)?;

    info!("Imported checkpoint at block #{}", imported.block_number);
    Ok(imported.block_number)
}

fn verify_imported_head<S: KvStore>(
    chain_store: &ChainStore<S>,
    expected_state_root: shell_primitives::ShellHash,
) -> Result<(), NodeError> {
    let head = chain_store.get_head_block()?.ok_or_else(|| {
        NodeError::Startup("checkpoint snapshot import did not publish a HEAD block".into())
    })?;
    if head.header.state_root != expected_state_root {
        return Err(NodeError::Startup(format!(
            "state_root mismatch after import: block has {:?}, snapshot expects {:?}",
            head.header.state_root, expected_state_root
        )));
    }
    Ok(())
}

/// Check whether the chain is empty (no blocks beyond genesis).
///
/// Returns `true` if checkpoint sync should proceed: head block is
/// either missing or is the genesis block (number == 0). Storage errors are
/// returned so a damaged or unavailable chain store is never treated as empty.
pub fn should_checkpoint_sync<S: KvStore>(chain_store: &ChainStore<S>) -> Result<bool, NodeError> {
    Ok(match chain_store.get_head_block()? {
        Some(head) => head.number() == 0,
        None => true,
    })
}

/// Download a file from `url` into an already-open exclusive file using `curl`.
async fn download_snapshot(url: &str, output_file: &std::fs::File) -> Result<(), NodeError> {
    let downloaded_file = output_file
        .try_clone()
        .map_err(|e| NodeError::Startup(format!("inspect checkpoint snapshot file: {e}")))?;
    let curl_output = output_file
        .try_clone()
        .map_err(|e| NodeError::Startup(format!("clone checkpoint snapshot output: {e}")))?;
    let output = tokio::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-filesize",
            "1073741824", // 1 GB max
            "--max-time",
            "600", // 10 minute timeout
            "--",
            url,
        ])
        .stdout(Stdio::from(curl_output))
        .output()
        .await
        .map_err(|e| NodeError::Startup(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).replace(url, "<checkpoint-url>");
        return Err(NodeError::Startup(format!(
            "curl failed (exit {}): {stderr}",
            output.status
        )));
    }

    if downloaded_file
        .metadata()
        .map_err(|e| NodeError::Startup(format!("inspect downloaded snapshot file: {e}")))?
        .len()
        == 0
    {
        return Err(NodeError::Startup(
            "downloaded snapshot file is empty".into(),
        ));
    }

    Ok(())
}

/// Validate that a file is a valid snapshot (parseable JSON-lines with META footer).
/// Returns the snapshot metadata on success.
fn validate_snapshot<R: Read + Seek>(
    reader: R,
) -> Result<shell_storage::SnapshotMetadata, NodeError> {
    let snap_reader = SnapshotReader::new(reader)
        .map_err(|e| NodeError::Startup(format!("invalid snapshot: {e}")))?;
    Ok(snap_reader.metadata().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::ShellHash;
    use shell_storage::{MemoryDb, SnapshotMetadata, SnapshotWriter, StorageError, WriteBatch};
    use std::io::Cursor;
    use std::sync::Arc;

    fn make_test_snapshot() -> Vec<u8> {
        let meta =
            SnapshotMetadata::new(1337, 42, ShellHash::ZERO, ShellHash::ZERO, ShellHash::ZERO);
        let mut buf = Vec::new();
        let mut writer = SnapshotWriter::new(Cursor::new(&mut buf), meta).unwrap();
        writer.write_entry(b"key1", b"value1").unwrap();
        writer.write_entry(b"key2", b"value2").unwrap();
        writer.finalize().unwrap();
        buf
    }

    #[test]
    fn test_validate_snapshot_valid() {
        let data = make_test_snapshot();
        let result = validate_snapshot(Cursor::new(data));
        assert!(result.is_ok());
        let meta = result.unwrap();
        assert_eq!(meta.block_number, 42);
        assert_eq!(meta.chain_id, 1337);
        assert_eq!(meta.entry_count, 2);
    }

    #[test]
    fn test_validate_snapshot_invalid() {
        let result = validate_snapshot(Cursor::new(b"not a valid snapshot"));
        assert!(result.is_err());
    }

    #[test]
    fn test_should_checkpoint_sync_empty_chain() {
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store);
        assert!(should_checkpoint_sync(&chain_store).unwrap());
    }

    #[test]
    fn test_should_checkpoint_sync_with_blocks() {
        use shell_core::{Block, BlockHeader};
        use shell_primitives::{Address, Bytes};

        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store);

        // Insert a block at number 5 (beyond genesis).
        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number: 5,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1700000005,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_canonical(5, &hash).unwrap();
        chain_store.set_head(&hash).unwrap();

        assert!(!should_checkpoint_sync(&chain_store).unwrap());
    }

    #[test]
    fn test_should_checkpoint_sync_genesis_only() {
        use shell_core::{Block, BlockHeader};
        use shell_primitives::{Address, Bytes};

        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store);

        // Insert genesis block (number 0).
        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number: 0,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1700000000,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_canonical(0, &hash).unwrap();
        chain_store.set_head(&hash).unwrap();

        // Genesis-only chain should still allow checkpoint sync.
        assert!(should_checkpoint_sync(&chain_store).unwrap());
    }

    struct FailingReadStore;

    impl KvStore for FailingReadStore {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::Database("injected read failure".into()))
        }

        fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn delete(&self, _key: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn flush(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn write_batch(&self, _batch: WriteBatch) -> Result<(), StorageError> {
            Ok(())
        }

        fn scan_prefix(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn checkpoint_decision_propagates_head_read_failure() {
        let chain_store = ChainStore::new(Arc::new(FailingReadStore));

        let err = should_checkpoint_sync(&chain_store).unwrap_err();

        assert!(matches!(err, NodeError::Storage(StorageError::Database(_))));
    }

    #[test]
    fn imported_head_verification_propagates_read_failure() {
        let chain_store = ChainStore::new(Arc::new(FailingReadStore));

        let err = verify_imported_head(&chain_store, ShellHash::ZERO).unwrap_err();

        assert!(matches!(err, NodeError::Storage(StorageError::Database(_))));
    }

    #[test]
    fn imported_head_verification_rejects_missing_head() {
        let chain_store = ChainStore::new(Arc::new(MemoryDb::new()));

        let err = verify_imported_head(&chain_store, ShellHash::ZERO).unwrap_err();

        assert!(matches!(err, NodeError::Startup(message) if message.contains("did not publish")));
    }

    #[test]
    fn downloaded_snapshot_guard_removes_file_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "shell-checkpoint-cleanup-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = {
            let snapshot = DownloadedSnapshot::create(&dir).unwrap();
            let mut file = snapshot.file().unwrap().try_clone().unwrap();
            std::io::Write::write_all(&mut file, b"partial snapshot").unwrap();
            snapshot.path.clone()
        };

        assert!(!path.exists());
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn downloaded_snapshot_files_are_unique_and_exclusive() {
        let dir = std::env::temp_dir().join(format!(
            "shell-checkpoint-unique-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let first = DownloadedSnapshot::create(&dir).unwrap();
        let second = DownloadedSnapshot::create(&dir).unwrap();

        assert_ne!(first.path, second.path);
        assert!(first.path.exists());
        assert!(second.path.exists());
        drop(first);
        drop(second);
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_validation_uses_reserved_file_after_path_replacement() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!(
            "shell-checkpoint-replacement-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let snapshot = DownloadedSnapshot::create(&dir).unwrap();
        let mut file = snapshot.file().unwrap().try_clone().unwrap();
        file.write_all(&make_test_snapshot()).unwrap();
        file.flush().unwrap();
        std::fs::remove_file(&snapshot.path).unwrap();
        std::fs::write(&snapshot.path, b"replacement file").unwrap();

        let metadata = validate_snapshot(snapshot.reader().unwrap()).unwrap();
        assert_eq!(metadata.block_number, 42);
        drop(snapshot);
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn downloaded_snapshot_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "shell-checkpoint-permissions-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let snapshot = DownloadedSnapshot::create(&dir).unwrap();
        let mode = std::fs::metadata(&snapshot.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);
        drop(snapshot);
        std::fs::remove_dir(&dir).unwrap();
    }
}
