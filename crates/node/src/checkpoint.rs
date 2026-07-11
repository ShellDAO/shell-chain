//! Checkpoint sync: download and import a snapshot from a remote URL.
//!
//! This is a one-time operation at node startup. If the chain is empty
//! (no blocks beyond genesis), the node downloads a snapshot file from
//! the given URL, validates it, and imports it via `ChainStore::import_snapshot`.

use std::io::BufReader;
use std::path::{Path, PathBuf};

use shell_storage::{ChainStore, KvStore, SnapshotReader};
use tracing::info;

use crate::error::NodeError;

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
    let snapshot_path = datadir.join("checkpoint_snapshot.jsonl");

    // Download the snapshot file using curl.
    info!("Downloading checkpoint from {url}...");
    download_snapshot(url, &snapshot_path).await?;

    // Validate the snapshot format before importing.
    info!("Validating checkpoint snapshot...");
    let metadata = validate_snapshot(&snapshot_path)?;
    info!(
        "Checkpoint snapshot: block #{}, chain_id={}, entries={}",
        metadata.block_number, metadata.chain_id, metadata.entry_count
    );

    // Always validate chain_id against the expected value.
    if metadata.chain_id != expected_chain_id {
        let _ = std::fs::remove_file(&snapshot_path);
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
    let file = std::fs::File::open(&snapshot_path)
        .map_err(|e| NodeError::Startup(format!("open snapshot: {e}")))?;
    let reader = BufReader::new(file);
    let imported = chain_store
        .import_snapshot(reader, config.chain_id, &config.genesis_hash)
        .map_err(NodeError::Storage)?;

    // Verify the imported HEAD block's state_root matches the snapshot metadata.
    if let Ok(Some(head)) = chain_store.get_head_block() {
        if head.header.state_root != imported.state_root {
            // Clean up before returning error.
            let _ = std::fs::remove_file(&snapshot_path);
            return Err(NodeError::Startup(format!(
                "state_root mismatch after import: block has {:?}, snapshot expects {:?}",
                head.header.state_root, imported.state_root
            )));
        }
    }

    // Clean up the downloaded file.
    let _ = std::fs::remove_file(&snapshot_path);

    info!("Imported checkpoint at block #{}", imported.block_number);
    Ok(imported.block_number)
}

/// Check whether the chain is empty (no blocks beyond genesis).
///
/// Returns `true` if checkpoint sync should proceed: head block is
/// either missing or is the genesis block (number == 0).
pub fn should_checkpoint_sync<S: KvStore>(chain_store: &ChainStore<S>) -> bool {
    match chain_store.get_head_block() {
        Ok(Some(head)) => head.number() == 0,
        Ok(None) => true,
        Err(_) => true,
    }
}

/// Download a file from `url` to `dest` using `curl`.
async fn download_snapshot(url: &str, dest: &PathBuf) -> Result<(), NodeError> {
    let dest_str = dest
        .to_str()
        .ok_or_else(|| NodeError::Startup("snapshot path contains invalid UTF-8".into()))?;

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
            "--output",
            dest_str,
            url,
        ])
        .output()
        .await
        .map_err(|e| NodeError::Startup(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NodeError::Startup(format!(
            "curl failed (exit {}): {stderr}",
            output.status
        )));
    }

    // Verify the file was created and is non-empty.
    let file_meta = std::fs::metadata(dest)
        .map_err(|e| NodeError::Startup(format!("snapshot file not found after download: {e}")))?;
    if file_meta.len() == 0 {
        let _ = std::fs::remove_file(dest);
        return Err(NodeError::Startup(
            "downloaded snapshot file is empty".into(),
        ));
    }

    Ok(())
}

/// Validate that a file is a valid snapshot (parseable JSON-lines with META footer).
/// Returns the snapshot metadata on success.
fn validate_snapshot(path: &Path) -> Result<shell_storage::SnapshotMetadata, NodeError> {
    let file = std::fs::File::open(path)
        .map_err(|e| NodeError::Startup(format!("open snapshot for validation: {e}")))?;
    let reader = BufReader::new(file);
    let snap_reader = SnapshotReader::new(reader)
        .map_err(|e| NodeError::Startup(format!("invalid snapshot: {e}")))?;
    Ok(snap_reader.metadata().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::ShellHash;
    use shell_storage::{MemoryDb, SnapshotMetadata, SnapshotWriter};
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
        let dir = std::env::current_dir().unwrap();
        let path = dir.join("test_validate_snapshot.jsonl");
        std::fs::write(&path, &data).unwrap();
        let result = validate_snapshot(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_ok());
        let meta = result.unwrap();
        assert_eq!(meta.block_number, 42);
        assert_eq!(meta.chain_id, 1337);
        assert_eq!(meta.entry_count, 2);
    }

    #[test]
    fn test_validate_snapshot_invalid() {
        let dir = std::env::current_dir().unwrap();
        let path = dir.join("test_validate_snapshot_bad.jsonl");
        std::fs::write(&path, b"not a valid snapshot").unwrap();
        let result = validate_snapshot(&path);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_checkpoint_sync_empty_chain() {
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store);
        assert!(should_checkpoint_sync(&chain_store));
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

        assert!(!should_checkpoint_sync(&chain_store));
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
        assert!(should_checkpoint_sync(&chain_store));
    }
}
