//! `shell-node backup` — hot backup and restore for the RocksDB data directory.
//!
//! # Subcommands
//!
//! - `backup create [--output <dir>]`  — create a consistent RocksDB checkpoint.
//!   Uses RocksDB's built-in `Checkpoint` API to create a hard-linked SST
//!   snapshot.  **The node process must be stopped before running this command**
//!   because `RocksDbStore::open_all` opens the database with an exclusive
//!   lock; attempting to open an already-open database will fail.
//!   For live (in-process) backups without stopping the node, use the
//!   `admin_createSnapshot` RPC method (planned) which calls `Checkpoint`
//!   on the live DB handle.
//!
//! - `backup restore <backup-dir>`     — restore the data directory from a checkpoint.
//!   The live `db/` directory is renamed to `db.bak.<timestamp>` before restore to
//!   allow manual rollback.
//!
//! Both subcommands print structured status to stderr and return a machine-readable
//! JSON summary to stdout so they can be composed in shell scripts.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a RocksDB checkpoint (offline backup) of the data directory.
///
/// Uses `rocksdb::checkpoint::Checkpoint` to create a consistent snapshot
/// of the database.  **Requires the node to be stopped** — RocksDB takes an
/// exclusive lock on the data directory, so this call will fail if the node
/// process already has the database open.
///
/// The checkpoint is placed in `output_dir` (defaults to
/// `<datadir>/backups/<unix_timestamp>/`).
pub fn create_backup(
    datadir: PathBuf,
    output_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "rocksdb")]
    {
        use shell_storage::RocksDbStore;

        let db_path = datadir.join("db");
        if !db_path.exists() {
            return Err(format!(
                "Database not found at {}. Run `shell-node init` first.",
                db_path.display()
            )
            .into());
        }

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let out = output_dir.unwrap_or_else(|| datadir.join("backups").join(ts.to_string()));
        std::fs::create_dir_all(&out)?;

        // Open the DB (read-only compatible) and create a checkpoint.
        let stores = RocksDbStore::open_all(&db_path, None)?;
        let checkpoint_path = out.join("db");
        stores.create_checkpoint(&checkpoint_path)?;

        let size_bytes = dir_size(&out).unwrap_or(0);
        eprintln!("✓ Backup created successfully");
        eprintln!("  Source:      {}", db_path.display());
        eprintln!("  Destination: {}", checkpoint_path.display());
        eprintln!("  Approx size: {} bytes", size_bytes);

        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "backup_path": checkpoint_path.display().to_string(),
                "timestamp": ts,
                "size_bytes": size_bytes,
            })
        );
        Ok(())
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = (datadir, output_dir);
        Err("RocksDB support not compiled. Rebuild with: cargo build -p shell-cli --features rocksdb".into())
    }
}

/// Restore the data directory from a RocksDB checkpoint.
///
/// Renames the existing `<datadir>/db` to `<datadir>/db.bak.<timestamp>` before
/// copying the backup into place, preserving the ability to manually roll back.
pub fn restore_backup(
    datadir: PathBuf,
    backup_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let checkpoint_src = if backup_path.join("db").exists() {
        backup_path.join("db")
    } else if backup_path.exists() {
        backup_path.clone()
    } else {
        return Err(format!("Backup path does not exist: {}", backup_path.display()).into());
    };

    let db_path = datadir.join("db");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Rename existing db to db.bak.<ts> for manual rollback.
    if db_path.exists() {
        let bak = datadir.join(format!("db.bak.{ts}"));
        std::fs::rename(&db_path, &bak)?;
        eprintln!("ℹ  Existing DB renamed to {}", bak.display());
    }

    // Copy (or hard-link) checkpoint into db/.
    copy_dir_all(&checkpoint_src, &db_path)?;

    eprintln!("✓ Restore completed successfully");
    eprintln!("  Source:      {}", checkpoint_src.display());
    eprintln!("  Destination: {}", db_path.display());

    println!(
        "{}",
        serde_json::json!({
            "status": "ok",
            "restored_from": checkpoint_src.display().to_string(),
            "db_path": db_path.display().to_string(),
        })
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively copy a directory tree (used for restore).
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

/// Approximate size of a directory in bytes (best-effort).
#[cfg(feature = "rocksdb")]
fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path()).unwrap_or(0);
        }
    }
    Ok(total)
}
