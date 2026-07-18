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

use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CURRENT_FILE_BYTES: u64 = 1_024;

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
/// Stages and validates the backup before renaming the existing `<datadir>/db`
/// to `<datadir>/db.bak.<timestamp>` and atomically installing the staged copy.
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
    let source_meta = std::fs::symlink_metadata(&checkpoint_src)?;
    if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
        return Err(format!(
            "Backup path must be a real directory: {}",
            checkpoint_src.display()
        )
        .into());
    }

    std::fs::create_dir_all(&datadir)?;
    let source_root = checkpoint_src.canonicalize()?;
    let data_root = datadir.canonicalize()?;
    if data_root.starts_with(&source_root) {
        return Err(format!(
            "Backup path must not contain data directory: {}",
            checkpoint_src.display()
        )
        .into());
    }
    let db_path = datadir.join("db");

    // Fully stage and validate the backup before moving the live database.
    // Keeping the staging directory under datadir makes the final rename
    // atomic on the same filesystem.
    let staging = tempfile::Builder::new()
        .prefix(".db.restore-")
        .tempdir_in(&datadir)?;
    let staged_db = staging.path().join("db");
    copy_dir_all(&source_root, &staged_db)?;
    validate_checkpoint(&staged_db)?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let backup = if db_path.exists() {
        let bak = next_backup_path(&datadir, ts);
        std::fs::rename(&db_path, &bak)?;
        eprintln!("ℹ  Existing DB renamed to {}", bak.display());
        Some(bak)
    } else {
        None
    };

    if let Err(install_error) = std::fs::rename(&staged_db, &db_path) {
        if let Some(backup) = &backup {
            if let Err(rollback_error) = std::fs::rename(backup, &db_path) {
                return Err(format!(
                    "failed to install restored database: {install_error}; failed to restore previous database: {rollback_error}"
                )
                .into());
            }
        }
        return Err(format!("failed to install restored database: {install_error}").into());
    }

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
    let source_meta = std::fs::symlink_metadata(src)?;
    if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("backup entry is not a real directory: {}", src.display()),
        ));
    }

    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if ty.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "backup contains a symbolic link: {}",
                    entry.path().display()
                ),
            ));
        } else if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dest)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "backup contains an unsupported entry: {}",
                    entry.path().display()
                ),
            ));
        }
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &std::path::Path) -> std::io::Result<()> {
    let current_path = checkpoint.join("CURRENT");
    let current_meta = std::fs::symlink_metadata(&current_path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("backup checkpoint CURRENT file is unavailable: {error}"),
        )
    })?;
    if current_meta.file_type().is_symlink() || !current_meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backup checkpoint CURRENT entry must be a regular file",
        ));
    }

    let mut current = Vec::new();
    std::fs::File::open(&current_path)?
        .take(MAX_CURRENT_FILE_BYTES + 1)
        .read_to_end(&mut current)?;
    if current.len() as u64 > MAX_CURRENT_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backup checkpoint CURRENT file is too large",
        ));
    }

    let manifest = std::str::from_utf8(&current)
        .ok()
        .and_then(|value| value.strip_suffix('\n'))
        .filter(|value| {
            value.strip_prefix("MANIFEST-").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "backup checkpoint CURRENT file is malformed",
            )
        })?;

    let manifest_path = checkpoint.join(manifest);
    let manifest_meta = std::fs::symlink_metadata(&manifest_path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("backup checkpoint manifest is unavailable: {error}"),
        )
    })?;
    if manifest_meta.file_type().is_symlink() || !manifest_meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "backup checkpoint manifest must be a regular file",
        ));
    }

    Ok(())
}

fn next_backup_path(datadir: &std::path::Path, timestamp: u64) -> PathBuf {
    let initial = datadir.join(format!("db.bak.{timestamp}"));
    if !initial.exists() {
        return initial;
    }

    for suffix in 1u32.. {
        let candidate = datadir.join(format!("db.bak.{timestamp}.{suffix}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("u32 backup suffix space exhausted")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_rejects_invalid_source_without_moving_live_database() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"live database").unwrap();

        let invalid_backup = root.path().join("backup-file");
        std::fs::write(&invalid_backup, b"not a directory").unwrap();

        let error = restore_backup(datadir.clone(), invalid_backup).unwrap_err();

        assert!(error.to_string().contains("real directory"));
        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"live database"
        );
        assert_eq!(
            std::fs::read_dir(datadir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("db.bak."))
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_backup_symlinks_without_moving_live_database() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"live database").unwrap();

        let backup = root.path().join("backup");
        std::fs::create_dir_all(&backup).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"outside data").unwrap();
        symlink(&outside, backup.join("MANIFEST")).unwrap();

        let error = restore_backup(datadir, backup).unwrap_err();

        assert!(error.to_string().contains("symbolic link"));
        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"live database"
        );
    }

    #[test]
    fn restore_rejects_source_containing_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"live database").unwrap();

        let error = restore_backup(datadir.clone(), root.path().to_path_buf()).unwrap_err();

        assert!(error
            .to_string()
            .contains("must not contain data directory"));
        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"live database"
        );
    }

    #[test]
    fn restore_rejects_non_checkpoint_directory_without_moving_live_database() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"live database").unwrap();

        let backup = root.path().join("backup");
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("README"), b"not a RocksDB checkpoint").unwrap();

        let error = restore_backup(datadir.clone(), backup).unwrap_err();

        assert!(error.to_string().contains("CURRENT"));
        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"live database"
        );
        assert_eq!(
            std::fs::read_dir(datadir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("db.bak."))
                .count(),
            0
        );
    }

    #[test]
    fn restore_rejects_malformed_current_without_moving_live_database() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"live database").unwrap();

        let backup = root.path().join("backup");
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join("CURRENT"), b"../outside\n").unwrap();
        std::fs::write(root.path().join("outside"), b"not a manifest").unwrap();

        let error = restore_backup(datadir.clone(), backup).unwrap_err();

        assert!(error.to_string().contains("CURRENT file is malformed"));
        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"live database"
        );
        assert_eq!(
            std::fs::read_dir(datadir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("db.bak."))
                .count(),
            0
        );
    }

    #[test]
    fn restore_stages_backup_before_replacing_live_database() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db_path = datadir.join("db");
        std::fs::create_dir_all(&db_path).unwrap();
        std::fs::write(db_path.join("CURRENT"), b"old database").unwrap();

        let backup = root.path().join("backup");
        std::fs::create_dir_all(backup.join("nested")).unwrap();
        std::fs::write(backup.join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        std::fs::write(backup.join("MANIFEST-000001"), b"manifest").unwrap();
        std::fs::write(backup.join("nested").join("MANIFEST"), b"manifest").unwrap();

        restore_backup(datadir.clone(), backup).unwrap();

        assert_eq!(
            std::fs::read(db_path.join("CURRENT")).unwrap(),
            b"MANIFEST-000001\n"
        );
        assert_eq!(
            std::fs::read(db_path.join("nested").join("MANIFEST")).unwrap(),
            b"manifest"
        );
        let backups: Vec<_> = std::fs::read_dir(datadir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("db.bak."))
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(
            std::fs::read(backups[0].path().join("CURRENT")).unwrap(),
            b"old database"
        );
    }
}
