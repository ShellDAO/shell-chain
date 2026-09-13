//! `shell-node removedb` — remove the chain database directory.

use std::path::{Path, PathBuf};

const MAX_DATABASE_TREE_DEPTH: usize = 128;
const MAX_DATABASE_TREE_ENTRIES: u64 = 1_000_000;

/// Remove the chain data directory.
///
/// Without `--force`, prints what would be removed and exits.
/// With `--force`, deletes the database directory.
pub fn removedb(datadir: PathBuf, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    if datadir.as_os_str().is_empty() {
        return Err("Data directory path must not be empty".into());
    }
    let db_path = datadir.join("db");

    let datadir_meta = match std::fs::symlink_metadata(&datadir) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Nothing to remove: {} does not exist.", db_path.display());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if datadir_meta.file_type().is_symlink() || !datadir_meta.is_dir() {
        return Err(format!(
            "Refusing to remove database through a non-directory or symbolic-link data path: {}",
            datadir.display()
        )
        .into());
    }

    let db_meta = match std::fs::symlink_metadata(&db_path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Nothing to remove: {} does not exist.", db_path.display());
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if db_meta.file_type().is_symlink() || !db_meta.is_dir() {
        return Err(format!(
            "Refusing to remove a non-directory or symbolic-link database path: {}",
            db_path.display()
        )
        .into());
    }

    // Calculate directory size for display.
    let dir_size = dir_size(&db_path)?;

    if !force {
        eprintln!("Would remove: {} ({} bytes)", db_path.display(), dir_size);
        eprintln!("Run with --force to actually delete.");
        return Ok(());
    }

    #[cfg(unix)]
    let _database_lock = super::database_lock::lock_database(&db_path)?;

    std::fs::remove_dir_all(&db_path)?;
    eprintln!("✓ Removed {} ({} bytes)", db_path.display(), dir_size);

    Ok(())
}

/// Recursively compute the total size of a directory.
fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut entries_seen = 0;
    dir_size_inner(path, 0, &mut entries_seen)
}

fn dir_size_inner(path: &Path, depth: usize, entries_seen: &mut u64) -> std::io::Result<u64> {
    if depth > MAX_DATABASE_TREE_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("database directory nesting exceeds {MAX_DATABASE_TREE_DEPTH} levels"),
        ));
    }

    let root_type = std::fs::symlink_metadata(path)?.file_type();
    if root_type.is_symlink() {
        return Ok(0);
    }
    if !root_type.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("database entry is not a directory: {}", path.display()),
        ));
    }

    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        *entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "database entry count overflowed",
            )
        })?;
        if *entries_seen > MAX_DATABASE_TREE_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("database tree exceeds {MAX_DATABASE_TREE_ENTRIES} entries"),
            ));
        }

        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let entry_size = if file_type.is_dir() {
            dir_size_inner(&entry.path(), depth + 1, entries_seen)?
        } else if file_type.is_file() {
            entry.metadata()?.len()
        } else {
            0
        };
        total = total.checked_add(entry_size).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "database size exceeds supported range",
            )
        })?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, feature = "rocksdb"))]
    #[test]
    fn remove_database_in_child_process() {
        let Some(datadir) = std::env::var_os("SHELL_TEST_REMOVE_DATA_DIR") else {
            return;
        };
        removedb(PathBuf::from(datadir), true).unwrap();
    }

    #[cfg(all(unix, feature = "rocksdb"))]
    #[test]
    fn removedb_refuses_database_held_open_by_another_process() {
        use shell_storage::{KvStore, RocksDbStore};

        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let db = datadir.join("db");
        let stores = RocksDbStore::open_all(&db, None).unwrap();
        stores.state.put(b"remove-marker", b"live").unwrap();
        let original_current = std::fs::read(db.join("CURRENT")).unwrap();
        let remove = || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::removedb::tests::remove_database_in_child_process",
                    "--nocapture",
                ])
                .env("SHELL_TEST_REMOVE_DATA_DIR", &datadir)
                .output()
                .unwrap()
        };

        let rejected = remove();
        assert!(
            !rejected.status.success(),
            "must refuse to remove an active database"
        );
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("stop the node"));
        assert_eq!(std::fs::read(db.join("CURRENT")).unwrap(), original_current);
        assert_eq!(
            stores.state.get(b"remove-marker").unwrap().unwrap(),
            b"live"
        );

        drop(stores);
        let removed = remove();
        assert!(removed.status.success(), "{removed:?}");
        assert!(!db.exists());
    }

    #[test]
    fn removedb_preview_does_not_create_lock_file() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        std::fs::create_dir(&db).unwrap();
        std::fs::write(db.join("CURRENT"), b"preview").unwrap();

        removedb(root.path().to_path_buf(), false).unwrap();

        assert_eq!(std::fs::read(db.join("CURRENT")).unwrap(), b"preview");
        assert_eq!(std::fs::read_dir(&db).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn removedb_refuses_abnormal_lock_entries() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        std::fs::create_dir(&db).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        symlink(&outside, db.join("LOCK")).unwrap();
        assert!(removedb(root.path().to_path_buf(), true).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(db.join("LOCK").is_symlink());

        std::fs::remove_file(db.join("LOCK")).unwrap();
        std::fs::create_dir(db.join("LOCK")).unwrap();
        assert!(removedb(root.path().to_path_buf(), true).is_err());
        assert!(db.join("LOCK").is_dir());
    }

    #[test]
    fn removedb_rejects_empty_data_directory() {
        let error = removedb(PathBuf::new(), false).unwrap_err();

        assert!(error.to_string().contains("must not be empty"));
    }

    #[cfg(unix)]
    #[test]
    fn directory_size_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&db).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(db.join("CURRENT"), b"live").unwrap();
        std::fs::write(outside.join("secret"), b"outside-data").unwrap();
        symlink(&outside, db.join("external")).unwrap();

        assert_eq!(dir_size(&db).unwrap(), 4);
    }

    #[test]
    fn directory_size_rejects_excessive_nesting() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        std::fs::create_dir(&db).unwrap();

        let mut nested = db.clone();
        for _ in 0..=128 {
            nested = nested.join("d");
            std::fs::create_dir(&nested).unwrap();
        }

        let error = dir_size(&db).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("nesting"));
    }

    #[cfg(unix)]
    #[test]
    fn removedb_refuses_symbolic_link_data_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real_datadir = root.path().join("real");
        let linked_datadir = root.path().join("linked");
        std::fs::create_dir_all(real_datadir.join("db")).unwrap();
        std::fs::write(real_datadir.join("db").join("CURRENT"), b"live").unwrap();
        symlink(&real_datadir, &linked_datadir).unwrap();

        let error = removedb(linked_datadir, true).unwrap_err();

        assert!(error.to_string().contains("symbolic-link data path"));
        assert!(real_datadir.join("db").join("CURRENT").exists());
    }

    #[cfg(unix)]
    #[test]
    fn removedb_refuses_symbolic_link_database_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        let real_db = root.path().join("real-db");
        std::fs::create_dir_all(&datadir).unwrap();
        std::fs::create_dir_all(&real_db).unwrap();
        std::fs::write(real_db.join("CURRENT"), b"live").unwrap();
        symlink(&real_db, datadir.join("db")).unwrap();

        let error = removedb(datadir, true).unwrap_err();

        assert!(error.to_string().contains("symbolic-link database path"));
        assert!(real_db.join("CURRENT").exists());
    }

    #[test]
    fn removedb_deletes_regular_database_directory() {
        let root = tempfile::tempdir().unwrap();
        let datadir = root.path().join("chain");
        std::fs::create_dir_all(datadir.join("db")).unwrap();
        std::fs::write(datadir.join("db").join("CURRENT"), b"live").unwrap();

        removedb(datadir.clone(), true).unwrap();

        assert!(!datadir.join("db").exists());
    }
}
