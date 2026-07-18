use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_SENSITIVE_FILE_SIZE: u64 = 1024 * 1024;

pub(crate) fn read_sensitive_file(path: &Path) -> io::Result<String> {
    let path_meta = std::fs::symlink_metadata(path)?;
    if path_meta.file_type().is_symlink() || !path_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sensitive file must be a regular file: {}", path.display()),
        ));
    }
    if path_meta.len() > MAX_SENSITIVE_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sensitive file exceeds {} bytes: {}",
                MAX_SENSITIVE_FILE_SIZE,
                path.display()
            ),
        ));
    }

    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let opened_meta = file.metadata()?;
        if path_meta.dev() != opened_meta.dev() || path_meta.ino() != opened_meta.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("sensitive file changed while opening: {}", path.display()),
            ));
        }
    }

    let mut bytes = Vec::new();
    file.take(MAX_SENSITIVE_FILE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SENSITIVE_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sensitive file exceeds {} bytes: {}",
                MAX_SENSITIVE_FILE_SIZE,
                path.display()
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) fn write_sensitive_file_new(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "sensitive file parent must be a real directory: {}",
                parent.display()
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    file.write_all(contents.as_ref())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_sensitive_file_refuses_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        write_sensitive_file_new(&path, b"first").unwrap();

        let err = write_sensitive_file_new(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    #[cfg(unix)]
    #[test]
    fn write_sensitive_file_uses_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.json");
        write_sensitive_file_new(&path, b"secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn read_sensitive_file_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let linked = dir.path().join("linked.json");
        std::fs::write(&target, b"secret").unwrap();
        symlink(&target, &linked).unwrap();

        let error = read_sensitive_file(&linked).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_sensitive_file_rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_SENSITIVE_FILE_SIZE + 1).unwrap();

        let error = read_sensitive_file(&path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn write_sensitive_file_rejects_symbolic_link_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        let linked_parent = dir.path().join("linked");
        std::fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &linked_parent).unwrap();

        let error =
            write_sensitive_file_new(&linked_parent.join("key.json"), b"secret").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!real_parent.join("key.json").exists());
    }
}
