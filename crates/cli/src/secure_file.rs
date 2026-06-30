use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub(crate) fn write_sensitive_file_new(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
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
}
