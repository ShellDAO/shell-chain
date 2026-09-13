//! Native database ownership checks for offline maintenance commands.

/// Acquire the same whole-file POSIX lock used by RocksDB without opening the
/// database itself, so an offline corrupt database can still be maintained.
pub(super) fn lock_database(
    path: &std::path::Path,
) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, CWD};

    let directory = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let lock = rustix::fs::openat(
        &directory,
        "LOCK",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    let metadata = rustix::fs::fstat(&lock).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "database LOCK entry must be a regular file",
        ));
    }
    rustix::fs::fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        let cause = std::io::Error::from(error);
        std::io::Error::new(
            cause.kind(),
            format!("cannot lock database; stop the node before retrying: {cause}"),
        )
    })?;

    let opened = rustix::fs::fstat(&directory).map_err(std::io::Error::from)?;
    let current =
        rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
    if opened.st_dev != current.st_dev || opened.st_ino != current.st_ino {
        return Err(std::io::Error::other(
            "database path changed while acquiring maintenance lock",
        ));
    }
    Ok(Some(lock))
}
