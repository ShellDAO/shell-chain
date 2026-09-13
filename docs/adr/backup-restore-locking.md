# Backup restore locking

Status: accepted

## Context

Renaming a database directory on Unix does not stop a running RocksDB instance
from accessing its files. A restore must refuse an active database while still
allowing replacement of an offline database whose contents cannot be opened.

## Decision

Use the existing `LOCK` file and the same nonblocking, whole-file POSIX `fcntl`
lock as RocksDB. Do not open the destination through the database engine merely
to test whether it is in use. Reject symbolic links and nonregular lock files.

Acquire the original and staged database locks after copying and validating the
checkpoint. Hold both through installation and any rollback. POSIX record locks
are process-associated: closing another descriptor for the same lock file can
release them, so copying must finish before either lock is acquired. The staged
lock follows its directory when installed and is released when restore exits.

## Consequences

Operators must stop the node before restoring. A competing database open fails
while restore holds its lock. Existing staging, rollback and corrupt-database
recovery behavior is preserved. This guard applies to Unix; other platforms
retain their existing filesystem behavior. It does not authorize concurrent
operator moves or edits of the database directory during restore.

The same native ownership check is shared with `removedb --force` on Unix. It
runs after the read-only size scan and before deletion, and refuses an already
open database without requiring its contents to be readable by RocksDB. A
preview does not acquire or create a lock. Unlike restore, removal unlinks the
lock file as part of deleting the directory; operators must prevent new node
starts for the entire operation. This is an active-owner check, not a guarantee
against concurrent process startup or manual directory replacement.
