# Live physical checkpoints

Status: accepted

## Context

The offline backup command opens RocksDB separately and therefore requires the
node to stop. Hot backups need the existing live database handle. A logical scan
can mix account state, canonical metadata and receipts from different writes.

## Decision

Expose the existing RocksDB checkpoint primitive through `KvStore`, with an
unsupported default for backends without physical checkpoint support. A RocksDB
column-family handle shares the full database, so the operation includes every
column family. Canonical state and metadata already publish in an atomic batch;
the physical checkpoint captures a consistent database sequence cut. Startup
continues to apply ordinary recovery to any unfinalized suffix.

Add a no-argument method in the opt-in admin namespace. The CLI selects a unique
path under its data directory's backups root. Reject symlink roots, destinations
inside the live database, existing destinations and supplied RPC paths. Run the
blocking native operation outside the async executor, retaining a shared permit
until completion even if the request is cancelled. Reject concurrent operations
instead of queuing unbounded filesystem work.

## Consequences

The source node continues processing transactions. Checkpoints are server-local
artifacts and require independent storage for disaster recovery; keys, trusted
genesis and mempool contents are separate recovery inputs. Restore remains an
offline operation with its existing validation, lock and rollback behavior. No
consensus parameter, activation boundary or database format changes.
