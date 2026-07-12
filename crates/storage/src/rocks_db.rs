//! RocksDB-backed implementation of [`KvStore`].
//!
//! [`RocksDbStore`] wraps a single RocksDB column family, exposing it through
//! the [`KvStore`] trait. Multiple `RocksDbStore` instances can share the same
//! underlying `rocksdb::DB` via `Arc`, each targeting a different column family.
//!
//! # Column Families
//!
//! Shell-chain uses 4 column families:
//! - **`state`**: account trie nodes (WorldState)
//! - **`chain`**: block headers, bodies, canonical index (ChainStore)
//! - **`receipts`**: transaction receipts
//! - **`index`**: secondary indexes (tx-hash → block, etc.)
//!
//! # Usage
//!
//! ```ignore
//! use shell_storage::{RocksDbStore, RocksDbConfig};
//!
//! let stores = RocksDbStore::open_all("/tmp/shell-chain-db", None)?;
//! let state_store = &stores.state;
//! let chain_store = &stores.chain;
//! ```

use std::path::Path;
use std::sync::Arc;

use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompactionStyle,
    DBCompressionType, DBWithThreadMode, MultiThreaded, Options, WriteBatch as RocksWriteBatch,
};

use crate::{KvStore, StorageError, WriteBatch, WriteBatchOp};

/// Column family names used by shell-chain.
pub const CF_STATE: &str = "state";
pub const CF_CHAIN: &str = "chain";
pub const CF_RECEIPTS: &str = "receipts";
pub const CF_INDEX: &str = "index";
/// Witness column family: stores `WitnessBundle` per block (Phase B).
/// Kept separate from `chain` CF to allow independent pruning after finality.
pub const CF_WITNESS: &str = "witness";

type RocksDb = DBWithThreadMode<MultiThreaded>;

/// Compression strategy per column family type.
///
/// Applied as per-level compression to RocksDB column families.
/// Level 0-1 use the hot-tier (typically None for minimal CPU overhead).
/// Level 2+ use the cold-tier (Zstd for maximum disk savings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfCompressionStrategy {
    /// No compression on any level (fastest writes, largest disk).
    None,
    /// Snappy on all levels (low CPU overhead, modest compression).
    Snappy,
    /// None on L0-L1 (hot), Zstd on L2+ (cold). Best for bulk chain/receipt data.
    ZstdCold,
}

/// Tuning configuration for the RocksDB engine.
///
/// Pass to [`RocksDbStore::open_all`] to override defaults. All fields have
/// sensible defaults via [`RocksDbConfig::default()`] that are suitable for
/// development and light workloads. For production nodes, tune based on
/// available RAM and disk characteristics.
///
/// # Example
///
/// ```ignore
/// let cfg = RocksDbConfig {
///     block_cache_mb: 256,
///     write_buffer_mb: 128,
///     ..Default::default()
/// };
/// let stores = RocksDbStore::open_all("/data/shell-chain", Some(cfg))?;
/// ```
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    /// LRU block cache size in megabytes. Shared across all column families.
    /// Higher values reduce disk reads for hot data.
    pub block_cache_mb: usize,
    /// Write buffer (memtable) size per column family in megabytes.
    pub write_buffer_mb: usize,
    /// Maximum number of write buffers per column family before stalling.
    pub max_write_buffers: i32,
    /// RocksDB compaction style. `Level` is best for most blockchain workloads.
    pub compaction_style: RocksCompactionStyle,
    /// Compression strategy for high-volume CFs (chain, receipts).
    ///
    /// Defaults to [`CfCompressionStrategy::ZstdCold`] which applies Zstd on
    /// compaction levels 2+ where 90%+ of bulk signature/block data resides.
    /// Expected to reduce on-disk size by 40-60% for PQ transaction data.
    pub bulk_compression: CfCompressionStrategy,
}

/// Compaction strategy selection (mirrors `rocksdb::DBCompactionStyle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RocksCompactionStyle {
    Level,
    Universal,
    Fifo,
}

impl Default for RocksDbConfig {
    fn default() -> Self {
        Self {
            block_cache_mb: 128,
            write_buffer_mb: 64,
            max_write_buffers: 3,
            compaction_style: RocksCompactionStyle::Level,
            bulk_compression: CfCompressionStrategy::ZstdCold,
        }
    }
}

fn mib_to_bytes(field: &str, value: usize) -> Result<usize, StorageError> {
    value
        .checked_mul(1024 * 1024)
        .ok_or_else(|| StorageError::InvalidInput(format!("{field} is too large")))
}

/// RocksDB-backed KvStore targeting a single column family.
///
/// Multiple instances can share the same `Arc<RocksDb>`, each operating
/// on a different column family. All operations are thread-safe.
#[derive(Clone)]
pub struct RocksDbStore {
    db: Arc<RocksDb>,
    cf_name: &'static str,
}

/// Collection of all RocksDB column family stores.
///
/// Returned by [`RocksDbStore::open_all`]. Each field is a `RocksDbStore`
/// targeting its respective column family, sharing the same underlying DB.
pub struct RocksDbStores {
    pub state: RocksDbStore,
    pub chain: RocksDbStore,
    pub receipts: RocksDbStore,
    pub index: RocksDbStore,
    /// Witness bundles per block (Phase B). Prunable after finality.
    pub witness: RocksDbStore,
}

impl RocksDbStores {
    /// Verify database integrity by performing basic health checks (F-124).
    ///
    /// Reads a probe key from each column family to confirm the DB is
    /// accessible and not corrupted. Returns an error with recovery
    /// guidance if any column family is unreadable.
    pub fn verify_integrity(&self) -> Result<(), StorageError> {
        let stores = [
            (&self.state, CF_STATE),
            (&self.chain, CF_CHAIN),
            (&self.receipts, CF_RECEIPTS),
            (&self.index, CF_INDEX),
            (&self.witness, CF_WITNESS),
        ];
        for (store, cf_name) in &stores {
            store.get(b"__integrity_probe__").map_err(|e| {
                StorageError::Database(format!(
                    "integrity check failed for column family '{cf_name}': {e}. \
                     The database may be corrupted. \
                     Back up the database directory and try RocksDB repair."
                ))
            })?;
        }
        Ok(())
    }

    /// Create a consistent RocksDB checkpoint at `output_path`.
    ///
    /// Uses [`rocksdb::checkpoint::Checkpoint`] — the node does **not** need to
    /// be stopped. The checkpoint directory is a valid RocksDB database that can
    /// be opened directly or copied to another host.
    ///
    /// Hard-links are used for SST files when source and destination are on the
    /// same filesystem, making this operation near-instant regardless of DB size.
    pub fn create_checkpoint<P: AsRef<Path>>(&self, output_path: P) -> Result<(), StorageError> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.state.db)
            .map_err(|e| StorageError::Database(format!("checkpoint init: {e}")))?;
        checkpoint
            .create_checkpoint(output_path.as_ref())
            .map_err(|e| StorageError::Database(format!("checkpoint create: {e}")))?;
        Ok(())
    }
}

impl RocksDbStore {
    /// Open a RocksDB database at the given path with all shell-chain column families.
    ///
    /// Pass `None` for config to use [`RocksDbConfig::default()`].
    /// Creates the database and column families if they don't exist.
    /// Returns a [`RocksDbStores`] struct with one `RocksDbStore` per column family.
    pub fn open_all<P: AsRef<Path>>(
        path: P,
        config: Option<RocksDbConfig>,
    ) -> Result<RocksDbStores, StorageError> {
        let cfg = config.unwrap_or_default();

        let block_cache_bytes = mib_to_bytes("block_cache_mb", cfg.block_cache_mb)?;
        let write_buffer_bytes = mib_to_bytes("write_buffer_mb", cfg.write_buffer_mb)?;

        // Shared block cache across all CFs
        let cache = Cache::new_lru_cache(block_cache_bytes);
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&cache);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        // Build per-CF options with tuning parameters
        let make_cf_opts = |bulk: bool| {
            let mut opts = Options::default();
            opts.set_write_buffer_size(write_buffer_bytes);
            opts.set_max_write_buffer_number(cfg.max_write_buffers);
            opts.set_compaction_style(match cfg.compaction_style {
                RocksCompactionStyle::Level => DBCompactionStyle::Level,
                RocksCompactionStyle::Universal => DBCompactionStyle::Universal,
                RocksCompactionStyle::Fifo => DBCompactionStyle::Fifo,
            });
            opts.set_block_based_table_factory(&table_opts);

            // Apply compression strategy. For bulk CFs (chain, receipts) that
            // store large PQ signatures, ZstdCold uses no compression on hot
            // L0/L1 levels (fast writes) and Zstd on L2+ (cold storage, 2-4×
            // compression ratio on structured binary data).
            if bulk {
                match cfg.bulk_compression {
                    CfCompressionStrategy::None => {
                        opts.set_compression_type(DBCompressionType::None);
                    }
                    CfCompressionStrategy::Snappy => {
                        opts.set_compression_type(DBCompressionType::Snappy);
                    }
                    CfCompressionStrategy::ZstdCold => {
                        // set_compression_per_level is only meaningful for
                        // Level compaction (where each level is distinct).
                        // Universal and FIFO have no stable level mapping, so
                        // fall back to uniform Zstd to still get disk savings.
                        match cfg.compaction_style {
                            RocksCompactionStyle::Level => {
                                // 7 levels: L0=None, L1=None, L2-L6=Zstd
                                // Hot L0/L1 skip compression (write-heavy path);
                                // cold L2+ get Zstd (2-4× ratio on PQ sig data).
                                opts.set_compression_per_level(&[
                                    DBCompressionType::None,
                                    DBCompressionType::None,
                                    DBCompressionType::Zstd,
                                    DBCompressionType::Zstd,
                                    DBCompressionType::Zstd,
                                    DBCompressionType::Zstd,
                                    DBCompressionType::Zstd,
                                ]);
                            }
                            RocksCompactionStyle::Universal | RocksCompactionStyle::Fifo => {
                                // Universal: no stable level mapping; Fifo: no levels at all.
                                // Use uniform Zstd to still benefit from compression.
                                opts.set_compression_type(DBCompressionType::Zstd);
                            }
                        }
                    }
                }
            }
            // state and index CFs use RocksDB defaults (Snappy if enabled)

            opts
        };

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = [
            (CF_STATE, false),
            (CF_CHAIN, true),
            (CF_RECEIPTS, true),
            (CF_INDEX, false),
            (CF_WITNESS, false), // witness: default compression (Snappy); prunable CF
        ]
        .iter()
        .map(|(name, bulk)| ColumnFamilyDescriptor::new(*name, make_cf_opts(*bulk)))
        .collect();

        let db = RocksDb::open_cf_descriptors(&db_opts, &path, cf_descriptors).map_err(|e| {
            let msg = e.to_string();
            // F-124: Detect corruption and provide recovery guidance.
            if msg.contains("Corruption") || msg.contains("corruption") || msg.contains("MANIFEST")
            {
                StorageError::Database(format!(
                    "database corruption detected at '{}': {msg}. \
                         Recovery steps: \
                         1) Stop the node. \
                         2) Back up the database directory. \
                         3) Try `ldb repair --db=<path>` (RocksDB repair tool). \
                         4) If repair fails, re-sync from a snapshot or genesis.",
                    path.as_ref().display()
                ))
            } else {
                StorageError::Database(msg)
            }
        })?;

        let db = Arc::new(db);

        Ok(RocksDbStores {
            state: RocksDbStore {
                db: db.clone(),
                cf_name: CF_STATE,
            },
            chain: RocksDbStore {
                db: db.clone(),
                cf_name: CF_CHAIN,
            },
            receipts: RocksDbStore {
                db: db.clone(),
                cf_name: CF_RECEIPTS,
            },
            index: RocksDbStore {
                db: db.clone(),
                cf_name: CF_INDEX,
            },
            witness: RocksDbStore {
                db,
                cf_name: CF_WITNESS,
            },
        })
    }

    /// Get a reference to the column family handle.
    fn cf(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(self.cf_name)
            .expect("column family must exist — opened via open_all")
    }
}

impl KvStore for RocksDbStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.db
            .get_cf(&self.cf(), key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db
            .put_cf(&self.cf(), key, value)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.db
            .delete_cf(&self.cf(), key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db
            .flush_cf(&self.cf())
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let cf = self.cf();
        let mut rocks_batch = RocksWriteBatch::default();
        for op in batch.ops() {
            match op {
                WriteBatchOp::Put { key, value } => {
                    rocks_batch.put_cf(&cf, key, value);
                }
                WriteBatchOp::Delete { key } => {
                    rocks_batch.delete_cf(&cf, key);
                }
            }
        }
        self.db
            .write(rocks_batch)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn contains(&self, key: &[u8]) -> Result<bool, StorageError> {
        self.db
            .get_pinned_cf(&self.cf(), key)
            .map(|v| v.is_some())
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let cf = self.cf();
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let iter = self.db.iterator_cf_opt(
            &cf,
            opts,
            rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward),
        );
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if !k.starts_with(prefix) {
                break;
            }
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    fn scan_prefix_after(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cf = self.cf();
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let start = after.unwrap_or(prefix);
        let iter = self.db.iterator_cf_opt(
            &cf,
            opts,
            rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward),
        );
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if !k.starts_with(prefix) {
                break;
            }
            if after.is_some_and(|after_key| k.as_ref() <= after_key) {
                continue;
            }
            results.push((k.to_vec(), v.to_vec()));
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let cf = self.cf();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

impl std::fmt::Debug for RocksDbStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbStore")
            .field("cf_name", &self.cf_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, RocksDbStores) {
        let dir = tempfile::tempdir().unwrap();
        let stores = RocksDbStore::open_all(dir.path(), None).unwrap();
        (dir, stores)
    }

    #[test]
    fn open_and_close() {
        let (_dir, _stores) = open_temp();
        // Database opens and drops without error.
    }

    #[test]
    fn put_get_delete() {
        let (_dir, stores) = open_temp();
        let s = &stores.state;

        assert_eq!(s.get(b"k1").unwrap(), None);

        s.put(b"k1", b"v1").unwrap();
        assert_eq!(s.get(b"k1").unwrap(), Some(b"v1".to_vec()));

        s.delete(b"k1").unwrap();
        assert_eq!(s.get(b"k1").unwrap(), None);
    }

    #[test]
    fn contains_check() {
        let (_dir, stores) = open_temp();
        let s = &stores.chain;

        assert!(!s.contains(b"missing").unwrap());
        s.put(b"present", b"yes").unwrap();
        assert!(s.contains(b"present").unwrap());
    }

    #[test]
    fn write_batch_atomic() {
        let (_dir, stores) = open_temp();
        let s = &stores.receipts;

        s.put(b"to_delete", b"old").unwrap();

        let mut batch = WriteBatch::new();
        batch.put(b"a".to_vec(), b"1".to_vec());
        batch.put(b"b".to_vec(), b"2".to_vec());
        batch.delete(b"to_delete".to_vec());

        s.write_batch(batch).unwrap();

        assert_eq!(s.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(s.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(s.get(b"to_delete").unwrap(), None);
    }

    #[test]
    fn scan_all_returns_all_entries_in_key_order() {
        let (_dir, stores) = open_temp();
        let s = &stores.state;

        s.put(b"b", b"2").unwrap();
        s.put(b"a", b"1").unwrap();
        s.put(b"c", b"3").unwrap();

        let entries = s.scan_all().unwrap();
        assert_eq!(
            entries,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec()),
            ]
        );
    }

    #[test]
    fn column_families_are_isolated() {
        let (_dir, stores) = open_temp();

        stores.state.put(b"key", b"state_val").unwrap();
        stores.chain.put(b"key", b"chain_val").unwrap();

        assert_eq!(
            stores.state.get(b"key").unwrap(),
            Some(b"state_val".to_vec())
        );
        assert_eq!(
            stores.chain.get(b"key").unwrap(),
            Some(b"chain_val".to_vec())
        );
        assert_eq!(stores.receipts.get(b"key").unwrap(), None);
        assert_eq!(stores.index.get(b"key").unwrap(), None);
    }

    #[test]
    fn flush_succeeds() {
        let (_dir, stores) = open_temp();
        stores.state.put(b"k", b"v").unwrap();
        stores.state.flush().unwrap();
        assert_eq!(stores.state.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn reopen_persists_data() {
        let dir = tempfile::tempdir().unwrap();

        // Open, write, close
        {
            let stores = RocksDbStore::open_all(dir.path(), None).unwrap();
            stores.state.put(b"persist", b"value").unwrap();
            stores.chain.put(b"block", b"data").unwrap();
        }

        // Reopen and verify
        {
            let stores = RocksDbStore::open_all(dir.path(), None).unwrap();
            assert_eq!(
                stores.state.get(b"persist").unwrap(),
                Some(b"value".to_vec())
            );
            assert_eq!(stores.chain.get(b"block").unwrap(), Some(b"data".to_vec()));
        }
    }

    #[test]
    fn large_value_roundtrip() {
        let (_dir, stores) = open_temp();
        let s = &stores.state;

        // Simulate a Dilithium3 public key (~1952 bytes)
        let large_val = vec![0xABu8; 1952];
        s.put(b"pq_pubkey", &large_val).unwrap();
        assert_eq!(s.get(b"pq_pubkey").unwrap(), Some(large_val));
    }

    #[test]
    fn empty_batch_is_noop() {
        let (_dir, stores) = open_temp();
        let batch = WriteBatch::new();
        stores.state.write_batch(batch).unwrap();
    }

    #[test]
    fn custom_config_opens_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RocksDbConfig {
            block_cache_mb: 16,
            write_buffer_mb: 8,
            max_write_buffers: 2,
            compaction_style: RocksCompactionStyle::Universal,
            bulk_compression: CfCompressionStrategy::ZstdCold,
        };
        let stores = RocksDbStore::open_all(dir.path(), Some(cfg)).unwrap();
        stores.state.put(b"k", b"v").unwrap();
        assert_eq!(stores.state.get(b"k").unwrap(), Some(b"v".to_vec()));
        // Verify bulk CFs also work with Universal + ZstdCold (falls back to
        // uniform Zstd since Universal compaction has no stable level mapping)
        stores.chain.put(b"ck", b"cv").unwrap();
        assert_eq!(stores.chain.get(b"ck").unwrap(), Some(b"cv".to_vec()));
    }

    #[test]
    fn oversized_memory_config_is_rejected_without_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let block_cache_err = match RocksDbStore::open_all(
            dir.path(),
            Some(RocksDbConfig {
                block_cache_mb: usize::MAX,
                ..Default::default()
            }),
        ) {
            Ok(_) => panic!("oversized block cache must be rejected"),
            Err(err) => err,
        };
        assert!(block_cache_err
            .to_string()
            .contains("block_cache_mb is too large"));

        let write_buffer_err = match RocksDbStore::open_all(
            dir.path(),
            Some(RocksDbConfig {
                write_buffer_mb: usize::MAX,
                ..Default::default()
            }),
        ) {
            Ok(_) => panic!("oversized write buffer must be rejected"),
            Err(err) => err,
        };
        assert!(write_buffer_err
            .to_string()
            .contains("write_buffer_mb is too large"));
    }

    #[test]
    fn zstd_compression_roundtrip() {
        // Verifies that chain and receipts CFs using ZstdCold can correctly
        // store and retrieve data (compression is transparent to callers).
        let dir = tempfile::tempdir().unwrap();
        let cfg = RocksDbConfig {
            bulk_compression: CfCompressionStrategy::ZstdCold,
            ..Default::default()
        };
        let stores = RocksDbStore::open_all(dir.path(), Some(cfg)).unwrap();

        // Simulate realistic PQ transaction data sizes
        let sig_bytes = vec![0xD3u8; 3309]; // Dilithium3 signature
        let pubkey_bytes = vec![0xABu8; 1952]; // Dilithium3 public key
        let payload_bytes = vec![0x11u8; 140]; // Tx payload

        stores.chain.put(b"sig", &sig_bytes).unwrap();
        stores.chain.put(b"pk", &pubkey_bytes).unwrap();
        stores.receipts.put(b"payload", &payload_bytes).unwrap();

        assert_eq!(stores.chain.get(b"sig").unwrap(), Some(sig_bytes));
        assert_eq!(stores.chain.get(b"pk").unwrap(), Some(pubkey_bytes));
        assert_eq!(
            stores.receipts.get(b"payload").unwrap(),
            Some(payload_bytes)
        );
    }

    #[test]
    fn snappy_compression_strategy_opens() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RocksDbConfig {
            bulk_compression: CfCompressionStrategy::Snappy,
            ..Default::default()
        };
        let stores = RocksDbStore::open_all(dir.path(), Some(cfg)).unwrap();
        stores.chain.put(b"k", b"v").unwrap();
        assert_eq!(stores.chain.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn no_compression_strategy_opens() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RocksDbConfig {
            bulk_compression: CfCompressionStrategy::None,
            ..Default::default()
        };
        let stores = RocksDbStore::open_all(dir.path(), Some(cfg)).unwrap();
        stores.chain.put(b"k", b"v").unwrap();
        assert_eq!(stores.chain.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn verify_integrity_passes_on_healthy_db() {
        let (_dir, stores) = open_temp();
        stores.state.put(b"test", b"data").unwrap();
        assert!(stores.verify_integrity().is_ok());
    }

    #[test]
    fn verify_integrity_on_empty_db() {
        let (_dir, stores) = open_temp();
        assert!(stores.verify_integrity().is_ok());
    }
}
