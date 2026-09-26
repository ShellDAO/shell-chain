use crate::StorageError;

pub(crate) fn saturating_entry_len(key_len: usize, value_len: usize) -> u64 {
    u64::try_from(key_len)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(value_len).unwrap_or(u64::MAX))
}

pub type EntryVisitor<'a> = dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError> + 'a;

/// Operation in a write batch.
#[derive(Debug, Clone)]
pub enum WriteBatchOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// Batch of write operations.
///
/// Atomicity guarantees depend on the backend implementation:
/// - `RocksDbStore`: fully atomic (all-or-nothing via RocksDB WriteBatch)
/// - `MemoryDb`: best-effort under write lock; not rollback-safe on panic
#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    ops: Vec<WriteBatchOp>,
}

impl WriteBatch {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(WriteBatchOp::Put { key, value });
    }

    pub fn delete(&mut self, key: Vec<u8>) {
        self.ops.push(WriteBatchOp::Delete { key });
    }

    pub fn ops(&self) -> &[WriteBatchOp] {
        &self.ops
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Low-level key-value store trait.
///
/// Each implementation represents a single logical namespace
/// (e.g., one RocksDB column family). This design keeps the trait
/// compatible with `eth_trie::DB` and allows typed stores to compose
/// multiple `KvStore` instances for different data domains.
pub trait KvStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    fn flush(&self) -> Result<(), StorageError>;
    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError>;

    /// Copy selected prefixes from one consistent read view, bounded by estimated
    /// entry storage. Implementations must not combine independently timed reads.
    #[allow(clippy::type_complexity)]
    fn snapshot_prefixes(
        &self,
        _prefixes: &[&[u8]],
        _max_bytes: usize,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, StorageError> {
        Err(StorageError::Database(
            "consistent prefix snapshots unavailable".into(),
        ))
    }

    /// Check if a key exists without reading the full value.
    fn contains(&self, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(key)?.is_some())
    }

    /// Scan all keys with the given prefix, returning (key, value) pairs.
    /// Results are sorted by key in ascending byte order.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;

    /// Scan matching keys from inclusive `start` to exclusive `end`, in ascending
    /// byte order. No end means the remainder of the prefix. Backends can avoid
    /// materializing entries outside the range.
    #[allow(clippy::type_complexity)]
    fn scan_prefix_range(
        &self,
        prefix: &[u8],
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        if end.is_some_and(|end| start >= end) {
            return Ok(Vec::new());
        }
        Ok(self
            .scan_prefix(prefix)?
            .into_iter()
            .filter(|(key, _)| {
                key.as_slice() >= start && end.is_none_or(|end| key.as_slice() < end)
            })
            .collect())
    }

    /// Sum the byte lengths of keys and values matching `prefix`.
    ///
    /// Backends may override this to stream entries without materializing the
    /// full prefix scan in memory.
    fn prefix_size_bytes(&self, prefix: &[u8]) -> Result<u64, StorageError> {
        Ok(self
            .scan_prefix(prefix)?
            .iter()
            .fold(0u64, |total, (key, value)| {
                total.saturating_add(saturating_entry_len(key.len(), value.len()))
            }))
    }

    /// Scan keys with `prefix` after an optional exclusive key, stopping once
    /// `limit` entries have been collected. Results are sorted by ascending key.
    #[allow(clippy::type_complexity)]
    fn scan_prefix_after(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (key, value) in self.scan_prefix(prefix)? {
            if after.is_some_and(|after_key| key.as_slice() <= after_key) {
                continue;
            }
            out.push((key, value));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Scan all keys in the store, returning (key, value) pairs in ascending key order.
    #[allow(clippy::type_complexity)]
    fn scan_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.scan_prefix(&[])
    }

    /// Visit every entry in ascending key order without requiring the caller
    /// to retain the complete store contents.
    fn visit_all(&self, visitor: &mut EntryVisitor<'_>) -> Result<(), StorageError> {
        for (key, value) in self.scan_all()? {
            visitor(&key, &value)?;
        }
        Ok(())
    }
}

/// Include a conservative allocation allowance in addition to encoded bytes.
const SNAPSHOT_ENTRY_OVERHEAD_BYTES: usize = 128;

pub(crate) fn insert_snapshot_entry(
    entries: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    bytes: &mut usize,
    max_bytes: usize,
    key: &[u8],
    value: &[u8],
) -> Result<(), StorageError> {
    if entries.contains_key(key) {
        return Ok(());
    }
    *bytes = bytes
        .saturating_add(key.len())
        .saturating_add(value.len())
        .saturating_add(SNAPSHOT_ENTRY_OVERHEAD_BYTES);
    if *bytes > max_bytes {
        return Err(StorageError::Database(
            "prefix snapshot exceeds memory limit".into(),
        ));
    }
    entries.insert(key.to_vec(), value.to_vec());
    Ok(())
}

#[cfg(test)]
pub(crate) fn assert_address_history_range_scan(store: &impl KvStore) {
    for key in [b"a/0".as_slice(), b"a/1", b"a/2", b"a/\xff", b"b/0"] {
        store.put(key, key).unwrap();
    }
    let keys = |start: &[u8], end: Option<&[u8]>| {
        store
            .scan_prefix_range(b"a/", start, end)
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(b"a/1", Some(b"a/2")), vec![b"a/1".to_vec()]);
    assert_eq!(
        keys(b"a/2", None),
        vec![b"a/2".to_vec(), b"a/\xff".to_vec()]
    );
    assert_eq!(keys(b"", Some(b"a/1")), vec![b"a/0".to_vec()]);
    assert!(keys(b"a/2", Some(b"a/1")).is_empty());
    assert!(keys(b"a/1", Some(b"a/1")).is_empty());
    assert!(keys(b"b/", None).is_empty());
    assert!(store
        .scan_prefix_range(b"missing/", b"", None)
        .unwrap()
        .is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WriteBatch unit tests ───────────────────────────────────

    #[test]
    fn new_batch_is_empty() {
        let batch = WriteBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(batch.ops().is_empty());
    }

    #[test]
    fn default_batch_is_empty() {
        let batch = WriteBatch::default();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn put_increases_len() {
        let mut batch = WriteBatch::new();
        batch.put(b"k1".to_vec(), b"v1".to_vec());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());

        batch.put(b"k2".to_vec(), b"v2".to_vec());
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn delete_increases_len() {
        let mut batch = WriteBatch::new();
        batch.delete(b"k1".to_vec());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn ops_returns_correct_operations() {
        let mut batch = WriteBatch::new();
        batch.put(b"k1".to_vec(), b"v1".to_vec());
        batch.delete(b"k2".to_vec());
        batch.put(b"k3".to_vec(), b"v3".to_vec());

        let ops = batch.ops();
        assert_eq!(ops.len(), 3);

        assert!(matches!(&ops[0], WriteBatchOp::Put { key, value }
            if key == b"k1" && value == b"v1"));
        assert!(matches!(&ops[1], WriteBatchOp::Delete { key }
            if key == b"k2"));
        assert!(matches!(&ops[2], WriteBatchOp::Put { key, value }
            if key == b"k3" && value == b"v3"));
    }

    #[test]
    fn ops_preserves_insertion_order() {
        let mut batch = WriteBatch::new();
        for i in 0..10u8 {
            batch.put(vec![i], vec![i + 100]);
        }
        let ops = batch.ops();
        for (i, op) in ops.iter().enumerate() {
            match op {
                WriteBatchOp::Put { key, value } => {
                    assert_eq!(key, &vec![i as u8]);
                    assert_eq!(value, &vec![i as u8 + 100]);
                }
                WriteBatchOp::Delete { .. } => panic!("unexpected delete at index {i}"),
            }
        }
    }

    #[test]
    fn mixed_put_delete_ordering() {
        let mut batch = WriteBatch::new();
        batch.put(b"a".to_vec(), b"1".to_vec());
        batch.delete(b"a".to_vec());
        batch.put(b"a".to_vec(), b"2".to_vec());

        let ops = batch.ops();
        assert_eq!(ops.len(), 3);
        // All three operations should be recorded in order
        assert!(matches!(&ops[0], WriteBatchOp::Put { .. }));
        assert!(matches!(&ops[1], WriteBatchOp::Delete { .. }));
        assert!(matches!(&ops[2], WriteBatchOp::Put { .. }));
    }

    #[test]
    fn batch_clone_is_independent() {
        let mut batch = WriteBatch::new();
        batch.put(b"k".to_vec(), b"v".to_vec());

        let mut cloned = batch.clone();
        cloned.delete(b"k".to_vec());

        assert_eq!(batch.len(), 1);
        assert_eq!(cloned.len(), 2);
    }

    #[test]
    fn batch_debug_format() {
        let batch = WriteBatch::new();
        let debug = format!("{:?}", batch);
        assert!(debug.contains("WriteBatch"));
    }

    #[test]
    fn write_batch_op_debug_format() {
        let put = WriteBatchOp::Put {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let del = WriteBatchOp::Delete { key: b"k".to_vec() };
        assert!(format!("{:?}", put).contains("Put"));
        assert!(format!("{:?}", del).contains("Delete"));
    }

    // ── KvStore::contains default method test (via MemoryDb) ────

    #[test]
    fn contains_default_impl_delegates_to_get() {
        use crate::MemoryDb;

        let db = MemoryDb::new();
        assert!(!db.contains(b"missing").unwrap());
        db.put(b"present", b"val").unwrap();
        assert!(db.contains(b"present").unwrap());
        db.delete(b"present").unwrap();
        assert!(!db.contains(b"present").unwrap());
    }

    #[test]
    fn entry_length_saturates() {
        assert_eq!(saturating_entry_len(usize::MAX, usize::MAX), u64::MAX);
    }
    fn assert_consistent_snapshot<S: KvStore + 'static>(store: std::sync::Arc<S>) {
        let put_pair = |n: u64| {
            let mut batch = WriteBatch::new();
            batch.put(b"a/x".to_vec(), n.to_be_bytes().to_vec());
            batch.put(b"b/x".to_vec(), n.to_be_bytes().to_vec());
            store.write_batch(batch).unwrap();
        };
        put_pair(0);
        store.put(b"excluded", b"value").unwrap();
        let snapshot = store
            .snapshot_prefixes(&[b"a/", b"a/x", b"b/"], 278)
            .unwrap();
        assert_eq!(snapshot.len(), 2);
        assert!(store.snapshot_prefixes(&[b"a/", b"b/"], 277).is_err());
        let writer_store = std::sync::Arc::clone(&store);
        let writer = std::thread::spawn(move || {
            for n in 1u64..1000 {
                let mut batch = WriteBatch::new();
                batch.put(b"a/x".to_vec(), n.to_be_bytes().to_vec());
                batch.put(b"b/x".to_vec(), n.to_be_bytes().to_vec());
                writer_store.write_batch(batch).unwrap();
            }
        });
        for _ in 0..1000 {
            let current = store.snapshot_prefixes(&[b"a/", b"b/"], 278).unwrap();
            assert_eq!(
                current.get(b"a/x".as_slice()),
                current.get(b"b/x".as_slice())
            );
        }
        writer.join().unwrap();
        assert_eq!(
            snapshot.get(b"a/x".as_slice()).unwrap(),
            &0u64.to_be_bytes()
        );
    }

    #[test]
    fn memory_snapshot_is_bounded_and_consistent() {
        assert_consistent_snapshot(std::sync::Arc::new(crate::MemoryDb::new()));
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocks_snapshot_is_bounded_and_consistent() {
        let directory = tempfile::tempdir().unwrap();
        let stores = crate::RocksDbStore::open_all(directory.path(), None).unwrap();
        assert_consistent_snapshot(std::sync::Arc::new(stores.chain));
    }
}
