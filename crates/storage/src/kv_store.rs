use crate::StorageError;

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

    /// Check if a key exists without reading the full value.
    fn contains(&self, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(key)?.is_some())
    }

    /// Scan all keys with the given prefix, returning (key, value) pairs.
    /// Results are sorted by key in ascending byte order.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;

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
}
