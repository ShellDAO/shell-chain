use std::collections::HashMap;
use std::sync::RwLock;

use crate::kv_store::saturating_entry_len;
use crate::{KvStore, StorageError, WriteBatch, WriteBatchOp};

/// In-memory KV store for testing and lightweight use cases.
///
/// Write batches are applied under a single write lock but are **not**
/// rollback-safe — if a panic occurs mid-batch, partial writes persist.
#[derive(Debug, Default)]
pub struct MemoryDb {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryDb {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> Result<usize, StorageError> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(data.len())
    }

    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }
}

impl KvStore for MemoryDb {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(data.get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        data.remove(key);
        Ok(())
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        for op in batch.ops() {
            match op {
                WriteBatchOp::Put { key, value } => {
                    data.insert(key.clone(), value.clone());
                }
                WriteBatchOp::Delete { key } => {
                    data.remove(key);
                }
            }
        }
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut results: Vec<(Vec<u8>, Vec<u8>)> = data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn prefix_size_bytes(&self, prefix: &[u8]) -> Result<u64, StorageError> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(data.iter().filter(|(key, _)| key.starts_with(prefix)).fold(
            0u64,
            |total, (key, value)| {
                total.saturating_add(saturating_entry_len(key.len(), value.len()))
            },
        ))
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
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut results: Vec<(Vec<u8>, Vec<u8>)> = data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .filter(|(k, _)| after.is_none_or(|after_key| k.as_slice() > after_key))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        results.sort_by(|a, b| a.0.cmp(&b.0));
        results.truncate(limit);
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let db = MemoryDb::new();
        db.put(b"key1", b"value1").unwrap();
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let db = MemoryDb::new();
        assert_eq!(db.get(b"nonexistent").unwrap(), None);
    }

    #[test]
    fn put_overwrite() {
        let db = MemoryDb::new();
        db.put(b"key", b"v1").unwrap();
        db.put(b"key", b"v2").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn delete_existing() {
        let db = MemoryDb::new();
        db.put(b"key", b"value").unwrap();
        db.delete(b"key").unwrap();
        assert_eq!(db.get(b"key").unwrap(), None);
    }

    #[test]
    fn delete_nonexistent_is_ok() {
        let db = MemoryDb::new();
        db.delete(b"nonexistent").unwrap();
    }

    #[test]
    fn contains_key() {
        let db = MemoryDb::new();
        assert!(!db.contains(b"key").unwrap());
        db.put(b"key", b"value").unwrap();
        assert!(db.contains(b"key").unwrap());
    }

    #[test]
    fn write_batch_atomic() {
        let db = MemoryDb::new();
        db.put(b"to_delete", b"old").unwrap();

        let mut batch = WriteBatch::new();
        batch.put(b"key1".to_vec(), b"val1".to_vec());
        batch.put(b"key2".to_vec(), b"val2".to_vec());
        batch.delete(b"to_delete".to_vec());
        db.write_batch(batch).unwrap();

        assert_eq!(db.get(b"key1").unwrap(), Some(b"val1".to_vec()));
        assert_eq!(db.get(b"key2").unwrap(), Some(b"val2".to_vec()));
        assert_eq!(db.get(b"to_delete").unwrap(), None);
    }

    #[test]
    fn empty_batch_is_noop() {
        let db = MemoryDb::new();
        let batch = WriteBatch::new();
        assert!(batch.is_empty());
        db.write_batch(batch).unwrap();
        assert!(db.is_empty().unwrap());
    }

    #[test]
    fn flush_is_noop() {
        let db = MemoryDb::new();
        db.put(b"key", b"val").unwrap();
        db.flush().unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"val".to_vec()));
    }

    #[test]
    fn scan_all_returns_all_entries_in_key_order() {
        let db = MemoryDb::new();
        db.put(b"b", b"2").unwrap();
        db.put(b"a", b"1").unwrap();
        db.put(b"c", b"3").unwrap();

        let entries = db.scan_all().unwrap();
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
    fn len_and_is_empty() {
        let db = MemoryDb::new();
        assert!(db.is_empty().unwrap());
        assert_eq!(db.len().unwrap(), 0);
        db.put(b"k1", b"v1").unwrap();
        db.put(b"k2", b"v2").unwrap();
        assert_eq!(db.len().unwrap(), 2);
        assert!(!db.is_empty().unwrap());
    }
}
