use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::{KvStore, StorageError, WriteBatch, WriteBatchOp};

/// A copy-on-write view over a key-value store.
///
/// Reads fall through to the base store while writes remain private until
/// [`commit`](Self::commit) is called.
pub struct OverlayStore<S: KvStore> {
    base: Arc<S>,
    changes: RwLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl<S: KvStore> OverlayStore<S> {
    pub fn new(base: Arc<S>) -> Self {
        Self {
            base,
            changes: RwLock::new(BTreeMap::new()),
        }
    }

    /// Atomically apply all pending changes to the base store.
    pub fn commit(&self) -> Result<(), StorageError> {
        self.commit_with_batch(WriteBatch::new())
    }

    /// Snapshot the currently staged writes for later per-operation rollback
    /// journaling. The snapshot does not include values read through from the
    /// base store.
    pub fn checkpoint(&self) -> Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>, StorageError> {
        self.changes
            .read()
            .map(|changes| changes.clone())
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Return the values visible at `checkpoint` for keys whose staged value
    /// has since changed and matches one of `prefixes`.
    #[allow(clippy::type_complexity)]
    pub fn previous_values_since(
        &self,
        checkpoint: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        prefixes: &[&[u8]],
    ) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, StorageError> {
        let changes = self
            .changes
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut previous = Vec::new();
        for (key, value) in changes.iter() {
            if !prefixes.iter().any(|prefix| key.starts_with(prefix))
                || checkpoint.get(key) == Some(value)
            {
                continue;
            }
            let old_value = match checkpoint.get(key) {
                Some(value) => value.clone(),
                None => self.base.get(key)?,
            };
            previous.push((key.clone(), old_value));
        }
        Ok(previous)
    }

    /// Atomically apply pending changes together with an additional batch.
    ///
    /// Additional operations are appended after overlay changes, so explicit
    /// commit metadata wins if both batches contain the same key.
    pub fn commit_with_batch(&self, additional: WriteBatch) -> Result<(), StorageError> {
        let mut changes = self
            .changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut batch = WriteBatch::new();
        for (key, value) in changes.iter() {
            match value {
                Some(value) => batch.put(key.clone(), value.clone()),
                None => batch.delete(key.clone()),
            }
        }
        for op in additional.ops() {
            match op {
                WriteBatchOp::Put { key, value } => batch.put(key.clone(), value.clone()),
                WriteBatchOp::Delete { key } => batch.delete(key.clone()),
            }
        }
        self.base.write_batch(batch)?;
        changes.clear();
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn merged_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> =
            self.base.scan_prefix(prefix)?.into_iter().collect();
        let changes = self
            .changes
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        for (key, value) in changes.iter().filter(|(key, _)| key.starts_with(prefix)) {
            match value {
                Some(value) => {
                    entries.insert(key.clone(), value.clone());
                }
                None => {
                    entries.remove(key);
                }
            }
        }
        Ok(entries.into_iter().collect())
    }
}

impl<S: KvStore> KvStore for OverlayStore<S> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if let Some(value) = self
            .changes
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?
            .get(key)
        {
            return Ok(value.clone());
        }
        self.base.get(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?
            .insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?
            .insert(key.to_vec(), None);
        Ok(())
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let mut changes = self
            .changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        for op in batch.ops() {
            match op {
                WriteBatchOp::Put { key, value } => {
                    changes.insert(key.clone(), Some(value.clone()));
                }
                WriteBatchOp::Delete { key } => {
                    changes.insert(key.clone(), None);
                }
            }
        }
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.merged_scan(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;

    #[test]
    fn changes_are_private_until_commit() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"item/a", b"old").unwrap();
        base.put(b"item/b", b"remove").unwrap();
        let overlay = OverlayStore::new(base.clone());

        overlay.put(b"item/a", b"new").unwrap();
        overlay.delete(b"item/b").unwrap();
        overlay.put(b"item/c", b"added").unwrap();

        assert_eq!(overlay.get(b"item/a").unwrap(), Some(b"new".to_vec()));
        assert_eq!(overlay.get(b"item/b").unwrap(), None);
        assert_eq!(base.get(b"item/a").unwrap(), Some(b"old".to_vec()));
        assert_eq!(base.get(b"item/b").unwrap(), Some(b"remove".to_vec()));

        overlay.commit().unwrap();
        assert_eq!(base.get(b"item/a").unwrap(), Some(b"new".to_vec()));
        assert_eq!(base.get(b"item/b").unwrap(), None);
        assert_eq!(base.get(b"item/c").unwrap(), Some(b"added".to_vec()));
    }

    #[test]
    fn commit_with_batch_applies_overlay_and_metadata_atomically() {
        let base = Arc::new(MemoryDb::new());
        let overlay = OverlayStore::new(base.clone());
        overlay.put(b"state/account", b"updated").unwrap();
        overlay.put(b"HEAD", b"stale").unwrap();

        let mut metadata = WriteBatch::new();
        metadata.put(b"block/1".to_vec(), b"encoded".to_vec());
        metadata.put(b"HEAD".to_vec(), b"canonical".to_vec());
        overlay.commit_with_batch(metadata).unwrap();

        assert_eq!(
            base.get(b"state/account").unwrap(),
            Some(b"updated".to_vec())
        );
        assert_eq!(base.get(b"block/1").unwrap(), Some(b"encoded".to_vec()));
        assert_eq!(base.get(b"HEAD").unwrap(), Some(b"canonical".to_vec()));
    }

    #[test]
    fn previous_values_since_checkpoint_tracks_base_and_staged_values() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"pk/account-a", b"base").unwrap();
        let overlay = OverlayStore::new(base);
        overlay.put(b"pk/account-a", b"first").unwrap();
        overlay.put(b"gc/account-b", b"config").unwrap();
        let checkpoint = overlay.checkpoint().unwrap();

        overlay.put(b"pk/account-a", b"second").unwrap();
        overlay.delete(b"gc/account-b").unwrap();
        overlay.put(b"unrelated", b"ignored").unwrap();

        assert_eq!(
            overlay
                .previous_values_since(&checkpoint, &[b"pk/", b"gc/"])
                .unwrap(),
            vec![
                (b"gc/account-b".to_vec(), Some(b"config".to_vec())),
                (b"pk/account-a".to_vec(), Some(b"first".to_vec())),
            ]
        );
    }
}
