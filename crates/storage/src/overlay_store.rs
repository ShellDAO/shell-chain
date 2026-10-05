use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::{KvStore, StorageError, WriteBatch, WriteBatchOp};

/// A copy-on-write view over a key-value store.
///
/// Reads fall through to the base store while writes remain private until
/// [`commit`](Self::commit) is called.
pub struct OverlayStore<S: KvStore> {
    base: Arc<S>,
    write_limit: Option<usize>,
    replay_namespace: Option<Vec<u8>>,
    staged_bytes: AtomicUsize,
    frozen_prefixes: Vec<Vec<u8>>,
    changes: RwLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl<S: KvStore> OverlayStore<S> {
    pub fn new(base: Arc<S>) -> Self {
        Self {
            base,
            write_limit: None,
            replay_namespace: None,
            staged_bytes: AtomicUsize::new(0),
            frozen_prefixes: Vec::new(),
            changes: RwLock::new(BTreeMap::new()),
        }
    }

    /// Freeze selected namespaces at one bounded consistent snapshot. Missing
    /// keys in these namespaces must not fall through to later base-store writes.
    /// This view is for read-only replay and cannot be committed.
    pub fn with_snapshot_prefixes(
        base: Arc<S>,
        prefixes: &[&[u8]],
        max_bytes: usize,
    ) -> Result<Self, StorageError> {
        let entries = base.snapshot_prefixes(prefixes, max_bytes)?;
        let staged_bytes = entries
            .iter()
            .map(|(key, value)| key.len() + value.len() + 64)
            .sum();
        Ok(Self {
            base,
            write_limit: None,
            replay_namespace: None,
            staged_bytes: AtomicUsize::new(staged_bytes),
            frozen_prefixes: prefixes.iter().map(|prefix| prefix.to_vec()).collect(),
            changes: RwLock::new(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, Some(value)))
                    .collect(),
            ),
        })
    }

    /// Limit private staged data, including an allowance for each map entry.
    /// A rejected write or batch leaves the overlay unchanged.
    pub fn with_write_limit(mut self, max_bytes: usize) -> Result<Self, StorageError> {
        if self.staged_bytes.load(Ordering::Relaxed) > max_bytes {
            return Err(StorageError::Database(
                "replay overlay write limit exceeded".into(),
            ));
        }
        self.write_limit = Some(max_bytes);
        Ok(self)
    }

    /// Use a caller-owned private namespace for durable replay checkpoints.
    /// Existing entries are visible beneath staged writes. The caller must use
    /// a fresh or authenticated namespace, separate from canonical store keys.
    pub fn with_replay_namespace(mut self, namespace: &[u8]) -> Result<Self, StorageError> {
        if namespace.is_empty() || self.frozen_prefixes.is_empty() {
            return Err(StorageError::InvalidInput(
                "durable replay requires a private namespace and frozen prefixes".into(),
            ));
        }
        self.replay_namespace = Some(namespace.to_vec());
        Ok(self)
    }

    /// Reopen an existing private replay without copying current live metadata.
    pub fn reopen_replay(
        base: Arc<S>,
        namespace: &[u8],
        prefixes: &[&[u8]],
    ) -> Result<Self, StorageError> {
        let mut overlay = Self::new(base);
        overlay.frozen_prefixes = prefixes.iter().map(|p| p.to_vec()).collect();
        overlay.with_replay_namespace(namespace)
    }

    fn replay_key(&self, suffix: &[u8]) -> Result<Vec<u8>, StorageError> {
        let namespace = self
            .replay_namespace
            .as_ref()
            .ok_or_else(|| StorageError::InvalidInput("replay namespace unavailable".into()))?;
        Ok([namespace.as_slice(), suffix].concat())
    }

    pub fn replay_checkpoint(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.base.get(&self.replay_key(b"cursor")?)
    }

    /// Persist a completed replay chunk and its cursor atomically. Only the
    /// private namespace is written; successful persistence releases staged RAM.
    pub fn persist_replay_checkpoint(&self, cursor: &[u8]) -> Result<(), StorageError> {
        let prefix = self.replay_key(b"data/")?;
        let mut changes = self
            .changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut batch = WriteBatch::new();
        for (key, value) in changes.iter() {
            let encoded = match value {
                Some(value) => [b"\x01".as_ref(), value.as_slice()].concat(),
                None => vec![0],
            };
            batch.put([prefix.as_slice(), key.as_slice()].concat(), encoded);
        }
        batch.put(self.replay_key(b"cursor")?, cursor.to_vec());
        self.base.write_batch(batch)?;
        changes.clear();
        self.staged_bytes.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Invalidate the cursor before reclaiming private replay data. Interrupted
    /// cleanup cannot leave a resumable cursor pointing at incomplete state.
    pub fn clear_replay(&self) -> Result<(), StorageError> {
        self.base.delete(&self.replay_key(b"cursor")?)?;
        let prefix = self.replay_key(b"data/")?;
        loop {
            let mut batch = WriteBatch::new();
            let mut after = None;
            for _ in 0..128 {
                // Do not retain a whole batch of potentially large values just
                // to remove their keys. Peak scan memory is one stored entry.
                let mut entries = self.base.scan_prefix_after(&prefix, after.as_deref(), 1)?;
                let Some((key, _)) = entries.pop() else { break };
                after = Some(key.clone());
                batch.delete(key);
            }
            if batch.is_empty() {
                return Ok(());
            }
            self.base.write_batch(batch)?;
        }
    }

    fn decode_replay_value(value: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match value {
            [0] => Ok(None),
            [1, rest @ ..] => Ok(Some(rest.to_vec())),
            _ => Err(StorageError::Database(
                "invalid persisted replay value".into(),
            )),
        }
    }

    fn unstaged_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.replay_namespace.is_some() {
            let prefix = self.replay_key(b"data/")?;
            if let Some(value) = self.base.get(&[prefix.as_slice(), key].concat())? {
                return Self::decode_replay_value(&value);
            }
        }
        if self
            .frozen_prefixes
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            return Ok(None);
        }
        self.base.get(key)
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

    /// Snapshot only staged writes whose keys match one of `prefixes`.
    ///
    /// This keeps narrow rollback journals proportional to the indexed data
    /// they protect instead of cloning unrelated state accumulated in the
    /// overlay.
    pub fn checkpoint_prefixes(
        &self,
        prefixes: &[&[u8]],
    ) -> Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>, StorageError> {
        let changes = self
            .changes
            .read()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let mut checkpoint = BTreeMap::new();
        for prefix in prefixes {
            for (key, value) in changes.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) {
                    break;
                }
                checkpoint.insert(key.clone(), value.clone());
            }
        }
        Ok(checkpoint)
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
        let mut previous = BTreeMap::new();
        for prefix in prefixes {
            for (key, value) in changes.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) {
                    break;
                }
                if checkpoint.get(key) == Some(value) {
                    continue;
                }
                let old_value = match checkpoint.get(key) {
                    Some(value) => value.clone(),
                    None => self.unstaged_value(key)?,
                };
                previous.insert(key.clone(), old_value);
            }
        }
        Ok(previous.into_iter().collect())
    }

    /// Atomically apply pending changes together with an additional batch.
    ///
    /// Additional operations are appended after overlay changes, so explicit
    /// commit metadata wins if both batches contain the same key.
    pub fn commit_with_batch(&self, additional: WriteBatch) -> Result<(), StorageError> {
        if !self.frozen_prefixes.is_empty() {
            return Err(StorageError::Database(
                "cannot commit a frozen replay overlay".into(),
            ));
        }
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
        self.staged_bytes.store(0, Ordering::Relaxed);
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn merged_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = if self
            .frozen_prefixes
            .iter()
            .any(|frozen| prefix.starts_with(frozen))
        {
            Vec::new()
        } else {
            self.base.scan_prefix(prefix)?
        }
        .into_iter()
        .filter(|(key, _)| {
            !self
                .frozen_prefixes
                .iter()
                .any(|frozen| key.starts_with(frozen))
        })
        .collect();
        if let Some(namespace) = &self.replay_namespace {
            entries.retain(|key, _| !key.starts_with(namespace));
            let data_prefix = self.replay_key(b"data/")?;
            let scan_prefix = [data_prefix.as_slice(), prefix].concat();
            for (key, value) in self.base.scan_prefix(&scan_prefix)? {
                let logical_key = key[data_prefix.len()..].to_vec();
                match Self::decode_replay_value(&value)? {
                    Some(value) => {
                        entries.insert(logical_key, value);
                    }
                    None => {
                        entries.remove(&logical_key);
                    }
                }
            }
        }
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
        self.unstaged_value(key)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.put(key.to_vec(), value.to_vec());
        self.write_batch(batch)
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.delete(key.to_vec());
        self.write_batch(batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let mut changes = self
            .changes
            .write()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        // Collapse duplicate keys before checking the final batch size. Borrow
        // values until the whole batch is accepted so rejection is atomic.
        let mut updates = BTreeMap::new();
        for op in batch.ops() {
            match op {
                WriteBatchOp::Put { key, value } => {
                    updates.insert(key, Some(value));
                }
                WriteBatchOp::Delete { key } => {
                    updates.insert(key, None);
                }
            }
        }
        let mut bytes = self.staged_bytes.load(Ordering::Relaxed);
        for (key, value) in &updates {
            if let Some(old) = changes.get(*key) {
                bytes -= key.len() + old.as_ref().map_or(0, Vec::len) + 64;
            }
            bytes = bytes.saturating_add(key.len() + value.map_or(0, Vec::len) + 64);
        }
        if self.write_limit.is_some_and(|limit| bytes > limit) {
            return Err(StorageError::Database(
                "replay overlay write limit exceeded".into(),
            ));
        }
        for (key, value) in updates {
            changes.insert(key.clone(), value.cloned());
        }
        self.staged_bytes.store(bytes, Ordering::Relaxed);
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

    #[cfg(feature = "rocksdb")]
    #[test]
    fn durable_replay_survives_process_exit() {
        const ENV: &str = "SHELL_REPLAY_TEST_DB";
        if let Some(path) = std::env::var_os(ENV) {
            let stores = crate::RocksDbStore::open_all(path, None).unwrap();
            let base = Arc::new(stores.chain);
            base.put(b"meta/key", b"live").unwrap();
            let overlay = OverlayStore::with_snapshot_prefixes(base, &[b"meta/"], 1024)
                .unwrap()
                .with_replay_namespace(b"private-test/")
                .unwrap()
                .with_write_limit(5 * 1024 * 1024)
                .unwrap();
            for index in 0..17u8 {
                overlay
                    .put(&[b's', index], &vec![index; 4 * 1024 * 1024])
                    .unwrap();
                overlay.put(b"meta/key", &[index]).unwrap();
                overlay.persist_replay_checkpoint(&[index]).unwrap();
            }
            // Exit without running RocksDB or overlay destructors. The next
            // process must recover the WAL, including the last cursor batch.
            std::process::exit(0);
        }
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_store::tests::durable_replay_survives_process_exit",
            ])
            .env(ENV, dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        let stores = crate::RocksDbStore::open_all(dir.path(), None).unwrap();
        let base = Arc::new(stores.chain);
        let overlay =
            OverlayStore::reopen_replay(base.clone(), b"private-test/", &[b"meta/"]).unwrap();
        assert_eq!(overlay.replay_checkpoint().unwrap(), Some(vec![16]));
        assert_eq!(overlay.get(b"meta/key").unwrap(), Some(vec![16]));
        assert_eq!(base.get(b"meta/key").unwrap(), Some(b"live".to_vec()));
        for index in 0..17u8 {
            assert_eq!(
                overlay.get(&[b's', index]).unwrap(),
                Some(vec![index; 4 * 1024 * 1024])
            );
            assert_eq!(base.get(&[b's', index]).unwrap(), None);
        }
        overlay.clear_replay().unwrap();
        assert!(base.scan_prefix(b"private-test/").unwrap().is_empty());
        assert_eq!(base.get(b"meta/key").unwrap(), Some(b"live".to_vec()));
    }

    #[test]
    fn durable_replay_preserves_frozen_values_tombstones_and_rollback_reads() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"meta/key", b"original").unwrap();
        base.put(b"state/deleted", b"live").unwrap();
        let overlay = OverlayStore::with_snapshot_prefixes(base.clone(), &[b"meta/"], 1024)
            .unwrap()
            .with_replay_namespace(b"private-replay/")
            .unwrap();
        overlay.put(b"meta/key", b"historical").unwrap();
        overlay.delete(b"state/deleted").unwrap();
        overlay.persist_replay_checkpoint(b"height-one").unwrap();
        drop(overlay);
        base.put(b"meta/new", b"later").unwrap();
        let reopened =
            OverlayStore::reopen_replay(base.clone(), b"private-replay/", &[b"meta/"]).unwrap();
        assert_eq!(
            reopened.replay_checkpoint().unwrap(),
            Some(b"height-one".to_vec())
        );
        assert_eq!(
            reopened.get(b"meta/key").unwrap(),
            Some(b"historical".to_vec())
        );
        assert_eq!(reopened.get(b"meta/new").unwrap(), None);
        assert_eq!(reopened.get(b"state/deleted").unwrap(), None);
        let before = reopened.checkpoint().unwrap();
        reopened.put(b"meta/key", b"next").unwrap();
        assert_eq!(
            reopened
                .previous_values_since(&before, &[b"meta/"])
                .unwrap(),
            vec![(b"meta/key".to_vec(), Some(b"historical".to_vec()))]
        );
        assert_eq!(
            reopened.scan_prefix(b"meta/").unwrap(),
            vec![(b"meta/key".to_vec(), b"next".to_vec())]
        );
        assert!(reopened
            .scan_prefix(b"")
            .unwrap()
            .iter()
            .all(|(key, _)| !key.starts_with(b"private-replay/")));
        assert_eq!(base.get(b"meta/key").unwrap(), Some(b"original".to_vec()));
        assert_eq!(base.get(b"state/deleted").unwrap(), Some(b"live".to_vec()));
        assert!(reopened.commit().is_err());
        reopened.clear_replay().unwrap();
        assert!(base.scan_prefix(b"private-replay/").unwrap().is_empty());
        assert_eq!(base.get(b"meta/key").unwrap(), Some(b"original".to_vec()));
        assert_eq!(base.get(b"state/deleted").unwrap(), Some(b"live".to_vec()));
    }

    #[test]
    fn durable_replay_spills_more_than_64_mib_in_bounded_chunks() {
        let base = Arc::new(MemoryDb::new());
        let chunk_size = 4 * 1024 * 1024;
        let overlay = OverlayStore::with_snapshot_prefixes(base.clone(), &[b"meta/"], 1024)
            .unwrap()
            .with_replay_namespace(b"private-replay/")
            .unwrap()
            .with_write_limit(chunk_size + 128)
            .unwrap();
        for index in 0u8..17 {
            let key = [b"state/".as_slice(), &[index]].concat();
            overlay.put(&key, &vec![index; chunk_size]).unwrap();
            overlay.persist_replay_checkpoint(&[index]).unwrap();
            assert_eq!(overlay.staged_bytes.load(Ordering::Relaxed), 0);
            assert_eq!(base.get(&key).unwrap(), None);
        }
        drop(overlay);
        let reopened = OverlayStore::reopen_replay(base, b"private-replay/", &[b"meta/"])
            .unwrap()
            .with_write_limit(chunk_size + 128)
            .unwrap();
        assert_eq!(reopened.replay_checkpoint().unwrap(), Some(vec![16]));
        for index in 0u8..17 {
            assert_eq!(
                reopened
                    .get(&[b"state/".as_slice(), &[index]].concat())
                    .unwrap(),
                Some(vec![index; chunk_size])
            );
        }
    }

    #[test]
    fn write_limit_rejects_whole_batch_and_reclaims_replaced_values() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"a", b"base").unwrap();
        let overlay = OverlayStore::new(base.clone())
            .with_write_limit(140)
            .unwrap();
        overlay.put(b"a", b"1234567890").unwrap();
        let before = overlay.checkpoint().unwrap();
        let mut batch = WriteBatch::new();
        batch.put(b"a".to_vec(), b"changed".to_vec());
        batch.put(b"b".to_vec(), b"oversized".to_vec());
        assert!(overlay.write_batch(batch).is_err());
        assert_eq!(overlay.checkpoint().unwrap(), before);
        assert!(overlay.put(b"huge", &[0; 200]).is_err());
        overlay.delete(b"a").unwrap();
        overlay.put(b"b", b"1234567890").unwrap();
        assert_eq!(overlay.get(b"a").unwrap(), None);
        let mut batch = WriteBatch::new();
        batch.put(b"b".to_vec(), vec![0; 200]);
        batch.put(b"b".to_vec(), b"short".to_vec());
        overlay.write_batch(batch).unwrap();
        assert_eq!(overlay.get(b"b").unwrap(), Some(b"short".to_vec()));
        assert_eq!(base.get(b"a").unwrap(), Some(b"base".to_vec()));
        assert_eq!(base.get(b"b").unwrap(), None);
    }

    #[test]
    fn address_history_range_scan_contract() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"a/1", b"old").unwrap();
        base.put(b"a/removed", b"old").unwrap();
        let store = OverlayStore::new(base);
        store.delete(b"a/removed").unwrap();
        crate::kv_store::assert_address_history_range_scan(&store);
    }

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

    #[test]
    fn prefix_checkpoint_excludes_unrelated_staged_writes() {
        let base = Arc::new(MemoryDb::new());
        let overlay = OverlayStore::new(base);
        overlay.put(b"state/account-a", &[7; 1024]).unwrap();
        overlay.put(b"pk/account-a", b"first").unwrap();
        overlay.put(b"gc/account-b", b"config").unwrap();

        let checkpoint = overlay.checkpoint_prefixes(&[b"pk/", b"gc/"]).unwrap();

        assert_eq!(checkpoint.len(), 2);
        assert_eq!(
            checkpoint.get(b"pk/account-a".as_slice()),
            Some(&Some(b"first".to_vec()))
        );
        assert_eq!(
            checkpoint.get(b"gc/account-b".as_slice()),
            Some(&Some(b"config".to_vec()))
        );
        assert!(!checkpoint.contains_key(b"state/account-a".as_slice()));
    }
    #[test]
    fn frozen_snapshot_hides_later_base_writes_and_cannot_commit() {
        let base = Arc::new(MemoryDb::new());
        base.put(b"meta/old", b"before").unwrap();
        let overlay =
            OverlayStore::with_snapshot_prefixes(Arc::clone(&base), &[b"meta/"], 1024).unwrap();
        base.delete(b"meta/old").unwrap();
        base.put(b"meta/new", b"after").unwrap();
        base.put(b"other", b"live").unwrap();
        assert_eq!(overlay.get(b"meta/old").unwrap(), Some(b"before".to_vec()));
        assert_eq!(overlay.get(b"meta/new").unwrap(), None);
        assert_eq!(overlay.get(b"other").unwrap(), Some(b"live".to_vec()));
        assert_eq!(
            overlay.scan_prefix(b"meta/").unwrap(),
            vec![(b"meta/old".to_vec(), b"before".to_vec())]
        );
        assert_eq!(overlay.scan_prefix(b"").unwrap().len(), 2);
        overlay.put(b"meta/new", b"private").unwrap();
        overlay.delete(b"meta/old").unwrap();
        assert_eq!(
            overlay.scan_prefix(b"meta/").unwrap(),
            vec![(b"meta/new".to_vec(), b"private".to_vec())]
        );
        assert!(overlay.commit().is_err());
        assert!(overlay.commit_with_batch(WriteBatch::new()).is_err());
        assert_eq!(base.get(b"meta/new").unwrap(), Some(b"after".to_vec()));
    }
}
