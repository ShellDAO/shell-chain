use std::sync::Arc;

use crate::{KvStore, StorageError};

/// Adapter that bridges [`KvStore`] to [`eth_trie::DB`].
///
/// This allows any `KvStore` implementation (e.g., `MemoryDb`, future `RocksColumn`)
/// to serve as the backing store for an Ethereum-compatible Merkle Patricia Trie.
pub struct KvStoreTrieDb<S> {
    inner: Arc<S>,
}

impl<S> KvStoreTrieDb<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { inner: store }
    }
}

impl<S: KvStore> eth_trie::DB for KvStoreTrieDb<S> {
    type Error = StorageError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inner.get(key)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.inner.put(key, &value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        // eth_trie stores trie nodes by their 32-byte content hash. Deleting
        // those physical nodes during a normal trie update is unsafe because
        // older state roots can still reference them for rollback, snapshots,
        // or parallel WorldState handles. Historical pruning uses explicit
        // batch deletes and bypasses this adapter.
        if key.len() == 32 {
            return Ok(());
        }
        self.inner.delete(key)
    }

    fn flush(&self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;
    use eth_trie::DB;

    fn make_adapter() -> KvStoreTrieDb<MemoryDb> {
        KvStoreTrieDb::new(Arc::new(MemoryDb::new()))
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let adapter = make_adapter();
        adapter.insert(b"key1", b"value1".to_vec()).unwrap();
        assert_eq!(adapter.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }

    #[test]
    fn get_missing_returns_none() {
        let adapter = make_adapter();
        assert_eq!(adapter.get(b"nonexistent").unwrap(), None);
    }

    #[test]
    fn insert_overwrite() {
        let adapter = make_adapter();
        adapter.insert(b"key", b"v1".to_vec()).unwrap();
        adapter.insert(b"key", b"v2".to_vec()).unwrap();
        assert_eq!(adapter.get(b"key").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn remove_existing_key() {
        let adapter = make_adapter();
        adapter.insert(b"key", b"value".to_vec()).unwrap();
        adapter.remove(b"key").unwrap();
        assert_eq!(adapter.get(b"key").unwrap(), None);
    }

    #[test]
    fn remove_preserves_content_addressed_trie_nodes() {
        let adapter = make_adapter();
        let key = [0x11u8; 32];
        adapter.insert(&key, b"node".to_vec()).unwrap();
        adapter.remove(&key).unwrap();
        assert_eq!(adapter.get(&key).unwrap(), Some(b"node".to_vec()));
    }

    #[test]
    fn remove_nonexistent_is_ok() {
        let adapter = make_adapter();
        adapter.remove(b"nonexistent").unwrap();
    }

    #[test]
    fn flush_succeeds() {
        let adapter = make_adapter();
        adapter.insert(b"k", b"v".to_vec()).unwrap();
        adapter.flush().unwrap();
        // Data should still be accessible after flush
        assert_eq!(adapter.get(b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn multiple_keys() {
        let adapter = make_adapter();
        for i in 0..10u8 {
            adapter.insert(&[i], vec![i + 100]).unwrap();
        }
        for i in 0..10u8 {
            assert_eq!(adapter.get(&[i]).unwrap(), Some(vec![i + 100]));
        }
    }

    #[test]
    fn shared_arc_reflects_writes() {
        let store = Arc::new(MemoryDb::new());
        let adapter = KvStoreTrieDb::new(Arc::clone(&store));

        // Write through the adapter
        adapter.insert(b"via_adapter", b"yes".to_vec()).unwrap();
        // Read directly from the underlying store
        assert_eq!(store.get(b"via_adapter").unwrap(), Some(b"yes".to_vec()));

        // Write directly to the store
        store.put(b"via_store", b"also").unwrap();
        // Read through the adapter
        assert_eq!(adapter.get(b"via_store").unwrap(), Some(b"also".to_vec()));
    }

    #[test]
    fn empty_key_and_value() {
        let adapter = make_adapter();
        adapter.insert(b"", b"".to_vec()).unwrap();
        assert_eq!(adapter.get(b"").unwrap(), Some(b"".to_vec()));
    }

    #[test]
    fn large_value() {
        let adapter = make_adapter();
        let big_value = vec![0xABu8; 1024 * 1024]; // 1 MiB
        adapter.insert(b"big", big_value.clone()).unwrap();
        assert_eq!(adapter.get(b"big").unwrap(), Some(big_value));
    }
}
