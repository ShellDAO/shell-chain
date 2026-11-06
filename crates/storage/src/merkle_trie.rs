use std::sync::Arc;

use eth_trie::{EthTrie, Trie};
use ethereum_types::H256;

use crate::trie_adapter::KvStoreTrieDb;
use crate::{KvStore, StorageError};

/// Ethereum-compatible Merkle Patricia Trie backed by any [`KvStore`].
///
/// Wraps [`eth_trie::EthTrie`] and maps errors to [`StorageError::Trie`].
/// Produces state roots identical to Ethereum given the same inputs.
///
/// **Phase 1 Accepted Risk (F-014):** The underlying `eth_trie` crate is
/// hardcoded to use Keccak-256 as its hash function. This is intentional
/// for Ethereum state compatibility in Phase 1. A migration to Verkle
/// Trees (with a PQ-friendly hash) is planned for Phase 2+.
pub struct MerkleTrie<S: KvStore> {
    trie: EthTrie<KvStoreTrieDb<S>>,
    root_is_hashed: bool,
}

impl<S: KvStore + 'static> MerkleTrie<S> {
    /// Create a new empty trie.
    pub fn new(store: Arc<S>) -> Self {
        let db = Arc::new(KvStoreTrieDb::new(store));
        Self {
            trie: EthTrie::new(db),
            root_is_hashed: false,
        }
    }

    /// Open an existing trie at the given root hash (32 bytes).
    pub fn at_root(store: Arc<S>, root: &[u8; 32]) -> Result<Self, StorageError> {
        let db = Arc::new(KvStoreTrieDb::new(store));
        let base = EthTrie::new(Arc::clone(&db));
        let root_hash = H256::from_slice(root);
        Ok(Self {
            trie: base.at_root(root_hash),
            root_is_hashed: true,
        })
    }

    /// Get a value by key.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.trie
            .get(key)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &[u8]) -> Result<bool, StorageError> {
        self.trie
            .contains(key)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }

    /// Insert or update a key-value pair.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.resolve_reopened_root()?;
        self.trie
            .insert(key, value)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }

    /// Remove a key from the trie.
    pub fn remove(&mut self, key: &[u8]) -> Result<bool, StorageError> {
        self.resolve_reopened_root()?;
        self.trie
            .remove(key)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }

    /// Compute and return the 32-byte trie root hash.
    pub fn root_hash(&mut self) -> Result<[u8; 32], StorageError> {
        if self.root_is_hashed {
            // Fail with StorageError for an unavailable root before eth_trie's
            // commit path, which assumes its root can always be recovered.
            self.trie
                .get(&[])
                .map_err(|e| StorageError::Trie(e.to_string()))?;
        }
        let h256 = self
            .trie
            .root_hash()
            .map_err(|e| StorageError::Trie(e.to_string()))?;
        self.root_is_hashed = false;
        Ok(h256.0)
    }

    fn resolve_reopened_root(&mut self) -> Result<(), StorageError> {
        if self.root_is_hashed {
            // A newly opened hash root has no pending mutations or cache
            // entries. root_hash only materializes that existing node here;
            // it performs no KV writes. Resolve before any mutation so this
            // path can never implicitly commit a caller's pending changes.
            // eth_trie::get_proof cannot encode its unresolved Hash root.
            self.root_hash()?;
        }
        Ok(())
    }

    /// Generate a Merkle proof for the given key. Commit pending mutations with
    /// `root_hash` first, so the proof refers to that saved root.
    pub fn get_proof(&mut self, key: &[u8]) -> Result<Vec<Vec<u8>>, StorageError> {
        self.resolve_reopened_root()?;
        self.trie
            .get_proof(key)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }

    /// Verify a Merkle proof against a root hash.
    pub fn verify_proof(
        store: Arc<S>,
        root_hash: &[u8; 32],
        key: &[u8],
        mut proof: Vec<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        // get_proof on the empty trie returns no nodes. Supply its unique
        // canonical empty node to the native verifier, which still checks
        // the requested root. Empty coverage for every other root rejects.
        if proof.is_empty() {
            proof.push(vec![0x80]);
        }
        let db = Arc::new(KvStoreTrieDb::new(store));
        let trie = EthTrie::new(db);
        let h256 = H256::from_slice(root_hash);
        trie.verify_proof(h256, key, proof)
            .map_err(|e| StorageError::Trie(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;

    struct ReadOnly(Arc<MemoryDb>);
    impl KvStore for ReadOnly {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.0.get(key)
        }
        fn put(&self, _: &[u8], _: &[u8]) -> Result<(), StorageError> {
            panic!("proof query attempted a KV put")
        }
        fn delete(&self, _: &[u8]) -> Result<(), StorageError> {
            panic!("proof query attempted a KV delete")
        }
        fn flush(&self) -> Result<(), StorageError> {
            panic!("proof query attempted a KV flush")
        }
        fn write_batch(&self, _: crate::WriteBatch) -> Result<(), StorageError> {
            panic!("proof query attempted a KV write batch")
        }
        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.0.scan_prefix(prefix)
        }
    }

    #[test]
    fn proof_reopened_root_is_read_only() {
        let db = Arc::new(MemoryDb::new());
        let mut writer = MerkleTrie::new(Arc::clone(&db));
        writer.insert(b"first", b"old account").unwrap();
        writer.insert(b"second", b"another account").unwrap();
        let old = writer.root_hash().unwrap();
        writer.insert(b"first", b"new account").unwrap();
        let current = writer.root_hash().unwrap();
        let before = db.scan_all().unwrap();
        let mut reopened = MerkleTrie::at_root(Arc::new(ReadOnly(Arc::clone(&db))), &old).unwrap();
        for key in [b"first".as_slice(), b"absent".as_slice()] {
            let proof = reopened.get_proof(key).unwrap();
            let value =
                MerkleTrie::verify_proof(Arc::new(MemoryDb::new()), &old, key, proof).unwrap();
            assert_eq!(
                value,
                if key == b"first" {
                    Some(b"old account".to_vec())
                } else {
                    None
                }
            );
        }
        assert_eq!(db.scan_all().unwrap(), before);
        let mut staged = MerkleTrie::at_root(Arc::new(ReadOnly(Arc::clone(&db))), &old).unwrap();
        staged.insert(b"pending", b"uncommitted").unwrap();
        assert!(!staged.remove(b"absent").unwrap());
        assert_eq!(
            staged.get(b"pending").unwrap(),
            Some(b"uncommitted".to_vec())
        );
        assert_eq!(db.scan_all().unwrap(), before);
        assert_eq!(
            MerkleTrie::at_root(Arc::clone(&db), &current)
                .unwrap()
                .get(b"first")
                .unwrap(),
            Some(b"new account".to_vec())
        );
        let mut missing = MerkleTrie::at_root(Arc::new(ReadOnly(db)), &[0x99; 32]).unwrap();
        assert!(missing.get_proof(b"key").is_err());
    }

    #[test]
    fn proof_empty_root_absence() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(Arc::clone(&db));
        let root = trie.root_hash().unwrap();
        let proof = trie.get_proof(b"absent").unwrap();
        assert!(proof.is_empty());
        assert_eq!(
            MerkleTrie::verify_proof(Arc::new(MemoryDb::new()), &root, b"absent", proof).unwrap(),
            None
        );
        assert!(MerkleTrie::verify_proof(
            Arc::new(MemoryDb::new()),
            &[0x99; 32],
            b"absent",
            vec![]
        )
        .is_err());
    }

    #[test]
    fn empty_trie_root_is_deterministic() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(db);
        let root = trie.root_hash().unwrap();
        assert_eq!(root.len(), 32);

        let db2 = Arc::new(MemoryDb::new());
        let mut trie2 = MerkleTrie::new(db2);
        assert_eq!(root, trie2.root_hash().unwrap());
    }

    #[test]
    fn insert_and_get() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(db);

        trie.insert(b"key1", b"value1").unwrap();
        assert_eq!(trie.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2").unwrap(), None);
    }

    #[test]
    fn insert_changes_root() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(db);

        let root_empty = trie.root_hash().unwrap();
        trie.insert(b"key", b"value").unwrap();
        let root_with_data = trie.root_hash().unwrap();
        assert_ne!(root_empty, root_with_data);
    }

    #[test]
    fn remove_key() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(db);

        trie.insert(b"key", b"value").unwrap();
        assert!(trie.contains(b"key").unwrap());

        trie.remove(b"key").unwrap();
        assert!(!trie.contains(b"key").unwrap());
    }

    #[test]
    fn root_hash_deterministic() {
        let db1 = Arc::new(MemoryDb::new());
        let mut trie1 = MerkleTrie::new(db1);
        trie1.insert(b"a", b"1").unwrap();
        trie1.insert(b"b", b"2").unwrap();

        let db2 = Arc::new(MemoryDb::new());
        let mut trie2 = MerkleTrie::new(db2);
        trie2.insert(b"a", b"1").unwrap();
        trie2.insert(b"b", b"2").unwrap();

        assert_eq!(trie1.root_hash().unwrap(), trie2.root_hash().unwrap());
    }

    #[test]
    fn proof_generation_and_verification() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(Arc::clone(&db));

        trie.insert(b"key1", b"value1").unwrap();
        trie.insert(b"key2", b"value2").unwrap();
        let root = trie.root_hash().unwrap();

        let proof = trie.get_proof(b"key1").unwrap();
        assert!(!proof.is_empty());

        let db2 = Arc::new(MemoryDb::new());
        let verified = MerkleTrie::<MemoryDb>::verify_proof(db2, &root, b"key1", proof).unwrap();
        assert_eq!(verified, Some(b"value1".to_vec()));
    }

    #[test]
    fn at_root_reopens_trie() {
        let db = Arc::new(MemoryDb::new());
        let mut trie = MerkleTrie::new(Arc::clone(&db));

        trie.insert(b"persist", b"data").unwrap();
        let root = trie.root_hash().unwrap();

        let trie2 = MerkleTrie::at_root(db, &root).unwrap();
        assert_eq!(trie2.get(b"persist").unwrap(), Some(b"data".to_vec()));
    }
}
