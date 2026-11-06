//! Bounded parent-state validation views over an independently trusted store.
//! These views do not prove consensus or transaction-body membership.
use crate::{
    chain_store::prefix, ChainConfig, ChainStore, KvStore, OverlayStore, StorageError, WorldState,
    WriteBatch, ADDRESS_METADATA_HISTORY_BLOCKS,
};
use shell_core::BlockHeader;
use shell_primitives::{Address, ShellHash};
use std::sync::Arc;
const MAX_VIEW_BYTES: usize = 64 * 1024 * 1024;
fn error(message: &str) -> StorageError {
    StorageError::State(message.into())
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, suffix].concat()
}
fn number_key(number: u64) -> Vec<u8> {
    key(prefix::HASH_BY_NUMBER, &number.to_be_bytes())
}

/// Read-only store for a sealed parent view. Only frozen metadata/context keys
/// and content-addressed trie-node reads are supported. It cannot be committed
/// or resampled from mutable live metadata by callers.
pub struct CanonicalParentStore<S: KvStore> {
    overlay: Arc<OverlayStore<S>>,
    prefixes: Vec<Vec<u8>>,
}
impl<S: KvStore> KvStore for CanonicalParentStore<S> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if key.len() == 32 {
            let value = self.overlay.get(key)?;
            if value.as_ref().is_some_and(|bytes| {
                shell_primitives::keccak256(bytes).as_bytes().as_slice() != key
            }) {
                return Err(error(
                    "non-content-addressed trie data in canonical parent view",
                ));
            }
            return Ok(value);
        }
        if self.prefixes.iter().any(|p| key.starts_with(p)) {
            self.overlay.get(key)
        } else {
            Err(error("read outside bounded canonical parent view"))
        }
    }

    fn put(&self, _: &[u8], _: &[u8]) -> Result<(), StorageError> {
        Err(error("canonical parent view is read-only"))
    }
    fn delete(&self, _: &[u8]) -> Result<(), StorageError> {
        Err(error("canonical parent view is read-only"))
    }
    fn flush(&self) -> Result<(), StorageError> {
        Err(error("canonical parent view is read-only"))
    }
    fn write_batch(&self, _: WriteBatch) -> Result<(), StorageError> {
        Err(error("canonical parent view is read-only"))
    }
    fn scan_prefix(&self, _: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Err(error("canonical parent view supports keyed reads only"))
    }
}
/// Frozen native authorization context at a retained canonical parent. The
/// expected tip is a caller trust anchor, not a proof of network consensus.
/// Canonical pointers/header ancestry are checked against the supplied store;
/// block bodies and undo journals remain trusted storage inputs.
pub struct CanonicalParentView<S: KvStore> {
    store: Arc<CanonicalParentStore<S>>,
    tip: ShellHash,
    parent: BlockHeader,
    config: ChainConfig,
}
impl<S: KvStore + 'static> CanonicalParentView<S> {
    pub fn tip(&self) -> ShellHash {
        self.tip
    }
    pub fn parent(&self) -> &BlockHeader {
        &self.parent
    }
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }
    pub fn store(&self) -> Arc<CanonicalParentStore<S>> {
        Arc::clone(&self.store)
    }
    pub fn world_state(&self) -> Result<WorldState<CanonicalParentStore<S>>, StorageError> {
        WorldState::at_root(self.store(), &self.parent.state_root)
    }
    pub fn registered_key(&self, address: &Address) -> Result<Option<Vec<u8>>, StorageError> {
        ChainStore::new(self.store()).get_pubkey(address)
    }
}
impl<S: KvStore + 'static> ChainStore<S> {
    /// Freeze the exact retained canonical parent, configuration and address
    /// metadata, then rewind complete native undo journals privately. Missing
    /// history, stale tips, inconsistent ancestry and unavailable snapshots fail
    /// closed. No current-key fallback or live metadata resampling is permitted.
    pub fn canonical_parent_view(
        &self,
        expected_tip: ShellHash,
        expected_parent: ShellHash,
    ) -> Result<CanonicalParentView<S>, StorageError> {
        let tip = self
            .get_header_by_hash(&expected_tip)?
            .ok_or_else(|| error("canonical tip header unavailable"))?;
        let parent = self
            .get_header_by_hash(&expected_parent)?
            .ok_or_else(|| error("canonical parent header unavailable"))?;
        if tip.hash() != expected_tip
            || parent.hash() != expected_parent
            || parent.number > tip.number
            || tip.number - parent.number > ADDRESS_METADATA_HISTORY_BLOCKS
        {
            return Err(error(
                "canonical parent ancestry or retention bound mismatch",
            ));
        }
        let initial_config = self
            .get_chain_config()?
            .ok_or_else(|| error("canonical configuration unavailable"))?;
        let mut headers = vec![(expected_tip, tip.clone())];
        while headers
            .last()
            .ok_or_else(|| error("missing ancestry"))?
            .1
            .number
            > parent.number
        {
            let previous = &headers.last().ok_or_else(|| error("missing ancestry"))?.1;
            let hash = previous.parent_hash;
            let next = self
                .get_header_by_hash(&hash)?
                .ok_or_else(|| error("canonical ancestor unavailable"))?;
            if next.hash() != hash || next.number.checked_add(1) != Some(previous.number) {
                return Err(error("canonical header link mismatch"));
            }
            headers.push((hash, next));
        }
        if headers.last().map(|p| p.0) != Some(expected_parent) {
            return Err(error("requested parent is not tip ancestor"));
        }
        let mut prefixes = vec![
            prefix::HEAD_BLOCK.to_vec(),
            prefix::CHAIN_CONFIG.to_vec(),
            prefix::PUBKEY_BY_ADDR.to_vec(),
            prefix::GUARDIAN_CONFIG.to_vec(),
            prefix::RECOVERY_PROPOSAL.to_vec(),
            number_key(0),
            key(
                prefix::HEADER_BY_HASH,
                initial_config.genesis_hash.as_bytes(),
            ),
        ];
        for (hash, header) in &headers {
            prefixes.push(number_key(header.number));
            for p in [
                prefix::HEADER_BY_HASH,
                prefix::BODY_BY_HASH,
                prefix::WITNESS_BY_HASH,
                prefix::SYSTEM_TXS_BY_HASH,
                prefix::ADDRESS_METADATA_UNDO,
            ] {
                prefixes.push(key(p, hash.as_bytes()));
            }
        }
        let refs = prefixes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let overlay = Arc::new(
            OverlayStore::with_snapshot_prefixes(Arc::clone(self.store()), &refs, MAX_VIEW_BYTES)?
                .with_write_limit(MAX_VIEW_BYTES)?,
        );
        let chain = ChainStore::new(Arc::clone(&overlay));
        if chain.get_head_hash()? != Some(expected_tip) {
            return Err(error("canonical tip changed before snapshot"));
        }
        let config = chain
            .get_chain_config()?
            .ok_or_else(|| error("snapshot configuration unavailable"))?;
        if config.genesis_hash != initial_config.genesis_hash
            || chain.get_block_hash_by_number(0)? != Some(config.genesis_hash)
        {
            return Err(error("canonical genesis identity mismatch"));
        }
        let genesis = chain
            .get_header_by_hash(&config.genesis_hash)?
            .ok_or_else(|| error("genesis header unavailable"))?;
        if genesis.number != 0 || genesis.hash() != config.genesis_hash {
            return Err(error("invalid canonical genesis header"));
        }
        let mut old_chain = Vec::new();
        for (hash, header) in &headers {
            if chain.get_block_hash_by_number(header.number)? != Some(*hash)
                || chain.get_header_by_hash(hash)?.as_ref() != Some(header)
            {
                return Err(error("snapshot canonical mapping/header mismatch"));
            }
            if *hash == expected_parent {
                continue;
            }
            // Require even empty journals: this view does not infer absence of
            // metadata changes from an uncommitted transaction-root field.
            if overlay
                .get(&key(prefix::ADDRESS_METADATA_UNDO, hash.as_bytes()))?
                .is_none()
            {
                return Err(error("canonical parent undo journal unavailable"));
            }
            let block = chain
                .get_block_by_hash(hash)?
                .ok_or_else(|| error("canonical rewind body unavailable"))?;
            if block.header != *header {
                return Err(error("canonical rewind body/header mismatch"));
            }
            old_chain.push(block);
        }
        old_chain.reverse();
        chain.restore_address_metadata(&old_chain)?;
        chain.set_head(&expected_parent)?;
        // The replay overlay is private and noncommittable; expose a sealed
        // reader so callers cannot override its frozen authorization metadata.
        let store = Arc::new(CanonicalParentStore { overlay, prefixes });
        WorldState::at_root(Arc::clone(&store), &parent.state_root)?.get_account(&Address::ZERO)?;
        Ok(CanonicalParentView {
            store,
            tip: expected_tip,
            parent,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;
    use shell_core::{Account, Block};
    use shell_primitives::U256;
    fn header(root: ShellHash, parent: ShellHash, number: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: parent,
            state_root: root,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Default::default(),
            number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: number,
            extra_data: Default::default(),
            proposer: Address::ZERO,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        }
    }
    fn block(header: BlockHeader) -> Block {
        Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }
    fn fixture() -> (Arc<MemoryDb>, Vec<Block>, Address) {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let address = Address::from([7; 32]);
        let mut world = WorldState::new(Arc::clone(&db));
        let mut account = Account::new_user_account(ShellHash::from([1; 32]), U256::from(100));
        world.set_account(&address, &account).unwrap();
        let genesis = block(header(world.state_root().unwrap(), ShellHash::ZERO, 0));
        let cfg = serde_json::from_value(
            serde_json::json!({"chain_id":10,"genesis_hash":genesis.hash()}),
        )
        .unwrap();
        cs.put_pubkey(&address, &[1, 2, 3]).unwrap();
        cs.commit_genesis_block(&genesis, &cfg).unwrap();
        let mut blocks = vec![genesis];
        // Storage-only journal fixtures, not executed key-rotation transactions.
        for number in 1..=2 {
            let overlay = Arc::new(OverlayStore::new(Arc::clone(&db)));
            let chain = ChainStore::new(Arc::clone(&overlay));
            let checkpoint = chain.address_metadata_checkpoint().unwrap();
            chain
                .put_pubkey(&address, &[number as u8 + 1, 2, 3])
                .unwrap();
            account.nonce = number;
            world.set_account(&address, &account).unwrap();
            let b = block(header(
                world.state_root().unwrap(),
                blocks.last().unwrap().hash(),
                number,
            ));
            chain
                .stage_address_metadata_undo(&b.hash(), &checkpoint)
                .unwrap();
            chain.commit_canonical_block(&b, None).unwrap();
            overlay.commit().unwrap();
            blocks.push(b);
        }
        (db, blocks, address)
    }
    #[test]
    fn canonical_parent_restores_history_and_freezes_absence_config_and_head() {
        let (db, blocks, address) = fixture();
        let before = db.scan_all().unwrap();
        let cs = ChainStore::new(Arc::clone(&db));
        let view = cs
            .canonical_parent_view(blocks[2].hash(), blocks[0].hash())
            .unwrap();
        assert_eq!(view.registered_key(&address).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(
            view.world_state()
                .unwrap()
                .get_account(&address)
                .unwrap()
                .unwrap()
                .nonce,
            0
        );
        assert_eq!(before, db.scan_all().unwrap());
        let absent = Address::from([9; 32]);
        assert_eq!(view.registered_key(&absent).unwrap(), None);
        cs.put_pubkey(&address, &[8]).unwrap();
        cs.put_pubkey(&absent, &[9]).unwrap();
        cs.set_head(&blocks[1].hash()).unwrap();
        db.put(prefix::CHAIN_CONFIG, b"corrupted live config")
            .unwrap();
        cs.set_canonical(0, &blocks[2].hash()).unwrap();
        assert_eq!(view.registered_key(&address).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(view.registered_key(&absent).unwrap(), None);
        assert_eq!(view.config().chain_id, 10);
        assert_eq!(
            ChainStore::new(view.store()).get_head_hash().unwrap(),
            Some(blocks[0].hash())
        );
        assert!(cs
            .canonical_parent_view(blocks[2].hash(), blocks[0].hash())
            .is_err());
        let readonly = view.store();
        assert!(readonly.put(b"pk/x", b"x").is_err());
        assert!(readonly.delete(b"HEAD").is_err());
        assert!(readonly.write_batch(WriteBatch::new()).is_err());
        assert!(readonly.flush().is_err());
        db.put(&[4; 32], b"mutable non-trie data").unwrap();
        assert!(readonly.get(&[4; 32]).is_err());
        assert!(readonly.get(b"unknown mutable namespace").is_err());
        assert!(readonly.snapshot_prefixes(&[b"pk/"], 1024).is_err());
    }
    #[test]
    fn canonical_parent_rejects_stale_noncanonical_missing_and_corrupt_history_without_writes() {
        let (db, blocks, _) = fixture();
        let entries = db.scan_all().unwrap();
        for mode in [
            "stale",
            "mapping",
            "header",
            "journal_missing",
            "journal_corrupt",
            "body_missing",
            "genesis",
        ] {
            let copy = Arc::new(MemoryDb::new());
            for (k, v) in &entries {
                copy.put(k, v).unwrap();
            }
            let chain = ChainStore::new(Arc::clone(&copy));
            match mode {
                "stale" => chain.set_head(&blocks[1].hash()).unwrap(),
                "mapping" => chain.set_canonical(1, &ShellHash::ZERO).unwrap(),
                "header" => copy
                    .put(
                        &key(prefix::HEADER_BY_HASH, blocks[1].hash().as_bytes()),
                        b"bad",
                    )
                    .unwrap(),
                "journal_missing" => copy
                    .delete(&key(
                        prefix::ADDRESS_METADATA_UNDO,
                        blocks[1].hash().as_bytes(),
                    ))
                    .unwrap(),
                "journal_corrupt" => copy
                    .put(
                        &key(prefix::ADDRESS_METADATA_UNDO, blocks[1].hash().as_bytes()),
                        b"bad",
                    )
                    .unwrap(),
                "body_missing" => copy
                    .delete(&key(prefix::BODY_BY_HASH, blocks[1].hash().as_bytes()))
                    .unwrap(),
                _ => chain.set_canonical(0, &ShellHash::ZERO).unwrap(),
            }
            let before = copy.scan_all().unwrap();
            assert!(
                chain
                    .canonical_parent_view(blocks[2].hash(), blocks[0].hash())
                    .is_err(),
                "{mode}"
            );
            assert_eq!(before, copy.scan_all().unwrap(), "{mode}");
        }
        assert_eq!(entries, db.scan_all().unwrap());
    }
    #[test]
    fn canonical_parent_accepts_tip_and_rejects_out_of_retention() {
        let (db, blocks, _) = fixture();
        let chain = ChainStore::new(Arc::clone(&db));
        let current = chain
            .canonical_parent_view(blocks[2].hash(), blocks[2].hash())
            .unwrap();
        assert_eq!(current.parent(), &blocks[2].header);
        let excessive = block(header(
            blocks[2].header.state_root,
            blocks[2].hash(),
            ADDRESS_METADATA_HISTORY_BLOCKS + 1,
        ));
        chain.commit_canonical_block(&excessive, None).unwrap();
        assert!(chain
            .canonical_parent_view(excessive.hash(), blocks[0].hash())
            .is_err());
        assert!(chain
            .canonical_parent_view(blocks[0].hash(), excessive.hash())
            .is_err());
    }
    struct AtSnapshot {
        db: Arc<MemoryDb>,
        replacement_head: ShellHash,
        before: bool,
    }
    impl KvStore for AtSnapshot {
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.db.get(k)
        }
        fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
            self.db.put(k, v)
        }
        fn delete(&self, k: &[u8]) -> Result<(), StorageError> {
            self.db.delete(k)
        }
        fn flush(&self) -> Result<(), StorageError> {
            self.db.flush()
        }
        fn write_batch(&self, b: WriteBatch) -> Result<(), StorageError> {
            self.db.write_batch(b)
        }
        fn scan_prefix(&self, p: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.db.scan_prefix(p)
        }
        fn snapshot_prefixes(
            &self,
            p: &[&[u8]],
            n: usize,
        ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, StorageError> {
            if self.before {
                self.db
                    .put(prefix::HEAD_BLOCK, self.replacement_head.as_bytes())?;
            }
            let snapshot = self.db.snapshot_prefixes(p, n)?;
            if !self.before {
                self.db
                    .put(prefix::HEAD_BLOCK, self.replacement_head.as_bytes())?;
                self.db
                    .put(prefix::CHAIN_CONFIG, b"changed after atomic snapshot")?;
            }
            Ok(snapshot)
        }
    }
    #[test]
    fn canonical_parent_atomic_point_rejects_before_and_preserves_after_changes() {
        for before in [true, false] {
            let (db, blocks, address) = fixture();
            let base = Arc::new(AtSnapshot {
                db,
                replacement_head: blocks[1].hash(),
                before,
            });
            let chain = ChainStore::new(base);
            let view = chain.canonical_parent_view(blocks[2].hash(), blocks[0].hash());
            if before {
                assert!(view.is_err());
            } else {
                let view = view.unwrap();
                assert_eq!(view.tip(), blocks[2].hash());
                assert_eq!(view.config().chain_id, 10);
                assert_eq!(view.registered_key(&address).unwrap(), Some(vec![1, 2, 3]));
            }
        }
    }
}
