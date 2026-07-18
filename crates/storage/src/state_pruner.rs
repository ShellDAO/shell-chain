//! State pruning: prevent unbounded storage growth by removing canonical
//! mappings for blocks outside the retention window.
//!
//! The [`StatePruner`] tracks which state roots are "active" (genesis,
//! finalized, current head) and which blocks have aged out of the retention
//! window.  When [`StatePruner::prune`] is called it deletes the canonical
//! `block_number → block_hash` mappings for prunable blocks, performing
//! lazy pruning — orphaned trie nodes remain in the KV store until a future
//! milestone adds reference-counted GC.

use std::collections::{BTreeMap, HashSet};

use shell_core::BlockHeader;
use shell_primitives::ShellHash;

use crate::chain_store::decode_versioned;
use crate::{KvStore, StorageError, WriteBatch};

/// Minimum allowed retention count (safety floor).
const MIN_RETENTION: u64 = 32;

/// Default retention count when none is specified.
const DEFAULT_RETENTION: u64 = 128;

/// Default pruning interval: run `prune()` every N blocks.
const DEFAULT_PRUNE_INTERVAL: u64 = 256;

/// Key prefix used by [`ChainStore`](crate::ChainStore) for canonical
/// `block_number → block_hash` mappings.  Duplicated here so the pruner
/// can operate on the same store without importing `ChainStore`.
const CANONICAL_PREFIX: &[u8] = b"n/";

/// Key prefix used by [`ChainStore`](crate::ChainStore) for block headers.
const HEADER_PREFIX: &[u8] = b"h/";

fn retention_cutoff(highest_block: u64, retention_count: u64) -> u64 {
    highest_block.saturating_sub(retention_count.saturating_sub(1))
}

/// Result of a single prune pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneResult {
    /// Number of canonical mappings deleted.
    pub pruned_count: u64,
    /// Number of blocks that were eligible but protected by active roots.
    pub protected_count: u64,
}

/// Maximum entries in block_roots before evicting oldest (F-304).
const MAX_BLOCK_ROOTS: usize = 10_000;

fn canonical_block_number(key: &[u8]) -> Result<u64, StorageError> {
    let number_bytes = key
        .strip_prefix(CANONICAL_PREFIX)
        .and_then(|suffix| <[u8; 8]>::try_from(suffix).ok())
        .ok_or_else(|| StorageError::Codec("invalid canonical mapping key".into()))?;
    Ok(u64::from_be_bytes(number_bytes))
}

/// Tracks active state roots and performs lazy pruning of canonical mappings.
///
/// # Safety invariants
/// - The genesis state root is **never** pruned.
/// - Any root in the `active_roots` set is **never** pruned.
/// - The retention count cannot drop below [`MIN_RETENTION`].
#[derive(Debug)]
pub struct StatePruner {
    /// Number of recent blocks whose state is always retained.
    retention_count: u64,
    /// Interval (in blocks) between automatic prune passes.
    prune_interval: u64,
    /// Genesis state root — always protected.
    genesis_root: Option<ShellHash>,
    /// Set of state roots explicitly marked as in-use (e.g. finalized, head).
    active_roots: HashSet<ShellHash>,
    /// Mapping from block number to the state root produced by that block.
    block_roots: BTreeMap<u64, ShellHash>,
    /// All blocks with number **strictly less than** this value are pruning
    /// candidates (subject to retention and active-root checks).
    prunable_below: u64,
}

impl StatePruner {
    /// Create a new pruner with the given retention count.
    ///
    /// The retention count is clamped to at least [`MIN_RETENTION`] (32).
    pub fn new(retention_count: u64) -> Self {
        Self {
            retention_count: retention_count.max(MIN_RETENTION),
            prune_interval: DEFAULT_PRUNE_INTERVAL,
            genesis_root: None,
            active_roots: HashSet::new(),
            block_roots: BTreeMap::new(),
            prunable_below: 0,
        }
    }

    /// Create a pruner with the default retention count (128 blocks).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_RETENTION)
    }

    /// Override the prune interval (number of blocks between prune passes).
    pub fn set_prune_interval(&mut self, interval: u64) {
        self.prune_interval = interval.max(1);
    }

    /// Set the genesis state root.  This root is always protected from pruning.
    pub fn set_genesis_root(&mut self, root: ShellHash) {
        self.active_roots.insert(root);
        self.genesis_root = Some(root);
    }

    /// Register the state root produced by a given block.
    ///
    /// Must be called after committing each new block so the pruner can track
    /// which state roots correspond to which block heights.
    pub fn register_block(&mut self, block_number: u64, state_root: ShellHash) {
        self.block_roots.insert(block_number, state_root);
        // F-304: Evict oldest entries if map grows too large.
        while self.block_roots.len() > MAX_BLOCK_ROOTS {
            if let Some(&oldest) = self.block_roots.keys().next() {
                self.block_roots.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Mark a state root as in-use.  Active roots are never pruned regardless
    /// of their age.  Typically called for the finalized root and head root.
    pub fn mark_active(&mut self, state_root: ShellHash) {
        self.active_roots.insert(state_root);
    }

    /// Remove the active flag from a state root.  If the root is the genesis
    /// root it remains protected.
    pub fn unmark_active(&mut self, state_root: &ShellHash) {
        if self.genesis_root.as_ref() == Some(state_root) {
            return; // genesis is permanently active
        }
        self.active_roots.remove(state_root);
    }

    /// Mark all blocks with number **strictly less than** `block_number` as
    /// pruning candidates.
    ///
    /// Typically called when finalization advances past `block_number`.
    pub fn mark_prunable(&mut self, block_number: u64) {
        if block_number > self.prunable_below {
            self.prunable_below = block_number;
        }
    }

    /// Returns `true` if a prune pass should be triggered at the given block
    /// height (every `prune_interval` blocks).
    pub fn should_prune(&self, block_number: u64) -> bool {
        block_number > 0 && block_number.is_multiple_of(self.prune_interval)
    }

    /// Execute a prune pass: delete canonical `block_number → block_hash`
    /// mappings for blocks that are both prunable and outside the retention
    /// window, provided their state root is not active.
    ///
    /// Returns a [`PruneResult`] summarising what happened.
    pub fn prune<S: KvStore>(&mut self, store: &S) -> Result<PruneResult, StorageError> {
        let highest_block = self.block_roots.keys().next_back().copied().unwrap_or(0);

        // Retention floor: keep exactly `retention_count` most recent blocks.
        let retention_cutoff = retention_cutoff(highest_block, self.retention_count);

        // Effective cutoff: the stricter of prunable_below and retention_cutoff.
        let cutoff = self.prunable_below.min(retention_cutoff);
        if cutoff == 0 {
            return Ok(PruneResult {
                pruned_count: 0,
                protected_count: 0,
            });
        }

        // Scan persisted canonical mappings so entries evicted from the bounded
        // root tracker remain discoverable. Each pass is capped to bound memory
        // and batch size; later passes resume naturally from mappings that remain.
        let tracked_to_remove: Vec<u64> = self
            .block_roots
            .range(..cutoff)
            .filter_map(|(&block_number, root)| {
                (!self.active_roots.contains(root)).then_some(block_number)
            })
            .collect();

        let mut pruned_count: u64 = 0;
        let mut protected_count: u64 = 0;
        let mut batch = WriteBatch::new();
        let mut after = None;

        'pages: loop {
            let mappings =
                store.scan_prefix_after(CANONICAL_PREFIX, after.as_deref(), MAX_BLOCK_ROOTS)?;
            let page_len = mappings.len();
            if page_len == 0 {
                break;
            }

            for (key, block_hash_bytes) in mappings {
                let block_number = canonical_block_number(&key)?;
                if block_number >= cutoff {
                    break 'pages;
                }
                after = Some(key.clone());

                let root = match self.block_roots.get(&block_number).copied() {
                    Some(root) => root,
                    None => {
                        let block_hash = ShellHash::try_from_slice(&block_hash_bytes)
                            .map_err(|e| StorageError::Codec(e.to_string()))?;
                        let header_key = [HEADER_PREFIX, block_hash.as_bytes()].concat();
                        let header_bytes = store.get(&header_key)?.ok_or_else(|| {
                            StorageError::Codec(format!(
                                "canonical block {block_number} is missing its header"
                            ))
                        })?;
                        let header: BlockHeader = decode_versioned(&header_bytes)?;
                        if header.number != block_number {
                            return Err(StorageError::Codec(format!(
                                "canonical block {block_number} header reports block {}",
                                header.number
                            )));
                        }
                        header.state_root
                    }
                };

                if self.active_roots.contains(&root) {
                    protected_count = protected_count.saturating_add(1);
                    continue;
                }

                batch.delete(key);
                pruned_count = pruned_count.saturating_add(1);
                if batch.len() >= MAX_BLOCK_ROOTS {
                    break 'pages;
                }
            }

            if page_len < MAX_BLOCK_ROOTS {
                break;
            }
        }

        if !batch.is_empty() {
            store.write_batch(batch)?;
        }

        // Remove pruned entries from the in-memory tracker.
        for block_number in tracked_to_remove {
            self.block_roots.remove(&block_number);
        }

        Ok(PruneResult {
            pruned_count,
            protected_count,
        })
    }

    // ── Accessors (mostly for tests) ───────────────────────────

    /// Configured retention count.
    pub fn retention_count(&self) -> u64 {
        self.retention_count
    }

    /// Number of state roots currently marked as active.
    pub fn active_root_count(&self) -> usize {
        self.active_roots.len()
    }

    /// Number of blocks currently tracked.
    pub fn tracked_block_count(&self) -> usize {
        self.block_roots.len()
    }

    /// Returns `true` if the given state root is in the active set.
    pub fn is_active(&self, root: &ShellHash) -> bool {
        self.active_roots.contains(root)
    }

    /// Returns `true` if the given block number is still tracked.
    pub fn is_tracked(&self, block_number: u64) -> bool {
        self.block_roots.contains_key(&block_number)
    }

    /// The current prunable-below threshold.
    pub fn prunable_below(&self) -> u64 {
        self.prunable_below
    }

    /// The configured prune interval.
    pub fn prune_interval(&self) -> u64 {
        self.prune_interval
    }

    /// The genesis root, if set.
    pub fn genesis_root(&self) -> Option<&ShellHash> {
        self.genesis_root.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;
    use alloy_rlp::Encodable;
    use shell_core::BlockHeader;
    use std::sync::Arc;

    struct FailingBatchStore<'a> {
        inner: &'a MemoryDb,
    }

    impl KvStore for FailingBatchStore<'_> {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(key, value)
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn write_batch(&self, _batch: WriteBatch) -> Result<(), StorageError> {
            Err(StorageError::Database("injected batch failure".into()))
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
    }

    fn dummy_root(n: u8) -> ShellHash {
        ShellHash::from([n; 32])
    }

    /// Build a canonical mapping key matching ChainStore format.
    fn canonical_key(block_number: u64) -> Vec<u8> {
        [CANONICAL_PREFIX, &block_number.to_be_bytes()].concat()
    }

    fn store_header(store: &MemoryDb, block_number: u64, block_hash: ShellHash, root: ShellHash) {
        let header = BlockHeader {
            number: block_number,
            state_root: root,
            ..Default::default()
        };
        let mut encoded = vec![0x02];
        header.encode(&mut encoded);
        let key = [HEADER_PREFIX, block_hash.as_bytes()].concat();
        store.put(&key, &encoded).unwrap();
    }

    /// Populate the store with canonical mappings for the given block range
    /// and register them in the pruner.
    fn setup_blocks(pruner: &mut StatePruner, store: &MemoryDb, range: std::ops::Range<u64>) {
        for n in range {
            let root = dummy_root(n as u8);
            setup_block(pruner, store, n, root);
        }
    }

    fn setup_block(pruner: &mut StatePruner, store: &MemoryDb, block_number: u64, root: ShellHash) {
        pruner.register_block(block_number, root);
        // Write canonical mapping so prune() can delete it.
        let key = canonical_key(block_number);
        let hash_bytes = root.as_bytes().to_vec();
        store.put(&key, &hash_bytes).unwrap();
    }

    // ── Retention policy tests ─────────────────────────────────

    #[test]
    fn retention_clamped_to_minimum() {
        let pruner = StatePruner::new(1);
        assert_eq!(pruner.retention_count(), MIN_RETENTION);

        let pruner = StatePruner::new(0);
        assert_eq!(pruner.retention_count(), MIN_RETENTION);

        let pruner = StatePruner::new(256);
        assert_eq!(pruner.retention_count(), 256);
    }

    #[test]
    fn default_retention_is_128() {
        let pruner = StatePruner::with_defaults();
        assert_eq!(pruner.retention_count(), DEFAULT_RETENTION);
    }

    // ── Pruning removes old data ───────────────────────────────

    #[test]
    fn prune_removes_old_canonical_mappings() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        // Register 100 blocks (0..100).
        setup_blocks(&mut pruner, &store, 0..100);

        // Mark all blocks below 80 as prunable.
        pruner.mark_prunable(80);

        let result = pruner.prune(&*store).unwrap();

        // Retention window: 100 - 32 = 68.  Effective cutoff = min(80, 68) = 68.
        // Blocks 0..68 should be pruned.
        assert_eq!(result.pruned_count, 68);
        assert_eq!(result.protected_count, 0);

        // Canonical mappings for pruned blocks should be gone.
        for n in 0..68 {
            assert!(
                store.get(&canonical_key(n)).unwrap().is_none(),
                "block {n} should have been pruned"
            );
        }

        // Blocks within retention window should still exist.
        for n in 68..100 {
            assert!(
                store.get(&canonical_key(n)).unwrap().is_some(),
                "block {n} should still exist"
            );
        }

        // In-memory tracker should only have the retained blocks.
        assert_eq!(pruner.tracked_block_count(), 32);
    }

    // ── Active roots are preserved ─────────────────────────────

    #[test]
    fn active_roots_are_not_pruned() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);

        // Mark block 10's root as active (e.g. finalized checkpoint).
        let root_10 = dummy_root(10);
        pruner.mark_active(root_10);

        pruner.mark_prunable(80);
        let result = pruner.prune(&*store).unwrap();

        // Block 10 should still exist in the store.
        assert!(store.get(&canonical_key(10)).unwrap().is_some());
        assert!(pruner.is_tracked(10));

        // One block was protected (block 10).
        assert_eq!(result.protected_count, 1);
        // 68 eligible minus 1 protected = 67 pruned.
        assert_eq!(result.pruned_count, 67);
    }

    // ── Safety guards ──────────────────────────────────────────

    #[test]
    fn genesis_root_never_pruned() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        let genesis = dummy_root(0);
        pruner.set_genesis_root(genesis);
        setup_blocks(&mut pruner, &store, 0..100);

        pruner.mark_prunable(100);
        let result = pruner.prune(&*store).unwrap();

        // Genesis (block 0) must survive.
        assert!(store.get(&canonical_key(0)).unwrap().is_some());
        assert!(pruner.is_tracked(0));
        assert!(result.protected_count >= 1);
    }

    #[test]
    fn finalized_root_never_pruned() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);

        // Simulate finalized root at block 50.
        let finalized_root = dummy_root(50);
        pruner.mark_active(finalized_root);

        pruner.mark_prunable(80);
        pruner.prune(&*store).unwrap();

        assert!(store.get(&canonical_key(50)).unwrap().is_some());
        assert!(pruner.is_tracked(50));
    }

    #[test]
    fn head_root_never_pruned() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);

        // Simulate head root at block 99.
        let head_root = dummy_root(99);
        pruner.mark_active(head_root);

        pruner.mark_prunable(100);
        pruner.prune(&*store).unwrap();

        // Block 99 is inside the retention window anyway, but double-check.
        assert!(store.get(&canonical_key(99)).unwrap().is_some());
        assert!(pruner.is_tracked(99));
    }

    #[test]
    fn unmark_active_does_not_remove_genesis() {
        let mut pruner = StatePruner::new(32);
        let genesis = dummy_root(0);
        pruner.set_genesis_root(genesis);

        // Attempt to unmark genesis — should be ignored.
        pruner.unmark_active(&genesis);
        assert!(pruner.is_active(&genesis));
    }

    #[test]
    fn unmark_active_removes_non_genesis() {
        let mut pruner = StatePruner::new(32);
        let root = dummy_root(42);
        pruner.mark_active(root);
        assert!(pruner.is_active(&root));

        pruner.unmark_active(&root);
        assert!(!pruner.is_active(&root));
    }

    // ── Retention policy ───────────────────────────────────────

    #[test]
    fn retention_window_respected_even_if_prunable() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(64);

        setup_blocks(&mut pruner, &store, 0..100);

        // Mark everything below 100 as prunable.
        pruner.mark_prunable(100);
        let result = pruner.prune(&*store).unwrap();

        // Retention window: 100 - 64 = 36.  Only blocks 0..36 should be pruned.
        assert_eq!(result.pruned_count, 36);

        // Blocks 36..100 should survive.
        for n in 36..100 {
            assert!(
                store.get(&canonical_key(n)).unwrap().is_some(),
                "block {n} should be retained"
            );
        }
    }

    #[test]
    fn no_pruning_when_within_retention_window() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(128);

        // Only 50 blocks — well within the 128-block retention window.
        setup_blocks(&mut pruner, &store, 0..50);
        pruner.mark_prunable(50);

        let result = pruner.prune(&*store).unwrap();
        assert_eq!(result.pruned_count, 0);
        assert_eq!(pruner.tracked_block_count(), 50);
    }

    #[test]
    fn prune_keeps_exact_retention_near_u64_max() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);
        let first_pruned = u64::MAX - 33;
        let last_pruned = u64::MAX - 32;
        let first_retained = u64::MAX - 31;
        let head = u64::MAX;

        setup_block(&mut pruner, &store, first_pruned, dummy_root(1));
        setup_block(&mut pruner, &store, last_pruned, dummy_root(2));
        setup_block(&mut pruner, &store, first_retained, dummy_root(3));
        setup_block(&mut pruner, &store, head, dummy_root(4));

        pruner.mark_prunable(u64::MAX);
        let result = pruner.prune(&*store).unwrap();

        assert_eq!(result.pruned_count, 2);
        assert_eq!(result.protected_count, 0);
        assert!(store.get(&canonical_key(first_pruned)).unwrap().is_none());
        assert!(store.get(&canonical_key(last_pruned)).unwrap().is_none());
        assert!(store.get(&canonical_key(first_retained)).unwrap().is_some());
        assert!(store.get(&canonical_key(head)).unwrap().is_some());
        assert!(!pruner.is_tracked(first_pruned));
        assert!(!pruner.is_tracked(last_pruned));
        assert!(pruner.is_tracked(first_retained));
        assert!(pruner.is_tracked(head));
    }

    #[test]
    fn no_pruning_when_prunable_below_is_zero() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);
        // prunable_below is 0 by default — nothing should be pruned.
        let result = pruner.prune(&*store).unwrap();
        assert_eq!(result.pruned_count, 0);
    }

    #[test]
    fn missing_canonical_mapping_is_not_counted_as_pruned() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);
        store.delete(&canonical_key(10)).unwrap();

        pruner.mark_prunable(80);
        let result = pruner.prune(&*store).unwrap();

        assert_eq!(result.pruned_count, 67);
        assert_eq!(result.protected_count, 0);
        assert!(!pruner.is_tracked(10));
        assert_eq!(pruner.tracked_block_count(), 32);
    }

    #[test]
    fn prune_revisits_mappings_evicted_from_root_tracker() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        for block_number in 0u64..20_001 {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[24..].copy_from_slice(&block_number.to_be_bytes());
            let block_hash = ShellHash::from(hash_bytes);
            setup_block(&mut pruner, &store, block_number, block_hash);
            store_header(&store, block_number, block_hash, block_hash);
        }
        assert_eq!(pruner.tracked_block_count(), MAX_BLOCK_ROOTS);
        assert!(!pruner.is_tracked(0));
        assert!(store.get(&canonical_key(0)).unwrap().is_some());

        pruner.mark_prunable(20_001);
        let first = pruner.prune(&*store).unwrap();
        let second = pruner.prune(&*store).unwrap();

        assert_eq!(first.pruned_count, 10_000);
        assert_eq!(second.pruned_count, 9_969);
        assert!(store.get(&canonical_key(0)).unwrap().is_none());
    }

    #[test]
    fn prune_preserves_evicted_genesis_and_active_roots() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);
        let mut genesis_bytes = [0xA1; 32];
        genesis_bytes[31] = 0x01;
        let genesis = ShellHash::from(genesis_bytes);
        let mut active_bytes = [0xB2; 32];
        active_bytes[31] = 0x02;
        let active = ShellHash::from(active_bytes);

        pruner.set_genesis_root(genesis);
        pruner.mark_active(active);
        setup_block(&mut pruner, &store, 0, genesis);
        setup_block(&mut pruner, &store, 1, active);
        setup_blocks(&mut pruner, &store, 2..10_002);
        store_header(&store, 0, genesis, genesis);
        store_header(&store, 1, active, active);
        assert!(!pruner.is_tracked(0));
        assert!(!pruner.is_tracked(1));

        pruner.mark_prunable(10_002);
        let result = pruner.prune(&*store).unwrap();

        assert_eq!(result.protected_count, 2);
        assert!(store.get(&canonical_key(0)).unwrap().is_some());
        assert!(store.get(&canonical_key(1)).unwrap().is_some());
    }

    #[test]
    fn failed_batch_does_not_advance_cleanup_progress() {
        let store = MemoryDb::new();
        let mut pruner = StatePruner::new(32);
        setup_blocks(&mut pruner, &store, 0..100);
        pruner.mark_prunable(80);
        let failing = FailingBatchStore { inner: &store };

        let err = pruner.prune(&failing).unwrap_err();

        assert!(matches!(err, StorageError::Database(_)));
        assert_eq!(pruner.tracked_block_count(), 100);
        for n in 0..68 {
            assert!(store.get(&canonical_key(n)).unwrap().is_some());
        }
    }

    // ── should_prune interval ──────────────────────────────────

    #[test]
    fn should_prune_at_interval() {
        let pruner = StatePruner::with_defaults();
        assert!(!pruner.should_prune(0));
        assert!(!pruner.should_prune(1));
        assert!(!pruner.should_prune(255));
        assert!(pruner.should_prune(256));
        assert!(!pruner.should_prune(257));
        assert!(pruner.should_prune(512));
    }

    #[test]
    fn custom_prune_interval() {
        let mut pruner = StatePruner::new(32);
        pruner.set_prune_interval(10);
        assert!(pruner.should_prune(10));
        assert!(pruner.should_prune(20));
        assert!(!pruner.should_prune(15));
    }

    // ── Edge cases ─────────────────────────────────────────────

    #[test]
    fn prune_empty_is_noop() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);
        let result = pruner.prune(&*store).unwrap();
        assert_eq!(result.pruned_count, 0);
        assert_eq!(result.protected_count, 0);
    }

    #[test]
    fn double_prune_is_idempotent() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..100);
        pruner.mark_prunable(80);

        let r1 = pruner.prune(&*store).unwrap();
        assert!(r1.pruned_count > 0);

        // Second prune should find nothing to do.
        let r2 = pruner.prune(&*store).unwrap();
        assert_eq!(r2.pruned_count, 0);
    }

    #[test]
    fn mark_prunable_only_advances() {
        let mut pruner = StatePruner::new(32);
        pruner.mark_prunable(50);
        assert_eq!(pruner.prunable_below(), 50);

        // Trying to set a lower value should be ignored.
        pruner.mark_prunable(30);
        assert_eq!(pruner.prunable_below(), 50);

        // Higher value should advance.
        pruner.mark_prunable(80);
        assert_eq!(pruner.prunable_below(), 80);
    }

    #[test]
    fn incremental_pruning_across_multiple_passes() {
        let store = Arc::new(MemoryDb::new());
        let mut pruner = StatePruner::new(32);

        setup_blocks(&mut pruner, &store, 0..200);

        // First pass: mark prunable below 100.
        pruner.mark_prunable(100);
        let r1 = pruner.prune(&*store).unwrap();
        // cutoff = min(100, 200-32=168) = 100 → prune blocks 0..100
        assert_eq!(r1.pruned_count, 100);

        // Second pass: mark prunable below 180.
        pruner.mark_prunable(180);
        let r2 = pruner.prune(&*store).unwrap();
        // cutoff = min(180, 168) = 168 → prune blocks 100..168
        assert_eq!(r2.pruned_count, 68);

        // 200 - 100 - 68 = 32 blocks remain.
        assert_eq!(pruner.tracked_block_count(), 32);
    }
}
