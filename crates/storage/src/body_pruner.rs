//! Block body expiry: remove old block bodies after they have aged past the
//! retention window (EIP-4444 style).
//!
//! Block **bodies** (the list of signed transactions) account for the vast
//! majority of historical storage.  Once a block is deeply finalized, full
//! nodes no longer need the individual transaction data for consensus — it
//! can be retrieved on demand from archive peers or portal-network nodes.
//!
//! The [`BodyPruner`] deletes only the `b/<hash>` KV entry for each expired
//! block. The block **header** (`h/<hash>`) and canonical mapping
//! (`n/<number>`) are preserved permanently so chain traversal and header
//! sync continue to work.
//!
//! Setting `retention_count = 0` enables **archive mode** — no bodies are
//! ever pruned.  The default ([`DEFAULT_BODY_RETENTION`]) is suitable for
//! full nodes that do not need to serve historical transaction data.
//!
//! # Example
//!
//! ```ignore
//! let mut pruner = BodyPruner::new(512);
//! let result = pruner.prune_before(head_number, &chain_store)?;
//! println!("pruned {} bodies", result.bodies_pruned);
//! ```

use tracing::debug;

use crate::{ChainStore, KvStore, StorageError};
use shell_primitives::ShellHash;

/// Default number of recent blocks whose bodies are always retained.
pub const DEFAULT_BODY_RETENTION: u64 = 512;

fn retention_cutoff(current_head: u64, retention_count: u64) -> u64 {
    current_head.saturating_sub(retention_count.saturating_sub(1))
}

/// Result of a single body prune pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BodyPruneResult {
    /// Number of block numbers checked in this pass.
    pub blocks_checked: u64,
    /// Number of block bodies deleted.
    pub bodies_pruned: u64,
}

/// Prunes old block bodies to bound historical storage growth.
///
/// # Archive mode
/// When `retention_count == 0`, [`BodyPruner::is_archive`] returns `true` and
/// [`BodyPruner::prune_before`] is a no-op.
///
/// # Idempotency
/// The pruner tracks `pruned_below` to avoid re-processing blocks that have
/// already been expired.  Multiple calls with the same `current_head` are safe
/// and cheap.
#[derive(Debug)]
pub struct BodyPruner {
    /// Blocks below the overflow-safe retention cutoff are eligible for expiry.
    /// Zero means archive mode (never prune).
    retention_count: u64,
    /// The highest block number whose body has already been pruned + 1.
    /// All block numbers `< pruned_below` have been processed.
    pruned_below: u64,
}

impl BodyPruner {
    /// Create a new pruner with the given retention window.
    ///
    /// Pass `retention_count = 0` to disable pruning (archive mode).
    pub fn new(retention_count: u64) -> Self {
        Self {
            retention_count,
            pruned_below: 0,
        }
    }

    /// Returns `true` when archive mode is active (retention == 0).
    pub fn is_archive(&self) -> bool {
        self.retention_count == 0
    }

    /// Prune block bodies for blocks that have aged past the retention window.
    ///
    /// Bodies for block numbers in `[pruned_below, expiry_horizon)` are
    /// deleted, where `expiry_horizon` keeps exactly `retention_count` recent
    /// blocks without overflowing at the maximum block height.
    ///
    /// Returns a [`BodyPruneResult`] summary.  Missing bodies (already pruned
    /// or never stored) are silently skipped.
    pub fn prune_before<S: KvStore>(
        &mut self,
        current_head: u64,
        chain_store: &ChainStore<S>,
    ) -> Result<BodyPruneResult, StorageError> {
        if self.is_archive() {
            return Ok(BodyPruneResult::default());
        }

        // Expiry horizon: prune everything strictly before this block number.
        let expiry_horizon = retention_cutoff(current_head, self.retention_count);

        if expiry_horizon <= self.pruned_below {
            // Nothing new to prune.
            return Ok(BodyPruneResult::default());
        }

        let mut result = BodyPruneResult::default();
        let start = self.pruned_below;
        let mut hashes_to_prune: Vec<ShellHash> = Vec::new();

        for block_number in start..expiry_horizon {
            result.blocks_checked = result.blocks_checked.saturating_add(1);

            // Resolve canonical hash for this block number.
            match chain_store.get_block_hash_by_number(block_number)? {
                None => {
                    return Err(StorageError::InvalidInput(format!(
                        "body pruner: canonical hash missing for block {block_number}"
                    )));
                }
                Some(hash) => {
                    if chain_store.has_body(&hash)? {
                        hashes_to_prune.push(hash);
                        result.bodies_pruned = result.bodies_pruned.saturating_add(1);
                        debug!(block_number, %hash, "body pruner: queued body deletion");
                    } else {
                        debug!(block_number, %hash, "body pruner: body already absent, skipping");
                    }
                }
            }
        }

        chain_store.delete_bodies(&hashes_to_prune)?;
        self.pruned_below = expiry_horizon;
        Ok(result)
    }

    /// The current lower bound: all numbers `< pruned_below` have been
    /// processed (either pruned or determined to have no canonical hash).
    pub fn pruned_below(&self) -> u64 {
        self.pruned_below
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use shell_core::{Block, BlockHeader};
    use shell_primitives::{Address, Bytes, ShellHash};

    use super::*;
    use crate::{ChainStore, MemoryDb};

    fn empty_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1700000000 + number,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    fn setup_chain(count: u64) -> ChainStore<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(db);
        for n in 0..count {
            let b = empty_block(n);
            cs.put_block(&b).unwrap();
            cs.set_canonical(n, &b.hash()).unwrap();
        }
        cs
    }

    #[test]
    fn archive_mode_no_pruning() {
        let cs = setup_chain(10);
        let mut pruner = BodyPruner::new(0);
        assert!(pruner.is_archive());
        let result = pruner.prune_before(9, &cs).unwrap();
        assert_eq!(result.bodies_pruned, 0);
        // All bodies still present.
        for n in 0..10 {
            let hash = cs.get_block_hash_by_number(n).unwrap().unwrap();
            assert!(cs.get_block_by_hash(&hash).unwrap().is_some());
        }
    }

    #[test]
    fn prune_below_retention_window() {
        // head=9, retention=5 → expiry_horizon=5 → prune blocks 0..5
        let cs = setup_chain(10);
        let mut pruner = BodyPruner::new(5);
        let result = pruner.prune_before(9, &cs).unwrap();
        assert_eq!(result.bodies_pruned, 5);
        assert_eq!(result.blocks_checked, 5);
        assert_eq!(pruner.pruned_below(), 5);

        // Blocks 0..5 should have no body.
        for n in 0..5 {
            let hash = cs.get_block_hash_by_number(n).unwrap().unwrap();
            // After body deletion, get_block_by_hash returns None (body gone).
            assert!(
                cs.get_block_by_hash(&hash).unwrap().is_none(),
                "block {n} body should be pruned"
            );
        }
        // Blocks 5..10 should still have bodies.
        for n in 5..10 {
            let hash = cs.get_block_hash_by_number(n).unwrap().unwrap();
            assert!(cs.get_block_by_hash(&hash).unwrap().is_some());
        }
    }

    #[test]
    fn idempotent_double_prune() {
        let cs = setup_chain(10);
        let mut pruner = BodyPruner::new(5);
        let r1 = pruner.prune_before(9, &cs).unwrap();
        let r2 = pruner.prune_before(9, &cs).unwrap();
        // Second call is a no-op.
        assert_eq!(r1.bodies_pruned, 5);
        assert_eq!(r2.bodies_pruned, 0);
        assert_eq!(r2.blocks_checked, 0);
    }

    #[test]
    fn prune_incremental_as_chain_advances() {
        let cs = setup_chain(20);
        let mut pruner = BodyPruner::new(5);

        // head=9 → prune 0..5
        let r1 = pruner.prune_before(9, &cs).unwrap();
        assert_eq!(r1.bodies_pruned, 5);

        // head=14 → prune 5..10 (new 5 blocks)
        let r2 = pruner.prune_before(14, &cs).unwrap();
        assert_eq!(r2.bodies_pruned, 5);
        assert_eq!(pruner.pruned_below(), 10);
    }

    #[test]
    fn no_prune_when_head_below_retention() {
        // head=3, retention=10 → expiry_horizon=0 → nothing to prune
        let cs = setup_chain(5);
        let mut pruner = BodyPruner::new(10);
        let result = pruner.prune_before(3, &cs).unwrap();
        assert_eq!(result.bodies_pruned, 0);
    }

    #[test]
    fn exact_boundary() {
        // head=10, retention=10 → expiry_horizon=1 → only block 0 pruned
        let cs = setup_chain(11);
        let mut pruner = BodyPruner::new(10);
        let result = pruner.prune_before(10, &cs).unwrap();
        assert_eq!(result.bodies_pruned, 1);
        assert_eq!(pruner.pruned_below(), 1);
    }

    #[test]
    fn missing_canonical_fails_without_advancing_or_deleting() {
        // Create chain but delete the canonical mapping for block 2.
        let cs = setup_chain(10);
        cs.delete_canonical(2).unwrap();

        let mut pruner = BodyPruner::new(5);
        let err = pruner.prune_before(9, &cs).unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical hash missing for block 2"));
        assert_eq!(pruner.pruned_below(), 0);
        for n in [0, 1, 3, 4] {
            let hash = cs.get_block_hash_by_number(n).unwrap().unwrap();
            assert!(cs.has_body(&hash).unwrap());
        }
    }

    #[test]
    fn missing_body_is_not_counted_as_pruned() {
        let cs = setup_chain(10);
        let hash = cs.get_block_hash_by_number(2).unwrap().unwrap();
        cs.delete_body(&hash).unwrap();

        let mut pruner = BodyPruner::new(5);
        let result = pruner.prune_before(9, &cs).unwrap();

        assert_eq!(result.blocks_checked, 5);
        assert_eq!(result.bodies_pruned, 4);
        assert_eq!(pruner.pruned_below(), 5);
    }

    #[test]
    fn prune_before_keeps_exact_retention_near_u64_max() {
        let cs = setup_chain(0);
        let first_number = u64::MAX - 2;
        let second_number = u64::MAX - 1;
        let mut hashes = Vec::new();
        for number in [first_number, second_number] {
            let mut block = empty_block(0);
            block.header.number = number;
            block.header.timestamp = 0;
            let hash = block.hash();
            cs.put_block(&block).unwrap();
            cs.set_canonical(number, &hash).unwrap();
            hashes.push(hash);
        }

        let mut pruner = BodyPruner::new(1);
        pruner.pruned_below = first_number;
        let result = pruner.prune_before(u64::MAX, &cs).unwrap();

        assert_eq!(result.blocks_checked, 2);
        assert_eq!(result.bodies_pruned, 2);
        assert_eq!(pruner.pruned_below(), u64::MAX);
        for hash in hashes {
            assert!(cs.get_block_by_hash(&hash).unwrap().is_none());
        }
    }
}
