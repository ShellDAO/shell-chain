//! Witness bundle pruning: remove old per-block witness bundles from the
//! witness store after they have aged past the retention window.
//!
//! Once a block is finalized and its age exceeds `retention_count`, the
//! corresponding `WitnessBundle` is no longer needed for consensus validation.
//! The `witness_root` hash in the block header is preserved permanently in the
//! chain; only the raw witness data (PQ signatures) is pruned.
//!
//! Setting `retention_count = 0` enables **archive mode** — no bundles are
//! ever pruned.  The default (`128`) is suitable for full nodes that do not
//! need to serve historical witness data.

use tracing::debug;

use crate::{ChainStore, KvStore, StorageError, WitnessStore};
use shell_primitives::ShellHash;

/// Default number of recent blocks whose witness bundles are always retained.
/// Set to 256 for testnet to provide STARK prover with additional headroom.
/// At 2s block times: 256 blocks ≈ 8.5 minutes retention window.
/// Tuning: Mainnet should use 512 (≈17 minutes); testnet uses 256 for faster development cycles.
pub const DEFAULT_WITNESS_RETENTION: u64 = 256;

/// Maximum canonical block numbers examined by one prune pass.
const MAX_WITNESS_PRUNE_BLOCKS_PER_PASS: u64 = 4_096;

fn retention_cutoff(current_head: u64, retention_count: u64) -> u64 {
    current_head.saturating_sub(retention_count.saturating_sub(1))
}

/// Result of a single witness prune pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WitnessPruneResult {
    /// Number of witness bundles deleted.
    pub pruned_count: u64,
    /// Number of block numbers examined (bundle not found or already deleted).
    pub not_found_count: u64,
}

/// Prunes old witness bundles from the [`WitnessStore`] based on a retention
/// window.
///
/// # Retention semantics
/// - `retention_count = 0` → archive mode; no bundles are deleted.
/// - `retention_count = N` → keep bundles for the `N` most recent blocks;
///   older bundles are deleted as finality advances.
///
/// # Usage
/// ```rust,ignore
/// let pruner = WitnessPruner::new(128);
/// pruner.prune_before(finalized_number, Some(stark_frontier), &chain_store, &witness_store)?;
/// ```
#[derive(Debug, Clone)]
pub struct WitnessPruner {
    /// Number of recent blocks to retain (0 = archive).
    retention_count: u64,
    /// Lowest block number that has not yet been pruned.
    pruned_below: u64,
}

impl WitnessPruner {
    /// Create a new pruner with the given retention window.
    pub fn new(retention_count: u64) -> Self {
        Self {
            retention_count,
            pruned_below: 0,
        }
    }

    /// Create a pruner in archive mode (no bundles ever deleted).
    pub fn archive() -> Self {
        Self::new(0)
    }

    /// Returns `true` if this pruner is in archive mode.
    pub fn is_archive(&self) -> bool {
        self.retention_count == 0
    }

    /// Prune witness bundles for all finalized blocks that fall outside the
    /// retention window.
    ///
    /// `current_head` is the block number of the latest finalized block.
    /// Bundles below the overflow-safe retention cutoff are deleted, subject to
    /// the STARK proving guard.
    ///
    /// `stark_frontier` is the first block number that has NOT yet been
    /// STARK-proved.  Witnesses for blocks at or above this number are always
    /// retained regardless of the retention window — the prover still needs them
    /// to build future proofs.  Pass `None` only when no proving guard applies.
    ///
    /// The method is idempotent: calling it multiple times with the same
    /// `current_head` is safe and will only prune newly-eligible blocks.
    pub fn prune_before<S: KvStore>(
        &mut self,
        current_head: u64,
        stark_frontier: Option<u64>,
        chain_store: &ChainStore<S>,
        witness_store: &WitnessStore<S>,
    ) -> Result<WitnessPruneResult, StorageError> {
        if self.is_archive() {
            return Ok(WitnessPruneResult::default());
        }

        // Retention-based cutoff: blocks below this are old enough to prune.
        let retention_cutoff = retention_cutoff(current_head, self.retention_count);

        // STARK guard: never prune witnesses for blocks that haven't been proved yet.
        let cutoff = stark_frontier
            .map(|frontier| retention_cutoff.min(frontier))
            .unwrap_or(retention_cutoff);

        if cutoff <= self.pruned_below {
            // Nothing new to prune.
            return Ok(WitnessPruneResult::default());
        }

        // A restarted node reconstructs this in-memory cursor from zero. Bound
        // each pass so a large finalized history cannot stall one block commit
        // or allocate a history-sized deletion batch.
        let pass_cutoff = cutoff.min(
            self.pruned_below
                .saturating_add(MAX_WITNESS_PRUNE_BLOCKS_PER_PASS),
        );

        let mut result = WitnessPruneResult::default();
        let mut hashes_to_prune: Vec<ShellHash> = Vec::new();

        for block_number in self.pruned_below..pass_cutoff {
            // Resolve block hash from chain store (canonical mapping).
            match chain_store.get_block_hash_by_number(block_number)? {
                Some(hash) => {
                    if witness_store.has_bundle(&hash)? {
                        hashes_to_prune.push(hash);
                        debug!(
                            block = block_number,
                            "witness pruner: queued bundle deletion for finalized block"
                        );
                        result.pruned_count = result.pruned_count.saturating_add(1);
                    } else {
                        result.not_found_count = result.not_found_count.saturating_add(1);
                    }
                }
                None => {
                    return Err(StorageError::InvalidInput(format!(
                        "witness pruner: canonical hash missing for block {block_number}"
                    )));
                }
            }
        }

        witness_store.delete_bundles(&hashes_to_prune)?;
        self.pruned_below = pass_cutoff;
        Ok(result)
    }

    /// The lowest block number not yet pruned.
    pub fn pruned_below(&self) -> u64 {
        self.pruned_below
    }

    /// Configured retention window.
    pub fn retention_count(&self) -> u64 {
        self.retention_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainStore, MemoryDb, WitnessStore};
    use shell_core::{Block, BlockHeader, TxWitness, WitnessBundle};
    use shell_crypto::PQSignature;
    use shell_crypto::SignatureType;
    use shell_primitives::{Bytes, ShellHash};
    use std::sync::Arc;

    fn make_store() -> (Arc<MemoryDb>, ChainStore<MemoryDb>, WitnessStore<MemoryDb>) {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(db.clone());
        let ws = WitnessStore::new(db.clone());
        (db, cs, ws)
    }

    fn dummy_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::default(),
                proposer: shell_primitives::Address::default(),
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

    fn store_block(cs: &ChainStore<MemoryDb>, number: u64) -> ShellHash {
        let block = dummy_block(number);
        let hash = block.hash();
        cs.put_block(&block).unwrap();
        cs.set_canonical(number, &hash).unwrap();
        hash
    }

    fn store_bundle(ws: &WitnessStore<MemoryDb>, hash: &ShellHash) {
        let sig = PQSignature {
            sig_type: SignatureType::Dilithium3,
            data: vec![0xAA; 16],
        };
        let bundle = WitnessBundle {
            witnesses: vec![TxWitness {
                signature: sig,
                pubkey: None,
            }],
        };
        ws.put_bundle(hash, &bundle).unwrap();
    }

    #[test]
    fn archive_mode_prunes_nothing() {
        let (_db, cs, ws) = make_store();
        let hash = store_block(&cs, 0);
        store_bundle(&ws, &hash);

        let mut pruner = WitnessPruner::archive();
        let result = pruner.prune_before(500, None, &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 0);
        assert!(
            ws.has_bundle(&hash).unwrap(),
            "archive: bundle must survive"
        );
    }

    #[test]
    fn prune_removes_old_bundles() {
        let (_db, cs, ws) = make_store();
        // Store bundles for blocks 0..10.
        let hashes: Vec<ShellHash> = (0..10).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        // Retention = 4; current head = 9 → cutoff = 9+1-4 = 6.
        let mut pruner = WitnessPruner::new(4);
        let result = pruner.prune_before(9, None, &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 6); // blocks 0..6
        assert_eq!(result.not_found_count, 0);

        // Blocks 0..6 should have no bundle.
        for (n, hash) in hashes.iter().enumerate().take(6) {
            assert!(
                !ws.has_bundle(hash).unwrap(),
                "block {n} bundle should be pruned"
            );
        }
        // Blocks 6..10 still have bundles.
        for (n, hash) in hashes.iter().enumerate().skip(6).take(4) {
            assert!(
                ws.has_bundle(hash).unwrap(),
                "block {n} bundle should be retained"
            );
        }
    }

    #[test]
    fn prune_is_incremental() {
        let (_db, cs, ws) = make_store();
        let hashes: Vec<ShellHash> = (0..20).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        let mut pruner = WitnessPruner::new(4);

        // First prune: head=9, cutoff=6 → prune 0..6.
        let r1 = pruner.prune_before(9, None, &cs, &ws).unwrap();
        assert_eq!(r1.pruned_count, 6);
        assert_eq!(pruner.pruned_below(), 6);

        // Second prune: head=15, cutoff=12 → prune 6..12.
        let r2 = pruner.prune_before(15, None, &cs, &ws).unwrap();
        assert_eq!(r2.pruned_count, 6);
        assert_eq!(pruner.pruned_below(), 12);

        // Blocks 0..12 pruned, 12..20 retained.
        for hash in hashes.iter().take(12) {
            assert!(!ws.has_bundle(hash).unwrap());
        }
        for hash in hashes.iter().skip(12) {
            assert!(ws.has_bundle(hash).unwrap());
        }
    }

    #[test]
    fn prune_idempotent_on_same_head() {
        let (_db, cs, ws) = make_store();
        let hashes: Vec<ShellHash> = (0..10).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        let mut pruner = WitnessPruner::new(4);
        let r1 = pruner.prune_before(9, None, &cs, &ws).unwrap();
        assert_eq!(r1.pruned_count, 6);

        // Same head again — nothing new to prune.
        let r2 = pruner.prune_before(9, None, &cs, &ws).unwrap();
        assert_eq!(r2.pruned_count, 0);
    }

    #[test]
    fn no_prune_within_retention_window() {
        let (_db, cs, ws) = make_store();
        // Only 5 blocks; retention=10 → nothing should be pruned.
        let hashes: Vec<ShellHash> = (0..5).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        let mut pruner = WitnessPruner::new(10);
        let result = pruner.prune_before(4, None, &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 0);
        for h in &hashes {
            assert!(ws.has_bundle(h).unwrap());
        }
    }

    #[test]
    fn prune_skips_blocks_without_bundles() {
        let (_db, cs, ws) = make_store();
        // Store blocks 0..5 but only put bundles for blocks 1 and 3.
        let hashes: Vec<ShellHash> = (0..5).map(|n| store_block(&cs, n)).collect();
        store_bundle(&ws, &hashes[1]);
        store_bundle(&ws, &hashes[3]);

        let mut pruner = WitnessPruner::new(2); // cutoff at head=4: 4+1-2=3
        let result = pruner.prune_before(4, None, &cs, &ws).unwrap();

        // Eligible: blocks 0..3. Bundles exist for 1 and 3. But 3 is not < 3 → only 1 is pruned.
        // Blocks with no bundle → not_found.
        assert_eq!(result.pruned_count, 1); // block 1
        assert_eq!(result.not_found_count, 2); // blocks 0 and 2 have no bundle
    }

    #[test]
    fn missing_canonical_fails_without_advancing_or_deleting() {
        let (_db, cs, ws) = make_store();
        let hashes: Vec<ShellHash> = (0..5).map(|n| store_block(&cs, n)).collect();
        for hash in &hashes {
            store_bundle(&ws, hash);
        }
        cs.delete_canonical(2).unwrap();

        let mut pruner = WitnessPruner::new(2);
        let err = pruner.prune_before(4, None, &cs, &ws).unwrap_err();

        assert!(err
            .to_string()
            .contains("canonical hash missing for block 2"));
        assert_eq!(pruner.pruned_below(), 0);
        for hash in hashes {
            assert!(ws.has_bundle(&hash).unwrap());
        }
    }

    #[test]
    fn stark_frontier_guard_prevents_pruning_unproved_blocks() {
        let (_db, cs, ws) = make_store();
        // Blocks 0..20, all with bundles.
        let hashes: Vec<ShellHash> = (0..20).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        // Without STARK guard: retention=4, head=19 → cutoff=16 → prune [0, 16) (blocks 0–15).
        // With STARK guard at frontier=10: effective cutoff = min(16, 10) = 10 → prune [0, 10) (blocks 0–9).
        let mut pruner = WitnessPruner::new(4);
        let result = pruner.prune_before(19, Some(10), &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 10); // blocks 0..10 pruned
        assert_eq!(pruner.pruned_below(), 10);

        // Blocks 0..10 pruned.
        for hash in hashes.iter().take(10) {
            assert!(!ws.has_bundle(hash).unwrap());
        }
        // Blocks 10..20 retained (STARK frontier protects them).
        for hash in hashes.iter().skip(10) {
            assert!(ws.has_bundle(hash).unwrap());
        }
    }

    #[test]
    fn no_stark_frontier_disables_guard() {
        let (_db, cs, ws) = make_store();
        let hashes: Vec<ShellHash> = (0..10).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        // Without a STARK frontier guard, prune normally up to cutoff=6.
        let mut pruner = WitnessPruner::new(4);
        let result = pruner.prune_before(9, None, &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 6);
    }

    #[test]
    fn stark_frontier_zero_retains_unproved_witnesses() {
        let (_db, cs, ws) = make_store();
        let hashes: Vec<ShellHash> = (0..10).map(|n| store_block(&cs, n)).collect();
        for h in &hashes {
            store_bundle(&ws, h);
        }

        // Frontier 0 means block 0 is the first unproved block, so every witness
        // bundle is still needed even though the retention cutoff is 6.
        let mut pruner = WitnessPruner::new(4);
        let result = pruner.prune_before(9, Some(0), &cs, &ws).unwrap();
        assert_eq!(result.pruned_count, 0);
        assert_eq!(pruner.pruned_below(), 0);
        for hash in hashes {
            assert!(ws.has_bundle(&hash).unwrap());
        }
    }

    #[test]
    fn prune_before_keeps_exact_retention_near_u64_max() {
        let (_db, cs, ws) = make_store();
        let first_number = u64::MAX - 2;
        let second_number = u64::MAX - 1;
        let mut hashes = Vec::new();
        for number in [first_number, second_number] {
            let mut block = dummy_block(0);
            block.header.number = number;
            block.header.timestamp = 0;
            let hash = block.hash();
            cs.put_block(&block).unwrap();
            cs.set_canonical(number, &hash).unwrap();
            store_bundle(&ws, &hash);
            hashes.push(hash);
        }

        let mut pruner = WitnessPruner::new(1);
        pruner.pruned_below = first_number;
        let result = pruner.prune_before(u64::MAX, None, &cs, &ws).unwrap();

        assert_eq!(result.pruned_count, 2);
        assert_eq!(result.not_found_count, 0);
        assert_eq!(pruner.pruned_below(), u64::MAX);
        for hash in hashes {
            assert!(!ws.has_bundle(&hash).unwrap());
        }
    }

    #[test]
    fn prune_pass_caps_restart_backlog() {
        let (_db, cs, ws) = make_store();
        for number in 0..MAX_WITNESS_PRUNE_BLOCKS_PER_PASS {
            store_block(&cs, number);
        }

        let mut pruner = WitnessPruner::new(1);
        let result = pruner
            .prune_before(MAX_WITNESS_PRUNE_BLOCKS_PER_PASS + 1, None, &cs, &ws)
            .unwrap();

        assert_eq!(result.not_found_count, MAX_WITNESS_PRUNE_BLOCKS_PER_PASS);
        assert_eq!(pruner.pruned_below(), MAX_WITNESS_PRUNE_BLOCKS_PER_PASS);
    }
}
