//! Chain reorganization engine.
//!
//! When a competing fork becomes the preferred chain, the reorg engine:
//! 1. Finds the common ancestor of current and target chains
//! 2. Rolls back state to the ancestor's state root
//! 3. Collects transactions from rolled-back blocks for mempool re-insertion
//! 4. Re-applies blocks on the new canonical chain
//! 5. Updates canonical chain pointers and head

use std::sync::Arc;

use parking_lot::RwLock;
use shell_primitives::ShellHash;
use shell_storage::{ChainStore, KvStore, WorldState};
use tracing::info;

use crate::error::NodeError;

/// Result of a chain reorganization.
#[derive(Debug)]
pub struct ReorgResult {
    /// Common ancestor block number.
    pub ancestor_number: u64,
    /// Common ancestor block hash.
    pub ancestor_hash: ShellHash,
    /// Number of blocks rolled back from the old chain.
    pub rolled_back: usize,
    /// Number of blocks applied from the new chain.
    pub applied: usize,
    /// Transactions from rolled-back blocks that should be re-added to mempool.
    pub reverted_txs: Vec<shell_core::SignedTransaction>,
    /// New head block hash after reorg.
    pub new_head: ShellHash,
}

/// Executes chain reorganizations.
pub struct ReorgEngine;

impl ReorgEngine {
    /// Execute a chain reorganization from the current head to a target fork.
    ///
    /// # Arguments
    /// * `chain_store` – block and canonical-mapping storage
    /// * `world_state` – current EVM world state (will be replaced)
    /// * `store` – underlying KV store used to reconstruct world state at a prior root
    /// * `ancestor_hash` – hash of the common ancestor block
    /// * `ancestor_number` – height of the common ancestor
    /// * `old_chain` – hashes of blocks to roll back, oldest first
    /// * `new_chain` – hashes of blocks to apply, oldest first
    /// * `finalized_number` – latest finalized block height (reorg cannot go past this)
    #[allow(clippy::too_many_arguments)]
    pub fn execute<S: KvStore>(
        chain_store: &Arc<ChainStore<S>>,
        world_state: &Arc<RwLock<WorldState<S>>>,
        store: &Arc<S>,
        ancestor_hash: ShellHash,
        ancestor_number: u64,
        old_chain: &[ShellHash],
        new_chain: &[ShellHash],
        finalized_number: u64,
    ) -> Result<ReorgResult, NodeError> {
        // Safety: cannot reorg past the finalized block
        if ancestor_number < finalized_number {
            return Err(NodeError::Startup(format!(
                "cannot reorg past finalized block {}: ancestor is at {}",
                finalized_number, ancestor_number
            )));
        }
        if finalized_number > 0 && ancestor_number == finalized_number {
            let canonical_finalized = chain_store
                .get_block_hash_by_number(finalized_number)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "cannot reorg from finalized block {finalized_number}: canonical mapping is missing"
                    ))
                })?;
            if ancestor_hash != canonical_finalized {
                return Err(NodeError::Startup(format!(
                    "cannot reorg from non-canonical ancestor at finalized block {finalized_number}"
                )));
            }
        }

        info!(
            ancestor = ancestor_number,
            rollback = old_chain.len(),
            apply = new_chain.len(),
            "starting chain reorganization"
        );

        Self::validate_chain_segment(
            chain_store.as_ref(),
            ancestor_hash,
            ancestor_number,
            old_chain,
            "old_chain",
        )?;
        Self::validate_chain_segment(
            chain_store.as_ref(),
            ancestor_hash,
            ancestor_number,
            new_chain,
            "new_chain",
        )?;

        // Preflight both world-state roots before mutating canonical indexes.
        // A missing tip trie must not leave a partially applied reorganization.
        let ancestor_block = chain_store
            .get_block_by_hash(&ancestor_hash)?
            .ok_or_else(|| {
                NodeError::Startup(format!("ancestor block not found: {:?}", ancestor_hash))
            })?;
        let mut ancestor_ws =
            WorldState::at_root(Arc::clone(store), &ancestor_block.header.state_root)?;
        ancestor_ws.validate()?;
        let tip_state_root = match new_chain.last() {
            Some(hash) => {
                chain_store
                    .get_block_by_hash(hash)?
                    .ok_or_else(|| {
                        NodeError::Startup(format!("new chain block not found: {:?}", hash))
                    })?
                    .header
                    .state_root
            }
            None => ancestor_block.header.state_root,
        };
        let mut tip_ws = WorldState::at_root(Arc::clone(store), &tip_state_root)?;
        tip_ws.validate()?;

        // Step 1: Collect transactions from blocks being rolled back (newest first)
        let mut reverted_txs = Vec::new();
        for hash in old_chain.iter().rev() {
            if let Ok(Some(block)) = chain_store.get_block_by_hash(hash) {
                reverted_txs.extend(block.transactions.clone());
            }
        }

        // Step 2: Restore world state to the ancestor's state root
        *world_state.write() = ancestor_ws;

        info!(
            state_root = ?ancestor_block.header.state_root,
            "restored world state to ancestor"
        );

        // Step 3: Apply new chain blocks — restore world state per block.
        // Full EVM re-execution is not performed here; instead we trust the
        // stored state roots which were validated at block import time.
        // The world state is set to the tip block's state root.

        for hash in old_chain {
            chain_store.delete_block_transaction_indexes(hash)?;
        }

        let mut applied = 0;
        let mut new_head = ancestor_hash;
        for hash in new_chain {
            let block = chain_store.get_block_by_hash(hash)?.ok_or_else(|| {
                NodeError::Startup(format!("new chain block not found: {:?}", hash))
            })?;

            chain_store.set_canonical(block.number(), hash)?;
            chain_store.index_block_transactions(&block)?;
            new_head = *hash;
            applied += 1;
        }

        // F-084/F-090: Remove stale canonical mappings if old chain was longer
        // than the new chain to prevent orphaned state.
        if old_chain.len() > new_chain.len() {
            let new_tip_number = ancestor_number + new_chain.len() as u64;
            let old_tip_number = ancestor_number + old_chain.len() as u64;
            for n in (new_tip_number + 1)..=old_tip_number {
                chain_store.delete_canonical(n)?;
            }
        }

        // Restore world state to the new chain tip's state root.
        *world_state.write() = tip_ws;

        // Step 4: Update head pointer
        chain_store.set_head(&new_head)?;

        // If aggregate counters are already initialized, refresh them against
        // the new canonical chain. Same-height reorgs otherwise leave
        // chain_totals_head unchanged while tx/gas totals still describe the
        // old canonical branch.
        if chain_store.get_chain_totals_head()?.is_some() {
            let new_tip_number = ancestor_number.saturating_add(new_chain.len() as u64);
            chain_store.rebuild_chain_totals(new_tip_number)?;
        }

        // Step 5: Remove transactions that already exist in the new chain
        let new_chain_tx_hashes: std::collections::HashSet<ShellHash> = new_chain
            .iter()
            .filter_map(|h| chain_store.get_block_by_hash(h).ok().flatten())
            .flat_map(|b| {
                b.transactions
                    .iter()
                    .map(|tx| tx.hash())
                    .collect::<Vec<_>>()
            })
            .collect();

        reverted_txs.retain(|tx| !new_chain_tx_hashes.contains(&tx.hash()));

        let result = ReorgResult {
            ancestor_number,
            ancestor_hash,
            rolled_back: old_chain.len(),
            applied,
            reverted_txs,
            new_head,
        };

        info!(
            rolled_back = result.rolled_back,
            applied = result.applied,
            reverted_txs = result.reverted_txs.len(),
            new_head = ?result.new_head,
            "chain reorganization complete"
        );

        Ok(result)
    }

    fn validate_chain_segment<S: KvStore>(
        chain_store: &ChainStore<S>,
        ancestor_hash: ShellHash,
        ancestor_number: u64,
        chain: &[ShellHash],
        label: &str,
    ) -> Result<(), NodeError> {
        let mut expected_parent = ancestor_hash;
        for (idx, hash) in chain.iter().enumerate() {
            let offset = u64::try_from(idx)
                .ok()
                .and_then(|idx| idx.checked_add(1))
                .ok_or_else(|| {
                    NodeError::Startup(format!("{label} length overflows block height"))
                })?;
            let expected_number = ancestor_number.checked_add(offset).ok_or_else(|| {
                NodeError::Startup(format!("{label} height overflows block number space"))
            })?;

            let block = chain_store.get_block_by_hash(hash)?.ok_or_else(|| {
                NodeError::Startup(format!("{label} block not found: {:?}", hash))
            })?;
            if block.number() != expected_number {
                return Err(NodeError::Startup(format!(
                    "{label} height continuity broken at {:?}: expected #{}, got #{}",
                    hash,
                    expected_number,
                    block.number()
                )));
            }
            if block.header.parent_hash != expected_parent {
                return Err(NodeError::Startup(format!(
                    "{label} parent continuity broken at {:?}: expected parent {:?}, got {:?}",
                    hash, expected_parent, block.header.parent_hash
                )));
            }
            expected_parent = *hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Block, BlockHeader, SignedTransaction, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};
    use shell_storage::MemoryDb;

    fn make_hash(n: u8) -> ShellHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ShellHash::from(bytes)
    }

    fn make_block(number: u64, parent_hash: ShellHash, state_root: ShellHash) -> Block {
        let header = BlockHeader {
            parent_hash,
            state_root,
            transactions_root: ShellHash::default(),
            receipts_root: ShellHash::default(),
            logs_bloom: Bytes::default(),
            number,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_000_000 + number,
            extra_data: Bytes::default(),
            proposer: Address::from_public_key(b"test-proposer", 0),
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        };
        Block {
            header,
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    /// Create a store + chain store + world state, returning the persisted empty
    /// state root so test blocks can reference it.
    #[allow(clippy::type_complexity)]
    fn setup_chain() -> (
        Arc<MemoryDb>,
        Arc<ChainStore<MemoryDb>>,
        Arc<RwLock<WorldState<MemoryDb>>>,
        ShellHash,
    ) {
        let store = Arc::new(MemoryDb::new());
        let chain_store = Arc::new(ChainStore::new(store.clone()));
        let mut ws = WorldState::new(store.clone());
        let empty_root = ws.state_root().unwrap();
        let world_state = Arc::new(RwLock::new(ws));
        (store, chain_store, world_state, empty_root)
    }

    fn make_tx() -> SignedTransaction {
        SignedTransaction::new(
            Address::from_public_key(b"sender", 0),
            Transaction {
                chain_id: 1,
                nonce: 0,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000,
                gas_limit: 21_000,
                to: None,
                value: U256::ZERO,
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature::new(SignatureType::Dilithium3, vec![1, 2, 3]),
        )
    }

    #[test]
    fn test_reorg_past_finalized_rejected() {
        let (store, chain_store, world_state, _root) = setup_chain();
        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            make_hash(0),
            5, // ancestor at 5
            &[],
            &[],
            10, // finalized at 10 — ancestor < finalized
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot reorg past finalized"));
    }

    #[test]
    fn test_reorg_from_non_canonical_finalized_ancestor_rejected() {
        let (store, chain_store, world_state, root) = setup_chain();
        let finalized = make_block(5, make_hash(0), root);
        let finalized_hash = finalized.hash();
        chain_store.put_block(&finalized).unwrap();
        chain_store.set_canonical(5, &finalized_hash).unwrap();

        let fork_ancestor = make_block(5, make_hash(9), root);
        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            fork_ancestor.hash(),
            5,
            &[],
            &[],
            5,
        );

        let err = result.unwrap_err().to_string();
        assert!(err.contains("non-canonical ancestor at finalized block 5"));
        assert_eq!(
            chain_store.get_block_hash_by_number(5).unwrap(),
            Some(finalized_hash)
        );
    }

    #[test]
    fn test_reorg_from_finalized_height_requires_canonical_mapping() {
        let (store, chain_store, world_state, root) = setup_chain();
        let ancestor = make_block(5, make_hash(0), root);
        let ancestor_hash = ancestor.hash();
        chain_store.put_block(&ancestor).unwrap();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[],
            &[],
            5,
        );

        let err = result.unwrap_err().to_string();
        assert!(err.contains("canonical mapping is missing"));
    }

    #[test]
    fn test_empty_reorg() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[], // nothing to roll back
            &[], // nothing to apply
            0,   // no finalized
        )
        .unwrap();

        assert_eq!(result.rolled_back, 0);
        assert_eq!(result.applied, 0);
        assert_eq!(result.reverted_txs.len(), 0);
    }

    #[test]
    fn test_reorg_collects_reverted_txs() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let mut old_block = make_block(6, ancestor_hash, root);
        old_block.transactions.push(make_tx());
        chain_store.put_block(&old_block).unwrap();
        let old_hash = old_block.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash], // roll back this block
            &[],         // no new blocks
            0,
        )
        .unwrap();

        assert_eq!(result.rolled_back, 1);
        assert_eq!(result.reverted_txs.len(), 1);
    }

    #[test]
    fn test_reorg_applies_new_chain() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let new_block_6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&new_block_6).unwrap();
        let new_hash_6 = new_block_6.hash();

        let new_block_7 = make_block(7, new_hash_6, root);
        chain_store.put_block(&new_block_7).unwrap();
        let new_hash_7 = new_block_7.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[],                       // nothing to roll back
            &[new_hash_6, new_hash_7], // apply these
            0,
        )
        .unwrap();

        assert_eq!(result.applied, 2);
        assert_eq!(result.new_head, new_hash_7);
    }

    #[test]
    fn test_reorg_rejects_new_chain_height_gap_before_mutation() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let old6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old6).unwrap();
        let old_hash = old6.hash();
        chain_store.set_canonical(6, &old_hash).unwrap();
        chain_store.set_head(&old_hash).unwrap();

        let bad_new7 = make_block(7, ancestor_hash, root);
        chain_store.put_block(&bad_new7).unwrap();
        let bad_hash = bad_new7.hash();

        let err = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[bad_hash],
            0,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("new_chain height continuity broken"));
        assert_eq!(
            chain_store.get_block_by_number(6).unwrap().unwrap().hash(),
            old_hash
        );
        assert_eq!(chain_store.get_head_hash().unwrap().unwrap(), old_hash);
    }

    #[test]
    fn test_reorg_rejects_missing_tip_state_before_mutation() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let old6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old6).unwrap();
        let old_hash = old6.hash();
        chain_store.set_canonical(6, &old_hash).unwrap();
        chain_store.set_head(&old_hash).unwrap();

        let new6 = make_block(6, ancestor_hash, make_hash(99));
        chain_store.put_block(&new6).unwrap();
        let new_hash = new6.hash();

        ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[new_hash],
            0,
        )
        .unwrap_err();

        assert_eq!(
            chain_store.get_block_by_number(6).unwrap().unwrap().hash(),
            old_hash
        );
        assert_eq!(chain_store.get_head_hash().unwrap().unwrap(), old_hash);
    }

    #[test]
    fn test_reorg_rejects_old_chain_parent_gap_before_mutation() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let bad_old6 = make_block(6, make_hash(99), root);
        chain_store.put_block(&bad_old6).unwrap();
        let bad_old_hash = bad_old6.hash();
        chain_store.set_canonical(6, &bad_old_hash).unwrap();
        chain_store.set_head(&bad_old_hash).unwrap();

        let new6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&new6).unwrap();
        let new_hash = new6.hash();

        let err = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[bad_old_hash],
            &[new_hash],
            0,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("old_chain parent continuity broken"));
        assert_eq!(
            chain_store.get_block_by_number(6).unwrap().unwrap().hash(),
            bad_old_hash
        );
        assert_eq!(chain_store.get_head_hash().unwrap().unwrap(), bad_old_hash);
    }

    #[test]
    fn test_reorg_filters_duplicate_txs() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let tx = make_tx();

        let mut old_block = make_block(6, ancestor_hash, root);
        old_block.transactions.push(tx.clone());
        chain_store.put_block(&old_block).unwrap();
        let old_hash = old_block.hash();

        let mut new_block = make_block(6, ancestor_hash, root);
        new_block.header.timestamp += 1; // different block, same tx
        new_block.transactions.push(tx);
        chain_store.put_block(&new_block).unwrap();
        let new_hash = new_block.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[new_hash],
            0,
        )
        .unwrap();

        // TX exists in new chain, so it should be filtered from reverted
        assert_eq!(result.reverted_txs.len(), 0);
    }

    // ── Extended reorg tests ───────────────────────────────────────────

    #[test]
    fn test_short_reorg_one_block() {
        let (store, chain_store, world_state, root) = setup_chain();

        // Build canonical chain: genesis → block5 → old_block6
        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let old_block = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old_block).unwrap();
        let old_hash = old_block.hash();
        chain_store.set_canonical(6, &old_hash).unwrap();
        chain_store.set_head(&old_hash).unwrap();

        // Create fork block at height 6 with different timestamp.
        let mut fork_block = make_block(6, ancestor_hash, root);
        fork_block.header.timestamp += 100;
        chain_store.put_block(&fork_block).unwrap();
        let fork_hash = fork_block.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[fork_hash],
            0,
        )
        .unwrap();

        assert_eq!(result.rolled_back, 1);
        assert_eq!(result.applied, 1);
        assert_eq!(result.new_head, fork_hash);
        assert_eq!(chain_store.get_head_hash().unwrap().unwrap(), fork_hash);
    }

    #[test]
    fn test_medium_reorg_three_blocks() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        // Old chain: 3 blocks (6, 7, 8)
        let old6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old6).unwrap();
        let oh6 = old6.hash();
        let old7 = make_block(7, oh6, root);
        chain_store.put_block(&old7).unwrap();
        let oh7 = old7.hash();
        let old8 = make_block(8, oh7, root);
        chain_store.put_block(&old8).unwrap();
        let oh8 = old8.hash();
        chain_store.set_head(&oh8).unwrap();

        // New fork chain: 3 blocks (6', 7', 8') with different timestamps
        let mut new6 = make_block(6, ancestor_hash, root);
        new6.header.timestamp += 50;
        chain_store.put_block(&new6).unwrap();
        let nh6 = new6.hash();
        let mut new7 = make_block(7, nh6, root);
        new7.header.timestamp += 50;
        chain_store.put_block(&new7).unwrap();
        let nh7 = new7.hash();
        let mut new8 = make_block(8, nh7, root);
        new8.header.timestamp += 50;
        chain_store.put_block(&new8).unwrap();
        let nh8 = new8.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[oh6, oh7, oh8],
            &[nh6, nh7, nh8],
            0,
        )
        .unwrap();

        assert_eq!(result.rolled_back, 3);
        assert_eq!(result.applied, 3);
        assert_eq!(result.ancestor_number, 5);
        assert_eq!(result.new_head, nh8);

        // Canonical mappings should point to new chain.
        let canon6 = chain_store.get_block_by_number(6).unwrap().unwrap();
        assert_eq!(canon6.hash(), nh6);
        let canon7 = chain_store.get_block_by_number(7).unwrap().unwrap();
        assert_eq!(canon7.hash(), nh7);
    }

    #[test]
    fn test_reorg_blocked_by_finalized() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(3, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        // Ancestor is at block 3, but finalized is at 5 → reorg should be rejected.
        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            3,
            &[],
            &[],
            5,
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot reorg past finalized"),
            "expected finalization safety error, got: {err_msg}"
        );
    }

    #[test]
    fn test_reorg_preserves_unique_reverted_txs() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        // Old chain: 2 blocks, each with 1 unique tx.
        let tx_a = make_tx();
        let mut tx_b = make_tx();
        tx_b.tx.nonce = 99; // different tx

        let mut old6 = make_block(6, ancestor_hash, root);
        old6.transactions.push(tx_a.clone());
        chain_store.put_block(&old6).unwrap();

        let mut old7 = make_block(7, old6.hash(), root);
        old7.transactions.push(tx_b.clone());
        chain_store.put_block(&old7).unwrap();

        // New chain: 1 block, no transactions.
        let mut new6 = make_block(6, ancestor_hash, root);
        new6.header.timestamp += 1;
        chain_store.put_block(&new6).unwrap();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old6.hash(), old7.hash()],
            &[new6.hash()],
            0,
        )
        .unwrap();

        // Both txs should be in reverted list since they aren't in the new chain.
        assert_eq!(result.reverted_txs.len(), 2);
    }

    #[test]
    fn test_reorg_updates_canonical_mappings() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        // Set canonical for old block 6.
        let old6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old6).unwrap();
        let old_hash = old6.hash();
        chain_store.set_canonical(6, &old_hash).unwrap();

        // Create new fork block 6.
        let mut new6 = make_block(6, ancestor_hash, root);
        new6.header.timestamp += 42;
        chain_store.put_block(&new6).unwrap();
        let new_hash = new6.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[new_hash],
            0,
        )
        .unwrap();

        assert_eq!(result.new_head, new_hash);

        // Canonical mapping at height 6 should now point to the new block.
        let canon = chain_store.get_block_by_number(6).unwrap().unwrap();
        assert_eq!(canon.hash(), new_hash);
    }

    #[test]
    fn test_reorg_replaces_canonical_transaction_indexes() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        let tx = make_tx();
        let tx_hash = tx.hash();
        let sender = tx.sender();
        let mut old6 = make_block(6, ancestor_hash, root);
        old6.transactions.push(tx);
        chain_store.put_block(&old6).unwrap();
        let old_hash = old6.hash();
        chain_store.set_canonical(6, &old_hash).unwrap();
        chain_store.set_head(&old_hash).unwrap();

        assert_eq!(
            chain_store.get_tx_location(&tx_hash).unwrap(),
            Some((old_hash, 0))
        );

        let mut new6 = make_block(6, ancestor_hash, root);
        new6.header.timestamp += 42;
        chain_store.put_side_fork_block(&new6).unwrap();
        let new_hash = new6.hash();

        ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[old_hash],
            &[new_hash],
            0,
        )
        .unwrap();

        assert!(chain_store.get_tx_location(&tx_hash).unwrap().is_none());
        assert!(chain_store
            .get_txs_by_address_cursor(&sender, 0, u64::MAX, None, 10, true)
            .unwrap()
            .0
            .is_empty());
    }

    #[test]
    fn test_reorg_refreshes_chain_totals_for_same_height_fork() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(0, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();
        chain_store.set_canonical(0, &ancestor_hash).unwrap();

        let mut old1 = make_block(1, ancestor_hash, root);
        old1.header.gas_used = 21_000;
        old1.transactions.push(make_tx());
        chain_store.put_block(&old1).unwrap();
        let old_hash = old1.hash();
        chain_store.set_canonical(1, &old_hash).unwrap();
        chain_store.set_head(&old_hash).unwrap();
        chain_store.set_total_tx_count(1).unwrap();
        chain_store
            .set_total_gas_used(U256::from(21_000u64))
            .unwrap();
        chain_store.set_chain_totals_head(1).unwrap();

        let mut tx_b = make_tx();
        tx_b.tx.nonce = 1;
        let mut new1 = make_block(1, ancestor_hash, root);
        new1.header.timestamp += 1;
        new1.header.gas_used = 42_000;
        new1.transactions.push(make_tx());
        new1.transactions.push(tx_b);
        chain_store.put_side_fork_block(&new1).unwrap();
        let new_hash = new1.hash();

        ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            0,
            &[old_hash],
            &[new_hash],
            0,
        )
        .unwrap();

        let (total_txs, total_gas) = chain_store.get_chain_totals(1).unwrap();
        assert_eq!(total_txs, 2);
        assert_eq!(total_gas, U256::from(42_000u64));
        assert_eq!(chain_store.get_chain_totals_head().unwrap(), Some(1));
    }

    #[test]
    fn test_reorg_cleans_stale_canonical_mappings() {
        let (store, chain_store, world_state, root) = setup_chain();

        let ancestor = make_block(5, make_hash(0), root);
        chain_store.put_block(&ancestor).unwrap();
        let ancestor_hash = ancestor.hash();

        // Old chain: 3 blocks at heights 6, 7, 8
        let old6 = make_block(6, ancestor_hash, root);
        chain_store.put_block(&old6).unwrap();
        let oh6 = old6.hash();
        chain_store.set_canonical(6, &oh6).unwrap();

        let old7 = make_block(7, oh6, root);
        chain_store.put_block(&old7).unwrap();
        let oh7 = old7.hash();
        chain_store.set_canonical(7, &oh7).unwrap();

        let old8 = make_block(8, oh7, root);
        chain_store.put_block(&old8).unwrap();
        let oh8 = old8.hash();
        chain_store.set_canonical(8, &oh8).unwrap();
        chain_store.set_head(&oh8).unwrap();

        // New chain: only 1 block at height 6
        let mut new6 = make_block(6, ancestor_hash, root);
        new6.header.timestamp += 100;
        chain_store.put_block(&new6).unwrap();
        let nh6 = new6.hash();

        let result = ReorgEngine::execute(
            &chain_store,
            &world_state,
            &store,
            ancestor_hash,
            5,
            &[oh6, oh7, oh8],
            &[nh6],
            0,
        )
        .unwrap();

        assert_eq!(result.rolled_back, 3);
        assert_eq!(result.applied, 1);

        // Height 6 should point to new block
        let canon6 = chain_store.get_block_by_number(6).unwrap().unwrap();
        assert_eq!(canon6.hash(), nh6);

        // Heights 7 and 8 should have stale canonical mappings removed
        assert!(
            chain_store.get_block_by_number(7).unwrap().is_none(),
            "stale canonical mapping at height 7 should be removed"
        );
        assert!(
            chain_store.get_block_by_number(8).unwrap().is_none(),
            "stale canonical mapping at height 8 should be removed"
        );
    }
}
