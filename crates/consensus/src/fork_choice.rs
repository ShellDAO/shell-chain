use shell_primitives::ShellHash;
use std::collections::HashMap;

/// Score assigned to a block for fork choice comparison.
/// Higher score = preferred chain. Compared lexicographically by fields in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockScore {
    /// Whether this block is on the finalized chain (1 = yes, 0 = no).
    /// Finalized chains always win.
    pub is_finalized: u8,
    /// Number of attestations this block has received.
    pub attestation_count: usize,
    /// Block number (height). Higher = better.
    pub block_number: u64,
    /// Block hash used as tiebreaker (higher hash bytes = preferred).
    pub block_hash: ShellHash,
}

impl PartialOrd for BlockScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.is_finalized
            .cmp(&other.is_finalized)
            .then(self.attestation_count.cmp(&other.attestation_count))
            .then(self.block_number.cmp(&other.block_number))
            .then(self.block_hash.as_bytes().cmp(other.block_hash.as_bytes()))
    }
}

/// Fork choice rule implementation.
///
/// Maintains a block tree and selects the canonical head based on:
/// 1. Finalized chain always wins
/// 2. More attestations = preferred
/// 3. Higher block number = preferred
/// 4. Higher block hash = tiebreaker
pub struct ForkChoice {
    /// Maps block hash to parent hash for tree traversal.
    parent_map: HashMap<ShellHash, ShellHash>,
    /// Maps block hash to its score.
    scores: HashMap<ShellHash, BlockScore>,
    /// Current canonical head.
    head: ShellHash,
    /// Current head score.
    head_score: BlockScore,
}

impl ForkChoice {
    /// Create a new fork choice tracker starting from genesis.
    pub fn new(genesis_hash: ShellHash) -> Self {
        let score = BlockScore {
            is_finalized: 0,
            attestation_count: 0,
            block_number: 0,
            block_hash: genesis_hash,
        };
        let mut scores = HashMap::new();
        scores.insert(genesis_hash, score.clone());
        let mut parent_map = HashMap::new();
        parent_map.insert(genesis_hash, ShellHash::ZERO);

        Self {
            parent_map,
            scores,
            head: genesis_hash,
            head_score: score,
        }
    }

    /// Register a new block in the fork choice tree.
    /// Returns true if this block becomes the new head.
    pub fn add_block(
        &mut self,
        block_hash: ShellHash,
        parent_hash: ShellHash,
        block_number: u64,
        attestation_count: usize,
        is_on_finalized_chain: bool,
    ) -> bool {
        let score = BlockScore {
            is_finalized: if is_on_finalized_chain { 1 } else { 0 },
            attestation_count,
            block_number,
            block_hash,
        };

        self.parent_map.insert(block_hash, parent_hash);
        self.scores.insert(block_hash, score.clone());

        if score > self.head_score {
            self.head = block_hash;
            self.head_score = score;
            true
        } else {
            false
        }
    }

    /// Update attestation count for a block. Returns true if head changed.
    pub fn update_attestations(&mut self, block_hash: &ShellHash, new_count: usize) -> bool {
        if let Some(score) = self.scores.get_mut(block_hash) {
            score.attestation_count = new_count;
            let updated_score = score.clone();

            if updated_score > self.head_score {
                self.head = *block_hash;
                self.head_score = updated_score;
                return true;
            }
            // Re-check in case the current head's score was updated
            if block_hash == &self.head {
                self.head_score = updated_score;
            }
        }
        false
    }

    /// Mark a block as finalized. Returns true if head changed.
    pub fn mark_finalized(&mut self, block_hash: &ShellHash) -> bool {
        if let Some(score) = self.scores.get_mut(block_hash) {
            score.is_finalized = 1;
            let updated_score = score.clone();

            if updated_score > self.head_score {
                self.head = *block_hash;
                self.head_score = updated_score;
                return true;
            }
            if block_hash == &self.head {
                self.head_score = updated_score;
            }
        }
        false
    }

    /// Get the current canonical head hash.
    pub fn head(&self) -> &ShellHash {
        &self.head
    }

    /// Get the score for a block.
    pub fn score(&self, block_hash: &ShellHash) -> Option<&BlockScore> {
        self.scores.get(block_hash)
    }

    /// Get the parent hash of a block.
    pub fn parent(&self, block_hash: &ShellHash) -> Option<&ShellHash> {
        self.parent_map.get(block_hash)
    }

    /// Check if a block is known to fork choice.
    pub fn contains(&self, block_hash: &ShellHash) -> bool {
        self.scores.contains_key(block_hash)
    }

    /// Find the common ancestor of two blocks by walking up the parent chain.
    /// Returns None if blocks are not in the same tree.
    pub fn find_common_ancestor(
        &self,
        hash_a: &ShellHash,
        hash_b: &ShellHash,
    ) -> Option<ShellHash> {
        // Collect ancestors of A
        let mut ancestors_a = std::collections::HashSet::new();
        let mut current = *hash_a;
        loop {
            ancestors_a.insert(current);
            match self.parent_map.get(&current) {
                Some(parent) if *parent != ShellHash::ZERO => current = *parent,
                Some(_) => break, // reached genesis
                None => break,
            }
        }

        // Walk up from B until we find a common ancestor
        let mut current = *hash_b;
        loop {
            if ancestors_a.contains(&current) {
                return Some(current);
            }
            match self.parent_map.get(&current) {
                Some(parent) if *parent != ShellHash::ZERO => current = *parent,
                Some(_) => {
                    // At genesis — check if genesis is a common ancestor
                    if ancestors_a.contains(&current) {
                        return Some(current);
                    }
                    return None;
                }
                None => return None,
            }
        }
    }

    /// Collect the chain from `from_hash` back to `to_hash` (exclusive).
    /// Returns block hashes in order from oldest to newest.
    pub fn chain_between(&self, from_hash: &ShellHash, to_hash: &ShellHash) -> Vec<ShellHash> {
        let mut chain = Vec::new();
        let mut current = *from_hash;
        let max_depth = self.parent_map.len().saturating_add(1);
        let mut iterations: usize = 0;
        while current != *to_hash {
            iterations = iterations.saturating_add(1);
            if iterations > max_depth {
                // Cycle detected or excessively deep chain — bail out.
                return Vec::new();
            }
            chain.push(current);
            match self.parent_map.get(&current) {
                Some(parent) => current = *parent,
                None => return Vec::new(), // broken chain
            }
        }
        chain.reverse();
        chain
    }

    /// Remove blocks that are below the finalized height and not on the canonical chain.
    /// This prevents unbounded memory growth.
    pub fn prune_below(&mut self, finalized_number: u64) {
        let to_remove: Vec<ShellHash> = self
            .scores
            .iter()
            .filter(|(_, score)| {
                score.block_number < finalized_number
                    && score.is_finalized == 0
                    && score.block_number > 0 // never prune genesis
            })
            .map(|(hash, _)| *hash)
            .collect();

        for hash in to_remove {
            self.scores.remove(&hash);
            self.parent_map.remove(&hash);
        }
    }

    /// Number of tracked blocks.
    pub fn block_count(&self) -> usize {
        self.scores.len()
    }

    /// Re-evaluate head by scanning all scores. Use after bulk updates.
    pub fn recalculate_head(&mut self) {
        if let Some((hash, score)) = self.scores.iter().max_by_key(|(_, s)| (*s).clone()) {
            self.head = *hash;
            self.head_score = score.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> ShellHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        bytes[31] = 1; // ensure non-zero so it doesn't collide with ZERO sentinel
        ShellHash::from(bytes)
    }

    #[test]
    fn test_genesis_is_head() {
        let fc = ForkChoice::new(hash(0));
        assert_eq!(fc.head(), &hash(0));
        assert!(fc.contains(&hash(0)));
    }

    #[test]
    fn test_linear_chain() {
        let mut fc = ForkChoice::new(hash(0));
        assert!(fc.add_block(hash(1), hash(0), 1, 0, true));
        assert_eq!(fc.head(), &hash(1));
        assert!(fc.add_block(hash(2), hash(1), 2, 0, true));
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn test_fork_higher_block_wins() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        // Fork at genesis: block 2 is also at height 1 but with higher hash
        let became_head = fc.add_block(hash(2), hash(0), 1, 0, false);
        // hash(2) > hash(1) as tiebreaker
        assert!(became_head);
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn test_attestations_win_over_height() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false); // height 2, 0 attestations
        fc.add_block(hash(3), hash(0), 1, 5, false); // height 1, 5 attestations
        assert_eq!(fc.head(), &hash(3));
    }

    #[test]
    fn test_finalized_always_wins() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 10, false); // 10 attestations, not finalized
        fc.add_block(hash(2), hash(0), 1, 1, true); // 1 attestation, finalized
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn test_update_attestations_changes_head() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(0), 1, 0, false);
        // hash(2) > hash(1) as bytes, so hash(2) is head
        assert_eq!(fc.head(), &hash(2));
        let changed = fc.update_attestations(&hash(1), 5);
        assert!(changed);
        assert_eq!(fc.head(), &hash(1));
    }

    #[test]
    fn test_mark_finalized() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 5, false); // higher score
                                                     // is_finalized comparison happens first: 1 > 0, so hash(1) wins
        fc.mark_finalized(&hash(1));
        assert_eq!(fc.head(), &hash(1));
    }

    #[test]
    fn test_common_ancestor_linear() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, true);
        fc.add_block(hash(2), hash(1), 2, 0, true);

        let ancestor = fc.find_common_ancestor(&hash(2), &hash(1));
        assert_eq!(ancestor, Some(hash(1)));

        let ancestor = fc.find_common_ancestor(&hash(2), &hash(0));
        assert_eq!(ancestor, Some(hash(0)));
    }

    #[test]
    fn test_common_ancestor_fork() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(0), 1, 0, false); // fork from genesis
        fc.add_block(hash(4), hash(3), 2, 0, false);
        let ancestor = fc.find_common_ancestor(&hash(2), &hash(4));
        assert_eq!(ancestor, Some(hash(0)));
    }

    #[test]
    fn test_chain_between() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, true);
        fc.add_block(hash(2), hash(1), 2, 0, true);
        fc.add_block(hash(3), hash(2), 3, 0, true);
        let chain = fc.chain_between(&hash(3), &hash(0));
        assert_eq!(chain, vec![hash(1), hash(2), hash(3)]);
    }

    #[test]
    fn test_prune_below() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, true); // finalized
        fc.add_block(hash(3), hash(0), 1, 0, false); // fork, not finalized
        fc.prune_below(2);
        assert!(!fc.contains(&hash(3))); // pruned
        assert!(!fc.contains(&hash(1))); // pruned
        assert!(fc.contains(&hash(2))); // kept (finalized)
        assert!(fc.contains(&hash(0))); // kept (genesis, block_number=0)
    }

    #[test]
    fn test_block_count() {
        let mut fc = ForkChoice::new(hash(0));
        assert_eq!(fc.block_count(), 1);
        fc.add_block(hash(1), hash(0), 1, 0, false);
        assert_eq!(fc.block_count(), 2);
    }

    #[test]
    fn test_score_ordering() {
        let s1 = BlockScore {
            is_finalized: 0,
            attestation_count: 10,
            block_number: 5,
            block_hash: hash(1),
        };
        let s2 = BlockScore {
            is_finalized: 1,
            attestation_count: 0,
            block_number: 1,
            block_hash: hash(2),
        };
        assert!(s2 > s1); // finalized wins

        let s3 = BlockScore {
            is_finalized: 0,
            attestation_count: 5,
            block_number: 10,
            block_hash: hash(3),
        };
        let s4 = BlockScore {
            is_finalized: 0,
            attestation_count: 3,
            block_number: 100,
            block_hash: hash(4),
        };
        assert!(s3 > s4); // more attestations wins over height
    }

    #[test]
    fn test_recalculate_head() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(0), 1, 0, false);

        // Manually change score
        if let Some(score) = fc.scores.get_mut(&hash(1)) {
            score.attestation_count = 100;
        }
        fc.recalculate_head();
        assert_eq!(fc.head(), &hash(1));
    }

    // ---- Additional comprehensive tests ----

    #[test]
    fn equal_attestations_higher_block_wins() {
        let mut fc = ForkChoice::new(hash(0));
        // Fork A: height 3, 5 attestations
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(2), 3, 5, false);

        // Fork B: height 2, 5 attestations (same attestation count, lower height)
        fc.add_block(hash(4), hash(0), 1, 0, false);
        fc.add_block(hash(5), hash(4), 2, 5, false);

        // hash(3) should win: same attestations but higher block number
        assert_eq!(fc.head(), &hash(3));
    }

    #[test]
    fn equal_score_hash_tiebreaker() {
        let mut fc = ForkChoice::new(hash(0));

        // Two blocks at same height, same attestations, not finalized
        // hash(10) has bytes [10, 0, ..., 1]
        // hash(20) has bytes [20, 0, ..., 1]
        fc.add_block(hash(10), hash(0), 1, 3, false);
        fc.add_block(hash(20), hash(0), 1, 3, false);

        // hash(20) > hash(10) as bytes, so hash(20) wins
        assert_eq!(fc.head(), &hash(20));
    }

    #[test]
    fn deep_fork_performance() {
        let mut fc = ForkChoice::new(hash(0));

        // Build a main chain of 150 blocks
        for i in 1..=150u8 {
            let parent = if i == 1 { hash(0) } else { hash(i - 1) };
            fc.add_block(hash(i), parent, i as u64, 0, true);
        }
        assert_eq!(fc.head(), &hash(150));
        assert_eq!(fc.block_count(), 151); // genesis + 150

        // Build a competing fork from block 50
        // Use a different hash scheme for the fork
        for i in 0..100u8 {
            let fork_hash = {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                bytes[1] = 0xFF; // differentiate from main chain
                bytes[31] = 1;
                ShellHash::from(bytes)
            };
            let parent = if i == 0 {
                hash(50)
            } else {
                let mut bytes = [0u8; 32];
                bytes[0] = i - 1;
                bytes[1] = 0xFF;
                bytes[31] = 1;
                ShellHash::from(bytes)
            };
            fc.add_block(fork_hash, parent, 51 + i as u64, 0, false);
        }

        // Main chain (finalized) should still be head
        assert_eq!(fc.head(), &hash(150));

        // Common ancestor should be hash(50)
        let fork_tip = {
            let mut bytes = [0u8; 32];
            bytes[0] = 99;
            bytes[1] = 0xFF;
            bytes[31] = 1;
            ShellHash::from(bytes)
        };
        let ancestor = fc.find_common_ancestor(&hash(150), &fork_tip);
        assert_eq!(ancestor, Some(hash(50)));
    }

    #[test]
    fn chain_between_broken_chain() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        // hash(5) is disconnected — not in the tree
        let chain = fc.chain_between(&hash(5), &hash(0));
        assert!(chain.is_empty(), "broken chain should return empty vec");
    }

    #[test]
    fn chain_between_same_block() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        let chain = fc.chain_between(&hash(1), &hash(1));
        assert!(
            chain.is_empty(),
            "chain from block to itself should be empty"
        );
    }

    #[test]
    fn common_ancestor_unknown_block() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);

        // hash(99) is not in the tree
        let ancestor = fc.find_common_ancestor(&hash(1), &hash(99));
        assert_eq!(ancestor, None);
    }

    #[test]
    fn multiple_competing_forks() {
        let mut fc = ForkChoice::new(hash(0));

        // Fork A: 3 blocks deep, 2 attestations on tip
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(2), 3, 2, false);

        // Fork B: 2 blocks deep, 5 attestations on tip
        fc.add_block(hash(4), hash(0), 1, 0, false);
        fc.add_block(hash(5), hash(4), 2, 5, false);

        // Fork C: 4 blocks deep, 1 attestation on tip
        fc.add_block(hash(6), hash(0), 1, 0, false);
        fc.add_block(hash(7), hash(6), 2, 0, false);
        fc.add_block(hash(8), hash(7), 3, 0, false);
        fc.add_block(hash(9), hash(8), 4, 1, false);

        // Fork B wins: 5 attestations > 2 > 1
        assert_eq!(fc.head(), &hash(5));
    }

    #[test]
    fn update_attestations_unknown_block() {
        let mut fc = ForkChoice::new(hash(0));
        // Updating an unknown block should be a no-op
        let changed = fc.update_attestations(&hash(99), 100);
        assert!(!changed);
        assert_eq!(fc.head(), &hash(0));
    }

    #[test]
    fn mark_finalized_unknown_block() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        // Marking an unknown block as finalized should be a no-op
        let changed = fc.mark_finalized(&hash(99));
        assert!(!changed);
    }

    #[test]
    fn prune_preserves_genesis_and_finalized() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, true); // on finalized chain
        fc.add_block(hash(3), hash(2), 3, 0, false);
        fc.add_block(hash(4), hash(0), 1, 0, false); // fork, not finalized

        fc.mark_finalized(&hash(2));
        fc.prune_below(3);

        assert!(fc.contains(&hash(0)), "genesis must survive pruning");
        assert!(
            fc.contains(&hash(2)),
            "finalized block must survive pruning"
        );
        assert!(fc.contains(&hash(3)), "block above finalized must survive");
        assert!(
            !fc.contains(&hash(4)),
            "non-finalized fork block below finalized should be pruned"
        );
        assert!(
            !fc.contains(&hash(1)),
            "non-finalized block below finalized should be pruned"
        );
    }

    #[test]
    fn add_block_becomes_head_then_superseded() {
        let mut fc = ForkChoice::new(hash(0));

        // Add block 1 → becomes head
        assert!(fc.add_block(hash(1), hash(0), 1, 0, false));
        assert_eq!(fc.head(), &hash(1));

        // Add block 2 → becomes head
        assert!(fc.add_block(hash(2), hash(1), 2, 0, false));
        assert_eq!(fc.head(), &hash(2));

        // Add block at same height with fewer attestations → does NOT become head
        assert!(!fc.add_block(hash(3), hash(0), 1, 0, false));
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn linear_chain_head_always_latest() {
        let mut fc = ForkChoice::new(hash(0));

        for i in 1..=20u8 {
            let parent = if i == 1 { hash(0) } else { hash(i - 1) };
            let became_head = fc.add_block(hash(i), parent, i as u64, 0, true);
            assert!(became_head, "block {i} should become new head");
            assert_eq!(fc.head(), &hash(i));
        }
    }

    #[test]
    fn chain_between_cycle_guard() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);

        // Manually inject a cycle: hash(1) -> hash(2) -> hash(1)
        fc.parent_map.insert(hash(1), hash(2));

        // Should detect the cycle and return empty instead of looping forever.
        let chain = fc.chain_between(&hash(2), &hash(99));
        assert!(
            chain.is_empty(),
            "cycle should be detected and return empty vec"
        );
    }
}
