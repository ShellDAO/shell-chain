use shell_primitives::ShellHash;
use std::collections::{HashMap, HashSet};

/// Score assigned to a block for fork choice comparison.
/// Higher score = preferred chain. Compared lexicographically by fields in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockScore {
    /// Whether this block is on or extends the finalized chain (1 = yes, 0 = no).
    /// Finalized-compatible chains always win.
    pub is_finalized: u8,
    /// Total attesting weight this block has received.
    pub attested_weight: u64,
    /// Block number (height). Higher = better.
    pub block_number: u64,
    /// Block hash used as deterministic tiebreaker (lower hash bytes = preferred).
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
            .then(self.attested_weight.cmp(&other.attested_weight))
            .then(self.block_number.cmp(&other.block_number))
            // Lower hash wins the deterministic final tiebreaker. Because higher
            // BlockScore is preferred, invert the comparison here.
            .then_with(|| other.block_hash.as_bytes().cmp(self.block_hash.as_bytes()))
    }
}

/// Fork choice rule implementation.
///
/// Maintains a block tree and selects the canonical head based on:
/// 1. Finalized chain always wins
/// 2. More attested weight = preferred
/// 3. Higher block number = preferred
/// 4. Lower block hash = deterministic tiebreaker
pub struct ForkChoice {
    /// Maps block hash to parent hash for tree traversal.
    parent_map: HashMap<ShellHash, ShellHash>,
    /// Maps block hash to its score.
    scores: HashMap<ShellHash, BlockScore>,
    /// Latest finalized checkpoint used to reject incompatible forks.
    finalized_root: Option<ShellHash>,
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
            attested_weight: 0,
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
            finalized_root: None,
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
        attested_weight: u64,
        is_on_finalized_chain: bool,
    ) -> bool {
        let is_finalized = match self.finalized_root {
            Some(_) => self
                .scores
                .get(&parent_hash)
                .is_some_and(|score| score.is_finalized == 1),
            None => is_on_finalized_chain,
        };
        let score = BlockScore {
            is_finalized: u8::from(is_finalized),
            attested_weight,
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

    /// Update attested weight for a block. Returns true if head changed.
    pub fn update_attested_weight(&mut self, block_hash: &ShellHash, new_weight: u64) -> bool {
        if let Some(score) = self.scores.get_mut(block_hash) {
            score.attested_weight = new_weight;
            let updated_score = score.clone();

            if block_hash == &self.head {
                self.head_score = updated_score;
                return false;
            }
            if updated_score > self.head_score {
                self.head = *block_hash;
                self.head_score = updated_score;
                return true;
            }
        }
        false
    }

    /// Mark a block as finalized. Returns true if head changed.
    pub fn mark_finalized(&mut self, block_hash: &ShellHash) -> bool {
        if !self.scores.contains_key(block_hash) {
            return false;
        }
        if let Some(finalized_root) = self.finalized_root {
            if finalized_root != *block_hash
                && self.chain_between(block_hash, &finalized_root).is_empty()
            {
                return false;
            }
        }

        let old_head = self.head;
        let mut children: HashMap<ShellHash, Vec<ShellHash>> = HashMap::new();
        for (child, parent) in &self.parent_map {
            children.entry(*parent).or_default().push(*child);
        }

        for score in self.scores.values_mut() {
            score.is_finalized = 0;
        }
        self.finalized_root = Some(*block_hash);

        let mut descendants = vec![*block_hash];
        let mut marked = HashSet::new();
        while let Some(parent) = descendants.pop() {
            if !marked.insert(parent) {
                continue;
            }
            if let Some(score) = self.scores.get_mut(&parent) {
                score.is_finalized = 1;
            }
            if let Some(child_hashes) = children.get(&parent) {
                descendants.extend(child_hashes);
            }
        }

        self.recalculate_head();
        self.head != old_head
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

    /// Retain the finalized block at `finalized_number` and its descendants.
    /// The retained finalized block becomes the new root of the in-memory tree.
    pub fn prune_below(&mut self, finalized_number: u64) {
        let Some(finalized_hash) = self
            .scores
            .iter()
            .filter(|(_, score)| score.is_finalized == 1 && score.block_number == finalized_number)
            .map(|(hash, _)| *hash)
            .min_by(|hash_a, hash_b| hash_a.as_bytes().cmp(hash_b.as_bytes()))
        else {
            return;
        };

        let mut children: HashMap<ShellHash, Vec<ShellHash>> = HashMap::new();
        for (child, parent) in &self.parent_map {
            children.entry(*parent).or_default().push(*child);
        }

        let mut protected = HashSet::from([finalized_hash]);
        let mut pending = vec![finalized_hash];
        while let Some(parent) = pending.pop() {
            if let Some(child_hashes) = children.get(&parent) {
                for child in child_hashes {
                    if protected.insert(*child) {
                        pending.push(*child);
                    }
                }
            }
        }

        self.scores.retain(|hash, _| protected.contains(hash));
        for score in self.scores.values_mut() {
            score.is_finalized = 1;
        }
        self.parent_map.retain(|hash, _| protected.contains(hash));
        self.parent_map.insert(finalized_hash, ShellHash::ZERO);
        self.finalized_root = Some(finalized_hash);

        self.recalculate_head();
    }

    /// Remove a terminally invalid block and every descendant from fork choice.
    ///
    /// Genesis and the finalized root are protected so validation failures
    /// cannot erase the trusted base of the fork-choice tree.
    pub fn remove_subtree(&mut self, root: &ShellHash) -> bool {
        if self.finalized_root == Some(*root)
            || self.parent_map.get(root) == Some(&ShellHash::ZERO)
            || !self.scores.contains_key(root)
        {
            return false;
        }

        let mut children: HashMap<ShellHash, Vec<ShellHash>> = HashMap::new();
        for (child, parent) in &self.parent_map {
            children.entry(*parent).or_default().push(*child);
        }

        let mut removed = HashSet::new();
        let mut pending = vec![*root];
        while let Some(parent) = pending.pop() {
            if !removed.insert(parent) {
                continue;
            }
            if let Some(child_hashes) = children.get(&parent) {
                pending.extend(child_hashes);
            }
        }
        if self
            .finalized_root
            .is_some_and(|finalized| removed.contains(&finalized))
        {
            return false;
        }

        self.scores.retain(|hash, _| !removed.contains(hash));
        self.parent_map.retain(|hash, _| !removed.contains(hash));
        self.recalculate_head();
        true
    }

    /// Number of tracked blocks.
    pub fn block_count(&self) -> usize {
        self.scores.len()
    }

    /// Re-evaluate head by scanning all scores. Use after bulk updates.
    pub fn recalculate_head(&mut self) {
        if let Some((hash, score)) = self.scores.iter().max_by(|(_, a), (_, b)| a.cmp(b)) {
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
    fn test_equal_score_low_hash_wins() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        // Fork at genesis: block 2 is also at height 1 but loses the low-hash tiebreaker.
        let became_head = fc.add_block(hash(2), hash(0), 1, 0, false);
        assert!(!became_head);
        assert_eq!(fc.head(), &hash(1));
    }

    #[test]
    fn test_attested_weight_wins_over_height() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false); // height 2, weight 0
        fc.add_block(hash(3), hash(0), 1, 5, false); // height 1, weight 5
        assert_eq!(fc.head(), &hash(3));
    }

    #[test]
    fn test_heavier_weight_beats_more_attesters() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 4, false);
        fc.add_block(hash(2), hash(0), 1, 5, false);
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn test_finalized_always_wins() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 10, false); // weight 10, not finalized
        fc.add_block(hash(2), hash(0), 1, 1, true); // weight 1, finalized
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn test_update_attested_weight_changes_head() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(0), 1, 0, false);
        // hash(1) < hash(2) as bytes, so hash(1) is head.
        assert_eq!(fc.head(), &hash(1));
        let changed = fc.update_attested_weight(&hash(1), 5);
        assert!(!changed);
        assert_eq!(fc.head(), &hash(1));
    }

    #[test]
    fn test_mark_finalized() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 5, false);

        assert!(!fc.mark_finalized(&hash(1)));
        assert_eq!(fc.score(&hash(1)).unwrap().is_finalized, 1);
        assert_eq!(fc.score(&hash(2)).unwrap().is_finalized, 1);
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn remove_subtree_rejects_invalid_head_and_descendants() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, true);
        fc.add_block(hash(2), hash(1), 2, 0, true);
        fc.add_block(hash(3), hash(0), 1, 10, true);
        fc.add_block(hash(4), hash(3), 2, 10, true);
        assert_eq!(fc.head(), &hash(4));

        assert!(fc.remove_subtree(&hash(3)));

        assert_eq!(fc.head(), &hash(2));
        assert!(!fc.contains(&hash(3)));
        assert!(!fc.contains(&hash(4)));
        assert_eq!(fc.block_count(), 3);
    }

    #[test]
    fn remove_subtree_preserves_genesis_and_finalized_root() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, true);
        fc.mark_finalized(&hash(1));

        assert!(!fc.remove_subtree(&hash(0)));
        assert!(!fc.remove_subtree(&hash(1)));
        assert_eq!(fc.head(), &hash(1));
        assert_eq!(fc.block_count(), 2);
    }

    #[test]
    fn finality_excludes_incompatible_forks() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(0), 1, 10, true);

        assert!(fc.mark_finalized(&hash(1)));
        assert_eq!(fc.score(&hash(2)).unwrap().is_finalized, 1);
        assert_eq!(fc.score(&hash(3)).unwrap().is_finalized, 0);
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn finality_cannot_move_to_an_incompatible_fork() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(0), 1, 100, false);

        fc.mark_finalized(&hash(1));
        fc.mark_finalized(&hash(2));
        assert!(!fc.mark_finalized(&hash(3)));
        assert_eq!(fc.score(&hash(2)).unwrap().is_finalized, 1);
        assert_eq!(fc.score(&hash(3)).unwrap().is_finalized, 0);
        assert_eq!(fc.head(), &hash(2));
    }

    #[test]
    fn descendants_added_after_finality_inherit_finalized_chain_status() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.mark_finalized(&hash(1));

        assert!(fc.add_block(hash(2), hash(1), 2, 0, false));
        assert_eq!(fc.score(&hash(2)).unwrap().is_finalized, 1);
        assert_eq!(fc.head(), &hash(2));

        fc.add_block(hash(3), hash(0), 1, 100, true);
        assert_eq!(fc.score(&hash(3)).unwrap().is_finalized, 0);
        assert_eq!(fc.head(), &hash(2));
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
        assert!(!fc.contains(&hash(1))); // history below finality is pruned
        assert!(fc.contains(&hash(2))); // kept (finalized)
        assert!(!fc.contains(&hash(0))); // finalized block is the new root
        assert_eq!(fc.parent(&hash(2)), Some(&ShellHash::ZERO));
    }

    #[test]
    fn prune_discards_canonical_history_below_finality() {
        let mut fc = ForkChoice::new(hash(0));
        for block_number in 1..=100u8 {
            fc.add_block(
                hash(block_number),
                hash(block_number - 1),
                u64::from(block_number),
                0,
                true,
            );
        }

        fc.prune_below(100);

        assert_eq!(fc.block_count(), 1);
        assert!(fc.contains(&hash(100)));
        assert_eq!(fc.parent(&hash(100)), Some(&ShellHash::ZERO));
    }

    #[test]
    fn prune_keeps_latest_finalized_block_as_head() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 100, true);
        fc.add_block(hash(2), hash(1), 2, 67, false);
        fc.mark_finalized(&hash(2));
        assert_eq!(fc.head(), &hash(2));

        fc.prune_below(2);

        assert_eq!(fc.head(), &hash(2));
        assert_eq!(fc.block_count(), 1);
        assert_eq!(fc.parent(&hash(2)), Some(&ShellHash::ZERO));
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
            attested_weight: 10,
            block_number: 5,
            block_hash: hash(1),
        };
        let s2 = BlockScore {
            is_finalized: 1,
            attested_weight: 0,
            block_number: 1,
            block_hash: hash(2),
        };
        assert!(s2 > s1); // finalized wins

        let s3 = BlockScore {
            is_finalized: 0,
            attested_weight: 5,
            block_number: 10,
            block_hash: hash(3),
        };
        let s4 = BlockScore {
            is_finalized: 0,
            attested_weight: 3,
            block_number: 100,
            block_hash: hash(4),
        };
        assert!(s3 > s4); // more attested weight wins over height
    }

    #[test]
    fn test_recalculate_head() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(0), 1, 0, false);

        // Manually change score
        if let Some(score) = fc.scores.get_mut(&hash(1)) {
            score.attested_weight = 100;
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

        // hash(10) < hash(20) as bytes, so hash(10) wins
        assert_eq!(fc.head(), &hash(10));
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
    fn update_attested_weight_unknown_block() {
        let mut fc = ForkChoice::new(hash(0));
        // Updating an unknown block should be a no-op
        let changed = fc.update_attested_weight(&hash(99), 100);
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
    fn prune_preserves_finalized_root_and_descendants() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, true); // on finalized chain
        fc.add_block(hash(3), hash(2), 3, 0, false);
        fc.add_block(hash(4), hash(0), 1, 0, false); // fork, not finalized

        fc.mark_finalized(&hash(2));
        fc.prune_below(2);

        assert!(!fc.contains(&hash(0)), "history below finality is pruned");
        assert!(
            fc.contains(&hash(2)),
            "finalized block must survive pruning"
        );
        assert!(fc.contains(&hash(3)), "block above finalized must survive");
        assert!(
            !fc.contains(&hash(4)),
            "non-finalized fork block below finalized should be pruned"
        );
        assert!(!fc.contains(&hash(1)), "ancestor below finality is pruned");
        assert_eq!(fc.chain_between(&hash(3), &hash(2)), vec![hash(3)]);
    }

    #[test]
    fn prune_removes_side_fork_and_finalized_ancestors() {
        let mut fc = ForkChoice::new(hash(0));
        fc.add_block(hash(1), hash(0), 1, 0, false);
        fc.add_block(hash(2), hash(1), 2, 0, false);
        fc.add_block(hash(3), hash(0), 1, 0, false);
        fc.add_block(hash(4), hash(3), 2, 0, false);

        fc.mark_finalized(&hash(2));
        fc.prune_below(2);

        assert!(!fc.contains(&hash(1)), "canonical history should be pruned");
        assert!(fc.contains(&hash(2)), "finalized block should remain");
        assert!(
            !fc.contains(&hash(3)),
            "side fork ancestor should be pruned"
        );
        assert!(
            !fc.contains(&hash(4)),
            "side fork block below finalized height should be pruned"
        );
        assert_eq!(fc.parent(&hash(2)), Some(&ShellHash::ZERO));
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
