//! State-root pruning: track recent state roots and mark old ones for eviction.
//!
//! The tracker records `(block_number, state_root)` pairs after each block is
//! finalised.  When the history exceeds [`PruningConfig::keep_recent`], the
//! oldest entries are evicted and logged.  Actual trie-node deletion is deferred
//! to a future milestone (requires reference-counting).

use serde::{Deserialize, Serialize};
use shell_primitives::ShellHash;
use shell_storage::{DEFAULT_BODY_RETENTION, DEFAULT_WITNESS_RETENTION};
use std::collections::VecDeque;

/// Configuration for state-root pruning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Number of recent state roots to retain.
    /// `0` means archive mode — no roots are ever evicted.
    pub keep_recent: u64,
    /// Number of recent blocks whose witness bundles are retained.
    /// `0` means archive mode — no witness bundles are ever pruned.
    /// Default: 128 (matches `DEFAULT_WITNESS_RETENTION`).
    pub witness_retention: u64,
    /// Number of recent blocks whose full bodies are retained.
    /// `0` means archive mode — no bodies are ever pruned.
    /// Default: 512 (matches `DEFAULT_BODY_RETENTION`).
    pub body_retention: u64,
    /// Minimum number of blocks to wait after a `ProofAmendment` is stored
    /// before the corresponding `WitnessBundle` (`w/<hash>`) is deleted.
    ///
    /// `0` (default) means delete immediately once the proof lands.
    /// A non-zero value keeps signatures available for that many extra blocks
    /// (useful for forensic / audit windows in production).
    pub proof_replacement_grace: u64,
    /// Enable experimental state-trie pruning (L3).
    ///
    /// When `false` (default), state roots are tracked in memory but no trie
    /// nodes are physically deleted on eviction — archive mode for trie data.
    /// When `true`, evicted state roots trigger reference-count decrements and
    /// zero-ref trie nodes are deleted from storage. **Experimental** — only
    /// enable after thorough testing; a bug here can corrupt the state trie.
    pub state_pruning_experimental: bool,
}

impl PruningConfig {
    /// Convenience constructor for a non-archive node.
    pub fn new(keep_recent: u64) -> Self {
        Self {
            keep_recent,
            witness_retention: DEFAULT_WITNESS_RETENTION,
            body_retention: DEFAULT_BODY_RETENTION,
            proof_replacement_grace: 0,
            state_pruning_experimental: false,
        }
    }

    /// Returns `true` when pruning is disabled (archive mode).
    pub fn is_archive(&self) -> bool {
        self.keep_recent == 0
    }
}

/// Entry in the state-root history ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRootEntry {
    pub block_number: u64,
    pub state_root: ShellHash,
}

/// In-memory tracker that records state roots and evicts old ones according to
/// the configured retention window.
#[derive(Debug)]
pub struct StateRootTracker {
    config: PruningConfig,
    history: VecDeque<StateRootEntry>,
}

impl StateRootTracker {
    /// Create a new tracker with the given pruning configuration.
    pub fn new(config: PruningConfig) -> Self {
        Self {
            config,
            history: VecDeque::new(),
        }
    }

    /// F-045: Even in archive mode, cap the in-memory tracker to prevent
    /// unbounded growth over very long running periods.
    const ARCHIVE_MAX_TRACKED: usize = 10_000;

    /// Record a newly finalised state root.
    ///
    /// If the history exceeds `keep_recent` (and pruning is enabled), the
    /// oldest entry is evicted and returned so the caller can log / act on it.
    /// In archive mode, the tracker is still capped at [`ARCHIVE_MAX_TRACKED`]
    /// entries to bound memory usage.
    pub fn record(&mut self, block_number: u64, state_root: ShellHash) -> Option<StateRootEntry> {
        self.history.push_back(StateRootEntry {
            block_number,
            state_root,
        });

        if self.config.is_archive() {
            // Archive mode: no pruning, but cap tracker memory.
            if self.history.len() > Self::ARCHIVE_MAX_TRACKED {
                return self.history.pop_front();
            }
            return None;
        }

        if self.history.len() as u64 > self.config.keep_recent {
            self.history.pop_front()
        } else {
            None
        }
    }

    /// Number of state roots currently tracked.
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Returns `true` when no roots are tracked.
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Oldest tracked entry (if any).
    pub fn oldest(&self) -> Option<&StateRootEntry> {
        self.history.front()
    }

    /// Most recent tracked entry (if any).
    pub fn latest(&self) -> Option<&StateRootEntry> {
        self.history.back()
    }

    /// Read-only access to the full history.
    pub fn history(&self) -> &VecDeque<StateRootEntry> {
        &self.history
    }

    /// Reference to the active pruning configuration.
    pub fn config(&self) -> &PruningConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_root(n: u8) -> ShellHash {
        ShellHash::from([n; 32])
    }

    #[test]
    fn archive_mode_never_evicts() {
        let mut tracker = StateRootTracker::new(PruningConfig::new(0));
        for i in 0..200u8 {
            let evicted = tracker.record(i as u64, dummy_root(i));
            assert!(evicted.is_none(), "archive mode must not evict");
        }
        assert_eq!(tracker.len(), 200);
    }

    #[test]
    fn evicts_oldest_when_exceeding_keep_recent() {
        let mut tracker = StateRootTracker::new(PruningConfig::new(3));

        assert!(tracker.record(1, dummy_root(1)).is_none());
        assert!(tracker.record(2, dummy_root(2)).is_none());
        assert!(tracker.record(3, dummy_root(3)).is_none());
        assert_eq!(tracker.len(), 3);

        // 4th entry should evict block 1.
        let evicted = tracker.record(4, dummy_root(4));
        assert!(evicted.is_some());
        let e = evicted.unwrap();
        assert_eq!(e.block_number, 1);
        assert_eq!(e.state_root, dummy_root(1));
        assert_eq!(tracker.len(), 3);

        // Oldest is now block 2.
        assert_eq!(tracker.oldest().unwrap().block_number, 2);
    }

    #[test]
    fn history_grows_within_limit() {
        let mut tracker = StateRootTracker::new(PruningConfig::new(5));
        for i in 1..=5 {
            assert!(tracker.record(i, dummy_root(i as u8)).is_none());
        }
        assert_eq!(tracker.len(), 5);
        assert_eq!(tracker.oldest().unwrap().block_number, 1);
        assert_eq!(tracker.latest().unwrap().block_number, 5);
    }

    #[test]
    fn keep_recent_one() {
        let mut tracker = StateRootTracker::new(PruningConfig::new(1));
        assert!(tracker.record(1, dummy_root(1)).is_none());
        let evicted = tracker.record(2, dummy_root(2)).unwrap();
        assert_eq!(evicted.block_number, 1);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.latest().unwrap().block_number, 2);
    }

    #[test]
    fn default_config_is_archive() {
        let cfg = PruningConfig::default();
        assert!(cfg.is_archive());
        assert_eq!(cfg.keep_recent, 0);
    }
}
