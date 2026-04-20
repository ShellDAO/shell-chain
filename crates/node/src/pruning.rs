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

/// High-level node storage classification.
///
/// Each profile maps to a concrete set of pruning parameters.  The `--storage-profile`
/// CLI flag sets the active profile; individual flags (`--body-retention`, etc.) can
/// still override individual fields after the profile defaults are applied.
///
/// | Profile   | body_retention | witness_retention | proof_replacement_grace | keep_recent |
/// |-----------|---------------|------------------|------------------------|-------------|
/// | Archive   | 0 (forever)   | 0 (forever)      | u64::MAX (never)       | 0 (forever) |
/// | Full      | 0 (forever)   | 128              | 0 (immediate)          | 0 (forever) |
/// | Light     | 4 096         | 64               | 0 (immediate)          | 4 096       |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StorageProfile {
    /// Complete forensic archive: TX bodies + PQ signatures + STARK proofs, all kept forever.
    /// Witness bundles are **not** deleted even when a STARK proof arrives.
    Archive,
    /// Recommended full-node profile: TX bodies kept forever, PQ signatures are replaced
    /// by STARK proofs once the proof lands (disk-efficient).
    #[default]
    Full,
    /// Lightweight rolling window: only the most recent ~2.3 h of data is retained.
    Light,
}

impl StorageProfile {
    /// Parse a case-insensitive string slice.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "archive" => Ok(Self::Archive),
            "full" => Ok(Self::Full),
            "light" => Ok(Self::Light),
            other => Err(format!(
                "unknown storage profile '{other}'; valid values: archive, full, light"
            )),
        }
    }

    /// Returns the canonical lowercase name used in logs and CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Full => "full",
            Self::Light => "light",
        }
    }

    /// Returns the default `PruningConfig` values for this profile as
    /// `(body_retention, witness_retention, keep_recent, proof_replacement_grace)`.
    pub fn pruning_defaults(self) -> (u64, u64, u64, u64) {
        match self {
            // Archive: keep everything forever; never delete witness even after STARK proof.
            Self::Archive => (0, 0, 0, u64::MAX),
            // Full: keep TX forever; delete witness when STARK proof arrives.
            Self::Full => (0, DEFAULT_WITNESS_RETENTION, 0, 0),
            // Light: rolling 4 096-block window (~2.3 h at 2 s/block).
            Self::Light => (4_096, 64, 4_096, 0),
        }
    }

    /// Build a `PruningConfig` from this profile, then apply any per-field overrides.
    ///
    /// A `None` override means "use the profile default".
    pub fn to_pruning_config(
        self,
        body_retention: Option<u64>,
        witness_retention: Option<u64>,
        keep_recent: Option<u64>,
    ) -> PruningConfig {
        let (body_def, witness_def, keep_def, grace_def) = self.pruning_defaults();
        PruningConfig {
            body_retention: body_retention.unwrap_or(body_def),
            witness_retention: witness_retention.unwrap_or(witness_def),
            keep_recent: keep_recent.unwrap_or(keep_def),
            proof_replacement_grace: grace_def,
            state_pruning_experimental: false,
        }
    }

    /// Infer the closest-matching `StorageProfile` from an existing `PruningConfig`.
    ///
    /// Used when the node needs to advertise its capability without explicitly
    /// knowing which profile was originally configured.
    pub fn from_pruning_config(cfg: &PruningConfig) -> Self {
        if cfg.proof_replacement_grace == u64::MAX
            && cfg.body_retention == 0
            && cfg.witness_retention == 0
        {
            Self::Archive
        } else if cfg.body_retention == 0 && cfg.keep_recent == 0 {
            Self::Full
        } else {
            Self::Light
        }
    }
}

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

    // ── StorageProfile tests ──────────────────────────────────────────────────

    #[test]
    fn storage_profile_from_str_roundtrip() {
        for (input, expected) in &[
            ("archive", StorageProfile::Archive),
            ("ARCHIVE", StorageProfile::Archive),
            ("full", StorageProfile::Full),
            ("Full", StorageProfile::Full),
            ("light", StorageProfile::Light),
            ("LIGHT", StorageProfile::Light),
        ] {
            assert_eq!(
                StorageProfile::from_str(input).unwrap(),
                *expected,
                "input: {input}"
            );
        }
        assert!(StorageProfile::from_str("unknown").is_err());
    }

    #[test]
    fn storage_profile_defaults_archive() {
        let (body, witness, keep, grace) = StorageProfile::Archive.pruning_defaults();
        assert_eq!(body, 0, "archive: body_retention must be 0");
        assert_eq!(witness, 0, "archive: witness_retention must be 0");
        assert_eq!(keep, 0, "archive: keep_recent must be 0");
        assert_eq!(grace, u64::MAX, "archive: grace must be u64::MAX");
    }

    #[test]
    fn storage_profile_defaults_full() {
        let (body, witness, keep, grace) = StorageProfile::Full.pruning_defaults();
        assert_eq!(body, 0, "full: body_retention must be 0");
        assert!(witness > 0, "full: witness_retention must be non-zero");
        assert_eq!(keep, 0, "full: keep_recent must be 0");
        assert_eq!(grace, 0, "full: grace must be 0");
    }

    #[test]
    fn storage_profile_defaults_light() {
        let (body, witness, keep, grace) = StorageProfile::Light.pruning_defaults();
        assert!(body > 0, "light: body_retention must be non-zero");
        assert!(witness > 0, "light: witness_retention must be non-zero");
        assert!(keep > 0, "light: keep_recent must be non-zero");
        assert_eq!(grace, 0, "light: grace must be 0");
    }

    #[test]
    fn storage_profile_explicit_override_wins() {
        // Explicit body_retention=999 must override full profile's default of 0.
        let cfg = StorageProfile::Full.to_pruning_config(Some(999), None, None);
        assert_eq!(cfg.body_retention, 999);
        // witness still uses the full profile default.
        assert_eq!(cfg.witness_retention, DEFAULT_WITNESS_RETENTION);
    }

    #[test]
    fn storage_profile_to_pruning_config_archive() {
        let cfg = StorageProfile::Archive.to_pruning_config(None, None, None);
        assert_eq!(cfg.body_retention, 0);
        assert_eq!(cfg.witness_retention, 0);
        assert_eq!(cfg.keep_recent, 0);
        assert_eq!(cfg.proof_replacement_grace, u64::MAX);
    }
}
