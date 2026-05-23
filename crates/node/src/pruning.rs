//! State-root pruning: track recent state roots and mark old ones for eviction.
//!
//! The tracker records `(block_number, state_root)` pairs after each block is
//! finalised. When the history exceeds [`PruningConfig::keep_recent`], rolling
//! storage profiles prune trie snapshots that fall outside the retention window
//! while preserving nodes still reachable from retained state roots.

use std::collections::{HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use shell_primitives::ShellHash;
use shell_storage::{
    ChainStore, KvStore, StorageError, WorldState, DEFAULT_BODY_RETENTION,
    DEFAULT_WITNESS_RETENTION,
};

/// High-level node storage classification.
///
/// Each profile maps to a concrete set of pruning parameters.  The `--storage-profile`
/// CLI flag sets the active profile; individual flags (`--body-retention`, etc.) can
/// still override individual fields after the profile defaults are applied.
///
/// White-paper canonical names are `Archive`, `Full`, and `Pruned (Rolling)`.
/// `Light` is an accepted alias for `Pruned` (backwards compatible).
///
/// | Profile (WP name)       | body_retention | witness_retention | proof_replacement_grace | keep_recent |
/// |-------------------------|---------------|------------------|------------------------|-------------|
/// | Archive                 | 0 (forever)   | 0 (forever)      | u64::MAX (never)       | 0 (forever) |
/// | Full                    | 0 (forever)   | 128              | 0 (immediate)          | 0 (forever) |
/// | Pruned / Rolling / Light| 4 096         | 64               | 0 (immediate)          | 4 096       |
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
    /// Rolling/pruned window: only the most recent ~2.3 h of data is retained.
    ///
    /// White-paper names: `Pruned` or `Rolling`.  Accepted CLI alias: `light`.
    Light,
}

impl StorageProfile {
    /// Returns the canonical lowercase name used in logs and CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Full => "full",
            Self::Light => "light",
        }
    }

    /// Returns the white-paper canonical name for this profile.
    ///
    /// Prefer this method when surfacing the profile externally (e.g. RPC response,
    /// metrics labels) so clients receive the white-paper standard name.
    ///
    /// - `Archive` → `"archive"`
    /// - `Full`    → `"full"`
    /// - `Light`   → `"pruned"` (white-paper name for the rolling window profile)
    pub fn whitepaper_name(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Full => "full",
            Self::Light => "pruned",
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
    ///
    /// Note: classification is based on body/witness retention and proof-replacement
    /// grace only. `keep_recent` (state-root pruning) is intentionally excluded from
    /// the profile check because state-root pruning is independent of block-body storage.
    pub fn from_pruning_config(cfg: &PruningConfig) -> Self {
        if cfg.proof_replacement_grace == u64::MAX
            && cfg.body_retention == 0
            && cfg.witness_retention == 0
        {
            Self::Archive
        } else if cfg.body_retention == 0 && cfg.witness_retention != 0 {
            Self::Full
        } else {
            Self::Light
        }
    }
}

impl FromStr for StorageProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "archive" => Ok(Self::Archive),
            "full" => Ok(Self::Full),
            // White-paper names ("pruned", "rolling") and legacy alias ("light")
            // all map to the same rolling-window profile.
            "light" | "pruned" | "rolling" => Ok(Self::Light),
            other => Err(format!(
                "unknown storage profile '{other}'; valid values: archive, full, pruned (aliases: rolling, light)"
            )),
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
    /// Legacy compatibility flag for the original experimental trie-pruning
    /// rollout.
    ///
    /// Rolling/pruned storage profiles now prune old trie snapshots
    /// automatically. The field is kept for backwards-compatible config/RPC
    /// serialisation and no longer gates snapshot deletion.
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

/// Summary of a state-trie prune pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StateTriePruneResult {
    pub pruned_roots: u64,
    pub deleted_nodes: u64,
    pub skipped_roots: u64,
}

/// Delete hashed trie nodes for canonical state snapshots older than
/// `keep_below_block`, while preserving any nodes still reachable from retained
/// state roots.
pub fn prune_state_trie<S: KvStore + 'static>(
    store: Arc<S>,
    keep_below_block: u64,
    profile: StorageProfile,
) -> Result<StateTriePruneResult, StorageError> {
    if keep_below_block == 0 || !matches!(profile, StorageProfile::Light) {
        return Ok(StateTriePruneResult::default());
    }

    let chain_store = ChainStore::new(Arc::clone(&store));
    let Some(head) = chain_store.get_head_block()? else {
        return Ok(StateTriePruneResult::default());
    };

    let mut old_roots = Vec::new();
    let mut retained_roots = HashSet::new();

    // Only walk the retention window for retained roots — avoids O(chain_height)
    // per call which would become O(N²) over the chain's lifetime.
    let window_start = keep_below_block.min(head.number());
    for block_number in window_start..=head.number() {
        let Some(block_hash) = chain_store.get_block_hash_by_number(block_number)? else {
            continue;
        };
        let Some(header) = chain_store.get_header_by_hash(&block_hash)? else {
            continue;
        };
        retained_roots.insert(header.state_root);
    }

    // Only evict the block that just fell outside the retention window; all
    // earlier blocks have already been pruned by previous calls.
    if keep_below_block > 0 {
        let evicted_block = keep_below_block - 1;
        if let Some(block_hash) = chain_store.get_block_hash_by_number(evicted_block)? {
            if let Some(header) = chain_store.get_header_by_hash(&block_hash)? {
                old_roots.push(header.state_root);
            }
        }
    }

    let mut protected_nodes = HashSet::new();
    for root in retained_roots {
        protected_nodes.extend(WorldState::<S>::collect_snapshot_node_hashes(
            store.as_ref(),
            root,
        )?);
    }

    let mut result = StateTriePruneResult::default();
    let mut seen_old_roots = HashSet::new();
    for root in old_roots {
        if !seen_old_roots.insert(root) {
            continue;
        }
        let deleted =
            WorldState::<S>::delete_state_snapshot(store.as_ref(), root, &protected_nodes)?;
        if deleted > 0 {
            result.pruned_roots = result.pruned_roots.saturating_add(1);
            result.deleted_nodes = result.deleted_nodes.saturating_add(deleted);
        } else {
            result.skipped_roots = result.skipped_roots.saturating_add(1);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use shell_core::{Block, BlockHeader};
    use shell_primitives::{Address, Bytes, U256};
    use shell_storage::{ChainConfig, MemoryDb};

    fn dummy_root(n: u8) -> ShellHash {
        ShellHash::from([n; 32])
    }

    fn make_block(number: u64, parent_hash: ShellHash, state_root: ShellHash) -> Block {
        Block {
            header: BlockHeader {
                parent_hash,
                state_root,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::default(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_000_000 + number,
                extra_data: Bytes::default(),
                proposer: Address::from([number as u8; 20]),
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

    fn sample_address(seed: u8) -> Address {
        Address::from([seed; 20])
    }

    fn populate_state_chain() -> (Arc<MemoryDb>, Vec<ShellHash>, Vec<Address>) {
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));
        let mut roots = Vec::new();
        let mut addresses = Vec::new();
        let mut parent_hash = ShellHash::ZERO;

        for block_number in 0..3u64 {
            let mut world_state = WorldState::new(Arc::clone(&store));
            let address = sample_address(block_number as u8 + 1);
            world_state
                .add_balance(&address, U256::from(block_number + 1))
                .unwrap();
            let state_root = world_state.state_root().unwrap();
            roots.push(state_root);
            addresses.push(address);

            let block = make_block(block_number, parent_hash, state_root);
            parent_hash = block.hash();
            if block_number == 0 {
                chain_store
                    .commit_genesis_block(
                        &block,
                        &ChainConfig {
                            chain_id: 1337,
                            genesis_hash: block.hash(),
                        },
                    )
                    .unwrap();
            } else {
                chain_store.commit_canonical_block(&block, None).unwrap();
            }
        }

        (store, roots, addresses)
    }

    fn root_balance(
        store: &Arc<MemoryDb>,
        root: ShellHash,
        address: Address,
    ) -> Result<U256, StorageError> {
        let snapshot = WorldState::at_root(Arc::clone(store), &root)?;
        snapshot.get_balance(&address)
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

    #[test]
    fn pruned_profile_triggers_trie_deletion() {
        let (store, roots, addresses) = populate_state_chain();

        let result = prune_state_trie(Arc::clone(&store), 2, StorageProfile::Light).unwrap();

        assert!(result.deleted_nodes > 0);
        assert!(result.pruned_roots > 0);
        assert!(root_balance(&store, roots[0], addresses[0]).is_err());
        assert_eq!(
            root_balance(&store, roots[2], addresses[2]).unwrap(),
            U256::from(3u64)
        );
    }

    #[test]
    fn archive_profile_does_not_delete_trie_nodes() {
        let (store, roots, addresses) = populate_state_chain();

        let result = prune_state_trie(Arc::clone(&store), 2, StorageProfile::Archive).unwrap();

        assert_eq!(result, StateTriePruneResult::default());
        assert_eq!(
            root_balance(&store, roots[0], addresses[0]).unwrap(),
            U256::from(1u64)
        );
        assert_eq!(
            root_balance(&store, roots[2], addresses[2]).unwrap(),
            U256::from(3u64)
        );
    }

    #[test]
    fn pruned_block_state_root_becomes_inaccessible_after_prune() {
        let (store, roots, addresses) = populate_state_chain();

        assert_eq!(
            root_balance(&store, roots[1], addresses[1]).unwrap(),
            U256::from(2u64)
        );
        prune_state_trie(Arc::clone(&store), 2, StorageProfile::Light).unwrap();

        assert!(root_balance(&store, roots[1], addresses[1]).is_err());
        assert_eq!(
            root_balance(&store, roots[2], addresses[2]).unwrap(),
            U256::from(3u64)
        );
    }

    // ── White-paper alias tests ───────────────────────────────────────────────

    #[test]
    fn storage_profile_pruned_alias_parses() {
        assert_eq!(
            StorageProfile::from_str("pruned").unwrap(),
            StorageProfile::Light
        );
        assert_eq!(
            StorageProfile::from_str("PRUNED").unwrap(),
            StorageProfile::Light
        );
    }

    #[test]
    fn storage_profile_rolling_alias_parses() {
        assert_eq!(
            StorageProfile::from_str("rolling").unwrap(),
            StorageProfile::Light
        );
        assert_eq!(
            StorageProfile::from_str("Rolling").unwrap(),
            StorageProfile::Light
        );
    }

    #[test]
    fn storage_profile_whitepaper_name_light_is_pruned() {
        assert_eq!(StorageProfile::Light.whitepaper_name(), "pruned");
    }

    #[test]
    fn storage_profile_whitepaper_names_archive_and_full_unchanged() {
        assert_eq!(StorageProfile::Archive.whitepaper_name(), "archive");
        assert_eq!(StorageProfile::Full.whitepaper_name(), "full");
    }

    #[test]
    fn storage_profile_unknown_error_mentions_aliases() {
        let err = StorageProfile::from_str("bad_profile").unwrap_err();
        // Error message should guide users to both canonical and alias names.
        assert!(err.contains("archive"), "error should mention archive");
        assert!(err.contains("full"), "error should mention full");
        assert!(err.contains("pruned"), "error should mention pruned");
    }
}
