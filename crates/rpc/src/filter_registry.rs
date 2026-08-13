//! Filter registry for `eth_newFilter`, `eth_newBlockFilter`, `eth_getFilterChanges`,
//! `eth_getFilterLogs`, and `eth_uninstallFilter` RPCs.
//!
//! Filters are poll-based: clients install a filter, then periodically call
//! `eth_getFilterChanges` to drain accumulated results since the last poll.
//! Filters expire after a configurable TTL (default 5 minutes) of inactivity.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::Rng;
use shell_primitives::ShellHash;

use crate::filter::RawLogFilter;
use crate::types::RpcLogWithMeta;

/// Default time-to-live for idle filters (5 minutes).
const DEFAULT_TTL_SECS: u64 = 300;

/// Maximum number of concurrent filters to prevent resource exhaustion.
const MAX_FILTERS: usize = 1024;

/// Maximum random ID attempts before reporting allocation failure.
const MAX_FILTER_ID_GENERATION_ATTEMPTS: usize = 8;

/// Filter IDs are `0x` plus a 128-bit random value.
const FILTER_ID_LEN: usize = 34;

/// Types of filters that can be registered.
pub enum FilterKind {
    /// Log filter with criteria (from `eth_newFilter`).
    Log(RawLogFilter),
    /// Block filter — tracks new block hashes (from `eth_newBlockFilter`).
    Block,
}

/// Result returned by `get_filter_changes`.
pub enum FilterChanges {
    /// Accumulated log entries since last poll.
    Logs(Vec<RpcLogWithMeta>),
    /// Accumulated block hashes since last poll.
    BlockHashes(Vec<ShellHash>),
}

/// Internal state for a single registered filter.
pub struct FilterEntry {
    pub kind: FilterKind,
    /// Block number at filter creation (or last successful poll).
    pub last_poll_block: u64,
    /// Canonical block hash at `last_poll_block`, when a head exists.
    pub last_poll_hash: Option<ShellHash>,
    /// First block whose changes can be reported by this filter.
    pub changes_from_block: Option<u64>,
    /// Last access time for TTL-based expiry.
    pub last_access: Instant,
}

/// Canonical position delivered by the last successful filter poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterCursor {
    pub block_number: u64,
    pub block_hash: Option<ShellHash>,
}

/// Thread-safe registry of active filters.
///
/// Filter IDs are cryptographically random hex strings to prevent enumeration.
pub struct FilterRegistry {
    filters: RwLock<HashMap<String, FilterEntry>>,
    ttl_secs: u64,
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterRegistry {
    /// Create a new registry with the default TTL.
    pub fn new() -> Self {
        Self {
            filters: RwLock::new(HashMap::new()),
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// Create a new registry with a custom TTL (seconds).
    #[cfg(test)]
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            filters: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Install a new filter and return its hex-encoded ID.
    /// Returns `None` if the maximum filter count has been reached.
    pub fn new_filter(&self, kind: FilterKind, current_block: u64) -> Option<String> {
        self.new_filter_at(kind, current_block, None)
    }

    /// Install a new filter at an exact canonical position.
    pub fn new_filter_at(
        &self,
        kind: FilterKind,
        current_block: u64,
        current_hash: Option<ShellHash>,
    ) -> Option<String> {
        self.new_filter_with_id_generator(kind, current_block, current_hash, random_filter_id)
    }

    fn new_filter_with_id_generator<F>(
        &self,
        kind: FilterKind,
        current_block: u64,
        current_hash: Option<ShellHash>,
        mut next_id: F,
    ) -> Option<String>
    where
        F: FnMut() -> String,
    {
        let mut filters = self.filters.write();
        cleanup_expired_filters(&mut filters, self.ttl_secs);
        if filters.len() >= MAX_FILTERS {
            return None;
        }

        for _ in 0..MAX_FILTER_ID_GENERATION_ATTEMPTS {
            let id = next_id();
            if filters.contains_key(&id) {
                continue;
            }

            let entry = FilterEntry {
                kind,
                last_poll_block: current_block,
                last_poll_hash: current_hash,
                changes_from_block: if current_block == 0 && current_hash.is_none() {
                    Some(0)
                } else {
                    current_block.checked_add(1)
                },
                last_access: Instant::now(),
            };
            filters.insert(id.clone(), entry);
            return Some(id);
        }

        None
    }

    /// Get the filter kind and last poll block for a given filter ID.
    /// Returns `None` if the filter does not exist.
    /// Updates the last access timestamp.
    pub fn get_filter_info(&self, id: &str) -> Option<(bool, u64)> {
        self.get_filter_cursor(id)
            .map(|(is_log, cursor)| (is_log, cursor.block_number))
    }

    /// Get the filter kind and exact canonical cursor.
    /// Returns `None` if the filter does not exist.
    /// Updates the last access timestamp.
    pub fn get_filter_cursor(&self, id: &str) -> Option<(bool, FilterCursor)> {
        self.get_filter_poll_state(id)
            .map(|(is_log, cursor, _)| (is_log, cursor))
    }

    /// Get the filter kind, canonical cursor, and first reportable block.
    /// Returns `None` if the filter does not exist.
    /// Updates the last access timestamp.
    pub fn get_filter_poll_state(&self, id: &str) -> Option<(bool, FilterCursor, Option<u64>)> {
        if !is_valid_filter_id(id) {
            return None;
        }
        let mut filters = self.filters.write();
        remove_expired_filter(&mut filters, id, self.ttl_secs);
        let entry = filters.get_mut(id)?;
        entry.last_access = Instant::now();
        let is_log = matches!(entry.kind, FilterKind::Log(_));
        Some((
            is_log,
            FilterCursor {
                block_number: entry.last_poll_block,
                block_hash: entry.last_poll_hash,
            },
            entry.changes_from_block,
        ))
    }

    /// Update the last_poll_block for a filter after a successful poll.
    pub fn update_last_poll(&self, id: &str, new_block: u64) {
        if !is_valid_filter_id(id) {
            return;
        }
        let mut filters = self.filters.write();
        remove_expired_filter(&mut filters, id, self.ttl_secs);
        if let Some(entry) = filters.get_mut(id) {
            if new_block > entry.last_poll_block {
                entry.last_poll_block = new_block;
                entry.last_poll_hash = None;
            }
            entry.last_access = Instant::now();
        }
    }

    /// Replace the canonical cursor after a successful poll.
    ///
    /// Returns `false` when another poll changed the cursor or the filter
    /// expired while results were being constructed.
    pub fn update_cursor(&self, id: &str, expected: FilterCursor, cursor: FilterCursor) -> bool {
        if !is_valid_filter_id(id) {
            return false;
        }
        let mut filters = self.filters.write();
        remove_expired_filter(&mut filters, id, self.ttl_secs);
        if let Some(entry) = filters.get_mut(id) {
            if entry.last_poll_block != expected.block_number
                || entry.last_poll_hash != expected.block_hash
            {
                return false;
            }
            entry.last_poll_block = cursor.block_number;
            entry.last_poll_hash = cursor.block_hash;
            entry.last_access = Instant::now();
            return true;
        }
        false
    }

    /// Check if a filter exists and whether it is a log filter.
    /// Returns the stored `RawLogFilter` for log filters (cloned).
    pub fn get_log_filter(&self, id: &str) -> Option<RawLogFilter> {
        if !is_valid_filter_id(id) {
            return None;
        }
        let mut filters = self.filters.write();
        remove_expired_filter(&mut filters, id, self.ttl_secs);
        let entry = filters.get_mut(id)?;
        entry.last_access = Instant::now();
        match &entry.kind {
            FilterKind::Log(raw) => Some(raw.clone()),
            _ => None,
        }
    }

    /// Remove a filter. Returns `true` if an unexpired filter existed.
    pub fn uninstall(&self, id: &str) -> bool {
        if !is_valid_filter_id(id) {
            return false;
        }
        let mut filters = self.filters.write();
        remove_expired_filter(&mut filters, id, self.ttl_secs);
        filters.remove(id).is_some()
    }

    /// Remove filters that have not been accessed within the TTL window.
    pub fn cleanup_expired(&self) {
        cleanup_expired_filters(&mut self.filters.write(), self.ttl_secs);
    }

    /// Returns the number of active filters.
    pub fn len(&self) -> usize {
        self.filters.read().len()
    }

    /// Returns true if there are no active filters.
    pub fn is_empty(&self) -> bool {
        self.filters.read().is_empty()
    }

    /// Spawn a periodic cleanup task. Call this once at startup.
    pub fn start_cleanup(registry: std::sync::Arc<Self>) {
        let registry = std::sync::Arc::downgrade(&registry);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let Some(registry) = registry.upgrade() else {
                    break;
                };
                let before = registry.len();
                registry.cleanup_expired();
                let after = registry.len();
                if before > after {
                    tracing::debug!(
                        removed = before - after,
                        remaining = after,
                        "cleaned up expired filters"
                    );
                }
                drop(registry);
            }
        });
    }
}

fn cleanup_expired_filters(filters: &mut HashMap<String, FilterEntry>, ttl_secs: u64) {
    let now = Instant::now();
    let ttl = Duration::from_secs(ttl_secs);
    filters.retain(|_, entry| now.saturating_duration_since(entry.last_access) <= ttl);
}

fn remove_expired_filter(filters: &mut HashMap<String, FilterEntry>, id: &str, ttl_secs: u64) {
    let ttl = Duration::from_secs(ttl_secs);
    if filters
        .get(id)
        .is_some_and(|entry| Instant::now().saturating_duration_since(entry.last_access) > ttl)
    {
        filters.remove(id);
    }
}

fn random_filter_id() -> String {
    format!("0x{:032x}", rand::rng().random::<u128>())
}

fn is_valid_filter_id(id: &str) -> bool {
    id.len() == FILTER_ID_LEN
        && id.starts_with("0x")
        && id[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_filter_returns_hex_id() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 0).unwrap();
        assert!(id.starts_with("0x"));
    }

    #[test]
    fn new_filter_respects_max_limit() {
        let reg = FilterRegistry::new();
        for _ in 0..MAX_FILTERS {
            assert!(reg.new_filter(FilterKind::Block, 0).is_some());
        }
        // One more should fail
        assert!(reg.new_filter(FilterKind::Block, 0).is_none());
    }

    #[test]
    fn filter_ids_are_random_and_unique() {
        let reg = FilterRegistry::new();
        let id1 = reg.new_filter(FilterKind::Block, 0).unwrap();
        let id2 = reg.new_filter(FilterKind::Block, 0).unwrap();
        assert!(id1.starts_with("0x"));
        assert!(id2.starts_with("0x"));
        assert_ne!(id1, id2);
        // Random IDs should be long hex strings (0x + 32 hex chars).
        assert!(id1.len() >= 34);
    }

    #[test]
    fn new_filter_retries_colliding_ids() {
        let reg = FilterRegistry::new();
        let duplicate = reg.new_filter(FilterKind::Block, 1).unwrap();
        let unique = "0x11111111111111111111111111111111".to_string();
        let mut ids = [duplicate.clone(), unique.clone()].into_iter();

        let id = reg
            .new_filter_with_id_generator(FilterKind::Block, 2, None, || ids.next().unwrap())
            .unwrap();

        assert_eq!(id, unique);
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.get_filter_info(&duplicate).unwrap().1, 1);
        assert_eq!(reg.get_filter_info(&unique).unwrap().1, 2);
    }

    #[test]
    fn new_filter_returns_none_when_id_generation_keeps_colliding() {
        let reg = FilterRegistry::new();
        let duplicate = reg.new_filter(FilterKind::Block, 1).unwrap();

        let id = reg.new_filter_with_id_generator(FilterKind::Block, 2, None, || duplicate.clone());

        assert!(id.is_none());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get_filter_info(&duplicate).unwrap().1, 1);
    }

    #[test]
    fn new_filter_reclaims_expired_capacity_before_rejecting() {
        let reg = FilterRegistry::with_ttl(1);
        let expired_at = Instant::now() - std::time::Duration::from_secs(2);
        {
            let mut filters = reg.filters.write();
            for i in 0..MAX_FILTERS {
                filters.insert(
                    format!("0x{i:032x}"),
                    FilterEntry {
                        kind: FilterKind::Block,
                        last_poll_block: i as u64,
                        last_poll_hash: None,
                        changes_from_block: (i as u64).checked_add(1),
                        last_access: expired_at,
                    },
                );
            }
        }

        let id = reg.new_filter(FilterKind::Block, 99).unwrap();

        assert_eq!(reg.len(), 1);
        assert_eq!(reg.get_filter_info(&id).unwrap().1, 99);
    }

    #[test]
    fn uninstall_existing_filter() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 10).unwrap();
        assert!(reg.uninstall(&id));
        assert!(!reg.uninstall(&id)); // already removed
    }

    #[test]
    fn get_filter_info_returns_correct_data() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 42).unwrap();
        let (is_log, last_poll) = reg.get_filter_info(&id).unwrap();
        assert!(!is_log);
        assert_eq!(last_poll, 42);
    }

    #[test]
    fn get_filter_info_for_log_filter() {
        let raw: RawLogFilter = serde_json::from_str(r#"{}"#).unwrap();
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Log(raw), 5).unwrap();
        let (is_log, last_poll) = reg.get_filter_info(&id).unwrap();
        assert!(is_log);
        assert_eq!(last_poll, 5);
    }

    #[test]
    fn poll_state_tracks_the_first_post_install_block() {
        let reg = FilterRegistry::new();
        let head_hash = ShellHash::from_slice(&[0x10; 32]);
        let at_head = reg
            .new_filter_at(FilterKind::Block, 5, Some(head_hash))
            .unwrap();
        let before_genesis = reg.new_filter(FilterKind::Block, 0).unwrap();
        let at_max = reg.new_filter(FilterKind::Block, u64::MAX).unwrap();

        assert_eq!(reg.get_filter_poll_state(&at_head).unwrap().2, Some(6));
        assert_eq!(
            reg.get_filter_poll_state(&before_genesis).unwrap().2,
            Some(0)
        );
        assert_eq!(reg.get_filter_poll_state(&at_max).unwrap().2, None);
    }

    #[test]
    fn get_filter_info_nonexistent() {
        let reg = FilterRegistry::new();
        assert!(reg.get_filter_info("0x999").is_none());
    }

    #[test]
    fn malformed_filter_ids_are_rejected_before_lookup() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 42).unwrap();

        assert!(reg.get_filter_info(&"x".repeat(1024 * 1024)).is_none());
        assert!(reg
            .get_filter_info("0xgggggggggggggggggggggggggggggggg")
            .is_none());
        assert!(!reg.uninstall("0x1"));
        assert_eq!(reg.get_filter_info(&id).unwrap().1, 42);
    }

    #[test]
    fn update_last_poll_advances_block() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 0).unwrap();
        reg.update_last_poll(&id, 50);
        let (_, last_poll) = reg.get_filter_info(&id).unwrap();
        assert_eq!(last_poll, 50);
    }

    #[test]
    fn update_last_poll_does_not_move_cursor_backwards() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 10).unwrap();

        reg.update_last_poll(&id, 20);
        reg.update_last_poll(&id, 15);

        assert_eq!(reg.get_filter_info(&id).unwrap().1, 20);
    }

    #[test]
    fn exact_cursor_tracks_hash_and_can_move_to_reorg_ancestor() {
        let reg = FilterRegistry::new();
        let old_hash = ShellHash::from_slice(&[0x11; 32]);
        let ancestor_hash = ShellHash::from_slice(&[0x22; 32]);
        let id = reg
            .new_filter_at(FilterKind::Block, 20, Some(old_hash))
            .unwrap();

        assert_eq!(
            reg.get_filter_cursor(&id).unwrap().1,
            FilterCursor {
                block_number: 20,
                block_hash: Some(old_hash),
            }
        );

        assert!(reg.update_cursor(
            &id,
            FilterCursor {
                block_number: 20,
                block_hash: Some(old_hash),
            },
            FilterCursor {
                block_number: 15,
                block_hash: Some(ancestor_hash),
            },
        ));

        assert_eq!(
            reg.get_filter_cursor(&id).unwrap().1,
            FilterCursor {
                block_number: 15,
                block_hash: Some(ancestor_hash),
            }
        );
    }

    #[test]
    fn number_only_cursor_update_clears_stale_hash() {
        let reg = FilterRegistry::new();
        let old_hash = ShellHash::from_slice(&[0x33; 32]);
        let id = reg
            .new_filter_at(FilterKind::Block, 7, Some(old_hash))
            .unwrap();

        reg.update_last_poll(&id, 8);

        assert_eq!(
            reg.get_filter_cursor(&id).unwrap().1,
            FilterCursor {
                block_number: 8,
                block_hash: None,
            }
        );
    }

    #[test]
    fn exact_cursor_update_rejects_stale_poll() {
        let reg = FilterRegistry::new();
        let hash = ShellHash::from_slice(&[0x44; 32]);
        let id = reg.new_filter_at(FilterKind::Block, 7, Some(hash)).unwrap();

        assert!(!reg.update_cursor(
            &id,
            FilterCursor {
                block_number: 6,
                block_hash: Some(hash),
            },
            FilterCursor {
                block_number: 8,
                block_hash: Some(ShellHash::from_slice(&[0x55; 32])),
            },
        ));
        assert_eq!(
            reg.get_filter_cursor(&id).unwrap().1,
            FilterCursor {
                block_number: 7,
                block_hash: Some(hash),
            }
        );
    }

    #[test]
    fn update_last_poll_does_not_revive_expired_filter() {
        let reg = FilterRegistry::with_ttl(1);
        let id = reg.new_filter(FilterKind::Block, 7).unwrap();
        reg.filters.write().get_mut(&id).unwrap().last_access =
            Instant::now() - Duration::from_secs(2);

        reg.update_last_poll(&id, 8);

        assert!(reg.get_filter_info(&id).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn get_log_filter_returns_raw_for_log_kind() {
        let raw: RawLogFilter =
            serde_json::from_str(r#"{"fromBlock":"0x1","toBlock":"0x5"}"#).unwrap();
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Log(raw), 1).unwrap();
        let retrieved = reg.get_log_filter(&id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn get_log_filter_returns_none_for_block_kind() {
        let reg = FilterRegistry::new();
        let id = reg.new_filter(FilterKind::Block, 0).unwrap();
        assert!(reg.get_log_filter(&id).is_none());
    }

    #[test]
    fn cleanup_removes_expired_filters() {
        let reg = FilterRegistry::with_ttl(1);
        let id = reg.new_filter(FilterKind::Block, 0).unwrap();
        reg.filters.write().get_mut(&id).unwrap().last_access =
            Instant::now() - Duration::from_secs(2);
        reg.cleanup_expired();
        assert_eq!(reg.len(), 0);
        assert!(!reg.uninstall(&id));
    }

    #[test]
    fn uninstall_expired_filter_returns_false_without_prior_cleanup() {
        let reg = FilterRegistry::with_ttl(1);
        let id = reg.new_filter(FilterKind::Block, 0).unwrap();
        reg.filters.write().get_mut(&id).unwrap().last_access =
            Instant::now() - Duration::from_secs(2);

        assert!(!reg.uninstall(&id));
        assert!(reg.is_empty());
    }

    #[test]
    fn cleanup_keeps_fresh_filters() {
        let reg = FilterRegistry::new(); // default 300s TTL
        let _id = reg.new_filter(FilterKind::Block, 0).unwrap();
        reg.cleanup_expired();
        assert_eq!(reg.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_task_does_not_retain_dropped_registry() {
        let reg = std::sync::Arc::new(FilterRegistry::new());
        let weak = std::sync::Arc::downgrade(&reg);
        FilterRegistry::start_cleanup(std::sync::Arc::clone(&reg));

        drop(reg);
        tokio::task::yield_now().await;

        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn cleanup_with_large_ttl_retains_recent_filters() {
        let reg = FilterRegistry::with_ttl(u64::MAX);
        let _id = reg.new_filter(FilterKind::Block, 0).unwrap();
        reg.cleanup_expired();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn cleanup_tolerates_future_last_access() {
        let reg = FilterRegistry::with_ttl(0);
        let id = "0x11111111111111111111111111111111".to_string();
        reg.filters.write().insert(
            id.clone(),
            FilterEntry {
                kind: FilterKind::Block,
                last_poll_block: 0,
                last_poll_hash: None,
                changes_from_block: Some(0),
                last_access: Instant::now() + std::time::Duration::from_secs(60),
            },
        );

        reg.cleanup_expired();

        assert!(reg.uninstall(&id));
    }

    #[test]
    fn get_filter_info_does_not_revive_expired_filter() {
        let reg = FilterRegistry::with_ttl(1);
        let id = reg.new_filter(FilterKind::Block, 7).unwrap();
        reg.filters.write().get_mut(&id).unwrap().last_access =
            Instant::now() - Duration::from_secs(2);

        assert!(reg.get_filter_info(&id).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn get_log_filter_does_not_revive_expired_filter() {
        let reg = FilterRegistry::with_ttl(1);
        let raw: RawLogFilter = serde_json::from_str(r#"{}"#).unwrap();
        let id = reg.new_filter(FilterKind::Log(raw), 7).unwrap();
        reg.filters.write().get_mut(&id).unwrap().last_access =
            Instant::now() - Duration::from_secs(2);

        assert!(reg.get_log_filter(&id).is_none());
        assert!(reg.is_empty());
    }
}
