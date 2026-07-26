//! Historical body back-fill — re-download pruned TX bodies from richer peers.
//!
//! When a node's `--storage-profile` is upgraded (e.g. `light → full`), blocks
//! that were pruned in the past no longer have a `b/<hash>` entry.  This module
//! detects those gaps on startup and fills them in by issuing `BodyRequest`
//! messages to peers that advertise a more complete storage profile.
//!
//! # Design
//!
//! ```text
//!  Node startup
//!      │
//!      ├─ PeerCapabilityTracker::record(peer, profile, oldest)
//!      │      (populated when StorageCapability messages arrive)
//!      │
//!      └─ HistoricalBodySync::run()
//!             │
//!             ├─ scan chain_store: find lowest block with missing body
//!             ├─ pick best peer (archive > full, lowest oldest_body_block)
//!             ├─ loop: send BodyRequest(start, 128) → receive BodyResponse
//!             │         → store_body(block) for each returned block
//!             └─ log "historical sync complete" when caught up
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use shell_network::{NetworkMessage, PeerId};
use shell_storage::{BlockAvailability, ChainStore, KvStore};

pub(crate) const MAX_PEER_CAPABILITY_RECORDS: usize = 16_384;

/// Capability metadata received from a remote peer.
#[derive(Debug, Clone)]
pub struct PeerCapability {
    /// Profile name as reported by the peer ("archive", "full", or "light").
    pub profile: String,
    /// Lowest block number the peer can serve bodies for.
    pub oldest_body_block: u64,
}

impl PeerCapability {
    /// Returns a numeric "richness" score (higher = preferred for sync).
    fn richness(&self) -> u8 {
        match self.profile.to_ascii_lowercase().as_str() {
            "archive" => 3,
            "full" => 2,
            "light" | "pruned" | "rolling" => 1,
            _ => 0,
        }
    }
}

/// Thread-safe registry of peer storage capabilities.
#[derive(Debug)]
struct PeerCapabilityRecord {
    capability: PeerCapability,
    update_sequence: u64,
}

#[derive(Debug, Default)]
struct PeerCapabilityState {
    records: HashMap<PeerId, PeerCapabilityRecord>,
    update_order: BTreeMap<u64, PeerId>,
    next_sequence: u64,
}

#[derive(Debug, Clone)]
pub struct PeerCapabilityTracker {
    inner: Arc<Mutex<PeerCapabilityState>>,
    max_records: usize,
}

impl Default for PeerCapabilityTracker {
    fn default() -> Self {
        Self::with_max_records(MAX_PEER_CAPABILITY_RECORDS)
    }
}

impl PeerCapabilityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_max_records(max_records: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PeerCapabilityState::default())),
            max_records: max_records.max(1),
        }
    }

    /// Record or update a peer's capability.
    pub fn record(&self, peer: PeerId, profile: String, oldest_body_block: u64) {
        let mut state = self.inner.lock();
        if !state.records.contains_key(&peer) && state.records.len() >= self.max_records {
            if let Some((_, oldest)) = state.update_order.pop_first() {
                state.records.remove(&oldest);
            }
        }
        let update_sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        if let Some(previous_sequence) = state
            .records
            .get(&peer)
            .map(|record| record.update_sequence)
        {
            state.update_order.remove(&previous_sequence);
        }
        state.update_order.insert(update_sequence, peer.clone());
        state.records.insert(
            peer,
            PeerCapabilityRecord {
                capability: PeerCapability {
                    profile,
                    oldest_body_block,
                },
                update_sequence,
            },
        );
    }

    /// Remove a peer (on disconnect).
    pub fn remove(&self, peer: &PeerId) {
        let mut state = self.inner.lock();
        if let Some(record) = state.records.remove(peer) {
            state.update_order.remove(&record.update_sequence);
        }
    }

    /// Return the best peer for back-filling bodies starting at `from_block`.
    ///
    /// Prefers archive > full > light and, within the same profile, the peer
    /// with the lowest `oldest_body_block` (most history available).
    pub fn best_peer_for_block(&self, from_block: u64) -> Option<PeerId> {
        let guard = self.inner.lock();
        guard
            .records
            .iter()
            .filter(|(_, record)| {
                record.capability.richness() > 0
                    && record.capability.oldest_body_block <= from_block
            })
            .max_by_key(|(_, record)| {
                (
                    record.capability.richness(),
                    u64::MAX - record.capability.oldest_body_block,
                )
            })
            .map(|(id, _)| id.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().records.len()
    }

    #[cfg(test)]
    fn update_order_len(&self) -> usize {
        self.inner.lock().update_order.len()
    }
}

/// How many blocks to request in a single `BodyRequest`.
pub(crate) const BODY_BACKFILL_BATCH_SIZE: u64 = 128;

/// Result of a single back-fill scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// No missing bodies were found; nothing to do.
    Complete,
    /// Back-fill started; `gaps_found` is the number of missing entries detected.
    Started { gaps_found: u64 },
    /// No suitable peer was available to serve the missing data.
    NoPeer { oldest_missing: u64 },
}

/// Historical body sync task.
///
/// Call [`HistoricalBodySync::run`] once after the node starts and peers have
/// had a moment to advertise their capabilities.
pub struct HistoricalBodySync<S: KvStore> {
    pub chain_store: Arc<ChainStore<S>>,
    pub peers: PeerCapabilityTracker,
    /// Send a `NetworkMessage` to a specific peer.
    pub send_fn: Arc<dyn Fn(PeerId, NetworkMessage) + Send + Sync + 'static>,
}

impl<S: KvStore + 'static> HistoricalBodySync<S> {
    /// Scan for body gaps and kick off back-fill if needed.
    ///
    /// Returns immediately after dispatching requests; actual body storage
    /// happens as `BodyResponse` messages arrive and are processed by the node
    /// event loop.
    pub fn run(&self) -> SyncStatus {
        let head = match self.chain_store.get_head_hash() {
            Ok(Some(h)) => h,
            _ => return SyncStatus::Complete,
        };

        let head_number = match self.chain_store.get_header_by_hash(&head) {
            Ok(Some(hdr)) => hdr.number,
            _ => return SyncStatus::Complete,
        };

        // Find the first missing body working forward from block 0.
        let Some(start) = self.first_missing_body(head_number) else {
            return SyncStatus::Complete;
        };

        // Count total gaps (approximate — just for logging).
        let gaps_found = self.count_missing_bodies(start, head_number);

        match self.peers.best_peer_for_block(start) {
            None => {
                warn!(
                    oldest_missing = start,
                    "historical sync: no peer available to serve body data"
                );
                SyncStatus::NoPeer {
                    oldest_missing: start,
                }
            }
            Some(peer) => {
                info!(
                    start,
                    gaps_found,
                    peer = %peer,
                    "historical sync: requesting missing bodies"
                );
                (self.send_fn)(
                    peer,
                    NetworkMessage::BodyRequest {
                        start_number: start,
                        count: BODY_BACKFILL_BATCH_SIZE,
                        nonce: 0,
                    },
                );
                SyncStatus::Started { gaps_found }
            }
        }
    }

    /// Continue back-fill after a `BodyResponse` was received.
    ///
    /// Stores each returned block's body and, if the range is not yet complete,
    /// issues the next `BodyRequest` batch.
    pub fn handle_response(&self, peer: PeerId, blocks: Vec<shell_core::Block>, head_number: u64) {
        let batch_start = blocks.first().map(|block| block.header.number);
        let mut first_gap: Option<u64> = None;
        let mut last_stored: Option<u64> = None;
        let mut expected_next = batch_start;
        for block in &blocks {
            let n = block.header.number;
            if let Some(expected) = expected_next {
                if n > expected {
                    first_gap.get_or_insert(expected);
                }
                if n >= expected {
                    expected_next = n.checked_add(1);
                }
            }

            let expected_hash = self.chain_store.get_block_hash_by_number(n).ok().flatten();
            let actual_hash = block.hash();
            if expected_hash.as_ref() != Some(&actual_hash) {
                warn!(
                    block = n,
                    "historical sync: BodyResponse hash mismatch, skipping body"
                );
                first_gap.get_or_insert(n);
                continue;
            }
            if self.chain_store.has_body(&actual_hash).unwrap_or(false) {
                last_stored = Some(n);
                continue;
            }
            if let Err(e) = self.chain_store.put_body_only(block) {
                warn!(block = n, error = %e, "historical sync: failed to store body");
                first_gap.get_or_insert(n);
            } else {
                last_stored = Some(n);
            }
        }

        let scan_start = first_gap
            .or_else(|| last_stored.and_then(|last| last.checked_add(1)))
            .or_else(|| batch_start.and_then(|start| start.checked_add(BODY_BACKFILL_BATCH_SIZE)));
        if let Some(scan_start) = scan_start {
            if scan_start <= head_number {
                if let Some(next_start) = self.first_missing_body_in_range(scan_start, head_number)
                {
                    info!(next_start, "historical sync: requesting next batch");
                    (self.send_fn)(
                        peer,
                        NetworkMessage::BodyRequest {
                            start_number: next_start,
                            count: BODY_BACKFILL_BATCH_SIZE,
                            nonce: 0,
                        },
                    );
                    return;
                }
            }
            info!("historical sync: back-fill complete");
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn first_missing_body(&self, head_number: u64) -> Option<u64> {
        self.first_missing_body_in_range(0, head_number)
    }

    fn first_missing_body_in_range(&self, from: u64, to: u64) -> Option<u64> {
        for n in from..=to {
            let hash = match self.chain_store.get_block_hash_by_number(n) {
                Ok(Some(h)) => h,
                _ => continue,
            };
            let availability = self
                .chain_store
                .block_availability(&hash)
                .unwrap_or(BlockAvailability::BodyOnly);
            if matches!(
                availability,
                BlockAvailability::Missing | BlockAvailability::HeaderOnly
            ) {
                return Some(n);
            }
        }
        None
    }

    fn count_missing_bodies(&self, from: u64, to: u64) -> u64 {
        (from..=to)
            .filter(|&n| {
                self.chain_store
                    .get_block_hash_by_number(n)
                    .ok()
                    .flatten()
                    .map(|h| {
                        matches!(
                            self.chain_store
                                .block_availability(&h)
                                .unwrap_or(BlockAvailability::BodyOnly),
                            BlockAvailability::Missing | BlockAvailability::HeaderOnly
                        )
                    })
                    .unwrap_or(false)
            })
            .count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use shell_core::{Block, BlockHeader};
    use shell_storage::MemoryDb;

    #[test]
    fn peer_capability_richness_ordering() {
        let archive = PeerCapability {
            profile: "archive".into(),
            oldest_body_block: 0,
        };
        let full = PeerCapability {
            profile: "full".into(),
            oldest_body_block: 0,
        };
        let light = PeerCapability {
            profile: "light".into(),
            oldest_body_block: 0,
        };
        assert!(archive.richness() > full.richness());
        assert!(full.richness() > light.richness());
    }

    #[test]
    fn tracker_best_peer_prefers_archive() {
        let tracker = PeerCapabilityTracker::new();
        tracker.record(PeerId("a".into()), "archive".into(), 0);
        tracker.record(PeerId("b".into()), "full".into(), 0);

        let best = tracker.best_peer_for_block(100).unwrap();
        assert_eq!(best, PeerId("a".into()));
    }

    #[test]
    fn tracker_filters_peers_that_cant_serve() {
        let tracker = PeerCapabilityTracker::new();
        // peer "a" only has data from block 500 onwards
        tracker.record(PeerId("a".into()), "archive".into(), 500);
        tracker.record(PeerId("b".into()), "full".into(), 0);

        // For block 100, only "b" qualifies
        let best = tracker.best_peer_for_block(100).unwrap();
        assert_eq!(best, PeerId("b".into()));

        // For block 600, "a" (archive) is richer
        let best = tracker.best_peer_for_block(600).unwrap();
        assert_eq!(best, PeerId("a".into()));
    }

    #[test]
    fn tracker_treats_pruned_aliases_as_light_profile() {
        let pruned = PeerCapability {
            profile: "pruned".into(),
            oldest_body_block: 0,
        };
        let rolling = PeerCapability {
            profile: "Rolling".into(),
            oldest_body_block: 0,
        };
        let light = PeerCapability {
            profile: "light".into(),
            oldest_body_block: 0,
        };

        assert_eq!(pruned.richness(), light.richness());
        assert_eq!(rolling.richness(), light.richness());
    }

    #[test]
    fn tracker_ignores_unknown_storage_profiles() {
        let tracker = PeerCapabilityTracker::new();
        tracker.record(PeerId("unknown".into()), "untrusted-profile".into(), 0);

        assert!(tracker.best_peer_for_block(100).is_none());

        tracker.record(PeerId("full".into()), "full".into(), 0);
        assert_eq!(
            tracker.best_peer_for_block(100),
            Some(PeerId("full".into()))
        );
    }

    #[test]
    fn tracker_remove_peer() {
        let tracker = PeerCapabilityTracker::new();
        tracker.record(PeerId("a".into()), "full".into(), 0);
        tracker.remove(&PeerId("a".into()));
        assert!(tracker.best_peer_for_block(0).is_none());
        assert_eq!(tracker.update_order_len(), 0);
    }

    #[test]
    fn tracker_capacity_evicts_oldest_record() {
        let tracker = PeerCapabilityTracker::with_max_records(2);
        tracker.record(PeerId("oldest".into()), "archive".into(), 0);
        tracker.record(PeerId("newer".into()), "full".into(), 0);
        tracker.record(PeerId("newest".into()), "light".into(), 0);

        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.update_order_len(), 2);
        assert_eq!(tracker.best_peer_for_block(0), Some(PeerId("newer".into())));
    }

    #[test]
    fn tracker_update_refreshes_eviction_order() {
        let tracker = PeerCapabilityTracker::with_max_records(2);
        tracker.record(PeerId("refreshed".into()), "full".into(), 0);
        tracker.record(PeerId("stale".into()), "archive".into(), 0);
        tracker.record(PeerId("refreshed".into()), "archive".into(), 0);
        tracker.record(PeerId("new".into()), "light".into(), 0);

        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.update_order_len(), 2);
        assert_eq!(
            tracker.best_peer_for_block(0),
            Some(PeerId("refreshed".into()))
        );
    }

    #[test]
    fn tracker_updates_keep_eviction_index_bounded() {
        let tracker = PeerCapabilityTracker::with_max_records(2);
        for oldest_body_block in 0..100 {
            tracker.record(
                PeerId("repeated".into()),
                "archive".into(),
                oldest_body_block,
            );
        }

        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.update_order_len(), 1);
    }

    fn numbered_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                number,
                ..BlockHeader::default()
            },
            transactions: Vec::new(),
            system_transactions: Vec::new(),
            proposer_seal: None,
        }
    }

    fn store_canonical_block(chain_store: &ChainStore<MemoryDb>, number: u64) -> Block {
        let block = numbered_block(number);
        let hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_canonical(number, &hash).unwrap();
        block
    }

    #[test]
    fn handle_response_does_not_request_past_max_block() {
        let chain_store = Arc::new(ChainStore::new(Arc::new(MemoryDb::new())));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_messages = Arc::clone(&sent);
        let sync = HistoricalBodySync {
            chain_store,
            peers: PeerCapabilityTracker::new(),
            send_fn: Arc::new(move |_peer, msg| sent_messages.lock().push(msg)),
        };
        let block = Block {
            header: BlockHeader {
                number: u64::MAX,
                ..BlockHeader::default()
            },
            transactions: Vec::new(),
            system_transactions: Vec::new(),
            proposer_seal: None,
        };

        sync.handle_response(PeerId("peer".into()), vec![block], u64::MAX);

        assert!(sent.lock().is_empty());
    }

    #[test]
    fn handle_response_re_requests_first_omitted_body() {
        let chain_store = Arc::new(ChainStore::new(Arc::new(MemoryDb::new())));
        let block0 = store_canonical_block(&chain_store, 0);
        let block1 = store_canonical_block(&chain_store, 1);
        let block2 = store_canonical_block(&chain_store, 2);
        chain_store.delete_body(&block1.hash()).unwrap();
        chain_store.delete_body(&block2.hash()).unwrap();

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_messages = Arc::clone(&sent);
        let sync = HistoricalBodySync {
            chain_store,
            peers: PeerCapabilityTracker::new(),
            send_fn: Arc::new(move |_peer, msg| sent_messages.lock().push(msg)),
        };

        sync.handle_response(PeerId("peer".into()), vec![block0, block2], 2);

        let sent = sent.lock();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            NetworkMessage::BodyRequest {
                start_number,
                count,
                ..
            } => {
                assert_eq!(*start_number, 1);
                assert_eq!(*count, BODY_BACKFILL_BATCH_SIZE);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
