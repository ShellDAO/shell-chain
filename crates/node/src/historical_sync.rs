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

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use shell_network::{NetworkMessage, PeerId};
use shell_storage::{ChainStore, KvStore};

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
        match self.profile.as_str() {
            "archive" => 3,
            "full" => 2,
            "light" => 1,
            _ => 0,
        }
    }
}

/// Thread-safe registry of peer storage capabilities.
#[derive(Debug, Default, Clone)]
pub struct PeerCapabilityTracker {
    inner: Arc<Mutex<HashMap<PeerId, PeerCapability>>>,
}

impl PeerCapabilityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record or update a peer's capability.
    pub fn record(&self, peer: PeerId, profile: String, oldest_body_block: u64) {
        self.inner.lock().insert(
            peer,
            PeerCapability {
                profile,
                oldest_body_block,
            },
        );
    }

    /// Remove a peer (on disconnect).
    pub fn remove(&self, peer: &PeerId) {
        self.inner.lock().remove(peer);
    }

    /// Return the best peer for back-filling bodies starting at `from_block`.
    ///
    /// Prefers archive > full > light and, within the same profile, the peer
    /// with the lowest `oldest_body_block` (most history available).
    pub fn best_peer_for_block(&self, from_block: u64) -> Option<PeerId> {
        let guard = self.inner.lock();
        guard
            .iter()
            .filter(|(_, cap)| cap.oldest_body_block <= from_block)
            .max_by_key(|(_, cap)| (cap.richness(), u64::MAX - cap.oldest_body_block))
            .map(|(id, _)| id.clone())
    }
}

/// How many blocks to request in a single `BodyRequest`.
const BATCH_SIZE: u64 = 128;

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
        let first_missing = self.first_missing_body(head_number);
        if first_missing.is_none() {
            return SyncStatus::Complete;
        }
        let start = first_missing.unwrap();

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
                        count: BATCH_SIZE,
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
    pub fn handle_response(
        &self,
        peer: PeerId,
        blocks: Vec<shell_core::Block>,
        head_number: u64,
    ) {
        let mut last_stored: Option<u64> = None;
        for block in &blocks {
            let n = block.header.number;
            if let Err(e) = self.chain_store.put_body_only(block) {
                warn!(block = n, error = %e, "historical sync: failed to store body");
            } else {
                last_stored = Some(n);
            }
        }

        if let Some(last) = last_stored {
            let next_start = last + 1;
            if next_start <= head_number {
                // Check if there are still missing bodies ahead.
                if self.first_missing_body_in_range(next_start, head_number).is_some() {
                    info!(next_start, "historical sync: requesting next batch");
                    (self.send_fn)(
                        peer,
                        NetworkMessage::BodyRequest {
                            start_number: next_start,
                            count: BATCH_SIZE,
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
            if !self.chain_store.has_body(&hash).unwrap_or(true) {
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
                    .map(|h| !self.chain_store.has_body(&h).unwrap_or(true))
                    .unwrap_or(false)
            })
            .count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn tracker_remove_peer() {
        let tracker = PeerCapabilityTracker::new();
        tracker.record(PeerId("a".into()), "full".into(), 0);
        tracker.remove(&PeerId("a".into()));
        assert!(tracker.best_peer_for_block(0).is_none());
    }
}
