//! Network security primitives: peer tracking, reputation, and banning.
//!
//! Implements findings F-069 (message size validation), F-070 (peer connection
//! limits), and F-071 (peer reputation and temporary banning).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::NetworkError;
use crate::message::PeerId;

const MAX_TEMP_BAN_DURATION: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

// ---------------------------------------------------------------------------
// F-070: Peer connection tracker
// ---------------------------------------------------------------------------

/// Tracks active peer connections and enforces a configurable upper bound.
#[derive(Debug)]
pub struct PeerTracker {
    max_peers: usize,
    peers: HashMap<PeerId, Instant>,
}

impl PeerTracker {
    /// Create a tracker with the given maximum peer limit.
    /// A `max_peers` of 0 means **unlimited**.
    pub fn new(max_peers: usize) -> Self {
        Self {
            max_peers,
            peers: HashMap::new(),
        }
    }

    /// Try to register a new peer connection.
    ///
    /// Returns `Ok(())` if the peer was added, or
    /// `Err(NetworkError::ConnectionLimitReached)` if the limit is hit.
    pub fn try_add_peer(&mut self, peer: PeerId) -> Result<(), NetworkError> {
        // Already tracked — allow (reconnect / duplicate event).
        if self.peers.contains_key(&peer) {
            return Ok(());
        }
        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            return Err(NetworkError::ConnectionLimitReached {
                current: self.peers.len(),
                max: self.max_peers,
            });
        }
        self.peers.insert(peer, Instant::now());
        Ok(())
    }

    /// Remove a peer when it disconnects.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// Number of currently tracked peers.
    pub fn active_count(&self) -> usize {
        self.peers.len()
    }

    /// Maximum allowed peers (0 = unlimited).
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Returns `true` if we are at or over the peer limit.
    pub fn is_full(&self) -> bool {
        self.max_peers > 0 && self.peers.len() >= self.max_peers
    }
}

// ---------------------------------------------------------------------------
// F-071: Peer reputation and banning
// ---------------------------------------------------------------------------

/// Entry tracking a single peer's violation history.
#[derive(Debug, Clone)]
struct PeerRecord {
    /// Cumulative violation count.
    violations: u32,
    /// If banned, the instant at which the ban expires.
    banned_until: Option<Instant>,
}

/// Manages peer reputation and temporary bans.
///
/// When a peer accumulates `ban_threshold` violations it is banned for
/// `ban_duration`. A threshold of 0 disables temporary bans. Bans are
/// time-limited and automatically expire.
#[derive(Debug)]
pub struct PeerBanList {
    records: HashMap<String, PeerRecord>,
    ban_threshold: u32,
    ban_duration: Duration,
}

impl PeerBanList {
    /// Create a new ban list.
    ///
    /// * `ban_threshold` — violations before a temporary ban is imposed (0 = disabled).
    /// * `ban_duration` — how long a ban lasts.
    pub fn new(ban_threshold: u32, ban_duration: Duration) -> Self {
        Self {
            records: HashMap::new(),
            ban_threshold,
            ban_duration,
        }
    }

    /// Record a violation for `peer`. Returns `true` if the peer is now
    /// banned as a result of this violation.
    pub fn record_violation(&mut self, peer: &PeerId) -> bool {
        let key = peer.0.clone();
        let record = self.records.entry(key).or_insert(PeerRecord {
            violations: 0,
            banned_until: None,
        });

        record.violations = record.violations.saturating_add(1);

        if self.ban_threshold > 0
            && record.violations >= self.ban_threshold
            && record.banned_until.is_none()
        {
            record.banned_until = Some(ban_deadline(Instant::now(), self.ban_duration));
            return true;
        }
        false
    }

    /// Check whether `peer` is currently banned.
    ///
    /// Expired bans are cleared automatically.
    pub fn is_banned(&mut self, peer: &PeerId) -> bool {
        let key = peer.0.as_str();
        if let Some(record) = self.records.get_mut(key) {
            if let Some(until) = record.banned_until {
                if Instant::now() >= until {
                    // Ban expired — clear it and reset violations.
                    record.banned_until = None;
                    record.violations = 0;
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Return an error if the peer is banned, otherwise `Ok(())`.
    pub fn check_peer(&mut self, peer: &PeerId) -> Result<(), NetworkError> {
        if self.is_banned(peer) {
            let remaining = self.remaining_ban_secs(peer);
            return Err(NetworkError::PeerBanned {
                peer: peer.0.clone(),
                until_secs: remaining,
            });
        }
        Ok(())
    }

    /// Remaining ban time in seconds (0 if not banned).
    pub fn remaining_ban_secs(&self, peer: &PeerId) -> u64 {
        self.records
            .get(peer.0.as_str())
            .and_then(|r| r.banned_until)
            .map(|until| {
                let now = Instant::now();
                if until > now {
                    (until - now).as_secs()
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    /// Number of violations recorded for `peer`.
    pub fn violations(&self, peer: &PeerId) -> u32 {
        self.records
            .get(peer.0.as_str())
            .map(|r| r.violations)
            .unwrap_or(0)
    }

    /// Remove all expired bans, reclaiming memory.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.records
            .retain(|_, r| !matches!(r.banned_until, Some(until) if now >= until));
    }

    /// Total number of peers currently tracked (with or without active ban).
    pub fn tracked_count(&self) -> usize {
        self.records.len()
    }

    /// Number of peers with an active (non-expired) ban.
    pub fn banned_count(&self) -> usize {
        let now = Instant::now();
        self.records
            .values()
            .filter(|r| r.banned_until.is_some_and(|until| now < until))
            .count()
    }
}

fn ban_deadline(now: Instant, duration: Duration) -> Instant {
    let duration = duration.min(MAX_TEMP_BAN_DURATION);
    if let Some(deadline) = now.checked_add(duration) {
        return deadline;
    }

    let mut capped = duration;
    while !capped.is_zero() {
        capped /= 2;
        if let Some(deadline) = now.checked_add(capped) {
            return deadline;
        }
    }

    now
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ---- PeerTracker (F-070) ----

    #[test]
    fn tracker_accepts_peers_under_limit() {
        let mut tracker = PeerTracker::new(3);
        assert!(tracker.try_add_peer(PeerId::from("a")).is_ok());
        assert!(tracker.try_add_peer(PeerId::from("b")).is_ok());
        assert!(tracker.try_add_peer(PeerId::from("c")).is_ok());
        assert_eq!(tracker.active_count(), 3);
    }

    #[test]
    fn tracker_rejects_over_limit() {
        let mut tracker = PeerTracker::new(2);
        tracker.try_add_peer(PeerId::from("a")).unwrap();
        tracker.try_add_peer(PeerId::from("b")).unwrap();
        let err = tracker.try_add_peer(PeerId::from("c"));
        assert!(err.is_err());
        match err.unwrap_err() {
            NetworkError::ConnectionLimitReached { current, max } => {
                assert_eq!(current, 2);
                assert_eq!(max, 2);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn tracker_allows_duplicate_peer() {
        let mut tracker = PeerTracker::new(1);
        tracker.try_add_peer(PeerId::from("a")).unwrap();
        // Same peer again should succeed.
        assert!(tracker.try_add_peer(PeerId::from("a")).is_ok());
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn tracker_remove_frees_slot() {
        let mut tracker = PeerTracker::new(1);
        tracker.try_add_peer(PeerId::from("a")).unwrap();
        assert!(tracker.is_full());
        tracker.remove_peer(&PeerId::from("a"));
        assert!(!tracker.is_full());
        assert!(tracker.try_add_peer(PeerId::from("b")).is_ok());
    }

    #[test]
    fn tracker_unlimited_when_zero() {
        let mut tracker = PeerTracker::new(0);
        for i in 0..1000 {
            assert!(tracker.try_add_peer(PeerId::from(format!("p{i}"))).is_ok());
        }
        assert_eq!(tracker.active_count(), 1000);
        assert!(!tracker.is_full());
    }

    // ---- PeerBanList (F-071) ----

    #[test]
    fn ban_after_threshold() {
        let mut bans = PeerBanList::new(3, Duration::from_secs(60));
        let peer = PeerId::from("bad-peer");

        assert!(!bans.record_violation(&peer)); // 1
        assert!(!bans.record_violation(&peer)); // 2
        assert!(bans.record_violation(&peer)); // 3 → banned
        assert!(bans.is_banned(&peer));
    }

    #[test]
    fn not_banned_below_threshold() {
        let mut bans = PeerBanList::new(5, Duration::from_secs(60));
        let peer = PeerId::from("mild-peer");

        bans.record_violation(&peer);
        bans.record_violation(&peer);
        assert!(!bans.is_banned(&peer));
        assert_eq!(bans.violations(&peer), 2);
    }

    #[test]
    fn zero_threshold_disables_bans() {
        let mut bans = PeerBanList::new(0, Duration::from_secs(60));
        let peer = PeerId::from("disabled-ban");

        assert!(!bans.record_violation(&peer));
        assert!(!bans.record_violation(&peer));
        assert!(!bans.is_banned(&peer));
        assert_eq!(bans.violations(&peer), 2);
        assert_eq!(bans.banned_count(), 0);
    }

    #[test]
    fn ban_expires() {
        let mut bans = PeerBanList::new(1, Duration::from_millis(0));
        let peer = PeerId::from("temp-ban");

        assert!(bans.record_violation(&peer)); // immediately banned
                                               // With 0ms duration, the ban should already be expired.
        std::thread::sleep(Duration::from_millis(1));
        assert!(!bans.is_banned(&peer));
        // Violations reset after expiry.
        assert_eq!(bans.violations(&peer), 0);
    }

    #[test]
    fn check_peer_returns_error_when_banned() {
        let mut bans = PeerBanList::new(1, Duration::from_secs(300));
        let peer = PeerId::from("bad");

        bans.record_violation(&peer);
        let err = bans.check_peer(&peer);
        assert!(err.is_err());
        match err.unwrap_err() {
            NetworkError::PeerBanned { peer: p, .. } => assert_eq!(p, "bad"),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn check_peer_ok_when_not_banned() {
        let mut bans = PeerBanList::new(5, Duration::from_secs(60));
        let peer = PeerId::from("good");
        assert!(bans.check_peer(&peer).is_ok());
    }

    #[test]
    fn purge_expired_cleans_up() {
        let mut bans = PeerBanList::new(1, Duration::from_millis(0));
        let peer = PeerId::from("gone");
        bans.record_violation(&peer);
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(bans.tracked_count(), 1);
        bans.purge_expired();
        assert_eq!(bans.tracked_count(), 0);
    }

    #[test]
    fn banned_count_accurate() {
        let mut bans = PeerBanList::new(1, Duration::from_secs(300));
        bans.record_violation(&PeerId::from("a"));
        bans.record_violation(&PeerId::from("b"));
        assert_eq!(bans.banned_count(), 2);
    }

    #[test]
    fn violations_saturate() {
        let mut bans = PeerBanList::new(u32::MAX, Duration::from_secs(60));
        let peer = PeerId::from("spammer");
        for _ in 0..10 {
            bans.record_violation(&peer);
        }
        assert_eq!(bans.violations(&peer), 10);
    }

    #[test]
    fn remaining_ban_secs_positive_when_banned() {
        let mut bans = PeerBanList::new(1, Duration::from_secs(300));
        let peer = PeerId::from("timed");
        bans.record_violation(&peer);
        let remaining = bans.remaining_ban_secs(&peer);
        assert!(remaining > 0);
        assert!(remaining <= 300);
    }

    #[test]
    fn extreme_ban_duration_does_not_panic() {
        let mut bans = PeerBanList::new(1, Duration::MAX);
        let peer = PeerId::from("long-ban");

        assert!(bans.record_violation(&peer));
        assert!(bans.is_banned(&peer));
        assert!(bans.remaining_ban_secs(&peer) <= MAX_TEMP_BAN_DURATION.as_secs());
    }

    #[test]
    fn remaining_ban_secs_zero_when_not_banned() {
        let bans = PeerBanList::new(5, Duration::from_secs(60));
        let peer = PeerId::from("clean");
        assert_eq!(bans.remaining_ban_secs(&peer), 0);
    }
}
