//! I6: Enhanced peer scoring for prover nodes.
//!
//! Extends the basic network peer scoring to account for prover-specific
//! behaviour: proof delivery timeliness, challenge responses, and equivocation.
//!
//! # Implementation Status (Constitution §13.5)
//!
//! **lib-only** — This module is intentionally NOT wired into the production node
//! or `shell-network`. It is a higher-level, proof-quality scoring layer designed
//! for the wPoA era, complementing the P2P-level [`network::security::PeerTracker`]
//! which handles basic ban/allow logic at the libp2p layer.
//!
//! When wPoA is activated (F-WPOA-ACTIVATE), this module should be wired into
//! `node::NodeState` and driven from the proof challenge/response event loop.
//! Until then it lives as a complete, tested library awaiting integration.
//!
//! # Scoring model
//!
//! Each peer starts at `initial_score`. Scores change on observable events:
//!
//! | Event                           | Δ score |
//! |---------------------------------|---------|
//! | Valid proof amendment delivered | +5      |
//! | Timely challenge response       | +3      |
//! | Unanswered challenge (timeout)  | -10     |
//! | Invalid proof payload           | -20     |
//! | Equivocation evidence received  | -100    |
//! | Duplicate/replayed message      | -2      |
//!
//! Peers whose score falls below `disconnect_threshold` should be disconnected
//! by the network layer. Scores are capped at `max_score`.
//!
//! `PeerId` here is a simple newtype over `String` matching the network layer's
//! definition. No dependency on `shell-network` is taken to avoid a circular dep.

use std::collections::HashMap;

/// Opaque peer identifier (mirrors `shell_network::PeerId`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Scoring deltas for prover-specific peer events.
#[derive(Debug, Clone)]
pub struct PeerScoringConfig {
    pub initial_score: i64,
    pub max_score: i64,
    pub disconnect_threshold: i64,
    pub delta_valid_proof: i64,
    pub delta_challenge_response: i64,
    pub delta_unanswered_challenge: i64,
    pub delta_invalid_proof: i64,
    pub delta_equivocation: i64,
    pub delta_duplicate_message: i64,
}

impl Default for PeerScoringConfig {
    fn default() -> Self {
        Self {
            initial_score: 100,
            max_score: 200,
            disconnect_threshold: 0,
            delta_valid_proof: 5,
            delta_challenge_response: 3,
            delta_unanswered_challenge: -10,
            delta_invalid_proof: -20,
            delta_equivocation: -100,
            delta_duplicate_message: -2,
        }
    }
}

/// Observable peer events relevant to proof scoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    ValidProofDelivered,
    TimelyChannelResponse,
    UnansweredChallenge,
    InvalidProofPayload,
    EquivocationDetected,
    DuplicateMessage,
}

/// I6: Per-peer score tracker with prover-aware scoring.
#[derive(Debug)]
pub struct PeerScorer {
    config: PeerScoringConfig,
    scores: HashMap<PeerId, i64>,
}

impl PeerScorer {
    pub fn new(config: PeerScoringConfig) -> Self {
        Self {
            config,
            scores: HashMap::new(),
        }
    }

    /// Record an event for a peer, adjusting their score accordingly.
    pub fn record_event(&mut self, peer: &PeerId, event: PeerEvent) {
        let delta = match event {
            PeerEvent::ValidProofDelivered => self.config.delta_valid_proof,
            PeerEvent::TimelyChannelResponse => self.config.delta_challenge_response,
            PeerEvent::UnansweredChallenge => self.config.delta_unanswered_challenge,
            PeerEvent::InvalidProofPayload => self.config.delta_invalid_proof,
            PeerEvent::EquivocationDetected => self.config.delta_equivocation,
            PeerEvent::DuplicateMessage => self.config.delta_duplicate_message,
        };
        let score = self
            .scores
            .entry(peer.clone())
            .or_insert(self.config.initial_score);
        *score = (*score + delta).min(self.config.max_score);
    }

    /// Get the current score for a peer (returns `initial_score` if unseen).
    pub fn score(&self, peer: &PeerId) -> i64 {
        self.scores
            .get(peer)
            .copied()
            .unwrap_or(self.config.initial_score)
    }

    /// Whether a peer's score is below the disconnect threshold.
    pub fn should_disconnect(&self, peer: &PeerId) -> bool {
        self.score(peer) < self.config.disconnect_threshold
    }

    /// Return all peers that should be disconnected.
    pub fn peers_to_disconnect(&self) -> Vec<PeerId> {
        self.scores
            .iter()
            .filter(|(_, &score)| score < self.config.disconnect_threshold)
            .map(|(peer, _)| peer.clone())
            .collect()
    }

    /// Remove a peer from the scorer (on disconnect).
    pub fn remove(&mut self, peer: &PeerId) {
        self.scores.remove(peer);
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> PeerId {
        PeerId(s.to_string())
    }

    fn scorer() -> PeerScorer {
        PeerScorer::new(PeerScoringConfig::default())
    }

    #[test]
    fn initial_score_for_unknown_peer() {
        let s = scorer();
        assert_eq!(s.score(&peer("x")), 100);
    }

    #[test]
    fn valid_proof_increases_score() {
        let mut s = scorer();
        s.record_event(&peer("a"), PeerEvent::ValidProofDelivered);
        assert_eq!(s.score(&peer("a")), 105);
    }

    #[test]
    fn invalid_proof_decreases_score() {
        let mut s = scorer();
        s.record_event(&peer("a"), PeerEvent::InvalidProofPayload);
        assert_eq!(s.score(&peer("a")), 80);
    }

    #[test]
    fn equivocation_causes_disconnect_threshold() {
        let mut s = scorer();
        s.record_event(&peer("a"), PeerEvent::EquivocationDetected);
        assert_eq!(s.score(&peer("a")), 0); // 100 - 100
        assert!(!s.should_disconnect(&peer("a"))); // threshold is 0, not < 0
        s.record_event(&peer("a"), PeerEvent::DuplicateMessage);
        assert!(s.should_disconnect(&peer("a"))); // -2 → below 0
    }

    #[test]
    fn score_capped_at_max() {
        let mut s = scorer();
        for _ in 0..50 {
            s.record_event(&peer("b"), PeerEvent::ValidProofDelivered);
        }
        assert_eq!(s.score(&peer("b")), 200); // capped
    }

    #[test]
    fn peers_to_disconnect_returns_below_threshold() {
        let mut s = scorer();
        s.record_event(&peer("bad"), PeerEvent::EquivocationDetected);
        s.record_event(&peer("bad"), PeerEvent::DuplicateMessage); // score = -2
        let to_disc = s.peers_to_disconnect();
        assert!(to_disc.contains(&peer("bad")));
    }

    #[test]
    fn remove_peer_clears_score() {
        let mut s = scorer();
        s.record_event(&peer("c"), PeerEvent::ValidProofDelivered);
        s.remove(&peer("c"));
        assert_eq!(s.score(&peer("c")), 100); // back to default
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn multiple_peers_independent() {
        let mut s = scorer();
        s.record_event(&peer("p1"), PeerEvent::ValidProofDelivered);
        s.record_event(&peer("p2"), PeerEvent::InvalidProofPayload);
        assert_eq!(s.score(&peer("p1")), 105);
        assert_eq!(s.score(&peer("p2")), 80);
    }
}
