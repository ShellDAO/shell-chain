use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use shell_primitives::{Address, ShellHash};

pub const VIEW_CHANGE_TIMEOUT_MS: u64 = 10_000;

/// Domain tag for the view-change signing payload.
const VIEWCHG_DOMAIN: &[u8; 16] = b"SHELL_VIEWCHG_V1";

/// A validator's request to advance the consensus view (rotate the proposer).
///
/// Signing payload (WP §1585-1596):
///   SHELL_VIEWCHG_V1 || chain_id(8 BE) || block_number(8 BE) || view(8 BE) || highest_qc_hash(32)
///
/// `chain_id` and `highest_qc_hash` are tagged `#[serde(default)]` so that messages
/// produced by pre-Phase-1 nodes (missing these fields) still deserialise without
/// panicking; their signatures will fail verification against the new payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewChangeMessage {
    /// Chain ID — binds the message to a specific network.
    #[serde(default)]
    pub chain_id: u64,
    /// Block number at which the view change is requested.
    pub block_number: u64,
    /// Requested view number.
    pub view: u64,
    /// Hash of the highest QC seen by this validator (last finalized block hash).
    #[serde(default)]
    pub highest_qc_hash: ShellHash,
    /// Address of the validator requesting the view change.
    pub validator: Address,
    /// PQ signature over the signing payload.
    pub signature: Vec<u8>,
}

impl ViewChangeMessage {
    pub fn new(
        chain_id: u64,
        block_number: u64,
        view: u64,
        highest_qc_hash: ShellHash,
        validator: Address,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            chain_id,
            block_number,
            view,
            highest_qc_hash,
            validator,
            signature,
        }
    }

    /// The canonical signing payload (WP §1585-1596):
    ///   SHELL_VIEWCHG_V1 || chain_id(8 BE) || block_number(8 BE) || view(8 BE) || highest_qc_hash(32)
    ///
    /// Total: 16 + 8 + 8 + 8 + 32 = 72 bytes.
    pub fn signing_message(
        chain_id: u64,
        block_number: u64,
        view: u64,
        highest_qc_hash: &ShellHash,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(VIEWCHG_DOMAIN);
        msg.extend_from_slice(&chain_id.to_be_bytes());
        msg.extend_from_slice(&block_number.to_be_bytes());
        msg.extend_from_slice(&view.to_be_bytes());
        msg.extend_from_slice(highest_qc_hash.as_bytes());
        msg
    }

    /// Reconstruct the signing message from this message's own fields.
    pub fn own_signing_message(&self) -> Vec<u8> {
        Self::signing_message(
            self.chain_id,
            self.block_number,
            self.view,
            &self.highest_qc_hash,
        )
    }
}

#[derive(Debug, Clone)]
pub struct ViewChangeState {
    pub current_view: u64,
    pub last_block_time_ms: u64,
    pub pending_view_changes: HashMap<u64, Vec<ViewChangeMessage>>,
    quorum_weight: u64,
    validator_weights: HashMap<Address, u64>,
    pending_view_change_weights: HashMap<u64, u64>,
    /// Chain ID used to reject cross-chain view-change messages.
    /// Zero means unconfigured (no chain-ID check).
    chain_id: u64,
}

impl ViewChangeState {
    pub fn new() -> Self {
        Self {
            current_view: 0,
            last_block_time_ms: wall_clock_millis(),
            pending_view_changes: HashMap::new(),
            quorum_weight: 1,
            validator_weights: HashMap::new(),
            pending_view_change_weights: HashMap::new(),
            chain_id: 0,
        }
    }

    /// Set the chain ID to enforce on incoming view-change messages.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    pub fn record_view_change(&mut self, msg: ViewChangeMessage) -> bool {
        if msg.view != self.current_view {
            return false;
        }
        if self.chain_id != 0 && msg.chain_id != self.chain_id {
            return false;
        }

        let Some(validator_weight) = self.validator_weights.get(&msg.validator).copied() else {
            return false;
        };
        if validator_weight == 0 {
            return false;
        }

        let messages = self.pending_view_changes.entry(msg.view).or_default();
        if messages
            .iter()
            .any(|existing| existing.validator == msg.validator)
        {
            return false;
        }
        if let Some(expected_block) = messages.first().map(|existing| existing.block_number) {
            if expected_block != msg.block_number {
                return false;
            }
        }

        messages.push(msg.clone());
        let vote_weight = self
            .pending_view_change_weights
            .entry(msg.view)
            .or_insert(0);
        *vote_weight = vote_weight.saturating_add(validator_weight);
        *vote_weight >= self.quorum_weight.max(1)
    }

    pub fn check_timeout(&self, now_ms: u64, block_time_ms: u64) -> bool {
        let timeout_ms = block_time_ms.max(VIEW_CHANGE_TIMEOUT_MS);
        now_ms.saturating_sub(self.last_block_time_ms) >= timeout_ms
    }

    pub fn advance_view(&mut self) -> u64 {
        self.current_view = self.current_view.saturating_add(1);
        self.pending_view_changes.clear();
        self.pending_view_change_weights.clear();
        self.current_view
    }

    pub fn select_proposer(view: u64, authorities: &[Address]) -> Address {
        assert!(!authorities.is_empty(), "authority set must not be empty");
        authorities[(view as usize) % authorities.len()]
    }

    pub fn reset_for_block(&mut self, now_ms: u64) {
        self.current_view = 0;
        self.last_block_time_ms = now_ms;
        self.pending_view_changes.clear();
        self.pending_view_change_weights.clear();
    }

    pub(crate) fn configure_quorum(
        &mut self,
        validator_weights: HashMap<Address, u64>,
        total_weight: u64,
    ) {
        self.validator_weights = validator_weights;
        self.quorum_weight = (2 * total_weight.max(1)).div_ceil(3);
    }
}

impl Default for ViewChangeState {
    fn default() -> Self {
        Self::new()
    }
}

fn wall_clock_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from([n; 32])
    }

    #[test]
    fn select_proposer_round_robins_through_authorities() {
        let authorities = vec![addr(1), addr(2), addr(3)];

        assert_eq!(ViewChangeState::select_proposer(0, &authorities), addr(1));
        assert_eq!(ViewChangeState::select_proposer(1, &authorities), addr(2));
        assert_eq!(ViewChangeState::select_proposer(2, &authorities), addr(3));
        assert_eq!(ViewChangeState::select_proposer(3, &authorities), addr(1));
    }

    #[test]
    fn record_view_change_returns_true_only_at_quorum() {
        let mut state = ViewChangeState::new();
        state.configure_quorum(HashMap::from([(addr(1), 1), (addr(2), 1), (addr(3), 1)]), 3);

        let first = ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(1), vec![1]);
        let second = ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(2), vec![2]);

        assert!(!state.record_view_change(first));
        assert!(state.record_view_change(second));
    }

    #[test]
    fn record_view_change_rejects_unknown_validator() {
        let mut state = ViewChangeState::new();
        state.configure_quorum(HashMap::from([(addr(1), 1), (addr(2), 1), (addr(3), 1)]), 3);

        let unknown = ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(99), vec![9]);

        assert!(!state.record_view_change(unknown));
        assert!(
            state.pending_view_changes.is_empty(),
            "unknown validators must not be recorded or counted toward quorum"
        );
    }

    #[test]
    fn record_view_change_rejects_zero_weight_validator() {
        let mut state = ViewChangeState::new();
        state.configure_quorum(HashMap::from([(addr(1), 0), (addr(2), 2)]), 2);

        let slashed = ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(1), vec![1]);
        let active = ViewChangeMessage::new(0, 7, 0, ShellHash::ZERO, addr(2), vec![2]);

        assert!(!state.record_view_change(slashed));
        assert!(state.pending_view_changes.is_empty());
        assert!(state.record_view_change(active));
    }

    #[test]
    fn check_timeout_respects_view_change_timeout() {
        let mut state = ViewChangeState::new();
        state.last_block_time_ms = 1_000;

        assert!(!state.check_timeout(1_000 + VIEW_CHANGE_TIMEOUT_MS - 1, 1_000));
        assert!(state.check_timeout(1_000 + VIEW_CHANGE_TIMEOUT_MS, 1_000));
    }

    #[test]
    fn advance_view_increments_monotonically() {
        let mut state = ViewChangeState::new();

        assert_eq!(state.advance_view(), 1);
        assert_eq!(state.advance_view(), 2);
        assert_eq!(state.advance_view(), 3);
    }

    #[test]
    fn signing_message_has_correct_layout_and_length() {
        let chain_id: u64 = 42;
        let block_number: u64 = 1_000;
        let view: u64 = 3;
        let qc_hash = ShellHash::from([0xab; 32]);

        let msg = ViewChangeMessage::signing_message(chain_id, block_number, view, &qc_hash);

        // Total length: 16 (domain) + 8 + 8 + 8 + 32 = 72 bytes
        assert_eq!(msg.len(), 72);

        // Domain tag at [0..16]
        assert_eq!(&msg[0..16], b"SHELL_VIEWCHG_V1");

        // chain_id at [16..24] big-endian
        assert_eq!(&msg[16..24], &42u64.to_be_bytes());

        // block_number at [24..32] big-endian
        assert_eq!(&msg[24..32], &1_000u64.to_be_bytes());

        // view at [32..40] big-endian
        assert_eq!(&msg[32..40], &3u64.to_be_bytes());

        // highest_qc_hash at [40..72]
        assert_eq!(&msg[40..72], &[0xab; 32]);
    }
}
