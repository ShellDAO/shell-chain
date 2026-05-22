use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use shell_primitives::Address;

pub const VIEW_CHANGE_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewChangeMessage {
    pub view: u64,
    pub block_number: u64,
    pub validator: Address,
    pub signature: Vec<u8>,
}

impl ViewChangeMessage {
    pub fn new(view: u64, block_number: u64, validator: Address, signature: Vec<u8>) -> Self {
        Self {
            view,
            block_number,
            validator,
            signature,
        }
    }

    pub fn signing_message(view: u64, block_number: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(16);
        msg.extend_from_slice(&view.to_be_bytes());
        msg.extend_from_slice(&block_number.to_be_bytes());
        msg
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
        }
    }

    pub fn record_view_change(&mut self, msg: ViewChangeMessage) -> bool {
        if msg.view != self.current_view {
            return false;
        }

        let validator_weight = self
            .validator_weights
            .get(&msg.validator)
            .copied()
            .unwrap_or(1)
            .max(1);

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

        let first = ViewChangeMessage::new(0, 7, addr(1), vec![1]);
        let second = ViewChangeMessage::new(0, 7, addr(2), vec![2]);

        assert!(!state.record_view_change(first));
        assert!(state.record_view_change(second));
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
}
