use std::collections::HashMap;

use shell_primitives::{Address, ShellHash};

pub const CHALLENGE_TIMEOUT_BLOCKS: u64 = 7200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeStatus {
    Open,
    Resolved,
    Slashed,
}

#[derive(Debug, Clone)]
pub struct ChallengeRecord {
    pub challenge_id: ShellHash,
    pub prover: Address,
    pub challenger: Address,
    pub opened_at_block: u64,
    pub status: ChallengeStatus,
}

#[derive(Debug, Default)]
pub struct ChallengeLifecycle {
    challenges: HashMap<ShellHash, ChallengeRecord>,
}

impl ChallengeLifecycle {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    pub fn open_challenge(&mut self, mut record: ChallengeRecord) {
        record.status = ChallengeStatus::Open;
        self.challenges.insert(record.challenge_id, record);
    }

    pub fn resolve_challenge(&mut self, id: &ShellHash) -> Option<ChallengeRecord> {
        let record = self.challenges.get_mut(id)?;
        if record.status != ChallengeStatus::Open {
            return None;
        }
        record.status = ChallengeStatus::Resolved;
        Some(record.clone())
    }

    pub fn check_timeouts(&mut self, current_block: u64) -> Vec<ChallengeRecord> {
        let mut slashed = Vec::new();
        for record in self.challenges.values_mut() {
            if record.status == ChallengeStatus::Open
                && current_block
                    >= record
                        .opened_at_block
                        .saturating_add(CHALLENGE_TIMEOUT_BLOCKS)
            {
                record.status = ChallengeStatus::Slashed;
                slashed.push(record.clone());
            }
        }
        slashed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get(&self, id: &ShellHash) -> Option<&ChallengeRecord> {
        self.challenges.get(id)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open_count(&self) -> usize {
        self.challenges
            .values()
            .filter(|record| record.status == ChallengeStatus::Open)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn hash(byte: u8) -> ShellHash {
        ShellHash::from([byte; 32])
    }

    fn open_record(id: u8, opened_at_block: u64) -> ChallengeRecord {
        ChallengeRecord {
            challenge_id: hash(id),
            prover: addr(id),
            challenger: addr(id.saturating_add(1)),
            opened_at_block,
            status: ChallengeStatus::Open,
        }
    }

    #[test]
    fn open_then_resolve_transitions_to_resolved() {
        let mut lifecycle = ChallengeLifecycle::new();
        let challenge_id = hash(1);
        lifecycle.open_challenge(open_record(1, 10));

        let resolved = lifecycle.resolve_challenge(&challenge_id).unwrap();

        assert_eq!(resolved.status, ChallengeStatus::Resolved);
        assert_eq!(
            lifecycle.get(&challenge_id).unwrap().status,
            ChallengeStatus::Resolved
        );
        assert_eq!(lifecycle.open_count(), 0);
    }

    #[test]
    fn open_then_timeout_transitions_to_slashed() {
        let mut lifecycle = ChallengeLifecycle::new();
        let challenge_id = hash(2);
        lifecycle.open_challenge(open_record(2, 100));

        let slashed = lifecycle.check_timeouts(100 + CHALLENGE_TIMEOUT_BLOCKS);

        assert_eq!(slashed.len(), 1);
        assert_eq!(slashed[0].challenge_id, challenge_id);
        assert_eq!(slashed[0].status, ChallengeStatus::Slashed);
        assert_eq!(
            lifecycle.get(&challenge_id).unwrap().status,
            ChallengeStatus::Slashed
        );
        assert_eq!(lifecycle.open_count(), 0);
    }

    #[test]
    fn multiple_challenges_only_slashes_expired_open_records() {
        let mut lifecycle = ChallengeLifecycle::new();
        let first = hash(3);
        let second = hash(4);
        let third = hash(5);
        lifecycle.open_challenge(open_record(3, 0));
        lifecycle.open_challenge(open_record(4, 500));
        lifecycle.open_challenge(open_record(5, 1_000));
        lifecycle.resolve_challenge(&second).unwrap();

        let slashed = lifecycle.check_timeouts(CHALLENGE_TIMEOUT_BLOCKS + 10);

        assert_eq!(slashed.len(), 1);
        assert_eq!(slashed[0].challenge_id, first);
        assert_eq!(
            lifecycle.get(&first).unwrap().status,
            ChallengeStatus::Slashed
        );
        assert_eq!(
            lifecycle.get(&second).unwrap().status,
            ChallengeStatus::Resolved
        );
        assert_eq!(lifecycle.get(&third).unwrap().status, ChallengeStatus::Open);
        assert_eq!(lifecycle.open_count(), 1);
    }

    #[test]
    fn timeout_boundary_is_exactly_7200_blocks() {
        let mut lifecycle = ChallengeLifecycle::new();
        let challenge_id = hash(6);
        lifecycle.open_challenge(open_record(6, 25));

        assert!(lifecycle
            .check_timeouts(25 + CHALLENGE_TIMEOUT_BLOCKS - 1)
            .is_empty());
        assert_eq!(
            lifecycle.get(&challenge_id).unwrap().status,
            ChallengeStatus::Open
        );

        let slashed = lifecycle.check_timeouts(25 + CHALLENGE_TIMEOUT_BLOCKS);
        assert_eq!(slashed.len(), 1);
        assert_eq!(slashed[0].status, ChallengeStatus::Slashed);
        assert_eq!(
            lifecycle.get(&challenge_id).unwrap().status,
            ChallengeStatus::Slashed
        );
    }
}
