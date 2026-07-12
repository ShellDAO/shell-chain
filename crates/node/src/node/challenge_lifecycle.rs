use std::collections::HashMap;

use shell_primitives::{Address, ShellHash};

pub const CHALLENGE_TIMEOUT_BLOCKS: u64 = 7200;
pub const MAX_TRACKED_CHALLENGES: usize = 4096;

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

    pub fn open_challenge(&mut self, mut record: ChallengeRecord) -> bool {
        if self.challenges.contains_key(&record.challenge_id)
            || self.challenges.len() >= MAX_TRACKED_CHALLENGES
        {
            return false;
        }
        record.status = ChallengeStatus::Open;
        self.challenges.insert(record.challenge_id, record);
        true
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
        self.challenges.retain(|_, record| {
            record.status == ChallengeStatus::Open
                || current_block
                    < record
                        .opened_at_block
                        .saturating_add(CHALLENGE_TIMEOUT_BLOCKS.saturating_mul(2))
        });
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn tracked_count(&self) -> usize {
        self.challenges.len()
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

    #[test]
    fn duplicate_challenge_does_not_reset_timeout() {
        let mut lifecycle = ChallengeLifecycle::new();
        let challenge_id = hash(7);
        assert!(lifecycle.open_challenge(open_record(7, 10)));
        assert!(!lifecycle.open_challenge(open_record(7, 1_000)));

        let slashed = lifecycle.check_timeouts(10 + CHALLENGE_TIMEOUT_BLOCKS);

        assert_eq!(slashed.len(), 1);
        assert_eq!(slashed[0].challenge_id, challenge_id);
    }

    #[test]
    fn challenge_tracking_is_bounded() {
        let mut lifecycle = ChallengeLifecycle::new();
        for id in 0..MAX_TRACKED_CHALLENGES {
            let mut challenge_id_bytes = [0u8; 32];
            challenge_id_bytes[24..].copy_from_slice(&(id as u64).to_be_bytes());
            let challenge_id = ShellHash::from(challenge_id_bytes);
            assert!(lifecycle.open_challenge(ChallengeRecord {
                challenge_id,
                prover: addr(1),
                challenger: addr(2),
                opened_at_block: 0,
                status: ChallengeStatus::Open,
            }));
        }

        assert!(!lifecycle.open_challenge(open_record(8, 0)));
        assert_eq!(lifecycle.tracked_count(), MAX_TRACKED_CHALLENGES);
    }

    #[test]
    fn terminal_challenges_are_eventually_pruned() {
        let mut lifecycle = ChallengeLifecycle::new();
        let challenge_id = hash(9);
        lifecycle.open_challenge(open_record(9, 10));
        lifecycle.resolve_challenge(&challenge_id).unwrap();

        lifecycle.check_timeouts(10 + CHALLENGE_TIMEOUT_BLOCKS * 2);

        assert_eq!(lifecycle.tracked_count(), 0);
    }
}
