use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shell_storage::{KvStore, StorageError, WriteBatch};

const STORAGE_KEY: &[u8] = b"node/challenge-lifecycle/v1";

#[derive(Serialize, Deserialize)]
struct Snapshot {
    records: Vec<ChallengeRecord>,
    penalties: Option<shell_consensus::PenaltyState>,
}

// The envelope deliberately lacks the legacy `records` field: old writers
// must refuse recovery instead of discarding the replay policy on their next save.
#[derive(Serialize, Deserialize)]
struct ReplaySnapshot {
    version: u8,
    equivocation_replay_height: u64,
    state: Snapshot,
}

use shell_primitives::{Address, ShellHash};

pub const CHALLENGE_TIMEOUT_BLOCKS: u64 = 7200;
pub const MAX_TRACKED_CHALLENGES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Open,
    Resolved,
    Slashed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: ShellHash,
    pub prover: Address,
    pub challenger: Address,
    pub opened_at_block: u64,
    pub status: ChallengeStatus,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChallengeLifecycle {
    challenges: HashMap<ShellHash, ChallengeRecord>,
    pub penalties: Option<shell_consensus::PenaltyState>,
    equivocation_replay_height: Option<u64>,
}

impl ChallengeLifecycle {
    pub fn load(store: &impl KvStore) -> Result<Self, StorageError> {
        let Some(bytes) = store.get(STORAGE_KEY)? else {
            return Ok(Self::new());
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| StorageError::Database(format!("invalid challenge snapshot: {e}")))?;
        let (snapshot, equivocation_replay_height) = if value.get("version").is_some() {
            let protected: ReplaySnapshot = serde_json::from_value(value)
                .map_err(|e| StorageError::Database(format!("invalid replay snapshot: {e}")))?;
            if protected.version != 2 {
                return Err(StorageError::Database(
                    "unsupported replay snapshot version".into(),
                ));
            }
            (protected.state, Some(protected.equivocation_replay_height))
        } else {
            (
                serde_json::from_value::<Snapshot>(value).map_err(|e| {
                    StorageError::Database(format!("invalid challenge snapshot: {e}"))
                })?,
                None,
            )
        };
        if let Some(penalties) = &snapshot.penalties {
            let slashed: std::collections::HashSet<_> = penalties.slashed.iter().collect();
            let reductions: std::collections::HashSet<_> = penalties
                .reductions
                .iter()
                .map(|(address, _)| address)
                .collect();
            if slashed.len() != penalties.slashed.len()
                || reductions.len() != penalties.reductions.len()
                || penalties.reductions.iter().any(|(address, weight)| {
                    !slashed.contains(address) || *weight > shell_primitives::MAX_VALIDATOR_WEIGHT
                })
            {
                return Err(StorageError::Database("invalid penalty snapshot".into()));
            }
        }
        let records = snapshot.records;
        if records.len() > MAX_TRACKED_CHALLENGES {
            return Err(StorageError::Database(
                "challenge snapshot exceeds capacity".into(),
            ));
        }
        let mut challenges = HashMap::with_capacity(records.len());
        for record in records {
            if challenges.insert(record.challenge_id, record).is_some() {
                return Err(StorageError::Database(
                    "duplicate challenge in snapshot".into(),
                ));
            }
        }
        Ok(Self {
            challenges,
            penalties: snapshot.penalties,
            equivocation_replay_height,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut records: Vec<_> = self.challenges.values().cloned().collect();
        records.sort_by(|a, b| a.challenge_id.as_bytes().cmp(b.challenge_id.as_bytes()));
        let state = Snapshot {
            records,
            penalties: self.penalties.clone(),
        };
        match self.equivocation_replay_height {
            Some(height) => serde_json::to_vec(&ReplaySnapshot {
                version: 2,
                equivocation_replay_height: height,
                state,
            }),
            None => serde_json::to_vec(&state),
        }
        .map_err(|e| StorageError::Database(format!("encode challenge snapshot: {e}")))
    }

    pub fn persist(&self, store: &impl KvStore) -> Result<(), StorageError> {
        store.put(STORAGE_KEY, &self.encode()?)
    }

    pub fn configure_equivocation_replay(
        &mut self,
        height: Option<u64>,
    ) -> Result<(), StorageError> {
        if self.equivocation_replay_height.is_some() && self.equivocation_replay_height != height {
            return Err(StorageError::State(
                "equivocation replay policy conflicts with persisted penalties".into(),
            ));
        }
        self.equivocation_replay_height = height;
        Ok(())
    }

    fn equivocation_key(proof: &shell_consensus::EquivocationProof) -> Vec<u8> {
        let (a, b) = if proof.hash_a.as_bytes() < proof.hash_b.as_bytes() {
            (proof.hash_a, proof.hash_b)
        } else {
            (proof.hash_b, proof.hash_a)
        };
        [
            b"node/equivocation/v1/".as_slice(),
            proof.offender.as_ref(),
            a.as_bytes(),
            b.as_bytes(),
        ]
        .concat()
    }

    pub fn has_equivocation(
        store: &impl KvStore,
        proof: &shell_consensus::EquivocationProof,
    ) -> Result<bool, StorageError> {
        match store.get(&Self::equivocation_key(proof))? {
            None => Ok(false),
            Some(value) if value == b"1" => Ok(true),
            Some(_) => Err(StorageError::Database(
                "invalid equivocation replay record".into(),
            )),
        }
    }

    pub fn persist_equivocation(
        &self,
        store: &impl KvStore,
        proof: &shell_consensus::EquivocationProof,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        batch.put(STORAGE_KEY.to_vec(), self.encode()?);
        batch.put(Self::equivocation_key(proof), b"1".to_vec());
        store.write_batch(batch)
    }

    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            penalties: None,
            equivocation_replay_height: None,
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
    fn replay_policy_migrates_legacy_state_and_refuses_downgrade() {
        let db = shell_storage::MemoryDb::new();
        let mut state = ChallengeLifecycle::new();
        state.open_challenge(open_record(1, 0));
        state.persist(&db).unwrap();
        let legacy = db.get(STORAGE_KEY).unwrap().unwrap();
        assert!(serde_json::from_slice::<Snapshot>(&legacy).is_ok());
        state.configure_equivocation_replay(Some(5)).unwrap();
        state.persist(&db).unwrap();
        let protected = db.get(STORAGE_KEY).unwrap().unwrap();
        assert!(serde_json::from_slice::<Snapshot>(&protected).is_err());
        let mut recovered = ChallengeLifecycle::load(&db).unwrap();
        assert_eq!(state, recovered);
        for conflicting in [None, Some(6)] {
            assert!(recovered
                .configure_equivocation_replay(conflicting)
                .is_err());
            assert_eq!(state, recovered);
        }
        recovered.configure_equivocation_replay(Some(5)).unwrap();
        let mut corrupt: serde_json::Value = serde_json::from_slice(&protected).unwrap();
        corrupt["version"] = 3.into();
        db.put(STORAGE_KEY, &serde_json::to_vec(&corrupt).unwrap())
            .unwrap();
        assert!(ChallengeLifecycle::load(&db).is_err());
    }

    #[test]
    fn snapshot_preserves_terminal_states_and_rejects_corruption() {
        let db = shell_storage::MemoryDb::new();
        let mut state = ChallengeLifecycle::new();
        state.open_challenge(open_record(1, 10));
        state.open_challenge(open_record(2, 20));
        state.resolve_challenge(&hash(1));
        state.check_timeouts(20 + CHALLENGE_TIMEOUT_BLOCKS);
        state.persist(&db).unwrap();
        let mut recovered = ChallengeLifecycle::load(&db).unwrap();
        assert_eq!(state, recovered);
        assert!(recovered
            .check_timeouts(21 + CHALLENGE_TIMEOUT_BLOCKS)
            .is_empty());
        assert_eq!(
            recovered.get(&hash(1)).unwrap().status,
            ChallengeStatus::Resolved
        );
        assert_eq!(
            recovered.get(&hash(2)).unwrap().status,
            ChallengeStatus::Slashed
        );
        db.put(STORAGE_KEY, b"invalid").unwrap();
        assert!(ChallengeLifecycle::load(&db).is_err());
        db.put(
            STORAGE_KEY,
            &serde_json::to_vec(&Snapshot {
                records: vec![open_record(1, 10); 2],
                penalties: None,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(ChallengeLifecycle::load(&db).is_err());
    }

    #[test]
    fn snapshot_rejects_ambiguous_penalty_state() {
        let db = shell_storage::MemoryDb::new();
        for penalties in [
            shell_consensus::PenaltyState {
                slashed: vec![addr(1); 2],
                reductions: vec![],
            },
            shell_consensus::PenaltyState {
                slashed: vec![addr(1)],
                reductions: vec![(addr(1), 10); 2],
            },
            shell_consensus::PenaltyState {
                slashed: vec![],
                reductions: vec![(addr(1), 10)],
            },
            shell_consensus::PenaltyState {
                slashed: vec![addr(1)],
                reductions: vec![(addr(1), u64::MAX)],
            },
        ] {
            db.put(
                STORAGE_KEY,
                &serde_json::to_vec(&Snapshot {
                    records: vec![],
                    penalties: Some(penalties),
                })
                .unwrap(),
            )
            .unwrap();
            assert!(ChallengeLifecycle::load(&db).is_err());
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
