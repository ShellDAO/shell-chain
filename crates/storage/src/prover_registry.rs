//! Prover registrations committed to the state trie independently of validators.
use shell_primitives::{blake3_hash, Address, ShellHash};

use crate::{validator_registry_addr, KvStore, StorageError, WorldState};

/// A governance-approved proof signing identity. Registration grants no voting power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredProver {
    pub public_key: Vec<u8>,
    pub algorithm: u8,
    pub registered_at: u64,
    pub proofs_submitted: u64,
    pub last_proof_block: u64,
}

pub(crate) const PROVER_DISCOVERY_GENESIS: &[u8] = b"prover-discovery/genesis/v1";
pub(crate) const PROVER_DISCOVERY_HEAD: &[u8] = b"prover-discovery/head/v1";
const CANDIDATES: &[u8] = b"prover-discovery/candidates/v1/";
const DISCOVERY_PAGE_SIZE: usize = 64;
const MAX_DISCOVERED_MEMBERS: usize = 64;

fn key(address: &Address, field: u64) -> ShellHash {
    let mut bytes = b"shell:prover-registry:v1:".to_vec();
    bytes.extend_from_slice(address.as_bytes());
    bytes.extend_from_slice(&field.to_be_bytes());
    blake3_hash(&bytes)
}

impl<S: KvStore> crate::ChainStore<S> {
    /// Check certificate availability without hiding database read failures.
    pub fn has_complete_prover_discovery(&self, genesis: ShellHash) -> Result<bool, StorageError> {
        if self.store().get(PROVER_DISCOVERY_GENESIS)?.as_deref() != Some(genesis.as_bytes()) {
            return Ok(false);
        }
        match self.validate_prover_discovery_coverage() {
            Ok(()) => Ok(true),
            Err(StorageError::State(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Publish only discovery hints after a caller has replayed the complete
    /// canonical history privately while holding exclusive startup ownership.
    pub fn publish_rebuilt_prover_discovery(
        &self,
        genesis: ShellHash,
        expected_head: ShellHash,
        members: &[Address],
    ) -> Result<(), StorageError> {
        if self.get_head_hash()? != Some(expected_head)
            || self.get_block_hash_by_number(0)? != Some(genesis)
        {
            return Err(StorageError::State(
                "canonical chain changed during prover discovery rebuild".into(),
            ));
        }
        let mut batch = crate::WriteBatch::new();
        for address in members {
            let mut key = CANDIDATES.to_vec();
            key.extend_from_slice(address.as_bytes());
            batch.put(key, vec![]);
        }
        batch.put(
            PROVER_DISCOVERY_GENESIS.to_vec(),
            genesis.as_bytes().to_vec(),
        );
        batch.put(
            PROVER_DISCOVERY_HEAD.to_vec(),
            expected_head.as_bytes().to_vec(),
        );
        self.store().write_batch(batch)
    }
}

impl<S: KvStore + 'static> WorldState<S> {
    /// Enumerate candidate preimages against this exact trie root. The local
    /// index is never registration evidence; rolled-back and orphaned candidates
    /// are filtered out without changing the queried or live state.
    pub fn registered_prover_members(
        &self,
        genesis: ShellHash,
    ) -> Result<Vec<(Address, u64)>, StorageError> {
        if self.store().get(PROVER_DISCOVERY_GENESIS)?.as_deref() != Some(genesis.as_bytes()) {
            return Err(StorageError::State(
                "complete prover discovery index is unavailable for this genesis".into(),
            ));
        }
        crate::ChainStore::new(std::sync::Arc::clone(self.store()))
            .validate_prover_discovery_coverage()?;
        self.prover_discovery_candidates()
    }

    /// Return valid hinted records at this root without certifying completeness.
    /// Private full-history replay uses this before publishing coverage. Worker
    /// assignment must use `registered_prover_members` instead.
    pub fn prover_discovery_candidates(&self) -> Result<Vec<(Address, u64)>, StorageError> {
        let mut members = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let candidates = self.store().scan_prefix_after(
                CANDIDATES,
                cursor.as_deref(),
                DISCOVERY_PAGE_SIZE,
            )?;
            if candidates.is_empty() {
                break;
            }
            cursor = candidates.last().map(|(key, _)| key.clone());
            for (key, _) in candidates {
                let address = Address::try_from_slice(&key[CANDIDATES.len()..])
                    .map_err(|error| StorageError::Codec(error.to_string()))?;
                if let Some(record) = self.get_registered_prover(&address)? {
                    if Address::from_public_key(&record.public_key, record.algorithm) != address {
                        return Err(StorageError::State(
                            "registered prover identity does not match its address".into(),
                        ));
                    }
                    members.push((address, record.registered_at));
                    if members.len() > MAX_DISCOVERED_MEMBERS {
                        return Err(StorageError::State(
                            "registry-derived cohort exceeds 64 workers".into(),
                        ));
                    }
                }
            }
        }
        Ok(members)
    }

    pub fn get_registered_prover(
        &self,
        address: &Address,
    ) -> Result<Option<RegisteredProver>, StorageError> {
        let registry = validator_registry_addr();
        let meta = self.get_storage(&registry, &key(address, 0))?;
        if meta == ShellHash::ZERO {
            return Ok(None);
        }
        let data = meta.as_bytes();
        let length = u16::from_be_bytes([data[1], data[2]]) as usize;
        if length == 0 || length > 4096 {
            return Err(StorageError::State(
                "invalid registered prover key length".into(),
            ));
        }
        let registered_at = u64::from_be_bytes(data[24..].try_into().expect("eight bytes"));
        let mut public_key = Vec::with_capacity(length.div_ceil(32) * 32);
        for index in 0..length.div_ceil(32) {
            public_key.extend_from_slice(
                self.get_storage(&registry, &key(address, 1 + index as u64))?
                    .as_bytes(),
            );
        }
        public_key.truncate(length);
        Ok(Some(RegisteredProver {
            public_key,
            algorithm: data[0],
            registered_at,
            proofs_submitted: u64::from_be_bytes(data[3..11].try_into().expect("eight bytes")),
            last_proof_block: u64::from_be_bytes(data[11..19].try_into().expect("eight bytes")),
        }))
    }

    /// Called by native governance execution on its transaction-local state.
    /// Identity and quorum validation belongs to the execution layer.
    pub fn set_registered_prover(
        &mut self,
        address: &Address,
        record: &RegisteredProver,
    ) -> Result<(), StorageError> {
        if record.public_key.is_empty() || record.public_key.len() > 4096 {
            return Err(StorageError::State(
                "invalid registered prover key length".into(),
            ));
        }
        let registry = validator_registry_addr();
        let mut meta = [0u8; 32];
        meta[0] = record.algorithm;
        meta[1..3].copy_from_slice(&(record.public_key.len() as u16).to_be_bytes());
        meta[3..11].copy_from_slice(&record.proofs_submitted.to_be_bytes());
        meta[11..19].copy_from_slice(&record.last_proof_block.to_be_bytes());
        meta[24..].copy_from_slice(&record.registered_at.to_be_bytes());
        for (index, chunk) in record.public_key.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            self.set_storage(
                &registry,
                &key(address, 1 + index as u64),
                &ShellHash::from(word),
            )?;
        }
        self.set_storage(&registry, &key(address, 0), &ShellHash::from(meta))?;
        // This is only an address-preimage hint. Canonical/historical trie reads
        // above decide membership, including after AA rollback and reorg.
        if self.store().get(PROVER_DISCOVERY_GENESIS)?.is_some() {
            let mut candidate = CANDIDATES.to_vec();
            candidate.extend_from_slice(address.as_bytes());
            self.store().put(&candidate, &[])?;
        }
        Ok(())
    }
    /// Count a successfully executed canonical settlement, not mere proof reception.
    pub fn record_prover_settlement(
        &mut self,
        address: &Address,
        source_block: u64,
    ) -> Result<(), StorageError> {
        let registry = validator_registry_addr();
        let mut word = self.get_storage(&registry, &key(address, 0))?.0;
        if word == [0; 32] {
            return Err(StorageError::State("prover is not registered".into()));
        }
        let count = u64::from_be_bytes(word[3..11].try_into().expect("eight bytes"))
            .checked_add(1)
            .ok_or_else(|| StorageError::State("prover proof count overflow".into()))?;
        let last =
            u64::from_be_bytes(word[11..19].try_into().expect("eight bytes")).max(source_block);
        word[3..11].copy_from_slice(&count.to_be_bytes());
        word[11..19].copy_from_slice(&last.to_be_bytes());
        self.set_storage(&registry, &key(address, 0), &ShellHash::from(word))
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::MemoryDb;
    use shell_crypto::{DilithiumSigner, Signer};
    use std::sync::Arc;

    fn record(signer: &DilithiumSigner, height: u64) -> (Address, RegisteredProver) {
        let algorithm = signer.sig_type().as_u8();
        (
            Address::from_public_key(signer.public_key(), algorithm),
            RegisteredProver {
                public_key: signer.public_key().to_vec(),
                algorithm,
                registered_at: height,
                proofs_submitted: 0,
                last_proof_block: 0,
            },
        )
    }

    #[test]
    fn prover_discovery_filters_rollback_and_future_records_and_survives_reopen() {
        let db = Arc::new(MemoryDb::new());
        let genesis = ShellHash::from([7; 32]);
        db.put(PROVER_DISCOVERY_HEAD, genesis.as_bytes()).unwrap();
        db.put(b"HEAD", genesis.as_bytes()).unwrap();
        db.put(PROVER_DISCOVERY_GENESIS, genesis.as_bytes())
            .unwrap();
        let mut state = WorldState::new(db.clone());
        let empty = state.state_root().unwrap();
        let (a, first) = record(&DilithiumSigner::generate(), 1);
        let (b, later) = record(&DilithiumSigner::generate(), 5);
        state.set_registered_prover(&a, &first).unwrap();
        let first_root = state.state_root().unwrap();
        state.set_registered_prover(&b, &later).unwrap();
        let latest = state.state_root().unwrap();
        let mut expected = vec![(a, 1), (b, 5)];
        expected.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(state.registered_prover_members(genesis).unwrap(), expected);
        let old = WorldState::at_root(db.clone(), &first_root).unwrap();
        assert_eq!(
            old.registered_prover_members(genesis).unwrap(),
            vec![(a, 1)]
        );
        let rolled_back = WorldState::at_root(db.clone(), &empty).unwrap();
        assert!(rolled_back
            .registered_prover_members(genesis)
            .unwrap()
            .is_empty());
        assert_eq!(
            state.state_root().unwrap(),
            latest,
            "historical discovery must not write live trie state"
        );
        assert_eq!(
            WorldState::at_root(db, &latest)
                .unwrap()
                .registered_prover_members(genesis)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn prover_discovery_rejects_missing_wrong_or_poisoned_index() {
        let db = Arc::new(MemoryDb::new());
        let genesis = ShellHash::from([7; 32]);
        db.put(PROVER_DISCOVERY_HEAD, genesis.as_bytes()).unwrap();
        db.put(b"HEAD", genesis.as_bytes()).unwrap();
        let mut state = WorldState::new(db.clone());
        assert!(state.registered_prover_members(genesis).is_err());
        db.put(PROVER_DISCOVERY_GENESIS, ShellHash::ZERO.as_bytes())
            .unwrap();
        assert!(state.registered_prover_members(genesis).is_err());
        db.put(PROVER_DISCOVERY_GENESIS, genesis.as_bytes())
            .unwrap();
        let (_, rec) = record(&DilithiumSigner::generate(), 1);
        state.set_registered_prover(&Address::ZERO, &rec).unwrap();
        assert!(state.registered_prover_members(genesis).is_err());
    }

    #[test]
    fn prover_discovery_pages_past_orphaned_candidates() {
        let db = Arc::new(MemoryDb::new());
        let genesis = ShellHash::from([7; 32]);
        db.put(PROVER_DISCOVERY_HEAD, genesis.as_bytes()).unwrap();
        db.put(b"HEAD", genesis.as_bytes()).unwrap();
        db.put(PROVER_DISCOVERY_GENESIS, genesis.as_bytes())
            .unwrap();
        for i in 0..=4096 {
            let mut key = CANDIDATES.to_vec();
            key.extend_from_slice(&[0; 24]);
            key.extend_from_slice(&(i as u64).to_be_bytes());
            db.put(&key, &[]).unwrap();
        }
        assert!(WorldState::new(db)
            .registered_prover_members(genesis)
            .unwrap()
            .is_empty());
    }
}
