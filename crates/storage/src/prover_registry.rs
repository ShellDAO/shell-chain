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

fn key(address: &Address, field: u64) -> ShellHash {
    let mut bytes = b"shell:prover-registry:v1:".to_vec();
    bytes.extend_from_slice(address.as_bytes());
    bytes.extend_from_slice(&field.to_be_bytes());
    blake3_hash(&bytes)
}

impl<S: KvStore + 'static> WorldState<S> {
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
        self.set_storage(&registry, &key(address, 0), &ShellHash::from(meta))
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
