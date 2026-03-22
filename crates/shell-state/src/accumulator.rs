use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Bound::{Excluded, Unbounded};

use sha2::{Digest, Sha256};
use shell_primitives::{MockProgressiveByteList, Root, StateKey, StateWitness};

use crate::errors::{StateError, WitnessOrderingError};
use crate::keys::{compare_state_keys, encode_state_key, StateKeyBytes};
use crate::transition::StatePatch;
use crate::witness::WitnessVerifier;

pub trait StateAccumulator {
    fn get_witness_for_accesses(
        &self,
        accesses: &[StateKey],
    ) -> Result<alloc::vec::Vec<StateWitness>, StateError>;

    fn apply_transition(&mut self, patch: &StatePatch) -> Result<Root, StateError>;

    fn state_root(&self) -> Root;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceProofLeaf {
    pub key: StateKey,
    pub canonical_key: StateKeyBytes,
    pub leaf_value: MockProgressiveByteList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceProofPath {
    pub expected_root: Root,
    pub leaf: ReferenceProofLeaf,
    pub left_neighbor: Option<ReferenceProofLeaf>,
    pub right_neighbor: Option<ReferenceProofLeaf>,
}

impl ReferenceProofPath {
    pub fn verify_witness(
        &self,
        witness: &StateWitness,
        expected_state_root: &Root,
    ) -> Result<(), StateError> {
        if self.expected_root != *expected_state_root {
            return Err(StateError::WitnessVerificationFailed(
                "reference proof path was built against a different state root",
            ));
        }

        if self.leaf.key != witness.key {
            return Err(StateError::WitnessVerificationFailed(
                "reference proof leaf does not match witness key",
            ));
        }

        if self.leaf.leaf_value != witness.leaf_value {
            return Err(StateError::WitnessVerificationFailed(
                "reference proof leaf does not match witness value",
            ));
        }

        if let Some(left_neighbor) = &self.left_neighbor {
            if !compare_state_keys(&left_neighbor.key, &witness.key).is_lt() {
                return Err(StateError::WitnessVerificationFailed(
                    "reference proof left boundary is not ordered before the witness key",
                ));
            }
        }

        if let Some(right_neighbor) = &self.right_neighbor {
            if !compare_state_keys(&witness.key, &right_neighbor.key).is_lt() {
                return Err(StateError::WitnessVerificationFailed(
                    "reference proof right boundary is not ordered after the witness key",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredLeaf {
    key: StateKey,
    leaf_value: MockProgressiveByteList,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryAccumulator {
    leaves: BTreeMap<StateKeyBytes, StoredLeaf>,
    root: Root,
}

impl InMemoryAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn derive_proof_path(
        &self,
        witness: &StateWitness,
    ) -> Result<ReferenceProofPath, StateError> {
        if !witness.proof.is_empty() {
            return Err(StateError::UnsupportedProofShape(
                "reference backend derives proof paths locally and does not interpret committed proof bytes",
            ));
        }

        let proof_path = self.proof_path_for_access(&witness.key)?;
        proof_path.verify_witness(witness, &self.root)?;
        Ok(proof_path)
    }

    pub fn proof_path_for_access(
        &self,
        access: &StateKey,
    ) -> Result<ReferenceProofPath, StateError> {
        let canonical_key = encode_state_key(access);
        let stored_leaf = self.leaves.get(&canonical_key).ok_or(StateError::Backend(
            "reference backend only supports proof paths for materialized keys",
        ))?;

        let left_neighbor = self
            .leaves
            .range(..canonical_key.clone())
            .next_back()
            .map(|(key, leaf)| ReferenceProofLeaf::from_stored_leaf(key.clone(), leaf));

        let right_neighbor = self
            .leaves
            .range((Excluded(canonical_key.clone()), Unbounded))
            .next()
            .map(|(key, leaf)| ReferenceProofLeaf::from_stored_leaf(key.clone(), leaf));

        Ok(ReferenceProofPath {
            expected_root: self.root,
            leaf: ReferenceProofLeaf::from_stored_leaf(canonical_key, stored_leaf),
            left_neighbor,
            right_neighbor,
        })
    }

    fn apply_leaf(&mut self, key: &StateKey, value: &MockProgressiveByteList) {
        self.leaves.insert(
            encode_state_key(key),
            StoredLeaf {
                key: key.clone(),
                leaf_value: value.clone(),
            },
        );
    }

    fn recompute_root(&mut self) {
        self.root = compute_reference_root(&self.leaves);
    }
}

impl ReferenceProofLeaf {
    fn from_stored_leaf(canonical_key: StateKeyBytes, stored_leaf: &StoredLeaf) -> Self {
        Self {
            key: stored_leaf.key.clone(),
            canonical_key,
            leaf_value: stored_leaf.leaf_value.clone(),
        }
    }
}

impl StateAccumulator for InMemoryAccumulator {
    fn get_witness_for_accesses(
        &self,
        accesses: &[StateKey],
    ) -> Result<Vec<StateWitness>, StateError> {
        ensure_canonical_access_order(accesses)?;

        accesses
            .iter()
            .map(|access| {
                let proof_path = self.proof_path_for_access(access)?;
                Ok(StateWitness {
                    key: access.clone(),
                    leaf_value: proof_path.leaf.leaf_value,
                    proof: Vec::new(),
                })
            })
            .collect()
    }

    fn apply_transition(&mut self, patch: &StatePatch) -> Result<Root, StateError> {
        patch.validate_shape()?;
        ensure_canonical_access_order(&patch.accesses)?;

        for (access, new_value) in patch.accesses.iter().zip(patch.new_values.iter()) {
            self.apply_leaf(access, new_value);
        }

        self.recompute_root();
        Ok(self.root)
    }

    fn state_root(&self) -> Root {
        self.root
    }
}

impl WitnessVerifier for InMemoryAccumulator {
    fn verify_witness(
        &self,
        witness: &StateWitness,
        expected_state_root: &Root,
    ) -> Result<(), StateError> {
        let proof_path = self.derive_proof_path(witness)?;
        proof_path.verify_witness(witness, expected_state_root)
    }
}

fn ensure_canonical_access_order(accesses: &[StateKey]) -> Result<(), StateError> {
    for (index, pair) in accesses.windows(2).enumerate() {
        if !compare_state_keys(&pair[0], &pair[1]).is_lt() {
            return Err(StateError::NonCanonicalWitnessOrdering(
                WitnessOrderingError {
                    index: index + 1,
                    context: "access keys must be strictly increasing in canonical StateKey order",
                },
            ));
        }
    }

    Ok(())
}

fn compute_reference_root(leaves: &BTreeMap<StateKeyBytes, StoredLeaf>) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(b"shell-state/reference-root/v1");

    for (canonical_key, leaf) in leaves {
        hasher.update(reference_leaf_digest(canonical_key, leaf));
    }

    let digest = hasher.finalize();
    let mut root = [0; 32];
    root.copy_from_slice(&digest);
    root
}

fn reference_leaf_digest(canonical_key: &StateKeyBytes, leaf: &StoredLeaf) -> Root {
    let mut hasher = Sha256::new();
    hasher.update(b"shell-state/reference-leaf/v1");
    hasher.update((canonical_key.as_slice().len() as u32).to_be_bytes());
    hasher.update(canonical_key.as_slice());
    hasher.update((leaf.leaf_value.len() as u32).to_be_bytes());
    hasher.update(leaf.leaf_value.as_slice());

    let digest = hasher.finalize();
    let mut leaf_root = [0; 32];
    leaf_root.copy_from_slice(&digest);
    leaf_root
}
