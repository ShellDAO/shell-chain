#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod accumulator;
pub mod errors;
pub mod keys;
pub mod transition;
pub mod views;
pub mod witness;

pub use crate::accumulator::{
    InMemoryAccumulator, ReferenceProofLeaf, ReferenceProofPath, StateAccumulator,
};
pub use crate::errors::{StateError, WitnessOrderingError};
pub use crate::keys::{
    canonicalize_execution_address, compare_state_keys, encode_state_key, StateKeyBytes,
};
pub use crate::transition::{StatePatch, StateTransitionApplier, StateTransitionOutcome};
pub use crate::views::{MetadataAdapter, ReadOnlyStateView};
pub use crate::witness::{ensure_canonical_witness_order, WitnessVerifier};
pub use shell_primitives::{StateKey, StateMetadata, StateWitness};

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;
    use shell_primitives::{ExecutionAddress, U256};

    struct StubView;

    impl ReadOnlyStateView for StubView {
        fn account_nonce(&self, _address: &ExecutionAddress) -> Option<u64> {
            Some(7)
        }

        fn account_balance(&self, _address: &ExecutionAddress) -> Option<U256> {
            Some(U256([3; 32]))
        }
    }

    #[test]
    fn canonicalize_execution_address_left_pads_to_bytes32() {
        let address: ExecutionAddress = [0x11; 20];
        let key = canonicalize_execution_address(&address);

        assert_eq!(&key[..12], &[0; 12]);
        assert_eq!(&key[12..], &address);
    }

    #[test]
    fn encoded_state_key_uses_stable_variant_tags() {
        let first = encode_state_key(&StateKey::AccountHeader([0; 20]));
        let second = encode_state_key(&StateKey::RawTreeKey([0; 32]));

        assert_eq!(first.as_slice()[0], 0);
        assert_eq!(second.as_slice()[0], 3);
        assert!(compare_state_keys(
            &StateKey::AccountHeader([0; 20]),
            &StateKey::RawTreeKey([0; 32]),
        )
        .is_lt());
    }

    #[test]
    fn witness_ordering_rejects_non_canonical_sequences() {
        let witnesses = [
            StateWitness {
                key: StateKey::RawTreeKey([0xFF; 32]),
                leaf_value: alloc::vec::Vec::new(),
                proof: alloc::vec::Vec::new(),
            },
            StateWitness {
                key: StateKey::RawTreeKey([0x00; 32]),
                leaf_value: alloc::vec::Vec::new(),
                proof: alloc::vec::Vec::new(),
            },
        ];

        let err = ensure_canonical_witness_order(&witnesses)
            .expect_err("descending witnesses must fail before proof work");

        assert_eq!(
            err,
            StateError::NonCanonicalWitnessOrdering(WitnessOrderingError {
                index: 1,
                context: "witness keys must be strictly increasing in canonical StateKey order",
            })
        );
    }

    #[test]
    fn state_patch_requires_matching_access_and_value_counts() {
        let err = StatePatch {
            accesses: alloc::vec![StateKey::RawTreeKey([0; 32])],
            new_values: alloc::vec![],
        }
        .validate_shape()
        .expect_err("patch entries should stay aligned");

        assert_eq!(
            err,
            StateError::TransitionShapeMismatch {
                accesses: 1,
                new_values: 0
            }
        );
    }

    #[test]
    fn metadata_adapter_implements_shared_primitives_trait() {
        let adapter = MetadataAdapter::new(StubView);
        let lookup: &dyn StateMetadata = &adapter;
        let address: ExecutionAddress = [0xAA; 20];

        assert_eq!(lookup.account_nonce(&address), Some(7));
        assert_eq!(lookup.account_balance(&address), Some(U256([3; 32])));
    }

    #[test]
    fn accumulator_trait_is_object_safe() {
        let _: Box<dyn StateAccumulator> = Box::new(InMemoryAccumulator::new());
    }

    #[test]
    fn in_memory_accumulator_rejects_non_canonical_access_sequences() {
        let mut accumulator = InMemoryAccumulator::new();
        let address: ExecutionAddress = [0xAB; 20];
        let low_key = StateKey::AccountHeader(address);
        let high_key = StateKey::StorageSlot {
            address,
            slot: [0xFF; 32],
        };

        accumulator
            .apply_transition(&StatePatch {
                accesses: vec![low_key.clone(), high_key.clone()],
                new_values: vec![vec![1], vec![2]],
            })
            .expect("canonical transition must apply");

        let err = accumulator
            .get_witness_for_accesses(&[high_key, low_key])
            .expect_err("descending access list must be rejected before proof shaping");

        assert_eq!(
            err,
            StateError::NonCanonicalWitnessOrdering(WitnessOrderingError {
                index: 1,
                context: "access keys must be strictly increasing in canonical StateKey order",
            })
        );
    }

    #[test]
    fn in_memory_accumulator_keeps_committed_witnesses_separate_from_derived_proof_paths() {
        let address: ExecutionAddress = [0x22; 20];
        let first_key = StateKey::AccountHeader(address);
        let second_key = StateKey::StorageSlot {
            address,
            slot: [0x10; 32],
        };
        let mut accumulator = InMemoryAccumulator::new();

        let first_root = accumulator
            .apply_transition(&StatePatch {
                accesses: vec![first_key.clone(), second_key.clone()],
                new_values: vec![vec![1, 2, 3], vec![4, 5, 6]],
            })
            .expect("canonical transition must produce a reference root");

        let witnesses = accumulator
            .get_witness_for_accesses(&[first_key.clone(), second_key.clone()])
            .expect("canonical accesses must materialize committed witnesses");

        assert_eq!(witnesses.len(), 2);
        assert!(witnesses.iter().all(|witness| witness.proof.is_empty()));
        assert_eq!(witnesses[1].leaf_value, vec![4, 5, 6]);

        let derived = accumulator
            .derive_proof_path(&witnesses[1])
            .expect("reference backend should derive a local proof path");

        assert_eq!(derived.expected_root, first_root);
        assert_eq!(derived.leaf.key, second_key);
        assert_eq!(
            derived
                .left_neighbor
                .as_ref()
                .expect("neighbor on the left should exist")
                .key,
            first_key
        );
        assert!(derived.right_neighbor.is_none());

        accumulator
            .verify_witness(&witnesses[1], &accumulator.state_root())
            .expect("derived proof path should verify against the current reference root");
    }

    #[test]
    fn in_memory_accumulator_reference_root_changes_with_transition_contents() {
        let address: ExecutionAddress = [0x44; 20];
        let mut accumulator = InMemoryAccumulator::new();
        let key = StateKey::CodeChunk {
            address,
            chunk_index: 7,
        };

        let root_before = accumulator.state_root();
        let root_after_first = accumulator
            .apply_transition(&StatePatch {
                accesses: vec![key.clone()],
                new_values: vec![vec![9, 9]],
            })
            .expect("first transition should update the root");
        let root_after_second = accumulator
            .apply_transition(&StatePatch {
                accesses: vec![key],
                new_values: vec![vec![9, 9, 9]],
            })
            .expect("updated leaf value should change the root again");

        assert_ne!(root_before, root_after_first);
        assert_ne!(root_after_first, root_after_second);
    }
}
