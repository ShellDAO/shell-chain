#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod accumulator;
pub mod errors;
pub mod keys;
pub mod transition;
pub mod views;
pub mod witness;

pub use crate::accumulator::StateAccumulator;
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

    use super::*;
    use shell_primitives::{ExecutionAddress, Root, U256};

    struct StubAccumulator {
        root: Root,
    }

    impl StateAccumulator for StubAccumulator {
        fn get_witness_for_accesses(
            &self,
            _accesses: &[StateKey],
        ) -> Result<alloc::vec::Vec<StateWitness>, StateError> {
            Ok(alloc::vec::Vec::new())
        }

        fn apply_transition(&mut self, patch: &StatePatch) -> Result<Root, StateError> {
            patch.validate_shape()?;
            self.root = [9; 32];
            Ok(self.root)
        }

        fn state_root(&self) -> Root {
            self.root
        }
    }

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
        let _: Box<dyn StateAccumulator> = Box::new(StubAccumulator { root: [0; 32] });
    }
}
