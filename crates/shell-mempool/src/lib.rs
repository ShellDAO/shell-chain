#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod admission;
pub mod errors;
pub mod fees;
pub mod outcomes;

pub use crate::admission::{
    AdmissionPipeline, AdmissionPolicy, AdmissionStateView, AuthorizationMaterial, NoncePolicy,
    TransactionAuthorizationDomain,
};
pub use crate::errors::{
    AuthorizationMaterialCountError, FeeFloorError, NoncePolicyError, SigningRootUnavailableError,
    ValidationError,
};
pub use crate::fees::{gas_price_covers, payload_lane_fee, witness_lane_fee, FeeLane, FeeSchedule};
pub use crate::outcomes::{AuthorizationValidated, TentativeAccepted};

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec};
    use core::cell::Cell;

    use shell_crypto::{
        CryptoError, SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier,
        UnsupportedSchemeError, VerificationFailure,
    };
    use shell_primitives::{
        Authorization, BasicFeesPerGas, BasicTransactionPayload, ExecutionAddress, GasPrice,
        TransactionEnvelope, TransactionPayload, TransactionPayloadSsz, U256,
    };

    use super::*;

    struct CountingDispatcher {
        verify_calls: Cell<usize>,
        should_fail: bool,
    }

    impl CountingDispatcher {
        fn new() -> Self {
            Self {
                verify_calls: Cell::new(0),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                verify_calls: Cell::new(0),
                should_fail: true,
            }
        }

        fn verify_calls(&self) -> usize {
            self.verify_calls.get()
        }
    }

    impl SignatureDispatcher for CountingDispatcher {
        fn register_verifier(
            &mut self,
            _verifier: Box<dyn SignatureVerifier>,
        ) -> Option<Box<dyn SignatureVerifier>> {
            None
        }

        fn verifier(&self, _scheme_id: u8) -> Option<&dyn SignatureVerifier> {
            None
        }

        fn verify_transaction_authorization(
            &self,
            scheme_id: u8,
            _request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), CryptoError> {
            self.verify_calls.set(self.verify_calls.get() + 1);
            if self.should_fail {
                Err(CryptoError::VerificationFailed(VerificationFailure {
                    scheme_id,
                    context: "mock dispatcher rejected the authorization",
                }))
            } else {
                Ok(())
            }
        }

        fn verify_validator_message(
            &self,
            scheme_id: u8,
            _request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), CryptoError> {
            Err(CryptoError::UnsupportedScheme(UnsupportedSchemeError {
                scheme_id,
            }))
        }
    }

    struct FixedNonceView {
        nonce: u64,
    }

    impl AdmissionStateView for FixedNonceView {
        fn observed_nonce(&self, _envelope: &TransactionEnvelope) -> Option<u64> {
            Some(self.nonce)
        }
    }

    fn sample_policy() -> AdmissionPolicy {
        AdmissionPolicy {
            fee_schedule: FeeSchedule {
                payload_lane_base_fee: GasPrice(U256(le_u256(2))),
                witness_lane_base_fee: GasPrice(U256(le_u256(3))),
            },
            nonce_policy: NoncePolicy {
                max_future_nonce_gap: 1,
            },
            authorization_domain: TransactionAuthorizationDomain::Explicit([0x01, 0, 0, 0]),
        }
    }

    fn sample_envelope() -> TransactionEnvelope {
        let payload =
            TransactionPayloadSsz::new(TransactionPayload::Basic(BasicTransactionPayload {
                nonce: 5,
                gas_limit: 21_000,
                fees: BasicFeesPerGas {
                    regular: GasPrice(U256(le_u256(5))),
                    max_priority_fee_per_gas: GasPrice(U256(le_u256(1))),
                    max_witness_priority_fee: GasPrice(U256(le_u256(7))),
                },
                to: sample_address(0x11),
                ..Default::default()
            }));
        let payload_root = payload.hash_tree_root().expect("payload root must exist");

        TransactionEnvelope {
            payload,
            authorizations: vec![Authorization {
                scheme_id: 0,
                payload_root,
                signature: vec![0xAB; 64],
            }],
        }
    }

    fn sample_authorization_materials() -> [AuthorizationMaterial<'static>; 1] {
        static PUBLIC_KEY: [u8; 32] = [0x77; 32];
        [AuthorizationMaterial {
            public_key_material: &PUBLIC_KEY,
        }]
    }

    fn sample_address(byte: u8) -> ExecutionAddress {
        [byte; 20]
    }

    fn le_u256(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn payload_root_mismatch_rejects_before_dispatch() {
        let dispatcher = CountingDispatcher::new();
        let pipeline = AdmissionPipeline::new(&dispatcher, sample_policy());
        let mut envelope = sample_envelope();
        envelope.authorizations[0].payload_root[0] ^= 0xFF;

        let error = pipeline
            .admit_and_verify(&envelope, None, &sample_authorization_materials())
            .expect_err("payload-root mismatch should fail in T1");

        assert!(matches!(error, ValidationError::Primitive(_)));
        assert_eq!(dispatcher.verify_calls(), 0);
    }

    #[test]
    fn fee_floor_failure_rejects_before_dispatch() {
        let dispatcher = CountingDispatcher::new();
        let policy = AdmissionPolicy {
            fee_schedule: FeeSchedule {
                payload_lane_base_fee: GasPrice(U256(le_u256(9))),
                witness_lane_base_fee: GasPrice(U256(le_u256(3))),
            },
            ..sample_policy()
        };
        let pipeline = AdmissionPipeline::new(&dispatcher, policy);
        let envelope = sample_envelope();

        let error = pipeline
            .admit_and_verify(&envelope, None, &sample_authorization_materials())
            .expect_err("fee-floor failure should stop before T3");

        assert!(matches!(
            error,
            ValidationError::FeeFloor(FeeFloorError {
                lane: FeeLane::Payload,
                ..
            })
        ));
        assert_eq!(dispatcher.verify_calls(), 0);
    }

    #[test]
    fn nonce_gap_policy_rejects_future_transactions() {
        let dispatcher = CountingDispatcher::new();
        let pipeline = AdmissionPipeline::new(&dispatcher, sample_policy());
        let envelope = sample_envelope();
        let view = FixedNonceView { nonce: 2 };

        let error = pipeline
            .screen_transaction(&envelope, Some(&view))
            .expect_err("future nonce beyond the configured gap should fail");

        assert!(matches!(error, ValidationError::NoncePolicy(_)));
    }

    #[test]
    fn explicit_domain_enables_signature_dispatch_after_t1_t2() {
        let dispatcher = CountingDispatcher::new();
        let pipeline = AdmissionPipeline::new(&dispatcher, sample_policy());
        let envelope = sample_envelope();

        let accepted = pipeline
            .screen_transaction(&envelope, None)
            .expect("T1/T2 should accept the sample transaction");
        let authorized = pipeline
            .verify_authorizations(&envelope, &accepted, &sample_authorization_materials())
            .expect("explicit domain bytes should allow T3 dispatch");

        assert_eq!(authorized.payload_root, accepted.payload_root);
        assert_eq!(authorized.verified_authorization_count, 1);
        assert_eq!(dispatcher.verify_calls(), 1);
    }

    #[test]
    fn pending_domain_fails_before_signature_dispatch() {
        let dispatcher = CountingDispatcher::new();
        let mut policy = sample_policy();
        policy.authorization_domain = TransactionAuthorizationDomain::Pending;
        let pipeline = AdmissionPipeline::new(&dispatcher, policy);
        let envelope = sample_envelope();

        let accepted = pipeline
            .screen_transaction(&envelope, None)
            .expect("T1/T2 should still accept");
        let error = pipeline
            .verify_authorizations(&envelope, &accepted, &sample_authorization_materials())
            .expect_err("pending domain must stay explicit");

        assert!(matches!(error, ValidationError::SigningRootUnavailable(_)));
        assert_eq!(dispatcher.verify_calls(), 0);
    }

    #[test]
    fn cryptographic_failures_are_normalized_at_t3() {
        let dispatcher = CountingDispatcher::with_failure();
        let pipeline = AdmissionPipeline::new(&dispatcher, sample_policy());
        let envelope = sample_envelope();

        let accepted = pipeline
            .screen_transaction(&envelope, None)
            .expect("T1/T2 should accept");
        let error = pipeline
            .verify_authorizations(&envelope, &accepted, &sample_authorization_materials())
            .expect_err("dispatcher failures must reject");

        assert!(matches!(error, ValidationError::SignatureVerification(_)));
        assert_eq!(dispatcher.verify_calls(), 1);
    }
}
