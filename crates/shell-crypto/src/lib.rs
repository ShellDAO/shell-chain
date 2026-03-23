#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod dispatch;
pub mod errors;
pub mod schemes;
pub mod traits;

pub use crate::dispatch::{DispatcherConfig, VerifierRegistry};
pub use crate::errors::{
    CryptoError, SignatureSizeExceededError, UnsupportedSchemeError, VerificationFailure,
};
pub use crate::schemes::DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE;
pub use crate::schemes::{Ed25519Verifier, SCHEME_ID_ED25519};
pub use crate::traits::{
    SignatureDispatcher, SignatureVerificationRequest, SignatureVerifier, VerificationPath,
};

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec};

    use super::*;
    use shell_primitives::Root;

    struct MockVerifier {
        scheme_id: u8,
        max_user_size: Option<usize>,
        max_validator_size: Option<usize>,
        should_fail: bool,
    }

    impl SignatureVerifier for MockVerifier {
        fn scheme_id(&self) -> u8 {
            self.scheme_id
        }

        fn max_signature_size(&self, path: VerificationPath) -> Option<usize> {
            match path {
                VerificationPath::TransactionAuthorization => self.max_user_size,
                VerificationPath::ValidatorMessage => self.max_validator_size,
            }
        }

        fn verify(
            &self,
            _request: &SignatureVerificationRequest<'_>,
        ) -> Result<(), VerificationFailure> {
            if self.should_fail {
                Err(VerificationFailure {
                    scheme_id: self.scheme_id,
                    context: "mock verifier rejected the artifact",
                })
            } else {
                Ok(())
            }
        }
    }

    fn sample_request(signature_len: usize) -> SignatureVerificationRequest<'static> {
        static PUBLIC_KEY: [u8; 32] = [7; 32];
        SignatureVerificationRequest {
            public_key_material: &PUBLIC_KEY,
            signing_root: Root::default(),
            signature: Box::leak(vec![1; signature_len].into_boxed_slice()),
        }
    }

    #[test]
    fn registry_rejects_unknown_schemes() {
        let registry = VerifierRegistry::default();
        let err = registry
            .verify_transaction_authorization(11, &sample_request(64))
            .expect_err("unknown scheme should fail fast");

        assert_eq!(
            err,
            CryptoError::UnsupportedScheme(UnsupportedSchemeError { scheme_id: 11 })
        );
    }

    #[test]
    fn user_path_limit_is_enforced_before_verification() {
        let mut registry = VerifierRegistry::default();
        registry.register_verifier(Box::new(MockVerifier {
            scheme_id: 1,
            max_user_size: Some(DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE * 2),
            max_validator_size: None,
            should_fail: false,
        }));

        let err = registry
            .verify_transaction_authorization(
                1,
                &sample_request(DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE + 1),
            )
            .expect_err("user-path signatures above 8 KiB stay rejected");

        assert_eq!(
            err,
            CryptoError::SignatureSizeExceeded(SignatureSizeExceededError {
                max_size: DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE,
                actual_size: DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE + 1,
                path: VerificationPath::TransactionAuthorization,
            })
        );
    }

    #[test]
    fn validator_path_uses_configurable_guards() {
        let mut registry = VerifierRegistry::with_config(DispatcherConfig {
            user_path_max_signature_size: DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE,
            validator_path_max_signature_size: Some(128),
        });
        registry.register_verifier(Box::new(MockVerifier {
            scheme_id: 9,
            max_user_size: None,
            max_validator_size: Some(256),
            should_fail: false,
        }));

        let err = registry
            .verify_validator_message(9, &sample_request(129))
            .expect_err("configured validator transport guard should be honored");

        assert_eq!(
            err,
            CryptoError::SignatureSizeExceeded(SignatureSizeExceededError {
                max_size: 128,
                actual_size: 129,
                path: VerificationPath::ValidatorMessage,
            })
        );
    }

    #[test]
    fn verifier_failures_are_normalized() {
        let mut registry = VerifierRegistry::default();
        registry.register_verifier(Box::new(MockVerifier {
            scheme_id: 3,
            max_user_size: None,
            max_validator_size: None,
            should_fail: true,
        }));

        let err = registry
            .verify_transaction_authorization(3, &sample_request(64))
            .expect_err("mock failure should propagate through a stable error type");

        assert_eq!(
            err,
            CryptoError::VerificationFailed(VerificationFailure {
                scheme_id: 3,
                context: "mock verifier rejected the artifact",
            })
        );
    }

    #[test]
    fn verifier_trait_is_object_safe() {
        let _: Box<dyn SignatureVerifier> = Box::new(MockVerifier {
            scheme_id: 5,
            max_user_size: None,
            max_validator_size: None,
            should_fail: false,
        });
    }
}
