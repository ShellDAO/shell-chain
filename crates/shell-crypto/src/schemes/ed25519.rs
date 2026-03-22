use crate::errors::VerificationFailure;
use crate::traits::{SignatureVerificationRequest, SignatureVerifier, VerificationPath};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Scheme ID for Ed25519.
/// This matches the conservative reference path choice.
pub const SCHEME_ID_ED25519: u8 = 0;

/// A concrete verifier for Ed25519 signatures.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn scheme_id(&self) -> u8 {
        SCHEME_ID_ED25519
    }

    fn max_signature_size(&self, _path: VerificationPath) -> Option<usize> {
        // Ed25519 signatures are fixed 64 bytes.
        Some(Signature::BYTE_SIZE)
    }

    fn verify(
        &self,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), VerificationFailure> {
        // 1. Parse Public Key
        let public_key_bytes: [u8; 32] =
            request
                .public_key_material
                .try_into()
                .map_err(|_| VerificationFailure {
                    scheme_id: self.scheme_id(),
                    context: "Invalid public key length",
                })?;

        let public_key =
            VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| VerificationFailure {
                scheme_id: self.scheme_id(),
                context: "Malformed public key",
            })?;

        // 2. Parse Signature
        let signature =
            Signature::from_slice(request.signature).map_err(|_| VerificationFailure {
                scheme_id: self.scheme_id(),
                context: "Invalid signature length or encoding",
            })?;

        // 3. Verify
        public_key
            .verify(&request.signing_root, &signature)
            .map_err(|_| VerificationFailure {
                scheme_id: self.scheme_id(),
                context: "Signature verification failed",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_ed25519_verification_success() {
        let signing_key_bytes = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let message = [0u8; 32]; // specific root
        let signature = signing_key.sign(&message);

        let verifier = Ed25519Verifier::new();
        let request = SignatureVerificationRequest {
            public_key_material: verifying_key.as_bytes(),
            signing_root: message,
            signature: &signature.to_bytes(),
        };

        assert!(verifier.verify(&request).is_ok());
    }

    #[test]
    fn test_ed25519_verification_failure_bad_sig() {
        let signing_key_bytes = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let message = [0u8; 32];
        let signature = signing_key.sign(&message);

        let verifier = Ed25519Verifier::new();
        let mut invalid_signature = signature.to_bytes();
        invalid_signature[0] ^= 0xFF; // Corrupt signature

        let request = SignatureVerificationRequest {
            public_key_material: verifying_key.as_bytes(),
            signing_root: message,
            signature: &invalid_signature,
        };

        assert!(verifier.verify(&request).is_err());
    }

    #[test]
    fn test_ed25519_verification_failure_bad_key() {
        let signing_key_bytes = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let message = [0u8; 32];
        let signature = signing_key.sign(&message);

        let verifier = Ed25519Verifier::new();
        let invalid_key = [0u8; 32]; // Not the key used for signing

        let request = SignatureVerificationRequest {
            public_key_material: &invalid_key,
            signing_root: message,
            signature: &signature.to_bytes(),
        };

        // It might fail parsing (unlikely for random bytes) or verification
        // But with all zeros it might parse but fail verification
        assert!(verifier.verify(&request).is_err());
    }
}
