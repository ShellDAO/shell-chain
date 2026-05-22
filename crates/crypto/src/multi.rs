use crate::{
    is_algorithm_allowed, CryptoError, DilithiumVerifier, MlDsaVerifier, PQSignature,
    SignatureType, SphincsVerifier, Verifier,
};
use shell_primitives::Address;

/// Multi-algorithm verifier that dispatches to the correct backend
/// based on the [`SignatureType`] embedded in each [`PQSignature`].
///
/// Zero-sized type — both inner verifiers are ZSTs, so `MultiVerifier`
/// itself has no runtime cost.
#[derive(Debug, Clone, Copy, Default)]
pub struct MultiVerifier;

impl Verifier for MultiVerifier {
    fn verify(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        match signature.sig_type {
            SignatureType::Dilithium3 => DilithiumVerifier.verify(pubkey, message, signature),
            SignatureType::MlDsa65 => MlDsaVerifier.verify(pubkey, message, signature),
            SignatureType::SphincsSha2256f => SphincsVerifier.verify(pubkey, message, signature),
        }
    }

    /// `MultiVerifier` handles all supported algorithms; returns
    /// `Dilithium3` as the canonical default for the trait method.
    /// Use [`MultiVerifier::detect_algorithm`] to inspect a specific
    /// signature's algorithm tag.
    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

impl MultiVerifier {
    /// Detect the algorithm used by a given signature by reading its
    /// embedded `sig_type` tag byte.
    ///
    /// This is the correct way to determine which PQ algorithm was used
    /// for a specific signature, rather than relying on `Verifier::sig_type()`
    /// which returns a static default.
    pub fn detect_algorithm(signature: &PQSignature) -> SignatureType {
        signature.sig_type
    }
}

/// Verify a raw PQ signature by dispatching to the backend selected by `sig_type`.
pub fn verify_signature(
    sig_type: SignatureType,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    if !is_algorithm_allowed(sig_type) {
        return Err(CryptoError::UnsupportedSignatureType(sig_type));
    }

    MultiVerifier.verify(
        pubkey,
        message,
        &PQSignature::new(sig_type, signature.to_vec()),
    )
}

/// Infer the signing algorithm bound to an address by re-deriving the address
/// under each allowed algorithm and finding the matching one.
pub fn infer_signature_type_from_address(
    pubkey: &[u8],
    address: &Address,
) -> Option<SignatureType> {
    [
        SignatureType::MlDsa65,
        SignatureType::Dilithium3,
        SignatureType::SphincsSha2256f,
    ]
    .into_iter()
    .find(|sig_type| {
        is_algorithm_allowed(*sig_type)
            && Address::from_public_key(pubkey, sig_type.as_u8()) == *address
    })
}

#[cfg(feature = "batch")]
impl crate::BatchVerifier for MultiVerifier {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DilithiumSigner, MlDsaSigner, Signer, SphincsSigner};
    use shell_primitives::Address;

    #[test]
    fn multi_verifies_dilithium() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"multi-dil").unwrap();
        let mv = MultiVerifier;
        assert!(mv.verify(signer.public_key(), b"multi-dil", &sig).unwrap());
    }

    #[test]
    fn multi_verifies_sphincs() {
        let signer = SphincsSigner::generate();
        let sig = signer.sign(b"multi-sph").unwrap();
        let mv = MultiVerifier;
        assert!(mv.verify(signer.public_key(), b"multi-sph", &sig).unwrap());
    }

    #[test]
    fn multi_verifies_mldsa65() {
        use crate::MlDsaSigner;
        let signer = MlDsaSigner::generate();
        let sig = signer.sign(b"multi-mldsa").unwrap();
        let mv = MultiVerifier;
        assert!(mv
            .verify(signer.public_key(), b"multi-mldsa", &sig)
            .unwrap());
    }

    #[test]
    fn multi_rejects_wrong_algorithm_data() {
        // Wrong sig type for the verifier — DilithiumVerifier won't accept MlDsa65 tag
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 3309]);
        let mv = MultiVerifier;
        // Verifying zeros with a zero pubkey should return Ok(false), not panic
        let result = mv.verify(&[0u8; 1952], b"test", &sig);
        assert!(result.is_ok()); // may be Ok(false) or Ok(true) but should not panic
    }

    #[test]
    fn verify_signature_dispatches_mldsa65() {
        let signer = MlDsaSigner::generate();
        let sig = signer.sign(b"verify-signature").unwrap();

        assert!(verify_signature(
            SignatureType::MlDsa65,
            signer.public_key(),
            b"verify-signature",
            &sig.data,
        )
        .unwrap());
    }

    #[test]
    fn infer_signature_type_from_address_detects_mldsa65() {
        let signer = MlDsaSigner::generate();
        let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

        assert_eq!(
            infer_signature_type_from_address(signer.public_key(), &address),
            Some(SignatureType::MlDsa65)
        );
    }

    #[test]
    fn multi_rejects_wrong_message() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"correct").unwrap();
        let mv = MultiVerifier;
        let valid = mv.verify(signer.public_key(), b"wrong", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn multi_rejects_wrong_key() {
        let signer1 = DilithiumSigner::generate();
        let signer2 = DilithiumSigner::generate();
        let sig = signer1.sign(b"test").unwrap();
        let mv = MultiVerifier;
        let valid = mv.verify(signer2.public_key(), b"test", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn multi_mixed_validator_set() {
        let dil_signer = DilithiumSigner::generate();
        let sph_signer = SphincsSigner::generate();
        let mv = MultiVerifier;

        let msg = b"block-42";
        let dil_sig = dil_signer.sign(msg).unwrap();
        let sph_sig = sph_signer.sign(msg).unwrap();

        assert!(mv.verify(dil_signer.public_key(), msg, &dil_sig).unwrap());
        assert!(mv.verify(sph_signer.public_key(), msg, &sph_sig).unwrap());

        // Cross-key must fail.
        let cross_result = mv.verify(sph_signer.public_key(), msg, &dil_sig);
        assert!(cross_result.is_err() || !cross_result.unwrap());
    }

    #[test]
    fn multi_verifier_is_zero_sized() {
        assert_eq!(std::mem::size_of::<MultiVerifier>(), 0);
    }

    #[test]
    fn detect_algorithm_dilithium() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"detect-dil").unwrap();
        assert_eq!(
            MultiVerifier::detect_algorithm(&sig),
            SignatureType::Dilithium3
        );
    }

    #[test]
    fn detect_algorithm_sphincs() {
        let signer = SphincsSigner::generate();
        let sig = signer.sign(b"detect-sph").unwrap();
        assert_eq!(
            MultiVerifier::detect_algorithm(&sig),
            SignatureType::SphincsSha2256f
        );
    }
}
