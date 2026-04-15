use pqcrypto_sphincsplus::sphincssha2256fsimple;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::{CryptoError, KeyPair, PQSignature, SignatureType, Signer, Verifier};

// ── Signer ───────────────────────────────────────────────────

/// SPHINCS+-SHA2-256f-simple signer (256-bit PQ security, stateless hash-based).
///
/// Stores key material as raw bytes wrapped in `Zeroizing` to ensure
/// secret key is zeroed on drop.
pub struct SphincsSigner {
    secret_key_bytes: zeroize::Zeroizing<Vec<u8>>,
    public_key_bytes: Vec<u8>,
}

impl SphincsSigner {
    /// Generate a fresh SPHINCS+-SHA2-256f-simple key pair.
    ///
    /// Uses `pqcrypto-sphincsplus`'s internal CSPRNG.
    pub fn generate() -> Self {
        let (pk, sk) = sphincssha2256fsimple::keypair();
        Self {
            secret_key_bytes: zeroize::Zeroizing::new(sk.as_bytes().to_vec()),
            public_key_bytes: pk.as_bytes().to_vec(),
        }
    }

    /// Reconstruct from raw key bytes.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        sphincssha2256fsimple::PublicKey::from_bytes(public_key).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: sphincssha2256fsimple::public_key_bytes(),
                got: public_key.len(),
            }
        })?;
        sphincssha2256fsimple::SecretKey::from_bytes(secret_key).map_err(|_| {
            CryptoError::InvalidSecretKeyLength {
                expected: sphincssha2256fsimple::secret_key_bytes(),
                got: secret_key.len(),
            }
        })?;
        Ok(Self {
            secret_key_bytes: zeroize::Zeroizing::new(secret_key.to_vec()),
            public_key_bytes: public_key.to_vec(),
        })
    }

    /// Export the public half as a [`KeyPair`].
    pub fn key_pair(&self) -> KeyPair {
        KeyPair::new(
            self.public_key_bytes.clone(),
            SignatureType::SphincsSha2256f,
        )
    }

    /// Return a reference to the zeroize-protected secret key bytes.
    ///
    /// Returns `&Zeroizing<Vec<u8>>` rather than raw `&[u8]` so the
    /// caller cannot accidentally copy the bytes out of the zeroize
    /// wrapper. Use `Deref` / `AsRef` when `&[u8]` is needed briefly.
    pub fn secret_key_bytes(&self) -> &zeroize::Zeroizing<Vec<u8>> {
        &self.secret_key_bytes
    }

    fn secret_key(&self) -> sphincssha2256fsimple::SecretKey {
        sphincssha2256fsimple::SecretKey::from_bytes(&self.secret_key_bytes)
            .unwrap_or_else(|_| unreachable!("secret key bytes validated at construction"))
    }
}

impl Signer for SphincsSigner {
    fn sign(&self, message: &[u8]) -> Result<PQSignature, CryptoError> {
        let sk = self.secret_key();
        let sig = sphincssha2256fsimple::detached_sign(message, &sk);
        // Explicitly consume the temporary SecretKey. The canonical key material
        // is held in `self.secret_key_bytes` which is wrapped in `Zeroizing`
        // and will be securely erased when this signer is dropped.
        let _ = sk;
        Ok(PQSignature::new(
            SignatureType::SphincsSha2256f,
            sig.as_bytes().to_vec(),
        ))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::SphincsSha2256f
    }
}

// ── Verifier ─────────────────────────────────────────────────

/// Stateless SPHINCS+-SHA2-256f-simple verifier (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct SphincsVerifier;

impl Verifier for SphincsVerifier {
    fn verify(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        if signature.sig_type != SignatureType::SphincsSha2256f {
            return Err(CryptoError::UnsupportedSignatureType(signature.sig_type));
        }

        let pk = sphincssha2256fsimple::PublicKey::from_bytes(pubkey).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: sphincssha2256fsimple::public_key_bytes(),
                got: pubkey.len(),
            }
        })?;

        let sig = sphincssha2256fsimple::DetachedSignature::from_bytes(&signature.data).map_err(
            |_| CryptoError::InvalidSignatureLength {
                expected: sphincssha2256fsimple::signature_bytes(),
                got: signature.data.len(),
            },
        )?;

        let valid = sphincssha2256fsimple::verify_detached_signature(&sig, message, &pk).is_ok();
        Ok(valid)
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::SphincsSha2256f
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DilithiumSigner, DilithiumVerifier};

    #[test]
    fn generate_and_sign_verify() {
        let signer = SphincsSigner::generate();
        let message = b"hello shell-chain sphincs";

        let sig = signer.sign(message).unwrap();
        assert_eq!(sig.sig_type, SignatureType::SphincsSha2256f);
        assert!(!sig.is_empty());

        let verifier = SphincsVerifier;
        let valid = verifier.verify(signer.public_key(), message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_wrong_message_fails() {
        let signer = SphincsSigner::generate();
        let sig = signer.sign(b"correct message").unwrap();

        let verifier = SphincsVerifier;
        let valid = verifier
            .verify(signer.public_key(), b"wrong message", &sig)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_wrong_key_fails() {
        let signer1 = SphincsSigner::generate();
        let signer2 = SphincsSigner::generate();
        let sig = signer1.sign(b"test").unwrap();

        let verifier = SphincsVerifier;
        let valid = verifier
            .verify(signer2.public_key(), b"test", &sig)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = SphincsSigner::generate();
        let pk = signer.public_key().to_vec();
        let sk = signer.secret_key_bytes.to_vec();

        let signer2 = SphincsSigner::from_bytes(&pk, &sk).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());

        let sig = signer2.sign(b"roundtrip").unwrap();
        let verifier = SphincsVerifier;
        assert!(verifier.verify(&pk, b"roundtrip", &sig).unwrap());
    }

    #[test]
    fn corrupted_signature_fails() {
        let signer = SphincsSigner::generate();
        let mut sig = signer.sign(b"test").unwrap();

        // Flip a byte in the middle of the signature
        let mid = sig.data.len() / 2;
        sig.data[mid] ^= 0xff;

        let verifier = SphincsVerifier;
        let valid = verifier.verify(signer.public_key(), b"test", &sig).unwrap();
        assert!(!valid);
    }

    #[test]
    fn cross_algorithm_rejection_dilithium_sig_on_sphincs_verifier() {
        let dil_signer = DilithiumSigner::generate();
        let dil_sig = dil_signer.sign(b"cross-algo test").unwrap();

        let sphincs_verifier = SphincsVerifier;
        let result = sphincs_verifier.verify(dil_signer.public_key(), b"cross-algo test", &dil_sig);
        assert!(
            result.is_err(),
            "SPHINCS+ verifier must reject Dilithium signatures"
        );
    }

    #[test]
    fn cross_algorithm_rejection_sphincs_sig_on_dilithium_verifier() {
        let sphincs_signer = SphincsSigner::generate();
        let sphincs_sig = sphincs_signer.sign(b"cross-algo test").unwrap();

        let dil_verifier = DilithiumVerifier;
        let result = dil_verifier.verify(
            sphincs_signer.public_key(),
            b"cross-algo test",
            &sphincs_sig,
        );
        assert!(
            result.is_err(),
            "Dilithium verifier must reject SPHINCS+ signatures"
        );
    }

    #[test]
    fn signature_size_check() {
        let sphincs_signer = SphincsSigner::generate();
        let dil_signer = DilithiumSigner::generate();

        let sphincs_sig = sphincs_signer.sign(b"size check").unwrap();
        let dil_sig = dil_signer.sign(b"size check").unwrap();

        // SPHINCS+-SHA2-256f signatures are ~49856 bytes (~49KB)
        // Dilithium3 signatures are ~3293 bytes (~3KB)
        assert!(
            sphincs_sig.len() > 10_000,
            "SPHINCS+ sig should be large (got {} bytes)",
            sphincs_sig.len()
        );
        assert!(
            dil_sig.len() < 5_000,
            "Dilithium sig should be small (got {} bytes)",
            dil_sig.len()
        );
        assert!(
            sphincs_sig.len() > dil_sig.len() * 3,
            "SPHINCS+ sig ({}) should be significantly larger than Dilithium ({})",
            sphincs_sig.len(),
            dil_sig.len()
        );
    }

    #[test]
    fn sphincs_verifier_is_zero_sized() {
        assert_eq!(std::mem::size_of::<SphincsVerifier>(), 0);
    }

    #[test]
    fn invalid_pubkey_length() {
        let verifier = SphincsVerifier;
        let bad_sig = PQSignature::new(SignatureType::SphincsSha2256f, vec![0u8; 100]);
        let result = verifier.verify(&[0u8; 10], b"test", &bad_sig);
        assert!(result.is_err());
    }
}
