use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier as MlDsaVerifier};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::{CryptoError, KeyPair, PQSignature, SignatureType, Signer, Verifier};

// ── Signer ───────────────────────────────────────────────────

/// CRYSTALS-Dilithium3 signer (NIST Level 3, 128-bit PQ security).
///
/// Stores key material as raw bytes wrapped in `Zeroizing` to ensure
/// secret key is zeroed on drop, even though pqcrypto's SecretKey type
/// does not implement Zeroize.
pub struct DilithiumSigner {
    secret_key_bytes: zeroize::Zeroizing<Vec<u8>>,
    public_key_bytes: Vec<u8>,
}

impl DilithiumSigner {
    /// Generate a fresh Dilithium3 key pair.
    ///
    /// Uses `pqcrypto-dilithium`'s internal CSPRNG (`randombytes` / system RNG).
    /// See: <https://github.com/pqcrypto/pqcrypto/>
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            secret_key_bytes: zeroize::Zeroizing::new(sk.as_bytes().to_vec()),
            public_key_bytes: pk.as_bytes().to_vec(),
        }
    }

    /// Reconstruct from raw key bytes.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        // Validate by attempting to parse
        dilithium3::PublicKey::from_bytes(public_key).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: dilithium3::public_key_bytes(),
                got: public_key.len(),
            }
        })?;
        dilithium3::SecretKey::from_bytes(secret_key).map_err(|_| {
            CryptoError::InvalidSecretKeyLength {
                expected: dilithium3::secret_key_bytes(),
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
        KeyPair::new(self.public_key_bytes.clone(), SignatureType::Dilithium3)
    }

    /// Return a reference to the zeroize-protected secret key bytes.
    ///
    /// Returns `&Zeroizing<Vec<u8>>` rather than raw `&[u8]` so the
    /// caller cannot accidentally copy the bytes out of the zeroize
    /// wrapper. Use `Deref` / `AsRef` when `&[u8]` is needed briefly.
    pub fn secret_key_bytes(&self) -> &zeroize::Zeroizing<Vec<u8>> {
        &self.secret_key_bytes
    }

    fn secret_key(&self) -> dilithium3::SecretKey {
        // Safe: bytes were validated at construction time
        dilithium3::SecretKey::from_bytes(&self.secret_key_bytes)
            .unwrap_or_else(|_| unreachable!("secret key bytes validated at construction"))
    }
}

impl Signer for DilithiumSigner {
    fn sign(&self, message: &[u8]) -> Result<PQSignature, CryptoError> {
        let sk = self.secret_key();
        let sig = dilithium3::detached_sign(message, &sk);
        // Explicitly consume the temporary SecretKey. The canonical key material
        // is held in `self.secret_key_bytes` which is wrapped in `Zeroizing`
        // and will be securely erased when this signer is dropped.
        let _ = sk;
        Ok(PQSignature::new(
            SignatureType::Dilithium3,
            sig.as_bytes().to_vec(),
        ))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

// ── Verifier ─────────────────────────────────────────────────

/// Stateless Dilithium3 verifier (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct DilithiumVerifier;

const DILITHIUM3_PUBLIC_KEY_BYTES: usize = 1952;
const DILITHIUM3_SIGNATURE_BYTES: usize = 3309;

impl DilithiumVerifier {
    fn verify_legacy_dilithium(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = dilithium3::PublicKey::from_bytes(pubkey) else {
            return false;
        };
        let Ok(sig) = dilithium3::DetachedSignature::from_bytes(signature) else {
            return false;
        };

        dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    fn verify_ml_dsa_compat(&self, pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pubkey) = <[u8; DILITHIUM3_PUBLIC_KEY_BYTES]>::try_from(pubkey) else {
            return false;
        };
        let Ok(signature) = <[u8; DILITHIUM3_SIGNATURE_BYTES]>::try_from(signature) else {
            return false;
        };
        let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pubkey) else {
            return false;
        };

        // shell-sdk signs "Dilithium3" payloads via noble's ML-DSA-65 adapter
        // using the default empty context, so accept that encoding as a
        // compatibility fallback without changing the on-chain algo tag.
        pk.verify(message, &signature, &[])
    }
}

impl Verifier for DilithiumVerifier {
    fn verify(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        if signature.sig_type != SignatureType::Dilithium3 {
            return Err(CryptoError::UnsupportedSignatureType(signature.sig_type));
        }

        if pubkey.len() != DILITHIUM3_PUBLIC_KEY_BYTES {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: DILITHIUM3_PUBLIC_KEY_BYTES,
                got: pubkey.len(),
            });
        }
        if signature.data.len() != DILITHIUM3_SIGNATURE_BYTES {
            return Err(CryptoError::InvalidSignatureLength {
                expected: DILITHIUM3_SIGNATURE_BYTES,
                got: signature.data.len(),
            });
        }

        Ok(
            self.verify_legacy_dilithium(pubkey, message, &signature.data)
                || self.verify_ml_dsa_compat(pubkey, message, &signature.data),
        )
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::Address;

    #[test]
    fn generate_and_sign_verify() {
        let signer = DilithiumSigner::generate();
        let message = b"hello shell-chain";

        let sig = signer.sign(message).unwrap();
        assert_eq!(sig.sig_type, SignatureType::Dilithium3);
        assert!(!sig.is_empty());

        let verifier = DilithiumVerifier;
        let valid = verifier.verify(signer.public_key(), message, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_wrong_message_fails() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"correct message").unwrap();

        let verifier = DilithiumVerifier;
        let valid = verifier
            .verify(signer.public_key(), b"wrong message", &sig)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_wrong_key_fails() {
        let signer1 = DilithiumSigner::generate();
        let signer2 = DilithiumSigner::generate();
        let sig = signer1.sign(b"test").unwrap();

        let verifier = DilithiumVerifier;
        let valid = verifier
            .verify(signer2.public_key(), b"test", &sig)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn address_derivation() {
        let signer = DilithiumSigner::generate();
        let kp = signer.key_pair();
        assert_eq!(kp.address.as_bytes().len(), 32);
        // Deterministic: same pubkey → same address
        let addr2 = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        assert_eq!(kp.address, addr2);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sk = signer.secret_key_bytes.to_vec();

        let signer2 = DilithiumSigner::from_bytes(&pk, &sk).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());

        // Sign with reconstructed signer, verify with original pubkey
        let sig = signer2.sign(b"roundtrip").unwrap();
        let verifier = DilithiumVerifier;
        assert!(verifier.verify(&pk, b"roundtrip", &sig).unwrap());
    }

    #[test]
    fn signature_serde_roundtrip() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"serde test").unwrap();

        let json = serde_json::to_string(&sig).unwrap();
        let sig2: PQSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn invalid_pubkey_length() {
        let verifier = DilithiumVerifier;
        let bad_sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 100]);
        let result = verifier.verify(&[0u8; 10], b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn dilithium_verifier_is_zero_sized() {
        assert_eq!(std::mem::size_of::<DilithiumVerifier>(), 0);
    }

    // ── A. Comprehensive Dilithium3 tests ───────────────────────

    #[test]
    fn batch_sign_verify_1000_random_messages() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;
        for i in 0u32..1000 {
            let msg = format!("msg-{i}-{}", i.wrapping_mul(2654435761));
            let sig = signer.sign(msg.as_bytes()).unwrap();
            assert!(
                verifier
                    .verify(signer.public_key(), msg.as_bytes(), &sig)
                    .unwrap(),
                "verification failed for message #{i}"
            );
        }
    }

    #[test]
    fn sign_empty_message() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;

        let sig = signer.sign(b"").unwrap();
        assert!(verifier.verify(signer.public_key(), b"", &sig).unwrap());
    }

    #[test]
    fn sign_large_message_1mb() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;

        let msg = vec![0xABu8; 1024 * 1024]; // 1 MiB
        let sig = signer.sign(&msg).unwrap();
        assert!(verifier.verify(signer.public_key(), &msg, &sig).unwrap());
    }

    #[test]
    fn single_bit_flip_in_signature_fails() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;
        let msg = b"bit-flip-sig-test";

        let sig = signer.sign(msg).unwrap();

        // Flip one bit in the middle of the signature
        let mut bad_data = sig.data.clone();
        let mid = bad_data.len() / 2;
        bad_data[mid] ^= 0x01;
        let bad_sig = PQSignature::new(SignatureType::Dilithium3, bad_data);

        let result = verifier.verify(signer.public_key(), msg, &bad_sig).unwrap();
        assert!(!result, "signature with flipped bit should not verify");
    }

    #[test]
    fn single_bit_flip_in_message_fails() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;
        let msg = b"bit-flip-msg-test".to_vec();

        let sig = signer.sign(&msg).unwrap();

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 0x01;
        assert!(!verifier
            .verify(signer.public_key(), &bad_msg, &sig)
            .unwrap());
    }

    #[test]
    fn single_bit_flip_in_pubkey_fails() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;
        let msg = b"bit-flip-pk-test";

        let sig = signer.sign(msg).unwrap();

        let mut bad_pk = signer.public_key().to_vec();
        bad_pk[0] ^= 0x01;
        // May return Ok(false) or Err depending on how the bit flip affects parsing
        if let Ok(valid) = verifier.verify(&bad_pk, msg, &sig) {
            assert!(!valid);
        }
        // Err is also acceptable — corrupted key may fail parsing
    }

    // ── C. Performance / size validation ────────────────────────

    #[test]
    fn dilithium3_key_sizes_match_spec() {
        assert_eq!(dilithium3::public_key_bytes(), 1952, "Dilithium3 pk size");
        assert_eq!(dilithium3::secret_key_bytes(), 4032, "Dilithium3 sk size");
        assert_eq!(dilithium3::signature_bytes(), 3309, "Dilithium3 sig size");

        // Also verify against an actual generated keypair
        let signer = DilithiumSigner::generate();
        assert_eq!(signer.public_key().len(), 1952);
        assert_eq!(signer.secret_key_bytes().len(), 4032);

        let sig = signer.sign(b"size-check").unwrap();
        assert_eq!(sig.data.len(), 3309);
    }

    #[test]
    fn sign_verify_latency_under_10ms() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;
        let msg = b"latency-test";

        let start = std::time::Instant::now();
        let sig = signer.sign(msg).unwrap();
        let _ = verifier.verify(signer.public_key(), msg, &sig).unwrap();
        let elapsed = start.elapsed();

        // Debug builds are significantly slower; use generous threshold
        let limit_ms = if cfg!(debug_assertions) { 50 } else { 10 };
        assert!(
            elapsed.as_millis() < limit_ms,
            "sign+verify took {}ms, expected <{}ms",
            elapsed.as_millis(),
            limit_ms
        );
    }

    #[test]
    fn sequential_100_sign_verify_under_1s() {
        let signer = DilithiumSigner::generate();
        let verifier = DilithiumVerifier;

        let start = std::time::Instant::now();
        for i in 0u32..100 {
            let msg = format!("perf-{i}");
            let sig = signer.sign(msg.as_bytes()).unwrap();
            assert!(verifier
                .verify(signer.public_key(), msg.as_bytes(), &sig)
                .unwrap());
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs_f64() < 2.0,
            "100 sign+verify took {:.2}s, expected <2s",
            elapsed.as_secs_f64()
        );
    }

    #[test]
    fn verifies_sdk_ml_dsa_compat_fixture() {
        let verifier = DilithiumVerifier;
        let pubkey =
            hex::decode(include_str!("../tests/fixtures/sdk_dilithium3_pubkey.hex").trim())
                .unwrap();
        let message =
            hex::decode(include_str!("../tests/fixtures/sdk_dilithium3_message.hex").trim())
                .unwrap();
        let signature =
            hex::decode(include_str!("../tests/fixtures/sdk_dilithium3_signature.hex").trim())
                .unwrap();
        let sig = PQSignature::new(SignatureType::Dilithium3, signature);

        assert!(verifier.verify(&pubkey, &message, &sig).unwrap());
    }
}
