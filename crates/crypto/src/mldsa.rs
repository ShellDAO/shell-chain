use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as FipsSigner, Verifier as FipsVerifier};

use crate::{CryptoError, KeyPair, PQSignature, SignatureType, Signer, Verifier};

// ML-DSA-65 (FIPS 204) key/signature byte sizes.
pub const ML_DSA_65_SK_LEN: usize = ml_dsa_65::SK_LEN; // 4032
pub const ML_DSA_65_PK_LEN: usize = ml_dsa_65::PK_LEN; // 1952
pub const ML_DSA_65_SIG_LEN: usize = ml_dsa_65::SIG_LEN; // 3309

// ── Signer ───────────────────────────────────────────────────

/// FIPS 204 ML-DSA-65 signer.
///
/// Uses the `fips204` crate which implements the final NIST FIPS 204 standard.
/// This is distinct from `DilithiumSigner` which uses the pre-standard
/// Round 3 `pqcrypto-dilithium` crate.
pub struct MlDsaSigner {
    secret_key_bytes: zeroize::Zeroizing<Vec<u8>>,
    public_key_bytes: Vec<u8>,
}

impl MlDsaSigner {
    /// Generate a fresh ML-DSA-65 key pair.
    pub fn generate() -> Self {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 key generation should not fail");
        Self {
            secret_key_bytes: zeroize::Zeroizing::new(sk.into_bytes().to_vec()),
            public_key_bytes: pk.into_bytes().to_vec(),
        }
    }

    /// Reconstruct from raw key bytes.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        let sk_arr = <[u8; ML_DSA_65_SK_LEN]>::try_from(secret_key).map_err(|_| {
            CryptoError::InvalidSecretKeyLength {
                expected: ML_DSA_65_SK_LEN,
                got: secret_key.len(),
            }
        })?;
        let pk_arr = <[u8; ML_DSA_65_PK_LEN]>::try_from(public_key).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: ML_DSA_65_PK_LEN,
                got: public_key.len(),
            }
        })?;
        // Validate by parsing both keys.
        ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|_| {
            CryptoError::InvalidSecretKeyLength {
                expected: ML_DSA_65_SK_LEN,
                got: secret_key.len(),
            }
        })?;
        ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: ML_DSA_65_PK_LEN,
                got: public_key.len(),
            }
        })?;
        Ok(Self {
            secret_key_bytes: zeroize::Zeroizing::new(secret_key.to_vec()),
            public_key_bytes: public_key.to_vec(),
        })
    }

    /// Export the public half as a [`KeyPair`].
    pub fn key_pair(&self) -> KeyPair {
        KeyPair::new(self.public_key_bytes.clone(), SignatureType::MlDsa65)
    }

    /// Return a reference to the zeroize-protected secret key bytes.
    pub fn secret_key_bytes(&self) -> &zeroize::Zeroizing<Vec<u8>> {
        &self.secret_key_bytes
    }
}

impl Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<PQSignature, CryptoError> {
        let sk_arr = <[u8; ML_DSA_65_SK_LEN]>::try_from(self.secret_key_bytes.as_slice())
            .expect("secret key bytes validated at construction");
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
            .expect("secret key bytes validated at construction");
        // Use empty context (matching the SDK's default behavior).
        let sig = sk
            .try_sign(message, &[])
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
        Ok(PQSignature::new(SignatureType::MlDsa65, sig.to_vec()))
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::MlDsa65
    }
}

// ── Verifier ─────────────────────────────────────────────────

/// Stateless ML-DSA-65 verifier (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct MlDsaVerifier;

impl Verifier for MlDsaVerifier {
    fn verify(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        if signature.sig_type != SignatureType::MlDsa65 {
            return Err(CryptoError::UnsupportedSignatureType(signature.sig_type));
        }
        let pk_arr = <[u8; ML_DSA_65_PK_LEN]>::try_from(pubkey).map_err(|_| {
            CryptoError::InvalidPublicKeyLength {
                expected: ML_DSA_65_PK_LEN,
                got: pubkey.len(),
            }
        })?;
        let sig_arr =
            <[u8; ML_DSA_65_SIG_LEN]>::try_from(signature.data.as_slice()).map_err(|_| {
                CryptoError::InvalidSignatureLength {
                    expected: ML_DSA_65_SIG_LEN,
                    got: signature.data.len(),
                }
            })?;
        let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
            return Ok(false);
        };
        Ok(pk.verify(message, &sig_arr, &[]))
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::MlDsa65
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::Address;

    #[test]
    fn generate_and_sign_verify() {
        let signer = MlDsaSigner::generate();
        let message = b"hello shell-chain ml-dsa-65";
        let sig = signer.sign(message).unwrap();
        assert_eq!(sig.sig_type, SignatureType::MlDsa65);
        assert_eq!(sig.data.len(), ML_DSA_65_SIG_LEN);

        let verifier = MlDsaVerifier;
        assert!(verifier.verify(signer.public_key(), message, &sig).unwrap());
    }

    #[test]
    fn wrong_message_fails() {
        let signer = MlDsaSigner::generate();
        let sig = signer.sign(b"correct message").unwrap();
        let verifier = MlDsaVerifier;
        assert!(!verifier
            .verify(signer.public_key(), b"wrong message", &sig)
            .unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let signer1 = MlDsaSigner::generate();
        let signer2 = MlDsaSigner::generate();
        let sig = signer1.sign(b"test").unwrap();
        let verifier = MlDsaVerifier;
        assert!(!verifier
            .verify(signer2.public_key(), b"test", &sig)
            .unwrap());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = MlDsaSigner::generate();
        let pk = signer.public_key().to_vec();
        let sk = signer.secret_key_bytes().to_vec();

        let signer2 = MlDsaSigner::from_bytes(&pk, &sk).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());

        let sig = signer2.sign(b"roundtrip").unwrap();
        let verifier = MlDsaVerifier;
        assert!(verifier.verify(&pk, b"roundtrip", &sig).unwrap());
    }

    #[test]
    fn key_sizes_match_spec() {
        assert_eq!(ML_DSA_65_SK_LEN, 4032);
        assert_eq!(ML_DSA_65_PK_LEN, 1952);
        assert_eq!(ML_DSA_65_SIG_LEN, 3309);

        let signer = MlDsaSigner::generate();
        assert_eq!(signer.public_key().len(), ML_DSA_65_PK_LEN);
        assert_eq!(signer.secret_key_bytes().len(), ML_DSA_65_SK_LEN);

        let sig = signer.sign(b"size-check").unwrap();
        assert_eq!(sig.data.len(), ML_DSA_65_SIG_LEN);
    }

    #[test]
    fn address_derivation() {
        let signer = MlDsaSigner::generate();
        let kp = signer.key_pair();
        assert_eq!(kp.address.as_bytes().len(), 32);
        let addr2 = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        assert_eq!(kp.address, addr2);
    }

    #[test]
    fn verifier_is_zero_sized() {
        assert_eq!(std::mem::size_of::<MlDsaVerifier>(), 0);
    }

    #[test]
    fn wrong_sig_type_rejected() {
        let signer = MlDsaSigner::generate();
        let mut sig = signer.sign(b"test").unwrap();
        sig.sig_type = SignatureType::Dilithium3;
        let verifier = MlDsaVerifier;
        assert!(verifier.verify(signer.public_key(), b"test", &sig).is_err());
    }

    #[test]
    fn bit_flip_in_signature_fails() {
        let signer = MlDsaSigner::generate();
        let msg = b"bit-flip-test";
        let sig = signer.sign(msg).unwrap();
        let mut bad_data = sig.data.clone();
        let mid = bad_data.len() / 2;
        bad_data[mid] ^= 0x01;
        let bad_sig = PQSignature::new(SignatureType::MlDsa65, bad_data);
        let verifier = MlDsaVerifier;
        // May be Ok(false) or Err — either is correct
        assert!(!verifier
            .verify(signer.public_key(), msg, &bad_sig)
            .unwrap_or(false));
    }
}
