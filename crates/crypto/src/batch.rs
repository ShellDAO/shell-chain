//! Batch parallel signature verification using rayon.
//!
//! Each PQ signature verification is independent, making this an
//! embarrassingly parallel workload. `BatchVerifier` dispatches items
//! across the rayon thread pool for significant throughput gains on
//! multi-core hardware.

use rayon::prelude::*;

use crate::{CryptoError, PQSignature, SignatureType, Verifier};

/// A (public_key, message, signature) triplet for batch verification.
pub struct VerifyItem<'a> {
    pub pubkey: &'a [u8],
    pub message: &'a [u8],
    pub signature: &'a PQSignature,
}

/// Extension trait for parallel batch signature verification.
///
/// Any type that implements [`Verifier`] can opt-in to batch verification
/// by implementing this trait. The default methods use `rayon::par_iter()`
/// to verify signatures across all available cores.
pub trait BatchVerifier: Verifier {
    /// Verify multiple signatures in parallel, returning per-item results.
    ///
    /// Returns `Ok(vec![true, false, ...])` with one result per item.
    /// Returns `Err` only if the underlying crypto produces an error
    /// (e.g. malformed key or unsupported algorithm).
    fn verify_batch(&self, items: &[VerifyItem<'_>]) -> Result<Vec<bool>, CryptoError> {
        if items.is_empty() {
            return Ok(vec![]);
        }
        let results: Result<Vec<bool>, CryptoError> = items
            .par_iter()
            .map(|item| self.verify(item.pubkey, item.message, item.signature))
            .collect();
        results
    }

    /// Verify all signatures in a batch, returning `Ok(())` only if every
    /// signature is valid. Returns `Err(VerificationFailed)` if any
    /// signature is invalid, or propagates crypto errors.
    fn verify_batch_all(&self, items: &[VerifyItem<'_>]) -> Result<(), CryptoError> {
        let results = self.verify_batch(items)?;
        if results.iter().all(|&v| v) {
            Ok(())
        } else {
            Err(CryptoError::BatchVerificationFailed {
                total: results.len(),
                failed: results.iter().filter(|&&v| !v).count(),
            })
        }
    }
}

/// No-op verifier that always returns `Ok(true)`.
///
/// Used after batch verification to run remaining non-signature validation
/// (chain-id, gas, access-list, address derivation) without redundantly
/// re-verifying signatures that were already checked in parallel.
#[derive(Debug, Clone, Copy)]
pub struct PreVerified;

impl Verifier for PreVerified {
    fn verify(
        &self,
        _pubkey: &[u8],
        _message: &[u8],
        _signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        Ok(true)
    }

    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DilithiumSigner, MultiVerifier, Signer, SphincsSigner};

    #[test]
    fn batch_verify_empty() {
        let mv = MultiVerifier;
        let result = mv.verify_batch(&[]).unwrap();
        assert!(result.is_empty());
        assert!(mv.verify_batch_all(&[]).is_ok());
    }

    #[test]
    fn batch_verify_single() {
        let signer = DilithiumSigner::generate();
        let sig = signer.sign(b"single").unwrap();
        let mv = MultiVerifier;

        let items = vec![VerifyItem {
            pubkey: signer.public_key(),
            message: b"single",
            signature: &sig,
        }];
        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results, vec![true]);
        assert!(mv.verify_batch_all(&items).is_ok());
    }

    #[test]
    fn batch_verify_ten_dilithium() {
        let signers: Vec<DilithiumSigner> = (0..10).map(|_| DilithiumSigner::generate()).collect();
        let messages: Vec<Vec<u8>> = (0..10).map(|i| format!("msg-{i}").into_bytes()).collect();
        let sigs: Vec<PQSignature> = signers
            .iter()
            .zip(messages.iter())
            .map(|(s, m)| s.sign(m).unwrap())
            .collect();
        let mv = MultiVerifier;

        let items: Vec<VerifyItem> = signers
            .iter()
            .zip(messages.iter().zip(sigs.iter()))
            .map(|(s, (m, sig))| VerifyItem {
                pubkey: s.public_key(),
                message: m,
                signature: sig,
            })
            .collect();

        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|&v| v));
        assert!(mv.verify_batch_all(&items).is_ok());
    }

    #[test]
    fn batch_verify_hundred() {
        let signers: Vec<DilithiumSigner> = (0..100).map(|_| DilithiumSigner::generate()).collect();
        let messages: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("batch-{i}").into_bytes())
            .collect();
        let sigs: Vec<PQSignature> = signers
            .iter()
            .zip(messages.iter())
            .map(|(s, m)| s.sign(m).unwrap())
            .collect();
        let mv = MultiVerifier;

        let items: Vec<VerifyItem> = signers
            .iter()
            .zip(messages.iter().zip(sigs.iter()))
            .map(|(s, (m, sig))| VerifyItem {
                pubkey: s.public_key(),
                message: m,
                signature: sig,
            })
            .collect();

        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results.len(), 100);
        assert!(results.iter().all(|&v| v));
    }

    #[test]
    fn batch_verify_mixed_valid_invalid() {
        let signer1 = DilithiumSigner::generate();
        let signer2 = DilithiumSigner::generate();
        let signer3 = DilithiumSigner::generate();
        let mv = MultiVerifier;

        let sig1 = signer1.sign(b"msg-1").unwrap();
        let sig2 = signer2.sign(b"msg-2").unwrap();
        let sig3 = signer3.sign(b"msg-3").unwrap();

        let items = vec![
            // Valid
            VerifyItem {
                pubkey: signer1.public_key(),
                message: b"msg-1",
                signature: &sig1,
            },
            // Invalid: wrong message
            VerifyItem {
                pubkey: signer2.public_key(),
                message: b"wrong",
                signature: &sig2,
            },
            // Valid
            VerifyItem {
                pubkey: signer3.public_key(),
                message: b"msg-3",
                signature: &sig3,
            },
        ];

        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results, vec![true, false, true]);

        // verify_batch_all should fail
        let err = mv.verify_batch_all(&items).unwrap_err();
        match err {
            CryptoError::BatchVerificationFailed { total, failed } => {
                assert_eq!(total, 3);
                assert_eq!(failed, 1);
            }
            _ => panic!("expected BatchVerificationFailed, got {err:?}"),
        }
    }

    #[test]
    fn batch_verify_mixed_algorithms() {
        let dil = DilithiumSigner::generate();
        let sph = SphincsSigner::generate();
        let mv = MultiVerifier;

        let sig_d = dil.sign(b"dil-msg").unwrap();
        let sig_s = sph.sign(b"sph-msg").unwrap();

        let items = vec![
            VerifyItem {
                pubkey: dil.public_key(),
                message: b"dil-msg",
                signature: &sig_d,
            },
            VerifyItem {
                pubkey: sph.public_key(),
                message: b"sph-msg",
                signature: &sig_s,
            },
        ];

        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results, vec![true, true]);
    }

    #[test]
    fn batch_verify_all_invalid() {
        let signer = DilithiumSigner::generate();
        let other = DilithiumSigner::generate();
        let mv = MultiVerifier;

        let sig = signer.sign(b"real").unwrap();

        let items = vec![
            VerifyItem {
                pubkey: other.public_key(),
                message: b"real",
                signature: &sig,
            },
            VerifyItem {
                pubkey: signer.public_key(),
                message: b"fake",
                signature: &sig,
            },
        ];

        let results = mv.verify_batch(&items).unwrap();
        assert_eq!(results, vec![false, false]);
    }

    #[test]
    fn pre_verified_always_true() {
        let pv = PreVerified;
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 10]);
        assert!(pv.verify(&[], &[], &sig).unwrap());
    }
}
