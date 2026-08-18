mod algorithm_registry;
#[cfg(feature = "batch")]
mod batch;
mod dilithium;
mod error;
pub mod hd;
mod keypair;
mod mldsa;
mod multi;
mod signature;
mod signer;
mod sphincs;
mod verifier;

pub use algorithm_registry::{
    is_algorithm_allowed, with_algorithm_registry_override, AlgorithmEntry, AlgorithmRegistry,
    AlgorithmStatus,
};
#[cfg(feature = "batch")]
pub use batch::{BatchVerifier, PreVerified, VerifyItem};
pub use dilithium::{DilithiumSigner, DilithiumVerifier};
pub use error::CryptoError;
pub use keypair::KeyPair;
pub use mldsa::{MlDsaSigner, MlDsaVerifier};
pub use multi::{infer_signature_type_from_address, verify_signature, MultiVerifier};
pub use signature::{
    PQSignature, SignatureType, ALLOWED_ALGORITHMS, MAX_ML_DSA_65_SIG_BYTES, MAX_SIGNATURE_BYTES,
};
pub use signer::Signer;
pub use sphincs::{SphincsSigner, SphincsVerifier};
pub use verifier::Verifier;
