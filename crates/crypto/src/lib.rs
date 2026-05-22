mod algorithm_registry;
#[cfg(feature = "batch")]
mod batch;
mod dilithium;
mod error;
mod keypair;
mod mldsa;
mod multi;
mod signature;
mod signer;
mod sphincs;
mod verifier;

pub use algorithm_registry::{
    is_algorithm_allowed, AlgorithmEntry, AlgorithmRegistry, AlgorithmStatus,
};
#[cfg(feature = "batch")]
pub use batch::{BatchVerifier, PreVerified, VerifyItem};
pub use dilithium::{DilithiumSigner, DilithiumVerifier};
pub use error::CryptoError;
pub use keypair::KeyPair;
pub use mldsa::{MlDsaSigner, MlDsaVerifier};
pub use multi::MultiVerifier;
pub use signature::{PQSignature, SignatureType, ALLOWED_ALGORITHMS};
pub use signer::Signer;
pub use sphincs::{SphincsSigner, SphincsVerifier};
pub use verifier::Verifier;
