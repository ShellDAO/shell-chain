use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },

    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },

    #[error("invalid secret key length: expected {expected}, got {got}")]
    InvalidSecretKeyLength { expected: usize, got: usize },

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("unsupported signature type: {0:?}")]
    UnsupportedSignatureType(crate::SignatureType),

    #[error("batch verification failed: {failed}/{total} signatures invalid")]
    BatchVerificationFailed { total: usize, failed: usize },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}
