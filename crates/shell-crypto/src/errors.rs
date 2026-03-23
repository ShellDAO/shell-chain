use crate::traits::VerificationPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedSchemeError {
    pub scheme_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSizeExceededError {
    pub max_size: usize,
    pub actual_size: usize,
    pub path: VerificationPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationFailure {
    pub scheme_id: u8,
    pub context: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    UnsupportedScheme(UnsupportedSchemeError),
    SignatureSizeExceeded(SignatureSizeExceededError),
    VerificationFailed(VerificationFailure),
}
