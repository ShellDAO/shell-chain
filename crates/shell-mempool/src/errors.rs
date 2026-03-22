use shell_crypto::{SignatureSizeExceededError, UnsupportedSchemeError, VerificationFailure};
use shell_primitives::{GasPrice, PrimitiveError};

use crate::fees::FeeLane;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeFloorError {
    pub lane: FeeLane,
    pub required: GasPrice,
    pub actual: GasPrice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncePolicyError {
    pub context: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningRootUnavailableError {
    pub context: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationMaterialCountError {
    pub expected: usize,
    pub actual: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Primitive(PrimitiveError),
    UnsupportedScheme(UnsupportedSchemeError),
    SignatureSizeExceeded(SignatureSizeExceededError),
    SignatureVerification(VerificationFailure),
    FeeFloor(FeeFloorError),
    NoncePolicy(NoncePolicyError),
    SigningRootUnavailable(SigningRootUnavailableError),
    AuthorizationMaterialCount(AuthorizationMaterialCountError),
}

impl From<PrimitiveError> for ValidationError {
    fn from(value: PrimitiveError) -> Self {
        Self::Primitive(value)
    }
}
