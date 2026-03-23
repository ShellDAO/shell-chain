use crate::types::Root;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    MalformedSsz(MalformedSszError),
    UnsupportedPayloadVariant(UnsupportedPayloadVariant),
    PayloadRootMismatch(PayloadRootMismatchError),
    SigningRootConstruction(SigningRootConstructionError),
    AuthorizationCount(AuthorizationCountError),
    SignatureSizeExceeded(SignatureSizeExceededError),
    Unimplemented(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedSszError {
    pub context: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedPayloadVariant {
    pub tag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRootMismatchError {
    pub expected: Root,
    pub actual: Root,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRootConstructionError {
    pub context: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    pub domain_name: &'static str,
}

/// Returned when the authorization list violates the currently supported count policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCountError {
    /// Minimum required by the closed local rule.
    pub expected_at_least: usize,
    pub actual: usize,
}

/// Returned when a signature artifact exceeds the locally enforced byte bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureSizeExceededError {
    pub max_bytes: usize,
    pub actual_bytes: usize,
}
