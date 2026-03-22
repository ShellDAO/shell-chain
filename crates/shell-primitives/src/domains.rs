use crate::errors::DomainError;
use crate::types::{Bytes4, Root, SigningData};

pub const DOMAIN_TYPE_WIDTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSelector {
    TransactionAuthorization,
    ValidatorMessage,
}

impl DomainSelector {
    pub const fn label(self) -> &'static str {
        match self {
            Self::TransactionAuthorization => "transaction-authorization",
            Self::ValidatorMessage => "validator-message",
        }
    }

    // The specs freeze the 4-byte width but not the concrete tag bytes yet.
    pub fn domain_type(self) -> Result<Bytes4, DomainError> {
        Err(DomainError {
            domain_name: self.label(),
        })
    }
}

pub fn build_signing_data(
    object_root: Root,
    domain: DomainSelector,
) -> Result<SigningData, DomainError> {
    Ok(SigningData {
        object_root,
        domain_type: domain.domain_type()?,
    })
}
