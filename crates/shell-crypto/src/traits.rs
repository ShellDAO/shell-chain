use shell_primitives::Root;

use crate::errors::VerificationFailure;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPath {
    TransactionAuthorization,
    ValidatorMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureVerificationRequest<'a> {
    pub public_key_material: &'a [u8],
    pub signing_root: Root,
    pub signature: &'a [u8],
}

pub trait SignatureVerifier {
    fn scheme_id(&self) -> u8;

    fn max_signature_size(&self, _path: VerificationPath) -> Option<usize> {
        None
    }

    fn verify(&self, request: &SignatureVerificationRequest<'_>)
        -> Result<(), VerificationFailure>;
}

pub trait SignatureDispatcher {
    fn register_verifier(
        &mut self,
        verifier: alloc::boxed::Box<dyn SignatureVerifier>,
    ) -> Option<alloc::boxed::Box<dyn SignatureVerifier>>;

    fn verifier(&self, scheme_id: u8) -> Option<&dyn SignatureVerifier>;

    fn verify_transaction_authorization(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), crate::errors::CryptoError>;

    fn verify_validator_message(
        &self,
        scheme_id: u8,
        request: &SignatureVerificationRequest<'_>,
    ) -> Result<(), crate::errors::CryptoError>;
}
