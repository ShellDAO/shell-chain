use shell_crypto::{CryptoError, SignatureDispatcher, SignatureVerificationRequest};
use shell_primitives::{
    check_authorization_count, check_authorization_payload_roots, check_user_signature_size,
    Bytes4, PrimitiveError, ProtocolObject, Root, SigningData, TransactionEnvelope,
    TransactionMetadata, TransactionPayload, TransactionPayloadSsz,
};

use crate::errors::{
    AuthorizationMaterialCountError, FeeFloorError, NoncePolicyError, SigningRootUnavailableError,
    ValidationError,
};
use crate::fees::{gas_price_covers, payload_lane_fee, witness_lane_fee, FeeLane, FeeSchedule};
use crate::outcomes::{AuthorizationValidated, TentativeAccepted};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncePolicy {
    pub max_future_nonce_gap: u64,
}

impl Default for NoncePolicy {
    fn default() -> Self {
        Self {
            max_future_nonce_gap: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionAuthorizationDomain {
    #[default]
    Pending,
    Explicit(Bytes4),
}

impl TransactionAuthorizationDomain {
    pub fn signing_root(self, payload_root: Root) -> Result<Root, SigningRootUnavailableError> {
        match self {
            Self::Pending => Err(SigningRootUnavailableError {
                context: "transaction authorization domain_type remains unresolved in the current spec set",
            }),
            Self::Explicit(domain_type) => SigningData {
                object_root: payload_root,
                domain_type,
            }
            .canonical_root()
            .map_err(|_| SigningRootUnavailableError {
                context: "failed to construct signing_root from explicit transaction domain bytes",
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdmissionPolicy {
    pub fee_schedule: FeeSchedule,
    pub nonce_policy: NoncePolicy,
    pub authorization_domain: TransactionAuthorizationDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationMaterial<'a> {
    pub public_key_material: &'a [u8],
}

pub trait AdmissionStateView {
    fn observed_nonce(&self, envelope: &TransactionEnvelope) -> Option<u64>;
}

pub struct AdmissionPipeline<'a, D: ?Sized> {
    dispatcher: &'a D,
    policy: AdmissionPolicy,
}

impl<'a, D> AdmissionPipeline<'a, D>
where
    D: SignatureDispatcher + ?Sized,
{
    pub fn new(dispatcher: &'a D, policy: AdmissionPolicy) -> Self {
        Self { dispatcher, policy }
    }

    pub fn policy(&self) -> AdmissionPolicy {
        self.policy
    }

    pub fn screen_transaction(
        &self,
        envelope: &TransactionEnvelope,
        state_view: Option<&dyn AdmissionStateView>,
    ) -> Result<TentativeAccepted, ValidationError> {
        let payload_root = envelope.payload_root()?;
        TransactionPayloadSsz::ensure_supported_tag(envelope.payload.protocol_tag())
            .map_err(PrimitiveError::UnsupportedPayloadVariant)?;
        check_authorization_count(&envelope.authorizations)?;
        check_authorization_payload_roots(&envelope.payload, &envelope.authorizations)?;
        for authorization in &envelope.authorizations {
            check_user_signature_size(&authorization.signature)?;
        }

        self.check_fee_policy(envelope)?;
        self.check_nonce_policy(envelope, state_view)?;

        Ok(TentativeAccepted {
            payload_root,
            authorization_count: envelope.authorizations.len(),
        })
    }

    pub fn verify_authorizations(
        &self,
        envelope: &TransactionEnvelope,
        accepted: &TentativeAccepted,
        authorization_materials: &[AuthorizationMaterial<'_>],
    ) -> Result<AuthorizationValidated, ValidationError> {
        if authorization_materials.len() != envelope.authorizations.len() {
            return Err(ValidationError::AuthorizationMaterialCount(
                AuthorizationMaterialCountError {
                    expected: envelope.authorizations.len(),
                    actual: authorization_materials.len(),
                },
            ));
        }

        let signing_root = self
            .policy
            .authorization_domain
            .signing_root(accepted.payload_root)
            .map_err(ValidationError::SigningRootUnavailable)?;

        for (authorization, material) in envelope
            .authorizations
            .iter()
            .zip(authorization_materials.iter())
        {
            let request = SignatureVerificationRequest {
                public_key_material: material.public_key_material,
                signing_root,
                signature: &authorization.signature,
            };
            self.dispatcher
                .verify_transaction_authorization(authorization.scheme_id, &request)
                .map_err(map_crypto_error)?;
        }

        Ok(AuthorizationValidated {
            payload_root: accepted.payload_root,
            signing_root,
            verified_authorization_count: envelope.authorizations.len(),
        })
    }

    pub fn admit_and_verify(
        &self,
        envelope: &TransactionEnvelope,
        state_view: Option<&dyn AdmissionStateView>,
        authorization_materials: &[AuthorizationMaterial<'_>],
    ) -> Result<AuthorizationValidated, ValidationError> {
        let accepted = self.screen_transaction(envelope, state_view)?;
        self.verify_authorizations(envelope, &accepted, authorization_materials)
    }

    fn check_fee_policy(&self, envelope: &TransactionEnvelope) -> Result<(), ValidationError> {
        let payload_fee = payload_lane_fee(envelope);
        if !gas_price_covers(payload_fee, self.policy.fee_schedule.payload_lane_base_fee) {
            return Err(ValidationError::FeeFloor(FeeFloorError {
                lane: FeeLane::Payload,
                required: self.policy.fee_schedule.payload_lane_base_fee,
                actual: payload_fee,
            }));
        }

        let witness_fee = witness_lane_fee(envelope);
        if !gas_price_covers(witness_fee, self.policy.fee_schedule.witness_lane_base_fee) {
            return Err(ValidationError::FeeFloor(FeeFloorError {
                lane: FeeLane::Witness,
                required: self.policy.fee_schedule.witness_lane_base_fee,
                actual: witness_fee,
            }));
        }

        Ok(())
    }

    fn check_nonce_policy(
        &self,
        envelope: &TransactionEnvelope,
        state_view: Option<&dyn AdmissionStateView>,
    ) -> Result<(), ValidationError> {
        let Some(state_view) = state_view else {
            return Ok(());
        };
        let Some(observed_nonce) = state_view.observed_nonce(envelope) else {
            return Ok(());
        };

        let tx_nonce = transaction_nonce(envelope);
        if tx_nonce < observed_nonce {
            return Err(ValidationError::NoncePolicy(NoncePolicyError {
                context: "transaction nonce is lower than the observed replay lane nonce",
            }));
        }

        let max_nonce =
            observed_nonce.saturating_add(self.policy.nonce_policy.max_future_nonce_gap);
        if tx_nonce > max_nonce {
            return Err(ValidationError::NoncePolicy(NoncePolicyError {
                context: "transaction nonce exceeds the configured future replay lane gap",
            }));
        }

        Ok(())
    }
}

fn transaction_nonce(envelope: &TransactionEnvelope) -> u64 {
    match envelope.payload.payload() {
        TransactionPayload::Basic(payload) => payload.nonce(),
        TransactionPayload::Create(payload) => payload.nonce(),
    }
}

fn map_crypto_error(error: CryptoError) -> ValidationError {
    match error {
        CryptoError::UnsupportedScheme(error) => ValidationError::UnsupportedScheme(error),
        CryptoError::SignatureSizeExceeded(error) => ValidationError::SignatureSizeExceeded(error),
        CryptoError::VerificationFailed(error) => ValidationError::SignatureVerification(error),
    }
}
