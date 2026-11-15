//! Full lattice-signature AIR and strict weight AIR for an expected commit context.
//! Native supplies current authority keys and weights independently. Historical
//! provenance, proposer selection and penalty lifecycle are not proved here.
use crate::{
    mldsa_verification::{verify_dilithium3, verify_mldsa65, Mldsa65VerificationProof},
    production_store::{bounded_json, ProductionError, ProductionProgress, ProductionStore},
    weighted_quorum::{
        prove_quorum_weight, verify_quorum_weight, QuorumWeightContext, QuorumWeightProof,
    },
};
use serde::{Deserialize, Serialize};
use shell_core::BlockSignerEvidence;
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_storage::KvStore;
use std::num::NonZeroUsize;

pub const MAX_COMMIT_PROOF_SIGNERS: usize = 16;

/// Expected inputs selected independently of the proof. The address/key binding
/// and current registry provenance are Native predicates, not additional AIRs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitQuorumSource {
    pub context: QuorumWeightContext,
    pub signatures: Vec<BlockSignerEvidence>,
}
impl CommitQuorumSource {
    fn validate(&self) -> Result<(), String> {
        self.context.validate()?;
        if self.signatures.is_empty()
            || self.signatures.len() > MAX_COMMIT_PROOF_SIGNERS
            || self.signatures.len() != self.context.signers.len()
        {
            return Err("commit proof signer count mismatch".into());
        }
        for (entry, address) in self.signatures.iter().zip(&self.context.signers) {
            if entry.address != *address
                || entry.public_key.len() != 1952
                || entry.signature.data.len() != 3309
                || !matches!(
                    entry.signature.sig_type,
                    SignatureType::MlDsa65 | SignatureType::Dilithium3
                )
                || shell_crypto::infer_signature_type_from_address(&entry.public_key, address)
                    != Some(entry.signature.sig_type)
            {
                return Err("commit proof signer order/key/tag/profile mismatch".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitQuorumProof {
    pub version: u8,
    pub weight: QuorumWeightProof,
    pub signatures: Vec<Mldsa65VerificationProof>,
}

/// Only full proof verification constructs this exact-tuple verifier. It is not
/// serializable and grants no authority for another key, hash, signer or context.
#[derive(Clone, Debug)]
pub struct VerifiedCommitQuorum {
    source: CommitQuorumSource,
}
impl VerifiedCommitQuorum {
    pub fn matches_source(&self, source: &CommitQuorumSource) -> bool {
        self.source == *source
    }
}
impl Verifier for VerifiedCommitQuorum {
    fn verify(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        if !shell_crypto::is_algorithm_allowed(signature.sig_type) {
            return Err(CryptoError::UnsupportedSignatureType(signature.sig_type));
        }
        Ok(message == self.source.context.block_hash.as_bytes()
            && self
                .source
                .signatures
                .iter()
                .any(|entry| key == entry.public_key && signature == &entry.signature))
    }
    fn sig_type(&self) -> SignatureType {
        SignatureType::Dilithium3
    }
}

/// Verify every full raw block-hash signature graph and the strict weighted AIR.
/// There is no native cryptographic fallback for a missing or invalid proof.
pub fn verify_commit_quorum(
    proof: &CommitQuorumProof,
    expected: &CommitQuorumSource,
) -> Result<VerifiedCommitQuorum, String> {
    expected.validate()?;
    if proof.version != 1 || proof.signatures.len() != expected.signatures.len() {
        return Err("commit proof version/signature count mismatch".into());
    }
    verify_quorum_weight(&proof.weight, &expected.context)?;
    for (proof, entry) in proof.signatures.iter().zip(&expected.signatures) {
        let verify = match (entry.signature.sig_type, proof.version) {
            (SignatureType::MlDsa65 | SignatureType::Dilithium3, 1) => verify_mldsa65,
            (SignatureType::Dilithium3, 2) => verify_dilithium3,
            _ => return Err("commit signature transcript mismatch".into()),
        };
        verify(
            proof,
            &entry.public_key,
            expected.context.block_hash.as_bytes(),
            &entry.signature.data,
        )?;
    }
    Ok(VerifiedCommitQuorum {
        source: expected.clone(),
    })
}

/// Exclusively own a separate job store. The original source and every reused
/// checkpoint are checked on reopen. A component limit pauses without changing
/// the Native chain; complete proof output is returned only after verification.
pub fn prove_commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(store, source, limit, false)
}

/// Reverify all original certificates without initializing a job or invoking
/// any proving closure. Missing or invalid components refuse rather than heal.
pub fn reverify_commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(store, source, None, true)
}

fn commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    read_only: bool,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    source.validate()?;
    // Validate the strict public arithmetic and native signatures before opening
    // a mutable job. Native verification selects a transcript only for proving.
    let total: u64 = source.context.authorities.iter().map(|a| a.weight).sum();
    let signed: u64 = source
        .context
        .authorities
        .iter()
        .filter(|a| {
            source
                .context
                .signers
                .binary_search_by(|s| s.as_bytes().cmp(a.address.as_bytes()))
                .is_ok()
        })
        .map(|a| a.weight)
        .sum();
    if total == 0 || 3 * signed <= 2 * total {
        return Err("commit source is below strict quorum".to_string().into());
    }
    let mut legacy = Vec::with_capacity(source.signatures.len());
    for entry in &source.signatures {
        let message = source.context.block_hash.as_bytes();
        let raw = entry.signature.sig_type == SignatureType::Dilithium3
            && shell_crypto::DilithiumVerifier.verify_legacy_transcript(
                &entry.public_key,
                message,
                &entry.signature,
            );
        let valid = raw
            || match entry.signature.sig_type {
                SignatureType::MlDsa65 => shell_crypto::MlDsaVerifier
                    .verify(&entry.public_key, message, &entry.signature)
                    .unwrap_or(false),
                SignatureType::Dilithium3 => shell_crypto::DilithiumVerifier.verify_sdk_transcript(
                    &entry.public_key,
                    message,
                    &entry.signature,
                ),
                _ => false,
            };
        if !valid {
            return Err("invalid commit source signature".to_string().into());
        }
        legacy.push(raw);
    }
    let bytes = bounded_json(&("commit-signature-weight-v1", source), 1024 * 1024)?;
    let mut job = if read_only {
        ProductionStore::open_existing_shared_matrix(store, &bytes)?
    } else {
        ProductionStore::open_shared_matrix(store, &bytes, limit)?
    };
    let weight = job.checkpoint(
        "commit-weight",
        || prove_quorum_weight(&source.context),
        |p| verify_quorum_weight(p, &source.context).map(|_| ()),
    )?;
    let mut signatures = Vec::with_capacity(source.signatures.len());
    for (i, (entry, raw)) in source.signatures.iter().zip(legacy).enumerate() {
        signatures.push(crate::canonical_producer::prove_signature(
            &mut job,
            &format!("commit-signer-{i}"),
            &entry.public_key,
            source.context.block_hash.as_bytes(),
            &entry.signature.data,
            raw,
        )?);
    }
    let proof = CommitQuorumProof {
        version: 1,
        weight,
        signatures,
    };
    verify_commit_quorum(&proof, source)?;
    Ok((proof, job.progress()))
}
