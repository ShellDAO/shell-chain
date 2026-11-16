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
    commit_quorum_persistent(store, source, limit, false, None)
}

/// Reverify all original certificates without initializing a job or invoking
/// any proving closure. Missing or invalid components refuse rather than heal.
pub fn reverify_commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    commit_quorum_persistent(store, source, None, true, None)
}

/// Reverify a complete, independently pinned donor before opening destination
/// checkpoints. Only exact key/address/signature/transcript and message matches
/// may supply untrusted component bytes; every borrowed certificate is verified
/// again against the destination input. Weight proofs are never borrowed.
/// Both stores must be separate and exclusively owned by the caller.
pub fn prove_commit_quorum_persistent_reusing<S: KvStore, D: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    donor: &mut D,
    donor_source: &CommitQuorumSource,
) -> Result<(CommitQuorumProof, ProductionProgress), ProductionError> {
    source.validate()?;
    reverify_commit_quorum_persistent(donor, donor_source)?;
    let reuse = |name: &str| {
        let Some(name) = donor_component_name(source, donor_source, name) else {
            return Ok(None);
        };
        let key = [b"production/component/".as_slice(), name.as_bytes()].concat();
        donor
            .get(&key)
            .map_err(|e| e.to_string())?
            .map(Some)
            .ok_or_else(|| "missing input-matched donor checkpoint".to_string())
    };
    commit_quorum_persistent(store, source, limit, false, Some(&reuse))
}

fn donor_component_name(
    source: &CommitQuorumSource,
    donor: &CommitQuorumSource,
    name: &str,
) -> Option<String> {
    if source.context.block_hash != donor.context.block_hash {
        return None;
    }
    let (position, suffix) = name.strip_prefix("commit-signer-")?.split_once('-')?;
    let index: usize = position.parse().ok()?;
    if position != index.to_string() || suffix.is_empty() {
        return None;
    }
    let entry = source.signatures.get(index)?;
    let old = donor.signatures.iter().position(|other| other == entry)?;
    Some(format!("commit-signer-{old}-{suffix}"))
}

fn commit_quorum_persistent<S: KvStore>(
    store: &mut S,
    source: &CommitQuorumSource,
    limit: Option<NonZeroUsize>,
    read_only: bool,
    reuse: Option<&crate::production_store::ComponentReuse<'_>>,
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
    if let Some(reuse) = reuse {
        job = job.with_reuse(reuse);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weighted_quorum::{AuthorityWeight, QuorumWeightContext};
    use shell_primitives::{Address, ShellHash};
    fn source() -> CommitQuorumSource {
        let address = Address::from([1; 32]);
        CommitQuorumSource {
            context: QuorumWeightContext {
                chain_id: 1337,
                parent_hash: ShellHash::ZERO,
                block_hash: ShellHash::from([3; 32]),
                block_number: 1,
                authorities: vec![AuthorityWeight { address, weight: 1 }],
                signers: vec![address],
            },
            signatures: vec![BlockSignerEvidence {
                address,
                public_key: vec![4; 1952],
                signature: PQSignature::new(SignatureType::MlDsa65, vec![5; 3309]),
            }],
        }
    }
    #[test]
    fn donor_policy_matches_exact_signature_message_and_relocated_position() {
        let donor = source();
        let mut current = donor.clone();
        current.context.authorities[0].weight = 2;
        let mut added = current.signatures[0].clone();
        added.address = Address::from([0; 32]);
        added.public_key[0] ^= 1;
        current.signatures.insert(0, added);
        assert_eq!(
            donor_component_name(&current, &donor, "commit-signer-1-key").as_deref(),
            Some("commit-signer-0-key")
        );
        assert!(donor_component_name(&current, &donor, "commit-signer-0-key").is_none());
        for name in [
            "commit-weight",
            "commit-signer-01-key",
            "commit-signer-1-",
            "commit-signer-2-key",
        ] {
            assert!(donor_component_name(&current, &donor, name).is_none());
        }
        for field in 0..5 {
            let mut changed = current.clone();
            match field {
                0 => changed.context.block_hash = ShellHash::ZERO,
                1 => changed.signatures[1].public_key[0] ^= 1,
                2 => changed.signatures[1].signature.data[0] ^= 1,
                3 => changed.signatures[1].signature.sig_type = SignatureType::Dilithium3,
                _ => changed.signatures[1].address = Address::from([2; 32]),
            };
            assert!(donor_component_name(&changed, &donor, "commit-signer-1-key").is_none());
        }
    }
}
