//! Bounded off-chain availability encoding. Decoding never authenticates a quorum.
use super::{CommitQuorumProof, MAX_COMMIT_PROOF_SIGNERS};
use crate::mldsa_verification::Mldsa65VerificationProof;
use serde::Deserializer;
const SLH_PREFIX: &[u8] = b"\0commit-quorum/cbor/v2/";
const PREFIX: &[u8] = b"\0commit-quorum/cbor/v1/";
const MAX_BYTES: usize = shell_core::MAX_CANONICAL_PROOF_BYTES as usize;

pub(super) fn deserialize_signatures<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<Mldsa65VerificationProof>, D::Error> {
    crate::compact_canonical::bounded_vec::<D, Mldsa65VerificationProof, MAX_COMMIT_PROOF_SIGNERS>(
        d,
    )
}
pub(super) fn deserialize_slh_signatures<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<super::slh::CommitSlhProof>, D::Error> {
    crate::compact_canonical::bounded_vec::<D, super::slh::CommitSlhProof, MAX_COMMIT_PROOF_SIGNERS>(
        d,
    )
}
/// Serialize public proof data under its own role domain and the shared byte cap.
pub fn encode(proof: &CommitQuorumProof, limit: usize) -> Result<Vec<u8>, String> {
    if !matches!(proof.version, 1 | 2)
        || (proof.version == 1 && !proof.slh_signatures.is_empty())
        || (proof.version == 2 && proof.slh_signatures.is_empty())
        || proof.signatures.len() + proof.slh_signatures.len() > MAX_COMMIT_PROOF_SIGNERS
    {
        return Err("quorum payload proof version/signer count".into());
    }
    let prefix = if proof.version == 1 {
        PREFIX
    } else {
        SLH_PREFIX
    };
    let body_limit = limit
        .min(MAX_BYTES)
        .checked_sub(prefix.len())
        .ok_or("quorum payload byte limit")?;
    let body = crate::compact_canonical::cbor(proof, body_limit)?;
    let mut result = prefix.to_vec();
    result.extend(body);
    Ok(result)
}
/// Reject other proof roles, noncanonical bytes, excess nesting/counts and trailers.
/// The caller must independently select the source and verify every AIR component.
pub fn decode(bytes: &[u8]) -> Result<CommitQuorumProof, String> {
    if bytes.len() > MAX_BYTES {
        return Err("quorum payload byte limit".into());
    }
    let (body, version) = if let Some(body) = bytes.strip_prefix(PREFIX) {
        (body, 1)
    } else if let Some(body) = bytes.strip_prefix(SLH_PREFIX) {
        (body, 2)
    } else {
        return Err("quorum payload role/domain mismatch".into());
    };
    let proof: CommitQuorumProof = crate::compact_canonical::uncbor(body)?;
    if proof.version != version {
        return Err("quorum payload role/version mismatch".into());
    }
    if encode(&proof, bytes.len())? != bytes {
        return Err("noncanonical quorum payload bytes".into());
    }
    Ok(proof)
}
