//! Bounded off-chain availability encoding. Decoding never authenticates a quorum.
use super::{CommitQuorumProof, MAX_COMMIT_PROOF_SIGNERS};
use crate::mldsa_verification::Mldsa65VerificationProof;
use serde::Deserializer;
const PREFIX: &[u8] = b"\0commit-quorum/cbor/v1/";
const MAX_BYTES: usize = shell_core::MAX_CANONICAL_PROOF_BYTES as usize;

pub(super) fn deserialize_signatures<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<Mldsa65VerificationProof>, D::Error> {
    crate::compact_canonical::bounded_vec::<D, Mldsa65VerificationProof, MAX_COMMIT_PROOF_SIGNERS>(
        d,
    )
}
/// Serialize public proof data under its own role domain and the shared byte cap.
pub fn encode(proof: &CommitQuorumProof, limit: usize) -> Result<Vec<u8>, String> {
    if proof.version != 1 || proof.signatures.len() > MAX_COMMIT_PROOF_SIGNERS {
        return Err("quorum payload proof version/signer count".into());
    }
    let body_limit = limit
        .min(MAX_BYTES)
        .checked_sub(PREFIX.len())
        .ok_or("quorum payload byte limit")?;
    let body = crate::compact_canonical::cbor(proof, body_limit)?;
    let mut result = PREFIX.to_vec();
    result.extend(body);
    Ok(result)
}
/// Reject other proof roles, noncanonical bytes, excess nesting/counts and trailers.
/// The caller must independently select the source and verify every AIR component.
pub fn decode(bytes: &[u8]) -> Result<CommitQuorumProof, String> {
    if bytes.len() > MAX_BYTES {
        return Err("quorum payload byte limit".into());
    }
    let body = bytes
        .strip_prefix(PREFIX)
        .ok_or("quorum payload role/domain mismatch")?;
    let proof: CommitQuorumProof = crate::compact_canonical::uncbor(body)?;
    if encode(&proof, bytes.len())? != bytes {
        return Err("noncanonical quorum payload bytes".into());
    }
    Ok(proof)
}
