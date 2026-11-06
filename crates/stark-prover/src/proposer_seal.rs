//! Exact ML-DSA-65 proposer seal against a frozen trusted canonical parent.
//! Selector and registry provenance remain caller/trusted-store inputs; this
//! does not prove validator weights, penalty history, quorum or consensus.
use crate::{
    canonical_signature::canonical_child_hash,
    header_hash::{verify_header_hash, BlockHeaderProof},
    mldsa_verification::{verify_mldsa65, Mldsa65VerificationProof},
};
use serde::{Deserialize, Serialize};
use shell_core::BlockHeader;
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_primitives::{Address, ShellHash};
use shell_storage::{CanonicalParentView, KvStore};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposerSealProof {
    pub version: u8,
    pub header: BlockHeaderProof,
    pub signature: Mldsa65VerificationProof,
}

/// Immutable exact-tuple crypto verifier; only full proof verification creates
/// it. Native proposer selection, header policy and authorization still apply.
#[derive(Clone, Debug)]
pub struct VerifiedProposerSeal {
    hash: ShellHash,
    proposer: Address,
    chain_id: u64,
    key: Vec<u8>,
    seal: PQSignature,
}
impl VerifiedProposerSeal {
    pub fn hash(&self) -> ShellHash {
        self.hash
    }
    pub fn proposer(&self) -> Address {
        self.proposer
    }
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}
impl Verifier for VerifiedProposerSeal {
    fn verify(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        // No native signature fallback for any changed tuple.
        Ok(key == self.key && message == self.hash.as_bytes() && signature == &self.seal)
    }
    fn sig_type(&self) -> SignatureType {
        SignatureType::MlDsa65
    }
}

/// Verify the genuine raw 32-byte header-hash message, not transaction framing.
/// The caller selects `expected_proposer` independently using its authenticated
/// authority context; a registry key alone does not establish validator status.
/// The key is captured at the parent, never resampled from live metadata.
pub fn verify_canonical_proposer_seal<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    header: &BlockHeader,
    expected_hash: &ShellHash,
    expected_proposer: &Address,
    expected_chain_id: u64,
    seal: &PQSignature,
    proof: &ProposerSealProof,
) -> Result<VerifiedProposerSeal, String> {
    if proof.version != 1
        || seal.sig_type != SignatureType::MlDsa65
        || seal.data.len() != 3309
        || header.proposer != *expected_proposer
        || view.config().chain_id != expected_chain_id
    {
        return Err("unsupported proposer seal framing or selected authority mismatch".into());
    }
    if canonical_child_hash(view, header)? != *expected_hash {
        return Err("proposer seal expected canonical hash mismatch".into());
    }
    let key = view
        .registered_key(expected_proposer)
        .map_err(|e| e.to_string())?
        .ok_or("proposer key absent at canonical parent")?;
    if key.len() != 1952 {
        return Err("proposer key is not ML-DSA-65 shaped".into());
    }
    verify_header_hash(&proof.header, header, expected_hash)?;
    verify_mldsa65(&proof.signature, &key, expected_hash.as_bytes(), &seal.data)?;
    Ok(VerifiedProposerSeal {
        hash: *expected_hash,
        proposer: *expected_proposer,
        chain_id: expected_chain_id,
        key,
        seal: seal.clone(),
    })
}
