//! Complete sender cryptography for one retained trusted canonical block.
//! Canonical storage and native body hashing select the sources independently;
//! this is not an AIR proof of body membership, proposer consensus or execution.
use crate::{
    account_state::AccountStateProof,
    canonical_signature::{canonical_child_hash, verify_canonical_registered_signature},
    registered_signature::{RegisteredSignatureProof, VerifiedRegisteredSignature},
};
use serde::{Deserialize, Serialize};
use shell_core::Block;
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_primitives::ShellHash;
use shell_storage::{CanonicalParentView, ChainStore, KvStore};

pub const MAX_CANONICAL_SIGNATURE_BATCH: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTransactionProof {
    pub account: AccountStateProof,
    pub signature: RegisteredSignatureProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSignatureBatchProof {
    pub version: u8,
    pub transactions: Vec<CanonicalTransactionProof>,
}

/// No public constructor or deserializer: every sender predicate must pass
/// before this verifier exists. Unmatched tuples never use native crypto.
#[derive(Clone, Debug)]
pub struct VerifiedCanonicalSignatureBatch {
    tip: ShellHash,
    parent: ShellHash,
    block: ShellHash,
    chain_id: u64,
    signatures: Vec<VerifiedRegisteredSignature>,
}
impl VerifiedCanonicalSignatureBatch {
    pub fn tip(&self) -> ShellHash {
        self.tip
    }
    pub fn parent(&self) -> ShellHash {
        self.parent
    }
    pub fn block(&self) -> ShellHash {
        self.block
    }
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn len(&self) -> usize {
        self.signatures.len()
    }
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
    pub fn matches_block(&self, block: &Block) -> bool {
        block.hash() == self.block
            && block.header.parent_hash == self.parent
            && block.transactions.len() == self.signatures.len()
            && self
                .signatures
                .iter()
                .zip(&block.transactions)
                .all(|(proof, tx)| proof.matches_transaction(tx))
    }
}
impl Verifier for VerifiedCanonicalSignatureBatch {
    fn verify(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        for proof in &self.signatures {
            if proof.verify(key, message, signature)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn sig_type(&self) -> SignatureType {
        SignatureType::MlDsa65
    }
}

/// Verify all ordered senders against one independently frozen historical
/// parent. The block must equal the captured canonical body, not merely carry
/// its header. This bounded registered/default-account profile cannot authorize
/// first-use keys, AA/custom validators, other algorithms or pruned witnesses.
pub fn verify_canonical_signature_batch<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    block: &Block,
    proof: &CanonicalSignatureBatchProof,
) -> Result<VerifiedCanonicalSignatureBatch, String> {
    if proof.version != 1
        || block.transactions.is_empty()
        || block.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
        || proof.transactions.len() != block.transactions.len()
    {
        return Err("canonical signature batch version/count/profile mismatch".into());
    }
    let hash = canonical_child_hash(view, &block.header)?;
    let chain = ChainStore::new(view.store());
    if chain
        .get_block_by_hash(&hash)
        .map_err(|e| e.to_string())?
        .as_ref()
        != Some(block)
    {
        return Err("canonical signature batch body differs from captured source".into());
    }
    chain
        .verify_block_body_commitment(block)
        .map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut signatures = Vec::with_capacity(block.transactions.len());
    for (tx, item) in block.transactions.iter().zip(&proof.transactions) {
        let checked =
            verify_canonical_registered_signature(view, tx, &item.account, &item.signature)?;
        let signature = checked.signature();
        if !seen.insert(*signature.entry().transaction_id()) {
            return Err("duplicate canonical signature batch source".into());
        }
        signatures.push(signature.clone());
    }
    Ok(VerifiedCanonicalSignatureBatch {
        tip: view.tip(),
        parent: view.parent().hash(),
        block: hash,
        chain_id: view.config().chain_id,
        signatures,
    })
}
