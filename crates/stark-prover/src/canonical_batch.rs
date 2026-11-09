//! Complete sender cryptography for one retained trusted canonical block.
//! Canonical storage and native body hashing select the sources independently;
//! this is not an AIR proof of body membership, proposer consensus or execution.
use crate::{
    account_state::AccountStateProof,
    canonical_signature::{
        canonical_child_hash, verify_canonical_registered_signature,
        verify_canonical_unbound_signature,
    },
    mldsa_source::VerifiedSignatureEntry,
    proposer_seal::{verify_seal_at_parent, ProposerSealProof, VerifiedProposerSeal},
    registered_signature::RegisteredSignatureProof,
};
use serde::{Deserialize, Serialize};
use shell_core::{Block, PubkeyMode, SignedTransaction, Transaction};
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};
use shell_primitives::ShellHash;
use shell_storage::{CanonicalParentView, ChainStore, KvStore};

pub const MAX_CANONICAL_SIGNATURE_BATCH: usize = 16;

/// Private exact tuple retained only after the account and complete sender predicate pass.
#[derive(Clone, Debug)]
struct VerifiedBatchSignature {
    entry: VerifiedSignatureEntry,
    transaction: Transaction,
    mode: PubkeyMode,
    key: Vec<u8>,
    signature: PQSignature,
}
impl VerifiedBatchSignature {
    fn matches_transaction(&self, signed: &SignedTransaction) -> bool {
        signed.from.as_bytes() == self.entry.sender()
            && signed.tx == self.transaction
            && signed.pubkey_mode == self.mode
            && signed.signature == self.signature
            && signed.aa_bundle.is_none()
    }
    fn verifies(&self, key: &[u8], message: &[u8], signature: &PQSignature) -> bool {
        key == self.key && message == self.entry.entry().msg_hash && signature == &self.signature
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer: Option<ProposerSealProof>,
}
impl CanonicalSignatureBatchProof {
    fn valid_profile(&self) -> bool {
        matches!(
            (self.version, self.proposer.is_some()),
            (1, false) | (2, true)
        )
    }
}

/// No public constructor or deserializer: every sender predicate must pass
/// before this verifier exists. Unmatched tuples never use native crypto.
#[derive(Clone, Debug)]
pub struct VerifiedCanonicalSignatureBatch {
    tip: ShellHash,
    parent: ShellHash,
    block: ShellHash,
    chain_id: u64,
    signatures: Vec<VerifiedBatchSignature>,
    proposer: Option<VerifiedProposerSeal>,
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
    pub fn proposer_seal(&self) -> Option<&VerifiedProposerSeal> {
        self.proposer.as_ref()
    }
    pub fn matches_block(&self, block: &Block) -> bool {
        block.hash() == self.block
            && self
                .proposer
                .as_ref()
                .is_none_or(|proof| proof.matches_block(block))
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
            if proof.verifies(key, message, signature) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn sig_type(&self) -> SignatureType {
        self.signatures
            .first()
            .map(|s| s.signature.sig_type)
            .unwrap_or(SignatureType::MlDsa65)
    }
}

/// Verify all ordered senders against one independently frozen historical
/// parent. The block must equal the captured canonical body, not merely carry
/// its header. Registered MLDSA65 and PQClean Dilithium3 use profiles one and
/// three respectively; unbound MLDSA65 and PQClean Dilithium3 default accounts
/// use versions two/four with a complete derived-address proof and the historical
/// registry's Embedded/Reference rules. AA, other algorithms and pruned witnesses
/// remain outside this profile.
pub fn verify_canonical_signature_batch<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    block: &Block,
    proof: &CanonicalSignatureBatchProof,
) -> Result<VerifiedCanonicalSignatureBatch, String> {
    if !proof.valid_profile()
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
    verify_batch_at_parent(view, block, proof, hash)
}

/// Verify a proposed canonical extension before its body exists in storage.
/// The caller must separately authenticate the proposer and execute the block.
/// Only an activated child of the independently captured current tip qualifies;
/// this never inserts a candidate into the trusted view.
pub fn verify_candidate_signature_batch<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    block: &Block,
    proof: &CanonicalSignatureBatchProof,
) -> Result<VerifiedCanonicalSignatureBatch, String> {
    if view.tip() != view.parent().hash()
        || view.parent().number.checked_add(1) != Some(block.number())
        || block.header.parent_hash != view.tip()
        || view
            .config()
            .block_commitment_height
            .is_none_or(|height| block.number() < height)
    {
        return Err("candidate signature batch requires activated current canonical parent".into());
    }
    ChainStore::new(view.store())
        .verify_block_body_commitment(block)
        .map_err(|e| e.to_string())?;
    verify_batch_at_parent(view, block, proof, block.hash())
}

fn verify_batch_at_parent<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    block: &Block,
    proof: &CanonicalSignatureBatchProof,
    hash: ShellHash,
) -> Result<VerifiedCanonicalSignatureBatch, String> {
    if !proof.valid_profile()
        || block.transactions.is_empty()
        || block.transactions.len() > MAX_CANONICAL_SIGNATURE_BATCH
        || proof.transactions.len() != block.transactions.len()
    {
        return Err("canonical signature batch version/count/profile mismatch".into());
    }
    // The independent native caller still selects and authorizes the proposer.
    // Refuse an invalid mandatory seal before spending work on sender graphs.
    let proposer = proof
        .proposer
        .as_ref()
        .map(|seal| {
            verify_seal_at_parent(
                view,
                &block.header,
                &hash,
                &block.header.proposer,
                view.config().chain_id,
                block
                    .proposer_seal
                    .as_ref()
                    .ok_or("full proof block has no proposer seal")?,
                seal,
            )
        })
        .transpose()?;
    let mut seen = std::collections::HashSet::new();
    let mut signatures = Vec::with_capacity(block.transactions.len());
    for (tx, item) in block.transactions.iter().zip(&proof.transactions) {
        let entry = match item.signature.version {
            1 | 3 => {
                verify_canonical_registered_signature(view, tx, &item.account, &item.signature)?
                    .signature()
                    .entry()
                    .clone()
            }
            2 | 4 => verify_canonical_unbound_signature(view, tx, &item.account, &item.signature)?,
            _ => return Err("unsupported canonical sender proof profile".into()),
        };
        if !seen.insert(*entry.transaction_id()) {
            return Err("duplicate canonical signature batch source".into());
        }
        let key = view
            .registered_key(&tx.from)
            .map_err(|e| e.to_string())?
            .or_else(|| tx.pubkey_mode.pubkey_bytes().map(|k| k.to_vec()))
            .ok_or("verified canonical sender key absent")?;
        signatures.push(VerifiedBatchSignature {
            entry,
            transaction: tx.tx.clone(),
            mode: tx.pubkey_mode.clone(),
            key,
            signature: tx.signature.clone(),
        });
    }
    Ok(VerifiedCanonicalSignatureBatch {
        tip: view.tip(),
        parent: view.parent().hash(),
        block: hash,
        chain_id: view.config().chain_id,
        signatures,
        proposer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::BlockHeader;
    use shell_storage::{MemoryDb, WorldState};
    use std::sync::Arc;
    #[test]
    fn legacy_wire_bytes_stay_unchanged_and_full_profile_cannot_omit_seal() {
        let bytes = br#"{"version":1,"transactions":[]}"#;
        let legacy: CanonicalSignatureBatchProof = serde_json::from_slice(bytes).unwrap();
        assert!(legacy.valid_profile());
        assert_eq!(serde_json::to_vec(&legacy).unwrap(), bytes);
        for version in [0, 2, 3] {
            let value = serde_json::json!({"version":version,"transactions":[]});
            let proof: CanonicalSignatureBatchProof = serde_json::from_value(value).unwrap();
            assert!(!proof.valid_profile());
        }
        assert!(serde_json::from_value::<CanonicalSignatureBatchProof>(
            serde_json::json!({"version":1,"transactions":[],"verified":true})
        )
        .is_err());
    }
    #[test]
    fn candidate_batch_requires_active_current_parent_and_exact_body() {
        for activation in [None, Some(1), Some(2)] {
            let db = Arc::new(MemoryDb::new());
            let root = WorldState::new(db.clone()).state_root().unwrap();
            let parent = Block {
                header: BlockHeader {
                    state_root: root,
                    ..Default::default()
                },
                transactions: vec![],
                system_transactions: vec![],
                proposer_seal: None,
            };
            let chain = ChainStore::new(db.clone());
            let cfg=serde_json::from_value(serde_json::json!({"chain_id":10,"genesis_hash":parent.hash(),"block_commitment_height":activation})).unwrap();
            chain.commit_genesis_block(&parent, &cfg).unwrap();
            let view = chain
                .canonical_parent_view(parent.hash(), parent.hash())
                .unwrap();
            let mut child = Block {
                header: BlockHeader {
                    parent_hash: parent.hash(),
                    number: 1,
                    ..Default::default()
                },
                transactions: vec![],
                system_transactions: vec![],
                proposer_seal: None,
            };
            let proof = CanonicalSignatureBatchProof {
                version: 1,
                transactions: vec![],
                proposer: None,
            };
            let before = db.scan_all().unwrap();
            let error = verify_candidate_signature_batch(&view, &child, &proof).unwrap_err();
            assert!(error.contains(if activation != Some(1) {
                "activated current canonical parent"
            } else {
                "body commitment mismatch"
            }));
            child.header.number = 2;
            assert!(verify_candidate_signature_batch(&view, &child, &proof)
                .unwrap_err()
                .contains("activated current canonical parent"));
            assert_eq!(db.scan_all().unwrap(), before);
            assert!(chain.get_header_by_hash(&child.hash()).unwrap().is_none());
        }
    }
}
