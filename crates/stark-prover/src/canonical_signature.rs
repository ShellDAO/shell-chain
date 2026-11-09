//! Registered signature verification against a sealed trusted-store parent.
//! Base verification uses local canonical context. Additional bindings prove
//! body membership and header hashing; consensus authentication remains external.
use crate::{
    account_state::{verify_account_state, AccountStateProof},
    registered_signature::{
        verify_registered_signature_entry, verify_unbound_signature_entry,
        RegisteredSignatureProof, VerifiedRegisteredSignature,
    },
    SigBatchEntry,
};
use shell_core::SignedTransaction;
use shell_primitives::ShellHash;
use shell_storage::{CanonicalParentView, KvStore};
/// Immutable cryptographic result plus the independently selected local parent.
#[derive(Clone, Debug)]
pub struct CanonicalRegisteredSignature {
    signature: VerifiedRegisteredSignature,
    tip: ShellHash,
    parent: ShellHash,
}
impl CanonicalRegisteredSignature {
    pub fn signature(&self) -> &VerifiedRegisteredSignature {
        &self.signature
    }
    pub fn tip(&self) -> ShellHash {
        self.tip
    }
    pub fn parent(&self) -> ShellHash {
        self.parent
    }
}
fn signing_source_in_bounds(signed: &SignedTransaction) -> bool {
    let mut raw_bytes = signed.tx.data.len();
    for entry in signed.tx.access_list.iter().flatten() {
        raw_bytes = raw_bytes
            .saturating_add(32)
            .saturating_add(entry.storage_keys.len().saturating_mul(32));
    }
    raw_bytes = raw_bytes.saturating_add(
        signed
            .tx
            .blob_versioned_hashes
            .as_ref()
            .map_or(0, |hashes| hashes.len().saturating_mul(32)),
    );
    raw_bytes <= crate::blake3_hash::MAX_HASH_BYTES
}

/// Resolve the key/account only from the sealed historical view, then prove
/// the complete registered signature predicate. A key first registered later
/// must not authorize this profile at an earlier parent. The transaction itself
/// is an independently expected caller input; canonical body membership and
/// native nonce/fee/activation policy remain separate checks.
pub fn verify_canonical_registered_signature<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    signed: &SignedTransaction,
    account_proof: &AccountStateProof,
    proof: &RegisteredSignatureProof,
) -> Result<CanonicalRegisteredSignature, String> {
    if signed.tx.chain_id != view.config().chain_id {
        return Err("transaction chain identity differs from canonical context".into());
    }
    if signed.tx.tx_type > 3
        || signed.aa_bundle.is_some()
        || !matches!(
            (proof.version, signed.signature.sig_type),
            (1, shell_crypto::SignatureType::MlDsa65)
                | (3, shell_crypto::SignatureType::Dilithium3)
        )
        || signed.signature.data.len() != 3309
        || signed
            .pubkey_mode
            .pubkey_bytes()
            .is_some_and(|key| key.len() != 1952)
    {
        return Err("unsupported canonical registered signature framing".into());
    }
    if !signing_source_in_bounds(signed) {
        return Err("canonical signing source exceeds hash resource bound".into());
    }
    let key = view
        .registered_key(&signed.from)
        .map_err(|e| e.to_string())?
        .ok_or("no registered key at canonical parent; first-use profile requires its own proof")?;
    if key.len() != 1952 {
        return Err("canonical registry key shape mismatch".into());
    }
    let account = view
        .world_state()
        .map_err(|e| e.to_string())?
        .get_account(&signed.from)
        .map_err(|e| e.to_string())?;
    let state = verify_account_state(
        account_proof,
        view.parent().state_root.as_bytes(),
        signed.from.as_bytes(),
        account.as_ref(),
    )?;
    // Build the native expected identity without copying a possibly stale hash
    // cache from the caller. Proof verification still authenticates each hash.
    let mut fresh =
        SignedTransaction::new(signed.from, signed.tx.clone(), signed.signature.clone());
    fresh.pubkey_mode = signed.pubkey_mode.clone();

    let entry = SigBatchEntry::from_signed_transaction(&fresh);
    let signature = verify_registered_signature_entry(
        proof,
        signed,
        &key,
        &state,
        fresh.hash().as_bytes(),
        &entry,
        &entry.to_leaf_bytes(),
    )?;
    Ok(CanonicalRegisteredSignature {
        signature,
        tip: view.tip(),
        parent: view.parent().hash(),
    })
}

/// Check the unbound-account profile against the independently frozen parent.
/// A later registry entry never supplies the key for an earlier first-use transaction.
pub(crate) fn verify_canonical_unbound_signature<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    signed: &SignedTransaction,
    account_proof: &AccountStateProof,
    proof: &RegisteredSignatureProof,
) -> Result<crate::mldsa_source::VerifiedSignatureEntry, String> {
    if signed.tx.chain_id != view.config().chain_id
        || signed.tx.tx_type > 3
        || signed.aa_bundle.is_some()
        || signed.signature.sig_type != shell_crypto::SignatureType::MlDsa65
        || signed.signature.data.len() != 3309
        || signed
            .pubkey_mode
            .pubkey_bytes()
            .is_some_and(|key| key.len() != 1952)
        || !signing_source_in_bounds(signed)
    {
        return Err("unsupported canonical unbound signature framing".into());
    }
    let registered = view
        .registered_key(&signed.from)
        .map_err(|e| e.to_string())?;
    let key = match (registered, signed.pubkey_mode.pubkey_bytes()) {
        (Some(key), Some(embedded)) if key.as_slice() != embedded => {
            return Err("canonical unbound Embedded key conflicts with parent registry".into());
        }
        (Some(key), _) => key,
        (None, Some(embedded)) => embedded.to_vec(),
        (None, None) => return Err("canonical first use requires an Embedded key".into()),
    };
    if key.len() != 1952 {
        return Err("canonical unbound registry key is not ML-DSA-65 shaped".into());
    }
    let account = view
        .world_state()
        .map_err(|e| e.to_string())?
        .get_account(&signed.from)
        .map_err(|e| e.to_string())?;
    let state = verify_account_state(
        account_proof,
        view.parent().state_root.as_bytes(),
        signed.from.as_bytes(),
        account.as_ref(),
    )?;
    let mut fresh =
        SignedTransaction::new(signed.from, signed.tx.clone(), signed.signature.clone());
    fresh.pubkey_mode = signed.pubkey_mode.clone();
    let entry = SigBatchEntry::from_signed_transaction(&fresh);
    verify_unbound_signature_entry(
        proof,
        signed,
        &key,
        &state,
        fresh.hash().as_bytes(),
        &entry,
        &entry.to_leaf_bytes(),
    )
}

/// Full registered signature plus AIR membership at a frozen trusted canonical header.
/// This still does not prove network consensus or the header's own hash in AIR.
#[derive(Clone, Debug)]
pub struct BodyBoundRegisteredSignature {
    canonical: CanonicalRegisteredSignature,
    membership: crate::body_membership::VerifiedBodyMembership,
}
impl BodyBoundRegisteredSignature {
    pub fn signature(&self) -> &VerifiedRegisteredSignature {
        self.canonical.signature()
    }
    pub fn canonical(&self) -> &CanonicalRegisteredSignature {
        &self.canonical
    }
    pub fn membership(&self) -> &crate::body_membership::VerifiedBodyMembership {
        &self.membership
    }
}
/// Bind the independently expected transaction to an activated, snapshot-frozen
/// child header before returning its proof-backed native crypto verifier.
pub fn verify_body_bound_registered_signature<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    header: &shell_core::BlockHeader,
    index: u64,
    signed: &SignedTransaction,
    account: &AccountStateProof,
    signature: &RegisteredSignatureProof,
    body: &crate::body_membership::TransactionBodyProof,
) -> Result<BodyBoundRegisteredSignature, String> {
    canonical_child_hash(view, header)?;
    let membership = crate::body_membership::verify_transaction_body(body, header, signed, index)?;
    let canonical = verify_canonical_registered_signature(view, signed, account, signature)?;
    Ok(BodyBoundRegisteredSignature {
        canonical,
        membership,
    })
}

/// Resolve the activated child exclusively against the captured canonical view.
pub(crate) fn canonical_child_hash<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    header: &shell_core::BlockHeader,
) -> Result<ShellHash, String> {
    if view
        .config()
        .block_commitment_height
        .is_none_or(|height| header.number < height)
        || view.parent().number.checked_add(1) != Some(header.number)
        || header.parent_hash != view.parent().hash()
    {
        return Err("body signature requires the activated canonical child of this parent".into());
    }
    let chain = shell_storage::ChainStore::new(view.store());
    let hash = header.hash();
    if chain
        .get_block_hash_by_number(header.number)
        .map_err(|e| e.to_string())?
        != Some(hash)
        || chain
            .get_header_by_hash(&hash)
            .map_err(|e| e.to_string())?
            .as_ref()
            != Some(header)
    {
        return Err("body signature header is not captured canonical history".into());
    }
    Ok(hash)
}

/// Complete registered/body predicate bound by AIR to a caller-selected hash.
/// Canonical state and consensus authentication still rely on the trusted view.
#[derive(Clone, Debug)]
pub struct HeaderBoundRegisteredSignature {
    body: BodyBoundRegisteredSignature,
    header: crate::header_hash::VerifiedHeaderHash,
}
impl HeaderBoundRegisteredSignature {
    pub fn signature(&self) -> &VerifiedRegisteredSignature {
        self.body.signature()
    }
    pub fn body(&self) -> &BodyBoundRegisteredSignature {
        &self.body
    }
    pub fn header(&self) -> &crate::header_hash::VerifiedHeaderHash {
        &self.header
    }
}

/// Extend an already verified predicate; there is no unchecked signature token
/// constructor. Expected hash selection must be independent of the proof.
pub fn bind_registered_signature_header(
    body: BodyBoundRegisteredSignature,
    header: &shell_core::BlockHeader,
    proof: &crate::header_hash::BlockHeaderProof,
    expected_hash: &ShellHash,
) -> Result<HeaderBoundRegisteredSignature, String> {
    if body.membership().block_hash() != *expected_hash {
        return Err("body and expected header identities differ".into());
    }
    let header = crate::header_hash::verify_header_hash(proof, header, expected_hash)?;
    Ok(HeaderBoundRegisteredSignature { body, header })
}
