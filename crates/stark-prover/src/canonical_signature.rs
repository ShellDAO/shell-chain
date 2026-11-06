//! Registered signature verification against a sealed trusted-store parent.
//! This is local canonical context, not a consensus or block-body proof.
use crate::{
    account_state::{verify_account_state, AccountStateProof},
    registered_signature::{
        verify_registered_signature_entry, RegisteredSignatureProof, VerifiedRegisteredSignature,
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
        || signed.signature.sig_type != shell_crypto::SignatureType::MlDsa65
        || signed.signature.data.len() != 3309
        || signed
            .pubkey_mode
            .pubkey_bytes()
            .is_some_and(|key| key.len() != 1952)
    {
        return Err("unsupported canonical registered signature framing".into());
    }
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
    if raw_bytes > crate::blake3_hash::MAX_HASH_BYTES {
        return Err("canonical signing source exceeds hash resource bound".into());
    }
    let key = view
        .registered_key(&signed.from)
        .map_err(|e| e.to_string())?
        .ok_or("no registered key at canonical parent; first-use profile requires its own proof")?;
    if key.len() != 1952 {
        return Err("canonical registry key is not ML-DSA-65 shaped".into());
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
