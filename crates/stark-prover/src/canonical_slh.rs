//! SHA2-256f default-account authority for an exact canonical block envelope.
//! The caller still authenticates consensus, activation and native execution.
use crate::{
    account_state::{verify_account_state, AccountStateProof},
    blake3_hash::{verify_hash, Blake3HashProof},
    body_membership::{verify_large_transaction_envelope, LargeTransactionEnvelopeProof},
    mldsa_source::VerifiedSignatureEntry,
    slh_fors::{SlhForsInputs, SlhForsProof, SLH_SHA2_256F_SIGNATURE_BYTES},
    slh_signature::{
        verify_slh_signature_profile_using, SlhSignatureManifest, SLH_HYPERTREE_LAYERS,
    },
    slh_xmss::SlhXmssProof,
    SigBatchEntry,
};
use serde::{Deserialize, Serialize};
use shell_core::{Account, BlockHeader, SignedTransaction};
use shell_crypto::SignatureType;
use shell_primitives::ShellHash;
use shell_storage::{CanonicalParentView, KvStore};

/// Version one binds a registered account; version two proves a funded unbound
/// account's tagged address. Version three binds a registered account with the
/// explicit wide-WOTS profile. Every version requires all seventeen layers.
/// Neither the manifest nor a persisted status is cryptographic authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSlhTransactionProof {
    pub version: u8,
    pub account: AccountStateProof,
    pub public_key_hash: Blake3HashProof,
    pub tagged_key: Option<Blake3HashProof>,
    pub envelope: LargeTransactionEnvelopeProof,
    pub leaf: Blake3HashProof,
    pub manifest: SlhSignatureManifest,
    pub fors: SlhForsProof,
    pub layers: Vec<SlhXmssProof>,
}

pub(crate) fn inputs(
    signed: &SignedTransaction,
    key: &[u8],
    message: [u8; 32],
) -> Result<SlhForsInputs, String> {
    if signed.signature.sig_type != SignatureType::SphincsSha2256f
        || signed.signature.data.len() != SLH_SHA2_256F_SIGNATURE_BYTES
        || key.len() != 64
        || signed.tx.tx_type > 3
        || signed.aa_bundle.is_some()
        || signed
            .pubkey_mode
            .pubkey_bytes()
            .is_some_and(|pk| pk != key)
    {
        return Err("unsupported canonical SLH sender framing/key/signature".into());
    }
    Ok(SlhForsInputs {
        public_seed: key[..32].try_into().expect("checked public key"),
        public_root: key[32..].try_into().expect("checked public key"),
        message,
        signature: signed.signature.data.to_vec(),
    })
}

pub(crate) fn verify_at_source(
    proof: &CanonicalSlhTransactionProof,
    parent: &BlockHeader,
    header: &BlockHeader,
    signed: &SignedTransaction,
    index: u64,
    key: &[u8],
    account: &Account,
) -> Result<VerifiedSignatureEntry, String> {
    let unbound = account.pq_pubkey_hash == ShellHash::ZERO;
    if !(if unbound {
        proof.version == 2
    } else {
        matches!(proof.version, 1 | 3)
    }) || proof.layers.len() != usize::from(SLH_HYPERTREE_LAYERS)
    {
        return Err("canonical SLH proof version/layer count mismatch".into());
    }
    let expected = inputs(signed, key, proof.envelope.signing_hash.output)?;
    let state = verify_account_state(
        &proof.account,
        parent.state_root.as_bytes(),
        signed.from.as_bytes(),
        Some(account),
    )?;
    let bound = state.account().ok_or("canonical SLH account absent")?;
    if bound.validation_code_hash.is_some() {
        return Err("canonical SLH requires a default account".into());
    }
    verify_hash(&proof.public_key_hash, key, &proof.public_key_hash.output)?;
    if unbound {
        let mut bytes = vec![signed.signature.sig_type.as_u8()];
        bytes.extend_from_slice(key);
        verify_hash(
            proof
                .tagged_key
                .as_ref()
                .ok_or("canonical SLH unbound address proof absent")?,
            &bytes,
            signed.from.as_bytes(),
        )?;
    } else if let Some(tagged) = &proof.tagged_key {
        let mut bytes = vec![signed.signature.sig_type.as_u8()];
        bytes.extend_from_slice(key);
        verify_hash(tagged, &bytes, bound.pq_pubkey_hash.as_bytes())?;
    } else if bound.pq_pubkey_hash.as_bytes() != &proof.public_key_hash.output {
        return Err("canonical SLH registered raw-key commitment mismatch".into());
    }
    let id = signed.uncached_hash();
    verify_large_transaction_envelope(&proof.envelope, header, signed, index, &id)?;
    // The expected message comes from the proved signing payload above. No native
    // signature verifier or SHA digest participates in this acceptance predicate.
    verify_slh_signature_profile_using(
        proof.version == 3,
        &proof.manifest,
        &expected,
        &proof.fors,
        |layer, _| Ok(proof.layers[usize::from(layer)].clone()),
    )?;
    let mut entry = SigBatchEntry::from_signed_transaction(signed);
    entry.msg_hash = expected.message;
    let mut bytes = entry.msg_hash.to_vec();
    bytes.extend_from_slice(&entry.pk_hash);
    let leaf = entry.to_leaf_bytes();
    verify_hash(&proof.leaf, &bytes, &leaf)?;
    Ok(VerifiedSignatureEntry::from_verified_parts(
        entry,
        leaf,
        *id.as_bytes(),
        *signed.from.as_bytes(),
    ))
}

/// Resolve authority only from the independently sealed historical parent.
/// A future registration never supplies this key. A funded unbound account can
/// supply its first Embedded key, but still needs the complete address AIR.
pub(crate) fn verify_at_parent<S: KvStore + 'static>(
    view: &CanonicalParentView<S>,
    header: &BlockHeader,
    signed: &SignedTransaction,
    index: u64,
    proof: &CanonicalSlhTransactionProof,
) -> Result<VerifiedSignatureEntry, String> {
    if signed.tx.chain_id != view.config().chain_id {
        return Err("canonical SLH chain identity mismatch".into());
    }
    let account = view
        .world_state()
        .map_err(|e| e.to_string())?
        .get_account(&signed.from)
        .map_err(|e| e.to_string())?
        .ok_or("canonical SLH parent account absent")?;
    let registered = view
        .registered_key(&signed.from)
        .map_err(|e| e.to_string())?;
    let key = registered
        .as_deref()
        .or_else(|| {
            if account.pq_pubkey_hash == ShellHash::ZERO {
                signed.pubkey_mode.pubkey_bytes()
            } else {
                None
            }
        })
        .ok_or("canonical SLH parent registry or first Embedded key absent")?;
    verify_at_source(proof, view.parent(), header, signed, index, key, &account)
}
