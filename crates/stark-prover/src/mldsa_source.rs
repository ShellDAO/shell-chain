//! Joint public verification of canonical outer signing sources and ML-DSA-65.
//!
//! The caller supplies the expected transaction, raw key/signature and key hash.
//! This does not authenticate chain history, account authority or an AA bundle.

use crate::{
    blake3_hash::{verify_hash, verify_transaction_signing_hash, Blake3HashProof},
    mldsa_verification::{verify_mldsa65, Mldsa65VerificationProof},
};
use serde::{Deserialize, Serialize};
use shell_crypto::SignatureType;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionSignatureProof {
    pub version: u8,
    pub signing_hash: Blake3HashProof,
    pub public_key_hash: Blake3HashProof,
    pub signature: Mldsa65VerificationProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedSenderSignatureProof {
    pub version: u8,
    pub sender_address: Blake3HashProof,
    pub transaction: TransactionSignatureProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentifiedSenderSignatureProof {
    pub version: u8,
    pub transaction_id: Blake3HashProof,
    pub sender: DerivedSenderSignatureProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntryProof {
    pub version: u8,
    pub leaf: Blake3HashProof,
    pub identified: IdentifiedSenderSignatureProof,
}

/// A verified snapshot of a caller-expected entry, leaf and transaction ID.
/// Only complete proof verification constructs this value. It does not prove
/// canonical chain membership, registry absence or account authority.
#[derive(Clone, Debug)]
pub struct VerifiedSignatureEntry {
    entry: crate::SigBatchEntry,
    leaf: [u8; 32],
    transaction_id: [u8; 32],
}

impl VerifiedSignatureEntry {
    pub fn entry(&self) -> &crate::SigBatchEntry {
        &self.entry
    }

    pub fn leaf_bytes(&self) -> &[u8; 32] {
        &self.leaf
    }

    pub fn transaction_id(&self) -> &[u8; 32] {
        &self.transaction_id
    }
}

/// Authenticate the existing Embedded batch-entry mapping and BLAKE3 leaf,
/// together with the complete identified sender/source/signature predicate.
/// The message identifier is the sender signing digest; the key identifier is
/// the first 32 raw key bytes (rho), not the full-key hash or sender address.
/// The native mapper/hash is not a verification fallback. Reference authority
/// and ordered batch/chain acceptance remain outside this stateless predicate.
pub fn verify_signature_entry(
    proof: &SignatureEntryProof,
    expected: &shell_core::SignedTransaction,
    expected_public_key_hash: &[u8; 32],
    expected_transaction_id: &[u8; 32],
    expected_entry: &crate::SigBatchEntry,
    expected_leaf: &[u8; 32],
) -> Result<VerifiedSignatureEntry, String> {
    if proof.version != 1 {
        return Err("invalid signature entry proof version".into());
    }
    let key = expected
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("signature entry requires an Embedded key; registry authority is not proved")?;
    if key.len() != 1952 {
        return Err("invalid signature entry ML-DSA-65 key shape".into());
    }
    if expected_entry.msg_hash != proof.identified.sender.transaction.signing_hash.output
        || expected_entry.pk_hash.as_slice() != &key[..32]
    {
        return Err("invalid signature entry message or legacy key identifier binding".into());
    }
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&expected_entry.msg_hash);
    preimage[32..].copy_from_slice(&expected_entry.pk_hash);
    verify_hash(&proof.leaf, &preimage, expected_leaf)
        .map_err(|e| format!("signature entry leaf: {e}"))?;
    verify_identified_sender_signature(
        &proof.identified,
        expected,
        expected_public_key_hash,
        expected_transaction_id,
    )?;
    Ok(VerifiedSignatureEntry {
        entry: expected_entry.clone(),
        leaf: *expected_leaf,
        transaction_id: *expected_transaction_id,
    })
}

/// Bind the complete address-derived sender/signature predicate to an expected
/// canonical transaction ID. This uses the native identity domain and full
/// sender/signing-digest widths. Authentication witnesses remain excluded from
/// the ID, but must still pass the complete signature predicate.
///
/// The caller supplies the expected ID independently. Neither a self-declared
/// proof output nor SignedTransaction's cached native hash is an acceptance
/// fallback. The inner predicate retains its stateless Embedded-only scope.
pub fn verify_identified_sender_signature(
    proof: &IdentifiedSenderSignatureProof,
    expected: &shell_core::SignedTransaction,
    expected_public_key_hash: &[u8; 32],
    expected_transaction_id: &[u8; 32],
) -> Result<(), String> {
    if proof.version != 1 {
        return Err("invalid identified sender proof version".into());
    }
    let mut preimage = Vec::with_capacity(shell_core::PQTX_ID_DOMAIN.len() + 64);
    preimage.extend_from_slice(shell_core::PQTX_ID_DOMAIN);
    preimage.extend_from_slice(expected.from.as_bytes());
    preimage.extend_from_slice(&proof.sender.transaction.signing_hash.output);
    verify_hash(&proof.transaction_id, &preimage, expected_transaction_id)
        .map_err(|e| format!("transaction ID source: {e}"))?;
    verify_derived_sender_signature(&proof.sender, expected, expected_public_key_hash)
}

/// Verify an address-derived Embedded sender and its ordinary ML-DSA-65
/// transaction signature. The address preimage is exactly algo_id || raw key.
///
/// This stateless predicate does not establish registry absence, current
/// account authority or permission to register a key. Native registered/rotated
/// accounts can retain an address derived from an earlier key and must follow
/// their canonical registry/hash/activation rules instead of this predicate.
/// Reference keys and native AA framing are outside this scope.
pub fn verify_derived_sender_signature(
    proof: &DerivedSenderSignatureProof,
    expected: &shell_core::SignedTransaction,
    expected_public_key_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.version != 1 || expected.signature.sig_type != SignatureType::MlDsa65 {
        return Err("invalid derived sender proof version or algorithm".into());
    }
    if expected.tx.tx_type > 3 || expected.aa_bundle.is_some() {
        return Err("unsupported derived sender AA or outer transaction framing".into());
    }
    let key = expected
        .pubkey_mode
        .pubkey_bytes()
        .ok_or("derived sender requires an Embedded key; registry authority is not proved")?;
    if key.len() != 1952 || expected.signature.data.len() != 3309 {
        return Err("invalid derived sender ML-DSA-65 shape".into());
    }
    let mut preimage = Vec::with_capacity(1 + key.len());
    preimage.push(SignatureType::MlDsa65.as_u8());
    preimage.extend_from_slice(key);
    verify_hash(&proof.sender_address, &preimage, expected.from.as_bytes())
        .map_err(|e| format!("sender address source: {e}"))?;
    verify_transaction_signature(
        &proof.transaction,
        &expected.tx,
        key,
        &expected.signature.data,
        expected_public_key_hash,
    )
}

/// Verify both source hashes and a complete signature over this exact signing
/// digest. There is no caller-supplied signing digest or native hash/signature
/// fallback. Only outer transaction types 0..=3 are supported; AA sender
/// signatures require their distinct bundle framing and are rejected here.
pub fn verify_transaction_signature(
    proof: &TransactionSignatureProof,
    expected_transaction: &shell_core::Transaction,
    expected_key: &[u8],
    expected_signature: &[u8],
    expected_public_key_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.version != 1 || expected_key.len() != 1952 || expected_signature.len() != 3309 {
        return Err("invalid transaction signature proof version or ML-DSA-65 shape".into());
    }
    if expected_transaction.tx_type > 3 {
        return Err(
            "unsupported outer transaction type; AA sender bundle framing is not proved".into(),
        );
    }
    verify_transaction_signing_hash(
        &proof.signing_hash,
        expected_transaction,
        SignatureType::MlDsa65.as_u8(),
        &proof.signing_hash.output,
    )
    .map_err(|e| format!("transaction source: {e}"))?;
    verify_hash(
        &proof.public_key_hash,
        expected_key,
        expected_public_key_hash,
    )
    .map_err(|e| format!("public key source: {e}"))?;
    verify_mldsa65(
        &proof.signature,
        expected_key,
        &proof.signing_hash.output,
        expected_signature,
    )
    .map_err(|e| format!("signature: {e}"))
}
