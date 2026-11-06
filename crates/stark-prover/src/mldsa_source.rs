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
