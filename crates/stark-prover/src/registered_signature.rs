//! Default account key/address binding and exact proof-backed signature verification.
//!
//! The account snapshot authenticates its key commitment or unbound status,
//! not the separate registry KV index. Callers must obtain that index, configuration and parent state from
//! their trusted chain context and still run native account/transaction policy.

use crate::{
    account_state::VerifiedAccountState,
    blake3_hash::{verify_hash, Blake3HashProof},
    mldsa_source::{
        verify_dilithium_transaction_signature, verify_sdk_transaction_signature,
        verify_transaction_signature, TransactionSignatureProof, VerifiedSignatureEntry,
    },
    SigBatchEntry,
};
use serde::{Deserialize, Serialize};
use shell_core::{PubkeyMode, SignedTransaction, Transaction, PQTX_ID_DOMAIN};
use shell_crypto::{CryptoError, PQSignature, SignatureType, Verifier};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredSignatureProof {
    /// One/two are bound/unbound MLDSA65, three/four bound/unbound raw Dilithium3, five bound Native SDK FIPS tag zero.
    pub version: u8,
    pub transaction: TransactionSignatureProof,
    pub transaction_id: Blake3HashProof,
    pub leaf: Blake3HashProof,
    /// Algorithm-tagged account hash in registered profiles, mandatory address in unbound profiles.
    /// Its activation is a native policy check, not established by this proof.
    pub tagged_key: Option<Blake3HashProof>,
}

/// An immutable, completely proved cryptographic result and account snapshot.
/// This is not an authorization ticket: native policy must independently check
/// the canonical parent/root, registry, activation, nonce, fees and resources.
#[derive(Clone, Debug)]
pub struct VerifiedRegisteredSignature {
    entry: VerifiedSignatureEntry,
    account: VerifiedAccountState,
    transaction: Transaction,
    mode: PubkeyMode,
    key: Vec<u8>,
    signature: PQSignature,
}

impl VerifiedRegisteredSignature {
    pub fn entry(&self) -> &VerifiedSignatureEntry {
        &self.entry
    }

    pub fn account(&self) -> &VerifiedAccountState {
        &self.account
    }

    /// Bind the native caller's transaction fields without trusting a cached ID.
    /// Native state/registry/configuration must still be checked independently.
    pub fn matches_transaction(&self, signed: &SignedTransaction) -> bool {
        signed.from.as_bytes() == self.entry.sender()
            && signed.tx == self.transaction
            && signed.pubkey_mode == self.mode
            && signed.signature == self.signature
            && signed.aa_bundle.is_none()
    }
}

impl Verifier for VerifiedRegisteredSignature {
    fn verify(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &PQSignature,
    ) -> Result<bool, CryptoError> {
        // No native signature fallback, including on a different input tuple.
        Ok(pubkey == self.key
            && message == self.entry.entry().msg_hash
            && signature == &self.signature)
    }

    fn sig_type(&self) -> SignatureType {
        self.signature.sig_type
    }
}

/// Verify a registered account's committed raw or algorithm-tagged key binding,
/// complete selected signature transcript, canonical ID and native batch leaf.
/// Embedded keys must equal the expected registry key; Reference leaves use
/// the retained full sender address. No derived-address equality is imposed.
///
/// `state` must already have been verified against an independently expected
/// root. This bounded default-account profile rejects absent/unbound accounts
/// and custom validators. It does not prove registry membership or its absence,
/// tagged-key activation, canonical history, or a key-rotation transaction.
pub fn verify_registered_signature_entry(
    proof: &RegisteredSignatureProof,
    expected: &SignedTransaction,
    expected_key: &[u8],
    state: &VerifiedAccountState,
    expected_id: &[u8; 32],
    expected_entry: &SigBatchEntry,
    expected_leaf: &[u8; 32],
) -> Result<VerifiedRegisteredSignature, String> {
    if !matches!(
        (proof.version, expected.signature.sig_type),
        (1, SignatureType::MlDsa65) | (3 | 5, SignatureType::Dilithium3)
    ) {
        return Err("invalid registered signature proof version or algorithm".into());
    }
    if expected.tx.tx_type > 3 || expected.aa_bundle.is_some() || expected_key.len() != 1952 {
        return Err("unsupported registered signature framing or key shape".into());
    }
    if state.address() != expected.from.as_bytes() {
        return Err("registered signature account address mismatch".into());
    }
    let account = state
        .account()
        .ok_or("registered signature account absent")?;
    if account.validation_code_hash.is_some()
        || account.pq_pubkey_hash == shell_primitives::ShellHash::ZERO
    {
        return Err("registered signature requires a bound default account".into());
    }
    if let Some(tagged) = &proof.tagged_key {
        let mut preimage = Vec::with_capacity(1 + expected_key.len());
        preimage.push(expected.signature.sig_type.as_u8());
        preimage.extend_from_slice(expected_key);
        verify_hash(tagged, &preimage, account.pq_pubkey_hash.as_bytes())
            .map_err(|e| format!("registered algorithm key binding: {e}"))?;
    } else if account.pq_pubkey_hash.as_bytes() != &proof.transaction.public_key_hash.output {
        return Err("registered raw key binding mismatch".into());
    }
    let entry = verify_entry_sources(
        proof,
        expected,
        expected_key,
        expected_id,
        expected_entry,
        expected_leaf,
    )?;
    Ok(VerifiedRegisteredSignature {
        entry,
        account: state.clone(),
        transaction: expected.tx.clone(),
        mode: expected.pubkey_mode.clone(),
        key: expected_key.to_vec(),
        signature: expected.signature.clone(),
    })
}

/// Verify an unbound default account's complete signature and derived address.
/// The caller must independently resolve the historical registry: Embedded is
/// required when it is absent; Reference is allowed only after registration.
/// Native activation, nonce, funds and atomic key registration remain mandatory.
pub fn verify_unbound_signature_entry(
    proof: &RegisteredSignatureProof,
    expected: &SignedTransaction,
    expected_key: &[u8],
    state: &VerifiedAccountState,
    expected_id: &[u8; 32],
    expected_entry: &SigBatchEntry,
    expected_leaf: &[u8; 32],
) -> Result<VerifiedSignatureEntry, String> {
    if !matches!(
        (proof.version, expected.signature.sig_type),
        (2, SignatureType::MlDsa65) | (4, SignatureType::Dilithium3)
    ) {
        return Err("invalid unbound signature proof version or algorithm".into());
    }
    if expected.tx.tx_type > 3 || expected.aa_bundle.is_some() || expected_key.len() != 1952 {
        return Err("unsupported unbound signature framing or key shape".into());
    }
    if state.address() != expected.from.as_bytes()
        || state.account().is_none_or(|account| {
            account.validation_code_hash.is_some()
                || account.pq_pubkey_hash != shell_primitives::ShellHash::ZERO
        })
    {
        return Err(
            "unbound signature requires the expected zero-commitment default account".into(),
        );
    }
    let mut address = Vec::with_capacity(1 + expected_key.len());
    address.push(expected.signature.sig_type.as_u8());
    address.extend_from_slice(expected_key);
    verify_hash(
        proof
            .tagged_key
            .as_ref()
            .ok_or("unbound signature address proof absent")?,
        &address,
        expected.from.as_bytes(),
    )
    .map_err(|e| format!("unbound sender address: {e}"))?;
    verify_entry_sources(
        proof,
        expected,
        expected_key,
        expected_id,
        expected_entry,
        expected_leaf,
    )
}

fn verify_entry_sources(
    proof: &RegisteredSignatureProof,
    expected: &SignedTransaction,
    expected_key: &[u8],
    expected_id: &[u8; 32],
    expected_entry: &SigBatchEntry,
    expected_leaf: &[u8; 32],
) -> Result<VerifiedSignatureEntry, String> {
    let key_id = match &expected.pubkey_mode {
        PubkeyMode::Embedded(key) if key.as_slice() == expected_key => &expected_key[..32],
        PubkeyMode::Embedded(_) => return Err("signature Embedded key conflict".into()),
        PubkeyMode::Reference => expected.from.as_bytes().as_slice(),
    };
    if expected_entry.msg_hash != proof.transaction.signing_hash.output
        || expected_entry.pk_hash.as_slice() != key_id
    {
        return Err("signature entry message or key identifier mismatch".into());
    }
    let mut id = Vec::with_capacity(PQTX_ID_DOMAIN.len() + 64);
    id.extend_from_slice(PQTX_ID_DOMAIN);
    id.extend_from_slice(expected.from.as_bytes());
    id.extend_from_slice(&expected_entry.msg_hash);
    verify_hash(&proof.transaction_id, &id, expected_id)
        .map_err(|e| format!("registered transaction ID: {e}"))?;
    let mut leaf = [0; 64];
    leaf[..32].copy_from_slice(&expected_entry.msg_hash);
    leaf[32..].copy_from_slice(&expected_entry.pk_hash);
    verify_hash(&proof.leaf, &leaf, expected_leaf)
        .map_err(|e| format!("registered entry leaf: {e}"))?;
    let verify = if proof.version == 5 {
        verify_sdk_transaction_signature
    } else if matches!(proof.version, 3 | 4) {
        verify_dilithium_transaction_signature
    } else {
        verify_transaction_signature
    };
    verify(
        &proof.transaction,
        &expected.tx,
        expected_key,
        &expected.signature.data,
        &proof.transaction.public_key_hash.output,
    )?;
    Ok(VerifiedSignatureEntry::from_verified_parts(
        expected_entry.clone(),
        *expected_leaf,
        *expected_id,
        *expected.from.as_bytes(),
    ))
}
