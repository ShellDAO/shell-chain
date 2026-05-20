//! Transaction validation pipeline.
//!
//! Performs pre-EVM checks on incoming signed transactions:
//! 1. **PQ signature verification** — verifies Dilithium3 signature
//! 2. **Address derivation check** — ensures `from` matches pubkey
//! 3. **Pubkey hybrid registration** — registers pubkey on first use
//! 4. **Nonce check** — tx.nonce must equal account.nonce
//! 5. **Balance check** — sender must afford gas_limit × max_fee_per_gas + value

use crate::aa_validation::{validate_aa_tx, AaValidationError};
use shell_core::SignedTransaction;
use shell_crypto::Verifier;
use shell_primitives::{Address, U256};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};

/// Errors returned during transaction validation.
#[derive(Debug, thiserror::Error)]
pub enum TxValidationError {
    #[error("pubkey not found: no sender_pubkey in tx and no registered pubkey on-chain")]
    PubkeyNotFound,

    #[error("address mismatch: from={from} but pubkey derives {derived}")]
    AddressMismatch { from: Address, derived: Address },

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("insufficient balance: need {needed}, have {have}")]
    InsufficientBalance { needed: U256, have: U256 },

    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    #[error("gas limit below intrinsic: {0}")]
    GasTooLow(u64),

    #[error("pubkey conflict: address already registered with a different pubkey")]
    PubkeyConflict,

    #[error("disallowed signature algorithm: {0:?}")]
    DisallowedAlgorithm(shell_crypto::SignatureType),

    #[error("crypto error: {0}")]
    Crypto(#[from] shell_crypto::CryptoError),

    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    #[error("invalid access list: {0}")]
    InvalidAccessList(String),

    #[error("invalid blob transaction: {0}")]
    InvalidBlobTx(String),

    #[error("invalid aa bundle: {0}")]
    InvalidAaBundle(String),

    #[error("paymaster pubkey not registered: {0}")]
    PaymasterPubkeyNotFound(Address),

    #[error("paymaster signature invalid")]
    PaymasterSignatureInvalid,

    #[error("paymaster insufficient balance: need {needed}, have {have} (paymaster {paymaster})")]
    PaymasterInsufficientBalance {
        paymaster: Address,
        needed: U256,
        have: U256,
    },

    #[error("contract paymaster rejected transaction (returned false)")]
    PaymasterRejected,

    #[error("contract paymaster validation failed: {0}")]
    PaymasterValidationFailed(String),

    #[error("session key expired at block {expiry_block} (current {current_block})")]
    SessionKeyExpired {
        expiry_block: u64,
        current_block: u64,
    },

    #[error("session key value cap exceeded")]
    SessionValueCapExceeded,

    #[error("session key target mismatch")]
    SessionTargetMismatch,

    #[error("session key root authorization signature invalid")]
    SessionRootSignatureInvalid,

    #[error("session key tx signature invalid")]
    SessionKeySignatureInvalid,

    #[error("session key algorithm not allowed: {0}")]
    SessionKeyDisallowedAlgorithm(u8),

    #[error("aa validation failed: {0}")]
    AaValidation(String),
}

impl TxValidationError {
    /// Returns a short, static label for this error variant that contains no
    /// account-state values (nonce, balance, addresses).  Use this for
    /// structured logging to avoid leaking account data into log files.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::PubkeyNotFound => "pubkey_not_found",
            Self::AddressMismatch { .. } => "address_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::NonceMismatch { .. } => "nonce_mismatch",
            Self::InsufficientBalance { .. } => "insufficient_balance",
            Self::ChainIdMismatch { .. } => "chain_id_mismatch",
            Self::GasTooLow(_) => "gas_too_low",
            Self::PubkeyConflict => "pubkey_conflict",
            Self::DisallowedAlgorithm(_) => "disallowed_algorithm",
            Self::Crypto(_) => "crypto_error",
            Self::Storage(_) => "storage_error",
            Self::InvalidAccessList(_) => "invalid_access_list",
            Self::InvalidBlobTx(_) => "invalid_blob_tx",
            Self::InvalidAaBundle(_) => "invalid_aa_bundle",
            Self::PaymasterPubkeyNotFound(_) => "paymaster_pubkey_not_found",
            Self::PaymasterSignatureInvalid => "paymaster_signature_invalid",
            Self::PaymasterInsufficientBalance { .. } => "paymaster_insufficient_balance",
            Self::PaymasterRejected => "paymaster_rejected",
            Self::PaymasterValidationFailed(_) => "paymaster_validation_failed",
            Self::SessionKeyExpired { .. } => "session_key_expired",
            Self::SessionValueCapExceeded => "session_value_cap_exceeded",
            Self::SessionTargetMismatch => "session_target_mismatch",
            Self::SessionRootSignatureInvalid => "session_root_signature_invalid",
            Self::SessionKeySignatureInvalid => "session_key_signature_invalid",
            Self::SessionKeyDisallowedAlgorithm(_) => "session_key_disallowed_algorithm",
            Self::AaValidation(_) => "aa_validation_failed",
        }
    }
}

/// Minimum gas for a plain transfer (no data).
const INTRINSIC_GAS_TX: u64 = 21_000;
/// Per-byte cost for non-zero calldata.
const GAS_PER_NONZERO_BYTE: u64 = 16;
/// Per-byte cost for zero calldata.
const GAS_PER_ZERO_BYTE: u64 = 4;
/// Extra gas for contract creation.
const GAS_CONTRACT_CREATION: u64 = 32_000;
/// EIP-2930: gas cost per address in the access list.
const ACCESS_LIST_ADDRESS_COST: u64 = 2400;
/// EIP-2930: gas cost per storage key in the access list.
const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1900;

/// Validate a signed transaction before EVM execution.
///
/// This function performs the full pre-execution validation pipeline:
///
/// 1. **Chain ID** — must match the expected chain ID
/// 2. **Intrinsic gas** — gas_limit must cover base cost + calldata
/// 3. **PQ pubkey resolution** — resolves via tx field or on-chain registry
/// 4. **Sender binding** — first use checks address derivation, later use checks
///    the registered pubkey binding
/// 5. **Signature verification** — PQ signature over tx hash
/// 6. **Pubkey registration** — if first use, writes pubkey to ChainStore
/// 7. **Nonce** — must equal account's current nonce
/// 8. **Balance** — must afford `gas_limit * max_fee_per_gas + value`
///
/// Returns the resolved public key bytes on success (needed by the executor
/// to know whether registration occurred).
pub fn validate_tx<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
    expected_chain_id: u64,
) -> Result<Vec<u8>, TxValidationError> {
    let tx = &signed_tx.tx;

    // 1. Chain ID check
    if tx.chain_id != expected_chain_id {
        return Err(TxValidationError::ChainIdMismatch {
            expected: expected_chain_id,
            got: tx.chain_id,
        });
    }

    // 1b. Access list size validation
    if let Err(msg) = tx.validate_access_list() {
        return Err(TxValidationError::InvalidAccessList(msg.to_string()));
    }

    // 1c. Blob transaction validation (F-233)
    if tx.tx_type == 3 {
        if let Err(msg) = tx.validate_blob_tx() {
            return Err(TxValidationError::InvalidBlobTx(msg.to_string()));
        }
    }

    // 1d. AA bundle structural + intrinsic gas pre-check (M2 native AA).
    let aa_extra_gas = validate_aa_bundle_structure(signed_tx)?;

    // 2. Intrinsic gas check
    let intrinsic =
        compute_intrinsic_gas(tx.data.as_ref(), tx.is_contract_creation(), &tx.access_list)
            .saturating_add(aa_extra_gas);
    if tx.gas_limit < intrinsic {
        return Err(TxValidationError::GasTooLow(tx.gas_limit));
    }

    let validation = validate_aa_tx(signed_tx, world_state, chain_store, verifier)?;
    let pubkey = validation.pubkey;

    // 6. Register pubkey if this is the first transaction (sender_pubkey present)
    if validation.should_register_pubkey {
        chain_store.put_pubkey(&signed_tx.from, &pubkey)?;
    }

    // 7. Nonce check
    if validation.protocol_checks_nonce {
        let account_nonce = world_state.get_nonce(&signed_tx.from)?;
        if tx.nonce != account_nonce {
            return Err(TxValidationError::NonceMismatch {
                expected: account_nonce,
                got: tx.nonce,
            });
        }
    }

    // 8. Paymaster verification + balance check.
    //
    // For AA bundles with a paymaster: verify the paymaster's PQ signature
    // over `paymaster_signing_hash`, then debit the gas-cost portion from
    // the paymaster's balance. The sender still needs to afford its own
    // value transfers (Σ inner.value), but `value` on the outer envelope
    // is ignored for AA txs.
    //
    // For all other paths: standard sender-pays balance check.
    let max_gas_cost = U256::from(tx.gas_limit).checked_mul(U256::from(tx.max_fee_per_gas));

    if let Some(bundle) = signed_tx.aa_bundle.as_ref() {
        if let Some(paymaster) = bundle.paymaster {
            // Paymaster PQ signature already verified by `validate_aa_tx` above;
            // skip redundant re-verification here (S-3, defence-in-depth is at
            // the aa_validation layer). Only the balance check is needed here.
            let needed_gas = match max_gas_cost {
                Some(n) => n,
                None => U256::MAX,
            };
            let pm_balance = world_state.get_balance(&paymaster)?;
            if pm_balance < needed_gas {
                return Err(TxValidationError::PaymasterInsufficientBalance {
                    paymaster,
                    needed: needed_gas,
                    have: pm_balance,
                });
            }
            // Sender still needs to afford the inner value transfers.
            let inner_value_sum = sum_inner_values(bundle);
            let balance = world_state.get_balance(&signed_tx.from)?;
            if balance < inner_value_sum {
                return Err(TxValidationError::InsufficientBalance {
                    needed: inner_value_sum,
                    have: balance,
                });
            }
            return Ok(pubkey);
        }
        // Self-sponsored AA bundle: sender pays gas + Σ inner.value.
        let inner_value_sum = sum_inner_values(bundle);
        let needed = match max_gas_cost.and_then(|c| c.checked_add(inner_value_sum)) {
            Some(n) => n,
            None => {
                return Err(TxValidationError::InsufficientBalance {
                    needed: U256::MAX,
                    have: world_state.get_balance(&signed_tx.from)?,
                });
            }
        };
        let balance = world_state.get_balance(&signed_tx.from)?;
        if balance < needed {
            return Err(TxValidationError::InsufficientBalance {
                needed,
                have: balance,
            });
        }
        return Ok(pubkey);
    }

    // 8 (legacy). Balance check: sender must afford gas_limit * max_fee_per_gas + value
    //    Use checked arithmetic to prevent overflow panic (debug) / wrapping (release).
    let needed = match max_gas_cost.and_then(|c| c.checked_add(tx.value)) {
        Some(n) => n,
        None => {
            // Overflow means the required amount exceeds U256::MAX — always insufficient.
            return Err(TxValidationError::InsufficientBalance {
                needed: U256::MAX,
                have: world_state.get_balance(&signed_tx.from)?,
            });
        }
    };
    let balance = world_state.get_balance(&signed_tx.from)?;
    if balance < needed {
        return Err(TxValidationError::InsufficientBalance {
            needed,
            have: balance,
        });
    }

    Ok(pubkey)
}

/// Validate security-critical transaction properties during block import.
///
/// Unlike [`validate_tx`], this function:
/// - Does NOT register pubkeys (read-only)
/// - Does NOT check nonce/balance (validated implicitly by EVM re-execution)
///
/// Checks performed:
/// 1. Chain ID
/// 2. Access list size limits
/// 3. Intrinsic gas
/// 4. Algorithm allowlist
/// 5. Pubkey binding conflict
/// 6. Address derivation
/// 7. Signature verification
pub fn validate_tx_for_import<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
    expected_chain_id: u64,
) -> Result<(), TxValidationError> {
    let tx = &signed_tx.tx;

    // 1. Chain ID
    if tx.chain_id != expected_chain_id {
        return Err(TxValidationError::ChainIdMismatch {
            expected: expected_chain_id,
            got: tx.chain_id,
        });
    }

    // 2. Access list size
    if let Err(msg) = tx.validate_access_list() {
        return Err(TxValidationError::InvalidAccessList(msg.to_string()));
    }

    // 2b. Blob transaction validation (F-233)
    if tx.tx_type == 3 {
        if let Err(msg) = tx.validate_blob_tx() {
            return Err(TxValidationError::InvalidBlobTx(msg.to_string()));
        }
    }

    // 2c. AA bundle structural + intrinsic gas pre-check (M2 native AA).
    let aa_extra_gas = validate_aa_bundle_structure(signed_tx)?;

    // 3. Intrinsic gas
    let intrinsic =
        compute_intrinsic_gas(tx.data.as_ref(), tx.is_contract_creation(), &tx.access_list)
            .saturating_add(aa_extra_gas);
    if tx.gas_limit < intrinsic {
        return Err(TxValidationError::GasTooLow(tx.gas_limit));
    }

    let _ = validate_aa_tx(signed_tx, world_state, chain_store, verifier)?;

    // Paymaster PQ signature already verified inside validate_aa_tx above
    // (aa_validation.rs:154-164). No additional verify_paymaster_signature
    // call needed here; avoid the expensive PQ double-verify at import time.

    Ok(())
}

fn sum_inner_values(bundle: &shell_core::AaBundle) -> U256 {
    bundle
        .inner_calls
        .iter()
        .fold(U256::ZERO, |acc: U256, c| acc.saturating_add(c.value))
}

/// Verify the paymaster's PQ signature over `paymaster_signing_hash`.
///
/// The paymaster MUST already have a registered PQ pubkey on-chain — there is
/// no "embedded paymaster pubkey" path, because the bundle does not carry one.
/// Sponsoring an account therefore requires that account to have transacted
/// at least once (or to have been provisioned via genesis / system contract).
pub(crate) fn verify_paymaster_signature<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    paymaster: &Address,
    chain_store: &ChainStore<S>,
    verifier: &V,
) -> Result<(), TxValidationError> {
    let bundle = signed_tx
        .aa_bundle
        .as_ref()
        .ok_or_else(|| TxValidationError::InvalidAaBundle("no bundle".into()))?;
    let sig_bytes = bundle
        .paymaster_signature
        .as_ref()
        .ok_or_else(|| TxValidationError::InvalidAaBundle("paymaster signature missing".into()))?;
    let pubkey = chain_store
        .get_pubkey(paymaster)?
        .ok_or(TxValidationError::PaymasterPubkeyNotFound(*paymaster))?;
    let hash = signed_tx
        .paymaster_signing_hash()
        .ok_or_else(|| TxValidationError::InvalidAaBundle("no paymaster_signing_hash".into()))?;
    // Reuse sender's algorithm tag as paymaster's algorithm tag for v0.18.0
    // (single-algorithm chain; multi-algo paymaster will land in v0.19.0+).
    let pq_sig =
        shell_crypto::PQSignature::new(signed_tx.signature.sig_type, sig_bytes.as_ref().to_vec());
    let valid = verifier
        .verify(&pubkey, hash.as_bytes(), &pq_sig)
        .map_err(TxValidationError::Crypto)?;
    if !valid {
        return Err(TxValidationError::PaymasterSignatureInvalid);
    }
    Ok(())
}

/// Verify that `tx.tx_type` and `signed_tx.aa_bundle` are consistent, and run
/// `AaBundle::validate_structure()` plus the inner-gas vs outer-gas budget
/// check. This is a pure function (no I/O); call it from both mempool and
/// import-time validation as the first AA check.
///
/// Returns the additional intrinsic-gas surcharge that a bundle adds on top
/// of the standard `compute_intrinsic_gas` for the outer envelope:
/// `Σ inner.gas_limit + bundle.intrinsic_gas_surcharge()`. For non-AA txs
/// this returns `0`.
pub fn validate_aa_bundle_structure(
    signed_tx: &SignedTransaction,
) -> Result<u64, TxValidationError> {
    let tx = &signed_tx.tx;
    let is_aa_type = tx.tx_type == shell_core::AA_BUNDLE_TX_TYPE;
    let has_bundle = signed_tx.aa_bundle.is_some();
    if is_aa_type != has_bundle {
        return Err(TxValidationError::InvalidAaBundle(format!(
            "tx_type ({:#x}) and aa_bundle presence ({}) must agree",
            tx.tx_type, has_bundle
        )));
    }
    let Some(bundle) = signed_tx.aa_bundle.as_ref() else {
        return Ok(0);
    };
    bundle
        .validate_structure()
        .map_err(|e| TxValidationError::InvalidAaBundle(e.to_string()))?;
    let inner_sum = bundle.inner_gas_sum();
    let surcharge = bundle.intrinsic_gas_surcharge();
    // Saturating cast: outer gas_limit is u64; bundle limits guarantee
    // inner_sum fits in u64 (16 calls × u64 each is well within range).
    let combined = inner_sum.saturating_add(surcharge as u128);
    if combined > tx.gas_limit as u128 {
        return Err(TxValidationError::InvalidAaBundle(format!(
            "inner_sum ({inner_sum}) + intrinsic_surcharge ({surcharge}) exceeds outer gas_limit ({})",
            tx.gas_limit
        )));
    }
    Ok(combined as u64)
}

/// Compute intrinsic gas cost for a transaction.
///
/// Base cost (21,000) + calldata cost (4/byte zero, 16/byte nonzero) +
/// contract creation surcharge (32,000) +
/// EIP-2930 access list cost (2,400/address + 1,900/storage key).
pub fn compute_intrinsic_gas(
    data: &[u8],
    is_create: bool,
    access_list: &Option<Vec<shell_core::AccessListItem>>,
) -> u64 {
    let mut gas = INTRINSIC_GAS_TX;
    if is_create {
        gas = gas.saturating_add(GAS_CONTRACT_CREATION);
    }
    for &byte in data {
        if byte == 0 {
            gas = gas.saturating_add(GAS_PER_ZERO_BYTE);
        } else {
            gas = gas.saturating_add(GAS_PER_NONZERO_BYTE);
        }
    }
    if let Some(ref list) = access_list {
        for item in list {
            gas = gas.saturating_add(ACCESS_LIST_ADDRESS_COST);
            gas = gas.saturating_add(
                ACCESS_LIST_STORAGE_KEY_COST.saturating_mul(item.storage_keys.len() as u64),
            );
        }
    }
    gas
}

impl From<AaValidationError> for TxValidationError {
    fn from(value: AaValidationError) -> Self {
        match value {
            AaValidationError::PubkeyNotFound => Self::PubkeyNotFound,
            AaValidationError::AddressMismatch { from, derived } => {
                Self::AddressMismatch { from, derived }
            }
            AaValidationError::SignatureInvalid => Self::SignatureInvalid,
            AaValidationError::PubkeyConflict => Self::PubkeyConflict,
            AaValidationError::DisallowedAlgorithm(sig_type) => Self::DisallowedAlgorithm(sig_type),
            AaValidationError::Crypto(
                shell_crypto::CryptoError::VerificationFailed
                | shell_crypto::CryptoError::InvalidPublicKeyLength { .. }
                | shell_crypto::CryptoError::InvalidSignatureLength { .. },
            ) => Self::SignatureInvalid,
            AaValidationError::Crypto(err) => Self::Crypto(err),
            AaValidationError::Storage(err) => Self::Storage(err),
            AaValidationError::StateDb(err) => Self::AaValidation(err.to_string()),
            AaValidationError::ValidationCodeMissing(hash) => {
                Self::AaValidation(format!("validation code missing for hash {hash}"))
            }
            AaValidationError::ValidationContractRejected(msg)
            | AaValidationError::ValidationContractExecution(msg) => Self::AaValidation(msg),
            AaValidationError::PaymasterSignatureInvalid(_) => Self::PaymasterSignatureInvalid,
            AaValidationError::PaymasterPubkeyNotFound(addr) => Self::PaymasterPubkeyNotFound(addr),
            AaValidationError::PaymasterRejected => Self::PaymasterRejected,
            AaValidationError::PaymasterValidationFailed(msg) => {
                Self::PaymasterValidationFailed(msg)
            }
            AaValidationError::SessionKeyExpired {
                expiry_block,
                current_block,
            } => Self::SessionKeyExpired {
                expiry_block,
                current_block,
            },
            AaValidationError::SessionValueCapExceeded { .. } => Self::SessionValueCapExceeded,
            AaValidationError::SessionTargetMismatch { .. } => Self::SessionTargetMismatch,
            AaValidationError::SessionRootSignatureInvalid => Self::SessionRootSignatureInvalid,
            AaValidationError::SessionKeySignatureInvalid => Self::SessionKeySignatureInvalid,
            AaValidationError::SessionKeyDisallowedAlgorithm(algo) => {
                Self::SessionKeyDisallowedAlgorithm(algo)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::Transaction;
    use shell_crypto::{DilithiumSigner, DilithiumVerifier, PQSignature, SignatureType, Signer};
    use shell_primitives::{Bytes, ShellHash};
    use shell_storage::MemoryDb;
    use std::sync::Arc;

    fn test_chain_id() -> u64 {
        1337
    }

    fn make_signer() -> DilithiumSigner {
        DilithiumSigner::generate()
    }

    fn signer_address(signer: &DilithiumSigner) -> Address {
        Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
    }

    fn setup_stores() -> (WorldState<MemoryDb>, ChainStore<MemoryDb>) {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        (ws, cs)
    }

    fn fund_account(ws: &mut WorldState<MemoryDb>, addr: &Address, balance: U256) {
        use shell_core::Account;
        let account = Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        };
        ws.set_account(addr, &account).unwrap();
    }

    fn simple_transfer(chain_id: u64, nonce: u64) -> Transaction {
        Transaction {
            chain_id,
            nonce,
            to: Some(Address::from([0x01; 32])),
            value: U256::from(100),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    fn sign_tx(
        signer: &DilithiumSigner,
        tx: Transaction,
        include_pubkey: bool,
    ) -> SignedTransaction {
        let from = signer_address(signer);
        let tx_hash = tx.hash();
        let sig = signer.sign(tx_hash.as_bytes()).unwrap();
        if include_pubkey {
            SignedTransaction::with_pubkey(from, tx, sig, signer.public_key().to_vec())
        } else {
            SignedTransaction::new(from, tx, sig)
        }
    }

    fn validator_returns_true() -> Vec<u8> {
        vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
    }

    // ── Intrinsic gas ─────────────────────────────────────────

    #[test]
    fn intrinsic_gas_plain_transfer() {
        assert_eq!(compute_intrinsic_gas(&[], false, &None), 21_000);
    }

    #[test]
    fn intrinsic_gas_with_data() {
        let data = vec![0x00, 0xFF, 0x00, 0x42];
        // 21000 + 4 + 16 + 4 + 16 = 21040
        assert_eq!(compute_intrinsic_gas(&data, false, &None), 21_040);
    }

    #[test]
    fn intrinsic_gas_contract_creation() {
        assert_eq!(compute_intrinsic_gas(&[], true, &None), 21_000 + 32_000);
    }

    // ── Happy path ────────────────────────────────────────────

    #[test]
    fn validate_first_tx_with_pubkey() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), 0);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(result.is_ok());

        // Pubkey should now be registered
        let registered = cs.get_pubkey(&from).unwrap();
        assert!(registered.is_some());
        assert_eq!(registered.unwrap(), signer.public_key());
    }

    #[test]
    fn validate_subsequent_tx_from_registry() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        // Pre-register pubkey
        cs.put_pubkey(&from, signer.public_key()).unwrap();

        // Tx without sender_pubkey
        let tx = simple_transfer(test_chain_id(), 0);
        let signed = sign_tx(&signer, tx, false);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(result.is_ok());
    }

    // ── Failure cases ─────────────────────────────────────────

    #[test]
    fn validate_wrong_chain_id() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(9999, 0); // wrong chain_id
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::ChainIdMismatch { .. })
        ));
    }

    #[test]
    fn validate_gas_too_low() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let mut tx = simple_transfer(test_chain_id(), 0);
        tx.gas_limit = 100; // way too low
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::GasTooLow(_))));
    }

    #[test]
    fn validate_no_pubkey_anywhere() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        // No sender_pubkey and not registered
        let tx = simple_transfer(test_chain_id(), 0);
        let signed = sign_tx(&signer, tx, false);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::PubkeyNotFound)));
    }

    #[test]
    fn validate_address_mismatch() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();

        // Use a wrong from address
        let wrong_from = Address::from([0xFF; 32]);
        fund_account(&mut ws, &wrong_from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), 0);
        let tx_hash = tx.hash();
        let sig = signer.sign(tx_hash.as_bytes()).unwrap();
        let signed =
            SignedTransaction::with_pubkey(wrong_from, tx, sig, signer.public_key().to_vec());

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::AddressMismatch { .. })
        ));
    }

    #[test]
    fn validate_bad_signature() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), 0);
        let bad_sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDE; 100]);
        let signed =
            SignedTransaction::with_pubkey(from, tx, bad_sig, signer.public_key().to_vec());

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::SignatureInvalid)));
    }

    #[test]
    fn validate_nonce_mismatch() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), 5); // nonce should be 0
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::NonceMismatch {
                expected: 0,
                got: 5
            })
        ));
    }

    #[test]
    fn validate_custom_validation_keeps_protocol_nonce_baseline() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);

        let code = validator_returns_true();
        let code_hash = shell_primitives::keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();

        use shell_core::Account;
        ws.set_account(
            &from,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(1_000_000),
                validation_code_hash: Some(code_hash),
                code_hash: None,
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();

        let tx = simple_transfer(test_chain_id(), 5);
        let signed = SignedTransaction::new(
            from,
            tx,
            PQSignature::new(SignatureType::MlDsa65, vec![0xAA; 64]),
        );

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::NonceMismatch {
                expected: 0,
                got: 5
            })
        ));
    }

    #[test]
    fn validate_insufficient_balance() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1)); // only 1 wei

        let tx = simple_transfer(test_chain_id(), 0); // needs 21000*10 + 100 = 210100
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn validate_overflow_gas_cost_does_not_panic() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::MAX);

        // Craft a tx where gas_limit * max_fee_per_gas + value overflows U256
        let tx = Transaction {
            chain_id: test_chain_id(),
            nonce: 0,
            to: Some(Address::from([0x01; 32])),
            value: U256::MAX, // near-max value
            data: Bytes::new(),
            gas_limit: u64::MAX,
            max_fee_per_gas: u64::MAX,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        // Must not panic — should return InsufficientBalance with needed = U256::MAX
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(
            matches!(result, Err(TxValidationError::InsufficientBalance { .. })),
            "overflow should be caught, got: {:?}",
            result
        );
    }

    // ── F-154: Pubkey binding tests ───────────────────────────

    #[test]
    fn validate_pubkey_conflict_rejected() {
        let signer1 = make_signer();
        let signer2 = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer1);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        // Pre-register signer1's pubkey
        cs.put_pubkey(&from, signer1.public_key()).unwrap();

        // Try to send tx with signer2's pubkey for the same address
        let tx = simple_transfer(test_chain_id(), 0);
        let tx_hash = tx.hash();
        let sig = signer1.sign(tx_hash.as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, signer2.public_key().to_vec());

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        // Should fail with either PubkeyConflict or AddressMismatch
        assert!(result.is_err());
    }

    #[test]
    fn validate_same_pubkey_reregistration_ok() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        // Pre-register same pubkey
        cs.put_pubkey(&from, signer.public_key()).unwrap();

        // Send tx with same pubkey — should succeed (idempotent)
        let tx = simple_transfer(test_chain_id(), 0);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(result.is_ok());
    }

    // ── F-170: Algorithm allowlist tests ──────────────────────

    #[test]
    fn validate_mismatched_algorithm_address_rejected() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), 0);
        let tx_hash = tx.hash();
        // Create a signature with reserved MlDsa65 algorithm type
        let real_sig = signer.sign(tx_hash.as_bytes()).unwrap();
        let bad_algo_sig = PQSignature::new(SignatureType::MlDsa65, real_sig.data.clone());
        let signed =
            SignedTransaction::with_pubkey(from, tx, bad_algo_sig, signer.public_key().to_vec());

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::AddressMismatch { .. })
        ));
    }

    // ── AA Bundle (M2a) ───────────────────────────────────────

    use shell_core::{AaBundle, InnerCall, AA_BUNDLE_TX_TYPE, MAX_INNER_CALLS};
    use shell_primitives::Bytes as ShellBytes;

    fn aa_outer_tx(chain_id: u64, nonce: u64, gas_limit: u64) -> Transaction {
        Transaction {
            chain_id,
            nonce,
            to: None,
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    fn inner(value: u64, gas: u64) -> InnerCall {
        InnerCall {
            to: Some(Address::from([0xAA; 32])),
            value: U256::from(value),
            data: ShellBytes::new(),
            gas_limit: gas,
        }
    }

    fn sign_aa(
        signer: &DilithiumSigner,
        tx: Transaction,
        bundle: AaBundle,
        include_pubkey: bool,
    ) -> SignedTransaction {
        let from = signer_address(signer);
        // First build a placeholder to compute the canonical batch signing hash.
        let placeholder = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]),
            shell_core::PubkeyMode::Reference,
            bundle.clone(),
        )
        .expect("valid bundle");
        let signing_hash = placeholder.sender_signing_hash();
        let real_sig = signer.sign(signing_hash.as_bytes()).unwrap();
        let mode = if include_pubkey {
            shell_core::PubkeyMode::Embedded(signer.public_key().to_vec())
        } else {
            shell_core::PubkeyMode::Reference
        };
        SignedTransaction::with_aa_bundle(from, tx, real_sig, mode, bundle).unwrap()
    }

    #[test]
    fn validate_aa_bundle_structure_zero_for_legacy_tx() {
        let signer = make_signer();
        let signed = sign_tx(&signer, simple_transfer(test_chain_id(), 0), false);
        assert_eq!(validate_aa_bundle_structure(&signed).unwrap(), 0);
    }

    #[test]
    fn validate_tx_type_bundle_mismatch_rejects_aa_type_without_bundle() {
        let signer = make_signer();
        // tx_type = AA but no bundle on SignedTransaction
        let mut tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        // Pass through normal sign_tx → no aa_bundle
        // But AA tx_type, so structural validator must reject.
        tx.tx_type = AA_BUNDLE_TX_TYPE;
        let signed = sign_tx(&signer, tx, false);
        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_tx_type_bundle_mismatch_rejects_bundle_with_legacy_tx_type() {
        let signer = make_signer();
        let bundle = AaBundle {
            inner_calls: vec![inner(1, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        // tx_type = legacy but bundle attached → expect rejection.
        // Bypass with_aa_bundle()'s tx_type check by hand-constructing.
        let from = signer_address(&signer);
        let tx = simple_transfer(test_chain_id(), 0);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);
        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_aa_bundle_inner_gas_overflow() {
        let signer = make_signer();
        // outer gas = 100_000, but inner calls demand 200_000
        let tx = aa_outer_tx(test_chain_id(), 0, 100_000);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, 100_000), inner(0, 100_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        // with_aa_bundle() rejects this at construction; bypass via direct field.
        let from = signer_address(&signer);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);
        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_aa_bundle_too_many_inner_calls() {
        let signer = make_signer();
        let tx = aa_outer_tx(test_chain_id(), 0, 10_000_000);
        let calls: Vec<_> = (0..(MAX_INNER_CALLS + 1))
            .map(|_| inner(0, 21_000))
            .collect();
        let bundle = AaBundle {
            inner_calls: calls,
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let from = signer_address(&signer);
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);
        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_aa_bundle_self_sponsored_happy_path() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        // Need balance for: 200_000 (outer gas_limit) * 10 (max_fee_per_gas) + Σ inner.value
        // = 2_000_000 + 5 = 2_000_005. Fund well above.
        fund_account(&mut ws, &from, U256::from(10_000_000u64));

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        let bundle = AaBundle {
            inner_calls: vec![inner(2, 50_000), inner(3, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed = sign_aa(&signer, tx, bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(res.is_ok(), "happy path should pass: {:?}", res.err());
    }

    #[test]
    fn validate_aa_bundle_self_sponsored_insufficient_balance_for_value() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        // Fund only enough for gas, NOT for inner value transfers.
        fund_account(&mut ws, &from, U256::from(2_000_000u64));

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        let bundle = AaBundle {
            inner_calls: vec![inner(1_000_000_000, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed = sign_aa(&signer, tx, bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            res,
            Err(TxValidationError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn validate_aa_bundle_sponsored_happy_path() {
        let sender_signer = make_signer();
        let pm_signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let sender = signer_address(&sender_signer);
        let paymaster = signer_address(&pm_signer);
        // Sender only needs to afford inner.value sums.
        fund_account(&mut ws, &sender, U256::from(1_000u64));
        // Paymaster must afford gas_limit * max_fee_per_gas = 200_000 * 10.
        fund_account(&mut ws, &paymaster, U256::from(10_000_000u64));
        // Pre-register paymaster pubkey (sponsorship requires a registered key).
        cs.put_pubkey(&paymaster, pm_signer.public_key()).unwrap();

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        // Build bundle with placeholder paymaster sig first to compute hashes.
        let initial_bundle = AaBundle {
            inner_calls: vec![inner(7, 50_000)],
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(vec![0u8; 1])),
            ..Default::default()
        };
        // Build placeholder signed_tx to derive paymaster_signing_hash.
        let placeholder = SignedTransaction::with_aa_bundle(
            sender,
            tx.clone(),
            PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]),
            shell_core::PubkeyMode::Embedded(sender_signer.public_key().to_vec()),
            initial_bundle.clone(),
        )
        .unwrap();
        let pm_hash = placeholder.paymaster_signing_hash().unwrap();
        let pm_sig = pm_signer.sign(pm_hash.as_bytes()).unwrap();

        let final_bundle = AaBundle {
            inner_calls: initial_bundle.inner_calls.clone(),
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(pm_sig.data.clone())),
            ..Default::default()
        };
        let signed = sign_aa(&sender_signer, tx, final_bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(
            res.is_ok(),
            "sponsored happy path should pass: {:?}",
            res.err()
        );
    }

    #[test]
    fn validate_aa_bundle_sponsored_paymaster_pubkey_unregistered() {
        let sender_signer = make_signer();
        let pm_signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let sender = signer_address(&sender_signer);
        let paymaster = signer_address(&pm_signer);
        fund_account(&mut ws, &sender, U256::from(1_000u64));
        fund_account(&mut ws, &paymaster, U256::from(10_000_000u64));
        // Note: paymaster pubkey NOT registered.

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(vec![0xAB; 64])),
            ..Default::default()
        };
        let signed = sign_aa(&sender_signer, tx, bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            res,
            Err(TxValidationError::PaymasterPubkeyNotFound(_))
        ));
    }

    #[test]
    fn validate_aa_bundle_sponsored_paymaster_signature_invalid() {
        let sender_signer = make_signer();
        let pm_signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let sender = signer_address(&sender_signer);
        let paymaster = signer_address(&pm_signer);
        fund_account(&mut ws, &sender, U256::from(1_000u64));
        fund_account(&mut ws, &paymaster, U256::from(10_000_000u64));
        cs.put_pubkey(&paymaster, pm_signer.public_key()).unwrap();

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        // Sign over a *different* hash — wrong paymaster sig.
        let bogus_sig = pm_signer.sign(b"wrong message").unwrap();
        let bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(bogus_sig.data.clone())),
            ..Default::default()
        };
        let signed = sign_aa(&sender_signer, tx, bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            res,
            Err(TxValidationError::PaymasterSignatureInvalid)
        ));
    }

    #[test]
    fn validate_aa_bundle_sponsored_paymaster_insufficient_balance() {
        let sender_signer = make_signer();
        let pm_signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let sender = signer_address(&sender_signer);
        let paymaster = signer_address(&pm_signer);
        fund_account(&mut ws, &sender, U256::from(1_000u64));
        // Fund paymaster with WAY too little for 200_000 * 10 = 2_000_000.
        fund_account(&mut ws, &paymaster, U256::from(100u64));
        cs.put_pubkey(&paymaster, pm_signer.public_key()).unwrap();

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        let initial_bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(vec![0u8; 1])),
            ..Default::default()
        };
        let placeholder = SignedTransaction::with_aa_bundle(
            sender,
            tx.clone(),
            PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]),
            shell_core::PubkeyMode::Embedded(sender_signer.public_key().to_vec()),
            initial_bundle.clone(),
        )
        .unwrap();
        let pm_hash = placeholder.paymaster_signing_hash().unwrap();
        let pm_sig = pm_signer.sign(pm_hash.as_bytes()).unwrap();

        let final_bundle = AaBundle {
            inner_calls: initial_bundle.inner_calls.clone(),
            paymaster: Some(paymaster),
            paymaster_signature: Some(ShellBytes::from(pm_sig.data.clone())),
            ..Default::default()
        };
        let signed = sign_aa(&sender_signer, tx, final_bundle, true);
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            res,
            Err(TxValidationError::PaymasterInsufficientBalance { .. })
        ));
    }

    #[test]
    fn validate_aa_bundle_sender_signature_uses_batch_hash() {
        // Regression: a sender PQ signature over the *legacy* hash() must NOT
        // be accepted for an AA-bundle tx; only sender_signing_hash works.
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(10_000_000u64));

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let placeholder = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]),
            shell_core::PubkeyMode::Embedded(signer.public_key().to_vec()),
            bundle.clone(),
        )
        .unwrap();
        // Sign the WRONG hash (legacy `hash()` instead of batch_signing_hash).
        let wrong_sig = signer.sign(placeholder.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_aa_bundle(
            from,
            tx,
            wrong_sig,
            shell_core::PubkeyMode::Embedded(signer.public_key().to_vec()),
            bundle,
        )
        .unwrap();
        let verifier = DilithiumVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(res, Err(TxValidationError::SignatureInvalid)));
    }

    // --- kind_str() tests: assert static labels contain no account-state values.

    #[test]
    fn kind_str_sensitive_variants_have_no_values() {
        let cases: &[(&str, TxValidationError)] = &[
            (
                "nonce_mismatch",
                TxValidationError::NonceMismatch {
                    expected: 5,
                    got: 3,
                },
            ),
            (
                "insufficient_balance",
                TxValidationError::InsufficientBalance {
                    needed: U256::from(1000u64),
                    have: U256::from(0u64),
                },
            ),
            (
                "address_mismatch",
                TxValidationError::AddressMismatch {
                    from: Address::ZERO,
                    derived: Address::ZERO,
                },
            ),
            (
                "paymaster_insufficient_balance",
                TxValidationError::PaymasterInsufficientBalance {
                    paymaster: Address::ZERO,
                    needed: U256::from(50u64),
                    have: U256::from(10u64),
                },
            ),
        ];
        for (expected_label, err) in cases {
            let label = err.kind_str();
            assert_eq!(label, *expected_label, "wrong label for {err:?}");
            assert!(
                !label.chars().any(|c| c.is_ascii_digit()),
                "kind_str label '{label}' must not contain numeric data"
            );
        }
    }

    #[test]
    fn kind_str_all_variants_are_non_empty() {
        let variants: &[TxValidationError] = &[
            TxValidationError::PubkeyNotFound,
            TxValidationError::AddressMismatch {
                from: Address::ZERO,
                derived: Address::ZERO,
            },
            TxValidationError::SignatureInvalid,
            TxValidationError::NonceMismatch {
                expected: 1,
                got: 0,
            },
            TxValidationError::InsufficientBalance {
                needed: U256::from(1u64),
                have: U256::ZERO,
            },
            TxValidationError::ChainIdMismatch {
                expected: 1,
                got: 2,
            },
            TxValidationError::GasTooLow(21_000),
            TxValidationError::PubkeyConflict,
            TxValidationError::InvalidAccessList("x".into()),
            TxValidationError::InvalidBlobTx("x".into()),
            TxValidationError::InvalidAaBundle("x".into()),
            TxValidationError::PaymasterSignatureInvalid,
            TxValidationError::PaymasterRejected,
            TxValidationError::PaymasterValidationFailed("x".into()),
            TxValidationError::SessionValueCapExceeded,
            TxValidationError::SessionTargetMismatch,
            TxValidationError::SessionRootSignatureInvalid,
            TxValidationError::SessionKeySignatureInvalid,
            TxValidationError::SessionKeyDisallowedAlgorithm(0),
            TxValidationError::AaValidation("x".into()),
        ];
        for err in variants {
            assert!(!err.kind_str().is_empty(), "kind_str() empty for {err:?}");
        }
    }
}
