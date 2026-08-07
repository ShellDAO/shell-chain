//! Transaction validation pipeline.
//!
//! Performs pre-EVM checks on incoming signed transactions:
//! 1. **PQ signature verification** — verifies Dilithium3 signature
//! 2. **Address derivation check** — ensures `from` matches pubkey
//! 3. **Pubkey hybrid registration** — registers pubkey on first use
//! 4. **Nonce check** — tx.nonce must equal account.nonce
//! 5. **Balance check** — sender must afford execution gas, blob gas, and value

use crate::aa_validation::{validate_aa_tx, AaValidationError};
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{infer_signature_type_from_address, Verifier};
use shell_primitives::{
    Address, ACCESS_LIST_ADDRESS_COST, ACCESS_LIST_STORAGE_KEY_COST, GAS_CONTRACT_CREATION,
    GAS_PER_NONZERO_BYTE, GAS_PER_ZERO_BYTE, INTRINSIC_GAS_TX, U256,
};
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

    #[error("nonce cannot advance past u64::MAX")]
    NonceOverflow,

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

    #[error("contract paymaster validation exceeded gas budget (50k limit)")]
    PaymasterGasExceeded,

    #[error("session key expired at block {expiry_block} (validation block {current_block})")]
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
            Self::NonceOverflow => "nonce_overflow",
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
            Self::PaymasterGasExceeded => "paymaster_gas_exceeded",
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

fn ensure_nonce_can_advance(nonce: u64) -> Result<(), TxValidationError> {
    nonce
        .checked_add(1)
        .map(|_| ())
        .ok_or(TxValidationError::NonceOverflow)
}

fn max_transaction_gas_cost(tx: &Transaction) -> Option<U256> {
    let execution_gas_cost =
        U256::from(tx.gas_limit).checked_mul(U256::from(tx.max_fee_per_gas))?;
    let blob_gas_cost = U256::from(tx.blob_gas())
        .checked_mul(U256::from(tx.max_fee_per_blob_gas.unwrap_or_default()))?;
    execution_gas_cost.checked_add(blob_gas_cost)
}

/// Validate a signed transaction before PQVM/revm execution.
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
/// 8. **Balance** — must afford maximum execution gas, blob gas, and value
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
    if let Err(msg) = tx.validate_blob_tx() {
        return Err(TxValidationError::InvalidBlobTx(msg.to_string()));
    }

    // 1d. AA bundle structural + intrinsic gas pre-check (M2 native AA).
    let aa_extra_gas = validate_aa_bundle_structure(signed_tx)?;

    ensure_nonce_can_advance(tx.nonce)?;

    // 2. Intrinsic gas check
    let intrinsic = total_intrinsic_gas(signed_tx, aa_extra_gas)?;
    if tx.gas_limit < intrinsic {
        return Err(TxValidationError::GasTooLow(tx.gas_limit));
    }

    let validation = validate_aa_tx(signed_tx, world_state, chain_store, verifier)?;
    let pubkey = validation.pubkey;

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
    // the paymaster's balance. The sender still needs to afford the
    // outer AA value budget, which caps the total ETH transferable by the
    // inner calls.
    //
    // For all other paths: standard sender-pays balance check.
    let max_gas_cost = max_transaction_gas_cost(tx);

    if let Some(bundle) = signed_tx.aa_bundle.as_ref() {
        if let Some(paymaster) = bundle.paymaster {
            // Paymaster authorization already ran in `validate_aa_tx` above,
            // including either the EOA signature or contract policy. Only the
            // balance check is needed here.
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
            // Sender still needs to afford the declared outer value budget.
            let balance = world_state.get_balance(&signed_tx.from)?;
            if balance < tx.value {
                return Err(TxValidationError::InsufficientBalance {
                    needed: tx.value,
                    have: balance,
                });
            }
            if validation.should_register_pubkey {
                chain_store.put_pubkey(&signed_tx.from, &pubkey)?;
            }
            return Ok(pubkey);
        }
        // Self-sponsored AA bundle: sender pays gas + outer value budget.
        let needed = match max_gas_cost.and_then(|c| c.checked_add(tx.value)) {
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
        if validation.should_register_pubkey {
            chain_store.put_pubkey(&signed_tx.from, &pubkey)?;
        }
        return Ok(pubkey);
    }

    // 8 (legacy). Balance check: sender must afford execution gas, blob gas, and value.
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

    // Register first-use pubkeys only after every validation gate has passed.
    if validation.should_register_pubkey {
        chain_store.put_pubkey(&signed_tx.from, &pubkey)?;
    }

    Ok(pubkey)
}

/// Validate security-critical transaction properties during block import.
///
/// Unlike [`validate_tx`], this function:
/// - Does NOT register pubkeys (read-only)
/// - Does NOT check balances (validated by the block state-root transition)
///
/// Checks performed:
/// 1. Chain ID
/// 2. Access list size limits
/// 3. Intrinsic gas
/// 4. Algorithm allowlist
/// 5. Pubkey binding conflict
/// 6. Address derivation
/// 7. Signature verification
/// 8. Protocol nonce equality
pub fn validate_tx_for_import<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
    expected_chain_id: u64,
) -> Result<(), TxValidationError> {
    validate_tx_for_import_inner(
        signed_tx,
        world_state,
        chain_store,
        verifier,
        expected_chain_id,
        None,
    )
}

/// Validate a transaction during block import using a caller-supplied expected
/// nonce.
///
/// Block import validates a whole block before executing it. For multiple
/// transactions from the same sender in one block, the second transaction's
/// expected nonce is the previous transaction's nonce plus one, even though the
/// isolated pre-execution world state still contains the parent-block nonce.
pub fn validate_tx_for_import_with_expected_nonce<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
    expected_chain_id: u64,
    expected_nonce: u64,
) -> Result<(), TxValidationError> {
    validate_tx_for_import_inner(
        signed_tx,
        world_state,
        chain_store,
        verifier,
        expected_chain_id,
        Some(expected_nonce),
    )
}

fn validate_tx_for_import_inner<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
    expected_chain_id: u64,
    expected_nonce: Option<u64>,
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
    if let Err(msg) = tx.validate_blob_tx() {
        return Err(TxValidationError::InvalidBlobTx(msg.to_string()));
    }

    // 2c. AA bundle structural + intrinsic gas pre-check (M2 native AA).
    let aa_extra_gas = validate_aa_bundle_structure(signed_tx)?;

    ensure_nonce_can_advance(tx.nonce)?;

    // 3. Intrinsic gas
    let intrinsic = total_intrinsic_gas(signed_tx, aa_extra_gas)?;
    if tx.gas_limit < intrinsic {
        return Err(TxValidationError::GasTooLow(tx.gas_limit));
    }

    let validation = validate_aa_tx(signed_tx, world_state, chain_store, verifier)?;

    if validation.protocol_checks_nonce {
        let account_nonce = match expected_nonce {
            Some(expected) => expected,
            None => world_state.get_nonce(&signed_tx.from)?,
        };
        if tx.nonce != account_nonce {
            return Err(TxValidationError::NonceMismatch {
                expected: account_nonce,
                got: tx.nonce,
            });
        }
    }

    // Paymaster authorization already ran in `validate_aa_tx` above. Avoid
    // repeating either the expensive EOA signature check or contract policy.

    Ok(())
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
    let paymaster_sig_type =
        infer_signature_type_from_address(&pubkey, paymaster).ok_or_else(|| {
            TxValidationError::InvalidAaBundle(
                "paymaster pubkey does not match the paymaster address under any allowed algorithm"
                    .into(),
            )
        })?;
    let pq_sig = shell_crypto::PQSignature::new(paymaster_sig_type, sig_bytes.as_ref().to_vec());
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
    if bundle.paymaster == Some(signed_tx.from) {
        return Err(TxValidationError::InvalidAaBundle(
            "paymaster must differ from sender".into(),
        ));
    }
    let inner_sum = bundle.inner_gas_sum();
    let surcharge = bundle.intrinsic_gas_surcharge();
    // Keep this sum wider than the outer u64 gas limit so oversized bundles
    // are rejected before returning the surcharge to callers.
    let combined = inner_sum.saturating_add(surcharge as u128);
    if combined > tx.gas_limit as u128 {
        return Err(TxValidationError::InvalidAaBundle(format!(
            "inner_sum ({inner_sum}) + intrinsic_surcharge ({surcharge}) exceeds outer gas_limit ({})",
            tx.gas_limit
        )));
    }
    let Some(inner_value_sum) = bundle.checked_inner_value_sum() else {
        return Err(TxValidationError::InvalidAaBundle(
            "inner_value_sum overflows U256".into(),
        ));
    };
    if inner_value_sum > tx.value {
        return Err(TxValidationError::InvalidAaBundle(format!(
            "inner_value_sum ({inner_value_sum}) exceeds outer value ({})",
            tx.value
        )));
    }
    Ok(combined as u64)
}

fn total_intrinsic_gas(
    signed_tx: &SignedTransaction,
    aa_extra_gas: u64,
) -> Result<u64, TxValidationError> {
    let tx = &signed_tx.tx;
    // An AA envelope does not execute `Transaction::to`; creation is expressed
    // by an inner call whose `to` is absent. Do not charge the outer envelope a
    // contract-creation surcharge merely because its unused `to` is absent.
    let is_create = tx.is_contract_creation() && !signed_tx.is_aa_bundle();
    compute_intrinsic_gas(tx.data.as_ref(), is_create, &tx.access_list)
        .checked_add(aa_extra_gas)
        .ok_or(TxValidationError::GasTooLow(tx.gas_limit))
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
            AaValidationError::PaymasterGasExceeded => Self::PaymasterGasExceeded,
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
    use shell_crypto::{
        DilithiumSigner, DilithiumVerifier, MlDsaSigner, MultiVerifier, PQSignature, SignatureType,
        Signer,
    };
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

    fn valid_blob_hash() -> ShellHash {
        let mut bytes = [0u8; 32];
        bytes[0] = shell_core::BLOB_VERSIONED_HASH_VERSION_KZG;
        ShellHash::from(bytes)
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

    fn fixture_account_sequence(addr: &Address) -> u64 {
        addr.as_bytes()
            .iter()
            .copied()
            .find(|byte| *byte != u8::default())
            .map(u64::from)
            .unwrap_or_else(|| u64::from(u8::MAX))
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

    fn validator_returns_false() -> Vec<u8> {
        vec![0x60, 0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
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
    fn validate_rejected_first_use_does_not_register_pubkey() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let mismatched_sequence = fixture_account_sequence(&from);
        let tx = simple_transfer(test_chain_id(), mismatched_sequence);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::NonceMismatch {
                expected: 0,
                got
            }) if got == mismatched_sequence
        ));
        assert_eq!(cs.get_pubkey(&from).unwrap(), None);
    }

    #[test]
    fn validate_rejects_max_nonce_that_cannot_advance() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), u64::MAX);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::NonceOverflow)));
    }

    #[test]
    fn validate_rejects_blob_fields_on_non_blob_transaction() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let mut tx = simple_transfer(test_chain_id(), u64::default());
        tx.blob_versioned_hashes = Some(vec![ShellHash::ZERO]);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::InvalidBlobTx(_))));
    }

    #[test]
    fn validate_import_rejects_nonce_mismatch() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let mismatched_sequence = fixture_account_sequence(&from);
        let tx = simple_transfer(test_chain_id(), mismatched_sequence);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx_for_import(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(
            matches!(
                result,
                Err(TxValidationError::NonceMismatch { expected, got })
                    if expected == 0 && got == mismatched_sequence
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn validate_import_rejects_max_nonce_that_cannot_advance() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let tx = simple_transfer(test_chain_id(), u64::MAX);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        let result = validate_tx_for_import_with_expected_nonce(
            &signed,
            &mut ws,
            &cs,
            &verifier,
            test_chain_id(),
            u64::MAX,
        );
        assert!(matches!(result, Err(TxValidationError::NonceOverflow)));
    }

    #[test]
    fn validate_import_accepts_caller_supplied_expected_nonce() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let block_sequence = fixture_account_sequence(&from);
        let tx = simple_transfer(test_chain_id(), block_sequence);
        let signed = sign_tx(&signer, tx, true);

        let verifier = DilithiumVerifier;
        validate_tx_for_import_with_expected_nonce(
            &signed,
            &mut ws,
            &cs,
            &verifier,
            test_chain_id(),
            block_sequence,
        )
        .unwrap();
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
    fn validate_custom_account_requires_paymaster_authorization() {
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

        let paymaster = Address::from([0x88; 20]);
        fund_account(&mut ws, &paymaster, U256::from(10_000_000));
        let signed = SignedTransaction::with_aa_bundle(
            from,
            aa_outer_tx(test_chain_id(), 0, 200_000, 0),
            PQSignature::new(SignatureType::MlDsa65, vec![0xAA; 64]),
            shell_core::PubkeyMode::Reference,
            AaBundle {
                inner_calls: vec![inner(0, 50_000)],
                paymaster: Some(paymaster),
                paymaster_signature: Some(Bytes::from(vec![1])),
                ..Default::default()
            },
        )
        .unwrap();

        let result = validate_tx(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::PaymasterPubkeyNotFound(addr)) if addr == paymaster
        ));
        let result =
            validate_tx_for_import(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::PaymasterPubkeyNotFound(addr)) if addr == paymaster
        ));

        let contract_paymaster = Address::from([0x77; 20]);
        let code = validator_returns_false();
        let code_hash = shell_primitives::keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();
        ws.set_account(
            &contract_paymaster,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(10_000_000),
                validation_code_hash: None,
                code_hash: Some(code_hash),
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();

        let signed = SignedTransaction::with_aa_bundle(
            from,
            aa_outer_tx(test_chain_id(), 0, 200_000, 0),
            PQSignature::new(SignatureType::MlDsa65, vec![0xAA; 64]),
            shell_core::PubkeyMode::Reference,
            AaBundle {
                inner_calls: vec![inner(0, 50_000)],
                paymaster: Some(contract_paymaster),
                paymaster_context: Some(Bytes::from(vec![1])),
                ..Default::default()
            },
        )
        .unwrap();

        let result = validate_tx(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::PaymasterRejected)));
        let result =
            validate_tx_for_import(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(result, Err(TxValidationError::PaymasterRejected)));
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
        assert_eq!(cs.get_pubkey(&from).unwrap(), None);
    }

    #[test]
    fn validate_blob_tx_balance_includes_blob_gas() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        let mut tx = simple_transfer(test_chain_id(), u64::default());
        tx.tx_type = 3;
        tx.max_fee_per_blob_gas = Some(10);
        tx.blob_versioned_hashes = Some(vec![valid_blob_hash()]);
        let execution_and_value = U256::from(tx.gas_limit)
            .checked_mul(U256::from(tx.max_fee_per_gas))
            .unwrap()
            .checked_add(tx.value)
            .unwrap();
        fund_account(&mut ws, &from, execution_and_value);
        let signed = sign_tx(&signer, tx, true);

        let result = validate_tx(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());

        assert!(matches!(
            result,
            Err(TxValidationError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn validate_blob_tx_rejects_unsupported_hash_version() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::MAX);
        let mut tx = simple_transfer(test_chain_id(), u64::default());
        tx.tx_type = 3;
        tx.max_fee_per_blob_gas = Some(10);
        tx.blob_versioned_hashes = Some(vec![ShellHash::ZERO]);
        let signed = sign_tx(&signer, tx, true);

        let result = validate_tx(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::InvalidBlobTx(message))
                if message == "blob tx has unsupported versioned hash version"
        ));

        let result =
            validate_tx_for_import(&signed, &mut ws, &cs, &DilithiumVerifier, test_chain_id());
        assert!(matches!(
            result,
            Err(TxValidationError::InvalidBlobTx(message))
                if message == "blob tx has unsupported versioned hash version"
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
            nonce: ws.get_nonce(&from).unwrap(),
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

    fn aa_outer_tx(chain_id: u64, nonce: u64, gas_limit: u64, value: u64) -> Transaction {
        Transaction {
            chain_id,
            nonce,
            to: None,
            value: U256::from(value),
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
    fn aa_outer_envelope_does_not_pay_contract_creation_intrinsic_gas() {
        let signer = make_signer();
        let account_sequence = fixture_account_sequence(&signer_address(&signer));
        let bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            ..Default::default()
        };
        let signed = sign_aa(
            &signer,
            aa_outer_tx(test_chain_id(), account_sequence, 71_000, 0),
            bundle,
            true,
        );
        let aa_extra_gas = validate_aa_bundle_structure(&signed).unwrap();

        assert_eq!(aa_extra_gas, 50_000);
        assert_eq!(total_intrinsic_gas(&signed, aa_extra_gas).unwrap(), 71_000);
    }

    #[test]
    fn validate_tx_type_bundle_mismatch_rejects_aa_type_without_bundle() {
        let signer = make_signer();
        // tx_type = AA but no bundle on SignedTransaction
        let mut tx = aa_outer_tx(test_chain_id(), 0, 200_000, 0);
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
        let tx = aa_outer_tx(test_chain_id(), 0, 100_000, 0);
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
    fn validate_aa_bundle_rejects_inner_gas_above_u64_limit() {
        let signer = make_signer();
        let nonce = u64::default();
        let tx = aa_outer_tx(test_chain_id(), nonce, u64::MAX, 0);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, u64::MAX), inner(0, 1)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let from = signer_address(&signer);
        let sig = signer.sign(b"aa-gas-boundary").unwrap();
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);

        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_aa_bundle_inner_gas_plus_base_overflow_rejected() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let tx = aa_outer_tx(test_chain_id(), u64::default(), u64::MAX, 0);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, u64::MAX)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed = sign_aa(&signer, tx, bundle, true);
        let verifier = DilithiumVerifier;

        let err = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id()).unwrap_err();
        assert!(matches!(err, TxValidationError::GasTooLow(u64::MAX)));
    }

    #[test]
    fn validate_import_aa_bundle_inner_gas_plus_base_overflow_rejected() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let tx = aa_outer_tx(test_chain_id(), u64::default(), u64::MAX, 0);
        let bundle = AaBundle {
            inner_calls: vec![inner(0, u64::MAX)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let signed = sign_aa(&signer, tx, bundle, true);
        let verifier = DilithiumVerifier;

        let err =
            validate_tx_for_import(&signed, &mut ws, &cs, &verifier, test_chain_id()).unwrap_err();
        assert!(matches!(err, TxValidationError::GasTooLow(u64::MAX)));
    }

    #[test]
    fn validate_aa_bundle_rejects_inner_value_overspend() {
        let signer = make_signer();
        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 2);
        let bundle = AaBundle {
            inner_calls: vec![inner(2, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let mut signed = sign_aa(&signer, tx, bundle, true);
        signed.tx.value = U256::from(1u64);
        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(err, TxValidationError::InvalidAaBundle(_)));
    }

    #[test]
    fn validate_aa_bundle_rejects_inner_value_overflow() {
        let signer = make_signer();
        let nonce = u64::default();
        let mut tx = aa_outer_tx(test_chain_id(), nonce, 200_000, 0);
        tx.value = U256::MAX;
        let bundle = AaBundle {
            inner_calls: vec![
                InnerCall {
                    value: U256::MAX,
                    ..inner(0, 50_000)
                },
                InnerCall {
                    value: U256::from(1u64),
                    ..inner(0, 50_000)
                },
            ],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let from = signer_address(&signer);
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);

        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(
            err,
            TxValidationError::InvalidAaBundle(msg) if msg.contains("overflows U256")
        ));
    }

    #[test]
    fn validate_aa_bundle_rejects_sender_as_paymaster() {
        let signer = make_signer();
        let nonce = u64::default();
        let tx = aa_outer_tx(test_chain_id(), nonce, 200_000, 1);
        let from = signer_address(&signer);
        let bundle = AaBundle {
            inner_calls: vec![inner(1, 50_000)],
            paymaster: Some(from),
            paymaster_signature: Some(ShellBytes::from(vec![0xCD; 96])),
            ..Default::default()
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let mut signed = SignedTransaction::new(from, tx, sig);
        signed.aa_bundle = Some(bundle);

        let err = validate_aa_bundle_structure(&signed).unwrap_err();
        assert!(matches!(
            err,
            TxValidationError::InvalidAaBundle(msg)
                if msg.contains("paymaster must differ from sender")
        ));
    }

    #[test]
    fn validate_aa_bundle_too_many_inner_calls() {
        let signer = make_signer();
        let tx = aa_outer_tx(test_chain_id(), 0, 10_000_000, 0);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 5);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 1_000_000_000);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 7);
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
    fn validate_aa_bundle_sponsored_happy_path_with_mixed_algorithms() {
        let sender_signer = make_signer();
        let pm_signer = MlDsaSigner::generate();
        let (mut ws, cs) = setup_stores();
        let sender = signer_address(&sender_signer);
        let paymaster =
            Address::from_public_key(pm_signer.public_key(), pm_signer.sig_type().as_u8());
        fund_account(&mut ws, &sender, U256::from(1_000u64));
        fund_account(&mut ws, &paymaster, U256::from(10_000_000u64));
        cs.put_pubkey(&paymaster, pm_signer.public_key()).unwrap();

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 7);
        let initial_bundle = AaBundle {
            inner_calls: vec![inner(7, 50_000)],
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
        let verifier = MultiVerifier;
        let res = validate_tx(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(
            res.is_ok(),
            "mixed-algorithm sponsored path should pass: {:?}",
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 0);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 0);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 0);
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

        let tx = aa_outer_tx(test_chain_id(), 0, 200_000, 0);
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
        // Sign the WRONG hash (legacy hash instead of batch_signing_hash).
        let wrong_sig = signer.sign(placeholder.legacy_hash().as_bytes()).unwrap();
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

    #[test]
    fn validate_import_rejects_aa_nonce_mismatch() {
        let signer = make_signer();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from, U256::from(1_000_000));

        let bundle = AaBundle {
            inner_calls: vec![inner(0, 50_000)],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let mismatched_sequence = fixture_account_sequence(&from);
        let signed = sign_aa(
            &signer,
            aa_outer_tx(test_chain_id(), mismatched_sequence, 200_000, 0),
            bundle,
            true,
        );

        let verifier = DilithiumVerifier;
        let res = validate_tx_for_import(&signed, &mut ws, &cs, &verifier, test_chain_id());
        assert!(
            matches!(
                res,
                Err(TxValidationError::NonceMismatch {
                    expected: 0,
                    got
                }) if got == mismatched_sequence
            ),
            "got {res:?}"
        );
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
            TxValidationError::NonceOverflow,
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
