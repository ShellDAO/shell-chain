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

    #[error("aa validation failed: {0}")]
    AaValidation(String),
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

    // 2. Intrinsic gas check
    let intrinsic =
        compute_intrinsic_gas(tx.data.as_ref(), tx.is_contract_creation(), &tx.access_list);
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

    // 8. Balance check: sender must afford gas_limit * max_fee_per_gas + value
    //    Use checked arithmetic to prevent overflow panic (debug) / wrapping (release).
    let max_gas_cost = U256::from(tx.gas_limit).checked_mul(U256::from(tx.max_fee_per_gas));
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

    // 3. Intrinsic gas
    let intrinsic =
        compute_intrinsic_gas(tx.data.as_ref(), tx.is_contract_creation(), &tx.access_list);
    if tx.gas_limit < intrinsic {
        return Err(TxValidationError::GasTooLow(tx.gas_limit));
    }

    let _ = validate_aa_tx(signed_tx, world_state, chain_store, verifier)?;

    Ok(())
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
            to: Some(Address::from([0x01; 20])),
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
        let wrong_from = Address::from([0xFF; 20]);
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
            to: Some(Address::from([0x01; 20])),
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
    fn validate_disallowed_algorithm_rejected() {
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
        assert!(
            matches!(result, Err(TxValidationError::DisallowedAlgorithm(_))),
            "MlDsa65 should be rejected, got: {:?}",
            result
        );
    }
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
        }
    }
}
