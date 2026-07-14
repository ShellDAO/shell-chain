use alloy_primitives::Bytes as AlBytes;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, CfgEnv, Context, Evm, TxEnv};
use revm::context_interface::result::HaltReason;
use revm::database_interface::Database;
use revm::handler::instructions::EthInstructions;
use revm::handler::{ExecuteEvm, MainnetContext};
use revm::primitives::hardfork::SpecId;
use revm::primitives::TxKind;
use revm::state::{AccountInfo, Bytecode};
use shell_core::{InnerCall, SessionAuth, SignedTransaction};
use shell_crypto::{
    infer_signature_type_from_address, is_algorithm_allowed, PQSignature, SignatureType, Verifier,
    ALLOWED_ALGORITHMS,
};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash, U256};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};

use crate::precompiles::ShellPrecompiles;
use crate::state_db::{shell_hash_to_b256, ShellStateDb, ShellStateRefDb, StateDbError};
use crate::tx_validation::verify_paymaster_signature;

pub const VALIDATION_GAS_CAP: u64 = 500_000;
/// Gas budget for `IPaymaster.validatePaymasterOp` staticcall (T-7).
pub const PAYMASTER_VALIDATE_GAS_CAP: u64 = 50_000;

const VALIDATE_PAYMASTER_OP_SIGNATURE: &[u8] = b"validatePaymasterOp(address,bytes,uint256,bytes)";

const VALIDATE_TRANSACTION_SIGNATURE: &[u8] = b"validateTransactionV2(bytes32,bytes32,uint64,bytes32,uint256,uint64,uint64,uint64,bytes32,bytes32,bytes,bytes)";
const VALIDATE_TRANSACTION_V1_SIGNATURE: &[u8] = b"validateTransaction(bytes32,bytes,bytes)";

#[derive(Debug)]
pub struct AaValidationOutcome {
    pub pubkey: Vec<u8>,
    pub should_register_pubkey: bool,
    pub protocol_checks_nonce: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AaValidationError {
    #[error("pubkey not found: no sender_pubkey in tx and no registered pubkey on-chain")]
    PubkeyNotFound,

    #[error("address mismatch: from={from} but pubkey derives {derived}")]
    AddressMismatch { from: Address, derived: Address },

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("pubkey conflict: address already registered with a different pubkey")]
    PubkeyConflict,

    #[error("disallowed signature algorithm: {0:?}")]
    DisallowedAlgorithm(SignatureType),

    #[error("validation code missing for hash {0}")]
    ValidationCodeMissing(ShellHash),

    #[error("validation contract rejected transaction: {0}")]
    ValidationContractRejected(String),

    #[error("validation contract execution failed: {0}")]
    ValidationContractExecution(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] shell_crypto::CryptoError),

    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    #[error("state db: {0}")]
    StateDb(#[from] StateDbError),

    #[error("paymaster signature invalid: {0}")]
    PaymasterSignatureInvalid(String),

    #[error("paymaster pubkey not found: {0}")]
    PaymasterPubkeyNotFound(Address),

    #[error("contract paymaster rejected transaction (returned false)")]
    PaymasterRejected,

    #[error("contract paymaster validation failed: {0}")]
    PaymasterValidationFailed(String),

    #[error("contract paymaster validation exceeded gas budget (50k limit)")]
    PaymasterGasExceeded,

    #[error("session key expired at block {expiry_block} (current {current_block})")]
    SessionKeyExpired {
        expiry_block: u64,
        current_block: u64,
    },

    #[error("session key value cap exceeded: sum {sum} > cap {cap}")]
    SessionValueCapExceeded { sum: String, cap: String },

    #[error("session key target mismatch: inner call to {got:?}, expected {expected:?}")]
    SessionTargetMismatch {
        expected: Address,
        got: Option<Address>,
    },

    #[error("session key root authorization signature invalid")]
    SessionRootSignatureInvalid,

    #[error("session key tx signature invalid")]
    SessionKeySignatureInvalid,

    #[error("session key algorithm not allowed: {0}")]
    SessionKeyDisallowedAlgorithm(u8),
}

pub fn validate_aa_tx<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
) -> Result<AaValidationOutcome, AaValidationError> {
    let account = world_state.get_account(&signed_tx.from)?;
    let registered_pubkey = chain_store.get_pubkey(&signed_tx.from)?;

    if let Some(account) = account.as_ref() {
        if let Some(validation_code_hash) = account.validation_code_hash {
            let pubkey = signed_tx
                .pubkey_mode
                .pubkey_bytes()
                .map(|b| b.to_vec())
                .or(registered_pubkey.clone())
                .unwrap_or_default();

            validate_custom_contract(
                signed_tx,
                world_state,
                chain_store,
                validation_code_hash,
                &pubkey,
            )?;

            return Ok(AaValidationOutcome {
                pubkey,
                should_register_pubkey: false,
                // Keep protocol nonce equality as the baseline replay guard
                // until the custom-validator ABI exposes enough tx context to
                // safely own nonce policy in userland.
                protocol_checks_nonce: true,
            });
        }
    }

    if !is_algorithm_allowed(signed_tx.signature.sig_type) {
        return Err(AaValidationError::DisallowedAlgorithm(
            signed_tx.signature.sig_type,
        ));
    }

    let pubkey = resolve_pubkey(
        signed_tx.pubkey_mode.pubkey_bytes(),
        registered_pubkey.as_ref(),
    )?;

    if signed_tx.pubkey_mode.is_embedded() {
        if let Some(registered) = registered_pubkey.as_ref() {
            if registered != &pubkey {
                return Err(AaValidationError::PubkeyConflict);
            }
        }
    }

    if registered_pubkey.is_none() {
        let derived = Address::from_public_key(&pubkey, signed_tx.signature.sig_type.as_u8());
        let uses_session_key = signed_tx
            .aa_bundle()
            .is_some_and(|bundle| bundle.session_auth.is_some());
        let address_matches = if uses_session_key {
            infer_signature_type_from_address(&pubkey, &signed_tx.from).is_some()
        } else {
            signed_tx.from == derived
        };
        if !address_matches {
            return Err(AaValidationError::AddressMismatch {
                from: signed_tx.from,
                derived,
            });
        }
    } else if let Some(account) = account.as_ref() {
        if account.pq_pubkey_hash != ShellHash::ZERO {
            let pubkey_hash = blake3_hash(&pubkey);
            if account.pq_pubkey_hash != pubkey_hash {
                return Err(AaValidationError::PubkeyConflict);
            }
        }
    }

    let tx_hash = signed_tx.sender_signing_hash();

    // Session key path: root_signature authorizes the session key; session key
    // signs the tx. Root pubkey sig check is replaced by the two-step session
    // verification. See AA Phase 2 spec §4.
    if let Some(bundle) = signed_tx.aa_bundle() {
        if let Some(session_auth) = &bundle.session_auth {
            validate_session_auth(
                signed_tx,
                session_auth,
                &pubkey,
                bundle.inner_calls.as_slice(),
                &tx_hash,
                chain_store,
                verifier,
            )?;
            // Paymaster validation runs after session auth.
        } else {
            // Normal path: root key signs the tx directly.
            let valid = verifier.verify(&pubkey, tx_hash.as_bytes(), &signed_tx.signature)?;
            if !valid {
                return Err(AaValidationError::SignatureInvalid);
            }
        }
    } else {
        let valid = verifier.verify(&pubkey, tx_hash.as_bytes(), &signed_tx.signature)?;
        if !valid {
            return Err(AaValidationError::SignatureInvalid);
        }
    }

    // Paymaster validation — dispatches on type:
    //   Phase 1 (EOA paymaster): paymaster_signature present → verify PQ sig.
    //   Phase 2 (contract paymaster): paymaster_context present → staticcall.
    // Self-sponsored (no paymaster) → no paymaster check needed.
    if let Some(bundle) = signed_tx.aa_bundle() {
        if let Some(paymaster) = bundle.paymaster {
            if paymaster != signed_tx.from {
                if let Some(context) = bundle.paymaster_context.as_ref().map(|b| b.as_ref()) {
                    // Phase 2: contract paymaster via staticcall sandbox.
                    call_paymaster_validate(
                        signed_tx,
                        &paymaster,
                        context,
                        world_state,
                        chain_store,
                    )?;
                } else {
                    // Phase 1: EOA paymaster PQ signature.
                    verify_paymaster_signature(signed_tx, &paymaster, chain_store, verifier)
                        .map_err(|e| match e {
                            crate::tx_validation::TxValidationError::PaymasterPubkeyNotFound(
                                addr,
                            ) => AaValidationError::PaymasterPubkeyNotFound(addr),
                            other => {
                                AaValidationError::PaymasterSignatureInvalid(other.to_string())
                            }
                        })?;
                }
            }
        }
    }

    Ok(AaValidationOutcome {
        should_register_pubkey: signed_tx.pubkey_mode.is_embedded() && registered_pubkey.is_none(),
        pubkey,
        protocol_checks_nonce: true,
    })
}

fn resolve_pubkey(
    sender_pubkey: Option<&[u8]>,
    registered_pubkey: Option<&Vec<u8>>,
) -> Result<Vec<u8>, AaValidationError> {
    if let Some(pk) = sender_pubkey {
        return Ok(pk.to_vec());
    }
    match registered_pubkey {
        Some(pk) => Ok(pk.clone()),
        None => Err(AaValidationError::PubkeyNotFound),
    }
}

fn validate_custom_contract<S: KvStore + 'static>(
    signed_tx: &SignedTransaction,
    world_state: &WorldState<S>,
    chain_store: &ChainStore<S>,
    validation_code_hash: ShellHash,
    pubkey: &[u8],
) -> Result<(), AaValidationError> {
    if chain_store.get_code(&validation_code_hash)?.is_none() {
        return Err(AaValidationError::ValidationCodeMissing(
            validation_code_hash,
        ));
    }

    let v2_calldata =
        encode_validate_transaction_calldata(signed_tx, &signed_tx.signature.data, pubkey);
    let output = match call_custom_validation_contract(
        signed_tx,
        world_state,
        chain_store,
        validation_code_hash,
        v2_calldata,
    ) {
        Ok(output) => output,
        Err(err) if should_fallback_to_v1(&err) => {
            let v1_calldata = encode_validate_transaction_v1_calldata(
                &signed_tx.sender_signing_hash(),
                &signed_tx.signature.data,
                pubkey,
            );
            call_custom_validation_contract(
                signed_tx,
                world_state,
                chain_store,
                validation_code_hash,
                v1_calldata,
            )?
        }
        Err(err) => return Err(err),
    };

    if !is_magic_valid(&output) {
        return Err(AaValidationError::ValidationContractRejected(format!(
            "unexpected return: 0x{}",
            hex::encode(output)
        )));
    }

    Ok(())
}

fn should_fallback_to_v1(error: &AaValidationError) -> bool {
    matches!(
        error,
        AaValidationError::ValidationContractRejected(message)
            if message.starts_with("reverted:")
    )
}

fn call_custom_validation_contract<S: KvStore + 'static>(
    signed_tx: &SignedTransaction,
    world_state: &WorldState<S>,
    chain_store: &ChainStore<S>,
    validation_code_hash: ShellHash,
    calldata: Vec<u8>,
) -> Result<Vec<u8>, AaValidationError> {
    let state_db = ValidationStateDb::new(
        world_state,
        chain_store,
        signed_tx.from,
        validation_code_hash,
    );

    let head = chain_store.get_head_block()?;
    let (number, timestamp, gas_limit, excess_blob_gas) = match head {
        Some(block) => (
            block.header.number,
            block.header.timestamp,
            block.header.gas_limit,
            block.header.excess_blob_gas,
        ),
        None => (0, 0, VALIDATION_GAS_CAP, 0),
    };

    let tx_env = TxEnv::builder()
        .caller(Address::ZERO.into())
        .gas_limit(VALIDATION_GAS_CAP)
        .max_fee_per_gas(0)
        .gas_priority_fee(Some(0))
        .kind(TxKind::Call(signed_tx.from.into()))
        .value(alloy_primitives::U256::ZERO)
        .data(AlBytes::from(calldata))
        .nonce(0)
        .chain_id(Some(signed_tx.tx.chain_id))
        .build_fill();

    let mut block_env = BlockEnv {
        number: alloy_primitives::U256::from(number),
        beneficiary: Address::ZERO.into(),
        timestamp: alloy_primitives::U256::from(timestamp),
        gas_limit,
        basefee: 0,
        difficulty: alloy_primitives::U256::ZERO,
        prevrandao: Some(alloy_primitives::B256::ZERO),
        blob_excess_gas_and_price: None,
        slot_num: 0,
    };
    block_env.set_blob_excess_gas_and_price(excess_blob_gas, 3_338_477);

    let mut db = state_db;
    let ctx: MainnetContext<&mut ValidationStateDb<S>> = Context::new(&mut db, SpecId::CANCUN)
        .modify_block_chained(|b| *b = block_env)
        .modify_cfg_chained(|cfg: &mut CfgEnv| {
            cfg.chain_id = signed_tx.tx.chain_id;
            cfg.disable_nonce_check = true;
            cfg.disable_base_fee = true;
        });

    let spec = SpecId::CANCUN;
    let mut evm = Evm::new(
        ctx,
        EthInstructions::new_mainnet_with_spec(spec),
        ShellPrecompiles::new(spec),
    );

    let exec_result = evm
        .transact(tx_env)
        .map_err(|e| AaValidationError::ValidationContractExecution(format!("{e:?}")))?
        .result;

    match exec_result {
        ExecutionResult::Success { output, .. } => match output {
            revm::context::result::Output::Call(bytes) => Ok(bytes.to_vec()),
            revm::context::result::Output::Create(bytes, _) => Ok(bytes.to_vec()),
        },
        ExecutionResult::Revert { output, .. } => {
            Err(AaValidationError::ValidationContractRejected(format!(
                "reverted: 0x{}",
                hex::encode(output)
            )))
        }
        ExecutionResult::Halt { reason, .. } => Err(AaValidationError::ValidationContractRejected(
            format!("halted: {reason:?}"),
        )),
    }
}

fn encode_validate_transaction_calldata(
    signed_tx: &SignedTransaction,
    signature: &[u8],
    pubkey: &[u8],
) -> Vec<u8> {
    const STATIC_WORDS: usize = 12;
    let tx = &signed_tx.tx;
    let tx_hash = signed_tx.sender_signing_hash();
    let to = tx.to.unwrap_or(Address::ZERO);
    let data_hash = blake3_hash(tx.data.as_ref());
    let aa_bundle_hash = signed_tx
        .aa_bundle()
        .map(|bundle| {
            let mut encoded = Vec::with_capacity(bundle.signing_length());
            bundle.encode_for_signing(&mut encoded);
            blake3_hash(&encoded)
        })
        .unwrap_or(ShellHash::ZERO);

    let sig_offset: usize = 32usize.saturating_mul(STATIC_WORDS);
    let sig_len = 32usize.saturating_add(padded_len(signature.len()));
    let pubkey_offset = sig_offset.saturating_add(sig_len);

    let capacity = 4usize
        .saturating_add(32usize.saturating_mul(STATIC_WORDS))
        .saturating_add(sig_len)
        .saturating_add(32)
        .saturating_add(padded_len(pubkey.len()));
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(
        keccak256(VALIDATE_TRANSACTION_SIGNATURE)
            .as_bytes()
            .get(..4)
            .unwrap_or_else(|| unreachable!("keccak256 is 32 bytes")),
    );
    out.extend_from_slice(tx_hash.as_bytes());
    out.extend_from_slice(signed_tx.from.as_bytes());
    out.extend_from_slice(&abi_word(tx.nonce));
    out.extend_from_slice(to.as_bytes());
    out.extend_from_slice(&tx.value.to_be_bytes::<32>());
    out.extend_from_slice(&abi_word(tx.gas_limit));
    out.extend_from_slice(&abi_word(tx.max_fee_per_gas));
    out.extend_from_slice(&abi_word(tx.chain_id));
    out.extend_from_slice(data_hash.as_bytes());
    out.extend_from_slice(aa_bundle_hash.as_bytes());
    out.extend_from_slice(&abi_word(sig_offset as u64));
    out.extend_from_slice(&abi_word(pubkey_offset as u64));
    encode_bytes(signature, &mut out);
    encode_bytes(pubkey, &mut out);
    out
}

fn encode_validate_transaction_v1_calldata(
    tx_hash: &ShellHash,
    signature: &[u8],
    pubkey: &[u8],
) -> Vec<u8> {
    let sig_offset: usize = 32usize.saturating_mul(3);
    let sig_len = 32usize.saturating_add(padded_len(signature.len()));
    let pubkey_offset = sig_offset.saturating_add(sig_len);

    let capacity = 4usize
        .saturating_add(32usize.saturating_mul(3))
        .saturating_add(sig_len)
        .saturating_add(32)
        .saturating_add(padded_len(pubkey.len()));
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(
        keccak256(VALIDATE_TRANSACTION_V1_SIGNATURE)
            .as_bytes()
            .get(..4)
            .unwrap_or_else(|| unreachable!("keccak256 is 32 bytes")),
    );
    out.extend_from_slice(tx_hash.as_bytes());
    out.extend_from_slice(&abi_word(sig_offset as u64));
    out.extend_from_slice(&abi_word(pubkey_offset as u64));
    encode_bytes(signature, &mut out);
    encode_bytes(pubkey, &mut out);
    out
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&abi_word(bytes.len() as u64));
    out.extend_from_slice(bytes);
    let padding = padded_len(bytes.len()).saturating_sub(bytes.len());
    if padding > 0 {
        out.resize(out.len().saturating_add(padding), 0);
    }
}

fn abi_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_word_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn padded_len(len: usize) -> usize {
    len.next_multiple_of(32)
}

fn is_magic_valid(output: &[u8]) -> bool {
    output == [0x01]
        || (output.len() == 32
            && ((output.last().copied().unwrap_or(0) == 1
                && output
                    .get(..31)
                    .map(|s| s.iter().all(|b| *b == 0))
                    .unwrap_or(false))
                || (output.first().copied().unwrap_or(0) == 1
                    && output
                        .get(1..)
                        .map(|s| s.iter().all(|b| *b == 0))
                        .unwrap_or(false))))
}

/// Validate `SessionAuth` in a session-key-signed AA bundle.
///
/// Steps (AA Phase 2 spec §4.2):
/// 1. Expiry: `session_auth.expiry_block > current_block`
/// 2. Value cap: Σ `inner_call.value ≤ session_auth.value_cap`
/// 3. Target: if `session_auth.target` is Some, all inner calls must target it
/// 4. Root authorization: verify `root_signature` over `session_auth.auth_hash(chain_id)`
///    using the root pubkey. All `ALLOWED_ALGORITHMS` are tried (root key algo is not
///    stored separately from the pubkey bytes).
/// 5. Session sig: verify `session_auth.session_signature` (signed by `session_pubkey`)
///    over the tx `sender_signing_hash()`. The outer `signed_tx.signature` MUST equal
///    `session_auth.session_signature` (same bytes and algo) to prevent injection.
fn validate_session_auth<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    session_auth: &SessionAuth,
    root_pubkey: &[u8],
    inner_calls: &[InnerCall],
    tx_hash: &ShellHash,
    chain_store: &ChainStore<S>,
    verifier: &V,
) -> Result<(), AaValidationError> {
    // 1. Expiry check.
    let current_block = chain_store
        .get_head_block()?
        .map(|b| b.header.number)
        .unwrap_or(0);
    if session_auth.expiry_block <= current_block {
        return Err(AaValidationError::SessionKeyExpired {
            expiry_block: session_auth.expiry_block,
            current_block,
        });
    }

    // 2. Value cap check: sum of all inner call values must not exceed cap.
    let Some(value_sum) = inner_calls
        .iter()
        .try_fold(U256::ZERO, |acc, c| acc.checked_add(c.value))
    else {
        return Err(AaValidationError::SessionValueCapExceeded {
            sum: "overflow".into(),
            cap: format!("{:?}", session_auth.value_cap),
        });
    };
    if value_sum > session_auth.value_cap {
        return Err(AaValidationError::SessionValueCapExceeded {
            sum: format!("{value_sum:?}"),
            cap: format!("{:?}", session_auth.value_cap),
        });
    }

    // 3. Target restriction: if set, every inner call must target it.
    if let Some(required_target) = session_auth.target {
        for call in inner_calls {
            if call.to != Some(required_target) {
                return Err(AaValidationError::SessionTargetMismatch {
                    expected: required_target,
                    got: call.to,
                });
            }
        }
    }

    // 4. Root authorization: root_signature over session_auth.auth_hash(chain_id).
    //
    // The root key's algorithm is not stored separately from the pubkey bytes,
    // so we try all ALLOWED_ALGORITHMS and accept if any succeeds. This handles
    // the case where the root key and session key use different algorithms.
    let auth_hash = session_auth.auth_hash(signed_tx.tx.chain_id);
    let root_valid = ALLOWED_ALGORITHMS.iter().copied().any(|algo| {
        let root_sig = PQSignature::new(algo, session_auth.root_signature.as_ref().to_vec());
        verifier
            .verify(root_pubkey, auth_hash.as_bytes(), &root_sig)
            .unwrap_or(false)
    });
    if !root_valid {
        return Err(AaValidationError::SessionRootSignatureInvalid);
    }

    // 5. Session signature: the outer tx signature IS the session signature —
    //    both must agree on algo and bytes. This binds the session key to the
    //    outer transaction envelope and prevents an attacker from injecting an
    //    arbitrary outer sig while supplying a valid session_signature separately.
    let session_algo = SignatureType::from_u8(session_auth.session_algo).ok_or(
        AaValidationError::SessionKeyDisallowedAlgorithm(session_auth.session_algo),
    )?;
    if !is_algorithm_allowed(session_algo) {
        return Err(AaValidationError::SessionKeyDisallowedAlgorithm(
            session_auth.session_algo,
        ));
    }
    if signed_tx.signature.sig_type != session_algo
        || signed_tx.signature.data.as_slice() != session_auth.session_signature.as_ref()
    {
        return Err(AaValidationError::SessionKeySignatureInvalid);
    }
    let session_sig = PQSignature::new(
        session_algo,
        session_auth.session_signature.as_ref().to_vec(),
    );
    let session_valid = verifier.verify(
        session_auth.session_pubkey.as_ref(),
        tx_hash.as_bytes(),
        &session_sig,
    )?;
    if !session_valid {
        return Err(AaValidationError::SessionKeySignatureInvalid);
    }

    Ok(())
}

///
/// revm journals writes inside the transaction result. The result is never
/// committed, so the borrowed world state remains unchanged even if the
/// paymaster contract internally writes storage.
///
/// `calldata` here is the outer transaction's `tx.data` (the AaBundle RLP).
fn call_paymaster_validate<S: KvStore + 'static>(
    signed_tx: &SignedTransaction,
    paymaster: &Address,
    context: &[u8],
    world_state: &WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<(), AaValidationError> {
    let max_gas_cost = U256::from(signed_tx.tx.gas_limit)
        .checked_mul(U256::from(signed_tx.tx.max_fee_per_gas))
        .unwrap_or(U256::MAX);

    let calldata = encode_validate_paymaster_op_calldata(
        &signed_tx.from,
        signed_tx.tx.data.as_ref(),
        max_gas_cost,
        context,
    );

    let wrapper_address = paymaster_validation_wrapper_address(paymaster);
    let state_db = ValidationStateDb::with_inline_code(
        world_state,
        chain_store,
        wrapper_address,
        paymaster_validation_wrapper_code(paymaster),
    );

    let head = chain_store.get_head_block()?;
    let (number, timestamp, gas_limit, excess_blob_gas) = match head {
        Some(block) => (
            block.header.number,
            block.header.timestamp,
            block.header.gas_limit,
            block.header.excess_blob_gas,
        ),
        None => (0, 0, PAYMASTER_VALIDATE_GAS_CAP, 0),
    };

    let tx_env = TxEnv::builder()
        .caller(Address::ZERO.into())
        .gas_limit(PAYMASTER_VALIDATE_GAS_CAP)
        .max_fee_per_gas(0)
        .gas_priority_fee(Some(0))
        .kind(TxKind::Call(wrapper_address.into()))
        .value(alloy_primitives::U256::ZERO)
        .data(AlBytes::from(calldata))
        .nonce(0)
        .chain_id(Some(signed_tx.tx.chain_id))
        .build_fill();

    let mut block_env = BlockEnv {
        number: alloy_primitives::U256::from(number),
        beneficiary: Address::ZERO.into(),
        timestamp: alloy_primitives::U256::from(timestamp),
        gas_limit,
        basefee: 0,
        difficulty: alloy_primitives::U256::ZERO,
        prevrandao: Some(alloy_primitives::B256::ZERO),
        blob_excess_gas_and_price: None,
        slot_num: 0,
    };
    block_env.set_blob_excess_gas_and_price(excess_blob_gas, 3_338_477);

    let mut db = state_db;
    let ctx: MainnetContext<&mut ValidationStateDb<'_, S>> = Context::new(&mut db, SpecId::CANCUN)
        .modify_block_chained(|b| *b = block_env)
        .modify_cfg_chained(|cfg: &mut CfgEnv| {
            cfg.chain_id = signed_tx.tx.chain_id;
            cfg.disable_nonce_check = true;
            cfg.disable_base_fee = true;
        });

    let spec = SpecId::CANCUN;
    let mut evm = Evm::new(
        ctx,
        EthInstructions::new_mainnet_with_spec(spec),
        ShellPrecompiles::new(spec),
    );

    let exec_result = evm
        .transact(tx_env)
        .map_err(|e| AaValidationError::PaymasterValidationFailed(format!("{e:?}")))?
        .result;

    match exec_result {
        ExecutionResult::Success { output, .. } => {
            let bytes = match output {
                revm::context::result::Output::Call(b) => b.to_vec(),
                revm::context::result::Output::Create(b, _) => b.to_vec(),
            };
            // Return value is `bool accepted` ABI-encoded as a 32-byte word.
            // The boolean true is represented as ...0001 (low byte = 1).
            let accepted = decode_abi_bool(&bytes) == Some(true);
            if accepted {
                Ok(())
            } else {
                Err(AaValidationError::PaymasterRejected)
            }
        }
        ExecutionResult::Revert { output, .. } => {
            Err(AaValidationError::PaymasterValidationFailed(format!(
                "reverted: 0x{}",
                hex::encode(output)
            )))
        }
        ExecutionResult::Halt { reason, .. } => {
            if matches!(reason, HaltReason::OutOfGas(_)) {
                Err(AaValidationError::PaymasterGasExceeded)
            } else {
                Err(AaValidationError::PaymasterValidationFailed(format!(
                    "halted: {reason:?}",
                )))
            }
        }
    }
}

fn paymaster_validation_wrapper_address(paymaster: &Address) -> Address {
    let mut bytes = [0xFF; 32];
    if paymaster.to_alloy().as_slice() == &bytes[12..] {
        bytes[31] = 0xFE;
    }
    Address::from(bytes)
}

/// Build a transient wrapper that forwards calldata with `STATICCALL` and
/// propagates the target's return or revert data.
fn paymaster_validation_wrapper_code(paymaster: &Address) -> Vec<u8> {
    let mut code = vec![
        0x36, 0x5F, 0x5F, 0x37, // calldatacopy(0, 0, calldatasize())
        0x5F, 0x5F, 0x36, 0x5F, 0x73, // staticcall output/input arguments + PUSH20
    ];
    code.extend_from_slice(paymaster.to_alloy().as_slice());
    code.extend_from_slice(&[
        0x5A, 0xFA, // gas(), staticcall(...)
        0x3D, 0x5F, 0x5F, 0x3E, // returndatacopy(0, 0, returndatasize())
        0x60, 0x29, 0x57, // jump to success when STATICCALL returned true
        0x3D, 0x5F, 0xFD, // revert(0, returndatasize())
        0x5B, 0x3D, 0x5F, 0xF3, // success: return(0, returndatasize())
    ]);
    code
}

fn decode_abi_bool(bytes: &[u8]) -> Option<bool> {
    let word: &[u8; 32] = bytes.try_into().ok()?;
    if word[..31].iter().any(|byte| *byte != 0) {
        return None;
    }
    match word[31] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// ABI-encode `validatePaymasterOp(address,bytes,uint256,bytes)` calldata.
///
/// Layout:
/// ```text
/// [0..4]   selector
/// [4..36]  sender (address, left-padded to 32 bytes)
/// [36..68] offset of callData (= 0x80 = 128)
/// [68..100] maxGasCost (uint256)
/// [100..132] offset of context (= 0x80 + 32 + padded(callData.len))
/// [132..]  callData length + callData padded
///          context length + context padded
/// ```
fn encode_validate_paymaster_op_calldata(
    sender: &Address,
    call_data: &[u8],
    max_gas_cost: U256,
    context: &[u8],
) -> Vec<u8> {
    let call_data_offset: usize = 128; // 4 static args × 32 bytes
    let call_data_len_padded = padded_len(call_data.len());
    let context_offset = call_data_offset
        .saturating_add(32) // length word
        .saturating_add(call_data_len_padded);

    let capacity = 4
        + 32 // sender
        + 32 // callData offset
        + 32 // maxGasCost
        + 32 // context offset
        + 32 + call_data_len_padded
        + 32 + padded_len(context.len());
    let mut out = Vec::with_capacity(capacity);

    // selector
    out.extend_from_slice(
        keccak256(VALIDATE_PAYMASTER_OP_SIGNATURE)
            .as_bytes()
            .get(..4)
            .unwrap_or_else(|| unreachable!("keccak256 is 32 bytes")),
    );

    // sender: address left-padded to 32 bytes
    let sender_evm = sender.to_alloy();
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(sender_evm.as_slice());

    // callData offset
    out.extend_from_slice(&abi_word(call_data_offset as u64));

    // maxGasCost
    out.extend_from_slice(&abi_word_u256(max_gas_cost));

    // context offset
    out.extend_from_slice(&abi_word(context_offset as u64));

    // callData bytes
    encode_bytes(call_data, &mut out);

    // context bytes
    encode_bytes(context, &mut out);

    out
}

struct ValidationStateDb<'a, S: KvStore + 'static> {
    inner: ShellStateRefDb<'a, S>,
    validation_target: Address,
    validation_code_hash: ShellHash,
    inline_code: Option<Bytecode>,
}

impl<'a, S: KvStore + 'static> ValidationStateDb<'a, S> {
    fn new(
        world_state: &'a WorldState<S>,
        chain_store: &'a ChainStore<S>,
        validation_target: Address,
        validation_code_hash: ShellHash,
    ) -> Self {
        Self {
            inner: ShellStateRefDb::new(world_state, chain_store),
            validation_target,
            validation_code_hash,
            inline_code: None,
        }
    }

    fn with_inline_code(
        world_state: &'a WorldState<S>,
        chain_store: &'a ChainStore<S>,
        validation_target: Address,
        code: Vec<u8>,
    ) -> Self {
        let validation_code_hash = keccak256(&code);
        Self {
            inner: ShellStateRefDb::new(world_state, chain_store),
            validation_target,
            validation_code_hash,
            inline_code: Some(
                Bytecode::new_raw_checked(code.into())
                    .unwrap_or_else(|_| unreachable!("wrapper bytecode is valid")),
            ),
        }
    }
}

impl<S: KvStore + 'static> Database for ValidationStateDb<'_, S> {
    type Error = StateDbError;

    fn basic(
        &mut self,
        address: alloy_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let mut info = self.inner.basic(address)?;
        if address == self.validation_target.to_alloy() {
            // If the inner lookup (which zero-pads to 32 bytes) didn't find the
            // account, try again with the full 32-byte validation_target address.
            if info.is_none() {
                info = self
                    .inner
                    .world_state()
                    .get_account(&self.validation_target)
                    .map_err(StateDbError::Storage)?
                    .map(|a| ShellStateDb::<S>::to_account_info(&a));
            }
            if info.is_none() && self.inline_code.is_some() {
                info = Some(AccountInfo::default());
            }
            if let Some(ref mut account) = info {
                account.code_hash = shell_hash_to_b256(&self.validation_code_hash);
                account.code = None;
            }
        }
        Ok(info)
    }

    fn code_by_hash(
        &mut self,
        code_hash: alloy_primitives::B256,
    ) -> Result<revm::state::Bytecode, Self::Error> {
        if code_hash == shell_hash_to_b256(&self.validation_code_hash) {
            if let Some(code) = &self.inline_code {
                return Ok(code.clone());
            }
        }
        self.inner.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: alloy_primitives::Address,
        index: alloy_primitives::U256,
    ) -> Result<alloy_primitives::U256, Self::Error> {
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{
        AaBundle, Account, InnerCall, PubkeyMode, SessionAuth, Transaction, AA_BUNDLE_TX_TYPE,
    };
    use shell_crypto::{
        DilithiumSigner, DilithiumVerifier, MlDsaSigner, MultiVerifier, PQSignature, Signer,
    };
    use shell_primitives::{Bytes, U256};
    use shell_storage::MemoryDb;
    use std::sync::Arc;

    fn setup_stores() -> (WorldState<MemoryDb>, ChainStore<MemoryDb>) {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        (ws, cs)
    }

    fn signer_address(signer: &DilithiumSigner) -> Address {
        Address::from_public_key(signer.public_key(), signer.sig_type().as_u8())
    }

    fn base_tx(chain_id: u64, nonce: u64) -> Transaction {
        Transaction {
            chain_id,
            nonce,
            to: Some(Address::from([0x01; 20])),
            value: U256::ZERO,
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

    fn fund_account(ws: &mut WorldState<MemoryDb>, addr: &Address) {
        ws.set_account(
            addr,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(1_000_000u64),
                validation_code_hash: None,
                code_hash: None,
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();
    }

    fn sign_tx(
        signer: &DilithiumSigner,
        tx: Transaction,
        include_pubkey: bool,
    ) -> SignedTransaction {
        let from = signer_address(signer);
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
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

    fn validator_stores_then_returns_true() -> Vec<u8> {
        vec![
            0x60, 0x01, 0x60, 0x00, 0x55, // sstore(0, 1)
            0x60, 0x01, 0x60, 0x00, 0x52, // mstore(0, 1)
            0x60, 0x20, 0x60, 0x00, 0xf3, // return(0, 32)
        ]
    }

    fn read_abi_u64(word: &[u8]) -> u64 {
        u64::from_be_bytes(word[24..32].try_into().unwrap())
    }

    fn read_abi_u256(word: &[u8]) -> U256 {
        U256::from_be_bytes::<32>(word.try_into().unwrap())
    }

    fn fixture_account_sequence(addr: &Address) -> u64 {
        addr.as_bytes()
            .iter()
            .copied()
            .find(|byte| *byte != u8::default())
            .map(u64::from)
            .unwrap_or_else(|| u64::from(u8::MAX))
    }

    #[test]
    fn custom_validator_v2_calldata_carries_full_tx_context() {
        let signer = DilithiumSigner::generate();
        let from = signer_address(&signer);
        let account_sequence = fixture_account_sequence(&from);
        let mut tx = base_tx(1337, account_sequence);
        tx.value = U256::from(42u64);
        tx.data = Bytes::from(vec![1, 2, 3, 4]);
        tx.gas_limit = 123_456;
        tx.max_fee_per_gas = 77;
        let signature = PQSignature::new(SignatureType::Dilithium3, vec![0xAB; 64]);
        let signed = SignedTransaction::with_pubkey(
            from,
            tx.clone(),
            signature,
            signer.public_key().to_vec(),
        );

        let calldata = encode_validate_transaction_calldata(
            &signed,
            &signed.signature.data,
            signer.public_key(),
        );
        let selector = keccak256(VALIDATE_TRANSACTION_SIGNATURE);
        assert_eq!(&calldata[0..4], &selector.as_bytes()[..4]);
        assert_eq!(&calldata[4..36], signed.sender_signing_hash().as_bytes());
        assert_eq!(&calldata[36..68], from.as_bytes());
        assert_eq!(read_abi_u64(&calldata[68..100]), account_sequence);
        assert_eq!(&calldata[100..132], tx.to.unwrap().as_bytes());
        assert_eq!(&calldata[132..164], &U256::from(42u64).to_be_bytes::<32>());
        assert_eq!(read_abi_u64(&calldata[164..196]), 123_456);
        assert_eq!(read_abi_u64(&calldata[196..228]), 77);
        assert_eq!(read_abi_u64(&calldata[228..260]), 1337);
        assert_eq!(
            &calldata[260..292],
            blake3_hash(tx.data.as_ref()).as_bytes()
        );
        assert_eq!(&calldata[292..324], ShellHash::ZERO.as_bytes());
        assert_eq!(read_abi_u64(&calldata[324..356]), 384);
        assert_eq!(read_abi_u64(&calldata[356..388]), 480);
        assert_eq!(read_abi_u64(&calldata[388..420]), 64);
        assert_eq!(&calldata[420..484], signed.signature.data.as_slice());
    }

    #[test]
    fn paymaster_validation_calldata_encodes_uint256_max_gas_cost() {
        let sender = Address::from([0x22; 20]);
        let call_data = [0xAA, 0xBB, 0xCC];
        let context = [0xDD, 0xEE];
        let max_gas_cost = U256::from(u64::MAX) + U256::from(42u64);

        let calldata =
            encode_validate_paymaster_op_calldata(&sender, &call_data, max_gas_cost, &context);
        let selector = keccak256(VALIDATE_PAYMASTER_OP_SIGNATURE);

        assert_eq!(&calldata[0..4], &selector.as_bytes()[..4]);
        assert_eq!(&calldata[4..16], &[0u8; 12]);
        assert_eq!(&calldata[16..36], sender.to_alloy().as_slice());
        assert_eq!(read_abi_u64(&calldata[36..68]), 128);
        assert_eq!(read_abi_u256(&calldata[68..100]), max_gas_cost);
        assert_eq!(read_abi_u64(&calldata[100..132]), 192);
        assert_eq!(read_abi_u64(&calldata[132..164]), call_data.len() as u64);
        assert_eq!(&calldata[164..167], call_data.as_slice());
        assert_eq!(read_abi_u64(&calldata[196..228]), context.len() as u64);
        assert_eq!(&calldata[228..230], context.as_slice());
    }

    #[test]
    fn paymaster_abi_bool_requires_canonical_word() {
        let mut accepted = [0u8; 32];
        accepted[31] = 1;
        assert_eq!(decode_abi_bool(&accepted), Some(true));

        assert_eq!(decode_abi_bool(&[0u8; 32]), Some(false));
        assert_eq!(decode_abi_bool(&[1]), None);
        assert_eq!(decode_abi_bool(&[0u8; 33]), None);

        let mut non_canonical = [0u8; 32];
        non_canonical[0] = 1;
        assert_eq!(decode_abi_bool(&non_canonical), None);

        let mut invalid_value = [0u8; 32];
        invalid_value[31] = 2;
        assert_eq!(decode_abi_bool(&invalid_value), None);
    }

    fn install_paymaster(
        ws: &mut WorldState<MemoryDb>,
        cs: &ChainStore<MemoryDb>,
        paymaster: Address,
        code: Vec<u8>,
    ) {
        let code_hash = keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();
        ws.set_account(
            &paymaster,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::ZERO,
                validation_code_hash: None,
                code_hash: Some(code_hash),
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();
    }

    #[test]
    fn paymaster_validation_accepts_read_only_contract() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let paymaster = Address::from([0x77; 20]);
        install_paymaster(&mut ws, &cs, paymaster, validator_returns_true());
        let signed = sign_tx(&signer, base_tx(1337, 0), true);

        assert!(call_paymaster_validate(&signed, &paymaster, &[1], &ws, &cs).is_ok());
    }

    #[test]
    fn paymaster_validation_rejects_state_changes() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let paymaster = Address::from([0x77; 20]);
        install_paymaster(
            &mut ws,
            &cs,
            paymaster,
            validator_stores_then_returns_true(),
        );
        let signed = sign_tx(&signer, base_tx(1337, 0), true);

        let error = call_paymaster_validate(&signed, &paymaster, &[1], &ws, &cs).unwrap_err();

        assert!(
            matches!(error, AaValidationError::PaymasterValidationFailed(message) if message.starts_with("reverted:"))
        );
    }

    #[test]
    fn custom_validator_v1_fallback_rejects_v2_halts() {
        assert!(should_fallback_to_v1(
            &AaValidationError::ValidationContractRejected("reverted: 0x".into())
        ));
        assert!(!should_fallback_to_v1(
            &AaValidationError::ValidationContractRejected("halted: OutOfGas".into())
        ));
        assert!(!should_fallback_to_v1(
            &AaValidationError::ValidationContractExecution("database error".into())
        ));
    }

    #[test]
    fn layer1_first_use_verifies_address_and_signature() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from);
        let account_nonce = ws.get_nonce(&from).unwrap();
        let signed = sign_tx(&signer, base_tx(1337, account_nonce), true);

        let outcome = validate_aa_tx(&signed, &ws, &cs, &DilithiumVerifier).unwrap();
        assert_eq!(outcome.pubkey, signer.public_key());
        assert!(outcome.should_register_pubkey);
        assert!(outcome.protocol_checks_nonce);
    }

    #[test]
    fn first_use_session_accepts_distinct_root_key_algorithm() {
        let root = MlDsaSigner::generate();
        let session = DilithiumSigner::generate();
        let from = Address::from_public_key(root.public_key(), root.sig_type().as_u8());
        let (mut ws, cs) = setup_stores();
        fund_account(&mut ws, &from);

        let mut auth = SessionAuth {
            session_pubkey: Bytes::from(session.public_key().to_vec()),
            session_algo: session.sig_type().as_u8(),
            target: None,
            value_cap: U256::ZERO,
            expiry_block: 10,
            root_signature: Bytes::new(),
            session_signature: Bytes::from(vec![1]),
        };
        auth.root_signature = Bytes::from(root.sign(auth.auth_hash(1337).as_bytes()).unwrap().data);
        let account_nonce = ws.get_nonce(&from).unwrap();
        let mut tx = base_tx(1337, account_nonce);
        tx.tx_type = AA_BUNDLE_TX_TYPE;
        tx.gas_limit = 100_000;
        let inner_call = InnerCall {
            to: tx.to,
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 50_000,
        };
        let placeholder = PQSignature::new(session.sig_type(), vec![1]);
        let unsigned = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            placeholder,
            PubkeyMode::Embedded(root.public_key().to_vec()),
            AaBundle {
                inner_calls: vec![inner_call.clone()],
                session_auth: Some(auth.clone()),
                ..AaBundle::default()
            },
        )
        .unwrap();
        let session_signature = session
            .sign(unsigned.sender_signing_hash().as_bytes())
            .unwrap();
        auth.session_signature = Bytes::from(session_signature.data.clone());
        let signed = SignedTransaction::with_aa_bundle(
            from,
            tx,
            session_signature,
            PubkeyMode::Embedded(root.public_key().to_vec()),
            AaBundle {
                inner_calls: vec![inner_call],
                session_auth: Some(auth),
                ..AaBundle::default()
            },
        )
        .unwrap();

        let outcome = validate_aa_tx(&signed, &ws, &cs, &MultiVerifier).unwrap();
        assert_eq!(outcome.pubkey, root.public_key());
        assert!(outcome.should_register_pubkey);
    }

    #[test]
    fn layer2_registered_pubkey_uses_builtin_verifier() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from);
        cs.put_pubkey(&from, signer.public_key()).unwrap();
        let account_nonce = ws.get_nonce(&from).unwrap();
        let signed = sign_tx(&signer, base_tx(1337, account_nonce), false);

        let outcome = validate_aa_tx(&signed, &ws, &cs, &DilithiumVerifier).unwrap();
        assert_eq!(outcome.pubkey, signer.public_key());
        assert!(!outcome.should_register_pubkey);
        assert!(outcome.protocol_checks_nonce);
    }

    #[test]
    fn custom_validation_contract_can_accept_without_builtin_signature_rules() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);

        let code = validator_returns_true();
        let code_hash = keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();
        ws.set_account(
            &from,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(1_000_000u64),
                validation_code_hash: Some(code_hash),
                code_hash: None,
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();

        let tx = base_tx(1337, 0);
        let signed = SignedTransaction::new(
            from,
            tx,
            PQSignature::new(SignatureType::MlDsa65, vec![0xaa; 64]),
        );

        let outcome = validate_aa_tx(&signed, &ws, &cs, &DilithiumVerifier).unwrap();
        assert!(outcome.pubkey.is_empty());
        assert!(!outcome.should_register_pubkey);
        assert!(outcome.protocol_checks_nonce);
    }

    #[test]
    fn custom_validation_discards_journaled_storage_writes() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        let storage_key = ShellHash::ZERO;

        let code = validator_stores_then_returns_true();
        let code_hash = keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();
        ws.set_account(
            &from,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(1_000_000u64),
                validation_code_hash: Some(code_hash),
                code_hash: None,
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();

        let account_nonce = ws.get_nonce(&from).unwrap();
        let signed = SignedTransaction::new(
            from,
            base_tx(1337, account_nonce),
            PQSignature::new(SignatureType::MlDsa65, vec![0xaa; 64]),
        );

        validate_aa_tx(&signed, &ws, &cs, &DilithiumVerifier).unwrap();
        assert_eq!(
            ws.get_storage(&from, &storage_key).unwrap(),
            ShellHash::ZERO
        );
    }

    #[test]
    fn custom_validation_contract_rejects_non_magic_return() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);

        let code = validator_returns_false();
        let code_hash = keccak256(&code);
        cs.put_code(&code_hash, &code).unwrap();
        ws.set_account(
            &from,
            &Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::from(1_000_000u64),
                validation_code_hash: Some(code_hash),
                code_hash: None,
                storage_root: ShellHash::ZERO,
            },
        )
        .unwrap();

        let signed = SignedTransaction::new(
            from,
            base_tx(1337, 0),
            PQSignature::new(SignatureType::MlDsa65, vec![0xbb; 64]),
        );

        let err = validate_aa_tx(&signed, &ws, &cs, &DilithiumVerifier).unwrap_err();
        assert!(matches!(
            err,
            AaValidationError::ValidationContractRejected(_)
        ));
    }
}
