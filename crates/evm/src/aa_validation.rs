use alloy_primitives::Bytes as AlBytes;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, CfgEnv, Context, Evm, TxEnv};
use revm::database_interface::Database;
use revm::handler::instructions::EthInstructions;
use revm::handler::{ExecuteEvm, MainnetContext};
use revm::primitives::hardfork::SpecId;
use revm::primitives::TxKind;
use revm::state::AccountInfo;
use shell_core::SignedTransaction;
use shell_crypto::{SignatureType, Verifier, ALLOWED_ALGORITHMS};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};

use crate::precompiles::ShellPrecompiles;
use crate::state_db::{shell_hash_to_b256, ShellStateDb, StateDbError};

pub const VALIDATION_GAS_CAP: u64 = 500_000;

const VALIDATE_TRANSACTION_SIGNATURE: &[u8] = b"validateTransaction(bytes32,bytes,bytes)";

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
}

pub fn validate_aa_tx<S: KvStore + 'static, V: Verifier>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    verifier: &V,
) -> Result<AaValidationOutcome, AaValidationError> {
    let account = world_state.get_account(&signed_tx.from)?;
    let registered_pubkey = chain_store.get_pubkey(&signed_tx.from)?;

    if let Some(account) = account.as_ref() {
        if let Some(validation_code_hash) = account.validation_code_hash {
            let pubkey = signed_tx
                .sender_pubkey
                .clone()
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

    if !ALLOWED_ALGORITHMS.contains(&signed_tx.signature.sig_type) {
        return Err(AaValidationError::DisallowedAlgorithm(
            signed_tx.signature.sig_type,
        ));
    }

    let pubkey = resolve_pubkey(signed_tx.sender_pubkey.as_ref(), registered_pubkey.as_ref())?;

    if signed_tx.sender_pubkey.is_some() {
        if let Some(registered) = registered_pubkey.as_ref() {
            if registered != &pubkey {
                return Err(AaValidationError::PubkeyConflict);
            }
        }
    }

    if registered_pubkey.is_none() {
        let derived = Address::from_public_key(&pubkey, signed_tx.signature.sig_type.as_u8());
        if signed_tx.from != derived {
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

    let tx_hash = signed_tx.hash();
    let valid = verifier.verify(&pubkey, tx_hash.as_bytes(), &signed_tx.signature)?;
    if !valid {
        return Err(AaValidationError::SignatureInvalid);
    }

    Ok(AaValidationOutcome {
        should_register_pubkey: signed_tx.sender_pubkey.is_some() && registered_pubkey.is_none(),
        pubkey,
        protocol_checks_nonce: true,
    })
}

fn resolve_pubkey(
    sender_pubkey: Option<&Vec<u8>>,
    registered_pubkey: Option<&Vec<u8>>,
) -> Result<Vec<u8>, AaValidationError> {
    if let Some(pk) = sender_pubkey {
        return Ok(pk.clone());
    }
    match registered_pubkey {
        Some(pk) => Ok(pk.clone()),
        None => Err(AaValidationError::PubkeyNotFound),
    }
}

fn validate_custom_contract<S: KvStore + 'static>(
    signed_tx: &SignedTransaction,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    validation_code_hash: ShellHash,
    pubkey: &[u8],
) -> Result<(), AaValidationError> {
    if chain_store.get_code(&validation_code_hash)?.is_none() {
        return Err(AaValidationError::ValidationCodeMissing(
            validation_code_hash,
        ));
    }

    let snapshot = world_state.snapshot()?;
    let validation_chain_store = ChainStore::new(chain_store.store().clone());
    let state_db = ValidationStateDb::new(
        snapshot,
        validation_chain_store,
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
        .data(AlBytes::from(encode_validate_transaction_calldata(
            &signed_tx.hash(),
            &signed_tx.signature.data,
            pubkey,
        )))
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

    let output = match exec_result {
        ExecutionResult::Success { output, .. } => match output {
            revm::context::result::Output::Call(bytes) => bytes.to_vec(),
            revm::context::result::Output::Create(bytes, _) => bytes.to_vec(),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(AaValidationError::ValidationContractRejected(format!(
                "reverted: 0x{}",
                hex::encode(output)
            )));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(AaValidationError::ValidationContractRejected(format!(
                "halted: {reason:?}"
            )));
        }
    };

    if !is_magic_valid(&output) {
        return Err(AaValidationError::ValidationContractRejected(format!(
            "unexpected return: 0x{}",
            hex::encode(output)
        )));
    }

    Ok(())
}

fn encode_validate_transaction_calldata(
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
        keccak256(VALIDATE_TRANSACTION_SIGNATURE)
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

fn padded_len(len: usize) -> usize {
    len.next_multiple_of(32)
}

fn is_magic_valid(output: &[u8]) -> bool {
    output == [0x01]
        || (output.len() == 32
            && ((output.last().copied().unwrap_or(0) == 1
                && output.get(..31).map(|s| s.iter().all(|b| *b == 0)).unwrap_or(false))
                || (output.first().copied().unwrap_or(0) == 1
                    && output.get(1..).map(|s| s.iter().all(|b| *b == 0)).unwrap_or(false))))
}

struct ValidationStateDb<S: KvStore + 'static> {
    inner: ShellStateDb<S>,
    validation_target: Address,
    validation_code_hash: ShellHash,
}

impl<S: KvStore + 'static> ValidationStateDb<S> {
    fn new(
        world_state: WorldState<S>,
        chain_store: ChainStore<S>,
        validation_target: Address,
        validation_code_hash: ShellHash,
    ) -> Self {
        Self {
            inner: ShellStateDb::new(world_state, chain_store),
            validation_target,
            validation_code_hash,
        }
    }
}

impl<S: KvStore + 'static> Database for ValidationStateDb<S> {
    type Error = StateDbError;

    fn basic(
        &mut self,
        address: alloy_primitives::Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let mut info = self.inner.basic(address)?;
        if address == alloy_primitives::Address::from(self.validation_target) {
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
    use shell_core::{Account, Transaction};
    use shell_crypto::{DilithiumSigner, DilithiumVerifier, PQSignature, Signer};
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

    #[test]
    fn layer1_first_use_verifies_address_and_signature() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from);
        let signed = sign_tx(&signer, base_tx(1337, 0), true);

        let outcome = validate_aa_tx(&signed, &mut ws, &cs, &DilithiumVerifier).unwrap();
        assert_eq!(outcome.pubkey, signer.public_key());
        assert!(outcome.should_register_pubkey);
        assert!(outcome.protocol_checks_nonce);
    }

    #[test]
    fn layer2_registered_pubkey_uses_builtin_verifier() {
        let signer = DilithiumSigner::generate();
        let (mut ws, cs) = setup_stores();
        let from = signer_address(&signer);
        fund_account(&mut ws, &from);
        cs.put_pubkey(&from, signer.public_key()).unwrap();
        let signed = sign_tx(&signer, base_tx(1337, 0), false);

        let outcome = validate_aa_tx(&signed, &mut ws, &cs, &DilithiumVerifier).unwrap();
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

        let outcome = validate_aa_tx(&signed, &mut ws, &cs, &DilithiumVerifier).unwrap();
        assert!(outcome.pubkey.is_empty());
        assert!(!outcome.should_register_pubkey);
        assert!(outcome.protocol_checks_nonce);
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

        let err = validate_aa_tx(&signed, &mut ws, &cs, &DilithiumVerifier).unwrap_err();
        assert!(matches!(
            err,
            AaValidationError::ValidationContractRejected(_)
        ));
    }
}
