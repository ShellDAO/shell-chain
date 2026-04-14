//! Transaction read/write-set extraction for parallel execution planning.
//!
//! This module provides a conservative, execution-free view of which state
//! surfaces a transaction is expected to read and write. The first milestone
//! covers native value transfers, native system contracts, and ERC20
//! `transfer(address,uint256)` calls. Unknown contract calls are explicitly
//! marked as incomplete so later scheduling layers can fall back to serial
//! execution.

use shell_core::SignedTransaction;
use shell_primitives::Address;

use crate::system_contracts::{
    account_manager_address, is_system_contract, registry_address, ADD_VALIDATOR_SELECTOR,
    CLEAR_VALIDATION_CODE_SELECTOR, GET_VALIDATORS_SELECTOR, IS_VALIDATOR_SELECTOR,
    REMOVE_VALIDATOR_SELECTOR, ROTATE_KEY_SELECTOR, SET_VALIDATION_CODE_SELECTOR,
};

const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// A symbolic state surface touched by a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TxAccessPath {
    /// Conservative barrier for contract creation or unsupported dynamic flows.
    GlobalState,
    /// Sender or recipient native SHELL balance.
    NativeBalance(Address),
    /// Sender account nonce.
    NativeNonce(Address),
    /// Any storage inside a contract when the exact slot set is unknown.
    ContractStorageAny(Address),
    /// ERC20 balance mapping entry for a specific owner.
    Erc20Balance { token: Address, owner: Address },
    /// Validator registry set.
    ValidatorSet,
    /// Native account public-key binding.
    PqPublicKey(Address),
    /// Native account validation code binding.
    ValidationCode(Address),
}

/// Conservative read/write summary for a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxReadWriteSet {
    /// State surfaces read during validation or execution.
    pub reads: Vec<TxAccessPath>,
    /// State surfaces written during execution or post-processing.
    pub writes: Vec<TxAccessPath>,
    /// `false` means the extractor had to fall back to a coarse summary.
    pub complete: bool,
}

impl TxReadWriteSet {
    /// Create an empty, complete read/write set.
    pub fn new() -> Self {
        Self {
            reads: Vec::new(),
            writes: Vec::new(),
            complete: true,
        }
    }

    pub fn add_read(&mut self, path: TxAccessPath) {
        if !self.reads.contains(&path) {
            self.reads.push(path);
        }
    }

    pub fn add_write(&mut self, path: TxAccessPath) {
        if !self.writes.contains(&path) {
            self.writes.push(path);
        }
    }

    pub fn mark_incomplete(&mut self) {
        self.complete = false;
    }
}

/// Extracts conservative state access summaries for transactions.
pub trait ReadWriteSetExtractor {
    fn extract(&self, tx: &SignedTransaction) -> TxReadWriteSet;
}

/// Heuristic extractor used by the M11 parallel-EVM PoC.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicRwSetExtractor;

impl ReadWriteSetExtractor for HeuristicRwSetExtractor {
    fn extract(&self, tx: &SignedTransaction) -> TxReadWriteSet {
        let mut rwset = TxReadWriteSet::new();
        let sender = tx.from;

        rwset.add_read(TxAccessPath::NativeBalance(sender));
        rwset.add_read(TxAccessPath::NativeNonce(sender));
        rwset.add_write(TxAccessPath::NativeBalance(sender));
        rwset.add_write(TxAccessPath::NativeNonce(sender));

        match tx.tx.to {
            None => {
                rwset.add_read(TxAccessPath::GlobalState);
                rwset.add_write(TxAccessPath::GlobalState);
                rwset.mark_incomplete();
            }
            Some(target) if is_system_contract(&target) => {
                classify_system_contract(&mut rwset, sender, target, tx.tx.data.as_ref());
            }
            Some(target) => {
                classify_user_contract(
                    &mut rwset,
                    sender,
                    target,
                    tx.tx.data.as_ref(),
                    !tx.tx.value.is_zero(),
                );
            }
        }

        rwset
    }
}

fn classify_system_contract(
    rwset: &mut TxReadWriteSet,
    sender: Address,
    target: Address,
    data: &[u8],
) {
    let Some(selector) = decode_selector(data) else {
        rwset.add_read(TxAccessPath::ContractStorageAny(target));
        rwset.add_write(TxAccessPath::ContractStorageAny(target));
        rwset.mark_incomplete();
        return;
    };

    if target == registry_address() {
        match selector {
            ADD_VALIDATOR_SELECTOR | REMOVE_VALIDATOR_SELECTOR => {
                rwset.add_read(TxAccessPath::ValidatorSet);
                rwset.add_write(TxAccessPath::ValidatorSet);
            }
            GET_VALIDATORS_SELECTOR | IS_VALIDATOR_SELECTOR => {
                rwset.add_read(TxAccessPath::ValidatorSet);
            }
            _ => {
                rwset.add_read(TxAccessPath::ValidatorSet);
                rwset.add_write(TxAccessPath::ValidatorSet);
                rwset.mark_incomplete();
            }
        }
        return;
    }

    if target == account_manager_address() {
        match selector {
            ROTATE_KEY_SELECTOR => {
                rwset.add_read(TxAccessPath::PqPublicKey(sender));
                rwset.add_write(TxAccessPath::PqPublicKey(sender));
            }
            SET_VALIDATION_CODE_SELECTOR | CLEAR_VALIDATION_CODE_SELECTOR => {
                rwset.add_read(TxAccessPath::ValidationCode(sender));
                rwset.add_write(TxAccessPath::ValidationCode(sender));
            }
            _ => {
                rwset.add_read(TxAccessPath::ContractStorageAny(target));
                rwset.add_write(TxAccessPath::ContractStorageAny(target));
                rwset.mark_incomplete();
            }
        }
        return;
    }

    rwset.add_read(TxAccessPath::ContractStorageAny(target));
    rwset.add_write(TxAccessPath::ContractStorageAny(target));
    rwset.mark_incomplete();
}

fn classify_user_contract(
    rwset: &mut TxReadWriteSet,
    sender: Address,
    target: Address,
    data: &[u8],
    has_value: bool,
) {
    if data.is_empty() {
        if has_value {
            rwset.add_read(TxAccessPath::NativeBalance(target));
            rwset.add_write(TxAccessPath::NativeBalance(target));
        }
        return;
    }

    if let Some(recipient) = decode_erc20_transfer_recipient(data) {
        let sender_balance = TxAccessPath::Erc20Balance {
            token: target,
            owner: sender,
        };
        let recipient_balance = TxAccessPath::Erc20Balance {
            token: target,
            owner: recipient,
        };
        rwset.add_read(sender_balance.clone());
        rwset.add_write(sender_balance);
        rwset.add_read(recipient_balance.clone());
        rwset.add_write(recipient_balance);
        if has_value {
            rwset.add_read(TxAccessPath::NativeBalance(target));
            rwset.add_write(TxAccessPath::NativeBalance(target));
        }
        return;
    }

    rwset.add_read(TxAccessPath::ContractStorageAny(target));
    rwset.add_write(TxAccessPath::ContractStorageAny(target));
    rwset.mark_incomplete();
}

fn decode_selector(data: &[u8]) -> Option<[u8; 4]> {
    data.get(..4)?.try_into().ok()
}

fn decode_erc20_transfer_recipient(data: &[u8]) -> Option<Address> {
    if data.len() < 4 + 32 + 32 {
        return None;
    }
    let selector = decode_selector(data)?;
    if selector != ERC20_TRANSFER_SELECTOR {
        return None;
    }

    Address::try_from_slice(&data[16..36]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{SignedTransaction, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Bytes, U256};

    use crate::system_contracts::{
        account_manager_address, encode_add_validator_calldata, encode_rotate_key_calldata,
    };

    fn signed_tx(to: Option<Address>, value: u64, data: Vec<u8>) -> SignedTransaction {
        let from = Address::from([0x11; 20]);
        let tx = Transaction {
            chain_id: 424242,
            nonce: 1,
            to,
            value: U256::from(value),
            data: Bytes::from(data),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0x55; 32]);
        SignedTransaction::new(from, tx, sig)
    }

    #[test]
    fn native_transfer_tracks_sender_and_recipient_balances() {
        let recipient = Address::from([0x22; 20]);
        let tx = signed_tx(Some(recipient), 50, Vec::new());
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.complete);
        assert!(rwset.reads.contains(&TxAccessPath::NativeBalance(tx.from)));
        assert!(rwset.reads.contains(&TxAccessPath::NativeNonce(tx.from)));
        assert!(rwset.writes.contains(&TxAccessPath::NativeBalance(tx.from)));
        assert!(rwset.writes.contains(&TxAccessPath::NativeNonce(tx.from)));
        assert!(rwset
            .reads
            .contains(&TxAccessPath::NativeBalance(recipient)));
        assert!(rwset
            .writes
            .contains(&TxAccessPath::NativeBalance(recipient)));
    }

    #[test]
    fn erc20_transfer_tracks_token_balances() {
        let token = Address::from([0x44; 20]);
        let recipient = Address::from([0x77; 20]);
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_bytes());
        data.extend_from_slice(&[0u8; 31]);
        data.push(5);

        let tx = signed_tx(Some(token), 0, data);
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.complete);
        assert!(rwset.reads.contains(&TxAccessPath::Erc20Balance {
            token,
            owner: tx.from,
        }));
        assert!(rwset.writes.contains(&TxAccessPath::Erc20Balance {
            token,
            owner: tx.from,
        }));
        assert!(rwset.reads.contains(&TxAccessPath::Erc20Balance {
            token,
            owner: recipient,
        }));
        assert!(rwset.writes.contains(&TxAccessPath::Erc20Balance {
            token,
            owner: recipient,
        }));
    }

    #[test]
    fn erc20_transfer_with_value_tracks_contract_native_balance() {
        let token = Address::from([0x66; 20]);
        let recipient = Address::from([0x77; 20]);
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_bytes());
        data.extend_from_slice(&[0u8; 31]);
        data.push(1);

        let tx = signed_tx(Some(token), 9, data);
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.reads.contains(&TxAccessPath::NativeBalance(token)));
        assert!(rwset.writes.contains(&TxAccessPath::NativeBalance(token)));
    }

    #[test]
    fn validator_registry_tracks_validator_set() {
        let validator = Address::from([0x33; 20]);
        let mut data = Vec::from(encode_add_validator_calldata(&validator));
        let tx = signed_tx(Some(registry_address()), 0, std::mem::take(&mut data));
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.complete);
        assert!(rwset.reads.contains(&TxAccessPath::ValidatorSet));
        assert!(rwset.writes.contains(&TxAccessPath::ValidatorSet));
    }

    #[test]
    fn rotate_key_tracks_sender_pubkey_binding() {
        let calldata = encode_rotate_key_calldata(&[0x99; 32], 1);
        let tx = signed_tx(Some(account_manager_address()), 0, calldata);
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(rwset.complete);
        assert!(rwset.reads.contains(&TxAccessPath::PqPublicKey(tx.from)));
        assert!(rwset.writes.contains(&TxAccessPath::PqPublicKey(tx.from)));
    }

    #[test]
    fn unknown_contract_call_falls_back_to_coarse_contract_storage() {
        let target = Address::from([0x55; 20]);
        let tx = signed_tx(Some(target), 0, vec![0xde, 0xad, 0xbe, 0xef]);
        let rwset = HeuristicRwSetExtractor.extract(&tx);

        assert!(!rwset.complete);
        assert!(rwset
            .reads
            .contains(&TxAccessPath::ContractStorageAny(target)));
        assert!(rwset
            .writes
            .contains(&TxAccessPath::ContractStorageAny(target)));
    }
}
