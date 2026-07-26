mod account;
mod block;
pub mod fee;
mod log;
mod receipt;
mod reward;
mod transaction;
mod witness;

pub use account::Account;
pub use block::{Block, BlockHeader, StrippedBlock};
pub use fee::{
    calc_blob_gas_price, calc_excess_blob_gas, calculate_base_fee, effective_gas_price, miner_tip,
    BLOB_BASE_FEE_UPDATE_FRACTION, BLOB_GAS_PER_BLOB, INITIAL_BASE_FEE, MAX_BLOB_GAS_PER_BLOCK,
    MIN_BLOB_BASE_FEE, TARGET_BLOB_GAS_PER_BLOCK,
};
pub use log::{Log, LogError, MAX_LOG_TOPICS};
pub use receipt::TransactionReceipt;
pub use reward::{StarkRewardParams, SystemTransaction, SystemTxKind};
pub use transaction::{
    AaBundle, AccessListItem, InnerCall, PubkeyMode, SessionAuth, SignedTransaction, Transaction,
    AA_BUNDLE_PRESENCE_FLAG, AA_BUNDLE_TX_TYPE, AA_INNER_CALL_INTRINSIC_GAS,
    BLOB_VERSIONED_HASH_VERSION_KZG, DILITHIUM3_PUBKEY_LEN, MAX_ACCESS_LIST_ENTRIES,
    MAX_ACCESS_LIST_STORAGE_KEYS, MAX_BLOB_HASHES_PER_TX, MAX_INNER_CALLDATA, MAX_INNER_CALLS,
    MAX_PAYMASTER_CONTEXT, MAX_SESSION_PUBKEY, PQTX_BUNDLE_DOMAIN, PQTX_PAYMASTER_DOMAIN,
    PQTX_SESSION_DOMAIN, PQTX_SIGNING_DOMAIN,
};
pub use witness::{StrippedTransaction, TxWitness, WitnessBundle};

pub(crate) fn rlp_payload_end(buf_len: usize, payload_length: usize) -> alloy_rlp::Result<usize> {
    buf_len
        .checked_sub(payload_length)
        .ok_or(alloy_rlp::Error::InputTooShort)
}
