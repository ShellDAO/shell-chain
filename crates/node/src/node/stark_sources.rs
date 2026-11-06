//! Canonical STARK source-entry reconstruction.
//!
//! The shared [`SigBatchEntry::from_signed_transaction`] mapper converts a [`SignedTransaction`] into
//! the corresponding [`SigBatchEntry`] used by the prover and validators.
//! Every site that builds `SigBatchEntry` values – block production, block
//! import, frontier back-log seeding, and amendment validation – **must**
//! call these helpers so the entries are deterministic and identical
//! everywhere.
//!
//! # Mapping rules
//!
//! * `msg_hash` – the 32-byte sender signing hash.
//! * `pk_hash`  – for [`shell_core::PubkeyMode::Embedded`], the first ≤32 bytes of the
//!   inline public key, zero padded; for [`shell_core::PubkeyMode::Reference`],
//!   the full 32-byte sender address.

use super::{Block, SigBatchEntry, SignedTransaction};

/// Derive a [`SigBatchEntry`] from a single signed transaction.
///
/// Delegate to the shared native mapper. All node entry-building sites call
/// this wrapper so block production, import and recovery share that definition.
pub(crate) fn tx_to_sig_batch_entry(tx: &SignedTransaction) -> SigBatchEntry {
    SigBatchEntry::from_signed_transaction(tx)
}

/// Build the ordered [`SigBatchEntry`] list from a slice of transactions.
///
/// Returns an empty `Vec` for 0-tx inputs.  The caller is responsible for
/// deciding whether to dispatch an empty-entry task to the prover; empty
/// tasks must **not** be sent to `prove_sig_batch` – see the backlog and
/// `ProverService` for that guard.
pub(crate) fn entries_from_txs(txs: &[SignedTransaction]) -> Vec<SigBatchEntry> {
    txs.iter().map(tx_to_sig_batch_entry).collect()
}

/// Build the ordered [`SigBatchEntry`] list for all user transactions in a
/// block.
///
/// Equivalent to [`entries_from_txs`]`(&block.transactions)`.
pub(crate) fn block_to_sig_batch_entries(block: &Block) -> Vec<SigBatchEntry> {
    entries_from_txs(&block.transactions)
}

#[cfg(test)]
mod tests {
    use shell_core::Transaction;
    use shell_crypto::{PQSignature, SignatureType};
    use shell_primitives::{Address, Bytes, U256};

    use super::*;

    #[test]
    fn signature_entry_uses_sender_signing_hash_not_transaction_id() {
        let tx = Transaction {
            chain_id: 10,
            nonce: 1,
            to: Some(Address::from([0x11; 20])),
            value: U256::from(2u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 0,
            tx_type: 0,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signed = SignedTransaction::new(
            Address::from([0x22; 32]),
            tx,
            PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 32]),
        );

        let entry = tx_to_sig_batch_entry(&signed);
        assert_eq!(entry.msg_hash, *signed.sender_signing_hash().as_bytes());
        assert_ne!(entry.msg_hash, *signed.hash().as_bytes());
        assert_eq!(entry.pk_hash, [0x22; 32]);

        let mut embedded = signed.clone();
        let mut key = vec![0x33; 1952];
        key[1951] = 0xff;
        embedded.pubkey_mode = shell_core::PubkeyMode::Embedded(key);
        let mapped = tx_to_sig_batch_entry(&embedded);
        assert_eq!(mapped.msg_hash, entry.msg_hash);
        assert_eq!(mapped.pk_hash, [0x33; 32]);
        embedded.pubkey_mode = shell_core::PubkeyMode::Embedded(vec![0xaa; 17]);
        let short = tx_to_sig_batch_entry(&embedded);
        assert_eq!(&short.pk_hash[..17], &[0xaa; 17]);
        assert_eq!(&short.pk_hash[17..], &[0; 15]);
    }
}
