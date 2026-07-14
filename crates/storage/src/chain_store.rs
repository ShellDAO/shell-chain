use std::io::{Read, Seek};
use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_core::{Block, BlockHeader, StrippedBlock, SystemTransaction, TransactionReceipt};
use shell_primitives::{Address, ShellHash, U256};

use crate::{KvStore, StorageError, WriteBatch};

/// Persistent chain configuration (written once at genesis).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_hash: ShellHash,
}

/// Maximum number of guardians per account.
pub const MAX_GUARDIANS: usize = 5;
/// Minimum timelock in blocks between recovery initiation and execution.
pub const MIN_RECOVERY_TIMELOCK: u64 = 100;

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredGuardianAddress {
    Native(Address),
    Legacy([u8; 20]),
}

fn deserialize_guardian_addresses<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let stored = Vec::<StoredGuardianAddress>::deserialize(deserializer)?;
    Ok(stored
        .into_iter()
        .map(|address| match address {
            StoredGuardianAddress::Native(address) => address,
            StoredGuardianAddress::Legacy(address) => Address::from(address),
        })
        .collect())
}

/// Guardian set configuration stored per account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianConfig {
    /// List of guardian addresses (1..=MAX_GUARDIANS).
    #[serde(deserialize_with = "deserialize_guardian_addresses")]
    pub guardians: Vec<Address>,
    /// Required number of guardian votes (1..=guardians.len()).
    pub threshold: u8,
    /// Minimum blocks between threshold-reach and execution.
    pub timelock: u64,
}

/// Active recovery proposal for an account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryProposal {
    /// Proposed new PQ public key bytes.
    pub new_pubkey: Vec<u8>,
    /// Algorithm ID of the new public key.
    pub new_algo: u8,
    /// Guardian addresses that have voted for this exact proposal.
    #[serde(deserialize_with = "deserialize_guardian_addresses")]
    pub votes: Vec<Address>,
    /// Block number after which `executeRecovery` may be called.
    /// Zero means the threshold has not yet been reached.
    pub maturity_block: u64,
}

/// Storage format version bytes for migration compatibility.
mod format_version {
    /// Legacy JSON format.
    pub const JSON: u8 = 0x01;
    /// RLP binary format (current).
    pub const RLP: u8 = 0x02;
}

/// Encode a value to RLP with a version prefix byte.
fn encode_rlp<T: Encodable>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1usize.saturating_add(value.length()));
    buf.push(format_version::RLP);
    value.encode(&mut buf);
    buf
}

/// Encode a slice of items as an RLP list with a version prefix byte.
fn encode_rlp_list<T: Encodable>(items: &[T]) -> Vec<u8> {
    let payload: usize = items.iter().map(|item| item.length()).sum();
    let header = alloy_rlp::Header {
        list: true,
        payload_length: payload,
    };
    let mut buf = Vec::with_capacity(
        1usize
            .saturating_add(header.length())
            .saturating_add(payload),
    );
    buf.push(format_version::RLP);
    header.encode(&mut buf);
    for item in items {
        item.encode(&mut buf);
    }
    buf
}

/// Decode a value from versioned storage format.
///
/// Supports three formats based on the first byte:
/// - `0x02` → RLP (current)
/// - `0x01` → JSON with explicit version prefix
/// - anything else → legacy JSON (no prefix, backward compatibility)
fn decode_versioned<T: Decodable + serde::de::DeserializeOwned>(
    data: &[u8],
) -> Result<T, StorageError> {
    if data.is_empty() {
        return Err(StorageError::Codec("empty data".into()));
    }
    match data.first().copied().unwrap_or(0) {
        format_version::RLP => {
            let rest = data
                .get(1..)
                .unwrap_or_else(|| unreachable!("data checked non-empty above"));
            T::decode(&mut &*rest).map_err(|e| StorageError::Codec(format!("RLP decode: {e}")))
        }
        format_version::JSON => {
            let rest = data
                .get(1..)
                .unwrap_or_else(|| unreachable!("data checked non-empty above"));
            serde_json::from_slice(rest).map_err(|e| StorageError::Codec(e.to_string()))
        }
        // Legacy data without version prefix — fall back to JSON.
        _ => serde_json::from_slice(data).map_err(|e| StorageError::Codec(e.to_string())),
    }
}

/// Key prefixes for chain store data. All keys are prefixed to avoid
/// collisions when sharing a single [`KvStore`] instance.
mod prefix {
    pub const HEADER_BY_HASH: &[u8] = b"h/";
    pub const BODY_BY_HASH: &[u8] = b"b/";
    /// Witness bundle (PQ signatures) key prefix — separate from body.
    pub const WITNESS_BY_HASH: &[u8] = b"w/";
    pub const HASH_BY_NUMBER: &[u8] = b"n/";
    pub const RECEIPTS_BY_HASH: &[u8] = b"r/";
    pub const SYSTEM_TXS_BY_HASH: &[u8] = b"sr/";
    pub const TX_INDEX: &[u8] = b"t/";
    pub const HEAD_BLOCK: &[u8] = b"HEAD";
    pub const CHAIN_CONFIG: &[u8] = b"CFG";
    pub const CODE_BY_HASH: &[u8] = b"c/";
    pub const PUBKEY_BY_ADDR: &[u8] = b"pk/";
    /// Address → tx_hash index: key = "a/" + address(32) + block_number(8) + tx_index(4)
    pub const ADDR_TX_INDEX: &[u8] = b"a/";
    /// Address → tx_hash newest-first index:
    /// key = "ar/" + address(32) + inverted_block_number(8) + tx_index(4)
    pub const ADDR_TX_INDEX_REV: &[u8] = b"ar/";
    /// Guardian config: key = "gc/" + address(32) → JSON-encoded GuardianConfig
    pub const GUARDIAN_CONFIG: &[u8] = b"gc/";
    /// Active recovery proposal: key = "rp/" + address(32) → JSON-encoded RecoveryProposal
    pub const RECOVERY_PROPOSAL: &[u8] = b"rp/";
    pub const TOTAL_TX_COUNT: &[u8] = b"TOTAL_TX_COUNT";
    pub const TOTAL_GAS_USED: &[u8] = b"TOTAL_GAS_USED";
    pub const TOTALS_HEAD: &[u8] = b"TOTALS_HEAD";
    /// Side fork marker: key = "sf/" + block_number(8) + block_hash(32).
    pub const SIDE_FORK_BY_NUMBER: &[u8] = b"sf/";
}

/// Block/receipt/transaction-index storage.
///
/// Provides chain-level data access: store and retrieve blocks by number or
/// hash, store transaction receipts, and maintain a transaction → block index.
pub struct ChainStore<S: KvStore> {
    store: Arc<S>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTxIndexEntry {
    pub block_number: u64,
    pub tx_index: u32,
    pub tx_hash: ShellHash,
    pub cursor: String,
}

/// Local availability class for a block hash.
///
/// Headers, stripped bodies, and PQ witnesses are stored independently so full,
/// light, and STARK-compressed nodes can share one canonical hash space without
/// pretending that all data is locally present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAvailability {
    /// No header or body is stored for this hash.
    Missing,
    /// Header exists, but the stripped body is absent.
    HeaderOnly,
    /// Header and stripped body exist, but no witness bundle is present.
    ///
    /// This can be an empty block, a body back-filled without witnesses, or a
    /// block whose witnesses were replaced by an accepted STARK proof.
    BodyOnly,
    /// Header, stripped body, and witness bundle are present.
    BodyWithWitness,
}

impl<S: KvStore> ChainStore<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn block_number_from_addr_index_key(
        prefix_len: usize,
        key: &[u8],
    ) -> Result<u64, StorageError> {
        if key.len() < prefix_len.saturating_add(12) {
            return Err(StorageError::Codec("invalid addr index key".into()));
        }
        let block_bytes: [u8; 8] = key[prefix_len..prefix_len.saturating_add(8)]
            .try_into()
            .map_err(|_| StorageError::Codec("invalid addr index key".into()))?;
        Ok(u64::from_be_bytes(block_bytes))
    }

    fn addr_index_key_parts(prefix_len: usize, key: &[u8]) -> Result<(u64, u32), StorageError> {
        if key.len() < prefix_len.saturating_add(12) {
            return Err(StorageError::Codec("invalid addr index key".into()));
        }
        let block_number = Self::block_number_from_addr_index_key(prefix_len, key)?;
        let tx_index_bytes: [u8; 4] = key
            [prefix_len.saturating_add(8)..prefix_len.saturating_add(12)]
            .try_into()
            .map_err(|_| StorageError::Codec("invalid addr index key".into()))?;
        Ok((block_number, u32::from_be_bytes(tx_index_bytes)))
    }

    /// Returns a reference to the underlying key-value store.
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Approximate total byte size of all values stored under a given key prefix.
    ///
    /// Scans the prefix and sums `key.len() + value.len()` for each entry.
    /// This is an O(n) operation and should only be called on low-frequency
    /// paths. Backends can stream this calculation to keep peak memory bounded.
    /// Returns `Ok(0)` for empty prefixes; propagates storage errors.
    pub fn approximate_prefix_bytes(&self, prefix: &[u8]) -> Result<u64, StorageError> {
        self.store.prefix_size_bytes(prefix)
    }

    // ── Key helpers ────────────────────────────────────────────

    fn header_key(hash: &ShellHash) -> Vec<u8> {
        [prefix::HEADER_BY_HASH, hash.as_bytes()].concat()
    }

    fn body_key(hash: &ShellHash) -> Vec<u8> {
        [prefix::BODY_BY_HASH, hash.as_bytes()].concat()
    }

    fn witness_key(hash: &ShellHash) -> Vec<u8> {
        [prefix::WITNESS_BY_HASH, hash.as_bytes()].concat()
    }

    fn number_key(number: u64) -> Vec<u8> {
        [prefix::HASH_BY_NUMBER, &number.to_be_bytes()].concat()
    }

    fn receipts_key(block_hash: &ShellHash) -> Vec<u8> {
        [prefix::RECEIPTS_BY_HASH, block_hash.as_bytes()].concat()
    }

    fn system_txs_key(block_hash: &ShellHash) -> Vec<u8> {
        [prefix::SYSTEM_TXS_BY_HASH, block_hash.as_bytes()].concat()
    }

    fn tx_index_key(tx_hash: &ShellHash) -> Vec<u8> {
        [prefix::TX_INDEX, tx_hash.as_bytes()].concat()
    }

    fn side_fork_key(number: u64, hash: &ShellHash) -> Vec<u8> {
        [
            prefix::SIDE_FORK_BY_NUMBER,
            &number.to_be_bytes(),
            hash.as_bytes(),
        ]
        .concat()
    }

    fn side_fork_prefix(number: u64) -> Vec<u8> {
        [prefix::SIDE_FORK_BY_NUMBER, &number.to_be_bytes()].concat()
    }

    /// Key for address→tx index: "a/" + address(32) + block_number(8 BE) + tx_index(4 BE)
    fn addr_tx_key(address: &Address, block_number: u64, tx_index: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 32 + 8 + 4);
        key.extend_from_slice(prefix::ADDR_TX_INDEX);
        key.extend_from_slice(address.as_ref());
        key.extend_from_slice(&block_number.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Key for newest-first address history. Ascending key order yields higher
    /// block numbers first because the block number is bitwise inverted.
    fn addr_tx_rev_key(address: &Address, block_number: u64, tx_index: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + 32 + 8 + 4);
        key.extend_from_slice(prefix::ADDR_TX_INDEX_REV);
        key.extend_from_slice(address.as_ref());
        key.extend_from_slice(&(!block_number).to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Prefix for scanning all txs of a given address.
    fn addr_tx_prefix(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 32);
        key.extend_from_slice(prefix::ADDR_TX_INDEX);
        key.extend_from_slice(address.as_ref());
        key
    }

    fn addr_tx_rev_prefix(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + 32);
        key.extend_from_slice(prefix::ADDR_TX_INDEX_REV);
        key.extend_from_slice(address.as_ref());
        key
    }

    fn addr_tx_rev_cursor_key(address: &Address, cursor: &str) -> Result<Vec<u8>, StorageError> {
        let raw = cursor.strip_prefix("0x").unwrap_or(cursor);
        let bytes = hex::decode(raw).map_err(|e| StorageError::InvalidInput(e.to_string()))?;
        if bytes.len() != 12 {
            return Err(StorageError::InvalidInput(
                "address tx cursor must encode 12 bytes".into(),
            ));
        }
        let mut key = Self::addr_tx_rev_prefix(address);
        key.extend_from_slice(&bytes);
        Ok(key)
    }

    fn addr_tx_cursor_key(address: &Address, cursor: &str) -> Result<Vec<u8>, StorageError> {
        let raw = cursor.strip_prefix("0x").unwrap_or(cursor);
        let bytes = hex::decode(raw).map_err(|e| StorageError::InvalidInput(e.to_string()))?;
        if bytes.len() != 12 {
            return Err(StorageError::InvalidInput(
                "address tx cursor must encode 12 bytes".into(),
            ));
        }
        let mut key = Self::addr_tx_prefix(address);
        key.extend_from_slice(&bytes);
        Ok(key)
    }

    fn addr_tx_cursor_from_key(prefix_len: usize, key: &[u8]) -> Result<String, StorageError> {
        if key.len() < prefix_len.saturating_add(12) {
            return Err(StorageError::Codec("invalid addr index key".into()));
        }
        Ok(format!(
            "0x{}",
            hex::encode(&key[prefix_len..prefix_len + 12])
        ))
    }

    fn addr_tx_rev_cursor_from_key(prefix_len: usize, key: &[u8]) -> Result<String, StorageError> {
        if key.len() < prefix_len.saturating_add(12) {
            return Err(StorageError::Codec("invalid reverse addr index key".into()));
        }
        Ok(format!(
            "0x{}",
            hex::encode(&key[prefix_len..prefix_len + 12])
        ))
    }

    fn block_number_from_addr_rev_index_key(
        prefix_len: usize,
        key: &[u8],
    ) -> Result<u64, StorageError> {
        let inverted = Self::block_number_from_addr_index_key(prefix_len, key)?;
        Ok(!inverted)
    }

    fn code_key(code_hash: &ShellHash) -> Vec<u8> {
        [prefix::CODE_BY_HASH, code_hash.as_bytes()].concat()
    }

    fn pubkey_key(address: &Address) -> Vec<u8> {
        [prefix::PUBKEY_BY_ADDR, address.as_ref()].concat()
    }

    // ── Block operations ───────────────────────────────────────

    /// Store a block — split into a stripped body (`b/<hash>`) and a witness
    /// bundle (`w/<hash>`) — and update the transaction index.
    ///
    /// The stripped body contains the header and transaction payloads (from /
    /// to / value / etc.) but **not** PQ signatures or public keys.  The
    /// witness bundle contains all PQ cryptographic material for the block's
    /// transactions in parallel order.
    ///
    /// Does **not** update HEAD or the canonical number→hash index.
    /// Callers must explicitly call [`set_canonical`] and [`set_head`]
    /// to mark a block as part of the canonical chain.
    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        self.put_block_parts(block, true)
    }

    /// Store a side-fork block without making it canonical and without updating
    /// transaction/address indexes that are reserved for canonical lookup.
    pub fn put_side_fork_block(&self, block: &Block) -> Result<(), StorageError> {
        let block_hash = block.hash();
        self.put_block_parts(block, false)?;
        self.store.put(
            &Self::side_fork_key(block.number(), &block_hash),
            block_hash.as_bytes(),
        )
    }

    /// Return side-fork block hashes recorded at a given block number.
    pub fn get_side_fork_hashes(&self, number: u64) -> Result<Vec<ShellHash>, StorageError> {
        let prefix = Self::side_fork_prefix(number);
        self.store
            .scan_prefix(&prefix)?
            .into_iter()
            .map(|(_, value)| {
                ShellHash::try_from_slice(&value).map_err(|e| StorageError::Codec(e.to_string()))
            })
            .collect()
    }

    fn append_block_parts(batch: &mut WriteBatch, block: &Block, index_transactions: bool) {
        let block_hash = block.hash();

        // Store header (RLP with version prefix)
        let header_bytes = encode_rlp(&block.header);
        batch.put(Self::header_key(&block_hash), header_bytes);

        // Split block into stripped body + witness bundle and store separately.
        let (stripped, bundle) = StrippedBlock::split(block);
        let body_bytes = encode_rlp(&stripped);
        batch.put(Self::body_key(&block_hash), body_bytes);

        // Only persist witness bundle when there are transactions to witness.
        // Empty blocks have no PQ material, so omitting the entry is correct
        // and allows WitnessPruner to distinguish "no bundle" from "pruned".
        if !bundle.is_empty() {
            let mut witness_buf = Vec::new();
            bundle.encode(&mut witness_buf);
            batch.put(Self::witness_key(&block_hash), witness_buf);
        }

        if index_transactions {
            Self::append_transaction_indexes(batch, block, &block_hash);
        }
    }

    fn append_transaction_indexes(batch: &mut WriteBatch, block: &Block, block_hash: &ShellHash) {
        let block_number = block.number();
        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_hash = tx.hash();
            let mut index_value = block_hash.as_bytes().to_vec();
            index_value.extend_from_slice(&(i as u32).to_be_bytes());
            batch.put(Self::tx_index_key(&tx_hash), index_value);

            let idx = i as u32;
            Self::append_addr_tx_index(batch, &tx.sender(), block_number, idx, &tx_hash);
            if let Some(to) = tx.tx.to {
                if to != tx.sender() {
                    Self::append_addr_tx_index(batch, &to, block_number, idx, &tx_hash);
                }
            }
        }
    }

    fn append_addr_tx_index(
        batch: &mut WriteBatch,
        address: &Address,
        block_number: u64,
        tx_index: u32,
        tx_hash: &ShellHash,
    ) {
        let value = tx_hash.as_bytes().to_vec();
        batch.put(
            Self::addr_tx_key(address, block_number, tx_index),
            value.clone(),
        );
        batch.put(
            Self::addr_tx_rev_key(address, block_number, tx_index),
            value,
        );
    }

    fn put_block_parts(&self, block: &Block, index_transactions: bool) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        Self::append_block_parts(&mut batch, block, index_transactions);
        self.store.write_batch(batch)
    }

    /// Add canonical transaction/address lookup indexes for an already stored block.
    ///
    /// This is used when a side-fork block becomes canonical during reorg. The
    /// block header/body records are left untouched.
    pub fn index_block_transactions(&self, block: &Block) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        Self::append_transaction_indexes(&mut batch, block, &block.hash());
        self.append_system_transactions(
            &mut batch,
            &block.hash(),
            block.number(),
            &block.system_transactions,
        )?;
        self.store.write_batch(batch)
    }

    fn delete_addr_tx_index(
        batch: &mut WriteBatch,
        address: &Address,
        block_number: u64,
        tx_index: u32,
    ) {
        batch.delete(Self::addr_tx_key(address, block_number, tx_index));
        batch.delete(Self::addr_tx_rev_key(address, block_number, tx_index));
    }

    fn append_delete_transaction_indexes(
        batch: &mut WriteBatch,
        block: &Block,
        system_txs: &[SystemTransaction],
    ) {
        let block_number = block.number();
        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_hash = tx.hash();
            let tx_index = i as u32;
            batch.delete(Self::tx_index_key(&tx_hash));
            Self::delete_addr_tx_index(batch, &tx.sender(), block_number, tx_index);
            if let Some(to) = tx.tx.to {
                if to != tx.sender() {
                    Self::delete_addr_tx_index(batch, &to, block_number, tx_index);
                }
            }
        }

        for tx in system_txs {
            batch.delete(Self::tx_index_key(&tx.hash()));
            Self::delete_addr_tx_index(batch, &tx.to, block_number, tx.tx_index);
        }
    }

    /// Delete canonical transaction/address lookup indexes for a stored block.
    ///
    /// Block body/header, receipts, and system transaction payloads remain
    /// available by block hash; only canonical lookup indexes are removed.
    pub fn delete_block_transaction_indexes(
        &self,
        block_hash: &ShellHash,
    ) -> Result<(), StorageError> {
        let Some(block) = self.get_block_by_hash(block_hash)? else {
            return Ok(());
        };
        let mut batch = WriteBatch::new();
        let system_txs = self.get_system_transactions(block_hash)?;
        Self::append_delete_transaction_indexes(&mut batch, &block, &system_txs);

        self.store.write_batch(batch)
    }

    /// Atomically switch canonical mappings, transaction indexes, and HEAD to
    /// a prevalidated replacement chain.
    pub fn commit_reorg(
        &self,
        old_chain: &[Block],
        new_chain: &[Block],
        stale_canonical_numbers: &[u64],
        new_head: &ShellHash,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();

        for block in old_chain {
            let block_hash = block.hash();
            let system_txs = self.get_system_transactions(&block_hash)?;
            Self::append_delete_transaction_indexes(&mut batch, block, &system_txs);
        }

        for block in new_chain {
            let block_hash = block.hash();
            Self::append_transaction_indexes(&mut batch, block, &block_hash);
            self.append_system_transactions(
                &mut batch,
                &block_hash,
                block.number(),
                &block.system_transactions,
            )?;
            batch.put(
                Self::number_key(block.number()),
                block_hash.as_bytes().to_vec(),
            );
        }

        for number in stale_canonical_numbers {
            batch.delete(Self::number_key(*number));
        }
        batch.put(prefix::HEAD_BLOCK.to_vec(), new_head.as_bytes().to_vec());

        self.store.write_batch(batch)
    }

    /// Mark a block number → hash mapping in the canonical chain index.
    pub fn set_canonical(&self, number: u64, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.put(&Self::number_key(number), hash.as_bytes())
    }

    /// Remove a canonical chain mapping for the given block number.
    pub fn delete_canonical(&self, number: u64) -> Result<(), StorageError> {
        self.store.delete(&Self::number_key(number))
    }

    /// Delete the stripped block body for the given block hash.
    ///
    /// The block header, witness bundle, and canonical mapping are preserved;
    /// only the stripped transaction payloads are removed.
    pub fn delete_body(&self, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::body_key(hash))
    }

    /// Delete multiple stripped block bodies in a single write batch.
    ///
    /// Headers, witness bundles, and canonical mappings are preserved for each
    /// block; only the stripped transaction payloads are removed.
    pub fn delete_bodies(&self, hashes: &[ShellHash]) -> Result<(), StorageError> {
        if hashes.is_empty() {
            return Ok(());
        }

        let mut batch = WriteBatch::new();
        for hash in hashes {
            batch.delete(Self::body_key(hash));
        }
        self.store.write_batch(batch)
    }

    /// Delete the witness bundle (PQ signatures) for the given block hash.
    ///
    /// Called after a [`ProofAmendment`] (STARK proof) is accepted for the
    /// block, replacing the individual signatures with a single aggregate proof.
    /// The stripped body at `b/<hash>` is preserved so transaction payloads
    /// remain readable.
    pub fn delete_witness_bundle(&self, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::witness_key(hash))
    }

    /// Returns `true` if a witness bundle is stored for the given block hash.
    pub fn has_witness_bundle(&self, hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::witness_key(hash))?.is_some())
    }

    /// Return the stored encoded witness bundle byte length for compression accounting.
    pub fn witness_bundle_size(&self, hash: &ShellHash) -> Result<Option<u64>, StorageError> {
        Ok(self
            .store
            .get(&Self::witness_key(hash))?
            .map(|bytes| bytes.len() as u64))
    }

    /// Returns `true` if a stripped body (`b/<hash>`) is stored for the given block hash.
    ///
    /// Used by the historical body sync to detect pruned blocks.
    pub fn has_body(&self, hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::body_key(hash))?.is_some())
    }

    /// Return the lowest canonical block number whose stripped body is present.
    ///
    /// Body storage can be non-contiguous during historical backfill or after
    /// interrupted pruning. This scans actual body keys instead of assuming the
    /// availability range is monotonic by block number.
    pub fn oldest_canonical_body_number(&self) -> Result<Option<u64>, StorageError> {
        if let Some(genesis_hash) = self.get_block_hash_by_number(0)? {
            if self.has_body(&genesis_hash)? {
                return Ok(Some(0));
            }
        }

        let mut oldest = None;
        for (key, _) in self.store.scan_prefix(prefix::BODY_BY_HASH)? {
            let raw_hash = key
                .strip_prefix(prefix::BODY_BY_HASH)
                .ok_or_else(|| StorageError::Codec("invalid body key prefix".into()))?;
            let hash = ShellHash::try_from_slice(raw_hash)
                .map_err(|e| StorageError::Codec(e.to_string()))?;
            let Some(header) = self.get_header_by_hash(&hash)? else {
                continue;
            };
            if self.get_block_hash_by_number(header.number)? == Some(hash) {
                oldest = Some(oldest.map_or(header.number, |n: u64| n.min(header.number)));
            }
        }

        Ok(oldest)
    }

    /// Classify which block components are available locally for a hash.
    pub fn block_availability(&self, hash: &ShellHash) -> Result<BlockAvailability, StorageError> {
        let has_header = self.store.get(&Self::header_key(hash))?.is_some();
        let has_body = self.store.get(&Self::body_key(hash))?.is_some();
        let has_witness = self.store.get(&Self::witness_key(hash))?.is_some();

        Ok(match (has_header, has_body, has_witness) {
            (false, false, false) => BlockAvailability::Missing,
            (true, false, _) => BlockAvailability::HeaderOnly,
            (_, true, false) => BlockAvailability::BodyOnly,
            (_, true, true) => BlockAvailability::BodyWithWitness,
            (false, false, true) => BlockAvailability::Missing,
        })
    }

    /// Store only the stripped body portion of a block (without witness bundle).
    ///
    /// The stored entry includes the block header and transaction list but omits
    /// PQ signature bundles, making it suitable for back-fill without overwriting
    /// any witness or proof data that may already be present.
    pub fn put_body_only(&self, block: &shell_core::Block) -> Result<(), StorageError> {
        let hash = block.hash();
        let (stripped, _bundle) = shell_core::StrippedBlock::split(block);
        let body_bytes = encode_rlp(&stripped);
        self.store.put(&Self::body_key(&hash), &body_bytes)?;
        Ok(())
    }

    // ── L3: Trie node reference counting ───────────────────────────────────────
    //
    // Key format: `refs/<node_hash>` → little-endian u32 (reference count).
    // The count is incremented each time a trie node is written and decremented
    // when it is overwritten or explicitly evicted.  A node is eligible for
    // physical deletion once its count reaches 0.
    //
    // Reference counts remain available for future fine-grained GC work.
    // Rolling/pruned profiles currently delete historical snapshot nodes via
    // retained-root reachability checks in the node pruning pipeline.

    fn trie_refcount_key(node_hash: &ShellHash) -> Vec<u8> {
        [b"refs/".as_ref(), node_hash.as_bytes()].concat()
    }

    /// Return the current reference count for a trie node (0 if not present).
    pub fn trie_node_refcount(&self, node_hash: &ShellHash) -> Result<u32, StorageError> {
        match self.store.get(&Self::trie_refcount_key(node_hash))? {
            None => Ok(0),
            Some(bytes) if bytes.len() == 4 => {
                Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            Some(bytes) => Err(StorageError::Codec(format!(
                "trie refcount: expected 4 bytes, got {}",
                bytes.len()
            ))),
        }
    }

    /// Increment the reference count for a trie node by 1.
    ///
    /// Called when a trie node is first written to storage.
    pub fn trie_refcount_inc(&self, node_hash: &ShellHash) -> Result<u32, StorageError> {
        let current = self.trie_node_refcount(node_hash)?;
        let next = current.saturating_add(1);
        self.store
            .put(&Self::trie_refcount_key(node_hash), &next.to_le_bytes())?;
        Ok(next)
    }

    /// Decrement the reference count for a trie node by 1.
    ///
    /// Returns the new count.  When the count reaches 0 the key is removed;
    /// the caller may then delete the actual trie node (`t/<hash>`).
    pub fn trie_refcount_dec(&self, node_hash: &ShellHash) -> Result<u32, StorageError> {
        let current = self.trie_node_refcount(node_hash)?;
        if current <= 1 {
            self.store.delete(&Self::trie_refcount_key(node_hash))?;
            Ok(0)
        } else {
            let next = current - 1;
            self.store
                .put(&Self::trie_refcount_key(node_hash), &next.to_le_bytes())?;
            Ok(next)
        }
    }

    /// Set the HEAD pointer to the given block hash.
    pub fn set_head(&self, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.put(prefix::HEAD_BLOCK, hash.as_bytes())
    }

    /// Get a block by its hash.
    ///
    /// Reads the stripped body (`b/<hash>`) and the witness bundle
    /// (`w/<hash>`) and reassembles a full [`Block`].  If the witness bundle
    /// has already been pruned (STARK-compressed block), the returned
    /// transactions carry empty stub signatures but transaction payloads
    /// (from / to / value / etc.) remain accessible.
    pub fn get_block_by_hash(&self, hash: &ShellHash) -> Result<Option<Block>, StorageError> {
        let stripped: StrippedBlock = match self.store.get(&Self::body_key(hash))? {
            Some(data) => decode_versioned(&data)?,
            None => return Ok(None),
        };

        let bundle = match self.store.get(&Self::witness_key(hash))? {
            Some(bytes) => {
                let b = shell_core::WitnessBundle::decode(&mut bytes.as_slice())
                    .map_err(|e| StorageError::Codec(format!("witness decode: {e}")))?;
                Some(b)
            }
            None => None,
        };

        Ok(Some(stripped.into_block(bundle)))
    }

    /// Get a block by its number.
    pub fn get_block_by_number(&self, number: u64) -> Result<Option<Block>, StorageError> {
        let hash_bytes = match self.store.get(&Self::number_key(number))? {
            Some(b) => b,
            None => return Ok(None),
        };
        let hash = ShellHash::try_from_slice(&hash_bytes)
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        self.get_block_by_hash(&hash)
    }

    /// Get only the block hash for a given block number (canonical mapping).
    /// More efficient than `get_block_by_number` when only the hash is needed.
    pub fn get_block_hash_by_number(&self, number: u64) -> Result<Option<ShellHash>, StorageError> {
        match self.store.get(&Self::number_key(number))? {
            Some(hash_bytes) => {
                let hash = ShellHash::try_from_slice(&hash_bytes)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Get a block header by hash.
    pub fn get_header_by_hash(
        &self,
        hash: &ShellHash,
    ) -> Result<Option<BlockHeader>, StorageError> {
        match self.store.get(&Self::header_key(hash))? {
            Some(data) => {
                let header: BlockHeader = decode_versioned(&data)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Get the HEAD (latest) block hash.
    pub fn get_head_hash(&self) -> Result<Option<ShellHash>, StorageError> {
        match self.store.get(prefix::HEAD_BLOCK)? {
            Some(data) => {
                let hash = ShellHash::try_from_slice(&data)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Get the HEAD (latest) block.
    pub fn get_head_block(&self) -> Result<Option<Block>, StorageError> {
        match self.get_head_hash()? {
            Some(hash) => self.get_block_by_hash(&hash),
            None => Ok(None),
        }
    }

    // ── Receipt operations ─────────────────────────────────────

    /// Store receipts for a block.
    pub fn put_receipts(
        &self,
        block_hash: &ShellHash,
        receipts: &[TransactionReceipt],
    ) -> Result<(), StorageError> {
        let data = encode_rlp_list(receipts);
        self.store.put(&Self::receipts_key(block_hash), &data)
    }

    /// Store deterministic system transactions for a canonical block and index
    /// them by tx hash/address so RPC and explorers can treat rewards as
    /// first-class tx-like records.
    pub fn put_system_transactions(
        &self,
        block_hash: &ShellHash,
        block_number: u64,
        system_txs: &[SystemTransaction],
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::new();
        self.append_system_transactions(&mut batch, block_hash, block_number, system_txs)?;
        self.store.write_batch(batch)
    }

    fn append_system_transactions(
        &self,
        batch: &mut WriteBatch,
        block_hash: &ShellHash,
        block_number: u64,
        system_txs: &[SystemTransaction],
    ) -> Result<(), StorageError> {
        let data = serde_json::to_vec(system_txs)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        batch.put(Self::system_txs_key(block_hash), data);

        for tx in system_txs {
            let tx_hash = tx.hash();
            let mut index_value = block_hash.as_bytes().to_vec();
            index_value.extend_from_slice(&tx.tx_index.to_be_bytes());
            batch.put(Self::tx_index_key(&tx_hash), index_value);
            Self::append_addr_tx_index(batch, &tx.to, block_number, tx.tx_index, &tx_hash);
        }

        Ok(())
    }

    /// Atomically commit all canonical block artifacts in one batch.
    ///
    /// This prevents partial storage visibility where only some of the block,
    /// receipt, tx-index, canonical, or HEAD records are written.
    pub fn commit_canonical_block(
        &self,
        block: &Block,
        receipts: Option<&[TransactionReceipt]>,
    ) -> Result<(), StorageError> {
        let block_hash = block.hash();
        let mut batch = WriteBatch::new();

        Self::append_block_parts(&mut batch, block, true);
        if let Some(receipts) = receipts {
            let data = encode_rlp_list(receipts);
            batch.put(Self::receipts_key(&block_hash), data);
        }
        self.append_system_transactions(
            &mut batch,
            &block_hash,
            block.number(),
            &block.system_transactions,
        )?;
        batch.put(
            Self::number_key(block.number()),
            block_hash.as_bytes().to_vec(),
        );
        batch.put(prefix::HEAD_BLOCK.to_vec(), block_hash.as_bytes().to_vec());

        self.store.write_batch(batch)
    }

    /// Atomically commit the genesis block, canonical/head pointers, and chain config.
    ///
    /// This keeps bootstrap metadata aligned with the genesis state root so
    /// startup never observes only part of the genesis chain records.
    pub fn commit_genesis_block(
        &self,
        block: &Block,
        config: &ChainConfig,
    ) -> Result<(), StorageError> {
        let genesis_hash = block.hash();
        let config_bytes =
            serde_json::to_vec(config).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let mut batch = WriteBatch::new();

        Self::append_block_parts(&mut batch, block, true);
        batch.put(
            Self::number_key(block.number()),
            genesis_hash.as_bytes().to_vec(),
        );
        batch.put(
            prefix::HEAD_BLOCK.to_vec(),
            genesis_hash.as_bytes().to_vec(),
        );
        batch.put(prefix::CHAIN_CONFIG.to_vec(), config_bytes);

        self.store.write_batch(batch)
    }

    /// Return system transactions attached to a block hash.
    pub fn get_system_transactions(
        &self,
        block_hash: &ShellHash,
    ) -> Result<Vec<SystemTransaction>, StorageError> {
        match self.store.get(&Self::system_txs_key(block_hash))? {
            Some(data) => {
                serde_json::from_slice(&data).map_err(|e| StorageError::Codec(e.to_string()))
            }
            None => Ok(vec![]),
        }
    }

    /// Return a system transaction by tx hash using the shared tx index.
    pub fn get_system_transaction_by_hash(
        &self,
        tx_hash: &ShellHash,
    ) -> Result<Option<SystemTransaction>, StorageError> {
        let (block_hash, tx_idx) = match self.get_tx_location(tx_hash)? {
            Some(loc) => loc,
            None => return Ok(None),
        };
        Ok(self
            .get_system_transactions(&block_hash)?
            .into_iter()
            .find(|tx| tx.tx_index == tx_idx && tx.hash() == *tx_hash))
    }

    /// Get receipts for a block by block hash.
    pub fn get_receipts(
        &self,
        block_hash: &ShellHash,
    ) -> Result<Option<Vec<TransactionReceipt>>, StorageError> {
        match self.store.get(&Self::receipts_key(block_hash))? {
            Some(data) => {
                let receipts: Vec<TransactionReceipt> = decode_versioned(&data)?;
                Ok(Some(receipts))
            }
            None => Ok(None),
        }
    }

    /// Get all receipts for a block by block number.
    ///
    /// Resolves the canonical block hash for `block_number`, then fetches
    /// the receipts stored under that hash.
    pub fn get_receipts_by_block(
        &self,
        block_number: u64,
    ) -> Result<Vec<TransactionReceipt>, StorageError> {
        let hash_bytes = match self.store.get(&Self::number_key(block_number))? {
            Some(b) => b,
            None => return Ok(vec![]),
        };
        let block_hash = ShellHash::try_from_slice(&hash_bytes)
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        Ok(self.get_receipts(&block_hash)?.unwrap_or_default())
    }

    /// Get a single receipt by transaction hash.
    ///
    /// Uses the transaction index to locate the block, then returns the
    /// matching receipt from that block's receipt list.
    pub fn get_receipt_by_tx_hash(
        &self,
        tx_hash: &ShellHash,
    ) -> Result<Option<TransactionReceipt>, StorageError> {
        let (block_hash, tx_idx) = match self.get_tx_location(tx_hash)? {
            Some(loc) => loc,
            None => return Ok(None),
        };
        let receipts = match self.get_receipts(&block_hash)? {
            Some(r) => r,
            None => return Ok(None),
        };
        Ok(receipts.into_iter().nth(tx_idx as usize))
    }

    // ── Transaction index ──────────────────────────────────────

    /// Look up which block contains a given transaction.
    /// Returns (block_hash, tx_index_in_block).
    pub fn get_tx_location(
        &self,
        tx_hash: &ShellHash,
    ) -> Result<Option<(ShellHash, u32)>, StorageError> {
        match self.store.get(&Self::tx_index_key(tx_hash))? {
            Some(data) => {
                if data.len() != 36 {
                    return Err(StorageError::Codec("invalid tx index entry".into()));
                }
                let block_hash = ShellHash::try_from_slice(
                    data.get(..32)
                        .unwrap_or_else(|| unreachable!("data.len() == 36 checked above")),
                )
                .map_err(|e| StorageError::Codec(e.to_string()))?;
                let tx_idx = u32::from_be_bytes(
                    data.get(32..36)
                        .unwrap_or_else(|| unreachable!("data.len() == 36 checked above"))
                        .try_into()
                        .map_err(|_| StorageError::Codec("invalid tx index byte length".into()))?,
                );
                Ok(Some((block_hash, tx_idx)))
            }
            None => Ok(None),
        }
    }

    /// Get transaction hashes involving a given address, with pagination.
    ///
    /// Scans the address→tx index for `address` within the specified block range.
    /// Returns tx hashes newest-first by block number, paginated by `offset` and `limit`.
    pub fn get_txs_by_address(
        &self,
        address: &Address,
        from_block: u64,
        to_block: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ShellHash>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let prefix = Self::addr_tx_prefix(address);
        let entries = self.store.scan_prefix(&prefix)?;

        let mut matches = Vec::new();
        for (key, value) in entries {
            let Ok((block_number, tx_index)) = Self::addr_index_key_parts(prefix.len(), &key)
            else {
                continue;
            };
            if block_number < from_block || block_number > to_block {
                continue;
            }
            if value.len() == 32 {
                let hash = ShellHash::try_from_slice(&value)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                matches.push((block_number, tx_index, hash));
            }
        }

        matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Ok(matches
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, _, hash)| hash)
            .collect())
    }

    /// Count transactions involving a given address within the specified block range.
    pub fn count_txs_by_address(
        &self,
        address: &Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<u64, StorageError> {
        let prefix = Self::addr_tx_prefix(address);
        let entries = self.store.scan_prefix(&prefix)?;

        let total = entries
            .iter()
            .filter_map(|(key, value)| {
                if value.len() != 32 {
                    return None;
                }
                let block_number =
                    Self::block_number_from_addr_index_key(prefix.len(), key).ok()?;
                (block_number >= from_block && block_number <= to_block).then_some(1u64)
            })
            .sum();

        Ok(total)
    }

    /// Return address transaction index entries using bounded cursor scanning.
    ///
    /// `descending = true` returns newest-first using the reverse index. The
    /// returned `bool` indicates whether more entries are available after the
    /// returned page.
    pub fn get_txs_by_address_cursor(
        &self,
        address: &Address,
        from_block: u64,
        to_block: u64,
        cursor: Option<&str>,
        limit: usize,
        descending: bool,
    ) -> Result<(Vec<AddressTxIndexEntry>, bool), StorageError> {
        if limit == 0 {
            return Ok((Vec::new(), false));
        }

        let prefix = if descending {
            Self::addr_tx_rev_prefix(address)
        } else {
            Self::addr_tx_prefix(address)
        };
        if from_block > to_block {
            return Ok((Vec::new(), false));
        }
        let after_key = match cursor {
            Some(cursor) if descending => {
                let key = Self::addr_tx_rev_cursor_key(address, cursor)?;
                let block_number = Self::block_number_from_addr_rev_index_key(prefix.len(), &key)?;
                if block_number < from_block || block_number > to_block {
                    return Err(StorageError::InvalidInput(
                        "address tx cursor is outside requested block range".into(),
                    ));
                }
                Some(key)
            }
            Some(cursor) => {
                let key = Self::addr_tx_cursor_key(address, cursor)?;
                let block_number = Self::block_number_from_addr_index_key(prefix.len(), &key)?;
                if block_number < from_block || block_number > to_block {
                    return Err(StorageError::InvalidInput(
                        "address tx cursor is outside requested block range".into(),
                    ));
                }
                Some(key)
            }
            None if descending && to_block < u64::MAX => Some(Self::addr_tx_rev_key(
                address,
                to_block.saturating_add(1),
                u32::MAX,
            )),
            None if !descending && from_block > 0 => Some(Self::addr_tx_key(
                address,
                from_block.saturating_sub(1),
                u32::MAX,
            )),
            None => None,
        };

        let mut entries = Vec::new();
        let mut next_after = after_key;
        let mut has_more = false;
        let mut exhausted_range = false;
        while entries.len() <= limit {
            let remaining = limit.saturating_sub(entries.len()).saturating_add(1);
            let page = self.store.scan_prefix_after(
                &prefix,
                next_after.as_deref(),
                remaining.max(1).saturating_mul(2),
            )?;
            if page.is_empty() {
                break;
            }
            for (key, value) in page {
                next_after = Some(key.clone());
                if value.len() != 32 {
                    continue;
                }
                let block_number = if descending {
                    Self::block_number_from_addr_rev_index_key(prefix.len(), &key)?
                } else {
                    Self::block_number_from_addr_index_key(prefix.len(), &key)?
                };
                if descending && block_number < from_block {
                    has_more = false;
                    exhausted_range = true;
                    break;
                }
                if !descending && block_number > to_block {
                    has_more = false;
                    exhausted_range = true;
                    break;
                }
                if block_number < from_block || block_number > to_block {
                    continue;
                }
                let (_, tx_index) = Self::addr_index_key_parts(prefix.len(), &key)?;
                let tx_hash = ShellHash::try_from_slice(&value)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                let cursor = if descending {
                    Self::addr_tx_rev_cursor_from_key(prefix.len(), &key)?
                } else {
                    Self::addr_tx_cursor_from_key(prefix.len(), &key)?
                };
                if entries.len() >= limit {
                    has_more = true;
                    break;
                }
                entries.push(AddressTxIndexEntry {
                    block_number,
                    tx_index,
                    tx_hash,
                    cursor,
                });
            }
            if has_more || entries.len() >= limit {
                break;
            }
            if exhausted_range {
                break;
            }
        }

        Ok((entries, has_more))
    }

    // ── Chain config ───────────────────────────────────────────

    /// Persist the chain configuration (chain_id + genesis hash).
    /// Should be called exactly once after genesis initialization.
    pub fn put_chain_config(&self, config: &ChainConfig) -> Result<(), StorageError> {
        let data =
            serde_json::to_vec(config).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.store.put(prefix::CHAIN_CONFIG, &data)
    }

    /// Retrieve the persisted chain configuration.
    pub fn get_chain_config(&self) -> Result<Option<ChainConfig>, StorageError> {
        match self.store.get(prefix::CHAIN_CONFIG)? {
            Some(data) => {
                let config: ChainConfig = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    // ── Contract code storage ──────────────────────────────────

    /// Store contract bytecode keyed by its hash.
    ///
    /// The caller is responsible for computing `keccak256(code)` and passing
    /// it as `code_hash`. The code can later be retrieved by hash via
    /// [`get_code`].
    pub fn put_code(&self, code_hash: &ShellHash, code: &[u8]) -> Result<(), StorageError> {
        self.store.put(&Self::code_key(code_hash), code)
    }

    /// Retrieve contract bytecode by its hash.
    pub fn get_code(&self, code_hash: &ShellHash) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(&Self::code_key(code_hash))
    }

    // ── PQ public key registry ─────────────────────────────────

    /// Register a PQ public key for an address.
    ///
    /// Called on the first transaction from this address (the Hybrid
    /// registration model). Subsequent transactions skip pubkey transfer
    /// and read from this registry.
    pub fn put_pubkey(&self, address: &Address, pubkey: &[u8]) -> Result<(), StorageError> {
        self.store.put(&Self::pubkey_key(address), pubkey)
    }

    /// Retrieve the registered PQ public key for an address.
    pub fn get_pubkey(&self, address: &Address) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(&Self::pubkey_key(address))
    }

    // ── Guardian recovery storage ──────────────────────────────

    /// Persist the guardian configuration for an account.
    pub fn put_guardian_config(
        &self,
        account: &Address,
        config: &GuardianConfig,
    ) -> Result<(), StorageError> {
        let encoded =
            serde_json::to_vec(config).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.store
            .put(&Self::guardian_config_key(account), &encoded)
    }

    /// Retrieve the guardian configuration for an account.
    pub fn get_guardian_config(
        &self,
        account: &Address,
    ) -> Result<Option<GuardianConfig>, StorageError> {
        match self.store.get(&Self::guardian_config_key(account))? {
            None => Ok(None),
            Some(bytes) => {
                let config = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(config))
            }
        }
    }

    /// Persist the active recovery proposal for an account.
    pub fn put_recovery_proposal(
        &self,
        account: &Address,
        proposal: &RecoveryProposal,
    ) -> Result<(), StorageError> {
        let encoded =
            serde_json::to_vec(proposal).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.store
            .put(&Self::recovery_proposal_key(account), &encoded)
    }

    /// Retrieve the active recovery proposal for an account.
    pub fn get_recovery_proposal(
        &self,
        account: &Address,
    ) -> Result<Option<RecoveryProposal>, StorageError> {
        match self.store.get(&Self::recovery_proposal_key(account))? {
            None => Ok(None),
            Some(bytes) => {
                let proposal = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                Ok(Some(proposal))
            }
        }
    }

    /// Remove the active recovery proposal for an account.
    pub fn delete_recovery_proposal(&self, account: &Address) -> Result<(), StorageError> {
        self.store.delete(&Self::recovery_proposal_key(account))
    }

    fn guardian_config_key(account: &Address) -> Vec<u8> {
        [prefix::GUARDIAN_CONFIG, account.as_ref()].concat()
    }

    fn recovery_proposal_key(account: &Address) -> Vec<u8> {
        [prefix::RECOVERY_PROPOSAL, account.as_ref()].concat()
    }

    // ── Snapshot import/export ─────────────────────────────────

    /// Export all chain data to a snapshot writer.
    ///
    /// Iterates all key-value entries in the underlying store and writes them
    /// to the snapshot. This is a logical export suitable for any KvStore
    /// implementation.
    pub fn export_snapshot<W: std::io::Write>(
        &self,
        metadata: crate::SnapshotMetadata,
        writer: W,
    ) -> Result<crate::SnapshotMetadata, StorageError> {
        let mut snap_writer = crate::SnapshotWriter::new(writer, metadata)?;
        for (key, value) in self.store.scan_all()? {
            snap_writer.write_entry(&key, &value)?;
        }
        snap_writer.finalize()
    }

    /// Import chain data from a snapshot reader.
    ///
    /// Validates the snapshot metadata against the current chain configuration,
    /// then restores all key-value entries from the snapshot.
    pub fn import_snapshot<R: Read + Seek>(
        &self,
        reader: R,
        expected_chain_id: u64,
        expected_genesis_hash: &ShellHash,
    ) -> Result<crate::SnapshotMetadata, StorageError> {
        let mut snap_reader = crate::SnapshotReader::new(reader)?;
        let metadata = snap_reader.metadata().clone();

        // Validate compatibility
        metadata.validate_compatibility(expected_chain_id, expected_genesis_hash)?;

        // Validate the canonical head and its state root before writing any
        // snapshot entries. This prevents a semantic import failure from
        // leaving partially restored keys in the destination store.
        let mut head_hash = None;
        while let Some(entry) = snap_reader.next_entry()? {
            if entry.key == prefix::HEAD_BLOCK {
                if entry.value.len() != 32 {
                    return Err(StorageError::State(
                        "snapshot HEAD value has invalid length".into(),
                    ));
                }
                if head_hash.is_some() {
                    return Err(StorageError::State(
                        "snapshot contains multiple HEAD entries".into(),
                    ));
                }
                head_hash = Some(ShellHash::from_slice(&entry.value));
            }
        }

        // Resolve the head header in a separate pass so snapshot record order
        // cannot affect validation.
        let mut head_header = None;
        if let Some(head_hash) = head_hash {
            let head_header_key = Self::header_key(&head_hash);
            snap_reader.rewind()?;
            while let Some(entry) = snap_reader.next_entry()? {
                if entry.key == head_header_key {
                    if head_header.is_some() {
                        return Err(StorageError::State(
                            "snapshot contains multiple canonical head headers".into(),
                        ));
                    }
                    head_header = Some(decode_versioned::<BlockHeader>(&entry.value)?);
                }
            }
        }

        if let Some(head) = head_header {
            if head.number != metadata.block_number
                || head.hash() != metadata.block_hash
                || head.state_root != metadata.state_root
            {
                return Err(StorageError::State(
                    "snapshot head metadata does not match the stored head header".into(),
                ));
            }
        } else if metadata.block_number != 0 {
            return Err(StorageError::State(
                "snapshot is missing the canonical head header".into(),
            ));
        }

        snap_reader.rewind()?;

        // Import all entries
        let mut batch = crate::WriteBatch::new();
        let mut pending_head = None;
        while let Some(entry) = snap_reader.next_entry()? {
            if entry.key == prefix::HEAD_BLOCK {
                pending_head = Some(entry.value);
                continue;
            }
            batch.put(entry.key, entry.value);

            // Flush in batches of 10000 to avoid excessive memory use
            if batch.len() >= 10_000 {
                self.store.write_batch(batch)?;
                batch = crate::WriteBatch::new();
            }
        }

        // Flush remaining
        if !batch.is_empty() {
            self.store.write_batch(batch)?;
        }

        // Publish HEAD only after every other record is durable. A failed
        // streaming import must not make a partial snapshot appear complete.
        if let Some(head) = pending_head {
            let mut head_batch = crate::WriteBatch::new();
            head_batch.put(prefix::HEAD_BLOCK.to_vec(), head);
            self.store.write_batch(head_batch)?;
        }

        Ok(metadata)
    }

    /// Store the finalized block number.
    pub fn set_finalized_number(&self, number: u64) -> Result<(), StorageError> {
        self.store.put(b"FINALIZED", &number.to_be_bytes())
    }

    /// Get the finalized block number.
    pub fn get_finalized_number(&self) -> Result<Option<u64>, StorageError> {
        match self.store.get(b"FINALIZED")? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Codec("invalid finalized number encoding".into()))?;
                let n = u64::from_be_bytes(arr);
                Ok(Some(n))
            }
            Some(_) => Err(StorageError::Codec(
                "invalid finalized number encoding".into(),
            )),
            None => Ok(None),
        }
    }

    /// Store a commit certificate sidecar for a finalized block.
    ///
    /// The certificate encodes the quorum signatures that finalized the block.
    /// Stored separately from the block header to preserve hash compatibility.
    /// Key format: `CERT<32-byte-block-hash>`.
    pub fn set_commit_certificate(
        &self,
        block_hash: &ShellHash,
        cert: &[u8],
    ) -> Result<(), StorageError> {
        let mut key = Vec::with_capacity(4 + 32);
        key.extend_from_slice(b"CERT");
        key.extend_from_slice(block_hash.as_bytes());
        self.store.put(&key, cert)
    }

    /// Retrieve the commit certificate for a finalized block, if any.
    pub fn get_commit_certificate(
        &self,
        block_hash: &ShellHash,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut key = Vec::with_capacity(4 + 32);
        key.extend_from_slice(b"CERT");
        key.extend_from_slice(block_hash.as_bytes());
        self.store.get(&key)
    }

    /// Store the total transaction count across all canonical blocks.
    pub fn set_total_tx_count(&self, count: u64) -> Result<(), StorageError> {
        self.store.put(prefix::TOTAL_TX_COUNT, &count.to_be_bytes())
    }

    /// Get the total transaction count across all canonical blocks, if stored.
    pub fn get_total_tx_count_opt(&self) -> Result<Option<u64>, StorageError> {
        match self.store.get(prefix::TOTAL_TX_COUNT)? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Codec("invalid tx count encoding".into()))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            Some(_) => Err(StorageError::Codec("invalid tx count encoding".into())),
            None => Ok(None),
        }
    }

    /// Get the total transaction count across all canonical blocks.
    pub fn get_total_tx_count(&self) -> Result<u64, StorageError> {
        Ok(self.get_total_tx_count_opt()?.unwrap_or(0))
    }

    /// Increment the total transaction count by `delta` and persist.
    pub fn increment_tx_count(&self, delta: u64) -> Result<u64, StorageError> {
        let current = self.get_total_tx_count()?;
        let new_count = current.saturating_add(delta);
        self.set_total_tx_count(new_count)?;
        Ok(new_count)
    }

    /// Store cumulative gas used across all canonical blocks.
    pub fn set_total_gas_used(&self, total: U256) -> Result<(), StorageError> {
        self.store
            .put(prefix::TOTAL_GAS_USED, &total.to_be_bytes::<32>())
    }

    /// Get cumulative gas used across all canonical blocks, if stored.
    pub fn get_total_gas_used_opt(&self) -> Result<Option<U256>, StorageError> {
        match self.store.get(prefix::TOTAL_GAS_USED)? {
            Some(bytes) if bytes.len() == 32 => Ok(Some(U256::from_be_slice(&bytes))),
            Some(_) => Err(StorageError::Codec("invalid total gas encoding".into())),
            None => Ok(None),
        }
    }

    /// Get cumulative gas used across all canonical blocks.
    pub fn get_total_gas_used(&self) -> Result<U256, StorageError> {
        Ok(self.get_total_gas_used_opt()?.unwrap_or(U256::ZERO))
    }

    /// Store the canonical head covered by the persisted aggregate counters.
    pub fn set_chain_totals_head(&self, head_number: u64) -> Result<(), StorageError> {
        self.store
            .put(prefix::TOTALS_HEAD, &head_number.to_be_bytes())
    }

    /// Get the canonical head covered by the persisted aggregate counters.
    pub fn get_chain_totals_head(&self) -> Result<Option<u64>, StorageError> {
        match self.store.get(prefix::TOTALS_HEAD)? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Codec("invalid totals head encoding".into()))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            Some(_) => Err(StorageError::Codec("invalid totals head encoding".into())),
            None => Ok(None),
        }
    }

    /// Rebuild canonical aggregate counters by scanning block 0 through `head_number`.
    pub fn rebuild_chain_totals(&self, head_number: u64) -> Result<(u64, U256), StorageError> {
        let fallback_tx_count = self.get_total_tx_count_opt()?;
        let mut scanned_txs = Some(0u64);
        let mut scanned_system_txs = 0u64;
        let mut total_gas = U256::ZERO;
        for number in 0..=head_number {
            let hash = self.get_block_hash_by_number(number)?.ok_or_else(|| {
                StorageError::Codec(format!(
                    "missing canonical block #{number} while rebuilding chain totals"
                ))
            })?;
            let header = self.get_header_by_hash(&hash)?.ok_or_else(|| {
                StorageError::Codec(format!(
                    "missing header for canonical block #{number} while rebuilding chain totals"
                ))
            })?;
            total_gas = total_gas.saturating_add(U256::from(header.gas_used));

            if let Some(total) = scanned_txs.as_mut() {
                if let Some(block) = self.get_block_by_hash(&hash)? {
                    *total = total.saturating_add(block.transactions.len() as u64);
                    scanned_system_txs = scanned_system_txs
                        .saturating_add(self.get_system_transactions(&hash)?.len() as u64);
                } else {
                    scanned_txs = None;
                }
            }
        }
        let total_txs = match scanned_txs {
            Some(total) => total.saturating_add(scanned_system_txs),
            None => fallback_tx_count.ok_or_else(|| {
                StorageError::Codec(
                    "cannot rebuild transaction total because canonical block bodies are pruned"
                        .into(),
                )
            })?,
        };
        self.set_total_tx_count(total_txs)?;
        self.set_total_gas_used(total_gas)?;
        self.set_chain_totals_head(head_number)?;
        Ok((total_txs, total_gas))
    }

    /// Return canonical aggregate counters, rebuilding once if legacy counters are missing or stale.
    pub fn get_chain_totals(&self, head_number: u64) -> Result<(u64, U256), StorageError> {
        let totals_head = self.get_chain_totals_head()?;
        let tx_count = self.get_total_tx_count_opt()?;
        let gas_used = self.get_total_gas_used_opt()?;
        match (totals_head, tx_count, gas_used) {
            (Some(marked_head), Some(txs), Some(gas)) if marked_head == head_number => {
                Ok((txs, gas))
            }
            _ => self.rebuild_chain_totals(head_number),
        }
    }

    /// Add a newly canonical block to aggregate counters, rebuilding if the previous state is stale.
    pub fn add_canonical_block_to_totals(
        &self,
        block_number: u64,
        tx_count: u64,
        gas_used: u64,
    ) -> Result<(u64, U256), StorageError> {
        let expected_previous = block_number.checked_sub(1);
        if self.get_chain_totals_head()? == expected_previous
            && self.get_total_tx_count_opt()?.is_some()
            && self.get_total_gas_used_opt()?.is_some()
        {
            let total_txs = self.increment_tx_count(tx_count)?;
            let total_gas = self
                .get_total_gas_used()?
                .saturating_add(U256::from(gas_used));
            self.set_total_gas_used(total_gas)?;
            self.set_chain_totals_head(block_number)?;
            Ok((total_txs, total_gas))
        } else {
            self.rebuild_chain_totals(block_number)
        }
    }
}

// ── WitnessStore ──────────────────────────────────────────────────────────────

/// Storage for [`WitnessBundle`]s in the dedicated `witness` column family.
///
/// A `WitnessBundle` contains all PQ signatures for a block's transactions
/// (Phase B witness separation). Stored separately from the block body to
/// allow independent pruning after finality (Phase D1).
///
/// Key format: block hash (32 bytes) → RLP-encoded `WitnessBundle`.
pub struct WitnessStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> WitnessStore<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn key(block_hash: &ShellHash) -> Vec<u8> {
        [b"w/".as_ref(), block_hash.as_bytes()].concat()
    }

    /// Store a [`WitnessBundle`] for a block identified by its hash.
    pub fn put_bundle(
        &self,
        block_hash: &ShellHash,
        bundle: &shell_core::WitnessBundle,
    ) -> Result<(), StorageError> {
        let mut buf = Vec::new();
        bundle.encode(&mut buf);
        self.store.put(&Self::key(block_hash), &buf)
    }

    /// Retrieve the [`WitnessBundle`] for a block, if stored.
    pub fn get_bundle(
        &self,
        block_hash: &ShellHash,
    ) -> Result<Option<shell_core::WitnessBundle>, StorageError> {
        match self.store.get(&Self::key(block_hash))? {
            None => Ok(None),
            Some(bytes) => {
                let bundle = shell_core::WitnessBundle::decode(&mut bytes.as_slice())
                    .map_err(|e| StorageError::Codec(format!("witness decode: {e}")))?;
                Ok(Some(bundle))
            }
        }
    }

    /// Delete the [`WitnessBundle`] for a block (witness pruning, Phase D1).
    pub fn delete_bundle(&self, block_hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::key(block_hash))
    }

    /// Delete multiple [`WitnessBundle`]s in a single write batch.
    pub fn delete_bundles(&self, block_hashes: &[ShellHash]) -> Result<(), StorageError> {
        if block_hashes.is_empty() {
            return Ok(());
        }

        let mut batch = WriteBatch::new();
        for block_hash in block_hashes {
            batch.delete(Self::key(block_hash));
        }
        self.store.write_batch(batch)
    }

    /// Returns `true` if a witness bundle exists for the given block hash.
    pub fn has_bundle(&self, block_hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::key(block_hash))?.is_some())
    }

    /// Return the encoded witness bundle byte length for compression accounting.
    pub fn bundle_size(&self, block_hash: &ShellHash) -> Result<Option<u64>, StorageError> {
        Ok(self
            .store
            .get(&Self::key(block_hash))?
            .map(|bytes| bytes.len() as u64))
    }
}

// ── ProofAmendmentStore ───────────────────────────────────────────────────────

/// Storage for async STARK [`ProofAmendment`]s.
///
/// When a block is sealed without an inline proof (async proving), a
/// [`ProofAmendment`] is generated later (possibly by a standalone Prover
/// node) and gossiped via P2P.  Nodes store amendments here, keyed by the
/// block hash, so that block import can verify the proof without storing the
/// full PQ signatures permanently.
///
/// Key format: `pa/` + block_hash (32 bytes) → JSON-encoded `ProofAmendment`.
///
/// Note: This store holds raw bytes so it does not take a dependency on the
/// `shell-stark-prover` crate.  Callers in the `shell-node` crate (which
/// already depends on the prover) perform serialization/deserialization.
pub struct ProofAmendmentStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> Clone for ProofAmendmentStore<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

/// Key prefix for proof amendments (`pa/`).
const PA_PREFIX: &[u8] = b"pa/";

impl<S: KvStore> ProofAmendmentStore<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn key(block_hash: &ShellHash) -> Vec<u8> {
        let mut k = PA_PREFIX.to_vec();
        k.extend_from_slice(block_hash.as_bytes());
        k
    }

    /// Store a serialized `ProofAmendment` for a block.
    ///
    /// `bytes` should be the JSON or other canonical encoding of the
    /// amendment produced by the prover.
    pub fn put_amendment(&self, block_hash: &ShellHash, bytes: &[u8]) -> Result<(), StorageError> {
        self.store.put(&Self::key(block_hash), bytes)
    }

    /// Retrieve the raw bytes of the `ProofAmendment` for a block, if present.
    pub fn get_amendment(&self, block_hash: &ShellHash) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(&Self::key(block_hash))
    }

    /// Returns `true` if a proof amendment is stored for the given block hash.
    pub fn has_amendment(&self, block_hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::key(block_hash))?.is_some())
    }

    /// Delete the proof amendment for a block (e.g., after sig stripping).
    pub fn delete_amendment(&self, block_hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::key(block_hash))
    }
}

// ── SettledSourceIndex ─────────────────────────────────────────────────────

/// Persistent index of settled (layer, source_hash) pairs.
///
/// Keyed as `ss/{layer_be4}{source_hash_32bytes}` → `[1u8]`.
/// Provides O(1) containment check and O(prefix-scan) enumeration — much
/// faster than rebuilding by scanning all block settlement transactions.
pub struct SettledSourceIndex<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> Clone for SettledSourceIndex<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

/// Key prefix for the settled-source index (`ss/`).
const SS_PREFIX: &[u8] = b"ss/";

impl<S: KvStore> SettledSourceIndex<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn key(layer: u32, hash: &ShellHash) -> Vec<u8> {
        let mut k = SS_PREFIX.to_vec();
        k.extend_from_slice(&layer.to_be_bytes());
        k.extend_from_slice(hash.as_bytes());
        k
    }

    /// Record that `(layer, hash)` has been settled.
    pub fn put(&self, layer: u32, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.put(&Self::key(layer, hash), &[1u8])
    }

    /// Remove the settled record for `(layer, hash)`. Used by reconcile to
    /// purge stale entries that are no longer backed by canonical StarkReward txs.
    pub fn delete(&self, layer: u32, hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::key(layer, hash))
    }

    /// Returns true if `(layer, hash)` is recorded as settled.
    pub fn has(&self, layer: u32, hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::key(layer, hash))?.is_some())
    }

    /// Return all (layer, hash) entries. Used at startup to fast-load the
    /// in-memory `settled_stark_sources` set without a full chain scan.
    pub fn all_entries(&self) -> Result<Vec<(u32, ShellHash)>, StorageError> {
        let raw = self.store.scan_prefix(SS_PREFIX)?;
        let mut out = Vec::with_capacity(raw.len());
        for (key, _) in raw {
            // key = b"ss/" (3) + layer_be4 (4) + hash (32)
            if key.len() != SS_PREFIX.len() + 4 + 32 {
                continue;
            }
            let layer = u32::from_be_bytes(
                key[SS_PREFIX.len()..SS_PREFIX.len() + 4]
                    .try_into()
                    .unwrap(),
            );
            let hash_bytes: [u8; 32] = key[SS_PREFIX.len() + 4..].try_into().unwrap();
            out.push((layer, ShellHash::from(hash_bytes)));
        }
        Ok(out)
    }

    /// Return true if any entry exists (used to detect whether the index is
    /// populated or whether a full chain-rebuild is needed).
    pub fn is_populated(&self) -> Result<bool, StorageError> {
        Ok(!self.store.scan_prefix(SS_PREFIX)?.is_empty())
    }
}

// ── L2InputIndex ───────────────────────────────────────────────────────────

/// Durable index of canonical L1 STARK amendments available as inputs for L2
/// recursive aggregation.
///
/// Keyed as `l2i/` + final_source_hash (32 bytes) → `[1u8]`.
///
/// **Only** populated from canonical [`StarkReward`] system transactions; gossiped
/// or locally-queued amendments are never written here.  This invariant ensures
/// the L2 aggregation pipeline only sees cryptographically committed L1 inputs.
///
/// The amendment payload itself is retrieved via [`ProofAmendmentStore`] using
/// the same hash as the key.
///
/// [`StarkReward`]: shell_core::SystemTxKind::StarkReward
pub struct L2InputIndex<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> Clone for L2InputIndex<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

/// Key prefix for the L2 input index (`l2i/`).
const L2I_PREFIX: &[u8] = b"l2i/";

impl<S: KvStore> L2InputIndex<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn key(final_hash: &ShellHash) -> Vec<u8> {
        let mut k = L2I_PREFIX.to_vec();
        k.extend_from_slice(final_hash.as_bytes());
        k
    }

    /// Record that the L1 amendment ending at `final_hash` is a canonical L2 input.
    pub fn put(&self, final_hash: &ShellHash) -> Result<(), StorageError> {
        self.store.put(&Self::key(final_hash), &[1u8])
    }

    /// Remove the L2 input entry for `final_hash`.  Used during reconcile to
    /// purge entries whose backing L1 amendment is no longer on the canonical chain.
    pub fn delete(&self, final_hash: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::key(final_hash))
    }

    /// Returns `true` if `final_hash` is recorded as a canonical L2 input.
    pub fn has(&self, final_hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::key(final_hash))?.is_some())
    }

    /// Return all recorded final source hashes.  Used at startup to reconstruct
    /// the in-memory L2 input set and by the scheduler to enumerate available inputs.
    pub fn all_hashes(&self) -> Result<Vec<ShellHash>, StorageError> {
        let raw = self.store.scan_prefix(L2I_PREFIX)?;
        let mut out = Vec::with_capacity(raw.len());
        for (key, _) in raw {
            // key = b"l2i/" (4) + hash (32)
            if key.len() != L2I_PREFIX.len() + 32 {
                continue;
            }
            let hash_bytes: [u8; 32] = key[L2I_PREFIX.len()..].try_into().unwrap();
            out.push(ShellHash::from(hash_bytes));
        }
        Ok(out)
    }

    /// Returns true if any entry exists.
    pub fn is_populated(&self) -> Result<bool, StorageError> {
        Ok(!self.store.scan_prefix(L2I_PREFIX)?.is_empty())
    }
}

// ── L2AggregationJob / L2JobStore ─────────────────────────────────────────

/// Status of a durable L2 aggregation proving job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L2JobStatus {
    /// Waiting for more canonical L1 proofs to fill the input window.
    PendingInputs,
    /// All inputs are present; ready to be submitted to the recursive prover.
    Ready,
    /// The recursive prover is currently working on this job.
    Proving,
    /// Recursive proof is generated and stored locally.
    ProofStored,
    /// Proof is queued for on-chain settlement.
    QueuedForSettlement,
    /// Settlement tx has been included in a canonical block.
    Settled,
    /// Proving or settlement failed transiently; eligible for retry.
    FailedRetryable,
    /// Permanently failed; will not be retried without manual intervention.
    FailedPermanent,
}

/// A durable record of one L2 recursive aggregation job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2AggregationJob {
    /// Deterministic ID: blake3 of sorted `l1_source_hashes`.
    pub id: ShellHash,
    pub status: L2JobStatus,
    /// Settled L1 amendment hashes that form the input to this L2 proof.
    pub l1_source_hashes: Vec<ShellHash>,
    /// First canonical block covered by the earliest L1 input.
    pub start_block: u64,
    /// Last canonical block covered by the latest L1 input.
    pub end_block: u64,
    /// `batch_root_bytes` of each contributing L1 proof, in order.
    pub l1_batch_roots: Vec<[u8; 32]>,
    /// Aggregate root produced by the recursive proof (set after ProofStored).
    pub aggregate_root: Option<[u8; 32]>,
    /// Number of times proving has been attempted.
    pub retry_count: u32,
    /// Human-readable reason for the last failure (if any).
    pub last_error: Option<String>,
    /// Block number at which this job was first created.
    pub created_at_block: u64,
    /// Block number at which the status was last updated.
    pub updated_at_block: u64,
}

impl L2AggregationJob {
    /// Compute the deterministic job ID from a set of L1 source hashes.
    ///
    /// Sorts the hashes lexicographically before hashing so the ID is
    /// independent of insertion order.
    pub fn compute_id(l1_source_hashes: &[ShellHash]) -> ShellHash {
        let mut sorted: Vec<&[u8]> = l1_source_hashes
            .iter()
            .map(|h| h.as_bytes().as_slice())
            .collect();
        sorted.sort_unstable();
        let mut buf = Vec::with_capacity(sorted.len() * 32);
        for h in sorted {
            buf.extend_from_slice(h);
        }
        shell_primitives::blake3_hash(&buf)
    }
}

const L2J_PREFIX: &[u8] = b"l2j/";

/// Durable key-value store for [`L2AggregationJob`] records.
///
/// Key: `l2j/` (4 bytes) + job `id` (32 bytes) → JSON-encoded job.
pub struct L2JobStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> Clone for L2JobStore<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
        }
    }
}

impl<S: KvStore> L2JobStore<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    fn key(id: &ShellHash) -> Vec<u8> {
        let mut k = Vec::with_capacity(L2J_PREFIX.len() + 32);
        k.extend_from_slice(L2J_PREFIX);
        k.extend_from_slice(id.as_bytes());
        k
    }

    /// Persist (insert or overwrite) a job.
    pub fn put(&self, job: &L2AggregationJob) -> Result<(), StorageError> {
        let value =
            serde_json::to_vec(job).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.store.put(&Self::key(&job.id), &value)
    }

    /// Retrieve a job by its deterministic ID, or `None` if not present.
    pub fn get(&self, id: &ShellHash) -> Result<Option<L2AggregationJob>, StorageError> {
        match self.store.get(&Self::key(id))? {
            None => Ok(None),
            Some(bytes) => {
                let job: L2AggregationJob = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(job))
            }
        }
    }

    /// Remove a job.
    pub fn delete(&self, id: &ShellHash) -> Result<(), StorageError> {
        self.store.delete(&Self::key(id))
    }

    /// Return every stored job.
    pub fn all_jobs(&self) -> Result<Vec<L2AggregationJob>, StorageError> {
        let mut out = Vec::new();
        for (_k, v) in self.store.scan_prefix(L2J_PREFIX)? {
            let job: L2AggregationJob = serde_json::from_slice(&v)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            out.push(job);
        }
        Ok(out)
    }

    /// Return all jobs whose status matches `filter`.
    pub fn jobs_with_status(
        &self,
        filter: L2JobStatus,
    ) -> Result<Vec<L2AggregationJob>, StorageError> {
        Ok(self
            .all_jobs()?
            .into_iter()
            .filter(|j| j.status == filter)
            .collect())
    }

    /// Update the status (and optionally the error string) of an existing job
    /// without loading the full job from scratch.
    pub fn update_status(
        &self,
        id: &ShellHash,
        status: L2JobStatus,
        updated_at_block: u64,
        error: Option<String>,
    ) -> Result<(), StorageError> {
        if let Some(mut job) = self.get(id)? {
            job.status = status;
            job.updated_at_block = updated_at_block;
            job.last_error = error;
            self.put(&job)?;
        }
        Ok(())
    }

    /// Returns `true` if any job exists in the store.
    pub fn is_populated(&self) -> Result<bool, StorageError> {
        Ok(!self.store.scan_prefix(L2J_PREFIX)?.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryDb, WriteBatch};
    use shell_primitives::{Address, Bytes};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct FailingBatchStore {
        inner: MemoryDb,
        fail_next_batch: AtomicBool,
        fail_batch_after: AtomicUsize,
        batch_calls: AtomicUsize,
        fail_put_after: AtomicUsize,
        put_calls: AtomicUsize,
    }

    impl FailingBatchStore {
        fn new() -> Self {
            Self {
                inner: MemoryDb::new(),
                fail_next_batch: AtomicBool::new(false),
                fail_batch_after: AtomicUsize::new(usize::MAX),
                batch_calls: AtomicUsize::new(0),
                fail_put_after: AtomicUsize::new(usize::MAX),
                put_calls: AtomicUsize::new(0),
            }
        }

        fn fail_next_batch(&self) {
            self.fail_next_batch.store(true, Ordering::SeqCst);
        }

        fn fail_batch_after(&self, batch_count: usize) {
            self.fail_batch_after.store(batch_count, Ordering::SeqCst);
            self.batch_calls.store(0, Ordering::SeqCst);
        }

        fn fail_put_after(&self, put_count: usize) {
            self.fail_put_after.store(put_count, Ordering::SeqCst);
            self.put_calls.store(0, Ordering::SeqCst);
        }
    }

    impl KvStore for FailingBatchStore {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            let call_num = self.put_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_num >= self.fail_put_after.load(Ordering::SeqCst) {
                return Err(StorageError::Database("injected put failure".into()));
            }
            self.inner.put(key, value)
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
            let call_num = self.batch_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_next_batch.swap(false, Ordering::SeqCst)
                || call_num >= self.fail_batch_after.load(Ordering::SeqCst)
            {
                return Err(StorageError::Database("injected batch failure".into()));
            }
            self.inner.write_batch(batch)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
    }

    #[test]
    fn approximate_prefix_bytes_sums_matching_entries() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&store));

        store.put(b"b/a", b"123").unwrap();
        store.put(b"b/bb", b"45").unwrap();
        store.put(b"h/a", b"ignored").unwrap();

        assert_eq!(cs.approximate_prefix_bytes(b"b/").unwrap(), 12);
    }

    fn empty_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1700000000 + number,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    /// Helper: put block + set canonical + set head (mimics old behavior).
    fn put_canonical(cs: &ChainStore<MemoryDb>, block: &Block) {
        let hash = block.hash();
        cs.put_block(block).unwrap();
        cs.set_canonical(block.number(), &hash).unwrap();
        cs.set_head(&hash).unwrap();
    }

    #[test]
    fn put_and_get_by_hash() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(0);
        let hash = block.hash();

        cs.put_block(&block).unwrap();
        let loaded = cs.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded.header, block.header);
    }

    #[test]
    fn put_block_does_not_set_head() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(0);

        cs.put_block(&block).unwrap();
        // HEAD should still be None — put_block no longer sets it
        assert!(cs.get_head_hash().unwrap().is_none());
    }

    #[test]
    fn put_block_does_not_set_canonical() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(42);

        cs.put_block(&block).unwrap();
        // Number→hash should not be set
        assert!(cs.get_block_by_number(42).unwrap().is_none());
    }

    #[test]
    fn side_fork_block_is_recorded_but_not_canonical() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let mut block = empty_block(7);
        block.header.timestamp += 1;
        let hash = block.hash();

        cs.put_side_fork_block(&block).unwrap();

        assert_eq!(cs.get_side_fork_hashes(7).unwrap(), vec![hash]);
        assert_eq!(cs.get_block_by_hash(&hash).unwrap().unwrap().hash(), hash);
        assert!(cs.get_block_by_number(7).unwrap().is_none());
        assert!(cs.get_head_hash().unwrap().is_none());
    }

    #[test]
    fn set_canonical_and_get_by_number() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(42);
        let hash = block.hash();

        cs.put_block(&block).unwrap();
        cs.set_canonical(42, &hash).unwrap();
        let loaded = cs.get_block_by_number(42).unwrap().unwrap();
        assert_eq!(loaded.number(), 42);
    }

    #[test]
    fn set_head_and_get_head() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(0);
        let hash = block.hash();

        cs.put_block(&block).unwrap();
        cs.set_head(&hash).unwrap();
        assert_eq!(cs.get_head_hash().unwrap().unwrap(), hash);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        assert!(cs.get_block_by_number(999).unwrap().is_none());
        assert!(cs.get_block_by_hash(&ShellHash::ZERO).unwrap().is_none());
    }

    #[test]
    fn block_availability_classifies_header_body_witness_components() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(9);
        let hash = block.hash();

        assert_eq!(
            cs.block_availability(&hash).unwrap(),
            BlockAvailability::Missing
        );

        cs.put_block(&block).unwrap();
        assert_eq!(
            cs.block_availability(&hash).unwrap(),
            BlockAvailability::BodyOnly
        );

        cs.store()
            .put(&ChainStore::<MemoryDb>::witness_key(&hash), b"present")
            .unwrap();
        assert_eq!(
            cs.block_availability(&hash).unwrap(),
            BlockAvailability::BodyWithWitness
        );

        cs.delete_body(&hash).unwrap();
        assert_eq!(
            cs.block_availability(&hash).unwrap(),
            BlockAvailability::HeaderOnly
        );
    }

    #[test]
    fn oldest_canonical_body_number_handles_non_contiguous_bodies() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let mut hashes = Vec::new();
        for number in 0..=5 {
            let block = empty_block(number);
            hashes.push(block.hash());
            put_canonical(&cs, &block);
        }

        cs.delete_body(&hashes[3]).unwrap();

        assert_eq!(cs.oldest_canonical_body_number().unwrap(), Some(0));

        for hash in hashes.iter().take(3) {
            cs.delete_body(hash).unwrap();
        }

        assert_eq!(cs.oldest_canonical_body_number().unwrap(), Some(4));
    }

    #[test]
    fn delete_bodies_removes_multiple_bodies() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let mut hashes = Vec::new();
        for number in 0..4 {
            let block = empty_block(number);
            let hash = block.hash();
            put_canonical(&cs, &block);
            hashes.push(hash);
        }

        cs.delete_bodies(&hashes[..3]).unwrap();

        for hash in hashes.iter().take(3) {
            assert!(!cs.has_body(hash).unwrap());
        }
        assert!(cs.has_body(&hashes[3]).unwrap());
    }

    #[test]
    fn oldest_canonical_body_number_ignores_side_fork_bodies() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let genesis = empty_block(0);
        let genesis_hash = genesis.hash();
        put_canonical(&cs, &genesis);
        cs.delete_body(&genesis_hash).unwrap();

        let canonical = empty_block(5);
        put_canonical(&cs, &canonical);

        let mut side_fork = empty_block(1);
        side_fork.header.extra_data = Bytes::from_static(b"side-fork");
        cs.put_side_fork_block(&side_fork).unwrap();

        assert_eq!(cs.oldest_canonical_body_number().unwrap(), Some(5));
    }

    #[test]
    fn head_block_tracking() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        assert!(cs.get_head_hash().unwrap().is_none());

        let b0 = empty_block(0);
        put_canonical(&cs, &b0);
        assert_eq!(cs.get_head_hash().unwrap().unwrap(), b0.hash());

        let mut b1 = empty_block(1);
        b1.header.parent_hash = b0.hash();
        put_canonical(&cs, &b1);
        assert_eq!(cs.get_head_hash().unwrap().unwrap(), b1.hash());
    }

    #[test]
    fn header_retrieval() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(5);
        let hash = block.hash();

        cs.put_block(&block).unwrap();
        let header = cs.get_header_by_hash(&hash).unwrap().unwrap();
        assert_eq!(header.number, 5);
    }

    #[test]
    fn receipt_storage() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(0);
        let hash = block.hash();
        cs.put_block(&block).unwrap();

        let receipts = vec![TransactionReceipt {
            tx_hash: ShellHash::ZERO,
            block_number: 0,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        }];

        cs.put_receipts(&hash, &receipts).unwrap();
        let loaded = cs.get_receipts(&hash).unwrap().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, 1);
    }

    #[test]
    fn multiple_blocks_chain() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let b0 = empty_block(0);
        put_canonical(&cs, &b0);

        let mut b1 = empty_block(1);
        b1.header.parent_hash = b0.hash();
        put_canonical(&cs, &b1);

        let mut b2 = empty_block(2);
        b2.header.parent_hash = b1.hash();
        put_canonical(&cs, &b2);

        // All blocks retrievable
        assert!(cs.get_block_by_number(0).unwrap().is_some());
        assert!(cs.get_block_by_number(1).unwrap().is_some());
        assert!(cs.get_block_by_number(2).unwrap().is_some());
        assert_eq!(cs.get_head_hash().unwrap().unwrap(), b2.hash());
    }

    #[test]
    fn chain_config_roundtrip() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        assert!(cs.get_chain_config().unwrap().is_none());

        let config = ChainConfig {
            chain_id: 1337,
            genesis_hash: ShellHash::ZERO,
        };
        cs.put_chain_config(&config).unwrap();

        let loaded = cs.get_chain_config().unwrap().unwrap();
        assert_eq!(loaded.chain_id, 1337);
        assert_eq!(loaded.genesis_hash, ShellHash::ZERO);
    }

    #[test]
    fn code_storage_roundtrip() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let code = b"\x60\x80\x60\x40\x52"; // PUSH1 0x80 PUSH1 0x40 MSTORE
        let code_hash = shell_primitives::keccak256(code);

        assert!(cs.get_code(&code_hash).unwrap().is_none());

        cs.put_code(&code_hash, code).unwrap();
        let loaded = cs.get_code(&code_hash).unwrap().unwrap();
        assert_eq!(loaded, code);
    }

    #[test]
    fn pubkey_registry_roundtrip() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let addr = Address::ZERO;
        let fake_pubkey = vec![0xAA; 1952]; // Dilithium3 pubkey size

        assert!(cs.get_pubkey(&addr).unwrap().is_none());

        cs.put_pubkey(&addr, &fake_pubkey).unwrap();
        let loaded = cs.get_pubkey(&addr).unwrap().unwrap();
        assert_eq!(loaded.len(), 1952);
        assert_eq!(loaded, fake_pubkey);
    }

    #[test]
    fn get_receipts_by_block_number() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(7);
        let hash = block.hash();
        cs.put_block(&block).unwrap();
        cs.set_canonical(7, &hash).unwrap();

        let receipts = vec![TransactionReceipt {
            tx_hash: shell_primitives::keccak256(b"tx-a"),
            block_number: 7,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        }];
        cs.put_receipts(&hash, &receipts).unwrap();

        let loaded = cs.get_receipts_by_block(7).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].tx_hash, shell_primitives::keccak256(b"tx-a"));

        // Non-existent block returns empty vec
        assert!(cs.get_receipts_by_block(999).unwrap().is_empty());
    }

    #[test]
    fn get_receipt_by_tx_hash_found() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(1);
        let block_hash = block.hash();
        cs.put_block(&block).unwrap();
        cs.set_canonical(1, &block_hash).unwrap();

        let tx_hash = shell_primitives::keccak256(b"some-tx");

        // Manually write a tx index entry (block_hash ++ tx_index_be)
        let mut index_value = block_hash.as_bytes().to_vec();
        index_value.extend_from_slice(&0u32.to_be_bytes());
        cs.store()
            .put(
                &[prefix::TX_INDEX, tx_hash.as_bytes()].concat(),
                &index_value,
            )
            .unwrap();

        let receipt = TransactionReceipt {
            tx_hash,
            block_number: 1,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        };
        cs.put_receipts(&block_hash, std::slice::from_ref(&receipt))
            .unwrap();

        // Look up by tx hash
        let found = cs.get_receipt_by_tx_hash(&tx_hash).unwrap().unwrap();
        assert_eq!(found, receipt);

        // Non-existent tx returns None
        assert!(cs
            .get_receipt_by_tx_hash(&ShellHash::ZERO)
            .unwrap()
            .is_none());
    }

    #[test]
    fn receipt_storage_with_logs_and_bloom() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(3);
        let hash = block.hash();
        cs.put_block(&block).unwrap();
        cs.set_canonical(3, &hash).unwrap();

        let event_sig = shell_primitives::keccak256(b"Transfer(address,address,uint256)");
        let log = shell_core::Log::new(
            Address::from([0xAB; 20]),
            vec![event_sig],
            Bytes::from(vec![1, 2, 3, 4]),
        )
        .unwrap();

        // Build a non-zero bloom (same algorithm the executor uses)
        let bloom_bytes = {
            let mut bloom = [0u8; 256];
            for item in std::iter::once(log.address.as_bytes() as &[u8])
                .chain(log.topics.iter().map(|t| t.as_bytes() as &[u8]))
            {
                let h = shell_primitives::keccak256(item);
                let hb = h.as_bytes();
                for i in 0..3 {
                    let bit = ((hb[i * 2] as usize) << 8 | hb[i * 2 + 1] as usize) & 0x7FF;
                    bloom[bit / 8] |= 1 << (7 - (bit % 8));
                }
            }
            Bytes::from(bloom.to_vec())
        };

        let receipt = TransactionReceipt {
            tx_hash: shell_primitives::keccak256(b"logtx"),
            block_number: 3,
            tx_index: 0,
            status: 1,
            gas_used: 35000,
            cumulative_gas_used: 35000,
            contract_address: None,
            logs_bloom: bloom_bytes.clone(),
            logs: vec![log.clone()],
        };

        cs.put_receipts(&hash, &[receipt]).unwrap();

        // Retrieve via block number
        let loaded = cs.get_receipts_by_block(3).unwrap();
        assert_eq!(loaded.len(), 1);

        let r = &loaded[0];
        // Verify logs survived round-trip
        assert_eq!(r.logs.len(), 1);
        assert_eq!(r.logs[0].address, Address::from([0xAB; 20]));
        assert_eq!(r.logs[0].topics.len(), 1);
        assert_eq!(r.logs[0].topics[0], event_sig);
        assert_eq!(r.logs[0].data.as_ref(), &[1, 2, 3, 4]);

        // Verify logs_bloom is non-empty and survived round-trip
        assert_eq!(r.logs_bloom.as_ref().len(), 256);
        assert_ne!(r.logs_bloom.as_ref(), &[0u8; 256]);
        assert_eq!(r.logs_bloom, bloom_bytes);
    }

    #[test]
    fn pubkey_overwrite() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let addr = Address::ZERO;

        cs.put_pubkey(&addr, &[1; 100]).unwrap();
        cs.put_pubkey(&addr, &[2; 200]).unwrap();

        let loaded = cs.get_pubkey(&addr).unwrap().unwrap();
        assert_eq!(loaded, vec![2; 200]);
    }

    #[test]
    fn guardian_storage_preserves_native_addresses_and_reads_legacy_entries() {
        let native = Address::from([0xabu8; 32]);
        let config = GuardianConfig {
            guardians: vec![native],
            threshold: 1,
            timelock: MIN_RECOVERY_TIMELOCK,
        };
        let encoded = serde_json::to_vec(&config).unwrap();
        let decoded: GuardianConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, config);

        let legacy: GuardianConfig = serde_json::from_value(serde_json::json!({
            "guardians": [vec![0xcdu8; 20]],
            "threshold": 1,
            "timelock": MIN_RECOVERY_TIMELOCK,
        }))
        .unwrap();
        assert_eq!(legacy.guardians, vec![Address::from([0xcdu8; 20])]);

        let legacy_proposal: RecoveryProposal = serde_json::from_value(serde_json::json!({
            "new_pubkey": [1, 2, 3],
            "new_algo": 1,
            "votes": [vec![0xefu8; 20]],
            "maturity_block": 100,
        }))
        .unwrap();
        assert_eq!(legacy_proposal.votes, vec![Address::from([0xefu8; 20])]);
    }

    #[test]
    fn test_finalized_number_roundtrip() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        assert_eq!(cs.get_finalized_number().unwrap(), None);
        cs.set_finalized_number(42).unwrap();
        assert_eq!(cs.get_finalized_number().unwrap(), Some(42));
        cs.set_finalized_number(100).unwrap();
        assert_eq!(cs.get_finalized_number().unwrap(), Some(100));
    }

    #[test]
    fn malformed_finalized_number_is_not_treated_as_missing() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&store));
        store.put(b"FINALIZED", &[0; 7]).unwrap();

        let error = cs.get_finalized_number().unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid finalized number encoding"));
    }

    #[test]
    fn test_import_snapshot_validates_chain_id() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        // Create a snapshot with chain_id=1337
        let meta = crate::SnapshotMetadata::new(
            1337,
            0,
            ShellHash::default(),
            ShellHash::default(),
            ShellHash::default(),
        );
        let mut buf = Vec::new();
        let writer = crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
        writer.finalize().unwrap();

        // Import with wrong chain_id
        let result = cs.import_snapshot(std::io::Cursor::new(&buf), 9999, &ShellHash::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_import_snapshot_restores_data() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        // Create snapshot with entries
        let meta = crate::SnapshotMetadata::new(
            1337,
            0,
            ShellHash::default(),
            ShellHash::default(),
            ShellHash::default(),
        );
        let mut buf = Vec::new();
        {
            let mut writer =
                crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
            writer.write_entry(b"test-key-1", b"value-1").unwrap();
            writer.write_entry(b"test-key-2", b"value-2").unwrap();
            writer.finalize().unwrap();
        }

        // Import
        let imported_meta = cs
            .import_snapshot(std::io::Cursor::new(&buf), 1337, &ShellHash::default())
            .unwrap();
        assert_eq!(imported_meta.entry_count, 2);

        // Verify data was written
        assert_eq!(store.get(b"test-key-1").unwrap(), Some(b"value-1".to_vec()));
        assert_eq!(store.get(b"test-key-2").unwrap(), Some(b"value-2".to_vec()));
    }

    #[test]
    fn test_import_snapshot_accepts_head_header_before_head_pointer() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let block = empty_block(1);
        let block_hash = block.hash();
        let meta = crate::SnapshotMetadata::new(
            1337,
            block.number(),
            block_hash,
            block.header.state_root,
            ShellHash::ZERO,
        );
        let mut buf = Vec::new();
        {
            let mut writer =
                crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
            writer
                .write_entry(
                    &ChainStore::<MemoryDb>::header_key(&block_hash),
                    &encode_rlp(&block.header),
                )
                .unwrap();
            writer
                .write_entry(prefix::HEAD_BLOCK, block_hash.as_bytes())
                .unwrap();
            writer.finalize().unwrap();
        }

        cs.import_snapshot(std::io::Cursor::new(&buf), 1337, &ShellHash::ZERO)
            .unwrap();
        assert_eq!(cs.get_head_hash().unwrap(), Some(block_hash));
    }

    #[test]
    fn test_import_snapshot_preserves_head_when_later_batch_fails() {
        let store = Arc::new(FailingBatchStore::new());
        let cs = ChainStore::new(Arc::clone(&store));
        let old_head = ShellHash::from([0xAA; 32]);
        cs.set_head(&old_head).unwrap();

        let block = empty_block(1);
        let block_hash = block.hash();
        let meta = crate::SnapshotMetadata::new(
            1337,
            block.number(),
            block_hash,
            block.header.state_root,
            ShellHash::ZERO,
        );
        let mut buf = Vec::new();
        {
            let mut writer =
                crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
            writer
                .write_entry(prefix::HEAD_BLOCK, block_hash.as_bytes())
                .unwrap();
            writer
                .write_entry(
                    &ChainStore::<FailingBatchStore>::header_key(&block_hash),
                    &encode_rlp(&block.header),
                )
                .unwrap();
            for index in 0..10_000 {
                writer
                    .write_entry(format!("snapshot/test/{index:05}").as_bytes(), b"value")
                    .unwrap();
            }
            writer.finalize().unwrap();
        }

        store.fail_batch_after(2);
        let error = cs
            .import_snapshot(std::io::Cursor::new(&buf), 1337, &ShellHash::ZERO)
            .unwrap_err();
        assert!(error.to_string().contains("injected batch failure"));
        assert_eq!(cs.get_head_hash().unwrap(), Some(old_head));
    }

    #[test]
    fn test_get_txs_by_address_applies_offset_after_block_filter() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&store));
        let address = Address::from([0x11; 20]);

        for (idx, block_number) in [1u64, 2, 3].into_iter().enumerate() {
            let hash = ShellHash::from([(idx as u8) + 1; 32]);
            store
                .put(
                    &ChainStore::<MemoryDb>::addr_tx_key(&address, block_number, idx as u32),
                    hash.as_bytes(),
                )
                .unwrap();
        }

        let page = cs.get_txs_by_address(&address, 2, 3, 1, 1).unwrap();
        assert_eq!(page, vec![ShellHash::from([2u8; 32])]);
    }

    #[test]
    fn test_get_txs_by_address_allows_deep_offset() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&store));
        let address = Address::from([0x22; 20]);

        for idx in 0..3u32 {
            let hash = ShellHash::from([(idx as u8) + 1; 32]);
            store
                .put(
                    &ChainStore::<MemoryDb>::addr_tx_key(&address, idx as u64, idx),
                    hash.as_bytes(),
                )
                .unwrap();
        }

        let page = cs.get_txs_by_address(&address, 0, u64::MAX, 20_000, 50);
        assert_eq!(page.unwrap(), Vec::<ShellHash>::new());
    }

    #[test]
    fn test_count_txs_by_address_respects_block_filter() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&store));
        let address = Address::from([0x33; 20]);

        for (idx, block_number) in [1u64, 2, 3].into_iter().enumerate() {
            let hash = ShellHash::from([(idx as u8) + 1; 32]);
            store
                .put(
                    &ChainStore::<MemoryDb>::addr_tx_key(&address, block_number, idx as u32),
                    hash.as_bytes(),
                )
                .unwrap();
        }

        assert_eq!(cs.count_txs_by_address(&address, 0, u64::MAX).unwrap(), 3);
        assert_eq!(cs.count_txs_by_address(&address, 2, 3).unwrap(), 2);
    }

    #[test]
    fn get_txs_by_address_cursor_returns_newest_first_with_cursor() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let address = Address::from([0xAA; 20]);

        for number in 1..=3 {
            let block = make_block_with_txs(number);
            put_canonical(&cs, &block);
        }

        let (first_page, has_more) = cs
            .get_txs_by_address_cursor(&address, 0, u64::MAX, None, 2, true)
            .unwrap();
        assert!(has_more);
        assert_eq!(first_page.len(), 2);
        assert_eq!(first_page[0].block_number, 3);
        assert_eq!(first_page[1].block_number, 2);

        let (second_page, has_more) = cs
            .get_txs_by_address_cursor(
                &address,
                0,
                u64::MAX,
                first_page.last().map(|entry| entry.cursor.as_str()),
                2,
                true,
            )
            .unwrap();
        assert!(!has_more);
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].block_number, 1);

        let (filtered, has_more) = cs
            .get_txs_by_address_cursor(&address, 2, 3, None, 10, true)
            .unwrap();
        assert!(!has_more);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].block_number, 3);
        assert_eq!(filtered[1].block_number, 2);

        let (first_asc, has_more) = cs
            .get_txs_by_address_cursor(&address, 0, u64::MAX, None, 2, false)
            .unwrap();
        assert!(has_more);
        assert_eq!(first_asc.len(), 2);
        assert_eq!(first_asc[0].block_number, 1);
        assert_eq!(first_asc[1].block_number, 2);

        let (second_asc, has_more) = cs
            .get_txs_by_address_cursor(
                &address,
                0,
                u64::MAX,
                first_asc.last().map(|entry| entry.cursor.as_str()),
                2,
                false,
            )
            .unwrap();
        assert!(!has_more);
        assert_eq!(second_asc.len(), 1);
        assert_eq!(second_asc[0].block_number, 3);
    }

    #[test]
    fn get_txs_by_address_cursor_rejects_cursor_outside_range() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let address = Address::from([0xAA; 20]);

        for number in 1..=4 {
            let block = make_block_with_txs(number);
            put_canonical(&cs, &block);
        }

        let (page, _) = cs
            .get_txs_by_address_cursor(&address, 0, u64::MAX, None, 2, true)
            .unwrap();
        assert_eq!(page[0].block_number, 4);
        assert_eq!(page[1].block_number, 3);

        let err = cs
            .get_txs_by_address_cursor(
                &address,
                1,
                2,
                page.last().map(|entry| entry.cursor.as_str()),
                2,
                true,
            )
            .unwrap_err();
        assert!(err.to_string().contains("outside requested block range"));
    }

    #[test]
    fn address_tx_index_keys_use_shell_address_width() {
        let address = Address::from_public_key(b"shell-address-width", 0);
        assert_eq!(
            ChainStore::<MemoryDb>::addr_tx_key(&address, 1, 2).len(),
            prefix::ADDR_TX_INDEX.len() + 32 + 8 + 4
        );
        assert_eq!(
            ChainStore::<MemoryDb>::addr_tx_rev_key(&address, 1, 2).len(),
            prefix::ADDR_TX_INDEX_REV.len() + 32 + 8 + 4
        );
    }

    #[test]
    fn delete_block_transaction_indexes_removes_user_and_system_history() {
        use shell_primitives::U256;

        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(db);
        let mut block = make_block_with_txs(5);
        let reward_to = Address::from_public_key(b"system-reward-recipient", 0);
        let reward = SystemTransaction::block_gas_reward(
            1,
            block.number(),
            1,
            reward_to,
            U256::from(10u64),
            block.header.parent_hash,
        );
        block.system_transactions.push(reward.clone());
        let block_hash = block.hash();
        let user_tx_hash = block.transactions[0].hash();
        let user_sender = block.transactions[0].sender();

        cs.commit_canonical_block(&block, None).unwrap();
        assert_eq!(
            cs.get_tx_location(&user_tx_hash).unwrap(),
            Some((block_hash, 0))
        );
        assert_eq!(
            cs.get_tx_location(&reward.hash()).unwrap(),
            Some((block_hash, reward.tx_index))
        );
        assert_eq!(
            cs.get_txs_by_address_cursor(&user_sender, 0, u64::MAX, None, 10, true)
                .unwrap()
                .0
                .len(),
            1
        );
        assert_eq!(
            cs.get_txs_by_address_cursor(&reward_to, 0, u64::MAX, None, 10, true)
                .unwrap()
                .0
                .len(),
            1
        );

        cs.delete_block_transaction_indexes(&block_hash).unwrap();
        assert!(cs.get_tx_location(&user_tx_hash).unwrap().is_none());
        assert!(cs.get_tx_location(&reward.hash()).unwrap().is_none());
        assert!(cs
            .get_txs_by_address_cursor(&user_sender, 0, u64::MAX, None, 10, true)
            .unwrap()
            .0
            .is_empty());
        assert!(cs
            .get_txs_by_address_cursor(&reward_to, 0, u64::MAX, None, 10, true)
            .unwrap()
            .0
            .is_empty());
    }

    // ── Snapshot round-trip tests ──────────────────────────────────────

    #[test]
    fn test_export_import_snapshot_roundtrip() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        // Store some real chain data.
        let b0 = empty_block(0);
        put_canonical(&cs, &b0);
        let mut b1 = empty_block(1);
        b1.header.parent_hash = b0.hash();
        put_canonical(&cs, &b1);

        cs.put_chain_config(&ChainConfig {
            chain_id: 1337,
            genesis_hash: b0.hash(),
        })
        .unwrap();

        // Export snapshot.
        let meta =
            crate::SnapshotMetadata::new(1337, 1, b1.hash(), ShellHash::default(), b0.hash());
        let mut buf = Vec::new();
        let exported = cs
            .export_snapshot(meta, std::io::Cursor::new(&mut buf))
            .unwrap();
        assert_eq!(exported.chain_id, 1337);
        assert_eq!(exported.block_number, 1);
        assert!(exported.entry_count > 0);

        // Import into a fresh store.
        let store2 = Arc::new(MemoryDb::new());
        let cs2 = ChainStore::new(store2.clone());

        let imported = cs2
            .import_snapshot(std::io::Cursor::new(&buf), 1337, &b0.hash())
            .unwrap();
        assert_eq!(imported.entry_count, exported.entry_count);

        // Verify chain metadata and canonical data were restored.
        let loaded_cfg = cs2.get_chain_config().unwrap().unwrap();
        assert_eq!(loaded_cfg.chain_id, 1337);
        assert_eq!(loaded_cfg.genesis_hash, b0.hash());
        assert_eq!(
            cs2.get_block_by_number(1).unwrap().unwrap().hash(),
            b1.hash()
        );
        assert_eq!(cs2.get_head_block().unwrap().unwrap().hash(), b1.hash());
    }

    #[test]
    fn test_export_snapshot_at_specific_block() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        let b0 = empty_block(0);
        put_canonical(&cs, &b0);

        // Export snapshot referencing block 0.
        let meta =
            crate::SnapshotMetadata::new(1337, 0, b0.hash(), ShellHash::default(), b0.hash());
        let mut buf = Vec::new();
        let exported = cs
            .export_snapshot(meta, std::io::Cursor::new(&mut buf))
            .unwrap();

        assert_eq!(exported.block_number, 0);
        assert_eq!(exported.block_hash, b0.hash());
        assert!(exported.entry_count > 0);
    }

    #[test]
    fn test_import_corrupted_snapshot_fails() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let corrupted = b"this is not valid snapshot data at all";
        let result =
            cs.import_snapshot(std::io::Cursor::new(corrupted), 1337, &ShellHash::default());
        assert!(result.is_err(), "corrupted snapshot should fail to import");
    }

    #[test]
    fn test_import_snapshot_metadata_mismatch_genesis() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let genesis_hash = ShellHash::from([0x01; 32]);
        let meta = crate::SnapshotMetadata::new(
            1337,
            10,
            ShellHash::default(),
            ShellHash::default(),
            genesis_hash,
        );
        let mut buf = Vec::new();
        {
            let writer = crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
            writer.finalize().unwrap();
        }

        // Import expecting a different genesis hash.
        let wrong_genesis = ShellHash::from([0x99; 32]);
        let result = cs.import_snapshot(std::io::Cursor::new(&buf), 1337, &wrong_genesis);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("genesis hash mismatch"),
            "expected genesis mismatch error, got: {err}"
        );
    }

    #[test]
    fn test_import_snapshot_chain_id_mismatch_detailed() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let meta = crate::SnapshotMetadata::new(
            42,
            5,
            ShellHash::default(),
            ShellHash::default(),
            ShellHash::default(),
        );
        let mut buf = Vec::new();
        {
            let writer = crate::SnapshotWriter::new(std::io::Cursor::new(&mut buf), meta).unwrap();
            writer.finalize().unwrap();
        }

        // Import expecting chain_id=1337 but snapshot has 42.
        let result = cs.import_snapshot(std::io::Cursor::new(&buf), 1337, &ShellHash::default());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("chain ID mismatch"),
            "expected chain ID mismatch error, got: {err}"
        );
    }

    // ── RLP serialization tests ───────────────────────────────────────

    #[test]
    fn rlp_block_roundtrip_through_store() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(42);
        let hash = block.hash();
        cs.put_block(&block).unwrap();

        let loaded = cs.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded.header, block.header);
        assert_eq!(loaded.transactions.len(), 0);
    }

    #[test]
    fn rlp_header_roundtrip_through_store() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(7);
        let hash = block.hash();
        cs.put_block(&block).unwrap();

        let header = cs.get_header_by_hash(&hash).unwrap().unwrap();
        assert_eq!(header, block.header);
    }

    #[test]
    fn rlp_receipts_roundtrip_through_store() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        let block = empty_block(0);
        let hash = block.hash();
        cs.put_block(&block).unwrap();

        let log = shell_core::Log {
            address: Address::from([0xAB; 20]),
            topics: vec![shell_primitives::keccak256(
                b"Transfer(address,address,uint256)",
            )],
            data: Bytes::from(vec![1, 2, 3]),
        };
        let receipts = vec![TransactionReceipt {
            tx_hash: shell_primitives::keccak256(b"tx1"),
            block_number: 0,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: Some(Address::from([0xCD; 20])),
            logs_bloom: Bytes::new(),
            logs: vec![log],
        }];

        cs.put_receipts(&hash, &receipts).unwrap();
        let loaded = cs.get_receipts(&hash).unwrap().unwrap();
        assert_eq!(loaded, receipts);
    }

    // ── Backward compatibility tests ──────────────────────────────────

    #[test]
    fn backward_compat_legacy_json_block() {
        // Simulate legacy data stored as plain JSON (no version prefix).
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        let block = empty_block(0);
        let hash = block.hash();

        // Write raw JSON directly (legacy format — no version prefix)
        let header_json = serde_json::to_vec(&block.header).unwrap();
        store
            .put(
                &[prefix::HEADER_BY_HASH, hash.as_bytes()].concat(),
                &header_json,
            )
            .unwrap();
        let body_json = serde_json::to_vec(&block).unwrap();
        store
            .put(
                &[prefix::BODY_BY_HASH, hash.as_bytes()].concat(),
                &body_json,
            )
            .unwrap();

        // Read back using the new versioned decoder
        let loaded_header = cs.get_header_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded_header, block.header);
        let loaded_block = cs.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded_block.header, block.header);
    }

    #[test]
    fn backward_compat_legacy_json_receipts() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        let hash = shell_primitives::keccak256(b"block");
        let receipts = vec![TransactionReceipt {
            tx_hash: ShellHash::ZERO,
            block_number: 0,
            tx_index: 0,
            status: 1,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![],
        }];

        // Write raw JSON directly
        let json = serde_json::to_vec(&receipts).unwrap();
        store
            .put(&[prefix::RECEIPTS_BY_HASH, hash.as_bytes()].concat(), &json)
            .unwrap();

        // Read back with versioned decoder
        let loaded = cs.get_receipts(&hash).unwrap().unwrap();
        assert_eq!(loaded, receipts);
    }

    #[test]
    fn backward_compat_prefixed_json_header() {
        // Test explicit JSON version prefix (0x01).
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());

        let block = empty_block(0);
        let hash = block.hash();

        let mut header_data = vec![format_version::JSON];
        header_data.extend_from_slice(&serde_json::to_vec(&block.header).unwrap());
        store
            .put(
                &[prefix::HEADER_BY_HASH, hash.as_bytes()].concat(),
                &header_data,
            )
            .unwrap();

        let loaded = cs.get_header_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded, block.header);
    }

    #[test]
    fn rlp_smaller_than_json() {
        // Verify RLP encoding is smaller than JSON for blocks.
        let block = empty_block(42);
        let rlp_bytes = encode_rlp(&block);
        let json_bytes = serde_json::to_vec(&block).unwrap();
        assert!(
            rlp_bytes.len() < json_bytes.len(),
            "RLP ({}) should be smaller than JSON ({})",
            rlp_bytes.len(),
            json_bytes.len()
        );
    }

    // ── WitnessStore tests ─────────────────────────────────────────────────

    use shell_core::{TxWitness, WitnessBundle};
    use shell_crypto::{DilithiumSigner, Signer};

    fn dummy_bundle() -> WitnessBundle {
        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig1 = signer.sign(b"tx0").expect("sign");
        let sig2 = signer.sign(b"tx1").expect("sign");
        WitnessBundle::new(vec![
            TxWitness::new_embedded(sig1, pk),
            TxWitness::new_reference(sig2),
        ])
    }

    #[test]
    fn witness_store_put_and_get() {
        let store = Arc::new(MemoryDb::default());
        let ws = WitnessStore::new(store);
        let hash = shell_primitives::keccak256(b"block-hash");
        let bundle = dummy_bundle();

        ws.put_bundle(&hash, &bundle).unwrap();
        let loaded = ws.get_bundle(&hash).unwrap().unwrap();
        assert_eq!(loaded, bundle);
    }

    #[test]
    fn witness_store_get_missing_returns_none() {
        let store = Arc::new(MemoryDb::default());
        let ws = WitnessStore::new(store);
        let hash = shell_primitives::keccak256(b"nonexistent");
        assert!(ws.get_bundle(&hash).unwrap().is_none());
    }

    #[test]
    fn witness_store_has_bundle() {
        let store = Arc::new(MemoryDb::default());
        let ws = WitnessStore::new(store);
        let hash = shell_primitives::keccak256(b"block");
        let bundle = dummy_bundle();

        assert!(!ws.has_bundle(&hash).unwrap());
        ws.put_bundle(&hash, &bundle).unwrap();
        assert!(ws.has_bundle(&hash).unwrap());
    }

    #[test]
    fn witness_store_delete_bundle() {
        let store = Arc::new(MemoryDb::default());
        let ws = WitnessStore::new(store);
        let hash = shell_primitives::keccak256(b"block");
        let bundle = dummy_bundle();

        ws.put_bundle(&hash, &bundle).unwrap();
        assert!(ws.has_bundle(&hash).unwrap());
        ws.delete_bundle(&hash).unwrap();
        assert!(!ws.has_bundle(&hash).unwrap());
    }

    #[test]
    fn witness_store_delete_bundles_removes_multiple_bundles() {
        let store = Arc::new(MemoryDb::default());
        let ws = WitnessStore::new(store);
        let bundle = dummy_bundle();
        let hashes: Vec<ShellHash> = (0..4)
            .map(|n| shell_primitives::keccak256(format!("block-{n}").as_bytes()))
            .collect();

        for hash in &hashes {
            ws.put_bundle(hash, &bundle).unwrap();
        }

        ws.delete_bundles(&hashes[..3]).unwrap();

        for hash in hashes.iter().take(3) {
            assert!(!ws.has_bundle(hash).unwrap());
        }
        assert!(ws.has_bundle(&hashes[3]).unwrap());
    }

    #[test]
    fn witness_store_independent_from_chain_store() {
        // Witness and chain stores use the same MemoryDb but different key spaces.
        // WitnessStore uses "w/<hash>"; ChainStore body uses "b/<hash>".
        let db = Arc::new(MemoryDb::default());
        let cs = ChainStore::new(Arc::clone(&db));
        let ws = WitnessStore::new(Arc::clone(&db));
        let block = empty_block(1);
        let hash = block.hash();
        let bundle = dummy_bundle();

        cs.put_block(&block).unwrap();
        ws.put_bundle(&hash, &bundle).unwrap();

        // Both can be retrieved independently
        assert!(cs.get_block_by_hash(&hash).unwrap().is_some());
        assert!(ws.get_bundle(&hash).unwrap().is_some());
    }

    // ── Phase B split / round-trip tests ──────────────────────────────────────

    fn make_block_with_txs(number: u64) -> Block {
        use shell_core::{SignedTransaction, Transaction};
        use shell_crypto::{DilithiumSigner, Signer};
        use shell_primitives::{Address, U256};

        let signer = DilithiumSigner::generate();
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"payload").unwrap();
        let tx = Transaction {
            chain_id: 1,
            nonce: number,
            to: Some(Address::from([0xBB; 20])),
            value: U256::from(number * 1000),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: 1_000,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let signed = SignedTransaction::with_pubkey(Address::from([0xAA; 20]), tx, sig, pk);
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::new(),
                number,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1700000000 + number,
                extra_data: Bytes::new(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![signed],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    #[test]
    fn put_block_stores_separate_body_and_witness_keys() {
        // After split: b/<hash> exists, w/<hash> exists, and they are distinct.
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = make_block_with_txs(0);
        let hash = block.hash();

        cs.put_block(&block).unwrap();

        let body_key = [b"b/".as_ref(), hash.as_bytes()].concat();
        let wit_key = [b"w/".as_ref(), hash.as_bytes()].concat();

        assert!(
            db.get(&body_key).unwrap().is_some(),
            "b/<hash> should exist"
        );
        assert!(db.get(&wit_key).unwrap().is_some(), "w/<hash> should exist");
    }

    #[test]
    fn get_block_reconstructs_tx_payload() {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(db);
        let block = make_block_with_txs(1);
        let hash = block.hash();
        let original_from = block.transactions[0].from;
        let original_value = block.transactions[0].tx.value;

        cs.put_block(&block).unwrap();
        let loaded = cs.get_block_by_hash(&hash).unwrap().unwrap();

        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].from, original_from);
        assert_eq!(loaded.transactions[0].tx.value, original_value);
    }

    #[test]
    fn delete_witness_returns_stub_sig_on_get() {
        // After deleting the witness bundle (STARK proof accepted),
        // get_block_by_hash still returns the block with payload intact,
        // but signatures are empty stubs.
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(db);
        let block = make_block_with_txs(2);
        let hash = block.hash();
        let original_from = block.transactions[0].from;

        cs.put_block(&block).unwrap();
        cs.delete_witness_bundle(&hash).unwrap();

        let loaded = cs.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded.transactions.len(), 1);
        assert_eq!(loaded.transactions[0].from, original_from, "from preserved");
        assert!(
            loaded.transactions[0].signature.data.is_empty(),
            "stub sig after witness deletion"
        );
    }

    #[test]
    fn empty_block_has_no_witness_key() {
        // Empty blocks (no txs) should NOT write a w/<hash> key.
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = empty_block(99);
        let hash = block.hash();

        cs.put_block(&block).unwrap();

        let wit_key = [b"w/".as_ref(), hash.as_bytes()].concat();
        assert!(
            db.get(&wit_key).unwrap().is_none(),
            "no w/<hash> for empty block"
        );
        assert!(!cs.has_witness_bundle(&hash).unwrap());
    }

    #[test]
    fn commit_canonical_block_writes_all_required_records() {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = make_block_with_txs(5);
        let hash = block.hash();
        let tx_hash = block.transactions[0].hash();
        let receipt = TransactionReceipt {
            tx_hash,
            block_number: block.number(),
            tx_index: 0,
            status: 1,
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            contract_address: None,
            logs_bloom: Bytes::default(),
            logs: vec![],
        };

        cs.commit_canonical_block(&block, Some(std::slice::from_ref(&receipt)))
            .unwrap();

        assert_eq!(cs.get_head_hash().unwrap(), Some(hash));
        assert_eq!(
            cs.get_block_by_number(block.number())
                .unwrap()
                .unwrap()
                .hash(),
            hash
        );
        assert_eq!(
            cs.get_receipts(&hash).unwrap().unwrap(),
            vec![receipt.clone()]
        );
        assert_eq!(cs.get_tx_location(&tx_hash).unwrap(), Some((hash, 0)));
    }

    #[test]
    fn commit_canonical_block_is_atomic_on_batch_error() {
        let db = Arc::new(FailingBatchStore::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = make_block_with_txs(9);
        let hash = block.hash();
        let tx_hash = block.transactions[0].hash();
        let receipt = TransactionReceipt {
            tx_hash,
            block_number: block.number(),
            tx_index: 0,
            status: 1,
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            contract_address: None,
            logs_bloom: Bytes::default(),
            logs: vec![],
        };

        // If this ever regresses to per-key puts, this injected put failure
        // would leave partial data behind.
        db.fail_put_after(2);
        db.fail_next_batch();
        let err = cs
            .commit_canonical_block(&block, Some(std::slice::from_ref(&receipt)))
            .unwrap_err();
        assert!(
            err.to_string().contains("injected batch failure"),
            "unexpected error: {err}"
        );

        assert!(cs.get_head_hash().unwrap().is_none());
        assert!(cs.get_block_by_hash(&hash).unwrap().is_none());
        assert!(cs.get_block_by_number(block.number()).unwrap().is_none());
        assert!(cs.get_receipts(&hash).unwrap().is_none());
        assert!(cs.get_tx_location(&tx_hash).unwrap().is_none());
    }

    #[test]
    fn commit_genesis_block_writes_all_required_records() {
        let db = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = empty_block(0);
        let genesis_hash = block.hash();
        let config = ChainConfig {
            chain_id: 1337,
            genesis_hash,
        };

        cs.commit_genesis_block(&block, &config).unwrap();

        assert_eq!(cs.get_head_hash().unwrap(), Some(genesis_hash));
        assert_eq!(
            cs.get_block_by_number(0).unwrap().unwrap().hash(),
            genesis_hash
        );
        assert_eq!(cs.get_chain_config().unwrap(), Some(config));
    }

    #[test]
    fn commit_genesis_block_is_atomic_on_batch_error() {
        let db = Arc::new(FailingBatchStore::new());
        let cs = ChainStore::new(Arc::clone(&db));
        let block = empty_block(0);
        let genesis_hash = block.hash();
        let config = ChainConfig {
            chain_id: 1337,
            genesis_hash,
        };

        db.fail_put_after(2);
        db.fail_next_batch();
        let err = cs.commit_genesis_block(&block, &config).unwrap_err();
        assert!(
            err.to_string().contains("injected batch failure"),
            "unexpected error: {err}"
        );

        assert!(cs.get_head_hash().unwrap().is_none());
        assert!(cs.get_block_by_hash(&genesis_hash).unwrap().is_none());
        assert!(cs.get_block_by_number(0).unwrap().is_none());
        assert!(cs.get_chain_config().unwrap().is_none());
    }

    // ── L2InputIndex tests ────────────────────────────────────────────────

    fn l2_hash(seed: u8) -> ShellHash {
        ShellHash::from([seed; 32])
    }

    #[test]
    fn l2_input_index_put_has_delete() {
        let store = Arc::new(MemoryDb::default());
        let idx = L2InputIndex::new(store);
        let h = l2_hash(0xAA);

        assert!(!idx.has(&h).unwrap());
        idx.put(&h).unwrap();
        assert!(idx.has(&h).unwrap());
        idx.delete(&h).unwrap();
        assert!(!idx.has(&h).unwrap());
    }

    #[test]
    fn l2_input_index_all_hashes_returns_inserted() {
        let store = Arc::new(MemoryDb::default());
        let idx = L2InputIndex::new(store);

        let h1 = l2_hash(1);
        let h2 = l2_hash(2);
        let h3 = l2_hash(3);
        idx.put(&h1).unwrap();
        idx.put(&h2).unwrap();
        idx.put(&h3).unwrap();

        let mut all = idx.all_hashes().unwrap();
        all.sort_by_key(|h| h.as_bytes().to_vec());
        let mut expected = vec![h1, h2, h3];
        expected.sort_by_key(|h| h.as_bytes().to_vec());
        assert_eq!(all, expected);
    }

    #[test]
    fn l2_input_index_delete_removes_from_all_hashes() {
        let store = Arc::new(MemoryDb::default());
        let idx = L2InputIndex::new(store);

        let h1 = l2_hash(10);
        let h2 = l2_hash(20);
        idx.put(&h1).unwrap();
        idx.put(&h2).unwrap();
        idx.delete(&h1).unwrap();

        let all = idx.all_hashes().unwrap();
        assert_eq!(all, vec![h2]);
    }

    #[test]
    fn l2_input_index_is_populated() {
        let store = Arc::new(MemoryDb::default());
        let idx = L2InputIndex::new(store);

        assert!(!idx.is_populated().unwrap());
        idx.put(&l2_hash(0xFF)).unwrap();
        assert!(idx.is_populated().unwrap());
    }

    #[test]
    fn l2_input_index_duplicate_put_is_idempotent() {
        let store = Arc::new(MemoryDb::default());
        let idx = L2InputIndex::new(store);
        let h = l2_hash(0x42);

        idx.put(&h).unwrap();
        idx.put(&h).unwrap(); // second put must not panic or duplicate
        assert_eq!(idx.all_hashes().unwrap().len(), 1);
    }

    // ── L2JobStore tests ──────────────────────────────────────────────────

    fn make_job(seed: u8, status: L2JobStatus, start: u64, end: u64) -> L2AggregationJob {
        let h1 = l2_hash(seed);
        let h2 = l2_hash(seed.wrapping_add(1));
        let hashes = vec![h1, h2];
        let id = L2AggregationJob::compute_id(&hashes);
        L2AggregationJob {
            id,
            status,
            l1_source_hashes: hashes,
            start_block: start,
            end_block: end,
            l1_batch_roots: vec![[seed; 32]],
            aggregate_root: None,
            retry_count: 0,
            last_error: None,
            created_at_block: start,
            updated_at_block: start,
        }
    }

    #[test]
    fn l2_job_store_put_get_delete() {
        let store = Arc::new(MemoryDb::default());
        let js = L2JobStore::new(store);
        let job = make_job(1, L2JobStatus::PendingInputs, 10, 20);

        assert!(js.get(&job.id).unwrap().is_none());
        js.put(&job).unwrap();
        let retrieved = js.get(&job.id).unwrap().unwrap();
        assert_eq!(retrieved.id, job.id);
        assert_eq!(retrieved.status, L2JobStatus::PendingInputs);
        assert_eq!(retrieved.start_block, 10);

        js.delete(&job.id).unwrap();
        assert!(js.get(&job.id).unwrap().is_none());
    }

    #[test]
    fn l2_job_store_all_jobs_and_filter_by_status() {
        let store = Arc::new(MemoryDb::default());
        let js = L2JobStore::new(store);

        let j1 = make_job(10, L2JobStatus::Ready, 1, 5);
        let j2 = make_job(20, L2JobStatus::Proving, 6, 10);
        let j3 = make_job(30, L2JobStatus::Ready, 11, 15);
        js.put(&j1).unwrap();
        js.put(&j2).unwrap();
        js.put(&j3).unwrap();

        assert_eq!(js.all_jobs().unwrap().len(), 3);

        let ready = js.jobs_with_status(L2JobStatus::Ready).unwrap();
        assert_eq!(ready.len(), 2);

        let proving = js.jobs_with_status(L2JobStatus::Proving).unwrap();
        assert_eq!(proving.len(), 1);
        assert_eq!(proving[0].start_block, 6);
    }

    #[test]
    fn l2_job_store_update_status() {
        let store = Arc::new(MemoryDb::default());
        let js = L2JobStore::new(store);
        let job = make_job(40, L2JobStatus::Ready, 20, 30);
        js.put(&job).unwrap();

        js.update_status(&job.id, L2JobStatus::Proving, 25, None)
            .unwrap();
        let updated = js.get(&job.id).unwrap().unwrap();
        assert_eq!(updated.status, L2JobStatus::Proving);
        assert_eq!(updated.updated_at_block, 25);
        assert!(updated.last_error.is_none());

        js.update_status(
            &job.id,
            L2JobStatus::FailedRetryable,
            26,
            Some("prover timeout".into()),
        )
        .unwrap();
        let failed = js.get(&job.id).unwrap().unwrap();
        assert_eq!(failed.status, L2JobStatus::FailedRetryable);
        assert_eq!(failed.last_error.as_deref(), Some("prover timeout"));
    }

    #[test]
    fn l2_job_store_is_populated() {
        let store = Arc::new(MemoryDb::default());
        let js = L2JobStore::new(store);

        assert!(!js.is_populated().unwrap());
        js.put(&make_job(50, L2JobStatus::PendingInputs, 0, 10))
            .unwrap();
        assert!(js.is_populated().unwrap());
    }

    #[test]
    fn l2_job_compute_id_is_order_independent() {
        let h1 = l2_hash(1);
        let h2 = l2_hash(2);
        let id_ab = L2AggregationJob::compute_id(&[h1, h2]);
        let id_ba = L2AggregationJob::compute_id(&[h2, h1]);
        assert_eq!(id_ab, id_ba);
    }

    #[test]
    fn l2_job_store_put_is_idempotent() {
        let store = Arc::new(MemoryDb::default());
        let js = L2JobStore::new(store);
        let job = make_job(60, L2JobStatus::PendingInputs, 5, 15);

        js.put(&job).unwrap();
        js.put(&job).unwrap();
        assert_eq!(js.all_jobs().unwrap().len(), 1);
    }
}
