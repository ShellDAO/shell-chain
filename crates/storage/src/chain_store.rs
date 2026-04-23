use std::sync::Arc;

use alloy_rlp::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use shell_core::{Block, BlockHeader, StrippedBlock, TransactionReceipt};
use shell_primitives::{Address, ShellHash};

use crate::{KvStore, StorageError};

/// Persistent chain configuration (written once at genesis).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_hash: ShellHash,
}

/// Storage format version bytes for migration compatibility.
mod format_version {
    /// Legacy JSON format.
    pub const JSON: u8 = 0x01;
    /// RLP binary format (current).
    pub const RLP: u8 = 0x02;
}

/// Maximum supported offset for address transaction history pagination.
///
/// Deep pagination currently relies on a prefix scan, so offsets beyond this
/// threshold are rejected explicitly instead of degrading into unbounded work.
pub const MAX_ADDRESS_TX_HISTORY_OFFSET: usize = 10_000;

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
    pub const TX_INDEX: &[u8] = b"t/";
    pub const HEAD_BLOCK: &[u8] = b"HEAD";
    pub const CHAIN_CONFIG: &[u8] = b"CFG";
    pub const CODE_BY_HASH: &[u8] = b"c/";
    pub const PUBKEY_BY_ADDR: &[u8] = b"pk/";
    /// Address → tx_hash index: key = "a/" + address(20) + block_number(8) + tx_index(4)
    pub const ADDR_TX_INDEX: &[u8] = b"a/";
}

/// Block/receipt/transaction-index storage.
///
/// Provides chain-level data access: store and retrieve blocks by number or
/// hash, store transaction receipts, and maintain a transaction → block index.
pub struct ChainStore<S: KvStore> {
    store: Arc<S>,
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

    /// Returns a reference to the underlying key-value store.
    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Approximate total byte size of all values stored under a given key prefix.
    ///
    /// Scans the prefix and sums `key.len() + value.len()` for each entry.
    /// This is an O(n) operation and should only be called on low-frequency
    /// paths (e.g., the 10-second metrics tick).  Returns `Ok(0)` for empty
    /// prefixes; propagates storage errors.
    pub fn approximate_prefix_bytes(&self, prefix: &[u8]) -> Result<u64, StorageError> {
        let entries = self.store.scan_prefix(prefix)?;
        let total: u64 = entries
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum();
        Ok(total)
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

    fn tx_index_key(tx_hash: &ShellHash) -> Vec<u8> {
        [prefix::TX_INDEX, tx_hash.as_bytes()].concat()
    }

    /// Key for address→tx index: "a/" + address(20) + block_number(8 BE) + tx_index(4 BE)
    fn addr_tx_key(address: &Address, block_number: u64, tx_index: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 20 + 8 + 4);
        key.extend_from_slice(prefix::ADDR_TX_INDEX);
        key.extend_from_slice(address.as_ref());
        key.extend_from_slice(&block_number.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Prefix for scanning all txs of a given address.
    fn addr_tx_prefix(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 20);
        key.extend_from_slice(prefix::ADDR_TX_INDEX);
        key.extend_from_slice(address.as_ref());
        key
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
        let block_hash = block.hash();
        let block_number = block.number();

        // Store header (RLP with version prefix)
        let header_bytes = encode_rlp(&block.header);
        self.store
            .put(&Self::header_key(&block_hash), &header_bytes)?;

        // Split block into stripped body + witness bundle and store separately.
        let (stripped, bundle) = StrippedBlock::split(block);
        let body_bytes = encode_rlp(&stripped);
        self.store.put(&Self::body_key(&block_hash), &body_bytes)?;

        // Only persist witness bundle when there are transactions to witness.
        // Empty blocks have no PQ material, so omitting the entry is correct
        // and allows WitnessPruner to distinguish "no bundle" from "pruned".
        if !bundle.is_empty() {
            let mut witness_buf = Vec::new();
            bundle.encode(&mut witness_buf);
            self.store
                .put(&Self::witness_key(&block_hash), &witness_buf)?;
        }

        // Transaction → (block_hash, tx_index) mapping + address index
        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_hash = tx.hash();
            let mut index_value = block_hash.as_bytes().to_vec();
            index_value.extend_from_slice(&(i as u32).to_be_bytes());
            self.store
                .put(&Self::tx_index_key(&tx_hash), &index_value)?;

            // Address index: sender
            let idx = i as u32;
            self.store.put(
                &Self::addr_tx_key(&tx.sender(), block_number, idx),
                tx_hash.as_bytes(),
            )?;
            // Address index: recipient (if not contract creation)
            if let Some(to) = tx.tx.to {
                if to != tx.sender() {
                    self.store.put(
                        &Self::addr_tx_key(&to, block_number, idx),
                        tx_hash.as_bytes(),
                    )?;
                }
            }
        }

        Ok(())
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

    /// Returns `true` if a stripped body (`b/<hash>`) is stored for the given block hash.
    ///
    /// Used by the historical body sync to detect pruned blocks.
    pub fn has_body(&self, hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::body_key(hash))?.is_some())
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
    // This is the foundation of L3 state-trie pruning; actual trie-node
    // eviction is gated behind `PruningConfig::state_pruning_experimental`.

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
    /// Returns tx hashes in ascending block order, paginated by `offset` and `limit`.
    pub fn get_txs_by_address(
        &self,
        address: &Address,
        from_block: u64,
        to_block: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ShellHash>, StorageError> {
        if offset > MAX_ADDRESS_TX_HISTORY_OFFSET {
            return Err(StorageError::InvalidInput(format!(
                "transaction history offset {offset} exceeds max {}",
                MAX_ADDRESS_TX_HISTORY_OFFSET
            )));
        }

        if limit == 0 {
            return Ok(Vec::new());
        }

        let prefix = Self::addr_tx_prefix(address);
        let entries = self.store.scan_prefix(&prefix)?;

        let mut tx_hashes = Vec::with_capacity(limit);
        let mut matched = 0usize;
        for (key, value) in &entries {
            let Ok(block_number) = Self::block_number_from_addr_index_key(prefix.len(), key) else {
                continue;
            };
            if block_number < from_block || block_number > to_block {
                continue;
            }
            if value.len() == 32 {
                if matched < offset {
                    matched = matched.saturating_add(1);
                    continue;
                }

                let hash = ShellHash::try_from_slice(value)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                tx_hashes.push(hash);
                matched = matched.saturating_add(1);
                if tx_hashes.len() == limit {
                    break;
                }
            }
        }

        Ok(tx_hashes)
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
    pub fn import_snapshot<R: std::io::Read>(
        &self,
        reader: R,
        expected_chain_id: u64,
        expected_genesis_hash: &ShellHash,
    ) -> Result<crate::SnapshotMetadata, StorageError> {
        let mut snap_reader = crate::SnapshotReader::new(reader)?;
        let metadata = snap_reader.metadata().clone();

        // Validate compatibility
        metadata.validate_compatibility(expected_chain_id, expected_genesis_hash)?;

        // Import all entries
        let mut batch = crate::WriteBatch::new();
        let mut count = 0u64;
        while let Some(entry) = snap_reader.next_entry()? {
            batch.put(entry.key, entry.value);
            count = count.saturating_add(1);

            // Flush in batches of 10000 to avoid excessive memory use
            if count.is_multiple_of(10_000) {
                self.store.write_batch(batch)?;
                batch = crate::WriteBatch::new();
            }
        }

        // Flush remaining
        if !batch.is_empty() {
            self.store.write_batch(batch)?;
        }

        // Verify state_root: if a head block was imported, its state_root
        // must match the snapshot metadata to prevent state injection.
        if let Ok(Some(head)) = self.get_head_block() {
            if head.header.state_root != metadata.state_root {
                return Err(StorageError::State(format!(
                    "snapshot state_root mismatch: block has {:?}, metadata has {:?}",
                    head.header.state_root, metadata.state_root
                )));
            }
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
            _ => Ok(None),
        }
    }

    /// Store the total transaction count across all blocks.
    pub fn set_total_tx_count(&self, count: u64) -> Result<(), StorageError> {
        self.store.put(b"TOTAL_TX_COUNT", &count.to_be_bytes())
    }

    /// Get the total transaction count across all blocks.
    pub fn get_total_tx_count(&self) -> Result<u64, StorageError> {
        match self.store.get(b"TOTAL_TX_COUNT")? {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Codec("invalid tx count encoding".into()))?;
                Ok(u64::from_be_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    /// Increment the total transaction count by `delta` and persist.
    pub fn increment_tx_count(&self, delta: u64) -> Result<u64, StorageError> {
        let current = self.get_total_tx_count()?;
        let new_count = current.saturating_add(delta);
        self.set_total_tx_count(new_count)?;
        Ok(new_count)
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

    /// Returns `true` if a witness bundle exists for the given block hash.
    pub fn has_bundle(&self, block_hash: &ShellHash) -> Result<bool, StorageError> {
        Ok(self.store.get(&Self::key(block_hash))?.is_some())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryDb;
    use shell_primitives::{Address, Bytes};

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
    fn test_import_snapshot_validates_chain_id() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);

        // Create a snapshot with chain_id=1337
        let meta = crate::SnapshotMetadata::new(
            1337,
            10,
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
            10,
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
        assert_eq!(page, vec![ShellHash::from([3u8; 32])]);
    }

    #[test]
    fn test_get_txs_by_address_rejects_deep_offset() {
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store);
        let address = Address::from([0x22; 20]);

        let result =
            cs.get_txs_by_address(&address, 0, u64::MAX, MAX_ADDRESS_TX_HISTORY_OFFSET + 1, 1);
        assert!(matches!(result, Err(StorageError::InvalidInput(_))));
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
}
