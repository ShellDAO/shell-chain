//! Core transaction pool implementation.

use std::collections::{BTreeMap, HashMap};

use parking_lot::RwLock;

use shell_core::SignedTransaction;
use shell_crypto::Verifier;
use shell_evm::{
    compute_intrinsic_gas, validate_aa_bundle_structure, validate_aa_tx, AaValidationError,
    AaValidationOutcome, TxValidationError,
};
use shell_primitives::{Address, ShellHash, U256};
use shell_storage::{ChainStore, KvStore, WorldState};

use crate::{MempoolConfig, MempoolError};

/// Maximum serialized transaction size accepted by the mempool (128 KB).
///
/// Protects against oversized SPHINCS+ signatures (~49 KB) and large
/// access lists flooding the pool.
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// Thread-safe transaction pool.
///
/// Accepts validated transactions, orders them by priority fee, enforces
/// per-sender nonce ordering, and provides block-building APIs.
///
/// # Ordering
///
/// Transactions are globally ordered by `(max_priority_fee_per_gas DESC, nonce ASC)`.
/// Within a single sender queue, transactions are strictly nonce-ordered.
///
/// # Thread Safety
///
/// All public methods acquire an internal `RwLock`. The pool is `Send + Sync`.
pub struct TxPool {
    config: MempoolConfig,
    inner: RwLock<PoolInner>,
}

/// Internal mutable state behind the lock.
struct PoolInner {
    /// All transactions by hash for O(1) lookup.
    by_hash: HashMap<ShellHash, PoolEntry>,
    /// Per-sender queues ordered by nonce.
    by_sender: HashMap<Address, BTreeMap<u64, ShellHash>>,
    /// Global ordering index: (priority_fee DESC, arrival_seq ASC) → tx hash.
    /// Uses negated priority_fee for natural BTreeMap ascending order.
    by_priority: BTreeMap<PriorityKey, ShellHash>,
    /// Monotonic counter for FIFO tie-breaking at equal fee levels.
    seq: u64,
}

/// Entry in the pool holding the transaction and metadata.
struct PoolEntry {
    tx: SignedTransaction,
    priority_key: PriorityKey,
}

/// Composite ordering key: higher fee first, then earlier arrival first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PriorityKey {
    /// Negated priority fee so BTreeMap ascending = highest fee first.
    neg_priority_fee: i128,
    /// Monotonic sequence number for FIFO within same fee tier.
    seq: u64,
}

impl TxPool {
    /// Create a new transaction pool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            inner: RwLock::new(PoolInner {
                by_hash: HashMap::new(),
                by_sender: HashMap::new(),
                by_priority: BTreeMap::new(),
                seq: 0,
            }),
        }
    }

    /// Insert a signed transaction into the pool after lightweight validation.
    ///
    /// Performs: chain ID check, gas price floor, signature verification,
    /// address derivation, balance floor check, duplicate/RBF detection,
    /// and capacity enforcement.
    ///
    pub fn insert<S: KvStore + 'static, V: Verifier>(
        &self,
        tx: SignedTransaction,
        world_state: &mut WorldState<S>,
        chain_store: &ChainStore<S>,
        verifier: &V,
    ) -> Result<ShellHash, MempoolError> {
        // --- Stateless checks (before acquiring lock) ---
        let validation = self.validate_stateless(&tx, world_state, chain_store, verifier)?;
        if validation.should_register_pubkey {
            chain_store
                .put_pubkey(&tx.from, &validation.pubkey)
                .map_err(MempoolError::Storage)?;
        }

        // --- Balance floor check (F-020) ---
        let sender = tx.sender();
        let gas_cost = U256::from(tx.tx.gas_limit)
            .checked_mul(U256::from(tx.tx.max_fee_per_gas))
            .unwrap_or(U256::MAX);

        // For AA bundles with a paymaster, gas is covered by the paymaster.
        // For all other transactions (including batch-only AA), the sender pays.
        let payer = tx
            .aa_bundle()
            .and_then(|b| b.paymaster)
            .filter(|pm| *pm != sender)
            .unwrap_or(sender);

        let payer_gas_balance = world_state.get_balance(&payer).unwrap_or(U256::ZERO);
        if payer_gas_balance < gas_cost {
            return Err(MempoolError::InsufficientBalance {
                needed: gas_cost,
                have: payer_gas_balance,
            });
        }

        // Sender must still cover the transferred value even when paymaster pays gas.
        let needed_for_value = tx.tx.value;
        let sender_balance = world_state.get_balance(&sender).unwrap_or(U256::ZERO);
        if payer != sender {
            // Paymaster covers gas; only check sender has enough for the value transfer.
            if sender_balance < needed_for_value {
                return Err(MempoolError::InsufficientBalance {
                    needed: needed_for_value,
                    have: sender_balance,
                });
            }
        } else {
            // Non-paymaster path: sender covers both gas and value.
            let needed = gas_cost.checked_add(tx.tx.value).unwrap_or(U256::MAX);
            if sender_balance < needed {
                return Err(MempoolError::InsufficientBalance {
                    needed,
                    have: sender_balance,
                });
            }
        }

        let hash = tx.hash();
        let nonce = tx.tx.nonce;
        let priority_fee = tx.tx.max_priority_fee_per_gas;
        let chain_nonce = world_state
            .get_nonce(&sender)
            .map_err(MempoolError::Storage)?;

        // --- Stateful checks (under write lock) ---
        let mut inner = self.inner.write();

        // Duplicate check
        if inner.by_hash.contains_key(&hash) {
            return Err(MempoolError::Duplicate { hash });
        }

        let sender_q = inner.by_sender.get(&sender);
        let existing_hash = sender_q.and_then(|q| q.get(&nonce).copied());
        let expected_next_nonce = next_expected_nonce(sender_q, chain_nonce);

        if nonce < chain_nonce {
            return Err(MempoolError::NonceTooLow {
                got: nonce,
                pending: chain_nonce,
            });
        }

        // Same-nonce handling: RBF replacement (F-021)
        if let Some(existing_hash) = existing_hash {
            // Check fee bump threshold
            let old_fee = inner
                .by_hash
                .get(&existing_hash)
                .map(|e| e.tx.tx.max_priority_fee_per_gas)
                .unwrap_or(0);
            let bump = self.config.replacement_fee_bump_pct;
            // required = old_fee * (100 + bump) / 100, rounded up
            let required = old_fee
                .checked_mul(100 + bump)
                .map(|v| v / 100)
                .unwrap_or(u64::MAX);
            if priority_fee < required {
                return Err(MempoolError::ReplacementFeeTooLow {
                    got: priority_fee,
                    required,
                });
            }
            // Evict old tx at this nonce
            Self::remove_entry(&mut inner, &existing_hash);
        } else if nonce > expected_next_nonce {
            return Err(MempoolError::NonceGap {
                expected: expected_next_nonce,
                got: nonce,
            });
        } else if nonce < expected_next_nonce {
            return Err(MempoolError::NonceTooLow {
                got: nonce,
                pending: expected_next_nonce,
            });
        }

        // Per-sender limit (checked after possible RBF eviction)
        let sender_count = inner.by_sender.get(&sender).map_or(0, |q| q.len());
        if sender_count >= self.config.max_per_sender {
            return Err(MempoolError::SenderQueueFull {
                sender,
                count: sender_count,
            });
        }

        // Pool full — evict lowest priority tx
        if inner.by_hash.len() >= self.config.max_pool_size {
            if let Some((&evict_key, _)) = inner.by_priority.last_key_value() {
                let incoming_neg = -(priority_fee as i128);
                if incoming_neg >= evict_key.neg_priority_fee {
                    return Err(MempoolError::PoolFull {
                        capacity: self.config.max_pool_size,
                    });
                }
                if let Some(evict_hash) = inner.by_priority.remove(&evict_key) {
                    Self::remove_entry(&mut inner, &evict_hash);
                }
            } else {
                return Err(MempoolError::PoolFull {
                    capacity: self.config.max_pool_size,
                });
            }
        }

        // --- Insert ---
        let seq = inner.seq;
        inner.seq += 1;

        let priority_key = PriorityKey {
            neg_priority_fee: -(priority_fee as i128),
            seq,
        };

        inner.by_priority.insert(priority_key, hash);
        inner
            .by_sender
            .entry(sender)
            .or_default()
            .insert(nonce, hash);
        inner.by_hash.insert(hash, PoolEntry { tx, priority_key });

        Ok(hash)
    }

    /// Remove a transaction from the pool by hash.
    ///
    /// Returns `true` if the transaction was found and removed.
    pub fn remove(&self, hash: &ShellHash) -> bool {
        let mut inner = self.inner.write();
        Self::remove_entry(&mut inner, hash)
    }

    /// Remove a batch of transactions (e.g., after block inclusion).
    pub fn remove_batch(&self, hashes: &[ShellHash]) {
        let mut inner = self.inner.write();
        for hash in hashes {
            Self::remove_entry(&mut inner, hash);
        }
    }

    /// Remove all transactions from the pool.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.by_hash.clear();
        inner.by_sender.clear();
        inner.by_priority.clear();
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &ShellHash) -> Option<SignedTransaction> {
        let inner = self.inner.read();
        inner.by_hash.get(hash).map(|e| e.tx.clone())
    }

    /// Check if a transaction is in the pool.
    pub fn contains(&self, hash: &ShellHash) -> bool {
        self.inner.read().by_hash.contains_key(hash)
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().by_hash.is_empty()
    }

    /// Number of pending transactions for a specific sender.
    pub fn sender_count(&self, sender: &Address) -> usize {
        let inner = self.inner.read();
        inner.by_sender.get(sender).map_or(0, |q| q.len())
    }

    /// Collect the best transactions for block building, up to `limit`.
    ///
    /// Returns transactions ordered by priority fee (highest first).
    /// Within a sender, transactions are nonce-ordered.
    pub fn pending(&self, limit: usize) -> Vec<SignedTransaction> {
        let inner = self.inner.read();
        let mut result = Vec::with_capacity(limit.min(inner.by_hash.len()));

        for (_key, hash) in inner.by_priority.iter() {
            if result.len() >= limit {
                break;
            }
            if let Some(entry) = inner.by_hash.get(hash) {
                result.push(entry.tx.clone());
            }
        }
        result
    }

    /// Collect all pending transaction hashes for a specific sender,
    /// ordered by nonce ascending.
    pub fn sender_txs(&self, sender: &Address) -> Vec<ShellHash> {
        let inner = self.inner.read();
        inner
            .by_sender
            .get(sender)
            .map(|q| q.values().copied().collect())
            .unwrap_or_default()
    }

    // --- Private helpers ---

    /// Lightweight validation performed before acquiring the pool lock.
    fn validate_stateless<S: KvStore + 'static, V: Verifier>(
        &self,
        tx: &SignedTransaction,
        world_state: &mut WorldState<S>,
        chain_store: &ChainStore<S>,
        verifier: &V,
    ) -> Result<AaValidationOutcome, MempoolError> {
        // Chain ID
        if tx.tx.chain_id != self.config.chain_id {
            return Err(MempoolError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: tx.tx.chain_id,
            });
        }

        // Minimum gas price
        if tx.tx.max_fee_per_gas < self.config.min_gas_price {
            return Err(MempoolError::GasPriceTooLow {
                got: tx.tx.max_fee_per_gas,
                min: self.config.min_gas_price,
            });
        }

        // Access list size limits
        if let Err(msg) = tx.tx.validate_access_list() {
            return Err(MempoolError::InvalidTransaction(msg.to_string()));
        }

        // Blob transaction validation (F-233)
        if tx.tx.tx_type == 3 {
            if let Err(msg) = tx.tx.validate_blob_tx() {
                return Err(MempoolError::InvalidTransaction(msg.to_string()));
            }
        }

        // AA bundle structural pre-check (M2 native AA): consistency between
        // tx_type and aa_bundle, MAX_INNER_CALLS / MAX_INNER_CALLDATA, and
        // inner-gas budget vs outer gas_limit. Returns the additional
        // intrinsic-gas surcharge for AA txs (zero otherwise).
        let aa_extra_gas = validate_aa_bundle_structure(tx)
            .map_err(|e: TxValidationError| MempoolError::InvalidTransaction(e.to_string()))?;

        let intrinsic = compute_intrinsic_gas(
            tx.tx.data.as_ref(),
            tx.tx.is_contract_creation(),
            &tx.tx.access_list,
        )
        .saturating_add(aa_extra_gas);
        if tx.tx.gas_limit < intrinsic {
            return Err(MempoolError::GasTooLow {
                got: tx.tx.gas_limit,
                minimum: intrinsic,
            });
        }

        // Per-tx serialized size limit — protects against oversized PQ
        // signatures and access lists.
        let tx_size = serde_json::to_vec(tx).map(|v| v.len()).map_err(|e| {
            MempoolError::InvalidTransaction(format!("tx serialization failed: {e}"))
        })?;
        if tx_size > MAX_TX_SIZE {
            return Err(MempoolError::InvalidTransaction(format!(
                "transaction too large: {} bytes (max {})",
                tx_size, MAX_TX_SIZE
            )));
        }

        validate_aa_tx(tx, world_state, chain_store, verifier)
            .map_err(|err| map_aa_validation_error(tx, err))
    }

    /// Remove a single entry from all indexes. Caller holds write lock.
    fn remove_entry(inner: &mut PoolInner, hash: &ShellHash) -> bool {
        if let Some(entry) = inner.by_hash.remove(hash) {
            let sender = entry.tx.sender();
            let nonce = entry.tx.tx.nonce;

            // Remove from priority index
            inner.by_priority.remove(&entry.priority_key);

            // Remove from sender queue
            if let Some(sender_q) = inner.by_sender.get_mut(&sender) {
                sender_q.remove(&nonce);
                if sender_q.is_empty() {
                    inner.by_sender.remove(&sender);
                }
            }
            true
        } else {
            false
        }
    }
}

fn map_aa_validation_error(tx: &SignedTransaction, err: AaValidationError) -> MempoolError {
    match err {
        AaValidationError::PubkeyNotFound => MempoolError::PubkeyRequired {
            sender: tx.sender(),
        },
        AaValidationError::AddressMismatch { from, derived } => {
            MempoolError::AddressMismatch { from, derived }
        }
        AaValidationError::SignatureInvalid => {
            MempoolError::InvalidSignature("PQ signature verification failed".into())
        }
        AaValidationError::Crypto(err) => MempoolError::Crypto(err),
        AaValidationError::DisallowedAlgorithm(sig_type) => MempoolError::InvalidTransaction(
            format!("disallowed signature algorithm: {sig_type:?}"),
        ),
        other => MempoolError::InvalidTransaction(other.to_string()),
    }
}

fn next_expected_nonce(sender_q: Option<&BTreeMap<u64, ShellHash>>, chain_nonce: u64) -> u64 {
    let mut expected = chain_nonce;
    if let Some(sender_q) = sender_q {
        for queued_nonce in sender_q.keys() {
            if *queued_nonce < expected {
                continue;
            }
            if *queued_nonce == expected {
                expected = expected.saturating_add(1);
                continue;
            }
            break;
        }
    }
    expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::Transaction;
    use shell_crypto::{DilithiumSigner, DilithiumVerifier, Signer};
    use shell_primitives::Bytes;
    use shell_storage::{ChainStore, MemoryDb, WorldState};
    use std::sync::Arc;

    fn test_address(seed: &[u8]) -> Address {
        Address::from_public_key(seed, 0)
    }

    fn make_config() -> MempoolConfig {
        MempoolConfig {
            max_pool_size: 10,
            max_per_sender: 4,
            chain_id: 42,
            min_gas_price: 1,
            replacement_fee_bump_pct: 10,
        }
    }

    /// Create a signed transaction from a fresh keypair.
    fn make_signed_tx(nonce: u64, priority_fee: u64) -> (SignedTransaction, Vec<u8>) {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);

        let tx = Transaction {
            chain_id: 42,
            nonce,
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: priority_fee + 10,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pubkey.clone());
        (signed, pubkey)
    }

    /// Convenience: create a signed tx from an existing signer for multi-nonce tests.
    fn make_signed_tx_with_signer(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        nonce: u64,
        priority_fee: u64,
    ) -> SignedTransaction {
        let from = test_address(pubkey);
        let tx = Transaction {
            chain_id: 42,
            nonce,
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: priority_fee + 10,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey.to_vec())
    }

    fn setup_validation_ctx() -> (WorldState<MemoryDb>, ChainStore<MemoryDb>) {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        (ws, cs)
    }

    fn insert_with_balance(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<MemoryDb>,
        cs: &ChainStore<MemoryDb>,
        balance: U256,
    ) -> Result<ShellHash, MempoolError> {
        ws.set_balance(&tx.sender(), balance).unwrap();
        pool.insert(tx, ws, cs, verifier)
    }

    fn insert_rich(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<MemoryDb>,
        cs: &ChainStore<MemoryDb>,
    ) -> Result<ShellHash, MempoolError> {
        insert_with_balance(pool, tx, verifier, ws, cs, U256::from(1_000_000_000_000u64))
    }

    fn insert_broke(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<MemoryDb>,
        cs: &ChainStore<MemoryDb>,
    ) -> Result<ShellHash, MempoolError> {
        insert_with_balance(pool, tx, verifier, ws, cs, U256::ZERO)
    }

    #[test]
    fn insert_and_get() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (tx, _pk) = make_signed_tx(0, 100);
        let hash = tx.hash();

        let result = insert_rich(&pool, tx, &verifier, &mut ws, &cs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hash);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));
        assert!(pool.get(&hash).is_some());
    }

    #[test]
    fn reject_duplicate() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (tx, _pk) = make_signed_tx(0, 100);

        insert_rich(&pool, tx.clone(), &verifier, &mut ws, &cs).unwrap();
        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::Duplicate { .. }));
    }

    #[test]
    fn reject_wrong_chain_id() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 999, // wrong
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pubkey);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::ChainIdMismatch { .. }));
    }

    #[test]
    fn reject_gas_price_too_low() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 0, // below min_gas_price=1
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pubkey);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::GasPriceTooLow { .. }));
    }

    #[test]
    fn reject_under_intrinsic_gas() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value: Default::default(),
            data: Bytes::copy_from_slice(&[0xde, 0xad]),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pubkey);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::GasTooLow { .. }));
    }

    #[test]
    fn reject_invalid_signature() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        // Sign a different message to produce invalid sig
        let bad_sig = signer.sign(b"wrong-message").unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, bad_sig, pubkey);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::InvalidSignature(_)));
    }

    #[test]
    fn reject_address_mismatch() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let wrong_from = test_address(b"different-key-bytes");
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(wrong_from, tx, sig, pubkey);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::AddressMismatch { .. }));
    }

    #[test]
    fn reject_missing_pubkey() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        // No pubkey attached, and lookup returns None
        let signed = SignedTransaction::new(from, tx, sig);

        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::PubkeyRequired { .. }));
    }

    #[test]
    fn first_transaction_registers_pubkey_for_follow_up_sends() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");

        let tx0 = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig0 = signer.sign(tx0.hash().as_bytes()).unwrap();
        let first = SignedTransaction::with_pubkey(from, tx0, sig0, pubkey.clone());
        insert_rich(&pool, first, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(cs.get_pubkey(&from).unwrap(), Some(pubkey));

        let tx1 = Transaction {
            chain_id: 42,
            nonce: 1,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig1 = signer.sign(tx1.hash().as_bytes()).unwrap();
        let follow_up = SignedTransaction::new(from, tx1, sig1);
        insert_rich(&pool, follow_up, &verifier, &mut ws, &cs).unwrap();
    }

    #[test]
    fn remove_transaction() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (tx, _pk) = make_signed_tx(0, 100);
        let hash = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap();

        assert!(pool.remove(&hash));
        assert!(!pool.contains(&hash));
        assert_eq!(pool.len(), 0);
        assert!(!pool.remove(&hash)); // already gone
    }

    #[test]
    fn remove_batch() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let (tx1, _) = make_signed_tx(0, 100);
        let (tx2, _) = make_signed_tx(0, 200);
        let h1 = insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        let h2 = insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();

        pool.remove_batch(&[h1, h2]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pending_ordered_by_priority_fee() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let (tx_low, _) = make_signed_tx(0, 10);
        let (tx_mid, _) = make_signed_tx(0, 50);
        let (tx_high, _) = make_signed_tx(0, 100);

        insert_rich(&pool, tx_low, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx_mid, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx_high, &verifier, &mut ws, &cs).unwrap();

        let pending = pool.pending(10);
        assert_eq!(pending.len(), 3);
        // Highest priority fee first
        assert_eq!(pending[0].tx.max_priority_fee_per_gas, 100);
        assert_eq!(pending[1].tx.max_priority_fee_per_gas, 50);
        assert_eq!(pending[2].tx.max_priority_fee_per_gas, 10);
    }

    #[test]
    fn per_sender_nonce_ordering() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);

        let tx0 = make_signed_tx_with_signer(&signer, &pubkey, 0, 50);
        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, 1, 50);
        let tx2 = make_signed_tx_with_signer(&signer, &pubkey, 2, 50);
        let hash0 = tx0.hash();
        let hash1 = tx1.hash();
        let hash2 = tx2.hash();

        insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        let err = insert_rich(&pool, tx2.clone(), &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(
            err,
            MempoolError::NonceGap {
                expected: 1,
                got: 2
            }
        ));
        insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();

        let sender_hashes = pool.sender_txs(&sender);
        assert_eq!(sender_hashes.len(), 3);
        assert_eq!(sender_hashes, vec![hash0, hash1, hash2]);
        assert_eq!(pool.sender_count(&sender), 3);
    }

    #[test]
    fn sender_queue_full() {
        let config = MempoolConfig {
            max_per_sender: 2,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        let tx0 = make_signed_tx_with_signer(&signer, &pubkey, 0, 50);
        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, 1, 50);
        let tx2 = make_signed_tx_with_signer(&signer, &pubkey, 2, 50);

        insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        let err = insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::SenderQueueFull { .. }));
    }

    #[test]
    fn pool_full_evicts_lowest_priority() {
        let config = MempoolConfig {
            max_pool_size: 2,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let (tx_low, _) = make_signed_tx(0, 10);
        let (tx_mid, _) = make_signed_tx(0, 50);
        let low_hash = tx_low.hash();

        insert_rich(&pool, tx_low, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx_mid, &verifier, &mut ws, &cs).unwrap();

        // Pool is full. Insert a higher priority tx — should evict tx_low.
        let (tx_high, _) = make_signed_tx(0, 100);
        insert_rich(&pool, tx_high, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&low_hash)); // evicted
    }

    #[test]
    fn pool_full_rejects_low_priority() {
        let config = MempoolConfig {
            max_pool_size: 2,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let (tx1, _) = make_signed_tx(0, 50);
        let (tx2, _) = make_signed_tx(0, 100);
        insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();

        // Try to insert a tx with lower priority than worst in pool
        let (tx_too_low, _) = make_signed_tx(0, 5);
        let err = insert_rich(&pool, tx_too_low, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::PoolFull { .. }));
    }

    #[test]
    fn known_pubkey_lookup() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(recipient),
            value: Default::default(),
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        // NO pubkey in transaction — rely on lookup
        let signed = SignedTransaction::new(from, tx, sig);

        cs.put_pubkey(&from, &pubkey).unwrap();
        let result = insert_rich(&pool, signed, &verifier, &mut ws, &cs);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_pool() {
        let pool = TxPool::new(make_config());
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.pending(10).len(), 0);
    }

    // --- F-020: Balance check tests ---

    #[test]
    fn reject_insufficient_balance() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (tx, _pk) = make_signed_tx(0, 100);

        let err = insert_broke(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
    }

    #[test]
    fn accept_exact_balance() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (tx, _pk) = make_signed_tx(0, 100);

        // gas_limit=21000, max_fee=110, value=0 → need 21000*110 = 2_310_000
        let result = insert_with_balance(
            &pool,
            tx,
            &verifier,
            &mut ws,
            &cs,
            U256::from(21_000u64 * 110),
        );
        assert!(result.is_ok());
    }

    // --- F-021: RBF tests ---

    #[test]
    fn rbf_replaces_with_sufficient_fee_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        // Insert tx at nonce 0 with priority_fee=100
        let tx_old = make_signed_tx_with_signer(&signer, &pubkey, 0, 100);
        let old_hash = tx_old.hash();
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();

        // Replace with priority_fee=111 (>= 110% of 100)
        let tx_new = make_signed_tx_with_signer(&signer, &pubkey, 0, 111);
        let new_hash = tx_new.hash();
        insert_rich(&pool, tx_new, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&old_hash));
        assert!(pool.contains(&new_hash));
    }

    #[test]
    fn rbf_rejects_insufficient_fee_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        // Insert tx at nonce 0 with priority_fee=100
        let tx_old = make_signed_tx_with_signer(&signer, &pubkey, 0, 100);
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();

        // Try to replace with priority_fee=105 (< 110% of 100)
        let tx_new = make_signed_tx_with_signer(&signer, &pubkey, 0, 105);
        let err = insert_rich(&pool, tx_new, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
        assert_eq!(pool.len(), 1); // old tx still there
    }

    #[test]
    fn rbf_custom_bump_percentage() {
        let config = MempoolConfig {
            replacement_fee_bump_pct: 20, // 20% bump required
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        let tx_old = make_signed_tx_with_signer(&signer, &pubkey, 0, 100);
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();

        // 115 < 120% of 100 → reject
        let tx_low = make_signed_tx_with_signer(&signer, &pubkey, 0, 115);
        let err = insert_rich(&pool, tx_low, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));

        // 120 >= 120% of 100 → accept
        let tx_ok = make_signed_tx_with_signer(&signer, &pubkey, 0, 120);
        insert_rich(&pool, tx_ok, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.len(), 1);
    }
}
