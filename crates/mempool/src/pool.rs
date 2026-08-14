//! Core transaction pool implementation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::warn;

use shell_core::{calc_blob_gas_price, calc_excess_blob_gas, miner_tip, SignedTransaction};
use shell_crypto::Verifier;
use shell_pqvm::{
    compute_intrinsic_gas, validate_aa_bundle_structure, validate_aa_tx, validate_transaction_type,
    AaValidationError, TxValidationError,
};
use shell_primitives::{Address, ShellHash, U256};
use shell_storage::{ChainStore, KvStore, WorldState};

use crate::{MempoolConfig, MempoolError};

/// Maximum serialized transaction size accepted by the mempool (128 KB).
///
/// Protects against oversized SPHINCS+ signatures (~49 KB) and large
/// access lists flooding the pool.
pub const MAX_TX_SIZE: usize = 128 * 1024;

#[derive(Default)]
struct SerializedSizeCounter(usize);

impl Write for SerializedSizeCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("serialized transaction size overflow"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_transaction_size(tx: &SignedTransaction) -> serde_json::Result<usize> {
    let mut counter = SerializedSizeCounter::default();
    serde_json::to_writer(&mut counter, tx)?;
    Ok(counter.0)
}

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
    /// Aggregate serialized size of all retained transactions.
    total_bytes: usize,
    /// Aggregate balance reserved by retained transactions for each sender or
    /// paymaster. This keeps admission checks independent of total pool size.
    reserved_by_account: HashMap<Address, ReservationTotal>,
}

#[derive(Clone, Copy, Default)]
struct ReservationTotal {
    /// Aggregate modulo 2^256.
    low: U256,
    /// Carry count retained so removals recover the exact aggregate.
    overflow_units: u64,
}

impl ReservationTotal {
    fn add(self, cost: U256) -> Self {
        let (low, overflowed) = self.low.overflowing_add(cost);
        Self {
            low,
            overflow_units: self.overflow_units.saturating_add(u64::from(overflowed)),
        }
    }

    fn subtract(self, cost: U256) -> Self {
        let (low, borrowed) = self.low.overflowing_sub(cost);
        if borrowed && self.overflow_units == 0 {
            return Self::default();
        }
        Self {
            low,
            overflow_units: self.overflow_units.saturating_sub(u64::from(borrowed)),
        }
    }

    fn saturating_u256(self) -> U256 {
        if self.overflow_units == 0 {
            self.low
        } else {
            U256::MAX
        }
    }

    fn is_zero(self) -> bool {
        self.overflow_units == 0 && self.low == U256::ZERO
    }
}

/// Entry in the pool holding the transaction and metadata.
struct PoolEntry {
    tx: Arc<SignedTransaction>,
    priority_key: PriorityKey,
    serialized_size: usize,
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
                total_bytes: 0,
                reserved_by_account: HashMap::new(),
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
        let (tx_size, base_fee_per_gas) =
            self.validate_stateless(&tx, world_state, chain_store, verifier)?;

        // --- Balance floor check (F-020) ---
        let sender = tx.sender();
        let gas_cost = max_gas_cost(&tx);

        // For AA bundles with a paymaster, gas is covered by the paymaster.
        // For all other transactions (including batch-only AA), the sender pays.
        let payer = tx
            .aa_bundle()
            .and_then(|b| b.paymaster)
            .filter(|pm| *pm != sender)
            .unwrap_or(sender);

        let payer_gas_balance = world_state
            .get_balance(&payer)
            .map_err(MempoolError::Storage)?;
        if payer_gas_balance < gas_cost {
            return Err(MempoolError::InsufficientBalance {
                needed: gas_cost,
                have: payer_gas_balance,
            });
        }

        // Sender must still cover the transferred value even when paymaster pays gas.
        let needed_for_value = tx.tx.value;
        let sender_balance = world_state
            .get_balance(&sender)
            .map_err(MempoolError::Storage)?;
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
            let needed = match gas_cost.checked_add(tx.tx.value) {
                Some(needed) => needed,
                None => {
                    return Err(MempoolError::InsufficientBalance {
                        needed: U256::MAX,
                        have: sender_balance,
                    });
                }
            };
            if sender_balance < needed {
                return Err(MempoolError::InsufficientBalance {
                    needed,
                    have: sender_balance,
                });
            }
        }

        let hash = tx.hash();
        let nonce = tx.tx.nonce;
        if nonce == u64::MAX {
            return Err(MempoolError::InvalidTransaction(
                "nonce cannot advance past u64::MAX".into(),
            ));
        }
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
            // Require each applicable fee dimension to meet the bump threshold.
            let (old_priority_fee, old_max_fee, old_blob_fee) = inner
                .by_hash
                .get(&existing_hash)
                .map(|e| {
                    (
                        e.tx.tx.max_priority_fee_per_gas,
                        e.tx.tx.max_fee_per_gas,
                        e.tx.tx.max_fee_per_blob_gas,
                    )
                })
                .unwrap_or((0, 0, None));
            let bump = self.config.replacement_fee_bump_pct;
            let fee_pairs = [
                (old_priority_fee, priority_fee),
                (old_max_fee, tx.tx.max_fee_per_gas),
            ]
            .into_iter()
            .chain(
                old_blob_fee
                    .map(|old_fee| (old_fee, tx.tx.max_fee_per_blob_gas.unwrap_or_default())),
            );
            for (old_fee, new_fee) in fee_pairs {
                // required = old_fee * (100 + bump) / 100, rounded up
                let Some(required) = replacement_fee_required(old_fee, bump) else {
                    return Err(MempoolError::ReplacementFeeTooLow {
                        got: new_fee,
                        required: u64::MAX,
                    });
                };
                if new_fee < required {
                    return Err(MempoolError::ReplacementFeeTooLow {
                        got: new_fee,
                        required,
                    });
                }
            }
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
        if existing_hash.is_none() && sender_count >= self.config.max_per_sender {
            return Err(MempoolError::SenderQueueFull {
                sender,
                count: sender_count,
            });
        }

        let initial_evictions = existing_hash.into_iter().collect();
        let (evicted_hashes, projected_bytes) = Self::capacity_evictions(
            &inner,
            initial_evictions,
            miner_tip(tx.tx.max_fee_per_gas, priority_fee, base_fee_per_gas),
            base_fee_per_gas,
            sender,
            nonce,
            tx_size,
            self.config.max_pool_size,
            self.config.max_pool_bytes,
        )?;
        Self::ensure_pending_balance_available(&inner, &tx, world_state, &evicted_hashes)?;

        let Some(next_seq) = inner.seq.checked_add(1) else {
            return Err(MempoolError::InvalidTransaction(
                "mempool arrival sequence exhausted".into(),
            ));
        };

        for evicted_hash in &evicted_hashes {
            Self::remove_entry(&mut inner, evicted_hash);
        }

        // --- Insert ---
        let seq = inner.seq;
        inner.seq = next_seq;

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
        Self::add_reservations(&mut inner, &tx);
        inner.by_hash.insert(
            hash,
            PoolEntry {
                tx: Arc::new(tx),
                priority_key,
                serialized_size: tx_size,
            },
        );
        inner.total_bytes = projected_bytes;

        Ok(hash)
    }

    /// Remove a transaction from the pool by hash.
    ///
    /// Returns `true` if the transaction was found and removed.
    pub fn remove(&self, hash: &ShellHash) -> bool {
        let mut inner = self.inner.write();
        let removed = Self::remove_entry(&mut inner, hash);
        if inner.by_hash.is_empty() {
            inner.seq = 0;
        }
        removed
    }

    /// Remove a transaction and all later nonces queued for the same sender.
    ///
    /// Use this when a transaction is permanently invalid. Its descendants
    /// cannot execute until the missing nonce is replaced, so retaining them
    /// would break the pool's contiguous sender-queue invariant.
    pub fn remove_with_descendants(&self, hash: &ShellHash) -> usize {
        let mut inner = self.inner.write();
        let removed = Self::remove_entry_and_descendants(&mut inner, hash);
        if inner.by_hash.is_empty() {
            inner.seq = 0;
        }
        removed
    }

    /// Remove a batch of transactions (e.g., after block inclusion).
    pub fn remove_batch(&self, hashes: &[ShellHash]) {
        let mut inner = self.inner.write();
        for hash in hashes {
            Self::remove_entry(&mut inner, hash);
        }
        if inner.by_hash.is_empty() {
            inner.seq = 0;
        }
    }

    /// Remove transactions whose nonce is below canonical state.
    ///
    /// Imported blocks can advance an account nonce even when the exact stale
    /// transaction was not in the block (for example, a lower-fee duplicate that
    /// arrived late). Pruning here prevents invalid nonce-too-low transactions
    /// from being selected or rebroadcast indefinitely.
    pub fn prune_nonce_too_low<S: KvStore + 'static>(&self, world_state: &WorldState<S>) -> usize {
        let senders: Vec<Address> = {
            let inner = self.inner.read();
            inner.by_sender.keys().copied().collect()
        };
        let canonical_nonces: HashMap<Address, u64> = senders
            .into_iter()
            .filter_map(|sender| match world_state.get_nonce(&sender) {
                Ok(nonce) => Some((sender, nonce)),
                Err(e) => {
                    warn!(
                        sender = ?sender,
                        error = %e,
                        "prune_nonce_too_low: get_nonce failed, skipping sender"
                    );
                    None
                }
            })
            .collect();

        let mut inner = self.inner.write();
        let stale_hashes: Vec<ShellHash> = canonical_nonces
            .iter()
            .flat_map(|(sender, canonical_nonce)| {
                inner
                    .by_sender
                    .get(sender)
                    .into_iter()
                    .flat_map(move |queue| queue.range(..*canonical_nonce).map(|(_, hash)| *hash))
            })
            .collect();
        let pruned = stale_hashes.len();
        for hash in stale_hashes {
            Self::remove_entry(&mut inner, &hash);
        }
        if inner.by_hash.is_empty() {
            inner.seq = 0;
        }
        pruned
    }

    /// Remove all transactions from the pool.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.by_hash.clear();
        inner.by_sender.clear();
        inner.by_priority.clear();
        inner.seq = 0;
        inner.total_bytes = 0;
        inner.reserved_by_account.clear();
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &ShellHash) -> Option<SignedTransaction> {
        self.get_shared(hash).map(|tx| tx.as_ref().clone())
    }

    /// Get a shared transaction by hash without cloning its payload.
    ///
    /// The pool lock is released after cloning the internal [`Arc`], allowing
    /// callers such as RPC handlers to inspect large signed transactions
    /// without holding the read lock or copying signature and calldata bytes.
    pub fn get_shared(&self, hash: &ShellHash) -> Option<Arc<SignedTransaction>> {
        let inner = self.inner.read();
        inner.by_hash.get(hash).map(|entry| Arc::clone(&entry.tx))
    }

    /// Check if a transaction is in the pool.
    pub fn contains(&self, hash: &ShellHash) -> bool {
        self.inner.read().by_hash.contains_key(hash)
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    /// Aggregate serialized size of transactions currently retained by the pool.
    pub fn size_bytes(&self) -> usize {
        self.inner.read().total_bytes
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
        let mut selected = Vec::with_capacity(limit.min(inner.by_hash.len()));

        for hash in inner.by_priority.values() {
            if selected.len() >= limit {
                break;
            }
            if let Some(entry) = inner.by_hash.get(hash) {
                selected.push(Arc::clone(&entry.tx));
            }
        }
        drop(inner);
        selected.into_iter().map(|tx| tx.as_ref().clone()).collect()
    }

    /// Collect transactions for block production while preserving per-sender
    /// nonce contiguity.
    ///
    /// The general [`pending`] view is globally priority ordered and is useful
    /// for RPC inspection. Block production must be stricter: for any sender,
    /// nonce `N + 1` must not be returned before nonce `N`, even if `N + 1`
    /// pays a higher priority fee.
    pub fn pending_for_block(&self, limit: usize) -> Vec<SignedTransaction> {
        self.pending_for_block_shared(limit)
            .into_iter()
            .map(|tx| tx.as_ref().clone())
            .collect()
    }

    /// Collect shared transaction handles for block production while preserving
    /// per-sender nonce contiguity.
    ///
    /// This avoids copying signatures and calldata during candidate selection;
    /// callers only need to clone transactions that are actually included.
    pub fn pending_for_block_shared(&self, limit: usize) -> Vec<Arc<SignedTransaction>> {
        self.pending_for_block_matching_shared(limit, |_| true, |tx| tx.tx.max_priority_fee_per_gas)
    }

    /// Collect transactions that can pay the next block's base fee while
    /// preserving per-sender nonce contiguity.
    ///
    /// Underpriced sender heads are retained in the pool but do not consume the
    /// result limit or allow later nonces from that sender to bypass them.
    pub fn pending_for_block_at_base_fee(
        &self,
        limit: usize,
        base_fee_per_gas: u64,
    ) -> Vec<SignedTransaction> {
        self.pending_for_block_at_base_fee_shared(limit, base_fee_per_gas)
            .into_iter()
            .map(|tx| tx.as_ref().clone())
            .collect()
    }

    /// Shared-handle variant of [`Self::pending_for_block_at_base_fee`].
    pub fn pending_for_block_at_base_fee_shared(
        &self,
        limit: usize,
        base_fee_per_gas: u64,
    ) -> Vec<Arc<SignedTransaction>> {
        self.pending_for_block_at_fees_shared(limit, base_fee_per_gas, 0)
    }

    /// Collect transactions that can pay the next block's execution and blob
    /// base fees while preserving per-sender nonce contiguity.
    pub fn pending_for_block_at_fees(
        &self,
        limit: usize,
        base_fee_per_gas: u64,
        blob_base_fee: u64,
    ) -> Vec<SignedTransaction> {
        self.pending_for_block_at_fees_shared(limit, base_fee_per_gas, blob_base_fee)
            .into_iter()
            .map(|tx| tx.as_ref().clone())
            .collect()
    }

    /// Shared-handle variant of [`Self::pending_for_block_at_fees`].
    pub fn pending_for_block_at_fees_shared(
        &self,
        limit: usize,
        base_fee_per_gas: u64,
        blob_base_fee: u64,
    ) -> Vec<Arc<SignedTransaction>> {
        self.pending_for_block_matching_shared(
            limit,
            |tx| {
                tx.tx.max_fee_per_gas >= base_fee_per_gas
                    && (tx.tx.tx_type != 3
                        || tx.tx.max_fee_per_blob_gas.unwrap_or_default() >= blob_base_fee)
            },
            |tx| {
                miner_tip(
                    tx.tx.max_fee_per_gas,
                    tx.tx.max_priority_fee_per_gas,
                    base_fee_per_gas,
                )
            },
        )
    }

    fn pending_for_block_matching_shared(
        &self,
        limit: usize,
        is_eligible: impl Fn(&SignedTransaction) -> bool,
        priority_fee: impl Fn(&SignedTransaction) -> u64,
    ) -> Vec<Arc<SignedTransaction>> {
        let inner = self.inner.read();
        let mut selected = Vec::with_capacity(limit.min(inner.by_hash.len()));
        let mut ready: BTreeMap<PriorityKey, (Address, ShellHash)> = BTreeMap::new();
        let selection_key = |entry: &PoolEntry| PriorityKey {
            neg_priority_fee: -(priority_fee(&entry.tx) as i128),
            seq: entry.priority_key.seq,
        };

        for (sender, queue) in &inner.by_sender {
            if let Some((_nonce, hash)) = queue.first_key_value() {
                if let Some(entry) = inner.by_hash.get(hash) {
                    if is_eligible(&entry.tx) {
                        ready.insert(selection_key(entry), (*sender, *hash));
                    }
                }
            }
        }

        while selected.len() < limit {
            let Some((priority_key, (sender, hash))) = ready.pop_first() else {
                break;
            };

            let Some(entry) = inner.by_hash.get(&hash) else {
                continue;
            };
            let nonce = entry.tx.tx.nonce;
            selected.push(Arc::clone(&entry.tx));

            if let Some(sender_queue) = inner.by_sender.get(&sender) {
                if let Some(next_nonce) = nonce.checked_add(1) {
                    if let Some((queued_nonce, next_hash)) = sender_queue.range(next_nonce..).next()
                    {
                        if *queued_nonce == next_nonce {
                            if let Some(next_entry) = inner.by_hash.get(next_hash) {
                                let next_priority_key = selection_key(next_entry);
                                if next_priority_key != priority_key && is_eligible(&next_entry.tx)
                                {
                                    ready.insert(next_priority_key, (sender, *next_hash));
                                }
                            }
                        }
                    }
                }
            }
        }

        selected
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

    /// Return the next nonce after contiguous pending transactions for a sender.
    ///
    /// This is the mempool view used by `"pending"` RPC nonce queries. Stale
    /// entries below `chain_nonce` are ignored, and gaps stop the count.
    pub fn pending_nonce(&self, sender: &Address, chain_nonce: u64) -> u64 {
        let inner = self.inner.read();
        next_expected_nonce(inner.by_sender.get(sender), chain_nonce)
    }

    // --- Private helpers ---

    /// Lightweight validation performed before acquiring the pool lock.
    fn validate_stateless<S: KvStore + 'static, V: Verifier>(
        &self,
        tx: &SignedTransaction,
        world_state: &mut WorldState<S>,
        chain_store: &ChainStore<S>,
        verifier: &V,
    ) -> Result<(usize, u64), MempoolError> {
        // Chain ID
        if tx.tx.chain_id != self.config.chain_id {
            return Err(MempoolError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: tx.tx.chain_id,
            });
        }

        validate_transaction_type(tx.tx.tx_type)
            .map_err(|err| MempoolError::InvalidTransaction(err.to_string()))?;

        let mut base_fee_per_gas = 0;
        if let Some(head_hash) = chain_store.get_head_hash().map_err(MempoolError::Storage)? {
            let head = chain_store
                .get_header_by_hash(&head_hash)
                .map_err(MempoolError::Storage)?
                .ok_or_else(|| {
                    MempoolError::InvalidTransaction("canonical head header is missing".into())
                })?;
            base_fee_per_gas = head.base_fee_per_gas;
            if tx.tx.gas_limit > head.gas_limit {
                return Err(MempoolError::InvalidTransaction(format!(
                    "transaction gas limit {} exceeds block gas limit {}",
                    tx.tx.gas_limit, head.gas_limit
                )));
            }
            if tx.tx.max_fee_per_gas < head.base_fee_per_gas {
                return Err(MempoolError::InvalidTransaction(format!(
                    "max fee per gas ({}) below current base fee ({})",
                    tx.tx.max_fee_per_gas, head.base_fee_per_gas
                )));
            }
            if tx.tx.tx_type == 3 {
                let next_excess_blob_gas =
                    calc_excess_blob_gas(head.excess_blob_gas, head.blob_gas_used);
                let blob_base_fee = calc_blob_gas_price(next_excess_blob_gas);
                if let Some(max_fee_per_blob_gas) = tx.tx.max_fee_per_blob_gas {
                    if max_fee_per_blob_gas < blob_base_fee {
                        return Err(MempoolError::InvalidTransaction(format!(
                            "max fee per blob gas ({max_fee_per_blob_gas}) below current blob base fee ({blob_base_fee})",
                        )));
                    }
                }
            }
        }

        if tx.tx.max_priority_fee_per_gas > tx.tx.max_fee_per_gas {
            return Err(MempoolError::InvalidTransaction(
                "max priority fee per gas exceeds max fee per gas".into(),
            ));
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
        if let Err(msg) = tx.tx.validate_blob_tx() {
            return Err(MempoolError::InvalidTransaction(msg.to_string()));
        }

        // AA bundle structural pre-check (M2 native AA): consistency between
        // tx_type and aa_bundle, MAX_INNER_CALLS / MAX_INNER_CALLDATA, and
        // inner-gas budget vs outer gas_limit. Returns the additional
        // intrinsic-gas surcharge for AA txs (zero otherwise).
        let aa_extra_gas = validate_aa_bundle_structure(tx)
            .map_err(|e: TxValidationError| MempoolError::InvalidTransaction(e.to_string()))?;

        let Some(intrinsic) = compute_intrinsic_gas(
            tx.tx.data.as_ref(),
            tx.tx.is_contract_creation(),
            &tx.tx.access_list,
        )
        .checked_add(aa_extra_gas) else {
            return Err(MempoolError::GasTooLow {
                got: tx.tx.gas_limit,
                minimum: u64::MAX,
            });
        };
        if tx.tx.gas_limit < intrinsic {
            return Err(MempoolError::GasTooLow {
                got: tx.tx.gas_limit,
                minimum: intrinsic,
            });
        }

        // Per-tx serialized size limit — protects against oversized PQ
        // signatures and access lists.
        let tx_size = serialized_transaction_size(tx).map_err(|e| {
            MempoolError::InvalidTransaction(format!("tx serialization failed: {e}"))
        })?;
        if tx_size > MAX_TX_SIZE {
            return Err(MempoolError::InvalidTransaction(format!(
                "transaction too large: {} bytes (max {})",
                tx_size, MAX_TX_SIZE
            )));
        }

        validate_aa_tx(tx, world_state, chain_store, verifier)
            .map_err(|err| map_aa_validation_error(tx, err))?;
        Ok((tx_size, base_fee_per_gas))
    }

    /// Remove a single entry from all indexes. Caller holds write lock.
    fn remove_entry(inner: &mut PoolInner, hash: &ShellHash) -> bool {
        if let Some(entry) = inner.by_hash.remove(hash) {
            inner.total_bytes = inner.total_bytes.saturating_sub(entry.serialized_size);
            Self::remove_reservations(inner, &entry.tx);
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

    /// Plan lower-priority evictions until both count and byte limits fit.
    ///
    /// Priority is the miner tip payable at the current base fee, matching
    /// block candidate ordering rather than the transaction's advertised cap.
    ///
    /// Selecting an entry also selects all later nonces from that sender so
    /// capacity pressure cannot leave an unexecutable nonce tail behind.
    #[allow(clippy::too_many_arguments)]
    fn capacity_evictions(
        inner: &PoolInner,
        mut evicted_hashes: HashSet<ShellHash>,
        incoming_effective_tip: u64,
        base_fee_per_gas: u64,
        incoming_sender: Address,
        incoming_nonce: u64,
        incoming_size: usize,
        max_pool_size: usize,
        max_pool_bytes: usize,
    ) -> Result<(HashSet<ShellHash>, usize), MempoolError> {
        let mut evicted_bytes = evicted_hashes
            .iter()
            .filter_map(|hash| inner.by_hash.get(hash))
            .fold(0usize, |total, entry| {
                total.saturating_add(entry.serialized_size)
            });
        loop {
            let projected_count = inner
                .by_hash
                .len()
                .saturating_sub(evicted_hashes.len())
                .saturating_add(1);
            let projected_bytes = inner
                .total_bytes
                .saturating_sub(evicted_bytes)
                .checked_add(incoming_size);
            let count_fits = projected_count <= max_pool_size;
            let bytes_fit = projected_bytes.is_some_and(|bytes| bytes <= max_pool_bytes);
            if count_fits && bytes_fit {
                return Ok((
                    evicted_hashes,
                    projected_bytes.expect("checked by bytes_fit"),
                ));
            }

            let candidate = inner
                .by_priority
                .iter()
                .filter_map(|(priority_key, hash)| {
                    if evicted_hashes.contains(hash) {
                        return None;
                    }
                    let entry = inner.by_hash.get(hash)?;
                    if entry.tx.sender() == incoming_sender && entry.tx.tx.nonce <= incoming_nonce {
                        return None;
                    }
                    let effective_tip = miner_tip(
                        entry.tx.tx.max_fee_per_gas,
                        entry.tx.tx.max_priority_fee_per_gas,
                        base_fee_per_gas,
                    );
                    Some((effective_tip, priority_key.seq, *hash))
                })
                .min_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
                .filter(|(effective_tip, _, _)| incoming_effective_tip > *effective_tip)
                .map(|(_, _, hash)| hash);

            let Some(candidate) = candidate else {
                return if count_fits {
                    Err(MempoolError::PoolBytesFull {
                        capacity: max_pool_bytes,
                    })
                } else {
                    Err(MempoolError::PoolFull {
                        capacity: max_pool_size,
                    })
                };
            };
            for hash in Self::entry_and_descendant_hashes(inner, &candidate) {
                if evicted_hashes.insert(hash) {
                    if let Some(entry) = inner.by_hash.get(&hash) {
                        evicted_bytes = evicted_bytes.saturating_add(entry.serialized_size);
                    }
                }
            }
        }
    }

    /// Remove a pool-capacity eviction candidate and all later transactions
    /// from the same sender, preserving nonce contiguity for block production.
    fn remove_entry_and_descendants(inner: &mut PoolInner, hash: &ShellHash) -> usize {
        let hashes = Self::entry_and_descendant_hashes(inner, hash);
        hashes
            .into_iter()
            .filter(|hash| Self::remove_entry(inner, hash))
            .count()
    }

    fn entry_and_descendant_hashes(inner: &PoolInner, hash: &ShellHash) -> Vec<ShellHash> {
        let Some(entry) = inner.by_hash.get(hash) else {
            return Vec::new();
        };
        let sender = entry.tx.sender();
        let nonce = entry.tx.tx.nonce;
        inner
            .by_sender
            .get(&sender)
            .map(|queue| queue.range(nonce..).map(|(_nonce, hash)| *hash).collect())
            .unwrap_or_else(|| vec![*hash])
    }

    fn ensure_pending_balance_available<S: KvStore + 'static>(
        inner: &PoolInner,
        tx: &SignedTransaction,
        world_state: &WorldState<S>,
        excluded_hashes: &HashSet<ShellHash>,
    ) -> Result<(), MempoolError> {
        for (account, incoming) in Self::reservation_costs(tx) {
            if incoming == U256::ZERO {
                continue;
            }

            let needed_total =
                Self::reserved_total_excluding(inner, &account, excluded_hashes).add(incoming);
            let needed = needed_total.saturating_u256();
            let have = world_state
                .get_balance(&account)
                .map_err(MempoolError::Storage)?;
            if needed_total.overflow_units > 0 || have < needed {
                return Err(MempoolError::InsufficientBalance { needed, have });
            }
        }
        Ok(())
    }

    fn reservation_costs(tx: &SignedTransaction) -> [(Address, U256); 2] {
        let sender = tx.sender();
        let gas_payer = gas_payer(tx);
        if gas_payer == sender {
            [
                (sender, add_or_max(max_gas_cost(tx), tx.tx.value)),
                (sender, U256::ZERO),
            ]
        } else {
            [(sender, tx.tx.value), (gas_payer, max_gas_cost(tx))]
        }
    }

    fn reservation_cost_for(tx: &SignedTransaction, account: &Address) -> U256 {
        Self::reservation_costs(tx)
            .into_iter()
            .filter(|(reserved_account, _cost)| reserved_account == account)
            .map(|(_account, cost)| cost)
            .fold(U256::ZERO, add_or_max)
    }

    fn add_reservations(inner: &mut PoolInner, tx: &SignedTransaction) {
        for (account, cost) in Self::reservation_costs(tx) {
            if cost == U256::ZERO {
                continue;
            }
            let total = inner.reserved_by_account.entry(account).or_default();
            *total = total.add(cost);
        }
    }

    fn remove_reservations(inner: &mut PoolInner, tx: &SignedTransaction) {
        for (account, cost) in Self::reservation_costs(tx) {
            if cost == U256::ZERO {
                continue;
            }
            let remove_account = if let Some(total) = inner.reserved_by_account.get_mut(&account) {
                *total = total.subtract(cost);
                total.is_zero()
            } else {
                false
            };
            if remove_account {
                inner.reserved_by_account.remove(&account);
            }
        }
    }

    fn reserved_total_excluding(
        inner: &PoolInner,
        account: &Address,
        excluded_hashes: &HashSet<ShellHash>,
    ) -> ReservationTotal {
        let mut total = inner
            .reserved_by_account
            .get(account)
            .copied()
            .unwrap_or_default();
        for entry in excluded_hashes
            .iter()
            .filter_map(|hash| inner.by_hash.get(hash))
        {
            total = total.subtract(Self::reservation_cost_for(&entry.tx, account));
        }
        total
    }
}

fn gas_payer(tx: &SignedTransaction) -> Address {
    let sender = tx.sender();
    tx.aa_bundle()
        .and_then(|bundle| bundle.paymaster)
        .filter(|paymaster| *paymaster != sender)
        .unwrap_or(sender)
}

fn max_gas_cost(tx: &SignedTransaction) -> U256 {
    let execution_gas_cost = U256::from(tx.tx.gas_limit)
        .checked_mul(U256::from(tx.tx.max_fee_per_gas))
        .unwrap_or(U256::MAX);
    let blob_gas_cost = U256::from(tx.tx.blob_gas())
        .checked_mul(U256::from(tx.tx.max_fee_per_blob_gas.unwrap_or_default()))
        .unwrap_or(U256::MAX);
    add_or_max(execution_gas_cost, blob_gas_cost)
}

fn add_or_max(left: U256, right: U256) -> U256 {
    left.checked_add(right).unwrap_or(U256::MAX)
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
        AaValidationError::Storage(err) => MempoolError::Storage(err),
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

fn replacement_fee_required(old_fee: u64, bump_pct: u64) -> Option<u64> {
    if bump_pct == 0 {
        return Some(old_fee);
    }

    let multiplier = u128::from(bump_pct).checked_add(100)?;
    let numerator = u128::from(old_fee).checked_mul(multiplier)?;
    let rounded = numerator.checked_add(99)? / 100;
    let minimum_bump = u128::from(old_fee).checked_add(1)?;
    let required = rounded.max(minimum_bump);
    u64::try_from(required).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{
        AaBundle, Block, BlockHeader, InnerCall, PubkeyMode, Transaction, AA_BUNDLE_TX_TYPE,
    };
    use shell_crypto::{DilithiumSigner, DilithiumVerifier, Signer};
    use shell_primitives::Bytes;
    use shell_storage::{ChainStore, KvStore, MemoryDb, StorageError, WorldState, WriteBatch};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct FailingPubkeyStore {
        inner: MemoryDb,
        fail_get: AtomicBool,
        fail_pubkey_put: AtomicBool,
    }

    impl FailingPubkeyStore {
        fn new(fail_pubkey_put: bool) -> Self {
            Self {
                inner: MemoryDb::new(),
                fail_get: AtomicBool::new(false),
                fail_pubkey_put: AtomicBool::new(fail_pubkey_put),
            }
        }

        fn fail_gets(&self) {
            self.fail_get.store(true, Ordering::SeqCst);
        }
    }

    impl KvStore for FailingPubkeyStore {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if self.fail_get.load(Ordering::SeqCst) && !key.starts_with(b"pk/") {
                return Err(StorageError::Database("injected get failure".into()));
            }
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            if self.fail_pubkey_put.load(Ordering::SeqCst) && key.starts_with(b"pk/") {
                return Err(StorageError::Database(
                    "injected pubkey write failure".into(),
                ));
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
            self.inner.write_batch(batch)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
    }

    fn test_address(seed: &[u8]) -> Address {
        Address::from_public_key(seed, 0)
    }

    fn make_config() -> MempoolConfig {
        MempoolConfig {
            max_pool_size: 10,
            max_pool_bytes: 1024 * 1024,
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

    fn make_signed_tx_with_data(priority_fee: u64, data_len: usize) -> SignedTransaction {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let tx = Transaction {
            chain_id: 42,
            nonce: u64::default(),
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value: U256::ZERO,
            data: Bytes::from(vec![1; data_len]),
            gas_limit: 21_000 + 16 * data_len as u64,
            max_fee_per_gas: priority_fee + 10,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey)
    }

    fn make_blob_tx(max_fee_per_blob_gas: u64) -> SignedTransaction {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        make_blob_tx_with_signer(&signer, &pubkey, 100, 1, max_fee_per_blob_gas)
    }

    fn make_blob_tx_with_signer(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        max_fee_per_blob_gas: u64,
    ) -> SignedTransaction {
        let from = test_address(pubkey);
        let mut blob_hash = [0u8; 32];
        blob_hash[0] = shell_core::BLOB_VERSIONED_HASH_VERSION_KZG;
        let tx = Transaction {
            chain_id: 42,
            nonce: u64::default(),
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value: U256::ZERO,
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list: None,
            tx_type: 3,
            max_fee_per_blob_gas: Some(max_fee_per_blob_gas),
            blob_versioned_hashes: Some(vec![ShellHash::from(blob_hash)]),
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey.to_vec())
    }

    /// Convenience: create a signed tx from an existing signer for multi-nonce tests.
    fn make_signed_tx_with_signer(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        nonce: u64,
        priority_fee: u64,
    ) -> SignedTransaction {
        make_signed_value_tx_with_signer(signer, pubkey, nonce, priority_fee, U256::ZERO)
    }

    fn make_signed_value_tx_with_signer(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        nonce: u64,
        priority_fee: u64,
        value: U256,
    ) -> SignedTransaction {
        make_signed_value_tx_with_fees(
            signer,
            pubkey,
            nonce,
            priority_fee + 10,
            priority_fee,
            value,
        )
    }

    fn make_signed_value_tx_with_fees(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        nonce: u64,
        max_fee: u64,
        priority_fee: u64,
        value: U256,
    ) -> SignedTransaction {
        let from = test_address(pubkey);
        let tx = Transaction {
            chain_id: 42,
            nonce,
            to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
            value,
            data: Bytes::default(),
            gas_limit: 21_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        SignedTransaction::with_pubkey(from, tx, sig, pubkey.to_vec())
    }

    fn make_sponsored_aa_value_tx_with_signers(
        signer: &DilithiumSigner,
        pubkey: &[u8],
        paymaster_signer: &DilithiumSigner,
        paymaster_pubkey: &[u8],
        nonce: u64,
        priority_fee: u64,
        value: U256,
    ) -> SignedTransaction {
        let from = test_address(pubkey);
        let paymaster = test_address(paymaster_pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let tx = Transaction {
            chain_id: 42,
            nonce,
            to: Some(recipient),
            value,
            data: Bytes::default(),
            gas_limit: 80_000,
            max_fee_per_gas: priority_fee + 10,
            max_priority_fee_per_gas: priority_fee,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let bundle = AaBundle {
            inner_calls: vec![InnerCall {
                to: Some(recipient),
                value,
                data: Bytes::default(),
                gas_limit: 30_000,
            }],
            paymaster: Some(paymaster),
            paymaster_signature: Some(Bytes::from(vec![0x01])),
            ..Default::default()
        };
        let placeholder_sig = signer.sign(b"placeholder-sender-aa-signature").unwrap();
        let unsigned = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            placeholder_sig,
            PubkeyMode::Embedded(pubkey.to_vec()),
            bundle.clone(),
        )
        .unwrap();
        let sender_sig = signer
            .sign(unsigned.sender_signing_hash().as_bytes())
            .unwrap();
        let sender_signed = SignedTransaction::with_aa_bundle(
            from,
            tx.clone(),
            sender_sig.clone(),
            PubkeyMode::Embedded(pubkey.to_vec()),
            bundle.clone(),
        )
        .unwrap();
        let paymaster_sig = paymaster_signer
            .sign(sender_signed.paymaster_signing_hash().unwrap().as_bytes())
            .unwrap();
        let final_bundle = AaBundle {
            paymaster_signature: Some(Bytes::from(paymaster_sig.data)),
            ..bundle
        };

        SignedTransaction::with_aa_bundle(
            from,
            tx,
            sender_sig,
            PubkeyMode::Embedded(pubkey.to_vec()),
            final_bundle,
        )
        .unwrap()
    }

    fn register_paymaster<S: KvStore + 'static>(
        cs: &ChainStore<S>,
        paymaster_pubkey: &[u8],
    ) -> Address {
        let paymaster = test_address(paymaster_pubkey);
        cs.put_pubkey(&paymaster, paymaster_pubkey).unwrap();
        paymaster
    }

    fn setup_validation_ctx() -> (WorldState<MemoryDb>, ChainStore<MemoryDb>) {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        (ws, cs)
    }

    fn set_head(cs: &ChainStore<MemoryDb>, gas_limit: u64, base_fee_per_gas: u64) {
        set_head_with_blob_gas(cs, gas_limit, base_fee_per_gas, 0, 0);
    }

    fn set_head_with_blob_gas(
        cs: &ChainStore<MemoryDb>,
        gas_limit: u64,
        base_fee_per_gas: u64,
        blob_gas_used: u64,
        excess_blob_gas: u64,
    ) {
        let block = Block {
            header: BlockHeader {
                parent_hash: ShellHash::ZERO,
                state_root: ShellHash::ZERO,
                transactions_root: ShellHash::ZERO,
                receipts_root: ShellHash::ZERO,
                logs_bloom: Bytes::default(),
                number: 0,
                gas_limit,
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::default(),
                proposer: Address::ZERO,
                sig_aggregate_proof: None,
                base_fee_per_gas,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used,
                excess_blob_gas,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        };
        let hash = block.hash();
        cs.put_block(&block).unwrap();
        cs.set_head(&hash).unwrap();
    }

    fn insert_with_balance<S: KvStore + 'static>(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<S>,
        cs: &ChainStore<S>,
        balance: U256,
    ) -> Result<ShellHash, MempoolError> {
        ws.set_balance(&tx.sender(), balance).unwrap();
        pool.insert(tx, ws, cs, verifier)
    }

    fn insert_rich<S: KvStore + 'static>(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<S>,
        cs: &ChainStore<S>,
    ) -> Result<ShellHash, MempoolError> {
        insert_with_balance(pool, tx, verifier, ws, cs, U256::from(1_000_000_000_000u64))
    }

    fn insert_broke<S: KvStore + 'static>(
        pool: &TxPool,
        tx: SignedTransaction,
        verifier: &DilithiumVerifier,
        ws: &mut WorldState<S>,
        cs: &ChainStore<S>,
    ) -> Result<ShellHash, MempoolError> {
        insert_with_balance(pool, tx, verifier, ws, cs, U256::ZERO)
    }

    fn indexed_reservation(pool: &TxPool, account: &Address) -> Option<ReservationTotal> {
        pool.inner.read().reserved_by_account.get(account).copied()
    }

    #[test]
    fn reservation_total_preserves_overflow_across_removal() {
        let total = ReservationTotal::default()
            .add(U256::MAX)
            .add(U256::from(1u64));
        assert_eq!(total.low, U256::ZERO);
        assert_eq!(total.overflow_units, 1);

        let total = total.subtract(U256::from(1u64));
        assert_eq!(total.low, U256::MAX);
        assert_eq!(total.overflow_units, 0);

        assert!(total.subtract(U256::MAX).is_zero());
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

        let first = pool.get_shared(&hash).expect("shared transaction");
        let second = pool.get_shared(&hash).expect("shared transaction");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.hash(), hash);
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
    fn identical_payloads_from_different_senders_do_not_collide() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (first, _first_pk) = make_signed_tx(0, 100);
        let (second, _second_pk) = make_signed_tx(0, 100);

        assert_ne!(first.sender(), second.sender());
        assert_eq!(first.tx, second.tx);
        assert_ne!(first.hash(), second.hash());

        insert_rich(&pool, first, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, second, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.len(), 2);
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
    fn reject_unsupported_transaction_type() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (mut tx, _pk) = make_signed_tx(u64::default(), 100);
        tx.tx.tx_type = 4;

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "unsupported transaction type: 0x4"
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_blob_fields_on_non_blob_transaction() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let (mut tx, _pk) = make_signed_tx(u64::default(), 100);
        tx.tx.max_fee_per_blob_gas = Some(1_000_000);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "non-blob tx cannot have max_fee_per_blob_gas"
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_blob_transaction_with_unsupported_hash_version() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let mut tx = make_blob_tx(1_000_000);
        tx.tx.blob_versioned_hashes = Some(vec![ShellHash::ZERO]);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "blob tx has unsupported versioned hash version"
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_transaction_that_cannot_fit_in_a_block() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head(&cs, 20_999, 0);
        let (tx, _pk) = make_signed_tx(0, 100);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "transaction gas limit 21000 exceeds block gas limit 20999"
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_transaction_below_current_base_fee() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head(&cs, 30_000_000, 111);
        let (tx, _pk) = make_signed_tx(u64::default(), 100);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "max fee per gas (110) below current base fee (111)"
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_blob_transaction_below_next_block_blob_base_fee() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head_with_blob_gas(
            &cs,
            30_000_000,
            1,
            shell_core::TARGET_BLOB_GAS_PER_BLOCK,
            shell_core::BLOB_BASE_FEE_UPDATE_FRACTION,
        );
        let tx = make_blob_tx(shell_core::MIN_BLOB_BASE_FEE);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message.contains("below current blob base fee")
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn reject_blob_transaction_when_balance_only_covers_execution_gas() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let tx = make_blob_tx(10);
        let execution_gas_cost = U256::from(tx.tx.gas_limit) * U256::from(tx.tx.max_fee_per_gas);

        let err = insert_with_balance(&pool, tx, &verifier, &mut ws, &cs, execution_gas_cost)
            .unwrap_err();

        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
        assert!(pool.is_empty());
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
    fn reject_priority_fee_above_max_fee() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let tx = Transaction {
            chain_id: 42,
            nonce: 0,
            to: Some(Address::from([0x11; 20])),
            value: U256::ZERO,
            gas_limit: 21_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 101,
            data: Bytes::default(),
            tx_type: 0,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed = SignedTransaction::with_pubkey(from, tx, sig, pubkey);
        let err = insert_rich(&pool, signed, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::InvalidTransaction(message)
                if message == "max priority fee per gas exceeds max fee per gas"
        ));
        assert!(pool.is_empty());
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
    fn reject_aa_intrinsic_gas_overflow() {
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
            value: U256::ZERO,
            data: Bytes::default(),
            gas_limit: u64::MAX,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 50,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let bundle = AaBundle {
            inner_calls: vec![InnerCall {
                to: Some(test_address(b"recipient-placeholder-key-data-for-address")),
                value: U256::ZERO,
                data: Bytes::default(),
                gas_limit: u64::MAX,
            }],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let sig = signer.sign(tx.hash().as_bytes()).unwrap();
        let signed =
            SignedTransaction::with_aa_bundle(from, tx, sig, PubkeyMode::Embedded(pubkey), bundle)
                .unwrap();

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
    fn admitted_transaction_does_not_register_pubkey_before_import() {
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

        assert_eq!(cs.get_pubkey(&from).unwrap(), None);

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
        let err = insert_rich(&pool, follow_up, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::PubkeyRequired { .. }));
    }

    #[test]
    fn rejected_embedded_pubkey_tx_does_not_register_pubkey() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_account_nonce = u64::default();
        let priority_fee = make_config().min_gas_price + 99;
        let tx = make_signed_tx_with_signer(&signer, &pubkey, first_account_nonce, priority_fee);
        let sender = tx.sender();

        let err = insert_broke(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
        assert_eq!(cs.get_pubkey(&sender).unwrap(), None);
        assert_ne!(cs.get_pubkey(&sender).unwrap(), Some(pubkey));
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
    fn remove_with_descendants_preserves_sender_queue_and_byte_accounting() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();

        let tx0 = make_signed_tx_with_signer(&signer, &pubkey, 0, 100);
        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, 1, 90);
        let tx2 = make_signed_tx_with_signer(&signer, &pubkey, 2, 80);
        let h0 = insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        let h1 = insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        let h2 = insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.remove_with_descendants(&h1), 2);
        assert!(pool.contains(&h0));
        assert!(!pool.contains(&h1));
        assert!(!pool.contains(&h2));
        assert_eq!(pool.sender_txs(&test_address(&pubkey)), vec![h0]);
        assert_eq!(
            pool.size_bytes(),
            serde_json::to_vec(&pool.get(&h0).unwrap()).unwrap().len()
        );
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
    fn prune_nonce_too_low_removes_stale_transactions() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);

        let tx0 = make_signed_tx_with_signer(&signer, &pubkey, 0, 100);
        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, 1, 90);
        let h0 = insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        let h1 = insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();

        ws.increment_nonce(&from).unwrap();
        assert_eq!(pool.prune_nonce_too_low(&ws), 1);
        assert!(!pool.contains(&h0));
        assert!(pool.contains(&h1));
    }

    #[test]
    fn prune_nonce_too_low_resets_sequence_when_pool_empties() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);

        let tx0 = make_signed_tx_with_signer(&signer, &pubkey, ws.get_nonce(&from).unwrap(), 100);
        insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        pool.inner.write().seq = u64::MAX;

        ws.increment_nonce(&from).unwrap();
        assert_eq!(pool.prune_nonce_too_low(&ws), 1);
        assert!(pool.is_empty());

        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, ws.get_nonce(&from).unwrap(), 100);
        assert!(insert_rich(&pool, tx1, &verifier, &mut ws, &cs).is_ok());
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
    fn shared_block_candidates_reuse_pool_transaction_allocations() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let nonce = ws.get_nonce(&sender).unwrap();
        let tx = make_signed_tx_with_signer(&signer, &pubkey, nonce, 100);
        let hash = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap();

        let stored = Arc::clone(&pool.inner.read().by_hash.get(&hash).unwrap().tx);
        let candidates = pool.pending_for_block_at_base_fee_shared(1, 0);

        assert_eq!(candidates.len(), 1);
        assert!(Arc::ptr_eq(&stored, &candidates[0]));
    }

    #[test]
    fn pending_for_block_preserves_sender_nonce_contiguity() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender_tx0 = make_signed_tx_with_signer(&signer, &pubkey, 0, 10);
        let sender_tx1 = make_signed_tx_with_signer(&signer, &pubkey, 1, 100);
        let sender_tx0_hash = sender_tx0.hash();
        let sender_tx1_hash = sender_tx1.hash();
        let (other_tx, _) = make_signed_tx(0, 50);
        let other_hash = other_tx.hash();

        insert_rich(&pool, sender_tx0, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, sender_tx1, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, other_tx, &verifier, &mut ws, &cs).unwrap();

        let priority_view: Vec<_> = pool.pending(10).into_iter().map(|tx| tx.hash()).collect();
        assert_eq!(priority_view[0], sender_tx1_hash);

        let block_view: Vec<_> = pool
            .pending_for_block(10)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(
            block_view,
            vec![other_hash, sender_tx0_hash, sender_tx1_hash]
        );
    }

    #[test]
    fn block_candidate_limit_does_not_count_underpriced_sender_heads() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head(&cs, 30_000_000, 1);

        let underpriced_signer = DilithiumSigner::generate();
        let underpriced_pubkey = underpriced_signer.public_key().to_vec();
        let underpriced = make_signed_value_tx_with_fees(
            &underpriced_signer,
            &underpriced_pubkey,
            0,
            100,
            90,
            U256::ZERO,
        );
        let underpriced_descendant = make_signed_value_tx_with_fees(
            &underpriced_signer,
            &underpriced_pubkey,
            1,
            200,
            95,
            U256::ZERO,
        );

        let eligible_signer = DilithiumSigner::generate();
        let eligible_pubkey = eligible_signer.public_key().to_vec();
        let eligible = make_signed_value_tx_with_fees(
            &eligible_signer,
            &eligible_pubkey,
            0,
            200,
            10,
            U256::ZERO,
        );
        let eligible_hash = eligible.hash();

        insert_rich(&pool, underpriced, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, underpriced_descendant, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, eligible, &verifier, &mut ws, &cs).unwrap();

        let candidates = pool.pending_for_block_at_base_fee(1, 150);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].hash(), eligible_hash);
    }

    #[test]
    fn block_candidates_order_by_effective_priority_fee() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let capped_signer = DilithiumSigner::generate();
        let capped_pubkey = capped_signer.public_key().to_vec();
        let capped =
            make_signed_value_tx_with_fees(&capped_signer, &capped_pubkey, 0, 101, 100, U256::ZERO);

        let higher_tip_signer = DilithiumSigner::generate();
        let higher_tip_pubkey = higher_tip_signer.public_key().to_vec();
        let higher_tip = make_signed_value_tx_with_fees(
            &higher_tip_signer,
            &higher_tip_pubkey,
            0,
            200,
            50,
            U256::ZERO,
        );
        let higher_tip_hash = higher_tip.hash();

        insert_rich(&pool, capped, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, higher_tip, &verifier, &mut ws, &cs).unwrap();

        let candidates = pool.pending_for_block_at_base_fee(1, 100);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].hash(), higher_tip_hash);
    }

    #[test]
    fn block_candidate_limit_does_not_count_underpriced_blob_sender_heads() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head_with_blob_gas(&cs, 30_000_000, 1, 0, 0);

        let blob_signer = DilithiumSigner::generate();
        let blob_pubkey = blob_signer.public_key().to_vec();
        let underpriced_blob = make_blob_tx_with_signer(&blob_signer, &blob_pubkey, 100, 90, 1);

        let eligible_signer = DilithiumSigner::generate();
        let eligible_pubkey = eligible_signer.public_key().to_vec();
        let eligible = make_signed_value_tx_with_fees(
            &eligible_signer,
            &eligible_pubkey,
            0,
            200,
            10,
            U256::ZERO,
        );
        let eligible_hash = eligible.hash();

        insert_rich(&pool, underpriced_blob, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, eligible, &verifier, &mut ws, &cs).unwrap();

        let includable = pool.pending_for_block_at_fees(1, 1, 2);

        assert_eq!(includable.len(), 1);
        assert_eq!(includable[0].hash(), eligible_hash);
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
    fn pending_nonce_counts_contiguous_sender_queue_from_chain_nonce() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        ws.increment_nonce(&sender).unwrap();
        let chain_nonce = ws.get_nonce(&sender).unwrap();

        let tx1 = make_signed_tx_with_signer(&signer, &pubkey, chain_nonce, 50);
        let tx1_nonce = tx1.tx.nonce;

        insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        let tx2_nonce = pool.pending_nonce(&sender, chain_nonce);
        let tx2 = make_signed_tx_with_signer(&signer, &pubkey, tx2_nonce, 50);
        insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();

        let expected = pool.pending_nonce(&sender, chain_nonce);
        assert!(tx2_nonce > tx1_nonce);
        assert!(expected > tx2_nonce);
        assert_eq!(pool.pending_nonce(&sender, tx2_nonce), expected);
        assert_eq!(pool.pending_nonce(&sender, expected), expected);
        assert_eq!(
            pool.sender_count(&sender) as u64,
            expected.saturating_sub(chain_nonce)
        );
    }

    #[test]
    fn insert_rejects_max_nonce_that_cannot_advance() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let tx = make_signed_tx_with_signer(&signer, &pubkey, u64::MAX, 50);

        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();
        assert!(
            matches!(err, MempoolError::InvalidTransaction(message) if message.contains("u64::MAX"))
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn insert_rejects_exhausted_arrival_sequence_without_side_effects() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        pool.inner.write().seq = u64::MAX;

        let first_nonce = u64::default();
        let (tx, _pk) = make_signed_tx(first_nonce, 100);
        let sender = tx.sender();
        let err = insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap_err();

        assert!(
            matches!(err, MempoolError::InvalidTransaction(message) if message.contains("arrival sequence exhausted"))
        );
        assert!(pool.is_empty());
        assert_eq!(cs.get_pubkey(&sender).unwrap(), None);
    }

    #[test]
    fn clear_resets_exhausted_arrival_sequence() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        pool.inner.write().seq = u64::MAX;

        pool.clear();

        let first_nonce = u64::default();
        let (tx, _pk) = make_signed_tx(first_nonce, 100);
        insert_rich(&pool, tx, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_last_transaction_resets_exhausted_arrival_sequence() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let first = make_signed_tx_with_signer(&signer, &pubkey, first_nonce, 100);
        let first_hash = first.hash();
        insert_rich(&pool, first, &verifier, &mut ws, &cs).unwrap();

        pool.inner.write().seq = u64::MAX;
        assert!(pool.remove(&first_hash));
        assert!(pool.is_empty());

        let second = make_signed_tx_with_signer(&signer, &pubkey, first_nonce, 100);
        insert_rich(&pool, second, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.len(), 1);
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
    fn pool_full_evicts_by_effective_tip_at_current_base_fee() {
        let config = MempoolConfig {
            max_pool_size: 1,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        set_head(&cs, 30_000_000, 100);

        let incumbent_signer = DilithiumSigner::generate();
        let incumbent_pubkey = incumbent_signer.public_key().to_vec();
        let first_nonce = u64::default();
        let incumbent = make_signed_value_tx_with_fees(
            &incumbent_signer,
            &incumbent_pubkey,
            first_nonce,
            101,
            100,
            U256::ZERO,
        );
        let incumbent_hash = incumbent.hash();
        insert_rich(&pool, incumbent, &verifier, &mut ws, &cs).unwrap();

        let incoming_signer = DilithiumSigner::generate();
        let incoming_pubkey = incoming_signer.public_key().to_vec();
        let incoming = make_signed_value_tx_with_fees(
            &incoming_signer,
            &incoming_pubkey,
            first_nonce,
            102,
            2,
            U256::ZERO,
        );
        let incoming_hash = incoming.hash();
        insert_rich(&pool, incoming, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&incumbent_hash));
        assert!(pool.contains(&incoming_hash));
    }

    #[test]
    fn pool_full_eviction_prunes_sender_nonce_tail() {
        let config = MempoolConfig {
            max_pool_size: 3,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let second_nonce = first_nonce.checked_add(1).unwrap();

        let sender_low_nonce = make_signed_tx_with_signer(&signer, &pubkey, first_nonce, 10);
        let sender_high_nonce = make_signed_tx_with_signer(&signer, &pubkey, second_nonce, 100);
        let low_nonce_hash = sender_low_nonce.hash();
        let high_nonce_hash = sender_high_nonce.hash();
        let (other_tx, _) = make_signed_tx(u64::default(), 50);
        let other_hash = other_tx.hash();

        insert_rich(&pool, sender_low_nonce, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, sender_high_nonce, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, other_tx, &verifier, &mut ws, &cs).unwrap();

        let (incoming_tx, _) = make_signed_tx(u64::default(), 60);
        let incoming_hash = incoming_tx.hash();
        insert_rich(&pool, incoming_tx, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&low_nonce_hash));
        assert!(!pool.contains(&high_nonce_hash));
        assert!(pool.contains(&other_hash));
        assert!(pool.contains(&incoming_hash));

        let block_view: Vec<_> = pool
            .pending_for_block(10)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(block_view, vec![incoming_hash, other_hash]);
    }

    #[test]
    fn pool_full_same_sender_incoming_skips_nonce_prerequisite_eviction() {
        let config = MempoolConfig {
            max_pool_size: 3,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let second_nonce = first_nonce.checked_add(1).unwrap();
        let third_nonce = second_nonce.checked_add(1).unwrap();

        let sender_tx0 = make_signed_tx_with_signer(&signer, &pubkey, first_nonce, 10);
        let sender_tx1 = make_signed_tx_with_signer(&signer, &pubkey, second_nonce, 100);
        let sender_tx0_hash = sender_tx0.hash();
        let sender_tx1_hash = sender_tx1.hash();
        let (other_tx, _) = make_signed_tx(u64::default(), 50);
        let other_hash = other_tx.hash();

        insert_rich(&pool, sender_tx0, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, sender_tx1, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, other_tx, &verifier, &mut ws, &cs).unwrap();

        let sender_tx2 = make_signed_tx_with_signer(&signer, &pubkey, third_nonce, 60);
        let sender_tx2_hash = sender_tx2.hash();
        insert_rich(&pool, sender_tx2, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 3);
        assert!(pool.contains(&sender_tx0_hash));
        assert!(pool.contains(&sender_tx1_hash));
        assert!(pool.contains(&sender_tx2_hash));
        assert!(!pool.contains(&other_hash));

        let block_view: Vec<_> = pool
            .pending_for_block(10)
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(
            block_view,
            vec![sender_tx0_hash, sender_tx1_hash, sender_tx2_hash]
        );
    }

    #[test]
    fn pool_full_rejects_when_only_nonce_prerequisites_are_evictable() {
        let config = MempoolConfig {
            max_pool_size: 2,
            ..make_config()
        };
        let pool = TxPool::new(config);
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let second_nonce = first_nonce.checked_add(1).unwrap();
        let third_nonce = second_nonce.checked_add(1).unwrap();

        let sender_tx0 = make_signed_tx_with_signer(&signer, &pubkey, first_nonce, 10);
        let sender_tx1 = make_signed_tx_with_signer(&signer, &pubkey, second_nonce, 100);
        let sender_tx0_hash = sender_tx0.hash();
        let sender_tx1_hash = sender_tx1.hash();

        insert_rich(&pool, sender_tx0, &verifier, &mut ws, &cs).unwrap();
        insert_rich(&pool, sender_tx1, &verifier, &mut ws, &cs).unwrap();

        let sender_tx2 = make_signed_tx_with_signer(&signer, &pubkey, third_nonce, 60);
        let err = insert_rich(&pool, sender_tx2, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(err, MempoolError::PoolFull { .. }));
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&sender_tx0_hash));
        assert!(pool.contains(&sender_tx1_hash));
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
        assert_eq!(pool.size_bytes(), 0);
        assert_eq!(pool.pending(10).len(), 0);
    }

    #[test]
    fn aggregate_byte_limit_evicts_lower_priority_and_reclaims_capacity() {
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let nonce = u64::default();
        let (tx0, _) = make_signed_tx(nonce, 100);
        let (tx1, _) = make_signed_tx(nonce, 101);
        let (tx2, _) = make_signed_tx(nonce, 100);
        let tx0_size = serde_json::to_vec(&tx0).unwrap().len();
        let tx1_size = serde_json::to_vec(&tx1).unwrap().len();
        let tx2_size = serde_json::to_vec(&tx2).unwrap().len();
        assert_eq!(tx0_size, tx1_size);
        assert_eq!(tx0_size, tx2_size);
        let pool = TxPool::new(MempoolConfig {
            max_pool_bytes: tx0_size,
            ..make_config()
        });

        let hash0 = insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.size_bytes(), tx0_size);

        let hash1 = insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        assert!(!pool.contains(&hash0));
        assert!(pool.contains(&hash1));
        assert_eq!(pool.size_bytes(), tx1_size);

        let err = insert_rich(&pool, tx2.clone(), &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::PoolBytesFull { .. }), "{err:?}");
        assert!(pool.contains(&hash1));
        assert_eq!(pool.size_bytes(), tx1_size);

        assert!(pool.remove(&hash1));
        assert_eq!(pool.size_bytes(), 0);
        insert_rich(&pool, tx2, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.size_bytes(), tx2_size);
        pool.clear();
        assert_eq!(pool.size_bytes(), 0);
    }

    #[test]
    fn streamed_transaction_size_matches_json_encoding() {
        let tx = make_signed_tx_with_data(100, 4096);

        assert_eq!(
            serialized_transaction_size(&tx).unwrap(),
            serde_json::to_vec(&tx).unwrap().len()
        );
    }

    #[test]
    fn aggregate_byte_limit_evicts_multiple_lower_priority_transactions() {
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let nonce = u64::default();
        let (tx0, _) = make_signed_tx(nonce, 100);
        let (tx1, _) = make_signed_tx(nonce, 101);
        let high_priority = make_signed_tx_with_data(200, 1024);
        let tx0_size = serde_json::to_vec(&tx0).unwrap().len();
        let tx1_size = serde_json::to_vec(&tx1).unwrap().len();
        let high_priority_size = serde_json::to_vec(&high_priority).unwrap().len();
        let byte_capacity = tx0_size + tx1_size;
        assert!(high_priority_size > tx0_size);
        assert!(high_priority_size <= byte_capacity);
        let pool = TxPool::new(MempoolConfig {
            max_pool_bytes: byte_capacity,
            ..make_config()
        });

        let hash0 = insert_rich(&pool, tx0, &verifier, &mut ws, &cs).unwrap();
        let hash1 = insert_rich(&pool, tx1, &verifier, &mut ws, &cs).unwrap();
        let high_priority_hash =
            insert_rich(&pool, high_priority, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&hash0));
        assert!(!pool.contains(&hash1));
        assert!(pool.contains(&high_priority_hash));
        assert_eq!(pool.size_bytes(), high_priority_size);
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

    #[test]
    fn reject_single_transaction_cost_overflow() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let tx = make_signed_value_tx_with_signer(&signer, &pubkey, u64::default(), 100, U256::MAX);
        let hash = tx.hash();

        let err = insert_with_balance(&pool, tx, &verifier, &mut ws, &cs, U256::MAX)
            .expect_err("gas plus value above U256::MAX must be rejected");

        assert!(matches!(
            err,
            MempoolError::InsufficientBalance {
                needed: U256::MAX,
                have: U256::MAX
            }
        ));
        assert!(pool.is_empty());
        assert!(!pool.contains(&hash));
    }

    #[test]
    fn reservation_index_tracks_insert_remove_and_clear() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let first_nonce = u64::default();
        let second_nonce = first_nonce.checked_add(1).unwrap();
        let tx0 = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            first_nonce,
            50,
            U256::from(1_000u64),
        );
        let tx1 = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            second_nonce,
            50,
            U256::from(2_000u64),
        );
        let hash0 = tx0.hash();
        let cost0 = add_or_max(max_gas_cost(&tx0), tx0.tx.value);
        let cost1 = add_or_max(max_gas_cost(&tx1), tx1.tx.value);
        let total = cost0.checked_add(cost1).unwrap();

        insert_with_balance(&pool, tx0, &verifier, &mut ws, &cs, total).unwrap();
        assert_eq!(
            indexed_reservation(&pool, &sender).map(ReservationTotal::saturating_u256),
            Some(cost0)
        );

        insert_with_balance(&pool, tx1, &verifier, &mut ws, &cs, total).unwrap();
        let reserved = indexed_reservation(&pool, &sender).unwrap();
        assert_eq!(reserved.saturating_u256(), total);
        assert_eq!(reserved.overflow_units, 0);

        assert!(pool.remove(&hash0));
        assert_eq!(
            indexed_reservation(&pool, &sender).map(ReservationTotal::saturating_u256),
            Some(cost1)
        );

        pool.clear();
        assert!(indexed_reservation(&pool, &sender).is_none());
    }

    #[test]
    fn reject_pending_sender_balance_oversubscription() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let second_nonce = first_nonce.saturating_add(1);
        let tx0 = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            first_nonce,
            50,
            U256::from(1_000u64),
        );
        let tx1 = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            second_nonce,
            50,
            U256::from(1_000u64),
        );
        let h0 = tx0.hash();
        let h1 = tx1.hash();
        let one_tx_budget = U256::from(21_000u64 * 60)
            .checked_add(U256::from(1_000u64))
            .unwrap();

        insert_with_balance(&pool, tx0, &verifier, &mut ws, &cs, one_tx_budget).unwrap();
        let err =
            insert_with_balance(&pool, tx1, &verifier, &mut ws, &cs, one_tx_budget).unwrap_err();

        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&h0));
        assert!(!pool.contains(&h1));
    }

    #[test]
    fn sponsored_aa_accepts_sender_value_only_with_paymaster_gas() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let paymaster_signer = DilithiumSigner::generate();
        let paymaster_pubkey = paymaster_signer.public_key().to_vec();
        let paymaster = register_paymaster(&cs, &paymaster_pubkey);
        let value = U256::from(1_000u64);
        let first_nonce = u64::default();
        let tx = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            first_nonce,
            50,
            value,
        );
        let hash = tx.hash();
        let gas_budget = max_gas_cost(&tx);

        ws.set_balance(&sender, value).unwrap();
        ws.set_balance(&paymaster, gas_budget).unwrap();

        pool.insert(tx, &mut ws, &cs, &verifier).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));
        assert_eq!(
            indexed_reservation(&pool, &sender).map(ReservationTotal::saturating_u256),
            Some(value)
        );
        assert_eq!(
            indexed_reservation(&pool, &paymaster).map(ReservationTotal::saturating_u256),
            Some(gas_budget)
        );

        assert!(pool.remove(&hash));
        assert!(indexed_reservation(&pool, &sender).is_none());
        assert!(indexed_reservation(&pool, &paymaster).is_none());
    }

    #[test]
    fn balance_lookup_storage_failure_returns_storage_error() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let state_store = Arc::new(FailingPubkeyStore::new(false));
        let mut ws = WorldState::new(Arc::clone(&state_store));
        let cs = ChainStore::new(Arc::clone(&state_store));

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let paymaster_signer = DilithiumSigner::generate();
        let paymaster_pubkey = paymaster_signer.public_key().to_vec();
        let paymaster = register_paymaster(&cs, &paymaster_pubkey);
        let first_nonce = u64::default();
        let tx = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            first_nonce,
            50,
            U256::ZERO,
        );

        ws.set_balance(&paymaster, max_gas_cost(&tx)).unwrap();
        let mut ws = ws.snapshot().unwrap();
        // Cache the sender account so AA validation can complete; the following
        // balance check for the uncached paymaster must surface the storage fault.
        assert_eq!(ws.get_account(&sender).unwrap(), None);
        state_store.fail_gets();

        let err = pool.insert(tx, &mut ws, &cs, &verifier).unwrap_err();

        match err {
            MempoolError::Storage(err) => {
                assert!(err.to_string().contains("injected get failure"));
            }
            other => panic!("expected storage get failure, got {other:?}"),
        }
        assert_eq!(pool.len(), 0);
        assert_eq!(cs.get_pubkey(&paymaster).unwrap(), Some(paymaster_pubkey));
    }

    #[test]
    fn sponsored_aa_rejects_pending_paymaster_gas_oversubscription() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let paymaster_signer = DilithiumSigner::generate();
        let paymaster_pubkey = paymaster_signer.public_key().to_vec();
        let paymaster = register_paymaster(&cs, &paymaster_pubkey);
        let first_nonce = u64::default();
        let second_nonce = first_nonce.saturating_add(1);
        let tx0 = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            first_nonce,
            50,
            U256::from(1_000u64),
        );
        let tx1 = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            second_nonce,
            50,
            U256::from(1_000u64),
        );
        let h0 = tx0.hash();
        let h1 = tx1.hash();
        let one_tx_gas_budget = max_gas_cost(&tx0);

        ws.set_balance(&sender, U256::from(2_000u64)).unwrap();
        ws.set_balance(&paymaster, one_tx_gas_budget).unwrap();

        pool.insert(tx0, &mut ws, &cs, &verifier).unwrap();
        let err = pool.insert(tx1, &mut ws, &cs, &verifier).unwrap_err();

        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&h0));
        assert!(!pool.contains(&h1));
    }

    #[test]
    fn sponsored_aa_rejects_pending_sender_value_oversubscription() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let sender = test_address(&pubkey);
        let paymaster_signer = DilithiumSigner::generate();
        let paymaster_pubkey = paymaster_signer.public_key().to_vec();
        let paymaster = register_paymaster(&cs, &paymaster_pubkey);
        let first_nonce = u64::default();
        let second_nonce = first_nonce.saturating_add(1);
        let value = U256::from(1_000u64);
        let tx0 = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            first_nonce,
            50,
            value,
        );
        let tx1 = make_sponsored_aa_value_tx_with_signers(
            &signer,
            &pubkey,
            &paymaster_signer,
            &paymaster_pubkey,
            second_nonce,
            50,
            value,
        );
        let h0 = tx0.hash();
        let h1 = tx1.hash();
        let two_tx_gas_budget = max_gas_cost(&tx0).checked_add(max_gas_cost(&tx1)).unwrap();

        ws.set_balance(&sender, value).unwrap();
        ws.set_balance(&paymaster, two_tx_gas_budget).unwrap();

        pool.insert(tx0, &mut ws, &cs, &verifier).unwrap();
        let err = pool.insert(tx1, &mut ws, &cs, &verifier).unwrap_err();

        assert!(matches!(err, MempoolError::InsufficientBalance { .. }));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&h0));
        assert!(!pool.contains(&h1));
    }

    // --- F-021: RBF tests ---

    #[test]
    fn rbf_replaces_with_sufficient_fee_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let nonce = u64::default();

        // Insert tx at nonce 0 with priority_fee=100
        let tx_old = make_signed_tx_with_signer(&signer, &pubkey, nonce, 100);
        let old_hash = tx_old.hash();
        let old_size = serde_json::to_vec(&tx_old).unwrap().len();
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.size_bytes(), old_size);

        // Replace with priority_fee=111 (>= 110% of 100)
        let tx_new = make_signed_tx_with_signer(&signer, &pubkey, nonce, 111);
        let new_hash = tx_new.hash();
        let new_size = serde_json::to_vec(&tx_new).unwrap().len();
        insert_rich(&pool, tx_new, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 1);
        assert_eq!(pool.size_bytes(), new_size);
        assert!(!pool.contains(&old_hash));
        assert!(pool.contains(&new_hash));
    }

    #[test]
    fn rbf_balance_check_excludes_replaced_transaction() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let replacement_nonce = u64::default();
        let tx_old = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            replacement_nonce,
            100,
            U256::from(1_000u64),
        );
        let old_hash = tx_old.hash();
        let tx_new = make_signed_value_tx_with_signer(
            &signer,
            &pubkey,
            replacement_nonce,
            111,
            U256::from(1_500u64),
        );
        let new_hash = tx_new.hash();
        let new_tx_budget = U256::from(21_000u64 * 121)
            .checked_add(U256::from(1_500u64))
            .unwrap();

        insert_with_balance(&pool, tx_old, &verifier, &mut ws, &cs, new_tx_budget).unwrap();
        insert_with_balance(&pool, tx_new, &verifier, &mut ws, &cs, new_tx_budget).unwrap();

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
    fn rbf_rejects_replacement_that_lowers_max_fee_cap() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let nonce = u64::default();
        let old_tx = make_signed_value_tx_with_fees(&signer, &pubkey, nonce, 200, 100, U256::ZERO);
        let old_hash = old_tx.hash();
        insert_rich(&pool, old_tx, &verifier, &mut ws, &cs).unwrap();

        let replacement =
            make_signed_value_tx_with_fees(&signer, &pubkey, nonce, 150, 110, U256::from(1u64));
        let replacement_hash = replacement.hash();
        let err = insert_rich(&pool, replacement, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: 150,
                required: 220
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&replacement_hash));
    }

    #[test]
    fn rbf_rejects_unrepresentable_max_fee_cap_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let nonce = u64::default();
        let old_tx =
            make_signed_value_tx_with_fees(&signer, &pubkey, nonce, u64::MAX, 100, U256::ZERO);
        let old_hash = old_tx.hash();
        insert_with_balance(&pool, old_tx, &verifier, &mut ws, &cs, U256::MAX).unwrap();

        let replacement = make_signed_value_tx_with_fees(
            &signer,
            &pubkey,
            nonce,
            u64::MAX,
            110,
            U256::from(1u64),
        );
        let replacement_hash = replacement.hash();
        let err = insert_with_balance(&pool, replacement, &verifier, &mut ws, &cs, U256::MAX)
            .unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: u64::MAX,
                required: u64::MAX
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&replacement_hash));
    }

    #[test]
    fn rbf_rejects_blob_replacement_without_blob_fee_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let old_tx = make_blob_tx_with_signer(&signer, &pubkey, 100, 10, 100);
        let old_hash = old_tx.hash();
        insert_rich(&pool, old_tx, &verifier, &mut ws, &cs).unwrap();

        let replacement = make_blob_tx_with_signer(&signer, &pubkey, 110, 11, 100);
        let replacement_hash = replacement.hash();
        let err = insert_rich(&pool, replacement, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: 100,
                required: 110
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&replacement_hash));
    }

    #[test]
    fn rbf_rejects_blob_replacement_without_blob_fee_cap() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let old_tx = make_blob_tx_with_signer(&signer, &pubkey, 100, 10, 100);
        let old_hash = old_tx.hash();
        insert_rich(&pool, old_tx, &verifier, &mut ws, &cs).unwrap();

        let replacement = make_signed_value_tx_with_fees(&signer, &pubkey, 0, 110, 11, U256::ZERO);
        let replacement_hash = replacement.hash();
        let err = insert_rich(&pool, replacement, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: 0,
                required: 110
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&replacement_hash));
    }

    #[test]
    fn rbf_rejects_unrepresentable_blob_fee_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let old_tx = make_blob_tx_with_signer(&signer, &pubkey, 100, 10, u64::MAX);
        let old_hash = old_tx.hash();
        insert_with_balance(&pool, old_tx, &verifier, &mut ws, &cs, U256::MAX).unwrap();

        let replacement = make_blob_tx_with_signer(&signer, &pubkey, 110, 11, u64::MAX);
        let replacement_hash = replacement.hash();
        let err = insert_with_balance(&pool, replacement, &verifier, &mut ws, &cs, U256::MAX)
            .unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: u64::MAX,
                required: u64::MAX
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&replacement_hash));
    }

    #[test]
    fn rbf_zero_fee_replacement_requires_positive_bump() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let first_nonce = u64::default();
        let tx_old = make_signed_value_tx_with_signer(&signer, &pubkey, first_nonce, 0, U256::ZERO);
        let old_hash = tx_old.hash();
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();

        let zero_fee_replacement =
            make_signed_value_tx_with_signer(&signer, &pubkey, first_nonce, 0, U256::from(1u64));
        let zero_fee_hash = zero_fee_replacement.hash();
        let err = insert_rich(&pool, zero_fee_replacement, &verifier, &mut ws, &cs).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: 0,
                required: 1
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&zero_fee_hash));

        let bumped_replacement =
            make_signed_value_tx_with_signer(&signer, &pubkey, first_nonce, 1, U256::from(1u64));
        let bumped_hash = bumped_replacement.hash();
        insert_rich(&pool, bumped_replacement, &verifier, &mut ws, &cs).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&old_hash));
        assert!(pool.contains(&bumped_hash));
    }

    #[test]
    fn rbf_fee_bump_rounds_up_for_small_fees() {
        assert_eq!(replacement_fee_required(0, 10), Some(1));
        assert_eq!(replacement_fee_required(1, 10), Some(2));
        assert_eq!(replacement_fee_required(10, 10), Some(11));
        assert_eq!(replacement_fee_required(101, 10), Some(112));
    }

    #[test]
    fn rbf_fee_bump_rejects_unrepresentable_required_fee() {
        assert_eq!(replacement_fee_required(u64::MAX, 10), None);
        assert_eq!(replacement_fee_required(u64::MAX, 0), Some(u64::MAX));
    }

    #[test]
    fn rbf_rejects_max_fee_when_positive_bump_is_impossible() {
        let pool = TxPool::new(make_config());
        let verifier = DilithiumVerifier;
        let (mut ws, cs) = setup_validation_ctx();

        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let from = test_address(&pubkey);
        let recipient = test_address(b"recipient-placeholder-key-data-for-address");
        let first_nonce = u64::default();

        let make_max_fee_tx = |value: U256| {
            let tx = Transaction {
                chain_id: 42,
                nonce: first_nonce,
                to: Some(recipient),
                value,
                data: Bytes::default(),
                gas_limit: 21_000,
                max_fee_per_gas: u64::MAX,
                max_priority_fee_per_gas: u64::MAX,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let sig = signer.sign(tx.hash().as_bytes()).unwrap();
            SignedTransaction::with_pubkey(from, tx, sig, pubkey.clone())
        };

        let tx_old = make_max_fee_tx(U256::ZERO);
        let old_hash = tx_old.hash();
        insert_with_balance(&pool, tx_old, &verifier, &mut ws, &cs, U256::MAX).unwrap();

        let tx_new = make_max_fee_tx(U256::from(1u64));
        let new_hash = tx_new.hash();
        let err =
            insert_with_balance(&pool, tx_new, &verifier, &mut ws, &cs, U256::MAX).unwrap_err();

        assert!(matches!(
            err,
            MempoolError::ReplacementFeeTooLow {
                got: u64::MAX,
                required: u64::MAX
            }
        ));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&old_hash));
        assert!(!pool.contains(&new_hash));
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

        let tx_old = make_signed_value_tx_with_fees(&signer, &pubkey, 0, 100, 100, U256::ZERO);
        insert_rich(&pool, tx_old, &verifier, &mut ws, &cs).unwrap();

        // 115 < 120% of 100 → reject
        let tx_low = make_signed_value_tx_with_fees(&signer, &pubkey, 0, 115, 115, U256::ZERO);
        let err = insert_rich(&pool, tx_low, &verifier, &mut ws, &cs).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));

        // 120 >= 120% of 100 → accept
        let tx_ok = make_signed_value_tx_with_fees(&signer, &pubkey, 0, 120, 120, U256::ZERO);
        insert_rich(&pool, tx_ok, &verifier, &mut ws, &cs).unwrap();
        assert_eq!(pool.len(), 1);
    }
}
