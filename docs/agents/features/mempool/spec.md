# Feature: Mempool

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `mempool` · Priority P2 · Module `shell-chain/crates/mempool`

## 1. Purpose

Thread-safe in-memory transaction pool for shell-chain. Accepts, validates, deduplicates,
and priority-orders transactions so that block proposers can reliably drain the highest-fee
transactions. Also handles Native-AA bundle admission.

## 2. Public API Surface

```rust
// crates/mempool/src/lib.rs (re-exports)
pub use config::MempoolConfig;
pub use error::MempoolError;
pub use pool::{TxPool, MAX_TX_SIZE};

// MAX_TX_SIZE = 128 * 1024 bytes (128 KiB)

impl TxPool {
    pub fn new(config: MempoolConfig) -> Self;

    /// Validate and admit a transaction.
    /// Returns MempoolError on duplicate hash, oversized tx, invalid nonce, low fee.
    pub fn add_tx(&self, tx: SignedTransaction) -> Result<(), MempoolError>;

    /// Return up to `limit` pending transactions ordered by priority fee (desc).
    pub fn pending_transactions(&self, limit: usize) -> Vec<SignedTransaction>;

    /// Return up to `limit` queued (nonce-gapped) transactions.
    pub fn queued_transactions(&self, limit: usize) -> Vec<SignedTransaction>;

    /// Remove a transaction by hash (after inclusion in a block).
    pub fn remove(&self, hash: &ShellHash) -> bool;

    /// Remove all transactions from a given sender with nonce <= committed_nonce.
    pub fn prune_committed(&self, sender: Address, committed_nonce: u64);

    /// Total number of pending transactions.
    pub fn pending_count(&self) -> usize;
}

pub struct MempoolConfig {
    pub max_pool_size: usize,     // default: 4096
    pub max_per_sender: usize,    // default: 64
    pub chain_id: u64,            // default: 1
}
```

## 3. Implementation Map

| Component | File | Notes |
|-----------|------|-------|
| `TxPool`, `MAX_TX_SIZE` | `crates/mempool/src/pool.rs` | Core pool; `Arc<Mutex<Inner>>` for thread safety |
| `MempoolConfig` | `crates/mempool/src/config.rs` | `max_pool_size=4096`, `max_per_sender=64`, `chain_id=1` |
| `MempoolError` | `crates/mempool/src/error.rs` | Typed error variants |
| Public re-exports | `crates/mempool/src/lib.rs:1-22` | Full crate surface |

### Internal data structures

The pool maintains two logical queues per sender:
- **pending**: transactions with `nonce == account_nonce` (immediately packagable).
- **queued**: transactions with `nonce > account_nonce` (nonce gap; held until gap closes).

Ordering within `pending` uses a **fee-priority BTreeMap** keyed by
`(max_priority_fee_per_gas DESC, tx_hash)`. This ensures highest-fee transactions are
returned first by `pending_transactions(limit)`.

Eviction: when `pending_count() >= max_pool_size`, the lowest-fee pending transaction is
evicted to make room for a higher-fee new entry. Queued transactions are evicted by LRU.

### AA bundle handling

Before admission, AA bundles (`tx_type == 0x7E`) are validated by
`validate_aa_bundle_structure` (from `shell-evm`). Structure checks include:
- At least 1 inner call, at most `MAX_INNER_CALLS` (16).
- Each inner call must have non-zero `gas_limit`.
- `paymaster` field, if present, must be a registered address.

AA bundles proceed through the same pending/queued nonce queue as regular transactions.

### Transaction size guard

`MAX_TX_SIZE = 128 * 1024` bytes. Transactions exceeding this are rejected with
`MempoolError::TooLarge` before any cryptographic validation is performed.

## 4. Invariants

- **INV-MEM-1**: Duplicate transaction hashes (same `ShellHash`) are rejected immediately;
  the pool is deduplicated by hash.
- **INV-MEM-2**: `pending_transactions(limit)` MUST return transactions in descending
  `max_priority_fee_per_gas` order. Block proposers rely on this ordering.
- **INV-MEM-3**: No transaction may exceed `MAX_TX_SIZE` bytes after RLP encoding.
- **INV-MEM-4**: Per-sender queue depth MUST NOT exceed `max_per_sender`. Excess new
  transactions from the same sender are rejected with `MempoolError::SenderQueueFull`.
- **INV-MEM-5**: AA bundle structure MUST pass `validate_aa_bundle_structure` before admission.
  PQ signature verification is NOT performed at mempool ingress (deferred to block execution).

## 5. Tests

Tests live in `crates/mempool/src/pool.rs` (inline `#[cfg(test)]`).

Key test cases:
- Valid transaction admitted, retrievable by `pending_transactions`.
- Duplicate hash rejected with `MempoolError::AlreadyKnown`.
- Oversized transaction rejected with `MempoolError::TooLarge`.
- `pending_transactions(limit)` returns correct count in fee-descending order.
- `prune_committed` removes all sender transactions with nonce ≤ committed.
- `max_per_sender` cap enforced.
- Pool capacity eviction: lowest-fee tx evicted when pool is full.

Run: `cargo test -p shell-mempool -- --nocapture`

## 6. Related ADRs

- (historical AA design — superseded by `features/account-abstraction/spec.md`) — AaBundle tx_type 0x7E format

## 7. Known Limitations / Open Work

- PQ signature verification is deferred to block execution (not validated at mempool ingress).
  A fast pre-check using cached pubkeys is planned to prevent DoS via bogus-signature flooding.
- No persistent mempool: pool contents are lost on node restart.
- Queued transaction eviction strategy (LRU) is simplistic; age-based expiry not yet implemented.
- `max_pool_size` is a count cap, not a byte-budget cap.

## 8. Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Spec rewritten from draft; corrected data-structure details, added AA bundle admission, MAX_TX_SIZE, MempoolConfig fields |
| M2 | Initial draft spec |
