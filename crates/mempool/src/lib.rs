//! Transaction mempool for shell-chain.
//!
//! Provides a thread-safe transaction pool that accepts, validates, orders,
//! and evicts pending transactions before they are included in blocks.
//!
//! # Architecture
//!
//! - [`TxPool`] — main pool holding pending transactions, keyed by hash
//! - [`MempoolConfig`] — configurable limits (max size, per-sender cap)
//! - [`MempoolError`] — typed errors for pool operations
//!
//! Transactions are ordered by priority fee (descending). Each sender has
//! an independent nonce-ordered queue to enable sequential inclusion.

mod config;
mod error;
mod pool;

pub use config::{MempoolConfig, DEFAULT_MAX_POOL_BYTES};
pub use error::MempoolError;
pub use pool::{TxPool, MAX_TX_SIZE};
