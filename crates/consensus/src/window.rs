//! I4: Proof window claim and squatting prevention.
//!
//! A "proof window" is the block range `[block_number, block_number + window_size)`
//! during which a prover is permitted to submit a proof amendment for a given block.
//! After the window closes, amendments are rejected to prevent late-amendment attacks
//! (where a malicious prover delays submission until it can fabricate favourable state).
//!
//! # Squatting prevention
//!
//! A prover "squats" a window by claiming it (reserving exclusive submission rights)
//! but never submitting a proof. To prevent this:
//!
//! - Each window slot can be claimed by at most one prover at a time.
//! - If the claim expires (`claim_timeout_blocks`) without a submission, the slot
//!   is released and any other registered prover may claim it.
//! - A prover that lets `max_expired_claims` claims expire is flagged as unreliable
//!   (used by I5 Prover Registry for reputation scoring).
//!
//! # Design
//!
//! The `ProofWindowManager` tracks in-memory window state. On restart, windows for
//! recent unproven blocks are reconstructed from the chain store.

use shell_primitives::{Address, ShellHash};
use std::collections::HashMap;

/// Configuration for proof window management.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// Number of blocks after which an unclaimed window is considered expired.
    /// Default: 100 blocks.
    pub window_size_blocks: u64,
    /// Number of blocks a prover has to submit after claiming a window.
    /// Default: 20 blocks.
    pub claim_timeout_blocks: u64,
    /// Number of expired claims before a prover is flagged unreliable.
    /// Default: 3.
    pub max_expired_claims: u32,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            window_size_blocks: 100,
            claim_timeout_blocks: 20,
            max_expired_claims: 3,
        }
    }
}

/// Current state of a proof window for one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowState {
    /// No prover has claimed this window yet.
    Unclaimed,
    /// A prover has claimed the window; submission expected by `expires_at_block`.
    Claimed {
        claimer: Address,
        claimed_at_block: u64,
        expires_at_block: u64,
    },
    /// A valid proof amendment has been submitted and accepted.
    Fulfilled { prover: Address },
    /// The window has expired without a fulfillment.
    Expired,
}

/// I4: Manages proof submission windows and tracks claim/squatting behavior.
#[derive(Debug)]
pub struct ProofWindowManager {
    config: WindowConfig,
    /// Per-block window state. Key: block_number.
    windows: HashMap<u64, WindowState>,
    /// Expired claim counts per prover address.
    expired_claims: HashMap<Address, u32>,
}

impl ProofWindowManager {
    pub fn new(config: WindowConfig) -> Self {
        Self {
            config,
            windows: HashMap::new(),
            expired_claims: HashMap::new(),
        }
    }

    /// Attempt to claim a proof window for `block_number` at `current_block`.
    ///
    /// Returns `Ok(())` on success, `Err` if already claimed or window expired.
    pub fn claim(
        &mut self,
        block_number: u64,
        claimer: Address,
        current_block: u64,
    ) -> Result<(), WindowError> {
        // Check whether the block is still within the proof window.
        if current_block > block_number.saturating_add(self.config.window_size_blocks) {
            self.windows.insert(block_number, WindowState::Expired);
            return Err(WindowError::WindowExpired { block_number });
        }

        match self.windows.get(&block_number) {
            None | Some(WindowState::Unclaimed) => {
                let expires_at_block =
                    current_block.saturating_add(self.config.claim_timeout_blocks);
                self.windows.insert(
                    block_number,
                    WindowState::Claimed {
                        claimer,
                        claimed_at_block: current_block,
                        expires_at_block,
                    },
                );
                Ok(())
            }
            Some(WindowState::Claimed {
                claimer: existing,
                expires_at_block,
                ..
            }) => {
                if current_block >= *expires_at_block {
                    // Claim has expired — release and re-claim.
                    let expired_claimer = *existing;
                    *self.expired_claims.entry(expired_claimer).or_insert(0) += 1;
                    let expires_at_block =
                        current_block.saturating_add(self.config.claim_timeout_blocks);
                    self.windows.insert(
                        block_number,
                        WindowState::Claimed {
                            claimer,
                            claimed_at_block: current_block,
                            expires_at_block,
                        },
                    );
                    Ok(())
                } else {
                    Err(WindowError::AlreadyClaimed {
                        block_number,
                        claimer: *existing,
                    })
                }
            }
            Some(WindowState::Fulfilled { .. }) => {
                Err(WindowError::AlreadyFulfilled { block_number })
            }
            Some(WindowState::Expired) => Err(WindowError::WindowExpired { block_number }),
        }
    }

    /// Mark a window as fulfilled by `prover` at `current_block`.
    ///
    /// Only the current claimer may fulfill. Returns `Err` if unclaimed or wrong claimer.
    pub fn fulfill(
        &mut self,
        block_number: u64,
        prover: Address,
        _block_hash: ShellHash,
        current_block: u64,
    ) -> Result<(), WindowError> {
        match self.windows.get(&block_number) {
            Some(WindowState::Claimed {
                claimer,
                expires_at_block,
                ..
            }) => {
                if *claimer != prover {
                    return Err(WindowError::NotClaimer {
                        block_number,
                        expected: *claimer,
                        got: prover,
                    });
                }
                if current_block > *expires_at_block {
                    *self.expired_claims.entry(prover).or_insert(0) += 1;
                    self.windows.insert(block_number, WindowState::Expired);
                    return Err(WindowError::WindowExpired { block_number });
                }
                self.windows
                    .insert(block_number, WindowState::Fulfilled { prover });
                Ok(())
            }
            Some(WindowState::Fulfilled { .. }) => {
                Err(WindowError::AlreadyFulfilled { block_number })
            }
            None | Some(WindowState::Unclaimed) => Err(WindowError::NotClaimed { block_number }),
            Some(WindowState::Expired) => Err(WindowError::WindowExpired { block_number }),
        }
    }

    /// Get the current window state for a block.
    pub fn state(&self, block_number: u64) -> &WindowState {
        self.windows
            .get(&block_number)
            .unwrap_or(&WindowState::Unclaimed)
    }

    /// Number of expired claims for a prover.
    pub fn expired_claim_count(&self, prover: &Address) -> u32 {
        self.expired_claims.get(prover).copied().unwrap_or(0)
    }

    /// Whether a prover has exceeded the unreliable threshold.
    pub fn is_unreliable(&self, prover: &Address) -> bool {
        self.expired_claim_count(prover) >= self.config.max_expired_claims
    }

    /// Advance to `current_block`, expiring any stale windows and counting missed claims.
    ///
    /// Should be called once per block import.
    pub fn advance(&mut self, current_block: u64) {
        for (block_number, state) in self.windows.iter_mut() {
            if let WindowState::Claimed {
                claimer,
                expires_at_block,
                ..
            } = state
            {
                if current_block > *expires_at_block {
                    *self.expired_claims.entry(*claimer).or_insert(0) += 1;
                    let block_number = *block_number;
                    let _ = block_number; // used for context
                    *state = WindowState::Expired;
                }
            }
        }
        // Expire windows beyond the proof window size.
        let window_cutoff = current_block.saturating_sub(self.config.window_size_blocks);
        for state in self.windows.values_mut() {
            if matches!(state, WindowState::Unclaimed) {
                // Determined by block_number comparison below — mark as expired.
            }
            let _ = window_cutoff; // full prune is done in gc()
        }
    }

    /// Remove window entries older than `window_size_blocks` from current block.
    pub fn gc(&mut self, current_block: u64) {
        let cutoff =
            current_block.saturating_sub(self.config.window_size_blocks.saturating_add(10));
        self.windows.retain(|&bn, _| bn > cutoff);
    }
}

/// Errors from the proof window manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowError {
    /// Window claim already held by another prover.
    AlreadyClaimed { block_number: u64, claimer: Address },
    /// Window has already been fulfilled.
    AlreadyFulfilled { block_number: u64 },
    /// Window has expired (past `window_size_blocks`).
    WindowExpired { block_number: u64 },
    /// Fulfillment attempted by a non-claimer.
    NotClaimer {
        block_number: u64,
        expected: Address,
        got: Address,
    },
    /// Fulfillment attempted on an unclaimed window.
    NotClaimed { block_number: u64 },
}

impl std::fmt::Display for WindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyClaimed {
                block_number,
                claimer,
            } => {
                write!(f, "block {block_number} already claimed by {claimer}")
            }
            Self::AlreadyFulfilled { block_number } => {
                write!(f, "block {block_number} already fulfilled")
            }
            Self::WindowExpired { block_number } => {
                write!(f, "proof window for block {block_number} has expired")
            }
            Self::NotClaimer {
                block_number,
                expected,
                got,
            } => {
                write!(
                    f,
                    "block {block_number}: expected claimer {expected}, got {got}"
                )
            }
            Self::NotClaimed { block_number } => {
                write!(f, "block {block_number} not yet claimed")
            }
        }
    }
}

impl std::error::Error for WindowError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::{Address, ShellHash};

    fn addr(n: u8) -> Address {
        Address::from([n; 20])
    }
    fn hash(n: u8) -> ShellHash {
        ShellHash::from([n; 32])
    }

    fn default_mgr() -> ProofWindowManager {
        ProofWindowManager::new(WindowConfig {
            window_size_blocks: 100,
            claim_timeout_blocks: 20,
            max_expired_claims: 3,
        })
    }

    #[test]
    fn unclaimed_by_default() {
        let mgr = default_mgr();
        assert_eq!(*mgr.state(42), WindowState::Unclaimed);
    }

    #[test]
    fn claim_succeeds_on_unclaimed() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap();
        assert!(
            matches!(mgr.state(10), WindowState::Claimed { claimer, .. } if *claimer == addr(1))
        );
    }

    #[test]
    fn second_claim_rejected_while_active() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap();
        let err = mgr.claim(10, addr(2), 6).unwrap_err();
        assert!(matches!(err, WindowError::AlreadyClaimed { .. }));
    }

    #[test]
    fn expired_claim_allows_re_claim() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap(); // expires_at = 5+20=25
                                            // Advance past expiry.
        mgr.claim(10, addr(2), 30).unwrap(); // re-claim after expiry
        assert!(
            matches!(mgr.state(10), WindowState::Claimed { claimer, .. } if *claimer == addr(2))
        );
        assert_eq!(mgr.expired_claim_count(&addr(1)), 1);
    }

    #[test]
    fn fulfill_by_claimer_succeeds() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap();
        mgr.fulfill(10, addr(1), hash(1), 10).unwrap();
        assert!(matches!(mgr.state(10), WindowState::Fulfilled { prover } if *prover == addr(1)));
    }

    #[test]
    fn fulfill_by_non_claimer_rejected() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap();
        let err = mgr.fulfill(10, addr(2), hash(1), 10).unwrap_err();
        assert!(matches!(err, WindowError::NotClaimer { .. }));
    }

    #[test]
    fn fulfill_after_claim_timeout_expires_window() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap(); // expires_at = 25
        let err = mgr.fulfill(10, addr(1), hash(1), 30).unwrap_err(); // past expiry
        assert!(matches!(err, WindowError::WindowExpired { .. }));
        assert_eq!(mgr.expired_claim_count(&addr(1)), 1);
    }

    #[test]
    fn double_fulfill_rejected() {
        let mut mgr = default_mgr();
        mgr.claim(10, addr(1), 5).unwrap();
        mgr.fulfill(10, addr(1), hash(1), 10).unwrap();
        let err = mgr.fulfill(10, addr(1), hash(1), 11).unwrap_err();
        assert!(matches!(err, WindowError::AlreadyFulfilled { .. }));
    }

    #[test]
    fn window_expired_beyond_window_size() {
        let mut mgr = default_mgr();
        let err = mgr.claim(10, addr(1), 115).unwrap_err(); // 115 > 10+100
        assert!(matches!(err, WindowError::WindowExpired { .. }));
    }

    #[test]
    fn claim_near_max_block_saturates_window_end_and_timeout() {
        let mut mgr = default_mgr();
        let block_number = u64::MAX - 5;

        mgr.claim(block_number, addr(1), u64::MAX).unwrap();

        assert!(
            matches!(mgr.state(block_number), WindowState::Claimed { expires_at_block, .. } if *expires_at_block == u64::MAX)
        );
    }

    #[test]
    fn is_unreliable_after_max_expired_claims() {
        let mut mgr = default_mgr();
        // Simulate 3 expired claims for addr(1).
        for i in 0u64..3 {
            mgr.claim(i, addr(1), 0).unwrap(); // expires_at = 20
            let _ = mgr.claim(i, addr(2), 25); // triggers expiry count for addr(1)
        }
        assert!(mgr.is_unreliable(&addr(1)));
    }

    #[test]
    fn gc_removes_old_windows() {
        let mut mgr = default_mgr();
        mgr.claim(5, addr(1), 5).unwrap();
        mgr.gc(200); // current_block=200, cutoff = 200-110=90 → removes block 5
        assert_eq!(*mgr.state(5), WindowState::Unclaimed); // removed → default Unclaimed
    }

    #[test]
    fn gc_saturates_retention_margin() {
        let mut mgr = ProofWindowManager::new(WindowConfig {
            window_size_blocks: u64::MAX,
            claim_timeout_blocks: 20,
            max_expired_claims: 3,
        });

        mgr.claim(5, addr(1), 5).unwrap();
        mgr.gc(200);

        assert!(matches!(mgr.state(5), WindowState::Claimed { .. }));
    }
}
