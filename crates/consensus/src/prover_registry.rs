//! I5: Prover registry and anti-Sybil defense.
//!
//! The `ProverRegistry` tracks registered standalone prover nodes, their
//! reputation scores, and enforces minimum-stake requirements to prevent
//! Sybil attacks where many low-quality provers flood the network.
//!
//! # Registration
//!
//! A node registers as a prover by calling `register()` with their address
//! and a declared stake amount. The registry records the registration and
//! assigns an initial reputation score.
//!
//! # Reputation
//!
//! Reputation decays over time (blocks without activity) and increases with
//! successful proof submissions. Provers whose reputation falls below
//! `min_reputation` are automatically deregistered.
//!
//! # Anti-Sybil
//!
//! - `min_stake`: minimum declared stake to register (not verified on-chain yet;
//!   on-chain verification is deferred to M-future).
//! - `max_provers_per_ip`: limit on registrations sharing the same IP prefix
//!   (enforced at the network layer; tracked here for context).
//! - Provers flagged as unreliable by the `ProofWindowManager` (I4) receive
//!   a reputation penalty via `penalize()`.

use shell_primitives::Address;
use std::collections::HashMap;

/// Configuration for the prover registry.
#[derive(Debug, Clone)]
pub struct ProverRegistryConfig {
    /// Minimum declared stake to register. Default: 1000 (arbitrary units).
    pub min_stake: u64,
    /// Initial reputation score on registration. Default: 100.
    pub initial_reputation: i64,
    /// Reputation below which a prover is auto-deregistered. Default: 0.
    pub min_reputation: i64,
    /// Reputation added per successful proof submission. Default: 10.
    pub reputation_per_proof: i64,
    /// Reputation penalty per expired window claim (I4 integration). Default: -20.
    pub penalty_expired_claim: i64,
    /// Reputation penalty per invalid proof submission. Default: -50.
    pub penalty_invalid_proof: i64,
    /// Reputation decay per block of inactivity. Default: -1 per 100 blocks.
    pub decay_per_100_blocks: i64,
}

impl Default for ProverRegistryConfig {
    fn default() -> Self {
        Self {
            min_stake: 1_000,
            initial_reputation: 100,
            min_reputation: 0,
            reputation_per_proof: 10,
            penalty_expired_claim: -20,
            penalty_invalid_proof: -50,
            decay_per_100_blocks: -1,
        }
    }
}

/// Registration record for one prover.
#[derive(Debug, Clone)]
pub struct ProverRecord {
    /// Declared stake (not yet verified on-chain).
    pub stake: u64,
    /// Current reputation score.
    pub reputation: i64,
    /// Block at which this prover was registered.
    pub registered_at_block: u64,
    /// Last block at which this prover submitted a valid proof.
    pub last_active_block: u64,
    /// Total successful proofs submitted.
    pub proofs_submitted: u64,
}

/// Error conditions from the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Stake below the minimum required.
    InsufficientStake { provided: u64, required: u64 },
    /// Prover is already registered.
    AlreadyRegistered,
    /// Prover is not registered.
    NotRegistered,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientStake { provided, required } => {
                write!(f, "stake {provided} below minimum {required}")
            }
            Self::AlreadyRegistered => write!(f, "prover already registered"),
            Self::NotRegistered => write!(f, "prover not registered"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// I5: Registry of known standalone prover nodes with reputation tracking.
#[derive(Debug)]
pub struct ProverRegistry {
    config: ProverRegistryConfig,
    provers: HashMap<Address, ProverRecord>,
}

impl ProverRegistry {
    pub fn new(config: ProverRegistryConfig) -> Self {
        Self {
            config,
            provers: HashMap::new(),
        }
    }

    /// Register a new prover node.
    pub fn register(
        &mut self,
        address: Address,
        stake: u64,
        current_block: u64,
    ) -> Result<(), RegistryError> {
        if stake < self.config.min_stake {
            return Err(RegistryError::InsufficientStake {
                provided: stake,
                required: self.config.min_stake,
            });
        }
        if self.provers.contains_key(&address) {
            return Err(RegistryError::AlreadyRegistered);
        }
        self.provers.insert(
            address,
            ProverRecord {
                stake,
                reputation: self.config.initial_reputation,
                registered_at_block: current_block,
                last_active_block: current_block,
                proofs_submitted: 0,
            },
        );
        Ok(())
    }

    /// Deregister a prover (voluntary exit or forced by low reputation).
    pub fn deregister(&mut self, address: &Address) -> Result<(), RegistryError> {
        self.provers
            .remove(address)
            .ok_or(RegistryError::NotRegistered)?;
        Ok(())
    }

    /// Record a successful proof submission.
    pub fn record_proof(
        &mut self,
        address: &Address,
        current_block: u64,
    ) -> Result<(), RegistryError> {
        let record = self
            .provers
            .get_mut(address)
            .ok_or(RegistryError::NotRegistered)?;
        record.proofs_submitted += 1;
        record.last_active_block = current_block;
        record.reputation = (record.reputation + self.config.reputation_per_proof)
            .min(self.config.initial_reputation * 2);
        Ok(())
    }

    /// Apply a reputation penalty.
    pub fn penalize(&mut self, address: &Address, penalty: i64) -> Result<(), RegistryError> {
        let record = self
            .provers
            .get_mut(address)
            .ok_or(RegistryError::NotRegistered)?;
        record.reputation += penalty;
        Ok(())
    }

    /// Apply reputation decay and deregister provers below `min_reputation`.
    ///
    /// Call once per epoch boundary.
    pub fn advance(&mut self, current_block: u64) {
        let decay = self.config.decay_per_100_blocks;
        let min_rep = self.config.min_reputation;

        let mut to_remove = Vec::new();
        for (addr, record) in self.provers.iter_mut() {
            let inactive_blocks = current_block.saturating_sub(record.last_active_block);
            let periods = inactive_blocks / 100;
            if periods > 0 {
                record.reputation += decay * periods as i64;
            }
            if record.reputation <= min_rep {
                to_remove.push(*addr);
            }
        }
        for addr in to_remove {
            self.provers.remove(&addr);
        }
    }

    /// Get a prover's record.
    pub fn get(&self, address: &Address) -> Option<&ProverRecord> {
        self.provers.get(address)
    }

    /// Whether an address is a registered prover.
    pub fn is_registered(&self, address: &Address) -> bool {
        self.provers.contains_key(address)
    }

    /// Number of registered provers.
    pub fn len(&self) -> usize {
        self.provers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.provers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shell_primitives::Address;

    fn addr(n: u8) -> Address {
        Address::from([n; 20])
    }

    fn registry() -> ProverRegistry {
        ProverRegistry::new(ProverRegistryConfig::default())
    }

    #[test]
    fn register_with_sufficient_stake_succeeds() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        assert!(r.is_registered(&addr(1)));
    }

    #[test]
    fn register_with_insufficient_stake_fails() {
        let mut r = registry();
        let err = r.register(addr(1), 500, 0).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientStake { .. }));
    }

    #[test]
    fn double_register_fails() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        assert_eq!(
            r.register(addr(1), 1_000, 0),
            Err(RegistryError::AlreadyRegistered)
        );
    }

    #[test]
    fn deregister_removes_prover() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        r.deregister(&addr(1)).unwrap();
        assert!(!r.is_registered(&addr(1)));
    }

    #[test]
    fn deregister_unknown_fails() {
        let mut r = registry();
        assert_eq!(r.deregister(&addr(99)), Err(RegistryError::NotRegistered));
    }

    #[test]
    fn record_proof_increments_count_and_reputation() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        r.record_proof(&addr(1), 5).unwrap();
        let record = r.get(&addr(1)).unwrap();
        assert_eq!(record.proofs_submitted, 1);
        assert_eq!(record.reputation, 110); // 100 + 10
    }

    #[test]
    fn penalize_reduces_reputation() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        r.penalize(&addr(1), -20).unwrap();
        assert_eq!(r.get(&addr(1)).unwrap().reputation, 80);
    }

    #[test]
    fn advance_deregisters_below_min_reputation() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        // Bring reputation to 1.
        r.penalize(&addr(1), -99).unwrap();
        // Advance 100 blocks — decay of -1 brings to 0 → deregistered.
        r.advance(100);
        assert!(!r.is_registered(&addr(1)));
    }

    #[test]
    fn advance_keeps_active_prover() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        r.record_proof(&addr(1), 50).unwrap(); // last_active=50
        r.advance(100); // inactive 50 blocks → 0 periods of 100 → no decay
        assert!(r.is_registered(&addr(1)));
    }

    #[test]
    fn reputation_capped_at_double_initial() {
        let mut r = registry();
        r.register(addr(1), 1_000, 0).unwrap();
        for _ in 0..25 {
            r.record_proof(&addr(1), 1).unwrap();
        }
        let rep = r.get(&addr(1)).unwrap().reputation;
        assert_eq!(rep, 200); // capped at 2 * initial (100)
    }
}
