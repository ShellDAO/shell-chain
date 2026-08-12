//! Validator information, lifecycle state machine, and weighted validator set.
//!
//! Models the Pending → Active → Exiting → Exited / Slashed lifecycle
//! for wPoA validators, plus weighted round-robin proposer selection.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use shell_primitives::Address;

use crate::ConsensusError;

// ---------------------------------------------------------------------------
// Validator status and info
// ---------------------------------------------------------------------------

/// Lifecycle state of a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Registered but not yet included in the active set.
    Pending,
    /// Actively participating in consensus.
    Active,
    /// Exit requested; waiting for the cooldown period to expire.
    Exiting {
        /// Epoch at which this validator becomes `Exited`.
        exit_epoch: u64,
    },
    /// Fully exited — no longer in the active set.
    Exited,
    /// Slashed for misbehaviour; removed from the active set immediately.
    Slashed,
}

impl ValidatorStatus {
    /// Return `true` if the validator participates in active consensus.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Per-validator state tracked by the consensus layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address (also the proposer identity).
    pub address: Address,
    /// Relative voting/proposer weight (default: 1).
    pub weight: u64,
    /// Lifecycle state.
    pub status: ValidatorStatus,
    /// Epoch in which the validator was activated (`None` = not yet activated).
    pub activation_epoch: Option<u64>,
    /// Epoch in which the validator exited or was slashed (`None` = not yet).
    pub exit_epoch: Option<u64>,
}

impl ValidatorInfo {
    /// Create a new validator in `Active` state with weight 1.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            weight: 1,
            status: ValidatorStatus::Active,
            activation_epoch: None,
            exit_epoch: None,
        }
    }

    /// Create a validator in `Pending` state.
    pub fn pending(address: Address) -> Self {
        Self {
            address,
            weight: 1,
            status: ValidatorStatus::Pending,
            activation_epoch: None,
            exit_epoch: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ValidatorSet — ordered, weighted set with lifecycle support
// ---------------------------------------------------------------------------

/// Parameters governing activation and exit throughput.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetConfig {
    /// Maximum number of validators that may be activated per epoch.
    pub max_activations_per_epoch: u64,
    /// Number of epochs a validator must wait after calling `begin_exit`
    /// before becoming `Exited`.
    pub exit_cooldown_epochs: u64,
}

impl Default for ValidatorSetConfig {
    fn default() -> Self {
        Self {
            max_activations_per_epoch: 5,
            exit_cooldown_epochs: 2,
        }
    }
}

/// Ordered, weighted set of validators with lifecycle management.
///
/// Ordering is preserved so that deterministic weighted round-robin proposer
/// selection is consistent across all nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Validators keyed by address; insertion order preserved in `order`.
    validators: HashMap<Address, ValidatorInfo>,
    /// Insertion-ordered list of all validator addresses (all statuses).
    order: Vec<Address>,
    /// Pending activation queue (FIFO).
    activation_queue: VecDeque<Address>,
    /// Configuration.
    config: ValidatorSetConfig,
}

impl ValidatorSet {
    /// Create an empty `ValidatorSet` with the given configuration.
    pub fn new(config: ValidatorSetConfig) -> Self {
        Self {
            validators: HashMap::new(),
            order: Vec::new(),
            activation_queue: VecDeque::new(),
            config,
        }
    }

    /// Create a `ValidatorSet` pre-populated from genesis data.
    ///
    /// All provided validators start in `Active` state.
    pub fn from_genesis(
        entries: impl IntoIterator<Item = (Address, u64)>,
        config: ValidatorSetConfig,
    ) -> Self {
        let mut set = Self::new(config);
        for (address, weight) in entries {
            let mut info = ValidatorInfo::new(address);
            info.weight = weight.clamp(1, shell_primitives::MAX_VALIDATOR_WEIGHT);
            info.activation_epoch = Some(0);
            set.order.push(address);
            set.validators.insert(address, info);
        }
        set
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Return all `Active` validators in deterministic order.
    pub fn active_validators(&self) -> Vec<&ValidatorInfo> {
        self.order
            .iter()
            .filter_map(|a| {
                let v = self.validators.get(a)?;
                if v.status.is_active() {
                    Some(v)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the number of active validators.
    pub fn active_count(&self) -> usize {
        self.order
            .iter()
            .filter_map(|address| self.validators.get(address))
            .filter(|validator| validator.status.is_active())
            .count()
    }

    /// Return validator info for `address`, or `None` if not found.
    pub fn get(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.get(address)
    }

    /// Return `true` if `address` is an active validator.
    pub fn is_active(&self, address: &Address) -> bool {
        self.validators
            .get(address)
            .map(|v| v.status.is_active())
            .unwrap_or(false)
    }

    // ── Weighted proposer selection ───────────────────────────────────────

    /// Compute the expected proposer for `block_number` using weighted round-robin.
    ///
    /// Algorithm:
    ///   1. Compute `slot = block_number % total_weight`.
    ///   2. Walk the ordered active validator list, subtracting weights until
    ///      the slot falls in the current validator's range.
    ///
    /// Returns `None` only if there are no active validators (should never
    /// occur in a live network).
    pub fn weighted_proposer(&self, block_number: u64) -> Option<Address> {
        let active = || {
            self.order.iter().filter_map(|address| {
                let validator = self.validators.get(address)?;
                validator.status.is_active().then_some(validator)
            })
        };
        let total =
            active().try_fold(0u64, |total, validator| total.checked_add(validator.weight))?;
        if total == 0 && active().next().is_none() {
            return None;
        }
        if total == 0 {
            // Fallback: plain round-robin when all weights are 0.
            let active_count = active().count();
            let idx = (block_number as usize)
                .checked_rem(active_count)
                .unwrap_or(0);
            return active().nth(idx).map(|validator| validator.address);
        }

        let slot = block_number.checked_rem(total).unwrap_or(0);
        let mut cumulative: u64 = 0;
        let mut last = None;
        for validator in active() {
            last = Some(validator.address);
            cumulative = cumulative.checked_add(validator.weight)?;
            if slot < cumulative {
                return Some(validator.address);
            }
        }
        // Unreachable: slot < total means we always find a validator.
        last
    }

    // ── Lifecycle mutations ───────────────────────────────────────────────

    /// Add a new validator to the activation queue (status = `Pending`).
    ///
    /// Returns `Err` if the address is already tracked.
    pub fn enqueue(&mut self, address: Address) -> Result<(), ConsensusError> {
        if self.validators.contains_key(&address) {
            return Err(ConsensusError::AlreadyValidator(address));
        }
        let info = ValidatorInfo::pending(address);
        self.order.push(address);
        self.validators.insert(address, info);
        self.activation_queue.push_back(address);
        Ok(())
    }

    /// Set the weight of an existing validator.
    ///
    /// Returns `Err` if the validator is not found or is not `Active`.
    pub fn set_weight(&mut self, address: &Address, weight: u64) -> Result<(), ConsensusError> {
        let info = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::UnknownProposer(*address))?;
        if !info.status.is_active() {
            return Err(ConsensusError::InvalidLifecycleTransition(format!(
                "{address} is not active"
            )));
        }
        if weight == 0 || weight > shell_primitives::MAX_VALIDATOR_WEIGHT {
            return Err(ConsensusError::InvalidLifecycleTransition(format!(
                "validator weight must be between 1 and {}",
                shell_primitives::MAX_VALIDATOR_WEIGHT
            )));
        }
        info.weight = weight;
        Ok(())
    }

    /// Process the activation queue at the start of epoch `epoch`.
    ///
    /// Activates up to `max_activations_per_epoch` pending validators.
    pub fn process_activations(&mut self, epoch: u64) {
        let mut activated = 0u64;
        while activated < self.config.max_activations_per_epoch {
            let Some(addr) = self.activation_queue.pop_front() else {
                break;
            };
            if let Some(info) = self.validators.get_mut(&addr) {
                if info.status == ValidatorStatus::Pending {
                    info.status = ValidatorStatus::Active;
                    info.activation_epoch = Some(epoch);
                    activated += 1;
                }
            }
        }
    }

    /// Finalize validators that have completed their exit cooldown.
    pub fn process_exits(&mut self, epoch: u64) {
        for info in self.validators.values_mut() {
            if let ValidatorStatus::Exiting { exit_epoch } = info.status {
                if epoch >= exit_epoch {
                    info.status = ValidatorStatus::Exited;
                    info.exit_epoch = Some(epoch);
                }
            }
        }
    }

    /// Start the exit process for `address`.
    ///
    /// Returns `Err` if the validator is not active, or if slashing/exit
    /// would leave the active set empty.
    pub fn begin_exit(
        &mut self,
        address: &Address,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        // Ensure at least 1 active validator remains.
        if self.active_count() <= 1 {
            return Err(ConsensusError::LastValidator);
        }
        let info = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::UnknownProposer(*address))?;
        if !info.status.is_active() {
            return Err(ConsensusError::InvalidLifecycleTransition(format!(
                "{address} is not active"
            )));
        }
        let exit_epoch = current_epoch.saturating_add(self.config.exit_cooldown_epochs);
        info.status = ValidatorStatus::Exiting { exit_epoch };
        Ok(())
    }

    /// Slash a validator, immediately removing it from the active set.
    ///
    /// Returns `Err` if the validator is not found or if slashing would
    /// leave the active set empty.
    pub fn slash(&mut self, address: &Address, current_epoch: u64) -> Result<(), ConsensusError> {
        // Slashing always succeeds even if only 1 validator is left
        // (the chain halts; that's the appropriate outcome for provable misbehaviour).
        let info = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::UnknownProposer(*address))?;
        info.status = ValidatorStatus::Slashed;
        info.exit_epoch = Some(current_epoch);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from([n; 20])
    }

    fn set_with(entries: Vec<(Address, u64)>) -> ValidatorSet {
        ValidatorSet::from_genesis(entries, ValidatorSetConfig::default())
    }

    #[test]
    fn weighted_proposer_uniform_weights() {
        let set = set_with(vec![(addr(1), 1), (addr(2), 1), (addr(3), 1)]);
        // slot = block_number % 3
        assert_eq!(set.weighted_proposer(0), Some(addr(1)));
        assert_eq!(set.weighted_proposer(1), Some(addr(2)));
        assert_eq!(set.weighted_proposer(2), Some(addr(3)));
        assert_eq!(set.weighted_proposer(3), Some(addr(1)));
    }

    #[test]
    fn weighted_proposer_non_uniform_weights() {
        // A:3, B:2, C:1 → total=6
        // slots: 0,1,2→A; 3,4→B; 5→C
        let set = set_with(vec![(addr(1), 3), (addr(2), 2), (addr(3), 1)]);
        assert_eq!(set.weighted_proposer(0), Some(addr(1)));
        assert_eq!(set.weighted_proposer(1), Some(addr(1)));
        assert_eq!(set.weighted_proposer(2), Some(addr(1)));
        assert_eq!(set.weighted_proposer(3), Some(addr(2)));
        assert_eq!(set.weighted_proposer(4), Some(addr(2)));
        assert_eq!(set.weighted_proposer(5), Some(addr(3)));
        assert_eq!(set.weighted_proposer(6), Some(addr(1))); // wraps
    }

    #[test]
    fn lifecycle_activation_queue() {
        let mut set = set_with(vec![(addr(1), 1)]);
        set.enqueue(addr(2)).unwrap();
        assert!(!set.is_active(&addr(2)));
        set.process_activations(1);
        assert!(set.is_active(&addr(2)));
    }

    #[test]
    fn lifecycle_begin_exit_and_finalize() {
        let mut set = set_with(vec![(addr(1), 1), (addr(2), 1)]);
        set.begin_exit(&addr(2), 0).unwrap();
        // Still "Exiting" — not yet exited.
        assert!(!set.is_active(&addr(2)));
        // Process exits at epoch 2 (cooldown = 2).
        set.process_exits(2);
        assert_eq!(set.get(&addr(2)).unwrap().status, ValidatorStatus::Exited);
    }

    #[test]
    fn lifecycle_last_validator_cannot_exit() {
        let mut set = set_with(vec![(addr(1), 1)]);
        assert!(set.begin_exit(&addr(1), 0).is_err());
    }

    #[test]
    fn slash_removes_from_active() {
        let mut set = set_with(vec![(addr(1), 1), (addr(2), 1)]);
        set.slash(&addr(2), 5).unwrap();
        assert!(!set.is_active(&addr(2)));
        assert_eq!(set.get(&addr(2)).unwrap().status, ValidatorStatus::Slashed);
    }

    #[test]
    fn enqueue_duplicate_fails() {
        let mut set = set_with(vec![(addr(1), 1)]);
        assert!(set.enqueue(addr(1)).is_err());
    }
}
