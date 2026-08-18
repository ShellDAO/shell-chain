//! Algorithm registry: governs which PQ signing algorithms are accepted by the network.
//!
//! # White-paper target (§6 — Algorithm Agility)
//! An on-chain algorithm registry controls accepted signing algorithms and supports
//! future activation and deprecation through governance proposals.
//!
//! # Current implementation
//! This module provides the process-global registry used by signature validation,
//! RPC exposure, and governance-triggered lifecycle transitions.
//! It is initialised from the compile-time [`ALLOWED_ALGORITHMS`] allowlist and can
//! then be updated at runtime as on-chain governance proposals reach quorum.
//!
//! Deferred items:
//! - Activation scheduling / epoch-gated transitions.
//! - Deprecation grace periods and migration tooling.
//!
//! [`ALLOWED_ALGORITHMS`]: crate::ALLOWED_ALGORITHMS

use std::cell::RefCell;
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde::{Deserialize, Serialize};

use crate::{SignatureType, ALLOWED_ALGORITHMS};

/// Lifecycle status of a PQ signing algorithm in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmStatus {
    /// Algorithm is active and accepted for new transactions.
    Active,
    /// Algorithm has been deprecated; existing UTXOs/accounts may still hold
    /// signatures of this type but new transactions using it are rejected.
    Deprecated,
    /// Algorithm has been proposed for activation but is not yet live.
    /// Useful for pre-announcing migrations without accepting the algorithm yet.
    PendingActivation,
}

impl AlgorithmStatus {
    /// Returns `true` if this status permits new transaction signatures.
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::fmt::Display for AlgorithmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Deprecated => f.write_str("deprecated"),
            Self::PendingActivation => f.write_str("pending_activation"),
        }
    }
}

/// On-chain governance specification attached to a proposed algorithm.
///
/// Populated when a validator submits `proposeAlgorithmActivation`; absent for
/// compile-time (genesis) entries that are always Active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmSpec {
    /// BLAKE3 hash of the reference verifier bytecode for this algorithm.
    /// Nodes verify their local verifier matches this before accepting signatures.
    pub verifier_hash: [u8; 32],
    /// Block height at which this algorithm transitions PendingActivation → Active.
    pub activation_height: u64,
}

/// A single algorithm entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmEntry {
    /// The algorithm identifier.
    pub algo: SignatureType,
    /// Current lifecycle status.
    pub status: AlgorithmStatus,
    /// Human-readable description / reference.
    pub description: &'static str,
    /// Governance spec; `None` for genesis compile-time entries.
    pub spec: Option<AlgorithmSpec>,
}

/// The canonical algorithm registry for this node.
///
/// Initialised from the compile-time allowlist and then updated at runtime by
/// governance operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmRegistry {
    entries: Vec<AlgorithmEntry>,
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::from_allowlist()
    }
}

impl AlgorithmRegistry {
    /// Build the registry from the compile-time allowlist.
    ///
    /// All algorithms in [`ALLOWED_ALGORITHMS`] are registered with status
    /// [`AlgorithmStatus::Active`]; no other algorithms are present.
    fn from_allowlist() -> Self {
        let entries: Vec<AlgorithmEntry> = ALLOWED_ALGORITHMS
            .iter()
            .map(|&algo| AlgorithmEntry {
                algo,
                status: AlgorithmStatus::Active,
                description: algo.registry_description(),
                spec: None,
            })
            .collect();
        Self { entries }
    }

    /// Return the process-global read-only registry.
    pub fn global() -> RwLockReadGuard<'static, Self> {
        global_registry()
            .read()
            .expect("algorithm registry lock poisoned")
    }

    /// Return the process-global mutable registry.
    pub fn global_mut() -> RwLockWriteGuard<'static, Self> {
        global_registry()
            .write()
            .expect("algorithm registry lock poisoned")
    }

    /// Mark an algorithm as pending activation.
    pub fn propose_activation(&mut self, algo: SignatureType) {
        self.upsert_status(algo, AlgorithmStatus::PendingActivation, None);
    }

    /// Mark an algorithm as pending activation with full governance spec.
    ///
    /// Called by the governance system contract when the first vote for a new
    /// proposal is cast, recording the agreed `activation_height` and
    /// `verifier_hash` alongside the `PendingActivation` status.
    /// `process_pending_activations` later calls [`Self::activate`] once the
    /// timelock has elapsed.
    pub fn propose_activation_with_spec(
        &mut self,
        algo: SignatureType,
        activation_height: u64,
        verifier_hash: [u8; 32],
    ) {
        let spec = Some(AlgorithmSpec {
            verifier_hash,
            activation_height,
        });
        self.upsert_status(algo, AlgorithmStatus::PendingActivation, spec);
    }

    /// Mark an algorithm as active.
    pub fn activate(&mut self, algo: SignatureType) {
        self.upsert_status(algo, AlgorithmStatus::Active, None);
    }

    /// Mark an algorithm as deprecated.
    pub fn deprecate(&mut self, algo: SignatureType) {
        self.upsert_status(algo, AlgorithmStatus::Deprecated, None);
    }

    fn upsert_status(
        &mut self,
        algo: SignatureType,
        status: AlgorithmStatus,
        spec: Option<AlgorithmSpec>,
    ) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.algo == algo) {
            entry.status = status;
            entry.description = algo.registry_description();
            if spec.is_some() {
                entry.spec = spec;
            }
            return;
        }

        self.entries.push(AlgorithmEntry {
            algo,
            status,
            description: algo.registry_description(),
            spec,
        });
    }

    /// Returns `true` if the given algorithm is currently accepted for new
    /// transaction signatures.
    ///
    /// This is the single validation indirection point. Call this instead of
    /// `ALLOWED_ALGORITHMS.contains()` so that runtime registry updates are
    /// respected automatically.
    pub fn is_allowed(&self, algo: SignatureType) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.algo == algo && entry.status.is_accepted())
    }

    /// Read-only view of all registered algorithms.
    pub fn get_all_entries(&self) -> &[AlgorithmEntry] {
        &self.entries
    }

    /// Backward-compatible alias for existing call sites.
    pub fn entries(&self) -> &[AlgorithmEntry] {
        self.get_all_entries()
    }
}

fn global_registry() -> &'static RwLock<AlgorithmRegistry> {
    static REGISTRY: OnceLock<RwLock<AlgorithmRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(AlgorithmRegistry::from_allowlist()))
}

thread_local! {
    static REGISTRY_OVERRIDES: RefCell<Vec<AlgorithmRegistry>> = const { RefCell::new(Vec::new()) };
}

struct RegistryOverrideGuard;

impl Drop for RegistryOverrideGuard {
    fn drop(&mut self) {
        REGISTRY_OVERRIDES.with(|overrides| {
            overrides
                .borrow_mut()
                .pop()
                .expect("algorithm registry override stack must be balanced");
        });
    }
}

/// Run synchronous validation against a branch-local algorithm registry.
///
/// The override is confined to the current thread and restored on return or
/// panic, so historical or provisional validation cannot expose its policy to
/// concurrent canonical validation.
pub fn with_algorithm_registry_override<T>(
    registry: &AlgorithmRegistry,
    operation: impl FnOnce() -> T,
) -> T {
    REGISTRY_OVERRIDES.with(|overrides| overrides.borrow_mut().push(registry.clone()));
    let _guard = RegistryOverrideGuard;
    operation()
}

/// Convenience function: check whether `algo` is allowed according to the
/// global compile-time registry.
///
/// Callers that cannot easily obtain a `&AlgorithmRegistry` reference should
/// use this instead of reaching for `ALLOWED_ALGORITHMS` directly.
pub fn is_algorithm_allowed(algo: SignatureType) -> bool {
    if let Some(allowed) = REGISTRY_OVERRIDES.with(|overrides| {
        overrides
            .borrow()
            .last()
            .map(|registry| registry.is_allowed(algo))
    }) {
        return allowed;
    }
    AlgorithmRegistry::global().is_allowed(algo)
}

// ── SignatureType registry descriptions ──────────────────────────────────────

impl SignatureType {
    /// Human-readable description for use in registry / RPC output.
    pub fn registry_description(self) -> &'static str {
        match self {
            Self::Dilithium3 => {
                "CRYSTALS-Dilithium3 (Round-3 pre-FIPS; active for legacy compatibility)"
            }
            Self::MlDsa65 => "FIPS 204 ML-DSA-65 (NIST post-quantum standard; primary algorithm)",
            Self::SphincsSha2256f => {
                "SPHINCS+-SHA2-256f-simple (stateless hash-based; high security margin)"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_registry_contains_all_allowed_algorithms() {
        let reg = AlgorithmRegistry::global();
        for algo in ALLOWED_ALGORITHMS {
            assert!(
                reg.is_allowed(*algo),
                "registry must allow {algo:?} (present in ALLOWED_ALGORITHMS)"
            );
        }
    }

    #[test]
    fn is_algorithm_allowed_matches_registry() {
        for algo in ALLOWED_ALGORITHMS {
            assert!(is_algorithm_allowed(*algo));
        }
    }

    #[test]
    fn registry_entries_count_matches_allowlist() {
        let reg = AlgorithmRegistry::global();
        assert_eq!(reg.get_all_entries().len(), ALLOWED_ALGORITHMS.len());
    }

    #[test]
    fn all_entries_are_active() {
        let reg = AlgorithmRegistry::global();
        for entry in reg.get_all_entries() {
            assert_eq!(
                entry.status,
                AlgorithmStatus::Active,
                "compile-time allowlist entries must all be Active"
            );
        }
    }

    #[test]
    fn algorithm_status_is_accepted() {
        assert!(AlgorithmStatus::Active.is_accepted());
        assert!(!AlgorithmStatus::Deprecated.is_accepted());
        assert!(!AlgorithmStatus::PendingActivation.is_accepted());
    }

    #[test]
    fn algorithm_status_display() {
        assert_eq!(AlgorithmStatus::Active.to_string(), "active");
        assert_eq!(AlgorithmStatus::Deprecated.to_string(), "deprecated");
        assert_eq!(
            AlgorithmStatus::PendingActivation.to_string(),
            "pending_activation"
        );
    }

    #[test]
    fn registry_lifecycle_transitions_update_status() {
        let mut reg = AlgorithmRegistry::default();

        reg.propose_activation(SignatureType::Dilithium3);
        assert_eq!(
            reg.get_all_entries()
                .iter()
                .find(|entry| entry.algo == SignatureType::Dilithium3)
                .map(|entry| entry.status),
            Some(AlgorithmStatus::PendingActivation)
        );

        reg.activate(SignatureType::Dilithium3);
        assert_eq!(
            reg.get_all_entries()
                .iter()
                .find(|entry| entry.algo == SignatureType::Dilithium3)
                .map(|entry| entry.status),
            Some(AlgorithmStatus::Active)
        );

        reg.deprecate(SignatureType::Dilithium3);
        assert_eq!(
            reg.get_all_entries()
                .iter()
                .find(|entry| entry.algo == SignatureType::Dilithium3)
                .map(|entry| entry.status),
            Some(AlgorithmStatus::Deprecated)
        );
    }

    #[test]
    fn non_active_statuses_are_not_allowed() {
        let mut reg = AlgorithmRegistry::default();

        reg.propose_activation(SignatureType::MlDsa65);
        assert!(!reg.is_allowed(SignatureType::MlDsa65));

        reg.activate(SignatureType::MlDsa65);
        assert!(reg.is_allowed(SignatureType::MlDsa65));

        reg.deprecate(SignatureType::MlDsa65);
        assert!(!reg.is_allowed(SignatureType::MlDsa65));
    }

    #[test]
    fn deprecated_algo_not_allowed() {
        // Build a custom registry with a deprecated entry to test the guard.
        let entries = vec![AlgorithmEntry {
            algo: SignatureType::Dilithium3,
            status: AlgorithmStatus::Deprecated,
            description: "test",
            spec: None,
        }];
        let reg = AlgorithmRegistry { entries };
        assert!(!reg.is_allowed(SignatureType::Dilithium3));
    }

    #[test]
    fn registry_override_is_thread_local_and_restored() {
        let algorithm = SignatureType::Dilithium3;
        let global_allowed = is_algorithm_allowed(algorithm);
        let mut provisional = AlgorithmRegistry::default();
        if global_allowed {
            provisional.deprecate(algorithm);
        } else {
            provisional.activate(algorithm);
        }

        with_algorithm_registry_override(&provisional, || {
            assert_eq!(is_algorithm_allowed(algorithm), !global_allowed);
            assert_eq!(
                std::thread::spawn(move || is_algorithm_allowed(algorithm))
                    .join()
                    .unwrap(),
                global_allowed,
                "another thread must continue using canonical policy"
            );
        });

        assert_eq!(is_algorithm_allowed(algorithm), global_allowed);
    }

    #[test]
    fn registry_description_is_non_empty() {
        for algo in ALLOWED_ALGORITHMS {
            let desc = algo.registry_description();
            assert!(
                !desc.is_empty(),
                "description must not be empty for {algo:?}"
            );
        }
    }
}
