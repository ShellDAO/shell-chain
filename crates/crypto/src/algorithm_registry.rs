//! Algorithm registry: governs which PQ signing algorithms are accepted by the network.
//!
//! # White-paper target (§6 — Algorithm Agility)
//! An on-chain algorithm registry controls accepted signing algorithms and supports
//! future activation and deprecation through governance proposals.
//!
//! # Current implementation (skeleton)
//! This module provides the *data model* and *validation interface* for the registry.
//! It is initialised from the compile-time [`ALLOWED_ALGORITHMS`] allowlist so
//! existing validation paths are unchanged while gaining an indirection layer that
//! will accept runtime updates (governance, activation schedules) in a future round.
//!
//! Deferred items:
//! - On-chain state storage and governance proposal lifecycle.
//! - Activation scheduling / epoch-gated transitions.
//! - Deprecation grace periods and migration tooling.
//!
//! [`ALLOWED_ALGORITHMS`]: crate::ALLOWED_ALGORITHMS

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

/// A single algorithm entry in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmEntry {
    /// The algorithm identifier.
    pub algo: SignatureType,
    /// Current lifecycle status.
    pub status: AlgorithmStatus,
    /// Human-readable description / reference.
    pub description: &'static str,
}

/// The canonical algorithm registry for this node.
///
/// Initialised from the compile-time allowlist; call [`AlgorithmRegistry::global`]
/// to obtain a read-only view.  Future rounds will add a mutable runtime registry
/// backed by on-chain governance state.
pub struct AlgorithmRegistry {
    entries: Vec<AlgorithmEntry>,
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
            })
            .collect();
        Self { entries }
    }

    /// Return the process-global read-only registry (initialised from the
    /// compile-time allowlist).
    ///
    /// This is a cheap operation — the registry is built once and reused.
    pub fn global() -> &'static Self {
        // SAFETY: no mutation, initialised once at first call.
        static REGISTRY: std::sync::OnceLock<AlgorithmRegistry> = std::sync::OnceLock::new();
        REGISTRY.get_or_init(Self::from_allowlist)
    }

    /// Returns `true` if the given algorithm is currently accepted for new
    /// transaction signatures.
    ///
    /// This is the single validation indirection point.  Call this instead of
    /// `ALLOWED_ALGORITHMS.contains()` so that future runtime updates to
    /// registry status are respected automatically.
    pub fn is_allowed(&self, algo: SignatureType) -> bool {
        self.entries
            .iter()
            .any(|e| e.algo == algo && e.status.is_accepted())
    }

    /// Read-only view of all registered algorithms.
    pub fn entries(&self) -> &[AlgorithmEntry] {
        &self.entries
    }
}

/// Convenience function: check whether `algo` is allowed according to the
/// global compile-time registry.
///
/// Callers that cannot easily obtain a `&AlgorithmRegistry` reference should
/// use this instead of reaching for `ALLOWED_ALGORITHMS` directly.
pub fn is_algorithm_allowed(algo: SignatureType) -> bool {
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
        assert_eq!(reg.entries().len(), ALLOWED_ALGORITHMS.len());
    }

    #[test]
    fn all_entries_are_active() {
        let reg = AlgorithmRegistry::global();
        for entry in reg.entries() {
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
    fn deprecated_algo_not_allowed() {
        // Build a custom registry with a deprecated entry to test the guard.
        let entries = vec![AlgorithmEntry {
            algo: SignatureType::Dilithium3,
            status: AlgorithmStatus::Deprecated,
            description: "test",
        }];
        let reg = AlgorithmRegistry { entries };
        assert!(!reg.is_allowed(SignatureType::Dilithium3));
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
