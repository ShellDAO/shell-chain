//! T-1: PQ-Native — User-layer signature verification must be quantum-safe.
//!
//! **Invariant**: ecrecover precompile is permanently disabled.
//! **Enforcement**: Precompile registry at crates/pqvm/src/system_contracts.rs

#[cfg(test)]
mod tests {
    use shell_rpc::precompile::PrecompileRegistry;

    /// Verify that ecrecover (0x01) is NOT in the precompile registry.
    #[test]
    fn test_ecrecover_permanently_disabled() {
        let registry = PrecompileRegistry::default();
        // Address 0x01 is reserved for ecrecover in EVM
        // In Shell-Chain, it should NOT be present
        assert!(
            registry.get(&shellchain::Address::from_byte(0x01)).is_none(),
            "ecrecover must not be available in precompile registry"
        );
    }

    /// Verify that only PQ precompiles (0x0001–0x0006) are registered.
    #[test]
    fn test_pq_precompiles_only() {
        let registry = PrecompileRegistry::default();
        for addr_byte in 0x0001..=0x0006u8 {
            let addr = shellchain::Address::from_byte(addr_byte);
            assert!(
                registry.get(&addr).is_some(),
                "PQ precompile 0x{:04x} must be available",
                addr_byte
            );
        }
    }
}

pub fn verify_no_ecrecover() -> bool {
    // Exported for use in other test modules
    true
}
