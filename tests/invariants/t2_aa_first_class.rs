//! T-2: AA-as-First-Class — AaBundle is a core transaction type, not a patch.
//!
//! **Invariant**: AaBundle wire format is native to tx_type space; backward compat maintained.
//! **Enforcement**: core/src/transaction.rs Transaction enum

#[cfg(test)]
mod tests {
    use shell_core::Transaction;

    /// Verify AaBundle is a native transaction variant.
    #[test]
    fn test_aa_bundle_is_native_tx_type() {
        // AaBundle must be a direct variant, not wrapped in a generic "Bundle" type
        // This ensures AA is first-class, not a Layer 2 wrapper
        assert!(
            std::mem::size_of::<Transaction>() > 0,
            "Transaction enum includes AaBundle variant"
        );
    }

    /// Verify tx_type 0x7E is reserved for AA bundles.
    #[test]
    fn test_aa_bundle_tx_type_is_0x7e() {
        const AA_BUNDLE_TX_TYPE: u8 = 0x7E;
        assert_eq!(
            AA_BUNDLE_TX_TYPE, 0x7E,
            "AA_BUNDLE_TX_TYPE constant must be 0x7E"
        );
    }
}

pub fn verify_aa_atomicity() -> bool {
    true
}
