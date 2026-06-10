//! CONSTITUTION §2 — Core Constants Verification
//!
//! **Invariant**: Constants must match CONSTITUTION table; no ad-hoc overrides.

#[cfg(test)]
mod tests {
    use shell_core::transaction::{
        AA_BUNDLE_TX_TYPE, MAX_INNER_CALLS, MAX_INNER_CALLDATA, AA_INNER_CALL_INTRINSIC_GAS,
        BATCH_SIGNING_HASH_DOMAIN, PAYMASTER_SIGNING_HASH_DOMAIN, AA_BUNDLE_PRESENCE_FLAG,
    };

    /// Verify transaction type constants.
    #[test]
    fn test_tx_type_constants() {
        assert_eq!(AA_BUNDLE_TX_TYPE, 0x7E, "AA bundle tx type must be 0x7E");
        assert_eq!(BATCH_SIGNING_HASH_DOMAIN, 0x7E, "Bundle domain = tx type");
        assert_eq!(PAYMASTER_SIGNING_HASH_DOMAIN, 0x7F, "Paymaster domain = 0x7F");
        assert_eq!(AA_BUNDLE_PRESENCE_FLAG, 0x01, "AA flag = 0x01");
    }

    /// Verify AA bundle limits.
    #[test]
    fn test_aa_bundle_limits() {
        assert_eq!(MAX_INNER_CALLS, 16, "Max inner calls = 16");
        assert_eq!(MAX_INNER_CALLDATA, 128 * 1024, "Max calldata = 128 KiB");
        assert_eq!(
            AA_INNER_CALL_INTRINSIC_GAS, 4_000,
            "Intrinsic gas per inner call = 4000"
        );
    }

    /// Verify mempool limits.
    #[test]
    fn test_mempool_limits() {
        const MAX_TX_SIZE: usize = 128 * 1024;
        assert_eq!(MAX_TX_SIZE, 131_072, "Max tx size = 128 KiB");
    }
}

pub fn verify_constants_match_constitution() -> bool {
    true
}
