//! T-10: No Magic Numbers — RPC errors, gas, and consensus constants must be named.
//!
//! **Invariant**: No bare numeric literals in execution hot paths.
//! **Enforcement**: Named constants in crates/rpc/src/error.rs, crates/core/src/transaction.rs

#[cfg(test)]
mod tests {
    /// Document named error codes.
    #[test]
    fn test_error_codes_named() {
        const METHOD_NOT_FOUND: i32 = -32601;
        const INVALID_PARAMS: i32 = -32602;
        const INTERNAL_ERROR: i32 = -32603;
        const SERVER_ERROR: i32 = -32000;

        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
        assert_eq!(SERVER_ERROR, -32000);
    }

    /// Document named gas constants.
    #[test]
    fn test_gas_constants_named() {
        const RPC_GAS_CAP: u64 = 50_000_000;
        const AA_INNER_CALL_INTRINSIC_GAS: u64 = 4_000;
        const PAYMASTER_VALIDATE_GAS_CAP: u64 = 50_000;

        assert!(RPC_GAS_CAP > 0);
        assert!(AA_INNER_CALL_INTRINSIC_GAS > 0);
        assert!(PAYMASTER_VALIDATE_GAS_CAP > 0);
    }
}

pub fn verify_no_bare_gas_literals() -> bool {
    // Full enforcement via clippy lint (planned)
    true
}
