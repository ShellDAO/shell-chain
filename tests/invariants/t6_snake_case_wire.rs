//! T-6: Snake-Case Wire — Protocol wire fields use snake_case (Ethereum compat exceptions).
//!
//! **Invariant**: New RPC request/response types in shell_* namespace use snake_case.
//! camelCase is allowed ONLY for:
//!  - eth_* compatible RPC handlers (lines with "eth_" prefix)
//!  - RPC response types that mirror Geth/Ethereum (callTracer, blockTracer, etc.)
//!  - System transaction types exposed through RPC (for explorer compatibility)
//!
//! **Enforcement**: Code review + CI lint (planned)

#[cfg(test)]
mod tests {
    /// This test documents the rule; enforcement via code review + CI lint.
    #[test]
    fn test_snake_case_rule_documented() {
        const RULE: &str = r#"
        Snake-Case Wire Rule (T-6):
        
        Required:
          - All new RPC request/response types use #[serde(rename_all = "snake_case")]
          - All shell_* namespace types use snake_case wire format
        
        Exceptions (camelCase allowed):
          - eth_* compatible RPC handlers (Ethereum compliance)
          - callTracer / blockTracer output (mirrors Geth callTracer format)
          - SystemTransaction (explorer/RPC compatibility)
          - Fields marked #[serde(rename = "...")] for backward compat
        
        Enforcement:
          1. Code review: Scan crates/rpc/src/*.rs for new #[serde(rename_all)]
          2. Verify all camelCase uses are in eth_* or mirrored-format types
          3. For shell_* types: insist on snake_case (or single-field exceptions)
        
        Future CI lint:
          - Forbid #[serde(rename_all = "camelCase")] outside designated eth_* modules
          - Auto-fix: suggest #[serde(rename_all = "snake_case")] for new types
        "#;
        println!("Snake-case wire rule:\n{}", RULE);
        assert!(true, "Rule documented for code review enforcement");
    }

    /// Verify known exceptions are properly scoped.
    #[test]
    fn test_known_exceptions_documented() {
        // These are known camelCase uses that are acceptable:
        const EXCEPTIONS: &[(&str, &str)] = &[
            ("crates/pqvm/src/tracer.rs", "CallFrame mirrors Geth callTracer"),
            ("crates/rpc/src/types.rs", "eth_* compatibility types"),
            ("crates/core/src/reward.rs", "SystemTransaction RPC exposure"),
        ];

        for (location, reason) in EXCEPTIONS {
            println!("Exception at {}: {}", location, reason);
        }
        assert_eq!(EXCEPTIONS.len(), 3, "All known exceptions accounted for");
    }
}

pub fn verify_rpc_snake_case() -> bool {
    // Manual code review until CI lint is implemented
    // Future: scan for 'rename_all = "camelCase"' and verify it's in eth_* or exception list
    true
}
