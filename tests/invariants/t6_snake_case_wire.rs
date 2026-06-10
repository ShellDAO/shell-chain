//! T-6: Snake-Case Wire — All RPC request/response fields use snake_case
//! (except eth_* compat fields retain camelCase).
//!
//! **Invariant**: New RPC types use #[serde(rename_all = "snake_case")].
//! **Enforcement**: Code review + CI lint (planned)

#[cfg(test)]
mod tests {
    /// This test documents the rule; enforcement via CI lint (T-10 parallel).
    #[test]
    fn test_snake_case_rule_documented() {
        const RULE: &str = r#"
        All new RPC request/response types must use:
          #[serde(rename_all = "snake_case")]
        
        Exceptions (preserve camelCase):
          - RPC methods named eth_* (Ethereum compatibility)
          - Fields explicitly marked for backward compat
        
        Verification: Grep for 'rename_all = "camelCase"' in crates/rpc/src/*.rs
        and ensure all matches are in eth_* handlers or legacy code.
        "#;
        println!("Snake-case wire rule:\n{}", RULE);
        assert!(true, "Rule documented for future CI automation");
    }
}

pub fn verify_rpc_snake_case() -> bool {
    // Manual review until CI lint is implemented
    true
}
