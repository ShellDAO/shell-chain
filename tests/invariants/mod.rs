//! Protocol Invariant Regression Tests
//!
//! Each invariant from CONSTITUTION.md is verified by at least one test case.
//! These tests enforce that protocol rules remain stable across releases.

mod t1_pq_native;
mod t2_aa_first_class;
mod t5_atomic_default;
mod t6_snake_case_wire;
mod t7_domain_separation;
mod t10_no_magic_numbers;
mod i_constants;

// Re-export key invariant validators for use in other test modules
pub use self::{
    t1_pq_native::verify_no_ecrecover,
    t2_aa_first_class::verify_aa_atomicity,
    t5_atomic_default::verify_bundle_revert_atomicity,
    t6_snake_case_wire::verify_rpc_snake_case,
    t7_domain_separation::verify_domain_bytes_unique,
    t10_no_magic_numbers::verify_no_bare_gas_literals,
    i_constants::verify_constants_match_constitution,
};
