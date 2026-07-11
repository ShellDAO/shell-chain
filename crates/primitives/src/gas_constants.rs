//! EVM-compatible gas constants for Shell-Chain
//!
//! This module defines all hardcoded gas values used in transaction validation,
//! execution, and fee calculations. These values are derived from the white paper
//! and EIP-2930 (access list) specification.
//!
//! # Invariant T-10 Enforcement
//! This module is part of protocol invariant T-10 (No Magic Numbers). All gas
//! calculations must use named constants from this module, never inline literals.

/// Gas cost for basic transaction (21_000 Wei)
pub const INTRINSIC_GAS_TX: u64 = 21_000;

/// Additional gas for contract creation (32_000 Wei)
pub const GAS_CONTRACT_CREATION: u64 = 32_000;

/// Gas cost per zero byte in calldata (4 Wei per byte)
pub const GAS_PER_ZERO_BYTE: u64 = 4;

/// Gas cost per non-zero byte in calldata (16 Wei per byte)
pub const GAS_PER_NONZERO_BYTE: u64 = 16;

/// Gas cost per address in access list (2_400 Wei)
pub const ACCESS_LIST_ADDRESS_COST: u64 = 2_400;

/// Gas cost per storage key in access list (1_900 Wei)
pub const ACCESS_LIST_STORAGE_KEY_COST: u64 = 1_900;

/// Maximum validator voting/proposer weight accepted by protocol state.
/// Keeping this bounded prevents total-weight overflow in consensus arithmetic.
pub const MAX_VALIDATOR_WEIGHT: u64 = 1_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_constants_are_eip_2930_compliant() {
        // Reference: https://eips.ethereum.org/EIPS/eip-2930
        assert_eq!(INTRINSIC_GAS_TX, 21_000);
        assert_eq!(GAS_CONTRACT_CREATION, 32_000);
        assert_eq!(GAS_PER_ZERO_BYTE, 4);
        assert_eq!(GAS_PER_NONZERO_BYTE, 16);
        assert_eq!(ACCESS_LIST_ADDRESS_COST, 2_400);
        assert_eq!(ACCESS_LIST_STORAGE_KEY_COST, 1_900);
    }

    #[test]
    fn intrinsic_gas_plain_transfer() {
        assert_eq!(INTRINSIC_GAS_TX, 21_000);
    }

    #[test]
    fn intrinsic_gas_contract_creation() {
        assert_eq!(INTRINSIC_GAS_TX + GAS_CONTRACT_CREATION, 53_000);
    }

    #[test]
    fn intrinsic_gas_with_data() {
        // 4 zero bytes + 4 nonzero bytes = 4*4 + 4*16 = 16 + 64 = 80
        let zero_bytes = 4;
        let nonzero_bytes = 4;
        let data_gas = zero_bytes * GAS_PER_ZERO_BYTE + nonzero_bytes * GAS_PER_NONZERO_BYTE;
        assert_eq!(data_gas, 80);
    }
}
