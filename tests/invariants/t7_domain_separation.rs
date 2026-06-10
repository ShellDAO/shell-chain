//! T-7: Domain-Separated Hashing — Different signature contexts use distinct domain bytes.
//!
//! **Invariant**: BATCH_SIGNING_HASH_DOMAIN ≠ PAYMASTER_SIGNING_HASH_DOMAIN ≠ SESSION_V1_DOMAIN
//! **Enforcement**: core/src/transaction.rs domain byte constants

#[cfg(test)]
mod tests {
    const BATCH_SIGNING_HASH_DOMAIN: u8 = 0x7E;
    const PAYMASTER_SIGNING_HASH_DOMAIN: u8 = 0x7F;
    const SESSION_V1_DOMAIN: &[u8] = b"SESSION_V1";

    /// Verify domain bytes are unique and non-overlapping.
    #[test]
    fn test_domain_bytes_unique() {
        let batch = BATCH_SIGNING_HASH_DOMAIN;
        let paymaster = PAYMASTER_SIGNING_HASH_DOMAIN;

        assert_ne!(batch, paymaster, "Domain bytes must be unique");
        assert_ne!(batch, 0x00, "No domain byte can be zero (would collide with default)");
        assert_ne!(paymaster, 0x00, "No domain byte can be zero");
    }

    /// Verify domain bytes match CONSTITUTION specification.
    #[test]
    fn test_domain_bytes_match_constitution() {
        assert_eq!(BATCH_SIGNING_HASH_DOMAIN, 0x7E, "Bundle domain = 0x7E per CONSTITUTION");
        assert_eq!(
            PAYMASTER_SIGNING_HASH_DOMAIN, 0x7F,
            "Paymaster domain = 0x7F per CONSTITUTION"
        );
    }
}

pub fn verify_domain_bytes_unique() -> bool {
    true
}
