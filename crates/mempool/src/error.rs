use shell_primitives::{Address, ShellHash, U256};
use shell_storage::StorageError;
use thiserror::Error;

/// Errors that can occur during mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("pool is full ({capacity} transactions)")]
    PoolFull { capacity: usize },

    #[error("sender {sender} has too many pending transactions ({count})")]
    SenderQueueFull { sender: Address, count: usize },

    #[error("duplicate transaction {hash}")]
    Duplicate { hash: ShellHash },

    #[error("chain ID mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    #[error("gas price {got} below minimum {min}")]
    GasPriceTooLow { got: u64, min: u64 },

    #[error("gas limit {got} below intrinsic minimum {minimum}")]
    GasTooLow { got: u64, minimum: u64 },

    #[error("nonce {got} too low, sender has pending nonce >= {pending}")]
    NonceTooLow { got: u64, pending: u64 },

    #[error("nonce gap: expected next nonce {expected}, got {got}")]
    NonceGap { expected: u64, got: u64 },

    #[error("insufficient balance: need {needed}, have {have}")]
    InsufficientBalance { needed: U256, have: U256 },

    #[error("replacement fee too low: need >{required}, got {got}")]
    ReplacementFeeTooLow { got: u64, required: u64 },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("pubkey required for first transaction from {sender}")]
    PubkeyRequired { sender: Address },

    #[error("address mismatch: from={from}, derived={derived}")]
    AddressMismatch { from: Address, derived: Address },

    #[error("crypto error: {0}")]
    Crypto(#[from] shell_crypto::CryptoError),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

impl MempoolError {
    /// Returns a short, static label for this error variant that contains no
    /// account-state values (nonce, balance, addresses).  Use this for
    /// structured logging to avoid leaking account data into log files.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::PoolFull { .. } => "pool_full",
            Self::SenderQueueFull { .. } => "sender_queue_full",
            Self::Duplicate { .. } => "duplicate",
            Self::ChainIdMismatch { .. } => "chain_id_mismatch",
            Self::GasPriceTooLow { .. } => "gas_price_too_low",
            Self::GasTooLow { .. } => "gas_too_low",
            Self::NonceTooLow { .. } => "nonce_too_low",
            Self::NonceGap { .. } => "nonce_gap",
            Self::InsufficientBalance { .. } => "insufficient_balance",
            Self::ReplacementFeeTooLow { .. } => "replacement_fee_too_low",
            Self::InvalidSignature(_) => "invalid_signature",
            Self::PubkeyRequired { .. } => "pubkey_required",
            Self::AddressMismatch { .. } => "address_mismatch",
            Self::Crypto(_) => "crypto_error",
            Self::InvalidTransaction(_) => "invalid_transaction",
            Self::Storage(_) => "storage_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- kind_str() tests: assert static labels and that they contain no
    // numeric or address values that could leak account state.

    #[test]
    fn kind_str_sensitive_variants_have_no_values() {
        // These variants normally embed nonce/balance/address in Display.
        // kind_str() must return a plain static label with no numbers/0x.
        let cases: &[(&str, MempoolError)] = &[
            (
                "nonce_too_low",
                MempoolError::NonceTooLow {
                    got: 7,
                    pending: 42,
                },
            ),
            (
                "nonce_gap",
                MempoolError::NonceGap {
                    expected: 1,
                    got: 5,
                },
            ),
            (
                "insufficient_balance",
                MempoolError::InsufficientBalance {
                    needed: U256::from(1000u64),
                    have: U256::from(1u64),
                },
            ),
            (
                "sender_queue_full",
                MempoolError::SenderQueueFull {
                    sender: Address::ZERO,
                    count: 64,
                },
            ),
            (
                "address_mismatch",
                MempoolError::AddressMismatch {
                    from: Address::ZERO,
                    derived: Address::ZERO,
                },
            ),
        ];
        for (expected_label, err) in cases {
            let label = err.kind_str();
            assert_eq!(label, *expected_label, "wrong label for {err:?}");
            // The label itself must not contain any digit or "0x" prefix.
            assert!(
                !label.chars().any(|c| c.is_ascii_digit()),
                "kind_str label '{label}' must not contain numeric data"
            );
        }
    }

    #[test]
    fn kind_str_all_variants_are_static() {
        // Smoke-test that every variant returns a non-empty static label.
        let variants: &[MempoolError] = &[
            MempoolError::PoolFull { capacity: 1 },
            MempoolError::SenderQueueFull {
                sender: Address::ZERO,
                count: 1,
            },
            MempoolError::Duplicate {
                hash: ShellHash::default(),
            },
            MempoolError::ChainIdMismatch {
                expected: 1,
                got: 2,
            },
            MempoolError::GasPriceTooLow { got: 1, min: 2 },
            MempoolError::GasTooLow { got: 1, minimum: 2 },
            MempoolError::NonceTooLow { got: 1, pending: 2 },
            MempoolError::NonceGap {
                expected: 1,
                got: 3,
            },
            MempoolError::InsufficientBalance {
                needed: U256::from(2u64),
                have: U256::from(1u64),
            },
            MempoolError::ReplacementFeeTooLow {
                got: 1,
                required: 2,
            },
            MempoolError::InvalidSignature("x".into()),
            MempoolError::PubkeyRequired {
                sender: Address::ZERO,
            },
            MempoolError::AddressMismatch {
                from: Address::ZERO,
                derived: Address::ZERO,
            },
            MempoolError::InvalidTransaction("x".into()),
        ];
        for err in variants {
            assert!(!err.kind_str().is_empty(), "kind_str() empty for {err:?}");
        }
    }

    #[test]
    fn pool_full_display() {
        let err = MempoolError::PoolFull { capacity: 4096 };
        assert_eq!(err.to_string(), "pool is full (4096 transactions)");
    }

    #[test]
    fn sender_queue_full_display() {
        let sender = Address::ZERO;
        let err = MempoolError::SenderQueueFull { sender, count: 64 };
        let msg = err.to_string();
        assert!(msg.contains("too many pending transactions"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn duplicate_display() {
        let hash = ShellHash::default();
        let err = MempoolError::Duplicate { hash };
        assert!(err.to_string().contains("duplicate transaction"));
    }

    #[test]
    fn chain_id_mismatch_display() {
        let err = MempoolError::ChainIdMismatch {
            expected: 1,
            got: 42,
        };
        assert_eq!(err.to_string(), "chain ID mismatch: expected 1, got 42");
    }

    #[test]
    fn gas_price_too_low_display() {
        let err = MempoolError::GasPriceTooLow { got: 5, min: 10 };
        assert_eq!(err.to_string(), "gas price 5 below minimum 10");
    }

    #[test]
    fn gas_too_low_display() {
        let err = MempoolError::GasTooLow {
            got: 21_000,
            minimum: 21_032,
        };
        assert_eq!(
            err.to_string(),
            "gas limit 21000 below intrinsic minimum 21032"
        );
    }

    #[test]
    fn nonce_too_low_display() {
        let err = MempoolError::NonceTooLow {
            got: 3,
            pending: 10,
        };
        assert!(err.to_string().contains("nonce 3 too low"));
        assert!(err.to_string().contains("10"));
    }

    #[test]
    fn nonce_gap_display() {
        let err = MempoolError::NonceGap {
            expected: 1,
            got: 3,
        };
        assert_eq!(err.to_string(), "nonce gap: expected next nonce 1, got 3");
    }

    #[test]
    fn insufficient_balance_display() {
        let err = MempoolError::InsufficientBalance {
            needed: U256::from(1000u64),
            have: U256::from(100u64),
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient balance"));
        assert!(msg.contains("1000"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn replacement_fee_too_low_display() {
        let err = MempoolError::ReplacementFeeTooLow {
            got: 10,
            required: 20,
        };
        assert!(err.to_string().contains("replacement fee too low"));
    }

    #[test]
    fn invalid_signature_display() {
        let err = MempoolError::InvalidSignature("bad sig".into());
        assert_eq!(err.to_string(), "invalid signature: bad sig");
    }

    #[test]
    fn pubkey_required_display() {
        let sender = Address::ZERO;
        let err = MempoolError::PubkeyRequired { sender };
        assert!(err.to_string().contains("pubkey required"));
    }

    #[test]
    fn address_mismatch_display() {
        let from = Address::from_slice(&[0x01; 20]);
        let derived = Address::from_slice(&[0x02; 20]);
        let err = MempoolError::AddressMismatch { from, derived };
        let msg = err.to_string();
        assert!(msg.contains("address mismatch"));
    }

    #[test]
    fn invalid_transaction_display() {
        let err = MempoolError::InvalidTransaction("bad tx data".into());
        assert_eq!(err.to_string(), "invalid transaction: bad tx data");
    }

    #[test]
    fn crypto_error_from_conversion() {
        let crypto_err = shell_crypto::CryptoError::VerificationFailed;
        let err = MempoolError::from(crypto_err);
        assert!(err.to_string().contains("crypto error"));
    }
}
