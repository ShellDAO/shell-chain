/// Default aggregate serialized transaction capacity (256 MiB).
pub const DEFAULT_MAX_POOL_BYTES: usize = 256 * 1024 * 1024;

/// Configuration for the transaction mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in the pool.
    pub max_pool_size: usize,
    /// Maximum aggregate serialized transaction bytes retained by the pool.
    pub max_pool_bytes: usize,
    /// Maximum number of pending transactions per sender address.
    pub max_per_sender: usize,
    /// Expected chain ID — reject transactions targeting other chains.
    pub chain_id: u64,
    /// Minimum gas price (max_fee_per_gas) to accept into the pool.
    pub min_gas_price: u64,
    /// Minimum fee bump percentage for Replace-by-Fee (RBF).
    /// A new tx must offer at least `(100 + bump_pct)%` of the old tx's
    /// `max_priority_fee_per_gas` to replace it at the same nonce.
    pub replacement_fee_bump_pct: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pool_size: 4096,
            max_pool_bytes: DEFAULT_MAX_POOL_BYTES,
            max_per_sender: 64,
            chain_id: 1,
            min_gas_price: 0,
            replacement_fee_bump_pct: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_pool_size() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.max_pool_size, 4096);
    }

    #[test]
    fn default_max_pool_bytes() {
        assert_eq!(
            MempoolConfig::default().max_pool_bytes,
            DEFAULT_MAX_POOL_BYTES
        );
    }

    #[test]
    fn default_max_per_sender() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.max_per_sender, 64);
    }

    #[test]
    fn default_chain_id() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.chain_id, 1);
    }

    #[test]
    fn default_min_gas_price_is_zero() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.min_gas_price, 0);
    }

    #[test]
    fn default_replacement_fee_bump_pct() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.replacement_fee_bump_pct, 10);
    }

    #[test]
    fn custom_config() {
        let cfg = MempoolConfig {
            max_pool_size: 100,
            max_pool_bytes: 1_000_000,
            max_per_sender: 5,
            chain_id: 42,
            min_gas_price: 1_000_000_000,
            replacement_fee_bump_pct: 25,
        };
        assert_eq!(cfg.max_pool_size, 100);
        assert_eq!(cfg.max_pool_bytes, 1_000_000);
        assert_eq!(cfg.max_per_sender, 5);
        assert_eq!(cfg.chain_id, 42);
        assert_eq!(cfg.min_gas_price, 1_000_000_000);
        assert_eq!(cfg.replacement_fee_bump_pct, 25);
    }

    #[test]
    fn clone_produces_equal_copy() {
        let cfg = MempoolConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg.max_pool_size, cloned.max_pool_size);
        assert_eq!(cfg.max_pool_bytes, cloned.max_pool_bytes);
        assert_eq!(cfg.max_per_sender, cloned.max_per_sender);
        assert_eq!(cfg.chain_id, cloned.chain_id);
        assert_eq!(cfg.min_gas_price, cloned.min_gas_price);
        assert_eq!(
            cfg.replacement_fee_bump_pct,
            cloned.replacement_fee_bump_pct
        );
    }

    #[test]
    fn debug_format() {
        let cfg = MempoolConfig::default();
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("MempoolConfig"));
    }
}
