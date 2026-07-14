/// Default initial base fee (1 gwei) used for the first block after genesis.
pub const INITIAL_BASE_FEE: u64 = 1_000_000_000;

/// EIP-1559 base fee elasticity denominator (max ±12.5% change per block).
const BASE_FEE_CHANGE_DENOMINATOR: u64 = 8;

/// Calculate the effective gas price paid by the transaction.
/// EIP-1559: effective_price = min(max_fee, base_fee + max_priority_fee)
pub fn effective_gas_price(max_fee: u64, max_priority_fee: u64, base_fee: u64) -> u64 {
    max_fee.min(base_fee.saturating_add(max_priority_fee))
}

/// Calculate the miner tip (priority fee actually paid).
/// tip = effective_price - base_fee
pub fn miner_tip(max_fee: u64, max_priority_fee: u64, base_fee: u64) -> u64 {
    effective_gas_price(max_fee, max_priority_fee, base_fee).saturating_sub(base_fee)
}

/// Calculate EIP-1559 base fee for the next block.
///
/// - If parent used more gas than target (50% of limit), base fee increases
/// - If parent used less gas than target, base fee decreases
/// - Minimum base fee is 1 (never 0 after genesis)
/// - Maximum change per block: ±12.5% (1/8)
///
/// Special case: if `parent_base_fee` is 0 (genesis block), returns
/// [`INITIAL_BASE_FEE`].
pub fn calculate_base_fee(
    parent_gas_used: u64,
    parent_gas_limit: u64,
    parent_base_fee: u64,
) -> u64 {
    // Genesis parent → bootstrap with initial base fee.
    if parent_base_fee == 0 {
        return INITIAL_BASE_FEE;
    }

    let gas_target = parent_gas_limit / 2;
    if gas_target == 0 {
        return parent_base_fee;
    }

    if parent_gas_used == gas_target {
        parent_base_fee
    } else if parent_gas_used > gas_target {
        let delta = base_fee_delta(
            parent_base_fee,
            parent_gas_used.saturating_sub(gas_target),
            gas_target,
        );
        parent_base_fee.saturating_add(delta.max(1))
    } else {
        let delta = base_fee_delta(
            parent_base_fee,
            gas_target.saturating_sub(parent_gas_used),
            gas_target,
        );
        (parent_base_fee.saturating_sub(delta)).max(1)
    }
}

fn base_fee_delta(parent_base_fee: u64, gas_delta: u64, gas_target: u64) -> u64 {
    let delta = u128::from(parent_base_fee).saturating_mul(u128::from(gas_delta))
        / u128::from(gas_target)
        / u128::from(BASE_FEE_CHANGE_DENOMINATOR);
    delta.min(u128::from(u64::MAX)) as u64
}

/// EIP-4844: target blob gas per block (3 blobs × 131072 gas each).
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 393_216;

/// EIP-4844: gas consumed by one blob.
pub const BLOB_GAS_PER_BLOB: u64 = 131_072;

/// EIP-4844: maximum blob gas per block (6 blobs).
pub const MAX_BLOB_GAS_PER_BLOCK: u64 = 786_432;

/// EIP-4844: minimum blob base fee (1 wei).
pub const MIN_BLOB_BASE_FEE: u64 = 1;

/// EIP-4844: blob base fee update fraction.
pub const BLOB_BASE_FEE_UPDATE_FRACTION: u64 = 3_338_477;

/// Calculate EIP-4844 blob gas price from excess blob gas.
///
/// Uses the exponential formula: `fake_exponential(MIN_BLOB_BASE_FEE, excess, BLOB_BASE_FEE_UPDATE_FRACTION)`
/// This is an integer approximation of `min_fee * e^(excess / fraction)`.
pub fn calc_blob_gas_price(excess_blob_gas: u64) -> u64 {
    fake_exponential(
        MIN_BLOB_BASE_FEE,
        excess_blob_gas,
        BLOB_BASE_FEE_UPDATE_FRACTION,
    )
}

/// Calculate excess blob gas for the next block.
///
/// excess = max(0, parent_excess + parent_used - target)
pub fn calc_excess_blob_gas(parent_excess: u64, parent_used: u64) -> u64 {
    let total = parent_excess.saturating_add(parent_used);
    total.saturating_sub(TARGET_BLOB_GAS_PER_BLOCK)
}

/// Integer approximation of `factor * e^(numerator / denominator)`.
///
/// Uses Taylor series: sum of factor * numerator^i / (denominator^i * i!)
fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u64 {
    let mut i: u128 = 1;
    let mut output: u128 = 0;
    let mut numerator_accum: u128 = (factor as u128).saturating_mul(denominator as u128);
    let numerator_128 = numerator as u128;
    let denominator_128 = denominator as u128;

    while numerator_accum > 0 {
        output = output.saturating_add(numerator_accum);
        numerator_accum = numerator_accum
            .saturating_mul(numerator_128)
            .checked_div(denominator_128.saturating_mul(i))
            .unwrap_or(0);
        i = i.saturating_add(1);
    }
    output.checked_div(denominator_128).unwrap_or(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAS_LIMIT: u64 = 30_000_000;
    const GAS_TARGET: u64 = GAS_LIMIT / 2; // 15_000_000

    #[test]
    fn genesis_returns_initial_base_fee() {
        assert_eq!(calculate_base_fee(0, GAS_LIMIT, 0), INITIAL_BASE_FEE,);
    }

    #[test]
    fn exact_target_unchanged() {
        let base = 1_000_000_000u64;
        assert_eq!(calculate_base_fee(GAS_TARGET, GAS_LIMIT, base), base);
    }

    #[test]
    fn full_block_increases_fee() {
        let base = 1_000_000_000u64;
        let new = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
        assert!(new > base, "base fee should increase when block is full");
        // At 100% full (used == limit), delta = base * target / target / 8 = base / 8
        assert_eq!(new, base + base / 8);
    }

    #[test]
    fn empty_block_decreases_fee() {
        let base = 1_000_000_000u64;
        let new = calculate_base_fee(0, GAS_LIMIT, base);
        assert!(new < base, "base fee should decrease when block is empty");
        // At 0% usage, delta = base * target / target / 8 = base / 8
        assert_eq!(new, base - base / 8);
    }

    #[test]
    fn minimum_base_fee_is_one() {
        // Even with zero usage and a very low fee, should never go below 1
        let new = calculate_base_fee(0, GAS_LIMIT, 1);
        assert_eq!(new, 1, "base fee must never drop below 1");
    }

    #[test]
    fn increase_at_least_one() {
        // With a very small base fee, ensure delta is at least 1
        let base = 8u64; // delta would be 8 * 1 / 8 = 1 without max(delta,1)
        let new = calculate_base_fee(GAS_TARGET + 1, GAS_LIMIT, base);
        assert!(new > base, "fee should increase even with tiny base");
    }

    #[test]
    fn maximum_increase_is_12_5_percent() {
        let base = 1_000_000_000u64;
        // Block 100% full → maximum increase
        let new = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
        let max_increase = base / 8;
        assert_eq!(new - base, max_increase);
    }

    #[test]
    fn maximum_decrease_is_12_5_percent() {
        let base = 1_000_000_000u64;
        // Block completely empty → maximum decrease
        let new = calculate_base_fee(0, GAS_LIMIT, base);
        let max_decrease = base / 8;
        assert_eq!(base - new, max_decrease);
    }

    #[test]
    fn consecutive_full_blocks_keep_increasing() {
        let mut base = INITIAL_BASE_FEE;
        for _ in 0..10 {
            let next = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
            assert!(next > base);
            base = next;
        }
    }

    #[test]
    fn consecutive_empty_blocks_keep_decreasing() {
        let mut base = INITIAL_BASE_FEE;
        for _ in 0..200 {
            let next = calculate_base_fee(0, GAS_LIMIT, base);
            assert!(next <= base);
            base = next;
        }
        // Should converge to a small value (≥ 1)
        assert!((1..=8).contains(&base), "converged to {base}");
    }

    #[test]
    fn half_full_block_unchanged() {
        let base = 500_000_000u64;
        assert_eq!(calculate_base_fee(GAS_TARGET, GAS_LIMIT, base), base);
    }

    #[test]
    fn slightly_over_target_increases() {
        let base = 1_000_000_000u64;
        let over = GAS_TARGET + 1_000_000;
        let new = calculate_base_fee(over, GAS_LIMIT, base);
        assert!(new > base);
    }

    #[test]
    fn slightly_under_target_decreases() {
        let base = 1_000_000_000u64;
        let under = GAS_TARGET - 1_000_000;
        let new = calculate_base_fee(under, GAS_LIMIT, base);
        assert!(new < base);
    }

    #[test]
    fn saturating_add_prevents_overflow() {
        // With a very high base fee, increase must not overflow.
        let base = u64::MAX - 1_000_000_000;
        let new = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
        assert!(new >= base, "fee should not wrap around");
        // saturating_add guarantees no overflow past u64::MAX
    }

    #[test]
    fn high_base_fee_decrease_uses_full_precision_delta() {
        let base = u64::MAX;
        let new = calculate_base_fee(0, GAS_LIMIT, base);

        assert_eq!(new, base - base / BASE_FEE_CHANGE_DENOMINATOR);
    }

    #[test]
    fn high_base_fee_increase_caps_at_u64_max() {
        let base = u64::MAX;
        let new = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);

        assert_eq!(new, u64::MAX);
    }

    // ── effective_gas_price tests ──────────────────────────────

    #[test]
    fn effective_price_capped_by_max_fee() {
        // max_fee < base_fee + priority → effective = max_fee
        assert_eq!(effective_gas_price(10, 5, 8), 10);
    }

    #[test]
    fn effective_price_capped_by_sum() {
        // base_fee + priority < max_fee → effective = base_fee + priority
        assert_eq!(effective_gas_price(20, 3, 10), 13);
    }

    #[test]
    fn effective_price_exact_match() {
        // max_fee == base_fee + priority
        assert_eq!(effective_gas_price(15, 5, 10), 15);
    }

    #[test]
    fn effective_price_zero_priority() {
        assert_eq!(effective_gas_price(10, 0, 8), 8);
    }

    #[test]
    fn effective_price_zero_base_fee() {
        assert_eq!(effective_gas_price(10, 3, 0), 3);
    }

    #[test]
    fn effective_price_saturates_on_overflow() {
        // base_fee + priority overflows u64 → min(max_fee, u64::MAX)
        assert_eq!(effective_gas_price(100, u64::MAX, u64::MAX), 100);
    }

    // ── miner_tip tests ───────────────────────────────────────

    #[test]
    fn tip_from_priority_fee() {
        // effective = min(20, 10+3) = 13; tip = 13 - 10 = 3
        assert_eq!(miner_tip(20, 3, 10), 3);
    }

    #[test]
    fn tip_capped_by_max_fee() {
        // effective = min(10, 8+5) = 10; tip = 10 - 8 = 2
        assert_eq!(miner_tip(10, 5, 8), 2);
    }

    #[test]
    fn tip_zero_when_no_priority() {
        assert_eq!(miner_tip(10, 0, 8), 0);
    }

    #[test]
    fn tip_zero_when_max_fee_equals_base() {
        assert_eq!(miner_tip(10, 5, 10), 0);
    }

    // ── EIP-4844 blob gas tests ───────────────────────────────

    #[test]
    fn blob_gas_price_zero_excess() {
        let price = calc_blob_gas_price(0);
        assert_eq!(
            price, MIN_BLOB_BASE_FEE,
            "zero excess should yield minimum blob fee"
        );
    }

    #[test]
    fn blob_gas_price_increases_with_excess() {
        let price0 = calc_blob_gas_price(0);
        // Need enough excess to overcome integer truncation (factor=1)
        let price1 = calc_blob_gas_price(BLOB_BASE_FEE_UPDATE_FRACTION);
        let price2 = calc_blob_gas_price(BLOB_BASE_FEE_UPDATE_FRACTION * 3);
        assert!(
            price1 > price0,
            "blob gas price should increase with excess (got {price1} vs {price0})"
        );
        assert!(
            price2 > price1,
            "blob gas price should keep increasing (got {price2} vs {price1})"
        );
    }

    #[test]
    fn excess_blob_gas_zero_when_under_target() {
        let excess = calc_excess_blob_gas(0, 0);
        assert_eq!(excess, 0);
    }

    #[test]
    fn excess_blob_gas_accumulates() {
        // Parent used more than target
        let excess = calc_excess_blob_gas(0, TARGET_BLOB_GAS_PER_BLOCK + 131_072);
        assert_eq!(excess, 131_072);
    }

    #[test]
    fn excess_blob_gas_drains() {
        // Parent had excess but used nothing
        let excess = calc_excess_blob_gas(100_000, 0);
        assert_eq!(excess, 0, "should drain to zero when under target");
    }

    #[test]
    fn excess_blob_gas_carries_forward() {
        let excess = calc_excess_blob_gas(500_000, TARGET_BLOB_GAS_PER_BLOCK);
        assert_eq!(excess, 500_000, "should carry forward when used == target");
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: EIP-1559 base fee adjustment comprehensive tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn eip1559_base_fee_increase_when_above_target() {
        let base = 1_000_000_000u64;
        let above_target = GAS_TARGET + 5_000_000;
        let new = calculate_base_fee(above_target, GAS_LIMIT, base);
        assert!(
            new > base,
            "base fee must increase when usage is above target"
        );
        let expected_delta = base * (above_target - GAS_TARGET) / GAS_TARGET / 8;
        assert_eq!(new, base + expected_delta.max(1));
    }

    #[test]
    fn eip1559_base_fee_decrease_when_below_target() {
        let base = 1_000_000_000u64;
        let below_target = GAS_TARGET - 5_000_000;
        let new = calculate_base_fee(below_target, GAS_LIMIT, base);
        assert!(
            new < base,
            "base fee must decrease when usage is below target"
        );
        let expected_delta = base * (GAS_TARGET - below_target) / GAS_TARGET / 8;
        assert_eq!(new, base - expected_delta);
    }

    #[test]
    fn eip1559_base_fee_alternating_full_empty_oscillates() {
        let base = INITIAL_BASE_FEE;
        let full = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
        assert!(full > base);
        let empty = calculate_base_fee(0, GAS_LIMIT, full);
        assert!(empty < full);
        assert!(
            empty > base / 2,
            "should not drop too far after one oscillation"
        );
    }

    #[test]
    fn eip1559_base_fee_stabilizes_at_50_pct() {
        let base = 500_000_000u64;
        let mut fee = base;
        for _ in 0..100 {
            fee = calculate_base_fee(GAS_TARGET, GAS_LIMIT, fee);
        }
        assert_eq!(
            fee, base,
            "base fee should remain constant at 50% utilization"
        );
    }

    #[test]
    fn eip1559_base_fee_never_zero() {
        let mut fee = 2u64;
        for _ in 0..1000 {
            fee = calculate_base_fee(0, GAS_LIMIT, fee);
            assert!(fee >= 1, "base fee must never be zero");
        }
    }

    #[test]
    fn eip1559_base_fee_max_change_bounded() {
        let base = 1_000_000u64;
        let max_increase = calculate_base_fee(GAS_LIMIT, GAS_LIMIT, base);
        assert!(
            max_increase - base <= base / 8 + 1,
            "increase {} exceeds 12.5% of {}",
            max_increase - base,
            base
        );

        let max_decrease = calculate_base_fee(0, GAS_LIMIT, base);
        assert!(
            base - max_decrease <= base / 8,
            "decrease {} exceeds 12.5% of {}",
            base - max_decrease,
            base
        );
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: EIP-4844 blob gas pricing comprehensive tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn eip4844_excess_blob_gas_multi_block_simulation() {
        let blob_gas_per_blob = 131_072u64;
        let used_per_block = blob_gas_per_blob * 4;
        let mut excess = 0u64;
        let mut prices = Vec::new();
        for _ in 0..5 {
            excess = calc_excess_blob_gas(excess, used_per_block);
            let price = calc_blob_gas_price(excess);
            prices.push(price);
        }
        for i in 1..prices.len() {
            assert!(
                prices[i] >= prices[i - 1],
                "blob gas price should increase: block {} = {}, block {} = {}",
                i - 1,
                prices[i - 1],
                i,
                prices[i]
            );
        }
    }

    #[test]
    fn eip4844_excess_drains_when_no_blobs() {
        let mut excess = 1_000_000u64;
        for _ in 0..20 {
            excess = calc_excess_blob_gas(excess, 0);
        }
        assert_eq!(
            excess, 0,
            "excess should drain to zero when no blobs are used"
        );
    }

    #[test]
    fn eip4844_exact_target_keeps_excess_constant() {
        let excess = 500_000u64;
        let next = calc_excess_blob_gas(excess, TARGET_BLOB_GAS_PER_BLOCK);
        assert_eq!(next, excess, "exact target usage should not change excess");
    }

    #[test]
    fn eip4844_blob_gas_price_exponential_growth() {
        let p0 = calc_blob_gas_price(0);
        let p1 = calc_blob_gas_price(BLOB_BASE_FEE_UPDATE_FRACTION);
        let p2 = calc_blob_gas_price(BLOB_BASE_FEE_UPDATE_FRACTION * 2);
        assert!(p1 > p0, "price should increase with excess");
        assert!(p2 > p1, "price should keep increasing with more excess");
        // Growth should be super-linear (exponential-like)
        let growth1 = p1 - p0;
        let growth2 = p2 - p1;
        assert!(
            growth2 > growth1,
            "growth should accelerate (exponential): g1={growth1}, g2={growth2}"
        );
    }
}
