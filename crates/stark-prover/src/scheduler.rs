//! J3: Aggregation scheduler — decides when to trigger L2 recursive aggregation.
//!
//! ## Canonical-input semantics
//!
//! The scheduler only accepts **settled, canonical** L1 proof inputs via
//! [`AggregationScheduler::on_settled_l1_amendment`].  Gossiped or locally
//! queued L1 amendments are **not** fed here; only amendments whose
//! [`StarkReward`] system tx has been committed to the canonical chain belong.
//!
//! ## Contiguity requirement
//!
//! Every accepted amendment must continue exactly from where the previous one
//! ended, i.e. `input.start_block == window_end + 1`.  If a gap is detected
//! the scheduler enters a *blocked* state: it logs the gap start and refuses
//! to emit any trigger until the gap is filled by a later canonical L1 proof.
//!
//! ## Trigger conditions (any one suffices, when not gap-blocked)
//!
//! 1. **Proof count trigger**: at least `min_l1_proofs_for_l2` canonical L1
//!    proofs accumulated in the current contiguous window.
//! 2. **Interval trigger**: `trigger_block_interval` blocks since the last
//!    trigger (or genesis) without firing.
//! 3. **Epoch boundary trigger**: first block of a new epoch when
//!    `epoch_length > 0`.
//! 4. **Cap trigger**: window covers `max_source_range` or more blocks.
//!
//! [`StarkReward`]: shell_core::SystemTxKind::StarkReward

use crate::recursive_air::AggregationJob;

// ── SettledL1Input ────────────────────────────────────────────────────────────

/// A single settled canonical L1 STARK proof, usable as input for L2
/// recursive aggregation.
///
/// Only produced from canonical [`StarkReward`] system transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledL1Input {
    /// First canonical block covered by this L1 proof (inclusive).
    pub start_block: u64,
    /// Last canonical block covered by this L1 proof (inclusive).
    pub end_block: u64,
    /// The L1 `batch_root` field element (as u128) produced by the STARK proof.
    pub batch_root: u128,
    /// The canonical amendment hash — the key used in the `l2i/` input index.
    pub source_hash: [u8; 32],
}

impl SettledL1Input {
    /// Number of canonical blocks covered by this proof.
    pub fn block_count(&self) -> u64 {
        self.end_block.saturating_sub(self.start_block) + 1
    }
}

// ── AggregationConfig ─────────────────────────────────────────────────────────

/// Configuration for the aggregation scheduler.
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    /// Number of blocks per epoch. 0 disables epoch-boundary triggering.
    pub epoch_length: u64,
    /// Minimum number of **contiguous** canonical L1 proofs required to
    /// trigger an L2 aggregation round.  Must be ≥ 2.
    pub min_l1_proofs_for_l2: u64,
    /// Trigger aggregation every N blocks regardless of proof count.
    /// 0 disables interval triggering.
    pub trigger_block_interval: u64,
    /// If > 0, trigger when the pending window covers this many blocks.
    /// Prevents unboundedly large aggregation inputs.
    pub max_source_range: u64,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            epoch_length: 100,
            min_l1_proofs_for_l2: 8,
            trigger_block_interval: 50,
            max_source_range: 0,
        }
    }
}

// ── AggregationTrigger ────────────────────────────────────────────────────────

/// The reason an aggregation round was triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerReason {
    /// Triggered because `min_l1_proofs_for_l2` was reached.
    ProofThreshold,
    /// Triggered by `trigger_block_interval` cadence.
    BlockInterval,
    /// Triggered at an epoch boundary.
    EpochBoundary,
    /// Triggered because the pending window reached `max_source_range` blocks.
    RangeCap,
}

/// Emitted by [`AggregationScheduler::on_block`] when an aggregation should run.
#[derive(Debug, Clone)]
pub struct AggregationTrigger {
    /// The block number that triggered aggregation.
    pub at_block: u64,
    /// The aggregation window (block range + L1 roots).
    pub job: AggregationJob,
    /// Why aggregation was triggered.
    pub reason: TriggerReason,
    /// The canonical settled L1 inputs forming this window.
    ///
    /// These are in contiguous ascending order; the node can use them to
    /// create a durable [`L2AggregationJob`] record in `L2JobStore`.
    pub inputs: Vec<SettledL1Input>,
}

// ── Gap state ────────────────────────────────────────────────────────────────

/// Describes a detected gap in the canonical L1 proof sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1Gap {
    /// The block number expected as the start of the next L1 proof.
    pub expected_start: u64,
    /// The block number the next received amendment actually started at.
    pub received_start: u64,
}

// ── AggregationScheduler ──────────────────────────────────────────────────────

/// Stateful scheduler that tracks pending settled L1 proofs and decides when
/// to trigger L2 recursive aggregation.
///
/// **Call order:**
/// - [`on_settled_l1_amendment`] each time a canonical L1 amendment is seen.
/// - [`on_block`] each time a new block is sealed.
///
/// Aggregation triggers are returned from [`on_block`].
///
/// [`on_settled_l1_amendment`]: AggregationScheduler::on_settled_l1_amendment
/// [`on_block`]: AggregationScheduler::on_block
#[derive(Debug)]
pub struct AggregationScheduler {
    config: AggregationConfig,
    /// The expected `start_block` of the next incoming L1 proof.
    /// Starts at `genesis_block` and advances to `last_settled_end + 1` after
    /// each accepted amendment.
    window_start: u64,
    /// Accumulated canonical L1 inputs for the current contiguous window.
    pending_inputs: Vec<SettledL1Input>,
    /// Block number when the last aggregation was triggered.
    last_trigger_block: u64,
    /// Present when a gap has been detected in the canonical L1 sequence.
    /// The scheduler will not emit triggers while blocked.
    gap: Option<L1Gap>,
}

impl AggregationScheduler {
    /// Create a new scheduler anchored at `genesis_block` (usually 0).
    pub fn new(config: AggregationConfig, genesis_block: u64) -> Self {
        Self {
            config,
            window_start: genesis_block,
            pending_inputs: Vec::new(),
            last_trigger_block: genesis_block,
            gap: None,
        }
    }

    // ── Input ingestion ───────────────────────────────────────────────────

    /// Record a newly settled canonical L1 STARK amendment.
    ///
    /// Returns `Ok(())` if the amendment was accepted into the pending window.
    /// Returns `Err(gap)` if the amendment does not continue the current
    /// window (gap detected or duplicate).
    ///
    /// When a gap is returned the scheduler becomes **gap-blocked** until
    /// [`clear_gap`] is called or a reconciliation pass fills the hole.
    ///
    /// [`clear_gap`]: AggregationScheduler::clear_gap
    pub fn on_settled_l1_amendment(&mut self, input: SettledL1Input) -> Result<(), L1Gap> {
        // Existing chains may have their first canonical L1 proof start well
        // after block 0 (for example after enabling L2 observability on a live
        // testnet). Anchor the initial empty window to that first canonical
        // proof instead of permanently gap-blocking on `expected=0`.
        if self.pending_inputs.is_empty()
            && self.window_start == 0
            && self.last_trigger_block == 0
            && self.gap.is_none()
            && input.start_block > 0
        {
            tracing::info!(
                start_block = input.start_block,
                "L2 scheduler: anchoring initial window to first canonical L1 proof"
            );
            self.window_start = input.start_block;
        }

        // Duplicate / already-covered: ignore silently.
        if input.end_block < self.window_start {
            return Ok(());
        }

        // Contiguity check.
        if input.start_block != self.window_start {
            let gap = L1Gap {
                expected_start: self.window_start,
                received_start: input.start_block,
            };
            self.gap = Some(gap.clone());
            tracing::warn!(
                expected = self.window_start,
                received = input.start_block,
                "L2 scheduler: gap detected in canonical L1 proof sequence; \
                 aggregation blocked until gap is filled"
            );
            return Err(gap);
        }

        // Clear any previous gap now that continuity is restored.
        if self.gap.is_some() {
            tracing::info!(
                at = input.start_block,
                "L2 scheduler: gap resolved; resuming aggregation window"
            );
            self.gap = None;
        }

        self.window_start = input.end_block + 1;
        self.pending_inputs.push(input);
        Ok(())
    }

    /// Explicitly clear a detected gap (e.g. after a chain reconciliation).
    ///
    /// Also resets `window_start` to `new_window_start` so the scheduler
    /// accepts the next contiguous amendment from that point.
    pub fn clear_gap(&mut self, new_window_start: u64) {
        self.gap = None;
        self.window_start = new_window_start;
        self.pending_inputs.clear();
        tracing::info!(
            new_window_start,
            "L2 scheduler: gap manually cleared; window reset"
        );
    }

    // ── Block advancement ─────────────────────────────────────────────────

    /// Advance the scheduler to `block_number`.
    ///
    /// Returns `Some(AggregationTrigger)` if aggregation should start now
    /// (and the window has ≥ 2 canonical L1 inputs), or `None` otherwise.
    ///
    /// After a trigger the pending window is reset.
    pub fn on_block(&mut self, block_number: u64) -> Option<AggregationTrigger> {
        // Never trigger while gap-blocked.
        if self.gap.is_some() {
            return None;
        }
        // Need at least 2 inputs (aggregating one proof is a no-op).
        if self.pending_inputs.len() < 2 {
            return None;
        }

        let reason = self.check_triggers(block_number)?;
        Some(self.emit_trigger(block_number, reason))
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    /// Number of contiguous canonical L1 proofs in the current window.
    pub fn pending_proof_count(&self) -> u64 {
        self.pending_inputs.len() as u64
    }

    /// Block number where the current window starts.
    pub fn window_start(&self) -> u64 {
        self.window_start
    }

    /// Current gap state (if any).
    pub fn gap(&self) -> Option<&L1Gap> {
        self.gap.as_ref()
    }

    /// Total block span currently accumulated in the pending window.
    pub fn pending_block_span(&self) -> u64 {
        self.pending_inputs.iter().map(|i| i.block_count()).sum()
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn check_triggers(&self, block_number: u64) -> Option<TriggerReason> {
        let count = self.pending_inputs.len() as u64;
        let span = self.pending_block_span();

        // 1. Proof threshold.
        if count >= self.config.min_l1_proofs_for_l2 {
            return Some(TriggerReason::ProofThreshold);
        }

        // 2. Block interval.
        if self.config.trigger_block_interval > 0 {
            let since_last = block_number.saturating_sub(self.last_trigger_block);
            if since_last >= self.config.trigger_block_interval && count > 0 {
                return Some(TriggerReason::BlockInterval);
            }
        }

        // 3. Epoch boundary.
        if self.config.epoch_length > 0
            && block_number > 0
            && block_number % self.config.epoch_length == 0
            && count > 0
        {
            return Some(TriggerReason::EpochBoundary);
        }

        // 4. Range cap.
        if self.config.max_source_range > 0 && span >= self.config.max_source_range {
            return Some(TriggerReason::RangeCap);
        }

        None
    }

    fn emit_trigger(&mut self, block_number: u64, reason: TriggerReason) -> AggregationTrigger {
        let inputs = std::mem::take(&mut self.pending_inputs);
        let l1_roots: Vec<u128> = inputs.iter().map(|i| i.batch_root).collect();
        let window_start = inputs
            .first()
            .map(|i| i.start_block)
            .unwrap_or(block_number);
        let window_end = inputs.last().map(|i| i.end_block).unwrap_or(block_number);

        let mut job = AggregationJob::new(window_start, window_end);
        for root in &l1_roots {
            job.push_root(*root);
        }

        self.last_trigger_block = block_number;
        // window_start is already advanced by on_settled_l1_amendment calls

        tracing::info!(
            at_block = block_number,
            window_start,
            window_end,
            n_inputs = inputs.len(),
            reason = ?reason,
            "L2 scheduler: aggregation triggered"
        );

        AggregationTrigger {
            at_block: block_number,
            job,
            reason,
            inputs,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_scheduler() -> AggregationScheduler {
        AggregationScheduler::new(AggregationConfig::default(), 0)
    }

    fn make_input(start: u64, end: u64, root: u128) -> SettledL1Input {
        SettledL1Input {
            start_block: start,
            end_block: end,
            batch_root: root,
            source_hash: [0u8; 32],
        }
    }

    /// Feed `n` contiguous single-block L1 inputs starting at `from_block`.
    fn feed_inputs(sched: &mut AggregationScheduler, from_block: u64, n: u64, base_root: u128) {
        for i in 0..n {
            let b = from_block + i;
            sched
                .on_settled_l1_amendment(make_input(b, b, base_root + i as u128))
                .expect("should accept contiguous input");
        }
    }

    // ── basic acceptance ──────────────────────────────────────────────────

    #[test]
    fn no_trigger_when_fewer_than_2_inputs() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 0, 10)).unwrap();
        assert!(sched.on_block(5).is_none());
    }

    #[test]
    fn no_trigger_when_few_proofs_and_early_block() {
        let mut sched = default_scheduler();
        feed_inputs(&mut sched, 0, 2, 1);
        // Only 2 proofs, block 5, interval=50 — none of the triggers fire.
        assert!(sched.on_block(5).is_none());
    }

    #[test]
    fn first_existing_chain_input_anchors_window_instead_of_gap_blocking() {
        let mut sched = default_scheduler();
        sched
            .on_settled_l1_amendment(make_input(54_232, 54_335, 10))
            .expect("first canonical L1 proof on an existing chain should anchor the window");

        assert!(sched.gap().is_none());
        assert_eq!(sched.window_start(), 54_336);
        assert_eq!(sched.pending_proof_count(), 1);
    }

    #[test]
    fn later_non_contiguous_input_still_gap_blocks() {
        let mut sched = default_scheduler();
        sched
            .on_settled_l1_amendment(make_input(54_232, 54_335, 10))
            .unwrap();

        let gap = sched
            .on_settled_l1_amendment(make_input(54_400, 54_500, 11))
            .expect_err("non-contiguous follow-up must remain a real gap");

        assert_eq!(gap.expected_start, 54_336);
        assert_eq!(gap.received_start, 54_400);
        assert!(sched.gap().is_some());
    }

    // ── proof threshold ───────────────────────────────────────────────────

    #[test]
    fn proof_threshold_triggers_aggregation() {
        let mut sched = default_scheduler(); // min_l1 = 8
        feed_inputs(&mut sched, 0, 8, 100);
        let trigger = sched.on_block(10).expect("threshold should fire");
        assert_eq!(trigger.reason, TriggerReason::ProofThreshold);
        assert_eq!(trigger.at_block, 10);
        assert_eq!(trigger.inputs.len(), 8);
    }

    #[test]
    fn window_resets_after_trigger() {
        let mut sched = default_scheduler();
        feed_inputs(&mut sched, 0, 8, 0);
        sched.on_block(10); // fires
        assert_eq!(sched.pending_proof_count(), 0);
        assert_eq!(sched.window_start(), 8); // next expected block
    }

    // ── block interval ────────────────────────────────────────────────────

    #[test]
    fn block_interval_triggers_aggregation() {
        let mut sched = default_scheduler(); // interval = 50
        feed_inputs(&mut sched, 0, 2, 0); // need ≥ 2 for trigger
        let trigger = sched.on_block(50).expect("interval should fire");
        assert_eq!(trigger.reason, TriggerReason::BlockInterval);
    }

    #[test]
    fn interval_does_not_trigger_with_fewer_than_2_inputs() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 0, 1)).unwrap();
        // Only 1 input; on_block guards with < 2 check.
        assert!(sched.on_block(50).is_none());
    }

    // ── epoch boundary ────────────────────────────────────────────────────

    #[test]
    fn epoch_boundary_triggers_aggregation() {
        let config = AggregationConfig {
            epoch_length: 100,
            min_l1_proofs_for_l2: 8,
            trigger_block_interval: 0,
            max_source_range: 0,
        };
        let mut sched = AggregationScheduler::new(config, 0);
        feed_inputs(&mut sched, 0, 2, 0);
        let trigger = sched.on_block(100).expect("epoch boundary should fire");
        assert_eq!(trigger.reason, TriggerReason::EpochBoundary);
    }

    // ── range cap ─────────────────────────────────────────────────────────

    #[test]
    fn range_cap_triggers_aggregation() {
        let config = AggregationConfig {
            epoch_length: 0,
            min_l1_proofs_for_l2: 100, // very high threshold
            trigger_block_interval: 0,
            max_source_range: 10,
        };
        let mut sched = AggregationScheduler::new(config, 0);
        // 2 inputs each covering 5 blocks → span = 10 → cap fires.
        sched.on_settled_l1_amendment(make_input(0, 4, 1)).unwrap();
        sched.on_settled_l1_amendment(make_input(5, 9, 2)).unwrap();
        let trigger = sched.on_block(9).expect("range cap should fire");
        assert_eq!(trigger.reason, TriggerReason::RangeCap);
    }

    // ── priority ──────────────────────────────────────────────────────────

    #[test]
    fn proof_threshold_takes_priority_over_interval() {
        let mut sched = default_scheduler();
        feed_inputs(&mut sched, 0, 8, 0);
        // block 50 would also trigger interval but threshold is checked first.
        let trigger = sched.on_block(50).expect("trigger");
        assert_eq!(trigger.reason, TriggerReason::ProofThreshold);
    }

    // ── contiguity / gap detection ────────────────────────────────────────

    #[test]
    fn gap_blocks_trigger() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 0, 1)).unwrap();
        // Gap: expected 1, got 5.
        let err = sched
            .on_settled_l1_amendment(make_input(5, 5, 2))
            .unwrap_err();
        assert_eq!(err.expected_start, 1);
        assert_eq!(err.received_start, 5);
        assert!(sched.gap().is_some());
        // Even with many proofs already queued, trigger must not fire.
        assert!(sched.on_block(50).is_none());
    }

    #[test]
    fn gap_is_cleared_by_clear_gap() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 0, 1)).unwrap();
        sched
            .on_settled_l1_amendment(make_input(5, 5, 2))
            .unwrap_err(); // gap
        sched.clear_gap(5);
        assert!(sched.gap().is_none());
        assert_eq!(sched.window_start(), 5);
        // Feed contiguous inputs from the new start and trigger.
        feed_inputs(&mut sched, 5, 8, 10);
        assert!(sched.on_block(20).is_some());
    }

    #[test]
    fn duplicate_amendment_silently_ignored() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 4, 1)).unwrap();
        // Second call with end_block < window_start is a duplicate — ignored.
        sched.on_settled_l1_amendment(make_input(0, 4, 1)).unwrap();
        // window_start should still be 5.
        assert_eq!(sched.window_start(), 5);
        assert_eq!(sched.pending_proof_count(), 1);
    }

    #[test]
    fn multi_block_amendment_advances_window_correctly() {
        let mut sched = default_scheduler();
        // One amendment covering blocks 0–9.
        sched.on_settled_l1_amendment(make_input(0, 9, 42)).unwrap();
        assert_eq!(sched.window_start(), 10);
        assert_eq!(sched.pending_block_span(), 10);
    }

    // ── trigger job contents ──────────────────────────────────────────────

    #[test]
    fn trigger_job_covers_correct_range() {
        let mut sched = default_scheduler();
        feed_inputs(&mut sched, 0, 8, 100);
        let trigger = sched.on_block(15).unwrap();
        assert_eq!(trigger.job.start_block, 0);
        assert_eq!(trigger.job.end_block, 7);
        assert_eq!(trigger.inputs.len(), 8);
    }

    #[test]
    fn trigger_inputs_carry_batch_roots() {
        let mut sched = default_scheduler();
        feed_inputs(&mut sched, 0, 8, 1000);
        let trigger = sched.on_block(10).unwrap();
        let roots: Vec<u128> = trigger.inputs.iter().map(|i| i.batch_root).collect();
        assert_eq!(roots, (1000..1008u128).collect::<Vec<_>>());
    }

    // ── disabled modes ────────────────────────────────────────────────────

    #[test]
    fn disabled_interval_does_not_trigger() {
        let config = AggregationConfig {
            trigger_block_interval: 0,
            min_l1_proofs_for_l2: 100,
            epoch_length: 0,
            max_source_range: 0,
        };
        let mut sched = AggregationScheduler::new(config, 0);
        feed_inputs(&mut sched, 0, 5, 0);
        for b in 1u64..=200 {
            assert!(sched.on_block(b).is_none(), "unexpected trigger at {b}");
        }
    }

    #[test]
    fn no_epoch_trigger_at_zero() {
        let mut sched = default_scheduler();
        assert!(sched.on_block(0).is_none());
    }

    // ── accessors ────────────────────────────────────────────────────────

    #[test]
    fn pending_proof_count_accessor() {
        let mut sched = default_scheduler();
        assert_eq!(sched.pending_proof_count(), 0);
        feed_inputs(&mut sched, 0, 3, 0);
        assert_eq!(sched.pending_proof_count(), 3);
    }

    #[test]
    fn pending_block_span_accessor() {
        let mut sched = default_scheduler();
        sched.on_settled_l1_amendment(make_input(0, 4, 1)).unwrap(); // 5 blocks
        sched.on_settled_l1_amendment(make_input(5, 7, 2)).unwrap(); // 3 blocks
        assert_eq!(sched.pending_block_span(), 8);
    }

    #[test]
    fn aggregation_config_default_values() {
        let cfg = AggregationConfig::default();
        assert_eq!(cfg.epoch_length, 100);
        assert_eq!(cfg.min_l1_proofs_for_l2, 8);
        assert_eq!(cfg.trigger_block_interval, 50);
        assert_eq!(cfg.max_source_range, 0);
    }
}
