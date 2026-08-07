//! Async proof backlog — decouples block production from STARK proving.
//!
//! [`ProofBacklog`] holds a queue of [`ProofTask`]s awaiting async proving.
//! A high-watermark threshold signals when the backlog is growing faster than
//! the prover can drain it, enabling the system to shed non-critical work or
//! activate additional prover capacity.

use std::collections::{BTreeMap, HashMap, VecDeque};

use shell_primitives::ShellHash;

use crate::prover::SigBatchEntry;

fn next_block_number(block_number: u64) -> Option<u64> {
    block_number.checked_add(1)
}

fn is_next_block_number(current: u64, next: u64) -> bool {
    next_block_number(current) == Some(next)
}

// ── ProofTask ─────────────────────────────────────────────────────────────────

/// A single unit of work for the async prover: one block worth of signatures.
#[derive(Debug, Clone)]
pub struct ProofTask {
    /// The block hash identifying which block this task covers.
    pub block_hash: [u8; 32],
    /// The block number (used for ordered range scans and priority).
    pub block_number: u64,
    /// Signature batch entries from the block — inputs to the STARK prover.
    pub entries: Vec<SigBatchEntry>,
    /// STARK layer. L1 covers canonical block witnesses; L2+ covers lower-layer artifacts.
    pub layer: u32,
    /// Source block/artifact hashes covered by this task.
    pub source_hashes: Vec<ShellHash>,
    /// Total source payload size in bytes, when known.
    pub original_size: Option<u64>,
}

impl ProofTask {
    /// Create a new proof task.
    pub fn new(block_hash: [u8; 32], block_number: u64, entries: Vec<SigBatchEntry>) -> Self {
        Self {
            block_hash,
            block_number,
            entries,
            layer: 1,
            source_hashes: vec![ShellHash::from(block_hash)],
            original_size: None,
        }
    }

    /// Create a cross-block or recursive proving task with explicit source metadata.
    pub fn with_sources(
        block_hash: [u8; 32],
        block_number: u64,
        entries: Vec<SigBatchEntry>,
        layer: u32,
        source_hashes: Vec<ShellHash>,
        original_size: Option<u64>,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            entries,
            layer: layer.max(1),
            source_hashes,
            original_size,
        }
    }

    /// Number of signatures in this task.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ── L2ProverTask / ProverTask ─────────────────────────────────────────────────

/// A single unit of L2 recursive aggregation work.
///
/// Created by the node event loop when [`AggregationScheduler::on_block`]
/// fires a trigger.  Submitted to [`ProverService`] only when
/// `L2StarkMode::Active` is configured; otherwise the service logs that
/// recursive proving is unavailable and the job remains in `L2JobStore`
/// with status `Ready`.
///
/// [`AggregationScheduler::on_block`]: crate::scheduler::AggregationScheduler::on_block
#[derive(Debug, Clone)]
pub struct L2ProverTask {
    /// Deterministic job ID from [`L2AggregationJob::id`].
    ///
    /// Used to look up and update the durable job record in `L2JobStore`.
    pub job_id: ShellHash,
    /// The settled canonical L1 amendment hashes that form the input window.
    pub l1_source_hashes: Vec<ShellHash>,
    /// L1 `batch_root` field elements (u128) in canonical order.
    pub l1_batch_roots: Vec<u128>,
    /// First canonical block covered by the earliest L1 input.
    pub start_block: u64,
    /// Last canonical block covered by the latest L1 input (inclusive).
    pub end_block: u64,
    /// Sum of `original_size` from all contributing L1 amendments.
    pub original_size: Option<u64>,
}

/// A task dispatched to [`ProverService`].
///
/// The service routes based on variant:
/// - [`L1SigBatch`] → `prove_sig_batch()` (current implementation, always available).
/// - [`L2Aggregation`] → recursive aggregation prover (gated behind `L2StarkMode::Active`).
///
/// [`L1SigBatch`]: ProverTask::L1SigBatch
/// [`L2Aggregation`]: ProverTask::L2Aggregation
#[derive(Debug)]
pub enum ProverTask {
    /// L1 signature-batch STARK proof.
    L1SigBatch(ProofTask),
    /// L2 recursive proof aggregating multiple settled L1 proofs.
    L2Aggregation(L2ProverTask),
}

/// Default high-watermark: warn when the backlog exceeds this many tasks.
pub const DEFAULT_WATERMARK_THRESHOLD: usize = 64;
/// Minimum L1 witness entries before the prover may seal an L1 compression range.
pub const MIN_L1_STARK_TXS: usize = 512;
/// Maximum source blocks to coalesce into one L1 range while waiting for the
/// minimum entry threshold.
pub const DEFAULT_MAX_L1_RANGE_SOURCES: usize = 1024;

/// Explicit reason a L1 backlog front cannot be dispatched yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1StallDiagnosis {
    /// The contiguous front range has too few entries and stops at a missing
    /// block. If that gap is permanent, the caller may drain the pre-gap range
    /// and advance to later tasks.
    GapBeforeThreshold {
        entries: usize,
        gap_at_block: u64,
        contiguous_take: usize,
    },
    /// The contiguous front range reaches the queue tail but still has too few
    /// entries. This is an expected live-chain state: keep waiting for more
    /// canonical successor blocks rather than proving or draining.
    AwaitingMoreEntries {
        entries: usize,
        contiguous_take: usize,
    },
}

/// Async proof backlog — a bounded work queue for the background prover.
///
/// Tasks are queued in FIFO order.  The backlog exposes a *watermark*: the
/// depth at which it considers itself "above threshold" and signals that the
/// prover is falling behind block production.
///
/// Two O(1)/O(log n) indexes are maintained alongside the queue:
/// - `source_index`: `(layer, source_hash)` → O(1) `contains_source` lookup.
/// - `layer_blocks`: per-layer block counts → O(log n) `min_block_number_for_layer`.
///
/// # Thread safety
///
/// `ProofBacklog` is not `Sync` — callers should wrap it in a `Mutex` or
/// `tokio::sync::Mutex` when sharing across async tasks.
#[derive(Debug)]
pub struct ProofBacklog {
    pending: VecDeque<ProofTask>,
    /// (layer, source_hash) reference counts — enables O(1) `contains_source`.
    source_index: HashMap<(u32, ShellHash), usize>,
    /// Sources removed from the queue while the prover is computing or handing
    /// off their amendment. They remain reserved so frontier seeding cannot
    /// enqueue the same canonical range concurrently.
    in_flight_sources: HashMap<(u32, ShellHash), usize>,
    /// Per-layer sorted block-number counts — enables O(log n) frontier lookups.
    layer_blocks: BTreeMap<u32, BTreeMap<u64, usize>>,
    /// Canonical L1 source heights covered by pending tasks.
    pending_block_coverage: BTreeMap<u32, BTreeMap<u64, usize>>,
    /// Canonical L1 source heights reserved by an active prover task.
    in_flight_block_coverage: BTreeMap<u32, BTreeMap<u64, usize>>,
    /// Depth at which [`is_above_threshold`] returns `true`.
    ///
    /// [`is_above_threshold`]: ProofBacklog::is_above_threshold
    watermark_threshold: usize,
    /// Total tasks ever enqueued (monotonically increasing; never wraps in practice).
    total_enqueued: u64,
    /// Total tasks ever completed (popped via [`pop`]).
    ///
    /// [`pop`]: ProofBacklog::pop
    total_completed: u64,
}

impl ProofBacklog {
    /// Create a new backlog with the default watermark threshold.
    pub fn new() -> Self {
        Self::with_threshold(DEFAULT_WATERMARK_THRESHOLD)
    }

    /// Create a new backlog with a custom watermark threshold.
    pub fn with_threshold(watermark_threshold: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            source_index: HashMap::new(),
            in_flight_sources: HashMap::new(),
            layer_blocks: BTreeMap::new(),
            pending_block_coverage: BTreeMap::new(),
            in_flight_block_coverage: BTreeMap::new(),
            watermark_threshold,
            total_enqueued: 0,
            total_completed: 0,
        }
    }

    /// Push a new proving task onto the back of the queue.
    pub fn push(&mut self, task: ProofTask) {
        self.index_add(&task);
        self.pending.push_back(task);
        self.total_enqueued += 1;
    }

    /// Push a proving task onto the front of the queue.
    pub fn push_front(&mut self, task: ProofTask) {
        self.index_add(&task);
        self.pending.push_front(task);
        self.total_enqueued += 1;
    }

    /// Insert a sorted batch before the first later task from the same layer.
    ///
    /// Frontier recovery uses this to fill historical gaps while live tip tasks
    /// are already queued. Appending relative to the global queue maximum would
    /// leave the recovered range behind the tip and make the apparent gap look
    /// permanent to the prover.
    pub fn insert_ordered_batch(&mut self, mut tasks: Vec<ProofTask>) {
        if tasks.is_empty() {
            return;
        }

        let layer = tasks[0].layer;
        debug_assert!(tasks.iter().all(|task| task.layer == layer));
        tasks.sort_by_key(|task| task.block_number);
        tasks.dedup_by_key(|task| task.block_number);
        tasks.retain(|task| {
            if task.source_hashes.is_empty() {
                !self.contains_source(task.layer, &ShellHash::from(task.block_hash))
            } else {
                !task
                    .source_hashes
                    .iter()
                    .any(|source| self.contains_source(task.layer, source))
            }
        });
        if tasks.is_empty() {
            return;
        }

        let mut incoming = tasks.into_iter().peekable();
        let existing = std::mem::take(&mut self.pending);
        let mut rebuilt = VecDeque::with_capacity(existing.len() + incoming.len());

        for queued in existing {
            if queued.layer == layer {
                while incoming
                    .peek()
                    .is_some_and(|task| task.block_number < queued.block_number)
                {
                    let task = incoming.next().expect("peeked incoming task");
                    self.index_add(&task);
                    self.total_enqueued += 1;
                    rebuilt.push_back(task);
                }
                if incoming
                    .peek()
                    .is_some_and(|task| task.block_number == queued.block_number)
                {
                    // A canonical reorg may replace an already-queued source at
                    // the same height. Prefer the freshly seeded canonical task.
                    self.index_remove(&queued);
                    self.total_completed += 1;
                    let task = incoming.next().expect("peeked replacement task");
                    self.index_add(&task);
                    self.total_enqueued += 1;
                    rebuilt.push_back(task);
                    continue;
                }
            }

            rebuilt.push_back(queued);
        }

        for task in incoming {
            self.index_add(&task);
            self.total_enqueued += 1;
            rebuilt.push_back(task);
        }
        self.pending = rebuilt;
    }

    /// Returns true when a pending task already covers `source_hash` at `layer`.
    ///
    /// O(1) — backed by an internal reference-counted hash index.
    pub fn contains_source(&self, layer: u32, source_hash: &ShellHash) -> bool {
        let key = (layer, *source_hash);
        self.source_index.contains_key(&key) || self.in_flight_sources.contains_key(&key)
    }

    /// Pop a proof range and reserve all of its sources until handoff finishes.
    pub fn pop_contiguous_for_proving(
        &mut self,
        max_sources: usize,
        min_l1_entries: usize,
    ) -> Option<ProofTask> {
        let task = self.pop_contiguous_with_min_entries(max_sources, min_l1_entries)?;
        self.reserve_in_flight(&task);
        Some(task)
    }

    /// Release source reservations after proof failure or event-loop handoff.
    pub fn complete_in_flight(
        &mut self,
        layer: u32,
        block_number: u64,
        source_hashes: &[ShellHash],
    ) {
        for source_hash in source_hashes {
            Self::decrement_hash_count(&mut self.in_flight_sources, &(layer, *source_hash));
        }
        let task = ProofTask::with_sources(
            [0u8; 32],
            block_number,
            Vec::new(),
            layer,
            source_hashes.to_vec(),
            None,
        );
        Self::decrement_task_coverage(&mut self.in_flight_block_coverage, &task);
    }

    /// Pop the next task from the front of the queue (FIFO).
    ///
    /// Returns `None` when the backlog is empty.
    pub fn pop(&mut self) -> Option<ProofTask> {
        let task = self.pending.pop_front()?;
        self.index_remove(&task);
        self.total_completed += 1;
        Some(task)
    }

    /// Pop the first task plus following contiguous-height tasks, merging them
    /// into one range proof task.
    pub fn pop_contiguous(&mut self, max_sources: usize) -> Option<ProofTask> {
        self.pop_contiguous_with_min_entries(max_sources, 0)
    }

    /// Pop a contiguous range only when the first range satisfies the configured
    /// L1 minimum entry threshold. L2+ ranges are not threshold-gated.
    ///
    /// The minimum-entries threshold is always enforced for L1. Sparse frontier
    /// ranges remain queued until enough non-empty canonical successors arrive;
    /// proving under-threshold ranges would produce settlements that validation
    /// rejects.
    pub fn pop_contiguous_with_min_entries(
        &mut self,
        max_sources: usize,
        min_l1_entries: usize,
    ) -> Option<ProofTask> {
        let max_sources = max_sources.max(1);
        let first = self.pending.front()?;
        let layer = first.layer;
        let mut take = 1usize;
        let mut entries = first.entries.len();
        let mut end_block = first.block_number;

        while take < max_sources {
            let Some(next) = self.pending.get(take) else {
                break;
            };
            if next.layer != layer || !is_next_block_number(end_block, next.block_number) {
                break;
            }
            entries = entries.saturating_add(next.entries.len());
            end_block = next.block_number;
            take += 1;
            if layer == 1 && min_l1_entries > 0 && entries >= min_l1_entries {
                break;
            }
        }

        // L1 empty/low-entry guard: the prover must never dispatch a L1 range
        // whose merged entry count is below the settlement minimum.  Under-threshold
        // proofs are always rejected by settlement validation (n_sigs and empty-batch
        // checks), so generating them wastes prover work with no reward.
        //
        // The guard is conditioned on min_l1_entries > 0 so the utility
        // pop_contiguous(max_sources) variant (used in index/merge tests with
        // min_l1_entries=0) is not affected.
        //
        // If the capacity cap is reached and entries are still below min_l1_entries,
        // extend past max_sources scanning all remaining contiguous pending blocks.
        // The chain may have a long 0-tx or low-tx historical prefix where the first
        // threshold-satisfying block is far away; scanning past the cap avoids a
        // permanent deadlock in that scenario.
        if layer == 1 && min_l1_entries > 0 && entries < min_l1_entries && take == max_sources {
            let mut scan = take;
            while scan < self.pending.len() {
                let Some(next) = self.pending.get(scan) else {
                    break;
                };
                if next.layer != layer || !is_next_block_number(end_block, next.block_number) {
                    break;
                }
                entries = entries.saturating_add(next.entries.len());
                end_block = next.block_number;
                scan += 1;
                take = scan;
                if entries >= min_l1_entries {
                    break;
                }
            }
        }
        // Strict threshold: for L1, never prove a range below the minimum entry
        // count regardless of position in the queue (tail, cap boundary, or gap).
        // The frontier seeding extends the backlog as new canonical blocks arrive;
        // the prover waits rather than produce a provably-invalid range.
        if layer == 1 && min_l1_entries > 0 && entries < min_l1_entries {
            return None;
        }

        let mut merged = self.pop()?;
        for _ in 1..take {
            // Use direct pop_front and call index_remove so the index stays consistent.
            let next = self.pending.pop_front().expect("take checked above");
            self.index_remove(&next);
            self.total_completed += 1;
            merged.block_hash = next.block_hash;
            merged.block_number = next.block_number;
            merged.entries.extend(next.entries);
            merged.source_hashes.extend(next.source_hashes);
            merged.original_size = match (merged.original_size, next.original_size) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                _ => None,
            };
        }
        Some(merged)
    }

    /// Diagnose why `pop_contiguous_with_min_entries` would return `None`.
    ///
    /// Returns `(total_entries, gap_at_block, contiguous_take)` for the
    /// current front of the backlog. Used for rate-limited logging.
    pub fn diagnose_stall(
        &self,
        max_sources: usize,
        min_l1_entries: usize,
    ) -> Option<(usize, Option<u64>, usize)> {
        self.diagnose_l1_stall(max_sources, min_l1_entries)
            .map(|diagnosis| match diagnosis {
                L1StallDiagnosis::GapBeforeThreshold {
                    entries,
                    gap_at_block,
                    contiguous_take,
                } => (entries, Some(gap_at_block), contiguous_take),
                L1StallDiagnosis::AwaitingMoreEntries {
                    entries,
                    contiguous_take,
                } => (entries, None, contiguous_take),
            })
    }

    /// Diagnose why the L1 backlog front cannot be dispatched yet.
    ///
    /// Returns `None` when the front range is not L1, threshold checks are
    /// disabled, or a range could be popped immediately.
    pub fn diagnose_l1_stall(
        &self,
        max_sources: usize,
        min_l1_entries: usize,
    ) -> Option<L1StallDiagnosis> {
        let first = self.pending.front()?;
        if first.layer != 1 || min_l1_entries == 0 {
            return None;
        }
        let mut take = 1usize;
        let mut entries = first.entries.len();
        let mut end_block = first.block_number;
        let mut gap_at: Option<u64> = None;

        while take < max_sources {
            let Some(next) = self.pending.get(take) else {
                break;
            };
            if next.layer != 1 || !is_next_block_number(end_block, next.block_number) {
                gap_at = next_block_number(end_block);
                break;
            }
            entries = entries.saturating_add(next.entries.len());
            end_block = next.block_number;
            take += 1;
            if entries >= min_l1_entries {
                return None; // would succeed, not stuck
            }
        }
        // extension scan
        if take == max_sources && entries < min_l1_entries {
            let mut scan = take;
            while scan < self.pending.len() {
                let Some(next) = self.pending.get(scan) else {
                    break;
                };
                if next.layer != 1 || !is_next_block_number(end_block, next.block_number) {
                    gap_at = next_block_number(end_block);
                    break;
                }
                entries = entries.saturating_add(next.entries.len());
                end_block = next.block_number;
                scan += 1;
                take = scan;
                if entries >= min_l1_entries {
                    return None; // would succeed
                }
            }
        }
        if entries >= min_l1_entries {
            return None; // would succeed
        }
        match gap_at {
            Some(gap_at_block) => Some(L1StallDiagnosis::GapBeforeThreshold {
                entries,
                gap_at_block,
                contiguous_take: take,
            }),
            None => Some(L1StallDiagnosis::AwaitingMoreEntries {
                entries,
                contiguous_take: take,
            }),
        }
    }

    /// Peek at the next task without removing it.
    pub fn peek(&self) -> Option<&ProofTask> {
        self.pending.front()
    }

    /// Current number of pending tasks.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// `true` when the backlog is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The configured high-watermark depth.
    pub fn watermark_threshold(&self) -> usize {
        self.watermark_threshold
    }

    /// `true` when the backlog depth exceeds the watermark threshold.
    ///
    /// Consumers (e.g. `ProverService`) should check this after each block to
    /// decide whether to activate additional prover capacity or log a warning.
    pub fn is_above_threshold(&self) -> bool {
        self.pending.len() > self.watermark_threshold
    }

    /// How far above (or below) the threshold the current depth is.
    ///
    /// Positive means the backlog is `n` tasks over the watermark.
    /// Negative means `n` tasks of remaining capacity before warning.
    pub fn watermark(&self) -> i64 {
        self.pending.len() as i64 - self.watermark_threshold as i64
    }

    /// Total tasks ever enqueued since creation.
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Total tasks ever completed (successfully popped) since creation.
    pub fn total_completed(&self) -> u64 {
        self.total_completed
    }

    /// Return the minimum block number among all pending tasks for the given layer,
    /// or `None` if no tasks for that layer are queued.
    ///
    /// O(log n) — backed by a per-layer sorted block-number index.
    pub fn min_block_number_for_layer(&self, layer: u32) -> Option<u64> {
        self.layer_blocks
            .get(&layer)?
            .first_key_value()
            .map(|(number, _)| *number)
    }

    /// Returns the highest block number tracked for the given STARK layer, or
    /// `None` if the layer has no pending tasks. Used to detect when newly-seeded
    /// tasks extend the backlog tail (contiguous append) vs. jump the frontier.
    pub fn max_block_number_for_layer(&self, layer: u32) -> Option<u64> {
        self.layer_blocks
            .get(&layer)?
            .last_key_value()
            .map(|(number, _)| *number)
    }

    /// Number of pending tasks for a STARK layer.
    pub fn pending_task_count_for_layer(&self, layer: u32) -> usize {
        self.layer_blocks
            .get(&layer)
            .map(|blocks| blocks.values().copied().sum())
            .unwrap_or(0)
    }

    /// Number of source heights covered by pending and in-flight L1 work.
    pub fn covered_block_count_for_layer(&self, layer: u32) -> usize {
        self.pending_block_coverage
            .get(&layer)
            .map(BTreeMap::len)
            .unwrap_or(0)
            .saturating_add(
                self.in_flight_block_coverage
                    .get(&layer)
                    .map(BTreeMap::len)
                    .unwrap_or(0),
            )
    }

    /// Return the first canonical L1 height not covered by pending or in-flight work.
    ///
    /// This lookup is entirely in memory. Frontier recovery uses it to avoid
    /// rereading every already-queued historical block from RocksDB on each
    /// production tick.
    pub fn first_uncovered_block_for_layer(&self, layer: u32, start: u64, end: u64) -> Option<u64> {
        if start > end {
            return None;
        }
        let pending = self.pending_block_coverage.get(&layer);
        let in_flight = self.in_flight_block_coverage.get(&layer);
        (start..=end).find(|number| {
            !pending.is_some_and(|blocks| blocks.contains_key(number))
                && !in_flight.is_some_and(|blocks| blocks.contains_key(number))
        })
    }

    /// Drain all pending tasks, returning them in FIFO order.
    ///
    /// Useful for graceful shutdown — the caller can persist or re-queue tasks.
    pub fn drain(&mut self) -> Vec<ProofTask> {
        let tasks: Vec<_> = self.pending.drain(..).collect();
        self.total_completed += tasks.len() as u64;
        self.source_index.clear();
        self.layer_blocks.clear();
        self.pending_block_coverage.clear();
        tasks
    }

    /// Discard the first `n` tasks from the front of the backlog (e.g. to skip
    /// a stuck pre-gap range whose witnesses are permanently missing).
    pub fn drain_front(&mut self, n: usize) {
        let count = n.min(self.pending.len());
        for _ in 0..count {
            if let Some(task) = self.pending.pop_front() {
                self.total_completed += 1;
                self.index_remove(&task);
            }
        }
    }

    // ── Private index helpers ────────────────────────────────────────────────

    fn index_add(&mut self, task: &ProofTask) {
        if task.source_hashes.is_empty() {
            *self
                .source_index
                .entry((task.layer, ShellHash::from(task.block_hash)))
                .or_default() += 1;
        } else {
            for sh in &task.source_hashes {
                *self.source_index.entry((task.layer, *sh)).or_default() += 1;
            }
        }
        *self
            .layer_blocks
            .entry(task.layer)
            .or_default()
            .entry(task.block_number)
            .or_default() += 1;
        Self::increment_task_coverage(&mut self.pending_block_coverage, task);
    }

    fn index_remove(&mut self, task: &ProofTask) {
        if task.source_hashes.is_empty() {
            Self::decrement_hash_count(
                &mut self.source_index,
                &(task.layer, ShellHash::from(task.block_hash)),
            );
        } else {
            for sh in &task.source_hashes {
                Self::decrement_hash_count(&mut self.source_index, &(task.layer, *sh));
            }
        }
        if let Some(blocks) = self.layer_blocks.get_mut(&task.layer) {
            Self::decrement_block_count(blocks, task.block_number);
            if blocks.is_empty() {
                self.layer_blocks.remove(&task.layer);
            }
        }
        Self::decrement_task_coverage(&mut self.pending_block_coverage, task);
    }

    fn reserve_in_flight(&mut self, task: &ProofTask) {
        if task.source_hashes.is_empty() {
            *self
                .in_flight_sources
                .entry((task.layer, ShellHash::from(task.block_hash)))
                .or_default() += 1;
        } else {
            for source_hash in &task.source_hashes {
                *self
                    .in_flight_sources
                    .entry((task.layer, *source_hash))
                    .or_default() += 1;
            }
        }
        Self::increment_task_coverage(&mut self.in_flight_block_coverage, task);
    }

    fn task_coverage(task: &ProofTask) -> Option<std::ops::RangeInclusive<u64>> {
        if task.layer != 1 {
            return None;
        }
        let source_count = u64::try_from(task.source_hashes.len().max(1)).ok()?;
        let start = task
            .block_number
            .saturating_add(1)
            .saturating_sub(source_count);
        Some(start..=task.block_number)
    }

    fn increment_task_coverage(
        coverage: &mut BTreeMap<u32, BTreeMap<u64, usize>>,
        task: &ProofTask,
    ) {
        let Some(range) = Self::task_coverage(task) else {
            return;
        };
        let blocks = coverage.entry(task.layer).or_default();
        for number in range {
            *blocks.entry(number).or_default() += 1;
        }
    }

    fn decrement_task_coverage(
        coverage: &mut BTreeMap<u32, BTreeMap<u64, usize>>,
        task: &ProofTask,
    ) {
        let Some(range) = Self::task_coverage(task) else {
            return;
        };
        let Some(blocks) = coverage.get_mut(&task.layer) else {
            return;
        };
        for number in range {
            Self::decrement_block_count(blocks, number);
        }
        if blocks.is_empty() {
            coverage.remove(&task.layer);
        }
    }

    fn decrement_hash_count<K: Eq + std::hash::Hash>(counts: &mut HashMap<K, usize>, key: &K) {
        let should_remove = counts.get_mut(key).is_some_and(|count| {
            debug_assert!(*count > 0);
            *count -= 1;
            *count == 0
        });
        if should_remove {
            counts.remove(key);
        }
    }

    fn decrement_block_count(counts: &mut BTreeMap<u64, usize>, block_number: u64) {
        let should_remove = counts.get_mut(&block_number).is_some_and(|count| {
            debug_assert!(*count > 0);
            *count -= 1;
            *count == 0
        });
        if should_remove {
            counts.remove(&block_number);
        }
    }
}

impl Default for ProofBacklog {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    fn make_task(n: u64) -> ProofTask {
        ProofTask::new([n as u8; 32], n, vec![])
    }

    fn make_entry(n: u8) -> SigBatchEntry {
        SigBatchEntry {
            msg_hash: [n; 32],
            pk_hash: [n.wrapping_add(1); 32],
        }
    }

    fn make_hash(prefix: u8, n: u64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = prefix;
        hash[1..9].copy_from_slice(&n.to_le_bytes());
        hash
    }

    fn assert_index_consistency(backlog: &ProofBacklog) {
        let mut expected_sources = HashMap::new();
        let mut expected_blocks: BTreeMap<u32, BTreeMap<u64, usize>> = BTreeMap::new();
        let mut expected_coverage: BTreeMap<u32, BTreeMap<u64, usize>> = BTreeMap::new();

        for task in &backlog.pending {
            if task.source_hashes.is_empty() {
                *expected_sources
                    .entry((task.layer, ShellHash::from(task.block_hash)))
                    .or_default() += 1;
            } else {
                for source_hash in &task.source_hashes {
                    *expected_sources
                        .entry((task.layer, *source_hash))
                        .or_default() += 1;
                }
            }
            *expected_blocks
                .entry(task.layer)
                .or_default()
                .entry(task.block_number)
                .or_default() += 1;
            if let Some(range) = ProofBacklog::task_coverage(task) {
                let blocks = expected_coverage.entry(task.layer).or_default();
                for number in range {
                    *blocks.entry(number).or_default() += 1;
                }
            }
        }

        assert_eq!(backlog.source_index, expected_sources);
        assert_eq!(backlog.layer_blocks, expected_blocks);
        assert_eq!(backlog.pending_block_coverage, expected_coverage);
    }

    #[test]
    fn new_backlog_is_empty() {
        let b = ProofBacklog::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert_eq!(b.watermark_threshold(), DEFAULT_WATERMARK_THRESHOLD);
    }

    #[test]
    fn push_increases_len() {
        let mut b = ProofBacklog::new();
        b.push(make_task(1));
        assert_eq!(b.len(), 1);
        b.push(make_task(2));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn push_front_takes_priority() {
        let mut b = ProofBacklog::new();
        b.push(make_task(2));
        b.push_front(make_task(1));
        assert_eq!(b.pop().unwrap().block_number, 1);
        assert_eq!(b.pop().unwrap().block_number, 2);
    }

    #[test]
    fn ordered_batch_fills_gap_before_live_tip() {
        let mut b = ProofBacklog::new();
        b.push(make_task(10));
        b.push(make_task(100));

        b.insert_ordered_batch(vec![make_task(12), make_task(11)]);

        let blocks: Vec<_> = std::iter::from_fn(|| b.pop().map(|task| task.block_number)).collect();
        assert_eq!(blocks, vec![10, 11, 12, 100]);
        assert_index_consistency(&b);
    }

    #[test]
    fn ordered_batch_skips_sources_already_queued() {
        let mut b = ProofBacklog::new();
        b.push(make_task(10));
        b.push(make_task(100));

        b.insert_ordered_batch(vec![make_task(10), make_task(11)]);

        assert_eq!(b.len(), 3);
        let blocks: Vec<_> = std::iter::from_fn(|| b.pop().map(|task| task.block_number)).collect();
        assert_eq!(blocks, vec![10, 11, 100]);
        assert_index_consistency(&b);
    }

    #[test]
    fn ordered_batch_replaces_stale_task_at_same_height() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 10, vec![]));
        b.push(make_task(100));

        b.insert_ordered_batch(vec![ProofTask::new([2u8; 32], 10, vec![])]);

        let replacement = b.pop().expect("replacement task");
        assert_eq!(replacement.block_number, 10);
        assert_eq!(replacement.block_hash, [2u8; 32]);
        assert_eq!(b.pop().expect("tip task").block_number, 100);
        assert_index_consistency(&b);
    }

    #[test]
    fn proving_pop_reserves_sources_until_handoff_completes() {
        let mut b = ProofBacklog::new();
        let source = ShellHash::from([10u8; 32]);
        b.push(make_task(10));

        let task = b.pop_contiguous_for_proving(1, 0).expect("proof task");
        assert!(b.is_empty());
        assert!(b.contains_source(1, &source));
        assert_eq!(b.first_uncovered_block_for_layer(1, 10, 11), Some(11));

        b.insert_ordered_batch(vec![make_task(10)]);
        assert!(b.is_empty(), "reserved source must not be re-enqueued");

        b.complete_in_flight(task.layer, task.block_number, &task.source_hashes);
        assert!(!b.contains_source(1, &source));
        assert_eq!(b.first_uncovered_block_for_layer(1, 10, 11), Some(10));
        b.insert_ordered_batch(vec![make_task(10)]);
        assert_eq!(b.len(), 1);
        assert_index_consistency(&b);
    }

    #[test]
    fn coverage_index_finds_gap_without_scanning_queued_sources() {
        let mut b = ProofBacklog::new();
        b.insert_ordered_batch(
            (10..=20)
                .filter(|number| *number != 15)
                .map(make_task)
                .collect(),
        );

        assert_eq!(b.pending_task_count_for_layer(1), 10);
        assert_eq!(b.covered_block_count_for_layer(1), 10);
        assert_eq!(b.first_uncovered_block_for_layer(1, 10, 20), Some(15));
        assert_eq!(b.first_uncovered_block_for_layer(1, 16, 20), None);
        assert_index_consistency(&b);
    }

    #[test]
    fn contains_source_detects_pending_source_hash() {
        let mut b = ProofBacklog::new();
        let hash = ShellHash::from([7u8; 32]);
        b.push(ProofTask::with_sources(
            [1u8; 32],
            10,
            vec![],
            1,
            vec![hash],
            Some(1),
        ));
        assert!(b.contains_source(1, &hash));
        assert!(!b.contains_source(2, &hash));
    }

    #[test]
    fn pop_returns_fifo_order() {
        let mut b = ProofBacklog::new();
        b.push(make_task(10));
        b.push(make_task(20));
        b.push(make_task(30));

        assert_eq!(b.pop().unwrap().block_number, 10);
        assert_eq!(b.pop().unwrap().block_number, 20);
        assert_eq!(b.pop().unwrap().block_number, 30);
        assert!(b.pop().is_none());
    }

    #[test]
    fn pop_contiguous_merges_adjacent_range() {
        let mut b = ProofBacklog::new();
        let mut t1 = make_task(10);
        t1.original_size = Some(100);
        let mut t2 = make_task(11);
        t2.original_size = Some(200);
        let mut t4 = make_task(13);
        t4.original_size = Some(400);
        b.push(t1);
        b.push(t2);
        b.push(t4);

        let merged = b.pop_contiguous(8).unwrap();
        assert_eq!(merged.block_number, 11);
        assert_eq!(merged.source_hashes.len(), 2);
        assert_eq!(merged.original_size, Some(300));
        assert_eq!(b.len(), 1);
        assert_eq!(b.peek().unwrap().block_number, 13);
    }

    #[test]
    fn pop_contiguous_does_not_merge_terminal_height_duplicate() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], u64::MAX, vec![make_entry(1)]));
        b.push(ProofTask::new([2u8; 32], u64::MAX, vec![make_entry(2)]));

        let merged = b.pop_contiguous(8).unwrap();
        assert_eq!(merged.block_number, u64::MAX);
        assert_eq!(merged.source_hashes.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(b.peek().unwrap().block_number, u64::MAX);
    }

    #[test]
    fn l1_pop_always_waits_when_below_threshold_even_at_tail() {
        // Under the strict policy, L1 ranges with fewer than MIN_L1_STARK_TXS
        // entries must never be dispatched, regardless of whether there is a
        // contiguous successor.  Previously the prover would force-prove at the
        // queue tail; now it must wait for the frontier seeding to add more
        // blocks.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        b.push(ProofTask::new([3u8; 32], 3, vec![make_entry(3); 1]));
        // 100+200+1 = 301 entries < MIN_L1_STARK_TXS (512), no block 4 → tail.
        let result =
            b.pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
        assert!(
            result.is_none(),
            "below-threshold run at tail must not be dispatched"
        );
        assert_eq!(b.len(), 3, "all tasks must remain in backlog");
    }

    #[test]
    fn l1_pop_pops_when_threshold_met_across_multiple_blocks() {
        // 4 consecutive blocks whose combined entry count meets MIN_L1_STARK_TXS.
        // The loop exits as soon as the threshold is reached, so blocks 1-3
        // (100+200+212 = 512) are popped; block 4 (1 entry) stays in the backlog.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        b.push(ProofTask::new([3u8; 32], 3, vec![make_entry(3); 212]));
        b.push(ProofTask::new([4u8; 32], 4, vec![make_entry(4); 1]));

        // 100+200+212 = 512 ≥ MIN_L1_STARK_TXS — threshold reached at block 3.
        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("L1 range reaches 512 entries");
        assert_eq!(
            merged.block_number, 3,
            "stops at the block that hits threshold"
        );
        assert_eq!(merged.entries.len(), 512);
        assert_eq!(b.len(), 1, "block 4 with 1 entry remains in backlog");
    }

    #[test]
    fn l1_pop_below_threshold_waits_even_with_gap_after() {
        // A historical range with a gap after it must still wait if total
        // entries are below MIN_L1_STARK_TXS.  Proving an under-threshold range
        // produces a proof that settlement will always reject (n_sigs check),
        // so waiting is always correct.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        // Block 10 is non-contiguous — gap at blocks 3..=9.
        b.push(ProofTask::new([10u8; 32], 10, vec![make_entry(10); 500]));

        // Run is blocks 1+2 (300 entries < 512). Must return None.
        let result =
            b.pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
        assert!(
            result.is_none(),
            "under-threshold isolated run must not be dispatched"
        );
        // All tasks remain.
        assert_eq!(b.len(), 3, "tasks must stay in backlog");
    }

    #[test]
    fn l1_stall_diagnosis_distinguishes_gap_from_tail_wait() {
        let mut with_gap = ProofBacklog::new();
        with_gap.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        with_gap.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 100]));
        with_gap.push(ProofTask::new([8u8; 32], 8, vec![make_entry(8); 400]));

        assert_eq!(
            with_gap.diagnose_l1_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
            Some(L1StallDiagnosis::GapBeforeThreshold {
                entries: 200,
                gap_at_block: 3,
                contiguous_take: 2,
            })
        );

        let mut at_tail = ProofBacklog::new();
        at_tail.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        at_tail.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 100]));

        assert_eq!(
            at_tail.diagnose_l1_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
            Some(L1StallDiagnosis::AwaitingMoreEntries {
                entries: 200,
                contiguous_take: 2,
            })
        );
        assert_eq!(
            at_tail.diagnose_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
            Some((200, None, 2)),
            "legacy tuple diagnosis remains compatible"
        );

        let mut at_terminal = ProofBacklog::new();
        at_terminal.push(ProofTask::new(
            [u8::MAX; 32],
            u64::MAX,
            vec![make_entry(1); 100],
        ));
        at_terminal.push(ProofTask::new(
            [0xFE; 32],
            u64::MAX,
            vec![make_entry(2); 100],
        ));

        assert_eq!(
            at_terminal.diagnose_l1_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
            Some(L1StallDiagnosis::AwaitingMoreEntries {
                entries: 100,
                contiguous_take: 1,
            })
        );
    }

    #[test]
    fn l1_stall_diagnosis_none_when_threshold_can_pop() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 400]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 112]));

        assert_eq!(
            b.diagnose_l1_stall(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS),
            None
        );
    }

    #[test]
    fn l1_stall_diagnosis_reports_gap_after_extension_scan() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 100]));
        b.push(ProofTask::new([5u8; 32], 5, vec![make_entry(5); 400]));

        assert_eq!(
            b.diagnose_l1_stall(1, MIN_L1_STARK_TXS),
            Some(L1StallDiagnosis::GapBeforeThreshold {
                entries: 200,
                gap_at_block: 3,
                contiguous_take: 2,
            }),
            "gaps found after scanning past max_sources must be reported"
        );
    }

    /// A L1 window with 1 entry per block pops as soon as MIN_L1_STARK_TXS is
    /// reached instead of greedily swallowing the full source cap. This keeps
    /// live proofs bounded under sustained transaction load.
    #[test]
    fn l1_pop_advances_when_threshold_met_at_capacity() {
        let mut b = ProofBacklog::new();
        for block_number in 1..=DEFAULT_MAX_L1_RANGE_SOURCES as u64 {
            // One entry per block; 1024 blocks × 1 = 1024 entries ≥ MIN_L1_STARK_TXS (512).
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![make_entry(block_number as u8)],
            ));
        }

        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("window meets entry threshold and must pop");
        assert_eq!(merged.block_number, MIN_L1_STARK_TXS as u64);
        assert_eq!(merged.entries.len(), MIN_L1_STARK_TXS);
        assert_eq!(b.len(), DEFAULT_MAX_L1_RANGE_SOURCES - MIN_L1_STARK_TXS);
    }

    /// A L1 window with fewer total entries than MIN_L1_STARK_TXS must never be
    /// dispatched, even when the queue tail is reached (no contiguous successor).
    /// Under-threshold proofs are rejected by settlement validation, so the prover
    /// must wait for more canonical blocks to accumulate enough entries.
    #[test]
    fn l1_pop_low_entry_tail_always_waits() {
        // 5 blocks × 1 entry = 5 entries, well below MIN_L1_STARK_TXS (512).
        let mut b = ProofBacklog::new();
        for block_number in 1u64..=5 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![make_entry(block_number as u8)],
            ));
        }
        let result =
            b.pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
        assert!(
            result.is_none(),
            "low-entry tail must not be dispatched (5 entries < {MIN_L1_STARK_TXS})"
        );
        assert_eq!(b.len(), 5, "low-entry tasks must remain in backlog");

        // Same at max capacity with only 1 entry per block but total below threshold
        // (using a small max_sources so threshold is not met).
        let small_max = MIN_L1_STARK_TXS / 2; // e.g. 256 blocks × 1 entry = 256 < 512
        let mut b2 = ProofBacklog::new();
        for block_number in 1..=small_max as u64 {
            b2.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![make_entry(block_number as u8)],
            ));
        }
        let result2 = b2.pop_contiguous_with_min_entries(small_max, MIN_L1_STARK_TXS);
        assert!(
            result2.is_none(),
            "under-threshold at cap must not be dispatched ({small_max} entries < {MIN_L1_STARK_TXS})"
        );
        assert_eq!(b2.len(), small_max, "tasks must remain in backlog");
    }

    /// An all-empty L1 window (all 0-tx blocks) must never be dispatched to the
    /// prover, regardless of window size. The tasks stay in the backlog so they can
    /// be merged with the first non-empty successor block.
    #[test]
    fn l1_pop_all_empty_window_always_waits() {
        let mut b = ProofBacklog::new();
        // Push a few empty blocks (small window, no contiguous successor).
        for block_number in 1u64..=5 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }
        let result =
            b.pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
        assert!(
            result.is_none(),
            "small all-empty frontier must not be dispatched"
        );
        assert_eq!(b.len(), 5, "empty tasks must remain in backlog");

        // Same behaviour when the window is at max capacity.
        let mut b2 = ProofBacklog::new();
        for block_number in 1..=DEFAULT_MAX_L1_RANGE_SOURCES as u64 {
            b2.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }
        let result2 =
            b2.pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS);
        assert!(
            result2.is_none(),
            "full-capacity all-empty window must not be dispatched"
        );
        assert_eq!(
            b2.len(),
            DEFAULT_MAX_L1_RANGE_SOURCES,
            "tasks must remain in backlog"
        );
    }

    /// When the first max_sources blocks are all empty but a non-empty block follows
    /// contiguously, the prover must extend past the capacity cap and include that
    /// non-empty block in the merged window instead of deadlocking forever.
    #[test]
    fn l1_pop_extends_past_max_sources_to_break_empty_deadlock() {
        let mut b = ProofBacklog::new();
        // Fill exactly max_sources empty blocks (the historical deadlock scenario).
        for block_number in 1..=DEFAULT_MAX_L1_RANGE_SOURCES as u64 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }
        // One non-empty block immediately after (block max_sources+1).
        let next_block = DEFAULT_MAX_L1_RANGE_SOURCES as u64 + 1;
        let entries: Vec<SigBatchEntry> =
            (0..MIN_L1_STARK_TXS).map(|i| make_entry(i as u8)).collect();
        b.push(ProofTask::new([0xffu8; 32], next_block, entries));

        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("must break deadlock by extending past max_sources to reach non-empty block");
        assert_eq!(
            merged.block_number, next_block,
            "merged range must end at the non-empty block"
        );
        assert_eq!(
            merged.source_hashes.len(),
            DEFAULT_MAX_L1_RANGE_SOURCES + 1,
            "all empty blocks plus the non-empty block must be in source_hashes"
        );
        assert_eq!(
            merged.entries.len(),
            MIN_L1_STARK_TXS,
            "entries come only from the non-empty block"
        );
        assert!(b.is_empty());
    }

    /// Leading empty blocks are included in the merged source_hashes when the window
    /// is eventually sealed by a trailing non-empty block.
    #[test]
    fn l1_pop_empty_leading_blocks_merge_with_non_empty_tail() {
        let mut b = ProofBacklog::new();
        // 3 empty blocks followed by 1 non-empty block (well above MIN_L1_STARK_TXS).
        for block_number in 1u64..=3 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }
        let entries_4: Vec<SigBatchEntry> =
            (0..MIN_L1_STARK_TXS).map(|i| make_entry(i as u8)).collect();
        b.push(ProofTask::new([4u8; 32], 4, entries_4));

        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("non-empty tail should trigger a pop");
        // All 4 blocks merged: source_hashes contains empty blocks + non-empty block.
        assert_eq!(merged.block_number, 4);
        assert_eq!(
            merged.source_hashes.len(),
            4,
            "all 4 source hashes must be present"
        );
        assert_eq!(
            merged.entries.len(),
            MIN_L1_STARK_TXS,
            "entries come only from the non-empty block"
        );
        assert!(b.is_empty());
    }

    /// When the initial max_sources window has some entries but below min_l1_entries,
    /// the extension scan must continue past the cap until enough entries accumulate —
    /// not stop at the first non-empty block. This mirrors the real SG testnet scenario
    /// where block 3740 contributed only 2 entries but MIN_L1_STARK_TXS=512.
    #[test]
    fn l1_pop_extension_scan_accumulates_to_min_not_just_first_nonempty() {
        let mut b = ProofBacklog::new();
        // Fill max_sources blocks, each with 1 entry (well below MIN_L1_STARK_TXS).
        for block_number in 1..=DEFAULT_MAX_L1_RANGE_SOURCES as u64 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![make_entry(block_number as u8)],
            ));
        }
        // Extension blocks: each has 1 entry. We need MIN_L1_STARK_TXS - DEFAULT_MAX_L1_RANGE_SOURCES
        // more entries. Since DEFAULT_MAX_L1_RANGE_SOURCES=1024 > MIN_L1_STARK_TXS=512, the
        // initial window already satisfies min. So use a smaller initial window (64 blocks × 1 entry)
        // and verify extension scan accumulates across multiple sparse blocks.
        let mut b2 = ProofBacklog::new();
        let small_max = 64usize;
        for block_number in 1..=small_max as u64 {
            b2.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }
        // Sparse blocks after the cap: 2 entries each, need ~256 blocks to hit 512.
        for block_number in (small_max as u64 + 1)..=(small_max as u64 + 400) {
            b2.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![
                    make_entry(block_number as u8),
                    make_entry(block_number as u8 ^ 0xff),
                ],
            ));
        }
        let merged = b2
            .pop_contiguous_with_min_entries(small_max, MIN_L1_STARK_TXS)
            .expect("extension scan must accumulate enough entries across many sparse blocks");
        assert!(
            merged.entries.len() >= MIN_L1_STARK_TXS,
            "must have at least {} entries, got {}",
            MIN_L1_STARK_TXS,
            merged.entries.len()
        );
        assert!(
            merged.source_hashes.len() > small_max,
            "source_hashes must extend past initial cap"
        );
        // entries come from 2-per-block, need at least 256 extension blocks → 64+256=320 sources
        let expected_extension = MIN_L1_STARK_TXS.div_ceil(2); // 256 blocks at 2 entries each
        assert!(
            merged.source_hashes.len() >= small_max + expected_extension,
            "expected at least {} sources, got {}",
            small_max + expected_extension,
            merged.source_hashes.len()
        );
    }

    #[test]
    fn l2_pop_does_not_require_l1_minimum() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::with_sources(
            [1u8; 32],
            1,
            vec![make_entry(1)],
            2,
            vec![ShellHash::from([1u8; 32])],
            Some(100),
        ));

        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("L2 range is not threshold-gated");
        assert_eq!(merged.layer, 2);
        assert_eq!(merged.entries.len(), 1);
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut b = ProofBacklog::new();
        assert!(b.pop().is_none());
    }

    #[test]
    fn peek_does_not_remove() {
        let mut b = ProofBacklog::new();
        b.push(make_task(7));
        assert_eq!(b.peek().unwrap().block_number, 7);
        assert_eq!(b.len(), 1); // still there
    }

    #[test]
    fn watermark_below_threshold() {
        let b = ProofBacklog::with_threshold(10);
        assert!(!b.is_above_threshold());
        assert_eq!(b.watermark(), -10);
    }

    #[test]
    fn watermark_exactly_at_threshold_is_not_above() {
        let mut b = ProofBacklog::with_threshold(3);
        b.push(make_task(1));
        b.push(make_task(2));
        b.push(make_task(3));
        assert!(!b.is_above_threshold()); // len == threshold → NOT above
        assert_eq!(b.watermark(), 0);
    }

    #[test]
    fn watermark_above_threshold() {
        let mut b = ProofBacklog::with_threshold(3);
        for i in 0..5 {
            b.push(make_task(i));
        }
        assert!(b.is_above_threshold()); // len=5 > threshold=3
        assert_eq!(b.watermark(), 2);
    }

    #[test]
    fn total_enqueued_and_completed_counters() {
        let mut b = ProofBacklog::new();
        b.push(make_task(1));
        b.push(make_task(2));
        b.push(make_task(3));
        assert_eq!(b.total_enqueued(), 3);
        assert_eq!(b.total_completed(), 0);

        b.pop();
        assert_eq!(b.total_completed(), 1);
        b.pop();
        assert_eq!(b.total_completed(), 2);
    }

    #[test]
    fn drain_empties_backlog() {
        let mut b = ProofBacklog::new();
        for i in 0..5 {
            b.push(make_task(i));
        }
        let tasks = b.drain();
        assert_eq!(tasks.len(), 5);
        assert!(b.is_empty());
        assert_eq!(b.total_completed(), 5);
        // Tasks come out in FIFO order
        for (i, task) in tasks.iter().enumerate() {
            assert_eq!(task.block_number, i as u64);
        }
    }

    #[test]
    fn drain_empty_backlog_is_ok() {
        let mut b = ProofBacklog::new();
        let tasks = b.drain();
        assert!(tasks.is_empty());
    }

    #[test]
    fn proof_task_entry_count() {
        let entries = vec![
            SigBatchEntry {
                msg_hash: [0u8; 32],
                pk_hash: [1u8; 32],
            },
            SigBatchEntry {
                msg_hash: [2u8; 32],
                pk_hash: [3u8; 32],
            },
        ];
        let task = ProofTask::new([0u8; 32], 1, entries);
        assert_eq!(task.entry_count(), 2);
    }

    #[test]
    fn default_backlog_uses_default_threshold() {
        let b = ProofBacklog::default();
        assert_eq!(b.watermark_threshold(), DEFAULT_WATERMARK_THRESHOLD);
    }

    #[test]
    fn custom_threshold_respected() {
        let b = ProofBacklog::with_threshold(128);
        assert_eq!(b.watermark_threshold(), 128);
    }

    // ── Index-consistency tests ──────────────────────────────────────────────

    #[test]
    fn source_index_cleared_after_pop() {
        let mut b = ProofBacklog::new();
        let hash = ShellHash::from([3u8; 32]);
        b.push(ProofTask::with_sources(
            [1u8; 32],
            1,
            vec![],
            1,
            vec![hash],
            None,
        ));
        assert!(b.contains_source(1, &hash));
        b.pop();
        assert!(
            !b.contains_source(1, &hash),
            "index must be cleaned up after pop"
        );
    }

    #[test]
    fn source_index_cleared_after_drain() {
        let mut b = ProofBacklog::new();
        let hash = ShellHash::from([5u8; 32]);
        b.push(ProofTask::with_sources(
            [1u8; 32],
            1,
            vec![],
            1,
            vec![hash],
            None,
        ));
        b.drain();
        assert!(
            !b.contains_source(1, &hash),
            "index must be cleared after drain"
        );
        assert!(b.layer_blocks.is_empty());
        assert!(b.source_index.is_empty());
    }

    #[test]
    fn source_index_cleared_after_pop_contiguous() {
        let mut b = ProofBacklog::new();
        let h1 = ShellHash::from([1u8; 32]);
        let h2 = ShellHash::from([2u8; 32]);
        b.push(ProofTask::with_sources(
            [1u8; 32],
            1,
            vec![],
            1,
            vec![h1],
            None,
        ));
        b.push(ProofTask::with_sources(
            [2u8; 32],
            2,
            vec![],
            1,
            vec![h2],
            None,
        ));
        b.pop_contiguous(10);
        assert!(!b.contains_source(1, &h1));
        assert!(!b.contains_source(1, &h2));
        assert!(b.is_empty());
    }

    #[test]
    fn min_block_number_for_layer_uses_index() {
        let mut b = ProofBacklog::new();
        b.push(make_task(5));
        b.push(make_task(3));
        b.push(make_task(8));
        assert_eq!(b.min_block_number_for_layer(1), Some(3));

        b.pop(); // removes 5 (FIFO)
                 // min should still be 3 (it was pushed second but is still pending)
        assert_eq!(b.min_block_number_for_layer(1), Some(3));
    }

    #[test]
    fn min_block_number_for_layer_none_when_empty() {
        let b = ProofBacklog::new();
        assert_eq!(b.min_block_number_for_layer(1), None);
    }

    #[test]
    fn min_block_number_cleared_after_drain() {
        let mut b = ProofBacklog::new();
        b.push(make_task(10));
        b.drain();
        assert_eq!(b.min_block_number_for_layer(1), None);
    }

    #[test]
    fn fallback_source_index_uses_block_hash_when_source_hashes_empty() {
        // ProofTask::new() leaves source_hashes = vec![ShellHash::from(block_hash)]
        // but a task constructed directly may have empty source_hashes.
        // index_add/remove fall back to block_hash in that case.
        let bh: [u8; 32] = [42u8; 32];
        let bh_hash = ShellHash::from(bh);
        let mut task = make_task(1);
        task.block_hash = bh;
        task.source_hashes.clear(); // empty — triggers fallback path
        let mut b = ProofBacklog::new();
        b.push(task);
        assert!(b.contains_source(1, &bh_hash));
        b.pop();
        assert!(!b.contains_source(1, &bh_hash));
    }

    #[test]
    fn source_index_retains_overlapping_pending_task() {
        let shared_source = ShellHash::from(make_hash(7, 1));
        let mut b = ProofBacklog::new();
        b.push(ProofTask::with_sources(
            make_hash(8, 10),
            10,
            vec![],
            2,
            vec![shared_source],
            None,
        ));
        b.push(ProofTask::with_sources(
            make_hash(8, 11),
            11,
            vec![],
            2,
            vec![shared_source],
            None,
        ));

        b.pop();
        assert!(b.contains_source(2, &shared_source));
        assert_index_consistency(&b);

        b.pop();
        assert!(!b.contains_source(2, &shared_source));
        assert_index_consistency(&b);
    }

    #[test]
    fn block_index_retains_duplicate_pending_height() {
        let mut b = ProofBacklog::new();
        b.push(ProofTask::with_sources(
            make_hash(9, 7),
            7,
            vec![],
            2,
            vec![ShellHash::from(make_hash(10, 1))],
            None,
        ));
        b.push(ProofTask::with_sources(
            make_hash(9, 8),
            7,
            vec![],
            2,
            vec![ShellHash::from(make_hash(10, 2))],
            None,
        ));

        b.pop();
        assert_eq!(b.min_block_number_for_layer(2), Some(7));
        assert_eq!(b.max_block_number_for_layer(2), Some(7));
        assert_index_consistency(&b);

        b.pop();
        assert_eq!(b.min_block_number_for_layer(2), None);
        assert_index_consistency(&b);
    }

    #[test]
    fn indexes_remain_consistent_after_mixed_operations() {
        let mut b = ProofBacklog::new();

        let source10 = ShellHash::from(make_hash(10, 10));
        let source11 = ShellHash::from(make_hash(10, 11));
        let source_l2 = ShellHash::from(make_hash(20, 4));
        let source_l2_front = ShellHash::from(make_hash(20, 3));

        b.push(ProofTask::with_sources(
            make_hash(100, 10),
            10,
            vec![],
            1,
            vec![source10],
            None,
        ));
        b.push(ProofTask::with_sources(
            make_hash(100, 11),
            11,
            vec![],
            1,
            vec![source11],
            None,
        ));
        let fallback_hash = ShellHash::from(make_hash(99, 9));
        b.push_front(ProofTask::with_sources(
            make_hash(99, 9),
            9,
            vec![],
            1,
            vec![],
            None,
        ));
        b.push(ProofTask::with_sources(
            make_hash(110, 4),
            4,
            vec![],
            2,
            vec![source_l2],
            None,
        ));

        assert!(b.contains_source(1, &fallback_hash));
        assert!(b.contains_source(1, &source10));
        assert_eq!(b.min_block_number_for_layer(1), Some(9));
        assert_index_consistency(&b);

        let popped = b.pop().expect("fallback task should pop first");
        assert_eq!(popped.block_number, 9);
        assert!(!b.contains_source(1, &fallback_hash));
        assert_eq!(b.min_block_number_for_layer(1), Some(10));
        assert_index_consistency(&b);

        let merged_l1 = b.pop_contiguous(8).expect("L1 contiguous range should pop");
        assert_eq!(merged_l1.layer, 1);
        assert_eq!(merged_l1.block_number, 11);
        assert!(!b.contains_source(1, &source10));
        assert!(!b.contains_source(1, &source11));
        assert_eq!(b.min_block_number_for_layer(1), None);
        assert_index_consistency(&b);

        b.push_front(ProofTask::with_sources(
            make_hash(110, 3),
            3,
            vec![],
            2,
            vec![source_l2_front],
            None,
        ));
        assert_index_consistency(&b);
        let merged_l2 = b.pop_contiguous(8).expect("L2 contiguous range should pop");
        assert_eq!(merged_l2.layer, 2);
        assert_eq!(merged_l2.block_number, 4);
        assert!(!b.contains_source(2, &source_l2));
        assert!(!b.contains_source(2, &source_l2_front));
        assert_eq!(b.min_block_number_for_layer(2), None);
        assert_index_consistency(&b);

        b.push(make_task(100));
        b.push(make_task(101));
        assert_eq!(b.min_block_number_for_layer(1), Some(100));
        assert_index_consistency(&b);

        b.drain();
        assert!(b.is_empty());
        assert!(b.source_index.is_empty());
        assert!(b.layer_blocks.is_empty());
    }

    #[test]
    fn stress_indices_under_large_workload() {
        const TASKS_PER_LAYER: u64 = 512;
        let mut b = ProofBacklog::new();
        let mut source_keys = Vec::new();
        let mut fallback_keys = Vec::new();
        let mut layer2_first_fallback = None;
        let mut layer2_second_source = None;
        let mut layer3_first_fallback = None;

        for layer in 1..=3u32 {
            for block_number in 1..=TASKS_PER_LAYER {
                let block_hash =
                    make_hash(0x80 + layer as u8, ((layer as u64) << 32) | block_number);
                if block_number % 2 == 0 {
                    let source_hash = ShellHash::from(make_hash(
                        0x10 + layer as u8,
                        ((layer as u64) << 32) | block_number,
                    ));
                    b.push(ProofTask::with_sources(
                        block_hash,
                        block_number,
                        vec![],
                        layer,
                        vec![source_hash],
                        None,
                    ));
                    source_keys.push((layer, source_hash));
                    if layer == 2 && block_number == 2 {
                        layer2_second_source = Some(source_hash);
                    }
                } else {
                    b.push(ProofTask::with_sources(
                        block_hash,
                        block_number,
                        vec![],
                        layer,
                        vec![],
                        None,
                    ));
                    let fallback_hash = ShellHash::from(block_hash);
                    fallback_keys.push((layer, fallback_hash));
                    if layer == 2 && block_number == 1 {
                        layer2_first_fallback = Some(fallback_hash);
                    }
                    if layer == 3 && block_number == 1 {
                        layer3_first_fallback = Some(fallback_hash);
                    }
                }
            }
        }

        for _ in 0..8 {
            for (layer, hash) in source_keys.iter().step_by(41) {
                assert!(b.contains_source(*layer, hash));
            }
            for (layer, hash) in fallback_keys.iter().step_by(41) {
                assert!(b.contains_source(*layer, hash));
            }
            assert_eq!(b.min_block_number_for_layer(1), Some(1));
            assert_eq!(b.min_block_number_for_layer(2), Some(1));
            assert_eq!(b.min_block_number_for_layer(3), Some(1));
        }
        assert!(!b.contains_source(2, &ShellHash::from(make_hash(0xFF, 999_999))));
        assert_index_consistency(&b);

        let merged_layer1 = b
            .pop_contiguous(TASKS_PER_LAYER as usize + 1)
            .expect("layer1 range should be contiguous");
        assert_eq!(merged_layer1.layer, 1);
        assert_eq!(merged_layer1.block_number, TASKS_PER_LAYER);
        assert_eq!(b.min_block_number_for_layer(1), None);
        assert_eq!(b.min_block_number_for_layer(2), Some(1));
        assert_eq!(b.min_block_number_for_layer(3), Some(1));
        assert_index_consistency(&b);

        for _ in 0..128 {
            b.pop().expect("layer2 still has entries");
        }
        assert_eq!(b.min_block_number_for_layer(2), Some(129));
        assert!(!b.contains_source(2, &layer2_first_fallback.expect("set above")));
        assert!(!b.contains_source(2, &layer2_second_source.expect("set above")));
        assert!(b.contains_source(3, &layer3_first_fallback.expect("set above")));
        assert_index_consistency(&b);

        b.drain();
        assert!(b.source_index.is_empty());
        assert!(b.layer_blocks.is_empty());
    }
}
