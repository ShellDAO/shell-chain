//! Async proof backlog — decouples block production from STARK proving.
//!
//! [`ProofBacklog`] holds a queue of [`ProofTask`]s awaiting async proving.
//! A high-watermark threshold signals when the backlog is growing faster than
//! the prover can drain it, enabling the system to shed non-critical work or
//! activate additional prover capacity.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use shell_primitives::ShellHash;

use crate::prover::SigBatchEntry;

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

// ── ProofBacklog ──────────────────────────────────────────────────────────────

/// Default high-watermark: warn when the backlog exceeds this many tasks.
pub const DEFAULT_WATERMARK_THRESHOLD: usize = 64;
/// Minimum L1 witness entries before the prover may seal an L1 compression range.
pub const MIN_L1_STARK_TXS: usize = 512;
/// Maximum source blocks to coalesce into one L1 range while waiting for the
/// minimum entry threshold.
pub const DEFAULT_MAX_L1_RANGE_SOURCES: usize = 1024;

/// Async proof backlog — a bounded work queue for the background prover.
///
/// Tasks are queued in FIFO order.  The backlog exposes a *watermark*: the
/// depth at which it considers itself "above threshold" and signals that the
/// prover is falling behind block production.
///
/// Two O(1)/O(log n) indexes are maintained alongside the queue:
/// - `source_index`: `(layer, source_hash)` → O(1) `contains_source` lookup.
/// - `layer_blocks`: per-layer `BTreeSet<block_number>` → O(log n) `min_block_number_for_layer`.
///
/// # Thread safety
///
/// `ProofBacklog` is not `Sync` — callers should wrap it in a `Mutex` or
/// `tokio::sync::Mutex` when sharing across async tasks.
#[derive(Debug)]
pub struct ProofBacklog {
    pending: VecDeque<ProofTask>,
    /// (layer, source_hash) presence index — enables O(1) `contains_source`.
    source_index: HashSet<(u32, ShellHash)>,
    /// Per-layer sorted block numbers — enables O(log n) `min_block_number_for_layer`.
    layer_blocks: BTreeMap<u32, BTreeSet<u64>>,
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
            source_index: HashSet::new(),
            layer_blocks: BTreeMap::new(),
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

    /// Returns true when a pending task already covers `source_hash` at `layer`.
    ///
    /// O(1) — backed by an internal HashSet index.
    pub fn contains_source(&self, layer: u32, source_hash: &ShellHash) -> bool {
        self.source_index.contains(&(layer, *source_hash))
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
    /// The minimum-entries threshold is only enforced when the current run has
    /// an immediate contiguous successor in the backlog — meaning more entries
    /// may arrive before the prover needs to decide. If there is no contiguous
    /// successor (a gap or end of queue), the prover proves whatever is
    /// available to avoid a permanent deadlock on sparse or historical ranges.
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
            if next.layer != layer || next.block_number != end_block.saturating_add(1) {
                break;
            }
            entries = entries.saturating_add(next.entries.len());
            end_block = next.block_number;
            take += 1;
        }

        // Only block on min_entries when the run can still grow: there is an
        // immediate contiguous successor waiting in the backlog. If the run
        // ends at a gap or the backlog is exhausted, prove what we have rather
        // than waiting indefinitely for entries that will never arrive.
        let has_contiguous_successor = self
            .pending
            .get(take)
            .map(|next| next.layer == layer && next.block_number == end_block.saturating_add(1))
            .unwrap_or(false);
        if layer == 1 && min_l1_entries > 0 && entries < min_l1_entries && has_contiguous_successor
        {
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
    /// O(log n) — backed by a per-layer `BTreeSet<u64>` index.
    pub fn min_block_number_for_layer(&self, layer: u32) -> Option<u64> {
        self.layer_blocks.get(&layer)?.first().copied()
    }

    /// Drain all pending tasks, returning them in FIFO order.
    ///
    /// Useful for graceful shutdown — the caller can persist or re-queue tasks.
    pub fn drain(&mut self) -> Vec<ProofTask> {
        let tasks: Vec<_> = self.pending.drain(..).collect();
        self.total_completed += tasks.len() as u64;
        self.source_index.clear();
        self.layer_blocks.clear();
        tasks
    }

    // ── Private index helpers ────────────────────────────────────────────────

    fn index_add(&mut self, task: &ProofTask) {
        if task.source_hashes.is_empty() {
            self.source_index
                .insert((task.layer, ShellHash::from(task.block_hash)));
        } else {
            for sh in &task.source_hashes {
                self.source_index.insert((task.layer, *sh));
            }
        }
        self.layer_blocks
            .entry(task.layer)
            .or_default()
            .insert(task.block_number);
    }

    fn index_remove(&mut self, task: &ProofTask) {
        if task.source_hashes.is_empty() {
            self.source_index
                .remove(&(task.layer, ShellHash::from(task.block_hash)));
        } else {
            for sh in &task.source_hashes {
                self.source_index.remove(&(task.layer, *sh));
            }
        }
        if let Some(set) = self.layer_blocks.get_mut(&task.layer) {
            set.remove(&task.block_number);
            if set.is_empty() {
                self.layer_blocks.remove(&task.layer);
            }
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

    fn make_task(n: u64) -> ProofTask {
        ProofTask::new([n as u8; 32], n, vec![])
    }

    fn make_entry(n: u8) -> SigBatchEntry {
        SigBatchEntry {
            msg_hash: [n; 32],
            pk_hash: [n.wrapping_add(1); 32],
        }
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
    fn l1_pop_waits_for_minimum_entries_when_run_is_extensible() {
        // The min-entries threshold only applies while a contiguous successor
        // exists in the backlog (the run can still grow).  Push three
        // consecutive blocks but only the first two up front; block 3 acts as
        // the contiguous successor that keeps the threshold active.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        // Block 3 is the contiguous successor — its presence means the run
        // could grow further, so the prover should wait for min_entries.
        b.push(ProofTask::new([3u8; 32], 3, vec![make_entry(3); 1]));

        // Blocks 1+2+3 = 301 entries; block 4 (the successor for 3) absent →
        // has_contiguous_successor = false. Because the run cannot extend, the
        // prover proves it immediately even though 301 < 512.
        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("non-extensible run proved immediately");
        assert_eq!(merged.block_number, 3);
        assert_eq!(merged.entries.len(), 301);
    }

    #[test]
    fn l1_pop_waits_while_run_can_grow() {
        // When the backlog contains a run that has a contiguous successor, the
        // prover waits until min_entries are accumulated.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        // Block 3 at the back is the contiguous successor for block 2.
        // Accumulated entries for 1+2 = 300; block 3 would extend the run.
        b.push(ProofTask::new([3u8; 32], 3, vec![make_entry(3); 212]));
        // Block 4 makes block 3 extensible, so the threshold stays active.
        b.push(ProofTask::new([4u8; 32], 4, vec![make_entry(4); 1]));

        // Entries for 1+2+3+4 = 513 ≥ 512 → prove immediately.
        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("L1 range reaches 512 entries");
        assert_eq!(merged.block_number, 4);
        assert_eq!(merged.entries.len(), 513);
    }

    #[test]
    fn l1_pop_proves_isolated_range_below_minimum() {
        // A historical range with a gap after it should be proved immediately,
        // not blocked indefinitely by the min-entries threshold.
        let mut b = ProofBacklog::new();
        b.push(ProofTask::new([1u8; 32], 1, vec![make_entry(1); 100]));
        b.push(ProofTask::new([2u8; 32], 2, vec![make_entry(2); 200]));
        // Block 10 is non-contiguous — gap at blocks 3..=9.
        b.push(ProofTask::new([10u8; 32], 10, vec![make_entry(10); 500]));

        // Run is blocks 1+2 (300 entries). The next entry (block 10) is NOT
        // contiguous → has_contiguous_successor = false → prove immediately.
        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("isolated historical range proved immediately");
        assert_eq!(merged.block_number, 2);
        assert_eq!(merged.entries.len(), 300);
        // Block 10 still in queue.
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn l1_pop_advances_when_max_sources_reached_below_minimum() {
        let mut b = ProofBacklog::new();
        for block_number in 1..=DEFAULT_MAX_L1_RANGE_SOURCES as u64 {
            b.push(ProofTask::new(
                [block_number as u8; 32],
                block_number,
                vec![],
            ));
        }

        let merged = b
            .pop_contiguous_with_min_entries(DEFAULT_MAX_L1_RANGE_SOURCES, MIN_L1_STARK_TXS)
            .expect("max source window must make forward progress");
        assert_eq!(merged.block_number, DEFAULT_MAX_L1_RANGE_SOURCES as u64);
        assert!(merged.entries.is_empty());
        assert!(b.is_empty());
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
}
