# ADR-003: Drain-Frontier Shared `Arc<AtomicU64>` to Break the Drain-Reseed Infinite Loop

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: CHANGELOG v0.22.2; checkpoints 292–296; ADR-006; ADR-002

## Context

### The infinite drain-reseed loop bug

On testnet-sg3 (v0.22.1), the STARK prover entered a permanent cycle:

1. The backlog contained a sparse range (e.g. 6 blocks, 58 entries) that ended
   immediately before a settled gap at block 118071.
2. `pop_contiguous_with_min_entries` returned `None` because the entry count
   never reached `MIN_L1_STARK_TXS` (512) and there was no contiguous
   successor past the gap.
3. After `stall_timeout`, `ProverService` called `drain_front(take)` and
   signalled `needs_reseed = true`.
4. The block-timer in `event_loop.rs` fired `enqueue_stark_frontier_backlog`.
   The seeder computed `scan_start` from `settled_l1_count` (a count of settled
   proofs, not a max block number). Because the gap at 118071 was never crossed
   by a new proof, `settled_l1_count` never advanced past it, so `scan_start`
   perpetually fell below the drained blocks.
5. The seeder re-inserted the same sparse blocks (`push_front` Case 1 in the
   seeder) → back to front → loop. Cycle period: 60 seconds.
   `frontier_lag` reached **4807** on SG3.

The root cause: the seeding floor had no memory of what had been drained.
`settled_l1_count` only advances when a proof is accepted on-chain, which cannot
happen for the sparse range on the wrong side of the gap.

### Amendment artifact orphan sub-problem

A related pathology: when a proof ordering validation fails in `event_loop.rs`,
the `ProofAmendment` artifact was left in `amendment_store`. On the next reseed,
the seeder found the artifact, created a new `ProofTask`, the prover generated
the same proof, the ordering check failed again — a second spin loop. This is
addressed by deleting the artifact on ordering failure (tip-loop rejection guard,
CONSTITUTION audit P-5).

## Decision

Add a shared `Arc<AtomicU64>` named `stark_drain_frontier` to `Node<S>`. After
every `drain_front(take)` call in the gap-stall handler inside `ProverService`,
update the atomic via `fetch_max(gap_at_block, Ordering::Release)`. The seeding
function `enqueue_stark_frontier_backlog` reads the frontier with
`Ordering::Acquire` and clamps:

```
scan_start = max(contiguous_pending_end − 16, drain_frontier.load(Acquire))
```

The value resets to 0 on node restart (safe: a fresh stall will re-trigger if
the range is still sparse, but exactly one drain+advance cycle will occur, then
the loop is broken).

Additionally, `ProverService` requires **two consecutive** `diagnose_stall`
checks (≥ 120 s total) before firing `drain_front(take)` — the first stall only
logs `WARN`; the second fires the drain. State field `consecutive_gap: (u64, u32)`
resets whenever the gap location changes (2-tick confirmation guard, merged
PR #43, v0.22.2).

## Rationale

- **Lock-free**: a single `AtomicU64` with `fetch_max` is the minimal shared
  state needed; no mutex, no channel, zero overhead on the hot seeding path.
- **Monotonic**: `fetch_max` ensures the floor only ever rises, so no previously
  drained block can be re-inserted below the frontier.
- **`contiguous_pending_end` instead of `pending_max_block`**: using the raw max
  block (e.g. 119237 from a stale tip-proof) caused `scan_start` to jump to the
  tip, seeding only tip blocks that then failed ordering — a second spin loop.
  The contiguous-walk formula prevents this by only extending the frontier while
  there are no gaps in pending coverage.
- **2-tick confirmation guard**: a single 60-second stall on a quiet testnet is
  a normal condition (prover legitimately waits for ≥ 512 user txs). Two
  consecutive stalls at the same block position confirm a permanent gap.

## Alternatives considered

- **Persist drain frontier to storage**: would survive restarts; but the extra
  storage write per drain event adds I/O to an error-recovery path. On restart
  a single additional drain cycle is acceptable and safe. Rejected as
  over-engineering.
- **Advance `settled_l1_count` past gaps**: would require changing the settled-
  count semantics from "number of settled proofs" to "max settled block". This
  breaks ordering validation invariants used by the settlement layer. Rejected.
- **Single `drain_frontier` without 2-tick guard**: accepted during initial
  implementation, then the Copilot code review (PR #43) identified false-
  positive drain risk on quiet testnets. 2-tick guard added before merge.

## Consequences

- **Positive**: drain-reseed infinite loop broken permanently; verified on SG3:
  `frontier_lag` dropped from **4807 → 1** within 5 minutes of deployment
  (checkpoint 296).
- **Positive**: drain events at blocks 119207 and 121238 each fired exactly once
  after the fix.
- **Positive**: lock-free; zero overhead on the hot seeding path (one `Acquire`
  load per `enqueue_stark_frontier_backlog` call).
- **Negative**: `stark_drain_frontier` resets to 0 on node restart; if a sparse
  range exists after restart, one additional stall+drain cycle will fire.
- **Risks / mitigations**: any future refactor of `ProverService` construction
  must preserve the `with_drain_frontier()` wire. A missed wire is caught at
  compile time because the builder pattern requires the `Arc` before
  `ProverService` can be built.

## Implementation references

- Code: `crates/node/src/node/mod.rs:150` — `stark_drain_frontier: Arc<AtomicU64>` field on `Node<S>`
- Code: `crates/node/src/node/mod.rs:656` — initialised to `Arc::new(AtomicU64::new(0))`
- Code: `crates/node/src/node/event_loop.rs:250` — `.with_drain_frontier(Arc::clone(&self.stark_drain_frontier))`
- Code: `crates/node/src/node/event_loop.rs:1891` — seeder reads `stark_drain_frontier` with `Acquire`
- Code: `crates/node/src/prover_service.rs:131` — `drain_frontier: Arc<AtomicU64>` field
- Code: `crates/node/src/prover_service.rs:172-176` — `with_drain_frontier()` builder
- Code: `crates/node/src/prover_service.rs:289-290` — `fetch_max(gap, Ordering::Release)` after `drain_front()`
- CHANGELOG: v0.22.2 ("STARK drain-reseed infinite loop" fix; "Reseed anchored
  at contiguous settled frontier" Fix B; "Pre-gap sparse drain" Fix A)

## Revisit triggers

- The sparse-gap problem is resolved by a protocol change that prevents gaps
  from forming (e.g., mandatory proof submission before settlement acceptance).
- `settled_l1_count` semantics change to a true max-block frontier, making the
  drain-frontier redundant.
- `ProverService` is split into independent microservices where a shared atomic
  is insufficient and a pub/sub channel is required.
