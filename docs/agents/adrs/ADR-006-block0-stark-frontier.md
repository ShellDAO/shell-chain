# ADR-006: STARK Frontier Starts at Block 0 — Continuous Proving from Genesis

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: CHANGELOG v0.22.0; checkpoints 269–272, 279–280; ADR-002; ADR-003; ADR-007

## Context

When STARK proving was first added to shell-chain, the proving frontier was
seeded from the current chain tip or from a configured start block. This caused
two classes of problems on long-running testnets:

1. **Historical gap**: all blocks before the seeding start-block would never be
   proved. If the chain had been running for thousands of blocks, the frontier
   would have a permanent gap starting at block 0, making the settled-source
   index incomplete and future L2 aggregation impossible (L2 windows require a
   contiguous L1 settlement history).

2. **0-tx / empty-block continuity**: quiet testnets produce mostly 0-tx blocks.
   The original "force-pop at tail" behaviour in `pop_contiguous_with_min_entries`
   dispatched `prove_sig_batch([])` for all-empty windows, which returned
   `Err("cannot prove empty batch")`, wasting CPU and flooding logs with errors.

The explicit design decision (checkpoint 269): "a 0-tx block only needs to be
covered by a contiguous L1 proof range; it does not need a standalone placeholder
proof." This means the prover must wait until at least one non-empty block is
present in the candidate window to accumulate ≥ 512 user-transaction entries
(`MIN_L1_STARK_TXS`).

## Decision

The STARK proving frontier is anchored at **block 0** at node startup. On every
startup the node calls `rebuild_settled_stark_sources_from_chain()` (see
`crates/node/src/node/event_loop.rs:217`) to reconstruct the settled-source
state from the persistent `SettledSourceIndex` (`ss/` prefix) and/or a full
canonical chain scan. STARK seeding then runs from `settled_l1_count` (the
count of already-proved L1 ranges) all the way forward, covering every canonical
block including 0-tx blocks.

Empty blocks are **included in `source_hashes`** as part of a contiguous range
proof; they are never skipped. The reward formula counts only non-empty source
blocks for the mint reward (`non_empty_source_count`); 0-tx gap blocks covered
for continuity do not inflate the reward.

A guard in `pop_contiguous_with_min_entries` (see
`crates/stark-prover/src/backlog.rs`) enforces: for L1, return `None` if
`entries < MIN_L1_STARK_TXS`, regardless of whether the window is at the
chain tail or has a contiguous successor. A secondary defence-in-depth guard
in `prover_service.rs` warns and returns early if `layer == 1 && entries.is_empty()`.

`is_stark_compression_source` returns `true` for any canonical block (including
0-tx) because it falls back to `chain_store.get_header_by_hash()`. This is
intentional: it seeds 0-tx blocks into the backlog for range coverage while the
threshold guard prevents standalone empty proofs.

## Rationale

- **Historical completeness**: a frontier starting at block 0 ensures the full
  canonical history can be proved and indexed, enabling future L2 aggregation
  over the complete L1 history.
- **No wasted proofs on idle chains**: the ≥ 512 entry threshold means the
  prover correctly idles on a quiet testnet without generating rejected proofs.
- **Economically correct reward**: the mint reward is proportional to productive
  signature work (`non_empty_source_count`), not block count.
- **Contiguous range semantics**: 0-tx blocks as implicit range members (not
  standalone proof targets) is the simplest model that satisfies both continuity
  and correctness.

## Alternatives considered

- **Skip 0-tx blocks entirely from source_hashes**: simplifies the window model
  but creates discontinuities in the source-hash range that break
  `validate_stark_amendment_ordering_with_overlay` (which requires a contiguous
  range with no settled block inside). Rejected.
- **Placeholder empty proof per 0-tx block**: generates on-chain transactions
  for blocks with no user activity; wastes settlement budget and inflates the
  settled-source index. Rejected.
- **Configurable start block**: allows operators to skip history but creates
  permanent gaps that block L2 aggregation. Rejected in favour of block-0 start
  with a fast-path index load.

## Consequences

- **Positive**: complete L1 proof coverage from genesis; prerequisite for future
  L2 recursive aggregation.
- **Positive**: no wasted proofs on idle chains; prover correctly idles.
- **Positive**: reward formula is economically correct.
- **Negative**: `frontier_lag` will be high on a quiet testnet (prover
  legitimately waiting for ≥ 512 user txs). Do **not** interpret high
  `frontier_lag` alone as a bug — it is correct behaviour.
- **Negative**: startup now performs a full chain scan on first run (O(chain
  height)); on SG3 at 119k+ blocks this adds a few seconds. Mitigated by the
  persistent `SettledSourceIndex` fast-path on subsequent restarts.
- **Risks / mitigations**: the `rebuild_settled_stark_sources_from_chain` fast-
  path must NOT blindly trust the durable index — orphaned fork-block entries
  during rolling upgrades can permanently wedge the frontier. Full reconcile
  against canonical chain is mandatory on startup (CHANGELOG v0.22.0; cf.
  checkpoint 249 stale-index deadlock incident).

## Implementation references

- Code: `crates/node/src/node/event_loop.rs:217` — `rebuild_settled_stark_sources_from_chain()` call at startup
- Code: `crates/node/src/node/event_loop.rs:228-258` — prover seed + `ProverService` spawn (see also CONSTITUTION audit §5.1 step 10a/11a)
- Code: `crates/stark-prover/src/backlog.rs` — `pop_contiguous_with_min_entries`, `MIN_L1_STARK_TXS` guard
- Tests: `l1_pop_low_entry_tail_always_waits`,
  `l1_pop_all_empty_window_always_waits`,
  `l1_pop_empty_leading_blocks_merge_with_non_empty_tail`
- CHANGELOG: v0.22.0 (durable `SettledSourceIndex`, O(3) `compression_layer_for_source` lookup,
  `rebuild_settled_stark_sources_from_chain` persistent-index fast-path)
- CHANGELOG: v0.22.1/v0.22.2 (STARK prover backlog stall fix on long low-entry
  L1 ranges at max-source window; empty-batch early return guard)

## Revisit triggers

- A future protocol adds checkpointed proof commitments so that the chain can
  start proving from a snapshot rather than block 0.
- `MIN_L1_STARK_TXS` (512) is tuned based on production proving throughput data.
- L2 aggregation `Active` mode is enabled, changing the block-0-frontier
  requirement (L2 windows must cover all settled L1 ranges from genesis).
