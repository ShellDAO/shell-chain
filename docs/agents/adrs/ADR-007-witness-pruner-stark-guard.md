# ADR-007: Witness Pruner STARK Guard — Effective Cutoff `min(retention_cutoff, stark_frontier)`

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: CHANGELOG v0.22.2; checkpoints 288–289; ADR-006; CONSTITUTION audit P-3; invariant S-13

## Context

`WitnessPruner` removes block witness bundles (transaction execution witnesses
stored by `WitnessStore`) for blocks older than `DEFAULT_WITNESS_RETENTION`
(128 blocks). Witnesses are required by the STARK prover to generate
`ProofAmendment` for a given block.

On testnet-sg3, the STARK prover pipeline was deployed on a chain that had been
running for ~111,500 blocks before proving was enabled. The default
`retention_cutoff` pruned witnesses for blocks below `111,500 − 128 = 111,372`.
The proving frontier at that point was block ~62,000. The old binary had already
deleted witnesses for blocks 62,001–111,372 (approximately 49,000 blocks).

This created a **permanent gap class of bugs**:
- `witness_store.has_bundle(&hash)` returns `false` for pruned blocks.
- `is_stark_compression_source` returns `true` (falls back to header check),
  so pruned blocks are seeded into the backlog.
- The prover generates a `prove_sig_batch` call with an empty witness, which
  fails with `cannot prove empty batch`.
- The block becomes a **permanent gap block** — it can never be proved, the
  frontier stalls, and the only recovery is `drain_front()` to discard the range.

The same data-loss race will occur on any testnet that pre-dates STARK proving
whenever a new deployment attempts to catch up.

## Decision

Add a `stark_frontier: u64` parameter to `WitnessPruner::prune_before()`. The
effective pruning cutoff becomes:

```
cutoff = if stark_frontier > 0 {
    retention_cutoff.min(stark_frontier)
} else {
    retention_cutoff
}
```

Passing `stark_frontier = 0` disables the guard (preserves all existing test
semantics — all existing tests pass unchanged because they use the
`stark_frontier = 0` default).

`stark_frontier` is derived from `settled_stark_sources.count()` — the first
block number not yet covered by a settled proof — and is passed from the D1
block handler in `crates/node/src/node/mod.rs`. When the guard is active
(`stark_frontier > 0`), witnesses for blocks at or above `stark_frontier` are
never pruned, regardless of their age.

## Rationale

- **Data-loss prevention**: witnesses are the only source of truth for block
  execution data needed by the prover. Once pruned, they cannot be recovered
  without a chain re-execution. The guard is the minimal targeted fix.
- **Zero-overhead on existing tests**: `stark_frontier = 0` disables the guard;
  all 5 existing `WitnessPruner` tests pass without modification.
- **Compile-time safety net**: adding `stark_frontier` as a required parameter
  (not `Option<u64>`) means any call site that is not updated fails with
  `E0061` at compile time. During the v0.22.1 deployment, a missed update to a
  test file was immediately caught by `cargo test` (checkpoint 289 build failure,
  then fixed in the same session).
- **Correctness**: `settled_stark_sources.count()` is the conservative frontier
  — it is the count of proved L1 proofs, and witnesses below this count are
  definitionally safe to prune.

## Alternatives considered

- **Disable pruning entirely when STARK is active**: guarantees no data loss but
  can cause unbounded witness storage growth on long chains. Rejected as
  operationally untenable for multi-year testnets.
- **Extend retention window (increase `DEFAULT_WITNESS_RETENTION`)**: larger
  retention only delays the problem; on a chain where proving is far behind the
  tip, any finite retention window will eventually prune unproved witnesses.
  Rejected.
- **Optional `stark_frontier: Option<u64>` parameter**: `None` could mean
  "disabled"; using `0` instead is equally expressive and avoids an `Option`
  wrap at every call site.

## Consequences

- **Positive**: witnesses are never pruned for blocks ahead of the STARK proving
  frontier; eliminates the permanent-gap-block data-loss race.
- **Positive**: all 5 existing `WitnessPruner` tests pass with `stark_frontier=0`;
  3 new frontier-guard tests added (see references).
- **Negative**: `stark_frontier = 0` must be explicitly passed at **all**
  `prune_before()` call sites. A missed call site causes `E0061` — a compile
  error, not a silent bug. (One instance caught on SG3 during deployment,
  checkpoint 289.)
- **Negative**: witnesses for blocks 64,038–117,185 on SG3 were permanently lost
  before the fix (pruned by the old binary). The workaround was `drain_front()`
  to advance the frontier past the unproveable range.
- **Risks / mitigations**: if `settled_stark_sources.count()` is incorrect (e.g.
  after a stale `SettledSourceIndex` fast-path load — see ADR-006 context), the
  frontier could be set too high, re-enabling premature pruning. Mitigated by
  the startup reconcile that validates the index against canonical chain.

## Implementation references

- Code: `crates/storage/src/witness_pruner.rs:83` — `prune_before()` signature
  with `stark_frontier: u64` parameter
- Code: `crates/storage/src/witness_pruner.rs:96-103` — `min(retention_cutoff, stark_frontier)` logic
- Tests: `crates/storage/src/witness_pruner.rs:343` — `stark_frontier_guard_prevents_pruning_unproved_blocks`
- Constitution: CONSTITUTION audit P-3 (Witness Pruner STARK Guard new clause);
  invariant S-13 (data-loss prevention)
- CHANGELOG: v0.22.2 ("Witness pruner safety: witness data is no longer pruned
  for blocks that do not yet have a settled STARK proof")

## Revisit triggers

- The STARK prover becomes fast enough that `stark_frontier` always trails the
  tip by less than `DEFAULT_WITNESS_RETENTION`, making the guard effectively a
  no-op. At that point the guard can be removed.
- A witness archival service (separate from the in-node store) is added, making
  it safe to prune witnesses even for unproved blocks.
- `settled_stark_sources.count()` is replaced by a direct max-block sentinel,
  changing how `stark_frontier` is computed.
