# ADR-005: Keep `crates/node` Singular (No Split into node-aa / node-stark-orchestrator)

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: ADR-002, ADR-003, ADR-004; `crates/node/MODULES.md`

## Context

During the v0.22 refactor planning we evaluated splitting `crates/node` into
finer crates to improve discoverability and "vibe coding" ergonomics:

- `crates/node-aa` — Account Abstraction execution path
- `crates/node-stark-orchestrator` — ProverService, drain-frontier, settled
  source index rebuild, system_rewards orchestration

Motivation was discoverability: `crates/node/src/` mixes builder construction,
event loop, consensus apply, AA paths, STARK orchestration, metrics, pruning,
and validator-store glue. New contributors and AI agents struggled to find the
right file.

## Decision

**Keep `crates/node` as a single crate.** Address discoverability via:

1. A logical module map at `crates/node/MODULES.md` documenting groupings
   (builder / orchestrator / consensus_apply / stark / aa / ops) without moving
   files.
2. Cross-references from `ARCHITECTURE.md`, `features/node-harness/spec.md`,
   and per-symptom lookups in `learnings.md`.
3. Future filename additions follow the logical grouping (e.g. a new STARK
   helper goes alongside `prover_service.rs` and `node/stark_sources.rs`).

A physical split is reopenable when *all* of the revisit triggers below fire.

## Rationale

### Why the split was attractive

- Smaller crates compile faster (incremental) and have clearer ownership.
- AA and STARK orchestration are conceptually distinct from "the node loop".

### Why we rejected it (this round)

1. **Shared mutable state crosses the proposed boundary**: the
   `Arc<AtomicU64>` *drain-frontier* (ADR-003) is owned by `Node` and read
   by `ProverService`. Splitting forces this object into a third "shared
   types" crate or into the public API of one of the new crates. That
   widens the public surface and makes it easier to violate invariants.
2. **AA path is interleaved with consensus apply**: AA bundles are
   constructed and applied inside `block_producer.rs` /
   `block_importer.rs`. There is no clean seam — extracting AA would require
   exposing private state from the consensus apply path.
3. **No production pain demands it**: discoverability problems are solved
   adequately by `MODULES.md` + ARCHITECTURE diagrams. Compile-time pain
   is not a current bottleneck.
4. **Refactor cost vs benefit**: Phase 3 estimate was ≥ 200-line diff plus
   `use ...` rewrites across ~25 files plus full CI cycles; ROI is too low
   for a docs-driven release.
5. **Risk of breaking v0.22.2 release artifacts**: STARK pipeline stability
   has just been recovered (frontier_lag 4807 → 1, see CHANGELOG v0.22.2).
   A large structural refactor risks subtle regressions that don't show up
   until production.

## Alternatives considered

- **Option A (chosen)**: Singular crate + `MODULES.md` logical map.
- **Option B**: Split into `node-aa` and `node-stark-orchestrator`. Rejected
  this round; revisit triggers below.
- **Option C**: Split inside `crates/node/src/` into subdirs (`builder/`,
  `orchestrator/`, `stark/`, `aa/`). Rejected because (a) Rust `use` paths
  ripple through dependents, (b) gains over `MODULES.md` are minimal, (c)
  AA path doesn't have a separable file set.

## Consequences

- **Positive**: zero breakage for v0.22.x consumers; clear logical map for
  agents; ADR documents the *why* for future readers.
- **Negative**: `crates/node` continues to grow; without discipline,
  unrelated concerns may keep accumulating in `event_loop.rs`.
- **Mitigation**: any new file in `crates/node/src/` MUST update
  `MODULES.md` and reference the appropriate logical group.

## Implementation references

- Module map: `crates/node/MODULES.md`
- Drain-frontier (the canonical "shared state across boundary" example):
  `crates/node/src/prover_service.rs:286-296`,
  `crates/node/src/node/mod.rs:145-150`
- AA interleavings: `crates/node/src/node/block_producer.rs`,
  `crates/node/src/node/block_importer.rs`
- ARCHITECTURE: `docs/agents/ARCHITECTURE.md`

## Revisit triggers

Reopen this decision when **any** of the following fire:

1. Compile times in `crates/node` exceed 90 s on the CI runner.
2. The drain-frontier or another shared atomic grows into more than one
   shared object across the AA / STARK boundary (suggesting a real
   coordination crate is warranted).
3. AA path develops a self-contained module set that does not need access
   to `block_producer` / `block_importer` private state.
4. A new sub-team takes ownership of either AA or STARK orchestration in
   isolation, making code-ownership friction concrete.
5. We add a second consumer of `ProverService` outside `crates/node`
   (currently no such consumer exists).

When reopening, write ADR-NNN superseding this one.
