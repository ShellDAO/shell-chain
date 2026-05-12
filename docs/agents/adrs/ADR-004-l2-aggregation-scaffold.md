# ADR-004: L2 STARK Aggregation Three-Mode Scaffold (`L2StarkMode`)

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: `crates/node/src/config.rs`; `docs/agents/adrs/ADR-004-l2-aggregation-scaffold.md` (wPoA + STARK design); CONSTITUTION.md §13.1 (scaffold row); checkpoints 272–273

## Context

Shell-Chain's long-term roadmap includes recursive L2 STARK aggregation: batches
of L1 proofs are themselves proved recursively, compressing on-chain proof
footprint exponentially. However, as of v0.22.x:

- No real recursive circuit exists in production code.
- The `recursive` cargo feature gates the actual `prove()` call; without it the
  mode is accepted but recursive proving is a no-op.
- L2 aggregation must be driven **exclusively** by canonical settled
  `StarkReward` transactions, not by locally gossiped or unconfirmed L1
  amendments — orphaned proofs never settle, and building L2 windows on
  unconfirmed L1 proofs risks invalid aggregation windows (explicitly stated in
  checkpoint 272 design review).
- Premature L2 settlement on a live testnet with an incomplete recursive prover
  would emit invalid canonical settlements that cannot be unwound without a
  genesis reset.

The design needs three clearly separated operational states with precise
activation semantics so that observability can be added safely before the
recursive prover is production-ready.

## Decision

Introduce a `L2StarkMode` enum with three variants:

| Variant    | `is_enabled()` | `is_active()` | Behaviour |
|------------|---------------|---------------|-----------|
| `Disabled` | `false`        | `false`        | Default for all deployments. No L2 index, no scheduler, no settlements. |
| `Scaffold` | `true`         | `false`        | `L2InputIndex` maintained, `AggregationScheduler` windows computed and logged, gap detection active. No recursive `prove()` call. |
| `Active`   | `true`         | `true`         | Full recursive proving. Requires the `recursive` cargo feature; without it the mode is accepted but proving is skipped. **Forbidden in production until §13.1 promotion.** |

`L2StarkMode::Active` must not be set in any production or public testnet
deployment until the recursive prover boundary passes the §13.1 promotion
checklist in CONSTITUTION.md.

## Rationale

- **Safety default**: `Disabled` ensures no L2 activity unless explicitly
  opted-in. A misconfigured or upgraded node cannot accidentally emit L2
  settlements.
- **Incremental observability**: `Scaffold` lets internal nodes accumulate
  metrics (`L2InputIndex` counts, scheduler window logs, gap detection alerts)
  without consensus risk. This data is needed to tune the L2 window size and
  epoch parameters before the recursive prover goes live.
- **Feature-gated `Active`**: the `recursive` feature gate provides a second
  defence-in-depth; a production release binary built without `--features
  recursive` cannot execute the recursive prover even if `L2StarkMode::Active`
  is set in config.
- **Canonical-tx-driven L2**: `L2InputIndex` is keyed on final L1 source hashes
  from confirmed `StarkReward` txs, not from local proof artifact paths. This
  prevents L2 windows from being built on fork-block proofs that were never
  confirmed.
- **`L2AggregationJob.compute_id()`** uses blake3 of sorted L1 source hashes to
  ensure idempotent job creation across restarts.

## Alternatives considered

- **Single boolean `enable_l2_aggregation`**: insufficient; a boolean cannot
  distinguish "index but don't prove" from "fully active". Rejected.
- **Feature flag only (no runtime enum)**: would require different binaries for
  scaffold vs active. Rejected: operator UX is simpler with a config string.
- **Immediate `Active` without scaffold phase**: rejected because the recursive
  prover circuit is not yet validated, and emitting invalid L2 settlements on a
  live chain requires a genesis reset to recover.

## Consequences

- **Positive**: testnet safety guaranteed by default; L2 never produces canonical
  settlements until the recursive prover is real and §13.1-promoted.
- **Positive**: `Scaffold` mode provides production-quality observability
  (metrics, gap detection, scheduler window logs) before the risky `Active`
  transition.
- **Negative**: `l2_job_store` field in `ProverOrchestratorBoundary` triggers a
  `dead_code` clippy warning in `Disabled` mode; suppressed with
  `#[allow(dead_code)]`.
- **Negative**: L2 scheduler will not trigger aggregation windows with fewer
  than 2 pending L1 inputs, which delays L2 window closure on low-activity
  testnets.
- **Risks / mitigations**: if `Active` is accidentally set in production before
  §13.1 promotion, the `recursive` feature gate prevents actual proof execution.
  The enum display and `from_mode_str` validator surface the error at startup.

## Implementation references

- Code: `crates/node/src/config.rs:116-167` — `L2StarkMode` enum definition,
  `is_enabled()`, `is_active()`, `from_mode_str()`, `FromStr` impl
- Code: `crates/node/src/config.rs:237-239` — `NodeConfig.l2_stark_mode` field
  (default `Disabled`)
- Code: `crates/node/src/config.rs:292-296` — default initialisation
- Tests: `crates/node/src/config.rs::l2_stark_mode_default_is_disabled`
- Tests: `crates/node/src/config.rs::l2_stark_mode_is_enabled`
- Spec: `docs/agents/adrs/ADR-004-l2-aggregation-scaffold.md`
  (L2 async architecture design)
- Constitution: CONSTITUTION.md §13.1 (`stark-recursive (L2)` scaffold row,
  `feature gate recursive` note)
- CHANGELOG: v0.22.1 / v0.22.2 (L2 infrastructure merged on `bump-v0.22.1`)

## Revisit triggers

- The recursive STARK circuit passes QA and is promoted to §13.1 production
  status; at that point `L2StarkMode::Active` becomes the recommended default
  for prover nodes.
- A `Scaffold`-only deployment reveals that the `AggregationScheduler` window
  parameters need adjustment; the enum allows production tuning without
  enabling proving.
- The `recursive` cargo feature is dropped in favour of a runtime plugin; the
  feature-gate defence-in-depth must be replaced by an equivalent mechanism.
