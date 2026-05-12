# ADR Registry — shell-chain

> **What is an ADR?** An *Architecture Decision Record* captures *why* a non-obvious
> design choice was made. ADRs complement feature specs: a spec describes *what is*;
> an ADR describes *why we chose this and not the alternatives*.

## Numbering & status

- ADRs are numbered sequentially: `ADR-001`, `ADR-002`, …
- Numbers are never reused. If an ADR is replaced, mark it `superseded by ADR-NNN`
  and write a new ADR.
- Status lifecycle: `proposed` → `accepted` → `deprecated` / `superseded`.

## Format

Use [`template.md`](template.md). Each ADR file is named
`ADR-NNN-<short-kebab-slug>.md`.

## Registry

| # | Title | Status |
|---|---|---|
| [001](ADR-001-pq-signature-stack.md) | PQ signature stack (Dilithium3 / ML-DSA-65 / SPHINCS+) | accepted |
| [002](ADR-002-stark-tx-level-settlement.md) | STARK tx-level settlement (system reward tx) | accepted |
| [003](ADR-003-drain-frontier.md) | Drain-frontier shared `Arc<AtomicU64>` | accepted |
| [004](ADR-004-l2-aggregation-scaffold.md) | L2 aggregation 3-mode scaffold | accepted |
| [005](ADR-005-node-crate-singular.md) | Keep `crates/node` singular (no node-aa / node-stark-orchestrator split) | accepted |
| [006](ADR-006-block0-stark-frontier.md) | Continuous block-0 STARK frontier | accepted |
| [007](ADR-007-witness-pruner-stark-guard.md) | Witness pruner STARK guard | accepted |
| [008](ADR-008-three-rpc-fanout.md) | Three-RPC fanout (8545 / 8547 / 8549) | accepted |
| [009](ADR-009-systemd-deployment-topology.md) | systemd / preflight deployment topology | accepted |
| [010](ADR-010-md-to-html-pipeline.md) | Markdown → HTML content pipeline (shell-site) | accepted |
