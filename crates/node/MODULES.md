# `crates/node/` — module map for AI agents and humans

> This file is a **logical map** for navigating `crates/node/`. It does NOT
> change the physical file layout — it is the conceptual grouping that the
> ARCHITECTURE.md refers to and that ADR-005 documents the rationale for.

## Why one crate (not split)

The historical question was whether to split `crates/node` into
`crates/node-aa` (Account Abstraction handling) and
`crates/node-stark-orchestrator` (ProverService + STARK glue). The decision
in **ADR-005** is to keep `crates/node` singular and instead organize by
*logical groups* documented here.

Reasons (full list in ADR-005):
- Tight coupling around shared `EventLoop` and `Storage` traits
- The drain-frontier `Arc<AtomicU64>` is a process-wide single-instance object
  that the ProverService and Node both hold; splitting would require either
  a third coordination crate or a wider public API
- AA bundle handling is interleaved with `block_importer` and `block_producer`
  state mutations; an inter-crate boundary would force public types that
  today are private

## Logical groups

```
crates/node/src/
│
├── builder/        ← Construction
│   └── builder.rs                       NodeBuilder, dependency wiring
│
├── orchestrator/   ← Lifecycle & runtime coordination
│   ├── node/event_loop.rs               main loop
│   ├── node/p2p_handlers.rs             network message dispatch
│   ├── node/readiness.rs                startup + readiness signaling
│   ├── historical_sync.rs               peer catch-up coordination
│   ├── reorg.rs                         ReorgEngine
│   └── checkpoint.rs                    snapshot / checkpoint
│
├── consensus_apply/ ← Block-level state changes (consensus side)
│   ├── node/block_producer.rs           proposal path
│   ├── node/block_importer.rs           import path (rejects extra_data STARK)
│   ├── node/chain_state_machine.rs      state transitions
│   └── node/invariants.rs               assertions
│
├── stark/          ← STARK orchestration (NOT the prover crate itself)
│   ├── prover_service.rs                ProverService + drain-frontier
│   └── node/stark_sources.rs            durable ss/ index rebuild
│
├── aa/             ← Account Abstraction interleavings
│   └── (in node/block_producer.rs + node/block_importer.rs;
│        AA bundle structures live in core; this group is logical only)
│
├── ops/            ← Operational concerns
│   ├── metrics.rs                       Prometheus
│   ├── pruning.rs                       PruningConfig, StorageProfile
│   ├── validator_store.rs               validator key store glue
│   ├── node/dev_rpc.rs                  dev-only RPC
│   └── error.rs                         NodeError
│
└── config.rs       ← NodeConfig, NodeRole, L2StarkMode (ADR-004)
```

## File → group lookup

| File | Group | Purpose |
|------|-------|---------|
| `builder.rs` | builder | Construct a `Node` from a `NodeConfig` |
| `config.rs` | (top) | Configuration surface; `NodeRole`, `L2StarkMode` |
| `prover_service.rs` | stark | STARK orchestration; drain-frontier (P-2 / ADR-003) |
| `historical_sync.rs` | orchestrator | Peer catch-up |
| `reorg.rs` | orchestrator | Reorg detection + apply |
| `checkpoint.rs` | orchestrator | Snapshot integration |
| `metrics.rs` | ops | Prometheus counters |
| `pruning.rs` | ops | `PruningConfig`, `StorageProfile` |
| `validator_store.rs` | ops | Validator key glue |
| `error.rs` | ops | `NodeError` |
| `node/event_loop.rs` | orchestrator | Main runtime loop |
| `node/p2p_handlers.rs` | orchestrator | Network msg dispatch |
| `node/readiness.rs` | orchestrator | Startup readiness |
| `node/block_producer.rs` | consensus_apply | Block production + AA path |
| `node/block_importer.rs` | consensus_apply | Block import + AA path + STARK reject |
| `node/chain_state_machine.rs` | consensus_apply | State transitions |
| `node/invariants.rs` | consensus_apply | Runtime assertions |
| `node/stark_sources.rs` | stark | Durable `ss/` index rebuild |
| `node/dev_rpc.rs` | ops | Dev-only RPC handlers |
| `node/system_rewards.rs` | consensus_apply | StarkReward system tx (P-1 / ADR-002) |

## Read order for new contributors

1. `config.rs` — what knobs exist
2. `builder.rs` — how the Node is wired
3. `node/event_loop.rs` — the main loop
4. `node/block_producer.rs` + `node/block_importer.rs` — the consensus apply path
5. `prover_service.rs` — the STARK orchestrator
6. `node/system_rewards.rs` — system tx settlement payload

## Where to look for what (symptom-driven)

| Symptom | File |
|---|---|
| "STARK proof stuck / drain-reseed loop" | `prover_service.rs` (ADR-003) |
| "Block import rejected extra_data STARK" | `node/block_importer.rs` (CONSTITUTION P-1) |
| "AA bundle execution path" | `node/block_producer.rs` + `node/block_importer.rs` |
| "Witness pruner cutoff is wrong" | (in `crates/storage`, but `pruning.rs` configures it; ADR-007) |
| "How is system reward emitted?" | `node/system_rewards.rs` |
| "Validator set updated" | `validator_store.rs` + `crates/consensus` |
| "Reorg behavior" | `reorg.rs` |
| "Startup hangs at readiness" | `node/readiness.rs` + `historical_sync.rs` |
