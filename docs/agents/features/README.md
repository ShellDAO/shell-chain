# Feature Registry

Feature-Driven Development (FDD) registry for the `shell-chain` submodule. All development work on shell-chain is organized as **Features**.

## Directory Convention

```
docs/agents/features/
├── README.md              # This file — feature overview & index
├── <feature-id>/          # One directory per Feature
│   ├── spec.md            # Feature specification
│   ├── design.md          # Technical design (optional)
│   └── notes.md           # Development notes (optional)
```

Use the existing spec.md files as templates.

## Feature Status Definitions

| Status | Meaning |
|--------|---------|
| `draft` | Requirements draft, not yet reviewed |
| `ready` | Spec confirmed, development may begin |
| `in-progress` | Actively under development |
| `review` | Development complete, awaiting Code Review |
| `done` | Merged into shell-chain |
| `archived` | Deprecated or postponed |

## Feature Index

<!-- sorted by priority -->

| Priority | Feature ID | Name | Status | Owner |
|----------|------------|------|--------|-------|
| P0 | [`primitives`](primitives/spec.md) | Primitive Types & Hashing | `done` | — |
| P0 | [`crypto-core`](crypto-core/spec.md) | PQ Cryptography Core | `done` | — |
| P0 | [`core-types`](core-types/spec.md) | Core Domain Types | `done` | — |
| P1 | [`storage`](storage/spec.md) | RocksDB Storage Layer + MPT | `done` | — |
| P1 | [`consensus-poa`](consensus-poa/spec.md) | PoA Consensus Engine | `done` | — |
| P1 | [`evm-executor`](evm-executor/spec.md) | EVM Execution Layer (revm + PQ precompiles) | `done` | — |
| P2 | [`mempool`](mempool/spec.md) | Transaction Pool | `done` | — |
| P2 | [`network-p2p`](network-p2p/spec.md) | P2P Network Layer | `done` | — |
| P2 | [`rpc-server`](rpc-server/spec.md) | JSON-RPC API | `done` | — |
| P3 | [`node-harness`](node-harness/spec.md) | Node Assembly (Node Builder) | `done` | — |
| P3 | [`genesis`](genesis/spec.md) | Genesis Block Config & Initialization | `done` | — |
| P3 | [`account-abstraction`](account-abstraction/spec.md) | Native AA Phase 1 (batch + sponsored gas) | `done` (v0.18.0) | — |
| P3 | `stark-prover-l1` | STARK L1 async prover (per-block + backlog) | `done` (v0.18.0) | — |
| P4 | `consensus-wpoa` | wPoA Consensus Engine (lib-only, not in production) | `lib-only` | see CONSTITUTION §13.2 |
| P4 | `stark-recursive-l2` | Recursive L2 STARK (research scaffold) | `scaffold` | see CONSTITUTION §13.3 |
| P4 | `prover-registry-i5` | I5 ProverRegistry (lib-only, not wired into node) | `lib-only` | see CONSTITUTION §13.2 |
| P4 | `proof-window-manager-i4` | I4 ProofWindowManager (lib-only, not wired into node) | `lib-only` | see CONSTITUTION §13.2 |
| P4 | `consensus-peer-scoring-i6` | I6 prover peer scoring (lib-only, not wired into node) | `lib-only` | see CONSTITUTION §13.5 |

## How to Add a New Feature

1. Copy an existing `spec.md` from another feature directory to `features/<feature-id>/spec.md`.
2. Fill in the specification.
3. Add a row to the index table above.
4. Submit a PR for review.
