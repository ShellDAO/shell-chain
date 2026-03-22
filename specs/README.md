# shell-chain Implementation Specifications

Implementation-facing specifications for `shell-chain` live in this directory.
They are intended to be understandable on their own, without requiring documents outside this repository for basic context.

## Scope

The specs in this directory describe how the planned Rust implementation should be organized and where responsibilities should live.
They focus on implementation contracts such as:

- crate and module boundaries,
- Rust-facing data types and codec expectations,
- validation order and error surfaces,
- future testing-vector responsibilities.

When a protocol detail is still unsettled, the local specs mark it as pending rather than inventing a finalized rule.

## Shared Protocol Context

The documents here assume the following core ideas throughout the repository:

- **Envelope and sidecar separation**: transaction payloads and the larger witness data needed for stateless checks are modeled as related but distinct objects.
- **Canonical SSZ behavior**: wire-facing objects must preserve exact SSZ encode/decode and merkleization behavior.
- **PQ-capable authorization paths**: signature verification is dispatched through a scheme-aware abstraction instead of hard-coding a single signature family.
- **Cheap-first validation**: structural decoding, root checks, and fee-floor checks should happen before expensive proof reconstruction or heavy execution.
- **Unified state accumulator**: state access proofs are expected to target a compressed binary-tree style accumulator and a stateless verification flow.

## Contents

| Spec | Status | Description |
|---|---|---|
| [Crate Structure](crate-structure.md) | stub | Planned workspace layout and dependency rules |
| [Data Types](data-types.md) | draft | Rust-facing object model, SSZ bindings, and state/witness types |
| [Validation Rules](validation-rules.md) | draft | Transaction, block, and peer-handling validation flow |
| [Testing Vectors](testing-vectors.md) | stub | Future vector coverage and invariant ownership |

## Reading Order

If you are new to the repository, this order provides the fastest local overview:

1. `crate-structure.md` for planned package boundaries
2. `data-types.md` for the object model
3. `validation-rules.md` for runtime flow and error handling
4. `testing-vectors.md` for future verification obligations
