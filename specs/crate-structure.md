# Crate Structure & Module Boundaries

> Implementation-ready workspace contract for the planned `shell-chain` Rust repository.
>
> This document is intentionally stricter than a high-level architecture note: it defines which crates own which responsibilities, which dependency directions are allowed, where shared traits should live, and which boundaries must remain stable when the first workspace scaffold is introduced.

## Status

Draft, but detailed enough to drive initial crate scaffolding and interface placement.

## 1. Goals

The workspace layout must support four constraints at the same time:

1. **Stateless verification first**
   - Core protocol objects, roots, and lightweight validation helpers must remain available without dragging in networking, execution, or node-runtime code.

2. **Protocol-shape fidelity**
   - Crate boundaries should follow the repository's local protocol model: wire objects, cryptographic dispatch, witness/state verification, execution, block orchestration, networking, and operator entry points.

3. **Replaceable implementations behind stable interfaces**
   - PQ signature libraries, accumulator internals, and runtime/networking backends may change, but higher-level crates should not need invasive rewrites when they do.

4. **Cheap-first validation ordering**
   - The crate graph must make it natural to perform decoding, root binding, fee checks, and signature prefilters before heavier witness reconstruction and execution work.

## 2. Planned Workspace Layout

The planned repository shape is:

```text
shell-chain/
├── Cargo.toml
├── crates/
│   ├── shell-primitives/
│   ├── shell-crypto/
│   ├── shell-state/
│   ├── shell-execution/
│   ├── shell-mempool/
│   ├── shell-consensus/
│   ├── shell-network/
│   └── shell-cli/
└── vectors/
    ├── transactions/
    ├── blocks/
    └── witnesses/
```

Notes:

- `vectors/` is not a crate. It is the planned repository-local home for canonical fixtures referenced by `specs/testing-vectors.md`.
- The first scaffold does not need to implement every module fully, but the crate names and their ownership boundaries should match this document from the start.

## 3. Crate Ownership

### 3.1 `shell-primitives`

Owns protocol-facing data shapes and pure helpers:

- SSZ-facing transaction, authorization, block, and witness container types,
- canonical encode/decode wrappers,
- `hash_tree_root` and signing-root helpers,
- domain constants and root/byte aliases,
- cross-crate error/value types that do not depend on heavy subsystems,
- narrow shared traits that describe protocol-shaped inputs/outputs without committing to a concrete backend.

Must not own:

- network peer scoring,
- mempool admission policy,
- concrete cryptographic verification backends,
- concrete state accumulator storage,
- execution engine logic.

Design rule:

- if a type is needed by three or more higher-level crates and can be expressed without backend-specific state, it should usually live here.

### 3.2 `shell-crypto`

Owns signature and hashing dispatch boundaries:

- scheme-aware verification traits,
- verifier registry / dispatcher logic,
- scheme-local byte-bound checks,
- normalized verification errors,
- hashing helpers that are specifically cryptographic-policy-facing rather than generic SSZ root helpers.

Must not own:

- transaction admission policy,
- block import orchestration,
- peer handling,
- protocol object definitions that are not crypto-specific.

### 3.3 `shell-state`

Owns state proof and accumulator behavior:

- witness verification,
- canonical witness ordering checks,
- state-key lookup modeling,
- proof reconstruction,
- accumulator traits and one or more concrete implementations,
- adapters that implement lower-layer read-only state metadata traits against concrete state views,
- state transition application interfaces that return post-state commitments.

Must not own:

- mempool fee policy,
- gossip transport policy,
- validator scheduling or block-import control flow.

### 3.4 `shell-execution`

Owns heavy execution logic:

- transaction execution against a validated state view,
- creation of execution outputs needed for `state_root` and `receipts_root`,
- execution-specific error taxonomy,
- sidecar-consumption interfaces after witness validation has already succeeded.

Must not own:

- direct P2P fetch logic,
- scheme dispatch,
- canonical SSZ object definitions,
- long-lived mempool replacement policy.

### 3.5 `shell-mempool`

Owns cheap-first transaction admission and local pool policy:

- transaction intake pipeline,
- fee-floor checks,
- replay / nonce-lane policy,
- replacement policy and pool eviction,
- cached stateless results for transaction-level checks,
- optional, trait-driven read access to lightweight state metadata when needed for admission.

Must not own:

- concrete state accumulator implementation,
- block import orchestration,
- peer reputation bookkeeping,
- wire codec definitions duplicated from `shell-primitives`.

### 3.6 `shell-consensus`

Owns block-level orchestration and binding:

- block-envelope and sidecar binding,
- proposer-signature validation flow,
- block import staging,
- header/body/sidecar commitment checks,
- coordination of transaction revalidation, witness preparation, and execution.

Must not own:

- raw transport plumbing,
- concrete cryptographic backends,
- protocol-type redefinitions,
- CLI/runtime startup wiring.

### 3.7 `shell-network`

Owns peer-facing behavior:

- gossip intake and announcement filtering,
- fetch policy for envelopes and sidecars,
- rate limiting and reputation consequences,
- mapping structured validation outcomes into peer actions,
- synchronization plumbing and request/response boundaries.

Must not own:

- cryptographic verification internals,
- canonical state proof verification logic,
- final block execution,
- operator CLI concerns.

### 3.8 `shell-cli`

Owns operator entry points:

- configuration loading,
- runtime wiring across crates,
- RPC server and administrative commands,
- node startup, shutdown, and local service composition.

`shell-cli` is expected to be the highest-level crate and may depend on all runtime crates that it wires together.

## 4. Allowed Dependency Direction

The dependency graph should remain acyclic and bottom-up. Use dependency edges, not physical directory nesting, as the source of truth:

```text
shell-crypto     -> shell-primitives
shell-state      -> shell-primitives
shell-state      -> shell-crypto      (optional; only for proof objects that require scheme-aware checks)
shell-execution  -> shell-primitives, shell-state
shell-mempool    -> shell-primitives, shell-crypto
shell-consensus  -> shell-primitives, shell-crypto, shell-state, shell-execution
shell-network    -> shell-primitives, shell-mempool, shell-consensus
shell-cli        -> shell-primitives, shell-crypto, shell-state, shell-execution, shell-mempool, shell-consensus, shell-network
```

More explicitly:

| Crate | Allowed direct dependencies | Forbidden dependency examples |
|---|---|---|
| `shell-primitives` | none or workspace-wide utility crates only | `shell-state`, `shell-mempool`, `shell-consensus`, `shell-network` |
| `shell-crypto` | `shell-primitives` | `shell-mempool`, `shell-network`, `shell-cli` |
| `shell-state` | `shell-primitives`, optionally `shell-crypto` if proof objects require scheme-aware checks | `shell-mempool`, `shell-network`, `shell-cli` |
| `shell-execution` | `shell-primitives`, `shell-state` | `shell-network`, `shell-cli` |
| `shell-mempool` | `shell-primitives`, `shell-crypto` | concrete `shell-state`, `shell-network`, `shell-cli` |
| `shell-consensus` | `shell-primitives`, `shell-crypto`, `shell-state`, `shell-execution` | `shell-network`, `shell-cli` |
| `shell-network` | `shell-primitives`, `shell-mempool`, `shell-consensus` | concrete PQ libraries, direct execution internals not surfaced through typed outcomes |
| `shell-cli` | all runtime crates as needed | none; it is the top-level composition crate |

Important constraint:

- `shell-mempool` must not depend on the concrete `shell-state` crate merely to answer lightweight admission questions. If mempool needs state-derived metadata, that interaction must go through a narrow trait defined in a lower layer.

Typed-outcome constraint:

- `shell-network` may consume only network-safe validation outcomes, never raw execution-engine structs.
- If an outcome type is shared by `shell-mempool`, `shell-consensus`, and `shell-network`, define it in `shell-primitives`.
- If a block-import path needs to compress richer execution details into a peer-facing result, `shell-consensus` must translate `shell-execution` errors into a smaller typed outcome before `shell-network` sees it.
- `shell-network` must not pattern-match on execution traces, post-state deltas, or engine-internal error enums.

## 5. Placement Rules for Shared Traits

Shared traits should live in the **lowest crate that can define them without importing a higher-level policy domain**.

### 5.1 Traits that belong in `shell-primitives`

Place a trait in `shell-primitives` when:

- it only refers to protocol data types, roots, or small value objects,
- it does not require a concrete storage engine,
- it is consumed by multiple higher-level crates.

Examples:

- lightweight root calculators,
- replay-domain or nonce-lane lookup interfaces expressed in protocol terms,
- lightweight state-metadata traits for mempool admission, with concrete implementations supplied by `shell-state`,
- read-only transaction metadata traits used by both mempool and consensus.

### 5.2 Traits that belong in `shell-crypto`

Place a trait in `shell-crypto` when it abstracts over verifier implementations or signer backends.

Examples:

- `SignatureVerifier`,
- dispatcher registration interfaces,
- scheme capability reporting.

Higher-level crates should consume these traits, not individual PQ vendor APIs.

### 5.3 Traits that belong in `shell-state`

Place a trait in `shell-state` when it inherently describes proof verification or state transition behavior and is primarily consumed after the workflow has already crossed into state-validation territory.

Examples:

- accumulator access traits,
- witness reconstruction interfaces,
- state transition application interfaces.

Do not place these in `shell-primitives` if doing so would force the lowest crate to encode state-engine semantics it does not own.

## 6. Module-Level Boundary Rules

Within each crate, modules should also preserve layering:

- `shell-primitives`
  - `types/`: protocol structs and wrappers,
  - `ssz/`: encode/decode and root helpers,
  - `domains/`: signing domains and constants,
  - `traits/`: cross-crate read-only traits and network-safe validation outcome types,
  - `errors/`: low-level protocol-shape errors.

- `shell-crypto`
  - `traits/`: verifier interfaces,
  - `dispatch/`: scheme routing,
  - `schemes/`: concrete implementations,
  - `errors/`: verification errors.

- `shell-state`
  - `keys/`, `witness/`, `accumulator/`, `transition/`, `views/`.

- `shell-execution`
  - `engine/`, `outputs/`, `errors/`, `state_view/`.

- `shell-mempool`
  - `admission/`, `fees/`, `replacement/`, `cache/`, `state_view/`.

- `shell-consensus`
  - `import/`, `header_checks/`, `sidecars/`, `execution_bridge/`, `outcomes/`.

- `shell-network`
  - `gossip/`, `fetch/`, `reputation/`, `sync/`.

- `shell-cli`
  - `config/`, `runtime/`, `rpc/`, `commands/`.

These module names are guidance rather than a frozen public API, but the layering intent should be preserved.

## 7. `std` / `no_std` Expectations

The first scaffold should keep `no_std` viability open for the lowest layers:

- `shell-primitives`: should be designed to support `no_std` with `alloc` if the chosen SSZ dependencies allow it.
- `shell-crypto`: should prefer `no_std`-compatible traits, even if some concrete verifier implementations require `std` behind feature flags.
- `shell-state`, `shell-execution`, `shell-mempool`: may start as `std` crates, but public interfaces should avoid unnecessary runtime coupling.
- `shell-network` and `shell-cli`: may assume `std`.

The important rule is not that every crate must be `no_std` on day one; it is that lower-layer interfaces should not casually close that option.

## 8. Feature-Flag Policy

Feature flags should expose implementation choices without changing the protocol contract.

Recommended categories:

- **backend-selection flags**
  - choose between concrete PQ libraries or accumulator backends.

- **operator/runtime flags**
  - enable RPC, telemetry, or optional node services.

- **test-only flags**
  - enable internal fixture helpers, mock signers, or debug assertions.

Feature flags must not:

- change SSZ discriminants,
- change canonical root calculation,
- silently redefine validation order,
- reinterpret a local protocol rule as optional when this spec treats it as required.

If a protocol area is still open, represent that openness with explicit provisional types or configuration surfaces, not with a feature flag that forks the protocol shape.

## 9. Third-Party Dependency Control

Protocol-sensitive dependencies should be selected and versioned at the workspace level.

At minimum, the workspace should centralize:

- SSZ codec dependencies,
- hashing dependencies,
- PQ signature dependencies,
- large-number and fixed-byte utility crates if shared across multiple crates.

Rules:

- do not let each crate pick a different SSZ or hashing stack,
- isolate vendor-specific PQ APIs inside `shell-crypto`,
- isolate execution-engine-specific dependencies inside `shell-execution`,
- prefer thin wrappers around external types before exposing them across crate boundaries.

## 10. Test Ownership and Fixture Placement

The workspace should keep tests close to the crate that owns the invariant, while allowing shared repository fixtures.

Ownership guidance:

- `shell-primitives`
  - SSZ round-trip tests,
  - union-tag compatibility tests,
  - root-calculation tests.

- `shell-crypto`
  - scheme dispatch tests,
  - signature size-bound tests,
  - verification pass/fail vectors.

- `shell-state`
  - witness ordering tests,
  - proof-reconstruction tests,
  - accumulator invariants.

- `shell-execution`
  - execution result and output-root tests.

- `shell-mempool`
  - cheap-first admission ordering tests,
  - fee-floor and replacement-policy tests.

- `shell-consensus`
  - header/body/sidecar binding tests,
  - block import stage-ordering tests.

- `shell-network`
  - peer consequence mapping tests,
  - fetch-policy and rate-limit tests.

Shared canonical fixtures should live under `vectors/` when the repository begins checking them in. Crates may mirror tiny inline fixtures inside unit tests, but reusable protocol vectors should not be duplicated across crates.

## 11. Initial Scaffolding Sequence

When the repository moves from documentation to code, scaffold in this order:

1. `shell-primitives`
2. `shell-crypto`
3. `shell-state`
4. `shell-mempool`
5. `shell-execution`
6. `shell-consensus`
7. `shell-network`
8. `shell-cli`

Rationale:

- `shell-primitives` goes first because every later crate depends on its protocol types, shared traits, and network-safe outcome vocabulary.
- `shell-crypto` goes second so signature-dispatch traits and normalized verification errors are fixed before mempool or consensus code starts calling vendor APIs directly.
- `shell-state` goes third because witness and accumulator interfaces must settle before execution or consensus code bakes in an incompatible state-access model.
- `shell-mempool` goes fourth because the cheap-first admission path depends only on `shell-primitives`, `shell-crypto`, and the lower-layer metadata traits that `shell-state` can implement later through adapters.
- `shell-execution` goes fifth because it should consume already-defined state interfaces rather than force `shell-state` to conform to engine-driven assumptions.
- `shell-consensus` goes sixth because it is the first crate that composes cryptographic checks, witness preparation, execution, and block-level binding into one import pipeline.
- `shell-network` goes seventh because it should depend on stable mempool and consensus outcome surfaces, not on still-moving execution internals.
- `shell-cli` goes last because it is pure composition and should wire together crates whose public interfaces are already stable enough to expose operational commands and services.

## 12. Non-Negotiable Boundary Checks

Any initial implementation should be reviewed against the following checklist:

- No higher-level crate is imported by `shell-primitives`.
- `shell-mempool` does not depend on a concrete state-engine implementation.
- PQ-library-specific types do not leak outside `shell-crypto`.
- Canonical SSZ/root logic is not reimplemented independently in multiple crates.
- Peer reputation logic stays in `shell-network`, not in validation crates.
- Runtime composition stays in `shell-cli`, not in consensus or networking crates.

If a proposed change breaks one of these checks, the default assumption should be that the boundary is wrong unless there is a documented reason to revise this spec.
