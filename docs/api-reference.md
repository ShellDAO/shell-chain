# API Reference

> Conceptual public API reference for the future `shell-chain` Rust workspace.

## Current Status

There is **no generated Rust API documentation yet** because the repository does not yet contain a buildable workspace.
This document captures the public surfaces the planned crates are expected to expose so contributors can keep names, responsibilities, and layering consistent while the implementation is still being designed.

## Stability Note

Everything below is a design contract for future work, not a promise that the exact item names already exist in code.
Where implementation specs are still evolving, the intended responsibility is stable even if concrete type names change.

## Planned Public Surface by Area

### 1. Primitives and Wire-Facing Types

The base layer is expected to expose:

- root and byte-wrapper aliases such as `Root`, `Bytes32`, and address-sized types,
- transaction fee wrappers such as `ChainId`, `TxValue`, `GasPrice`, and `BasicFeesPerGas`,
- canonical SSZ encode/decode helpers,
- `hash_tree_root`-style helpers shared across higher layers.

This layer should remain policy-free: it owns object shape and canonical encoding, not mempool or consensus decisions.

### 2. Transaction Objects

The transaction model is expected to revolve around:

- `TransactionPayload` as the payload union,
- payload variants such as basic transfer/call and contract-creation forms,
- `Authorization` entries that bind a signature to a payload root,
- `TransactionEnvelope` as the executable object,
- signing helpers similar to `SigningData` for domain-separated signing roots.

The key API requirement is that payload encoding, decoding, and root calculation follow one canonical path so mempool, execution, and consensus code cannot disagree about what was signed.

### 3. Cryptography Interfaces

The crypto layer is expected to provide:

- a scheme-aware verification trait, similar to `SignatureVerifier`,
- a dispatcher that routes transaction-path and validator-path verification,
- scheme-local size checks and uniform verification errors,
- hashing boundaries shared with the primitives layer.

Callers should depend on stable traits rather than on concrete post-quantum libraries.

### 4. State and Witness Interfaces

The state layer is expected to expose:

- key types such as `StateKey`,
- committed witness containers such as `StateWitness`,
- transition containers such as `StatePatch`,
- accumulator-style traits for proof retrieval, transition application, and state-root reporting.

A core design goal is to keep committed transport objects separate from any optimized in-memory proof index used during execution.

### 5. Validation and Execution Boundaries

Higher layers are expected to expose structured validation entry points for:

- cheap transaction admission,
- witness and proof verification,
- heavy execution and output-root calculation,
- block import orchestration,
- peer-handling consequences for malformed versus merely excessive traffic.

The public contract here is mostly about clean layering and error taxonomy rather than about one monolithic "validate everything" function.

### 6. Operator and Node Entry Points

The CLI-facing layer is expected to provide:

- configuration loading,
- node startup wiring,
- RPC server integration,
- operational commands once the runtime exists.

Those entry points are planned, not currently implemented.

## What Does Not Exist Yet

The repository does not yet provide:

- generated `cargo doc` output,
- a stable crate list in `Cargo.toml`,
- versioned Rust APIs,
- runnable node or CLI binaries.

When those pieces are added, this document should be updated to point to concrete local API docs instead of remaining purely conceptual.
