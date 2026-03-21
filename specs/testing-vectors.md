# Testing Vectors

> Reference test vectors and invariants for shell-chain validation.

## Status: STUB

## Purpose

Define canonical test vectors, invariant assertions, and example transactions/states that implementations must pass.

## Research Source

- `research/docs/target-chain/testing-invariants-vectors.md`

## Validation Responsibility Map

Before implementing concrete test vectors, crates must establish isolated testing guarantees:
- **`shell-primitives`**: Manages underlying SSZ serialization/deserialization integrity and boundary rules for Transaction/Block/Witness structures.
- **`shell-crypto`**: Manages hashing profiles and boundary vectors for selected Signature Schemes.
- **`shell-state`**: Manages the Unified Binary Tree via stateless `StatePatch` transitions and state invariance assertions.
- **`shell-consensus`**: Manages verification mapping bindings between Block Headers and Sidecars (executing Rules 2 & 3).

## Sections (TODO)

- [ ] Transaction serialization/deserialization vectors
- [ ] Signature verification vectors
- [ ] Block validation vectors
- [ ] State transition invariants
- [ ] Edge case and failure mode vectors
