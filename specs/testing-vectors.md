# Testing Vectors

> Reference test vectors and invariants for shell-chain validation.

## Status: STUB

## Purpose

Define canonical test vectors, invariant assertions, and example transactions/states that implementations must pass.

## Local Testing Assumptions

Until full canonical vectors are checked in, this repository should treat the following as the minimum local test surface:

- `TransactionPayload` union encoding is append-only for known variants, with tag `0` for `BasicTransactionPayload` and tag `1` for `CreateTransactionPayload`.
- `payload_root`, `tx_root`, `transactions_root`, and `execution_witnesses_root` are binding commitments and must fail closed on mismatch.
- User-path authorization signatures above 8 KB are rejected by default as a local stress-control rule.
- Witness-sidecar ordering checks use the canonical `StateKey` comparator before proof reconstruction.
- Block witness bytes and validator-path signature size guards are configurable transport limits, not frozen consensus constants.
- Witness compression, canonical witness encoding, and richer multi-authorization semantics remain open and should be tested as provisional behavior rather than permanent guarantees.

## Validation Responsibility Map

Before implementing concrete test vectors, crates must establish isolated testing guarantees:
- **`shell-primitives`**: Manages underlying SSZ serialization/deserialization integrity and boundary rules for Transaction/Block/Witness structures.
- **`shell-crypto`**: Manages hashing profiles and boundary vectors for selected Signature Schemes.
- **`shell-state`**: Manages the Unified Binary Tree via stateless `StatePatch` transitions and state invariance assertions.
- **`shell-consensus`**: Manages verification mapping bindings between Block Headers and Sidecars (executing Rules 2 & 3).

## Sections (TODO)

- [ ] Transaction serialization / deserialization vectors for both currently known payload variants
- [ ] Payload-root and signing-root binding vectors, including mismatched authorization roots
- [ ] Signature verification vectors for supported schemes and oversize-artifact rejection
- [ ] Block validation vectors covering `transactions_root`, `sidecar.block_root`, and `execution_witnesses_root`
- [ ] State witness ordering and proof-reconstruction invariants
- [ ] Edge-case and failure-mode vectors for provisional limits and pending-closure areas
