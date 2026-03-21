# Validation Rules

> Implementation specification for block and transaction validation in shell-chain.

## Status: DRAFT (protocol mapping complete; pipeline details TODO)

## Purpose

Define the validation logic implementation: ordering of checks, error types, and the relationship between protocol-level rules and Rust code.

## 1. Error Type Taxonomy

- `SidecarMismatchError(ExpectedRoot, ActualRoot)`: Sidecar commitment validation failed.
- `WitnessSizeExceededError(MaxSize, ActualSize)`: Witness artifact volume exceeded network constraints (enforces TCP-001 8KB hard limit).

## 2. Protocol Rule Mapping

*   **Rule 1: Header Stateless Check**
    *   **Responsibility Scope**: Upstream block ingestion pre-check (extracting Header to verify `witness_bytes`).
    *   **Assigned Crate**: `shell-consensus` or `shell-network` (exact boundary subject to subsystem packet flow mapping)
*   **Rule 2: Header/Body Binding Check**
    *   **Assigned Crate**: `shell-consensus`
*   **Rule 3: Sidecar Matching Check**
    *   **Assigned Crate**: `shell-consensus`
*   **Rule 4: Stateless Execution Check**
    *   **Assigned Crate**: `shell-execution`

## Sections (TODO)

- [ ] Transaction validation pipeline
- [ ] Block validation pipeline
- [ ] Signature verification dispatch
- [ ] Validation ordering constraints
