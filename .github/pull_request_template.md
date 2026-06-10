## Description

<!-- What does this PR do? Link to related Feature or Issue if applicable. -->

Closes #

## Type of Change

- [ ] `feat` — New feature
- [ ] `fix` — Bug fix
- [ ] `refactor` — Code restructuring (no behavior change)
- [ ] `docs` — Documentation only
- [ ] `test` — Adding or updating tests
- [ ] `chore` — Build, CI, or tooling changes

## Related Feature

<!-- Feature ID (if applicable) -->

Feature: `<feature-id>`

## Changes

<!-- Brief bullet-point summary of what changed -->

-

## Testing

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` has no warnings
- [ ] New code has test coverage

## Protocol Invariant Checklist

<!-- Changes touching consensus, mempool, RPC, core, or pqvm require review -->

**If this PR modifies consensus, mempool, RPC, core types, or pqvm:**

- [ ] **T-1 (PQ-Native)**: No `ecrecover` or classical crypto introduced
- [ ] **T-2 (AA-First)**: AaBundle handling is consistent; changes don't break atomicity
- [ ] **T-3 (PQVM)**: No 20-byte address surface leakage; revm adapter usage unchanged
- [ ] **T-6 (Wire Format)**: New RPC types use `#[serde(rename_all = "snake_case")]` (or preserved eth_* camelCase)
- [ ] **T-10 (No Magic)**: All constants extracted to named `const` (no bare literals in execution paths)
- [ ] **Atomicity (T-5)**: AA bundle failures revert atomically; gas consumed
- [ ] **Signature Domains (T-7)**: New signing contexts use distinct domain bytes; no domain reuse

**If changes affect storage, state, or constants:**

- [ ] StorageProfile semantics unchanged (archive/full/light behavior preserved)
- [ ] No new magic numbers in gas, block, or consensus parameters

## Security Checklist

<!-- For changes in shell-crypto or signature-related code -->

- [ ] No classical (non-PQ) cryptography introduced
- [ ] Secret key material uses `Zeroizing` wrapper
- [ ] Negative test cases included (invalid signatures, wrong keys)

## Notes

<!-- Any additional context, trade-offs, or future work -->
