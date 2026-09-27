# Separate native Registry reads from PQ precompiles

## Problem

The contract example called low address 1 as a Registry, but contract execution
reserves that address for ML-DSA verification. The compiled example returned an
empty validator array and false for a real validator, while direct and native AA
reads returned the actual set. A real ML-DSA payload sent to the same contract
call target returned true. The code also used 20-byte Solidity address values
for native 32-byte members; changing dispatch alone cannot preserve identity.

## Decision

Introduce a read-only NativeRegistryView at `2^32 + 1`, outside the whitepaper's
reserved precompile interval `[0, 2^32)`. Keep direct/AA native addresses and all
six existing PQ precompiles unchanged. Never guess routing from input selectors,
lengths or signature-verification results. A new opcode is unnecessary for this
bounded read capability and would require additional compiler/tooling changes.

The independent `native_registry_view_height` defaults to absent. Before the
height, the new address retains ordinary execution semantics. At and after it,
it is reserved for the view. Adding an existing-chain schedule requires a future
height; persisted schedules are immutable and trusted imports reject mismatches.
Network operators coordinate activation and the address reservation separately.

The ABI is `getValidators() -> bytes32[]` and `isValidator(bytes32) -> bool`.
Use the exact full identifier; do not convert a 20-byte caller into a purported
native identifier. CALL and STATICCALL with zero value are supported. Native
write selectors, malformed lengths, delegate calls and nonzero value revert.
The existing native read base gas applies, including an out-of-gas boundary.

A provider captures the bounded validator set from its world-state root before
one PQVM execution. No view method changes it during that execution. Rebuilding
the provider for every AA inner execution observes preceding native changes.
Ordinary execution, account validation and paymaster validation share the same
provider and gate; block import and historical replay use their respective
world-state roots. The storage bound of 1,000 validators also bounds snapshot
work. Enabling the view adds that bounded snapshot read to each PQVM execution.

## Scope and validation

This restores contract reads; it does not implement contract-originated native
writes, full-width PQ addresses throughout the interpreter, new governance
policy or a production activation. The canonical example uses explicit bytes32
arguments, preserving the whole validator identifier at the Solidity boundary.

Focused checks:

```sh
cargo test -p shell-pqvm native_registry_view_
cargo test -p shell-storage native_registry_view_
cargo test -p shell-cli protocol_activation_scheduling_is_independent_atomic_and_persistent
```

The [signed acceptance command](../SYSTEM_CONTRACTS.md#reproduce-the-contract-view)
compiles the exact included example. It checks independent producer/follower
state, receipts, finality and restart, as well as old crypto compatibility and
historical nonmutation. It uses a single authority and source SDK; it does not
establish multiple-authority quorum, package publication or live activation.
