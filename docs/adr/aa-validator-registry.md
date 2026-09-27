# Native ValidatorRegistry calls in AA bundles

## Problem

Direct transactions reach the native ValidatorRegistry dispatcher, but AA inner
calls previously entered ordinary execution. A signed `getValidators()` batch
could report success while returning a zero word instead of the validator array.
The registry also changes runtime algorithm policy, so account rollback alone
cannot provide atomic batch semantics.

## Decision

Use an independent optional `aa_validator_registry_height`. Omitted and
preactivation configurations preserve legacy behavior, including read output.
Existing databases can add only a future height; stored schedules cannot be
changed or removed, and trusted snapshot import rejects mismatches before writes.
AccountManager activation does not implicitly enable Registry dispatch.

An enabled Registry inner call uses the native dispatcher with the authenticated
outer sender, candidate height and parent-chain context. Existing authorization,
governance and algorithm schedules remain authoritative. Native methods reject
value and consume both their inner gas budget and remaining outer allowance.
Successful validator changes contribute the ordinary consensus-update effects.

Reuse the native AA overlay for account and metadata writes. Additionally run
Registry-containing batches in a nested thread-local algorithm registry. Publish
that registry only after successful batch settlement and overlay commit. Failure
leaves the prior runtime policy intact and retains only ordinary outer fees and
nonce settlement. A caller without an existing registry override holds the
canonical registry mutation lock; callers inside block execution or historical
replay update only their outer branch. This prevents provisional or historical
algorithm policy from leaking into canonical signature validation.

Historical tracing recognizes enabled Registry inner calls when preparing native
metadata, including earlier transactions in the replay prefix. Its account,
metadata and algorithm branches are never committed to live state. Existing
history-retention limits apply.

## Scope and validation

This covers AA inner calls to Registry, including mixed batches with enabled
AccountManager calls. It does not add native dispatch to calls from contract
bytecode, change consensus algorithm-deprecation policy, or activate a network.

```sh
cargo test -p shell-pqvm aa_validator_registry_
cargo test -p shell-storage aa_validator_registry_
cargo test -p shell-cli protocol_activation_scheduling_is_independent_atomic_and_persistent
cargo build -p shell-cli --features libp2p
SHELL_SDK_ENTRY=/path/to/shell-sdk/dist/index.js node tests/e2e/native-aa-registry.mjs
```

The signed runtime command uses a single validator and an independent follower.
Its assertions cover native output at activation, authorization, mutation and
policy rollback, historical isolation, block/state/receipt/finality agreement
and restart catch-up. Multiple-authority quorum is outside this fixture.
