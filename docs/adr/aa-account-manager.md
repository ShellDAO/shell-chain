# Native AccountManager calls in AA bundles

## Problem

An AccountManager operation submitted directly reaches the native dispatcher.
The same calldata in an AA inner call previously entered the ordinary PQVM
path instead. For example, a signed batch containing `setGuardians` failed,
while the identical direct call configured the guardians successfully.

## Decision

The independent, optional `aa_account_manager_height` enables native
AccountManager dispatch for AA inner calls at and after the configured block.
Before that height, and when the field is omitted, existing execution remains
unchanged. Persisted schedules are immutable; an existing database may add only
a future activation. Trusted snapshot import checks the schedule before writes.

Execution uses the authenticated outer account as the native caller. The native
method sees the candidate block height and the same parent-chain context as a
direct operation. A native call rejects nonzero value, observes its inner gas
limit and the remaining outer budget, and contributes its actual native gas to
the ordinary AA settlement. The outer transaction advances its nonce once.

A batch containing an enabled native call executes against an isolated overlay
of the account and chain metadata store. Successful batches commit the overlay.
A failed batch discards it and publishes only the ordinary outer fee and nonce
settlement. This includes failures in later PQVM calls, native calls and final
payer-balance checks. Guardian configuration, recovery proposals and registered
public keys cannot survive a failed batch. The account and metadata handles
must share the same backing store, as they do in node execution and RPC replay.

Historical tracing restores native metadata for these batches before executing
the recorded prefix. Native calls contribute actual call frames and gas without
synthetic opcode logs. Existing history-retention and capture limits apply.

## Scope and validation

This change covers the native AccountManager methods in AA `inner_calls`.
ValidatorRegistry dispatch inside AA is covered by the independent
[registry decision](aa-validator-registry.md). Native calls initiated by contract
bytecode remain separate follow-up work. Custom validator policy and signature
validation are unchanged. Key rotation keeps its independent algorithm-binding
schedule. Activation must be coordinated by network operators.

Regression commands:

```bash
cargo test -p shell-pqvm aa_account_manager
cargo test -p shell-storage aa_account_manager
cargo test -p shell-cli protocol_activation_scheduling_is_independent_atomic_and_persistent
```

The regressions cover activation boundaries, native gas/value rejection, key
and guardian rollback, proposal/cancellation rollback, fee sponsorship,
future-only startup scheduling and trusted snapshot mismatch rejection.
