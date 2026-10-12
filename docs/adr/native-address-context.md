# Native address context compatibility profile

Status: development; deployment gated on completion of creation semantics and release checks

## Problem

The full-width PQABI requires 32-byte identities. Truncating a foreign address
before the execution adapter can resolve it aliases different contracts and
loses the high bytes of CALLER, ADDRESS, ORIGIN and COINBASE.

## Decision

Persist an optional immutable native_address_context_height in chain and genesis
configuration. Absence preserves historical execution. Reject retroactive or
conflicting startup schedules before changing stored state.

At activation, maintain a transaction-local bidirectional mapping from full Shell
addresses to adapter handles. Preserve canonical zero-extended addresses and
reserved precompile handles. For other addresses, allocate collision-checked
BLAKE3 handles using the shell-pqvm-address-handle-v1 domain and a retry counter.
Share this context across nested calls, state loading, commits and tracing.
Resolve address-bearing stack operands before execution and expose full words
for identity opcodes. Ordinary and AA receipt log emitters resolve the same
mapping independently of the older log-address activation schedule; bloom
format activation remains separate. Commit only touched journal accounts at
native activation so read-only probes do not create missing accounts.

## Limits and acceptance

This opt-in profile is unreleased and must not be enabled on deployed networks.
Native CREATE/CREATE2 and creation transactions currently reject until the full
address derivation and frame mapping are specified and implemented. This does
not define a new creation-address scheme or remove the protocol requirement.

Acceptance uses distinct full addresses with equal low 20 bytes, original SDK
compiled call fixtures, authentic transaction signatures, independent block
import, committed-root reopening and historical replay across activation.
Existing legacy execution and log/bloom schedules remain covered before the
native activation boundary. Source acceptance does not establish a published
compiler package, node binary, or deployed activation.

## Stateful overload source regression

The compiler must preserve the original selectors of `set(address)` and
`set(uint256)` when address values become full ABI/storage words. The fixture
`crates/pqvm/tests/fixtures/native-stateful-overloads.json` includes the original
Solidity source, compiler version, SDK source commit and both compiler targets.
Its address branch stores the complete argument; its integer branch stores the
argument plus one. Zero-address refusal, truncated input and integer overflow
must preserve the contract's owner, amount and write counter.

Run the isolated signed-transaction and disk-recovery regression with the
repository Rust toolchain and RocksDB build prerequisites:

```bash
cargo test -p shell-node --features rocksdb --lib native_overload_ -- --nocapture
```

The regressions create temporary accounts and node databases, sign ordinary
transactions and root-signed AA batches with Dilithium3 and ML-DSA-65, import
their blocks independently and verify
historical RPC results, replay, receipts, fees and state after abrupt writer
exit. It retains failed databases for diagnosis and removes successful test
databases. AA cases execute both overloaded setters in both orders, then test
later zero-address refusal, integer overflow and truncated input after successful
inner writes. Every earlier write and counter update rolls back on batch failure;
the included outer transaction still consumes one nonce and pays its billed fee.
Corrupt signatures, changed signed inner arguments and funded wrong senders
must be refused without changing persisted state. Call traces retain each inner
result, including exact overflow panic data.

These address-value operations use no native identity or creation opcodes;
the regressions leave the context profile unconfigured. Published packages,
live network synchronization and native CREATE/CREATE2 require their own
acceptance.
