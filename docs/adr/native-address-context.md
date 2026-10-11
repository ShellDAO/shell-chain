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
