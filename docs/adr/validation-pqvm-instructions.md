# PQVM instruction parity for account and paymaster validation

## Context

Normal execution installs PQVERIFY, PQHASH and PQADDR and removes CALLCODE and
SELFDESTRUCT. Custom-account and contract-paymaster validation instead built
unmodified Ethereum instruction tables. A PQHASH policy that works as an ordinary
contract therefore halts during authorization; legacy instructions can also
behave differently across these entry points.

## Decision

Use one shared instruction installer for ordinary transactions, AA inner calls
and both validation interpreters. Introduce an independent, default-off
`validation_pqvm_height` because changing accepted validation programs affects
block validity. At and after that candidate height, validation installs the same
PQ instructions and rejects the same removed legacy operations. Preserve previous
validation tables before activation and when the schedule is absent.

Persist the immutable activation in genesis and chain configuration, permit only
future additions to existing chains, and validate trusted snapshot schedules
before writing imported state. Admission uses the next candidate block; execution,
canonical/fork import and historical replay use their explicit header.

## Scope

Preserve gas budgets, algorithm lifecycle checks, validation return conventions,
read-only paymaster execution and discarded custom-validation writes. This does
not enable deprecated cryptographic algorithms, alter transaction formats or
activate any network. Acceptance covers computed hash/address policy results and
removed legacy calls; cryptographic validation capacity under existing gas caps
is a separate assertion.
