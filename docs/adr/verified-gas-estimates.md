# Verify gas estimates against execution

Status: accepted for unreleased RPC source.

## Problem

A contract can branch on remaining gas. Measuring gas consumed by one successful
execution and adding 20% can produce a limit at which the same call reverts.
Storage refunds also cannot supply gas before execution completes. Returning an
unchecked recommendation prevents readers from using the estimate to submit a
successful transaction.

## Decision

Capture the current state root and block header once. Execute every probe on a
fresh private overlay of that snapshot. First establish a passing upper bound
from the caller's optional gas cap, current block limit and 50 million RPC cap.
If execution fails at that upper bound, preserve its execution error.

Keep the usual 20% gross-consumption recommendation when it passes execution.
Otherwise use at most 16 binary refinements to retain a passing bound. Verify
any additional buffer too: gas-dependent execution is not necessarily monotonic.
Never return a new limit merely because it is larger than a passing limit.

Bound cumulative simulated work at 50 million gas. Successful probes consume
measured gross gas; failed probes conservatively consume their full cap. A probe
is started only when its cap fits the remaining work budget. On exhaustion keep
an already passing bound. The estimator prioritizes a usable result and bounded
RPC work over finding the minimum or exploring every possible passing window.

## Consequences

This changes the RPC recommendation without changing transaction execution,
consensus rules, receipt refunds or activation heights. Normal transfer results
remain 25,200 gas. Explicit insufficient caps remain execution errors. A result
is sufficient in the captured simulation context; later state, signature costs
and transaction admission rules still require separate consideration.

The signed regression is `tests/e2e/native-aa-registry.mjs --gas-estimate`, with
`--gas-estimate-legacy-address` for the default address-context profile. It checks
GAS guards, nonmonotonic guards, refunds, value, reverted writes, follower import,
fees, and historical results after state changes and reopening. Unit coverage
also asserts canonical store isolation and ordinary-transfer compatibility.
