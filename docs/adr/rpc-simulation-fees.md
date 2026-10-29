# Explicit fees in RPC simulation

Status: accepted for unreleased RPC source.

## Problem

The call request discarded legacy and dynamic fee fields, and every simulation
used zero caps. A contract reading GASPRICE therefore returned zero even for an
explicit nonzero price. Writing that value to an initially zero storage slot
also made estimation cheaper than the actual signed nonzero write, returning an
insufficient gas limit. Access-list discovery could choose the wrong branch.

## Decision

Deserialize optional gasPrice, maxFeePerGas and maxPriorityFeePerGas in the
shared call request and carry them into the existing transaction execution
adapter on private state. A legacy price supplies both caps. Dynamic priority
defaults to zero; a priority-only request derives its maximum from the captured
header's base fee plus priority, using checked u64 arithmetic. Reject mixed
legacy/dynamic fields, invalid quantities and priority above maximum.

For gas estimation, cap probes by available balance after reserving value,
divided by the explicit nonzero maximum fee. Read that balance from the captured
root, preserving the same snapshot across all probes. A caller can afford the
actual transaction even when it cannot reserve a full block's gas. Do not add
artificial balance to make such a probe pass.

Keep zero caps when all fee fields are omitted. Preserve existing execution
profiles, fee accounting, nonce handling and block-header selection. Supplied
fees use the existing execution balance checks; no artificial balance top-up,
fixed GASPRICE opcode override, protocol activation or new fee policy is needed.

## Verification

Use independent header fees and genuine signed receipts as the price oracle.
The shared regression is native-aa-registry.mjs --fee-context, with
--fee-context-legacy-address for the default address context. It checks actual
estimated-limit execution, price-dependent storage and access lists, value,
reverts, malformed/conflicting fields, zero defaults, independent node import,
changed-state historical reads and physical reopening. Original failed
transactions remain retained without replay. Public v0.27.13 remains affected
until matching source is normally delivered.
