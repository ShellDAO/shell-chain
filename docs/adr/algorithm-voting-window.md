# Bound algorithm voting with a persisted block deadline

Status: accepted for optional client support; live activation requires coordination.

## Context

The white paper requires algorithm approval votes within seven days, measured in
blocks at the prevailing interval. Staging keeps live policy intact until quorum,
but previously retained candidates could collect votes indefinitely. Changing
existing staging semantics would invalidate historical execution and state roots.

## Decision

Add the separate, default-off `algorithm_voting_window_activation_height` schedule.
Require proposal staging no later than this activation. Persist the effective
genesis consensus interval alongside the height in trusted chain configuration;
local CLI scheduling time cannot change consensus deadlines. Both values are
immutable, and introducing the schedule on an existing chain requires a future
height. Genesis initialization, restart and snapshot import validate the same
prerequisites before writing state.

For a new staged proposal first voted in block N, store the exclusive deadline
N + floor(604800 / nominal interval). The floor selects whole blocks without
exceeding seven nominal days. Reject zero or greater-than-seven-day intervals and
checked-add overflow. Votes at or after the deadline fail before recording votes
or changing candidate/live registry state. Before quorum, retain live policy;
on quorum, publish through the existing helper, mark approval, and clear the
candidate and deadline. The existing per-vote timelock remains independently
selected. Execution uses block context, never wall time or the current RPC tip.

Pre-window staged candidates have no deadline and remain grandfathered, as do
legacy pending proposals. Avoid writing new zero-valued deadline keys for those
paths so their state roots remain unchanged. The canonical deadline is shared by
production, import, restart and isolated historical replay. Snapshots must match
the trusted schedule and interval.

## Limits

The deadline measures nominal block time, not actual elapsed wall time. No default
network configuration or live activation height changes. A rollout must account
for old unbounded candidates. Expired candidates and votes remain in state: reset,
retry, complete proposal identity, verifier matching, emergency policy and the
approved-pending signature policy require separate changes. This closes the voting
expiry gap only for newly staged candidates after explicit activation.
