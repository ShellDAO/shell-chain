# Transaction-wide AA access warmth

Status: accepted for unreleased node source

The whitepaper retains Cancun gas accounting for non-PQ operations. EIP-2929
accessed account/slot sets belong to one transaction, including all AA inner calls.
The adapter's synthetic revm transaction per inner call restarted those sets.
A repeated slot was charged 2100 gas instead of 100, and a valid capped read could
fail after a prior access in the same batch.

After optional `aa_access_warmth_height`, keep a local native-address map of warm
accounts and slots for the outer execution. Seed it with the outer access list,
whose intrinsic cost is already charged at the envelope boundary. A small handler
uses revm's journal prewarming after ordinary account loading, without putting a
synthetic list into each inner transaction or charging it repeatedly. Existing fee
modes use their original beneficiary handling; traced and untraced paths share
this loading hook.

Collect account and slot markers from each completed inner journal before
untouched accounts are filtered for commit. Check the inner transaction ID and
cold flags: revm restores them on frame revert, so reverted first accesses do not
become warm in later calls. Keep previously warm entries. Read-only foreign
account access counts without materializing missing accounts. Key the outer map
by complete native identity; legacy interpreter aliases receive only entries that
resolve to that identity in the current context. The map is dropped on every
outer return. Native system-call intercepts do not clear it.

Default to absent activation and allow only a future first schedule on existing
chains. Persist and validate it through genesis, restart and trusted snapshots.
Historical execution/import selects the original block's height. This schedules no
online activation. This change covers access sets; transaction-wide original-value
SSTORE metering and refund aggregation remain separate assertions, and batch gas
estimation keeps its documented limitations.

Validation uses the public binary's actual signed AA trace against literal opcode
costs from EIP-2929, then the same stopped database with a future local schedule.
Regressions cover default/boundary/after, fee modes, tracing, identity separation,
foreign read-only accounts, nested/outer rollback, capped reads, outer access lists
and duplicate intrinsic charges. Independent nodes, persisted receipts, historical
traces after state changes and physical database reopen qualify the serving path.
