# Outer transaction lifetime for AA transient storage

Status: accepted for unreleased node source

## Problem

The whitepaper retains Cancun transient storage, while a native AA batch is one
signed transaction. The adapter creates a revm transaction for each inner call.
Revm ends each such transaction by clearing transient storage. A successful
set-then-read batch therefore persists zero instead of the value set earlier.

## Decision

After `aa_transient_storage_height`, move one transient map between the revm
contexts of an outer batch. Seed each context before execution. A small handler
captures the map just before revm's normal transaction-finalization hook clears
it, then delegates output and cleanup to the standard handler. Nested calls
continue using revm's own transient journal and frame checkpoints. Existing fee
modes retain their beneficiary handling. Traced and untraced execution use the
same boundary hook.

The map is a local variable of the AA execution. It is dropped on every success,
revert or error path; native system-contract intercepts can run between ordinary
inner calls without ending its lifetime. It never enters persistent state or a
shared VM field. Key the outer map by complete native identities. In the legacy
address profile, distinct direct AA targets can share an interpreter key; seed
only entries resolving to the same identity in the current inner context and
retain the others for later calls. Capture results through that inner context's
address registry. Full-native execution additionally supplies stable handles.
This preserves native identities, zero-value deletion and delegate ownership.

## Compatibility

This changes consensus-visible execution results. Default the schedule to absent,
preserve all prior blocks, and allow only a future first activation on an existing
chain. Persist the schedule in genesis-derived chain configuration and reject
restart or trusted snapshot substitution, omission and rescheduling. Batch execution, block import and historical replay use their selected block
height. Batch gas estimation remains subject to its documented independent-call
and explicit-cap limitations.
No deployed-network activation is scheduled by this change.

## Validation

Use a literal TSTORE/TLOAD runtime and an independent nested-CALL control on the
public binary, then check the actual persistent word, nonce and fee rather than
only a success receipt. Storage/startup regressions cover schedule ownership.
Focused VM regressions cover default/before/boundary/after execution, both fee
modes, traced execution, distinct native identities, delegate ownership, nested
reverts, static writes and clearing after failed or successful outer transactions.
The portable native entry adds genuine signatures, independent import, native
policy rollback, historical replay and physical RocksDB reopen.
