# Read-only execution tracing

Status: accepted

## Problem

The debug RPC previously constructed a top-level call frame from a stored
transaction and receipt. Receipts do not contain return bytes, internal calls,
opcode gas, or storage accesses, so this could not satisfy the contract guide.

## Decision

Replay ordinary transactions and AA bundles using the existing PQVM executor
against the containing block's parent state. Replay earlier transactions in the
same block before tracing the selected transaction. Capture revm inspector
callbacks only for selected transactions; normal block execution retains its
existing execution path. Use the same fee handler and instruction/precompile
tables for inspected execution.

All replay trie, code, and metadata writes use a private OverlayStore that is
never committed. Scope the algorithm registry to the replay worker thread.
Compare every replayed receipt with the stored receipt before returning results.
Run replay on blocking workers with two concurrent permits. Bound capture to
50,000 instructions and 8 MiB per transaction and serialized block results to
16 MiB; fail explicitly when a bound or required historical state is unavailable.

Keep the existing call-frame response shape, adding nested frames, actual output
and revert data, and `structLogs`. Payload omission flags affect opcode payloads,
not the presence of child calls. Storage observations are attempted SLOAD/SSTORE
operations; a failed transaction or frame does not imply those writes committed.

## Limits and follow-up

Native system contracts also read address metadata outside the state trie.
Their undo journals are pruned at finality, so parent trie state alone is not
sufficient for faithful replay. Refuse native transactions and prefixes requiring
them until historical metadata is reconstructed or execution traces are retained.
This keeps that capability gap explicit while delivering real contract tracing.

The separate OpenEthereum-shaped `trace_` methods still need to migrate from
receipt summaries to the replay result. This change does not claim full Geth
tracer compatibility, retained pruned history, or a transaction validation replay.
