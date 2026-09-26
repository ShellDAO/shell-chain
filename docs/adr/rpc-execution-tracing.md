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

AccountManager `rotateKey` and `clearValidationCode` read only state-trie data
and can be replayed from the parent root, including as earlier transactions in
the same block. Rotation's address-keyed public-key write stays in the private
overlay; it never reads or replaces the live public key. Native calls return the
executor's actual output, gas and success/error status without opcode logs.

AccountManager guardian configuration, recovery and validation-code changes
also replay address metadata outside the trie. Freeze public keys, guardian
configurations, recovery proposals, the head pointer and undo journals in one
MemoryDb read lock or RocksDB snapshot. Missing keys in these namespaces remain
missing even if canonical import concurrently creates them. Rewind canonical
journals from that captured head through the target block and set the private
head to its parent, matching the height observed during native execution.
Reject a target outside that ancestry. Frozen overlays cannot be committed.

Retain the latest 128 finalized blocks' journals, as well as all unfinalized
journals needed for reorganization. Native metadata replay is limited to the
latest 128 blocks relative to the captured head and a 64 MiB snapshot budget
including encoded entries and an allocation allowance. Large metadata sets can
exceed this budget even for recent blocks. Missing/pruned journals or trie data,
unsupported snapshot backends and exceeded limits return explicit errors.
Upgrading does not recreate previously pruned journals. State-only selectors do
not require metadata history; keep this exemption conservative as methods change.
ValidatorRegistry native transactions and prefixes still require separately
validated historical context and remain unavailable.

The OpenEthereum-shaped `trace_` methods use this same replay path and flatten
observed call/creation frames on the blocking worker. Each entry preserves its
transaction identity and child-index path. Failed actions omit successful
results; creations expose init code, deployed code and address. AA bundles use
an explicit `callType: "batch"` root extension. Serialized flattened responses
are bounded both per transaction and across the whole block.

PQVM removes SELFDESTRUCT and CALLCODE under the white-paper opcode rules;
there are no successful SELFDESTRUCT balance-transfer events to capture. This
does not claim full Geth tracer compatibility, retained pruned history, or a
transaction validation replay.
