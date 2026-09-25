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

Other native methods can read address metadata outside the state trie, and
recovery methods also use the chain-head height. Their undo journals are pruned
at finality. Refuse those native transactions and prefixes until their historical
metadata and chain context are reconstructed or execution traces are retained.
Keep the state-only selector list conservative when native implementations change.

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
