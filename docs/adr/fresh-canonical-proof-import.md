# Complete sender proofs for an offline canonical extension

Status: accepted for unreleased node source.

## Context

The retained-history verifier deliberately requires the child body to exist in
its independently captured canonical view. Reusing that constructor for a fresh
candidate would require trusting or publishing the candidate before verification.
Normal block import also repeats sender cryptography during sequential policy
validation, so replacing only its first signature batch would leave an incomplete
proof-consumption path.

## Decision

Keep the strict historical constructor and add a separate candidate constructor
anchored to the captured current canonical parent. Verify the candidate's native
activated body commitment and every ordered registered sender predicate without
inserting the child into the parent view. Return the same immutable exact-tuple
verifier only after the entire graph succeeds.

Consume that verifier in both batch and sequential checks of the existing native
importer. Preserve proposer authentication, transaction policy, execution, fees,
receipt/root checks and its atomic canonical commit. Constrain the new entry to
the next extension and the existing bounded default-account profile. Load the
parent's algorithm registry into a thread-local override, including activation
updates, so offline import does not depend on or rewrite another process-global
registry snapshot.

Expose an explicit offline CLI command rather than introducing concurrent RPC
imports or enlarging peer messages. Require an existing exclusively opened native
database, an independently selected parent and local consensus configuration,
and bounded block/manifest/proof files. Stored chain identity remains the trust
anchor. Verification status and provider assertions never construct an import
authorization. This does not change normal network admission or activation.

## Validation

`tests/e2e/mldsa-fresh-proof.sh` drives the actual CLI with independently produced
signed blocks and complete proofs. It checks refusal without native writes,
injects a failed canonical batch after full verification and execution, imports
the genuine extension, and cold-rechecks persisted body, receipts and accounts
against native execution. Unit coverage guards the activated candidate boundary,
explicit parent/gap refusal and input-size limits. Native proposer verification
remains separate from the complete sender graph; automatic producer and peer
consumption, forks and public release remain open acceptance work.
