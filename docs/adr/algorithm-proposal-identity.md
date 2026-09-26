# Explicit algorithm proposal identity

Status: accepted; opt-in protocol rule.

The legacy activation call combines proposal creation and voting. Its vote keys
identify only the operation, algorithm, validator and validator set. An expired
round therefore cannot safely reuse those keys for a new candidate, and the
call does not identify the full candidate or its proposer.

Add an independent `algorithm_proposal_identity_height`, requiring the existing
window and staging upgrades no later than activation. Keep historical execution
unchanged. New submission and vote selectors separate candidate registration
from explicit assent. Retain the old selector only for pre-upgrade rounds.

Use the bounded installed descriptors and canonical packed hash preimage in
[SYSTEM_CONTRACTS.md](../SYSTEM_CONTRACTS.md#explicit-algorithm-proposal-identity).
The whitepaper specifies the hash fields but does not specify their byte
encoding. Fixed-width fields, an explicit requested Active status and the
registered proposer key make this encoding unambiguous. Candidate metadata and
approval remain queryable under the ID. Unknown installed descriptors are
rejected rather than accepting costs or sizes the client cannot execute.

Persist each proposal's deadline as its permanent existence marker. Duplicate
IDs stay rejected after expiry or replacement. Store votes under ID and voter;
count only current validators, using wide weight sums. Submission is not a
vote. Approval freezes on quorum, while unapproved candidates never change live
policy. At expiry allow a fresh identity to replace the candidate; keep old
records and votes for replay rejection. The timelock remains checked per vote.

The genesis/startup/snapshot paths validate and preserve the immutable schedule.
No live activation is implied by this implementation. Verifier-bytecode hash
matching, emergency dual-key voting and new primitive installation remain
separate work; this decision does not declare the whole governance chapter
implemented.
