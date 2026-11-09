# Unbound default-account signature proofs

## Context

Funding a derived address does not register its public key. Normal Native
execution accepts an Embedded first-use key and registers it on successful
canonical commit. The account may retain a zero key commitment; later Reference
transactions resolve the registered key. Requiring a bound parent key commitment
throughout the proof path excluded these ordinary transactions.

## Decision

Retain sender proof version 1 for bound registered accounts, including rotated
addresses. Add sender proof version 2 for funded zero-commitment default accounts.
Its mandatory `tagged_key` certificate proves the existing BLAKE3 AIR statement
over `algo_id || pubkey`, with the full sender address as the expected output.
The same source/key/signature, transaction-ID, leaf and account-MPT AIR remain
mandatory. The existing serialized proof structure and outer batch versions stay
unchanged; old version-1 bytes retain their meaning.

The consumer selects keys only from its independently captured historical
registry or, when absent, the exact Embedded key. Reference mode cannot borrow a
later registration. Custom validators and nonzero commitments cannot use the
unbound profile. A private batch tuple exists only after all predicates pass and
matches exact key/message/signature/transaction inputs without native crypto
fallback. Native policy still decides activation, nonce, funds, fees and atomic
registration during execution.

The producer captures the trusted parent key/account/MPT, persists the existing
mathematical components and rechecks them on recovery. It does not use the live
registry to replace frozen proving inputs. This does not prove the separate
registry KV index in AIR or remove historical-context availability requirements.
There is no new proof primitive, checkpoint layout, quota, transport message,
consensus schedule or network activation.

New unbound jobs select the existing compact checkpoint format even for one or
two transactions. Its bounded per-coordinate sampler/sponge proofs avoid the
legacy standalone matrix's storage expansion. Existing jobs retain their original
index and immutable certificates; selecting compact storage does not migrate or
repair an already exhausted legacy job. Final payload bounds and full mathematical
verification remain mandatory.

## Verification

The `first-use` standalone full-proof entry uses fresh memory-only keys, actual
Native first-use execution, Embedded and Reference bodies, peer proof admission,
signed wrong-root rollback, genuine-certificate refusal and changed-state cold
replay. A separate Native crypto control checks fresh-registration rollback;
it is explicitly separate from proof admission. Existing registered proof graphs
must still verify without regeneration. Publication and coordinated activation
remain separate delivery steps.
