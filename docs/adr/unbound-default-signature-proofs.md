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

The `mixed-first-use` entry exercises sixteen independent senders with eight
registered bound accounts and eight unregistered unbound accounts, plus a distinct
proposer. Genesis reconstruction and post-import checks use each actual sender's
mode rather than treating a whole block as bound or unbound. Both full graphs must
contain eight proofs of each sender version. The later wrong-root child uses
Reference mode for all sixteen senders and must preserve Native state on refusal.


## Genuine Dilithium3 unbound profile

Profiles 1/2 remain bound/unbound ML-DSA-65, and profile 3 remains bound genuine
PQClean Dilithium3. Profile 4 selects an unbound genuine PQClean sender, the
existing raw signature/challenge version 2 and mandatory tag-zero address AIR.
The actual transaction algorithm supplies the address preimage tag; matching
key widths do not authorize another transcript or profile. The producer captures
and restores the same exact parent account, key and MPT witness. The consumer
still checks all signature, source, account, leaf and transaction-ID predicates.
Native SDK compatibility is unchanged; SDK FIPS-adapter signatures under tag
zero are not raw proofs. Bound SDK senders use the separate profile 5 below;
unbound SDK senders select the distinct profile 6 below.

`tests/e2e/dilithium-full-proof.sh unbound output` requires complete peer Native
import/finality of the original Embedded first-use and subsequent Reference
blocks, independent registration/receipt/fee/account checks, and cold read-only
replay of both graphs after ordinary third-block execution. Genuine certificate,
missing-address-tag and wrong-profile substitutions must refuse without Native
writes or new mathematical certificates. Separate real-signature Native intake
and registration-rollback controls retain their own scope. No quota, schedule,
default or public activation changes; other account arrangements remain open.


## Bound Native SDK FIPS profile

Profile 5 binds a nonzero default-account key commitment and the exact historical
registered Native tag-zero key to transaction source envelope 3. That envelope
proves the tag-zero signing hash with complete FIPS signature/challenge version-1
AIR. Native raw-or-SDK verification remains unchanged. The producer selects the
strict FIPS transcript only after the raw transcript fails, freezes the explicit
selection in source format 3, and rejects relabelled or unknown selections on
restore. Old source formats 1/2 omit this field and keep their bytes and meaning;
proof batch versions still depend on whether a proposer proof is present.

The public `sdk` regression uses the exact published candidate's signer and
provider against local Node RPC, then complete peer proof admission/finality and
changed-state historical replay. Test-only storage signers are not evidence of
public SDK execution. This bound sender profile is separate from the primary-sender SDK proposer
entry and from the unbound SDK sender profile below.


## Unbound Native SDK FIPS profile

Profile 6 combines the existing complete tag-zero derived-address AIR with SDK
transaction envelope 3 and complete FIPS signature/challenge version 1. It
requires a zero-commitment default account and the independently captured
historical key: Embedded at first use, Reference only after registration.
Frozen source format 4 explicitly selects unbound SDK inputs; source format 3
stays bound SDK only. Old source/proof versions retain their bytes and meaning.
The Native raw-or-SDK verifier, activation checks and atomic registration policy
remain unchanged. A typed signature entry exists only after all mathematical,
account, address, transaction-ID and leaf predicates succeed.

The `sdk-unbound` public entry uses the documented first-use public-key option,
real published SDK signing/provider/RPC, two full peer Native graphs and changed-
state dual-history replay. Genuine-certificate and profile/address substitutions
must refuse without writing current KV or replacing mathematical inputs. Other SDK proposer/sender combinations and excluded account arrangements
remain separate.
