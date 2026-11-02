# Certified offline enforcement

Status: protocol rule accepted; implementation in progress. This document does
not activate a running network.

A weighted validator can legitimately have hundreds of global heights between
assigned proposals. The prototype block-gap helper and its 1% offline fraction
cannot implement the promised 100-opportunity suspension rule. Legacy view-change
signatures also omit the parent and membership epoch needed by replayable
assigned-miss evidence.

Count only 100 consecutive assigned proposal misses certified by weighted quorum.
A valid proposal resets its own counter; joining starts a new counter. The
threshold schedules suspension at the next common epoch. Once triggered,
suspension requires authenticated governance recovery at an epoch boundary;
proposal activity alone cannot cancel it. Preserve account balances, stake
principal and base weights. Idle time and another validator's slot do not count.

The bound timeout signing payload is:

```
SHELL_TIMEOUT_V1 (16 bytes)
chain_id (8 BE) || block_number (8 BE) || view (8 BE)
parent_hash (32) || epoch (8 BE) || ordered_authority_set_hash (32)
assigned_proposer (32) || admitted_opportunity_hash (32) || voter (32)
```

All address words are native 32-byte identities. The 208-byte payload uses a
separate domain from `SHELL_VIEWCHG_V1`. The authority commitment preserves
canonical ordering and effective weights, because both affect proposer selection.
A certificate requires distinct active voters, matching key-derived identities,
valid allowed signatures and the existing ceiling-of-two-thirds weighted quorum.
The executing caller supplies the independently admitted canonical context;
matching an arbitrary caller-supplied opportunity hash does not grant admission.

Proofs use the zero-value `timeoutEvidence` system envelope. Its canonical JSON
payload sorts signer records by complete address words. Envelope validation
checks the executing index and all metadata, not only signatures. The transaction
hash commits the payload; the native offline-state transcript commits each
accepted payload into the account-trie state root. No header `extra_data` carrier
or economic reward is used.

Full and summary transaction views, single and block receipt queries, and the
receipt embedded in a transaction summary identify evidence consistently as
`type: "0x82"` and `shellType: "timeoutEvidence"`. Evidence has no `rewardKind`
or `rewardSourceHash`; it must not be classified as a block reward. Genuine gas
and STARK rewards retain their reward metadata and tags `0x80` and `0x81`.
The published SDK 0.13.0 `getBlockReceipts` entry is verified against all 100
retained certificates on the local development profile, including historical
state after recovery. This does not mean the backend correction is released
or activated on a public network.


The native ledger uses ordinary validator-registry storage words for membership,
counters, pending suspension epochs, the ordered opportunity cursor and the
proof transcript. Final proposals also store the ordered effective authorities
and weights used for that block, including existing economic reductions. The
shared commitment is checked against the native cursor; zero, duplicate,
oversized or mismatched entries are rejected. Existing trie history and snapshot traversal therefore cover
those fields without a separate state-body sidecar. Updates use an independent
world-state snapshot and publish only after all trie writes succeed. Leaving and
joining, historical queries and failed execution must preserve the same rules.

The bound vote transport carries a complete signed work transaction and its
witnessed admission timestamp, or a heartbeat marker. The opportunity commitment
binds the full transaction RLP, including sender, signature, key mode and AA
payload. Heartbeat commitments bind the frozen eligibility time derived from
the parent. An idle observation alone remains insufficient.

Work admission reuses full transaction validation against an isolated parent
state and an explicit block environment. It checks signature/account policy,
nonce, affordability, block fees, gas and size bounds without publishing key
registrations or validation writes. Changing current balances or nonce cannot
substitute for the witnessed parent's state. Historical callers must separately
restore the parent's algorithm/address policy and ordered effective authority
set; the admission helper does not authenticate an arbitrary supplied set.

Received bound votes use a separate consensus message with its own size and
routing classification. A durable journal retains one payload per voter and opportunity context,
including its work witness. Different payloads cannot overwrite that record;
a newly randomized signature for the same verified payload retains the original.
The receiver rechecks stored signatures and weighted quorum, then flushes the
retained certificate before returning it. Different valid work witnesses for the same assigned slot may each collect
separate signatures, so different admission timestamps cannot permanently split
honest voters. Signatures never pool across those contexts. Canonical execution
accepts at most one miss for the slot, even if several witnesses reach quorum.
The receiver alone does not modify canonical counters. The event loop advances
the engine only after independently revalidating a complete, durable certificate
chain from view zero for the current parent and height. Startup restores that
in-flight view from the same journal. The shared admitted-evidence executor
requires the durable witness, verifies its eligibility and quorum, then publishes
the native counter/transcript atomically; missing witnesses and replays fail.

View recovery also returns each certificate's original signed work to ordinary
mempool admission after releasing the engine lock. A certificate alone must not
strand its transfer after the volatile pool is lost. Existing pool entries are
not duplicated; a partial vote does not restore work, and a new parent does not
requeue already committed work. Admission failures retain the durable witness
and report the failure without disabling the verified view. This is recovery of
certificate-carried work, not general persistence of every pending transaction.

The event loop now observes eligible work or heartbeat using a monotonic timer
and the frozen timeout interval. Parent age cannot replace that interval when
work arrives late. It rechecks fresh work eligibility while waiting; expiry or a
rejected account policy discards the pending observation. Signing and validation
use `block_in_place` to keep the async worker available. The local receiver
verifies and flushes the signed vote before broadcast. A restarted loop reloads
and rebroadcasts its exact durable vote without another signature. Legacy V1
view-change input and emission remain available only before activation.

Actual event-loop tests cover idle and late work, the full ten-second interval,
heartbeat observation, concurrent async progress during signing and exact vote
reuse after a node rebuild. Two loops with unequal weights and different
witnessed timestamps converge on a valid quorum for the same slot, advance to
the next assigned proposer, and produce, import and finalize the same sealed
block with a real transfer. The block carries the certificate in its system
transaction tail; both stores agree on the native state, receipt and single
miss. Separate component checks reject a second certificate for the same slot.
These channel-network checks use separate in-memory stores in one process;
they do not establish TCP networking or physical process recovery.

Development kernels and a shared native executor are implemented. Their tests
use genuine keys, the 100-miss kernel boundary, low-frequency controls,
changed-current versus historical state, replay rejection and failed trie writes.
These are component checks, not live-network or physical restart acceptance.

The optional `offline_enforcement` chain profile freezes activation height,
positive epoch length, nominal block interval and heartbeat interval. An omitted
profile preserves legacy encoding and behavior. Existing chains can first add
the complete profile strictly above the canonical head; once stored, neither
its activation nor its timings may change or be removed. Genesis and startup
require matching wPoA epoch and nominal block parameters. Operational polling
hints do not rewrite this profile. Trusted snapshot import checks every profile
field and rejects an omitted scheduled profile before publishing any entries.
The miss threshold remains fixed at 100, outside operator configuration.

Forward production and import execute the verified timeout prefix and final
proposal reset before user transactions, then publish the native ledger, body,
receipts and head in the existing atomic batch. Evidence must form a contiguous
view chain bound to the enclosing parent, height and final assigned proposer;
its exact receipt indices follow other system transactions. Empty blocks require
frozen heartbeat eligibility. A failed canonical publication leaves the head,
counters, account nonce and transfer value unchanged; retry applies them once.
A heartbeat-only block and a rebuilt node restoring its durable view are also
covered. Historical queries retain the original root without writing current
state.

Accepted canonical bodies with retained native roots now replay the complete
verified prefix, proposal reset and evidence receipts using their sealed authority
context. This reuses the historical algorithm/address-policy overlay; a later
change in live penalties does not substitute current weights for old ones. A
real missing body and legacy witness can be restored through the atomic
backfill entry after later nonce/counter changes. Tampered witnesses do not
publish a partial body. Snapshot export/import preserves the native authority
context. These checks cover retained canonical roots, not historical roots
omitted from a snapshot or deleted by retention.

Competing branches now replay independently when their input committee is
anchored by an already accepted block at the exact same parent and height, or
by verified parent ancestry and committed epoch reload states. Pending raw
registry edits do not redefine the active input base. Surviving identities carry
their authenticated base-minus-effective economic reduction into a governed new
base, clamped at zero. A returning identity recovers that reduction when its last participating epoch
contains a positive sealed input, using that input's verified epoch base. The
history walk verifies every parent hash and consecutive height; it never reads
the candidate child's claimed post-state to grant weight. Missing roots,
unavailable effective input and unqualified new identities still require
independent reconstruction. Committed
suspension filters child participation separately. The accepted slot anchor also covers the first activation block; the received block's own
claimed post-state never grants voting authority. Historical policy and address
metadata stay in the disposable parent overlay. Provisional admission executes
the complete native prefix, user transactions and system receipts, compares
the root, and discards trial writes before storing a fork candidate.

A genuine weighted attestation quorum can then select a multi-block competing
branch. Replay uses trial ancestry mappings and restores the original mappings
before the atomic replacement batch checks rollback preconditions. Adoption
resets the abandoned pending view, preserves current economic penalties and
retains the intermediate block's native counter history. Attestations and stored
target commit certificates use that target's independently verified input
committee for signer weights and quorum. Active certificates without the target
body/context are refused. Adoption stages the head's next-slot base in the trial
state, then applies that roster and participation mask after atomic publication. Tests use real keys,
certificates and attestations with controlled development timestamps; they do
not establish physical-network recovery or real elapsed timeout duration.

Committed pending suspension now controls participation for the next block's
epoch. A separate mask excludes suspended identities from proposer selection,
timeout quorum and attestation weight without changing registry base weights,
account balances, stake principal or existing economic reductions. The activated
engine and timeout verifier use the same ordered effective committee. Disabled
profiles retain legacy selection. Startup, snapshot restoration and fork adoption
rebuild the mask from native state; a local timeout cannot create it.

An independent-store test produces and imports501 actual sequential blocks with
weights1/1/3. A validator misses100 genuinely certified assigned heartbeat
opportunities while the low-frequency control remains unaffected. Miss100 at
height496 schedules epoch50; participation changes for height500, while the
validator remains eligible before that boundary. A valid returning proposal
before the boundary resets its counter but preserves pending suspension. Real
signed proposals, timeout votes and attestations from the suspended key are
rejected without publishing state. Snapshot restoration preserves suspension
even when that returning proposal reset the counter to zero. These tests use
controlled development timestamps and in-memory databases, not production time
or physical process recovery.

Root-signed ValidatorRegistry recovery votes now bind the chain, current epoch,
exact suspension incident and ordered effective committee. The native ABI
`recoverValidator(address,uint64,bytes32)` uses three 32-byte words after the
selector: target identity, suspension epoch and committee hash. A strict weighted
supermajority greater than two thirds schedules recovery for the next common
epoch. Suspended members cannot vote. Duplicate votes and stale contexts fail;
minority votes persist without lifting suspension. Registered roots and first-use
embedded roots are verified independently of custom account validation. Native
AA calls require their separate registry activation and the outer root signature;
a failing later inner call rolls back vote storage and scheduled recovery.

The canonical acceptance continues the genuine 100-miss history through funding,
minority and quorum transactions, failed head publication, pending-recovery
snapshot restoration, boundary rebuild and a real proposal by the recovered
validator. Recovery changes participation and resets the miss counter at the
epoch, preserving the validator's balance, stake and base weight. These remain
controlled development-time tests with independent in-memory stores.

Pending raw registry membership changes no longer rewrite the native counter
roster mid-epoch. The native roster changes with the existing base-authority
reload after its boundary block commits. A raw remove/readd before actual exit
preserves the old counter; still-active members can propose or receive certified
assigned misses even while absent from the pending raw list. True exit removes
the native entry, and a later activated rejoin initializes it afresh. An empty raw
registry retains the same fallback as the existing base reload.

A 23-block independent-store acceptance uses real governed remove/add
transactions, authentic weighted timeout certificates, a legitimate proposal
while the proposer is absent from the raw registry, and a nonzero counter before
actual exit. It verifies fresh zero after rejoin, failures at both boundary
publications, pre/post-exit snapshots, startup rebuilds and immutable historical
counter reads. This covers the recorded two-member, initially active profile;
it does not establish every membership, penalty or activation combination.

First activation initializes its native counter roster from the effective epoch
base on the authenticated parent branch. Starting at the parent, verify each
ancestor hash and consecutive height down to the existing authority reload
boundary, bind boundary zero to the trusted genesis, validate its state and check
that the admitted effective committee fits that base. Pending raw membership
cannot replace this source. A nonempty preactivation ledger or missing active
ledger context is rejected instead of silently resetting history.

An independent-store acceptance removes a member through real governance before
future activation at heights 8, 10 and 11 in a ten-block epoch. It exercises the
still-assigned old member at activation, real timeout certificates on the
boundary, and the changed base immediately afterwards. Missing and mismatched
ancestor data is refused without publication. Pre/post-activation snapshot
restoration, startup, accepted first-active body replay and missing body/witness
restoration preserve the same results after the live committee changes. A
canonical preactivation body also replays without changing current state.
These are controlled development-time, initially two-member tests, not general
unanchored foreign-committee or physical-process acceptance.

An unanchored pending-removal fork acceptance uses real governed registry edits,
a genuine assigned-miss certificate and signed weighted attestations to replace a
three-block branch. The remote child's parent differs from the local canonical
slot, so no same-parent anchor can grant it authority. Provisional admission leaves
the remote trie root absent; only final adoption publishes matching roots,
receipts, nonce and transfer value. Wrong roots, corrupted signatures and a
cryptographically valid self-authorized committee are refused without KV changes.
An observer's separately configured later economic reduction stays unchanged;
this control does not establish a new canonical penalty transition.

The same competing branch also crosses the actual member exit at reload 10 and
an unanchored child 11, while the observer retains a different canonical branch
through 10. The removed member cannot propose or attest to child 11. The sole
surviving member's real signature supplies the target's full quorum, using either
attestations or a commit certificate. A failed replacement batch preserves the
old root, roster and penalties; retry publishes the complete branch, receipts,
nonce, transfer value and native exit. The new runtime roster contains only the
survivor, preserving its observer economic reduction across restart. Historical
block 4 still resolves its old input weights without writing current state.

A further branch performs a genuine governed rejoin at 11, freezes it until
reload 20, then admits an unanchored child 21 against another canonical parent.
Two real assigned misses remain in historical block 9; actual exit removes the
record and rejoin starts at zero. Tests cover both an unchanged returning base
and governed reweighting: a prior base 2/effective 1 reduction yields effective
2 under new base 3, and stays at zero under new base 1. Zero-weight members
cannot attest or contribute to quorum. A surviving base 5/effective 3 identity
becomes effective 5 under new base 7; an observer's later reduction instead
leaves its current weight at 4 after adoption. These reductions are seeded
before the shared anchor and do not establish new challenge-penalty events.
Real native transactions, signatures, attestation and certificate quorums,
failed publication/retry, restart, and read-only historical counter queries
cover these paths. Missing or substituted ancestor headers refuse without
publishing a partial state or granting a fresh raw weight.

Governed reloads may reorder surviving identities. The verified native reload
state supplies the new order; inherited economic reductions follow addresses,
not old vector positions. A real remove at 3 and re-add at 5 changes `[A, C]`
to `[C, A]` at reload 10 without an effective epoch exit. Certified misses at
4 and 8 remain visible before A makes its newly assigned proposal at 11 and
resets its counter. Both attested and certified branch adoption preserve roots,
receipts, historical reads and restart state. A governed C base change from 5
to 7 also preserves its prior reduction of 2 in the target input, while the
observer's later reduction remains intact after adoption. These economic
controls are shared historical fixtures, not new canonical penalty events.

A separately qualified first-member case uses a chain initialized with
`prover_registry_height = 0` and offline enforcement active from block 1. Retained roots must prove no earlier validator or
registered-prover role through genesis. The first member then has no inherited
validator or prover reduction to discard. The test funds a fresh account, uses
a signed first-use transaction to persist its public key, submits real native
admission governance, waits for reload 20, and imports the unanchored new set.
The new key signs its first assigned proposal at 23. A real fee-paying transfer
in that block credits the new producer; an empty proposal has no fee subsidy.
Attested and certified branch replacement, wrong-key rejection, historical
queries and restart preserve the resulting state and observer penalties.

This case does not complete the original unrestricted-prover flow. Standalone
provers can acquire economic reductions without prior validator membership.
A legacy pre-activation interval, unbounded historical prover admission, any prior registered-prover role, or
missing retained roots therefore still require authenticated economic
provenance; a new raw registry entry cannot erase that context.

Once the configured offline rule governs the next slot, signed equivocation
messages also bind the offender's key and both alleged proposal slots to
verified parent epoch bases. A key becoming a validator today does not grant it
validator authority at a pre-admission or pending-admission height. Real network
loop tests reject those messages, keep valid historical member evidence
punishable, and allow evidence against the newly admitted key's actual proposal.
The economic journal persists while native account state stays unchanged.
The legacy validation route remains selected before activation. These controls
do not establish canonical replay of new economic-penalty events.

Unanchored native recovery now follows authenticated suspension history back to
its last eligible sealed input and verified epoch base. A header omitting a
validator can be skipped only when its verified input parent's native ledger
proves suspension for that slot's epoch. Missing ancestry, missing eligible
input or an unexplained absence cannot grant raw weight. Native quorum recovery
lifts the participation mask at the common epoch; inherited economic reductions
remain independent.

The actual 501-block suspension prefix is reused in independent competing
stores. Signed minority recovery at 503 stays pending; quorum at 504 schedules
epoch 51. B remains excluded from the input of 509, returns with weight 1 at
510, and signs its assigned proposal at 511. A separate general weight vote by
C at 505 needs A's vote at 506 to exceed two thirds of registered base weight;
it supplies B weight 2 after reload 510. The post-recovery C+B quorum adopts the
branch, while C alone is insufficient. Attested and certified variants preserve
receipts, historical counter 100 after current counter 0, and restart state.
Missing or substituted last-eligible ancestry refuses atomically. Failed head
publication retains the old root, participation mask and observer penalty; a
retry restores B while retaining the observer's later C reduction.
The economic control also uses B's historical base 2/input 1 with an accepted
inherited reduction of 1 in both independent stores. Actual recovery restores
input 1 and preserves that reduction, balance 123 and stake 50. A separate
zero-effective case funds the restored B for a signed weight vote at 511; C's
matching vote at 512 reaches the strict registered-base quorum. Input stays 1
through reload 520, then a native base of 1 clamps B's effective input to zero.
The recovered member and counter remain present, but B's proposal, attestation
and certificate contribution at 521 are rejected; C alone now forms a valid
quorum over A1/C3. Both adoption routes preserve the inherited and observer
reductions through rollback and restart. The funding and bounded governance gas
are separate from suspension; stake 50 is unchanged.
These reductions are explicit accepted pre-anchor economic fixtures, not new
canonical misconduct events. Missing last-eligible input, zero input before
suspension, newly introduced penalties and mixed histories still need
qualification; suspension itself grants no raw weight. Trusted snapshots at
496 and 500 also restore the genuine base 2/input 1 prefix into independent
stores. They preserve stake 50, balance 123, counter 100, pending epoch 50 and
the inherited reduction before and during the mask; forward import and native
recovery restore effective input 1. The existing trusted snapshot includes the
persisted economic journal. This does not authenticate arbitrary untrusted
economic metadata.

The portable physical acceptance uses the actual CLI, TCP libp2p and separate
RocksDB stores, with generated ML-DSA authorities A1, B1 and C3. Initially B is
offline. Real transfer work produces 100 distinct assigned-miss certificates
with both A and C signatures. Miss 100 at 496 schedules epoch 50; block 500
removes participation while preserving B's native membership, base weight,
stake and funds. A's minority recovery vote at 501 does not lift suspension;
quorum at 502 schedules epoch 51. A new B process catches up from genesis while
masked, recovers at 510 and actually proposes the finalized transfer at 511.
Its normal proposer gas-fee credit is accounted for separately. All three
processes then stop and reopen their exact stores, retaining both the recovered
state and the original historical receipt, counter and root. The physical
fixture uses zero stake; the nonzero stake 50 control above is independent.

Run from a compatible source checkout with Rust and Node.js 20 or newer:

```bash
cargo build --locked -p shell-cli --features libp2p
node tests/e2e/native-offline-network.mjs
node tests/e2e/native-offline-network.mjs --algorithm=slhdsa
node tests/e2e/native-offline-network.mjs --interrupt-work
node tests/e2e/native-offline-network.mjs --full
```

The short commands cover one real miss and both-process restart with ML-DSA-65
(default) or SLH-DSA-SHA2-256f. Both algorithms have passed the short flow;
the SLH-DSA evidence carries two genuine 49,856-byte signatures and is imported
with identical state roots and historical receipts after restart. This verifies
the existing transport budget for this three-validator fixture, not arbitrary
committee sizes. `--full` has been verified with ML-DSA-65 and covers
the complete 100-miss sequence and three-process recovery/restart; allow about
one to two hours. The script creates private temporary keys, isolated loopback
ports and its own local genesis, checks business state and exits nonzero on
failure. It prints the result artifact path and retains data for diagnosis.
It neither shortens the fixed threshold nor activates a deployed network.
`--interrupt-work` kills the isolated C3 process after it retains a minority
vote and the original signed transfer. An offline snapshot export verifies that
the vote exists without a quorum certificate. After reopening, C alone still
cannot advance; reconnecting A1 must confirm that original transfer without
resubmission, followed by the usual receipt, funds, history and restart checks.
The local profile uses epoch length 10, nominal blocks of two seconds and a
600-second heartbeat. SLH-DSA's full lifecycle, mixed signature/account
combinations, partitions and
crashes during in-flight voting remain separate acceptance cases.

Before release, complete unanchored effective authority and new challenge-penalty
reconstruction and the remaining mixed-history and compatibility cases.
The forward path currently uses the live effective authority set;
accepted history restores its sealed set. Competing branches restore the trusted
slot or parent context described above. New penalty transitions without such an
anchor remain incomplete and fail closed; later live penalties are never
silently applied to old slots or cleared by fork adoption.
These development changes must remain inactive until the remaining lifecycle
and compatibility checks pass. No legacy vote or manually constructed proof
may bypass opportunity admission.
