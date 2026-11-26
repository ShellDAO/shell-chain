# Commit-quorum signature and weight proof composition

Status: unreleased development profile.

The arithmetic quorum ingredient alone authenticates no signatures. Compose it
with every complete lattice-signature graph over the original block-hash
message. The expected input comes from the Node's canonical header and current
Native authority context, independently of the proof. Preserve transcript and
algorithm distinctions; a signature proof for transaction framing or another
header cannot authorize a commit certificate.

Use the existing source-bound production store and shared matrix encoding for
separate, exclusively owned jobs. A bounded pause returns no complete proof.
Reopening verifies the immutable source and actual checkpoint certificates.
Only successful full verification constructs the non-deserializable exact-tuple
verifier. The explicit finality entry reconstructs the current context again
before the existing atomic certificate, signer-evidence and cursor write.
Changed weights or keys refuse even when the old certificate still exceeds a
new native threshold. Rejections must not write any Native row.

Run from a checkout containing this implementation with the stable Rust
toolchain and the dependencies pinned by `Cargo.lock`:

```sh
cargo test --locked -p shell-node --lib commit_quorum_air_persistent_native_finality -- --nocapture
cargo test --locked -p shell-node --lib fast_finalize -- --nocapture
```

The first entry generates its own temporary genuine signer, then drops the
private key before proof production. It uses a separate MemoryDb job, restores
persisted rows into another job store after a bounded pause, and checks actual
proof verification, canonical finality, retained signer evidence and no-write
refusals. The fixture uses stored canonical headers; it is not an executed
transfer, RocksDB process recovery, independent peer or multiple-signer
acceptance test. Full proof generation is substantially more expensive than a
native signature check. The complete repository CI remains a separate gate.

To retain the public fixtures and reverify them in a fresh process, select a
new output directory:

```sh
SHELL_COMMIT_QUORUM_ARTIFACTS="$PWD/quorum-fixture" cargo test --locked -p shell-node --lib commit_quorum_air_persistent_native_finality -- --nocapture
cargo run --locked -p shell-node --example commit-quorum-cold -- "$PWD/quorum-fixture"
```

The second command restores the serialized public job rows into MemoryDb,
reverifies every component with zero new proofs, compares the complete proof
bytes, then restores the original Native context and checks that every final
row matches the original finality control. Input files remain read-only. The
fixture's authority configuration is a separately trusted caller input; an
untrusted fixture cannot supply production authority. This is a process-cold
CBOR fixture check, not RocksDB recovery or peer authentication. Existing
output directories refuse rather than overwrite retained evidence.

To migrate that same completed job to real RocksDB and check a process-cold
proof output, run:

```sh
cargo run --locked -p shell-stark-prover --example commit-quorum -- restore quorum-fixture/source.cbor quorum-fixture/job-complete.cbor quorum-job
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove quorum-fixture/source.cbor quorum-job quorum-proof.cbor
cargo run --locked -p shell-stark-prover --example commit-quorum -- verify quorum-fixture/source.cbor quorum-job quorum-proof.cbor
cargo test --locked -p shell-stark-prover --lib production_store::tests -- --nocapture
cargo test --locked -p shell-stark-prover --example commit-quorum verification_output_comparison -- --nocapture
```

Use a new, separate `quorum-job` directory. `restore` checks every original
certificate before opening a persistent output, writes the exact public rows
atomically, flushes, and reverifies them from RocksDB. This imports a completed
checkpoint, not a fresh proof computation. `prove` can also create a separate
job directly from an independently supplied source; its optional positive
component limit pauses after bounded new work. Complete proof output is written
only after full verification. Existing valid identical output is reusable;
conflicting output refuses before the job opens.

`verify` requires an existing pinned source, database and output. Its dedicated
checkpoint path never initializes a source or invokes a proving closure, even
when a structurally consistent partial job lacks a certificate. Invalid cached
proofs refuse rather than heal. Every reused certificate and the full output
are checked, with zero new proofs and unchanged logical source/component rows.
An output that disappears during verification refuses instead of being recreated.
RocksDB may update its own logs on open; this is not a byte-for-byte database
directory immutability claim. Retain all input files and job directories after
a failed attempt. Other signer combinations and public release remain separate
acceptance work. The self-contained production-store regressions check missing-source,
missing-component and invalid-cache refusals without requiring saved keys or
external fixtures.

For a separate, self-contained Native execution and history check, install the
C/C++ compiler and libclang required by the pinned RocksDB dependency, then use
a checkout containing the new `quorum-native` example:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare native-quorum
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove native-quorum/source.cbor native-quorum-job native-quorum-proof.cbor 1
# The bounded command exits nonzero with Paused; retain its job and inputs.
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove native-quorum/source.cbor native-quorum-job native-quorum-proof.cbor
cargo run --locked -p shell-stark-prover --example commit-quorum -- verify native-quorum/source.cbor native-quorum-job native-quorum-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- verify native-quorum native-quorum-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- verify native-quorum native-quorum-proof.cbor
```

`prepare` requires a new directory. It creates temporary accounts and a funded
isolated genesis, admits genuine signed transactions, produces three blocks,
and independently executes/imports them in RocksDB. It retains all original
blocks and quorum certificates before dropping temporary signing keys. Its
single authority uses primary ML-DSA-65, while the sender uses Dilithium3.
The example captures block 1's current authority context and preserves ordinary
finality at 1 while the chain follows through block 3. No testnet funds, stored
personal keys or external fixture files are required.

The first proof command starts an empty, separate RocksDB job and durably
pauses after its weight component; the next process reuses that component and
produces the complete primary signature graph. Verification-only intake then
rechecks every certificate without proving. A complete proof, rather than the
pause or a successful native signature check, is required for Node acceptance.

The first Node verification starts a fresh receiver at the same funded genesis,
executes/imports block 1, rejects a damaged proof without writes, and finalizes
with the full quorum proof. It follows the retained blocks 2 and 3, checks nonce,
value, gas fees and persisted signer/finality evidence, and replays historical
block 1 from its frozen parent on all three stores. Receipts include both the
ordinary transfer and the block reward; the transfer is selected by its exact
transaction hash. Historical replay verifies identical roots and full receipts
without writing back to current state. It requires full quorum AIR while
ordinary transaction signatures remain Native, as reported in the result.
The second invocation reopens existing receiver data and repeats the historical
and refusal checks without new signing or importing those blocks again.
Changed proof, certificate, current weight, target and expected tip must refuse
with unchanged logical Native rows. An authority/key configuration in these
public test controls is a separately trusted caller input, not production
authority supplied by an untrusted proof.

Every unexpected failure exits nonzero. Preserve partial directories and public
inputs after a failed preparation; its dropped private identities cannot be
recreated to manufacture missing successors. `quorum-native inspect native-quorum`
rechecks the first retained transfer and its ordinary receipt on the original
provider and importer stores without writing Native rows. RocksDB may update
its own logs on open. This controlled three-block, single-authority flow does
not establish independent peer transport, power-loss recovery, sender-signature
AIR, changing historical validator provenance, or all activation combinations.
Repository-wide CI and public release acceptance remain required separately.

To import and finalize block 1 in one durable transaction, reuse those same
complete public controls and proof with a new receiver directory:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive native-quorum native-quorum-proof.cbor native-quorum-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-verify native-quorum native-quorum-proof.cbor native-quorum-import
```

The exclusive offline `Node::import_block_with_commit_proof` reconstructs the
fresh child's authority context from its independent current parent and registry;
it does not require storing the target header before verifying its full QC proof.
It rejects a stale parent, inactive body-commitment profile or damaged proof,
certificate and body without publishing a child. After execution it rechecks the
parent and current authority tuple, retaining the consensus read lock through
one canonical backend batch containing state, block, receipts, the original
certificate, signer evidence and finalized cursor. In-memory world state and
finality update after the durable batch succeeds. Duplicate/stale imports refuse.
Sender and proposer cryptography remain Native, and validator/key provenance is
still a separate trust input. This entry does not opt a running node into new
network intake or supply historical penalty context.

`receive` creates no new signing keys or proof graphs. It reuses the original
three genuine blocks/quorums and complete proof, checks changed proof, weight,
signature graph, certificate, parent, body and activation refusals, then injects
a failure at the final backend batch. The attempted batch must contain the
canonical head, finalized cursor and exact certificate, while all durable rows
and the in-memory world/finality remain at genesis. Retrying the same original
inputs with that controlled storage fault removed must execute and finalize
block 1 together, then follow the retained blocks 2 and 3. The example compares
all logical Native rows with an independent ordinary importer and replays block
1 after state 3. `receive-verify` reopens both stores in another process and
checks persisted state/receipts, signer evidence, finality and no-write history
and duplicate refusals. This tests a controlled RocksDB batch failure and
process reopen; power loss and real peer transport require separate acceptance.
Inactive profiles use separate genesis configurations. An attempted change to
an existing stored configuration must refuse without modifying it. Retain all
directories after any unexpected nonzero exit. If a `receive` attempt stopped
while both original receivers still match their funded genesis, continue those
same public inputs without resetting or replacing the stores:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-resume native-quorum native-quorum-proof.cbor native-quorum-import
```

This continuation requires both original genesis heads, zero finality and equal
logical rows. It then checks the immutable-configuration refusal and uses
separate genesis databases for omitted and future activation heights. A partial
receiver beyond this precise genesis state refuses; preserve it for diagnosis.

For a two-authority development check, retain the original primary controls and
completed job, then export the same three block hashes for an installed SDK.
The development checks use Rust 1.94.1, the default allocator and this build
configuration; debug assertions and overflow checks remain enabled. Other
compiler/resource profiles and published artifacts need separate verification.

```sh
export CARGO_PROFILE_DEV_OPT_LEVEL=1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2
```

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- co-sign-input native-quorum quorum-messages.json
node tests/e2e/sdk-quorum-cosign.mjs quorum-messages.json sdk-quorum-signatures.json sdk-package-directory
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- augment native-quorum sdk-quorum-signatures.json two-signer-quorum
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove-reusing two-signer-quorum/source.cbor two-signer-job two-signer-proof.cbor native-quorum/source.cbor native-quorum-job 1
# Paused is an expected nonzero exit; preserve both jobs and all public inputs.
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove-reusing two-signer-quorum/source.cbor two-signer-job two-signer-proof.cbor native-quorum/source.cbor native-quorum-job
cargo run --locked -p shell-stark-prover --example commit-quorum -- verify two-signer-quorum/source.cbor two-signer-job two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one two-signer-quorum two-signer-proof.cbor two-signer-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one-verify two-signer-quorum two-signer-proof.cbor two-signer-import
```

The JavaScript helper requires Node 20.19 or later and an SDK installation that
exports `shell-sdk/adapters` and `shell-sdk/signer` (the development check uses
SDK 0.14.0-rc.3 with Noble 0.6.0). `sdk-package-directory` is the installed or source-built SDK package directory containing its
`package.json`; omit it when that package is the current directory. It invokes
the actual `ShellSigner` API, writes only the public key, address and all three
raw block-hash signatures to a new file, and disposes the temporary private key.
A source-built or cached installation must be labeled as that substitution;
using it does not qualify a fresh public npm package or website flow.

`augment` verifies the original primary signatures and the SDK FIPS transcript,
preserves the original headers/transactions/genesis, and creates a new trusted
current authority configuration with primary weight 2 and SDK weight 1. This is
an independent development genesis configuration, not proof of a historical
validator-set transition. The original primary private identity is never
recreated. Primary-only certificates at exactly two thirds must refuse, and a
full proof cannot omit either signature graph or use an old single-signer
weight context.

Use separate, exclusively owned source-pinned donor and destination jobs.
`prove-reusing` cryptographically reverifies the donor, maps only exact
signature/key/address/tag and message matches, and verifies every borrowed
certificate again against the destination inputs. Weight proofs are never
borrowed. A missing matched donor component refuses rather than regenerating
its old math. Borrowed checkpoints may add rows even when no new mathematical
proof is computed. The completed destination is independently cold-verifiable
without the donor. The donor's logical rows remain unchanged; RocksDB may
maintain logs on open. Copy a closed donor job first if its original directory
must remain byte-for-byte unchanged, retaining and checking both copies.

`receive-one` ends at the first genuine block and finality 1, checking
independent Native row equality, both signature graphs, strict quorum,
activation/refusal boundaries and backend-batch rollback; `receive-one-verify`
reopens that same first-block state. Run it before advancing the stores.

The original single-authority controls may have only one second between
blocks. Under the new weighted authority context, block 2 can belong to a
rotated proposer whose earliest legal view starts after the existing ten-second
timeout. Even both genuine quorum signatures cannot authorize an earlier
header. `inspect-follow` reports that rejection without opening a Native store;
retain those inputs and their first-block proof as refusal evidence. Do not
change their headers, recreate the dropped keys or reduce the timeout.

For the full peer and later-state history check, create distinct timed controls.
`prepare-certified` waits the real view timeout between producing each new
successor, then drops its new temporary sender and primary keys after all three
signed controls are saved. The original controls and proof remain unchanged.
The new keys and block hashes require a new independently pinned proof job:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare-certified timed-primary-quorum
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- co-sign-input timed-primary-quorum timed-quorum-messages.json
node tests/e2e/sdk-quorum-cosign.mjs timed-quorum-messages.json timed-sdk-signatures.json sdk-package-directory
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- augment timed-primary-quorum timed-sdk-signatures.json timed-two-signer-quorum
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- inspect-follow timed-two-signer-quorum
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove timed-two-signer-quorum/source.cbor timed-two-signer-job timed-two-signer-proof.cbor 1
# Paused is an expected nonzero exit; preserve this new job and its inputs.
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove timed-two-signer-quorum/source.cbor timed-two-signer-job timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- follow-peer timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- follow-verify timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
```

`follow-peer` resumes both finalized first-block stores through `Node.run` and
real loopback TCP/Noise peers. The peers cap each response at the requested
block count and answer actual requests with the new timed blocks and both
genuine certificate signatures. A transparent transport observer waits until
the real node event loop has finished dispatching each response before the
example checks its resulting state; retries may retain the same request nonce. The normal sync path
verifies each quorum before using historical view validation, imports blocks 2
and 3, and persists their certificates and finality 3. The receiver first
rejects a stale nonce, a primary-only exact two-thirds certificate and a changed
SDK signature without changing its first-block rows. An independent reference
follows the same certified data; the example checks all Native rows, receipts,
nonce, transferred value and fees. It shuts down the event loops gracefully
before reopening either store. `follow-verify` cold-reopens the completed stores
and replays the full first-block quorum proof against current block 3 without
writing historical state back. Nonzero exit means the flow or an assertion
failed; preserve all state for diagnosis.

The peer example retains the weighted selector and verifies successor quorum
signatures natively; it does not prove those successor signatures or selector
provenance in AIR. The throwaway runtime signer is outside the authority set,
cannot produce blocks and never replaces either signing identity. Discovery
and external bootnodes are disabled; no authority keys are persisted.

Current registry and address/key matching remain Native context predicates.
This does not establish historical penalty provenance or the selector in AIR,
add a consensus carrier, activate a network schedule, or replace the ordinary
wire certificate. Public release and broader profiles require separate checks.

## Authenticated historical RPC and explicit peer fetch

For the completed timed two-authority stores above, the node accepts an
off-chain `CanonicalProofManifest` with `version: 2`. Its block hash selects an
already canonical stored block and certificate; chain ID and genesis must match
the node. The node derives the expected keys, current trusted weights and
historical parent independently of the payload. The existing block-commitment
activation boundary applies. Sender manifests keep version 1 and their exact
identities; automatic sender discovery and fresh sender admission select only
that role.

The payload uses the `\0commit-quorum/cbor/v1/` domain and lossless CBOR for the
existing version-one mathematical proof. Decoding enforces the shared 256 MiB
artifact limit, 64 nesting levels, sixteen signer slots, exact canonical bytes
and no trailing data. Availability encoding grants no authorization. Every
explicit recheck runs complete commit-signature/weight AIR and Native historical
execution, returning the source block's receipts, state root and proved signer
count. Chunk and result writes stay in the bounded local proof cache; canonical
Native state and finality remain unchanged.

The existing authenticated operator methods are `admin_beginCanonicalProof`,
`admin_appendCanonicalProof`, `admin_verifyCanonicalProof`,
`admin_canonicalProofStatus` and `admin_fetchCanonicalProof`. Explicit fetch uses
the existing dedicated TCP/Noise chunk protocol and an exact version-two
manifest. Version-two objects are kept out of automatic sender discovery.
The shared chunk size is 256 KiB; a verification receipt remains informational,
and `recheck: true` requests full cryptographic verification again.

Use the same controls, proof and finalized third-block stores from the previous
commands. These commands add proof-cache records to those owned stores:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- rpc-pause timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- rpc-verify timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- rpc-recheck timed-two-signer-quorum timed-two-signer-proof.cbor timed-two-signer-import
```

The example creates temporary authenticated loopback RPC listeners and
non-authority runtime signers, preserving the original signing identities and
proof. It stops after three uploaded chunks, cold-resumes that exact upload,
checks authorization/source/size refusals, rejects a correct-hash damaged weight
proof and a sender-role relabeling, and transfers the genuine quorum artifact
to the independent third-block store over real peers. A final process-cold
recheck verifies both caches and compares returned data with independently
persisted Native receipts while checking all canonical rows for writeback.
Nonzero exit means a failed operation or assertion; keep every store and public
input for diagnosis. No new signature or proof generation is required.

This operation serves historical verification against the trusted current
authority context. Fresh full-quorum AIR admission, automatic quorum discovery
or production, successor quorum AIR, historical validator/penalty provenance,
network activation and public artifact acceptance remain separate work.

## Fresh certified sync with explicit quorum proofs

The local `canonical_quorum_admission` option, exposed as
`--canonical-quorum-admission` and `[consensus].canonical_quorum_admission`,
selects a separate certified-sync follower profile in the current source.
Build the CLI with dedicated transport (`cargo build --locked -p shell-cli --features libp2p`);
startup refuses this option when that transport is absent.
It defaults to false. The
existing sender option, sender manifest-one discovery, ordinary default behavior
and wire QC remain unchanged. No activation height or on-chain carrier is added.

For an exact next child at the existing block-commitment activation boundary,
the normal requested `BlockResponse` supplies the body and original QC. The
node retains them as bounded untrusted inputs before canonical execution. An
uncertified gossip block cannot bypass that requirement in this mode. The
node discovers a matching version-two manifest through the dedicated authenticated
peer protocol, then pulls and fully verifies its bytes. Explicit authenticated
upload or fetch remains supported. Quorum discovery requires its own option;
sender permission never enables it.

The existing admission queue and worker lifetime are reused: at most two
retained candidates, a 2 MiB body, a 3,194,880-byte QC and one active verification worker. The QC bound covers the JSON byte-array encoding of up to sixteen supported signatures.
The original body bytes and QC hash bind the record. A worker checks the
complete signature/weight graph against independently selected parent, header,
keys and current authority weights. Only the serialized canonical event loop
receives that opaque in-memory tuple, rechecks context and executes the single
atomic state/block/receipt/QC/signer/finality batch. The exclusive offline API
uses the same verification and commit functions. Shutdown retains the source
and pauses unfinished verification; recovery requires full verification again.
Stored upload results and pending statuses remain informational.

Using the timed controls and full proof above, first prepare an owned provider
at finalized height three, then run a separate receiver:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one timed-two-signer-quorum timed-two-signer-proof.cbor quorum-provider
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- follow-peer timed-two-signer-quorum timed-two-signer-proof.cbor quorum-provider
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-pause timed-two-signer-quorum timed-two-signer-proof.cbor quorum-receiver quorum-provider/db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-import timed-two-signer-quorum timed-two-signer-proof.cbor quorum-receiver quorum-provider/db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-cold timed-two-signer-quorum timed-two-signer-proof.cbor quorum-receiver quorum-provider/db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-history3 timed-two-signer-quorum timed-two-signer-proof.cbor quorum-receiver quorum-provider/db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-default timed-two-signer-quorum timed-two-signer-proof.cbor native-receiver quorum-provider/db
```

The commands use self-created timed controls and test funding, preserve the
original proof, and exit nonzero on failed operations or assertions. They start
real loopback TCP/Noise peers and authenticated RPC listeners. `live-pause`
retains the received source at genesis without proof bytes; `live-import`
cold-resumes it, rejects a correct-hash damaged weight graph and wrong role or
chain, fetches the genuine proof from the independent provider and checks
canonical height/finality one, receipts, balance, nonce and fees. `live-cold`
performs another full cryptographic historical recheck without Native writeback.
`live-history3` disables the quorum option for the already signed successors,
follows them through ordinary Native QC verification, then rechecks the first
block against current height three and compares all canonical rows with the
independent provider. This does not prove successor QC AIR. `live-default`
checks the existing Native sync path from genesis with the option disabled.
Provider and receiver directories must be owned, closed stores between commands.
No original authority signing or new proof generation is required by these
continuation commands.

This bounded local profile does not provide an unbounded retained queue,
full successor QC AIR, historical
validator/penalty/selector provenance, network activation or public artifact
acceptance. Existing fork/reorganization paths retain Native certificate
verification; this option is not a chain-wide full-PQ verification switch.
Sender and proposer authorization in this path remain Native. The
first-block example must not be interpreted as a full-PQ chain acceptance.

## Node-owned quorum proof production

The local `canonical_quorum_production` option, CLI
`--canonical-quorum-production` and `[consensus].canonical_quorum_production`
default to false. It requires a prover role and respects the existing readiness
and `canonical_proof_component_budget` gates. Sender and quorum production
options cannot be enabled in the same node process; run separate workers for
those roles. A CLI build that serves dedicated peer transfer needs its
`libp2p` feature. This source option does not change consensus carriers, activation
heights or penalty policy.

The controller selects finalized canonical blocks in activation order, derives
their original stored QCs and current trusted authority/key/weight context, and
captures immutable source descriptors. It uses the existing bounded checkpoint
owner in a disjoint quorum namespace: two active jobs and bounded completed
history (at most eight total source identities), a 256 MiB checkpoint quota,
immutable component writes, compression and full verification on reuse.
Native and sender keys cannot cross the namespace adapter. The controller
checks cancellation at durable component boundaries and records actual progress
even when a budget or readiness change pauses work. Completed jobs are queued
for full rechecking on process restart.

After complete verification and repeated canonical/context checks, the node
encodes the real version-two payload and writes the existing bounded chunk
cache. `admin_quorumProofProduction` returns progress and its manifest. Cache
state is `ready`, indicating byte availability; it does not provide a Native
execution receipt or an import authorization token. An independently running
receiver must still perform full verification and canonical execution. Automatic
quorum discovery uses typed dedicated-peer requests and availability messages;
explicit authenticated manifest fetch remains supported.

An operator may recover an already complete, separately owned quorum job through
`Node::recover_quorum_production_job` while the node is offline. The node selects
the source from the expected canonical block and verifies the entire donor
before writing its own descriptor or checkpoints. Donor stores containing
Native keys or conflicting sources refuse. Original donor logical rows remain
unchanged. Recovery alone does not publish an artifact: the node worker must
verify the copied checkpoints again before availability.

Using the self-created controls, complete proof and separate job from the
earlier commands, prepare a new owned first-block provider and receiver:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one timed-two-signer-quorum timed-two-signer-proof.cbor producer-native
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-seed timed-two-signer-quorum timed-two-signer-job producer-native/db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-disabled timed-two-signer-quorum producer-native/db unused-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-live timed-two-signer-quorum producer-native/db produced-proof-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-cold timed-two-signer-quorum producer-native/db produced-proof-receiver timed-two-signer-proof.cbor
```

The example checks checkpoint-boundary cancellation, a correctly hashed damaged
donor, wrong source and foreign Native keys before valid recovery. It then
starts the actual node producer with the existing component budget, checks
107 reverified components and zero new proving, obtains the node-produced
manifest and transfers its bytes through real TCP/Noise peers. No client proof
upload supplies the provider artifact. The fresh receiver must commit/finalize
block one and match independent receipts, balance, nonce and fees. A separate
process verifies the complete node-owned graph again. Temporary loopback RPC
listeners use authentication and non-authority runtime signers. Commands exit
nonzero on failed operations or assertions; preserve failed stores for diagnosis.

`producer-disabled` checks that the seeded job stays paused without publishing
bytes. The destructive fault modes require separate closed database copies:
`producer-corrupt` damages a checkpoint in a seeded copy before publication,
while `producer-manifest` changes the role of a completed copy's persisted
manifest. Both require refusal and unchanged Native state; retain each failed
copy and keep the original provider intact. Checkpoint cancellation through the
offline API is covered; live readiness loss and power-loss interruption remain
separate acceptance cases.

This complete-job recovery flow reuses the existing genuine graph to avoid
repeating input-equivalent mathematics. It does not qualify fresh-from-zero
full generation on every host, successor/fork QC AIR,
historical validator/penalty/selector provenance, an unbounded job archive,
network activation or public artifacts. Sender and proposer authorization
remain Native in this profile, and the full-PQ parent promise remains open.

## Automatic quorum availability and cold continuation

Manifest discovery keeps transport envelope version one and requests an explicit
`artifact_version`: one for sender proofs, two for complete QC proofs. The field
is omitted on sender requests and defaults to one when absent, preserving legacy
sender wire messages. Unknown roles refuse; an older provider that ignores the
new field cannot downgrade a quorum candidate to a sender manifest. Nonzero
response nonces bind the requested block and authenticated peer. Unsolicited
availability messages still require a matching independently retained candidate,
network identity, body and QC before any proof bytes are allocated.

With `canonical_quorum_admission` enabled, the ordinary certified-sync path
retains the next child and discovers version-two availability automatically.
Only matching role-two bytes enter the existing bounded pull and full verifier;
the same serialized atomic importer supplies the canonical result. A cold
waiting receiver may discover the proof from a different authenticated provider.
Discovery responses and persisted progress remain untrusted status, and the
sender and quorum permission switches remain separate and default off.

After creating a complete provider with the earlier production commands, a new
receiver needs no proof upload, fetch or verify RPC:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto timed-two-signer-quorum producer-native/db automatic-proof-receiver timed-two-signer-proof.cbor
```

To check a durable availability gap, first prepare a separate provider containing
only the canonical first block, then restart the waiting receiver against the
complete provider:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one timed-two-signer-quorum timed-two-signer-proof.cbor body-only-provider
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-wait timed-two-signer-quorum body-only-provider/db waiting-proof-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-resume timed-two-signer-quorum producer-native/db waiting-proof-receiver timed-two-signer-proof.cbor
```

The wait command requires no proof cache, preserves genesis Native state and
retains the genuine body/QC. The resume command reopens those waiting inputs,
rechecks the complete provider graph, automatically discovers and transfers the
proof through real TCP/Noise, and requires the receiver's committed/finalized
block one, independent receipts, balance, nonce and fee results. The proof file
is used only for an independent expected payload identity on the provider;
it is never uploaded or handed to the receiver as a manifest. Unexpected failures
exit nonzero; retain all partial inputs and stores. These controlled flows do
not qualify successor/fork QC AIR, historical authority provenance, all-host
fresh proof generation, public artifacts or network activation.


To exercise real partial-byte recovery and a verification worker interrupted by
normal node shutdown, use separate new receivers and a separate process for each
recovery command:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-partial timed-two-signer-quorum producer-native/db partial-proof-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-recover timed-two-signer-quorum producer-native/db partial-proof-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-worker timed-two-signer-quorum producer-native/db interrupted-worker-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-recover timed-two-signer-quorum producer-native/db interrupted-worker-receiver timed-two-signer-proof.cbor
```

The partial command observes at least three chunks received through the ordinary
automatic peer pull, then calls `Node.shutdown`. It requires an incomplete cache,
unchanged canonical rows, genesis finality and no child receipts after closing
and physically reopening the store. Its recovery preserves every retained chunk
hash and the upload generation, binds a higher nonce to a different authenticated
provider peer, and requires full verification before atomic block/finality one.
The worker command observes an actual CPU verification attempt, requests normal
shutdown and waits for the worker without committing its result. The retained
complete bytes must be ready for a new attempt; their cached state cannot
replace verification. Recovery must increase the verification-attempt count and
match the independent provider's receipts, balances, nonce and fees. Complete
cached bytes can be reverified locally without a new byte transfer.

Both commands retain a `recovery.json` checkpoint containing public manifest,
progress and chunk digests beside the receiver store. Keep that file and store
together. No proof mutation RPC, injected payload, operating-system signal or new
authority signature is used. An unexpected observation or changed checkpoint
exits nonzero and preserves all partial data. These checks cover graceful
shutdown; abrupt process loss and backend failure during a live import require
separate acceptance.


## Live backend commit failure and cold recovery

A database error returned by the native commit of a newly verified sender or
full-QC tuple is distinct from a cryptographic worker rejection. Keep the raw
proof ready without an execution receipt, pause the candidate and stop automatic
admission/discovery retries in that node process. After repairing the backend,
a normal restart reconstructs the retained source and performs complete proof
verification again before canonical mutation. Stored status or error text cannot
supply authority: a worker error that merely says "database error" remains a
proof rejection. Other proof failures and previously rejected objects keep their
existing rejection semantics; rejected historical generations are retained.

With the complete provider prepared above, run the following commands as
separate processes with a new receiver directory:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-batch-fault timed-two-signer-quorum producer-native/db batch-failure-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto-batch-recover timed-two-signer-quorum producer-native/db batch-failure-receiver timed-two-signer-proof.cbor
```

The first command uses ordinary automatic TCP/Noise transfer and full CPU
verification. A RocksDB wrapper rejects exactly one batch containing `HEAD`,
`FINALIZED` and the original certificate, while allowing proof-cache writes.
It checks every canonical row, in-memory finality, funded balances and absent
child receipts at genesis; a two-second observation must not start another
verification after the one-shot fault is disarmed. It then closes and physically
reopens the store, preserving all complete proof chunks and a `recovery.json`
checkpoint. The recovery command uses the normal backend, reopens that exact
cache and independently checks a new full verification attempt, atomic
canonical/finality one, receipts, balances, nonce and fees after physical reopen.
Neither business flow uploads, fetches or verifies through an operator proof RPC.
Unexpected failures exit nonzero and preserve the stores. This injected batch
rejection covers the native handoff and rollback path; it does not qualify
power-loss durability, persistent backend damage, protocol activation or public
binary/package delivery.


## Explicit recheck of an intact rejected candidate

An intact rejected full-QC candidate is different from a corrupted byte cache.
`admin_fetchCanonicalProof` does not replace intact content or allocate a new
generation; the explicit verification entry is `admin_verifyCanonicalProof`
with `[proofId, true]`. For an enabled full-QC live candidate, that authenticated
request validates retained source and payload identity and durably queues the
specific proof ID. It does not start an RPC-owned verifier or import a block.
`Node.run` consumes the request, reconstructs current context, claims a new full
verification attempt and clears the intent before handing a verified tuple to
the serialized canonical importer. Generation and raw chunks remain unchanged.

The immediate response reports actual cached status, which may still be
`rejected` while the intent is queued. Inspect `admin_canonicalProofAdmission`
for `explicitRecheck` or verification in progress, then wait for a higher
verification-attempt count and a verified result plus canonical receipts and
finality. Neither HTTP success nor the queued flag authorizes execution.
Unauthenticated requests and `recheck=false` cannot request this transition.
Disabled admission, a backend-paused process, an unrelated busy candidate,
corrupted bytes or an untrusted source refuse without reviving the candidate.
Unrequested rejected candidates stay rejected. Existing records omit the new
optional intent field and deserialize with no request.

For a runnable controlled case using the complete provider and generated
accounts/proof from the earlier commands:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-intact-rejection timed-two-signer-quorum producer-native/db rejected-proof-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-explicit-recheck timed-two-signer-quorum timed-two-signer-proof.cbor rejected-proof-receiver producer-native/db
```

The preparation runs genuine complete verification over normal peer transfer,
then rejects exactly the final canonical batch with a one-shot non-database
`State` error. Its valid proof remains intact and rejected under the existing
hard-failure policy; no rejection metadata is forged. The recheck uses the
existing authenticated verification RPC after the backend fault has been
removed. It verifies bearer and non-explicit refusals, requires a new complete
verification attempt before atomic block/finality one, preserves all original
chunk digests and checks receipts, balances, nonce and fees against the
independent first-block source after physical reopen. This operator recovery is
labelled explicitly and does not claim automatic migration, new-generation
fetch, public deployment or activation. Unexpected failures exit nonzero and
retain all stores.


To check that an explicit retry cannot authorize invalid cryptography, create a
separate Native first-block provider without a proof-availability cache, then run:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- receive-one timed-two-signer-quorum timed-two-signer-proof.cbor invalid-proof-provider
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-invalid-recheck timed-two-signer-quorum timed-two-signer-proof.cbor invalid-proof-receiver invalid-proof-provider/db
```

This entry copies the complete genuine proof and decreases its claimed final
cumulative total weight by one within the allowed nonzero range. Context, trace
layout and serialized STARK proof bytes remain intact; the manifest hash is
computed for the altered complete payload. Body and certificate
sync use TCP/Noise; complete proof upload and the explicit retry use authenticated
operator HTTP RPC. Both verification attempts must reject while retaining the
same generation and chunk hashes. A two-second observation must not start a
third attempt. Canonical rows, genesis balances, nonce, fees and in-memory
finality must stay unchanged, with no child receipts. After both nodes stop, a
physical cold reopen checks the persisted second refusal and consumed retry
intent. Both attempts must report a weight AIR verification error rather than a
layout, context/range or payload-hash refusal. This checks binding to public
weight inputs; it does not claim that later proof components were verified. It performs no new original signing
or proof generation. Failures exit nonzero and retain the stores.


To check orderly persistence before the event loop consumes an explicit request,
prepare a separate intact rejection using the existing provider, then run:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-intact-rejection timed-two-signer-quorum producer-native/db cold-intent-receiver timed-two-signer-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- live-cold-intent-recheck timed-two-signer-quorum timed-two-signer-proof.cbor cold-intent-receiver producer-native/db
```

The second command first runs the retained rejection without a request and
requires it to stay rejected. It then starts the real authenticated HTTP proof
control without `Node.run`, checks bearer and non-explicit refusals, and queues
`[proofId, true]`. A duplicate request must leave every stored row unchanged.
During this controlled RPC-only phase, the proof remains rejected with its old
verification count; the durable admission record alone carries the exact ID.
The server stops normally and the store is flushed and dropped. A physical cold
reopen must preserve that record, generation, every proof chunk and genesis
state, with no new verification or child receipts.

A new `Node.run` then consumes the retained request and performs complete proof
verification before canonical import. The command compares persisted receipts,
balances, nonce, fees and finalized height one with the independent Native
reference. Another live restart must not start a third attempt. It uses generated
test controls and the existing complete proof, performs no new authority signing
or proving, and exits nonzero on failure while retaining the stores. The RPC-only
phase makes the consumption boundary deterministic; it does not suspend a running
event loop or qualify power-loss durability, process crashes or network activation.


## Experimental SHA2-256f commit-signature composition

The proof-job backend also accepts a genuine SHA2-256f authority source. It
combines strict weight AIR with the existing complete FORS and seventeen-layer
XMSS/WOTS graph for each SLH signer. The explicit wide-WOTS profile retains the
original security options and all layers. Native signature checks select valid
production inputs; they never replace missing AIR certificates during proof
verification. This development extension remains experimental. A local run with
one SLH authority and one block completed all seventeen layers, bounded wire
verification, atomic Native import, authenticated RPC and TCP/Noise transfer,
and a full recheck after restart. The artifact occupied 247,550,803 bytes; its
version-two availability payload occupied 247,550,826 bytes (945 chunks of at
most 256 KiB), within the existing 256 MiB cap. Public-release acceptance, network
activation and combinations beyond the local mixed-signer and SLH history cases
described below remain open.
The current accumulator protocol and default-off admission/production settings
remain unchanged.

Lattice-only sources keep their original job binding, version-one proof and
byte-identical `commit-quorum/cbor/v1` payload. Sources containing SLH use a
separate version-two job binding and payload domain. Version two carries lattice
and SLH certificates in separate bounded lists; independently expected signer
order and algorithm select each certificate. Counts, complete inputs and every
signature graph must match before any proof-backed verifier is returned. The
shared 256 MiB availability cap and maximum sixteen signers remain unchanged;
each complete artifact must fit before availability can be claimed. Live quorum
candidate storage bounds JSON certificates by the supported signer count and
largest signature encoding, including SHA2-256f, on both receipt and restart.
The public Rust proof struct adds an optional `slh_signatures` list. Existing
Rust struct literals need `slh_signatures: Vec::new()`; its empty value is omitted
from legacy serialization.

Use fresh local test controls and a separate proof job:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare-slh slh-quorum-controls
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- inspect-slh slh-quorum-controls
cargo run --locked -p shell-stark-prover --example commit-quorum -- prove slh-quorum-controls/source.cbor slh-quorum-job slh-quorum-proof.cbor 1
cargo run --locked -p shell-stark-prover --example commit-quorum -- checkpoints slh-quorum-controls/source.cbor slh-quorum-job
```

Preparation generates temporary keys, runs an ordinary Native transfer with a
real SLH authority block/certificate and an independent follower, then discards
the private keys. It preserves signed controls before source validation. Inspect
reuses those exact controls and refuses conflicting retained sources. A component
limit applies to newly generated certificates: a bounded pause exits nonzero,
keeps verified checkpoints and does not create a complete proof output. Resume
with the same `prove` inputs and job; do not repeat preparation. `checkpoints`
replays retained components without generating missing certificates or changing
logical rows, reports the first refusal and exits nonzero while incomplete.
Neither a retained component count nor an ordinary Native certificate authorizes
full-quorum AIR import.

Only after the complete graph exists, verify and import it:

```sh
cargo run --locked -p shell-stark-prover --example commit-quorum -- verify slh-quorum-controls/source.cbor slh-quorum-job slh-quorum-proof.cbor
cargo run --locked -p shell-stark-prover --example commit-quorum -- verify-wire slh-quorum-controls/source.cbor slh-quorum-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- accept-slh slh-quorum-controls slh-quorum-proof.cbor slh-quorum-import
```

To measure new node-owned production, create fresh SLH controls and copy their
closed independent Native1 database to a new provider directory:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare-slh fresh-slh-controls
test ! -e fresh-slh-provider-db
cp -R fresh-slh-controls/control-db fresh-slh-provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-step fresh-slh-controls fresh-slh-provider-db fresh-slh-receiver 2
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-step fresh-slh-controls fresh-slh-provider-db fresh-slh-receiver 2
```

Stop if preparation or the copy fails. `producer-step` accepts a new-component
budget from one through sixteen. It starts the actual node worker with that
budget, captures the finalized canonical source, and persists each newly proved
certificate in the node-owned namespace. A budget pause must retain prior
checkpoint bytes, leave Native and sender rows unchanged, expose no proof bytes,
and survive physical cold reopen. The checkpoint byte counter includes the
logical source and indexed certificates; physical rows may use compression or
references. The example checks that logical bound against the pinned source and
index, and preserves prior physical bytes. Repeat the same command to resume from those
checkpoints; preserve the controls and provider directory. The receiver and its
sibling `fresh-slh-receiver.proof.cbor` remain absent during partial production.
A paused step is partial progress, and does not establish a complete SLH graph.

When the full graph finishes within the existing resource bounds, the command
exports the actual node-produced proof and continues through `producer-auto`.
The provider rechecks its complete graph, and a fresh real peer must discover,
fetch and verify the proof, commit/finalize block one and match independent cold
Native state. Each controlled step waits at most one hour; failed or timed-out
steps exit nonzero and retain their stores. This entry supports incremental
measurements; complete fresh-source and host coverage require actual end-to-end
results, separately from reuse of a previously complete job.

The existing `producer-seed`, `producer-disabled`, `producer-auto` and
`producer-cold` commands also accept a completed SLH job. Keep the original
job and signed controls, and copy the closed independent Native database to a
new provider directory before recovery:

```sh
test ! -e slh-quorum-producer-db
cp -R slh-quorum-controls/control-db slh-quorum-producer-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-seed slh-quorum-controls slh-quorum-job slh-quorum-producer-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-disabled slh-quorum-controls slh-quorum-producer-db unused-receiver slh-quorum-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-auto slh-quorum-controls slh-quorum-producer-db slh-produced-receiver slh-quorum-proof.cbor
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-cold slh-quorum-controls slh-quorum-producer-db slh-produced-receiver slh-quorum-proof.cbor
```

Stop if the destination already exists or the copy fails. Run these commands
only after `verify` succeeds for the complete job. Recovery verifies the
whole donor and its source before copying checkpoints into the node's separate
quorum namespace. The example derives the unique component count from that
verified job rather than assuming the two-authority lattice graph's count.
Shared SLH seed-prefix certificates can be reverified more than once, so the
reuse counter can exceed the unique checkpoint count. Cancellation, damaged
correct-hash donors, foreign sources and Native keys must still refuse without
changing destination rows.

The disabled node must retain a paused job and empty proof cache. When enabled,
the actual node worker must reverify every component with zero new proving and
produce exactly the original complete payload, including its bytes and
manifest. Availability is still `ready`, without Native authorization. A fresh
peer discovers and fetches those bytes automatically over TCP/Noise, verifies
the full proof and commits/finalizes block one. Its cold canonical rows,
receipts, balances, nonce and fees must match the independent Native provider.
`producer-cold` requires a previously complete job, starts another process and
waits to observe `queued` or `proving` before accepting a new `complete` result.
RPC can start before the cold worker requeues persisted metadata; the old
`complete` result alone cannot establish that this process reverified the graph.
The example waits at most five minutes for production and exits nonzero on a
timeout, retaining the affected stores. These commands qualify recovery of an
already complete job; fresh-from-zero production and other host/resource
combinations require their own measurements.


To exercise mixed production, `prepare-mixed` creates a new SLH authority,
funded sender and independently generated ML-DSA-65 coauthority. It retains the
original one-block SLH controls under `single-slh`, then imports that unchanged
block into two new Native references with weights `[2, 1]`. The complete
certificate includes both genuine block-hash signatures. Each reference rejects
the primary-only certificate at exactly two thirds and a damaged co-signature
without changing persistent rows or in-memory finality. It then finalizes the
valid mixed certificate and captures the independently selected source. No
private key is written to disk.

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare-mixed mixed-quorum-controls
test ! -e mixed-quorum-provider-db || exit 1
cp -R mixed-quorum-controls/control-db mixed-quorum-provider-db || exit "$?"
test ! -e mixed-quorum-receiver || exit 1
test ! -e mixed-quorum-receiver.proof.cbor || exit 1
while test ! -e mixed-quorum-receiver.proof.cbor; do
  cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-step mixed-quorum-controls mixed-quorum-provider-db mixed-quorum-receiver 16 || exit "$?"
done
```

A controlled local run of this two-authority case completed 756 components
from an empty owned job. Its version-two availability payload occupied
261,279,917 bytes, within the unchanged 256 MiB cap. A fresh peer automatically
verified both signature graphs and committed Native state and finality one;
cold canonical rows and receipts matched the independent Native reference.
A separate process reverified all 756 retained components without new proving
or Native writes. A changed proof version was refused before import. This
qualifies one static `[2, 1]` authority layout on the local ARM64 development
profile with optimization level one, debug assertions and overflow checks
enabled; other profiles, signer layouts and network activation remain open.

The same owned-job, durable component budget and cold-recheck rules apply.
Partial progress proves only the completed components. A complete step must
encode both full signature graphs under the existing 256 MiB cap, then deliver
the node-produced payload to a fresh peer through automatic discovery and
TCP/Noise. The receiver must report two proved commit signatures, execute the
transfer and persist finality one; its cold canonical rows, receipts, balances,
nonce and fees must match the independent Native provider. A byte-cap refusal
is a failed complete workflow even if individual graphs are valid. This entry
does not guarantee capacity for every signature, signer count or ordering; keep
mixed full-graph acceptance open until the complete endpoint succeeds. It does
not enable proof admission or production on a deployed network.

For a changed-state SLH historical query, prepare a new temporary authority
with signed successors before discarding its keys:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- prepare-slh-history slh-history-controls
test ! -e slh-history-producer-db || exit 1
cp -R slh-history-controls/control-db slh-history-producer-db || exit "$?"
test ! -e slh-history-receiver || exit 1
test ! -e slh-history-receiver.proof.cbor || exit 1
while test ! -e slh-history-receiver.proof.cbor; do
  cargo run --locked -p shell-node --features rocksdb --example quorum-native -- producer-step slh-history-controls slh-history-producer-db slh-history-receiver 16 || exit "$?"
done
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-history3 slh-history-controls slh-history-receiver.proof.cbor slh-history-receiver slh-history-controls/history-provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-history3 slh-history-controls slh-history-receiver.proof.cbor slh-history-receiver slh-history-controls/history-provider-db
```

Use unused destination paths in a local repository checkout and stop at the
first failed command. The preparation
command retains one-block `control.cbor`, its source, and independent Native1
stores for production. It signs blocks two and three with the same temporary
authority, advances a separate pair of Native stores, and writes
`history-control.cbor` before dropping the signing keys. The first-block source
captured at height three must equal the source captured at height one, without
writing current Native rows. Existing single-block controls cannot supply new
successor signatures after their keys have been discarded.

The loop performs real bounded production for this new source; each pause must
preserve earlier checkpoints and cold-reopen its state. It can take substantial
time. Its terminal branch exports the node-produced first-block proof and
automatically verifies/imports it on a fresh peer before the history commands
run. Do not treat a partial batch as a complete proof.

`slh-live-history3` first reimports any missing signed successors from a matching
retained prefix, then authenticates and persists all three retained
certificates on the independent Native3 provider and reference stores, advancing
finality to three. Modified signatures on certificates two and three must refuse
without changing any rows or in-memory finality. Persisting successor finality
before starting the provider prevents normal startup recovery from rewinding an
unfinalized suffix. It then disables quorum proof admission while the
receiver follows the genuinely signed Native successors and finalizes height
three. It then explicitly
reverifies the cached first-block proof through authenticated historical RPC,
checking its original root and receipts against the current canonical context.
Current balances, nonce, fees and canonical rows must agree with the independent
Native3 provider and remain unchanged by the historical query. The second
invocation starts another process and must increase the verification-attempt
counter. Only the first block has full SLH AIR in this sequence; successor
signatures and certificates use ordinary cryptographic verification. This
sequence does not establish mixed-authority capacity, abrupt-loss recovery,
other host/profile combinations, public release or network activation.

The import entry requires full AIR verification before the atomic canonical
write and compares cold persisted rows, receipts, balances, nonce, fees and
finalized height with the independent Native control. Invalid or cross-profile
proofs must leave genesis rows/finality unchanged with no child receipts. The
local single-authority sequence above has passed with the original signed
controls and complete proof, without generating replacement signatures.

Continue with real loopback nodes and the same signed controls. Run these modes
in order; `slh-live-import` requires the three chunks retained by
`slh-live-pause`, and `slh-live-cold` reopens the imported receiver:

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-pause slh-quorum-controls slh-quorum-proof.cbor slh-quorum-live slh-quorum-controls/provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-import slh-quorum-controls slh-quorum-proof.cbor slh-quorum-live slh-quorum-controls/provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-cold slh-quorum-controls slh-quorum-proof.cbor slh-quorum-live slh-quorum-controls/provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-default slh-quorum-controls slh-quorum-proof.cbor slh-quorum-default slh-quorum-controls/provider-db
```

The pause mode receives the real body and quorum certificate over TCP/Noise,
rejects unauthenticated operator requests and invalid metadata, and retains
three authenticated chunks while Native stays at genesis. The import mode
reopens that partial upload, rejects a damaged proof carrying its own correct
payload hash without changing Native state, and fetches the valid proof from
the independent provider. Success requires head/finalized height one, the full
commit-signature AIR result, and persisted rows, receipts, balances, nonce and
fees matching ordinary Native execution. The cold mode requires a new full
verification attempt and unchanged canonical rows. The default mode reaches
height one through ordinary Native sync with no proof-cache allocation or
pending proof admission. Any failed assertion exits nonzero; retain the affected
directories for diagnosis. These checks cover the single-block test conditions;
Other persistent full-SLH backend errors and mixed or multi-block combinations
remain open; the controlled one-shot and persistent final-batch checks below
are separately qualified.


To test a damaged SLH AIR with the same complete original proof, use the
independent ordinary Native reference from preparation. Its proof cache must
be empty; a provider already serving the valid proof can legitimately complete
admission before the negative upload arrives.

```sh
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-invalid-recheck slh-quorum-controls slh-quorum-proof.cbor slh-quorum-invalid slh-quorum-controls/control-db
```

This mode changes one public operation in the final XMSS layer's seed-prefix
certificate while retaining its original STARK bytes and the entire quorum
weight proof. It encodes a complete payload with its own correct hash and uses
authenticated RPC after real TCP/Noise body and certificate sync. Both the first
attempt and an explicitly authenticated second attempt must fail at SHA2 AIR
verification, with no automatic third attempt or canonical, in-memory finality,
account, fee or receipt changes. After graceful shutdown, a physical cold reopen
must preserve the same rejected generation, every chunk and the genesis state.
This single-layer witness-tamper check has passed locally; other SLH components,
metadata and physical backend errors, later-height and mixed combinations remain
separately open.


A one-shot database failure at the final canonical batch can be tested with the
same complete SLH proof. Use an empty proof cache on an independent Native1
provider and new directories, with the preparation nodes stopped:

```sh
mkdir slh-quorum-batch-provider-db && cp -R slh-quorum-controls/control-db/. slh-quorum-batch-provider-db/
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-batch-fault slh-quorum-controls slh-quorum-proof.cbor slh-quorum-batch slh-quorum-batch-provider-db
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-batch-recover slh-quorum-controls slh-quorum-proof.cbor slh-quorum-batch slh-quorum-batch-provider-db
```

The provider receives and historically verifies the original artifact through
authenticated RPC. The receiver automatically obtains the body, quorum
certificate and complete proof over TCP/Noise, without receiver upload, fetch or
verify requests. The fault mode injects one typed database error only when the
real serialized batch contains HEAD, FINALIZED and the original certificate.
Success requires no canonical rows, account or fee changes, no child receipts,
in-memory finality zero, Ready proof bytes with no authorization result, a
paused admission and no retry in that live process.

After orderly shutdown, the recovery mode checks the retained manifest, full
chunk hashes, generation and first attempt before starting the receiver again.
A new complete verification attempt must precede atomic head/finality one;
physical cold rows, receipts, balances, nonce and fees must equal the independent
ordinary Native1 provider. These modes have passed for the original single-SLH
block. The provider artifact is manually supplied; this does not qualify
node-owned full-SLH proof generation. Other persistent backend failures, abrupt power
loss, other profiles, later-height history and public-network activation remain
open.
### Persistent final-batch refusal across process restarts

The persistent variant reuses the complete SLH proof and its original signed
one-block controls. Each fault invocation keeps a controlled `Database` error
active for the complete canonical `HEAD`/`FINALIZED`/certificate batch. Other
storage operations continue normally. It requires one failed native commit per
process, no canonical or in-memory finality changes, and no child receipts.
The upload remains `Ready` with no execution result; that status is not an
authorization to commit. An unauthenticated retry returns 401, and authenticated
hot retries must report that backend repair and restart are required.

Close the control stores before copying. Run the commands as separate processes
with a fresh receiver directory, using the previously completed proof:

```sh
test ! -e slh-persistent-provider-db || exit 1
cp -R slh-quorum-controls/control-db slh-persistent-provider-db || exit "$?"
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-persistent-batch-fault slh-quorum-controls slh-quorum-proof.cbor slh-persistent-receiver slh-persistent-provider-db || exit "$?"
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-persistent-batch-cold slh-quorum-controls slh-quorum-proof.cbor slh-persistent-receiver slh-persistent-provider-db || exit "$?"
cargo run --locked -p shell-node --features rocksdb --example quorum-native -- slh-live-batch-recover slh-quorum-controls slh-quorum-proof.cbor slh-persistent-receiver slh-persistent-provider-db || exit "$?"
```

The first process fetches and verifies the proof over real TCP/Noise before
refusing its final canonical batch. The second reopens the same pending source,
verifies the retained complete payload again and refuses the batch again. Both
preserve the original generation, chunk hashes, balances, nonce and fees without
new signing or proving. Each writes a separate `persistent-attempt-N.json`
receipt while advancing the same recovery checkpoint. The final command uses
the repaired normal RocksDB backend and must perform a new complete verification
before committing Native state and finality one; cold rows and receipts must
match the independent Native provider. An earlier failed attempt or cached
`Ready` record is insufficient.

The local single-SLH-authority run completed this sequence with 951 retained
chunks: verification attempts one and two preserved Native state and finality
zero, and attempt three reached independent Native state and finality one after
backend repair. No new signature or proof generation was required.

A status query may read the old canonical mapping immediately before the native
batch publishes its new head. If fresh-source preflight then fails, the node
checks the mapping again. Only the exact candidate becoming canonical allows
validation to continue against the actual canonical body and stored certificate.
A different canonical block or malformed stored certificate still fails; cached
upload status grants no execution authority. Run the deterministic interleaving
regression with:

```sh
cargo test --locked -p shell-node --lib quorum_proof_status_survives_publication_between_source_reads
```

This controlled final-batch adapter and orderly process-restart sequence does
not establish physical device failure, simultaneous metadata-write failure,
process kill, power loss, or other algorithms and host profiles. Reproducing this
case requires all three processes to reach their stated endpoints.

### Abrupt receiver worker loss

The separate POSIX process-loss regression uses Python 3.9 or later and the
complete proof and temporary-account controls from the full-SLH workflow above.
It generates no new signatures or mathematical certificates. Use a separate
copy of the closed Native1 reference; the original controls and proof are inputs.
Build the example with the measured development profile, retaining its default
debug assertions, overflow checks and allocator:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo build --locked -p shell-node --features rocksdb --example quorum-native
test ! -e slh-crash-provider-db || exit 1
cp -R slh-quorum-controls/control-db slh-crash-provider-db || exit "$?"
python3 tests/e2e/quorum-worker-crash.py \
  --binary target/debug/examples/quorum-native \
  --controls slh-quorum-controls --proof slh-quorum-proof.cbor \
  --receiver slh-crash-receiver --provider-db slh-crash-provider-db
```

The receiver and its adjacent driver receipt/log paths must be unused. Keep all
outputs on failure; do not run the driver again against the same receiver.
The driver first starts `slh-live-crash-worker`. The provider verifies the full
proof, and a fresh receiver obtains the body, quorum and complete payload over
TCP/Noise without receiver proof-control calls. After observing the persisted
`Verifying` claim, attempt one, unchanged Native genesis and no child receipts,
the child syncs an observation file and flushes its progress line. It does not
request node shutdown or add a database flush at this boundary. The parent
sends SIGKILL only to that exact spawned child and requires its signal exit.
The claim can include payload loading; no particular inner AIR operation or
layer is asserted as the interruption point.

`slh-live-crash-recover` starts a different OS process. Before starting the
canonical event loop, it checks the same upload/fetch records, generation and
chunk digests, no cached result, and Native state zero. Recovery must perform
full attempt two before atomic Native import and finality one, matching the
independent Native reference's canonical rows, receipts, balances, nonce and
fees. A third process runs `slh-live-cold`, requiring another full verification
attempt and historical replay without current-state writes. Success requires
exit codes `[-9, 0, 0]`; a missing/foreign marker, timeout, early publication,
changed retained inputs or failed revalidation exits nonzero.

A local ARM64 run reused a complete 696-component proof and all 951 received
chunks. The three OS processes returned `[-9, 0, 0]`, with verification attempts
one, two and three respectively. Recovery and cold replay reached the independent
Native1 endpoint without regenerating the proof or changing its source.

This measures one active verification claim on a healthy local backend, with
one static SLH authority. It does not establish power-loss or torn-write
durability, every process-loss boundary, mixed-authority histories, other host
profiles, public-release acceptance or network activation.

### Mixed-authority history after state changes

`prepare-mixed-history` generates temporary SLH and ML-DSA-65 authorities with
weights `[2, 1]`, plus a funded test sender. It produces three genuine blocks
under that dual-authority configuration, selecting and configuring the assigned
base proposer for each height before sealing. Each block's certificate includes
both genuine authority signatures. The primary-only certificate at exactly two
thirds and a damaged co-signature must refuse without native or finality writes.
The preparation retains independent Native1 and Native3 store pairs and signs
all successors before discarding the temporary private keys. The first-block
source captured at states one and three must be identical without writeback.

Use the same Rust toolchain and RocksDB prerequisites as the full-SLH example.
The following commands assume the default target directory and unused output
paths. The measured development profile keeps default assertions, overflow
checks and allocator behavior:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo build --locked -p shell-node --features rocksdb --example quorum-native || exit "$?"
target/debug/examples/quorum-native prepare-mixed-history mixed-history-controls || exit "$?"
test ! -e mixed-history-producer-db || exit 1
cp -R mixed-history-controls/control-db mixed-history-producer-db || exit "$?"
test ! -e mixed-history-receiver || exit 1
test ! -e mixed-history-receiver.proof.cbor || exit 1
target/debug/examples/quorum-native producer-step mixed-history-controls mixed-history-producer-db mixed-history-receiver 2 || exit "$?"
target/debug/examples/quorum-native producer-step mixed-history-controls mixed-history-producer-db mixed-history-receiver 2 || exit "$?"
while test ! -e mixed-history-receiver.proof.cbor; do
  target/debug/examples/quorum-native producer-step mixed-history-controls mixed-history-producer-db mixed-history-receiver 16 || exit "$?"
done
target/debug/examples/quorum-native producer-cold mixed-history-controls mixed-history-producer-db mixed-history-receiver mixed-history-receiver.proof.cbor || exit "$?"
target/debug/examples/quorum-native mixed-live-history3 mixed-history-controls mixed-history-receiver.proof.cbor mixed-history-receiver mixed-history-controls/history-provider-db || exit "$?"
target/debug/examples/quorum-native mixed-live-history3 mixed-history-controls mixed-history-receiver.proof.cbor mixed-history-receiver mixed-history-controls/history-provider-db || exit "$?"
```

Preparation alone does not establish complete AIR verification. The production
loop must finish both full signature graphs within the unchanged 256 MiB bound,
deliver the node-produced payload automatically over TCP/Noise, and atomically
execute and finalize the first block on a fresh receiver. The cold production
command must observe a new recheck cycle with no new proving. Keep every store
and checkpoint if a command fails; stop at the first failure.

`mixed-live-history3` certifies both retained signatures on all three headers,
persists successor finality on the independent references, and rejects modified
successor co-signatures without changing native state. With proof admission
disabled for the ordinary signed successors, the receiver follows to height and
finality three. Authenticated historical RPC then fully verifies both first-block
AIR graphs again. Original roots and receipts, current balances, nonce, fees
and canonical rows must match the independent Native3 reference and remain
unchanged by the query. The second invocation starts another OS process and
must increase the verification-attempt counter again.

A local ARM64 run completed a new 750-component graph from an empty job. Its
CBOR artifact occupied 258,197,382 bytes and its version-two payload occupied
258,197,405 bytes, within the original cap. Automatic peer admission reached
Native1; both subsequent state-three historical queries passed, with attempts
two and three and no current-state writes. A separate cold production cycle
reverified the retained graph without new proving. Only the first block has
full commit-signature AIR; successors use ordinary genuine signatures and
certificates. This covers one static `[2, 1]` local case. Dynamic historical
committees or penalties, successor AIR, other host profiles, public release
and network activation remain separate work.


### Consecutive exact-child quorum admission

`prepare-successor` creates temporary primary ML-DSA-65 authority and sender
keys, three genuinely signed transfers and two independently executed Native3
stores. Temporary private keys are dropped after signing all three blocks. The
retained ordinary certificates finalize both independent stores before the
entry returns. `successor-source` captures block two or three's authority
context and original persisted certificate without writing Native rows. Retained
compatible two-authority controls can also supply the same entries; each proof
must match its original block exactly.

With the same Rust and RocksDB prerequisites, use unused paths and build both
examples in the measured development profile:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p shell-node --features rocksdb --example quorum-native || exit "$?"
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p shell-stark-prover --example commit-quorum || exit "$?"
target/debug/examples/quorum-native prepare-successor successor-controls || exit "$?"
target/debug/examples/quorum-native successor-source successor-controls successor-controls/provider-db successor-source2.cbor 2 || exit "$?"
target/debug/examples/quorum-native successor-source successor-controls successor-controls/provider-db successor-source3.cbor 3 || exit "$?"
target/debug/examples/commit-quorum prove successor-controls/source.cbor successor-job1 successor-proof1.cbor || exit "$?"
target/debug/examples/commit-quorum prove successor-source2.cbor successor-job2 successor-proof2.cbor || exit "$?"
target/debug/examples/commit-quorum prove successor-source3.cbor successor-job3 successor-proof3.cbor || exit "$?"
target/debug/examples/quorum-native successor-live successor-controls successor-proof1.cbor successor-proof2.cbor successor-proof3.cbor successor-receiver successor-controls/provider-db || exit "$?"
target/debug/examples/quorum-native successor-cold successor-controls successor-proof1.cbor successor-proof2.cbor successor-proof3.cbor successor-receiver successor-controls/provider-db || exit "$?"
```

Each proof job is separate and source-bound. Preserve its checkpoints on a
failure; retry that same source and job rather than regenerating keys or signed
blocks. Already complete matching proofs can be reused unchanged; only a new
source needs a new graph. The source command defaults to block two when its
last argument is omitted. The live and cold entries also retain their two-proof
form by omitting the third proof. Use a provider with no cached third proof for
that form: a matching third proof would correctly allow automatic admission.

The live entry advertises the first proof and starts a fresh TCP/Noise receiver
with quorum admission enabled throughout. Each later proof is withheld until
its body and certificate are pending; no receipts or Native state for that
child may appear yet. Verifier preflight rejects a previous block's proof and
a damaged current proof. These are local verifier rejection checks, not wire
tamper tests. After publication, automatic discovery, fetch and full verification
must precede execution and finality for that child. No receiver upload, fetch
or explicit verification command authorizes a fresh child.

The local intake index still retains at most two records. When that bound is
reached, inserting another quorum candidate can atomically replace only the
oldest role-two `Complete` record with no outstanding recheck or error. The
retired target must be finalized and canonical, have matching Native body,
receipts and original certificate, and retain matching valid native signer
evidence. Its manifest must belong to this chain and genesis. Corrupt metadata
fails closed. Pending, failed, paused, unfinalized and sender-role records do
not qualify. Retirement of duplicate local status/body/certificate rows and
insertion of the next untrusted source share one storage batch, so a batch
failure preserves the previous index and all its inputs.

Native blocks, state, receipts, certificates, signer evidence, proof cache
payloads and production jobs are retained. An old target's intake-status query
can return null after retirement; that status is not authorization. Its proof
remains available for full historical verification. At height three the entry
compares Native rows with the independently executed provider, checks every
proof payload and all original body/certificate/signer evidence, and confirms
that only the first intake record has retired. Account balances, nonce, gas,
fees, roots and receipts must agree with the independent state. Explicit hot
and separate-process cold rechecks of all three proofs increase their attempt
counters without writing current Native rows, even for the retired target.

This qualifies a bounded three-child static-context flow. The proof cache's
512 MiB/eight-object capacity and the producer's two active jobs, bounded completed history and 256 MiB checkpoint
budget remain independent backpressure limits; no proof or job eviction is
introduced here. An unbounded chain, fork or reorganization, dynamic authority
or penalty provenance, sender/proposer AIR, node-owned successor production,
public release and network activation remain separate work. The default-off
option, activation boundaries and consensus rules are unchanged.


### Node-owned successor job lifecycle

This exercise uses three separate complete checkpoint jobs. Each must match its
own retained signed block and authority context exactly. It verifies and
publishes those existing graphs through the real Node worker; it does not claim
new from-scratch proof generation in this lifecycle exercise. Use unused paths,
the Rust/RocksDB prerequisites above and these self-contained controls:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p shell-node --features rocksdb --example quorum-native || exit "$?"
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p shell-stark-prover --example commit-quorum || exit "$?"
target/debug/examples/quorum-native prepare-producer-successor producer-controls || exit "$?"
target/debug/examples/quorum-native successor-source producer-controls producer-controls/provider-db producer-source2.cbor 2 || exit "$?"
target/debug/examples/quorum-native successor-source producer-controls producer-controls/provider-db producer-source3.cbor 3 || exit "$?"
target/debug/examples/commit-quorum prove producer-controls/source.cbor producer-job1 producer-proof1.cbor || exit "$?"
target/debug/examples/commit-quorum prove producer-source2.cbor producer-job2 producer-proof2.cbor || exit "$?"
target/debug/examples/commit-quorum prove producer-source3.cbor producer-job3 producer-proof3.cbor || exit "$?"
target/debug/examples/quorum-native producer-successor-live producer-controls producer-job1 producer-job2 producer-job3 producer-lifecycle || exit "$?"
target/debug/examples/quorum-native producer-successor-cold producer-controls producer-job1 producer-job2 producer-job3 producer-lifecycle || exit "$?"
```

Preparation creates temporary two-primary-ML-DSA authorities, three genuinely
signed transfers and independent Native references before dropping private keys.
Matching complete jobs can be reused instead of generating them again. Preserve
all sources, checkpoints and proofs on failure. The lifecycle entry needs genuine
two-authority controls and refuses an existing destination in its live form.

Preparation retains a Native2 snapshot taken after actual execution and
finalization, alongside the independently executed Native3 control store. The
lifecycle creates fresh Native-only destinations from these matching snapshots;
all original databases, local cache bytes and checkpoints remain in their source
stores. It recovers the two complete jobs and lets the ordinary prover-role Node
worker fully reverify and publish them. It then shuts down and advances the
provider to the real third block through an actual TCP/Noise certified peer,
preserving proposer selection, certificate-view and timeout checks. Raw block
import does not substitute for that path. After shutdown it tests ordinary
startup capture before proving is ready.
Only this short probe uses the non-development, two-authority no-peer readiness
condition: network classification is `Testnet`, with the same chain ID, genesis,
consensus configuration, signed blocks and activation settings. This holds the
CPU worker while the third actual source must become durably queued. No third
checkpoint may be generated. The probe stops before recovering the third
complete donor. Subsequent publication and peer execution use the local
`Dev` profile and the normal readiness gate.

The next Node process fully rechecks all three jobs, including the first job
now in completed history, and publishes source-bound bytes without new proving.
A fresh TCP/Noise peer with proof admission enabled must automatically discover,
fetch and fully verify each child before Native execution and finality three.
No receiver upload, fetch or explicit fresh authorization call supplies that
path. The provider and receiver must match independently executed Native3 rows,
receipts, balances, nonce, gas and fees. Original checkpoint rows and sender
production state remain unchanged. Hot and separate-OS-process cold history
rechecks increase all three verification counters without writing current
Native state; the cold provider also fully rechecks the archived job again.

Two active jobs plus bounded completed history do not increase the existing
256 MiB checkpoint, 512 MiB cache or eight-object limits. Archive metadata and
all original job bytes remain charged. Default-off production and admission,
consensus, activation and proof formats are unchanged. This does not qualify
unbounded production, changing committees or penalties, forks, new host/profile
combinations, public release or network activation.


If the live exercise stops after the provider reaches Native3 and before a
receiver is created, preserve the directory and use `producer-successor-resume`
with the same five path arguments. It resumes the third-source readiness probe
and checkpoint recovery in that existing provider; it does not replay the
successful Native2 setup or change signed controls. The probe waits for producer
startup capture to finish because authenticated RPC can become reachable before
job capture/requeue completes. A missing third status in that initial window
is not a persistent failure. The resume form refuses a directory that already
contains a receiver; use the cold form after a completed live exercise.

### Fresh Node-owned three-source generation

The seeded lifecycle above does not establish initial source capture or fresh
generation. This separate exercise starts with empty production and proof-cache
namespaces. It needs Python 3.11 or later on POSIX, the Rust/RocksDB prerequisites
above, and the matching unreleased source:

```sh
CARGO_BUILD_JOBS=2 CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
  cargo build --locked --profile test -p shell-node --features rocksdb --example quorum-native
python3 tools/check-fresh-quorum-production.py target/debug/examples/quorum-native fresh-quorum-case
```

Use a new case directory. Preparation generates temporary signers in memory,
saves three genuine signed blocks and certificates, and independently executes
the Native controls before dropping private keys. No existing keystore, testnet
funds, complete donor job or proof artifact is an input. The initial provider is
a fresh Native-only snapshot at height 2. An actual Node session first checks
that default-off production leaves sources, checkpoints and cache empty.

Opt-in Node sessions then capture the original finalized sources and produce
their full graphs with at most sixteen newly proved components per process.
Cold sessions reverify existing checkpoints before continuing; equivalent
certificates created within this same new owner may be reused after verification.
No external completed job or reported completion flag is imported. Read-only
snapshots and every production step check preserved Native and earlier
source/checkpoint bytes. After the first two jobs complete, an actual certified
TCP/Noise peer advances the provider to height 3. Normal Node startup captures
the third source and rotates the eligible completed-job index within the same
active, total, byte and cache bounds.

The tool then uses ordinary automatic full-QC peer admission to reach Native
execution and finality 3 from fresh genesis, followed by hot and separate-process
cold historical verification after state 3. The provider, receiver and independent
Native reference must agree on rows, receipts, balances, nonce, value, gas and
fees. Historical checks must not write current Native state, and all completed
checkpoints and payloads must remain unchanged.

The underlying entries are `producer-fresh-init`, `producer-fresh-step` (with a
budget from 1 through 16), `producer-fresh-snapshot`, `producer-fresh-advance`,
`producer-fresh-peer` and `producer-fresh-cold`; each takes the retained controls
and runtime directory. Failed assertions exit nonzero with command arguments,
PIDs, exit codes and logs in the case directory. Inspect the first failure,
repair its cause and continue that same case:

```sh
python3 tools/check-fresh-quorum-production.py --resume \
  target/debug/examples/quorum-native fresh-quorum-case
```

Do not recreate signed controls, delete databases or regenerate a completed
graph. This bounded static two-ML-DSA weight-[2,1] exercise does not qualify
changing committees or penalties, forks, physical quota saturation, all host or
build profiles, public releases or network activation.

To exercise abrupt loss during initial generation, use a different new case:

```sh
python3 tools/check-fresh-quorum-production.py --interrupt-production \
  target/debug/examples/quorum-native interrupted-quorum-case
```

This form first persists two genuine components with a budget of two. A second
owned child revalidates both, then the tool sends `SIGKILL` only to that child
at the exact `Proving commit-signer-0-signature` log line. The line precedes
the new component's proving call and checkpoint write; observing it does not
identify a particular CPU instruction inside the prover. A separate offline
process must observe the durable `proving` claim with unchanged original source
and component rows, checkpoint counts and bytes, Native state and empty payload
cache. Mutable production metadata can change.

The same case then resumes through normal bounded Node sessions and completes
all three sources, automatic peer admission and hot/cold history checks above.
It uses new disposable controls and never changes a completed job into an
incomplete job. After a later failure, use `--resume` with that retained case;
the successful interruption is recorded and is not repeated. An incomplete
interruption receipt instead exits nonzero for inspection. This is a process
loss at a component dispatch boundary, not a torn-write, power-loss or
all-host guarantee.

### Live source capture from genesis

The same portable entry can start the producer at the funded genesis, with
empty source, checkpoint and proof-cache namespaces, using a separate new case:

```sh
python3 tools/check-fresh-quorum-production.py --live-genesis \
  target/debug/examples/quorum-native live-genesis-quorum-case
```

Use the matching example build above. This option and `--interrupt-production`
are separate scenarios. Preparation creates new temporary genuine signed
controls once. The reference has independently executed their three blocks;
the producer receives their bodies and certificates through an actual TCP/Noise
peer while its Node worker is already running from genesis. Native rows are
not copied into the producer. An independent default-off genesis follower
first receives all three blocks and must retain empty production and cache
namespaces, with Native state equal to the reference.

The opt-in producer uses a budget of two new components in its first process.
At Native finality 3, the first source must have a genuine partial checkpoint,
the second must be queued, and the third must remain absent while both active
slots are unfinished. Continued worker polling must preserve this deferral and
must not publish a partial proof. Subsequent bounded sessions resume the same
checkpoints; the Node captures the third source after a completed job becomes
eligible for history. No caller inserts a source, marks a job complete or
raises the active, total, byte or cache bounds.

The process then completes all three full graphs, a new automatic proof-backed
receiver through Native execution and finality 3, and hot and separate-process
cold history against the independent Native rows, receipts, accounts and fees.
The underlying additional entries are `producer-fresh-genesis-init` and
`producer-fresh-follow`, each taking the retained controls and runtime
directory. After a failure, retain the case and inspect the exact command log;
`--resume` keeps its original scenario and never repeats preparation or a
completed follow step. A partial failed initialization requires inspection.
This is live certified-peer catch-up in the stated local static profile, not
live validator transaction forging, changing committees, all-host coverage,
public release or network activation.

### Persistent refusal of the producer history index

The same controls and three complete jobs can exercise a controlled database
refusal before the third source is inserted. Use a new destination and the
Rust/RocksDB build above; no new signature graph is required:

```sh
target/debug/examples/quorum-native producer-history-prepare producer-controls producer-job1 producer-job2 producer-job3 producer-index-recovery || exit "$?"
target/debug/examples/quorum-native producer-history-fault producer-controls producer-job1 producer-job2 producer-job3 producer-index-recovery || exit "$?"
target/debug/examples/quorum-native producer-history-fault-cold producer-controls producer-job1 producer-job2 producer-job3 producer-index-recovery || exit "$?"
target/debug/examples/quorum-native producer-successor-resume producer-controls producer-job1 producer-job2 producer-job3 producer-index-recovery || exit "$?"
target/debug/examples/quorum-native producer-successor-cold producer-controls producer-job1 producer-job2 producer-job3 producer-index-recovery || exit "$?"
```

Preparation fully rechecks and publishes the first two jobs on Native2, then
follows the actual certified peer to Native3 with production disabled. It saves
the logical baseline before the third owner source exists. Each fault command
runs in a separate OS process. Its RocksDB adapter forwards ordinary operations
and persistently returns `StorageError::Database` for the complete third-source,
record, version-2 index and byte-counter batch before applying it. It checks
that this exact batch is attempted once, every logical row remains equal to
the baseline, and startup returns the backend error and releases RPC/backend
resources. The command exits zero only when this expected refusal is observed;
an unexpected error exits nonzero and preserves the directory.

The baseline and numbered `producer-history-refusal-*.json` observations are
kept without replacement. Preserve them on failure. This is a controlled
adapter refusal over a real persistent store, not a disk-corruption, torn-write
or power-loss simulation. RPC reachability alone does not establish completed
producer startup.

The resume command uses the normal backend on that same prefix. It must capture
the third source, recover its complete checkpoints and continue through the
three-job publication, automatic peer execution/finality and hot/cold historical
checks above. It neither deletes old jobs nor changes consensus, activation,
defaults or resource limits. These commands qualify the stated failure boundary;
other storage faults and process-loss boundaries need separate results.

### ML-DSA primary with an SLH coauthority

`prepare-mixed-reversed` creates new test accounts with an ML-DSA-65 primary
authority of weight two and an SLH-DSA-SHA2-256f coauthority of weight one. It
retains the signed primary controls under `single-mldsa`, then checks the
original block and full mixed certificate in two independent Native1 stores.
Preparation checks exact-two-thirds and damaged-cosignature refusals and drops
the temporary signing keys. Inspect `primaryAlgorithm`, `coAlgorithm` and
`sourceSignerAlgorithms` in its output: the source's actual signer ordering is
recorded separately from primary/coauthority role labels.

Build the example with the prerequisites above and use new paths:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p shell-node --features rocksdb --example quorum-native || exit "$?"
target/debug/examples/quorum-native prepare-mixed-reversed reversed-controls || exit "$?"
test ! -e reversed-provider-db || exit 1
cp -R reversed-controls/control-db reversed-provider-db || exit "$?"
test ! -e reversed-receiver || exit 1
test ! -e reversed-receiver.proof.cbor || exit 1
while test ! -e reversed-receiver.proof.cbor; do
  target/debug/examples/quorum-native producer-step reversed-controls reversed-provider-db reversed-receiver 16 || exit "$?"
done
target/debug/examples/quorum-native producer-cold reversed-controls reversed-provider-db reversed-receiver reversed-receiver.proof.cbor || exit "$?"
target/debug/examples/quorum-native producer-recheck reversed-controls reversed-receiver reversed-receiver.proof.cbor || exit "$?"
```

The one-block step entry uses the Node's original canonical source, certificate,
registered key and supported-algorithm validation. Its budget remains one through
sixteen new components per process, with the same immutable-checkpoint,
default-off and byte-limit checks. Preserve the controls and provider between
steps. A pause qualifies only its completed components; full acceptance requires
the actual produced artifact and automatic peer execution/finality endpoint.
This run starts with an empty owned job and does not recover a seeded graph.

`producer-cold` fully rechecks the completed provider graph in another process.
`producer-recheck` opens the already canonical one-block receiver, compares its
cold Native rows with the independent reference, checks unauthenticated request
refusal, and requests a new full read-only proof replay. Verification attempts
must increase while current Native rows, finality, balances and original payload
remain unchanged. Wrong proof version, foreign block and reordered signer source
are checked as verifier preflight refusals. The receiver remains at tip one;
later-tip replay for this role layout, other signer layouts and host/resource
profiles require their own results. These commands do not activate a network or
guarantee that every mixed graph fits the existing resource bounds.
### Abrupt loss during complete-job revalidation

After the preceding one-block production flow completes, stop the provider
before running this POSIX Python 3.11-or-newer regression. It locks the input databases
while copying them to a new directory, then operates only on those copies:

```sh
python3 tools/check-quorum-producer-crash.py \
  target/debug/examples/quorum-native \
  reverse-controls reverse-provider-db reverse-receiver.proof.cbor \
  reverse-crash-case \
  --marker 'Reverified commit-signer-1-layer-5-chain-1'
```

Choose a marker present in the successful production log for your generated
keys. The example selects a completed SLH component in the ML-DSA-primary
profile; a zero-length WOTS chain can be absent for other inputs.
The script kills only its own verifier child after observing that exact line.
It requires a non-complete persisted job after interruption, identical source,
component bytes, logical checkpoint charge, original payload and independent
Native state. It then resumes the same owner through `producer-auto`, requires
zero new proving and a real automatic TCP/Noise peer at Native/finality 1, and
runs the receiver's full cold historical verification again.

The `producer-snapshot <controls> <existing-owner-db> <complete-proof.cbor>`
entry performs the offline comparisons without running a worker. Its Ready
payload check measures availability; full proof authorization is established
by the producer revalidation and receiving node. Snapshot reads must preserve
all logical database rows.

Success prints `quorumProducerCrashRecovery: true` and exits zero. Failure exits
nonzero and leaves `result.json`, command logs and all copied databases in the
new directory. A missing marker, timeout, unexpected exit, new proving or
changed state fails the check. No input database, proof, key or dependency is
deleted. This exercises process loss after a completed component revalidation,
not interruption at an exact STARK instruction, initial checkpoint creation,
machine power loss or every signer/host profile.

### Wallet submission through a running validator

The preceding controls sign their blocks before starting the proof provider.
To exercise live transaction admission and block production, use the matching
experimental source and its CLI instead. This follows the public
[quickstart](https://shell.org/en/docs/quickstart) wallet commands and the
[operator guide](https://shell.org/en/docs/testnet-operator#node-roles)
`validator-prover` role:

```sh
cargo build --locked --release -p shell-cli --bin shell-node --features libp2p
python3 tools/check-live-wallet-quorum.py target/release/shell-node live-wallet-case
```

This Unix Python 3.11-or-newer check creates disposable ML-DSA validator and
recipient keystores, a password file and a funded Dev1337 genesis with the
operator guide's explicit `authority_pubkeys` mapping. It retains
those files. The validator is also the sender, matching the quickstart; its
balance must account for the gas fee returning through the real system reward.
The check submits one SHELL through `tx send`, waits for the live proposal and
stored quorum certificate, and compares transfer and gas-reward receipts,
balances and nonces. Malformed input and a stale signed nonce must refuse
without changing that state.

The explicit experimental profile uses WPoA, persistent RocksDB, native address
context, fee accounting and block commitments from block one, and full-QC
production. Metrics use an ephemeral loopback port for each process. These extend the quickstart's PoA, memory-backed example; they do
not change a deployed network or qualify a published binary. RPC and P2P listen
only on loopback. Empty-block production keeps its normal idle-skipping setting,
and settlement aggregation remains disabled.

The initial validator process pauses after two genuine proof components and
stops before another process opens its database. Subsequent prover-role
processes continue only missing components, at most sixteen per process.
For a bounded initial run and later continuation:

```sh
python3 tools/check-live-wallet-quorum.py --stop-after-partial \
  target/release/shell-node live-wallet-partial
python3 tools/check-live-wallet-quorum.py --resume \
  target/release/shell-node live-wallet-partial
```

A complete run also starts an independent default-off Native follower and a
fresh proof-backed receiver from the same genesis. Both must actually follow
the provider over TCP/Noise and match its finalized block, roots, receipts and
account state. The receiver must record complete proof admission and pass hot
and separate-process cold full verification without changing its Native state.
Historical verification is asynchronous: the check saves the initial RPC
response, polls to a verified terminal result and requires one new verification
attempt for each explicit recheck.
This single-block check does not establish replay after a later state change;
the multi-block history checks above cover their separately recorded layouts.

Success exits zero and prints `liveWalletQuorumComplete: true`. A partial run
prints `liveWalletPartial: true` and establishes only its two components.
Failures exit nonzero and retain `result.json`, exact CLI arguments, process
exits, command logs and all databases. Keep the same case and binary for resume;
inspect an interrupted submission before retrying it. The check neither seeds
completed proof jobs nor directly writes blocks, certificates or registry rows;
the configured authority key enters through normal CLI genesis startup.
Full proving can take hours and requires enough memory and disk for the
existing proof bounds.


For the supported SLH-DSA-SHA2-256f signing identity, select the authority and
wallet sender scheme explicitly:

```sh
python3 tools/check-live-wallet-quorum.py --validator-algorithm slhdsa \
  target/release/shell-node live-slh-wallet-case
python3 tools/check-live-wallet-quorum.py --resume \
  target/release/shell-node live-slh-wallet-case
```

This check defaults to its existing ML-DSA case; the recipient remains ML-DSA
for either authority scheme. The selected scheme is saved before key generation
and cannot change on resume. Older cases without that field retain their
original ML-DSA interpretation. The SLH case uses the CLI's existing
`key generate --algorithm slhdsa` entry and the operator guide's genesis key
mapping. It creates a distinct signing identity and preserves governance
fallback policy.

The full-QC artifact proves the actual SLH commit signature. Wallet and proposer
seal signatures also pass ordinary Native validation; their separate sender or
proposer AIR production profiles require their own results. Keep the new case
through bounded proving sessions and resume it without repeating completed
components. The same receipt, fee reward, independent peer, default-off and
asynchronous hot/cold history checks apply.

### Live sender and proposer signature proof role

The same source workflow can select the existing automatic sender/proposer
producer and admission paths. It uses a separate case and worker from quorum
production:

```sh
python3 tools/check-live-wallet-quorum.py --validator-algorithm slhdsa \
  --proof-kind sender-proposer --stop-after-partial \
  target/release/shell-node live-slh-signature-case
python3 tools/check-live-wallet-quorum.py --resume \
  target/release/shell-node live-slh-signature-case
```

This optional source workflow selects `--canonical-proof-production=true` and
`admin_canonicalProofProduction`; its independent receiver selects
`--canonical-proof-admission=true`. Keep the explicit genesis authority key and
private activation profile used by the wallet check above. The eligible case
contains one ordinary SLH wallet transaction, its block gas reward, and a
registered SLH proposer seal. The producer freezes the actual committed source
and persists bounded missing components across normal CLI restarts.

The selected proof role is saved with the case and cannot change on resume.
New cases default to `quorum`; older cases without a role field preserve that
interpretation. Scheme selection and the recipient remain as described above.
The initial partial run has no complete manifest. Continue the same directory
to the full artifact, automatic independent peer admission, and asynchronous
hot/cold verification. Each terminal historical result must report
`proved_sender_signatures: 1` and `proved_proposer_signature: true`, with the same
block, parent, state root, transaction receipts and gas as the independent
Native result. Current balances, nonces and finality must remain unchanged by
historical verification and rejected inputs.

Success prints `liveWalletSenderProposerComplete: true`. The quorum selection
retains its separate commit-signature proof and output. Defaults, proof limits,
governance policy and network activation remain as configured; each source
profile and public released artifact requires its own complete acceptance.

### Historical proof after a real later wallet transaction

Keep the completed case and its nodes offline. The same helper can copy its
closed receiver and disposable wallet controls into a separate directory, send
another real transaction, and verify the original proof against its retained
historical state:

```sh
python3 tools/check-live-wallet-quorum.py --resume \
  --history-after-advance live-slh-history-case \
  target/release/shell-node live-slh-signature-case
```

Run this after the complete sender/proposer workflow above. The source directory
stays unchanged; the tool locks its databases during the check and refuses a
running source, changed binary, unsafe destination, or destination belonging to
another source. Scheme and proof role come from the original case. The copy
keeps all keys, chain data, proof intake and command receipts; use the same
command to resume its recorded progress. An interrupted submission without a
recorded transaction hash requires inspecting the retained command log before
recovery, so it cannot silently submit a second transaction.

The second wallet transfer must finalize block 2 with balances of 998 and 2
SHELL and nonces 2 and 0. Proof production stays off. Both the hot query and a
separate-process cold query force asynchronous verification of the original
block 1 artifact and compare its sender/proposer proof result, state root and
receipts with the original Native result. The result's `tip` identifies the
current canonical view anchor at block 2; its `block` identifies historical
block 1. The later block, receipts, balances,
nonces and finality must remain unchanged, including after stale-nonce and
unknown-proof refusals. Success prints `liveWalletAdvancedHistoryComplete: true`.
This check reuses the complete artifact and matching binary; it does not prove
the second block or establish public network activation or all resource and
failure combinations.

### Rehashed inner proof tampering at the newer Native state

After the advanced-history check, the following optional regression copies its
closed receiver into another directory and reuses the actual complete artifact.
Its additional Python dependencies are `blake3==1.0.8` and `cbor2==6.3.0`:

```sh
python3 -m venv proof-check-env
. proof-check-env/bin/activate
python3 -m pip install blake3==1.0.8 cbor2==6.3.0
python3 tools/check-live-wallet-tamper.py \
  target/release/shell-node live-slh-history-case live-slh-tamper-case
```

The tested source profile is the compact frame 11/12 SLH sender/proposer
artifact. Both original CBOR roundtrips and certificate hashes must match before
mutation. The tool changes one bit in a BLAKE3 compression certificate's inner
Winterfell proof nonce, preserves framing and byte count, and recomputes both
the certificate hash and complete artifact manifest hash. It uploads the new
artifact through the real chunk RPCs and requires an asynchronous inner
`BLAKE3 compression verification` refusal, including after a separate-process
cold restart. Transport hash or payload decoding errors do not satisfy this
check. It does not generate another proof or change any quota or activation.
The nonce mutation exercises query-seed proof-of-work verification; changing
arithmetic witnesses or other proof fields requires its own evidence. Chunk
requests are paced below the default RPC rate limit. A completed download
prefix and the server's persisted upload offset are reused on resume.

The current block 2 accounts, receipts, head and finality, and the authentic
original proof intake/result must remain unchanged. The source case stays
offline and locked during copying and verification. Keep the new directory and
repeat the same command to resume; an unexpected result retains its exact
first error for inspection. Success prints `liveWalletInnerTamperRejected: true`.
This checks the stated mutation and local source profile; other proof parts,
signer combinations and original public releases require separate evidence.
