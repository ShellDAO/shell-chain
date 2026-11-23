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
retained candidates, a 2 MiB body, a 64 KiB QC and one active verification worker.
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
owner in a disjoint quorum namespace: two retained jobs, a 256 MiB checkpoint
quota, immutable component writes, compression and full verification on reuse.
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
activation, mixed-signer capacity and later-height SLH history remain open.
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
Persistent full-SLH backend errors and mixed or multi-block combinations remain open; the controlled one-shot final-batch check below is separately qualified.


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
persistent backend errors, later-height and mixed combinations remain separately open.


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
node-owned full-SLH proof generation. Persistent backend failures, abrupt power
loss, other profiles, later-height history and public-network activation remain
open.
