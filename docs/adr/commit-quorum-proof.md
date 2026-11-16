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
completed job, then export the same three block hashes for an installed SDK:

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

`receive-one` deliberately ends at the first genuine block and finality 1,
checking independent Native row equality, both signature graphs, strict quorum,
activation/refusal boundaries and backend-batch rollback; the second command
reopens that same first-block state. All three genuine co-signatures remain
available. Mixed-authority successor sync and historical replay after a later
state change remain required acceptance work: ordinary import of the original
single-authority block 2 does not supply the certified-view provenance required
by the new weighted proposer schedule. This check does not disable the selector
or claim the earlier single-authority three-block test covers that combination.

Current registry and address/key matching remain Native context predicates.
This does not establish historical penalty provenance or the selector in AIR,
add a consensus carrier, activate a network schedule, or replace the ordinary
wire certificate. Public release and broader profiles require separate checks.
