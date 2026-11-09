# STARK Aggregate Proof

> Shell Chain — Asynchronous STARK Signature Aggregation (STK block)

---

## Overview

Shell Chain uses post-quantum (PQ) signatures — either Dilithium3 or ML-DSA-65 — for every
transaction. These are large (2–4 KB each) compared to ECDSA. The **STARK aggregate proof**
compresses all per-transaction PQ signatures in a block into a single STARK proof, allowing
light clients to verify block integrity without downloading every individual signature.

The proof is generated **asynchronously** (after block sealing) to keep block latency low.
A prover node generates the proof, attaches it as a `ProofAmendment`, and propagates it via
P2P gossip. Peers store the amendment so future block importers can skip per-signature checks.

---

## Header batch source checks

On import, a present `sig_aggregate_proof` must use `SigBatchProof` version 2.
Its count must equal the block's user transaction count and its root must match
the existing shared mapper over those transactions in their original order.
These checks also apply to commitment-only headers, finalized imports, fork
admission and preferred-fork replay, before the block can be persisted.
System transactions are excluded, matching block production. An absent header
claim retains its existing behavior.

A full accumulator proof for a different batch is rejected even when its
Winterfell proof is valid. This binding does not prove the PQ signature
equations: native signature checks remain required. Complete transaction,
header and proposer-seal AIR artifacts still have separate development
verifiers and are not consumed by this header format.

Run the signed production/import and persistence regression with:

```bash
tests/e2e/header-batch-source.sh
```

It requires the repository Rust toolchain and the C/C++ and libclang tooling
used by its RocksDB feature. It generates temporary test accounts and databases,
checks commitment-only and full proof claims, rejects unrelated batches and
unsupported versions without storage changes, retains native signature
rejection, and closes and reopens the imported native state and receipts.
No pre-existing account keys or network funds are required; any failed
assertion exits nonzero. The test prints the retained database directory.

Design decision: bind the existing version-2 public inputs at the common import
check, using the same source mapper as the producer and L1 amendment validation.
This fixes acceptance of foreign claims without assigning full-signature
semantics to the accumulator proof or selecting a new proof carrier or schedule.

## Automatic complete sender proofs (unreleased)

A dedicated prover can opt into complete sender-certificate generation:

```bash
shell-node --datadir node-data run --config node.toml --db rocksdb \
  --node-role prover --canonical-proof-production
```

Use a RocksDB-enabled build, a previously initialized node with an activated
body-commitment schedule and its matching `node.toml` runtime configuration.
An eligible canonical block contains 1–16 supported ML-DSA-65 or genuine PQClean
Dilithium3 user transactions
and only gas-reward system transactions. Supported default accounts have either
a parent-registered committed key or a zero key commitment with the derived-address
predicate described below. Dilithium3 requires a bound parent-registered default
account and the raw transcript described below. Transaction types remain 0–3 and signing payloads
remain within the existing 4096-byte hash limit. AA, other signature transcripts
and other first-use account arrangements require separate producer work.
After normal production or import,
the node captures the signed body and parent account/key witnesses. Startup
also captures an eligible current head. One background worker generates the
complete mathematical graph when normal prover readiness permits work.

The feature defaults off. Its `[consensus]` configuration keys are
`canonical_proof_production` and optional nonzero
`canonical_proof_component_budget`; explicit CLI values take precedence.
`--canonical-proof-production=false` disables a configured producer. Validator
roles without proving capability and a budget without production mode are
rejected before startup. The budget counts new certificates per process;
restarting resumes and cryptographically rechecks retained certificates.
Shutdown and readiness changes pause between certificates, so shutdown may
wait for the current expensive certificate to finish.

The native database retains at most two jobs with a global 256 MiB logical
key/value checkpoint limit (64 KiB reserved for status updates). Captured
sources are bounded to 4 MiB. Completed, failed and stale jobs remain retained;
there is no automatic deletion or rotation. Capacity refusal leaves normal
canonical execution intact. A raw graph can exceed these quotas even for an
eligible block. Use a separate prover database and account for the
existing 512 MiB raw proof-cache limit plus database/backend overhead.

With the `admin` namespace enabled, query
`admin_canonicalProofProduction` with the block hash. It returns `status`, the
captured `block` and `nativeExecutionVerified: false`. A complete job exposes a
manifest; use its ID with `admin_canonicalProofStatus` and
`admin_getCanonicalProofChunk` to retrieve bounded chunks. Configure the normal
RPC API-key protection before exposing admin methods. The cache is `ready`:
a follower must independently verify the full mathematics, canonical context,
native consensus and execution before accepting the block. A producer status
or stored completion flag never authorizes acceptance.

Recovery authenticates captured MPT witnesses against independently retained
canonical headers and rechecks the committed body and raw signatures. It does
not substitute the current registry or account for the historical parent.
These retained inputs support long proving jobs after live state changes and
historical undo metadata expires. Canonical remapping refuses stale sources.
Headers and canonical mappings must remain available. This producer does not
alter the legacy 512-entry accumulator schedule, settlement rewards, pruning,
activation heights, amendment carrier or peer admission rules.

Run the expensive standalone regression with Python 3, stable Rust and the
repository's RocksDB C/C++/libclang prerequisites:

```bash
tests/e2e/mldsa-automatic-proof.sh run proof-output
tests/e2e/mldsa-automatic-proof.sh verify proof-output
```

It creates fresh funded test accounts in memory, pauses actual `Node.run`
production after three certificates, imports 129 further native blocks, and
cold resumes the remaining 58. A further process dispatches the second job
captured by ordinary import and pauses after one newly generated certificate.
It downloads the complete first graph through authenticated
RPC and checks independent CLI import and two cold proof-backed replays against
native execution. Accelerated heights and a widened local future-time window
are explicit test conditions. Private keys are not saved. Keep the output;
repeated runs retain checkpoints and command receipts, and failed assertions
exit nonzero. `verify` rechecks existing output without generating certificates.
This source feature is not a published binary or network activation.

Design: [Automatic canonical production](adr/automatic-canonical-proof-production.md).

### Unbound default-account signatures

A funded account with `pq_pubkey_hash = 0` and no custom validator can use an
Embedded ML-DSA-65 key for first use. The parent registry must either be absent
or contain exactly that key. Reference mode requires the key to be registered
at that parent. A later registry entry cannot authorize an earlier Reference
transaction.

Sender proof version 2 verifies `BLAKE3(algo_id || pubkey)` against the full
32-byte sender address in AIR, together with the actual parent account MPT,
signing source, transaction ID, leaf and complete signature. It reuses the
existing `tagged_key` certificate field; no new hash primitive or checkpoint
layout is introduced. Version 1 still requires a bound registered account and
retains its existing wire bytes and rotated-address behavior. Historical registry
selection, activation, funds, nonces and atomic key registration remain Native
policy. Missing or rejected proofs never become authorization through a status
flag or native signature fallback.

Run the expensive regression with the same prerequisites as the full proof entry:

```bash
tests/e2e/mldsa-full-proof.sh first-use first-use-test
tests/e2e/mldsa-full-proof.sh verify first-use-test
```

It creates a fresh funded unbound account and a distinct proposer with memory-only
keys, executes two Embedded transfers, then uses Reference successors. Real
missing-key, wrong-address and insufficient-funds controls leave the registry
unchanged. A separate Native crypto control checks fresh first-use registration
rollback after execution reaches a wrong signed root; it is not proof admission.
The peer path independently verifies complete sender/proposer AIR, commits and
finalizes the valid child, and refuses a signed wrong-root Reference child after
both VM transactions with all Native data unchanged. Genuine foreign-key and
raw-key-hash certificates cannot replace the sender or address predicate.
Shutdown/resume and cold read-only replay after ordinary successor execution
retain all sources and proofs. Account MPT shapes can change certificate counts
between the two jobs; the complete consumer predicates and execution results
decide acceptance. Existing quotas and activation settings are unchanged.

The mixed full-batch entry creates sixteen independently funded sender keys and
a distinct proposer. Eight senders start bound and registered in Reference mode;
eight start unbound and unregistered in Embedded mode:

```bash
tests/e2e/mldsa-full-proof.sh mixed-first-use mixed-first-use-test
tests/e2e/mldsa-full-proof.sh verify mixed-first-use-test
```

It reconstructs the eight/eight genesis independently and checks both sender
proof versions in each complete graph. The valid first child registers the eight
fresh keys. A later all-Reference signed wrong-root child must pass full AIR and
execute all sixteen VM transactions before refusal without Native writes. The
ordinary correct successor changes current state for cold historical replay.
Genuine foreign-key/address certificates and an altered intermediate Keccak lane
must fail. Existing checkpoint, payload and transport limits remain in force;
this isolated regression does not establish other account distributions,
sustained capacity, publication or network activation.

Design: [Unbound default-account signature proofs](adr/unbound-default-signature-proofs.md).

## Ordinary peer admission with complete proofs (unreleased)

A follower can select complete sender verification for supported fresh extensions:

```bash
shell-node --datadir follower-data run --config node.toml --db rocksdb \
  --node-role prover --canonical-proof-admission
```

It defaults off; `[consensus].canonical_proof_admission` and explicit
`--canonical-proof-admission=false` follow the normal config/CLI precedence.
Use matching initialized genesis/runtime configuration, an activated body
commitment schedule and a dedicated proof-capable network implementation.
Supported blocks have 1–16 supported default-account ML-DSA-65 or bound genuine
PQClean Dilithium3 senders,
transaction types 0–3, signing payloads up to 4096 bytes, gas-reward system
transactions only, and a serialized body up to 2 MiB. Unsupported profiles use
the existing native path. Selected candidates wait for a full proof; rejected
proofs do not silently fall back to native sender verification.

Normal block gossip or synchronization stages the untrusted body, discovers an
available manifest from a compatible peer, resumes bounded chunks and verifies
full AIR. Native consensus and execution still decide acceptance. Canonical
commit runs on the node event loop after a fresh parent/context check. No admin
fetch or import command is required. Producers can serve `ready` graph bytes;
ready/verified metadata never replaces the receiver's complete verification.
Discovery uses authenticated protocol version 2 capability advertisements;
legacy chunk protocol version 1 remains offered and receives no new frames.

At most two bodies remain retained, including complete and failed candidates.
The separate raw cache remains bounded to 512 MiB with its existing object and
immutable-generation limits. Two distinct manifests and one hash-corrupt
recovery per candidate are allowed; there is no automatic eviction. A peer can
withhold a graph, and a valid graph can still exceed capacity. Shutdown joins an
in-flight verifier and pauses before native commit. Cold restart independently
rechecks retained bytes and native context. With an authenticated `admin`
namespace, `admin_canonicalProofAdmission` takes a block hash and reports local
status and native canonical membership; status is not authorization.

Run the expensive self-contained regression with Python 3, stable Rust and the
repository RocksDB prerequisites:

```bash
tests/e2e/mldsa-live-peer-proof.sh run proof-output
tests/e2e/mldsa-live-peer-proof.sh verify proof-output
```

A new output first creates fresh signed test accounts and the complete source
graph through the automatic producer regression. Two actual nodes then use
ordinary synchronization and dedicated proof discovery/transfer. The receiver
stops after three chunks without canonical mutation, cold resumes the same
immutable chunks, commits through native execution and performs two cold full
proof replays against independent native receipts and balances. A second isolated
receiver rejects a correctly hashed graph with damaged key AIR despite genuine
raw signatures, without canonical writes. It also cold-rechecks a stale verifier
record and a forged local verified-cache receipt; neither authorizes admission.
The provider then automatically resumes the captured second sender job and
publishes its distinct complete graph. The follower receives and verifies it
through normal peer intake. A deliberately held suffix response freezes the
follower at height 2 for a full read-only proof replay; releasing that response
allows ordinary synchronization through the remaining signed empty blocks to
local height 130. Cold checks compare every canonical body/hash/receipt and
latest accounts with independent native execution. A historical proof query
outside the existing 128-block parent-view bound must refuse without writes;
the earlier height-2 replay records the complete mathematical verification.

A separate fresh receiver then exercises gossip-only intake. The provider
broadcasts the genuine signed first block over libp2p gossip while the test
suppresses every direct `NewBlock` and `BlockResponse`. Dedicated authenticated
proof discovery and chunk transfer remain real. Native commit must match the
independent execution, followed by two cold full-proof replays without writes.
To exercise only this route with an existing output containing the captured
native source and complete first graph, use
`tests/e2e/mldsa-live-peer-proof.sh gossip output`; use `gossip-verify` for a cold
recheck. The focused mode never regenerates certificates. Retain an incomplete
gossip fixture and inspect its command receipt before starting another attempt.

Private keys are not persisted; command receipts and output remain available.
Proving can take hours. Checkpoint component counts and follower height are
written to `network/sync-progress.json`; allow four hours overall and up to
30 minutes without component/head progress before the test refuses. These are
explicit local test bounds and accelerated heights. `run` resumes the retained
second job without regenerating the completed first graph. `verify` cold-checks
the latest completed native state without generating certificates. Any assertion
failure exits nonzero. This limited profile does not establish fork/amendment handling,
full proposer AIR, multi-sender load behavior or a published/activated network.

Design: [Live canonical admission](adr/live-canonical-proof-admission.md).

The opt-in full signature profile adds primary ML-DSA-65 or genuine locked
PQClean Dilithium3 proposer-seal and header-hash
AIR to the registered sender graph. Its payload version 2 requires a full seal;
version 1 remains sender-only with native proposer verification. Current
consumers on both peers are required for version 2. Native authority selection,
algorithm policy, consensus, fees and atomic execution remain mandatory.

Run `tests/e2e/mldsa-full-proof.sh run output` for a fresh isolated full-profile
regression, or `verify output` to cold-recheck retained results. It requires the
same Python 3, stable Rust and RocksDB prerequisites. The script creates fresh
test accounts and test funds, keeps private keys only in memory, pauses a real
producer through shutdown, resumes verified checkpoints and imports the full
graph through ordinary peer intake. It checks native receipts/accounts, full
read-only replay after current state changes, correctly hashed bad proposer AIR,
missing/version-mismatched seals and native authority rejection. The later
ordinary native block is an explicit historical-state control, not another
proof-admitted block. Any failed assertion exits nonzero.

Generating 118 components can take hours. The bound is six hours overall or
30 minutes without component/admission progress, recorded in
`network-full/progress.json`. Retain the output to resume or inspect its command
receipts. The existing 256 MiB global checkpoint and per-payload bounds apply;
multi-sender load, full validator-selection AIR, other algorithms and network
activation are not established by this local profile.

After a completed full run, execute
`tests/e2e/mldsa-full-proof.sh consecutive output` to continue with its retained
genuinely signed second block. This creates separate local stores and a fresh
genesis receiver; it rechecks common key-dependent certificates, generates the
new signature/message-dependent proofs, and checks two full native peer imports,
finality, independent receipts/accounts and cold historical replay. Private keys
are not required for the continuation. The single-authority test submits the
retained proposer signature as a genuine vote over the same block hash.

The two-job profile shares immutable certificate bytes through checked one-hop
references. Its 256 MiB global checkpoint quota and 512 MiB transport-cache quota
remain unchanged. Donor source/certificates must remain byte-for-byte intact;
corrupt reference recovery must refuse before generating new proofs or writing
native state. `verify output` rechecks the consecutive result when present.
This bounded two-job case does not establish indefinite capacity or eviction.

## Registered prover activation

The unreleased `prover_registry_height` schedule enables the canonical registry
and registered-only proof admission and settlement. It is disabled by default;
existing networks must schedule a future height consistently across peers. Both
standalone provers and validator-provers need a separate registry entry after
activation. See [ProverRegistry](PROVER_GUIDE.md#proverregistry) for the exact
public-key governance request, quorum and finalized-state checks. A proof's
counter increments only during successful settlement, using execution-local
registry state on producers, importers and historical replay.

## Architecture

```
  Block Producer
  ─────────────
  1. Seal block (header + transactions, no proof yet)
  2. Broadcast block immediately → fast finality

  Prover Service (ValidatorProver node role)
  ─────────────────────────────────────────
  3. Receive sealed block from internal channel
  4. Extract PQ signatures from witness bundle
  5. Run STARK batch proof over all signatures
  6. Wrap in ProofAmendment { block_hash, block_number, proof, prover, prover_signature }
  7. Store in ProofAmendmentStore (key: "pa/<block_hash>")
  8. Broadcast amendment via P2P gossip

  Peers
  ─────
  9.  Receive amendment gossip
  10. Verify prover_signature, check prover is registered
  11. Store in local ProofAmendmentStore
  12. Optionally prune raw witness bundle (proof_replacement_grace window)
```

---

## ProofAmendment Format

```json
{
  "version": 1,
  "block_hash": "0x...",
  "block_number": 12345,
  "proof": {
    "batch_root": "0x...",
    "batch_root_bytes": "...(hex)...",
    "proof_bytes": "...(hex STARK proof)..."
  },
  "prover": "0x<PROVER_ADDRESS_64_HEX>",
  "prover_signature": "...(hex PQ signature)..."
}
```

Fields:
| Field | Type | Description |
|-------|------|-------------|
| `version` | `u8` | Protocol version. Current: `1`. |
| `block_hash` | `ShellHash` | Hash of the block this proof covers. |
| `block_number` | `u64` | Height of the block (allows cheap range queries). |
| `proof` | `SigBatchProof` | STARK batch commitment proof over all tx signatures. |
| `prover` | `Address` (`0x` + 64 lowercase hex) | The prover's registered address. |
| `prover_signature` | `Bytes` | PQ signature over `"proof-amendment" ‖ block_hash ‖ block_number_le ‖ proof.batch_root_bytes`. |

---

## Node Roles

| Role | Behavior |
|------|----------|
| `Validator` | Produces and validates blocks. No proving. |
| `ValidatorProver` | Produces blocks AND runs ProverService concurrently. |
| `Prover` | Dedicated prover: does not produce blocks, only generates proofs. |

To enable proving, start the node with:

```bash
shell-node run \
  --node-role validator-prover \
  --enable-stark-aggregation \
  --keystore authority.json
```

`--enable-stark-aggregation` defaults to **`false`**. Ordinary validators should
stay on `--node-role validator` and leave local proving disabled. Run proof work
only on a dedicated `prover` node or on an explicitly sized `validator-prover`
node.

---

## RPC Interface

### Check if a block has a STARK proof

`eth_getBlockByHash` and `eth_getBlockByNumber` responses include:

```json
{
  "sigAggregateProof": "0x...",
  "sigAggregateProofSize": 4096
}
```

These fields are `null` when no proof has been generated yet. The RPC handler automatically
falls back to the `ProofAmendmentStore` if the block header's inline proof field is `None`.

### Fetch a proof amendment directly

```bash
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"shell_getProofAmendment","params":["0x<block_hash>"],"id":1}'
```

**Response (proof present):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block_hash": "0x...",
    "block_number": 12345,
    "proof_version": 1,
    "prover": "0x<PROVER_ADDRESS_64_HEX>",
    "proof": "0x...(hex STARK bytes)..."
  }
}
```

**Response (no proof):** `"result": null`

---

## Storage and Pruning

Proof amendments are stored under the key prefix `pa/<block_hash>` in the chain KV store.
The `ProofAmendmentStore` provides:

| Method | Description |
|--------|-------------|
| `put_amendment(block_hash, bytes)` | Store serialized amendment. |
| `get_amendment(block_hash)` | Retrieve raw bytes. Returns `None` if not found. |
| `has_amendment(block_hash)` | Check existence without deserializing. |
| `delete_amendment(block_hash)` | Prune (e.g. after archival compression). |

When a proof amendment arrives for a block, the node can optionally delete the raw
witness bundle if the storage profile is not `"archive"` and the
`proof_replacement_grace` window has elapsed. Challenges for a proof stay `Open` for at most `T_c = 7200` blocks; a valid response marks them `Resolved`, while a timeout marks them `Slashed` and triggers prover slashing.

---

## Metrics

| Metric | Description |
|--------|-------------|
| `stark_amendments_queried_total` | Incremented each time `shell_getProofAmendment` returns a non-null proof. |
| `shell_stark_settlements_accepted_total` | STARK settlement transactions accepted into chain state (v0.22.x). |
| `shell_stark_settlements_rejected_total` | STARK settlements rejected due to ordering, layer, or frontier violations (v0.22.x). |
| `shell_stark_pending_settlements` | Generated amendments waiting for canonical settlement. The prover admission window is limited to two. |
| `shell_stark_amendments_rate_limited_total` | Authenticated amendments rejected because the settlement window or per-prover rate limit was exhausted. |
| `shell_stark_frontier_lag` | Blocks between the chain tip and the highest continuously-settled STARK layer. Alert if > 100 (v0.22.x). |

Proving is disabled until the node passes its synchronization and readiness
gates. Alert when pending settlements remain at the limit while the frontier
does not advance, or when the rate-limited counter grows continuously. Do not
raise admission limits until block propagation and settlement are confirmed
healthy.

---

## Challenge lifecycle

The challenge path is now an explicit lifecycle:

```text
OPEN --(valid ChallengeResponse)--> RESOLVED
OPEN --(timeout at 7200 blocks)--> SLASHED
```

Nodes create an `Open` record when they emit `ProofChallenge`, resolve it when proof bytes validate, and slash the responsible prover if the record is still open after the timeout.

### Restart recovery (unreleased)

The node stores challenge records, their original opening heights and terminal
states in its database. Restarting with the same database preserves the original
7200-block deadline. Timeout status and the resulting absolute consensus penalty
are committed together; failed writes leave both in-memory states unchanged.
Recovery restores the penalty instead of applying another percentage reduction.
Later equivocation penalties update the same snapshot, so recovery cannot replace
them with an older challenge penalty. Terminal-record garbage collection retains
the penalty snapshot.

These are local protocol observations, not canonical transaction state: a head
rewind does not reopen a resolved challenge or reset its original deadline.
A malformed persisted snapshot prevents network startup. This recovery support
requires a build containing the change; it does not retrofit records lost by an
older node before upgrading.

Run the database process-recovery and failed-write regressions with:

```bash
cargo test -p shell-node --features rocksdb challenge -- --nocapture
```

## Security Model

1. **Prover registration** — Only nodes registered in the `ProverRegistry` system contract
   can submit valid amendments. The `prover` field must match a registered address.
2. **Prover signature** — The amendment carries a PQ signature from the prover's key.
   Verifiers check `sig over (block_hash ‖ block_number ‖ proof.batch_root_bytes)`.
3. **STARK soundness** — The STARK proof itself proves that all transaction signatures in
   the block are valid PQ signatures without revealing the raw signatures.
4. **Amendment ordering** — Only one amendment per `(layer, source_hash)` pair is stored (tracked by `SettledSourceIndex`, `ss/` key prefix). A settlement from a lower-priority prover cannot overwrite one from a higher-priority prover. The index is rebuilt from genesis on first v0.22.x boot.

---

## Multi-Layer Settlement (v0.22.x)

v0.22.x introduced **recursive multi-layer STARK compression** with three compression layers:

| Layer | Description |
|-------|-------------|
| **L1** | Per-block STARK proofs over raw PQ signatures (`ProofAmendment`) |
| **L2** | Epoch-level STARK proofs recursively compressing L1 proofs from an epoch |
| **L3** | Long-horizon STARK proofs recursively compressing L2 epoch proofs |

Settlement pairs `(layer, source_hash)` are durably tracked in `SettledSourceIndex` (RocksDB key prefix `ss/`). On first boot after upgrading to v0.22.x, the index is rebuilt from genesis — expect a one-time warmup delay.

StarkReward system transactions (`shellType: "starkReward"`) carry settlement payloads and appear as ordinary transactions in blocks. The `decodedInput` field in `eth_getTransactionByHash` responses describes the settlement layer and source range.

---

## References

- `crates/stark-prover/src/amendment.rs` — `ProofAmendment` struct
- `crates/stark-prover/src/proof.rs` — `SigBatchProof` struct
- `crates/node/src/prover_service.rs` — `ProverService` implementation
- `crates/storage/src/chain_store.rs` — `ProofAmendmentStore` (line ~983)
- `crates/rpc/src/handler/shell_api.rs` — `shell_getProofAmendment` RPC


### Compact large canonical proof jobs (Unreleased)

New jobs above two transactions use bounded compact certificate bytes and share
only source-matched identical inputs. Stored unique checkpoints and all recipient
AIR checks are counted separately. Legacy jobs keep their original bytes; this
adds no automatic migration or eviction. The 256 MiB payload/per-job/global
checkpoint and 512 MiB transport bounds remain unchanged. Availability packing
is not recursive proof compression or evidence of native execution.

Producer, cached RPC verification, peer intake and offline import accept the new
versioned encoding. The offline producer writes `proof.cbor` for compact jobs and
reports that filename; legacy `proof.json` remains unchanged. Use compatible
source builds at both ends. The native importer still enforces authority,
activation, ordered nonce, gas, fees, receipts and resulting state root.

Run the expensive isolated sixteen-transfer acceptance with Python 3, stable Rust
and the repository's RocksDB prerequisites. The entry builds an optimized local
verifier with Cargo's release profile for the expensive proving work:

```sh
tests/e2e/mldsa-full-proof.sh wide full16-test
tests/e2e/mldsa-full-proof.sh verify full16-test
```

The test creates and funds its own temporary accounts, uses one registered sender
and a distinct proposer, preserves real shutdown checkpoints, and checks all 17
receipts, nonce 16, gas 336,000, balances and finality against native execution.
It also requires atomic refusal of a genuinely signed wrong-root sixteen-transfer
successor and cold historical replay after a correct ordinary successor. Keys are
not saved. Repeating `wide` continues retained inputs; `verify` creates no proofs.
These are source acceptance commands, not public package, arbitrary key layout,
throughput or network activation claims.

For two independently registered sender keys, use a separate fresh directory:

```sh
tests/e2e/mldsa-full-proof.sh mixed mixed16-test
tests/e2e/mldsa-full-proof.sh verify mixed16-test
```

This profile executes eight transfers from each sender with a distinct proposer.
The priority caps are one and two; both effective gas prices are capped at two.
Both senders must reach nonce 8, and then nonce 16 after the separately labelled
ordinary successor. Independent genesis reconstruction funds and registers both
keys. All 17 receipts, value, fees, proposer reward, finality, wrong-root atomic
refusal and read-only historical replay must match native execution. Shared
certificates may cross positions or jobs only for identical inputs; different
keys require different AIR certificates. This two-key experiment does not qualify
every possible sixteen-key layout or throughput. It also replaces one sender's
key certificate with the other sender's valid certificate, rebuilds correct
content hashes, and requires native proof verification to refuse it without
changing any stored data. Repeating `mixed` resumes its
retained inputs; `verify` never generates proofs.

Matrix certificates in checkpoint version 2 jobs use SHAKE version 2: each group of at
most eight Keccak permutations has one aggregate AIR proof. Every input lane,
all 24 rounds, permutation order, sponge links and rejection-sampling result
remain constrained. Aggregation uses a separate public-input domain; empty
standalone proof fields carry routing states only and never authorize acceptance.
Legacy SHAKE version 1 certificates remain readable and retained equal-input
checkpoints are reverified rather than regenerated. Other proof stages retain
their existing statements. This reduces matrix proof bytes without raising
checkpoint limits; arbitrary sixteen-key and sustained-job capacity still need
separate acceptance.

Exercise sixteen transfers from eight independently registered sender keys with
a distinct proposer in another fresh directory:

```sh
tests/e2e/mldsa-full-proof.sh eight-keys eight-key-test
tests/e2e/mldsa-full-proof.sh verify eight-key-test
```

Each sender executes two transfers, reaching nonce 2 and then nonce 4 after the
ordinary successor. The entry checks independent native accounts, all receipts,
fees, reward, finality, durable pause/resume, wrong-root rollback and cold history.
It also recomputes correct availability hashes after changing an intermediate
Keccak lane while retaining the genuine aggregate proof, and requires the native
reader to reject it without state or original-proof writes. These source
experiments require fresh in-memory test keys and no network funds. Repeating
`eight-keys` resumes its retained inputs; `verify` generates no proofs.

New jobs with more than eight distinct senders use checkpoint version 3 and
complete matrix version 2. All thirty ordered coordinates share sampler and
sponge AIR proofs in groups of at most eight streams. Their permutation states
are flattened in that same coordinate order into groups of at most eight full
Keccak permutations. Separate public-input domains bind each count and ordered
statement. The complete matrix verifier requires every sampler, sponge and
permutation group; individual version 2 polynomials and version 3 SHAKE routing
objects have no standalone proof authority.

The producer persists each proof part separately, reconstructs routing only on
the prover, and verifies every recovered or borrowed part against its exact
inputs before continuing. The native reader verifies all AIRs without native
SHAKE or sampling as a substitute. Existing checkpoint versions 1 and 2 retain
their original bytes and layout, including when reopened by the newer producer.
No checkpoint, payload, job-count or transport quota is increased.

For sixteen independently registered senders, each making one transfer, and a
distinct proposer, use a separate fresh directory:

```sh
tests/e2e/mldsa-full-proof.sh sixteen-keys sixteen-key-test
tests/e2e/mldsa-full-proof.sh verify sixteen-key-test
```

This source acceptance profile requires all sixteen sender nonces to reach one,
then two after the ordinary successor, with all seventeen receipts, balances,
gas, fees and proposer reward matching independent native execution. It retains
the same wrong-root rollback, key-substitution and intermediate-lane rejection,
shutdown/resume and cold historical replay checks. Repeating `sixteen-keys`
continues the retained inputs; `verify` generates no proofs. Published artifacts,
network activation, other signature profiles and sustained load require their
own acceptance evidence.

### Stable account identity after key rotation

```sh
bash tests/e2e/mldsa-full-proof.sh rotation output
bash tests/e2e/mldsa-full-proof.sh verify output
```

This expensive source regression creates fresh memory-only ML-DSA-65 keys and
independent Native databases. It proof-admits an AccountManager rotation from
K0 to K1, then a Reference transfer signed by K1 at the original account address.
The isolated network activates `registered_key_algorithm_height` at height 1;
the second proof binds the stored algorithm-tagged commitment while the first
uses the legacy raw commitment at genesis. Both sender and proposer signatures
require complete AIR, and both targets must reach Native import and finality.

An ordinary further rotation to K2 changes the current registry before cold
replay of both proofs. Replays must preserve current Native data and resolve
the historical K0 and K1 keys. A genuine old-key certificate must not authorize
the new-key transfer. Separate ordinary Native controls check default-disabled
raw commitments, stale signatures and atomic rollback of a signed wrong-root
rotation; those controls are not claimed as proof admission. The output directory
retains public signed inputs, proof checkpoints and command receipts. This
exercise does not activate a public network or establish other algorithms,
custom validators, same-block rotation sequences or release availability.

Use the default-disabled raw binding without scheduling an activation:

```sh
bash tests/e2e/mldsa-full-proof.sh rotation-raw raw-output
bash tests/e2e/mldsa-full-proof.sh verify raw-output
```

This mode requires the same complete proof, Native import/finality, stable address
and changed-current-key historical replay endpoints. Both rotations retain
`BLAKE3(pubkey)`; neither proof carries a `tagged_key` certificate. The ordinary
Native control remains distinct from these two proof-admitted targets. Both modes
refuse an output prepared for the other activation choice, preserving its keys,
signed inputs and checkpoints. This source exercise leaves public network
configuration unchanged.

### Genuine PQClean Dilithium3 sender proofs

```sh
tests/e2e/dilithium-full-proof.sh run dilithium-output
tests/e2e/dilithium-full-proof.sh verify dilithium-output
```

Use Python 3, stable Rust and the RocksDB C/C++/libclang prerequisites above.
This expensive source regression generates a `DilithiumSigner` sender and an
independent ML-DSA-65 proposer, retaining only public signed inputs. It pauses
and resumes the complete graph, requires peer Native import and finality, and
checks receipts, fees and balances against ordinary Native execution. An
ordinary signed successor changes current balances and nonce before three cold
historical replays check that the full proof does not write current state.
Genuine foreign key, FIPS challenge and commitment certificates, and a relabelled
profile must be refused. A separate signed wrong-root ordinary Native control
checks rollback; it is not proof admission. Keep the output to resume; failed
assertions exit nonzero and `verify` generates no new certificates.

The supported sender transcript is the implementation in locked
`pqcrypto-dilithium 0.5.0`: a 1952-byte key, 3309-byte signature, 48-byte
c-tilde, a SampleInBall seed restricted to its first 32 bytes, and
`mu = SHAKE256(tr || message, 64)` without FIPS empty-context framing. All 48
c-tilde bytes still participate in the final commitment check. The sampler has
a separate AIR domain and version 2; full signature and outer transaction
proofs also use version 2, and the registered-account sender profile is version
3. Existing FIPS version-1 proofs and unbound ML-DSA-65 profile 2 keep their
meaning. Shared key, matrix and NTT arithmetic is reverified against exact
inputs; tagged-key checkpoints also require an equal algorithm tag.

The Native tag-zero verifier continues accepting its existing SDK ML-DSA
adapter. That adapter, unbound Dilithium3, AA and custom
validators require separate proof profiles. Unsupported live candidates retain
ordinary Native handling; selected full-proof candidates require complete AIR
without Native signature fallback. Production/admission defaults, quotas,
activation schedules and public release availability remain unchanged.

### Genuine PQClean Dilithium3 proposer proofs

```sh
tests/e2e/dilithium-full-proof.sh proposer proposer-output
tests/e2e/dilithium-full-proof.sh verify proposer-output
```

This mode uses a fresh primary ML-DSA-65 registered sender and a distinct genuine
`DilithiumSigner` proposer. It requires the same toolchain and full mathematical,
peer Native import/finality, receipt/fee/balance, pause/resume and changed-current-
state historical replay endpoints as the sender mode. Genuine primary sender
certificates cannot replace the raw proposer's key, challenge or commitment;
changing the raw signature proof to the FIPS version must also refuse. Mode
selection refuses outputs prepared with the opposite algorithm roles before
opening nodes or generating keys. Keep the output; `verify` generates no proofs.

Proposer seal proof version 2 selects the genuine locked raw transcript, with
signature/challenge version 2 and the 32-byte sampler seed described above.
Proposer proof version 1 retains primary FIPS semantics. The payload remains
version 2 with a required complete seal and header proof. Native authority and
parent-registry selection remain independent of that proof, and the opaque
verifier checks policy for the actual seal algorithm. A retired algorithm or
changed input tuple has no Native signature fallback.

The initial ordinary Native control explicitly disables automatic capture; its
separate source collection records the original missing full-proposer result.
Repaired acceptance enables actual automatic production on the same original
Native provider head. Private keys, signed inputs and databases are preserved.
Previously captured version-1 sender-only jobs retain that meaning; they are not
silently rewritten into full proposer jobs. SDK FIPS-adapter proposer signatures
under tag zero still use the older sender-only profile. Both-Dilithium roles,
other account arrangements and public artifacts/network activation require
separate acceptance evidence.
