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
adapter. Bound SDK signatures have the distinct profile described below;
unbound raw signatures use profile 4. AA and custom validators require separate
proof profiles. Unsupported live candidates retain
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
silently rewritten into full proposer jobs. Previously captured SDK FIPS-adapter sender-only sources retain that scope;
new full SDK proposer jobs use the distinct profile below. Other account
arrangements and public artifacts/network activation require separate acceptance
evidence.


### Genuine Dilithium3 sender and proposer together

```sh
tests/e2e/dilithium-full-proof.sh both both-output
tests/e2e/dilithium-full-proof.sh verify both-output
```

This source regression creates distinct genuine `DilithiumSigner` keys for the
registered sender and proposer, with optional registered-key algorithm binding
left disabled. Both signatures use the locked raw transcript described above:
sender profile 3, transaction/signature/challenge version 2, and proposer seal
version 2. It keeps the same prerequisites, limits and pause/resume behavior.
The original signed Native transfer, quorum and ordinary successor are retained;
automatic production and a separate peer must consume the complete graph and
reach Native import/finality. Receipts, gas, fees, balances and nonces must match
ordinary execution. Cold historical replays after the successor advances current
state must preserve every current database row.

The negative checks substitute the genuine sender's key, challenge and final
commitment certificates into the distinct proposer's graph, then separately
relabel the raw signature as FIPS. Each correctly hashed payload must fail the
full historical predicate without changing original proof bytes or Native data.
These checks are distinct from new block imports and the ordinary signed
wrong-root rollback control. `run`, `proposer` and `both` reject retained outputs
with different algorithm roles before opening nodes or replacing keys or proofs.
`verify` accepts any of those retained role profiles without generating proofs.
This bounded source regression does not change public release or network
activation status, defaults, quotas, or other account and SDK-adapter profiles.


### Unbound genuine Dilithium3 signatures

```sh
tests/e2e/dilithium-full-proof.sh unbound unbound-output
tests/e2e/dilithium-full-proof.sh verify unbound-output
```

With the same Python, stable Rust and RocksDB prerequisites, this source entry
creates a funded zero-commitment default account at the genuine Dilithium3
address and a distinct primary ML-DSA-65 proposer. Keys exist only in memory.
The sender initially has no parent registry entry: its first block uses Embedded
mode, and the next block uses the newly registered Reference key. Both original
signed blocks require complete sender/address/proposer AIR, real peer Native
import and finality through height 2. A separately signed ordinary third block
changes current state before cold full replay of both original graphs. Replays
must leave every current database row unchanged. Accounts, receipts, gas, fees,
nonces and successful key registration are checked against ordinary execution.

Unbound sender profile 4 binds `BLAKE3(0 || pubkey)` to the complete native sender
address and selects raw transaction/signature/challenge version 2. It does not
turn the zero account commitment into a bound commitment. Historical key
selection uses the exact parent registry or Embedded key, so first use cannot
borrow a later registration. Bound Dilithium3 profile 3 and ML-DSA-65 profiles 1/2
retain their meanings. The existing compact checkpoints serve these jobs under
the same global quota, job count, payload and cache limits.

Real Reference-before-registration, wrong-address and tampered-signature Native
controls must refuse without state or key-registration writes. A separately
signed wrong-root ordinary Native control checks registration rollback. Full
historical predicate refusals use genuine foreign key/challenge/commitment
certificates, a genuine raw key-hash certificate without its address tag, and
relabelled signature/account profiles, each with a correct outer payload hash.
They preserve original proofs and current state and are distinct from new block
imports. The entry refuses retained outputs with a different account profile
before opening nodes or generating keys. Keep the output directory to resume;
failed assertions exit nonzero, and `verify` generates no proofs.

This bounded default-account case leaves absent-state account creation, AA/custom validators, same-block Reference after an
Embedded first use without a parent key, other activation combinations and
public release/network activation as separate acceptance work.


### Published SDK Dilithium3 bound sender

```bash
tests/e2e/dilithium-full-proof.sh sdk sdk-output
tests/e2e/dilithium-full-proof.sh verify sdk-output
```

This source regression additionally needs Node.js 20 or newer and npm registry
access. It installs the exact published `shell-sdk@0.14.0-rc.3` candidate into
`sdk-output.client` with a local npm cache. The candidate targets the maintained
V2 transaction codec; this is not a claim of public testnet activation. A retained
incomplete consumer fails instead of replacing dependencies. The driver checks
the package version and generates memory-only `MlDsa65Adapter` keys through the
public `ShellSigner("Dilithium3", adapter)` entry. Only its public key and two
original signed transfers are retained. The real SDK provider submits those
bytes through an actual local Node RPC server and observes successful receipts.
The Rust fixture never signs the SDK sender's transactions. The bound `sdk`
mode sends Reference transactions from an already registered account; the
unbound entry below explicitly includes the public key at first use.

The first transfer uses a funded bound default account with its exact parent
registered key and an independent ML-DSA-65 proposer. It completes automatic
production, durable recovery, full mathematical verification, real peer Native
import and finality. A separately signed original SDK successor advances current
state to height 2 before repeated cold read-only historical checks. Receipt,
21,000-gas, effective-fee, account and nonce results must match ordinary Native
execution. Genuine foreign certificates, cross-profile substitutions and SDK
signed-input tampering must refuse. Native intake and signed wrong-root rollback
controls are labelled separately from full proof admission and historical
predicate refusal. Failed assertions exit nonzero; keep the outputs to resume.

Native algorithm tag 0 accepts both its locked PQClean raw transcript and the
SDK FIPS adapter. Their equal key/signature widths do not make their transcripts
interchangeable. Bound SDK sender account profile 5 requires transaction source
envelope 3, the Native tag-zero signing hash, and complete FIPS signature and
challenge proofs of version 1, including the 48-byte sampler seed and empty-
context framing. Raw bound/unbound profiles 3/4 keep transaction/signature version
2 and the raw 32-byte sampler seed. Primary ML-DSA profiles 1/2 remain unchanged.
Frozen source format 3 explicitly records the SDK selection; old source formats
1/2 and proof batch formats retain their original meanings and exact bytes.
Selection is a producer preflight; consumers require complete AIR without Native
signature fallback.

This bounded case covers one bound SDK sender and a primary proposer. Other SDK-proposer/sender combinations beyond the entry below, absent-state creation, AA/custom validators,
same-block registration sequences, other activations and public binary/network
acceptance remain separate. Limits, defaults and activation schedules are unchanged.


### Funded unbound SDK Dilithium3 first use

```bash
tests/e2e/dilithium-full-proof.sh sdk-unbound sdk-first-use-output
tests/e2e/dilithium-full-proof.sh verify sdk-first-use-output
```

Use the same published SDK candidate, Node.js/npm, Python, Rust and RocksDB
prerequisites as the bound entry. The SDK's public default omits the key. This
entry uses the documented `includePublicKey: true` for its original first-use
transaction, then `false` for the two original Reference transfers. The signing
keys are disposed after all three public signed inputs are saved; a retained
output is never a request to replace keys or signatures. Funding a derived
address leaves its default account's key commitment zero and registry empty.

The real SDK provider submits the Embedded first transaction through local Node
RPC. Native canonical commit must register the exact key; the later Reference
transaction resolves that registration. Both original graphs must complete
automatic production, durable recovery, full mathematics, actual peer Native
import and finality through height 2. Original Reference advancement to height 3
changes current balances and nonce before repeated cold read-only historical
queries replay both proved blocks. Registration, receipts, 21,000 gas, effective
fee, balances and nonces must match ordinary Native execution.

Unbound SDK sender profile 6 requires complete `BLAKE3(0 || pubkey)` address AIR,
transaction source envelope 3 and complete FIPS signature/challenge version 1.
New frozen source format 4 carries unbound SDK selection; old bound SDK source
format 3 retains its meaning. Bound SDK profile 5, genuine raw profiles 3/4 and
primary profiles 1/2 remain strict. Neither late registration nor equal key widths
authorizes borrowing a current key or changing a historical transcript.

The regression rejects genuine foreign key/challenge/commitment certificates,
wrong transaction/signature/account profiles, a genuine key-hash certificate
without the address tag, and bound SDK profile 5 before historical registration.
These full historical predicate refusals preserve original proofs and all KV
bytes. Real SDK Reference-before-registration, wrong-address and signed-input
intake refusals, plus signed wrong-root registration rollback, are separate
ordinary Native controls. They do not claim a new proof-backed bad-block import.
A retained account/transcript/role mismatch exits before key or proof generation.
Failed checks exit nonzero; `verify` generates no proofs.

This is a funded default-account case with a primary65 proposer and algorithm
binding omitted. Other SDK-proposer combinations beyond the entry below,
absent-state creation, AA/custom
validators, same-block registration sequences, other activations, forks,
platforms and sustained load remain separate. Production/admission defaults,
quotas, activation schedules and public binary/network availability are unchanged.


### Published SDK Dilithium3 proposer seal

```bash
tests/e2e/dilithium-full-proof.sh sdk-proposer sdk-proposer-output
tests/e2e/dilithium-full-proof.sh verify sdk-proposer-output
```

Use the same exact published SDK candidate, Node.js/npm, Python 3, stable Rust
and RocksDB prerequisites as the SDK sender entries. This case has an independent
primary65 registered sender and an SDK Native tag-zero FIPS proposer. A disposable
SDK process owns the proposer's secret key and calls public `ShellSigner.sign`
on the exact raw 32-byte Native header hash. The Native signer interface forwards
only public hash requests and receives public key/signature bytes; it never
reconstructs or persists the SDK secret key. The process disposes the key and
stops through a cooperative message before proof production begins.

Actual Native production, quorum/finality and a separately signed wrong-root
ordinary import control precede complete proof capture. The same original graph
must complete automatic production, durable recovery, full mathematics and real
peer Native import/finality. An original ordinary successor changes state before
repeated cold historical checks compare receipts, 21,000 gas, effective fee,
accounts and nonce while preserving every KV byte. Keep the outputs to resume;
retained-role mismatches and failed assertions exit nonzero, and `verify` creates
no new proofs or signing keys.

New frozen source format 5 explicitly records the SDK proposer transcript. Seal
profile 3 binds the complete Native header hash to FIPS signature/challenge
version 1 and its full 48-byte sampler seed under Native algorithm tag zero.
Primary seal profile 1 and genuine PQClean raw profile 2 keep their distinct
algorithms/transcripts. Source formats 1/2/3/4 and already captured SDK sender-only
jobs retain their exact bytes and meaning; recovery does not upgrade them in
place. Native raw-or-SDK verification, algorithm deprecation policy, consensus
selector/quorum checks, limits, defaults and activation schedules are unchanged.
A fully verified proposer token authorizes only its exact key/hash/seal tuple.

The entry refuses genuine foreign primary key/challenge/commitment certificates,
raw/primary seal relabelling and a complete header-hash certificate for the
original independently SDK-signed successor, each with a correct outer payload
hash and unchanged original proof/state. These are full historical predicate
refusals; the separate ordinary Native wrong-root control is not a new
proof-backed bad-block import. Missing-parent-key authorities, other sender or
account combinations, selector/quorum/penalty AIR, other activations/forks and
public artifact/network acceptance remain separate.


### Published SDK sender and proposer together

```bash
tests/e2e/dilithium-full-proof.sh sdk-both sdk-both-output
tests/e2e/dilithium-full-proof.sh verify sdk-both-output
```

Use the exact published candidate and prerequisites above. Two independent SDK
keys sign the sender's bound-account transfers through the public provider/RPC
and the proposer's raw 32-byte Native header/vote hashes through public
`ShellSigner.sign`. Both keys stay inside disposable SDK processes; retained
outputs contain only public inputs. The original Native flow reaches block 1
and finality, then executes an ordinary successor and refuses a separately signed
wrong-root import before proving starts.

This composition uses existing source format 5, sender profile 5 with transaction
profile 3, and proposer seal profile 3. Both signatures require complete FIPS
version-1 AIR and 48-byte challenge seeds under Native algorithm tag zero. A
successful original full capture records supported behavior. The same graph must
survive pause/reopen/recovery, real peer Native import/finality, receipt/fee/account
comparison and repeated read-only history after the successor changes state.
Genuine independent SDK sender certificates cannot authorize the proposer;
sender/account and proposer/header profile relabelling must also fail while
preserving the original proof and every KV byte. Retained incompatible role
requests refuse before signing.

This entry covers the bound default-account combination only. Unbound SDK sender
with SDK proposer, AA/custom accounts, consensus selector/quorum/penalty AIR,
other activations/forks/platforms and public release/network acceptance require
separate evidence. Limits, defaults, Native transcript union and prior frozen
source meanings remain unchanged.


### Published SDK first use with an SDK proposer

```bash
tests/e2e/dilithium-full-proof.sh sdk-both-unbound sdk-first-use-output
tests/e2e/dilithium-full-proof.sh verify sdk-first-use-output
```

Use the published candidate and prerequisites above. The sender has a funded
default account with zero key commitment and no registered key; the independent
SDK proposer has a parent-registered key. The SDK's original default Reference
first-use envelope is retained and must be refused. The public transaction builder
adds only the sender's original public key to that same signed envelope for
Embedded first use; transaction and signature bytes stay unchanged. This is the
explicit first-use public-key requirement, without re-signing or replacing keys.

Actual provider/RPC execution must register the sender's key in block 1. Reference
transfers then execute in blocks 2 and 3. Both original block-1 Embedded and block-2
Reference proof graphs must complete automatic durable recovery, real peer Native
import/finality and receipt/fee/account comparisons. Ordinary block 3 precedes
repeated read-only history for both targets. Existing source format 5 combines
sender profile 6 and tag-zero address AIR for both retained zero-commitment
targets, transaction profile 3 and SDK proposer seal profile 3. Registration
adds the Native key lookup for Reference use; the account commitment stays zero. Both roles
require full FIPS signature/challenge version 1 with 48-byte seeds.

Genuine cross-role SDK certificates, foreign header proofs, raw/primary profiles,
untagged address and bound-at-first-use substitutions must fail without changing
original proofs or KV bytes. Default Reference, wrong-address and signed-tamper
intake controls and a separately signed wrong-root ordinary import must leave
state and key registration unchanged. These remain separate from proof-backed
bad-block imports. Both SDK keys are memory-only; keep public outputs to resume.
Other account/role combinations, consensus selector/quorum/penalty AIR and public
release/network acceptance remain separate; limits and defaults are unchanged.


### Published SDK sender with a genuine raw proposer

```bash
tests/e2e/dilithium-full-proof.sh sdk-raw-proposer sdk-raw-output
tests/e2e/dilithium-full-proof.sh verify sdk-raw-output
```

Use the same published SDK candidate and prerequisites above. This case combines
an actual SDK Native tag-zero FIPS bound sender with an independent genuine
locked PQClean raw Native tag-zero proposer. The SDK signs and submits retained
transfers through its public provider and Node RPC. Ordinary Native block 1,
quorum/finality, a successor and a separately signed wrong-root control precede
the supported original full source capture; no missing capability is assumed.

Existing source format 3 combines sender profile 5 and transaction profile 3
with complete FIPS signature/challenge version 1 and a 48-byte seed. Proposer
seal profile 2 independently requires the complete genuine raw signature/challenge
version 2 and its 32-byte seed. A shared Native algorithm tag does not make their
signing domains or certificate inputs interchangeable. The same original graph
must complete automatic durable recovery and real peer Native import/finality,
matching receipts, fees, accounts and nonce. Repeated read-only history follows
the ordinary successor.

Genuine SDK key/challenge/commitment certificates cannot authorize the raw
proposer. FIPS/SDK/primary seal relabelling, a complete header proof for the
original independently raw-signed successor and SDK sender source/account
relabelling must fail without altering original proofs or KV bytes. Separate
Native signed-tamper and wrong-root controls remain distinct from proof-backed
bad-block import. Keys remain memory-only; retained-role mismatches refuse before
signing. Other role/account combinations, consensus selector/quorum/penalty AIR
and public release/network acceptance remain separate. Limits, Native transcript
union, defaults and frozen source meanings are unchanged.


### Genuine raw sender with a published SDK proposer

```bash
tests/e2e/dilithium-full-proof.sh raw-sdk-proposer raw-sdk-output
tests/e2e/dilithium-full-proof.sh verify raw-sdk-output
```

Use the same published SDK candidate and prerequisites above. This is the
opposite mixed transcript: a genuine locked PQClean raw Native tag-zero bound
sender and an independent actual SDK Native tag-zero FIPS proposer. A disposable
SDK process calls public `ShellSigner.sign` on exact raw 32-byte Native header
and vote hashes, receives only public requests and never exports its secret.
The ordinary Native block/quorum/finality, successor and separately signed
wrong-root rollback precede supported full source capture.

Existing source format 5 combines sender profile 3 and transaction profile 2
with complete raw signature/challenge version 2 and a 32-byte seed. SDK proposer
seal profile 3 independently requires full FIPS signature/challenge version 1
and its 48-byte seed. The original graph must survive automatic durable
pause/reopen/recovery, real peer Native import/finality, receipt/fee/account
comparison and repeated read-only history after the ordinary successor.

Genuine raw sender key/challenge/commitment certificates cannot authorize the
SDK proposer. Raw/primary seal relabelling, a complete header certificate for
the original independently SDK-signed successor and raw sender source/account
relabelling must refuse without changing original proofs or KV bytes. SDK
secrets are disposed cooperatively before proof production. Keep public outputs
to resume; retained-role mismatches refuse before signing. Unbound mixed roles,
other account arrangements, consensus selector/quorum/penalty AIR and public
release/network acceptance remain separate. Limits, defaults, Native transcript
union and prior frozen source meanings are unchanged.


### Published SDK first use with a genuine raw proposer

```bash
tests/e2e/dilithium-full-proof.sh sdk-unbound-raw-proposer sdk-first-raw-output
tests/e2e/dilithium-full-proof.sh verify sdk-first-raw-output
```

Use the same exact published SDK candidate and prerequisites above. This combines
a funded zero-commitment SDK Native tag-zero FIPS sender with an independent
genuine locked PQClean raw Native tag-zero proposer. The original SDK default
Reference first-use envelope must be refused. The public transaction builder
adds only the original public key for Embedded first use, keeping original
transaction and signature bytes unchanged without re-signing.

Actual SDK provider/RPC execution registers the key in block 1, then executes
Reference transfers in blocks 2 and 3. Both original Embedded1 and Reference2 full
mixed-transcript graphs must complete automatic durable recovery and real peer
Native import/finality2 with matching receipts, fees, accounts and nonce. Ordinary
block 3 precedes repeated read-only history for both targets. Existing source
format 4 retains sender profile 6 and tag-zero address AIR for both targets:
registration adds a key lookup while the account commitment stays zero. Sender
transaction profile 3 requires FIPS signature/challenge version 1 and a 48-byte
seed; proposer seal profile 2 separately requires raw signature/challenge version
2 and a 32-byte seed.

Genuine mixed certificates, FIPS/SDK/primary seal relabelling, a complete header
proof for the original independently raw-signed successor, sender source/account,
untagged address and bound-at-first-use substitutions must fail without changing
original proofs or KV bytes. Separate genuine SDK Reference/wrong-address/tamper
intake refusals and a signed wrong-root ordinary import must preserve state and
key registration; they are distinct from proof-backed bad-block imports. Keep
public outputs to resume. Other unbound raw/account combinations, consensus
selector/quorum/penalty AIR and public release/network acceptance remain separate;
limits, defaults, Native transcript union and frozen source meanings are unchanged.


### Genuine raw first use with a published SDK proposer

```bash
tests/e2e/dilithium-full-proof.sh raw-unbound-sdk-proposer raw-first-sdk-output
tests/e2e/dilithium-full-proof.sh verify raw-first-sdk-output
```

Use the exact published SDK candidate and prerequisites above. The funded raw
Native tag-zero sender begins with zero key commitment and no registered key;
the independent SDK Native tag-zero FIPS proposer signs exact raw 32-byte Native
header/vote hashes through public `ShellSigner.sign` in a disposable process.
The first genuine raw Reference transaction is signed once and retained for the
expected refusal. Embedded first use adds only that original public key to a
clone of the same transaction/signature; signed bytes and signing hash must match.

Native block 1 registers the key and reaches quorum/finality, then Reference
transfers execute in blocks 2 and 3. Both original Embedded1 and Reference2 full
graphs must complete automatic durable recovery and real peer Native import/
finality2 with equal receipts, fees, accounts and nonce. Ordinary block 3 precedes
repeated read-only history for both targets. Existing source format 5 retains
sender profile 4, tag-zero address AIR and transaction profile 2 with complete
raw signature/challenge version 2 and a 32-byte seed. Registration adds a key
lookup while the account commitment stays zero for both targets. SDK proposer
seal profile 3 separately requires full FIPS signature/challenge version 1 and
a 48-byte seed.

Genuine mixed certificates, Raw/primary seal relabelling, the original independently
SDK-signed successor's full header certificate, Raw sender source/account,
untagged address and bound-at-first-use substitutions must refuse without changing
original proofs or KV bytes. Genuine Reference/wrong-address/tamper intake controls
and an independently SDK-signed wrong-root ordinary import must preserve state
and registration; they are distinct from proof-backed bad-block import. The SDK
key is disposed cooperatively before proving. Keep public outputs to resume.
Other unbound raw/account combinations, consensus selector/quorum/penalty AIR
and public release/network acceptance remain separate; limits, defaults, Native
transcript union and prior frozen source meanings are unchanged.

### Genuine raw sender first use with a genuine raw proposer

```bash
tests/e2e/dilithium-full-proof.sh both-unbound raw-first-both-output
tests/e2e/dilithium-full-proof.sh verify raw-first-both-output
```

This mode uses independent memory-only keys from locked
`pqcrypto-dilithium 0.5.0` for both Native tag-zero roles. The funded sender
starts with zero account commitment and no registered key. Its original signed
Reference transaction must refuse; Embedded first use adds only the original
public key, keeping the transaction, signature and signing hash unchanged.
Native block 1 registers the key and reaches quorum/finality. Reference
transfers execute in blocks 2 and 3, including an ordinary successor before
repeated read-only historical verification.

Both original Embedded1 and Reference2 complete automatic durable full proof
recovery and real peer Native import/finality2 with equal receipts, fees,
accounts and nonces. Existing source format 2 requires sender profile 4,
tag-zero address AIR, transaction profile 2 and full raw signature/challenge
version 2 with a 32-byte seed. The separate proposer seal profile 2 also requires
full raw signature/challenge version 2 and a 32-byte seed. Registration creates
a key lookup while the account commitment remains zero, so sender profile 4
and address AIR remain mandatory for both targets.

Genuine cross-role key/challenge/commitment certificates, FIPS/primary seal
relabelling, the original independently raw-signed successor's complete header,
SDK sender source/account profiles, untagged address and bound-at-first-use
substitutions must refuse with original proofs and KV bytes unchanged. Native
Reference/wrong-address/tamper intake and signed wrong-root registration rollback
remain distinct from proof-backed bad-block imports. Keep public outputs to
resume. Account abstraction/custom validators, same-block key sequencing,
selector/quorum/penalty AIR and public release/network acceptance remain
separate; frozen source meanings, limits, defaults and activation are unchanged.

### Native SLH-DSA fallback and canonical proof reproduction

```bash
tests/e2e/slh-full-proof.sh native slh-output
tests/e2e/slh-full-proof.sh capture slh-output
```

Use the source-build and RocksDB prerequisites above. Native mode generates
memory-only `fips205 0.4.1` SLH-DSA-SHA2-256f keys and genuine signatures with
the empty pure-signature context: Native algorithm 2, 64-byte public keys and
49,856-byte signatures. It exercises a bound Reference transfer, an independent
ML-DSA proposer, Native quorum/finality, independent Native database import,
wrong-owner/message refusals, signed wrong-root rollback and an ordinary
successor. Existing output is refused before generating any new key.

The unreleased registered-sender source profile below integrates this fallback
with historical account authority, full signature/body proofs and durable
production. Native execution and the standalone SHA2 primitives alone do not
establish canonical proof admission. Network transport, automatic production,
changed-state history and public release acceptance require separate evidence.
Keep original outputs and signatures when investigating a failure. The explicit
`recover-native` mode can checkpoint an already imported/finalized retained
first block without any private key or re-signing; it cannot recreate an
unsigned successor or supply missing later acceptance evidence.

The `sha2_compression` API proves complete SHA-256/SHA-512 compression schedules,
64/80 rounds and feedforward, including all Boolean operations and 32-bit limb
carries. Its caller must independently bind every expected chaining value and
block. All 64-bit public values are split into limbs, avoiding reduction aliases
in the Goldilocks base field. The separate quadratic-extension proof profile
preserves query, blowup, grinding and FRI settings; global options are unchanged.
Its 16-block batch bound is a development proof resource profile, not a Native
transaction limit. Compression certificates alone do not prove digest padding,
chaining, transaction authority or an SLH signature.

```bash
cargo test --locked --release -p shell-stark-prover --lib sha2_compression -- --test-threads=1
```

For a persistent SHA-256 compression certificate, save the following padded
`abc` block as `sha2-input.json`:

```json
{"algorithm":"Sha256","inputs":[{"chaining_value":[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],"block":[1633837952,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24]}]}
```

```bash
cargo run --locked --release -p shell-stark-prover --example sha2-compression -- prove sha2-input.json sha2-proof.cbor
cargo run --locked --release -p shell-stark-prover --example sha2-compression -- verify sha2-input.json sha2-proof.cbor
```

The verifier starts separately and checks the certificate against the supplied
inputs. An existing proof is never overwritten; wrong inputs, malformed proofs
and trailing certificate data return a failure exit code. Use `Sha512` with
64-bit words for SHA-512 compression. Complete digest and signature framing
remain the caller's responsibility.

The `sha2_digest` API adds complete FIPS 180-4 byte-message hashing: the standard
initial state, exact padding and bit length, every chained block and canonical
groups of up to sixteen compressions. The message profile is bounded to 4,096
bytes. It verifies the compression AIR and all input edges; verification never
computes a native SHA digest. This is a proving profile, not a change to Native
transaction limits or the global proof-store quota.

The `slh_sha2` API builds on those digests for the **SHA2-256f** verification hash
functions. `Message` uses the Native 32-byte signing hash in pure mode with an
empty context, SHA-512 and the fixed 49-byte MGF1 output. `F` uses SHA-256;
`H`, `WotsPublicKey` and `ForsRoots` use SHA-512 truncated to 32 bytes. The public
seed padding, 22-byte address, domain and fixed 67/35-node counts are bound to
the independently supplied request. The address fields are `layer`, `tree`,
`kind`, `key_pair`, `chain_or_height` and `hash_or_index`; their byte order follows
FIPS 205. The full signature verifier still needs to establish the correct
tree positions and node relationships.

To prove H_msg from the retained Native test output above, export the public
key and request without generating another key or signature:

```bash
python3 - <<'PY'
import json
with open("slh-output/actors.json") as source:
    public_key = json.load(source)["sender_key"]
with open("slh-public-key.json", "x") as output:
    json.dump(public_key, output)
PY
cargo run --locked --release -p shell-stark-prover --example slh-sha2 -- native-hmsg slh-output/signed-first.json slh-public-key.json slh-hmsg.json
cargo run --locked --release -p shell-stark-prover --example slh-sha2 -- prove slh-hmsg.json slh-hmsg.cbor
cargo run --locked --release -p shell-stark-prover --example slh-sha2 -- verify slh-hmsg.json slh-hmsg.cbor
```

The exporter first checks the retained Native signature and exact algorithm,
key and signature lengths. This native check validates export inputs; it is
separate from mathematical hash-proof acceptance. Verification starts in a new
process with independently supplied JSON. Output is exclusive and flushed to
disk; changed request bytes, malformed or trailing certificate bytes and
attempted output replacement fail with a nonzero exit code. Keep all original
inputs and certificates after a failure. The output explicitly identifies a
hash-only proof, with no signature-admission authority.

Run the focused digest, compression and SLH hash regressions with:

```bash
cargo test --locked --release -p shell-stark-prover --lib sha2 -- --test-threads=1
```

These tests cover independent RustCrypto digests, padding and block boundaries,
the bounded maximum message and multiple chunks, genuine compression proofs
with false IV/padding/chaining/order, FIPS 205 routing and public-input refusals.
They do not establish WOTS+/hypertree or canonical node/peer/history
acceptance. Existing source formats, activation and consensus policy remain
unchanged.

The `slh_fors` API composes these hashes into the complete fixed SHA2-256f FORS
forest. It derives all 35 nine-bit indices from H_msg's first 315 bits, the
64-bit tree index and four-bit leaf index. Each tree constrains its secret-leaf
hash, all nine authentication hashes, their left/right ordering and global
tree indices. The final T hash combines all 35 ordered roots. Every hash uses
the complete SHA2 AIR. No native hash or native signature verifier participates
in FORS proof acceptance.

Run the self-contained full-forest regression with Rust stable, the source-build
and RocksDB prerequisites above, and Python 3 (standard library only):

```bash
tests/e2e/slh-fors.sh fors-output
```

The default fixture generates a genuine memory-only SLH signature and drops the
private key after exporting public inputs. It exercises standalone cryptographic
verification; it does not execute a Native transaction. To continue from the
same retained Native signature and public key exported above instead:

```bash
tests/e2e/slh-fors.sh fors-original slh-output/signed-first.json slh-public-key.json
```

Both modes prove all 35 trees at the real nine-level parameter, independently
reconstruct the entire forest with Python `hashlib`, cold-verify the certificate
in a separate process and check genuine foreign-tree/branch, message/key/node,
proof and serialization refusals. A wrong input, corrupt checkpoint or attempted
output replacement fails with a nonzero exit code. Keep the original inputs,
steps and full certificate; the command refuses an existing regression output.
The independent Python oracle also hashes the remaining hypertree to check that
the FORS output reaches the original public root. Those oracle operations are
unproved and never participate in proof acceptance.

The `slh-fors` example stores each of its 352 verified hash steps with exclusive
creation and file synchronization. Recovery rechecks every retained step against
the independently derived request before using its result. It never replaces a
bad step or changes frozen inputs. The assembled `fors.cbor` can be verified
without the step directory:

```bash
cargo run --locked --release -p shell-stark-prover --example slh-fors -- resume fors-output/input.json fors-output/proof
cargo run --locked --release -p shell-stark-prover --example slh-fors -- verify fors-output/input.json fors-output/proof/fors.cbor
```

This development certificate reader has a separate 128 MiB bound; Native and
global proof-store limits are unchanged. The result is a FORS public key. The
full original signature envelope is compared to caller-supplied bytes, while
the WOTS+/hypertree tail's mathematical relation to the SLH public root remains
unproved. The output explicitly reports `full_signature_verified: false`.
Complete signature authorization, canonical sources/jobs, node import and
historical acceptance still require integration.

The `slh_xmss` API proves one complete SHA2-256f XMSS layer: all 64 message
nibbles, three checksum digits, 67 WOTS+ chain start positions and lengths,
the ordered chain endpoints and their T hash, and all four XMSS authentication
hashes. It binds the independently expected layer/tree/leaf coordinates and
signature bytes. A single proved SHA-256 compression authenticates the public
seed plus zero padding. Canonical groups of at most sixteen F suffix
compressions reuse that state, with the exact address, node, SHA padding and
absolute 118-byte message length. Verification never computes a native SHA.

Use the same build prerequisites and Python 3 to run a self-contained genuine
signature, full FORS and first-layer XMSS regression:

```bash
tests/e2e/slh-xmss.sh xmss-output
```

To reuse the exact retained FORS input and certificate instead of generating
another signature or regenerating FORS:

```bash
tests/e2e/slh-xmss.sh xmss-original fors-original/input.json fors-original/proof/fors.cbor
```

The `from-fors` example command first mathematically verifies the retained FORS
certificate, then exports layer zero's message, coordinates and original
2,272-byte XMSS signature. The regression proves all 67 chains and four actual
authentication levels, compares the root to the independent Python hash
oracle, cold-verifies in a separate process and resumes from immutable verified
compression/hash checkpoints. Wrong chain batches, prefixes, addresses, input
bytes, authentication order and corrupt/trailing proofs are refused. Existing
outputs and frozen inputs are never replaced.

```bash
cargo run --locked --release -p shell-stark-prover --example slh-xmss -- resume xmss-output/layer.json xmss-output/proof
cargo run --locked --release -p shell-stark-prover --example slh-xmss -- verify xmss-output/layer.json xmss-output/proof/xmss.cbor
```

The complete layer certificate has a separate 64 MiB development reader bound;
the compression batch bound and global limits are unchanged. This standalone
regression covers layer zero of seventeen. Full signature composition uses
all seventeen independently verified layer certificates as described below.
The standalone independent Python full-hypertree check is an unproved oracle,
and every layer result reports `full_signature_verified: false`. This does not
establish canonical source/job, node/peer or historical admission.


The `slh_signature` API completes the mathematical SHA2-256f signature relation
for a 32-byte signing message in pure mode with an empty context. It verifies
the original H_msg/FORS certificate, then all seventeen complete WOTS+/XMSS
certificates. Each layer uses the preceding **proved** root as its message;
subsequent leaf indices consume the low four bits of the prior tree index,
which then shifts right by four. Layer addresses and the exact original
2,272-byte signature slices are derived independently of the supplied proofs.
The final proved root must equal the root in the 64-byte public key. There is
no native SHA or signature-verification fallback in this acceptance path.

A versioned manifest freezes the original public seed, root, signing message
and all 49,856 signature bytes. The manifest alone cannot authorize anything:
verification reads the complete FORS certificate and every one of the seventeen
bounded layer certificates. Streaming retains FORS and one layer in memory,
with the existing separate 128 MiB FORS and 64 MiB layer development bounds.
Existing source formats, global quotas, defaults and activation remain unchanged.

Run the complete regression with Rust stable, the source-build dependencies,
Python 3 standard library and enough disk for the retained component proofs:

```bash
tests/e2e/slh-signature.sh signature-output
```

This self-contained mode first creates a separate genuine, memory-only
`fips205 0.4.1` test signature through the FORS entry. It requires no saved key
or account and never uses those native verification checks as AIR acceptance.
To continue exactly retained public inputs, without signing or regenerating
FORS, supply them explicitly; an optional complete layer-zero certificate also
avoids regenerating its proof:

```bash
tests/e2e/slh-signature.sh signature-original fors-original/input.json fors-original/proof/fors.cbor xmss-original/proof/xmss.cbor
```

The `init` command verifies imported components before creating a new owned
output directory. Proving freezes exact inputs and persists only verified
compression/hash steps, complete layer certificates and a final manifest. A
single authenticated seed-prefix certificate can be reused across all layers;
every use checks it against the independently derived seed. `resume` rechecks
all available complete certificates, reuses verified partial steps only for
missing layers, and refuses input replacement or corrupt consumed checkpoints.
Full-cache resume produces no new proof. The same directory can cold-verify
without the original checkpoint directories or private keys:

```bash
cargo run --locked --release -p shell-stark-prover --example slh-signature -- resume fors-original/input.json signature-original/proof
cargo run --locked --release -p shell-stark-prover --example slh-signature -- verify fors-original/input.json signature-original/proof
```

The regression compares every proved layer root and the final public root with
an independent Python hash oracle, cold-verifies in another process and checks
version/count, original key/message/signature, foreign/rebound layer, corrupt
AIR, missing-final-layer and authentication-order refusals. A separately prepared
missing-last-hash checkpoint resumes by generating just that hash and reproduces
the original certificate bytes. This does not test actual power loss. Invalid
input, failed proof verification and attempted output replacement exit nonzero.
Original input and proof artifacts remain immutable after every control.

Only this full composition reports `full_signature_verified: true`. It proves
the mathematical signature for the supplied signing message. Binding that
message to a canonical transaction/header and account authority requires the
separate registered-sender composition below. The standalone mathematical
command still reports `canonical_admission: false`; it does not execute a block. This source entry is not a claim that a
published node binary or an activated network accepts full SLH proof sources.


For a large native signed envelope such as SLH-DSA-SHA2-256f, the ordinary body
leaf contains the complete encoded signature and can exceed the existing
16 KiB body-leaf proof profile. `prove_large_body_hash_using` and
`verify_large_body_hash` use an explicit BLAKE3 hash version 3 with a 65,536-byte
bound. `prove_large_transaction_body_using` and
`verify_large_transaction_body` use body-membership version 2, binding the exact
ordinary envelope, index, sibling order, odd carry, total leaf count and expected
header transaction root. Existing hash versions 1/2 retain their 4,096/16,384-byte
bounds; legacy membership version 1 rejects the large profile. Native byte
formats, transaction limits, gas, source formats and activation are unchanged.

The canonical transaction ID remains the existing 80-byte preimage:
`PQTX_IDENTITY_V1 || from || sender_signing_hash`. Authentication witnesses are
excluded from that ID. `LargeTransactionEnvelopeProof` separately proves the
ordinary signing payload, this small ID and the large body membership using
actual compression AIRs. Its verifier takes the expected transaction ID and
header independently. A changed signature can retain the same ID while failing
body membership. This is body/identity evidence, not signature or consensus
authorization. Header hashing labels the result; the caller must authenticate
the selected header and link the mathematical signature/account/source context.

Use the Rust stable/source-build prerequisites and Python 3 standard library:

```bash
tests/e2e/large-body.sh body-output
```

The default fixture generates a separate genuine, memory-only SLH signature and
a mathematical block-body fixture; it is not a claim about Native execution.
To prove the exact first ordinary envelope in an already retained Native block
without generating a key or signature:

```bash
tests/e2e/large-body.sh body-original original-native-block.json
```

An optional third argument copies and rechecks an exact retained proof directory
when continuing a failed regression. Its frozen public inputs must match the
exported original block inputs byte-for-byte; it cannot substitute another
target, signature or body. The original directory remains read-only and no
proof is generated on the initial cache replay:

```bash
tests/e2e/large-body.sh body-rechecked original-native-block.json body-original/proof
```

The example exports public inputs without re-signing. Every BLAKE3 compression
checkpoint is verified against independently routed byte/chaining/counter/flag
operands before its output is used. Input snapshots, component hashes and final
certificates are create-new and never replaced. The final envelope verifies in
a separate process; full-cache resume creates no proof. A prepared partial
boundary removes only the final leaf compression and the derived assemblies
from a separate copy. Resume verifies retained steps, generates exactly the
missing compression and reproduces the original final bytes. This tests a
prepared checkpoint boundary, not actual process termination or power loss.

```bash
cargo run --locked --release -p shell-stark-prover --example large-body -- resume body-original/input.json body-original/proof
cargo run --locked --release -p shell-stark-prover --example large-body -- verify body-original/input.json body-original/proof
```

The complete development reader has a separate 512 MiB bound for its component
proof aggregate. Individual compression constraints/options and global
proof-store quotas are unchanged. Wrong profiles, signatures, keys, sender,
index, count, siblings, root, genuine reordered/foreign certificates,
corrupt/trailing bytes and attempted input/output replacement fail nonzero.
The regression checks independent Native hashing references, proves that a
changed witness keeps the old ID but fails the body proof, and retains all
original artifacts. `inspect` is explicitly a native reference command, never
an AIR-verification fallback. Successful body verification reports
`signature_verified: false` and `canonical_admission: false`; complete canonical
signature source/jobs, node/peer import, historical replay and public binary
acceptance remain separate integration work.


### Registered SLH canonical source and durable production

This source-build entry continues exactly one retained, bound default-account
SLH-DSA-SHA2-256f sender with a parent-registered key and an independent existing
ML-DSA/Dilithium proposer seal. Use the RocksDB/C++ toolchain prerequisites above,
Python 3 and the locked Rust dependencies (`fips205 0.4.1`). No private key is
read, recreated or persisted by these commands.

```bash
tests/e2e/slh-canonical.sh capture slh-output canonical-output
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["senders"][0]["key"]))' canonical-output/source.json > slh-public-key.json
tests/e2e/slh-fors.sh fors-original slh-output/signed-first.json slh-public-key.json
tests/e2e/slh-signature.sh signature-original fors-original/input.json fors-original/proof/fors.cbor
tests/e2e/large-body.sh body-original slh-output/candidate.json
tests/e2e/slh-canonical.sh pause slh-output canonical-output signature-original/proof body-original/proof
tests/e2e/slh-canonical.sh resume slh-output canonical-output signature-original/proof body-original/proof
tests/e2e/slh-canonical.sh verify slh-output canonical-output signature-original/proof body-original/proof
tests/e2e/slh-canonical.sh refusals slh-output canonical-output signature-original/proof body-original/proof
```

Create `slh-output` with the Native entry above, or keep an existing original
Native output. Reuse matching existing FORS/full-signature/body directories;
never regenerate them merely because proving paused. Capture uses an independent
output, so an old failed Native capture receipt remains intact. The source fixes
the original signed envelope, parent account/MPT witness, historical public key,
chain/genesis and supported proposer. Explicit source format 6 and batch profile
3 bind full signature mathematics to the proved signing message, unchanged
80-byte identity preimage, complete large body and exact header. Older source
formats 1–5 and batch profiles 1–2 retain their meanings.

The job stores verified components in a separate database. `pause` requests one
new component; `resume` rechecks retained components and imports matching original
mathematical certificates. It proves missing account/key/batch-entry and proposer
components, without re-signing. `proof.cbor` uses explicit availability frame 4.
Checkpoint format 4/component format 2 reconstruct deterministic SHA2 witness
words only after exact equality during encoding; decoding grants no authority.
Every complete restored AIR, routing edge and original proof byte is still
verified before an output can authorize Native execution. See
[the encoding rationale](adr/canonical-slh-proofs.md).

A raw compact intermediate can exceed the existing 256 MiB checkpoint quota.
Its failed output is retained; it is never silently rewritten as format 4.
Use a new owned canonical output for that encoding. An optional final
`prior-job-output` argument imports already verified binding certificates from
that exact-source job; the old database and index remain unchanged. The
256 MiB store/payload,
8 MiB full component and 2,048-certificate limits stay in force. The single large
sender shares the existing 1 GiB expanded-pool ceiling with its proposer; old
frames keep their prior per-transaction bounds. Body compression certificates
are grouped in canonical runs of at most sixteen. Source/circuit defaults, gas,
algorithm lifecycle and activation heights do not change.

The regression replays through the actual Native Node in a read-only historical
overlay and compares receipts/state with the original control. It also constructs
a separate RocksDB receiver at the original authenticated genesis using only
content-addressed trie nodes and historical registrations, imports the original
child with full proofs, then cold-replays persisted receipts/state. This is an
explicit test-parent reconstruction; no executed child or success flag seeds
that receiver. Wrong source/proof profiles, altered keys, chain, signing message,
signature witness and body/header root are refused without writing Native state.
Unmatched signature tuples receive no native crypto fallback.

This profile covers the first registered sender and direct offline import.
Fresh automatic generation, actual peer transport/finality, history after a
later original signed block, other account/role combinations and public
package/binary/network activation remain separate acceptance work. A retained
unsigned successor cannot be recreated after its private key has been dropped.

#### Automatic recovery from a retained SLH checkpoint

Continue the same `slh-output` and completed `canonical-output` above:

```bash
tests/e2e/slh-canonical.sh automatic-prepare slh-output canonical-output automatic-output
tests/e2e/slh-canonical.sh automatic-pause slh-output canonical-output automatic-output
tests/e2e/slh-canonical.sh automatic-resume slh-output canonical-output automatic-output
tests/e2e/slh-canonical.sh automatic-verify slh-output canonical-output automatic-output
tests/e2e/slh-canonical.sh automatic-refuse slh-output canonical-output automatic-output
```

Preparation creates an isolated receiver from authenticated genesis-reachable
trie nodes and parent registrations, executes the original signed child through
ordinary Native import, and checks the normal hook captured a queued source.
It explicitly transplants the completed same-source mathematical checkpoint into
that job as a test fixture. A queued record and retained component count grant no
verification authority. Keep both original input directories.

`pause` starts real `Node.run` production and requests graceful shutdown after
`proving` becomes observable. Cancellation can take effect before the first
certificate is rechecked. A separate `resume` process must reverify the entire
graph, generate zero new certificates, publish the ready byte cache and download
every chunk through authenticated loopback RPC. The downloaded frame must equal
the original complete proof byte for byte. The prover actor holds only its public
key and refuses every signing request; no original private key is recovered.

The regression refuses unauthenticated RPC, checks that ready availability has no
execution result, and cold-replays the downloaded proof against persisted Native
receipts, state, balances and nonces. The negative case keeps the valid output
and mutates AIR proof bytes only in a separate checkpoint copy, updating its
component hash and quota accounting. The actual background worker must reject
it even when the earlier ready payload remains available. Canonical Native data
must remain unchanged throughout.

This covers warm-checkpoint background recovery and local RPC availability.
Fresh automatic proof generation, later-original history, abrupt process
termination and network activation retain their separate acceptance requirements.

#### Fresh automatic SLH generation

Use the retained Native `slh-output` from the earlier source-build setup and a
new output directory. This flow needs no completed proof or mathematical cache:

```bash
tests/e2e/slh-canonical.sh automatic-fresh-prepare slh-output fresh-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-pause slh-output fresh-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-resume slh-output fresh-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-verify slh-output fresh-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-refuse slh-output fresh-automatic-output
```

The Rust/native dependencies and RocksDB feature are the same as above. Failed
assertions produce a nonzero exit code. Preparation reconstructs only the
authenticated genesis parent, ordinarily imports the original signed child and
requires a queued source with zero mathematical components and no availability
cache. It never opens or copies a donor checkpoint. Keep the original Native
input; its existing test signature supplies public proving inputs without any
new signing or private-key recovery.

`pause` runs the real background worker with a one-component budget and requests
graceful shutdown after nonzero new mathematical progress becomes durable.
`resume` runs a separate process without a per-pass component ceiling, rechecks
the retained component and generates the remaining graph. The existing job,
component, cache and expanded-proof quotas still apply. Full generation is
expensive; the regression allows up to 24 hours and retains each mathematical
checkpoint. A stopped partial job is progress, not a complete proof.

Completion requires the authenticated RPC to return the entire generated frame,
with a ready cache that has no execution result. Cold verification checks all
AIRs and replays the proof against the original persisted receipts, state,
balances and nonces without writeback. The negative command uses a separate
copy with damaged proof bytes and correct component hash/accounting; the worker
must reject it even while an earlier ready payload is retained. Public-only
actors reject every signing request.

Use `fresh-automatic-output` as the provider input in the peer regression below
to test its generated frame through independent receiver execution and signed
certificate finality. This remains the original first child and single-authority
profile. Later-original history, quorum AIR, broader roles, abrupt termination,
public releases and network activation retain their separate requirements.

#### Registered SLH admission over the proof channel

Continue the same retained `slh-output` and completed `automatic-output`:

```bash
tests/e2e/slh-peer-proof.sh prepare slh-output automatic-output peer-output
tests/e2e/slh-peer-proof.sh pause slh-output automatic-output peer-output
tests/e2e/slh-peer-proof.sh resume slh-output automatic-output peer-output
tests/e2e/slh-peer-proof.sh verify slh-output automatic-output peer-output
tests/e2e/slh-peer-proof.sh refuse slh-output automatic-output peer-output
```

Use the Rust toolchain, native build dependencies and RocksDB feature required
by the earlier source-build regressions. Each command exits unsuccessfully on
a failed assertion. Preparation requires a new output directory, keeps both
inputs, and uses their original test signature and complete proof graph. It
copies the ready availability cache to an isolated provider and restores the
original signed quorum certificate through normal certificate verification.
The independent receiver gets only authenticated genesis trie nodes and parent
key registrations, without the child state, receipts or finality.

Ordinary block discovery must stage the supported registered SLH child when
canonical proof admission is enabled. Real TCP/Noise peers then transfer the
proof through the dedicated channel; there is no operator fetch or import.
`pause` holds chunk three after the first three chunks arrive and requires
unchanged canonical genesis data. A separate `resume` process requests chunk
three first with a fresh nonce, verifies the complete graph, executes the
original child and finalizes it using the retained signed quorum certificate.
The attached certificate is independently verified when retained and again
against the canonical target after proof-backed import. It cannot authorize
an unverified proof. The fixture suppresses standalone certificate messages,
so finality must use the certificate attached to the ordinary block response.
Public-only prover actors reject every signing request.

`verify` cold-replays the actually received frame and compares persisted
receipts, root, balances and nonces without writing back. `refuse` uses a
separate fresh receiver and a correct-hash payload containing a genuine
signing-hash certificate in the key-hash slot. The original signatures and
quorum certificate remain genuine, but the wrong mathematical statement must
fail and leave genesis unchanged, without a native signature fallback.

This regression covers one registered sender, its independent supported
proposer and the original first child. It does not establish fresh automatic
generation, quorum AIR, later-original history, broader account/role
combinations, public release or network activation. Admission remains opt-in;
unsupported profiles keep their existing behavior.

#### Funded SLH first use

A funded default account can start without a registered key and with a zero
key commitment. Its first transaction must supply the 64-byte public key in
Embedded mode, derive the same algorithm-tagged sender address and pass the
complete SHA2-256f signature graph. Source format 7 and SLH transaction proof
version 2 add the mandatory address AIR; bound source 6 and proof version 1
retain their existing meanings. An absent account or custom validator is not
covered by this profile.

Continue a retained Native SLH output and its complete bound canonical proof:

```bash
tests/e2e/slh-first-use.sh prepare slh-output canonical-output first-use-output
tests/e2e/slh-first-use.sh capture slh-output canonical-output first-use-output
tests/e2e/slh-first-use.sh pause slh-output canonical-output first-use-output
tests/e2e/slh-first-use.sh resume slh-output canonical-output first-use-output
tests/e2e/slh-first-use.sh verify slh-output canonical-output first-use-output
tests/e2e/slh-first-use.sh refuse slh-output canonical-output first-use-output
```

Use the same locked Rust, RocksDB/C++ and Python prerequisites as the preceding
SLH entries. `prepare` refuses an existing output. It uses the retained public
SLH key and signature without signing again, creates an independent funded
genesis with a memory-only ML-DSA proposer, and drops that proposer's keys after
creating genuine Native controls. Switching Reference to Embedded preserves the
signed transaction, signature, signing hash and canonical identity; the complete
body and batch-entry proofs must bind the changed envelope. Matching retained
signature and body compression certificates are fully reverified; changed
account/address/envelope/proposer statements require their own certificates.
`pause` durably stores one new component; `resume` continues that same job.
These commands require the retained outputs, not personal keys or a preset
account. Errors exit nonzero and preserve the failing output.

Successful intake cannot register the sender key. The full proof receiver must
start at the independently authenticated genesis without that registration,
execute the first child through Native commit, and match the control receipts,
accounts and key registration. The existing funded account can still have a
zero commitment after registration. `verify` advances both the independent
Native control and proof receiver to a different second state and checks the
first child's historical replay without writing either current database.
`refuse` rejects a bound-proof substitution, absent or foreign address proof,
changed signature and changed envelope without registering a key or writing
Native state. This independent second block does not replace an unavailable
successor from the original bound history.

The ready frame can also drive the same real peer regression:

```bash
tests/e2e/slh-peer-proof.sh prepare first-use-output first-use-output/published first-use-peer
tests/e2e/slh-peer-proof.sh pause first-use-output first-use-output/published first-use-peer
tests/e2e/slh-peer-proof.sh resume first-use-output first-use-output/published first-use-peer
tests/e2e/slh-peer-proof.sh verify first-use-output first-use-output/published first-use-peer
tests/e2e/slh-peer-proof.sh refuse first-use-output first-use-output/published first-use-peer
```

The first-use receiver must remain unregistered while the proof is partial or
rejected and register only after complete verified Native import. The ordinary
attached quorum certificate still requires independent verification before
finality. Automatic first-use generation without a reference graph, other
account/proposer combinations, quorum AIR, public binary/package acceptance
and network activation require separate acceptance.

#### Fresh automatic generation for funded SLH first use

The same automatic entry accepts the `first-use-output` Native input above.
It restores only historical parent registrations: the first-use sender key must
remain absent until ordinary Embedded Native import commits it. The proposer
still needs its registered historical key. This avoids treating a future sender
registration as authority at genesis.

```bash
tests/e2e/slh-canonical.sh automatic-fresh-prepare first-use-output first-use-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-pause first-use-output first-use-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-resume first-use-output first-use-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-verify first-use-output first-use-automatic-output
tests/e2e/slh-canonical.sh automatic-fresh-refuse first-use-output first-use-automatic-output
```

Use a new automatic output. Keep the Native input, signatures and failed outputs;
`prepare` refuses replacement. These three-argument commands require no completed
canonical proof, checkpoint transplant or saved private key. Ordinary import
must capture source 7 as a queued job with zero mathematical components and no
availability cache. The actual background worker generates a nonzero durable
pause, cold-resumes and produces the full address/signature/body/proposer graph
within the existing quotas. A warmed checkpoint cannot satisfy this check.
The existing authenticated chunk retrieval, readiness-versus-execution check and
correct-hash damaged-checkpoint refusal remain part of the entry.

For a first-use Native input carrying the retained independent later control,
`verify` also creates a separate history checkpoint, imports that genuine second
block and cold-replays the generated first-use proof against its sealed parent.
It checks the ordinary Native later control too: the current key is present,
the historical parent key is absent, receipts and roots match, and neither
historical query writes current state. This separate control does not create
an unavailable successor in the original bound history.

Use the generated frame for actual peer import and certificate-backed finality:

```bash
tests/e2e/slh-peer-proof.sh prepare first-use-output first-use-automatic-output first-use-automatic-peer
tests/e2e/slh-peer-proof.sh pause first-use-output first-use-automatic-output first-use-automatic-peer
tests/e2e/slh-peer-proof.sh resume first-use-output first-use-automatic-output first-use-automatic-peer
tests/e2e/slh-peer-proof.sh verify first-use-output first-use-automatic-output first-use-automatic-peer
tests/e2e/slh-peer-proof.sh refuse first-use-output first-use-automatic-output first-use-automatic-peer
```

The transport checks partial-proof rejection, cold missing-chunk resume,
complete Native execution/key registration/finality and a genuine certificate
in the wrong statement slot. Public binaries, packages and network activation,
other account combinations and quorum AIR remain separate acceptance work.

### Complete SLH proposer seal with a bound primary sender

This separate profile supports a registered SLH-DSA-SHA2-256f proposer and one
independent, bound default-account ML-DSA-65 sender. The proposer signs the raw
32-byte Native header hash. Its 64-byte public key and 49,856-byte signature
must pass H_msg, FORS and all seventeen WOTS+/XMSS layers, including the final
public-key root. A sender proof or Native signature check cannot stand in for
these proposer certificates.

With the Rust, RocksDB/C++ toolchain and locked dependencies described above:

```bash
tests/e2e/slh-proposer.sh prepare slh-proposer-output
tests/e2e/slh-proposer.sh capture slh-proposer-output
tests/e2e/slh-proposer.sh pause slh-proposer-output
tests/e2e/slh-proposer.sh resume slh-proposer-output
tests/e2e/slh-proposer.sh verify slh-proposer-output
tests/e2e/slh-proposer.sh refuse slh-proposer-output
tests/e2e/slh-proposer.sh publish slh-proposer-output
```

Use a new output directory. `prepare` creates memory-only sender/proposer keys,
two independent Native database controls, genuine first and later signed
blocks, and verified quorum certificates. It drops private keys and refuses to
replace existing data. Preserve that output and resume the same job; proving
all layers can take substantial time. No saved private key, reference graph or
completed proof donor is required. A process failure exits nonzero and leaves
its evidence and durable progress in place.

The ordinary offline CLI can reuse that exact durable job and emit the same
frame without generating the signature again. Stop any node using the Native
database and use the captured block hash for both arguments:

```bash
cargo build --locked --release -p shell-cli
BLOCK_HASH=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["block"])' slh-proposer-output/context.json)
target/release/shell-node --datadir slh-proposer-output/provider produce-block-proof \
  --block-hash "$BLOCK_HASH" --expected-tip "$BLOCK_HASH" \
  --output slh-proposer-output/proof
```

The CLI rechecks every retained component and reports zero newly proved
components for a complete matching job. Keep its manifest and frame alongside
the Native controls; an incompatible source cannot reuse that job.

Capture uses source format 8, batch profile 4 and streamed availability frame 5.
The sender retains its existing complete account/signature/identity/body proof;
the proposer has a separate complete header/signature graph. Authority comes
from the sealed parent registration and Native-selected proposer. Only complete
verification creates the private exact-tuple proposer token. Native lifecycle,
selection, execution, fees, rollback, activation and quorum verification remain
in force. Legacy sender-only source 1 remains explicitly partial; it cannot be
relabeled as source 8. Sources 1–7 and existing frame encodings retain their
previous behavior and limits.

`pause` persists one actual mathematical component. `resume` cold-revalidates
retained progress, completes the full graph and round-trips frame 5 without
raising the 256 MiB checkpoint/payload, 2,048-certificate or shared 1 GiB expanded
pool limits. `verify` imports the first child through proof-backed Native
execution, compares receipts/accounts with ordinary Native controls, advances
to a genuinely changed second state, and replays the first proof against both
historical controls without writing current state. `refuse` rejects missing or
relabeled roles, changed signature data, missing layers and a genuine hash
certificate placed in the wrong header slot; every refusal preserves genesis.

`publish` makes the completed frame available in a separate provider checkpoint;
readiness alone grants no execution authority. Exercise the ordinary peer path:

```bash
tests/e2e/slh-peer-proof.sh prepare slh-proposer-output slh-proposer-output/published slh-proposer-peer
tests/e2e/slh-peer-proof.sh pause slh-proposer-output slh-proposer-output/published slh-proposer-peer
tests/e2e/slh-peer-proof.sh resume slh-proposer-output slh-proposer-output/published slh-proposer-peer
tests/e2e/slh-peer-proof.sh verify slh-proposer-output slh-proposer-output/published slh-proposer-peer
tests/e2e/slh-peer-proof.sh refuse slh-proposer-output slh-proposer-output/published slh-proposer-peer
```

The receiver starts from authenticated genesis state, receives no child receipts
or execution state, pauses after three proof chunks and resumes the missing
chunk in a new process. Complete graph verification must precede Native import
and finality from the separately verified attached quorum certificate. A payload
with a correct outer hash and genuine certificate in the wrong statement slot
must fail without Native fallback. Cold replay checks the received graph with
no writeback. This bounded profile does not establish two simultaneous SLH
roles, other sender/account combinations, quorum AIR, power-loss recovery,
public release acceptance or network activation.

#### Fresh automatic SLH proposer generation

The same bounded proposer profile can start through ordinary Native import and
the actual automatic worker. Prepare the independent Native controls once with
`tests/e2e/slh-proposer.sh prepare slh-proposer-output`, or keep the existing
output from the preceding entry. These commands need no completed standalone
proof, published cache, checkpoint donor or private key:

```bash
tests/e2e/slh-canonical.sh automatic-fresh-prepare slh-proposer-output slh-proposer-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause slh-proposer-output slh-proposer-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume slh-proposer-output slh-proposer-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify slh-proposer-output slh-proposer-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse slh-proposer-output slh-proposer-automatic
```

Use a new automatic output and retain failed outputs. Both the bound sender and
proposer require their sealed parent registrations. Ordinary Native import must
capture Source 8 with zero mathematical components and no availability cache;
production remains disabled unless explicitly enabled. The public-only worker
must generate nonzero new progress, persist a graceful pause, cold-revalidate
that progress, and finish the full sender/header/SLH signature graph. A complete
warm checkpoint cannot satisfy this fresh-generation check. Limits and Native
activation, execution and quorum rules are unchanged.

Authenticated chunk retrieval must reproduce the ready frame without claiming
execution authority. Cold verification checks the generated graph and Native
receipts/accounts, then advances a separate history checkpoint to the retained
genuine second block. Replay against that checkpoint and the ordinary Native
later control must prove both signature roles, match first-block receipts and
root, resolve the original sealed parent keys and leave both current databases
unchanged. A separate correct-hash damaged checkpoint must fail without Native
changes, retrying or using a prior ready result.

Use the generated frame for the existing actual peer regression:

```bash
tests/e2e/slh-peer-proof.sh prepare slh-proposer-output slh-proposer-automatic slh-proposer-automatic-peer
tests/e2e/slh-peer-proof.sh pause slh-proposer-output slh-proposer-automatic slh-proposer-automatic-peer
tests/e2e/slh-peer-proof.sh resume slh-proposer-output slh-proposer-automatic slh-proposer-automatic-peer
tests/e2e/slh-peer-proof.sh verify slh-proposer-output slh-proposer-automatic slh-proposer-automatic-peer
tests/e2e/slh-peer-proof.sh refuse slh-proposer-output slh-proposer-automatic slh-proposer-automatic-peer
```

This checks ordinary discovery, three-chunk pause/cold resume, complete
proof-backed Native import and attached-certificate finality, cold replay and a
genuine hash certificate placed in the wrong header slot. These are local
source-build checks; public artifacts, network activation, quorum AIR and other
role/account combinations require separate acceptance.

#### Funded primary sender first use with an SLH proposer

A separate profile supports a funded default primary ML-DSA-65 account whose
parent key commitment is zero, together with a registered SLH-DSA-SHA2-256f
proposer. First use must carry its Embedded 1,952-byte sender key. Reference
mode is refused until the ordinary Native commit registers that key. Intake
and failed proofs cannot perform registration.

Use the preceding Native proposer control as a public signature source, or
create it once with `tests/e2e/slh-proposer.sh prepare slh-proposer-output`.
The first-use preparation retains its genuine primary first/later signatures;
switching the first envelope from Reference to Embedded preserves the signing
hash and transaction identity. A new independent proposer signs the new
headers while its key is in memory, then drops it. No sender private key or
new sender signature is needed:

```bash
tests/e2e/slh-proposer-first-use.sh prepare slh-proposer-output primary-first-use
tests/e2e/slh-proposer-first-use.sh capture primary-first-use
tests/e2e/slh-proposer-first-use.sh pause primary-first-use
tests/e2e/slh-proposer-first-use.sh resume primary-first-use
tests/e2e/slh-proposer-first-use.sh verify primary-first-use
tests/e2e/slh-proposer-first-use.sh refuse primary-first-use
tests/e2e/slh-proposer-first-use.sh publish primary-first-use
```

Use new output directories and retain signatures, controls, failed outputs and
durable progress. Preparation verifies Reference-without-key, changed address,
message and Embedded-key refusals, then compares two independent Native imports
and genuine later state changes. Never repeat preparation to replace dropped
keys or existing data. The Rust/RocksDB/C++ dependencies above apply, and every
failed command exits nonzero.

Source 9, batch 5 and frame 6 explicitly distinguish this profile from bound
Source 8/batch 4/frame 5. The complete tagged-address AIR binds the algorithm
tag and all 1,952 sender-key bytes to the account address; account, signature,
identity/body and full seventeen-layer raw-header proposer proofs remain
mandatory. Neither a nonzero commitment nor a future key cache can replace
the sealed zero-commitment parent. Old profiles reject relabeling. Existing
checkpoint/component encodings, quotas and Native lifecycle, economics,
selection, quorum and activation rules remain unchanged.

Proof-backed Native commit registers the Embedded key. Cold replay after the
retained second state must keep the current key present, resolve the first
block's absent sealed-parent sender key, prove both signature roles, match
ordinary Native receipts/root and write no current state. Refusal includes a
missing address certificate, bound-profile substitution and a genuine hash
certificate in the wrong header slot; rejected graphs leave genesis and the
sender registration unchanged.

The ready frame also uses the ordinary peer entry:

```bash
tests/e2e/slh-peer-proof.sh prepare primary-first-use primary-first-use/published primary-first-use-peer
tests/e2e/slh-peer-proof.sh pause primary-first-use primary-first-use/published primary-first-use-peer
tests/e2e/slh-peer-proof.sh resume primary-first-use primary-first-use/published primary-first-use-peer
tests/e2e/slh-peer-proof.sh verify primary-first-use primary-first-use/published primary-first-use-peer
tests/e2e/slh-peer-proof.sh refuse primary-first-use primary-first-use/published primary-first-use-peer
```

The receiver must remain unregistered during partial or rejected proof transfer
and register only after complete verified Native import. Finality separately
requires the genuine attached certificate. Fresh automatic-worker generation
for this first-use profile uses the entry below. Other sender/account
combinations, quorum AIR, power-loss recovery, public artifacts and network
activation require separate acceptance.

#### Fresh automatic generation for primary first use with an SLH proposer

Reuse the existing `primary-first-use` Native output and its retained first and
later signed blocks. The automatic entry restores only historical parent keys:
the sender has no key at genesis, while the SLH proposer is already registered.
It checks the funded zero-commitment default account and the complete 1952-byte
primary key's tagged address before ordinary Native import. Only that import
registers the Embedded sender key and captures the source 9 job.

```sh
tests/e2e/slh-canonical.sh automatic-fresh-prepare primary-first-use primary-first-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause primary-first-use primary-first-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume primary-first-use primary-first-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify primary-first-use primary-first-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse primary-first-use primary-first-automatic
```

Preparation must report source 9, an empty mathematical job and no proof donor.
The actual public-only `Node.run` worker generates a nonzero durable pause and
cold-resumes the complete primary signature/address and seventeen-layer SLH
proposer graph under the existing quotas. It publishes frame 6 through the
authenticated RPC only after verification, without signing again. A checkpoint
with a correct outer hash but damaged mathematical proof must fail without
Native state changes or automatic retries.

Verification imports the retained genuine second block, then replays the first
proof against its sealed parent. The sender key must remain absent there even
though it exists in the current registry. Both sender and proposer proofs,
receipts and state must match the independent Native controls without writeback.

The generated frame also serves the existing peer regression:

```sh
tests/e2e/slh-peer-proof.sh prepare primary-first-use primary-first-automatic primary-first-automatic-peer
tests/e2e/slh-peer-proof.sh pause primary-first-use primary-first-automatic primary-first-automatic-peer
tests/e2e/slh-peer-proof.sh resume primary-first-use primary-first-automatic primary-first-automatic-peer
tests/e2e/slh-peer-proof.sh verify primary-first-use primary-first-automatic primary-first-automatic-peer
tests/e2e/slh-peer-proof.sh refuse primary-first-use primary-first-automatic primary-first-automatic-peer
```

Partial or rejected transfer must leave the receiver's genesis and missing
sender registration unchanged. Complete verified Native import registers the
key, and the genuine attached certificate supplies finality. Cold replay and a
genuine certificate for the wrong header remain separate checks. Source 8 bound
proposers and source 7 first-use senders retain their existing profiles and
encodings; the worker still defaults off. Other role/account combinations,
quorum AIR, power-loss recovery, public release and network activation remain
separate acceptance work.

#### Bound published SDK sender with an SLH proposer

Use the existing `sdk-output` from the published SDK bound-sender entry above.
If no such control exists, create it once with
`tests/e2e/dilithium-full-proof.sh sdk sdk-output`, which installs the pinned
public `shell-sdk@0.14.0-rc.3` consumer. Keep that control and its signed first
and later transactions; do not rerun preparation to replace dropped keys.

```sh
tests/e2e/slh-proposer-sdk.sh prepare sdk-output sdk-slh-output
tests/e2e/slh-proposer-sdk.sh capture sdk-slh-output
tests/e2e/slh-proposer-sdk.sh pause sdk-slh-output
tests/e2e/slh-proposer-sdk.sh resume sdk-slh-output
tests/e2e/slh-proposer-sdk.sh verify sdk-slh-output
tests/e2e/slh-proposer-sdk.sh refuse sdk-slh-output
tests/e2e/slh-proposer-sdk.sh publish sdk-slh-output
```

Preparation retains the original SDK transaction and signature bytes and checks
the public package version/key plus the actual Native SDK transcript. The sender
already has its bound default-account parent registration. A distinct SLH
proposer signs the new first and later Native headers and quorum controls with
memory-only keys, then drops them. Both independent Native nodes must agree on
receipts, accounts and the genuinely changed second state. No sender signing or
replacement is needed.

Capture reports source 10, batch 6 and frame 7. The Native sender tag remains
zero: account/signature profile 5 and SDK transaction source 3 require the
complete FIPS signature/challenge profile 1 with a 48-byte challenge seed.
This preserves the SDK domain rather than accepting a raw PQClean or primary-tag
certificate in its place. The proposer proves its full raw header and all
seventeen SHA2-256f signature layers against the sealed parent key. Earlier
primary sender source 8/9 profiles retain their distinct account requirements.

`pause` and `resume` preserve durable progress within the existing 256 MiB
checkpoint/payload, 2,048-certificate and shared 1 GiB expansion limits. `verify`
imports the first complete graph through Native execution, advances to the
retained genuine second block and checks historical replay on both independent
controls without writing current state. `refuse` covers missing/changed proposer
roles and layers, SDK/raw/primary account and transaction substitutions, raw
challenge relabeling and a genuine certificate in the wrong header slot.

For the ordinary CLI, use `sdk-slh-output` in the complete-job command above;
it must reverify the retained components and report zero newly proved components.
`publish` provides availability only. Check actual peer transport and Native
admission with the published frame:

```sh
tests/e2e/slh-peer-proof.sh prepare sdk-slh-output sdk-slh-output/published sdk-slh-peer
tests/e2e/slh-peer-proof.sh pause sdk-slh-output sdk-slh-output/published sdk-slh-peer
tests/e2e/slh-peer-proof.sh resume sdk-slh-output sdk-slh-output/published sdk-slh-peer
tests/e2e/slh-peer-proof.sh verify sdk-slh-output sdk-slh-output/published sdk-slh-peer
tests/e2e/slh-peer-proof.sh refuse sdk-slh-output sdk-slh-output/published sdk-slh-peer
```

Partial or rejected transfer must preserve receiver genesis. Complete verified
import must match the independent Native receipts/accounts; finality separately
requires the genuine attached quorum certificate. Cold replay and a genuine
wrong-header certificate remain required checks.

To produce Source 10 through the background worker, keep the same
`sdk-slh-output` and choose a new output directory. This entry starts with an
empty mathematical job and never opens the completed standalone proof as a
donor:

```sh
tests/e2e/slh-canonical.sh automatic-fresh-prepare sdk-slh-output sdk-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause sdk-slh-output sdk-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume sdk-slh-output sdk-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify sdk-slh-output sdk-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse sdk-slh-output sdk-slh-automatic
tests/e2e/slh-peer-proof.sh prepare sdk-slh-output sdk-slh-automatic sdk-slh-automatic-peer
tests/e2e/slh-peer-proof.sh pause sdk-slh-output sdk-slh-automatic sdk-slh-automatic-peer
tests/e2e/slh-peer-proof.sh resume sdk-slh-output sdk-slh-automatic sdk-slh-automatic-peer
tests/e2e/slh-peer-proof.sh verify sdk-slh-output sdk-slh-automatic sdk-slh-automatic-peer
tests/e2e/slh-peer-proof.sh refuse sdk-slh-output sdk-slh-automatic sdk-slh-automatic-peer
```

Ordinary Native import must capture a queued Source 10 job with zero components.
The actual worker generates durable progress, stops gracefully and continues
from disk in a new process. Its authenticated RPC must return the complete
frame 7 graph without claiming Native execution merely from availability.
Cold verification advances to the retained second Native block and replays the
first graph against the exact registered sender and proposer keys in its sealed
parent, without writing either current database. A damaged mathematical
checkpoint with a corrected outer hash must fail without retries or Native
state changes. The generated frame then follows the same real peer admission
and independent finality checks above. No sender or proposer signing keys are
needed, and proof production remains disabled by default.

Two SLH roles, other accounts, quorum AIR, power-loss recovery, public artifacts
and network activation remain separate acceptance work.

#### Bound raw PQClean sender with an SLH proposer

Keep the `dilithium-output` from the genuine PQClean sender entry above. If it
does not exist, create it once with
`tests/e2e/dilithium-full-proof.sh run dilithium-output`. Use the same Python 3,
stable Rust and RocksDB C/C++/libclang prerequisites. This source regression is
expensive; retain its public signatures and Native checkpoints to continue it.
Preparation refuses an existing destination and never recreates dropped keys.

```sh
tests/e2e/slh-proposer-raw.sh prepare dilithium-output raw-slh-output
tests/e2e/slh-proposer-raw.sh capture raw-slh-output
tests/e2e/slh-proposer-raw.sh pause raw-slh-output
tests/e2e/slh-proposer-raw.sh resume raw-slh-output
tests/e2e/slh-proposer-raw.sh verify raw-slh-output
tests/e2e/slh-proposer-raw.sh refuse raw-slh-output
tests/e2e/slh-proposer-raw.sh publish raw-slh-output
```

Preparation checks both original Native tag-zero raw transcripts and their
bound default-account parent registration. A distinct memory-only SLH proposer
signs first-block and successor headers and genuine quorum controls, then drops
its keys. The sender signs nothing new. Independent Native controls must agree
on receipts, accounts, fees and changed successor state before proof production.

Capture selects Source 12, batch 8 and frame 9. The sender keeps registered
account/signature profile 3, transaction source 2 and full raw signature/challenge
version 2: all 48 c-tilde bytes bind the commitment, while SampleInBall uses the
first 32 bytes. SDK FIPS framing, primary tags and unbound account profiles are
refused. The proposer graph proves its exact raw header against the sealed
registered key, including all seventeen SHA2-256f layers.

`pause` persists one actual component; a separate `resume` process verifies that
checkpoint and generates the remaining graph. `verify` imports the complete
proof through Native execution and genuine finality, advances to the retained
second block, then replays historical verification on both independent controls
without writing current state. `refuse` rejects domain/profile substitutions,
missing or changed proposer layers and genuine certificates for foreign headers
without Native mutation. Assertions exit nonzero on failure. Existing payload,
checkpoint, certificate, expansion and transport limits remain in force.

Use `raw-slh-output` in the complete-job CLI command above; it must report zero
newly proved components and preserve the accepted graph. Check real transport
and Native admission separately from availability:

```sh
tests/e2e/slh-peer-proof.sh prepare raw-slh-output raw-slh-output/published raw-slh-peer
tests/e2e/slh-peer-proof.sh pause raw-slh-output raw-slh-output/published raw-slh-peer
tests/e2e/slh-peer-proof.sh resume raw-slh-output raw-slh-output/published raw-slh-peer
tests/e2e/slh-peer-proof.sh verify raw-slh-output raw-slh-output/published raw-slh-peer
tests/e2e/slh-peer-proof.sh refuse raw-slh-output raw-slh-output/published raw-slh-peer
```

The receiver must preserve genesis after partial or rejected transfer. Complete
verified import must match the Native control and finalize with its genuine
quorum certificate. Cold replay and foreign-header refusal remain independent
checks. Raw first-use background generation, a later Reference target, other
account/role combinations,
public release and activation remain separate acceptance work. Proof production
still defaults off.

To generate Source 12 through the background worker, keep the same
`raw-slh-output` and choose a new automatic output. This entry does not open
the completed standalone graph as a mathematical donor:

```sh
tests/e2e/slh-canonical.sh automatic-fresh-prepare raw-slh-output raw-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause raw-slh-output raw-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume raw-slh-output raw-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify raw-slh-output raw-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse raw-slh-output raw-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-rpc-refuse raw-slh-output raw-slh-automatic
tests/e2e/slh-peer-proof.sh prepare raw-slh-output raw-slh-automatic raw-slh-automatic-peer
tests/e2e/slh-peer-proof.sh pause raw-slh-output raw-slh-automatic raw-slh-automatic-peer
tests/e2e/slh-peer-proof.sh resume raw-slh-output raw-slh-automatic raw-slh-automatic-peer
tests/e2e/slh-peer-proof.sh verify raw-slh-output raw-slh-automatic raw-slh-automatic-peer
tests/e2e/slh-peer-proof.sh refuse raw-slh-output raw-slh-automatic raw-slh-automatic-peer
```

Ordinary Native import must capture a queued Source 12 job with zero
mathematical components and no availability cache. Both sender and proposer
keys come from the sealed registered parent. The actual public-only `Node.run`
worker must persist a component-budget pause, stop gracefully and continue that
same job from disk in a new process. Never repeat successful preparation to
replace a paused output or dropped keys. Authenticated RPC retrieval must return
the full frame 9 graph while reporting availability separately from execution.

Cold verification advances to the retained second Native state and replays the
first graph against the original parent on both independent controls without
writing either current database. A damaged inner component with a corrected
outer hash must fail without Native mutation or retries. A separate status
source-hash refusal must surface through the authenticated RPC and shut the
Node down gracefully, preserving the original job. Finally, the generated frame
must pass real peer transfer, cold continuation, proof-backed Native import,
genuine certificate finality and foreign-header refusal. Warm checkpoint reuse
does not establish fresh generation; broader accounts, first-use raw background
generation, later Reference targets, power-loss recovery, public artifacts and activation remain
separate checks.

#### Funded raw first use with an SLH proposer

Keep `raw-first-output` from the genuine funded unbound raw sender entry above.
If needed, create it once with
`tests/e2e/dilithium-full-proof.sh unbound raw-first-output`, using Python 3,
stable Rust and the RocksDB C/C++/libclang prerequisites. Retain all three
original signed inputs: Embedded first use, the Reference successor and the
ordinary third transaction. Preparation refuses an existing destination; never
rerun it to replace dropped keys or a paused proof job.

```sh
tests/e2e/slh-proposer-raw.sh prepare-first-use raw-first-output raw-first-slh
tests/e2e/slh-proposer-raw.sh capture raw-first-slh
tests/e2e/slh-proposer-raw.sh pause raw-first-slh
tests/e2e/slh-proposer-raw.sh resume raw-first-slh
tests/e2e/slh-proposer-raw.sh verify raw-first-slh
tests/e2e/slh-proposer-raw.sh refuse raw-first-slh
tests/e2e/slh-proposer-raw.sh publish raw-first-slh
```

The original sender signs nothing new. Its sealed parent must contain a funded
default account with a zero key commitment, no registered sender key and a
matching Embedded 1,952-byte key. Preparation checks the actual raw Native
tag-zero transcript of every retained signature. One new independent SLH
proposer signs genuine headers and quorum controls for all three transactions,
then drops its memory-only keys. Both independent Native controls must agree on
receipts, accounts, state changes and finality at heights 1, 2 and 3. Separate
checkpoints preserve every available header and quorum certificate before key
disposal; neither old sender nor proposer identities are regenerated.

Capture selects Source 13, batch 9 and frame 10. Account/signature profile 4
requires the full `BLAKE3(0 || pubkey)` address AIR, zero-commitment parent MPT
and raw transaction source 2. Complete raw signature/challenge version 2 keeps
the first-32-byte sampler domain and all 48 commitment bytes. SDK FIPS framing,
primary tags and bound Source 12 cannot substitute. The registered SLH proposer
proves the exact raw header and all seventeen SHA2-256f layers against its sealed
historical key. Earlier profiles retain their original predicates and formats.

`pause` stores one real component. A separate `resume` process verifies that
checkpoint and generates the remaining graph within the existing quotas.
`verify` imports the complete first-block proof, registers its sender and
finalizes with the genuine original certificate. The retained second and third
blocks then change current state. Cold first-block replay against both the proof
receiver and ordinary Native third-state control must still use the absent
parent key and write neither database, even though the current key is present.
`refuse` covers Native Reference-without-parent-key rejection, missing or
tag-changed address AIR, raw/SDK/primary/bound profile and transcript swaps,
missing or changed proposer layers, and genuine foreign-header certificates.
Every assertion exits nonzero on failure.

Use `raw-first-slh` in the complete-job CLI command above: revalidation must
report zero newly proved components and preserve the accepted graph. Publication
provides availability only; exercise actual transport and Native admission:

```sh
tests/e2e/slh-peer-proof.sh prepare raw-first-slh raw-first-slh/published raw-first-slh-peer
tests/e2e/slh-peer-proof.sh pause raw-first-slh raw-first-slh/published raw-first-slh-peer
tests/e2e/slh-peer-proof.sh resume raw-first-slh raw-first-slh/published raw-first-slh-peer
tests/e2e/slh-peer-proof.sh verify raw-first-slh raw-first-slh/published raw-first-slh-peer
tests/e2e/slh-peer-proof.sh refuse raw-first-slh raw-first-slh/published raw-first-slh-peer
```

The receiver starts with the genuine funded genesis and no sender registration.
Partial or rejected transfer must preserve it. Successful proof-backed import
must register the original key and match Native receipts/accounts; finality
separately requires the attached genuine quorum certificate. Cold replay and
foreign-header refusal remain independent checks. This first-use target does
not qualify a later Reference proof or fresh background generation. Other
accounts/roles, quorum AIR, power-loss recovery, public artifacts and activation
remain separate acceptance work; production defaults and limits do not change.

#### Funded SDK first use with an SLH proposer

Keep the existing `sdk-first-use-output` from the funded unbound SDK entry.
If needed, create it once with
`tests/e2e/dilithium-full-proof.sh sdk-unbound sdk-first-use-output`, using the
same pinned public `shell-sdk@0.14.0-rc.3` prerequisites. Preserve its original
Embedded first transaction and later Reference transaction after the SDK keys
are dropped. Preparation supports a retained SDK node that has already advanced
by authenticating its first block against the current canonical chain.

```sh
tests/e2e/slh-proposer-sdk.sh prepare-first-use sdk-first-use-output sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh capture sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh pause sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh resume sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh verify sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh refuse sdk-first-use-slh
tests/e2e/slh-proposer-sdk.sh publish sdk-first-use-slh
tests/e2e/slh-peer-proof.sh prepare sdk-first-use-slh sdk-first-use-slh/published sdk-first-use-slh-peer
tests/e2e/slh-peer-proof.sh pause sdk-first-use-slh sdk-first-use-slh/published sdk-first-use-slh-peer
tests/e2e/slh-peer-proof.sh resume sdk-first-use-slh sdk-first-use-slh/published sdk-first-use-slh-peer
tests/e2e/slh-peer-proof.sh verify sdk-first-use-slh sdk-first-use-slh/published sdk-first-use-slh-peer
tests/e2e/slh-peer-proof.sh refuse sdk-first-use-slh sdk-first-use-slh/published sdk-first-use-slh-peer
```

This entry creates one independent SLH proposer in memory, signs the new first
and later headers/quorum controls, then drops its keys. Sender signatures and
transactions remain unchanged. The funded genesis account has zero key
commitment and no registered sender key. Intake must preserve that absence;
only Native commit of the original Embedded transaction registers its key.
The later original Reference transaction must then succeed on both independent
Native controls.

Capture selects Source 11, batch 7 and frame 8. Account/signature profile 6
requires the full `BLAKE3(0 || pubkey)` address proof for the 1,952-byte SDK key.
It also requires SDK transaction source 3 and full FIPS signature/challenge
profile 1 with the 48-byte seed. The registered 64-byte SLH proposer key binds
the exact raw header and all seventeen SHA2-256f signature layers. Bound SDK
Source 10 and primary first-use Source 9 keep their distinct formats.

Durable pause/cold continuation, ordinary CLI zero-new-component completion,
full Native import/key registration, genuine changed-state history and actual
peer admission/finality follow the checks above. Historical replay must see the
absent sealed-parent sender key despite its current registration, and must not
write either current database. Refusals cover missing/tag-changed address AIR,
bound/raw/primary account and SDK transaction/challenge substitutions, missing
proposer layers and genuine wrong-header certificates. Existing size/count/
expansion limits and default-off production remain unchanged. Raw Native
tag-zero SLH proposer combinations,
two SLH roles, other accounts, quorum AIR, power-loss recovery, public artifacts
and network activation remain separate acceptance work.

For background generation, use the same Native control with a new automatic
output directory. If this job already has a durable initial pause, continue
with `automatic-fresh-resume`; do not repeat preparation or replace the job.

```sh
tests/e2e/slh-canonical.sh automatic-fresh-prepare sdk-first-use-slh sdk-first-use-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause sdk-first-use-slh sdk-first-use-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume sdk-first-use-slh sdk-first-use-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify sdk-first-use-slh sdk-first-use-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse sdk-first-use-slh sdk-first-use-slh-automatic
tests/e2e/slh-peer-proof.sh prepare sdk-first-use-slh sdk-first-use-slh-automatic sdk-first-use-slh-automatic-peer
tests/e2e/slh-peer-proof.sh pause sdk-first-use-slh sdk-first-use-slh-automatic sdk-first-use-slh-automatic-peer
tests/e2e/slh-peer-proof.sh resume sdk-first-use-slh sdk-first-use-slh-automatic sdk-first-use-slh-automatic-peer
tests/e2e/slh-peer-proof.sh verify sdk-first-use-slh sdk-first-use-slh-automatic sdk-first-use-slh-automatic-peer
tests/e2e/slh-peer-proof.sh refuse sdk-first-use-slh sdk-first-use-slh-automatic sdk-first-use-slh-automatic-peer
```

Preparation must capture Source 11 through ordinary Native import with zero
mathematical components and no proof donor. Native key registration must happen
at commit; the restored genesis sender key stays absent. The worker generates
durable progress and cold-resumes the complete frame 8 graph, with no new SDK
or proposer signing. Authenticated RPC retrieval provides availability only.
Cold verification must replay against the absent sealed-parent sender key after
genuine state 2, match both Native controls and write neither current database.
A damaged checkpoint with a corrected component hash must fail without Native
changes or retries. The generated frame then passes real peer transfer,
Native key registration/import, attached-certificate finality and cold replay.


#### SDK Reference proof with an SLH proposer after first use

Keep all three original signed transactions from `sdk-first-use-output`: the
Embedded nonce-zero transaction and the Reference transactions with nonces one
and two. Use the pinned public SDK prerequisites above. This entry creates a
separate SLH proposer control once; it does not extend or replace a two-block
control whose proposer keys have already been dropped.

```sh
tests/e2e/slh-proposer-sdk.sh prepare-reference sdk-first-use-output sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh capture sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh pause sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh resume sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh verify sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh refuse sdk-reference-slh
tests/e2e/slh-proposer-sdk.sh publish sdk-reference-slh
tests/e2e/slh-peer-proof.sh prepare sdk-reference-slh sdk-reference-slh/published sdk-reference-slh-peer
tests/e2e/slh-peer-proof.sh pause sdk-reference-slh sdk-reference-slh/published sdk-reference-slh-peer
tests/e2e/slh-peer-proof.sh resume sdk-reference-slh sdk-reference-slh/published sdk-reference-slh-peer
tests/e2e/slh-peer-proof.sh verify sdk-reference-slh sdk-reference-slh/published sdk-reference-slh-peer
tests/e2e/slh-peer-proof.sh refuse sdk-reference-slh sdk-reference-slh/published sdk-reference-slh-peer
```

Preparation validates the retained SDK signatures before creating the independent
SLH proposer. It signs three genuine headers and quorum controls, then drops
the proposer keys; SDK signing is never called. Both Native controls execute the
original Embedded transaction in block 1, the target Reference transaction in
block 2 and the later Reference transaction in block 3. The independently
imported and finalized block-1 checkpoint is preserved before either control
advances. Proof and peer receivers start from that actual parent, with its
registered sender key and no target block, receipts or state root preloaded.

The funded account still has a zero key commitment, so the Reference target
uses Source 11/batch 7/frame 8 and the complete tagged-address/FIPS graph. A zero
account commitment does not imply an absent registered key: authority must come
from the sealed block-1 parent. Proof import must match ordinary Native receipts,
accounts and state root and finalize block 2 with its genuine certificate.
Cold historical replay after genuine block 3 must reproduce block 2 without
writing either current database. Durable continuation, ordinary CLI completion
without new mathematical components, real peer chunk recovery/finality and
wrong-statement refusals remain required. Fresh automatic generation for this Reference target uses the separate
empty-job entry below; standalone completion does not qualify that worker.
Production defaults, quotas and network activation remain unchanged.


For fresh background production of the Reference target, retain the same
three-block `sdk-reference-slh` control and choose a new automatic output.
Preparation restores its genuine independent parent at height 1. Ordinary Native
import of target block 2 must capture a Source 11 job with zero mathematical
components, without opening the standalone graph as a donor. The sender key is
already registered in this sealed parent; its account commitment remains zero.

```sh
tests/e2e/slh-canonical.sh automatic-fresh-prepare sdk-reference-slh sdk-reference-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-pause sdk-reference-slh sdk-reference-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-resume sdk-reference-slh sdk-reference-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-verify sdk-reference-slh sdk-reference-slh-automatic
tests/e2e/slh-canonical.sh automatic-fresh-refuse sdk-reference-slh sdk-reference-slh-automatic
tests/e2e/slh-peer-proof.sh prepare sdk-reference-slh sdk-reference-slh-automatic sdk-reference-slh-automatic-peer
tests/e2e/slh-peer-proof.sh pause sdk-reference-slh sdk-reference-slh-automatic sdk-reference-slh-automatic-peer
tests/e2e/slh-peer-proof.sh resume sdk-reference-slh sdk-reference-slh-automatic sdk-reference-slh-automatic-peer
tests/e2e/slh-peer-proof.sh verify sdk-reference-slh sdk-reference-slh-automatic sdk-reference-slh-automatic-peer
tests/e2e/slh-peer-proof.sh refuse sdk-reference-slh sdk-reference-slh-automatic sdk-reference-slh-automatic-peer
```

If the automatic job already has a durable initial pause, continue from that
job with `automatic-fresh-resume`. Preserve the original Native control, signed
SDK transactions, signed SLH headers and quorum controls; all signing keys have
already been dropped. The actual worker must generate the complete frame 8
graph after cold continuation. Authenticated RPC retrieval supplies availability
only. Cold replay after genuine block 3 must match both current Native stores,
use the registered sealed-parent keys and write neither database. A damaged
component with a corrected outer hash must fail without retries or Native
changes. The generated frame must also pass real peer chunk recovery, Native
import, attached-certificate finality at height 2 and cold replay/refusal.
Production defaults, quotas, public release and network activation are unchanged.


A Reference worker starts only after the original target quorum certificate has
been verified and persisted. With an already finalized parent, normal startup
rewinds an unfinalized suffix. Retaining that genuine certificate completes the
Native consensus stage; do not disable startup recovery or change finality
parameters to keep an uncertified target. For an existing stopped automatic job,
the entry can reimport the same retained target after this expected rewind and
complete its genuine finality before resuming. It preserves all existing jobs
and components and records the completed Native baseline separately. Production
must leave that baseline unchanged. Authenticated status errors must fail the
regression and shut down its Node gracefully, rather than being hidden by a
long polling loop.


Exercise the status-error shutdown regression separately on a copy of the
completed job. It changes only local status provenance in that copy, preserving
the original graph and Native data. An authenticated status error must surface
and the Node must stop gracefully without new signing or proving:

```sh
tests/e2e/slh-canonical.sh automatic-fresh-rpc-refuse sdk-reference-slh sdk-reference-slh-automatic
```
