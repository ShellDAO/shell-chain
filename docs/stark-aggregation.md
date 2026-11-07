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

A dedicated prover can opt into full ML-DSA-65 sender-certificate generation:

```bash
shell-node --datadir node-data run --config node.toml --db rocksdb \
  --node-role prover --canonical-proof-production
```

Use a RocksDB-enabled build, a previously initialized node with an activated
body-commitment schedule and its matching `node.toml` runtime configuration.
An eligible canonical block contains 1–16 supported ML-DSA-65 user transactions
and only gas-reward system transactions. The supported profile requires
parent-registered keys, default account validation, transaction types 0–3 and
signing payloads within the existing 4096-byte hash limit. AA, first-use key
registration and other signature algorithms require separate producer work.
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
Supported blocks have 1–16 registered default-account ML-DSA-65 senders,
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
