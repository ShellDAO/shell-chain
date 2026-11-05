# STARK Aggregate Proof

> Shell Chain — Asynchronous STARK Signature Aggregation (STK block)

---

## Overview

The target is to compress the evidence for PQ-signed transactions into STARK
proofs. The current implementation is a **batch-commitment STARK**: native
validation checks the PQ signatures, and the prover builds a dual accumulator
from message/public-key hash entries. Its four-column AIR checks accumulator
transitions and boundary values. It does **not** implement Dilithium3 or
ML-DSA signature verification inside the AIR. Full in-AIR PQ verification
remains an unimplemented target; a commitment proof must not be described as
that capability or used to bypass applicable native/canonical-source checks.

Proof generation runs asynchronously after block sealing. A prover wraps the
artifact in an authenticated `ProofAmendment` and propagates it via P2P. Peers
apply the relevant authentication, source, registration and proof checks before
using an artifact for settlement or witness replacement.

### Run the current proof statement

In the `0.27.14` development source checkout, run:

```bash
cargo run --locked -p shell-stark-prover --example batch-commitment
```

The [example](../crates/stark-prover/examples/batch-commitment.rs) generates a
temporary ML-DSA key in memory, verifies two genuine signatures natively,
generates actual Winterfell proof bytes, verifies them and checks a JSON
roundtrip. It rejects changed native signatures/messages, a mismatched expected
source root, a changed proof root/count, a truncated proof, and a commitment-only
payload. No private key is printed or saved. An assertion failure exits nonzero.

The example also shows why native verification is separate: changing a signature
does not change the message/key hash entries supplied to this AIR. It is a
primitive proof-statement demonstration, not block admission, registration,
settlement, pruning, full PQ verification in AIR, or a released binary acceptance.

---

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
  5. Prove the batch commitment of native-verified message/key entries
  6. Wrap in the versioned ProofAmendment envelope and authenticate its metadata
  7. Store in ProofAmendmentStore (key: "pa/<block_hash>")
  8. Broadcast amendment via P2P gossip

  Peers
  ─────
  9.  Receive amendment gossip
  10. Check envelope authentication and applicable source/registration/proof rules
  11. Store in local ProofAmendmentStore
  12. Prune only after canonical settlement and profile/grace eligibility
```

---

## ProofAmendment Format

The current source serializes the following JSON fields. Hashes, addresses and
`prover_signature` use `0x`-prefixed hex; the proof's `batch_root_bytes` and
`proof_bytes` use JSON byte arrays.

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u8` | Amendment version `1`. |
| `block_hash` | `ShellHash` | Hash of the inclusive end block. |
| `end_block` | `u64` | Inclusive end height; Rust field `block_number` (also accepted as a legacy JSON alias). |
| `start_block` | optional `u64` | Inclusive start height. |
| `source_hashes` | `Vec<ShellHash>` | Canonical hashes in source order. Legacy single-block payloads may omit the range fields. |
| `proof.version` | `u8` | `SigBatchProof` version `2`. |
| `proof.batch_root_bytes` | `[u8; 32]` | 32-byte accumulator root. |
| `proof.n_sigs` | `usize` | Number of covered signature entries. |
| `proof.proof_bytes` | `Vec<u8>` | Serialized Winterfell proof; empty only for a commitment-only payload. |
| `prover` | `Address` (`0x` + 64 lowercase hex) | Address bound to the envelope's public key and algorithm. |
| `prover_signature` | `Bytes` | Versioned envelope: authentication version, algorithm ID, two-byte big-endian public-key length, public key, PQ signature. |
| `layer` | `u32` | Compression layer; defaults to `1`. |
| `original_size`, `compressed_size` | optional `u64` | Source payload size and signed artifact size. |
| `settlement_tx_hash` | optional `ShellHash` | Canonical settlement link, checked separately from prover authentication. |

Use `ProofAmendment::sign_prover_authentication` to set the prover address,
compressed size and authentication envelope. Its `signing_message()` uses the
`shell-proof-amendment-auth-v1` domain and binds the block/source range, proof
version/root/count/proof-bytes digest, prover, layer and compression metadata.
A raw signature over the old short concatenation is invalid. Verify with
`verify_prover_authentication` before treating the envelope as authentic;
canonical source, registration activation and STARK proof checks still apply.

The [Prover Guide example](PROVER_GUIDE.md#serialize-and-authenticate-an-amendment)
runs serialization, genuine PQ authentication and changed-root rejection using
the source API. Its commitment-only payload demonstrates the format and is not
a submitted proof or a settlement.

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

These optional fields are omitted when the block has no aggregate proof;
consumers should also tolerate `null` from other versions. Presence or a nonzero
summary size alone does not establish a full Winterfell payload or PQ signature
validity. The handler can consult the `ProofAmendmentStore` when no inline proof
is present. Inspect the amendment response and apply the appropriate verifier
rather than treating a block summary as a verified proof.

### Fetch a proof amendment directly

```bash
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"shell_getProofAmendment","params":["0x<block_hash>"],"id":1}'
```

**Response (amendment summary, illustrative values):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block_hash": "0x<64 hex digits>",
    "block_number": 12345,
    "start_block": 12345,
    "end_block": 12345,
    "source_count": 1,
    "layer": 1,
    "proof_entries": 1,
    "original_size": null,
    "compressed_size": null,
    "proof_version": 1,
    "prover": "0x<64 hex digits>",
    "settlement_tx_hash": null,
    "proof": "0x<Winterfell proof bytes>"
  }
}
```

`proof_version` here is the **outer amendment** version (`1`), not the inner
`SigBatchProof.version` (`2`). This RPC returns an inspection summary, not the
serialized, signed `ProofAmendment` JSON described above. It does not expose the
complete authentication envelope or batch root. Do not feed this summary to
`ProofAmendment::from_json` or treat the prover address alone as authentication.

For an amendment, `proof` is the hex-encoded `proof.proof_bytes`. A
commitment-only payload returns `"proof": "0x"`, which is not a full STARK proof.
A range's non-terminal source may instead return a **pointer** object with
`source_hash`, `source_block`, `target_hash`, `target_block`, `start_block`,
`end_block`, `source_count`, `layer`, `settlement_tx_hash` and `"proof": null`.
Query `target_hash` for the target amendment; a pointer is not itself proof bytes.
When no artifact is available, the entire result is JSON `null`.

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

Receiving an amendment alone does not authorize witness deletion. Replacement
must satisfy the canonical settled frontier and the storage profile's retention
and `proof_replacement_grace` rules; archive nodes retain witnesses. See the
[pruning rules](BLOCK_PRUNING_AND_COMPRESSION.md) for the exact cutoff. Challenges for a proof stay `Open` for at most `T_c = 7200` blocks; a valid response marks them `Resolved`, while a timeout marks them `Slashed` and triggers prover slashing.

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

1. **Prover registration** — Registered-only admission applies when the
   `prover_registry_height` activation rule is enabled. The authenticated
   prover address must match its public key and the applicable registry policy.
2. **Prover authentication** — Verify the versioned public-key/signature
   envelope over `ProofAmendment::signing_message()`. It binds the full source
   range, proof metadata and proof-bytes digest described in
   [the format section](#proofamendment-format). The old short concatenation
   `(block_hash || block_number || batch_root_bytes)` is not this message.
3. **Proof statement** — The current AIR proves accumulator consistency over
   hash-derived entries. Native PQ signature validation and canonical-source
   binding remain separate requirements. Full cryptographic PQ verification
   inside the AIR is still unimplemented. A commitment-only payload has no
   Winterfell proof bytes; neither envelope authentication nor an RPC summary
   alone establishes full proof verification or settlement.
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
