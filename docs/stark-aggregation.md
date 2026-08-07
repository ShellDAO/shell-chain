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
