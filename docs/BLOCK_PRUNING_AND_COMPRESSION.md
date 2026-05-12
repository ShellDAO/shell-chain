# Block Pruning and Compression

Shell Chain implements a **three-segment block storage model** that separates
transaction details, PQ signatures, and STARK aggregate proofs into independent
storage keys — each with its own lifecycle and retention policy.

---

## Why Three Segments?

The naive approach stores every block as a single RLP blob containing
transaction payloads *and* Dilithium3 signatures side by side. This creates two
problems:

1. **All-or-nothing pruning** — any pruner that frees space also destroys
   transaction details needed for the explorer and RPC.
2. **STARK compression wasted** — the STARK prover reduces N individual
   signatures into a single aggregate proof, but if the original signatures are
   never removed, no disk space is actually freed.

The three-segment model solves both by giving each data class its own key and
its own deletion trigger.

---

## Storage Layout

| Segment | RocksDB key | Content | Size (50-tx block) | Retention |
|---|---|---|---|---|
| **TX Detail** | `b/<block_hash>` | `StrippedBlock` — header + `Vec<StrippedTransaction>` (from/to/value/nonce/gas/input) | ~7 KB | Profile-dependent (see below) |
| **Witness Bundle** | `w/<block_hash>` | `WitnessBundle` — one `TxWitness` per tx (Dilithium3 sig + optional pubkey) | ~180 KB | Deleted after STARK proof arrives |
| **STARK Proof** | `pa/<block_hash>` | `ProofAmendment` — Winterfell aggregate proof or pointer metadata for a contiguous source range | ~15 KB for full proof, tiny for pointer | **Forever** |

### Per-transaction witness breakdown

```
TxWitness (Dilithium3 mode):
  signature.data   3,309 bytes   always present
  pubkey           1,952 bytes   only for sender's first-ever tx (~30 % of txs)
  RLP overhead       ~50 bytes
  ─────────────────────────────
  avg per tx       ~3,900 bytes  (weighted by pubkey frequency)
```

### Aggregate STARK proof

A `SigBatchProof` (Winterfell STARK) covers a contiguous range of source blocks
at the same layer. The proof size grows very slowly with batch size —
empirically ~10–20 KB for hundreds of tx witnesses. The full proof bytes are
stored once, at the final source block for the range; earlier covered blocks
store pointer metadata that references the same settlement transaction/proof.

```
ProofAmendment total ≈ 15 KB  (constant per block, independent of tx count)
```

---

## Disk Savings by Block Load

| Txs / block | WitnessBundle | ProofAmendment | Freed per block | Compression ratio |
|---|---|---|---|---|
| 10 | ~39 KB | ~15 KB | ~24 KB | 2.6× |
| 50 | ~195 KB | ~15 KB | ~180 KB | **13×** |
| 100 | ~390 KB | ~15 KB | ~375 KB | **26×** |
| 200 | ~780 KB | ~15 KB | ~765 KB | **52×** |
| 500 | ~1,950 KB | ~15 KB | ~1,935 KB | **130×** |

> The compression ratio scales linearly with tx count because WitnessBundle
> grows O(n) while the STARK proof stays roughly constant.

### Daily savings at sustained load

```
Block time: 2 s  →  43,200 blocks/day

@ 50 tx/block:   43,200 × 180 KB  ≈  7.5 GB/day
@ 100 tx/block:  43,200 × 375 KB  ≈  15.5 GB/day
@ 200 tx/block:  43,200 × 765 KB  ≈  32 GB/day
```

TX Detail (`b/`) + ProofAmendment (`pa/`) together add only ~22 KB/block, so
the net storage growth rate drops dramatically once the STARK pipeline is active.

---

## Implementation

### L1 — Split on write (`put_block`)

`ChainStore::put_block` calls `block.split()` and writes two separate keys:

```rust
// TX details — permanent
store.put(block_key(&hash), stripped.encode_versioned())?;

// Witness bundle — ephemeral (skipped for empty blocks)
if !bundle.is_empty() {
    store.put(witness_key(&hash), bundle.rlp_bytes())?;
}
```

`get_block_by_hash` reads both keys and calls `stripped.into_block(bundle)` to
reconstruct a full `Block`. When `w/<hash>` is absent (already pruned), the
returned block has empty signature stubs — TX payload is fully intact.

`ChainStore::block_availability(hash)` classifies local data before sync/RPC
code assumes a block is complete:

| Availability | Local data | Meaning |
|---|---|---|
| `Missing` | no header/body | canonical map points to data not present locally, or unknown hash |
| `HeaderOnly` | `h/<hash>` only | body must be back-filled before transaction/RPC detail can be served |
| `BodyOnly` | `b/<hash>` without `w/<hash>` | valid for empty blocks, STARK-replaced witnesses, or body-only back-fill |
| `BodyWithWitness` | `b/<hash>` + `w/<hash>` | full local block data with PQ witness material |

Historical body sync uses this classifier to request only missing stripped
bodies. Import may execute body-only/reference transactions with empty signature
stubs during historical catch-up; the canonical state-root check remains the
security backstop.

### L2 — Proof replaces witness (`ProofAmendment` handler)

When the node receives a valid `ProofAmendment`:

1. STARK proof is verified from the `StarkReward` system transaction payload.
   Block-level STARK settlement in header `extraData` is deprecated and rejected.
   Normal STARK-settled blocks keep `extraData=0x`.
2. The proof artifact must satisfy `compressed_size * 2 < original_size`.
3. After `proof_replacement_grace` blocks (default: **0**), eligible witness
   data is deleted.

```toml
# node config (TOML)
[pruning]
proof_replacement_grace = 0   # delete immediately; set > 0 for forensic window
```

When `enable_stark_aggregation = true`, the node automatically initialises
`witness_retention = 0` — no manual config needed.

The compression threshold is a protocol invariant for pruning and rewards:
non-compressing proofs may be retained for verification or diagnostics, but
they cannot replace witness data or claim STARK rewards. L1 artifacts may cover
contiguous canonical block ranges; L2+ artifacts compress prior-layer STARK
artifacts rather than raw witnesses.

### Ordered compression frontiers

Compression is accepted only at the next contiguous frontier for its layer:

- **L1** compresses canonical block witness payloads from the first eligible block
  that is not already L1-compressed. If blocks `0..=100` are L1, the next L1
  artifact must start at block `101`; gaps and overlaps are invalid.
- **L2+** compress prior-layer artifacts. An L2 artifact may start again from the
  beginning of the L1 frontier, but every covered block must already have the
  lower layer (`L-1`) and must not already have layer `L`.
- Blocks with no witness/proof payload, such as genesis or empty heartbeat
  blocks, are included as zero-entry sources in L1 range metadata. They do not
  count toward the L1 minimum tx-entry threshold, but they prevent gaps: a fresh
  chain's first L1 range starts at block `0`.

Validators enforce these rules both when accepting proof amendments and when
replaying STARK reward settlements during block import. Out-of-order, overlapping,
or lower-layer-gap artifacts cannot prune witnesses or claim rewards.

`eth_getBlockByNumber`, `eth_getBlockByHash`, and Shell block RPC responses expose:

| Field | Meaning |
|---|---|
| `compressionLayer` | Highest STARK compression layer currently known for the block (`0` means no accepted proof artifact). |
| `pruningStatus` | Local witness state: `unpruned`, `compressedWitnessRetained`, `pruned`, `notWitnessed`, `pending`, or `unknown`. |

### L3 — State trie pruning (experimental)

Controlled by `state_pruning_experimental = false` (default off).

When enabled, the node maintains a ref-count column family `refs/<node_hash>`
(4-byte little-endian u32). `StateRootTracker` decrements counts for trie nodes
no longer referenced by any retained root; nodes reaching zero are deleted.

**Not yet production-ready.** Enable only for testing.

---

## Configuration Reference

```toml
[pruning]
# How many finalized blocks to retain witness bundles for before deletion.
# Ignored when proof_replacement_grace is non-zero.
witness_retention = 128        # default; overridden to 0 when STARK is on

# Grace window: keep witness bundle for N blocks after proof arrival.
# 0 = delete immediately on proof receipt (default, recommended for STARK nodes).
proof_replacement_grace = 0

# Experimental: enable trie node ref-counting and eviction. Default false.
state_pruning_experimental = false
```

---

## Monitoring

The `/metrics` endpoint exposes column-family byte counts updated every 10 s:

```
shell_storage_cf_size_bytes{cf="chain"}    # b/ prefix — TX detail (grows forever)
shell_storage_cf_size_bytes{cf="witness"}  # w/ prefix — should shrink toward 0
shell_storage_cf_size_bytes{cf="proof"}    # pa/ prefix — grows slowly (~15 KB/block)
shell_storage_cf_size_bytes{cf="state"}    # trie nodes (0 unless L3 enabled)
```

A healthy STARK node should show `witness` converging to near-zero.

### Startup banner

On every start the node logs a three-line pruning summary:

```
[PRUNING] state  : experimental=false  retained_roots=128
[PRUNING] bodies : witness_retention=0  proof_replacement_grace=0
[PRUNING] stark  : aggregation=true  — witnesses replaced by proof on receipt
```

---

## Data Flow Diagram

```
Block sealed
     │
     ▼
put_block()
  ├── b/<hash>  ←─ StrippedBlock (TX detail)   ─────────────────► forever
  └── w/<hash>  ←─ WitnessBundle (sigs)
                         │
                         │  ProofAmendment received + verified
                         ▼
                  pa/<final-source-hash> ←─ SigBatchProof   ───► forever
                  pa/<earlier-source-hash> ←─ ProofPointer ─────► forever
                         │
                         │  grace_window elapsed (default: 0 blocks)
                         ▼
                  delete w/<hash>   ─── ~180 KB/block freed (@ 50 tx)
```

---

## FAQ

**Q: Will old blocks lose their transaction list?**

No. `b/<hash>` is never deleted by default. The explorer and
`eth_getBlockByNumber` always return full TX detail regardless of whether the
witness bundle still exists.

**Q: Can I recover a deleted witness bundle?**

No. Deletion is irreversible. If forensic retention is needed, set
`proof_replacement_grace` to the desired block count (e.g., `604800` ≈ 7 days
at 1 block/s).

**Q: Does the compression ratio hold for empty blocks?**

Empty blocks have no witness bundle at all (never written), but they are still
included in ordered STARK frontier ranges as zero-entry sources. This keeps
range metadata continuous from block `0` without changing compression accounting.

**Q: Is the STARK proof itself verifiable after witness deletion?**

Yes. The settlement transaction input carries the full proof payload, and the
final source block stores the full `ProofAmendment`. Pointer blocks store
`settlement_tx_hash`, `start_block`, `end_block`, and `target_block` metadata so
clients can find the full proof without duplicating bytes on every source block.

---

## Storage Profiles

Shell Chain nodes choose a *storage profile* with a single CLI flag that sets
all retention parameters at once. Profiles replace the confusing
`--body-retention` / `--witness-retention` pair as the primary user interface.

### Choosing a profile

```
shell-node run --storage-profile <archive|full|light>
```

Default: **`full`**

| Profile | `body_retention` | `witness_retention` | `proof_replacement_grace` | `keep_recent` | Typical use |
|---|---|---|---|---|---|
| `archive` | 0 (forever) | 0 (forever) | u64::MAX (never delete) | 0 (forever) | Complete cryptographic audit trail; PQ signatures kept even after STARK proof |
| `full` (**default**) | 0 (forever) | 128 | 0 (replace immediately) | 0 (forever) | Full node: TX history queryable forever; STARK proof replaces PQ signatures |
| `light` | 4096 (~2.3 h) | 64 | 0 | 4096 | Light / embedded node; rolling ~2-hour window only |

### Data volume estimates

Base: 50 tx/block, 2 s/block → 43,200 blocks/day.

| Profile | Daily write | Annual steady-state |
|---|---|---|
| `archive` | ~12.8 GB/day | ~4.7 TB/year |
| `full` | ~1.5 GB/day | ~550 GB/year |
| `light` | no growth | ~1 GB fixed |

### Override individual parameters

`--body-retention` and `--witness-retention` override profile defaults:

```
# full profile but keep the last 2048 blocks of witnesses too
shell-node run --storage-profile full --witness-retention 2048
```

Explicit flags take priority over the profile for body and witness retention.
`--storage-profile` also sets `proof_replacement_grace` (how long to wait before
replacing PQ witness data with a STARK proof) and — when `--pruning` is omitted —
the `keep_recent` (state-root) default for the profile. To fully override all
profile values, use `--body-retention`, `--witness-retention`, and `--pruning`
explicitly.

### Auto-sync on profile upgrade

When a node is restarted with a higher storage profile (e.g. `light → full`),
it automatically back-fills missing block bodies from peers that advertise a
richer profile via the `StorageCapability` P2P message. Back-fill runs in the
background; normal consensus is not interrupted. When finished, the node logs:

```
✓ historical body back-fill complete
```

If no peer with sufficient history is reachable, the node logs a warning and
retries on each new peer connection.

> **Note**: if *all* nodes in a network ran `light` profile and data has been
> pruned, that history is permanently lost and cannot be recovered.

### Docker Compose defaults

The bundled `docker-compose.yml` assigns:

- **node1** — `archive` (serves as authoritative history source)
- **node2 / node3** — `full` (typical validator nodes)
