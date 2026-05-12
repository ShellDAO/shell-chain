# Shell Chain Benchmarks

## Overview

This document reports benchmark results for the block data reduction initiative (A1 + A2)
and the M13 STARK signature aggregation system (A3).

All benchmarks run on the Criterion framework (`cargo bench -p bench`).

---

## A3: STARK Signature Aggregation (v0.15.0 baseline)

> **v0.22.x note:** v0.22.x ships multi-layer (L1/L2/L3) recursive STARK compression. For current per-layer compression numbers, see [`docs/BLOCK_PRUNING_AND_COMPRESSION.md`](BLOCK_PRUNING_AND_COMPRESSION.md).

### Methodology

- Block-level Dilithium3 signature aggregation via Winterfell STARK prover
- Batch sizes 1–20 tx; each batch covers all unique pubkeys and signatures in a block
- Compression ratio = `raw_dilithium3_bytes / stark_proof_bytes`
- Soak test: 6-hour continuous run on testnet devnet (Docker Compose, 3 validators + 1 prover)
- Run: `cargo run -p tools/stark-bench --release`

### Compression Results

| Batch (tx) | STARK proof | Raw Dilithium3 | Compression |
|-----------|------------|----------------|-------------|
| 1 | 2.1 KB | 5.3 KB | 2.5× |
| 5 | 3.7 KB | 25.7 KB | **7.1×** |
| 10 | 12.7 KB | 52.7 KB | **4.0×** |
| 20 | 18.4 KB | 105.4 KB | **5.7×** |

> Peak compression (batch=5) is 7.1×; the sweet spot balances proof size vs verification cost.

### 6-Hour Soak Results

| Metric | Value |
|--------|-------|
| Duration | 6 h 04 min |
| Proofs generated | 3,403,200 |
| Failures | 0 |
| Throughput | 157 proofs/sec |
| Mean latency | 6.4 ms/proof |
| p99 latency | 18.7 ms/proof |
| Memory (prover service) | 312 MB |
| CPU utilisation | 38% (4-core) |

### Analysis

STARK aggregation reduces on-chain Dilithium3 proof data by 4–7× at typical transaction rates.
The proving pipeline is fully asynchronous and never blocks block production;
in the soak test no block was delayed by prover activity.
The `ProofBacklog` depth stabilised at ≤ 12 tasks under 10-tx batching.

---


### Methodology

- 10,000 random key-value writes to a temp RocksDB instance (64-byte key, 4 KB value)
- Measured: write throughput (MiB/s), read latency (ns), and read throughput (GiB/s)
- Two configurations: `NoCompression` vs `ZstdCold` (level 3, applied to L0+)
- Run: `cargo bench -p bench --bench bench_compression rocksdb`

### Results

| Metric | NoCompression | ZstdCold |
|--------|--------------|---------|
| Write latency (mean) | 10.997 ms | 13.155 ms |
| Write throughput | 46.840 MiB/s | 39.154 MiB/s |
| Read latency (mean) | 479.94 ns | 471.01 ns |
| Read throughput | 10.481 GiB/s | 10.679 GiB/s |

### Analysis

- **Write overhead**: ~16% slower writes (10.997 ms → 13.155 ms)
  - Within acceptable range: writes are I/O-bound; CPU is not the bottleneck
  - Block production rate (1 block/2 s) is not affected
- **Read benefit**: ~2% faster reads (decompressed data is smaller, fits better in OS page cache)
- **Disk savings estimate**: 8–15% on `chain` + `receipts` CFs
  - Dilithium3 signatures (3,309 B) and pubkeys (1,952 B) are near-random → Zstd <5% compression
  - Transaction metadata (nonce, to, value, gas) and block headers are repetitive → ~30–40% compression
  - PQ bytes dominate volume (97% of tx data), so overall savings are modest

### Conclusion

A1 delivers moderate disk savings (~8–15%) with acceptable overhead. Primary value is as a
baseline for future improvements — once witness separation (B-tier) reduces PQ bytes from
the chain CF, Zstd will become significantly more effective.

---

## A2: PubkeyMode — Pubkey-by-Reference Deduplication

### Methodology

- Encoded `SignedTransaction` RLP in two modes:
  - **Embedded**: full 1,952-byte Dilithium3 pubkey inline (first tx from a sender)
  - **Reference**: empty pubkey field (0x80 = 1 byte); node resolves from `pk/` store
- Measured: RLP encoding speed (ns) and throughput (GiB/s)
- Batch deduplication measured at 0 / 50 / 90 / 95 / 99% repeat-sender rates
- Run: `cargo bench -p bench --bench bench_compression pubkeymode`

### Results: Encoding Speed

| Mode | Latency (mean) | Throughput |
|------|---------------|-----------|
| Embedded | 155.58 ns | 31.949 GiB/s |
| Reference | 137.50 ns | 22.914 GiB/s |

> Reference mode is ~12% faster to encode (smaller payload). Throughput appears lower
> because throughput is computed against bytes encoded — Reference encodes fewer bytes total.

### Results: Per-Transaction Wire Size

| Mode | RLP size | Delta |
|------|---------|-------|
| Embedded (`PubkeyMode::Embedded`) | ~5,431 B | baseline |
| Reference (`PubkeyMode::Reference`) | ~3,477 B | **-1,954 B (-36%)** |

### Results: Batch Impact (500 tx/block)

| Dedup Rate | Embedded txs | Reference txs | Block saving | Block size reduction |
|-----------|-------------|--------------|-------------|---------------------|
| 0% | 500 | 0 | 0 B | 0% |
| 50% | 250 | 250 | ~488 KB | ~18% |
| 90% | 50 | 450 | ~878 KB | ~32% |
| 95% | 25 | 475 | ~927 KB | ~34% |
| 99% | 5 | 495 | ~966 KB | ~36% |

Base block size (0% dedup, 500 tx): ~2.7 MB  
At 95% dedup: ~1.77 MB/block = **~34% reduction from A2 alone**

### Analysis

- Real-world dedup rate: Most active chains see 80–95%+ repeat senders per block
- 95% dedup is the target operating point
- Savings are deterministic and proportional to sender-repeat rate

---

## Combined A1 + A2 Impact

| Scenario | Per-block | Per-hour | Per-day |
|---------|----------|---------|--------|
| Baseline (no optimization) | 2.70 MB | 2.35 GB | ~56 GB |
| A1 only (Zstd, ~12% disk) | 2.38 MB | 2.07 GB | ~49 GB |
| A2 only (95% dedup) | 1.77 MB | 1.54 GB | ~37 GB |
| A1 + A2 combined | ~1.56 MB | ~1.36 GB | ~32 GB |

**Combined reduction: ~42% vs baseline** at 95% dedup rate. The 50% design target is
achievable at ≥99% dedup rate or when account deduplication extends to intra-epoch reuse.

> Note: Zstd compression ratio improves further after B-tier witness separation removes
> raw PQ bytes from the `chain` CF. Post-B-tier estimate: 55–65% combined reduction.

---

## Benchmark Commands

```bash
# Run all compression benchmarks
cargo bench -p bench --bench bench_compression

# Run specific group
cargo bench -p bench --bench bench_compression -- pubkeymode_rlp
cargo bench -p bench --bench bench_compression -- batch_dedup
cargo bench -p bench --bench bench_compression -- rocksdb_write
cargo bench -p bench --bench bench_compression -- rocksdb_read

# Open HTML report
open target/criterion/rocksdb_write/write_zstd_cold/report/index.html
```

---

## Environment

| Item | Value |
|------|-------|
| CPU | Apple Silicon M-series |
| Compression | RocksDB ZstdCold level 3 |
| Bench framework | Criterion 0.5 |
| Signature scheme | Dilithium3 (CRYSTALS-Dilithium, NIST PQC standard) |
| Pubkey size | 1,952 bytes (`DILITHIUM3_PUBKEY_LEN`) |
| Signature size | 3,309 bytes |

### v0.22.0 Settlement Metrics

The following Prometheus metrics were added in v0.22.0 to monitor STARK settlement liveness:

| Metric | Type | Description |
|--------|------|-------------|
| `shell_stark_frontier_lag` | Gauge | Blocks between chain tip and highest contiguous settled layer |
| `shell_stark_settlements_accepted_total` | Counter | STARK settlement transactions accepted |
| `shell_stark_settlements_rejected_total` | Counter | STARK settlements rejected (ordering/layer violations) |
