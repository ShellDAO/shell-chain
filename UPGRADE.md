# Upgrade Guide

## v0.15.0 → v0.22.2 (M14–M16: STARK hardening, ops maturity)

### Overview

This covers all breaking and notable changes from v0.15.0 through v0.22.2.

| Area | Change |
|------|--------|
| STARK aggregation | Prover defaults, ordered-frontier validation, settled-source index |
| Consensus | wPoA finality hardening, commit-certificate sidecars |
| Storage | Three-segment block model (TX detail / WitnessBundle / STARK proof) |
| RPC | `compressionLayer` and `pruningStatus` fields on block responses |
| Metrics | `shell_stark_frontier_lag`, `shell_stark_settlements_accepted_total`, `shell_stark_settlements_rejected_total` |
| CLI | `--algorithm mldsa65` (FIPS 204 ML-DSA-65) now available in `key generate` |

### STARK aggregation — `enable_stark_aggregation` default

In v0.15.0, STARK aggregation was disabled by default (`false`). From v0.21.0+, the
default depends on the **network profile**:

| Profile | Default |
|---------|---------|
| `mainnet` | `true` |
| `testnet` | `true` |
| `dev` | `false` |

If you were previously setting `--enable-stark-aggregation` explicitly and have upgraded
to a testnet/mainnet profile, the flag is no longer needed.

### New RocksDB column families (auto-created on first start)

`witness_store`, `proof_amendments`, `ss/` (settled-source index — v0.22.0+).

No manual migration required; new column families are created automatically.

### Storage profiles (replaces --body-retention / --witness-retention)

The `--storage-profile <archive|full|light>` flag replaces the confusing
`--body-retention` / `--witness-retention` pair as the primary UX. The old flags
still work as overrides but are no longer recommended as primary configuration.

### Docker image

```yaml
image: ghcr.io/shelldao/shell-chain:0.22.2
```

---

## v0.14.0 → v0.15.0 (M13: wPoA+STARK)

### Overview

v0.15.0 introduces STARK signature aggregation. The upgrade is **non-breaking** for existing nodes — new fields have safe defaults and the prover service starts disabled until explicitly enabled.

### New CLI Flags (`shell-node run`)

| Flag | Default | Description |
|------|---------|-------------|
| `--network <dev\|testnet\|mainnet>` | `dev` | Network profile; sets STARK/block-time defaults |
| `--witness-retention <blocks>` | 1000 | How many blocks of witness data to keep |
| `--body-retention <blocks>` | 0 (forever) | How many blocks of full bodies to keep before stripping |

### New Config Keys (`config.toml`)

```toml
[node]
network = "dev"          # or testnet / mainnet
witness_retention = 1000
body_retention    = 0

[stark]
enabled           = false   # set true to run the prover service
batch_size        = 10      # signatures per STARK proof
backlog_limit     = 1000    # max queued proof tasks
```

### New Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shell_stark_proofs_total` | Counter | STARK proofs generated |
| `shell_stark_proof_latency_seconds` | Histogram | End-to-end prove latency |
| `shell_stark_backlog_depth` | Gauge | Current proof task queue depth |
| `shell_stark_amendments_broadcast_total` | Counter | ProofAmendment gossip messages sent |

### Docker image

```yaml
image: ghcr.io/lucienSong/shell-chain:v0.15.0
```

### Data directory

No migration required. Two new RocksDB column families are created automatically:
`witness_store`, `proof_amendments`.

---

## v0.15.0 → v0.20.0 (wPoA Genesis & Testnet Launch)

### Overview

v0.20.0 activates the Weighted Proof of Authority (wPoA) consensus engine as a first-class production path, launches the public testnet (chain ID 10), and autogenerates the canonical RPC reference doc (79 methods).

### Breaking: Genesis format

Genesis files with a `[consensus]` section must now use the `"engine"` field:

```json
{
  "engine": "wpoa",
  "chainId": 10,
  "authorities": [
    { "address": "pq1...", "weight": 2 },
    { "address": "pq1...", "weight": 1 },
    { "address": "pq1...", "weight": 1 }
  ]
}
```

The old `"engine": "poa"` single-authority format still works but receives no new features.

### New CLI flag

| Flag | Default | Description |
|------|---------|-------------|
| `--consensus-engine poa\|wpoa` | auto | Override consensus engine (auto-detected from genesis `engine` field) |

### New RPC method

| Method | Description |
|--------|-------------|
| `shell_consensusInfo` | Returns current engine type, epoch length, and live validator set with weights |

### Data directory

No migration required. New column family `validator_registry` created automatically.

### Docker image

```yaml
image: ghcr.io/shelldao/shell-chain:0.22.2
```

---

## v0.20.0 → v0.21.0 (F-PQ1-ONLY: `pq1...` address enforcement)

### Overview

v0.21.0 is a **breaking** release. All `0x` hex addresses are completely removed from every input path. Operators must update keystores, genesis files, scripts, and SDK calls before upgrading.

### Breaking: `0x` addresses rejected everywhere

- **RPC**: `eth_getBalance`, `eth_getTransactionCount`, `shell_getPqPubkey`, and all other methods reject `0x...` address parameters. Use `pq1...` bech32m addresses exclusively.
- **CLI**: `shell-node tx send --to`, `genesis add-alloc`, `key inspect` all output and accept `pq1...` only.
- **Genesis files**: `alloc` map keys must be `pq1...`. Re-derive addresses with `shell-node key inspect <keystore.json>`.
- **SDK**: `signer.getHexAddress()` removed. Use `signer.getAddress()` (returns `pq1...`).
- **Keystores**: `address` field stored as `pq1...`. Old keystores with `0x` hex address are still **readable** (backwards compat for decryption), but all newly generated keystores use `pq1...`.

### Breaking: Faucet environment variables

The faucet service no longer accepts a raw private key. Replace:

```bash
# Old (< v0.21.0)
FAUCET_PRIVATE_KEY=<hex-private-key>

# New (v0.21.0+)
FAUCET_KEYSTORE_FILE=/path/to/faucet-keystore.json
FAUCET_KEYSTORE_PASSWORD=<password>
```

Also note the faucet endpoint changed from `POST /faucet` to `POST /drip`, and the address parameter must now be a `pq1...` address.

### Breaking: ML-DSA-65 algo_id changed

If you have **ML-DSA-65** keystores generated before F-TESTNET-FIXES (when ML-DSA-65 was a Dilithium3 alias), re-generate them:

```bash
shell-node key generate --algorithm mldsa65 --output new-keystore.json
```

All **Dilithium3** keystores (`algo_id=0`) are unaffected.

### New: `--enable-stark-aggregation` default changed

`--enable-stark-aggregation` now defaults to **`true`** (was `false`). To keep the prover disabled, explicitly pass `--enable-stark-aggregation=false` or set `enable_stark_aggregation = false` in `config.toml`.

### New RPC methods

| Method | Description |
|--------|-------------|
| `shell_getFinalityInfo` | Returns the latest finalized block and quorum state |
| `shell_finalityProof` | Returns the commit certificate for a finalized block |
| `shell_getProofAmendment` | Returns the async STARK proof amendment for a block |

### Migration checklist

- [ ] Replace all `0x` addresses in genesis files with `pq1...` equivalents
- [ ] Update faucet env vars: `FAUCET_PRIVATE_KEY` → `FAUCET_KEYSTORE_FILE` + `FAUCET_KEYSTORE_PASSWORD`
- [ ] Update SDK: `signer.getHexAddress()` → `signer.getAddress()`
- [ ] Re-generate any ML-DSA-65 keystores created before F-TESTNET-FIXES
- [ ] Update scripts/docker-compose/.env files that reference `0x` addresses

---

## v0.21.x → v0.22.x (STARK Multi-Layer Settlement)

### Overview

v0.22.x ships durable multi-layer STARK compression (L1/L2/L3), settlement liveness metrics, and several prover correctness fixes. The upgrade is **non-breaking** for block format — no genesis reset required.

### One-time startup: SettledSourceIndex backfill

On the **first boot after upgrading**, `SettledSourceIndex` (RocksDB key prefix `ss/`) is rebuilt from genesis automatically. Depending on chain length, this may add seconds to minutes to startup. Normal operation resumes once backfill completes.

### New Prometheus metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shell_stark_settlements_accepted_total` | Counter | STARK settlement txs accepted |
| `shell_stark_settlements_rejected_total` | Counter | STARK settlements rejected (ordering/layer/frontier violations) |
| `shell_stark_frontier_lag` | Gauge | Blocks between chain tip and highest contiguous settled layer |

**Alert rule**: page if `shell_stark_frontier_lag > 100` for more than 5 minutes.

### New system transaction type: StarkReward

v0.22.x introduces `StarkReward` system transactions that carry STARK proof settlement payloads. These appear in blocks with `shellType: "starkReward"` and include a structured `decodedInput` field in `eth_getTransactionByHash` responses (block range, layer, entry count). Block explorers or indexers that parse system transactions may need to be updated.

### Docker image

```yaml
image: ghcr.io/shelldao/shell-chain:0.22.2
```

### Migration checklist

- [ ] Update image tag to `0.22.2`
- [ ] Allow extra startup time on first boot (SettledSourceIndex backfill)
- [ ] Add `shell_stark_frontier_lag` alert to monitoring
- [ ] Update block explorer or indexer if it processes system transactions


This guide covers breaking changes and migration steps when upgrading a
`shell-chain` node from any v0.9.x release to v0.13.0.

---

## Table of Contents

1. [Overview](#overview)
2. [New CLI Flags](#new-cli-flags)
3. [Configuration File Changes](#configuration-file-changes)
4. [wPoA Migration](#wpoa-migration)
5. [RPC Changes](#rpc-changes)
6. [Metrics Changes](#metrics-changes)
7. [Data Directory](#data-directory)
8. [Docker / Docker Compose](#docker--docker-compose)
9. [SDK Changes](#sdk-changes)
10. [Rollback](#rollback)

---

## Overview

v0.13.0 is a significant mainnet-readiness release. The highlights are:

| Area | Change |
|------|--------|
| Consensus | PoA → wPoA (Weighted PoA) |
| Security | TLS support, per-IP rate limiting, API key auth |
| Performance | LRU account cache, mempool priority tuning |
| Observability | Structured JSON logging, extended Prometheus metrics, Admin RPC |
| SDK | `shell-sdk` TypeScript SDK with PQ signer |

---

## New CLI Flags

### `shell-node run`

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc-tls-cert <path>` | — | TLS certificate file (PEM) |
| `--rpc-tls-key <path>` | — | TLS private key file (PEM) |
| `--rpc-rate-limit <n>` | 100 | Max requests/second (server-wide) |
| `--rpc-api-key <key>` | — | Bearer token required for all methods |
| `--log-format <json\|text>` | text | Structured logging format |
| `--state-cache-size-mb <n>` | 64 | LRU account cache size |
| `--mempool-max-size <n>` | 4096 | Max transactions in mempool |
| `--mempool-price-bump <pct>` | 10 | Minimum fee bump % for tx replacement |

### `shell-node validator`

```
shell-node validator register --stake <amount>
shell-node validator status [--address <addr>]
shell-node validator exit
```

### `shell-node backup`

```
shell-node backup create <path>
shell-node backup restore <path>
shell-node backup schedule --interval 6h --keep 7
```

### `shell-node wallet`

```
shell-node wallet create
shell-node wallet balance <addr>
shell-node wallet send <to> <amount>
shell-node wallet export
```

---

## Configuration File Changes

If you use a `config.toml` file, add the following new fields under `[node]`:

```toml
[node]
state_cache_size_mb = 64   # LRU account cache (new in v0.13.0)

[mempool]
max_pool_size = 4096        # previously hardcoded to 4096
replacement_fee_bump_pct = 10  # previously hardcoded to 10%

[consensus]
engine = "wpoa"             # upgraded from "poa"
```

---

## wPoA Migration

### Genesis changes

If you are starting a fresh network, add `[validators]` to your genesis config:

```toml
[[genesis.validators]]
address = "pq1..."
weight  = 100
stake   = "1000000000000000000"  # 1 token in wei
```

### Existing PoA networks

Existing PoA networks with a single validator are automatically migrated:
the existing validator is registered with `weight = 1` and `stake = 0`.

To update validator weights after genesis:
```
shell-node validator register --stake <amount>
```

### Slashing configuration

Add to `config.toml` to override defaults:

```toml
[consensus.slashing]
slash_fraction_double_sign = 10    # percent (default: 10%)
slash_fraction_offline     = 1     # percent (default: 1%)
offline_window_blocks      = 50    # blocks (default: 50)
```

---

## RPC Changes

### New methods

| Method | Description |
|--------|-------------|
| `shell_getValidators` | Returns current active validator set with weights |
| `shell_getValidatorStatus(addr)` | Returns single validator state + stake |
| `shell_submitSlashEvidence(evidence)` | Submit double-sign proof |
| `admin_nodeInfo` | Node info (requires `--admin-api`) |
| `admin_peers` | Peer list (requires `--admin-api`) |
| `admin_addPeer(enode)` | Add peer dynamically (requires `--admin-api`) |
| `admin_removePeer(enode)` | Remove peer (requires `--admin-api`) |

### Rate limiting

If `--rpc-rate-limit` is set, clients exceeding the limit receive:
```json
{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limited"},"id":1}
```

Configure your client to back off on `-32005` errors with exponential retry.

### TLS

For production deployments, we recommend terminating TLS at a reverse proxy
(Caddy or Nginx) rather than enabling the built-in TLS. Example Caddyfile:

```caddy
rpc.example.com {
    reverse_proxy localhost:8545
}
```

To use the built-in TLS directly (e.g., for operator tools):
```bash
shell-node run --rpc-tls-cert /etc/ssl/node.crt --rpc-tls-key /etc/ssl/node.key
```

---

## Metrics Changes

New Prometheus metrics added in v0.13.0:

| Metric | Type | Description |
|--------|------|-------------|
| `shell_aa_tx_total` | Counter | AA transactions (by `validation_type` label) |
| `shell_key_rotation_total` | Counter | PQ key rotations |
| `shell_validator_weight{address}` | Gauge | Current validator weight |
| `shell_consensus_slot_miss` | Counter | Empty slots (missed proposer) |
| `shell_evm_gas_used_total` | Counter | Cumulative gas used |
| `shell_snapshot_size_bytes` | Gauge | Latest backup snapshot size |

Update your Grafana dashboards by importing the updated JSON from `docker/grafana/`.

---

## Data Directory

The data directory layout is unchanged. No migration steps are required.

RocksDB column families added: `validator_registry`, `slash_records`.
These are created automatically on first start.

---

## Docker / Docker Compose

The default image is `ghcr.io/lucienSong/shell-chain:v0.13.0`.

Multi-arch images are available for `linux/amd64` and `linux/arm64`:

```yaml
services:
  node1:
    image: ghcr.io/lucienSong/shell-chain:v0.13.0
    platform: linux/amd64   # or linux/arm64
```

---

## SDK Changes

The `shell-sdk` npm package is published separately from the node binary.

```bash
npm install @shellchain/sdk@0.13.0
```

### Breaking changes in `shell-sdk`

- `PQAddress.encode()` now returns `pq1...` bech32m by default (was hex in pre-release)
- `ShellProvider` constructor now requires `{ transport }` option object

### Migration example

```typescript
// Before (pre-M10)
const provider = new ShellProvider("http://localhost:8545");

// After (v0.13.0)
import { ShellProvider, httpTransport } from "@shellchain/sdk";
const provider = new ShellProvider({ transport: httpTransport("http://localhost:8545") });
```

---

## Rollback

To roll back to a v0.9.x node:

1. Stop the v0.13.0 node
2. The RocksDB data is forward-compatible; v0.9.x can read blocks written by v0.13.0
3. **Exception**: if wPoA was activated (any validator registration occurred), v0.9.x
   cannot read the `validator_registry` column family — a fresh sync from genesis is required
4. Restart the v0.9.x binary with the old config

For network-wide rollbacks, coordinate a governance vote to freeze the wPoA
activation epoch before downgrading.
