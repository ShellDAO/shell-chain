# Observability Guide

shell-chain exposes Prometheus metrics, structured tracing, and HTTP health
probes out of the box. This document describes every signal available and how
to consume it.

---

## 1. Metrics HTTP server

The node starts a lightweight HTTP server for observability endpoints. Configure
it in `node.toml`:

```toml
[metrics]
enabled  = true
listen_addr = "0.0.0.0:9000"   # default
```

### Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/metrics` | GET | Prometheus text exposition (v0.0.4) |
| `/health` / `/healthz` | GET | Liveness probe — always 200 when process is up |
| `/ready` / `/readyz` | GET | Readiness probe — 503 until first block imported |

#### `/healthz` response

```json
{
  "status": "ok",
  "version": "0.22.2",
  "block_height": 12345,
  "peer_count": 4,
  "syncing": false
}
```

#### `/readyz` response (ready)

```json
{ "ready": true }
```

#### `/readyz` response (not ready — HTTP 503)

```json
{ "ready": false, "reason": "node has not imported any blocks yet" }
```

---

## 2. Prometheus metrics reference

All metrics are prefixed `shell_`.

### Chain

| Metric | Type | Description |
|--------|------|-------------|
| `shell_block_height` | Gauge | Current canonical chain tip height |
| `shell_blocks_imported_total` | Counter | Cumulative blocks imported since startup |
| `shell_block_production_duration_seconds` | Histogram | Wall-clock time to produce one block |
| `shell_txs_received_total` | Counter | Cumulative transactions admitted to mempool |
| `shell_tx_pool_size` | Gauge | Pending transactions in mempool |

### Network

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shell_peer_count` | Gauge | — | Connected libp2p peers |

### Consensus (wPoA)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shell_epoch_number` | Gauge | — | Current wPoA epoch |
| `shell_validator_active_count` | Gauge | — | Active validators in current epoch |
| `shell_validator_weight` | Gauge | `validator` | Proposer weight per validator address |
| `shell_consensus_slot_miss_total` | Counter | `validator` | Missed proposer slots per validator |
| `shell_last_finalized_number` | Gauge | — | Latest block finalized by weighted wPoA quorum |
| `shell_finality_lag_blocks` | Gauge | — | Difference between canonical head and latest finalized block |

### STARK prover (K4)

| Metric | Type | Description |
|--------|------|-------------|
| `shell_stark_proofs_generated_total` | Counter | Successfully generated STARK proofs |
| `shell_stark_proof_failures_total` | Counter | Failed STARK proof generation attempts |
| `shell_stark_proof_duration_seconds` | Histogram | STARK proof generation latency |
| `shell_stark_backlog_depth` | Gauge | Pending proof tasks in queue |
| `shell_stark_amendments_broadcast_total` | Counter | ProofAmendment messages broadcast |
| `shell_stark_equivocations_detected_total` | Counter | Equivocation proofs detected |
| `shell_stark_settlements_accepted_total` | Counter | STARK settlement transactions accepted (v0.22.x) |
| `shell_stark_settlements_rejected_total` | Counter | STARK settlements rejected — ordering/layer/frontier violations (v0.22.x) |
| `shell_stark_frontier_lag` | Gauge | Blocks between chain tip and highest contiguous settled layer (alert if > 100) (v0.22.x) |

### RPC

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shell_rpc_request_duration_seconds` | Histogram | `method` | Request latency per JSON-RPC method |

Use `record_rpc_call(method, duration_secs)` on the `Metrics` handle to record
a completed call. Integration with jsonrpsee middleware is planned for a future release.

### Storage

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `shell_storage_cf_size_bytes` | Gauge | `cf` | On-disk size per column family (`chain`, `witness`, `state`, `proof`) |

Column family sizes are lazily updated (300-second TTL) to avoid expensive
prefix scans on every scrape.

---

## 3. Tracing

shell-chain uses the [`tracing`](https://docs.rs/tracing) crate for structured,
levelled diagnostics. Control verbosity via the `RUST_LOG` environment variable
(powered by `tracing-subscriber` with `EnvFilter`).

```bash
# Show info-level logs for all crates
RUST_LOG=info shell-chain-node

# Verbose RPC + consensus, info elsewhere
RUST_LOG=info,shell_rpc=debug,shell_consensus=debug shell-chain-node

# JSON output (for log aggregators)
RUST_LOG=info SHELL_LOG_FORMAT=json shell-chain-node
```

Key spans and log fields:

| Location | Event / span | Key fields |
|----------|-------------|------------|
| `event_loop` | `block_imported` | `number`, `hash`, `txs` |
| `event_loop` | `block_produced` | `number`, `hash`, `duration_ms` |
| `shell_rpc` | `rpc_error` | `rpc_internal_error` |
| `metrics` | `metrics server listening` | `addr` |
| `p2p_handlers` | `peer connected/disconnected` | `peer_id` |

---

## 4. Grafana dashboard (starter)

The JSON below creates a minimal dashboard. Import it via
**Dashboards → Import → Paste JSON**.

```json
{
  "title": "shell-chain node",
  "panels": [
    {
      "title": "Block height",
      "type": "stat",
      "targets": [{ "expr": "shell_block_height" }]
    },
    {
      "title": "Mempool size",
      "type": "timeseries",
      "targets": [{ "expr": "shell_tx_pool_size" }]
    },
    {
      "title": "Peers",
      "type": "stat",
      "targets": [{ "expr": "shell_peer_count" }]
    },
    {
      "title": "Blocks / min",
      "type": "timeseries",
      "targets": [{ "expr": "rate(shell_blocks_imported_total[1m]) * 60" }]
    },
    {
      "title": "RPC p99 latency",
      "type": "timeseries",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(shell_rpc_request_duration_seconds_bucket[5m]))",
          "legendFormat": "{{method}}"
        }
      ]
    },
    {
      "title": "Block production latency p50/p99",
      "type": "timeseries",
      "targets": [
        { "expr": "histogram_quantile(0.50, rate(shell_block_production_duration_seconds_bucket[5m]))", "legendFormat": "p50" },
        { "expr": "histogram_quantile(0.99, rate(shell_block_production_duration_seconds_bucket[5m]))", "legendFormat": "p99" }
      ]
    }
  ]
}
```

---

## 5. Kubernetes probes

Add to your deployment manifest:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9000
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 9000
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 6
```

The readiness probe fails until the node has imported at least one block, which
is the right gate before routing traffic to a fresh node.
