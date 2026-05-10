//! Prometheus metrics collection and HTTP endpoint for shell-chain.
//!
//! Exposes `/metrics` (Prometheus text format), `/health` (JSON) and `/ready`
//! (readiness probe) via a lightweight hyper HTTP server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{
    CounterVec, Encoder, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntGauge,
    Opts, Registry, TextEncoder,
};

/// Prometheus metrics for a shell-chain node.
pub struct Metrics {
    /// Current block height.
    pub block_height: IntGauge,
    /// Latest finalized block number.
    pub last_finalized_number: IntGauge,
    /// Difference between current head and latest finalized block.
    pub finality_lag_blocks: IntGauge,
    /// Number of connected peers.
    pub peer_count: IntGauge,
    /// Number of pending transactions in the mempool.
    pub tx_pool_size: IntGauge,
    /// Block production latency in seconds.
    pub block_production_ms: Histogram,
    /// Total number of blocks imported.
    pub blocks_imported: IntCounter,
    /// Total number of transactions received.
    pub txs_received: IntCounter,
    /// Current epoch number (wPoA).
    pub epoch_number: IntGauge,
    /// Number of currently active validators.
    pub validator_active_count: IntGauge,
    /// Per-validator weight gauge: `shell_validator_weight{validator="0x..."}`.
    pub validator_weight: GaugeVec,
    /// Per-validator missed-slot counter: `shell_consensus_slot_miss_total{validator="0x..."}`.
    pub validator_slot_miss: CounterVec,
    // -----------------------------------------------------------------------
    // K4: STARK prover metrics
    // -----------------------------------------------------------------------
    /// Total STARK proofs successfully generated.
    pub stark_proofs_generated: IntCounter,
    /// Total STARK proof generation failures.
    pub stark_proof_failures: IntCounter,
    /// STARK proof generation latency in seconds.
    pub stark_proof_duration_seconds: Histogram,
    /// Current proof backlog depth (tasks pending).
    pub stark_backlog_depth: IntGauge,
    /// Total ProofAmendment messages broadcast.
    pub stark_amendments_broadcast: IntCounter,
    /// Total equivocation proofs detected and broadcast.
    pub stark_equivocations_detected: IntCounter,
    /// Number of STARK settlements accepted and included in a produced block.
    pub stark_settlements_accepted: IntCounter,
    /// Number of STARK amendments rejected during validation.
    pub stark_settlements_rejected: IntCounter,
    /// Current frontier lag: how many L0 blocks are not yet settled at L1.
    pub stark_frontier_lag: IntGauge,
    // -----------------------------------------------------------------------
    // L2 STARK observability
    // -----------------------------------------------------------------------
    /// Number of settled canonical L1 proofs currently pending in the L2 scheduler window.
    pub stark_l2_pending_inputs: IntGauge,
    /// Number of L2 aggregation jobs currently in `Ready` state (waiting for prover).
    pub stark_l2_ready_jobs: IntGauge,
    /// Block number of the last L2 scheduler trigger (0 if never triggered).
    pub stark_l2_last_trigger_block: IntGauge,
    /// Expected start block of the missing L1 proof when the L2 scheduler is
    /// gap-blocked (0 if not blocked).
    pub stark_l2_blocked_gap_start: IntGauge,
    /// Total L2 recursive proofs generated.
    pub stark_l2_proofs_generated: IntCounter,
    /// Total L2 settlements accepted as canonical.
    pub stark_l2_settlements_accepted: IntCounter,
    /// Total L2 settlements rejected during validation.
    pub stark_l2_settlements_rejected: IntCounter,
    /// Timestamp when the node started, used for uptime calculation.
    pub uptime_start: Instant,
    // -----------------------------------------------------------------------
    // Storage size metrics (ops-metrics)
    // -----------------------------------------------------------------------
    /// Approximate logical data size per column family (prefix scan estimate).
    /// Labels: `cf` ∈ { "chain", "witness", "state", "proof" }.
    /// Updated on a 300-second TTL cache to avoid expensive full-prefix scans
    /// on every metrics scrape. RocksDB nodes can replace this with
    /// `property_int_value_cf` calls for exact SST file sizes.
    pub storage_cf_size: GaugeVec,
    // -----------------------------------------------------------------------
    // OPS-3: RPC latency
    // -----------------------------------------------------------------------
    /// Per-method RPC request duration in seconds.
    /// Label: `method` — JSON-RPC method name (e.g. `"shell_getBlock"`).
    /// Record via [`Metrics::record_rpc_call`].
    pub rpc_request_duration_seconds: HistogramVec,
    registry: Registry,
}

impl Metrics {
    /// Create a new `Metrics` instance with all gauges, counters and histograms
    /// registered against a fresh [`Registry`].
    ///
    /// Returns an error if metric registration fails (e.g. duplicate names).
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        let block_height =
            IntGauge::with_opts(Opts::new("shell_block_height", "Current block height"))?;
        let last_finalized_number = IntGauge::with_opts(Opts::new(
            "shell_last_finalized_number",
            "Latest finalized block number",
        ))?;
        let finality_lag_blocks = IntGauge::with_opts(Opts::new(
            "shell_finality_lag_blocks",
            "Difference between current head and latest finalized block",
        ))?;
        let peer_count =
            IntGauge::with_opts(Opts::new("shell_peer_count", "Number of connected peers"))?;
        let tx_pool_size = IntGauge::with_opts(Opts::new(
            "shell_tx_pool_size",
            "Number of pending transactions",
        ))?;
        let block_production_ms = Histogram::with_opts(
            HistogramOpts::new(
                "shell_block_production_duration_seconds",
                "Block production latency",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        )?;
        let blocks_imported = IntCounter::with_opts(Opts::new(
            "shell_blocks_imported_total",
            "Total blocks imported",
        ))?;
        let txs_received = IntCounter::with_opts(Opts::new(
            "shell_txs_received_total",
            "Total transactions received",
        ))?;
        let epoch_number =
            IntGauge::with_opts(Opts::new("shell_epoch_number", "Current wPoA epoch"))?;
        let validator_active_count = IntGauge::with_opts(Opts::new(
            "shell_validator_active_count",
            "Number of currently active validators",
        ))?;
        let validator_weight = GaugeVec::new(
            Opts::new("shell_validator_weight", "Per-validator proposer weight"),
            &["validator"],
        )?;
        let validator_slot_miss = CounterVec::new(
            Opts::new(
                "shell_consensus_slot_miss_total",
                "Per-validator missed proposer slots",
            ),
            &["validator"],
        )?;

        // K4: STARK prover metrics
        let stark_proofs_generated = IntCounter::with_opts(Opts::new(
            "shell_stark_proofs_generated_total",
            "Total STARK proofs successfully generated",
        ))?;
        let stark_proof_failures = IntCounter::with_opts(Opts::new(
            "shell_stark_proof_failures_total",
            "Total STARK proof generation failures",
        ))?;
        let stark_proof_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "shell_stark_proof_duration_seconds",
                "STARK proof generation latency",
            )
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
        )?;
        let stark_backlog_depth = IntGauge::with_opts(Opts::new(
            "shell_stark_backlog_depth",
            "Current STARK proof backlog depth",
        ))?;
        let stark_amendments_broadcast = IntCounter::with_opts(Opts::new(
            "shell_stark_amendments_broadcast_total",
            "Total ProofAmendment messages broadcast",
        ))?;
        let stark_equivocations_detected = IntCounter::with_opts(Opts::new(
            "shell_stark_equivocations_detected_total",
            "Total equivocation proofs detected and broadcast",
        ))?;
        let stark_settlements_accepted = IntCounter::with_opts(Opts::new(
            "shell_stark_settlements_accepted_total",
            "Number of STARK settlements accepted and included in a produced block",
        ))?;
        let stark_settlements_rejected = IntCounter::with_opts(Opts::new(
            "shell_stark_settlements_rejected_total",
            "Number of STARK amendments rejected during validation",
        ))?;
        let stark_frontier_lag = IntGauge::with_opts(Opts::new(
            "shell_stark_frontier_lag",
            "Current frontier lag: how many L0 blocks are not yet settled at L1",
        ))?;

        // L2 observability metrics
        let stark_l2_pending_inputs = IntGauge::with_opts(Opts::new(
            "shell_stark_l2_pending_inputs",
            "Canonical L1 proofs pending in the L2 scheduler window",
        ))?;
        let stark_l2_ready_jobs = IntGauge::with_opts(Opts::new(
            "shell_stark_l2_ready_jobs",
            "L2 aggregation jobs in Ready state waiting for the prover",
        ))?;
        let stark_l2_last_trigger_block = IntGauge::with_opts(Opts::new(
            "shell_stark_l2_last_trigger_block",
            "Block number of the last L2 scheduler trigger (0 = never)",
        ))?;
        let stark_l2_blocked_gap_start = IntGauge::with_opts(Opts::new(
            "shell_stark_l2_blocked_gap_start",
            "Expected L1 proof start block when gap-blocked (0 = not blocked)",
        ))?;
        let stark_l2_proofs_generated = IntCounter::with_opts(Opts::new(
            "shell_stark_l2_proofs_generated_total",
            "Total L2 recursive proofs generated",
        ))?;
        let stark_l2_settlements_accepted = IntCounter::with_opts(Opts::new(
            "shell_stark_l2_settlements_accepted_total",
            "Total L2 settlements accepted as canonical",
        ))?;
        let stark_l2_settlements_rejected = IntCounter::with_opts(Opts::new(
            "shell_stark_l2_settlements_rejected_total",
            "Total L2 settlements rejected during validation",
        ))?;

        // ops-metrics: per-CF storage size
        let storage_cf_size = GaugeVec::new(
            Opts::new(
                "shell_storage_cf_size_bytes",
                "On-disk SST file size per column family (lazy, updated on scrape)",
            ),
            &["cf"],
        )?;

        // OPS-3: RPC latency per method
        let rpc_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "shell_rpc_request_duration_seconds",
                "RPC request duration by method",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &["method"],
        )?;

        registry.register(Box::new(block_height.clone()))?;
        registry.register(Box::new(last_finalized_number.clone()))?;
        registry.register(Box::new(finality_lag_blocks.clone()))?;
        registry.register(Box::new(peer_count.clone()))?;
        registry.register(Box::new(tx_pool_size.clone()))?;
        registry.register(Box::new(block_production_ms.clone()))?;
        registry.register(Box::new(blocks_imported.clone()))?;
        registry.register(Box::new(txs_received.clone()))?;
        registry.register(Box::new(epoch_number.clone()))?;
        registry.register(Box::new(validator_active_count.clone()))?;
        registry.register(Box::new(validator_weight.clone()))?;
        registry.register(Box::new(validator_slot_miss.clone()))?;
        registry.register(Box::new(stark_proofs_generated.clone()))?;
        registry.register(Box::new(stark_proof_failures.clone()))?;
        registry.register(Box::new(stark_proof_duration_seconds.clone()))?;
        registry.register(Box::new(stark_backlog_depth.clone()))?;
        registry.register(Box::new(stark_amendments_broadcast.clone()))?;
        registry.register(Box::new(stark_equivocations_detected.clone()))?;
        registry.register(Box::new(stark_settlements_accepted.clone()))?;
        registry.register(Box::new(stark_settlements_rejected.clone()))?;
        registry.register(Box::new(stark_frontier_lag.clone()))?;
        registry.register(Box::new(stark_l2_pending_inputs.clone()))?;
        registry.register(Box::new(stark_l2_ready_jobs.clone()))?;
        registry.register(Box::new(stark_l2_last_trigger_block.clone()))?;
        registry.register(Box::new(stark_l2_blocked_gap_start.clone()))?;
        registry.register(Box::new(stark_l2_proofs_generated.clone()))?;
        registry.register(Box::new(stark_l2_settlements_accepted.clone()))?;
        registry.register(Box::new(stark_l2_settlements_rejected.clone()))?;
        registry.register(Box::new(storage_cf_size.clone()))?;
        registry.register(Box::new(rpc_request_duration_seconds.clone()))?;

        Ok(Self {
            block_height,
            last_finalized_number,
            finality_lag_blocks,
            peer_count,
            tx_pool_size,
            block_production_ms,
            blocks_imported,
            txs_received,
            epoch_number,
            validator_active_count,
            validator_weight,
            validator_slot_miss,
            stark_proofs_generated,
            stark_proof_failures,
            stark_proof_duration_seconds,
            stark_backlog_depth,
            stark_amendments_broadcast,
            stark_equivocations_detected,
            stark_settlements_accepted,
            stark_settlements_rejected,
            stark_frontier_lag,
            stark_l2_pending_inputs,
            stark_l2_ready_jobs,
            stark_l2_last_trigger_block,
            stark_l2_blocked_gap_start,
            stark_l2_proofs_generated,
            stark_l2_settlements_accepted,
            stark_l2_settlements_rejected,
            uptime_start: Instant::now(),
            storage_cf_size,
            rpc_request_duration_seconds,
            registry,
        })
    }

    /// Encode all collected metrics into Prometheus text exposition format.
    pub fn gather(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            tracing::error!(error = %e, "failed to encode Prometheus metrics");
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }

    /// Update finality gauges from the current canonical head/finality pair.
    pub fn update_finality(&self, current_head: u64, finalized: u64) {
        self.last_finalized_number.set(finalized as i64);
        self.finality_lag_blocks
            .set(current_head.saturating_sub(finalized) as i64);
    }

    /// Update validator weight metric for a single validator.
    ///
    /// `validator` should be a hex-encoded address string (e.g. `"0xabc..."`).
    pub fn set_validator_weight(&self, validator: &str, weight: f64) {
        self.validator_weight
            .with_label_values(&[validator])
            .set(weight);
    }

    /// Record a missed proposer slot for a validator.
    pub fn record_slot_miss(&self, validator: &str) {
        self.validator_slot_miss
            .with_label_values(&[validator])
            .inc();
    }

    /// Record the duration of a completed RPC call.
    ///
    /// `method` is the JSON-RPC method name (e.g. `"shell_getBlock"`).
    /// `duration_secs` is the wall-clock time from request start to response.
    pub fn record_rpc_call(&self, method: &str, duration_secs: f64) {
        self.rpc_request_duration_seconds
            .with_label_values(&[method])
            .observe(duration_secs);
    }

    /// Update per-column-family storage size gauges.    ///
    /// Call this lazily (e.g., on every metrics scrape) to report disk
    /// footprint without blocking the critical path.  Pass `0` for any CF
    /// whose size is unavailable (e.g., MemoryDb backends).
    ///
    /// # Column family labels
    /// - `"chain"`   — block headers, bodies, canonical mapping (`b/`, `h/`, `c/`, …)
    /// - `"witness"` — PQ signature witness bundles (`w/<hash>`)
    /// - `"state"`   — Merkle-Patricia trie nodes
    /// - `"proof"`   — STARK proof amendments (`p/<hash>`)
    pub fn update_cf_sizes(&self, chain: u64, witness: u64, state: u64, proof: u64) {
        self.storage_cf_size
            .with_label_values(&["chain"])
            .set(chain as f64);
        self.storage_cf_size
            .with_label_values(&["witness"])
            .set(witness as f64);
        self.storage_cf_size
            .with_label_values(&["state"])
            .set(state as f64);
        self.storage_cf_size
            .with_label_values(&["proof"])
            .set(proof as f64);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("failed to register Prometheus metrics")
    }
}

/// Build a plain-text response (fallback for builder errors, which should never occur).
fn plain_response(
    status: StatusCode,
    text: &'static str,
) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    let mut resp = Response::new(http_body_util::Full::new(hyper::body::Bytes::from(text)));
    *resp.status_mut() = status;
    resp
}

/// Build a JSON response with the given status code and body.
fn json_response(
    status: StatusCode,
    body: serde_json::Value,
) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    match Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(
            body.to_string(),
        ))) {
        Ok(resp) => resp,
        Err(_) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, "response build error"),
    }
}

/// Handle a single HTTP request, routing to `/metrics`, `/health[z]`, or `/read[y|yz]`.
fn handle_request<B>(
    req: Request<B>,
    metrics: &Arc<Metrics>,
) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let body = metrics.gather();
            match Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))
            {
                Ok(resp) => resp,
                Err(_) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, "response build error"),
            }
        }
        // `/health` and `/healthz` are equivalent.
        (&Method::GET, "/health") | (&Method::GET, "/healthz") => {
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "block_height": metrics.block_height.get(),
                "peer_count": metrics.peer_count.get(),
                "syncing": false,
            });
            json_response(StatusCode::OK, body)
        }
        // `/ready` and `/readyz` are equivalent (Kubernetes-style).
        (&Method::GET, "/ready") | (&Method::GET, "/readyz") => {
            let block_height = metrics.block_height.get();
            if block_height > 0 {
                json_response(StatusCode::OK, serde_json::json!({ "ready": true }))
            } else {
                json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "ready": false,
                        "reason": "node has not imported any blocks yet",
                    }),
                )
            }
        }
        _ => plain_response(StatusCode::NOT_FOUND, "Not Found"),
    }
}

/// Start an HTTP server that exposes Prometheus metrics and a health endpoint.
///
/// The server runs until the process exits or the task is cancelled.
pub async fn serve_metrics(metrics: Arc<Metrics>, addr: SocketAddr) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%addr, error = %e, "failed to bind metrics server");
            return;
        }
    };
    tracing::info!(%addr, "metrics server listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "metrics server accept error");
                continue;
            }
        };

        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req| {
                let metrics = Arc::clone(&metrics);
                async move { Ok::<_, std::convert::Infallible>(handle_request(req, &metrics)) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "metrics connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_json(body: http_body_util::Full<hyper::body::Bytes>) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn get(path: &str) -> Request<http_body_util::Empty<hyper::body::Bytes>> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(http_body_util::Empty::new())
            .unwrap()
    }

    #[test]
    fn metrics_new_creates_valid_instance() {
        let m = Metrics::new().expect("metrics init");
        assert_eq!(m.block_height.get(), 0);
        assert_eq!(m.last_finalized_number.get(), 0);
        assert_eq!(m.finality_lag_blocks.get(), 0);
        assert_eq!(m.peer_count.get(), 0);
        assert_eq!(m.tx_pool_size.get(), 0);
        assert_eq!(m.blocks_imported.get(), 0);
        assert_eq!(m.txs_received.get(), 0);
    }

    #[test]
    fn gather_returns_prometheus_text_format() {
        let m = Metrics::new().expect("metrics init");
        m.block_height.set(42);
        m.update_finality(42, 40);
        m.blocks_imported.inc();

        let output = m.gather();
        assert!(
            output.contains("shell_block_height 42"),
            "should contain block_height metric"
        );
        assert!(
            output.contains("shell_blocks_imported_total 1"),
            "should contain blocks_imported metric"
        );
        assert!(
            output.contains("shell_last_finalized_number 40"),
            "should contain last_finalized_number metric"
        );
        assert!(
            output.contains("shell_finality_lag_blocks 2"),
            "should contain finality_lag_blocks metric"
        );
        assert!(
            output.contains("shell_peer_count"),
            "should contain peer_count metric"
        );
        assert!(
            output.contains("shell_tx_pool_size"),
            "should contain tx_pool_size metric"
        );
        assert!(
            output.contains("shell_block_production_duration_seconds"),
            "should contain block_production_duration_seconds metric"
        );
        assert!(
            output.contains("shell_txs_received_total"),
            "should contain txs_received metric"
        );
    }

    #[tokio::test]
    async fn health_returns_ok_with_version() {
        let m = Arc::new(Metrics::new().expect("metrics init"));
        m.block_height.set(12345);
        m.peer_count.set(3);

        let resp = handle_request(get("/health"), &m);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["block_height"], 12345);
        assert_eq!(body["peer_count"], 3);
        assert_eq!(body["syncing"], false);
        assert!(body["version"].is_string(), "version should be a string");
    }

    #[tokio::test]
    async fn ready_returns_true_when_blocks_imported() {
        let m = Arc::new(Metrics::new().expect("metrics init"));
        m.block_height.set(1);

        let resp = handle_request(get("/ready"), &m);
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ready"], true);
    }

    #[tokio::test]
    async fn ready_returns_503_when_no_blocks() {
        let m = Arc::new(Metrics::new().expect("metrics init"));

        let resp = handle_request(get("/ready"), &m);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ready"], false);
        assert!(body["reason"].is_string());
    }

    #[tokio::test]
    async fn ready_does_not_require_peers() {
        let m = Arc::new(Metrics::new().expect("metrics init"));
        m.block_height.set(10);
        assert_eq!(m.peer_count.get(), 0);

        let resp = handle_request(get("/ready"), &m);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn block_height_gauge_updates() {
        let m = Metrics::new().expect("metrics init");
        assert_eq!(m.block_height.get(), 0);
        m.block_height.set(100);
        assert_eq!(m.block_height.get(), 100);
        m.block_height.inc();
        assert_eq!(m.block_height.get(), 101);
    }

    #[test]
    fn histogram_records_values() {
        let m = Metrics::new().expect("metrics init");
        m.block_production_ms.observe(0.05);
        m.block_production_ms.observe(0.25);
        m.block_production_ms.observe(1.5);

        let output = m.gather();
        assert!(
            output.contains("shell_block_production_duration_seconds_count 3"),
            "histogram should record 3 observations"
        );
    }

    #[test]
    fn wpoa_metrics_default_to_zero() {
        let m = Metrics::new().expect("metrics init");
        assert_eq!(m.epoch_number.get(), 0);
        assert_eq!(m.validator_active_count.get(), 0);
    }

    #[test]
    fn validator_weight_gauge_updates() {
        let m = Metrics::new().expect("metrics init");
        m.set_validator_weight("0xabcd", 3.0);
        m.set_validator_weight("0xabcd", 5.0);

        let output = m.gather();
        assert!(
            output.contains("shell_validator_weight"),
            "should contain validator_weight metric"
        );
        assert!(
            output.contains(r#"validator="0xabcd""#),
            "should have validator label"
        );
    }

    #[test]
    fn validator_slot_miss_counter_increments() {
        let m = Metrics::new().expect("metrics init");
        m.record_slot_miss("0xdead");
        m.record_slot_miss("0xdead");

        let output = m.gather();
        assert!(
            output.contains("shell_consensus_slot_miss_total"),
            "should contain slot_miss metric"
        );
    }

    #[test]
    fn epoch_and_active_count_setters() {
        let m = Metrics::new().expect("metrics init");
        m.epoch_number.set(7);
        m.validator_active_count.set(4);
        assert_eq!(m.epoch_number.get(), 7);
        assert_eq!(m.validator_active_count.get(), 4);

        let output = m.gather();
        assert!(output.contains("shell_epoch_number 7"));
        assert!(output.contains("shell_validator_active_count 4"));
    }

    #[test]
    fn rpc_latency_histogram_records_by_method() {
        let m = Metrics::new().expect("metrics init");
        m.record_rpc_call("shell_getBlock", 0.005);
        m.record_rpc_call("shell_getBlock", 0.010);
        m.record_rpc_call("eth_getBalance", 0.002);

        let output = m.gather();
        assert!(
            output.contains("shell_rpc_request_duration_seconds"),
            "should contain rpc duration metric"
        );
        assert!(
            output.contains(r#"method="shell_getBlock""#),
            "should label by method"
        );
        assert!(
            output.contains(r#"method="eth_getBalance""#),
            "should label different methods separately"
        );
        // getBlock has 2 observations
        assert!(
            output
                .contains("shell_rpc_request_duration_seconds_count{method=\"shell_getBlock\"} 2"),
            "should count 2 shell_getBlock calls"
        );
    }

    #[tokio::test]
    async fn healthz_alias_returns_same_as_health() {
        let m = Arc::new(Metrics::new().expect("metrics init"));
        m.block_height.set(5);

        let resp = handle_request(get("/healthz"), &m);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["block_height"], 5);
    }

    #[tokio::test]
    async fn readyz_alias_returns_same_as_ready() {
        let m = Arc::new(Metrics::new().expect("metrics init"));
        m.block_height.set(3);

        let resp = handle_request(get("/readyz"), &m);
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ready"], true);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_no_blocks() {
        let m = Arc::new(Metrics::new().expect("metrics init"));

        let resp = handle_request(get("/readyz"), &m);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["ready"], false);
    }
}
