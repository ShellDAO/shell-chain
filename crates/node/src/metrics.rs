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
    CounterVec, Encoder, GaugeVec, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry,
    TextEncoder,
};

/// Prometheus metrics for a shell-chain node.
pub struct Metrics {
    /// Current block height.
    pub block_height: IntGauge,
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
    /// Timestamp when the node started, used for uptime calculation.
    pub uptime_start: Instant,
    // -----------------------------------------------------------------------
    // Storage size metrics (ops-metrics)
    // -----------------------------------------------------------------------
    /// On-disk SST file size per column family.
    /// Labels: `cf` ∈ { "chain", "witness", "state", "proof" }.
    /// Updated lazily when the `/metrics` endpoint is scraped (via
    /// `update_cf_sizes`). Returns 0 for backends that don't expose CF sizes.
    pub storage_cf_size: GaugeVec,
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

        // ops-metrics: per-CF storage size
        let storage_cf_size = GaugeVec::new(
            Opts::new(
                "shell_storage_cf_size_bytes",
                "On-disk SST file size per column family (lazy, updated on scrape)",
            ),
            &["cf"],
        )?;

        registry.register(Box::new(block_height.clone()))?;
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
        registry.register(Box::new(storage_cf_size.clone()))?;

        Ok(Self {
            block_height,
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
            uptime_start: Instant::now(),
            storage_cf_size,
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

    /// Update per-column-family storage size gauges.
    ///
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

/// Handle a single HTTP request, routing to `/metrics`, `/health`, or `/ready`.
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
        (&Method::GET, "/health") => {
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "block_height": metrics.block_height.get(),
                "peer_count": metrics.peer_count.get(),
                "syncing": false,
            });
            json_response(StatusCode::OK, body)
        }
        (&Method::GET, "/ready") => {
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
        assert_eq!(m.peer_count.get(), 0);
        assert_eq!(m.tx_pool_size.get(), 0);
        assert_eq!(m.blocks_imported.get(), 0);
        assert_eq!(m.txs_received.get(), 0);
    }

    #[test]
    fn gather_returns_prometheus_text_format() {
        let m = Metrics::new().expect("metrics init");
        m.block_height.set(42);
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
}
