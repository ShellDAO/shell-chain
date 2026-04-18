//! Multi-prover L1–L2 STARK soak test.
//!
//! Simulates N independent L1 provers running concurrently, feeding their
//! completed proofs into an aggregation scheduler that triggers L2
//! (`compute_aggregate_root`) rounds.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────┐   ProofEvent   ┌─────────────────────┐
//!  │ L1 Prover 0  │ ──────────────►│                     │──► l1_proofs.csv
//!  │ L1 Prover 1  │ ──────────────►│   Coordinator       │
//!  │ L1 Prover N  │ ──────────────►│  (AggregationSched) │──► l2_aggregations.csv
//!  └──────────────┘                │                     │
//!  ┌──────────────┐  BlockNumber   │                     │
//!  │ Node Monitor │ ──────────────►│                     │
//!  └──────────────┘                └─────────────────────┘
//! ```
//!
//! L2 aggregation uses [`compute_aggregate_root`] from the `recursive_air`
//! module — the same hash-chain accumulator the full L2 recursive AIR will
//! use, giving valid complexity/compression measurements without requiring
//! the feature-gated ZK prover.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use csv::WriterBuilder;
use hdrhistogram::Histogram;
use rand::{Rng, SeedableRng};
use tracing::{info, warn};

use shell_stark_prover::{
    compute_aggregate_root, prove_sig_batch, verify_sig_batch, AggregationConfig,
    AggregationScheduler, SigBatchEntry,
};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "shell-multi-prover",
    about = "Multi-prover L1–L2 STARK soak test (simulates N concurrent provers)"
)]
struct Cli {
    /// Number of concurrent L1 prover workers
    #[arg(long, default_value_t = 4)]
    num_provers: usize,

    /// Test duration in seconds
    #[arg(long, default_value_t = 18_000)]
    duration: u64,

    /// Node JSON-RPC URL for live block-height polling
    #[arg(long, default_value = "http://localhost:8545")]
    node_url: String,

    /// Output directory for CSV files
    #[arg(long, default_value = "/tmp/shell-multi-prover")]
    out_dir: PathBuf,

    /// Console report interval in seconds
    #[arg(long, default_value_t = 60)]
    report_interval: u64,

    /// Minimum L1 proofs to trigger L2 aggregation
    #[arg(long, default_value_t = 8)]
    l2_threshold: u64,

    /// Trigger L2 aggregation every N blocks (0 = off)
    #[arg(long, default_value_t = 50)]
    l2_block_interval: u64,

    /// Epoch length for epoch-boundary L2 trigger (0 = off)
    #[arg(long, default_value_t = 100)]
    epoch_length: u64,
}

// ─── Prover worker profiles ───────────────────────────────────────────────────

/// Batch-size profiles for the 4 default provers.
/// Each simulates a different class of validator node.
fn worker_batch_sizes(prover_id: usize, total_provers: usize) -> Vec<usize> {
    // Distribute batch sizes evenly across provers.
    // Default batch sizes: 1,4,8,16,32,64,128,256
    let all: Vec<usize> = vec![1, 4, 8, 16, 32, 64, 128, 256];
    if total_provers <= 1 {
        return all;
    }
    // Divide the range: prover 0 gets small, last gets large
    let chunk = (all.len() + total_provers - 1) / total_provers;
    let start = (prover_id * chunk).min(all.len());
    let end = (start + chunk).min(all.len());
    if start >= end {
        // wrap-around: reuse full set
        all
    } else {
        all[start..end].to_vec()
    }
}

// ─── Message types ────────────────────────────────────────────────────────────

/// Result from a single L1 prove+verify cycle.
#[derive(Debug)]
struct ProofEvent {
    prover_id: usize,
    batch_size: usize,
    batch_root: u128,
    prove_ms: f64,
    verify_us: f64,
    proof_bytes: usize,
    ok: bool,
    error_msg: String,
    elapsed_secs: u64,
    block_number: u64,
}

/// Message sent to the coordinator.
enum CoordMsg {
    Proof(ProofEvent),
    Block(u64),
}

// ─── CSV record types ─────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct L1Record {
    timestamp_utc: String,
    elapsed_secs: u64,
    block_number: u64,
    prover_id: usize,
    batch_size: usize,
    prove_ms: f64,
    verify_us: f64,
    proof_bytes: usize,
    compression_ratio: f64,
    ok: u8,
    error_msg: String,
}

#[derive(serde::Serialize)]
struct L2Record {
    timestamp_utc: String,
    elapsed_secs: u64,
    at_block: u64,
    window_start: u64,
    num_l1_proofs: usize,
    aggregate_root_hex: String,
    aggregate_ms: f64,
    l1_bytes_total: usize,
    l2_bytes: usize,
    compression_ratio: f64,
    reason: String,
}

// ─── Prover worker ────────────────────────────────────────────────────────────

async fn prover_worker(
    prover_id: usize,
    batch_sizes: Vec<usize>,
    duration: Duration,
    tx: tokio::sync::mpsc::Sender<CoordMsg>,
    current_block: Arc<AtomicU64>,
    start: Instant,
) {
    let seed = prover_id as u64 + 0xdead_beef_0000_0000;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut batch_idx = 0usize;

    loop {
        if start.elapsed() >= duration {
            break;
        }

        let batch_size = batch_sizes[batch_idx % batch_sizes.len()];
        batch_idx += 1;

        let entries: Vec<SigBatchEntry> = (0..batch_size)
            .map(|_| {
                let mut msg_hash = [0u8; 32];
                let mut pk_hash = [0u8; 32];
                rng.fill(&mut msg_hash);
                rng.fill(&mut pk_hash);
                SigBatchEntry { msg_hash, pk_hash }
            })
            .collect();

        let block_number = current_block.load(Ordering::Relaxed);
        let elapsed_secs = start.elapsed().as_secs();

        // Prove in blocking thread (CPU-intensive).
        let entries_clone = entries.clone();
        let prove_result = tokio::task::spawn_blocking(move || {
            let t = Instant::now();
            let result = prove_sig_batch(&entries_clone);
            (result, t.elapsed())
        })
        .await;

        let (event, should_break) = match prove_result {
            Err(_) => {
                warn!("prover {prover_id}: spawn_blocking panicked");
                break;
            }
            Ok((Err(e), prove_elapsed)) => {
                let ev = ProofEvent {
                    prover_id,
                    batch_size,
                    batch_root: 0,
                    prove_ms: prove_elapsed.as_secs_f64() * 1000.0,
                    verify_us: 0.0,
                    proof_bytes: 0,
                    ok: false,
                    error_msg: format!("prove: {e}"),
                    elapsed_secs,
                    block_number,
                };
                (ev, false)
            }
            Ok((Ok(proof), prove_elapsed)) => {
                let serialized = serde_json::to_vec(&proof).unwrap_or_default();
                let proof_bytes = serialized.len();

                // Extract batch_root for L2 aggregation.
                let batch_root =
                    u128::from_le_bytes(proof.batch_root_bytes);

                let verify_result = tokio::task::spawn_blocking(move || {
                    let t = Instant::now();
                    let r = verify_sig_batch(&proof);
                    (r, t.elapsed())
                })
                .await;

                let (ok, verify_us, error_msg) = match verify_result {
                    Ok((Ok(()), dur)) => (true, dur.as_secs_f64() * 1e6, String::new()),
                    Ok((Err(e), dur)) => {
                        (false, dur.as_secs_f64() * 1e6, format!("verify: {e}"))
                    }
                    Err(_) => (false, 0.0, "verify: spawn panic".into()),
                };

                let ev = ProofEvent {
                    prover_id,
                    batch_size,
                    batch_root,
                    prove_ms: prove_elapsed.as_secs_f64() * 1000.0,
                    verify_us,
                    proof_bytes,
                    ok,
                    error_msg,
                    elapsed_secs,
                    block_number,
                };
                (ev, false)
            }
        };

        if tx.send(CoordMsg::Proof(event)).await.is_err() {
            break;
        }
        if should_break {
            break;
        }
    }

    info!("prover {prover_id}: done");
}

// ─── Node monitor ─────────────────────────────────────────────────────────────

async fn node_monitor(
    node_url: String,
    duration: Duration,
    tx: tokio::sync::mpsc::Sender<CoordMsg>,
    current_block: Arc<AtomicU64>,
    start: Instant,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let mut last_block = 0u64;
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;

        if start.elapsed() >= duration {
            break;
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        match client.post(&node_url).json(&body).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(hex) = json.get("result").and_then(|v| v.as_str()) {
                        let block = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                            .unwrap_or(last_block);
                        if block > last_block {
                            last_block = block;
                            current_block.store(block, Ordering::Relaxed);
                            let _ = tx.send(CoordMsg::Block(block)).await;
                        }
                    }
                }
            }
            Err(e) => {
                warn!("node monitor: RPC error: {e}");
            }
        }
    }

    info!("node monitor: done (last block: {last_block})");
}

// ─── Coordinator ─────────────────────────────────────────────────────────────

async fn coordinator(
    num_provers: usize,
    duration: Duration,
    l2_threshold: u64,
    l2_block_interval: u64,
    epoch_length: u64,
    report_interval: Duration,
    out_dir: PathBuf,
    mut rx: tokio::sync::mpsc::Receiver<CoordMsg>,
    start: Instant,
) -> Result<()> {
    std::fs::create_dir_all(&out_dir)?;
    let ts = Utc::now().format("%Y%m%dT%H%M%S");
    let l1_path = out_dir.join(format!("l1_proofs_{ts}.csv"));
    let l2_path = out_dir.join(format!("l2_aggregations_{ts}.csv"));

    let l1_file = std::fs::File::create(&l1_path)?;
    let l2_file = std::fs::File::create(&l2_path)?;
    let mut l1_csv = WriterBuilder::new().has_headers(true).from_writer(l1_file);
    let mut l2_csv = WriterBuilder::new().has_headers(true).from_writer(l2_file);

    info!("CSV L1 → {}", l1_path.display());
    info!("CSV L2 → {}", l2_path.display());

    let config = AggregationConfig {
        epoch_length,
        min_l1_proofs_for_l2: l2_threshold,
        trigger_block_interval: l2_block_interval,
    };
    let mut scheduler = AggregationScheduler::new(config, 0);

    // Per-prover L1 histograms.
    let mut l1_prove_hist: Vec<Histogram<u64>> = (0..num_provers)
        .map(|_| Histogram::new(4).unwrap())
        .collect();
    let mut l1_verify_hist: Vec<Histogram<u64>> = (0..num_provers)
        .map(|_| Histogram::new(4).unwrap())
        .collect();

    // Pending L1 roots for next L2 round.
    let mut pending_roots: Vec<u128> = Vec::new();
    let mut pending_l1_bytes: usize = 0;
    let mut window_start_block: u64 = 0;

    let mut total_l1_ok = 0u64;
    let mut total_l1_fail = 0u64;
    let mut total_l2_rounds = 0u64;
    let mut last_report = Instant::now();
    let mut current_block = 0u64;

    // L2 aggregation histogram (milliseconds * 1000 = microseconds).
    let mut l2_hist: Histogram<u64> = Histogram::new(4).unwrap();

    loop {
        if start.elapsed() >= duration {
            break;
        }

        let msg = match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => CoordMsg::Block(current_block), // tick even if no messages
        };

        match msg {
            CoordMsg::Block(block) => {
                current_block = block;
                scheduler.on_proof(block); // no-op for block events directly
                if let Some(trigger) = scheduler.on_block(block) {
                    // Run L2 aggregation.
                    if !pending_roots.is_empty() {
                        let roots_for_agg = std::mem::take(&mut pending_roots);
                        let l1_bytes = pending_l1_bytes;
                        pending_l1_bytes = 0;

                        let num_roots = roots_for_agg.len();
                        let t_agg = Instant::now();
                        let aggregate_root = compute_aggregate_root(&roots_for_agg);
                        let agg_ms = t_agg.elapsed().as_secs_f64() * 1000.0;

                        // L2 "proof" is the 16-byte aggregate root (u128).
                        let l2_bytes = 16usize;
                        let compression = if l2_bytes > 0 {
                            l1_bytes as f64 / l2_bytes as f64
                        } else {
                            0.0
                        };

                        let _ = l2_hist.record((agg_ms * 1000.0) as u64);
                        total_l2_rounds += 1;

                        let elapsed_secs = start.elapsed().as_secs();
                        l2_csv.serialize(L2Record {
                            timestamp_utc: Utc::now().to_rfc3339(),
                            elapsed_secs,
                            at_block: trigger.at_block,
                            window_start: window_start_block,
                            num_l1_proofs: num_roots,
                            aggregate_root_hex: format!("{aggregate_root:#018x}"),
                            aggregate_ms: agg_ms,
                            l1_bytes_total: l1_bytes,
                            l2_bytes,
                            compression_ratio: compression,
                            reason: format!("{:?}", trigger.reason),
                        })?;

                        info!(
                            "L2 AGGREGATE  block={block}  l1_proofs={num_roots}  \
                             agg_root={aggregate_root:#018x}  compress={compression:.0}×  \
                             reason={:?}",
                            trigger.reason
                        );

                        window_start_block = block + 1;
                    }
                }
            }

            CoordMsg::Proof(ev) => {
                // Write L1 CSV row.
                let raw_bytes = ev.batch_size * 64;
                let compression = if ev.proof_bytes > 0 {
                    raw_bytes as f64 / ev.proof_bytes as f64
                } else {
                    0.0
                };

                l1_csv.serialize(L1Record {
                    timestamp_utc: Utc::now().to_rfc3339(),
                    elapsed_secs: ev.elapsed_secs,
                    block_number: ev.block_number,
                    prover_id: ev.prover_id,
                    batch_size: ev.batch_size,
                    prove_ms: ev.prove_ms,
                    verify_us: ev.verify_us,
                    proof_bytes: ev.proof_bytes,
                    compression_ratio: compression,
                    ok: ev.ok as u8,
                    error_msg: ev.error_msg.clone(),
                })?;

                if ev.ok {
                    total_l1_ok += 1;
                    let pid = ev.prover_id.min(num_provers - 1);
                    let _ = l1_prove_hist[pid].record((ev.prove_ms * 1000.0) as u64);
                    let _ = l1_verify_hist[pid].record(ev.verify_us as u64);

                    // Accumulate for L2 aggregation.
                    pending_roots.push(ev.batch_root);
                    pending_l1_bytes += ev.proof_bytes;

                    // Notify scheduler of a new L1 proof.
                    scheduler.on_proof(ev.block_number);
                } else {
                    total_l1_fail += 1;
                }

                // Periodic CSV flush.
                if (total_l1_ok + total_l1_fail).is_multiple_of(200) {
                    l1_csv.flush()?;
                    l2_csv.flush()?;
                }
            }
        }

        // Periodic console report.
        if last_report.elapsed() >= report_interval {
            last_report = Instant::now();
            let elapsed = start.elapsed();
            let remaining = duration.saturating_sub(elapsed);
            info!(
                "─── Multi-Prover Report @ {}h{:02}m{:02}s  ({}h{:02}m rem)  block={} ───",
                elapsed.as_secs() / 3600,
                (elapsed.as_secs() % 3600) / 60,
                elapsed.as_secs() % 60,
                remaining.as_secs() / 3600,
                (remaining.as_secs() % 3600) / 60,
                current_block,
            );
            info!(
                "L1: total_ok={}  total_fail={}  pending_l2={}",
                total_l1_ok,
                total_l1_fail,
                pending_roots.len()
            );
            for pid in 0..num_provers {
                if !l1_prove_hist[pid].is_empty() {
                    info!(
                        "  prover {}  prove p50={:.1}ms p99={:.1}ms  \
                         verify p50={:.1}µs",
                        pid,
                        l1_prove_hist[pid].value_at_quantile(0.50) as f64 / 1_000.0,
                        l1_prove_hist[pid].value_at_quantile(0.99) as f64 / 1_000.0,
                        l1_verify_hist[pid].value_at_quantile(0.50) as f64 / 1_000.0,
                    );
                }
            }
            info!(
                "L2: rounds={}  {}",
                total_l2_rounds,
                if l2_hist.is_empty() {
                    "agg p50=—".to_string()
                } else {
                    format!(
                        "agg p50={:.2}ms p99={:.2}ms",
                        l2_hist.value_at_quantile(0.50) as f64 / 1_000.0,
                        l2_hist.value_at_quantile(0.99) as f64 / 1_000.0,
                    )
                }
            );
        }
    }

    l1_csv.flush()?;
    l2_csv.flush()?;

    // Final summary.
    let total_elapsed = start.elapsed();
    info!("══════════════════════════════════════════════════════════");
    info!(
        "FINAL MULTI-PROVER SUMMARY  ({:.1}h elapsed)",
        total_elapsed.as_secs_f64() / 3600.0
    );
    info!("══════════════════════════════════════════════════════════");
    info!("L1 proofs OK  : {total_l1_ok}");
    info!(
        "L1 failures   : {} ({:.2}%)",
        total_l1_fail,
        if total_l1_ok + total_l1_fail > 0 {
            100.0 * total_l1_fail as f64 / (total_l1_ok + total_l1_fail) as f64
        } else {
            0.0
        }
    );
    info!("L2 agg rounds : {total_l2_rounds}");
    info!("Last block    : {current_block}");
    info!("──────────────────────────────────────────────────────────");
    for pid in 0..num_provers {
        if !l1_prove_hist[pid].is_empty() {
            info!(
                "Prover {:2}  prove p50={:.1}ms p99={:.1}ms  verify p50={:.1}µs",
                pid,
                l1_prove_hist[pid].value_at_quantile(0.50) as f64 / 1_000.0,
                l1_prove_hist[pid].value_at_quantile(0.99) as f64 / 1_000.0,
                l1_verify_hist[pid].value_at_quantile(0.50) as f64 / 1_000.0,
            );
        }
    }
    if !l2_hist.is_empty() {
        info!(
            "L2 agg        p50={:.2}ms p99={:.2}ms",
            l2_hist.value_at_quantile(0.50) as f64 / 1_000.0,
            l2_hist.value_at_quantile(0.99) as f64 / 1_000.0,
        );
    }
    info!("CSV L1 → {}", l1_path.display());
    info!("CSV L2 → {}", l2_path.display());
    info!("══════════════════════════════════════════════════════════");

    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();

    let duration = Duration::from_secs(cli.duration);
    let report_interval = Duration::from_secs(cli.report_interval);
    let start = Instant::now();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  Shell-chain Multi-Prover L1–L2 STARK Soak Test          ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("Provers       : {}", cli.num_provers);
    info!(
        "Duration      : {}h {:02}m ({} s)",
        cli.duration / 3600,
        (cli.duration % 3600) / 60,
        cli.duration
    );
    info!("Node URL      : {}", cli.node_url);
    info!("L2 threshold  : {} L1 proofs", cli.l2_threshold);
    info!("L2 block int  : every {} blocks", cli.l2_block_interval);
    info!("Epoch length  : {} blocks", cli.epoch_length);
    info!("Output dir    : {}", cli.out_dir.display());

    for pid in 0..cli.num_provers {
        let batch_sizes = worker_batch_sizes(pid, cli.num_provers);
        info!("  prover {pid}  batch_sizes={batch_sizes:?}");
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<CoordMsg>(4096);
    let current_block = Arc::new(AtomicU64::new(0));

    // Spawn prover workers.
    let mut handles = Vec::new();
    for pid in 0..cli.num_provers {
        let batch_sizes = worker_batch_sizes(pid, cli.num_provers);
        let tx2 = tx.clone();
        let cb = current_block.clone();
        let h = tokio::spawn(prover_worker(pid, batch_sizes, duration, tx2, cb, start));
        handles.push(h);
    }

    // Spawn node monitor.
    {
        let tx2 = tx.clone();
        let cb = current_block.clone();
        let url = cli.node_url.clone();
        tokio::spawn(node_monitor(url, duration, tx2, cb, start));
    }

    // Drop the original sender so coordinator can detect when all are done.
    drop(tx);

    // Run coordinator (owns the CSV writers and scheduler).
    coordinator(
        cli.num_provers,
        duration,
        cli.l2_threshold,
        cli.l2_block_interval,
        cli.epoch_length,
        report_interval,
        cli.out_dir,
        rx,
        start,
    )
    .await?;

    // Wait for all prover workers.
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}
