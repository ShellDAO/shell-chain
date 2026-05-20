//! Shell-chain 10-hour high-TPS load test harness.
//!
//! Spawns N async workers. Each worker owns a Dilithium3 keypair + pre-funded
//! account and submits transactions as fast as possible for the configured
//! duration. Transactions are drawn from a weighted mix:
//!
//!   60 % — simple value transfer
//!   20 % — zero-value transfer with 32-byte data payload
//!   15 % — contract deployment (dummy bytecode ~200 bytes)
//!    5 % — self-transfer with large (1 KB) data
//!
//! Metrics are collected in HDR histograms and flushed to CSV every
//! REPORT_INTERVAL seconds. A final summary is printed at the end.
//!
//! Usage:
//!   shell-load-test [OPTIONS]
//!
//! Example (10 hours, 50 workers, target ≥500 TPS):
//!   shell-load-test --duration 36000 --workers 50 --rpc http://127.0.0.1:8545

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use clap::Parser;
use hdrhistogram::Histogram;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, warn};

use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, Signer};
use shell_primitives::{Address, Bytes, ShellHash, U256};

// anyhow re-export shorthand
use anyhow::Result as AResult;

extern crate alloy_rlp;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "shell-load-test",
    about = "Shell-chain high-TPS load test (10-hour soak)"
)]
struct Cli {
    /// JSON-RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Total test duration in seconds (default 36000 = 10 h)
    #[arg(long, default_value_t = 36_000)]
    duration: u64,

    /// Number of concurrent sender workers
    #[arg(long, default_value_t = 50)]
    workers: usize,

    /// Initial balance for each funded account (in SHELL, decimal)
    #[arg(long, default_value_t = 1_000_000)]
    fund_shell: u64,

    /// Metrics CSV output directory
    #[arg(long, default_value = "/tmp/shell-load-test")]
    out_dir: PathBuf,

    /// How often to flush metrics to CSV (seconds)
    #[arg(long, default_value_t = 30)]
    report_interval: u64,

    /// Chain ID
    #[arg(long, default_value_t = 1337)]
    chain_id: u64,
}

// ─── Tx types ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum TxType {
    Transfer,     // 60 % — simple value transfer
    DataTransfer, // 20 % — zero-value + 32-byte data
    Deploy,       // 15 % — contract deployment
    LargeData,    //  5 % — self-transfer, 1 KB data
}

fn pick_tx_type(counter: u64) -> TxType {
    match counter % 100 {
        0..=59 => TxType::Transfer,
        60..=79 => TxType::DataTransfer,
        80..=94 => TxType::Deploy,
        _ => TxType::LargeData,
    }
}

use rand::Rng;

// ─── Load tier ────────────────────────────────────────────────────────────────

/// Five load tiers that control how many txs are injected per block window.
#[derive(Clone, Copy, Debug)]
enum LoadTier {
    Zero,   //   0 txs  — complete pause
    Few,    //   1–50   — light traffic
    Medium, //  51–200  — moderate traffic
    Many,   // 201–400  — heavy traffic
    Max,    // 401–500  — saturate mempool
}

impl LoadTier {
    fn budget(self, rng: &mut impl Rng) -> i64 {
        match self {
            LoadTier::Zero => 0,
            LoadTier::Few => rng.gen_range(1..=50),
            LoadTier::Medium => rng.gen_range(51..=200),
            LoadTier::Many => rng.gen_range(201..=400),
            LoadTier::Max => rng.gen_range(401..=500),
        }
    }

    fn label(self) -> &'static str {
        match self {
            LoadTier::Zero => "ZERO",
            LoadTier::Few => "FEW",
            LoadTier::Medium => "MED",
            LoadTier::Many => "MANY",
            LoadTier::Max => "MAX",
        }
    }
}

fn pick_load_tier(rng: &mut impl Rng) -> LoadTier {
    match rng.gen_range(0u8..5) {
        0 => LoadTier::Zero,
        1 => LoadTier::Few,
        2 => LoadTier::Medium,
        3 => LoadTier::Many,
        _ => LoadTier::Max,
    }
}

/// Deploy bytecode that stores a 1-byte runtime code (STOP opcode).
/// Initializer: PUSH1 0x01, PUSH1 0x00, RETURN → runtime = memory[0..1] = 0x00
/// eth_getCode returns "0x00", which is non-empty → detected as Contract.
fn dummy_deploy_data() -> Vec<u8> {
    let mut data = vec![0x60, 0x01, 0x60, 0x00, 0xf3]; // deploy 1-byte runtime code
    data.extend(std::iter::repeat_n(0x00, 195)); // pad to 200 bytes
    data
}

fn small_data() -> Vec<u8> {
    // 32 bytes of incrementing values
    (0u8..32).collect()
}

fn large_data() -> Vec<u8> {
    // 1 KB of patterned bytes
    (0u8..=255).cycle().take(1024).collect()
}

// ─── RPC helpers ─────────────────────────────────────────────────────────────

async fn rpc_call(client: &Client, rpc_url: &str, method: &str, params: Value) -> AResult<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .json::<Value>()
        .await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("RPC error: {err}");
    }
    Ok(resp["result"].clone())
}

async fn get_nonce(client: &Client, rpc_url: &str, addr: &str) -> AResult<u64> {
    let result = rpc_call(
        client,
        rpc_url,
        "eth_getTransactionCount",
        json!([addr, "latest"]),
    )
    .await?;
    let hex = result.as_str().unwrap_or("0x0");
    Ok(u64::from_str_radix(hex.trim_start_matches("0x"), 16)?)
}

async fn fund_account(client: &Client, rpc_url: &str, addr: &str, wei_hex: &str) -> AResult<()> {
    rpc_call(client, rpc_url, "shell_setBalance", json!([addr, wei_hex])).await?;
    Ok(())
}

async fn submit_signed_tx(
    client: &Client,
    rpc_url: &str,
    signed: &SignedTransaction,
) -> AResult<ShellHash> {
    // Encode as RLP and send via eth_sendRawTransaction (same as CLI)
    let encoded = alloy_rlp::encode(signed);
    let hex_data = format!("0x{}", hex::encode(&encoded));

    let result = rpc_call(client, rpc_url, "eth_sendRawTransaction", json!([hex_data])).await?;
    let hex_str = result
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no result hash from eth_sendRawTransaction"))?;
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        anyhow::bail!("unexpected tx hash length: {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ShellHash::from(arr))
}

// ─── Per-worker state ─────────────────────────────────────────────────────────

struct Worker {
    id: usize,
    signer: DilithiumSigner,
    address: Address,
    pq_address: String,
    nonce: u64,
    chain_id: u64,
    tx_counter: u64,
}

impl Worker {
    fn new(id: usize, chain_id: u64) -> Self {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let address =
            Address::from_public_key(&pubkey, shell_crypto::SignatureType::Dilithium3.as_u8());
        let pq_address = address.to_string(); // Display trait formats as 0x hex.
        Worker {
            id,
            signer,
            address,
            pq_address,
            nonce: 0,
            chain_id,
            tx_counter: 0,
        }
    }

    fn build_tx(&self, tx_type: TxType, recipient: Address, rng_seed: u64) -> Transaction {
        // Pick a random transfer value: 1–1000 SHELL (non-zero)
        let shell_amount = (rng_seed % 1000) + 1; // 1–1000 SHELL
        let transfer_value = U256::from(shell_amount) * U256::from(10u64).pow(U256::from(18u64));

        match tx_type {
            TxType::Transfer => Transaction {
                chain_id: self.chain_id,
                nonce: self.nonce,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 21_000,
                to: Some(recipient),
                value: transfer_value,
                data: Bytes::default(),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            TxType::DataTransfer => Transaction {
                chain_id: self.chain_id,
                nonce: self.nonce,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 50_000,
                to: Some(recipient),
                value: U256::ZERO,
                data: Bytes::from(small_data()),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            TxType::Deploy => Transaction {
                chain_id: self.chain_id,
                nonce: self.nonce,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 200_000,
                to: None, // contract creation
                value: U256::ZERO,
                data: Bytes::from(dummy_deploy_data()),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            TxType::LargeData => Transaction {
                chain_id: self.chain_id,
                nonce: self.nonce,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 500_000,
                to: Some(self.address), // self-transfer
                value: U256::ZERO,
                data: Bytes::from(large_data()),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
        }
    }

    fn sign(&self, tx: Transaction) -> SignedTransaction {
        let sig = self.signer.sign(tx.hash().0.as_slice()).unwrap();
        // Include pubkey on first tx so the node registers the account
        if self.nonce == 0 {
            let pubkey = self.signer.public_key().to_vec();
            SignedTransaction::with_pubkey(self.address, tx, sig, pubkey)
        } else {
            SignedTransaction::new(self.address, tx, sig)
        }
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

struct PeriodMetrics {
    ts: String,
    period_secs: u64,
    submitted: u64,
    confirmed: u64,
    errors: u64,
    tps_submit: f64,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    max_ms: u64,
}

struct MetricsCollector {
    histogram: Histogram<u64>,
    submitted: u64,
    errors: u64,
    period_start: Instant,
}

impl MetricsCollector {
    fn new() -> Self {
        Self {
            histogram: Histogram::<u64>::new(3).unwrap(),
            submitted: 0,
            errors: 0,
            period_start: Instant::now(),
        }
    }

    fn record_ok(&mut self, latency_ms: u64) {
        self.submitted += 1;
        let _ = self.histogram.record(latency_ms);
    }

    fn record_err(&mut self) {
        self.errors += 1;
    }

    fn flush(&mut self, report_interval: u64) -> PeriodMetrics {
        let elapsed = self.period_start.elapsed().as_secs_f64();
        let tps = self.submitted as f64 / elapsed.max(0.001);
        let m = PeriodMetrics {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            period_secs: report_interval,
            submitted: self.submitted,
            confirmed: 0, // filled later by block scanner
            errors: self.errors,
            tps_submit: tps,
            p50_ms: self.histogram.value_at_quantile(0.50),
            p95_ms: self.histogram.value_at_quantile(0.95),
            p99_ms: self.histogram.value_at_quantile(0.99),
            max_ms: self.histogram.max(),
        };
        // Reset for next period
        self.histogram.reset();
        self.submitted = 0;
        self.errors = 0;
        self.period_start = Instant::now();
        m
    }
}

// ─── CSV writer ──────────────────────────────────────────────────────────────

fn write_csv_header(w: &mut csv::Writer<std::fs::File>) {
    w.write_record([
        "timestamp",
        "period_secs",
        "submitted",
        "confirmed",
        "errors",
        "tps_submit",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "max_ms",
    ])
    .unwrap();
    w.flush().unwrap();
}

fn write_csv_row(w: &mut csv::Writer<std::fs::File>, m: &PeriodMetrics) {
    w.write_record([
        &m.ts,
        &m.period_secs.to_string(),
        &m.submitted.to_string(),
        &m.confirmed.to_string(),
        &m.errors.to_string(),
        &format!("{:.2}", m.tps_submit),
        &m.p50_ms.to_string(),
        &m.p95_ms.to_string(),
        &m.p99_ms.to_string(),
        &m.max_ms.to_string(),
    ])
    .unwrap();
    w.flush().unwrap();
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> AResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter("shell_load_test=info,warn")
        .init();

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.out_dir)?;

    let run_id = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let csv_path = cli.out_dir.join(format!("load-test-{run_id}.csv"));
    info!("Load test starting — run_id={run_id}");
    info!("RPC: {}", cli.rpc);
    info!(
        "Duration: {}s ({:.1}h)",
        cli.duration,
        cli.duration as f64 / 3600.0
    );
    info!("Workers:  {}", cli.workers);
    info!("Output:   {}", csv_path.display());

    let client = Client::builder()
        .pool_max_idle_per_host(cli.workers + 4)
        .timeout(Duration::from_secs(15))
        .build()?;

    // ── Fund all workers ─────────────────────────────────────────────────────
    let fund_wei = U256::from(cli.fund_shell) * U256::from(10u64).pow(U256::from(18u64));
    let fund_hex = format!("0x{:x}", fund_wei);

    info!("Creating and funding {} worker accounts…", cli.workers);
    let mut workers: Vec<Worker> = Vec::with_capacity(cli.workers);
    for i in 0..cli.workers {
        let w = Worker::new(i, cli.chain_id);
        fund_account(&client, &cli.rpc, &w.pq_address, &fund_hex)
            .await
            .map_err(|e| anyhow::anyhow!("fund worker {i}: {e}"))?;
        if i.is_multiple_of(10) {
            info!("  Funded {}/{}", i + 1, cli.workers);
        }
        workers.push(w);
    }
    info!(
        "All {} accounts funded with {} SHELL each",
        cli.workers, cli.fund_shell
    );

    // Shared metrics collector
    let metrics = Arc::new(Mutex::new(MetricsCollector::new()));
    let total_submitted = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));

    // CSV writer
    let mut csv_writer = csv::Writer::from_path(&csv_path)?;
    write_csv_header(&mut csv_writer);

    // Deadline
    let test_start = Instant::now();
    let deadline = Duration::from_secs(cli.duration);

    // Recipient pool (round-robin among workers)
    let addrs: Vec<Address> = workers.iter().map(|w| w.address).collect();

    // ── Block budget controller ───────────────────────────────────────────────
    // Shared atomic budget: workers atomically decrement before each send.
    // A background task resets the budget every BLOCK_MS with a random tier.
    const BLOCK_MS: u64 = 2000;
    let block_budget = Arc::new(AtomicU64::new(200)); // start with Medium
    {
        let budget = block_budget.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(BLOCK_MS)).await;
                // Generate random tier+budget without holding ThreadRng across await
                let new_budget: u64 = {
                    let mut rng = rand::thread_rng();
                    let tier = pick_load_tier(&mut rng);
                    let b = tier.budget(&mut rng) as u64;
                    if b == 0 {
                        info!("Block budget: 0 ({})", tier.label());
                    }
                    b
                };
                budget.store(new_budget, Ordering::Relaxed);
            }
        });
    }

    // ── Spawn workers ────────────────────────────────────────────────────────
    info!("Starting load ({} workers)…", cli.workers);
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  Shell-chain 10-hour Load Test                       ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!("  Workers : {}", cli.workers);
    println!("  Duration: {}h", cli.duration / 3600);
    println!("  CSV     : {}", csv_path.display());
    println!();

    let mut handles = Vec::with_capacity(cli.workers);
    for mut w in workers {
        let client = client.clone();
        let rpc_url = cli.rpc.clone();
        let metrics = metrics.clone();
        let total_submitted = total_submitted.clone();
        let total_errors = total_errors.clone();
        let addrs = addrs.clone();
        let block_budget = block_budget.clone();

        let handle = tokio::spawn(async move {
            let mut rng_counter: u64 = w.id as u64 * 1_000_000;

            while test_start.elapsed() < deadline {
                // Respect block budget: try to claim a slot
                let slot = block_budget.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |b| {
                    if b > 0 {
                        Some(b - 1)
                    } else {
                        None
                    }
                });
                if slot.is_err() {
                    // Budget exhausted (Zero tier or window full) — wait for next window
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    rng_counter = rng_counter.wrapping_add(1);
                    continue;
                }

                let tx_type = pick_tx_type(rng_counter);
                let recipient_idx = (rng_counter as usize + w.id) % addrs.len();
                let recipient = addrs[recipient_idx];

                let tx = w.build_tx(tx_type, recipient, rng_counter);
                let signed = w.sign(tx);

                let t0 = Instant::now();
                match submit_signed_tx(&client, &rpc_url, &signed).await {
                    Ok(_) => {
                        let lat_ms = t0.elapsed().as_millis() as u64;
                        w.nonce += 1;
                        w.tx_counter += 1;
                        total_submitted.fetch_add(1, Ordering::Relaxed);
                        let mut m = metrics.lock().await;
                        m.record_ok(lat_ms);
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        // Pool full → back off to let the block producer drain it
                        if msg.contains("pool is full") || msg.contains("too many pending") {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        // Nonce too low → re-sync from node
                        else if msg.contains("nonce") || msg.contains("Nonce") {
                            let nc = get_nonce(&client, &rpc_url, &w.pq_address)
                                .await
                                .unwrap_or(w.nonce + 1);
                            w.nonce = nc;
                        }
                        // Any other error: small yield to avoid tight loop
                        else {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        total_errors.fetch_add(1, Ordering::Relaxed);
                        let mut m = metrics.lock().await;
                        m.record_err();

                        if w.tx_counter < 5 {
                            warn!("worker {} early error: {}", w.id, msg);
                        }
                    }
                }
                rng_counter += 1;
            }
        });
        handles.push(handle);
    }

    // ── Metrics reporter loop ─────────────────────────────────────────────────
    let report_interval = cli.report_interval;
    let mut period_end = Instant::now() + Duration::from_secs(report_interval);
    let mut period_num = 1u64;
    let mut grand_submitted = 0u64;
    let mut grand_errors = 0u64;
    let mut peak_tps: f64 = 0.0;

    while test_start.elapsed() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;

        if Instant::now() >= period_end {
            let mut m = metrics.lock().await;
            let pm = m.flush(report_interval);
            drop(m);

            grand_submitted += pm.submitted;
            grand_errors += pm.errors;
            if pm.tps_submit > peak_tps {
                peak_tps = pm.tps_submit;
            }

            let elapsed_total = test_start.elapsed().as_secs();
            let remaining = cli.duration.saturating_sub(elapsed_total);
            let overall_tps = grand_submitted as f64 / elapsed_total.max(1) as f64;

            println!(
                "[{:>5}s / {:>5}s remain] period #{:>4} | \
                 submit={:>6}  err={:>4}  TPS={:>7.1}  \
                 p50={:>4}ms  p95={:>5}ms  p99={:>5}ms",
                elapsed_total,
                remaining,
                period_num,
                pm.submitted,
                pm.errors,
                pm.tps_submit,
                pm.p50_ms,
                pm.p95_ms,
                pm.p99_ms
            );

            if period_num.is_multiple_of(10) {
                println!(
                    "  ↳ cumulative: {} txs, {} errors, {:.1} avg TPS, {:.1} peak TPS",
                    grand_submitted, grand_errors, overall_tps, peak_tps
                );
            }

            write_csv_row(&mut csv_writer, &pm);
            period_end = Instant::now() + Duration::from_secs(report_interval);
            period_num += 1;
        }
    }

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }

    // Final flush
    {
        let mut m = metrics.lock().await;
        let pm = m.flush(report_interval);
        if pm.submitted > 0 {
            grand_submitted += pm.submitted;
            grand_errors += pm.errors;
            write_csv_row(&mut csv_writer, &pm);
        }
    }

    let elapsed_s = test_start.elapsed().as_secs();
    let avg_tps = grand_submitted as f64 / elapsed_s.max(1) as f64;

    println!();
    println!("════════════════════════════════════════════════════════");
    println!("  Load Test Complete");
    println!("════════════════════════════════════════════════════════");
    println!(
        "  Total duration:    {}s ({:.2}h)",
        elapsed_s,
        elapsed_s as f64 / 3600.0
    );
    println!("  Total submitted:   {}", grand_submitted);
    println!("  Total errors:      {}", grand_errors);
    println!(
        "  Error rate:        {:.2}%",
        grand_errors as f64 * 100.0 / grand_submitted.max(1) as f64
    );
    println!("  Average TPS:       {:.1}", avg_tps);
    println!("  Peak TPS (period): {:.1}", peak_tps);
    println!("  CSV output:        {}", csv_path.display());
    println!();

    Ok(())
}
