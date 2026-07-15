//! Shell-Chain testnet transaction generator.
//!
//! Generates random post-quantum-signed transactions and submits them via
//! JSON-RPC to stress-test the RPC layer, mempool, and signature verification
//! pipeline.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, Signer};
use shell_primitives::{Address, Bytes, U256};
use shell_tx_generator::load_dev_authority;

const MAX_RUN_DURATION_SECS: u64 = 365 * 24 * 60 * 60;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "shell-tx-generator",
    about = "Testnet stress-testing transaction generator"
)]
struct Cli {
    /// JSON-RPC endpoint URL.
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Additional JSON-RPC endpoints that should receive the same dev funding.
    #[arg(long = "fund-rpc-url")]
    fund_rpc_urls: Vec<String>,

    /// Path to a dev-authority.json file used for canonical on-chain funding.
    #[arg(long)]
    funding_key_file: Option<PathBuf>,

    /// Number of test accounts to generate.
    #[arg(long = "accounts", default_value_t = 5)]
    num_accounts: usize,

    /// How long to run, in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Minimum delay between transactions (ms).
    #[arg(long, default_value_t = 500)]
    min_interval: u64,

    /// Maximum delay between transactions (ms).
    #[arg(long, default_value_t = 3000)]
    max_interval: u64,

    /// Chain ID.
    #[arg(long, default_value_t = 1337)]
    chain_id: u64,
}

fn validate_cli(cli: &Cli) -> Result<(), String> {
    if cli.num_accounts < 2 {
        return Err("--accounts must be at least 2".into());
    }
    if cli.min_interval > cli.max_interval {
        return Err("--min-interval must not exceed --max-interval".into());
    }
    if cli.duration > MAX_RUN_DURATION_SECS {
        return Err(format!(
            "--duration must not exceed {MAX_RUN_DURATION_SECS} seconds"
        ));
    }
    Ok(())
}

// ── Account ──────────────────────────────────────────────────────────

struct TestAccount {
    signer: DilithiumSigner,
    address: Address,
    pubkey: Vec<u8>,
    nonce: u64,
    pubkey_registered: bool,
    tx_sent: u64,
    tx_ok: u64,
    tx_fail: u64,
}

impl TestAccount {
    fn generate() -> Self {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let address = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        Self {
            signer,
            address,
            pubkey,
            nonce: 0,
            pubkey_registered: false,
            tx_sent: 0,
            tx_ok: 0,
            tx_fail: 0,
        }
    }
}

// ── Transaction types ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxKind {
    SimpleTransfer,
    ContractCreation,
    ContractCall,
    ZeroValue,
    HighGas,
}

impl TxKind {
    const ALL: [TxKind; 5] = [
        TxKind::SimpleTransfer,
        TxKind::ContractCreation,
        TxKind::ContractCall,
        TxKind::ZeroValue,
        TxKind::HighGas,
    ];

    fn pick(rng: &mut impl Rng) -> Self {
        Self::ALL[rng.random_range(0..Self::ALL.len())]
    }

    fn label(self) -> &'static str {
        match self {
            TxKind::SimpleTransfer => "transfer",
            TxKind::ContractCreation => "create",
            TxKind::ContractCall => "call",
            TxKind::ZeroValue => "zero-val",
            TxKind::HighGas => "high-gas",
        }
    }
}

// ── Statistics ───────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    total: u64,
    ok: u64,
    fail: u64,
    latency_sum_ms: u64,
    by_kind: [u64; 5],
}

impl Stats {
    fn record(&mut self, kind: TxKind, success: bool, latency: Duration) {
        self.total += 1;
        if success {
            self.ok += 1;
        } else {
            self.fail += 1;
        }
        self.latency_sum_ms += latency.as_millis() as u64;
        self.by_kind[kind as usize] += 1;
    }
}

// ── JSON-RPC helpers ─────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_send_tx(
    client: &reqwest::Client,
    url: &str,
    signed_tx: &SignedTransaction,
    req_id: u64,
) -> Result<String, String> {
    let tx_json = serde_json::to_value(signed_tx).map_err(|e| format!("serialize: {e}"))?;
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "shell_sendTransaction",
        params: serde_json::json!([tx_json]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if let Some(result) = body.result {
        Ok(result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| result.to_string()))
    } else {
        Err("empty response".into())
    }
}

async fn rpc_set_balance(
    client: &reqwest::Client,
    url: &str,
    address: &Address,
    balance_hex: &str,
    req_id: u64,
) -> Result<bool, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "shell_setBalance",
        params: serde_json::json!([address, balance_hex]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if body
        .result
        .as_ref()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        Ok(true)
    } else {
        Err(format!(
            "unexpected result: {:?}",
            body.result.unwrap_or(serde_json::Value::Null)
        ))
    }
}

async fn rpc_get_transaction_count(
    client: &reqwest::Client,
    url: &str,
    address: &Address,
    req_id: u64,
) -> Result<u64, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: serde_json::json!([address, "latest"]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if let Some(result) = body.result {
        let hex = result
            .as_str()
            .ok_or_else(|| format!("unexpected result: {result:?}"))?;
        let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
        u64::from_str_radix(trimmed, 16).map_err(|e| format!("invalid nonce {hex}: {e}"))
    } else {
        Err("empty response".into())
    }
}

async fn rpc_mine_blocks(
    client: &reqwest::Client,
    url: &str,
    blocks: u64,
    req_id: u64,
) -> Result<(), String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "evm_mine",
        params: serde_json::json!([blocks]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else {
        Ok(())
    }
}

async fn rpc_get_balance(
    client: &reqwest::Client,
    url: &str,
    address: &Address,
    req_id: u64,
) -> Result<U256, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_getBalance",
        params: serde_json::json!([address, "latest"]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if let Some(result) = body.result {
        let hex = result
            .as_str()
            .ok_or_else(|| format!("unexpected result: {result:?}"))?;
        let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
        U256::from_str_radix(trimmed, 16).map_err(|e| format!("invalid balance {hex}: {e}"))
    } else {
        Err("empty response".into())
    }
}

async fn rpc_block_number(client: &reqwest::Client, url: &str, req_id: u64) -> Result<u64, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_blockNumber",
        params: serde_json::json!([]),
        id: req_id,
    };
    let resp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;

    let body: RpcResponse = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if let Some(result) = body.result {
        let hex = result
            .as_str()
            .ok_or_else(|| format!("unexpected result: {result:?}"))?;
        let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
        u64::from_str_radix(trimmed, 16).map_err(|e| format!("invalid block number {hex}: {e}"))
    } else {
        Err("empty response".into())
    }
}

async fn wait_for_cluster_height(
    client: &reqwest::Client,
    urls: &[String],
    target: u64,
    timeout: Duration,
    req_id: &mut u64,
) -> Result<(), Vec<(String, String)>> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut pending = Vec::new();
        for url in urls {
            let id = *req_id;
            *req_id += 1;
            match rpc_block_number(client, url, id).await {
                Ok(height) if height >= target => {}
                Ok(height) => pending.push((
                    url.clone(),
                    format!("height {height} < target barrier {target}"),
                )),
                Err(err) => pending.push((url.clone(), err)),
            }
        }

        if pending.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(pending);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_cluster_balances(
    client: &reqwest::Client,
    urls: &[String],
    accounts: &[Address],
    expected_min_balance: U256,
    timeout: Duration,
    req_id: &mut u64,
) -> Result<(), Vec<(String, String)>> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut pending = Vec::new();
        for url in urls {
            for address in accounts {
                let id = *req_id;
                *req_id += 1;
                match rpc_get_balance(client, url, address, id).await {
                    Ok(balance) if balance >= expected_min_balance => {}
                    Ok(balance) => pending.push((
                        url.clone(),
                        format!(
                            "balance for {address} is {balance}, below required {expected_min_balance}"
                        ),
                    )),
                    Err(err) => pending.push((url.clone(), format!("{address}: {err}"))),
                }
            }
        }

        if pending.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(pending);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ── Transaction builder ──────────────────────────────────────────────

fn sample_fees(base_max_fee: u64, base_priority_fee: u64, rng: &mut impl Rng) -> (u64, u64) {
    let jitter = rng.random_range(0..1_000_000u64);
    (
        base_max_fee.saturating_add(jitter),
        base_priority_fee.saturating_add(jitter),
    )
}

fn build_tx(
    kind: TxKind,
    chain_id: u64,
    nonce: u64,
    recipient: Address,
    rng: &mut impl Rng,
) -> Transaction {
    match kind {
        TxKind::SimpleTransfer => {
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                sample_fees(1_000_000_000, 100_000_000, rng);
            Transaction {
                chain_id,
                nonce,
                to: Some(recipient),
                value: U256::from(rng.random_range(1_000u64..1_000_000)),
                data: Bytes::new(),
                gas_limit: 21_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            }
        }
        TxKind::ContractCreation => {
            // Minimal bytecode: PUSH1 1, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
            let mut bytecode = hex::decode("600160005260206000f3").unwrap();
            bytecode.extend_from_slice(&rng.random::<u64>().to_be_bytes());
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                sample_fees(1_000_000_000, 100_000_000, rng);
            Transaction {
                chain_id,
                nonce,
                to: None,
                value: U256::ZERO,
                data: Bytes::copy_from_slice(&bytecode),
                gas_limit: 100_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            }
        }
        TxKind::ContractCall => {
            // Random 4-byte function selector + 32 bytes of random data
            let mut data = vec![0u8; 36];
            rng.fill(&mut data[..]);
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                sample_fees(1_000_000_000, 100_000_000, rng);
            Transaction {
                chain_id,
                nonce,
                to: Some(recipient),
                value: U256::ZERO,
                data: Bytes::copy_from_slice(&data),
                gas_limit: 50_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            }
        }
        TxKind::ZeroValue => {
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                sample_fees(1_000_000_000, 100_000_000, rng);
            Transaction {
                chain_id,
                nonce,
                to: Some(recipient),
                value: U256::ZERO,
                data: Bytes::new(),
                gas_limit: 21_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            }
        }
        TxKind::HighGas => {
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                sample_fees(5_000_000_000, 500_000_000, rng);
            Transaction {
                chain_id,
                nonce,
                to: Some(recipient),
                value: U256::from(rng.random_range(1u64..1_000)),
                data: Bytes::new(),
                gas_limit: 10_000_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            }
        }
    }
}

fn sign_tx(
    signer: &DilithiumSigner,
    from: Address,
    tx: Transaction,
    pubkey: Option<Vec<u8>>,
) -> SignedTransaction {
    let sig = signer.sign(tx.hash().0.as_slice()).expect("signing failed");
    match pubkey {
        Some(pk) => SignedTransaction::with_pubkey(from, tx, sig, pk),
        None => SignedTransaction::new(from, tx, sig),
    }
}

fn build_funding_tx(chain_id: u64, nonce: u64, recipient: Address, value: U256) -> Transaction {
    Transaction {
        chain_id,
        nonce,
        to: Some(recipient),
        value,
        data: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

// ── ANSI colours ─────────────────────────────────────────────────────

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// ── main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = validate_cli(&cli) {
        eprintln!("{err}");
        std::process::exit(2);
    }

    println!("\n{BOLD}{CYAN}═══ Shell-Chain Transaction Generator ═══{RESET}\n");
    println!("  RPC endpoint : {}", cli.rpc_url);
    println!("  Accounts     : {}", cli.num_accounts);
    println!("  Duration     : {}s", cli.duration);
    println!(
        "  Interval     : {}–{}ms",
        cli.min_interval, cli.max_interval
    );
    println!("  Chain ID     : {}", cli.chain_id);
    println!();

    // ── 1. Generate accounts ────────────────────────────────────────
    println!(
        "{BOLD}▸ Generating {} Dilithium3 keypairs …{RESET}",
        cli.num_accounts
    );
    let mut accounts: Vec<TestAccount> = (0..cli.num_accounts)
        .map(|_| TestAccount::generate())
        .collect();
    for (i, acct) in accounts.iter().enumerate() {
        println!(
            "  {CYAN}[{}]{RESET} {}  (pubkey {}…)",
            i,
            acct.address,
            hex::encode(&acct.pubkey[..8])
        );
    }
    println!();

    // ── 1b. Fund accounts via shell_setBalance ──────────────────────
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let fund_amount = "0x3635c9adc5dea00000"; // 1000 ETH each
    let fund_amount_u256 =
        U256::from_str_radix(fund_amount.trim_start_matches("0x"), 16).expect("valid fund amount");
    let mut cluster_rpc_urls = vec![cli.rpc_url.clone()];
    for url in &cli.fund_rpc_urls {
        if !cluster_rpc_urls.contains(url) {
            cluster_rpc_urls.push(url.clone());
        }
    }
    let mut fund_req_id: u64 = 1000;
    if let Some(path) = &cli.funding_key_file {
        let funder = match load_dev_authority(path) {
            Ok(funder) => funder,
            Err(err) => {
                eprintln!("\n{RED}ERROR: {err}{RESET}");
                std::process::exit(1);
            }
        };
        let funded_addresses = accounts.iter().map(|acct| acct.address).collect::<Vec<_>>();

        println!(
            "{BOLD}▸ Funding accounts via canonical on-chain transfers from {} …{RESET}",
            funder.address
        );
        let mut funding_nonce =
            match rpc_get_transaction_count(&client, &cli.rpc_url, &funder.address, fund_req_id)
                .await
            {
                Ok(nonce) => nonce,
                Err(err) => {
                    eprintln!(
                        "\n{RED}ERROR: failed to read funding nonce for {}: {err}{RESET}",
                        funder.address
                    );
                    std::process::exit(1);
                }
            };
        fund_req_id += 1;

        let mut fund_ok = 0usize;
        for (i, acct) in accounts.iter().enumerate() {
            let tx = build_funding_tx(cli.chain_id, funding_nonce, acct.address, fund_amount_u256);
            let signed = sign_tx(
                &funder.signer,
                funder.address,
                tx,
                Some(funder.pubkey.clone()),
            );
            let id = fund_req_id;
            fund_req_id += 1;
            match rpc_send_tx(&client, &cli.rpc_url, &signed, id).await {
                Ok(hash) => {
                    println!(
                        "  {GREEN}✓{RESET} [{i}] {} funding tx accepted (hash={hash})",
                        acct.address
                    );
                    funding_nonce += 1;
                    fund_ok += 1;
                }
                Err(err) => {
                    println!(
                        "  {RED}✗{RESET} [{i}] {} funding tx rejected: {err}",
                        acct.address
                    );
                }
            }
        }
        if fund_ok != accounts.len() {
            eprintln!(
                "\n{RED}ERROR: on-chain funding failed for {} account(s).{RESET}",
                accounts.len() - fund_ok
            );
            std::process::exit(1);
        }

        println!(
            "  {GREEN}✓{RESET} Submitted {} funding transfer(s); sealing funding blocks",
            fund_ok
        );
        for label in ["funding block", "post-funding barrier block"] {
            match rpc_mine_blocks(&client, &cli.rpc_url, 1, fund_req_id).await {
                Ok(()) => println!("  {GREEN}✓{RESET} {label} mined on primary endpoint"),
                Err(err) => {
                    eprintln!("\n{RED}ERROR: failed to mine {label}: {err}{RESET}");
                    std::process::exit(1);
                }
            }
            fund_req_id += 1;
        }

        let barrier_height = match rpc_block_number(&client, &cli.rpc_url, fund_req_id).await {
            Ok(barrier_height) => barrier_height,
            Err(err) => {
                eprintln!(
                    "\n{RED}ERROR: failed to read funded barrier height from primary: {err}{RESET}"
                );
                std::process::exit(1);
            }
        };
        fund_req_id += 1;

        match wait_for_cluster_height(
            &client,
            &cluster_rpc_urls,
            barrier_height,
            Duration::from_secs(90),
            &mut fund_req_id,
        )
        .await
        {
            Ok(()) => println!(
                "  {GREEN}✓{RESET} cluster synced to funded barrier block #{barrier_height}"
            ),
            Err(pending) => {
                eprintln!(
                    "\n{RED}ERROR: cluster did not catch up to funded barrier block #{barrier_height}.{RESET}"
                );
                for (url, status) in pending {
                    eprintln!("  - {url}: {status}");
                }
                std::process::exit(1);
            }
        }

        match wait_for_cluster_balances(
            &client,
            &cluster_rpc_urls,
            &funded_addresses,
            fund_amount_u256,
            Duration::from_secs(90),
            &mut fund_req_id,
        )
        .await
        {
            Ok(()) => println!(
                "  {GREEN}✓{RESET} funded balances are visible on all {} endpoint(s)",
                cluster_rpc_urls.len()
            ),
            Err(pending) => {
                eprintln!(
                    "\n{RED}ERROR: cluster did not observe canonical funded balances after barrier sync.{RESET}"
                );
                for (url, status) in pending {
                    eprintln!("  - {url}: {status}");
                }
                std::process::exit(1);
            }
        }
    } else if cluster_rpc_urls.len() > 1 {
        eprintln!(
            "\n{RED}ERROR: multi-node funding now requires --funding-key-file so funding can be executed as canonical on-chain transfers.{RESET}"
        );
        eprintln!(
            "  shell_setBalance mutates local node state and cannot safely fund a synced cluster.\n"
        );
        std::process::exit(1);
    } else {
        println!("{BOLD}▸ Funding accounts via shell_setBalance on the primary endpoint …{RESET}");
        let mut fund_ok = 0usize;
        for (i, acct) in accounts.iter().enumerate() {
            let id = fund_req_id;
            fund_req_id += 1;
            if rpc_set_balance(&client, &cli.rpc_url, &acct.address, fund_amount, id)
                .await
                .is_ok()
            {
                println!(
                    "  {GREEN}✓{RESET} [{i}] {} funded with 1000 ETH on primary endpoint",
                    acct.address
                );
                fund_ok += 1;
            } else {
                println!(
                    "  {RED}✗{RESET} [{i}] {} funding failed on the primary endpoint",
                    acct.address
                );
            }
        }
        if fund_ok != accounts.len() {
            eprintln!(
                "\n{RED}ERROR: primary funding failed for {} account(s).{RESET}",
                accounts.len() - fund_ok
            );
            eprintln!(
                "  Make sure shell_setBalance is available and reachable on the primary endpoint.\n"
            );
            std::process::exit(1);
        }
    }
    println!();

    // ── 2. Run loop ─────────────────────────────────────────────────
    let mut stats = Stats::default();
    let mut rng = rand::rng();
    let mut req_id: u64 = 1;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(cli.duration))
        .expect("validated run duration must fit in Instant");
    println!(
        "{BOLD}▸ Sending transactions for {}s …{RESET}\n",
        cli.duration
    );

    while Instant::now() < deadline {
        // Pick random sender / recipient (distinct)
        let sender_idx = rng.random_range(0..accounts.len());
        let mut recip_idx = rng.random_range(0..accounts.len());
        while recip_idx == sender_idx {
            recip_idx = rng.random_range(0..accounts.len());
        }
        let recipient = accounts[recip_idx].address;

        let kind = TxKind::pick(&mut rng);
        let nonce = accounts[sender_idx].nonce;

        let tx = build_tx(kind, cli.chain_id, nonce, recipient, &mut rng);

        // Always include pubkey — node only registers it when tx is included in a block,
        // so subsequent txs before block inclusion would fail without it.
        let pubkey = Some(accounts[sender_idx].pubkey.clone());

        let signed = sign_tx(
            &accounts[sender_idx].signer,
            accounts[sender_idx].address,
            tx,
            pubkey,
        );

        let t0 = Instant::now();
        let result = rpc_send_tx(&client, &cli.rpc_url, &signed, req_id).await;
        let latency = t0.elapsed();

        accounts[sender_idx].tx_sent += 1;
        req_id += 1;

        match &result {
            Ok(hash) => {
                accounts[sender_idx].tx_ok += 1;
                accounts[sender_idx].nonce += 1;
                accounts[sender_idx].pubkey_registered = true;
                stats.record(kind, true, latency);
                println!(
                    "  {GREEN}✓{RESET} #{:<4} {:<8} sender={} hash={} ({:.0}ms)",
                    stats.total,
                    kind.label(),
                    &accounts[sender_idx].address.to_string()[..10],
                    hash,
                    latency.as_secs_f64() * 1000.0,
                );
            }
            Err(e) => {
                accounts[sender_idx].tx_fail += 1;
                stats.record(kind, false, latency);
                println!(
                    "  {RED}✗{RESET} #{:<4} {:<8} sender={} err={} ({:.0}ms)",
                    stats.total,
                    kind.label(),
                    &accounts[sender_idx].address.to_string()[..10],
                    e,
                    latency.as_secs_f64() * 1000.0,
                );
            }
        }

        // Random sleep between txs
        let delay_ms = rng.random_range(cli.min_interval..=cli.max_interval);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    // ── 3. Report ───────────────────────────────────────────────────
    println!("\n{BOLD}{CYAN}═══ Summary ═══{RESET}\n");
    println!("  Total sent   : {}", stats.total);
    println!("  Succeeded    : {GREEN}{}{RESET}", stats.ok);
    println!("  Failed       : {RED}{}{RESET}", stats.fail);
    if stats.total > 0 {
        println!(
            "  Success rate : {:.1}%",
            stats.ok as f64 / stats.total as f64 * 100.0
        );
        println!(
            "  Avg latency  : {:.1}ms",
            stats.latency_sum_ms as f64 / stats.total as f64
        );
    }

    println!("\n  {BOLD}By type:{RESET}");
    for kind in TxKind::ALL {
        let count = stats.by_kind[kind as usize];
        if count > 0 {
            println!("    {:<12} : {}", kind.label(), count);
        }
    }

    println!("\n  {BOLD}Per account:{RESET}");
    for (i, acct) in accounts.iter().enumerate() {
        if acct.tx_sent > 0 {
            println!(
                "    {CYAN}[{}]{RESET} {} — sent:{} ok:{GREEN}{}{RESET} fail:{RED}{}{RESET}",
                i,
                &acct.address.to_string()[..10],
                acct.tx_sent,
                acct.tx_ok,
                acct.tx_fail,
            );
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli() -> Cli {
        Cli {
            rpc_url: "http://localhost:8545".into(),
            fund_rpc_urls: Vec::new(),
            funding_key_file: None,
            num_accounts: 2,
            duration: 60,
            min_interval: 500,
            max_interval: 3_000,
            chain_id: 1_337,
        }
    }

    #[test]
    fn rejects_too_few_accounts_before_generating_keys() {
        let mut cli = cli();
        cli.num_accounts = 1;

        assert_eq!(
            validate_cli(&cli).unwrap_err(),
            "--accounts must be at least 2"
        );
    }

    #[test]
    fn rejects_reversed_interval_range() {
        let mut cli = cli();
        cli.min_interval = 3_001;

        assert_eq!(
            validate_cli(&cli).unwrap_err(),
            "--min-interval must not exceed --max-interval"
        );
    }

    #[test]
    fn rejects_unbounded_duration() {
        let mut cli = cli();
        cli.duration = u64::MAX;

        assert_eq!(
            validate_cli(&cli).unwrap_err(),
            format!("--duration must not exceed {MAX_RUN_DURATION_SECS} seconds")
        );
    }
}
