use std::{
    mem,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Parser, ValueEnum};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::{DilithiumSigner, Signer};
use shell_evm::{account_manager_address, encode_rotate_key_calldata};
use shell_primitives::{Address, Bytes, U256};
use shell_tx_generator::load_dev_authority;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Mixed,
    Attack,
}

#[derive(Parser, Debug)]
#[command(
    name = "shell-aa-injector",
    about = "Exercises native AA usage and attack scenarios against a running Shell-Chain testnet"
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

    /// Scenario mode.
    #[arg(long, value_enum, default_value_t = Mode::Attack)]
    mode: Mode,

    /// How long to run, in seconds.
    #[arg(long, default_value_t = 3600)]
    duration: u64,

    /// Chain ID.
    #[arg(long, default_value_t = 1337)]
    chain_id: u64,

    /// Delay between scenario cycles (ms).
    #[arg(long, default_value_t = 1500)]
    interval_ms: u64,

    /// How many duplicate submissions to attempt after the first valid send.
    #[arg(long, default_value_t = 3)]
    duplicate_attempts: u32,

    /// Funding amount used with `shell_setBalance`.
    #[arg(long, default_value = "0x3635c9adc5dea00000")]
    fund_amount: String,
}

struct ScenarioAccount {
    signer: DilithiumSigner,
    address: Address,
    pubkey: Vec<u8>,
    nonce: u64,
    needs_pubkey: bool,
}

impl ScenarioAccount {
    fn generate() -> Self {
        let signer = DilithiumSigner::generate();
        let pubkey = signer.public_key().to_vec();
        let address = Address::from_public_key(&pubkey, signer.sig_type().as_u8());
        Self {
            signer,
            address,
            pubkey,
            nonce: 0,
            needs_pubkey: true,
        }
    }

    fn sign_tx(&self, tx: Transaction, include_pubkey: bool) -> SignedTransaction {
        let sig = self
            .signer
            .sign(tx.hash().0.as_slice())
            .expect("signing failed");
        if include_pubkey {
            SignedTransaction::with_pubkey(self.address, tx, sig, self.pubkey.clone())
        } else {
            SignedTransaction::new(self.address, tx, sig)
        }
    }

    fn note_success(&mut self, included_pubkey: bool) {
        self.nonce += 1;
        if included_pubkey {
            self.needs_pubkey = false;
        }
    }
}

#[derive(Default)]
struct Stats {
    valid_ok: u64,
    valid_fail: u64,
    rotations_ok: u64,
    rotations_fail: u64,
    post_rotation_ok: u64,
    post_rotation_fail: u64,
    invalid_sig_rejected: u64,
    invalid_sig_unexpected_ok: u64,
    old_key_rejected: u64,
    old_key_unexpected_ok: u64,
    nonce_gap_rejected: u64,
    nonce_gap_unexpected_ok: u64,
    duplicate_first_ok: u64,
    duplicate_first_fail: u64,
    duplicate_rejected: u64,
    duplicate_unexpected_ok: u64,
    malformed_addr_rejected: u64,
    malformed_addr_unexpected_ok: u64,
}

impl Stats {
    fn has_failures(&self, mode: Mode) -> bool {
        self.valid_fail > 0
            || self.rotations_fail > 0
            || self.post_rotation_fail > 0
            || (matches!(mode, Mode::Attack)
                && (self.invalid_sig_unexpected_ok > 0
                    || self.old_key_unexpected_ok > 0
                    || self.nonce_gap_unexpected_ok > 0
                    || self.duplicate_first_fail > 0
                    || self.duplicate_unexpected_ok > 0
                    || self.malformed_addr_unexpected_ok > 0))
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_post(client: &Client, url: &str, req: &RpcRequest<'_>) -> Result<RpcResponse, String> {
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .map_err(|e| format!("http: {e}"))?;
    resp.json::<RpcResponse>()
        .await
        .map_err(|e| format!("decode: {e}"))
}

async fn rpc_send_tx(
    client: &Client,
    url: &str,
    signed_tx: &SignedTransaction,
    req_id: u64,
) -> Result<String, String> {
    let tx_json = serde_json::to_value(signed_tx).map_err(|e| format!("serialize: {e}"))?;
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "shell_sendTransaction",
        params: json!([tx_json]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if let Some(result) = body.result {
        Ok(result
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| result.to_string()))
    } else {
        Err("empty response".into())
    }
}

async fn rpc_set_balance(
    client: &Client,
    url: &str,
    address: &Address,
    balance_hex: &str,
    req_id: u64,
) -> Result<(), String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "shell_setBalance",
        params: json!([address, balance_hex]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else if body
        .result
        .as_ref()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(format!(
            "unexpected result: {:?}",
            body.result.unwrap_or(serde_json::Value::Null)
        ))
    }
}

async fn rpc_get_transaction_count(
    client: &Client,
    url: &str,
    address: &Address,
    req_id: u64,
) -> Result<u64, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: json!([address, "latest"]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
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
    client: &Client,
    url: &str,
    blocks: u64,
    req_id: u64,
) -> Result<(), String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "evm_mine",
        params: json!([blocks]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
    if let Some(err) = body.error {
        Err(format!("[{}] {}", err.code, err.message))
    } else {
        Ok(())
    }
}

async fn rpc_get_balance(
    client: &Client,
    url: &str,
    address: &Address,
    req_id: u64,
) -> Result<U256, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_getBalance",
        params: json!([address, "latest"]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
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

async fn rpc_block_number(client: &Client, url: &str, req_id: u64) -> Result<u64, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_blockNumber",
        params: json!([]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
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

async fn wait_for_cluster_balances(
    client: &Client,
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

async fn wait_for_cluster_height(
    client: &Client,
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

async fn wait_for_registered_pubkey(
    client: &Client,
    url: &str,
    address: &Address,
    expected_pubkey: &[u8],
    req_id: &mut u64,
    timeout: Duration,
) -> Result<(), String> {
    let expected_hex = format!("0x{}", hex::encode(expected_pubkey));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let req = RpcRequest {
            jsonrpc: "2.0",
            method: "shell_getPqPubkey",
            params: json!([address]),
            id: *req_id,
        };
        *req_id += 1;

        let body = rpc_post(client, url, &req).await?;
        if let Some(err) = body.error {
            return Err(format!(
                "pubkey lookup for {address} failed: [{}] {}",
                err.code, err.message
            ));
        }

        if let Some(result) = body.result {
            if let Some(pubkey_hex) = result.as_str() {
                if pubkey_hex.eq_ignore_ascii_case(&expected_hex) {
                    return Ok(());
                }
            } else if !result.is_null() {
                return Err(format!(
                    "unexpected shell_getPqPubkey result for {address}: {result}"
                ));
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(format!(
        "timed out waiting for pubkey registration for {address}"
    ))
}

async fn malformed_balance_probe(client: &Client, url: &str, req_id: u64) -> Result<bool, String> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "eth_getBalance",
        params: json!(["0xdefinitelynotavalidaddress", "latest"]),
        id: req_id,
    };
    let body = rpc_post(client, url, &req).await?;
    Ok(body.error.is_some())
}

fn build_transfer_tx(chain_id: u64, nonce: u64, recipient: Address, value: u64) -> Transaction {
    Transaction {
        chain_id,
        nonce,
        to: Some(recipient),
        value: U256::from(value),
        data: Bytes::new(),
        gas_limit: 21_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

fn build_system_tx(chain_id: u64, nonce: u64, data: Vec<u8>) -> Transaction {
    Transaction {
        chain_id,
        nonce,
        to: Some(account_manager_address()),
        value: U256::ZERO,
        data: Bytes::from(data),
        gas_limit: 100_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 100_000_000,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

async fn send_valid_transfer(
    client: &Client,
    cli: &Cli,
    primary: &mut ScenarioAccount,
    recipient: Address,
    req_id: &mut u64,
) -> Result<(), String> {
    let include_pubkey = primary.needs_pubkey;
    let tx = build_transfer_tx(cli.chain_id, primary.nonce, recipient, 1_000);
    let signed = primary.sign_tx(tx, include_pubkey);
    rpc_send_tx(client, &cli.rpc_url, &signed, *req_id).await?;
    *req_id += 1;
    if include_pubkey {
        wait_for_registered_pubkey(
            client,
            &cli.rpc_url,
            &primary.address,
            &primary.pubkey,
            req_id,
            Duration::from_secs(30),
        )
        .await?;
    }
    primary.note_success(include_pubkey);
    Ok(())
}

async fn rotate_key(
    client: &Client,
    cli: &Cli,
    primary: &mut ScenarioAccount,
    req_id: &mut u64,
) -> Result<(DilithiumSigner, Vec<u8>), String> {
    let new_signer = DilithiumSigner::generate();
    let new_pubkey = new_signer.public_key().to_vec();
    let calldata = encode_rotate_key_calldata(&new_pubkey, new_signer.sig_type().as_u8());
    let tx = build_system_tx(cli.chain_id, primary.nonce, calldata);
    let signed = primary.sign_tx(tx, true);
    rpc_send_tx(client, &cli.rpc_url, &signed, *req_id).await?;
    *req_id += 1;
    wait_for_registered_pubkey(
        client,
        &cli.rpc_url,
        &primary.address,
        &new_pubkey,
        req_id,
        Duration::from_secs(30),
    )
    .await?;

    let old_signer = mem::replace(&mut primary.signer, new_signer);
    let old_pubkey = mem::replace(&mut primary.pubkey, new_pubkey);
    primary.nonce += 1;
    primary.needs_pubkey = true;
    Ok((old_signer, old_pubkey))
}

async fn setup_account(
    client: &Client,
    cli: &Cli,
    primary: &mut ScenarioAccount,
    recipient: Address,
    req_id: &mut u64,
    stats: &mut Stats,
) -> Option<(DilithiumSigner, Vec<u8>)> {
    println!("bootstrap valid transfer from {}", primary.address);
    match send_valid_transfer(client, cli, primary, recipient, req_id).await {
        Ok(()) => stats.valid_ok += 1,
        Err(err) => {
            stats.valid_fail += 1;
            eprintln!("bootstrap transfer failed: {err}");
            return None;
        }
    }

    println!("steady-state valid transfer without sender_pubkey");
    match send_valid_transfer(client, cli, primary, recipient, req_id).await {
        Ok(()) => stats.valid_ok += 1,
        Err(err) => {
            stats.valid_fail += 1;
            eprintln!("steady-state transfer failed: {err}");
            return None;
        }
    }

    println!("rotating key for {}", primary.address);
    let old_key = match rotate_key(client, cli, primary, req_id).await {
        Ok(pair) => {
            stats.rotations_ok += 1;
            pair
        }
        Err(err) => {
            stats.rotations_fail += 1;
            eprintln!("rotateKey failed: {err}");
            return None;
        }
    };

    println!("post-rotation valid transfer with new sender_pubkey");
    match send_valid_transfer(client, cli, primary, recipient, req_id).await {
        Ok(()) => stats.post_rotation_ok += 1,
        Err(err) => {
            stats.post_rotation_fail += 1;
            eprintln!("post-rotation transfer failed: {err}");
            return None;
        }
    }

    Some(old_key)
}

async fn run_mixed_mode(
    client: &Client,
    cli: &Cli,
    primary: &mut ScenarioAccount,
    recipient: Address,
    req_id: &mut u64,
    stats: &mut Stats,
) {
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let mut cycle = 0u64;

    while Instant::now() < deadline {
        if cycle > 0 && cycle.is_multiple_of(5) {
            match rotate_key(client, cli, primary, req_id).await {
                Ok(_) => stats.rotations_ok += 1,
                Err(err) => {
                    stats.rotations_fail += 1;
                    eprintln!("mixed rotateKey failed: {err}");
                }
            }
        } else {
            let expected_post_rotation = primary.needs_pubkey;
            match send_valid_transfer(client, cli, primary, recipient, req_id).await {
                Ok(()) => {
                    if expected_post_rotation {
                        stats.post_rotation_ok += 1;
                    } else {
                        stats.valid_ok += 1;
                    }
                }
                Err(err) => {
                    stats.valid_fail += 1;
                    eprintln!("mixed valid transfer failed: {err}");
                }
            }
        }

        cycle += 1;
        tokio::time::sleep(Duration::from_millis(cli.interval_ms)).await;
    }
}

async fn run_attack_mode(
    client: &Client,
    cli: &Cli,
    primary: &mut ScenarioAccount,
    recipient: Address,
    old_key: &(DilithiumSigner, Vec<u8>),
    req_id: &mut u64,
    stats: &mut Stats,
) {
    let deadline = Instant::now() + Duration::from_secs(cli.duration);

    while Instant::now() < deadline {
        let invalid_tx = build_transfer_tx(cli.chain_id, primary.nonce, recipient, 1_111);
        let mut invalid_signed = primary.sign_tx(invalid_tx, primary.needs_pubkey);
        if let Some(first) = invalid_signed.signature.data.first_mut() {
            *first ^= 0x01;
        }
        match rpc_send_tx(client, &cli.rpc_url, &invalid_signed, *req_id).await {
            Ok(hash) => {
                stats.invalid_sig_unexpected_ok += 1;
                eprintln!("unexpected accept for invalid signature tx: {hash}");
            }
            Err(_) => stats.invalid_sig_rejected += 1,
        }
        *req_id += 1;

        let old_key_tx = build_transfer_tx(cli.chain_id, primary.nonce, recipient, 1_222);
        let old_sig = old_key
            .0
            .sign(old_key_tx.hash().0.as_slice())
            .expect("old signer failed");
        let old_signed =
            SignedTransaction::with_pubkey(primary.address, old_key_tx, old_sig, old_key.1.clone());
        match rpc_send_tx(client, &cli.rpc_url, &old_signed, *req_id).await {
            Ok(hash) => {
                stats.old_key_unexpected_ok += 1;
                eprintln!("unexpected accept for old-key tx: {hash}");
            }
            Err(_) => stats.old_key_rejected += 1,
        }
        *req_id += 1;

        let nonce_gap_tx = build_transfer_tx(cli.chain_id, primary.nonce + 3, recipient, 1_333);
        let nonce_gap_signed = primary.sign_tx(nonce_gap_tx, primary.needs_pubkey);
        match rpc_send_tx(client, &cli.rpc_url, &nonce_gap_signed, *req_id).await {
            Ok(hash) => {
                stats.nonce_gap_unexpected_ok += 1;
                eprintln!("unexpected accept for nonce-gap tx: {hash}");
            }
            Err(_) => stats.nonce_gap_rejected += 1,
        }
        *req_id += 1;

        match malformed_balance_probe(client, &cli.rpc_url, *req_id).await {
            Ok(true) => stats.malformed_addr_rejected += 1,
            Ok(false) => {
                stats.malformed_addr_unexpected_ok += 1;
                eprintln!("unexpected success for malformed address probe");
            }
            Err(err) => {
                stats.malformed_addr_rejected += 1;
                eprintln!("malformed address probe returned transport error (acceptable): {err}");
            }
        }
        *req_id += 1;

        let duplicate_tx = build_transfer_tx(cli.chain_id, primary.nonce, recipient, 1_444);
        let include_pubkey = primary.needs_pubkey;
        let duplicate_signed = primary.sign_tx(duplicate_tx, include_pubkey);
        match rpc_send_tx(client, &cli.rpc_url, &duplicate_signed, *req_id).await {
            Ok(_) => {
                stats.duplicate_first_ok += 1;
                primary.note_success(include_pubkey);
            }
            Err(err) => {
                stats.duplicate_first_fail += 1;
                eprintln!("first duplicate-seed tx failed: {err}");
            }
        }
        *req_id += 1;

        for _ in 0..cli.duplicate_attempts {
            match rpc_send_tx(client, &cli.rpc_url, &duplicate_signed, *req_id).await {
                Ok(hash) => {
                    stats.duplicate_unexpected_ok += 1;
                    eprintln!("unexpected duplicate accept: {hash}");
                }
                Err(_) => stats.duplicate_rejected += 1,
            }
            *req_id += 1;
        }

        tokio::time::sleep(Duration::from_millis(cli.interval_ms)).await;
    }
}

fn print_summary(mode: Mode, stats: &Stats) {
    println!("\n=== shell-aa-injector summary ===");
    println!("SUMMARY mode={:?}", mode);
    println!("SUMMARY valid_ok={}", stats.valid_ok);
    println!("SUMMARY valid_fail={}", stats.valid_fail);
    println!("SUMMARY rotations_ok={}", stats.rotations_ok);
    println!("SUMMARY rotations_fail={}", stats.rotations_fail);
    println!("SUMMARY post_rotation_ok={}", stats.post_rotation_ok);
    println!("SUMMARY post_rotation_fail={}", stats.post_rotation_fail);
    println!(
        "SUMMARY invalid_sig_rejected={}",
        stats.invalid_sig_rejected
    );
    println!(
        "SUMMARY invalid_sig_unexpected_ok={}",
        stats.invalid_sig_unexpected_ok
    );
    println!("SUMMARY old_key_rejected={}", stats.old_key_rejected);
    println!(
        "SUMMARY old_key_unexpected_ok={}",
        stats.old_key_unexpected_ok
    );
    println!("SUMMARY nonce_gap_rejected={}", stats.nonce_gap_rejected);
    println!(
        "SUMMARY nonce_gap_unexpected_ok={}",
        stats.nonce_gap_unexpected_ok
    );
    println!("SUMMARY duplicate_first_ok={}", stats.duplicate_first_ok);
    println!(
        "SUMMARY duplicate_first_fail={}",
        stats.duplicate_first_fail
    );
    println!("SUMMARY duplicate_rejected={}", stats.duplicate_rejected);
    println!(
        "SUMMARY duplicate_unexpected_ok={}",
        stats.duplicate_unexpected_ok
    );
    println!(
        "SUMMARY malformed_addr_rejected={}",
        stats.malformed_addr_rejected
    );
    println!(
        "SUMMARY malformed_addr_unexpected_ok={}",
        stats.malformed_addr_unexpected_ok
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let mut primary = ScenarioAccount::generate();
    let recipient = ScenarioAccount::generate();
    let observer = ScenarioAccount::generate();
    let mut req_id = 1u64;
    let mut stats = Stats::default();

    println!("mode={:?}", cli.mode);
    println!("rpc_url={}", cli.rpc_url);
    println!("duration={}s", cli.duration);
    println!("primary={}", primary.address);
    println!("recipient={}", recipient.address);
    println!("observer={}", observer.address);

    let mut cluster_rpc_urls = vec![cli.rpc_url.clone()];
    for url in &cli.fund_rpc_urls {
        if !cluster_rpc_urls.contains(url) {
            cluster_rpc_urls.push(url.clone());
        }
    }

    let scenario_addresses = [primary.address, recipient.address, observer.address];
    let fund_amount_u256 = match U256::from_str_radix(cli.fund_amount.trim_start_matches("0x"), 16)
    {
        Ok(value) => value,
        Err(err) => {
            eprintln!("invalid --fund-amount {}: {err}", cli.fund_amount);
            std::process::exit(1);
        }
    };

    if let Some(path) = &cli.funding_key_file {
        let funder = match load_dev_authority(path) {
            Ok(funder) => funder,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        };
        println!(
            "funding scenario accounts via canonical on-chain transfers from {}",
            funder.address
        );
        let mut funding_nonce =
            match rpc_get_transaction_count(&client, &cli.rpc_url, &funder.address, req_id).await {
                Ok(nonce) => nonce,
                Err(err) => {
                    eprintln!("failed to read funding nonce for {}: {err}", funder.address);
                    std::process::exit(1);
                }
            };
        req_id += 1;

        for addr in scenario_addresses {
            let tx = build_funding_tx(cli.chain_id, funding_nonce, addr, fund_amount_u256);
            let sig = funder
                .signer
                .sign(tx.hash().0.as_slice())
                .expect("signing failed");
            let signed =
                SignedTransaction::with_pubkey(funder.address, tx, sig, funder.pubkey.clone());
            let id = req_id;
            req_id += 1;
            match rpc_send_tx(&client, &cli.rpc_url, &signed, id).await {
                Ok(hash) => {
                    println!("funding tx accepted for {addr} (hash={hash})");
                    funding_nonce += 1;
                }
                Err(err) => {
                    eprintln!("failed to fund {addr} via on-chain transfer: {err}");
                    std::process::exit(1);
                }
            }
        }

        for label in ["funding block", "post-funding barrier block"] {
            match rpc_mine_blocks(&client, &cli.rpc_url, 1, req_id).await {
                Ok(()) => println!("{label} mined on primary endpoint"),
                Err(err) => {
                    eprintln!("failed to mine {label}: {err}");
                    std::process::exit(1);
                }
            }
            req_id += 1;
        }

        let barrier_height = match rpc_block_number(&client, &cli.rpc_url, req_id).await {
            Ok(height) => height,
            Err(err) => {
                eprintln!("failed to read funded barrier height from primary: {err}");
                std::process::exit(1);
            }
        };
        req_id += 1;
        if let Err(pending) = wait_for_cluster_height(
            &client,
            &cluster_rpc_urls,
            barrier_height,
            Duration::from_secs(90),
            &mut req_id,
        )
        .await
        {
            eprintln!("cluster did not catch up to funded barrier block #{barrier_height}");
            for (url, status) in pending {
                eprintln!("  - {url}: {status}");
            }
            std::process::exit(1);
        }
        if let Err(pending) = wait_for_cluster_balances(
            &client,
            &cluster_rpc_urls,
            &scenario_addresses,
            fund_amount_u256,
            Duration::from_secs(90),
            &mut req_id,
        )
        .await
        {
            eprintln!("cluster did not observe canonical funded balances after barrier sync");
            for (url, status) in pending {
                eprintln!("  - {url}: {status}");
            }
            std::process::exit(1);
        }
        println!("cluster synced to funded barrier block #{barrier_height}");
    } else if cluster_rpc_urls.len() > 1 {
        eprintln!(
            "multi-node AA funding now requires --funding-key-file so funding can be executed as canonical on-chain transfers"
        );
        std::process::exit(1);
    } else {
        match rpc_mine_blocks(&client, &cli.rpc_url, 1, req_id).await {
            Ok(()) => println!("barrier block mined on primary endpoint before funding"),
            Err(err) => eprintln!("warning: pre-funding barrier block skipped: {err}"),
        }
        req_id += 1;

        for addr in scenario_addresses {
            let id = req_id;
            req_id += 1;
            if let Err(err) =
                rpc_set_balance(&client, &cli.rpc_url, &addr, &cli.fund_amount, id).await
            {
                eprintln!("failed to fund {addr} on primary endpoint: {err}");
                std::process::exit(1);
            }
            println!(
                "funded {} with {} on primary endpoint",
                addr, cli.fund_amount
            );
        }

        match rpc_mine_blocks(&client, &cli.rpc_url, 1, req_id).await {
            Ok(()) => {
                println!("funded state sealed with a barrier block");
                req_id += 1;
                let barrier_height = match rpc_block_number(&client, &cli.rpc_url, req_id).await {
                    Ok(height) => height,
                    Err(err) => {
                        eprintln!("failed to read funded barrier height from primary: {err}");
                        std::process::exit(1);
                    }
                };
                req_id += 1;
                if let Err(pending) = wait_for_cluster_height(
                    &client,
                    &cluster_rpc_urls,
                    barrier_height,
                    Duration::from_secs(90),
                    &mut req_id,
                )
                .await
                {
                    eprintln!("cluster did not catch up to funded barrier block #{barrier_height}");
                    for (url, status) in pending {
                        eprintln!("  - {url}: {status}");
                    }
                    std::process::exit(1);
                }
                println!("cluster synced to funded barrier block #{barrier_height}");
            }
            Err(err) => {
                eprintln!("funded-state barrier failed: {err}");
                std::process::exit(1);
            }
        }
    }

    let old_key = match setup_account(
        &client,
        &cli,
        &mut primary,
        recipient.address,
        &mut req_id,
        &mut stats,
    )
    .await
    {
        Some(pair) => pair,
        None => {
            print_summary(cli.mode, &stats);
            std::process::exit(1);
        }
    };

    match cli.mode {
        Mode::Mixed => {
            run_mixed_mode(
                &client,
                &cli,
                &mut primary,
                observer.address,
                &mut req_id,
                &mut stats,
            )
            .await;
        }
        Mode::Attack => {
            run_attack_mode(
                &client,
                &cli,
                &mut primary,
                observer.address,
                &old_key,
                &mut req_id,
                &mut stats,
            )
            .await;
        }
    }

    print_summary(cli.mode, &stats);
    if stats.has_failures(cli.mode) {
        std::process::exit(1);
    }
}
