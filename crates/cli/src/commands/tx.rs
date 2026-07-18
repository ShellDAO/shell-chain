//! `shell-node tx` — transaction subcommands.
//!
//! Sends transactions and makes read-only calls to a running shell-node
//! via JSON-RPC.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use shell_core::{SignedTransaction, Transaction};
use shell_crypto::Signer;
use shell_keystore::{decrypt_any, EncryptedKey};
use shell_primitives::{Address, Bytes, U256};

use crate::password::{resolve_password, PasswordArgs};
use crate::secure_file::read_sensitive_file;

#[derive(Subcommand)]
pub enum TxCommand {
    /// Send a value transfer transaction.
    Send {
        /// Recipient address (`0x` + 64 lowercase hex).
        #[arg(long)]
        to: String,

        /// Value to transfer (decimal wei).
        #[arg(long)]
        value: String,

        /// Path to the encrypted keystore file.
        #[arg(long)]
        keystore: PathBuf,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,

        /// Chain ID (queried from node if omitted).
        #[arg(long)]
        chain_id: Option<u64>,

        /// Nonce override (queried from node if omitted).
        #[arg(long)]
        nonce: Option<u64>,

        /// Gas limit override (estimated if omitted).
        #[arg(long)]
        gas_limit: Option<u64>,
    },

    /// Deploy a contract (send a transaction with no `to` address).
    Deploy {
        /// Contract init bytecode (0x-prefixed hex).
        #[arg(long)]
        code: String,

        /// Path to the encrypted keystore file.
        #[arg(long)]
        keystore: PathBuf,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,

        /// Chain ID (queried from node if omitted).
        #[arg(long)]
        chain_id: Option<u64>,

        /// Value to send with deployment (decimal wei).
        #[arg(long)]
        value: Option<String>,
    },

    /// Make a read-only call (eth_call).
    Call {
        /// Contract address (`0x` + 64 lowercase hex).
        #[arg(long)]
        to: String,

        /// Calldata (0x-prefixed hex).
        #[arg(long)]
        data: Option<String>,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },
}

/// Execute a transaction subcommand.
pub fn execute(
    cmd: TxCommand,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        TxCommand::Send {
            to,
            value,
            keystore,
            rpc_url,
            chain_id,
            nonce,
            gas_limit,
        } => cmd_send(
            SendArgs {
                to,
                value,
                keystore,
                rpc_url,
                chain_id,
                nonce,
                gas_limit,
            },
            &password_args,
        ),
        TxCommand::Deploy {
            code,
            keystore,
            rpc_url,
            chain_id,
            value,
        } => cmd_deploy(code, keystore, rpc_url, chain_id, value, &password_args),
        TxCommand::Call { to, data, rpc_url } => cmd_call(to, data, rpc_url),
    }
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

struct SendArgs {
    to: String,
    value: String,
    keystore: PathBuf,
    rpc_url: String,
    chain_id: Option<u64>,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
}

fn cmd_send(
    args: SendArgs,
    password_args: &PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let SendArgs {
        to,
        value,
        keystore,
        rpc_url,
        chain_id,
        nonce,
        gas_limit,
    } = args;

    let signer = load_keystore(&keystore, password_args)?;
    let from = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let to_addr = parse_address(&to)?;

    let chain_id = match chain_id {
        Some(id) => id,
        None => rpc_chain_id(&rpc_url)?,
    };
    let nonce = match nonce {
        Some(n) => n,
        None => rpc_get_nonce(&rpc_url, &from)?,
    };
    let gas_price = rpc_gas_price(&rpc_url)?;

    let value_u256 = parse_u256(&value)?;

    let tx = Transaction {
        chain_id,
        nonce,
        to: Some(to_addr),
        value: value_u256,
        data: Bytes::default(),
        gas_limit: gas_limit.unwrap_or(21_000),
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: 0,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let gas_limit_final = match gas_limit {
        Some(g) => g,
        None => rpc_estimate_gas(&rpc_url, &from, Some(&to_addr), &value_u256, &[])?,
    };

    let tx = Transaction {
        gas_limit: gas_limit_final,
        ..tx
    };

    let signed = sign_and_build(from, tx, &*signer, &rpc_url)?;
    let tx_hash = submit_tx(&rpc_url, &signed)?;
    eprintln!("✓ Transaction submitted");
    println!("{tx_hash}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

fn cmd_deploy(
    code: String,
    keystore: PathBuf,
    rpc_url: String,
    chain_id: Option<u64>,
    value: Option<String>,
    password_args: &PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = load_keystore(&keystore, password_args)?;
    let from = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    let chain_id = match chain_id {
        Some(id) => id,
        None => rpc_chain_id(&rpc_url)?,
    };
    let nonce = rpc_get_nonce(&rpc_url, &from)?;
    let gas_price = rpc_gas_price(&rpc_url)?;

    let code_bytes = parse_hex_bytes(&code)?;
    let value_u256 = match &value {
        Some(v) => parse_u256(v)?,
        None => U256::ZERO,
    };

    let estimated_gas = rpc_estimate_gas(&rpc_url, &from, None, &value_u256, &code_bytes)?;

    let tx = Transaction {
        chain_id,
        nonce,
        to: None,
        value: value_u256,
        data: Bytes::from(code_bytes),
        gas_limit: estimated_gas,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: 0,
        access_list: None,
        tx_type: 2,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    };

    let signed = sign_and_build(from, tx, &*signer, &rpc_url)?;
    let tx_hash = submit_tx(&rpc_url, &signed)?;
    eprintln!("✓ Contract deployment submitted");
    println!("{tx_hash}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Call (read-only)
// ---------------------------------------------------------------------------

fn cmd_call(
    to: String,
    data: Option<String>,
    rpc_url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let to_addr = parse_address(&to)?;
    let data_hex = match &data {
        Some(d) => d.clone(),
        None => "0x".to_string(),
    };

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": format!("{to_addr}"),
            "data": data_hex,
        }, "latest"],
        "id": 1
    });

    let result = rpc_post(&rpc_url, &body)?;
    if let Some(err) = result.get("error") {
        return Err(format!("RPC error: {err}").into());
    }
    let result_str = result["result"]
        .as_str()
        .ok_or("unexpected eth_call response")?;
    println!("{result_str}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a keystore file and decrypt the signer.
fn load_keystore(
    path: &Path,
    password_args: &PasswordArgs,
) -> Result<Box<dyn Signer>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("keystore file not found: {}", path.display()).into());
    }
    let json = read_sensitive_file(path)?;
    let encrypted: EncryptedKey = serde_json::from_str(&json)?;

    let password = resolve_password("Enter keystore password: ", password_args)?;
    let signer = decrypt_any(&encrypted, password.as_bytes());
    // Zeroize password from memory immediately after use.
    let mut pw_bytes = password.into_bytes();
    pw_bytes.fill(0);
    drop(pw_bytes);
    let signer = signer?;

    Ok(signer)
}

/// Parse a user-facing address string. Only `0x` + 64 hex is accepted.
fn parse_address(s: &str) -> Result<Address, Box<dyn std::error::Error>> {
    Address::parse(s).map_err(|e| format!("invalid address '{s}': {e}").into())
}

/// Parse a decimal or hex string into U256.
fn parse_u256(s: &str) -> Result<U256, Box<dyn std::error::Error>> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        // Hex input
        if hex_str.len() > 64 {
            return Err("hex value too large for U256".into());
        }
        let padded = format!("{:0>64}", hex_str);
        let bytes = hex::decode(&padded)?;
        Ok(U256::from_be_slice(&bytes))
    } else {
        // Decimal input
        let val =
            U256::from_str_radix(s, 10).map_err(|e| format!("invalid decimal value '{s}': {e}"))?;
        Ok(val)
    }
}

/// Parse a 0x-prefixed hex string into bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

/// Sign and build a [`SignedTransaction`].
///
/// Checks the on-chain pubkey registry via `rpc_url`: if the sender's pubkey
/// is already registered, uses [`shell_core::PubkeyMode::Reference`] (saves ~1,952 bytes).
/// On the first transaction from a new address, uses [`shell_core::PubkeyMode::Embedded`].
fn sign_and_build(
    from: Address,
    tx: Transaction,
    signer: &dyn Signer,
    rpc_url: &str,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let tx_hash = tx.signing_hash(signer.sig_type().as_u8());
    let sig = signer.sign(tx_hash.as_bytes())?;

    let pubkey_registered = rpc_is_pubkey_registered(rpc_url, &from).unwrap_or(false);
    let signed = if pubkey_registered {
        SignedTransaction::new(from, tx, sig)
    } else {
        SignedTransaction::with_pubkey(from, tx, sig, signer.public_key().to_vec())
    };
    Ok(signed)
}

/// Returns `true` if the sender's pubkey is already registered on-chain.
///
/// Calls `shell_getPqPubkey`. On any error (network, node not running), returns
/// `false` so the caller falls back to `Embedded` mode (safe default).
fn rpc_is_pubkey_registered(
    rpc_url: &str,
    addr: &Address,
) -> Result<bool, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "shell_getPqPubkey",
        "params": [addr.to_string()],
        "id": 1
    });
    let result = rpc_post(rpc_url, &body)?;
    // result is Some(hex_pubkey_string) if registered, null if not
    Ok(!result["result"].is_null())
}

/// RLP-encode and hex-encode a signed transaction, then submit via RPC.
fn submit_tx(
    rpc_url: &str,
    signed: &SignedTransaction,
) -> Result<String, Box<dyn std::error::Error>> {
    let encoded = alloy_rlp::encode(signed);
    let hex_data = format!("0x{}", hex::encode(&encoded));

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [hex_data],
        "id": 1
    });

    let result = rpc_post(rpc_url, &body)?;
    let tx_hash = rpc_result_str(&result, "eth_sendRawTransaction")?;
    Ok(tx_hash.to_string())
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

fn rpc_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let resp = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())?;
    let json: serde_json::Value = resp.into_json()?;
    Ok(json)
}

fn rpc_chain_id(url: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_chainId",
        "params": [],
        "id": 1
    });
    let result = rpc_post(url, &body)?;
    let hex_str = rpc_result_str(&result, "eth_chainId")?;
    parse_rpc_quantity(hex_str)
}

fn rpc_get_nonce(url: &str, addr: &Address) -> Result<u64, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [format!("{addr}"), "latest"],
        "id": 1
    });
    let result = rpc_post(url, &body)?;
    let hex_str = rpc_result_str(&result, "eth_getTransactionCount")?;
    parse_rpc_quantity(hex_str)
}

fn rpc_gas_price(url: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_gasPrice",
        "params": [],
        "id": 1
    });
    let result = rpc_post(url, &body)?;
    let hex_str = rpc_result_str(&result, "eth_gasPrice")?;
    parse_rpc_quantity(hex_str)
}

fn rpc_estimate_gas(
    url: &str,
    from: &Address,
    to: Option<&Address>,
    value: &U256,
    data: &[u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut call_obj = serde_json::json!({
        "from": format!("{from}"),
        "value": format!("0x{:x}", value),
        "data": format!("0x{}", hex::encode(data)),
    });
    if let Some(to_addr) = to {
        call_obj["to"] = serde_json::json!(format!("{to_addr}"));
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_estimateGas",
        "params": [call_obj],
        "id": 1
    });
    let result = rpc_post(url, &body)?;
    let hex_str = rpc_result_str(&result, "eth_estimateGas")?;
    parse_rpc_quantity(hex_str)
}

fn rpc_result_str<'a>(
    response: &'a serde_json::Value,
    method: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    if let Some(err) = response.get("error") {
        return Err(format!("RPC error from {method}: {err}").into());
    }
    response
        .get("result")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("unexpected {method} response").into())
}

fn parse_rpc_quantity(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let hex = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("RPC quantity must be 0x-prefixed: {s}"))?;
    if hex.is_empty() {
        return Err("RPC quantity must not be empty".into());
    }
    if hex.len() > 1 && hex.starts_with('0') {
        return Err(format!("RPC quantity must be canonical without leading zeroes: {s}").into());
    }
    if hex.len() > 16 {
        return Err(format!("RPC quantity overflows u64: {s}").into());
    }
    Ok(u64::from_str_radix(hex, 16)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_address() {
        let raw = Address::from([0x11; 32]);
        let addr = parse_address(&raw.to_string()).unwrap();
        assert_eq!(addr, raw);
    }

    #[test]
    fn parse_address_accepts_only_prefixed_32_byte_hex() {
        assert!(parse_address(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_ok());
        assert!(
            parse_address("0000000000000000000000000000000000000000000000000000000000000001")
                .is_err()
        );
    }

    #[test]
    fn parse_address_invalid_format() {
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn parse_u256_decimal() {
        let val = parse_u256("1000000000000000000").unwrap();
        assert_eq!(val, U256::from(1_000_000_000_000_000_000u64));
    }

    #[test]
    fn parse_u256_hex() {
        let val = parse_u256("0xff").unwrap();
        assert_eq!(val, U256::from(255u64));
    }

    #[test]
    fn parse_hex_bytes_works() {
        let bytes = parse_hex_bytes("0xdeadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_rpc_quantity_accepts_prefixed_hex() {
        assert_eq!(parse_rpc_quantity("0x0").unwrap(), 0);
        assert_eq!(parse_rpc_quantity("0xff").unwrap(), 255);
    }

    #[test]
    fn parse_rpc_quantity_rejects_invalid_values() {
        assert!(parse_rpc_quantity("").is_err());
        assert!(parse_rpc_quantity("0x").is_err());
        assert!(parse_rpc_quantity("ff").is_err());
        assert!(parse_rpc_quantity("0x00").is_err());
        assert!(parse_rpc_quantity("0x01").is_err());
        assert!(parse_rpc_quantity("0x10000000000000000").is_err());
    }

    #[test]
    fn rpc_result_str_surfaces_rpc_errors() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "boom"},
            "id": 1
        });

        let err = rpc_result_str(&response, "eth_chainId").unwrap_err();
        assert!(err.to_string().contains("RPC error from eth_chainId"));
    }

    #[test]
    fn rpc_result_str_requires_string_result() {
        let missing = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        assert!(rpc_result_str(&missing, "eth_chainId").is_err());

        let non_string = serde_json::json!({
            "jsonrpc": "2.0",
            "result": 1,
            "id": 1
        });
        assert!(rpc_result_str(&non_string, "eth_chainId").is_err());
    }
}
