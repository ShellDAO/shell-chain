//! `shell-node account` — account management subcommands.

use std::path::PathBuf;

use clap::Subcommand;
use shell_keystore::EncryptedKey;
use shell_primitives::Address;

use crate::secure_file::read_sensitive_file;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// List keystore addresses found in the data directory.
    List {
        /// Data directory to scan for keystore files.
        #[arg(long, default_value = "shell-data")]
        datadir: PathBuf,
    },

    /// Query the balance of an address.
    Balance {
        /// Address to query (`0x` + 64 lowercase hex).
        address: String,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },

    /// Query the nonce (transaction count) of an address.
    Nonce {
        /// Address to query (`0x` + 64 lowercase hex).
        address: String,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },
}

/// Execute an account subcommand.
pub fn execute(cmd: AccountCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AccountCommand::List { datadir } => cmd_list(datadir),
        AccountCommand::Balance { address, rpc_url } => cmd_balance(address, rpc_url),
        AccountCommand::Nonce { address, rpc_url } => cmd_nonce(address, rpc_url),
    }
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

fn cmd_list(datadir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let datadir_meta = std::fs::symlink_metadata(&datadir)?;
    if datadir_meta.file_type().is_symlink() || !datadir_meta.is_dir() {
        return Err(format!("data path must be a real directory: {}", datadir.display()).into());
    }

    let mut found = 0u32;

    for entry in std::fs::read_dir(&datadir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            if let Ok(contents) = read_sensitive_file(&path) {
                if let Ok(ek) = serde_json::from_str::<EncryptedKey>(&contents) {
                    let address = Address::parse(&ek.address).map_err(|e| {
                        format!("invalid keystore address in {}: {e}", path.display())
                    })?;
                    println!("{address} ({})", path.display());
                    found += 1;
                }
            }
        }
    }

    if found == 0 {
        eprintln!("No keystore files found in {}", datadir.display());
    } else {
        eprintln!("{found} keystore(s) found");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

fn cmd_balance(address: String, rpc_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_address(&address)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [format!("{addr}"), "latest"],
        "id": 1
    });

    let result = rpc_post(&rpc_url, &body)?;
    if let Some(err) = result.get("error") {
        return Err(format!("RPC error: {err}").into());
    }
    let hex_str = result["result"]
        .as_str()
        .ok_or("unexpected eth_getBalance response")?;
    println!("{hex_str}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

fn cmd_nonce(address: String, rpc_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_address(&address)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [format!("{addr}"), "latest"],
        "id": 1
    });

    let result = rpc_post(&rpc_url, &body)?;
    if let Some(err) = result.get("error") {
        return Err(format!("RPC error: {err}").into());
    }
    let hex_str = result["result"]
        .as_str()
        .ok_or("unexpected eth_getTransactionCount response")?;
    println!("{hex_str}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers (shared with tx.rs via duplication — small surface, not worth a
// shared module for two one-liners)
// ---------------------------------------------------------------------------

fn parse_address(s: &str) -> Result<Address, Box<dyn std::error::Error>> {
    Address::parse(s).map_err(|e| format!("invalid address '{s}': {e}").into())
}

fn rpc_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let resp = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())?;
    let json: serde_json::Value = resp.into_json()?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_address() {
        let expected = Address::from([0x42; 32]);
        let parsed = parse_address(&expected.to_string()).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parse_hex_address() {
        let raw = Address::from([0x24; 32]);
        let addr = parse_address(&raw.to_string()).unwrap();
        assert_eq!(addr, raw);
    }

    #[test]
    fn parse_address_rejects_short() {
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = cmd_list(dir.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn list_skips_symbolic_link_keystores() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let linked = dir.path().join("linked.json");
        std::fs::write(
            &target,
            r#"{
  "version": 1,
  "address": "invalid",
  "key_type": "dilithium3",
  "public_key": "deadbeef",
  "ciphertext": "00",
  "cipher": "xchacha20-poly1305",
  "kdf": "argon2id",
  "kdf_params": {"m_cost": 65536, "t_cost": 3, "p_cost": 1, "salt": "00"},
  "cipher_params": {"nonce": "00"}
}"#,
        )
        .unwrap();
        symlink(target, linked).unwrap();

        assert!(cmd_list(dir.path().to_path_buf()).is_ok());
    }
}
