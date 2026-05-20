//! `shell-node wallet` — lightweight wallet UX.

use std::path::PathBuf;

use clap::Subcommand;
use shell_keystore::EncryptedKey;

use super::{account, key, tx};
use crate::password::PasswordArgs;

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Generate a new PQ keystore-backed wallet.
    Create {
        /// Output path for the keystore file.
        #[arg(long, default_value = "wallet.json")]
        output: PathBuf,
    },

    /// Query the balance of an address.
    Balance {
        /// Address to query (`0x` + 64 lowercase hex).
        address: String,

        /// JSON-RPC endpoint URL.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },

    /// Send a value transfer.
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

    /// Export the keystore JSON to a destination path.
    Export {
        /// Source keystore file.
        #[arg(long)]
        keystore: PathBuf,

        /// Destination file path.
        #[arg(long)]
        output: PathBuf,
    },
}

pub fn execute(
    cmd: WalletCommand,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        WalletCommand::Create { output } => {
            key::key_generate(output, password_args, "dilithium3".into())
        }
        WalletCommand::Balance { address, rpc_url } => {
            account::execute(account::AccountCommand::Balance { address, rpc_url })
        }
        WalletCommand::Send {
            to,
            value,
            keystore,
            rpc_url,
            chain_id,
            nonce,
            gas_limit,
        } => tx::execute(
            tx::TxCommand::Send {
                to,
                value,
                keystore,
                rpc_url,
                chain_id,
                nonce,
                gas_limit,
            },
            password_args,
        ),
        WalletCommand::Export { keystore, output } => cmd_export(keystore, output),
    }
}

fn cmd_export(keystore: PathBuf, output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(&keystore)?;
    let encrypted: EncryptedKey = serde_json::from_str(&raw)?;
    let normalized = serde_json::to_string_pretty(&encrypted)?;
    std::fs::write(&output, normalized)?;
    eprintln!("✓ Wallet keystore exported to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_keystore_json() {
        let dir = std::env::temp_dir().join(format!("shell-wallet-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.json");
        let dst = dir.join("dst.json");

        std::fs::write(
            &src,
            r#"{
  "version": 1,
  "address": "0x0000000000000000000000000000000000000000000000000000000000000001",
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

        let result = cmd_export(src.clone(), dst.clone());
        assert!(result.is_ok());
        assert!(dst.exists());

        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
        let _ = std::fs::remove_dir(dir);
    }
}
