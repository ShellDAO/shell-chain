//! `shell-chain pq-hd` — Shell PQ-HD v1 wallet commands.
//!
//! Subcommands:
//! - `generate`  — generate a new mnemonic, derive account 0, save encrypted HD keystore.
//! - `derive`    — load an encrypted HD keystore and derive an account at a specific path.
//! - `address`   — print addresses for a mnemonic without storing anything.

use std::path::PathBuf;

use shell_crypto::hd::{
    derive_account, generate_mnemonic, mnemonic_to_seed, HdAlgo, HD_COIN_TYPE, HD_PURPOSE,
};
use shell_keystore::{decrypt_hd_seed, encrypt_hd_seed, EncryptedKey};

use crate::password::{resolve_new_password, resolve_password, PasswordArgs};

pub enum PqHdCommand {
    Generate {
        output: PathBuf,
        algo: String,
        password_args: PasswordArgs,
    },
    Derive {
        keystore: PathBuf,
        account: u32,
        change: u32,
        index: u32,
        algo: String,
        password_args: PasswordArgs,
    },
    Address {
        count: u32,
        algo: String,
    },
}

pub fn execute(cmd: PqHdCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        PqHdCommand::Generate {
            output,
            algo,
            password_args,
        } => generate(output, algo, password_args),
        PqHdCommand::Derive {
            keystore,
            account,
            change,
            index,
            algo,
            password_args,
        } => derive(keystore, algo, account, change, index, password_args),
        PqHdCommand::Address { count, algo } => print_addresses(count, algo),
    }
}

fn parse_algo(s: &str) -> Result<HdAlgo, Box<dyn std::error::Error>> {
    match s {
        "mldsa65" | "ml-dsa-65" | "1" => Ok(HdAlgo::MlDsa65),
        "slhdsa" | "slh-dsa" | "sphincs" | "2" => Ok(HdAlgo::SlhDsaSha2256f),
        other => Err(format!("unknown algorithm '{other}'; valid: mldsa65, slhdsa").into()),
    }
}

/// Generate a new BIP-39 mnemonic, derive account 0, and save encrypted HD keystore.
fn generate(
    output: PathBuf,
    algo_str: String,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let algo = parse_algo(&algo_str)?;
    let password = resolve_new_password(&password_args)?;

    let mnemonic = generate_mnemonic();
    let mnemonic_str = mnemonic.to_string();
    let seed = mnemonic_to_seed(&mnemonic_str, "");
    let account = derive_account(&seed, algo, 0, 0, 0)?;

    let encrypted = encrypt_hd_seed(&seed, &account.address, password.as_bytes())?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    std::fs::write(&output, &json)?;

    eprintln!("✓ HD keystore written to {}", output.display());
    eprintln!();
    eprintln!("  RECOVERY PHRASE (write this down — shown only once):");
    eprintln!("  {mnemonic_str}");
    eprintln!();
    eprintln!("  Default account  : {}", account.address);
    eprintln!("  Path             : {}", account.path);
    eprintln!("  Algorithm        : {algo_str}");
    eprintln!("  Purpose/CoinType : {HD_PURPOSE}'/{HD_COIN_TYPE}'");

    Ok(())
}

/// Load an encrypted HD keystore and derive an account at the specified path indices.
fn derive(
    keystore: PathBuf,
    algo_str: String,
    account_index: u32,
    change_index: u32,
    address_index: u32,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let algo = parse_algo(&algo_str)?;
    let password = resolve_password("Enter keystore password: ", &password_args)?;

    let json = std::fs::read_to_string(&keystore)?;
    let encrypted: EncryptedKey = serde_json::from_str(&json)?;
    let seed = decrypt_hd_seed(&encrypted, password.as_bytes())?;

    let account = derive_account(&seed, algo, account_index, change_index, address_index)?;

    println!("Address   : {}", account.address);
    println!("Path      : {}", account.path);
    println!("Algorithm : {algo_str}");
    println!("Public key: 0x{}", hex::encode(&account.public_key));

    Ok(())
}

/// Print addresses for a mnemonic without storing anything.
/// Reads mnemonic from stdin (never from CLI args to avoid shell history exposure).
fn print_addresses(count: u32, algo_str: String) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let algo = parse_algo(&algo_str)?;

    eprint!("Enter recovery phrase (24 words): ");
    std::io::stderr().flush()?;
    let mnemonic = rpassword::read_password()?;

    eprint!("BIP-39 passphrase (leave empty for none): ");
    std::io::stderr().flush()?;
    let passphrase = rpassword::read_password()?;

    let seed = mnemonic_to_seed(&mnemonic, &passphrase);

    println!("Algorithm : {algo_str}");
    println!();
    for i in 0..count {
        let account = derive_account(&seed, algo, i, 0, 0)?;
        println!("[{}] {} ({})", i, account.address, account.path);
    }

    Ok(())
}
