//! `shell-chain pq-hd` — Shell PQ-HD v1 wallet commands.
//!
//! Subcommands:
//! - `generate`  — generate a new mnemonic, derive account 0, save encrypted HD keystore.
//! - `restore`   — recover the encrypted HD seed from an existing mnemonic.
//! - `derive`    — load an encrypted HD keystore and derive an account at a specific path.
//! - `address`   — print addresses for a mnemonic without storing anything.

use std::path::PathBuf;

use shell_crypto::hd::{
    derive_account, generate_mnemonic, mnemonic_to_seed, HdAlgo, HD_COIN_TYPE, HD_PURPOSE,
};
use shell_keystore::{decrypt_hd_seed, encrypt_hd_seed, EncryptedKey};
use zeroize::Zeroizing;

use crate::password::{resolve_new_password, resolve_password, PasswordArgs};
use crate::secure_file::read_sensitive_file;
use crate::secure_file::write_sensitive_file_new;

pub enum PqHdCommand {
    Restore {
        output: PathBuf,
        algo: String,
        mnemonic_file: Option<PathBuf>,
        passphrase_file: Option<PathBuf>,
        password_args: PasswordArgs,
    },
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
        PqHdCommand::Restore {
            output,
            algo,
            mnemonic_file,
            passphrase_file,
            password_args,
        } => restore(output, algo, mnemonic_file, passphrase_file, password_args),
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

fn restore(
    output: PathBuf,
    algo_str: String,
    mnemonic_file: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let algo = parse_algo(&algo_str)?;
    let interactive = mnemonic_file.is_none();
    let mnemonic = Zeroizing::new(match mnemonic_file {
        Some(path) => read_sensitive_file(&path)?,
        None => rpassword::prompt_password("Enter recovery phrase: ")?,
    });
    let passphrase = Zeroizing::new(match passphrase_file {
        Some(path) => read_sensitive_file(&path)?,
        None if interactive => rpassword::prompt_password("BIP-39 passphrase (empty for none): ")?,
        None => String::new(),
    });
    let seed = Zeroizing::new(mnemonic_to_seed(&mnemonic, &passphrase)?);
    let account = derive_account(&seed, algo, 0, 0, 0)?;
    let password = Zeroizing::new(resolve_new_password(&password_args)?);
    let encrypted = encrypt_hd_seed(&seed, &account.address, password.as_bytes())?;
    write_sensitive_file_new(&output, serde_json::to_string_pretty(&encrypted)?)?;

    eprintln!("HD keystore restored to {}", output.display());
    eprintln!("Default account: {}", account.address);
    eprintln!("Path: {}", account.path);
    Ok(())
}

/// Generate a new BIP-39 mnemonic, derive account 0, and save encrypted HD keystore.
fn generate(
    output: PathBuf,
    algo_str: String,
    password_args: PasswordArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let algo = parse_algo(&algo_str)?;
    let password = resolve_new_password(&password_args)?;

    let mnemonic = generate_mnemonic()?;
    let mnemonic_str = mnemonic.to_string();
    let seed = mnemonic_to_seed(&mnemonic_str, "")?;
    let account = derive_account(&seed, algo, 0, 0, 0)?;

    let encrypted = encrypt_hd_seed(&seed, &account.address, password.as_bytes())?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    write_sensitive_file_new(&output, &json)?;

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

    let json = read_sensitive_file(&keystore)?;
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

    let seed = mnemonic_to_seed(&mnemonic, &passphrase)?;

    println!("Algorithm : {algo_str}");
    println!();
    for i in 0..count {
        let account = derive_account(&seed, algo, i, 0, 0)?;
        println!("[{}] {} ({})", i, account.address, account.path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_encrypts_normalized_seed_and_preserves_passphrase_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mnemonic = generate_mnemonic().unwrap().to_string();
        let phrase_file = dir.path().join("phrase.txt");
        let passphrase_file = dir.path().join("passphrase.txt");
        let password_file = dir.path().join("password.txt");
        let output = dir.path().join("restored.json");
        let passphrase = " é㍍ \n";
        write_sensitive_file_new(&phrase_file, format!("  {}\n", mnemonic.to_uppercase())).unwrap();
        write_sensitive_file_new(&passphrase_file, passphrase).unwrap();
        write_sensitive_file_new(&password_file, "temporary test password").unwrap();
        let args = PasswordArgs {
            password_file: Some(password_file),
            ..Default::default()
        };
        restore(
            output.clone(),
            "slhdsa".into(),
            Some(phrase_file.clone()),
            Some(passphrase_file.clone()),
            args.clone(),
        )
        .unwrap();
        let json = read_sensitive_file(&output).unwrap();
        let encrypted: EncryptedKey = serde_json::from_str(&json).unwrap();
        let seed = decrypt_hd_seed(&encrypted, b"temporary test password").unwrap();
        let expected = mnemonic_to_seed(&mnemonic, passphrase).unwrap();
        assert!(seed == expected);
        assert!(!json.contains(&mnemonic));
        assert!(!json.contains(&hex::encode(expected)));
        assert!(decrypt_hd_seed(&encrypted, b"wrong password").is_err());
        assert!(restore(
            output.clone(),
            "slhdsa".into(),
            Some(phrase_file),
            Some(passphrase_file),
            args,
        )
        .is_err());
        assert_eq!(read_sensitive_file(&output).unwrap(), json);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_recovery_phrase_creates_no_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let phrase = dir.path().join("phrase.txt");
        let output = dir.path().join("restored.json");
        write_sensitive_file_new(&phrase, "invalid recovery phrase").unwrap();
        assert!(restore(
            output.clone(),
            "mldsa65".into(),
            Some(phrase),
            None,
            PasswordArgs::default(),
        )
        .is_err());
        assert!(!output.exists());
    }
}
