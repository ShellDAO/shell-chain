//! `shell-node genesis` — genesis file management utilities.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;
use shell_genesis::read_genesis_file;
use shell_primitives::Address;

/// Add (or update) an allocation entry in a genesis JSON file.
///
/// Reads genesis, inserts `alloc[address] = { "balance": balance }`, then
/// writes back to `output` (or the same file if `output` is `None`).
pub fn genesis_add_alloc(
    genesis_path: PathBuf,
    address: String,
    balance: String,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = read_genesis_file(&genesis_path)?;

    let mut doc: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", genesis_path.display()))?;

    let address = Address::parse(&address).map_err(|e| format!("invalid address: {e}"))?;
    let addr_key = address.to_string();

    // Ensure `alloc` object exists.
    let alloc = doc
        .as_object_mut()
        .ok_or("genesis is not a JSON object")?
        .entry("alloc")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));

    // Insert or overwrite the allocation entry.
    let entry = serde_json::json!({
        "balance": balance,
        "nonce": 0
    });
    alloc
        .as_object_mut()
        .ok_or("genesis.alloc is not a JSON object")?
        .insert(addr_key.clone(), entry);

    write_json_doc(&genesis_path, output, &doc)?;

    eprintln!("✓ Alloc added: {addr_key} → {balance} wei");

    Ok(())
}

pub fn genesis_set_economics(
    genesis_path: PathBuf,
    initial_supply: String,
    stake_unit: String,
    min_validator_stake: String,
    max_validator_weight: u64,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = read_json_doc(&genesis_path)?;
    doc.as_object_mut()
        .ok_or("genesis is not a JSON object")?
        .insert(
            "economics".to_string(),
            serde_json::json!({
                "staking_enabled": true,
                "initial_supply": initial_supply,
                "stake_unit": stake_unit,
                "min_validator_stake": min_validator_stake,
                "max_validator_weight": max_validator_weight,
            }),
        );
    write_json_doc(&genesis_path, output, &doc)?;
    eprintln!("✓ Staking economics updated");
    Ok(())
}

pub fn genesis_set_validator_stake(
    genesis_path: PathBuf,
    address: String,
    stake: String,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut doc = read_json_doc(&genesis_path)?;
    let address = Address::parse(&address).map_err(|e| format!("invalid address: {e}"))?;
    let root = doc.as_object_mut().ok_or("genesis is not a JSON object")?;
    let consensus = root
        .get_mut("consensus")
        .and_then(Value::as_object_mut)
        .ok_or("genesis.consensus is not a JSON object")?;
    let authority_values = consensus
        .get("authorities")
        .and_then(Value::as_array)
        .ok_or("genesis.consensus.authorities is not an array")?;
    let address_key = address.to_string();
    let authorities_len = authority_values.len();
    let index = authority_values
        .iter()
        .position(|value| value.as_str() == Some(address_key.as_str()))
        .ok_or_else(|| format!("address {address} is not in consensus.authorities"))?;
    let stakes = consensus
        .entry("stakes")
        .or_insert_with(|| Value::Array(vec![Value::String("0".into()); authorities_len]));
    let stakes = stakes
        .as_array_mut()
        .ok_or("genesis.consensus.stakes is not an array")?;
    while stakes.len() < authorities_len {
        stakes.push(Value::String("0".into()));
    }
    stakes[index] = Value::String(stake);
    write_json_doc(&genesis_path, output, &doc)?;
    eprintln!("✓ Validator stake updated: {address}");
    Ok(())
}

pub fn genesis_validate_supply(genesis_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let genesis = shell_genesis::GenesisConfig::from_file(&genesis_path)
        .map_err(|e| format!("invalid genesis file: {e}"))?;
    genesis.validate_economics()?;
    eprintln!("✓ Genesis economics and supply invariants are valid");
    Ok(())
}

fn read_json_doc(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = read_genesis_file(path)?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()).into())
}

fn write_json_doc(
    genesis_path: &Path,
    output: Option<PathBuf>,
    doc: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let out_path = output.unwrap_or_else(|| genesis_path.to_path_buf());
    let new_json = serde_json::to_string_pretty(doc)?;
    write_file_atomic(&out_path, new_json.as_bytes())?;
    eprintln!("  Written to: {}", out_path.display());
    Ok(())
}

fn write_file_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;

    if let Ok(metadata) = std::fs::metadata(path) {
        temp.as_file().set_permissions(metadata.permissions())?;
    }

    temp.write_all(contents)?;
    temp.as_file_mut().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;

    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_json_doc_replaces_existing_file_atomically() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        std::fs::write(&path, br#"{"chain_id": 1}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let original_inode = std::fs::metadata(&path).unwrap().ino();

        write_json_doc(&path, None, &serde_json::json!({"chain_id": 2})).unwrap();

        let replacement_inode = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(replacement_inode, original_inode);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
            serde_json::json!({"chain_id": 2})
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn validate_supply_rejects_oversized_genesis_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(shell_genesis::MAX_GENESIS_FILE_SIZE + 1)
            .unwrap();

        let error = genesis_validate_supply(path).unwrap_err();
        assert!(
            error.to_string().contains("genesis file too large"),
            "unexpected error: {error}"
        );
    }
}
