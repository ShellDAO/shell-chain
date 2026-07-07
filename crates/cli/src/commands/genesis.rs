//! `shell-node genesis` — genesis file management utilities.

use std::path::{Path, PathBuf};

use serde_json::Value;
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
    let raw = std::fs::read_to_string(&genesis_path)
        .map_err(|e| format!("cannot read {}: {e}", genesis_path.display()))?;

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

    let out_path = output.unwrap_or_else(|| genesis_path.clone());
    let new_json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(&out_path, &new_json)?;

    eprintln!("✓ Alloc added: {addr_key} → {balance} wei");
    eprintln!("  Written to: {}", out_path.display());

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
    let raw = std::fs::read_to_string(&genesis_path)
        .map_err(|e| format!("cannot read {}: {e}", genesis_path.display()))?;
    let genesis = shell_genesis::GenesisConfig::from_json(&raw)
        .map_err(|e| format!("invalid genesis JSON: {e}"))?;
    genesis.validate_economics()?;
    eprintln!("✓ Genesis economics and supply invariants are valid");
    Ok(())
}

fn read_json_doc(path: &PathBuf) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
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
    std::fs::write(&out_path, &new_json)?;
    eprintln!("  Written to: {}", out_path.display());
    Ok(())
}
