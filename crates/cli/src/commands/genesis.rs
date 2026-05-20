//! `shell-node genesis` — genesis file management utilities.

use std::path::PathBuf;

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
