//! Regenerate SDK Dilithium3 transaction fixtures.
//!
//! Generates a new Dilithium3 keypair, computes the Shell-Chain PQ signing hash
//! for the canonical test transaction (chain_id=42, nonce=0, tx_type=2, self-transfer
//! of 1 unit), signs it, and writes the fixture files:
//!
//!   crates/rpc/tests/fixtures/sdk_dilithium3_tx_pubkey.hex
//!   crates/rpc/tests/fixtures/sdk_dilithium3_tx_signature.hex
//!   crates/rpc/tests/fixtures/sdk_dilithium3_tx_hash.hex
//!   crates/rpc/tests/fixtures/sdk_dilithium3_tx_secretkey.hex   ← NEW (needed for regen)
//!
//! After running, update the hardcoded address in:
//!   crates/rpc/src/handler/mod.rs  (search "0x07d843505276...")
//!
//! Usage:
//!   cargo run -p shell-crypto --bin gen_dilithium3_tx_fixtures

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use shell_primitives::{blake3_hash, Address, U256};

/// Signing-hash preimage layout (matches `Transaction::signing_hash`):
///   chain_id(8B be) || nonce(8B be) || to(32B) || value(32B) ||
///   data || gas_limit(8B be) || max_fee_per_gas(8B be) || max_priority_fee_per_gas(8B be) ||
///   sig_type(1B) || tx_type(1B)
/// For tx_type == 3: also max_fee_per_blob_gas(8B be) || blob_hashes...
fn signing_hash(
    chain_id: u64,
    nonce: u64,
    to: Option<&Address>,
    value: U256,
    data: &[u8],
    gas_limit: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    sig_type: u8,
    tx_type: u8,
    max_fee_per_blob_gas: Option<u64>,
    blob_versioned_hashes: Option<&[[u8; 32]]>,
) -> [u8; 32] {
    let blob_extra = if tx_type == 3 {
        8 + blob_versioned_hashes.map_or(0, |h| h.len() * 32)
    } else {
        0
    };
    let mut preimage =
        Vec::with_capacity(8 + 8 + 32 + 32 + data.len() + 8 + 8 + 8 + 1 + 1 + blob_extra);
    preimage.extend_from_slice(&chain_id.to_be_bytes());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    match to {
        Some(addr) => preimage.extend_from_slice(&addr.0),
        None => preimage.extend_from_slice(&[0u8; 32]),
    }
    preimage.extend_from_slice(&value.to_be_bytes::<32>());
    preimage.extend_from_slice(data);
    preimage.extend_from_slice(&gas_limit.to_be_bytes());
    preimage.extend_from_slice(&max_fee_per_gas.to_be_bytes());
    preimage.extend_from_slice(&max_priority_fee_per_gas.to_be_bytes());
    preimage.push(sig_type);
    preimage.push(tx_type);
    if tx_type == 3 {
        preimage.extend_from_slice(&max_fee_per_blob_gas.unwrap_or(0).to_be_bytes());
        if let Some(hashes) = blob_versioned_hashes {
            for h in hashes {
                preimage.extend_from_slice(h);
            }
        }
    }
    *blake3_hash(&preimage).as_bytes()
}

fn main() {
    // ── Step 1: Generate keypair ─────────────────────────────────────────────
    let (pk, sk) = dilithium3::keypair();
    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();

    // ── Step 2: Derive address ───────────────────────────────────────────────
    // SIG_TYPE_DILITHIUM3 = 0x00
    let from = Address::from_public_key(pk_bytes, 0);
    println!("New address: {}", from);
    println!("Update 'assert_eq!(addr.to_string(), ...)' in crates/rpc/src/handler/mod.rs");

    // ── Step 3: Build test transaction (matches the fixture tx in tests) ─────
    // chain_id=42, nonce=0, to=from (self-transfer), value=1, data=[],
    // gas_limit=21_000, max_fee_per_gas=1e9, max_priority_fee_per_gas=1e8,
    // tx_type=2, no blob fields.  sig_type=Dilithium3=0.
    let hash = signing_hash(
        42,               // chain_id
        0,                // nonce
        Some(&from),      // to = self-transfer
        U256::from(1u64), // value
        &[],              // data
        21_000,           // gas_limit
        1_000_000_000,    // max_fee_per_gas
        100_000_000,      // max_priority_fee_per_gas
        0,                // sig_type = Dilithium3
        2,                // tx_type
        None,
        None,
    );
    println!("New signing hash: {}", hex::encode(hash));

    // ── Step 4: Sign ─────────────────────────────────────────────────────────
    let sig = dilithium3::detached_sign(&hash, &sk);
    let sig_bytes = sig.as_bytes();

    // ── Step 5: Self-verify ──────────────────────────────────────────────────
    dilithium3::verify_detached_signature(&sig, &hash, &pk)
        .expect("self-verify failed — fixture would be invalid");
    println!("Self-verify: OK");

    // ── Step 6: Write fixtures ───────────────────────────────────────────────
    let fixtures_dir = std::path::PathBuf::from("crates/rpc/tests/fixtures");
    std::fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");

    let write_hex = |name: &str, bytes: &[u8]| {
        let path = fixtures_dir.join(name);
        std::fs::write(&path, hex::encode(bytes)).expect("write fixture");
        println!("Written: {}", path.display());
    };

    write_hex("sdk_dilithium3_tx_pubkey.hex", pk_bytes);
    write_hex("sdk_dilithium3_tx_signature.hex", sig_bytes);
    write_hex("sdk_dilithium3_tx_hash.hex", &hash);
    write_hex("sdk_dilithium3_tx_secretkey.hex", sk_bytes);

    println!("\nDone. Bytes written:");
    println!("  pubkey:    {} bytes", pk_bytes.len());
    println!("  signature: {} bytes", sig_bytes.len());
    println!("  hash:      {} bytes", hash.len());
    println!("  secretkey: {} bytes", sk_bytes.len());
}
