//! Shell PQ-HD v1: Post-Quantum Hierarchical-Deterministic wallet derivation.
//!
//! Produces byte-identical keys and addresses as the TypeScript SDK
//! (`shell-sdk/src/hdwallet.ts`).  Cross-implementation parity is enforced by
//! the shared test vectors in `test-vectors/pq-hd-v1.json`.
//!
//! # Scheme summary
//!
//! - **Mnemonic**: BIP-39, 24 words (256-bit entropy), NFKD-normalised.
//! - **Seed**: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)` → 64 bytes.
//! - **Master**: `BLAKE3_keyed(KEY_MASTER, seed512, xof_len=64)`.
//! - **Child** (hardened-only): `encoded_index = 0x80000000 | n`;
//!   `data = CTX_CHILD || 0x00 || parent_secret || ser32BE(encoded_index)`;
//!   `I = BLAKE3_keyed(parent_chain_code, data, xof_len=64)`.
//! - **Leaf ML-DSA-65**: `ml_seed32 = BLAKE3_keyed(KEY_MLDSA_LEAF, child_secret, xof_len=32)`.
//! - **Leaf SLH-DSA**: `slh_seed96 = BLAKE3_keyed(KEY_SLH_LEAF, child_secret, xof_len=96)`.
//! - **Address**: `BLAKE3(algo_id || raw_pk)[0:32]` → existing Shell rule.
//!
//! NORMATIVE byte formats (locked by `test-vectors/pq-hd-v1.json`):
//! - ML-DSA-65 pk: raw FIPS 204 bytes, length **1952**, `algo_id = 0x01`.
//! - SLH-DSA-SHA2-256f pk: raw FIPS 205 bytes, length **64**, `algo_id = 0x02`.
//!
//! See ADR-011 in `workspace/projects/shell-chain/adrs/ADR-011-pq-hd-wallet.md`.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as Fips204KeyGen, SerDes as Fips204SerDes};
use fips205::slh_dsa_sha2_256f;
use fips205::traits::SerDes as Fips205SerDes;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;

// ── Domain-separation constants ──────────────────────────────────────────────

fn key_master() -> [u8; 32] {
    *blake3::hash(b"Shell-Chain PQ-HD master key v1").as_bytes()
}

fn key_mldsa_leaf() -> [u8; 32] {
    *blake3::hash(b"Shell-Chain PQ-HD ML-DSA-65 leaf seed v1").as_bytes()
}

fn key_slh_leaf() -> [u8; 32] {
    *blake3::hash(b"Shell-Chain PQ-HD SLH-DSA-SHA2-256f leaf seed v1").as_bytes()
}

const CTX_CHILD: &[u8] = b"Shell-Chain PQ-HD child v1";

/// BIP-32 hardened offset. NORMATIVE: `encoded_index = HARDENED_OFFSET | raw_index`.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Shell PQ-HD v1 purpose level (raw, applied as hardened).
pub const HD_PURPOSE: u32 = 9000;
/// Shell coin type (raw, applied as hardened; placeholder pending SLIP-0044 registration).
pub const HD_COIN_TYPE: u32 = 8888;
/// Algorithm path level for ML-DSA-65 (raw, applied as hardened).
pub const ALGO_MLDSA65: u32 = 1;
/// Algorithm path level for SLH-DSA-SHA2-256f (raw, applied as hardened).
pub const ALGO_SLH_DSA: u32 = 2;

/// AA Phase 2 session-key subtree: account level index (raw, applied as hardened).
/// Path: `m/1'/1'/k'` — fixed first two components.
pub const HD_SESSION_ACCOUNT: u32 = 1;
/// AA Phase 2 session-key subtree: subtree level index (raw, applied as hardened).
/// Path: `m/1'/1'/k'` — fixed second component marking the session subtree.
pub const HD_SESSION_SUBTREE: u32 = 1;

/// Expected ML-DSA-65 public key length in bytes (FIPS 204, NORMATIVE).
pub const MLDSA65_PK_LENGTH: usize = 1952;
/// Expected SLH-DSA-SHA2-256f public key length in bytes (FIPS 205, NORMATIVE).
pub const SLHDSA_PK_LENGTH: usize = 64;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A node in the HD tree (secret + chain code, both 32 bytes each).
/// HD-internal only — never store or export as an account private key.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct HdNode {
    /// 32-byte secret — HD-internal.
    pub secret: [u8; 32],
    /// 32-byte chain code — HD-internal.
    pub chain_code: [u8; 32],
}

/// A fully-derived account at a leaf path.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HdAccount {
    /// BIP-44-like path string, e.g. `"m/9000'/8888'/1'/0'/0'/0'"`.
    pub path: String,
    /// Algorithm identifier: 1 = ML-DSA-65, 2 = SLH-DSA-SHA2-256f.
    pub algo_id: u8,
    /// Raw public key bytes (1952 for ML-DSA-65; 64 for SLH-DSA).
    pub public_key: Vec<u8>,
    /// Raw secret key bytes — keep in memory only, never persist directly.
    pub secret_key: Vec<u8>,
    /// Shell address: 0x + 64 lowercase hex.
    pub address: String,
}

// ── Deterministic RNG from fixed seed bytes ────────────────────────────────────

/// A simple sequential RNG that reads bytes from a fixed buffer.
/// Used to pass a deterministic seed to fips205's `try_keygen_with_rng`.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SeedReader {
    buf: Vec<u8>,
    pos: usize,
}

impl SeedReader {
    fn new(seed: &[u8]) -> Self {
        Self {
            buf: seed.to_vec(),
            pos: 0,
        }
    }
}

impl RngCore for SeedReader {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let available = self.buf.len() - self.pos;
        assert!(dest.len() <= available, "SeedReader exhausted");
        dest.copy_from_slice(&self.buf[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// SeedReader is used only in deterministic keygen — it is not truly random,
// but satisfies the CryptoRng marker trait for keygen from a pre-expanded seed.
impl CryptoRng for SeedReader {}

// ── BLAKE3-keyed XOF helper ────────────────────────────────────────────────────

/// Compute `BLAKE3_keyed(key32, data, xof_len)` → `output[0..xof_len]`.
/// Returns a `Zeroizing` wrapper so the secret material is wiped on drop.
fn blake3_keyed_xof(key: &[u8; 32], data: &[u8], xof_len: usize) -> Zeroizing<Vec<u8>> {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; xof_len];
    reader.fill(&mut output);
    Zeroizing::new(output)
}

// ── Mnemonic helpers ─────────────────────────────────────────────────────────

/// Validate a BIP-39 mnemonic (English wordlist).
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    bip39::Mnemonic::parse_normalized(mnemonic).is_ok()
}

/// Generate a fresh BIP-39 mnemonic (256-bit entropy, 24 words).
pub fn generate_mnemonic() -> bip39::Mnemonic {
    bip39::Mnemonic::generate(24).expect("bip39: 24-word mnemonic generation failed")
}

// ── Seed derivation ───────────────────────────────────────────────────────────

/// Derive the 512-bit seed from a BIP-39 mnemonic using PBKDF2-HMAC-SHA512.
///
/// Normalization: applies BIP-39 normalization (NFKD) before PBKDF2. This
/// matches the TypeScript implementation for standard BIP-39 mnemonics.
///
/// Returns a 64-byte seed.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
        .unwrap_or_else(|_| {
            // Fall back to parsing without normalization for already-normalized input
            bip39::Mnemonic::parse_normalized(mnemonic).expect("invalid mnemonic")
        });
    m.to_seed(passphrase)
}

// ── HD tree ───────────────────────────────────────────────────────────────────

/// Derive the master HD node from a 64-byte seed.
pub fn master_node_from_seed(seed512: &[u8; 64]) -> HdNode {
    let key = key_master();
    let i = blake3_keyed_xof(&key, seed512, 64);
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..64]);
    HdNode { secret, chain_code }
}

/// Derive a single hardened child node.
///
/// `raw_index` must be in `[0, 2^31)`.
/// Internally applies `encoded_index = HARDENED_OFFSET | raw_index` (NORMATIVE).
pub fn derive_child_node(parent: &HdNode, raw_index: u32) -> Result<HdNode, CryptoError> {
    if raw_index >= HARDENED_OFFSET {
        return Err(CryptoError::InvalidInput(format!(
            "raw_index must be < 2^31, got {raw_index}"
        )));
    }
    let encoded_index = HARDENED_OFFSET | raw_index; // 0x80000000 | n, NORMATIVE

    // data = CTX_CHILD || 0x00 || parent_secret(32) || ser32BE(encoded_index)
    // Zeroizing ensures the parent_secret copy is wiped after the hash.
    let mut data = Zeroizing::new(Vec::with_capacity(CTX_CHILD.len() + 1 + 32 + 4));
    data.extend_from_slice(CTX_CHILD);
    data.push(0x00);
    data.extend_from_slice(&parent.secret);
    data.extend_from_slice(&encoded_index.to_be_bytes()); // big-endian

    let i = blake3_keyed_xof(&parent.chain_code, &data, 64);
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..64]);
    Ok(HdNode { secret, chain_code })
}

/// Derive the HD node at the given path components.
/// All components are raw (un-hardened) indices; the hardened bit is applied automatically.
pub fn derive_at_path(master: &HdNode, path_components: &[u32]) -> Result<HdNode, CryptoError> {
    let mut node = master.clone();
    for &idx in path_components {
        node = derive_child_node(&node, idx)?;
    }
    Ok(node)
}

// ── Leaf keypair derivation ───────────────────────────────────────────────────

/// Derive an ML-DSA-65 account at the given leaf node.
///
/// Returns an [`HdAccount`] with `public_key` of length `MLDSA65_PK_LENGTH` (1952 bytes).
pub fn derive_mldsa65_account(leaf_node: &HdNode, path: String) -> Result<HdAccount, CryptoError> {
    let key = key_mldsa_leaf();
    let ml_seed_xof = blake3_keyed_xof(&key, &leaf_node.secret, 32);
    let mut ml_seed = [0u8; 32];
    ml_seed.copy_from_slice(&ml_seed_xof);
    // ml_seed_xof is dropped and zeroized here

    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&ml_seed);
    let pk_bytes = pk.into_bytes();
    let sk_bytes = sk.into_bytes();

    if pk_bytes.len() != MLDSA65_PK_LENGTH {
        return Err(CryptoError::InvalidInput(format!(
            "unexpected ML-DSA-65 pk length: {} (expected {MLDSA65_PK_LENGTH})",
            pk_bytes.len()
        )));
    }

    let address = derive_shell_address(&pk_bytes, 0x01);
    Ok(HdAccount {
        path,
        algo_id: 1,
        public_key: pk_bytes.to_vec(),
        secret_key: sk_bytes.to_vec(),
        address,
    })
}

/// Derive an SLH-DSA-SHA2-256f account at the given leaf node.
///
/// The 96-byte seed layout is: `SK.seed(32) || SK.prf(32) || PK.seed(32)`.
/// Returns an [`HdAccount`] with `public_key` of length `SLHDSA_PK_LENGTH` (64 bytes).
pub fn derive_slhdsa_account(leaf_node: &HdNode, path: String) -> Result<HdAccount, CryptoError> {
    let key = key_slh_leaf();
    // slh_seed96 layout: SK.seed(32) || SK.prf(32) || PK.seed(32)
    let slh_seed96 = blake3_keyed_xof(&key, &leaf_node.secret, 96);

    // Provide the 96-byte seed to fips205 via a deterministic RNG that reads sequentially:
    // fips205 calls rng.try_fill_bytes(sk_seed[32]), try_fill_bytes(sk_prf[32]), try_fill_bytes(pk_seed[32]).
    let mut seed_rng = SeedReader::new(&slh_seed96);
    let (pk, sk) = slh_dsa_sha2_256f::try_keygen_with_rng(&mut seed_rng)
        .map_err(|e| CryptoError::InvalidInput(format!("SLH-DSA keygen failed: {e}")))?;

    let pk_bytes = pk.into_bytes();
    let sk_bytes = sk.into_bytes();

    if pk_bytes.len() != SLHDSA_PK_LENGTH {
        return Err(CryptoError::InvalidInput(format!(
            "unexpected SLH-DSA pk length: {} (expected {SLHDSA_PK_LENGTH})",
            pk_bytes.len()
        )));
    }

    let address = derive_shell_address(&pk_bytes, 0x02);
    Ok(HdAccount {
        path,
        algo_id: 2,
        public_key: pk_bytes.to_vec(),
        secret_key: sk_bytes.to_vec(),
        address,
    })
}

// ── High-level API ────────────────────────────────────────────────────────────

/// Supported algorithms for HD leaf derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdAlgo {
    MlDsa65,
    SlhDsaSha2256f,
}

/// Derive a Shell HD account from a 64-byte seed.
///
/// Path: `m/9000'/8888'/algo'/account'/change'/address_index'` (all hardened).
pub fn derive_account(
    seed512: &[u8; 64],
    algo: HdAlgo,
    account_index: u32,
    change_index: u32,
    address_index: u32,
) -> Result<HdAccount, CryptoError> {
    let algo_val = match algo {
        HdAlgo::MlDsa65 => ALGO_MLDSA65,
        HdAlgo::SlhDsaSha2256f => ALGO_SLH_DSA,
    };
    let components = [
        HD_PURPOSE,
        HD_COIN_TYPE,
        algo_val,
        account_index,
        change_index,
        address_index,
    ];
    let path = format_path(&components);

    let master = master_node_from_seed(seed512);
    let leaf = derive_at_path(&master, &components)?;

    match algo {
        HdAlgo::MlDsa65 => derive_mldsa65_account(&leaf, path),
        HdAlgo::SlhDsaSha2256f => derive_slhdsa_account(&leaf, path),
    }
}

/// Derive an AA Phase 2 session key from a 64-byte seed.
///
/// Path: `m/1'/1'/k'` (all hardened), where k = `session_index`.
///
/// Session keys are time-bounded delegated signing keys used in AA bundles.
/// They are intentionally separated from the primary account key tree
/// (`m/9000'/8888'/...`) to prevent namespace collisions between session
/// and wallet keys.
///
/// # Key Space
/// - `m/1'/1'/0'` — first session key (k=0)
/// - `m/1'/1'/1'` — second session key (k=1)
/// - `m/1'/1'/k'` — up to 2^31 session keys per seed
///
/// # Guarantees
/// - Deterministic: same (seed512, algo, k) always yields the same key pair
/// - Isolated: session keys cannot be confused with primary account keys
/// - Cross-algorithm safe: specifying `algo` prevents collisions across key types
/// - Memory-safe: `HdNode` secret material is zeroized on drop
///
/// # Usage
/// ```no_run
/// use shell_crypto::hd::{derive_session_key, mnemonic_to_seed, HdAlgo};
///
/// let seed = mnemonic_to_seed("word1 word2 ...", "");
/// let session_0 = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
/// let session_1 = derive_session_key(&seed, HdAlgo::MlDsa65, 1).unwrap();
/// assert_ne!(session_0.public_key, session_1.public_key);
/// ```
pub fn derive_session_key(
    seed512: &[u8; 64],
    algo: HdAlgo,
    session_index: u32,
) -> Result<HdAccount, CryptoError> {
    let components = [HD_SESSION_ACCOUNT, HD_SESSION_SUBTREE, session_index];
    let path = format_path(&components);

    let master = master_node_from_seed(seed512);
    let leaf = derive_at_path(&master, &components)?;

    match algo {
        HdAlgo::MlDsa65 => derive_mldsa65_account(&leaf, path),
        HdAlgo::SlhDsaSha2256f => derive_slhdsa_account(&leaf, path),
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

/// Format path components as a hardened BIP-44-like path string.
///
/// All components are displayed as hardened (suffixed with `'`).
pub fn format_path(components: &[u32]) -> String {
    let levels: Vec<String> = components.iter().map(|c| format!("{}'", c)).collect();
    format!("m/{}", levels.join("/"))
}

/// Parse a hardened-only path string to raw component indices.
///
/// # Errors
/// Returns an error if any component is not hardened or the path is malformed.
pub fn parse_path(path: &str) -> Result<Vec<u32>, CryptoError> {
    let path = path
        .strip_prefix("m/")
        .ok_or_else(|| CryptoError::InvalidInput(format!("path must start with \"m/\": {path}")))?;
    path.split('/')
        .map(|part| {
            let raw = part.strip_suffix('\'').ok_or_else(|| {
                CryptoError::InvalidInput(format!(
                    "all path components must be hardened (end with '): {part}"
                ))
            })?;
            let n: u32 = raw.parse().map_err(|_| {
                CryptoError::InvalidInput(format!("invalid path component: {part}"))
            })?;
            if n >= HARDENED_OFFSET {
                return Err(CryptoError::InvalidInput(format!(
                    "path component >= 2^31: {n}"
                )));
            }
            Ok(n)
        })
        .collect()
}

// ── Address derivation ────────────────────────────────────────────────────────

/// Derive a Shell address from a raw public key and algorithm ID.
/// `address = 0x + hex(BLAKE3(algo_id || pubkey)[0:32])`
fn derive_shell_address(public_key: &[u8], algo_id: u8) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[algo_id]);
    hasher.update(public_key);
    let hash = hasher.finalize();
    format!("0x{}", hex::encode(hash.as_bytes()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn load_vectors() -> serde_json::Value {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let vectors_path = manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-vectors/pq-hd-v1.json");
        let data = std::fs::read_to_string(&vectors_path)
            .unwrap_or_else(|e| panic!("failed to read test-vectors/pq-hd-v1.json: {e}"));
        serde_json::from_str(&data).expect("invalid JSON in test vectors")
    }

    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).unwrap()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    // ── Seed derivation ───────────────────────────────────────────────────────

    #[test]
    fn seed_matches_vector() {
        let v = load_vectors();
        let mnemonic = v["mnemonic"].as_str().unwrap();
        let passphrase = v["passphrase"].as_str().unwrap();
        let expected_seed = v["seed_512"].as_str().unwrap();

        let seed = mnemonic_to_seed(mnemonic, passphrase);
        assert_eq!(bytes_to_hex(&seed), expected_seed, "seed_512 mismatch");
    }

    // ── Master node ────────────────────────────────────────────────────────────

    #[test]
    fn master_node_matches_vector() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed_bytes = hex_to_bytes(seed_hex);
        let seed: [u8; 64] = seed_bytes.try_into().unwrap();

        let master = master_node_from_seed(&seed);
        assert_eq!(
            bytes_to_hex(&master.secret),
            v["master"]["secret"].as_str().unwrap(),
            "master secret mismatch"
        );
        assert_eq!(
            bytes_to_hex(&master.chain_code),
            v["master"]["chain_code"].as_str().unwrap(),
            "master chain_code mismatch"
        );
    }

    // ── ML-DSA-65 intermediate nodes ──────────────────────────────────────────

    #[test]
    fn mldsa65_intermediate_nodes_match_vectors() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();
        let master = master_node_from_seed(&seed);

        let mlv = &v["ml_dsa_65"];
        let nodes = mlv["intermediate_nodes"].as_array().unwrap();
        let mut node = master;
        for (i, expected) in nodes.iter().enumerate() {
            let raw_index = expected["raw_index"].as_u64().unwrap() as u32;
            node = derive_child_node(&node, raw_index).unwrap();
            assert_eq!(
                bytes_to_hex(&node.secret),
                expected["secret"].as_str().unwrap(),
                "ML-DSA intermediate node[{i}] secret mismatch"
            );
            assert_eq!(
                bytes_to_hex(&node.chain_code),
                expected["chain_code"].as_str().unwrap(),
                "ML-DSA intermediate node[{i}] chain_code mismatch"
            );
        }
    }

    // ── SLH-DSA intermediate nodes ────────────────────────────────────────────

    #[test]
    fn slhdsa_intermediate_nodes_match_vectors() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();
        let master = master_node_from_seed(&seed);

        let slhv = &v["slh_dsa_sha2_256f"];
        let nodes = slhv["intermediate_nodes"].as_array().unwrap();
        let mut node = master;
        for (i, expected) in nodes.iter().enumerate() {
            let raw_index = expected["raw_index"].as_u64().unwrap() as u32;
            node = derive_child_node(&node, raw_index).unwrap();
            assert_eq!(
                bytes_to_hex(&node.secret),
                expected["secret"].as_str().unwrap(),
                "SLH-DSA intermediate node[{i}] secret mismatch"
            );
            assert_eq!(
                bytes_to_hex(&node.chain_code),
                expected["chain_code"].as_str().unwrap(),
                "SLH-DSA intermediate node[{i}] chain_code mismatch"
            );
        }
    }

    // ── ML-DSA-65 leaf ────────────────────────────────────────────────────────

    #[test]
    fn mldsa65_leaf_pubkey_matches_vector() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();
        let mlv = &v["ml_dsa_65"];

        let components: Vec<u32> = mlv["path_components_raw"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();
        let path = mlv["path"].as_str().unwrap().to_string();

        let master = master_node_from_seed(&seed);
        let leaf = derive_at_path(&master, &components).unwrap();
        let account = derive_mldsa65_account(&leaf, path).unwrap();

        assert_eq!(
            account.public_key.len(),
            MLDSA65_PK_LENGTH,
            "ML-DSA-65 pk length"
        );
        assert_eq!(
            bytes_to_hex(&account.public_key),
            mlv["public_key_hex"].as_str().unwrap(),
            "ML-DSA-65 pk mismatch"
        );
        assert_eq!(
            account.address,
            mlv["address"].as_str().unwrap(),
            "ML-DSA-65 address mismatch"
        );
        assert_eq!(account.algo_id, 1);
    }

    // ── SLH-DSA leaf ──────────────────────────────────────────────────────────

    #[test]
    fn slhdsa_leaf_pubkey_matches_vector() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();
        let slhv = &v["slh_dsa_sha2_256f"];

        let components: Vec<u32> = slhv["path_components_raw"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();
        let path = slhv["path"].as_str().unwrap().to_string();

        let master = master_node_from_seed(&seed);
        let leaf = derive_at_path(&master, &components).unwrap();
        let account = derive_slhdsa_account(&leaf, path).unwrap();

        assert_eq!(
            account.public_key.len(),
            SLHDSA_PK_LENGTH,
            "SLH-DSA pk length"
        );
        assert_eq!(
            bytes_to_hex(&account.public_key),
            slhv["public_key_hex"].as_str().unwrap(),
            "SLH-DSA pk mismatch"
        );
        assert_eq!(
            account.address,
            slhv["address"].as_str().unwrap(),
            "SLH-DSA address mismatch"
        );
        assert_eq!(account.algo_id, 2);
    }

    // ── High-level API ────────────────────────────────────────────────────────

    #[test]
    fn derive_account_mldsa65_matches_vector() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();

        let account = derive_account(&seed, HdAlgo::MlDsa65, 0, 0, 0).unwrap();
        assert_eq!(account.path, v["ml_dsa_65"]["path"].as_str().unwrap());
        assert_eq!(account.address, v["ml_dsa_65"]["address"].as_str().unwrap());
    }

    #[test]
    fn derive_account_slhdsa_matches_vector() {
        let v = load_vectors();
        let seed_hex = v["seed_512"].as_str().unwrap();
        let seed: [u8; 64] = hex_to_bytes(seed_hex).try_into().unwrap();

        let account = derive_account(&seed, HdAlgo::SlhDsaSha2256f, 0, 0, 0).unwrap();
        assert_eq!(
            account.path,
            v["slh_dsa_sha2_256f"]["path"].as_str().unwrap()
        );
        assert_eq!(
            account.address,
            v["slh_dsa_sha2_256f"]["address"].as_str().unwrap()
        );
    }

    // ── Path utilities ────────────────────────────────────────────────────────

    #[test]
    fn format_path_produces_hardened_string() {
        assert_eq!(
            format_path(&[9000, 8888, 1, 0, 0, 0]),
            "m/9000'/8888'/1'/0'/0'/0'"
        );
    }

    #[test]
    fn parse_path_roundtrip() {
        let original = vec![9000u32, 8888, 1, 0, 0, 0];
        let path = format_path(&original);
        let parsed = parse_path(&path).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_path_rejects_non_hardened() {
        assert!(parse_path("m/9000'/8888'/1'/0/0'/0'").is_err());
    }

    #[test]
    fn parse_path_rejects_missing_prefix() {
        assert!(parse_path("9000'/8888'/1'/0'/0'/0'").is_err());
    }

    #[test]
    fn hardened_offset_is_correct() {
        assert_eq!(HARDENED_OFFSET, 0x8000_0000);
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(HD_PURPOSE, 9000);
        assert_eq!(HD_COIN_TYPE, 8888);
        assert_eq!(ALGO_MLDSA65, 1);
        assert_eq!(ALGO_SLH_DSA, 2);
    }

    // ── Session key derivation (AA Phase 2) ──────────────────────────────────

    #[test]
    fn session_key_path_is_correct() {
        let seed = [0u8; 64];
        let session = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        assert_eq!(session.path, "m/1'/1'/0'", "session key 0 path");

        let session1 = derive_session_key(&seed, HdAlgo::MlDsa65, 1).unwrap();
        assert_eq!(session1.path, "m/1'/1'/1'", "session key 1 path");

        let session100 = derive_session_key(&seed, HdAlgo::MlDsa65, 100).unwrap();
        assert_eq!(session100.path, "m/1'/1'/100'", "session key 100 path");
    }

    #[test]
    fn session_keys_are_deterministic() {
        // Same (seed, algo, index) always produces the same key pair.
        let seed = [0xABu8; 64];
        let s0a = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        let s0b = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        assert_eq!(s0a.public_key, s0b.public_key, "same index must be deterministic");
        assert_eq!(s0a.address, s0b.address, "same index address must be deterministic");
    }

    #[test]
    fn session_keys_differ_by_index() {
        // Different indices produce different keys.
        let seed = [0xCDu8; 64];
        let s0 = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        let s1 = derive_session_key(&seed, HdAlgo::MlDsa65, 1).unwrap();
        let s2 = derive_session_key(&seed, HdAlgo::MlDsa65, 2).unwrap();
        assert_ne!(s0.public_key, s1.public_key, "index 0 != index 1");
        assert_ne!(s0.public_key, s2.public_key, "index 0 != index 2");
        assert_ne!(s1.public_key, s2.public_key, "index 1 != index 2");
        assert_ne!(s0.address, s1.address, "addresses must differ by index");
    }

    #[test]
    fn session_key_differs_from_account_key() {
        // Session tree (m/1'/1'/k') must not collide with account tree (m/9000'/8888'/...).
        let seed = [0xEFu8; 64];
        let session = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        let account = derive_account(&seed, HdAlgo::MlDsa65, 0, 0, 0).unwrap();
        assert_ne!(
            session.public_key, account.public_key,
            "session key must not collide with account key"
        );
        assert_ne!(
            session.address, account.address,
            "session address must not collide with account address"
        );
    }

    #[test]
    fn session_key_slhdsa_works() {
        // SLH-DSA session keys follow the same path scheme.
        let seed = [0x12u8; 64];
        let s0 = derive_session_key(&seed, HdAlgo::SlhDsaSha2256f, 0).unwrap();
        let s1 = derive_session_key(&seed, HdAlgo::SlhDsaSha2256f, 1).unwrap();
        assert_eq!(s0.path, "m/1'/1'/0'");
        assert_eq!(s0.algo_id, 2, "SLH-DSA algo_id");
        assert_eq!(s0.public_key.len(), SLHDSA_PK_LENGTH);
        assert_ne!(s0.public_key, s1.public_key, "different SLH-DSA session keys");
    }

    #[test]
    fn session_key_mldsa_slhdsa_differ_same_index() {
        // Same index but different algo must produce different keys (cross-algorithm safety).
        let seed = [0x34u8; 64];
        let ml = derive_session_key(&seed, HdAlgo::MlDsa65, 0).unwrap();
        let slh = derive_session_key(&seed, HdAlgo::SlhDsaSha2256f, 0).unwrap();
        assert_ne!(ml.address, slh.address, "ML-DSA and SLH-DSA addresses must differ");
    }

    #[test]
    fn session_key_constants_are_correct() {
        assert_eq!(HD_SESSION_ACCOUNT, 1);
        assert_eq!(HD_SESSION_SUBTREE, 1);
    }
}
