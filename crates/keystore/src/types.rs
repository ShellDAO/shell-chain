//! Keystore types and JSON format.

use serde::{Deserialize, Serialize};

/// Maximum Argon2id memory accepted while opening a keystore (128 MiB).
pub const MAX_KDF_MEMORY_KIB: u32 = 131_072;
/// Maximum Argon2id iterations accepted while opening a keystore.
pub const MAX_KDF_TIME_COST: u32 = 10;
/// Maximum Argon2id parallelism accepted while opening a keystore.
pub const MAX_KDF_PARALLELISM: u32 = 16;

/// Errors returned by keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed (wrong password or corrupted data)")]
    Decryption,

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("crypto: {0}")]
    Crypto(#[from] shell_crypto::CryptoError),
}

/// argon2id key derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism degree.
    pub p_cost: u32,
    /// Salt (hex-encoded).
    pub salt: String,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
            salt: String::new(),
        }
    }
}

/// XChaCha20-Poly1305 cipher parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Nonce (hex-encoded, 24 bytes).
    pub nonce: String,
}

/// Encrypted private key in JSON-serializable format.
///
/// Compatible with a PQ-adapted variant of the Web3 Secret Storage
/// definition. The `address` field stores the Shell account as a `0x`-prefixed
/// hex string derived from `BLAKE3(algo_id || pubkey)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Format version (always 1).
    pub version: u32,
    /// Shell-chain address derived from the public key (`0x` + 64 lowercase hex).
    pub address: String,
    /// PQ algorithm type ("dilithium3" or "sphincs-sha2-256f").
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// KDF algorithm identifier.
    pub kdf: String,
    /// KDF parameters.
    pub kdf_params: KdfParams,
    /// AEAD cipher identifier.
    pub cipher: String,
    /// Cipher parameters (nonce).
    pub cipher_params: CipherParams,
    /// Encrypted secret key (hex-encoded).
    pub ciphertext: String,
    /// Public key (hex-encoded) for address verification on decrypt.
    pub public_key: String,
}

fn default_key_type() -> String {
    "dilithium3".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── KdfParams tests ────────────────────────────────────────

    #[test]
    fn kdf_params_default_values() {
        let params = KdfParams::default();
        assert_eq!(params.m_cost, 65536);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
        assert!(params.salt.is_empty());
    }

    #[test]
    fn kdf_params_serialization_roundtrip() {
        let params = KdfParams {
            m_cost: 131072,
            t_cost: 5,
            p_cost: 8,
            salt: "deadbeef".into(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let decoded: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.m_cost, 131072);
        assert_eq!(decoded.t_cost, 5);
        assert_eq!(decoded.p_cost, 8);
        assert_eq!(decoded.salt, "deadbeef");
    }

    #[test]
    fn kdf_params_clone() {
        let params = KdfParams::default();
        let cloned = params.clone();
        assert_eq!(params.m_cost, cloned.m_cost);
        assert_eq!(params.t_cost, cloned.t_cost);
        assert_eq!(params.p_cost, cloned.p_cost);
    }

    // ── CipherParams tests ─────────────────────────────────────

    #[test]
    fn cipher_params_serialization_roundtrip() {
        let cp = CipherParams {
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        let decoded: CipherParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.nonce, cp.nonce);
    }

    // ── EncryptedKey tests ─────────────────────────────────────

    #[test]
    fn encrypted_key_serialization_roundtrip() {
        let ek = EncryptedKey {
            version: 1,
            address: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            key_type: "dilithium3".into(),
            kdf: "argon2id".into(),
            kdf_params: KdfParams::default(),
            cipher: "xchacha20-poly1305".into(),
            cipher_params: CipherParams {
                nonce: "aabbcc".into(),
            },
            ciphertext: "deadbeef".into(),
            public_key: "001122".into(),
        };
        let json = serde_json::to_string_pretty(&ek).unwrap();
        let decoded: EncryptedKey = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.address, ek.address);
        assert_eq!(decoded.key_type, "dilithium3");
        assert_eq!(decoded.kdf, "argon2id");
        assert_eq!(decoded.cipher, "xchacha20-poly1305");
        assert_eq!(decoded.ciphertext, "deadbeef");
        assert_eq!(decoded.public_key, "001122");
    }

    #[test]
    fn encrypted_key_default_key_type_on_missing_field() {
        let json = r#"{
            "version": 1,
            "address": "0x0000",
            "kdf": "argon2id",
            "kdf_params": {"m_cost": 65536, "t_cost": 3, "p_cost": 4, "salt": ""},
            "cipher": "xchacha20-poly1305",
            "cipher_params": {"nonce": "abc"},
            "ciphertext": "def",
            "public_key": "012"
        }"#;
        let decoded: EncryptedKey = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.key_type, "dilithium3");
    }

    #[test]
    fn encrypted_key_explicit_key_type_sphincs() {
        let json = r#"{
            "version": 1,
            "address": "0x0000",
            "key_type": "sphincs-sha2-256f",
            "kdf": "argon2id",
            "kdf_params": {"m_cost": 65536, "t_cost": 3, "p_cost": 4, "salt": ""},
            "cipher": "xchacha20-poly1305",
            "cipher_params": {"nonce": "abc"},
            "ciphertext": "def",
            "public_key": "012"
        }"#;
        let decoded: EncryptedKey = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.key_type, "sphincs-sha2-256f");
    }

    #[test]
    fn encrypted_key_debug_format() {
        let ek = EncryptedKey {
            version: 1,
            address: "0x00".into(),
            key_type: "dilithium3".into(),
            kdf: "argon2id".into(),
            kdf_params: KdfParams::default(),
            cipher: "xchacha20-poly1305".into(),
            cipher_params: CipherParams { nonce: "".into() },
            ciphertext: "".into(),
            public_key: "".into(),
        };
        let debug = format!("{:?}", ek);
        assert!(debug.contains("EncryptedKey"));
    }

    // ── KeystoreError tests ────────────────────────────────────

    #[test]
    fn keystore_error_encryption_display() {
        let err = KeystoreError::Encryption("bad data".into());
        assert_eq!(err.to_string(), "encryption failed: bad data");
    }

    #[test]
    fn keystore_error_decryption_display() {
        let err = KeystoreError::Decryption;
        assert_eq!(
            err.to_string(),
            "decryption failed (wrong password or corrupted data)"
        );
    }

    #[test]
    fn keystore_error_invalid_key_display() {
        let err = KeystoreError::InvalidKey("too short".into());
        assert_eq!(err.to_string(), "invalid key material: too short");
    }

    #[test]
    fn keystore_error_from_serde_json() {
        let json_err: serde_json::Error = serde_json::from_str::<bool>("not_json").unwrap_err();
        let err = KeystoreError::from(json_err);
        assert!(err.to_string().starts_with("serialization:"));
    }

    // ── default_key_type ───────────────────────────────────────

    #[test]
    fn default_key_type_is_dilithium3() {
        assert_eq!(default_key_type(), "dilithium3");
    }
}
