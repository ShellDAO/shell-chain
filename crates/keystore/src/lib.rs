//! Post-quantum keystore for shell-chain.
//!
//! Encrypts and decrypts Dilithium3 and SPHINCS+-SHA2-256f private keys using:
//! - **KDF**: argon2id (m=64 MiB, t=3, p=4) — memory-hard, side-channel resistant
//! - **AEAD**: XChaCha20-Poly1305 — 24-byte nonce safe for random generation
//!
//! The encrypted key is stored as a JSON file compatible with the
//! Ethereum Web3 Secret Storage format (adapted for PQ keys).
//!
//! # Example
//! ```no_run
//! use shell_keystore::{encrypt, decrypt};
//! use shell_crypto::DilithiumSigner;
//!
//! let signer = DilithiumSigner::generate();
//! let encrypted = encrypt(&signer, b"my-password").unwrap();
//! let json = serde_json::to_string_pretty(&encrypted).unwrap();
//!
//! // Later...
//! let loaded: shell_keystore::EncryptedKey = serde_json::from_str(&json).unwrap();
//! let recovered = decrypt(&loaded, b"my-password").unwrap();
//! ```

mod crypto;
mod types;

pub use crypto::{
    decrypt, decrypt_any, decrypt_hd_seed, decrypt_mldsa, decrypt_sphincs, encrypt,
    encrypt_hd_seed, encrypt_mldsa, encrypt_sphincs,
};
pub use types::{CipherParams, EncryptedKey, KdfParams, KeystoreError};
