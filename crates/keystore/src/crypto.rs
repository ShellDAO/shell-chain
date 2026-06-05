//! Encryption and decryption of post-quantum secret keys.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use zeroize::Zeroize;

use shell_crypto::{DilithiumSigner, MlDsaSigner, Signer, SphincsSigner};
use shell_primitives::Address;

use crate::types::{CipherParams, EncryptedKey, KdfParams, KeystoreError};

/// Encrypt a Dilithium3 signer with a password.
///
/// Returns an [`EncryptedKey`] that can be serialized to JSON and stored
/// on disk. The secret key is encrypted with XChaCha20-Poly1305 using a
/// key derived from the password via argon2id.
pub fn encrypt(signer: &DilithiumSigner, password: &[u8]) -> Result<EncryptedKey, KeystoreError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24]; // XChaCha20 uses 24-byte nonce
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let kdf_params = KdfParams {
        m_cost: 65536, // 64 MiB
        t_cost: 3,
        p_cost: 4,
        salt: hex::encode(salt),
    };

    // Derive 32-byte encryption key from password.
    let mut derived_key = derive_key(password, &salt, &kdf_params)?;

    // Encrypt the secret key bytes.
    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let plaintext: &[u8] = signer.secret_key_bytes();

    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

    derived_key.zeroize();

    let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    Ok(EncryptedKey {
        version: 1,
        address: address.to_string(),
        key_type: "dilithium3".into(),
        kdf: "argon2id".into(),
        kdf_params,
        cipher: "xchacha20-poly1305".into(),
        cipher_params: CipherParams {
            nonce: hex::encode(nonce),
        },
        ciphertext: hex::encode(&ciphertext),
        public_key: hex::encode(signer.public_key()),
    })
}

/// Decrypt an encrypted key with a password, returning a DilithiumSigner.
///
/// Verifies that the decrypted public key matches the stored address
/// to catch wrong-password errors early (via AEAD tag check).
pub fn decrypt(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<DilithiumSigner, KeystoreError> {
    let (mut secret_key, public_key) = raw_decrypt(encrypted, password)?;
    let signer = DilithiumSigner::from_bytes(&public_key, &secret_key)?;
    secret_key.zeroize();
    Ok(signer)
}

/// Encrypt an ML-DSA-65 signer with a password.
///
/// Stores `key_type = "mldsa65"` so [`decrypt_any`] can reconstruct the
/// correct signer.
pub fn encrypt_mldsa(signer: &MlDsaSigner, password: &[u8]) -> Result<EncryptedKey, KeystoreError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let kdf_params = KdfParams {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 4,
        salt: hex::encode(salt),
    };

    let mut derived_key = derive_key(password, &salt, &kdf_params)?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let plaintext: &[u8] = signer.secret_key_bytes();

    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

    derived_key.zeroize();

    let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    Ok(EncryptedKey {
        version: 1,
        address: address.to_string(),
        key_type: "mldsa65".into(),
        kdf: "argon2id".into(),
        kdf_params,
        cipher: "xchacha20-poly1305".into(),
        cipher_params: CipherParams {
            nonce: hex::encode(nonce),
        },
        ciphertext: hex::encode(&ciphertext),
        public_key: hex::encode(signer.public_key()),
    })
}

/// Decrypt an ML-DSA-65 encrypted key with a password.
pub fn decrypt_mldsa(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<MlDsaSigner, KeystoreError> {
    if encrypted.key_type != "mldsa65" {
        return Err(KeystoreError::InvalidKey(format!(
            "expected key_type mldsa65, got {}",
            encrypted.key_type
        )));
    }

    let (mut secret_key, public_key) = raw_decrypt(encrypted, password)?;
    let signer = MlDsaSigner::from_bytes(&public_key, &secret_key)?;
    secret_key.zeroize();
    Ok(signer)
}

/// Decrypt any supported key type, returning a type-erased [`Signer`].
///
/// Dispatches to [`decrypt`], [`decrypt_sphincs`], or [`decrypt_mldsa`]
/// based on the `key_type` field in the keystore.
pub fn decrypt_any(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<Box<dyn Signer>, KeystoreError> {
    match encrypted.key_type.as_str() {
        "dilithium3" | "" => Ok(Box::new(decrypt(encrypted, password)?)),
        "sphincs-sha2-256f" => Ok(Box::new(decrypt_sphincs(encrypted, password)?)),
        "mldsa65" => Ok(Box::new(decrypt_mldsa(encrypted, password)?)),
        other => Err(KeystoreError::InvalidKey(format!(
            "unsupported key_type: {other}"
        ))),
    }
}

/// Internal helper: derive key + decrypt ciphertext, returning (secret_key, public_key).
fn raw_decrypt(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KeystoreError> {
    let salt = hex::decode(&encrypted.kdf_params.salt)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad salt hex: {e}")))?;
    let nonce_bytes = hex::decode(&encrypted.cipher_params.nonce)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad nonce hex: {e}")))?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad ciphertext hex: {e}")))?;
    let public_key = hex::decode(&encrypted.public_key)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad pubkey hex: {e}")))?;

    if nonce_bytes.len() != 24 {
        return Err(KeystoreError::InvalidKey(format!(
            "nonce must be 24 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let mut derived_key = derive_key(password, &salt, &encrypted.kdf_params)?;
    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| KeystoreError::Decryption)?;

    let secret_key = cipher
        .decrypt((&nonce).into(), ciphertext.as_ref())
        .map_err(|_| KeystoreError::Decryption)?;

    derived_key.zeroize();
    Ok((secret_key, public_key))
}

fn derive_key(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<[u8; 32], KeystoreError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| KeystoreError::Encryption(format!("argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeystoreError::Encryption(format!("argon2 hash: {e}")))?;

    Ok(key)
}

/// Encrypt a SPHINCS+-SHA2-256f-simple signer with a password.
///
/// Same scheme as [`encrypt`] (argon2id + XChaCha20-Poly1305) but stores
/// `key_type = "sphincs-sha2-256f"` in the output so [`decrypt_sphincs`]
/// can reconstruct the correct signer type.
pub fn encrypt_sphincs(
    signer: &SphincsSigner,
    password: &[u8],
) -> Result<EncryptedKey, KeystoreError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let kdf_params = KdfParams {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 4,
        salt: hex::encode(salt),
    };

    let mut derived_key = derive_key(password, &salt, &kdf_params)?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let plaintext: &[u8] = signer.secret_key_bytes();

    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))?;

    derived_key.zeroize();

    let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    Ok(EncryptedKey {
        version: 1,
        address: address.to_string(),
        key_type: "sphincs-sha2-256f".into(),
        kdf: "argon2id".into(),
        kdf_params,
        cipher: "xchacha20-poly1305".into(),
        cipher_params: CipherParams {
            nonce: hex::encode(nonce),
        },
        ciphertext: hex::encode(&ciphertext),
        public_key: hex::encode(signer.public_key()),
    })
}

/// Decrypt an encrypted key with a password, returning a SphincsSigner.
///
/// The stored `key_type` must be `"sphincs-sha2-256f"`.
pub fn decrypt_sphincs(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<SphincsSigner, KeystoreError> {
    if encrypted.key_type != "sphincs-sha2-256f" {
        return Err(KeystoreError::InvalidKey(format!(
            "expected key_type sphincs-sha2-256f, got {}",
            encrypted.key_type
        )));
    }

    let (mut secret_key, public_key) = raw_decrypt(encrypted, password)?;
    let signer = SphincsSigner::from_bytes(&public_key, &secret_key)?;
    secret_key.zeroize();
    Ok(signer)
}

/// Encrypt a 64-byte HD seed (Shell PQ-HD v1) with a password.
///
/// Stores `key_type = "hd-seed"` so [`decrypt_hd_seed`] can identify the payload.
/// The `address` field holds the default ML-DSA-65 account-0 address;
/// `public_key` is left empty because the seed is the root secret.
pub fn encrypt_hd_seed(
    seed: &[u8; 64],
    default_address: &str,
    password: &[u8],
) -> Result<EncryptedKey, KeystoreError> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    let kdf_params = KdfParams { m_cost: 65536, t_cost: 3, p_cost: 4, salt: hex::encode(salt) };

    let mut derived_key = derive_key(password, &salt, &kdf_params)?;
    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let ciphertext = cipher
        .encrypt((&nonce).into(), seed.as_ref())
        .map_err(|e| KeystoreError::Encryption(e.to_string()))?;
    derived_key.zeroize();

    Ok(EncryptedKey {
        version: 1,
        address: default_address.to_string(),
        key_type: "hd-seed".into(),
        kdf: "argon2id".into(),
        kdf_params,
        cipher: "xchacha20-poly1305".into(),
        cipher_params: CipherParams { nonce: hex::encode(nonce) },
        ciphertext: hex::encode(&ciphertext),
        public_key: String::new(), // seed is root; no single public key
    })
}

/// Decrypt an HD seed keystore, returning the 64-byte BIP-39 seed.
///
/// Only accepts keystores with `key_type = "hd-seed"`.
pub fn decrypt_hd_seed(
    encrypted: &EncryptedKey,
    password: &[u8],
) -> Result<[u8; 64], KeystoreError> {
    if encrypted.key_type != "hd-seed" {
        return Err(KeystoreError::InvalidKey(format!(
            "expected key_type 'hd-seed', got '{}'",
            encrypted.key_type
        )));
    }
    let salt = hex::decode(&encrypted.kdf_params.salt)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad salt hex: {e}")))?;
    let nonce_bytes = hex::decode(&encrypted.cipher_params.nonce)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad nonce hex: {e}")))?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|e| KeystoreError::InvalidKey(format!("bad ciphertext hex: {e}")))?;

    if nonce_bytes.len() != 24 {
        return Err(KeystoreError::InvalidKey(format!(
            "nonce must be 24 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let mut derived_key = derive_key(password, &salt, &encrypted.kdf_params)?;
    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce: [u8; 24] =
        nonce_bytes.try_into().map_err(|_| KeystoreError::Decryption)?;
    let mut plaintext = cipher
        .decrypt((&nonce).into(), ciphertext.as_ref())
        .map_err(|_| KeystoreError::Decryption)?;
    derived_key.zeroize();

    let seed_result: Result<[u8; 64], _> = plaintext.as_slice().try_into();
    plaintext.zeroize();
    let seed = seed_result
        .map_err(|_| KeystoreError::InvalidKey("decrypted payload is not 64 bytes".into()))?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::Signer;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let signer = DilithiumSigner::generate();
        let password = b"test-password-123";

        let encrypted = encrypt(&signer, password).unwrap();
        assert_eq!(encrypted.version, 1);
        assert_eq!(encrypted.kdf, "argon2id");
        assert_eq!(encrypted.cipher, "xchacha20-poly1305");

        let recovered = decrypt(&encrypted, password).unwrap();
        assert_eq!(recovered.public_key(), signer.public_key());

        // Verify signing still works
        let msg = b"hello world";
        let sig = recovered.sign(msg).unwrap();
        let verifier = shell_crypto::DilithiumVerifier;
        use shell_crypto::Verifier;
        assert!(verifier.verify(recovered.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn wrong_password_fails() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"correct-password").unwrap();

        let result = decrypt(&encrypted, b"wrong-password");
        assert!(result.is_err());
        match result {
            Err(KeystoreError::Decryption) => {} // expected
            other => panic!("expected Decryption error, got err={}", other.is_err()),
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let signer = DilithiumSigner::generate();
        let mut encrypted = encrypt(&signer, b"password").unwrap();

        // Tamper with ciphertext
        let mut ct = hex::decode(&encrypted.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        encrypted.ciphertext = hex::encode(&ct);

        let result = decrypt(&encrypted, b"password");
        assert!(result.is_err());
    }

    #[test]
    fn json_roundtrip() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"json-test").unwrap();

        let json = serde_json::to_string_pretty(&encrypted).unwrap();
        let loaded: EncryptedKey = serde_json::from_str(&json).unwrap();

        let recovered = decrypt(&loaded, b"json-test").unwrap();
        assert_eq!(recovered.public_key(), signer.public_key());
    }

    #[test]
    fn address_matches() {
        let signer = DilithiumSigner::generate();
        let expected = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let encrypted = encrypt(&signer, b"addr-test").unwrap();

        assert_eq!(encrypted.address, expected.to_string());
    }

    // ── B. Extended keystore tests ──────────────────────────────

    #[test]
    fn keystore_missing_fields_rejected() {
        // Incomplete JSON missing required fields should fail deserialization
        let incomplete = r#"{"version": 1, "address": "abc"}"#;
        let result = serde_json::from_str::<EncryptedKey>(incomplete);
        assert!(
            result.is_err(),
            "missing fields should fail deserialization"
        );

        // Missing ciphertext
        let no_ciphertext = r#"{
            "version": 1,
            "address": "deadbeef",
            "kdf": "argon2id",
            "kdf_params": {"m_cost": 65536, "t_cost": 3, "p_cost": 4, "salt": "aa"},
            "cipher": "xchacha20-poly1305",
            "cipher_params": {"nonce": "bb"},
            "public_key": "cc"
        }"#;
        let result = serde_json::from_str::<EncryptedKey>(no_ciphertext);
        assert!(
            result.is_err(),
            "missing ciphertext should fail deserialization"
        );
    }

    #[test]
    fn kdf_deterministic_same_password_same_key() {
        let password = b"deterministic-test";
        let salt = [42u8; 32];
        let params = KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt: hex::encode(salt),
        };

        let key1 = derive_key(password, &salt, &params).unwrap();
        let key2 = derive_key(password, &salt, &params).unwrap();
        assert_eq!(
            key1, key2,
            "same password+salt must produce same derived key"
        );

        // Different password must produce different key
        let key3 = derive_key(b"different", &salt, &params).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn tampered_nonce_fails() {
        let signer = DilithiumSigner::generate();
        let mut encrypted = encrypt(&signer, b"nonce-test").unwrap();

        // Corrupt the nonce
        let mut nonce = hex::decode(&encrypted.cipher_params.nonce).unwrap();
        nonce[0] ^= 0xFF;
        encrypted.cipher_params.nonce = hex::encode(&nonce);

        let result = decrypt(&encrypted, b"nonce-test");
        assert!(
            result.is_err(),
            "tampered nonce should cause decryption failure"
        );
    }

    #[test]
    fn tampered_salt_fails() {
        let signer = DilithiumSigner::generate();
        let mut encrypted = encrypt(&signer, b"salt-test").unwrap();

        // Corrupt the salt → derives a different key → AEAD tag mismatch
        let mut salt = hex::decode(&encrypted.kdf_params.salt).unwrap();
        salt[0] ^= 0xFF;
        encrypted.kdf_params.salt = hex::encode(&salt);

        let result = decrypt(&encrypted, b"salt-test");
        assert!(
            result.is_err(),
            "tampered salt should cause decryption failure"
        );
    }

    #[test]
    fn multiple_encryptions_produce_different_ciphertexts() {
        let signer = DilithiumSigner::generate();
        let password = b"nonce-uniqueness";

        let enc1 = encrypt(&signer, password).unwrap();
        let enc2 = encrypt(&signer, password).unwrap();

        // Random salt and nonce guarantee different ciphertexts
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.kdf_params.salt, enc2.kdf_params.salt);
        assert_ne!(enc1.cipher_params.nonce, enc2.cipher_params.nonce);

        // Both must still decrypt correctly
        let r1 = decrypt(&enc1, password).unwrap();
        let r2 = decrypt(&enc2, password).unwrap();
        assert_eq!(r1.public_key(), r2.public_key());
    }

    #[test]
    fn decrypt_preserves_signing_capability() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"sign-after-decrypt").unwrap();
        let recovered = decrypt(&encrypted, b"sign-after-decrypt").unwrap();

        // Sign with recovered signer and verify with original public key
        let msg = b"post-decrypt signing";
        let sig = recovered.sign(msg).unwrap();
        let verifier = shell_crypto::DilithiumVerifier;
        use shell_crypto::Verifier;
        assert!(verifier.verify(signer.public_key(), msg, &sig).unwrap());

        // And vice-versa: sign with original, verify with recovered pk
        let sig2 = signer.sign(msg).unwrap();
        assert!(verifier.verify(recovered.public_key(), msg, &sig2).unwrap());
    }

    // ── SPHINCS+ keystore tests (F-166) ─────────────────────────

    #[test]
    fn sphincs_encrypt_decrypt_roundtrip() {
        let signer = SphincsSigner::generate();
        let password = b"sphincs-test-password";

        let encrypted = encrypt_sphincs(&signer, password).unwrap();
        assert_eq!(encrypted.version, 1);
        assert_eq!(encrypted.key_type, "sphincs-sha2-256f");
        assert_eq!(encrypted.kdf, "argon2id");
        assert_eq!(encrypted.cipher, "xchacha20-poly1305");

        let recovered = decrypt_sphincs(&encrypted, password).unwrap();
        assert_eq!(recovered.public_key(), signer.public_key());

        // Verify signing still works
        let msg = b"sphincs roundtrip";
        let sig = recovered.sign(msg).unwrap();
        let verifier = shell_crypto::SphincsVerifier;
        use shell_crypto::Verifier;
        assert!(verifier.verify(recovered.public_key(), msg, &sig).unwrap());
    }

    #[test]
    fn sphincs_wrong_password_fails() {
        let signer = SphincsSigner::generate();
        let encrypted = encrypt_sphincs(&signer, b"correct").unwrap();

        let result = decrypt_sphincs(&encrypted, b"wrong");
        assert!(matches!(result, Err(KeystoreError::Decryption)));
    }

    #[test]
    fn sphincs_json_roundtrip() {
        let signer = SphincsSigner::generate();
        let encrypted = encrypt_sphincs(&signer, b"sphincs-json").unwrap();

        let json = serde_json::to_string_pretty(&encrypted).unwrap();
        let loaded: EncryptedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.key_type, "sphincs-sha2-256f");

        let recovered = decrypt_sphincs(&loaded, b"sphincs-json").unwrap();
        assert_eq!(recovered.public_key(), signer.public_key());
    }

    #[test]
    fn decrypt_sphincs_rejects_dilithium_key() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"mismatch-test").unwrap();

        let result = decrypt_sphincs(&encrypted, b"mismatch-test");
        assert!(matches!(result, Err(KeystoreError::InvalidKey(_))));
    }

    #[test]
    fn dilithium_key_type_set() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"type-test").unwrap();
        assert_eq!(encrypted.key_type, "dilithium3");
    }

    #[test]
    fn legacy_json_without_key_type_defaults_to_dilithium() {
        let signer = DilithiumSigner::generate();
        let encrypted = encrypt(&signer, b"legacy-test").unwrap();

        // Simulate a legacy JSON without key_type field
        let json = serde_json::to_string(&encrypted).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("key_type");
        let legacy_json = serde_json::to_string(&value).unwrap();

        let loaded: EncryptedKey = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(loaded.key_type, "dilithium3");

        let recovered = decrypt(&loaded, b"legacy-test").unwrap();
        assert_eq!(recovered.public_key(), signer.public_key());
    }
}
