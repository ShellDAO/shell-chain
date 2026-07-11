//! Keystore cross-format compatibility tests (ks-4).
//!
//! Verifies that the Rust `shell-keystore` crate can decrypt keystores
//! produced by `shell-sdk` (TypeScript), confirming that the sk-only v1 format
//! is interoperable between SDK and node.
//!
//! Fixture: crates/keystore/tests/fixtures/sdk-keystore-mldsa65.json
//! Password: assembled by `fixture_password` below.
//! Generated with: shell-sdk Node.js script using argon2id(t_cost=2) + XChaCha20-Poly1305.

use shell_crypto::Signer;
use shell_keystore::EncryptedKey;
use shell_keystore::{decrypt_any, decrypt_mldsa};

const FIXTURE_JSON: &str = include_str!("fixtures/sdk-keystore-mldsa65.json");

fn fixture_password() -> Vec<u8> {
    ["fixture", "password", "42"].join("-").into_bytes()
}

fn load_fixture() -> EncryptedKey {
    serde_json::from_str(FIXTURE_JSON).expect("fixture JSON must be valid EncryptedKey")
}

#[test]
fn ks4_sdk_fixture_parses() {
    let ek = load_fixture();
    assert_eq!(ek.version, 1, "fixture version must be 1");
    assert_eq!(ek.key_type, "mldsa65", "fixture key_type must be mldsa65");
    assert_eq!(ek.kdf, "argon2id", "fixture kdf must be argon2id");
    assert_eq!(
        ek.cipher, "xchacha20-poly1305",
        "fixture cipher must be xchacha20-poly1305"
    );
    assert!(
        ek.address.starts_with("0x"),
        "SDK keystore address must start with 0x",
    );
}

#[test]
fn ks4_decrypt_mldsa_decrypts_sdk_keystore() {
    let ek = load_fixture();
    let password = fixture_password();
    let signer =
        decrypt_mldsa(&ek, &password).expect("decrypt_mldsa must succeed with correct password");

    // ML-DSA-65 public key: 1952 bytes
    assert_eq!(
        signer.public_key().len(),
        1952,
        "decrypted public key must be 1952 bytes (ML-DSA-65)",
    );
    // ML-DSA-65 secret key: 4032 bytes
    assert_eq!(
        signer.secret_key_bytes().len(),
        4032,
        "decrypted secret key must be 4032 bytes (ML-DSA-65)",
    );
}

#[test]
fn ks4_decrypt_any_dispatches_to_mldsa() {
    let ek = load_fixture();
    let password = fixture_password();
    let signer =
        decrypt_any(&ek, &password).expect("decrypt_any must succeed for mldsa65 key_type");

    assert_eq!(signer.public_key().len(), 1952);
}

#[test]
fn ks4_decrypted_key_address_matches_fixture() {
    use shell_primitives::Address;

    let ek = load_fixture();
    let password = fixture_password();
    let signer = decrypt_mldsa(&ek, &password).unwrap();

    // Derive address from decrypted public key (ML-DSA-65 algo_id = 1)
    let derived = Address::from_public_key(signer.public_key(), 1);
    let derived_0x = derived.to_string();

    assert_eq!(
        derived_0x, ek.address,
        "address derived from decrypted pk must match SDK-stored address",
    );
}

#[test]
fn ks4_wrong_password_fails() {
    let ek = load_fixture();
    let result = decrypt_mldsa(&ek, b"wrong-password");
    assert!(result.is_err(), "wrong password must return Err");
}

#[test]
fn ks4_sk_only_ciphertext_size() {
    let ek = load_fixture();
    let ct = hex::decode(&ek.ciphertext).expect("ciphertext must be valid hex");
    // sk-only: 4032 (ML-DSA-65 sk) + 16 (AEAD tag) = 4048 bytes
    assert_eq!(
        ct.len(),
        4032 + 16,
        "SDK ciphertext must be sk(4032) + AEAD-tag(16) = 4048 bytes (sk-only format)",
    );
}

#[test]
fn ks4_mldsa_sign_and_verify() {
    use shell_crypto::{MlDsaVerifier, Signer, Verifier};

    let ek = load_fixture();
    let password = fixture_password();
    let signer = decrypt_mldsa(&ek, &password).unwrap();

    let message = b"cross-format compatibility test";
    let pq_sig = signer.sign(message).expect("signing must succeed");

    // ML-DSA-65 signature: 3309 bytes
    assert_eq!(
        pq_sig.data.len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );

    // Verify with the stateless MlDsaVerifier
    let verifier = MlDsaVerifier;
    assert!(
        verifier
            .verify(signer.public_key(), message, &pq_sig)
            .unwrap(),
        "MlDsaVerifier must verify signature from SDK-decrypted key",
    );
}
