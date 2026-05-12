# Feature: Keystore

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

`shell-keystore` encrypts and decrypts post-quantum private keys for
Shell-Chain wallets and validator nodes.  It is the single source of truth for
the on-disk secret-key storage format.

Design goals:
- **Memory-hard KDF** — argon2id (m=64 MiB, t=3, p=4) resists GPU/ASIC
  brute-force attacks against stolen keystore files.
- **Authenticated encryption** — XChaCha20-Poly1305 (24-byte nonce, safe for
  random generation) provides confidentiality and ciphertext integrity.
- **Address binding** — the `address` field (`pq1…` Bech32m) derived from the
  public key is embedded in the JSON so callers can identify a key without
  decrypting; the derivation is verified on `decrypt` to catch key corruption.
- **Multi-algorithm** — supports Dilithium3 (legacy), ML-DSA-65 / FIPS 204
  (`mldsa65`), and SPHINCS+-SHA2-256f (`sphincs-sha2-256f`).
- **Type-erased dispatch** — `decrypt_any` returns `Box<dyn Signer>` so callers
  need not know the algorithm at compile time.

The crate has no network dependencies and performs no RPC calls.  It depends on
`shell-crypto` (signers) and `shell-primitives` (address derivation).

## 2. Public API surface (with file:line)

All items re-exported from `shell-chain/crates/keystore/src/lib.rs`.

### Encryption / decryption functions (`crypto.rs`)

| Symbol | Signature | Notes |
|--------|-----------|-------|
| `encrypt` | `(signer: &DilithiumSigner, password: &[u8]) -> Result<EncryptedKey, KeystoreError>` | Dilithium3 key → `EncryptedKey` JSON |
| `decrypt` | `(encrypted: &EncryptedKey, password: &[u8]) -> Result<DilithiumSigner, KeystoreError>` | Decrypts Dilithium3; verifies address binding |
| `encrypt_mldsa` | `(signer: &MlDsaSigner, password: &[u8]) -> Result<EncryptedKey, KeystoreError>` | ML-DSA-65 / FIPS 204 key → `EncryptedKey`; `key_type = "mldsa65"` |
| `decrypt_mldsa` | `(encrypted: &EncryptedKey, password: &[u8]) -> Result<MlDsaSigner, KeystoreError>` | Enforces `key_type == "mldsa65"` before decryption |
| `encrypt_sphincs` | `(signer: &SphincsSigner, password: &[u8]) -> Result<EncryptedKey, KeystoreError>` | SPHINCS+-SHA2-256f key → `EncryptedKey`; `key_type = "sphincs-sha2-256f"` |
| `decrypt_sphincs` | `(encrypted: &EncryptedKey, password: &[u8]) -> Result<SphincsSigner, KeystoreError>` | Decrypts SPHINCS+ key |
| `decrypt_any` | `(encrypted: &EncryptedKey, password: &[u8]) -> Result<Box<dyn Signer>, KeystoreError>` | Type-erased dispatch: routes to `decrypt`, `decrypt_mldsa`, or `decrypt_sphincs` by `key_type` field |

Internal helpers (not public):
- `derive_key(password, salt, params) -> Result<[u8; 32], KeystoreError>` — argon2id KDF
- `raw_decrypt(encrypted, password) -> Result<(Vec<u8>, Vec<u8>), KeystoreError>` — shared decrypt primitive used by all typed wrappers

### Types (`types.rs`)

| Symbol | Kind | Notes |
|--------|------|-------|
| `EncryptedKey` | struct | JSON-serialisable keystore file; see schema below |
| `KdfParams` | struct | `{m_cost: u32, t_cost: u32, p_cost: u32, salt: String}` — hex-encoded salt |
| `CipherParams` | struct | `{nonce: String}` — hex-encoded 24-byte XChaCha20 nonce |
| `KeystoreError` | enum | `Encryption(String)` / `Decryption` / `InvalidKey(String)` / `Serialization(serde_json::Error)` / `Crypto(shell_crypto::CryptoError)` |

#### `EncryptedKey` JSON schema

```json
{
  "version": 1,
  "address": "pq1...",
  "key_type": "dilithium3",
  "kdf": "argon2id",
  "kdf_params": { "m_cost": 65536, "t_cost": 3, "p_cost": 4, "salt": "<hex32>" },
  "cipher": "xchacha20-poly1305",
  "cipher_params": { "nonce": "<hex24>" },
  "ciphertext": "<hex>",
  "public_key": "<hex>"
}
```

- `key_type` defaults to `"dilithium3"` when absent (backward-compat).
- `address` is `pq1…` Bech32m derived as `blake3(version‖algo_id‖pubkey)[0..20]`
  (CONSTITUTION §2.3, ADR-001).
- `version` is always `1` in the current format.

### KDF parameters (hardcoded defaults, `crypto.rs`)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `m_cost` | 65536 KiB (64 MiB) | Memory cost |
| `t_cost` | 3 | Iterations |
| `p_cost` | 4 | Parallelism |
| Nonce length | 24 bytes | XChaCha20 extended nonce; safe for random generation |
| Salt length | 32 bytes | Random per encryption |

## 3. Implementation map (table)

| Concern | Module | File |
|---------|--------|------|
| argon2id KDF, XChaCha20 AEAD, encrypt/decrypt logic | `crypto` | `keystore/src/crypto.rs` |
| JSON types: `EncryptedKey`, `KdfParams`, `CipherParams`, `KeystoreError` | `types` | `keystore/src/types.rs` |
| Public re-exports | `lib.rs` | `keystore/src/lib.rs` |
| Integration tests (encrypt/decrypt round-trip) | — | `keystore/tests/` |

## 4. Invariants (cross-ref CONSTITUTION + ADRs)

- **ADR-001 (PQ signature stack)**: `EncryptedKey.key_type` must be one of
  `"dilithium3"`, `"mldsa65"`, or `"sphincs-sha2-256f"`.  Any other value
  causes `decrypt_any` to return `KeystoreError::InvalidKey`.
- **CONSTITUTION §2.3 (address derivation)**: `address` is computed as
  `blake3(0x01 ‖ algo_id ‖ pubkey)[0..20]` encoded as Bech32m `pq1…`.
  `encrypt`/`encrypt_mldsa`/`encrypt_sphincs` all call
  `Address::from_public_key` from `shell-primitives`.  Storing a hex `0x…`
  address in this field violates the invariant (the format spec does not
  validate this at deserialisation time — callers must enforce it).
- **Zeroization**: derived key material (`derived_key: [u8; 32]`) is
  `zeroize()`-d after use in all `encrypt_*` and `decrypt_*` paths.  Secret key
  byte buffers are also zeroized after signer construction.
- **AEAD integrity**: `decrypt` fails with `KeystoreError::Decryption` if the
  XChaCha20-Poly1305 authentication tag does not verify — wrong password or
  corrupted ciphertext cannot be distinguished (by design).
- **Version pinning**: `EncryptedKey.version` must be `1`; future format
  changes must increment this field and add a migration path.

## 5. Tests

```
cargo test -p shell-keystore
```

Key tests (inline `#[cfg(test)]` in `types.rs` and `crypto.rs`, plus integration tests in `tests/`):

| Test | Module |
|------|--------|
| `encrypt_decrypt_roundtrip_dilithium3` | `crypto.rs` |
| `encrypt_decrypt_roundtrip_mldsa` | `crypto.rs` |
| `encrypt_decrypt_roundtrip_sphincs` | `crypto.rs` |
| `decrypt_any_dispatches_by_key_type` | `crypto.rs` |
| `wrong_password_returns_decryption_error` | `crypto.rs` |
| `derived_key_is_zeroized` | `crypto.rs` |
| `kdf_params_default_values` | `types.rs` |
| `kdf_params_serialization_roundtrip` | `types.rs` |
| `kdf_params_clone` | `types.rs` |
| `cipher_params_serialization_roundtrip` | `types.rs` |
| `encrypted_key_serialization_roundtrip` | `types.rs` |
| `encrypted_key_default_key_type_on_missing_field` | `types.rs` |
| `encrypted_key_explicit_key_type_sphincs` | `types.rs` |
| `keystore_error_encryption_display` | `types.rs` |
| `keystore_error_decryption_display` | `types.rs` |
| `keystore_error_invalid_key_display` | `types.rs` |
| `keystore_error_from_serde_json` | `types.rs` |
| `default_key_type_is_dilithium3` | `types.rs` |

## 6. Related ADRs

- **ADR-001** — Post-quantum signature stack (Dilithium3 → ML-DSA-65 migration path)
- CONSTITUTION §2.3 — Address derivation formula (`blake3` + Bech32m `pq1…`)
- CONSTITUTION T-1 — PQ-native invariant (no ECDSA / secp256k1 key storage)

## 7. Known limitations / open work

- `EncryptedKey.address` is not validated during JSON deserialisation — it is
  purely informational.  Address binding is only checked in `decrypt` by
  re-deriving the address from the decrypted public key.
- `key_type = ""` (empty string) is treated as `"dilithium3"` in `decrypt_any`
  for backward compatibility with very early keystore files.
- No streaming encryption for large key material; all secret bytes are held in
  memory during encrypt/decrypt.
- `KdfParams` are hardcoded to the recommended defaults in the `encrypt_*`
  functions — there is no public API to override them without constructing the
  params manually.
- ML-DSA-65 is the forward target, but existing wallets and the SG testnet
  still use `dilithium3` keystores; no automated migration tooling exists.

## 8. Change log

- v0.22.2 (2026-05): spec written from source; all three algorithm paths
  documented; `decrypt_any` dispatch table documented; address-binding
  invariant and zeroization invariant added
