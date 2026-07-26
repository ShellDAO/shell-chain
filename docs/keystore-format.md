# Shell-Chain Keystore Format Specification

> Version 1 · Post-Quantum Encrypted Key Storage

---

## Table of Contents

1. [Overview](#1-overview)
2. [JSON Schema (v1)](#2-json-schema-v1)
3. [Field Descriptions](#3-field-descriptions)
4. [Supported Algorithms](#4-supported-algorithms)
5. [KDF: argon2id](#5-kdf-argon2id)
6. [Cipher: XChaCha20-Poly1305](#6-cipher-xchacha20-poly1305)
7. [Address Derivation](#7-address-derivation)
8. [Encrypt / Decrypt Algorithm](#8-encrypt--decrypt-algorithm)
9. [Example Keystores](#9-example-keystores)
10. [SDK Compatibility](#10-sdk-compatibility)
11. [Security Notes](#11-security-notes)
12. [Migration from Pre-v1 (sk+pk) Format](#12-migration-from-pre-v1-skpk-format)

---

## 1. Overview

A Shell-chain keystore is a JSON file that stores an encrypted post-quantum private key.
It is produced by `shell-node key generate` and consumed by `shell-node run`, `tx send`,
and the TypeScript SDK (`shell-sdk`).

**Design decisions:**

- **sk-only ciphertext** — only the secret key is encrypted. The public key is stored in
  cleartext (`public_key` field) because it is by definition public. This is more compact,
  KMS-friendly, and avoids the split-point ambiguity in older sk‖pk encodings.
- **argon2id KDF** — memory-hard, OWASP-recommended for password-based key derivation.
- **XChaCha20-Poly1305 AEAD** — authenticated encryption with 192-bit nonce (no nonce reuse
  risk for a single file) and 128-bit Poly1305 MAC.
- **No password in the file** — the derived key is never stored; only the ciphertext and MAC.

---

## 2. JSON Schema (v1)

```json
{
  "version": 1,
  "address": "0x<64-lowercase-hex>",
  "key_type": "<algorithm>",
  "kdf": "argon2id",
  "kdf_params": {
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "salt": "<32-byte-hex>"
  },
  "cipher": "xchacha20-poly1305",
  "cipher_params": {
    "nonce": "<24-byte-hex>"
  },
  "ciphertext": "<hex>",
  "public_key": "<hex>"
}
```

---

## 3. Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u32` | Always `1`. Future breaking changes increment this. |
| `address` | `string` | Canonical `0x` + 64 lowercase hex address derived from the public key (see §7). |
| `key_type` | `string` | Algorithm identifier: `"dilithium3"` or `"mldsa65"` (see §4). |
| `kdf` | `string` | Always `"argon2id"`. |
| `kdf_params.m_cost` | `u32` | Argon2id memory cost in KiB (CLI default: `65536` = 64 MiB). |
| `kdf_params.t_cost` | `u32` | Argon2id time cost / iterations (CLI default: `3`). |
| `kdf_params.p_cost` | `u32` | Argon2id parallelism degree (CLI default: `4`). |
| `kdf_params.salt` | `string` | Random 32-byte salt, hex-encoded. Unique per keystore. |
| `cipher` | `string` | Always `"xchacha20-poly1305"`. |
| `cipher_params.nonce` | `string` | Random 24-byte nonce, hex-encoded. Unique per keystore. |
| `ciphertext` | `string` | Authenticated ciphertext of the **secret key only**, hex-encoded. Includes 16-byte Poly1305 MAC appended by the AEAD library. |
| `public_key` | `string` | Raw public key bytes, hex-encoded. Used to verify decryption and derive the address. |

### Ciphertext Length

| Algorithm | SK length | Ciphertext length (SK + 16-byte MAC) |
|-----------|-----------|--------------------------------------|
| `dilithium3` | 4000 B | 4016 B (8032 hex chars) |
| `mldsa65` | 4032 B | 4048 B (8096 hex chars) |

---

## 4. Supported Algorithms

| `key_type` | Standard | Public Key | Secret Key | Notes |
|------------|----------|------------|------------|-------|
| `mldsa65` | ML-DSA-65 (FIPS 204) | 1952 B | 4032 B | **Primary** (`--algorithm mldsa65`) |
| `dilithium3` | Dilithium3 (NIST Round 3 reference) | 1952 B | 4000 B | Legacy-compatible active path; use with `--algorithm dilithium3` |

Both algorithms use the same keystore format. The `key_type` field tells the runtime which
decryption path to use.

---

## 5. KDF: argon2id

The password-based key derivation function is **argon2id** (OWASP recommended, NIST-approved).

```
dk = argon2id(
    password  = user_password_utf8,
    salt      = kdf_params.salt (32 bytes),
    m_cost    = kdf_params.m_cost (KiB),
    t_cost    = kdf_params.t_cost,
    p_cost    = kdf_params.p_cost,
    key_len   = 32 bytes
)
```

The derived key `dk` is 32 bytes and is used directly as the XChaCha20-Poly1305 key.
It is zeroed from memory immediately after use.

**CLI defaults** (v0.27.2):

| Parameter | Default | Notes |
|-----------|---------|-------|
| `m_cost` | 65536 KiB (64 MiB) | Tunable; higher = more GPU-resistant |
| `t_cost` | 3 | Tunable |
| `p_cost` | 4 | Matches typical core count |

When opening a keystore, implementations must reject Argon2id parameters above
131,072 KiB of memory, 10 iterations, or parallelism 16. These limits keep
untrusted keystore files from requesting unbounded local work; the standard
64 MiB profile and SDK-compatible profiles remain within the accepted range.

The SDK may use different params (e.g. lower for test fixtures) — they are always stored in the
file and re-read at decrypt time, so interoperability is preserved.

---

## 6. Cipher: XChaCha20-Poly1305

```
ciphertext = xchacha20_poly1305_seal(
    key   = dk (32 bytes from KDF),
    nonce = cipher_params.nonce (24 bytes),
    aad   = b"" (empty),
    msg   = secret_key_bytes
)
```

The output includes the 16-byte Poly1305 authentication tag appended to the ciphertext.
Decryption will fail (return error) if the tag does not match — i.e. wrong password or
corrupted data.

---

## 7. Address Derivation

```
address_bytes = blake3(algo_id || public_key_bytes)   // full 32-byte BLAKE3 output
address       = "0x" + lowercase_hex(address_bytes)
```

The `algo_id` used in the address derivation scheme:

| `key_type` | `algo_id` |
|------------|-----------|
| `dilithium3` | `0` |
| `mldsa65` | `1` |

Shell Chain addresses are encoded as `0x` + 64 lowercase hex everywhere user-facing:
CLI, explorer, RPC, genesis, SDK APIs, and the keystore `address` field. Legacy
keystores with a `pq1...` address field can still be inspected and decrypted when the
public key is valid; run `shell-node key migrate` to rewrite them in the canonical format.

---

## 8. Encrypt / Decrypt Algorithm

### Encrypt

```
1. Generate random salt (32 bytes) and nonce (24 bytes)
2. dk = argon2id(password, salt, m_cost, t_cost, p_cost, 32)
3. derive public_key from secret_key
4. address_bytes = blake3(algo_id || public_key)
5. address = "0x" + lowercase_hex(address_bytes)
6. Write JSON: version=1, address=0x-encoded, key_type, kdf_params+salt,
              cipher_params+nonce, ciphertext=hex(ciphertext), public_key=hex(public_key)
7. Zeroize dk
```

> **Note (F-PQ1-ONLY):** Step 5 uses `xchacha20_poly1305_seal` on the secret key,
> then the result is written in step 6. The step numbering above was condensed for clarity.

### Decrypt

```
1. Read salt, nonce, ciphertext_bytes, public_key_bytes from JSON
2. dk = argon2id(password, salt, m_cost, t_cost, p_cost, 32)
3. secret_key = xchacha20_poly1305_open(dk, nonce, b"", ciphertext_bytes)
                  → error if MAC fails (wrong password or corrupted)
4. Verify: derive public_key' from secret_key
           if public_key' != public_key_bytes → error
5. Return secret_key
6. Zeroize dk
```

---

## 9. Example Keystores

### Dilithium3 (generated by `shell-node key generate`)

```json
{
  "version": 1,
  "address": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "key_type": "dilithium3",
  "kdf": "argon2id",
  "kdf_params": {
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "salt": "a1b2c3d4..."
  },
  "cipher": "xchacha20-poly1305",
  "cipher_params": {
    "nonce": "e5f6a7b8..."
  },
  "ciphertext": "...(8032 hex chars)...",
  "public_key": "...(3904 hex chars)..."
}
```

### ML-DSA-65 (generated by `shell-node key generate --algorithm mldsa65`)

Same structure; `key_type` is `"mldsa65"` and ciphertext/public_key are slightly longer.

---

## 10. SDK Compatibility

The TypeScript SDK (`shell-sdk`) uses the same format. Key details:

- `encryptKeystore()` writes **sk-only** ciphertext (matching Rust CLI)
- `decryptKeystore()` reads `public_key` from the JSON for address verification
- `SIG_IDS`: `{ dilithium3: 0, mldsa65: 1 }` — used to derive the correct address

The SDK and CLI are **fully cross-compatible** since shell-chain v0.21.0 / shell-sdk v0.7.0:
- A Rust CLI keystore can be decrypted by `shell-sdk`
- An SDK keystore can be decrypted by the Rust CLI / `shell-keystore` crate

---

## 11. Security Notes

1. **File permissions** — `shell-node` rejects keystores with world- or group-readable
   permissions (`chmod 600 keystore.json` before use).
2. **Never commit keystores to git** — add `*.json` (or specific paths) to `.gitignore`.
3. **Use unique salts and nonces** — each `key generate` call generates fresh random values.
4. **Password strength** — argon2id (64 MiB, t=3, p=4) provides strong brute-force resistance
   for passwords ≥ 12 characters. Use a password manager.
5. **Memory zeroization** — derived keys are zeroized after use in the Rust implementation.

---

## 12. Migration from Pre-v1 (sk+pk) Format

Before F-TESTNET-FIXES (v0.20.0), the SDK `encryptKeystore()` stored `sk ‖ pk` in the
ciphertext. This format is **not supported** by shell-chain v0.21.0+ / shell-sdk v0.7.0+.

If you have keystores produced by `shell-sdk < 0.7.0`, re-encrypt them:

```bash
# 1. Decrypt with old SDK → extract sk
# 2. Re-encrypt with current shell-node
echo "old-password" | shell-node --password-stdin key generate \
    --algorithm dilithium3 \
    --output new-keystore.json
# (then manually import your existing key material)
```

Or use the `shell-node key migrate` subcommand (v0.21.0+):

```bash
shell-node --password-file /run/secrets/pw key migrate \
    --input old-keystore.json \
    --output new-keystore.json
```

---

## See Also

- [CLI Automation Guide](cli-automation.md)
- [Node CLI Reference](node-cli.md)
- [Post-Quantum Crypto Guide](PQ_CRYPTO_GUIDE.md)
- `crates/keystore/src/types.rs` — Rust type definitions
- `crates/keystore/src/crypto.rs` — encrypt/decrypt implementation
- `shell-sdk/src/keystore.ts` — TypeScript SDK implementation
