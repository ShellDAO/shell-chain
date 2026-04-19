# Shell-Chain Post-Quantum Cryptography Guide

Shell-chain is built from the ground up with post-quantum cryptographic primitives, making it resistant to attacks from both classical and quantum computers.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Native Account Abstraction Guide](ACCOUNT_ABSTRACTION_GUIDE.md)

---

## Table of Contents

1. [Why Post-Quantum Cryptography Matters](#why-post-quantum-cryptography-matters)
2. [Algorithms Used](#algorithms-used)
3. [Key Generation](#key-generation)
4. [Keystore Format](#keystore-format)
5. [Address Derivation](#address-derivation)
6. [Signature Sizes and Performance](#signature-sizes-and-performance)
7. [Incompatibility with ECDSA and MetaMask](#incompatibility-with-ecdsa-and-metamask)
8. [Future: SPHINCS+ and Hybrid Schemes](#future-sphincs-and-hybrid-schemes)

---

## Why Post-Quantum Cryptography Matters

Traditional blockchains (Bitcoin, Ethereum) rely on **ECDSA** (Elliptic Curve Digital Signature Algorithm) for transaction signatures. ECDSA's security depends on the hardness of the **elliptic curve discrete logarithm problem** — a problem that quantum computers can solve efficiently using **Shor's algorithm**.

A sufficiently powerful quantum computer could:

- **Forge signatures** on any transaction by recovering private keys from public keys.
- **Steal funds** from any account whose public key has been revealed (i.e., any account that has ever sent a transaction).
- **Rewrite history** by forging block proposer signatures.

While large-scale quantum computers don't exist yet, the threat is real:

- **NIST** finalized the first post-quantum cryptography standards in 2024.
- **"Harvest now, decrypt later"** attacks mean adversaries can record blockchain traffic today and break it once quantum computers arrive.
- Key transitions take years — blockchains must migrate *before* quantum computers become practical.

Shell-chain eliminates this risk by using **NIST-standardized lattice-based** and **hash-based** signature schemes **before Q-Day** — no migration, no emergency hard fork needed.

---

## Algorithms Used

### CRYSTALS-Dilithium3 (Primary Signature Algorithm)

Shell-chain's default signature algorithm. Based on the hardness of lattice problems (Module-LWE and Module-SIS), Dilithium3 provides **NIST Level 3** security (128-bit post-quantum security, comparable to AES-192).

| Property | Value |
|----------|-------|
| **Standard** | NIST FIPS 204 (ML-DSA-65, draft) |
| **Security Level** | NIST Level 3 (128-bit PQ) |
| **Public Key Size** | 1,952 bytes |
| **Secret Key Size** | 4,032 bytes |
| **Signature Size** | 3,309 bytes |
| **Implementation** | `pqcrypto-dilithium` crate (`dilithium3` module) |

### Keccak-256 (Hashing)

Used for Ethereum-compatible hashing surfaces such as `web3_sha3` and other
EVM-facing data structures. **It is no longer used for Shell account address
derivation.**

### BLAKE3 (Internal Hashing)

Used for Shell account address derivation and other high-performance internal
operations where Ethereum compatibility is not required.

```text
address = blake3(version || algo_id || public_key)[0..20]
```

### Argon2id (Key Derivation)

Used in the keystore for password-based key derivation:

| Parameter | Value |
|-----------|-------|
| Memory | 64 MiB (65,536 KiB) |
| Iterations | 3 |
| Parallelism | 4 threads |
| Output | 32 bytes |

### XChaCha20-Poly1305 (Keystore Encryption)

AEAD cipher used to encrypt private keys at rest. The 24-byte nonce is safe for random generation (no nonce reuse risk).

---

## Key Generation

### Command

```bash
shell-node key generate --output keystore.json
```

### What happens internally

1. **CSPRNG key generation** — The `dilithium3::keypair()` function generates a random keypair using the system's cryptographically secure random number generator.

2. **Address derivation** — The 20-byte address is computed as:
   ```
   address = blake3(version || algo_id || public_key)[0..20]
   ```

3. **Password prompt** — You enter an encryption password.

4. **Key derivation** — Argon2id derives a 32-byte encryption key from your password and a random 32-byte salt.

5. **Encryption** — The secret key is encrypted with XChaCha20-Poly1305 using the derived key and a random 24-byte nonce.

6. **Keystore file** — The encrypted key, public key, address, and all parameters are written to a JSON file.

### Security properties

- **Secret keys are zeroized** in memory after use via the `zeroize` crate. When a `DilithiumSigner` is dropped, its secret key bytes are overwritten with zeros.
- **The derived encryption key is zeroized** immediately after encrypting/decrypting.
- **Each encryption uses a unique salt and nonce**, so encrypting the same key with the same password produces different ciphertext.

---

## Keystore Format

The keystore file is a JSON document inspired by the Ethereum Web3 Secret Storage format, adapted for post-quantum keys.

### Structure

```json
{
  "version": 1,
  "address": "742d35cc6634c0532925a3b844bc9e7595f2bd18",
  "key_type": "dilithium3",
  "kdf": "argon2id",
  "kdf_params": {
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "salt": "0a1b2c3d...64_hex_chars"
  },
  "cipher": "xchacha20-poly1305",
  "cipher_params": {
    "nonce": "0a1b2c3d...48_hex_chars"
  },
  "ciphertext": "encrypted_secret_key_hex...",
  "public_key": "dilithium3_public_key_hex..."
}
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `version` | `u32` | Format version (always `1`) |
| `address` | `String` | Legacy hex address string stored for compatibility; CLI / RPC surfaces display canonical `pq1...` |
| `key_type` | `String` | `"dilithium3"` or `"sphincs-sha2-256f"` |
| `kdf` | `String` | Key derivation function (always `"argon2id"`) |
| `kdf_params.m_cost` | `u32` | Memory cost in KiB (65,536 = 64 MiB) |
| `kdf_params.t_cost` | `u32` | Time cost / iterations (3) |
| `kdf_params.p_cost` | `u32` | Parallelism degree (4) |
| `kdf_params.salt` | `String` | 32-byte random salt (hex) |
| `cipher` | `String` | AEAD cipher (always `"xchacha20-poly1305"`) |
| `cipher_params.nonce` | `String` | 24-byte random nonce (hex) |
| `ciphertext` | `String` | Encrypted secret key (hex) |
| `public_key` | `String` | Full public key (hex), used for verification |

### Inspecting a keystore

```bash
shell-node key inspect keystore.json
# Output: Address: pq1...
```

This does **not** require the password. The keystore stores the address in
plaintext for compatibility, while CLI output uses the canonical `pq1...` form.

---

## Address Derivation

Shell-chain addresses remain **20 bytes internally**, but their canonical
external form is `pq1...`.

```
version || algo_id || public_key  ──→  blake3()  ──→  32-byte hash  ──→  take bytes [0..20]  ──→  20-byte address
                                                                         └──── Bech32m encode ───→  pq1...
```

### Step by step

1. Start with the derivation version, the signature algorithm ID, and the raw public key.
2. Compute `blake3(version || algo_id || public_key)` → 32-byte hash.
3. Take the first 20 bytes (bytes 0–19 inclusive).
4. Encode that 20-byte value as Bech32m with HRP `pq` for user-facing display.

### Important notes

- The same public key always produces the same address (deterministic).
- The same public key under different supported algorithms produces different addresses because `algo_id` is part of the preimage.
- Different public keys produce different addresses (collision-resistant, 160-bit security).
- Unlike Ethereum, the public key is a Dilithium3 key (1,952 bytes), not an ECDSA key (64 bytes). This means you **cannot** derive the public key from a signature as you can with ECDSA's `ecrecover`.
- The public key must be registered on-chain with the first transaction. Query it via `shell_getPqPubkey`.

---

## Signature Sizes and Performance

### Size comparison

| Algorithm | Public Key | Secret Key | Signature | PQ Security |
|-----------|-----------|------------|-----------|-------------|
| **Dilithium3** (shell-chain) | 1,952 B | 4,032 B | 3,309 B | NIST Level 3 (128-bit) |
| **SPHINCS+-SHA2-256f** (shell-chain, secondary) | 32 B | 64 B | ~49,856 B | NIST Level 5 (256-bit) |
| ECDSA secp256k1 (Ethereum) | 64 B | 32 B | 64 B | 0-bit PQ (broken) |
| Ed25519 (Solana) | 32 B | 64 B | 64 B | 0-bit PQ (broken) |

Dilithium3 signatures are ~52× larger than ECDSA, but this is a necessary trade-off for quantum resistance.

### Performance characteristics

| Operation | Dilithium3 | SPHINCS+-SHA2-256f |
|-----------|-----------|-------------------|
| Key generation | < 1 ms | < 1 ms |
| Sign | < 5 ms | ~50 ms |
| Verify | < 2 ms | ~10 ms |
| Sign + Verify | < 10 ms (debug < 50 ms) | ~60 ms |
| 100 Sign+Verify ops | < 1 s | ~6 s |

Dilithium3 is the default because it offers the best balance of security, signature size, and performance. SPHINCS+ is available as a conservative alternative with higher security but larger signatures.

### Batch verification

Shell-chain supports parallel batch verification (feature: `batch`) using `rayon`:

```rust
// ~1.5-2× speedup on multi-core systems
batch_verifier.verify_batch(&items)?;
```

This is used during block import to verify all transaction signatures in parallel.

---

## Incompatibility with ECDSA and MetaMask

Shell-chain is **not compatible** with MetaMask, Ledger, or other wallets that use ECDSA signatures. This is by design — ECDSA provides zero protection against quantum computers.

### What doesn't work

| Tool | Why |
|------|-----|
| **MetaMask** | Cannot generate Dilithium3 keys or sign PQ transactions |
| **Ledger/Trezor** | Hardware wallets use ECDSA/Ed25519 chips |
| **ethers.js / web3.js** | Client libraries assume 64-byte ECDSA signatures |
| **`ecrecover`** | Dilithium3 does not support public key recovery from signatures |

### What to use instead

| Operation | Tool |
|-----------|------|
| Generate a key | `shell-node key generate --output keystore.json` |
| View address | `shell-node key inspect keystore.json` |
| Send a transaction | `shell-node tx send --to pq1... --value ... --keystore keystore.json` |
| Deploy a contract | `shell-node tx deploy --code 0x... --keystore keystore.json` |
| Call a contract | `shell-node tx call --to pq1... --data 0x...` |
| Check balance | `shell-node account balance pq1ADDRESS` |
| Check nonce | `shell-node account nonce pq1ADDRESS` |
| List keystores | `shell-node account list --datadir shell-data` |

### JSON-RPC compatibility

Despite the different signature scheme, shell-chain's JSON-RPC API is **Ethereum-compatible** for read operations. Standard tools like `curl`, `cast` (Foundry), and custom scripts can query blocks, balances, logs, and more using the `eth_` namespace. Only transaction signing requires the shell-chain CLI or SDK.

The `eth_sign` and `eth_signTransaction` methods return error `-32601` because the node does not hold user private keys.

---

## Future: SPHINCS+ and Hybrid Schemes

### SPHINCS+-SHA2-256f (Available Today)

Shell-chain already supports **SPHINCS+-SHA2-256f-simple** as a secondary algorithm. SPHINCS+ is a **stateless hash-based** signature scheme, providing a fundamentally different security assumption from lattice-based Dilithium:

| Property | Dilithium3 | SPHINCS+-SHA2-256f |
|----------|-----------|-------------------|
| Security basis | Lattice problems (Module-LWE) | Hash function security (SHA-256) |
| PQ Security | 128-bit (NIST Level 3) | 256-bit (NIST Level 5) |
| Signature size | 3,309 bytes | ~49,856 bytes |
| Speed | Fast | Slower |
| Conservative | Moderate | Very conservative |

SPHINCS+ keystores use `"key_type": "sphincs-sha2-256f"` and are managed with the same CLI tools.

The `MultiVerifier` automatically detects the algorithm from the signature's embedded type tag, enabling mixed validator sets where some validators use Dilithium3 and others use SPHINCS+.

### ML-DSA-65 (Planned)

The `SignatureType` enum includes a reserved variant for **ML-DSA-65** (FIPS 204), the finalized NIST standard based on Dilithium. Shell-chain will add ML-DSA-65 support when stable implementations are available in the Rust ecosystem. This will be a non-breaking upgrade — existing Dilithium3 keys and signatures remain valid.

### Hybrid Schemes (Research)

Future versions may support hybrid signature schemes that combine a classical algorithm (e.g., Ed25519) with a post-quantum algorithm (e.g., Dilithium3). This provides security even if one of the two algorithms is broken, offering a migration path for ecosystems transitioning from classical to post-quantum cryptography.

### Algorithm Agility

Shell-chain's `PQSignature` container embeds the algorithm type:

```rust
pub struct PQSignature {
    pub sig_type: SignatureType,  // Algorithm identifier
    pub data: Vec<u8>,            // Raw signature bytes
}
```

This design enables seamless addition of new algorithms without protocol-breaking changes. The `MultiVerifier` dispatches to the correct verifier at runtime based on `sig_type`, so the network can process transactions signed with any supported algorithm in the same block.

---

## Summary

| Component | Choice | Rationale |
|-----------|--------|-----------|
| **Signatures** | Dilithium3 (default) | Fast, compact (for PQ), NIST Level 3 |
| **Signatures (alt)** | SPHINCS+-SHA2-256f | Conservative, hash-based, NIST Level 5 |
| **Hashing** | Keccak-256 | Ethereum compatibility |
| **Internal hashing** | BLAKE3 | Performance |
| **Keystore KDF** | Argon2id | Memory-hard, side-channel resistant |
| **Keystore cipher** | XChaCha20-Poly1305 | AEAD, safe random nonces |
| **Address format** | 20 bytes, `blake3(version \|\| algo_id \|\| pubkey)[0..20]` | PQ-bound, algo-agnostic |
| **Key zeroization** | `zeroize` crate | Secure memory erasure |

Shell-chain is quantum-ready today. No migration will be needed when quantum computers arrive.

---

*Last updated: 2025*
