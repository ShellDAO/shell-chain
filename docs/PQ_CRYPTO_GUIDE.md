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
8. [Algorithm Registry Governance](#algorithm-registry-governance)

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

### ML-DSA-65 (Primary Runtime Algorithm)

`ML-DSA-65` is the primary algorithm in the live registry and the FIPS 204 path Shell-Chain targets for long-term production deployments. It shares the same NIST Level 3 security target as Dilithium3 while using the standardized ML-DSA parameterization.

| Property | Value |
|----------|-------|
| **Standard** | FIPS 204 ML-DSA-65 |
| **Security Level** | NIST Level 3 (128-bit PQ) |
| **Public Key Size** | 1,952 bytes |
| **Secret Key Size** | 4,032 bytes |
| **Signature Size** | 3,309 bytes |
| **Implementation** | `fips204` crate (`mldsa` module) |

### CRYSTALS-Dilithium3 (Legacy Compatibility Path)

Dilithium3 remains deployed for backwards compatibility and mixed-validator migrations. It uses the same security basis as ML-DSA-65, but the chain now documents it as the legacy Round-3 compatibility algorithm rather than the primary target.

| Property | Value |
|----------|-------|
| **Standard** | NIST Round 3 reference (pre-FIPS) |
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
address = blake3(algo_id || public_key)
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
shell-node key generate --algorithm mldsa65 --output keystore.json
```

### What happens internally

1. **CSPRNG key generation** — The selected signer backend (ML-DSA-65 by default in this guide; Dilithium3 for legacy compatibility if requested explicitly) generates a random keypair using the system's cryptographically secure random number generator.

2. **Address derivation** — The canonical 32-byte address is computed as:
   ```
   address = blake3(algo_id || public_key)
   ```

3. **Password prompt** — You enter an encryption password.

4. **Key derivation** — Argon2id derives a 32-byte encryption key from your password and a random 32-byte salt.

5. **Encryption** — The secret key is encrypted with XChaCha20-Poly1305 using the derived key and a random 24-byte nonce.

6. **Keystore file** — The encrypted key, public key, address, and all parameters are written to a JSON file.

### Security properties

- **Secret keys are zeroized** in memory after use via the `zeroize` crate. When a signer is dropped, its secret key bytes are overwritten with zeros.
- **The derived encryption key is zeroized** immediately after encrypting/decrypting.
- **Each encryption uses a unique salt and nonce**, so encrypting the same key with the same password produces different ciphertext.

---

## Keystore Format

The keystore file is a JSON document inspired by the Ethereum Web3 Secret Storage format, adapted for post-quantum keys.

### Structure

```json
{
  "version": 1,
  "address": "0xYOUR_32_BYTE_ADDRESS",
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
| `address` | `String` | Canonical 32-byte `0x` address derived from `blake3(algo_id || public_key)` |
| `key_type` | `String` | `"dilithium3"`, `"mldsa65"`, or `"sphincs-sha2-256f"` |
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
# Output: Address: 0x...
```

This does **not** require the password. The keystore stores the canonical 32-byte `0x...` address in plaintext so operators can inspect and verify it without decrypting the secret key.

---

## Address Derivation

Shell-chain addresses are **32 bytes end-to-end** and are rendered canonically as `0x` + 64 lowercase hex characters.

```
algo_id || public_key  ──→  blake3()  ──→  32-byte address  ──→  `0x` + 64 lowercase hex chars
```

### Step by step

1. Start with the signature algorithm ID and the raw public key.
2. Compute `blake3(algo_id || public_key)` → 32-byte hash.
3. Use the full 32-byte digest as the account address.
4. Render it as canonical lowercase hex: `0x` + 64 characters.

### Important notes

- The same public key always produces the same address (deterministic).
- The same public key under different supported algorithms produces different addresses because `algo_id` is part of the preimage.
- Different public keys produce different addresses (collision-resistant, 256-bit BLAKE3 output).
- Unlike Ethereum, the public key is a PQ key (ML-DSA-65, Dilithium3, or SPHINCS+), not an ECDSA key (64 bytes). This means you **cannot** derive the public key from a signature as you can with ECDSA's `ecrecover`.
- The public key must be registered on-chain with the first transaction. Query it via `shell_getPqPubkey`.

---

## Signature Sizes and Performance

### Size comparison

| Algorithm | Public Key | Secret Key | Signature | PQ Security |
|-----------|-----------|------------|-----------|-------------|
| **Dilithium3** (shell-chain) | 1,952 B | 4,032 B | 3,309 B | NIST Level 3 (128-bit) |
| **ML-DSA-65** (shell-chain) | 1,952 B | 4,032 B | 3,309 B | NIST Level 3 (FIPS 204) |
| **SLH-DSA-SHA2-256f** (shell-chain, secondary) | 32 B | 64 B | ~49,856 B | NIST Level 5 (256-bit) |
| ECDSA secp256k1 (Ethereum) | 64 B | 32 B | 64 B | 0-bit PQ (broken) |
| Ed25519 (Solana) | 32 B | 64 B | 64 B | 0-bit PQ (broken) |

Dilithium3 signatures are ~52× larger than ECDSA, but this is a necessary trade-off for quantum resistance.

### Performance characteristics

| Operation | Dilithium3 | SLH-DSA-SHA2-256f |
|-----------|-----------|-------------------|
| Key generation | < 1 ms | < 1 ms |
| Sign | < 5 ms | ~50 ms |
| Verify | < 2 ms | ~10 ms |
| Sign + Verify | < 10 ms (debug < 50 ms) | ~60 ms |
| 100 Sign+Verify ops | < 1 s | ~6 s |

ML-DSA-65 is the primary governed path, while Dilithium3 remains available for compatibility where older tooling or validator sets still depend on it. SLH-DSA-SHA2-256f is available as a conservative alternative with higher security but larger signatures.

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
| Send a transaction | `shell-node tx send --to 0x... --value ... --keystore keystore.json` |
| Deploy a contract | `shell-node tx deploy --code 0x... --keystore keystore.json` |
| Call a contract | `shell-node tx call --to 0x... --data 0x...` |
| Check balance | `shell-node account balance 0xADDRESS` |
| Check nonce | `shell-node account nonce 0xADDRESS` |
| List keystores | `shell-node account list --datadir shell-data` |

### JSON-RPC compatibility

Despite the different signature scheme, shell-chain's JSON-RPC API is **Ethereum-compatible** for read operations. Standard tools like `curl`, `cast` (Foundry), and custom scripts can query blocks, balances, logs, and more using the `eth_` namespace. Only transaction signing requires the shell-chain CLI or SDK.

The `eth_sign` and `eth_signTransaction` methods return error `-32601` because the node does not hold user private keys.

---

## Algorithm Registry Governance

The live algorithm registry is process-global and is exposed through `shell_getAlgorithmRegistry`. Validators can transition an algorithm through the following lifecycle using system-contract governance:

| Operation | Resulting status | Meaning |
|-----------|------------------|---------|
| `proposeAlgorithmActivation(uint8)` | `pending_activation` | announce an algorithm before it is accepted for new transactions |
| activation commit | `active` | the algorithm is accepted for new signatures |
| `deprecateAlgorithm(uint8)` | `deprecated` | keep registry visibility but reject new signatures |

This lets the network phase algorithms in or out without changing the transaction container format.

### Governance quorum rules

A proposal requires $\lceil 2N/3 \rceil$ weighted validator votes. The votes
must use **ML-DSA-65 or SLH-DSA-SHA2-256f** signatures — this dual-algorithm
bootstrap safety ensures governance is not blocked if Dilithium3 is the algorithm
being deprecated.

Each proposal carries a unique identifier:
```text
proposal_id = BLAKE3(algo_id ‖ spec_bytes ‖ activation_height ‖ proposer_pk)
```
This prevents replay of old proposals at a later block height.

The minimum activation delay is **Δ_min = 30 days** (~1,296,000 blocks at 2 s/block),
giving the network time to upgrade software before the new algorithm goes live.

### SLH-DSA-SHA2-256f (Available Today)

Shell-chain supports **SLH-DSA-SHA2-256f**, the FIPS 205 successor to the SPHINCS+-SHA2-256f parameter set, as a secondary algorithm. It is a **stateless hash-based** signature scheme, providing a fundamentally different security assumption from lattice-based Dilithium:

| Property | Dilithium3 | SLH-DSA-SHA2-256f |
|----------|-----------|-------------------|
| Security basis | Lattice problems (Module-LWE) | Hash function security (SHA-256) |
| PQ Security | 128-bit (NIST Level 3) | 256-bit (NIST Level 5) |
| Signature size | 3,309 bytes | ~49,856 bytes |
| Speed | Fast | Slower |
| Conservative | Moderate | Very conservative |

SLH-DSA keystores use `"key_type": "sphincs-sha2-256f"` for wire compatibility and are managed with the same CLI tools.

The `MultiVerifier` automatically detects the algorithm from the signature's embedded type tag, enabling mixed validator sets where some validators use Dilithium3 and others use SLH-DSA.

### Generating ML-DSA-65 Keys

Generate ML-DSA-65 keys with:

```bash
shell-node key generate --algorithm mldsa65 --output keystore.json
```

Existing Dilithium3 keys remain fully valid for legacy compatibility. The `MultiVerifier` dispatches to the correct algorithm at runtime using the embedded `sig_type` tag.

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
| **Signatures (primary)** | ML-DSA-65 | FIPS 204 path and primary governed algorithm |
| **Signatures (legacy)** | Dilithium3 | Round-3 compatibility for existing deployments and migrations |
| **Signatures (alt)** | SLH-DSA-SHA2-256f | Conservative, hash-based, NIST Level 5 |
| **Hashing** | Keccak-256 | Ethereum compatibility |
| **Internal hashing** | BLAKE3 | Performance |
| **Keystore KDF** | Argon2id | Memory-hard, side-channel resistant |
| **Keystore cipher** | XChaCha20-Poly1305 | AEAD, safe random nonces |
| **Address format** | 32 bytes, `blake3(algo_id \|\| pubkey)` | PQ-bound, algo-agnostic |
| **Key zeroization** | `zeroize` crate | Secure memory erasure |

Shell-chain is quantum-ready today. No migration will be needed when quantum computers arrive.

---

*Last updated: 2026-05-22*
