# Feature: PQ Crypto Core

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Implements all post-quantum cryptographic primitives used by Shell-Chain:
signing, verification, key-pair management, and multi-algorithm dispatch.

Two distinct implementations coexist:
- **`DilithiumSigner`** — legacy Round 3 CRYSTALS-Dilithium3 via `pqcrypto-dilithium 0.5`; used by existing wallets and the wire format for `SignatureType::Dilithium3`
- **`MlDsaSigner`** — FIPS 204 final standard ML-DSA-65 via the `fips204` crate; the migration target for new key generation

`SphincsSigner` (SPHINCS+-SHA2-256f, stateless hash-based) is supported as a high-security fallback and is fully operational. Keystore encryption was extracted into a dedicated `shell-keystore` crate (see keystore/spec.md).

## 2. Public API surface

All items re-exported from `shell-chain/crates/crypto/src/lib.rs:1-24`:

| Symbol | Kind | Notes |
|--------|------|-------|
| `Signer` | trait | Key-holding signing interface (`sign`, `public_key`, `sig_type`) |
| `Verifier` | trait | Stateless verification interface (`verify`, `sig_type`) — `dyn Verifier` capable |
| `DilithiumSigner` | struct | Round 3 Dilithium3 (legacy); `pqcrypto-dilithium` backend |
| `DilithiumVerifier` | struct | ZST verifier for `Dilithium3` |
| `MlDsaSigner` | struct | **FIPS 204 ML-DSA-65**; `fips204` crate backend |
| `MlDsaVerifier` | struct | ZST verifier for `MlDsa65` |
| `SphincsSigner` | struct | SPHINCS+-SHA2-256f signer |
| `SphincsVerifier` | struct | ZST verifier for `SphincsSha2256f` |
| `MultiVerifier` | struct | ZST dispatch verifier; routes by `PQSignature.sig_type` |
| `BatchVerifier` | struct | Feature-gated (`batch`) batch PQ verification pipeline |
| `PreVerified` / `VerifyItem` | types | Batch verification result wrappers |
| `KeyPair` | struct | PQ key-pair container (holds both public and secret bytes) |
| `PQSignature` | struct | Signature container: `{ sig_type: SignatureType, data: Vec<u8> }` |
| `SignatureType` | enum | `Dilithium3 = 0`, `MlDsa65 = 1`, `SphincsSha2256f = 2` |
| `ALLOWED_ALGORITHMS` | const | `&[Dilithium3, MlDsa65, SphincsSha2256f]` — accepted algorithms |
| `CryptoError` | enum | Unified error type |

### ML-DSA-65 key/signature sizes (from `mldsa.rs:6-8`)

| Constant | Value |
|----------|-------|
| `ML_DSA_65_SK_LEN` | 4032 bytes |
| `ML_DSA_65_PK_LEN` | 1952 bytes |
| `ML_DSA_65_SIG_LEN` | 3309 bytes |

### Signature byte limits (from `signature.rs`)

| Constant | Value |
|----------|-------|
| `MAX_SIGNATURE_BYTES` | 51 200 bytes (SPHINCS+ headroom) |
| `MAX_ML_DSA_65_SIG_BYTES` | 4 096 bytes |

### Trait signatures

```rust
pub trait Signer: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<PQSignature, CryptoError>;
    fn public_key(&self) -> &[u8];
    fn sig_type(&self) -> SignatureType;
}

pub trait Verifier: Send + Sync {
    fn verify(&self, pubkey: &[u8], message: &[u8], sig: &PQSignature)
        -> Result<bool, CryptoError>;
    fn sig_type(&self) -> SignatureType;
}
```

`Verifier` implementations (`DilithiumVerifier`, `MlDsaVerifier`, `SphincsVerifier`,
`MultiVerifier`) are zero-sized types — `&self` carries no runtime overhead and
enables `dyn Verifier` dispatch required by the AA bundle validation path.

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| FIPS 204 ML-DSA-65 signer/verifier | `mldsa.rs` | `crypto/src/mldsa.rs:1-40` |
| Legacy Dilithium3 signer/verifier | `dilithium.rs` | `crypto/src/dilithium.rs` |
| SPHINCS+-SHA2-256f signer/verifier | `sphincs.rs` | `crypto/src/sphincs.rs` |
| Multi-algorithm dispatch verifier | `multi.rs` | `crypto/src/multi.rs:1-35` |
| Batch PQ verification (feature `batch`) | `batch.rs` | `crypto/src/batch.rs` |
| `SignatureType`, `PQSignature`, `ALLOWED_ALGORITHMS` | `signature.rs` | `crypto/src/signature.rs:1-80` |
| `Signer` trait definition | `signer.rs` | `crypto/src/signer.rs` |
| `Verifier` trait definition | `verifier.rs` | `crypto/src/verifier.rs` |
| `KeyPair` container | `keypair.rs` | `crypto/src/keypair.rs` |
| Error types | `error.rs` | `crypto/src/error.rs` |
| Public re-exports | `lib.rs` | `crypto/src/lib.rs:1-24` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-1 (PQ-Native)**: Only algorithms in `ALLOWED_ALGORITHMS` may sign chain transactions. New signature schemes require `@PQCrypto + @Security` dual sign-off. `ecrecover` is permanently disabled.
- **`MlDsaSigner` uses `fips204` crate** (FIPS 204 final standard) — NOT the pre-standard `pqcrypto-dilithium`. The two coexist because existing wallets hold Dilithium3 keys. Both are in `ALLOWED_ALGORITHMS`.
- **Keystore moved**: private key encryption (argon2id + XChaCha20-Poly1305) lives in `shell-keystore`; `crypto` only manages in-memory key material.
- Private key bytes are wrapped in `zeroize::Zeroizing<Vec<u8>>` in both `MlDsaSigner` and `DilithiumSigner` — zeroed on drop.
- `MultiVerifier` is the preferred verifier in production code paths (consensus, mempool, EVM validation). It routes by the `sig_type` embedded in each `PQSignature` — no external dispatch logic needed.
- `BatchVerifier` is feature-gated (`--features batch`); not enabled in the default build profile.

## 5. Tests

```
cargo test -p shell-crypto
cargo test -p shell-crypto --features batch
```

Key tests and locations:

| Test | File |
|------|------|
| `generate_and_sign_verify` | `mldsa.rs` |
| `wrong_message_fails` | `mldsa.rs` |
| `wrong_key_fails` | `mldsa.rs` |
| `from_bytes_roundtrip` | `mldsa.rs` |
| `key_sizes_match_spec` | `mldsa.rs` |
| `address_derivation` | `mldsa.rs` |
| `verifier_is_zero_sized` | `mldsa.rs` |
| `wrong_sig_type_rejected` | `mldsa.rs` |
| `bit_flip_in_signature_fails` | `mldsa.rs` |
| `multi_verifier_dispatches_dilithium` | `multi.rs` |
| `multi_verifier_dispatches_mldsa` | `multi.rs` |
| `multi_verifier_dispatches_sphincs` | `multi.rs` |
| `batch_verify_all_valid` | `batch.rs` |

## 6. Related ADRs

- CONSTITUTION T-1 (PQ-Native — only `ALLOWED_ALGORITHMS` accepted)
- CONSTITUTION §2.3 (Address derivation from PQ public key)
- `../adrs/ADR-001-pq-signature-stack.md` (rationale for Dilithium3 → ML-DSA-65 migration path)

## 7. Known limitations / open work

- `BatchVerifier` is not yet integrated into the block import pipeline; individual `MultiVerifier::verify` calls are used per transaction in consensus.
- ML-DSA-65 migration: existing wallets retain `Dilithium3` keys. A key rotation flow via `AccountManager::encode_rotate_key_calldata` exists but no automated migration tooling yet.
- SPHINCS+ verification is ~200ms per signature; it is not suitable for high-throughput block validation and is gated to special-purpose accounts.

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; ML-DSA-65 (FIPS 204) added; `MultiVerifier`/`BatchVerifier` documented; `pqcrypto-dilithium` vs `fips204` crate distinction clarified; keystore extraction noted; `ALLOWED_ALGORITHMS` and all key constants added
