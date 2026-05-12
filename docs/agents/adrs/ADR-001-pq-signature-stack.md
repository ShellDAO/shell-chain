# ADR-001: Post-Quantum Signature Stack

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: CONSTITUTION.md §13.1 (feature registry); `crates/crypto/`; CHANGELOG v0.20.0; ADR-008

## Context

Shell-Chain requires all on-chain signatures (block proposals, validator votes,
user transactions) to be resistant to quantum-computer attacks. Classical ECDSA
(`ecrecover`) is insufficient for this requirement and has been disabled at the
EVM precompile layer. The chain needs a primary PQ signature scheme that is NIST
standardised, a backward-compatible transition path from the pre-standard
Dilithium3 Round-3 artefacts, and a conservative stateless fallback for
high-security contexts.

Three candidate algorithms were evaluated:
- CRYSTALS-Dilithium3 (Round 3, pre-standard) — already deployed in early
  testnet keystores.
- ML-DSA-65 (FIPS 204) — final NIST standard, structurally similar to
  Dilithium3 but with distinct key/signature encoding and `algo_id`.
- SPHINCS+-SHA2-256f-simple (SLH-DSA) — stateless hash-based, larger
  signatures, no algebraic structure.

## Decision

Deploy a three-algorithm PQ signature stack:

1. **ML-DSA-65 (FIPS 204)** via the `fips204` crate is the **primary** signing
   algorithm for all new keystores and validator identities (`algo_id = 1`,
   `key_type = "mldsa65"`).
2. **Dilithium3** via `pqcrypto-dilithium` is retained as a **backward-
   compatible** secondary algorithm for existing keystores and accounts
   (`algo_id = 0`, `key_type = "dilithium3"`); the string alias `"Dilithium3"`
   is preserved for JSON compatibility.
3. **SPHINCS+-SHA2-256f-simple** via `pqcrypto-sphincsplus` is available as a
   **stateless hash-based fallback** through `SphincsSigner`/`SphincsVerifier`;
   it is not the default signing path but is supported by `MultiVerifier`.

## Rationale

- **ML-DSA-65 as primary**: FIPS 204 (August 2024) is the final NIST standard
  for lattice-based digital signatures. Using the `fips204` crate ensures
  compliance with the published standard encoding rather than the Round-3
  encoding used by `pqcrypto-dilithium`. The schemes differ in secret-key
  layout and are not wire-compatible; treating them as aliases would silently
  corrupt signatures.
- **Dilithium3 retention**: early testnet validators and the pre-funded account
  set use Dilithium3 keystores. Removing the verifier would orphan those
  accounts. Backward-compatible multi-algorithm verification (via `MultiVerifier`)
  allows a smooth migration without a forced chain reset.
- **SPHINCS+ as fallback**: SPHINCS+ provides a conservative hedge: its security
  relies only on hash function collision resistance, with no algebraic structure
  that could be attacked by future quantum or classical techniques. The large
  signature size (~49 kB) makes it unsuitable for block-level hot paths but
  acceptable for high-value offline operations.
- **`ecrecover` disabled**: classical ECDSA is permanently disabled at the EVM
  precompile level (see CONSTITUTION.md §13.1, `crates/evm` row).

## Alternatives considered

- **ML-DSA-65 only (no Dilithium3 compat)**: rejected — would require a hard
  genesis reset every time a validator or test account held a Dilithium3 key;
  operationally fragile during the testnet phase.
- **Single algorithm (Dilithium3)**: rejected — pqcrypto-dilithium implements
  Round-3 Dilithium, not the final FIPS 204 standard. Shipping a non-standard
  algorithm as the production primary exposes the chain to future
  standardisation divergence.
- **Falcon-512 / Falcon-1024**: considered during early design; rejected because
  the NIST standardisation path for Falcon (FN-DSA) lags ML-DSA-65 and no
  mature Rust crate existed at decision time.

## Consequences

- **Positive**: FIPS 204 compliance from mainnet genesis; multi-algorithm
  `MultiVerifier` allows zero-downtime migration of validator keystores.
- **Positive**: Dilithium3 accounts remain fully functional; no account
  migration required for existing testnet participants.
- **Negative**: Two lattice-based verifier code paths must be maintained;
  confusion between `"Dilithium3"` (alias, backward compat) and `"mldsa65"`
  (primary) must be carefully documented.
- **Risks / mitigations**: Key-type confusion could cause address-derivation
  bugs (a previous `SIG_IDS` bug was fixed in v0.20.0, CHANGELOG). Mitigated by
  unit tests `ks-3`/`ks-4` in the keystore suite and by the `algo_id` field
  being mandatory in every serialised signature.

## Implementation references

- Code: `crates/crypto/src/mldsa.rs` — `MlDsaSigner`, `MlDsaVerifier`
- Code: `crates/crypto/src/dilithium.rs` — `DilithiumSigner`, `DilithiumVerifier`
- Code: `crates/crypto/src/sphincs.rs` — `SphincsSigner`, `SphincsVerifier`
- Code: `crates/crypto/src/lib.rs:3,10,15,22` — public re-exports
- Cargo: `crates/crypto/Cargo.toml` — `fips204`, `pqcrypto-dilithium`,
  `pqcrypto-sphincsplus`, `pqcrypto-traits` dependencies
- Constitution: CONSTITUTION.md §13.1 feature registry (ML-DSA-65, Dilithium3,
  SPHINCS+ rows)
- CHANGELOG: v0.20.0 (ML-DSA-65 as independent algo, `algo_id=1`, SIG_IDS fix);
  v0.21.0 (F-PQ1-ONLY — `0x` hex addresses removed, all paths use `pq1...`
  bech32m)

## Revisit triggers

- NIST publishes breaking errata to FIPS 204 that changes wire encoding.
- A cryptographic weakness is found in ML-DSA-65 at the 128-bit PQ security
  level, requiring an upgrade to ML-DSA-87.
- Shell-Chain adds a remote signing HSM path that requires a different key
  serialisation format.
- The SPHINCS+ fallback is promoted to a co-primary signing algorithm.
