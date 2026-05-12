# Feature: Primitives

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Defines the foundational scalar types used throughout Shell-Chain: hash digests,
account addresses, byte containers, and numeric types. Every other crate depends
on this crate; it has no upstream shell-chain dependencies.

The address derivation scheme (`blake3(version || algo_id || pubkey)[0..20]`
encoded as Bech32m `pq1…`) is a constitutional invariant — see CONSTITUTION §2.3
and T-1.

## 2. Public API surface

All items re-exported from `shell-chain/crates/primitives/src/lib.rs:1-10`:

| Symbol | Kind | Notes |
|--------|------|-------|
| `ShellHash` | struct | 32-byte digest; newtype over `alloy_primitives::B256` |
| `Address` | struct | 20-byte account address; Bech32m `pq1…` display |
| `Bytes` | struct | Variable-length byte container |
| `U256` | re-export | `alloy_primitives::U256`; used for balance and gas values |
| `keccak256` | fn | Keccak-256 wrapper (Ethereum-compatible) |
| `blake3_hash` | fn | BLAKE3 wrapper (used in address derivation and witness roots) |
| `PrimitivesError` | enum | Error type for invalid slice lengths and parse failures |

### Key type details

**`ShellHash`** (`hash.rs`):
- `ShellHash::ZERO` — sentinel for genesis parent hash
- `ShellHash::from_slice(&[u8]) -> Self` — panics if len ≠ 32
- `ShellHash::try_from_slice(&[u8]) -> Result<Self, PrimitivesError>` — safe variant
- Implements: `Copy`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Default`, `Debug`, `Display`, `Serialize`, `Deserialize`, `Encodable` (alloy-rlp)

**`Address`** (`address.rs`):
- `Address::DERIVATION_VERSION_V1 = 0x01`
- `Address::BECH32_HRP = "pq"` — Bech32m human-readable part
- `Address::from_public_key(pubkey: &[u8], algo_id: u8) -> Self`
  — computes `blake3(0x01 || algo_id || pubkey)[0..20]`
- `Address::to_bech32m(version: u8) -> String` — `pq1…` canonical display
- `Address::from_hash(hash: &ShellHash) -> Self` — last 20 bytes of a hash
- Implements: `Copy`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Default`, `Debug` (displays as `pq1…`), `Display`, `Serialize`/`Deserialize` (Bech32m JSON), `Encodable`

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| `ShellHash` type + hash wrappers | `hash.rs` | `primitives/src/hash.rs:1-120` |
| `Address` type + derivation | `address.rs` | `primitives/src/address.rs:1-200` |
| `Bytes` type | `bytes.rs` | `primitives/src/bytes.rs` |
| Error types | `error.rs` | `primitives/src/error.rs` |
| Public re-exports | `lib.rs` | `primitives/src/lib.rs:1-10` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-1 (PQ-Native)**: `Address` derivation uses `blake3` — NOT `keccak256(pubkey)[12:]`. The `keccak256` address formula was intentionally replaced in the pre-M1 revision. Any code computing user addresses from raw PQ keys must call `Address::from_public_key`.
- **Bech32m mandatory**: all display, JSON serialization, and RPC output of `Address` must use `pq1…` Bech32m. Hex `0x…` addresses are rejected by the JSON deserializer (`address_serde_rejects_hex` test).
- `ShellHash` is fixed 32 bytes; `try_from_slice` must be used for untrusted input.
- `U256` is re-exported directly from `alloy-primitives`; no custom wrapping — ensures EVM opcode compatibility (CONSTITUTION T-3).

## 5. Tests

```
cargo test -p shell-primitives
```

Key tests and locations:

| Test | File |
|------|------|
| `address_from_public_key` | `address.rs` |
| `address_derivation_binds_algorithm` | `address.rs` |
| `address_derivation_binds_version` | `address.rs` |
| `address_display` | `address.rs` |
| `address_bech32m_roundtrip` | `address.rs` |
| `address_bech32m_rejects_wrong_hrp` | `address.rs` |
| `address_debug_uses_pq1` | `address.rs` |
| `address_serde_rejects_hex` | `address.rs` |
| `address_parse_rejects_hex` | `address.rs` |
| `address_from_hash` | `address.rs` |
| `keccak256_empty` | `hash.rs` |
| `keccak256_hello` | `hash.rs` |
| `blake3_deterministic` | `hash.rs` |
| `shell_hash_zero` | `hash.rs` |
| `shell_hash_serde_roundtrip` | `hash.rs` |
| `shell_hash_rlp_roundtrip` | `hash.rs` |
| `try_from_slice_valid` / `try_from_slice_wrong_length` | `hash.rs` |

## 6. Related ADRs

- CONSTITUTION §2.3 (Address derivation formula — `blake3` + Bech32m)
- CONSTITUTION T-1 (PQ-Native — ecrecover permanently disabled)
- CONSTITUTION T-3 (EVM Compatible — `U256` matches alloy-primitives)

## 7. Known limitations / open work

- `Bytes` does not implement `Encodable` directly; callers encode the inner `Vec<u8>`.
- No `ShellHash` → `Address` truncation utility in the public API (use `Address::from_hash`).

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; all 9 requirements ticked; address derivation formula corrected to `blake3`; Bech32m invariant documented
