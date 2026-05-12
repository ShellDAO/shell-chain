# Feature: Core Types

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Defines the blockchain domain model shared by all Shell-Chain crates: blocks,
transactions (including EIP-2718/1559/4844 fields and Native-AA bundles),
accounts, receipts, logs, witness-separated types, system transactions, and
EIP-1559/4844 fee calculation utilities.

This crate is the "common language" of the node — all of consensus, EVM
executor, storage, network, and RPC operate on these types.

## 2. Public API surface

All items re-exported from `shell-chain/crates/core/src/lib.rs:1-25`:

### Block types

| Symbol | Kind | Notes |
|--------|------|-------|
| `BlockHeader` | struct | Full Ethereum-compatible header incl. `witness_root`, `extra_data` |
| `Block` | struct | `header + transactions: Vec<SignedTransaction>` |
| `StrippedBlock` | struct | Block body with signatures removed; used in witness-separated archive path |

### Transaction types

| Symbol | Kind | Notes |
|--------|------|-------|
| `Transaction` | struct | Unsigned tx; EIP-2718 `tx_type`, EIP-1559 fee fields, EIP-4844 blob fields |
| `SignedTransaction` | struct | `Transaction` + `PQSignature` + `from: Address` |
| `AaBundle` | struct | Native-AA multi-call bundle (`inner_calls`, `paymaster_*`) |
| `InnerCall` | struct | Single call within an `AaBundle` |
| `SessionAuth` | struct | Session-key authorization record |
| `PubkeyMode` | enum | `Standard` / `Session` — which pubkey validates the bundle |
| `AccessListItem` | struct | EIP-2930 access list entry |

**Transaction field highlights** (`transaction.rs:25-60`):

```rust
pub struct Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,           // EIP-1559
    pub max_priority_fee_per_gas: u64,  // EIP-1559
    pub access_list: Option<Vec<AccessListItem>>, // EIP-2930
    pub tx_type: u8,                    // EIP-2718 (default 2)
    pub max_fee_per_blob_gas: Option<u64>,         // EIP-4844
    pub blob_versioned_hashes: Option<Vec<ShellHash>>, // EIP-4844
}
```

### Transaction wire constants (CONSTITUTION §2.1 — Single Source of Truth)

| Constant | Value | Location |
|----------|-------|----------|
| `AA_BUNDLE_TX_TYPE` | `0x7E` | `transaction.rs:355` |
| `AA_BUNDLE_PRESENCE_FLAG` | `0x01` | `transaction.rs:1068` |
| `BATCH_SIGNING_HASH_DOMAIN` | `0x7E` | `transaction.rs:370` |
| `PAYMASTER_SIGNING_HASH_DOMAIN` | `0x7F` | `transaction.rs:373` |
| `MAX_INNER_CALLS` | `16` | `transaction.rs:358` |
| `MAX_INNER_CALLDATA` | `131 072` (128 KiB) | `transaction.rs:361` |
| `AA_INNER_CALL_INTRINSIC_GAS` | `4 000` | `transaction.rs:378` |
| `MAX_BLOB_HASHES_PER_TX` | `6` | `transaction.rs:17` |
| `DILITHIUM3_PUBKEY_LEN` | `1952` | `transaction.rs:330` |

### Witness-separation types (`witness.rs:1-60`)

Phase B witness separation moves all PQ signatures out of block bodies and into
a parallel `WitnessBundle`. Full nodes store both; light clients skip the bundle.

| Symbol | Kind | Notes |
|--------|------|-------|
| `StrippedTransaction` | struct | Tx without signature/pubkey; carries `from`, `tx`, optional `aa_bundle` |
| `TxWitness` | struct | Per-tx PQ signature material |
| `WitnessBundle` | struct | Ordered list of `TxWitness` for one block; stored under `CF_WITNESS` |

### System transactions (`reward.rs:1-60`)

Deterministic consensus-layer transactions embedded in blocks for reward
accounting and STARK settlement. Not user-signed.

| Symbol | Kind | Notes |
|--------|------|-------|
| `SystemTransaction` | struct | First-class record; surfaced via RPC so explorers can account for rewards |
| `SystemTxKind` | enum | `BlockGasReward = 1`, `StarkReward = 2` |
| `StarkRewardParams` | struct | Inputs for constructing a `StarkReward` system tx; includes `proof_payload` (opaque bytes decoded as `ProofAmendment` during validation) |

### Fee calculations (`fee.rs`)

EIP-1559 and EIP-4844 fee math:

| Symbol | Notes |
|--------|-------|
| `calculate_base_fee(parent_gas_limit, parent_gas_used, parent_base_fee) -> u64` | EIP-1559 |
| `effective_gas_price(max_fee, max_priority_fee, base_fee) -> u64` | EIP-1559 |
| `miner_tip(max_priority_fee, max_fee, base_fee) -> u64` | EIP-1559 |
| `calc_blob_gas_price(excess_blob_gas) -> u128` | EIP-4844 |
| `calc_excess_blob_gas(parent_excess, parent_used) -> u64` | EIP-4844 |
| `BLOB_BASE_FEE_UPDATE_FRACTION` | `3 338 477` |
| `MIN_BLOB_BASE_FEE` | `1` |
| `TARGET_BLOB_GAS_PER_BLOCK` | `393 216` |
| `INITIAL_BASE_FEE` | `1 000 000 000` (1 Gwei) |

### Account model (`account.rs`)

```rust
pub struct Account {
    pub pq_pubkey_hash: ShellHash,
    pub nonce: u64,
    pub balance: U256,
    pub validation_code_hash: Option<ShellHash>, // AA: custom validation code (NOT `validation_code`)
    pub code_hash: Option<ShellHash>,
    pub storage_root: ShellHash,
}
```

> ⚠️ The field is `validation_code_hash` (not `validation_code`). This was
> updated in the M9 AA redesign. Code using the old name will not compile.

### Other types

| Symbol | Kind | Notes |
|--------|------|-------|
| `TransactionReceipt` | struct | `status`, `gas_used`, `logs`, `bloom`, `tx_hash` |
| `Log` | struct | EVM event log |
| `LogError` | enum | Log validation errors |
| `MAX_LOG_TOPICS` | const | `4` |

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| `BlockHeader`, `Block`, `StrippedBlock` | `block.rs` | `core/src/block.rs` |
| `Transaction`, `SignedTransaction`, `AaBundle`, wire constants | `transaction.rs` | `core/src/transaction.rs:1-400` |
| `StrippedTransaction`, `TxWitness`, `WitnessBundle` | `witness.rs` | `core/src/witness.rs:1-60` |
| `SystemTransaction`, `SystemTxKind`, `StarkRewardParams` | `reward.rs` | `core/src/reward.rs:1-60` |
| EIP-1559/4844 fee math | `fee.rs` | `core/src/fee.rs` |
| `Account` | `account.rs` | `core/src/account.rs` |
| `TransactionReceipt` | `receipt.rs` | `core/src/receipt.rs` |
| `Log`, `LogError`, `MAX_LOG_TOPICS` | `log.rs` | `core/src/log.rs` |
| Public re-exports | `lib.rs` | `core/src/lib.rs:1-25` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-2 (AA-as-First-Class)**: `AaBundle` is a core type on `Transaction`, not a late EIP. `AA_BUNDLE_TX_TYPE = 0x7E` is a constitutional constant.
- **T-5 (Atomic)**: `AaBundle` inner-call failure must revert the entire bundle; gas is still consumed. Enforced at the EVM executor layer, but the invariant is defined here.
- **T-7 (Domain-Separated Hashing)**: `BATCH_SIGNING_HASH_DOMAIN ≠ PAYMASTER_SIGNING_HASH_DOMAIN` prevents replay between bundle and paymaster authorization signatures.
- **T-9 (Backward-Compatible Defaults)**: `access_list`, `max_fee_per_blob_gas`, `blob_versioned_hashes` all have `#[serde(default)]` — legacy wallets can omit them.
- **T-10 (No Magic Numbers)**: All wire constants must be referenced by name (e.g., `AA_BUNDLE_TX_TYPE`), never as bare literals.
- `validation_code_hash` (not `validation_code`) — the M9 rename is permanent.
- `StrippedBlock` / `WitnessBundle` split is permanent (Phase B). Any code path that needs signatures must fetch the `WitnessBundle` from `CF_WITNESS` separately.

## 5. Tests

```
cargo test -p shell-core
```

Key test areas:

| Concern | File |
|---------|------|
| Transaction RLP round-trip | `transaction.rs` |
| `AaBundle` encoding/decoding | `transaction.rs` |
| EIP-4844 field handling | `transaction.rs` |
| `StrippedTransaction` / `WitnessBundle` encoding | `witness.rs` |
| `SystemTransaction` serialization | `reward.rs` |
| Fee calculation correctness (EIP-1559 / 4844) | `fee.rs` |
| `Account` storage round-trip | `account.rs` |

## 6. Related ADRs

- CONSTITUTION T-2 (AA-as-First-Class — `AaBundle` is a core type)
- CONSTITUTION T-5 (Atomic — inner-call failure reverts bundle)
- CONSTITUTION T-7 (Domain-Separated Hashing — `BATCH_SIGNING_HASH_DOMAIN`)
- CONSTITUTION T-9 (Backward-Compatible Defaults — `#[serde(default)]`)
- CONSTITUTION §2.1 (Wire constants table — constitutional SSOT)
- (historical AA design — superseded by `features/account-abstraction/spec.md`) (M9 AA redesign, `validation_code_hash` rename)
- `../adrs/ADR-007-witness-pruner-stark-guard.md` (witness separation rationale)

## 7. Known limitations / open work

- `StrippedBlock` is used in the archive/light-client path but the full witness-separated block import pipeline is not yet enabled by default in `NodeConfig`.
- `StarkRewardParams.proof_payload` is treated as opaque bytes in this crate; decoding as `ProofAmendment` happens in the STARK prover crate. Tight coupling through opaque bytes is a known smell.
- EIP-4844 blob sidecar handling (actual blob data, KZG proofs) is not yet implemented; only the versioned hash list on `Transaction` is present.

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; witness separation types added (`StrippedBlock`, `StrippedTransaction`, `TxWitness`, `WitnessBundle`); `AaBundle`/`InnerCall`/`SessionAuth`/`PubkeyMode` documented; `SystemTransaction`/`StarkRewardParams` added; EIP-4844 fields added; fee module documented; `validation_code_hash` rename from M9 AA redesign noted; all wire constants cross-referenced to CONSTITUTION §2.1
