# Shell-Chain Native Account Abstraction Guide

Shell-Chain implements **account abstraction at the protocol layer**. Every user
account is treated as a smart account from the start: the chain validates
post-quantum signatures natively and uses canonical 32-byte BLAKE3-derived
addresses rendered as `0x` + 64 lowercase hex characters.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md)

---

## 1. What "native AA" means on Shell-Chain

Shell-Chain does **not** rely on ERC-4337's `EntryPoint` / Bundler architecture.
Instead, transaction validation is part of the base protocol:

- **Default path:** built-in post-quantum signature validation
- **Upgradeable path:** account-specific validation contract logic
- **Stable account identity:** address stays the same across key rotation
- **32-byte native addresses:** Shell-Chain uses 32-byte BLAKE3-derived addresses throughout; system contracts use the `from_alloy`/`to_alloy` shims only at the PQVM/revm execution boundary for retained ABI/tooling interoperability

In practice, this means the chain can support:

- first-use account creation from a PQ public key
- key rotation without changing account identity
- custom validation logic such as multisig or social recovery

---

## 2. Address format

### 2.1 Internal address derivation

Shell-Chain derives account addresses from the signing algorithm and public key:

```text
address = blake3(algo_id || pubkey)   →   32-byte digest
```

- `algo_id = SignatureType::as_u8()` (1 byte)
- the address is the full **32 bytes** of the BLAKE3 output — no truncation
- rendered as `0x` + 64 lowercase hex characters

This gives a 256-bit address space bound to both the algorithm and key material,
with no backward-compatibility bridge to any 20-byte model.

### 2.2 External address encoding

Shell-Chain uses `0x`-prefixed lowercase hex as the canonical address format:

```text
0x<64 lowercase hex characters>
```

Examples:
- `0xd3b4f2a9c01e5f78a2b3...` (64 hex chars = 32 bytes)

Unlike Ethereum's 20-byte `0x` addresses, Shell-Chain addresses are 32 bytes end-to-end.

### 2.3 Why Shell-Chain uses full 32-byte addresses

Shell-Chain addresses are 32 bytes end-to-end for three reasons:

- the BLAKE3 output is 256 bits — truncating to 20 bytes would waste 12 bytes of collision resistance
- PQ public keys encode algorithm identity via `algo_id`; the full-length digest preserves this binding
- no `keccak256(pubkey)[12..]` truncation means no compatibility bridge to the Ethereum address space

The `0x`-prefix is kept for tooling familiarity. Addresses are 64 hex characters, not 40.

---

## 3. Validation model

Shell-Chain uses a **three-layer validation flow**.

| Layer | Trigger | Validation rule | Purpose |
| --- | --- | --- | --- |
| **Layer 1** | First transaction from an account with no state entry | Re-derive `tx.from` from `(algo_id, pubkey)` and verify signature | Account creation / first-use safety |
| **Layer 2** | Existing account with `validation_code_hash = None` | Verify `pubkey_hash` and PQ signature | Normal operation with key rotation support |
| **Layer 3** | Existing account with `validation_code_hash = Some(hash)` | Call account-specific validation logic in the EVM | Multisig / recovery / custom policies |

### 3.1 Layer 1 — first-use validation

When the account does not yet exist in world state:

1. the node requires `sender_pubkey`
2. it derives the expected address from `(algo_id, pubkey)`
3. it checks that the derived address matches `tx.from`
4. it verifies the PQ signature

This is the only stage where address derivation itself is re-checked.

### 3.2 Layer 2 — default existing-account validation

Once an account exists and uses the built-in validator path:

1. the node resolves the sender public key
2. it compares `blake3(pubkey)` with `account.pq_pubkey_hash`
3. it verifies the PQ signature

At this stage the chain no longer needs to re-derive the address from the new
public key, which is what makes **key rotation without address changes**
possible.

### 3.3 Layer 3 — custom validator path

If `account.validation_code_hash` is set, the chain delegates validation to
account-specific EVM logic instead of the built-in PQ verifier.

This is the hook for advanced account policies such as:

- multisig
- social recovery
- time locks
- contract-defined signature / authorization gates

---

## 4. Custom validator contract interface

Shell-Chain's native AA path first calls the V2 validation function. V2 gives
the validator enough transaction context to enforce target, value, gas, data,
and bundle policies without guessing from an opaque hash:

```solidity
interface IAccountValidator {
    function validateTransactionV2(
        bytes32 txHash,
        bytes32 from,
        uint64 nonce,
        bytes32 to,
        uint256 value,
        uint64 gasLimit,
        uint64 maxFeePerGas,
        uint64 chainId,
        bytes32 dataHash,
        bytes32 aaBundleHash,
        bytes calldata sig,
        bytes calldata pubkey
    ) external returns (bytes1);
}
```

For compatibility with existing validators, the node falls back to the legacy
V1 selector only when the V2 call reverts. Execution halts such as out-of-gas
remain validation failures and are never retried through the reduced V1 ABI:

```solidity
function validateTransaction(
    bytes32 txHash,
    bytes calldata sig,
    bytes calldata pubkey
) external returns (bytes1);
```

### Validation call behavior

- **target:** the account address being validated
- **gas cap:** `500_000`
- **preferred input:** `validateTransactionV2(bytes32,bytes32,uint64,bytes32,uint256,uint64,uint64,uint64,bytes32,bytes32,bytes,bytes)`
- **legacy fallback:** `validateTransaction(bytes32,bytes,bytes)` only after V2 reverts
- **execution model:** isolated validation dry-run against a world-state snapshot
- **replay guard:** protocol nonce equality is still enforced before execution

### Compatibility and nonce policy

V2 validators receive enough typed context to enforce application policy, but
Shell-Chain still keeps protocol nonce equality as the baseline replay guard
when `validation_code_hash` is set. Legacy V1 validators receive only
`txHash`, `sig`, and `pubkey`; they remain supported for compatibility but
should be upgraded to V2 for new deployments.

Validation succeeds when the return value is interpreted as **true / valid**.
Current node logic accepts the common "magic valid" encodings:

- raw `0x01`
- ABI-encoded `bool(true)`
- ABI-encoded `bytes1(0x01)`

This call path is implemented in:

- `crates/pqvm/src/aa_validation.rs`
- `crates/pqvm/src/tx_validation.rs`
- `contracts/DefaultPQValidator.sol`

---

## 5. Key rotation and validator upgrades

The long-term AA model includes a protocol-managed account controller for:

- `rotateKey(pubkey, algo_id)`
- `setValidationCode(code_hash)`
- `clearValidationCode()`

### Why address rotation is not required

Shell-Chain checks address derivation only when the account is first created.
After that, validation depends on the account's stored `pq_pubkey_hash` or
custom validator configuration.

That means a user can:

1. keep the same account address
2. rotate to a new keypair
3. even move to a different supported PQ algorithm

without changing the account's on-chain identity.

### Current status

The validation dispatcher, AccountManager system-contract flow, and reference
validator contract are all landed. The remaining AA work is focused on wider
workspace regression and final rollout validation.

---

## 6. How this differs from ERC-4337

| Topic | Shell-Chain native AA | ERC-4337 |
| --- | --- | --- |
| Validation location | Protocol-level | EntryPoint contract |
| Bundler required | No | Yes |
| Separate alt-mempool | No | Usually yes |
| Default validator | Built into the chain | Wallet contract-defined |
| Address format | `0x` + 64 hex (32-byte BLAKE3) | `0x` + 40 hex (20-byte keccak) |

Shell-Chain's model is closer to a **native smart-account chain** than to an
Ethereum add-on AA layer.

---

## 8. Implementation status

| Area | Status | Notes |
| --- | --- | --- |
| PQ address derivation (`blake3(algo_id || pubkey)`) | ✅ Implemented | 32-byte BLAKE3 digest, `0x` + 64 hex |
| RPC / CLI / genesis address format | ✅ Implemented | `0x` + 64 lowercase hex throughout |
| AA validation dispatcher core | ✅ Implemented | Layer 1 / Layer 2 / Layer 3 routing exists |
| Custom validator dry-run path | ✅ Implemented | Snapshot-based EVM validation with gas cap |
| Mempool / production ingress integration | ✅ Implemented | Revalidation and block-production paths are wired |
| AccountManager (`rotateKey`, `setValidationCode`) | ✅ Implemented | Native system-contract flow is live and tested |
| Reference validator contract | ✅ Implemented | `contracts/DefaultPQValidator.sol` + compiled runtime fixture |

---

## 9. Developer pointers

If you want to trace the implementation in code:

- `crates/primitives/src/address.rs` — address derivation (`BLAKE3(algo_id || pubkey)`, 32-byte output, `0x` hex encoding)
- `crates/pqvm/src/aa_validation.rs` — native AA dispatcher and custom-validator path
- `crates/pqvm/src/tx_validation.rs` — transaction validation entry points
- `crates/mempool/src/pool.rs` — mempool-side validation integration

---

## 10. Summary

Shell-Chain's AA model combines:

- **protocol-native smart-account validation**
- **post-quantum key material**
- **32-byte `0x`-prefixed addresses** derived as `BLAKE3(algo_id || pubkey)`
- **future-safe key rotation and validator upgrades**

The goal is to make account abstraction the default account model, not an
optional overlay.
