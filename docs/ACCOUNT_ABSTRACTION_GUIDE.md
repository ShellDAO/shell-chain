# Shell-Chain Native Account Abstraction Guide

Shell-Chain implements **account abstraction at the protocol layer**. Every user
account is treated as a smart account from the start: the chain validates
post-quantum signatures natively, keeps EVM-compatible 20-byte addresses
internally, and exposes a Shell-specific `pq1...` address format externally.

> **See also:** [Quickstart Guide](QUICKSTART.md) · [JSON-RPC API Reference](JSON_RPC_API.md) · [Post-Quantum Cryptography Guide](PQ_CRYPTO_GUIDE.md)

---

## 1. What "native AA" means on Shell-Chain

Shell-Chain does **not** rely on ERC-4337's `EntryPoint` / Bundler architecture.
Instead, transaction validation is part of the base protocol:

- **Default path:** built-in post-quantum signature validation
- **Upgradeable path:** account-specific validation contract logic
- **Stable account identity:** address stays the same across key rotation
- **EVM compatibility:** contracts still see standard 20-byte addresses

In practice, this means the chain can support:

- first-use account creation from a PQ public key
- key rotation without changing account identity
- custom validation logic such as multisig or social recovery

---

## 2. Address format

### 2.1 Internal address derivation

Shell-Chain derives account addresses from the signing algorithm and public key:

```text
preimage = version(1 byte) || algo_id(1 byte) || pubkey(n bytes)
address  = blake3(preimage)[0..20]
```

- `version = 0x01` for the first derivation scheme
- `algo_id = SignatureType::as_u8()`
- the final address is still **20 bytes**

This keeps the EVM and storage layout compatible with 20-byte EVM address slots
while avoiding Ethereum's `keccak256(pubkey)[12..]` address space.

### 2.2 External address encoding

Externally, Shell-Chain uses **Bech32m** with HRP `pq`:

```text
pq1...
```

Examples:

- canonical user-facing address: `pq1...`
- internal debug form: `0x...` (20-byte hex)

### 2.3 Why Shell-Chain does not use `0x...` as the canonical format

The `pq1...` format exists to make the account space visibly distinct from
Ethereum and other EVM chains:

- it reduces accidental deposits to the wrong network
- it binds the address to the PQ algorithm used at creation time
- it leaves room for future derivation upgrades via `version`

**Migration note:** some CLI / RPC input paths still accept legacy `0x...`
addresses as a transitional compatibility shim, but canonical output, docs,
genesis, and testnet operations use `pq1...`.

---

## 3. Validation model

Shell-Chain uses a **three-layer validation flow**.

| Layer | Trigger | Validation rule | Purpose |
| --- | --- | --- | --- |
| **Layer 1** | First transaction from an account with no state entry | Re-derive `tx.from` from `(version, algo_id, pubkey)` and verify signature | Account creation / first-use safety |
| **Layer 2** | Existing account with `validation_code_hash = None` | Verify `pubkey_hash` and PQ signature | Normal operation with key rotation support |
| **Layer 3** | Existing account with `validation_code_hash = Some(hash)` | Call account-specific validation logic in the EVM | Multisig / recovery / custom policies |

### 3.1 Layer 1 — first-use validation

When the account does not yet exist in world state:

1. the node requires `sender_pubkey`
2. it derives the expected address from `(version, algo_id, pubkey)`
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

Shell-Chain's native AA path calls a validation function with the transaction
hash and signature material:

```solidity
interface IAccountValidator {
    function validateTransaction(
        bytes32 txHash,
        bytes calldata sig,
        bytes calldata pubkey
    ) external returns (bytes1);
}
```

### Validation call behavior

- **target:** the account address being validated
- **gas cap:** `500_000`
- **input:** `validateTransaction(bytes32,bytes,bytes)`
- **execution model:** isolated validation dry-run against a world-state snapshot
- **replay guard:** protocol nonce equality is still enforced before execution

### Current limitation

Custom validators currently receive only `txHash`, `sig`, and `pubkey`.
That is enough for custom signature / policy checks, but **not** enough to
safely replace canonical nonce handling. Because of that, Shell-Chain keeps the
protocol nonce check as the baseline replay guard even when
`validation_code_hash` is set. Richer custom nonce schemes are deferred until
the validator ABI carries more transaction context.

Validation succeeds when the return value is interpreted as **true / valid**.
Current node logic accepts the common "magic valid" encodings:

- raw `0x01`
- ABI-encoded `bool(true)`
- ABI-encoded `bytes1(0x01)`

This call path is implemented in:

- `crates/evm/src/aa_validation.rs`
- `crates/evm/src/tx_validation.rs`
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
| Address format | `pq1...` externally, 20-byte internally | `0x...` |

Shell-Chain's model is closer to a **native smart-account chain** than to an
Ethereum add-on AA layer.

---

## 8. Implementation status

| Area | Status | Notes |
| --- | --- | --- |
| PQ address derivation (`blake3(version || algo_id || pubkey)`) | ✅ Implemented | Canonical external format is `pq1...` |
| RPC / CLI / genesis address migration | ✅ Implemented | User-facing outputs now use Bech32m |
| AA validation dispatcher core | ✅ Implemented | Layer 1 / Layer 2 / Layer 3 routing exists |
| Custom validator dry-run path | ✅ Implemented | Snapshot-based EVM validation with gas cap |
| Mempool / production ingress integration | ✅ Implemented | Revalidation and block-production paths are wired |
| AccountManager (`rotateKey`, `setValidationCode`) | ✅ Implemented | Native system-contract flow is live and tested |
| Reference validator contract | ✅ Implemented | `contracts/DefaultPQValidator.sol` + compiled runtime fixture |

---

## 9. Developer pointers

If you want to trace the implementation in code:

- `crates/primitives/src/address.rs` — address derivation and `pq1...` encoding
- `crates/evm/src/aa_validation.rs` — native AA dispatcher and custom-validator path
- `crates/evm/src/tx_validation.rs` — transaction validation entry points
- `crates/mempool/src/pool.rs` — mempool-side validation integration

---

## 10. Summary

Shell-Chain's AA model combines:

- **protocol-native smart-account validation**
- **post-quantum key material**
- **`pq1...` chain-specific addresses**
- **future-safe key rotation and validator upgrades**

The goal is to make account abstraction the default account model, not an
optional overlay.
