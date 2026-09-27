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
2. it checks the registered key against `account.pq_pubkey_hash` (legacy
   `blake3(pubkey)`, or the algorithm-aware commitment described below)
3. it verifies the PQ signature

At this stage the chain no longer needs to re-derive the address from the new
public key, which is what makes **key rotation without address changes**
possible.

Session root signatures follow the same rotation model in transaction
validation. For block import, configure `session_registered_root_height` to
apply registered-key binding from a coordinated candidate height. A replacement
root confirmed in an earlier block then works with either embedded or reference
keys. The node still checks the account key hash, root authorization and session
signature; possession of an unrelated key cannot claim the stable address.

Legacy rotations do not retain their selected algorithm, so verification tries
the currently active installed verifiers, including compatibility fallbacks.
This address-binding schedule alone does not identify the algorithm or permit
deprecated rotated roots. Use `registered_key_algorithm_height` below to persist
that identity on subsequent rotations. Omitting the session binding schedule
preserves the legacy import address check. Rotating and using
the replacement key within the same block remains a separate limitation.

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
V1 selector only when the V2 call reverts without return data, as an unsupported
selector normally does. Policy reverts with return data and execution halts
such as out-of-gas remain validation failures and are never retried through the
reduced V1 ABI:

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
- **legacy fallback:** `validateTransaction(bytes32,bytes,bytes)` only after an empty-data V2 revert
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

After a successful rotation receipt, sign subsequent transactions with the new
key bound to the original address. Canonical production, import and fork adoption
remove pending transactions admitted under a replaced default-validator root,
along with their nonce descendants and reserved balance. The new key does not
need to pay a replacement fee to dislodge an invalid old-key transaction.
Transactions authorized by custom validator code retain that policy's semantics.

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

For `shell_sendTransaction`, each AA `inner_calls[].gas_limit` accepts either
a JSON unsigned integer or a canonical `0x` quantity (for example, `21000` or
`"0x5208"`). Both forms must fit in `u64`; hexadecimal quantities must have no
leading zeroes except `"0x0"`. JSON output remains numeric, and this input
compatibility does not change RLP encoding or signing hashes.

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

## Algorithm deprecation and migration

With `algorithm_deprecation_height` explicitly scheduled, a registered account
can continue using its root key from that block onward when governance marks the
algorithm `Deprecated`. This covers ordinary transactions and root-signed AA
bundles: an account can transfer funds to a replacement account using an active
algorithm. Both embedded and reference public keys use the same registered-key
binding and real signature checks. An existing balance alone does not qualify;
the public key must already be registered. New registrations under a deprecated
algorithm remain rejected, as do signatures using a `PendingActivation` entry.
Offline address derivation is a pure calculation, not account registration.

Omitting the schedule retains the legacy rejection of deprecated signatures.
Operators must coordinate activation; source availability does not enable the
rule on a running network. See [the compatibility decision](adr/algorithm-deprecation-migration.md).
A separate optional `algorithm_session_deprecation_height` extends this behavior
to session authorization by an account's original registered root key. At its
activation block, an active session key can submit transactions authorized by a
deprecated root. The root key must still derive the account address under its
original algorithm, and the session must satisfy its signature, expiry, value
cap and target restrictions. New accounts and pending root algorithms remain
rejected. Admission and block import use the same root-signature policy.

This session schedule is independent of `algorithm_deprecation_height`. Omitting
it preserves legacy session verification, including the ML-DSA compatibility
fallback through an active Dilithium verifier. Once enabled for a registered
original root, verification binds to its address algorithm, so a pending entry
cannot pass through that fallback. Configure and coordinate a future height on
all participating nodes; a stored schedule cannot be changed or removed.

For legacy rotations, session authorization retains the active-verifier policy.
After an algorithm-aware rotation, the session deprecation schedule also applies
to the persisted replacement algorithm. `session_registered_root_height` remains
necessary for rotated-root block import. Each schedule is immutable once stored;
an existing chain may add only a future activation.
For EOA sponsorship, the independent `algorithm_paymaster_deprecation_height`
allows an already registered original-key paymaster to keep paying transaction
fees after its algorithm becomes `Deprecated`. At the scheduled candidate block,
the registered key must derive the paymaster address under the exact algorithm
used to verify the signature. `PendingActivation`, missing keys, mismatched keys
and invalid signatures remain rejected. The sender still pays transferred value;
the paymaster pays execution fees without consuming its own transaction nonce.

Omitting this schedule preserves legacy active-only EOA authorization. Existing
chains may add only a future activation, and a persisted schedule cannot change
or be removed. Configure the same schedule on participating nodes. Contract
paymaster validation is unchanged. Legacy rotated keys require the additional binding upgrade below. Custom-validator
cryptographic operations and validator consensus signatures have separate policies.

## PQVM instructions in validation contracts

With `validation_pqvm_height` explicitly scheduled, custom account validation
and contract paymaster validation use the same instruction table as normal
PQVM execution from that candidate block onward. A policy can use `PQHASH` or
`PQADDR` to calculate and check native hashes or addresses. `CALLCODE` and
`SELFDESTRUCT` are rejected, matching the normal execution rules. Existing
validation gas limits, return-value checks, paymaster static-call restrictions
and discarded validation-state writes remain in force.

This independent schedule preserves historical validation behavior when omitted
or before activation. Existing chains can add only a future height; a persisted
schedule cannot be changed or removed. Coordinate the same height on all nodes.
Import and historical replay use the candidate header, while admission uses the
next block. See [the instruction-set decision](adr/validation-pqvm-instructions.md).

Instruction availability alone does not relax algorithm status or signature checks
in PQ verification primitives, nor increase the gas available to a validation
contract. The separate lifecycle schedule below controls deprecated verification.


## Deprecated signatures in existing validation policies

At `validation_deprecation_height`, custom-account and contract-paymaster
validation may verify signatures from Active or Deprecated algorithms. This
applies to the existing single/batch verification precompiles and, when
`validation_pqvm_height` is also active, PQVERIFY. The contract still controls
which keys and transaction fields authorize an operation; pending algorithms,
invalid signatures and malformed inputs remain rejected. Ordinary contract
execution keeps its existing algorithm policy.

The new schedule is independent and defaults off. Configure the same future
height on participating nodes; persisted schedules cannot change or be removed,
and snapshot import must match trusted configuration. Admission uses the next
candidate height; execution, import and replay use the explicit header.

Gas budgets remain unchanged. The current 500,000 custom-validation cap cannot
accommodate SLH-DSA's 2,300,000-gas verification, and the smaller contract-paymaster
budget also limits signature policies. Lifecycle compatibility alone does not
resolve these capacity gaps. See [the decision](adr/validation-deprecation.md).

### Rotated EOA sponsors

An EOA sponsor keeps its address after `rotateKey`. At or after the independently
configured `paymaster_registered_root_height`, authorization uses the current
registered public key and requires its hash to match the sponsor account state.
The replacement key signs the existing paymaster signing hash; no transaction
field changes. For legacy key bindings, only active algorithms are tried for this untagged
signature. Algorithm-aware bindings select exactly the recorded algorithm and
use `algorithm_paymaster_deprecation_height` for its deprecation exception.

The upgrade defaults to disabled and preserves earlier block validation. Its
height is persisted, immutable once scheduled, and must match trusted snapshots.
Operators must coordinate activation; merging this implementation does not
activate it on an existing network. Contract-paymaster validation is unchanged.


### Persist the replacement algorithm

At or after optional `registered_key_algorithm_height`, AccountManager
`rotateKey(pubkey, algo_id)` and successful guardian recovery store
`BLAKE3(algo_id || pubkey)` in `account.pq_pubkey_hash`, where `algo_id` is one
byte. The registered public-key bytes must also match. The account address,
account serialization and transaction signing domains do not change.

Direct signatures must carry that exact algorithm tag. Session-root and EOA
paymaster signatures use the same committed algorithm; an active compatibility
verifier cannot substitute for a pending selected algorithm. An existing
account can continue using a deprecated replacement root only when the relevant
independent schedule is enabled:

| Path | Additional schedule |
| --- | --- |
| Direct root signatures | `algorithm_deprecation_height` |
| Session authorization | `algorithm_session_deprecation_height`; `session_registered_root_height` for import |
| EOA sponsorship | `algorithm_paymaster_deprecation_height` and `paymaster_registered_root_height` |

The new binding schedule defaults to disabled. Earlier rotations and recovery
retain `BLAKE3(pubkey)` and their previous verification rules; enabling the
schedule does not infer or rewrite historical algorithm identities. To migrate
an existing binding, submit an authorized `rotateKey` with the current key and
its intended algorithm at or after activation, wait for its successful receipt,
and then use sessions or sponsorship. A deprecated existing direct root can
perform this reaffirmation when its direct-root deprecation schedule is enabled.

Coordinate an immutable future height across nodes before activation. Trusted
snapshot imports require the same schedule. Source delivery does not imply
public binary availability or network activation. See the
[binding decision](adr/registered-key-algorithm.md).

The source regressions can be run with:

```sh
cargo test -p shell-pqvm rotated_key_lifecycle_preserves_algorithm_identity
cargo test -p shell-pqvm -p shell-node -p shell-mempool -p shell-storage registered_key_algorithm
```

They cover genuine signatures for all three installed algorithms, lifecycle
rejection, rotation/recovery activation, import parent-state binding, transaction
pool retention and snapshot mismatch rejection. They do not claim consensus-key
migration or production activation.


### Native AccountManager inner calls

The optional `aa_account_manager_height` enables native AccountManager operations
inside an AA bundle. This fixes the separate batch entry previously sending
AccountManager calldata to the ordinary PQVM execution path. Use compatible SDK
native encoders and the full 32-byte AccountManager address. The authenticated
outer account is the caller for every inner operation.

At activation, a batch can configure guardians, submit or cancel recovery,
rotate its root key, and change its validation code through the native methods.
Native calls reject attached value and honor both the inner gas limit and the
remaining outer budget. All inner effects commit together: a later failure
rolls back account state, registered public keys, guardian configuration and
recovery proposals, while ordinary outer fees and the single nonce increment
still apply. A replacement root signs later transactions after confirmation;
changing a root within a batch does not change that batch's already authenticated
caller. Custom validation policy is preserved unless explicitly changed.

The schedule defaults to disabled. Historical blocks retain their earlier
behavior; existing databases accept only a future activation and reject schedule
changes or incompatible trusted snapshots. A source merge does not schedule
activation or publish a compatible SDK. Historical tracing uses retained native
metadata and is subject to the existing 128-block window.

See [the atomic execution decision](adr/aa-account-manager.md) for scope,
compatibility and reproducible regression commands. Native ValidatorRegistry AA
dispatch and native calls from contract bytecode remain open follow-up work.


### Reproduce the native AccountManager lifecycle

Build the node with `cargo build -p shell-cli`. Use Node.js 20 or later and a
compatible built `shell-sdk` checkout exposing transaction wire format v2
(`0.14.0-rc.1` tested). Set `SHELL_SDK_ENTRY` to that checkout's `dist/index.js`;
this source acceptance does not imply that the matching SDK is published on npm.
From the node repository, run:

```sh
NODE_BIN=./target/debug/shell-node \
SHELL_SDK_ENTRY="$SDK_CHECKOUT/dist/index.js" \
node tests/e2e/native-aa-lifecycle.mjs
```

Set `SDK_CHECKOUT` to your compatible SDK checkout before running the command.
The script creates fresh test accounts, a temporary validator keystore and an
isolated RocksDB node on a loopback RPC port. It checks real signed AA batches:
guardian voting and cancellation, recovery timing and atomic rollback, recovered
key authorization, and custom validation code setting, replacement and clearing.
Value-filter policies distinguish active validation behavior after failed batches,
restarts and historical replay. These policies are test fixtures, not production
authentication contracts.

A failed assertion exits nonzero. The script stops its node on completion. The printed private temporary directory
retains logs, isolated node data, the encrypted test validator key and its password
for diagnosis and recovery. It uses development mining and synthetic
timestamps to check block-height boundaries, not elapsed wall-clock time. Native
AA is enabled only in this test genesis; no existing network configuration changes.
