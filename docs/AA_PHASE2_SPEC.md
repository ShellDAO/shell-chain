# Native AA Phase 2 — Contract Paymaster + Session Keys + Guardian Recovery

> **Status**: Design Spec · Target: v0.19.0
>
> Builds on Phase 1 (v0.18.0): `AaBundle`, EOA paymaster, batch inner-calls.
> See [`AA_BATCH_AND_SPONSORED_SPEC.md`](AA_BATCH_AND_SPONSORED_SPEC.md) and
> [`ACCOUNT_ABSTRACTION_GUIDE.md`](ACCOUNT_ABSTRACTION_GUIDE.md) for Phase 1 context.
>
> **CONSTITUTION tenets wired through this spec**: T-2 (PQ-first), T-5 (EVM
> compatibility via 20-byte addresses), T-7 (trust-minimised validation).

---

## 1. Goals & Non-Goals

### Goals

1. **Contract Paymaster (Phase 2)** — gas sponsorship is programmable: a
   paymaster smart contract can accept or reject sponsorship requests based on
   arbitrary on-chain logic (ERC-20 allowance, NFT ownership, rate limits, etc.).
2. **Session Keys** — an account owner can mint a short-lived sub-key scoped to
   a specific call target, value cap, and expiry block. Session key transactions
   skip the main PQ signer and go through a separate fast verification path.
3. **Guardian Recovery** — an account can define a guardian set; k-of-n
   guardians may rotate the account's root PQ key after a configurable timelock.

### Non-Goals (deferred to v0.20.0+)

- ERC-4337 `EntryPoint` / `UserOperation` / `Bundler` compatibility.
- Cross-chain session key delegation.
- Recursive guardian sets (guardian of a guardian).
- `postOp` gas metering callbacks (Phase 2 focuses on pre-execution validation;
  post-execution metering can be added without breaking the wire format).

---

## 2. Constitution Invariant Mapping

| Invariant | Phase 2 implication |
|-----------|---------------------|
| T-2 (PQ-first) | Session keys use Dilithium by default; SPHINCS+ optional. |
| T-5 (EVM compat) | `IPaymaster` is a standard EVM interface; 20-byte addresses everywhere. |
| T-7 (trust-minimised) | Contract paymaster validation executes in a read-only EVM sandbox; it cannot modify world state during admission. |
| S-3 (single PQ verify path) | Session key verification re-uses the existing `Verifier` trait; no new sig path. |
| H-1 (bounded idle) | Guardian timelock must be ≥ `max_idle_interval_ms / 1000` seconds in blocks to prevent race with heartbeat blocks. |

---

## 3. Contract Paymaster

### 3.1 `IPaymaster` Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPaymaster {
    /**
     * @notice Validate a sponsorship request.
     * @param sender       The account requesting sponsorship.
     * @param callData     The outer tx calldata (AaBundle RLP).
     * @param maxGasCost   The maximum gas cost the paymaster would pay (wei).
     * @param context      Arbitrary paymaster-supplied data from the wire bundle.
     * @return accepted    True iff the paymaster agrees to sponsor.
     */
    function validatePaymasterOp(
        address sender,
        bytes calldata callData,
        uint256 maxGasCost,
        bytes calldata context
    ) external view returns (bool accepted);
}
```

**Key design constraints (T-7)**:

- Called with `staticcall` (read-only). Cannot mutate storage during admission.
- Gas budget for the call is capped at `PAYMASTER_VALIDATE_GAS_CAP` (= 50,000).
- `context` is opaque: the paymaster encodes its own state in it (e.g. an EIP-712
  permit for ERC-20 fee payment). It is NOT interpreted by the protocol.
- Revert or return `false` → admission rejected with
  `TxValidationError::PaymasterRejected`.

### 3.2 Wire Format Extensions

Phase 1 `AaBundle` gains two new optional fields:

```rust
pub struct AaBundle {
    // --- Phase 1 (unchanged) ---
    pub inner_calls: Vec<InnerCall>,
    pub paymaster: Option<Address>,
    pub paymaster_signature: Option<Bytes>,
    // --- Phase 2 additions ---
    /// For contract paymasters: arbitrary bytes passed to validatePaymasterOp().
    pub paymaster_context: Option<Bytes>,
    /// Session key authorisation (see §4).
    pub session_auth: Option<SessionAuth>,
}
```

`paymaster_context.len()` ≤ `MAX_PAYMASTER_CONTEXT` (= **4 KiB**).

#### Paymaster type dispatch

| `paymaster` | `paymaster_signature` | `paymaster_context` | Meaning |
|------------|----------------------|---------------------|---------|
| None | None | None | Sender self-pays (Phase 1) |
| Some(addr) | Some(sig) | None | EOA paymaster (Phase 1) |
| Some(addr) | None | Some(ctx) | **Contract paymaster (Phase 2)** |
| Some(addr) | Some(sig) | Some(ctx) | Invalid (wire error) |

For contract paymasters, admission validation calls `IPaymaster.validatePaymasterOp`
in a `staticcall` sandbox instead of checking a PQ signature.

### 3.3 Admission Validation Path (`validate_aa_tx`)

```
validate_aa_tx(signed_tx)
  └─ has paymaster?
       ├─ EOA paymaster (Phase 1): verify_paymaster_signature()    ← unchanged
       └─ Contract paymaster (Phase 2): call_paymaster_validate()
            └─ staticcall IPaymaster.validatePaymasterOp(...)
                 ├─ returns true  → Ok
                 ├─ returns false → Err(PaymasterRejected)
                 └─ reverts / OOG → Err(PaymasterValidationFailed)
```

`call_paymaster_validate` is a new function in `crates/evm` that creates a
temporary read-only EVM context using `ShellEvm::call_static`.

### 3.4 Balance Settlement

For contract paymasters, balance deduction happens at **execution time**, not
admission time, to avoid charging before the call is included. The contract
must ensure sufficient ETH balance or implement ERC-20 metering via a
permit-style mechanism in `context`.

Protocol responsibility (unchanged from Phase 1): if the contract paymaster's
ETH balance falls below `max_gas_cost` at execution time, the block producer
replaces the inner calls with a REVERT but still charges the outer gas.

---

## 4. Session Keys

### 4.1 Overview

A session key is a short-lived Dilithium (or SPHINCS+) keypair whose scope is
restricted to a single `(target, value_cap, expiry_block)` triple. It is
authorized by the account's root PQ key at setup time and verifiable on-chain
without an EVM call.

### 4.2 Wire Format

```rust
/// Session key authorization embedded in AaBundle.
pub struct SessionAuth {
    /// The session public key (Dilithium by default).
    pub session_pubkey: Bytes,
    /// Algorithm of the session key.
    pub session_algo: SignatureType,
    /// Permitted call target (None = any, scoped to inner_calls[0].to).
    pub target: Option<Address>,
    /// Maximum ETH value per tx the session key may authorize.
    pub value_cap: U256,
    /// Block number after which this session key is invalid.
    pub expiry_block: u64,
    /// Root account's PQ signature over session_auth_hash().
    pub root_signature: Bytes,
    /// Session key's PQ signature over the tx sender_signing_hash().
    pub session_signature: Bytes,
}
```

`session_auth_hash()` = `blake3(session_pubkey || target || value_cap || expiry_block || chain_id)`.

### 4.3 Validation Rules

1. `expiry_block` > `current_block_number`.
2. Σ inner_call.value ≤ `value_cap`.
3. If `target` is Some: all inner calls must have `to == target`.
4. `root_signature` is a valid PQ sig from the account's root key over `session_auth_hash()`.
5. `session_signature` is a valid PQ sig from `session_pubkey` over `sender_signing_hash()`.
6. Session keys do NOT bypass nonce: the outer tx nonce still increments.

### 4.4 Storage

Session keys are **not stored on-chain**; they are validated entirely from the
data in `SessionAuth`. This keeps storage overhead zero. Revocation is implicit:
use an `expiry_block` in the past, or rotate the root key (which invalidates
the `root_signature`).

### 4.5 Gas Cost Adjustment

Two additional PQ sig verifications (root + session) add approximately
`2 × PQ_VERIFY_GAS` to the intrinsic gas of a session-key tx. The intrinsic
gas computation in `compute_intrinsic_gas()` must be updated accordingly.

---

## 5. Guardian Recovery

### 5.1 Overview

An account may register a guardian set (up to `MAX_GUARDIANS` = 5 addresses)
with a k-of-n threshold. After the threshold number of guardians submit
recovery attestations and a configurable timelock passes, the account's root
PQ key can be rotated to a new one without the old key's signature.

### 5.2 `AccountManager` Extensions

The existing `AccountManager` system contract (deployed at genesis) gains two
new entry points:

```solidity
/**
 * @notice Register or update the guardian set for msg.sender.
 * @param guardians  List of guardian addresses (1..MAX_GUARDIANS).
 * @param threshold  Required k-of-n (1..guardians.length).
 * @param timelock   Minimum blocks between initiation and execution.
 */
function setGuardians(
    address[] calldata guardians,
    uint8 threshold,
    uint64 timelock
) external;

/**
 * @notice Initiate or vote for a recovery proposal.
 * @param account     The account to recover.
 * @param newPubkey   The new root PQ public key bytes.
 * @param newAlgo     The algo_id for newPubkey.
 */
function submitRecovery(
    address account,
    bytes calldata newPubkey,
    uint8 newAlgo
) external;

/**
 * @notice Execute a matured recovery proposal (anyone may call).
 * @param account  The account to rotate.
 */
function executeRecovery(address account) external;
```

### 5.3 Recovery Lifecycle

```
t=0     : Guardian A calls submitRecovery(account, newPubkey, algo)
t=1,2   : Guardians B, C call submitRecovery (same proposal hash)
          → threshold reached, proposal recorded with maturity_block = t + timelock
t=T+lock: anyone calls executeRecovery(account)
          → AccountManager rotates account.pq_pubkey_hash
          → all session keys derived from old root become invalid immediately
```

Cancellation: the account owner (if they still hold the old key) may call
`cancelRecovery(account)` before maturity.

### 5.4 Invariants

- `timelock` ≥ `MIN_RECOVERY_TIMELOCK` = 100 blocks (≈10 min at 6s blocks).
- Guardian cannot be the account itself.
- Duplicate guardian signatures for the same proposal are rejected.
- At most one active recovery proposal per account at a time.
- `H-1` compliance: `MIN_RECOVERY_TIMELOCK` >> `max_idle_interval_ms / 1000`
  (100 blocks >> 60s / 6s = 10 blocks), so heartbeat blocks do not race with
  timelock expiry.

---

## 6. Implementation Plan

| Track | Crates affected | Risk | Notes |
|-------|----------------|------|-------|
| 6.1 Contract paymaster dispatch | `shell-evm`, `shell-core` | Medium | New `staticcall` sandbox path |
| 6.2 Wire format extension (`AaBundle`) | `shell-core`, `shell-storage` | Low | Additive; old bundles still decode |
| 6.3 Session key validation | `shell-evm`, `shell-crypto` | Low | Two extra PQ verifies per tx |
| 6.4 Guardian set storage | `shell-evm` (AccountManager) | Medium | New contract state layout |
| 6.5 Recovery execution | `shell-evm` (AccountManager) | Medium | State mutation via system contract |
| 6.6 Intrinsic gas update | `shell-evm` | Low | Add `2 × PQ_VERIFY_GAS` for session-key path |
| 6.7 SDK updates | `shell-sdk` | Low | TypeScript types + builder helpers |

**Suggested order**: 6.2 → 6.1 → 6.3 → 6.6 → 6.4 → 6.5 → 6.7

---

## 7. Open Questions

| # | Question | Owner | Default if unresolved |
|---|----------|-------|-----------------------|
| Q1 | Should `postOp` callbacks be in Phase 2 scope? | Protocol team | Defer to v0.20.0 |
| Q2 | Should session keys be stored on-chain for revocation? | Security review | No — zero-storage model preferred |
| Q3 | `MIN_RECOVERY_TIMELOCK`: 100 blocks acceptable for testnet? | Ops team | Yes, increase to 1000 for mainnet |
| Q4 | Contract paymaster balance settlement: block producer vs system contract? | EVM team | Block producer (simpler, no re-entrancy) |
| Q5 | `MAX_GUARDIANS` = 5: is this sufficient for enterprise wallets? | Wallet team | 5 for v0.19.0; extend to 10 later |

---

## 8. Security Considerations

- **Contract paymaster DoS**: `staticcall` with gas cap (50k) prevents
  paymaster from exhausting block gas budget. Node must enforce this cap.
- **Session key replay across chains**: `session_auth_hash` includes `chain_id`
  to prevent cross-chain replay (T-2 compliance).
- **Guardian bribery / collusion**: threshold + timelock are the primary defenses.
  Social recovery is inherently trust-requiring; the timelock allows the original
  key holder to cancel fraudulent proposals.
- **Root key invalidation race**: `executeRecovery` must atomically update
  `pq_pubkey_hash` and invalidate all session-key caches. Since session keys
  are not stored, this is automatic once `root_signature` verification fails.
- **`validatePaymasterOp` return value manipulation**: the protocol must not trust
  the return data beyond the `bool accepted` ABI decode; OOG / revert both map to
  `PaymasterValidationFailed`.
