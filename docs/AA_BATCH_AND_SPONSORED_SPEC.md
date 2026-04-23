# Native AA Phase 1 — Batch Tx & Sponsored Gas (v0.18.0)

> Status: design spec for v0.18.0. Implementation lives behind branch
> `feat/v0.18.0-dev`. Builds on the existing native AA infrastructure already
> on `main` (Layer 1/2/3 validators, AccountManager, AA validation
> dispatcher).

## 1. Goals & Non-Goals

### Goals
1. **Batch tx** — a single PQ-signed transaction that executes N inner calls
   atomically (revert-on-any-failure), under one nonce and one gas budget.
2. **Sponsored gas (paymaster v1)** — the gas for a transaction may be paid
   by a *paymaster account* (an EOA-like account on the chain), authorized
   by an explicit `paymaster_signature` over the canonical batch/tx hash.

### Non-goals (deferred to v0.19.0+)
- ERC-4337-style EntryPoint / Bundler architecture.
- Smart-contract paymasters with arbitrary policy code (this spec keeps
  paymaster validation purely native).
- Session keys, guardian recovery (separate AA Phase 2 work).

---

## 2. Wire Format

### 2.1 Transaction type byte

We extend `Transaction.tx_type: u8` with a new value:

| `tx_type` | Meaning |
|-----------|---------|
| `0`/`1`/`2`/`3` | Existing legacy / 2930 / 1559 / 4844 (unchanged) |
| `0x7E` (126) | **Shell AA bundle** (batch + optional sponsored) |

`0x7E` is chosen to stay clear of EIP-2718 envelope bytes already used by
Ethereum (`0x01`/`0x02`/`0x03`/`0x04`/`0x7F`).

### 2.2 New optional payload — `AaBundle` on `SignedTransaction`

To minimize blast radius, **`Transaction` is unchanged**. The AA payload lives
in a new `AaBundle` carried as an *optional trailing* field on
`SignedTransaction`:

```rust
pub struct InnerCall {
    pub to: Option<Address>,   // None = contract creation
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,        // per-inner advisory cap; sum ≤ outer gas_limit
}

pub struct AaBundle {
    pub inner_calls: Vec<InnerCall>,
    pub paymaster: Option<Address>,
    pub paymaster_signature: Option<Bytes>,
}

pub struct SignedTransaction {
    // ... all existing fields unchanged ...
    pub aa_bundle: Option<AaBundle>,
}
```

Invariants enforced at construction (`SignedTransaction::with_aa_bundle`)
and re-checked on decode/admission:

- `aa_bundle.is_some()` iff `tx.tx_type == 0x7E`.
- `inner_calls.len()` ∈ `1..=MAX_INNER_CALLS` (= **16**).
- Each inner `data.len()` ≤ `MAX_INNER_CALLDATA` (= **128 KiB**).
- Σ `inner.gas_limit` ≤ outer `tx.gas_limit`.
- `paymaster.is_some() ⇔ paymaster_signature.is_some()`.
- For `tx_type == 0x7E`, outer `to/value/data` are ignored by execution
  (callers SHOULD set them to zero for canonicalization, but this is not
  enforced at the wire layer).

### 2.3 RLP encoding (zero-overhead for legacy txs)

`Transaction` RLP is unchanged — every v0.17.0 byte stream still decodes
identically. `SignedTransaction` keeps its existing four-field layout
(`from`, `tx`, `signature`, `pubkey_mode`); the optional `aa_bundle` is
appended **after** `pubkey_mode`, *inside* the same outer list header, as:

```
[ ... existing 4 fields ... , 0x01_byte_flag , rlp(AaBundle) ]
```

When `aa_bundle == None`, **nothing** is emitted — the encoded bytes are
byte-for-byte identical to v0.17.0 (pinned by
`signed_tx_legacy_rlp_byte_for_byte_unchanged_when_no_aa_bundle`).

The decoder detects presence by comparing bytes consumed so far against the
outer header's `payload_length`: any remaining bytes inside the list MUST
start with the 1-byte presence flag (`AA_BUNDLE_PRESENCE_FLAG = 0x01`)
followed by an RLP-encoded `AaBundle`. Any other flag value is a hard
decode error (no silent skipping).

`AaBundle` RLP layout: `[ list<InnerCall>, paymaster_or_empty, paymaster_sig_or_empty ]`,
where absent `Option`s are encoded as empty bytes (`0x80`). `InnerCall`
layout: `[ to_or_empty, value, data, gas_limit ]`.

### 2.4 Paymaster signature placement

The paymaster's signature lives **inside `AaBundle`** as
`paymaster_signature: Option<Bytes>` (not on `SignedTransaction` directly).
Sender-pays transactions set both `paymaster` and `paymaster_signature` to
`None`; sponsored transactions MUST set both. Mismatched pairing is a
construction-time error.

### 2.5 Hash domain separation

To prevent any cross-domain replay:

```text
batch_signing_hash    = keccak256( 0x7E || rlp(Transaction) || rlp_signing(AaBundle) )
paymaster_signing_hash = keccak256( 0x7F || from || batch_signing_hash )
```

`rlp_signing(AaBundle)` is the canonical bundle RLP encoding **with the
`paymaster_signature` field omitted** (only `inner_calls` + `paymaster` are
hashed). This breaks the otherwise-circular dependency where the sender's
`batch_signing_hash` would depend on the paymaster's signature, which itself
depends on `batch_signing_hash`. The signing-form encoder lives at
`AaBundle::encode_for_signing`; the wire encoder still includes
`paymaster_signature` so the RLP roundtrip is lossless.

The leading domain bytes (`0x7E`, `0x7F`) plus the encoded `tx_type` field
inside the inner RLP give belt-and-suspenders isolation from
legacy/EIP-1559/blob transaction hashes.

> **Sender hash routing.** `SignedTransaction::sender_signing_hash()` returns
> `batch_signing_hash` for AA-bundle txs and the legacy `hash()` otherwise.
> All sender PQ-signature verification paths (mempool ingress, witness
> import, custom-validation calldata) MUST use this single entry point; this
> avoids per-call-site branching on `tx_type`.

---

## 3. Validation flow (mempool ingress)

For `tx_type == 0x7E` a transaction passes mempool admission when:

1. **Structural** (`tx_validation::validate_aa_bundle_structure`):
   - `aa_bundle.is_some()` ⇔ `tx_type == 0x7E` (both directions)
   - `inner_calls` non-empty & `len ≤ MAX_INNER_CALLS` (16)
   - per-inner `data.len() ≤ MAX_INNER_CALLDATA` (128 KiB)
   - `tx.gas_limit ≥ compute_intrinsic_gas(...) + Σ inner.gas_limit + AA_INNER_CALL_INTRINSIC_GAS × len(inner_calls)`
   - outer `to/value/data` zero (enforced by `with_aa_bundle`)
2. **Sender PQ signature**: existing Layer 1/2/3 dispatch via
   `aa_validation`, signing `sender_signing_hash()` (= `batch_signing_hash`).
3. **Paymaster (if `paymaster.is_some()`)** — see `verify_paymaster_signature`:
   - `paymaster_signature` is `Some(non-empty)`
   - paymaster's pubkey **must already be registered on-chain** (looked up via
     `ChainStore::get_pubkey(paymaster)`); on miss → `PaymasterPubkeyNotFound`.
     **v0.18.0 limitation**: sponsoring requires the paymaster to have
     transacted at least once (or be provisioned via genesis). Embedded
     paymaster pubkeys / multi-algo paymasters are deferred to v0.19.0+.
   - PQ-verify `paymaster_signature` over `paymaster_signing_hash`. The
     paymaster signature wrapper reuses the **sender's `sig_type`** for v0.18.0
     (single-algorithm chain assumption); a future minor may relax this.
   - paymaster account balance ≥ `gas_limit × max_fee_per_gas`.
4. **Sender balance**: `account.balance ≥ Σ inner.value` (paymaster covers
   gas; sender still pays inner-call value transfers). For self-sponsored
   bundles (no paymaster), sender pays both gas + Σ inner.value. The outer
   envelope `value` is ignored for AA txs (and forced to zero by
   `with_aa_bundle`).
5. **Sender nonce**: standard `account.nonce == tx.nonce`.

Any failure → reject before block inclusion.

> **Executor hard guard.** `ShellEvm::execute_tx()` rejects any AA bundle
> with `ExecutorError::AaBundleNotYetExecutable` until the M2b dispatcher
> lands. This is fail-loud insurance against accidentally executing a bundle
> as a legacy tx.

---

## 4. Execution semantics

`crates/evm/src/executor.rs` gains a `BatchExecutor` path:

1. Charge gas upfront from **paymaster** if set, else from **sender**:
   `gas_reserve = gas_limit * max_fee_per_gas` debited from chosen payer's balance.
2. For each `InnerCall i`:
   - Bump effective EVM call depth by 1 (inner calls execute as if from
     `tx.from`, with `msg.sender == tx.from`).
   - Run with the call's own gas limit (capped to remaining budget).
   - Collect logs/receipt entry.
3. **Atomicity**: if any inner call reverts (`Halt` other than gas refund) or
   any per-call gas runs out, the whole batch reverts; remaining gas refunds
   computed once at the outer level.
4. Bump sender's nonce by **1** (single bump per batch, not per inner call).
5. Emit one outer receipt + one `inner_logs` array (or N synthetic receipts
   under `inner_results[]` — see § 5 RPC shape).

### Gas accounting
- Intrinsic gas: `21_000` outer + `4_000` per additional inner call (encourages
  using batch for ≥2 calls; for 1 inner call the cost is identical to a normal
  tx + 0 surcharge).
- Calldata gas: charged on outer-level RLP bytes including inner_calls.

---

## 5. RPC surface

### 5.1 Existing RPCs (unchanged behavior; AA-aware)
- `eth_sendRawTransaction` accepts `tx_type=0x7E` payloads.
- `eth_estimateGas` for AA payload simulates the whole batch atomically.
- `eth_call` for AA payload runs all inner calls in a snapshot; returns the
  *last* call's return data plus a `inner_results` array via custom field.
- `eth_getTransactionReceipt` extends with optional fields:
  - `inner_results: [{ status, gasUsed, logs }]`
  - `paymaster: 0x... | null`

### 5.2 New RPCs

```text
shell_estimateBatch(tx) → {
  total_gas: 0x...,
  inner_estimates: [ 0x..., ... ]
}

shell_getPaymasterPolicy(address) → {
  is_paymaster: bool,
  balance: 0x...,
  // policy fields reserved for v0.19.0:
  daily_cap: null,
  allowed_targets: null
}

shell_isSponsored(txHash) → {
  sponsored: bool,
  paymaster: 0x... | null
}
```

### 5.3 Error codes
- `-32030 batch_too_large` (>16 inner calls)
- `-32031 batch_inner_revert` (returned by simulate/estimate, with
  `data.failed_index`)
- `-32032 paymaster_unauthorized` (sig verify failed)
- `-32033 paymaster_insufficient_balance`

---

## 6. Compatibility

- **Old SDK / wallet**: ignore `tx_type=0x7E` payloads on the wire — legacy/1559
  txs continue to work byte-identical.
- **Existing tests**: no field on legacy `Transaction` changes its on-wire
  encoding (presence flags default-zero); all goldens unchanged.
- **Parallel EVM** (PoC): batch tx is treated as a single conflict-set unit by
  the scheduler (its inner-calls' rwset is unioned).

---

## 7. Test plan

- **Unit (`crates/core`)**: round-trip RLP for `tx_type=0x7E`, with/without
  paymaster; rejects malformed (>16, oversized data, missing inner_calls).
- **Unit (`crates/evm`)**: BatchExecutor — happy path, mid-batch revert,
  out-of-gas, sponsored happy path, paymaster underbalance.
- **Integration (`tests/e2e/aa-batch.rs`)**: sdk-style payload (golden vectors)
  → mempool → block → receipt with `inner_results` populated.
- **Integration (`tests/e2e/aa-sponsored.rs`)**: paymaster pays gas; sender
  balance unchanged except for value transfer; paymaster balance deducted.

---

## 8. Out-of-scope checklist

- [ ] Smart-contract paymaster with policy code (v0.19.0)
- [ ] Session keys (v0.19.0)
- [ ] Guardian recovery (v0.19.0)
- [ ] EntryPoint / Bundler compatibility (no plan)
