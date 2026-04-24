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

`crates/evm/src/executor.rs::ShellEvm::execute_aa_bundle` implements the
atomic bundle dispatcher. `execute_tx` hard-rejects AA bundles with
`ExecutorError::AaBundleNotYetExecutable`; `block_producer` / `block_importer`
dispatch on `tx.is_aa_bundle()`.

### 4.1 Settlement model

Instead of relying on revm's default "charge caller up-front, refund later"
flow (which cannot route gas to a *paymaster* distinct from the revm caller),
the dispatcher runs each inner with revm's balance check disabled
(`CfgEnv::disable_balance_check = true`), lets each inner mutate state, and
performs a single post-bundle reconciliation that forces the canonical
balances and nonce.

1. **Snapshot** `pre_root = world_state.state_root()`, `sender_pre_balance`,
   `payer_pre_balance` (for sponsored bundles).
2. **Re-check payer balance** at execution time against
   `gas_reserve = gas_limit × max_fee_per_gas`. If short, bump sender nonce,
   emit a `status = 0` receipt with `gas_used = 0`, no further state changes.
   This protects against mempool→execution balance drift without consuming
   gas the payer cannot afford.
3. **For each `InnerCall i`**, run a fresh `revm::Evm` with:
   - `caller = tx.from` (sender) — msg.sender in the inner call is *always*
     `tx.from`, never the paymaster;
   - `kind = Call(to)` or `Create` when `to = None`;
   - `CfgEnv { disable_nonce_check: true, disable_base_fee: true,
              disable_balance_check: true, .. }`.

   After each successful inner call the revm state diff is committed to
   `world_state` so subsequent inners observe prior effects. Logs are
   appended to a single list in **inner-call iteration order**.

4. **Atomicity**: any `ExecutionResult::Revert` / `ExecutionResult::Halt` in
   an inner call — or an outright `transact()` error — triggers
   `world_state.rollback_to_root(&pre_root)`, wiping **all** bundle
   mutations (including prior successful inners' state changes).

5. **Settlement**:
   - **Success**: override sender & payer balances and bump sender nonce
     exactly once. Self-sponsored:
     `sender.balance = sender_pre - Σ inner.value - total_gas_used × max_fee`;
     sender nonce `= tx.nonce + 1`. Sponsored:
     `sender.balance = sender_pre - Σ inner.value`, `sender.nonce = tx.nonce + 1`,
     `payer.balance = payer_pre - total_gas_used × max_fee`.
   - **Failure (atomic revert)**: post-rollback, charge payer
     `total_gas_used × max_fee` (clamped at `payer_pre_balance`), bump
     sender nonce by 1.

6. **Receipt**: one outer `TransactionReceipt` with `status ∈ {0,1}`,
   `gas_used = Σ inner gas_used`, `logs = all inner-call logs in order`
   on success / empty on failure, `output = revert_data` on failure.

### 4.2 Invariants

- `sender.nonce` bumps by **exactly 1** per bundle, regardless of inner count.
- `msg.sender` in every inner is `tx.from`; paymaster identity is never
  borrowed inside inner execution.
- Logs ordering is deterministic (inner-call iteration order).
- Outer receipt gas refund is computed once; no double-refund via inner paths.
- Payer balance shortfall at execution time never fails the block — it
  produces a receipt with `status = 0`, `gas_used = 0` and bumps nonce for
  DoS protection.

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

> **Note:** The schemas below reflect the original design intent. The v0.18.0
> implementation uses snake_case JSON keys.

```text
shell_estimateBatch(tx) → {
  total_gas: "0x...",
  outer_intrinsic: "0x...",
  inner_sum: "0x...",
  intrinsic_surcharge: "0x...",
  per_inner: [ { gas_limit: "0x...", simulated: bool }, ... ]
}

shell_getPaymasterPolicy(address) → {
  address: "0x...",
  has_pq_pubkey: bool,
  pubkey_bytes: number | null,
  balance: "0x...",
  policy: "eoa-open",
  max_gas_sponsorship: null
}
// Always returns an object; never null. Unregistered → default "eoa-open" policy.

shell_isSponsored(txHash) → {
  found: bool,
  location: "mempool" | "chain" | null,
  is_aa_bundle: bool,
  sponsored: bool,
  paymaster: "0x..." | null,
  sender: "0x..." | null,
  inner_call_count: number | null
}
// Returns { found: false, location: null, ... } for unknown tx (no -32001 error).
```

### 5.3 Error codes

> **Note:** The custom `-32030`–`-32033` codes below were the original design.
> The v0.18.0 implementation uses standard codes for simplicity:

Actual shipped error codes:
- `-32602 invalid_params` — structural rejections (empty/too-many inner calls, zero-gas inner)
- `-32000 server_error` — EVM simulation failure (with detail message)
- `-32602 invalid_params` — paymaster signature verification failure (in mempool admission)
- `-32003 feature_not_enabled` — paymaster not configured on this node

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
