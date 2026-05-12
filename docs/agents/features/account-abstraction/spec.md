# Feature: Native Account Abstraction (Native AA)

Status: archived
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `account-abstraction` · Priority P2 · Modules `shell-chain/crates/evm`, `shell-chain/crates/core`

---

## ARCHIVED NOTICE

This spec is **archived**. It originally documented an early `EntryPoint / UserOperation / Bundler`
design that was never shipped. Since M9, Native AA has been implemented using a different
architecture. **The authoritative design documents are:**

- (historical AA design — superseded by this spec)
- `shell-chain/docs/ACCOUNT_ABSTRACTION_GUIDE.md`

---

## Current Implementation Reference (v0.22.2)

Shell-Chain's live AA model is **direct-transaction native AA** — no ERC-4337 EntryPoint
contract, no separate Bundler process.

### Core types — `crates/core/src/transaction.rs`

| Type | Description |
|------|-------------|
| `AaBundle` | Native-AA transaction envelope (`tx_type = 0x7E`, `AA_BUNDLE_TX_TYPE`) |
| `InnerCall` | Single call within an AA bundle (`to`, `value`, `data`, `gas_limit`) |
| `SessionAuth` | Session-key authorization within a bundle |
| `PubkeyMode` | Key mode for bundle signing (`PrimaryKey` / `SessionKey`) |

Constants: `AA_BUNDLE_TX_TYPE = 0x7E`, `AA_BUNDLE_PRESENCE_FLAG`, `PAYMASTER_SIGNING_HASH_DOMAIN`,
`BATCH_SIGNING_HASH_DOMAIN`, `MAX_INNER_CALLS = 16`, `MAX_INNER_CALLDATA`.

### AA validation — `crates/evm/src/aa_validation.rs`

```rust
pub fn validate_aa_tx(
    bundle: &AaBundle,
    world_state: &WorldState<impl KvStore>,
) -> Result<AaValidationOutcome, AaValidationError>;

pub const VALIDATION_GAS_CAP: u64;  // maximum gas for AA validation phase
pub struct AaValidationOutcome { /* sender, paymaster, gas_used */ }
```

### AA bundle structure check — `crates/evm/src/tx_validation.rs`

```rust
pub fn validate_aa_bundle_structure(bundle: &AaBundle) -> Result<(), TxValidationError>;
```

Called at mempool ingress before signature verification.

### System contract — `crates/evm/src/system_contracts.rs`

`AccountManager` at `ACCOUNT_MANAGER_ADDR` handles:
- `rotateKey(newPubkey)` — updates `pq_pubkey_hash` on-chain
- `setValidationCode(codeHash)` — installs custom validator contract
- `clearValidationCode()` — reverts to default PQ validation

```rust
pub const ACCOUNT_MANAGER_ADDR: Address;
pub fn encode_rotate_key_calldata(new_pubkey: &[u8]) -> Bytes;
pub fn encode_set_validation_code_calldata(code_hash: ShellHash) -> Bytes;
pub fn encode_clear_validation_code_calldata() -> Bytes;
```

### Social recovery metadata — `crates/storage/src/chain_store.rs`

```rust
pub struct GuardianConfig { /* guardian addresses, threshold */ }
pub struct RecoveryProposal { /* new_pubkey, guardian signatures */ }
```

Stored in the chain store; not yet enforced at protocol level (Phase 3 work).

### Paymaster (sponsored path)

In Phase 1 (v0.18+), paymasters are plain EOAs. A bundle is "sponsored" when
`bundle.paymaster != bundle.sender`. The paymaster's balance covers `gas_used × max_fee_per_gas`.
No on-chain paymaster registry exists yet; policy is `"eoa-open"` (any EOA can sponsor
any bundle it signs).

RPC: `shell_getPaymasterPolicy(address)`, `shell_isSponsored(tx_hash)`,
`shell_estimateBatch(req)`.

### What is NOT implemented (confirmed out of scope)

- ERC-4337 `EntryPoint` contract
- `UserOperation` transaction type
- Bundler service
- On-chain paymaster registry / stake requirement
- Social recovery at protocol level (only storage metadata)

These remain deferred. Any future work MUST open a new spec based on the M9 architecture,
not revive this archived document.

---

## Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Added "Current Implementation Reference" section: AaBundle type, aa_validation.rs, system contract, paymaster path, GuardianConfig; preserved archived notice |
| M9 | Spec archived; AA redesigned as direct-tx native model |
| M2 | Initial draft (EntryPoint/UserOperation direction — never implemented) |
