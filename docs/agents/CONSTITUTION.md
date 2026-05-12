# Shell-Chain Project Constitution

> **Version**: 1.6 — v0.21.0: F-PQ1-ONLY pq1 address enforcement + STARK proof integration + fork finality
> **Effective**: 2026-05-02
> **Maintainers**: Shell-Chain Core Maintainers (LucienSong / ShellDAO)
> **Amendment rule**: Any clause change requires a full Review Board review (@Architecture + @Security + @Quality + @Harness all sign off) and must be explicitly tagged `Constitution-Change` in CHANGELOG.

---

## Preamble

Shell-Chain is a **PQ-native L1 blockchain built from scratch**. This Constitution is the supreme constraint document for all development activity — every PR, Review, release, and parameter adjustment must comply with the invariants listed here. When code, documentation, and this Constitution conflict, the **precedence** is:

```
Constitution > spec/design docs > code implementation > CHANGELOG > README
```

Conflicts are "drift" and must be resolved through the Drift Audit process (see §10).

---

## Chapter 1 · Architectural Tenets

| # | Tenet | Invariant |
|---|-------|-----------|
| **T-1** | **PQ-Native** | User-layer signature verification must be quantum-safe. The `ecrecover` precompile is **permanently disabled**. Adding a new signature scheme requires dual sign-off by @PQCrypto + @Security. |
| **T-2** | **AA-as-First-Class** | AA is a first-class citizen — a built-in variant of the core transaction model (`AaBundle`), **not** a late-stage EIP patch. |
| **T-3** | **EVM Compatible** | revm is the sole execution backend, following the Shanghai spec; opcode behaviour unrelated to PQ must not deviate from mainnet EVM. |
| **T-4** | **Modular Harness** | Layers are decoupled via trait boundaries; any cross-crate direct call must be reviewed by @Harness. |
| **T-5** | **Atomic by Default** | If any inner call inside an AA bundle fails → the entire batch reverts, but gas is still consumed. |
| **T-6** | **Snake-Case Wire** | All RPC request/response fields use `snake_case` (consistent with Rust defaults). `#[serde(rename_all = "camelCase")]` is **forbidden** on new RPC types (only `eth_*` compatibility fields retain camelCase). |
| **T-7** | **Domain-Separated Hashing** | Signing preimages with different semantics must be isolated by distinct domain bytes (replay prevention). |
| **T-8** | **Storage Profile Symmetry** | The archive / full / light three-tier semantics must be driven by a single `StorageProfile` type; no duplicate logic is permitted. |
| **T-9** | **Backward-Compatible Defaults** | All new fields must be `Option`/`#[serde(default)]`; old SDK/wallet clients must continue to send legacy transactions. |
| **T-10** | **No Magic Numbers** | RPC error codes, wire constants, and gas parameters must have named constants; bare numeric literals are forbidden in handlers. |

---

## Chapter 2 · Core Constants (Single Source of Truth)

> **This section is constitution-level SSOT** — any code or documentation using the following values must reference the Rust constant symbol; hard-coding is forbidden.

### 2.1 Transaction Types / Wire Format

| Constant | Value | Location | Meaning |
|----------|-------|----------|---------|
| `AA_BUNDLE_TX_TYPE` | `0x7E` | `core/src/transaction.rs:355` | AA bundle transaction type byte |
| `BATCH_SIGNING_HASH_DOMAIN` | `0x7E` | `core/src/transaction.rs:370` | Bundle signing domain (same value as tx_type — intentional) |
| `PAYMASTER_SIGNING_HASH_DOMAIN` | `0x7F` | `core/src/transaction.rs:373` | Paymaster authorization signing domain |
| `AA_BUNDLE_PRESENCE_FLAG` | `0x01` | `core/src/transaction.rs:1068` | Flag marking AA fields present in RLP envelope |
| `MAX_INNER_CALLS` | `16` | `core/src/transaction.rs:358` | Maximum inner calls per bundle |
| `MAX_INNER_CALLDATA` | `128 * 1024` | `core/src/transaction.rs:361` | Maximum calldata bytes per inner call |
| `AA_INNER_CALL_INTRINSIC_GAS` | `4_000` | `core/src/transaction.rs:378` | Intrinsic gas per additional inner call |
| `MAX_BLOB_HASHES_PER_TX` | `6` | `core/src/transaction.rs:17` | EIP-4844 compatibility limit |
| `MAX_ACCESS_LIST_ENTRIES` | `256` | `core/src/transaction.rs:102` | EIP-2930 compatibility limit |
| `MAX_ACCESS_LIST_STORAGE_KEYS` | `512` | `core/src/transaction.rs:104` | EIP-2930 compatibility limit |
| `DILITHIUM3_PUBKEY_LEN` | `1952` | `core/src/transaction.rs:330` | ML-DSA-65 public key byte length |

### 2.2 Mempool

| Constant | Value | Location |
|----------|-------|----------|
| `MAX_TX_SIZE` | `128 * 1024` (128 KiB) | `mempool/src/pool.rs:22` |

### 2.3 Storage

| Constant | Value | Location |
|----------|-------|----------|
| `DEFAULT_BODY_RETENTION` | `512` blocks | `storage/src/body_pruner.rs:31` |
| `DEFAULT_WITNESS_RETENTION` | `128` blocks | `storage/src/witness_pruner.rs:18` |
| `MAX_ADDRESS_TX_HISTORY_OFFSET` | `10_000` | `storage/src/chain_store.rs:29` |
| RocksDB CFs | `state / chain / receipts / index / witness` | `storage/src/rocks_db.rs:36-42` |

**Storage Profile semantics** (must not be changed):

| Profile | `body_retention` | `witness_retention` | `proof_replacement_grace` |
|---------|------------------|---------------------|---------------------------|
| `archive` | `u64::MAX` (never prune) | `u64::MAX` | `u64::MAX` |
| `full` | `512` | `128` | normal |
| `light` | small | small | normal |

### 2.4 Consensus / Network Profiles (`NetworkType`)

> Single driver: `NetworkType::default_params()` (`genesis/src/config.rs:43-72`)

| Param | Dev | Testnet | Mainnet |
|-------|-----|---------|---------|
| `block_time_ms` | `30_000` | `30_000` | `2_000` |
| `max_tx_per_block` | `100` | `500` | `500` |
| `stark_aggregation` | ❌ | ✅ | ✅ |
| `async_prover` | ❌ | ✅ | ✅ |
| `min_validators` | `1` | `3` | `5` |
| `slashing_enabled` | ❌ | ✅ | ✅ |
| `proof_challenge_window` | `10` | `100` | `100` |

**Genesis defaults**:
- `default_gas_limit`: `30_000_000` (`genesis/src/config.rs:167`)
- `DEFAULT_MAX_FUTURE_SECS`: `60` seconds (block timestamp upper bound, `consensus/src/poa.rs:29`)

**Block-Production Idle Behavior** (`crates/node/src/node/event_loop.rs:190-210`):

| `NodeConfig.max_idle_interval_ms` | Behavior |
|-----------------------------------|----------|
| `0` | Legacy — produce a block on every `block_time` tick (including empty blocks) |
| `>0` (**default `60_000` = 60s**) | **Idle-Skip + Heartbeat** — if mempool is empty and less than `max_idle_interval_ms` has elapsed since last block, skip production; otherwise produce an empty heartbeat block |

CLI flag `--max-idle-interval` unit is seconds, default `60` (`crates/cli/src/main.rs`); `NodeConfig.max_idle_interval_ms` unit is milliseconds, default `60_000` (`crates/node/src/config.rs`).

**Invariant H-1** (Heartbeat Floor): Even with idle-skip enabled, the chain must not stall indefinitely — `max_idle_interval_ms` must be a finite value (typically ≤ 5 minutes) to guarantee light-client sync, defense-in-depth time windows, and timestamp monotonicity. The default 60s satisfies this invariant for all NetworkType profiles (Mainnet 2s blocks, Dev/Testnet 30s blocks).

### 2.5 Chain IDs (Reserved)

| Network | chain_id | Source |
|---------|----------|--------|
| Mainnet | `1` | (pending activation) |
| Testnet | `1338` | `genesis/src/config.rs` test constant |
| Dev (default) | `1337` | `genesis/src/config.rs` test constant |

**Prohibited**: reusing these IDs for any derived network.

### 2.6 RPC Error Codes (`crates/rpc/src/error.rs`)

| Code | Name | Purpose |
|------|------|---------|
| `-32601` | `METHOD_NOT_FOUND` | Standard JSON-RPC |
| `-32602` | `INVALID_PARAMS` | Standard JSON-RPC |
| `-32603` | `INTERNAL_ERROR` | Standard JSON-RPC |
| `-32000` | `SERVER_ERROR` | General execution failure |
| `-32001` | `NOT_FOUND` | Resource missing |
| `-32002` | `DEV_MODE_REQUIRED` | Dev-only feature |
| `-32003` | `FEATURE_NOT_ENABLED` | Node capability disabled |
| `-32005` | `LIMIT_EXCEEDED` | Quota / rate limit exceeded |

**RPC gas cap**: `eth_call` / `eth_estimateGas` cap at `50_000_000` gas (CPU DoS prevention).

### 2.7 PQ Crypto

- Primary signature scheme: **ML-DSA-65** (FIPS 204, independent algorithm)
  - Public key 1952 B / signature ~3309 B / private key 4032 B
  - `key_type = "mldsa65"` · `algo_id = 1` · `crates/crypto/mldsa.rs`
- Legacy signature scheme: **Dilithium3** (backward compatibility)
  - `key_type = "dilithium3"` · `algo_id = 0` · `crates/crypto/dilithium.rs`
  - Alias compatibility: the string `"Dilithium3"` is retained as a backward-compatible alias
- Alternative signature: **SPHINCS+** (conservative option)
- Hashing: **Keccak-256** (EVM compatible) + **BLAKE3** (internal high-speed)
- Address derivation: `keccak256(pq_pubkey)[12..]` (20 bytes)
- Keystore: v1 sk-only format (argon2id + XChaCha20-Poly1305); SDK and Rust CLI are fully interoperable

---

## Chapter 3 · Module Boundaries (Crate Topology)

```
            ┌────────────────────────────────────────┐
            │         shell-cli / shell-node         │
            └────┬───────────┬───────────┬───────────┘
                 │           │           │
            ┌────▼────┐ ┌────▼────┐ ┌───▼────┐
            │   rpc   │ │ mempool │ │network │
            └────┬────┘ └────┬────┘ └────┬───┘
                 │           │           │
                 └─────┬─────┴───────────┘
                       │
              ┌────────▼────────┐
              │   consensus     │ (PoA / future wPoA)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │     evm         │ (revm + PQ precompiles)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   storage       │ (RocksDB + MPT)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   genesis       │
              └────────┬────────┘
                       │
       ┌───────────────┼───────────────┐
       │               │               │
   ┌───▼───┐      ┌───▼────┐     ┌────▼─────┐
   │ core  │      │ crypto │     │primitives│
   └───────┘      └────────┘     └──────────┘
                       │              │
                       └──────┬───────┘
                              │
                       ┌──────▼──────┐
                       │   keystore  │
                       └─────────────┘

 Periphery: stark-prover, bench, tools/load-test, tools/stark-bench, tools/multi-prover-test
```

**No reverse dependencies**: lower-level crates (primitives/crypto/core) **must not** depend on upper-level crates (rpc/node/cli).
**No cross-layer shortcuts**: rpc must not call storage directly; it must go through the evm/node interface.

---

## Chapter 4 · Feature Registry (Authoritative)

> Any new or modified feature must simultaneously update this table and `features/README.md`; both must remain consistent.
>
> **Status definitions**: `done` = available on production path | `lib-only` = library code complete but not wired into production path | `scaffold` = research-phase skeleton, not production-ready | `preview` = available but not stable

| Pri | Feature ID | Status | Location | Key invariant |
|-----|-----------|--------|----------|---------------|
| P0 | `primitives` | done | `crates/primitives` | T-7 |
| P0 | `crypto-core` | done | `crates/crypto` | T-1 |
| P0 | `core-types` | done | `crates/core` | T-2, T-5, T-7 |
| P1 | `storage` | done | `crates/storage` | T-8 |
| P1 | `consensus-poa` | done | `crates/consensus/poa.rs` | — |
| P1 | `evm-executor` | done | `crates/evm` | T-1, T-3 |
| P2 | `mempool` | done | `crates/mempool` | T-5, T-9 |
| P2 | `network-p2p` | done | `crates/network` | — |
| P2 | `rpc-server` | done | `crates/rpc` | T-6, T-10 |
| P3 | `node-harness` | done | `crates/node`+`crates/cli` | T-4 |
| P3 | `genesis` | done | `crates/genesis` | §2.4 |
| P3 | **`account-abstraction`** | **done (v0.18.0)** | across `core/evm/mempool/rpc` | T-2, T-5, T-6 |
| P3 | `stark-prover` (L1/async) | preview | `crates/stark-prover` — wired in `node/prover_service.rs` | — |
| P4 | `consensus-wpoa` | **production** ✅ | `crates/consensus/wpoa.rs` — wired into Node/NodeConfig (v0.20.0, W.1-W.7) | §13 |
| P4 | `stark-recursive` (L2) | **scaffold** | `crates/stark-prover/recursive_air.rs`, feature gate `recursive` not enabled | §13 |
| P4 | `prover-registry` (I5) | **lib-only** | `crates/consensus/prover_registry.rs` — not wired into node | §13 |
| P4 | `proof-window-manager` (I4) | **lib-only** | `crates/consensus/window.rs` — not wired into node | §13 |
| P4 | `consensus-peer-scoring` | **production** ✅ | `crates/consensus/peer_scoring.rs` — wired into `Node` via PS.1+PS.2 (v0.20.0) | §13 |

**Drift fix (DRIFT-1)**: `account-abstraction` was previously missing from the `features/README.md` registry; this Constitution normalizes the record.

---

## Chapter 5 · Harness Design Contracts (`crates/node`)

The Harness responsibility is **assembly, not implementation**.

### 5.1 Startup Sequence Contract

```
1. Load NodeConfig (CLI flag → config file → genesis-derived defaults)
2. Validate StorageProfile vs on-disk data (fail-fast)
3. Open RocksDB (or MemoryDb in dev)
4. Init WorldState from ChainStore HEAD (or genesis if empty)
5. Construct ConsensusEngine (PoA from genesis authorities)
6. Construct Mempool (with chain_id from config)
7. Construct EVM Executor (Shanghai spec + PQ precompiles)
8. Spawn JSON-RPC server (HTTP + WS)
9. Spawn libp2p network task (GossipSub + Kademlia + mDNS dev only)
10. Spawn block-production loop (validators only)
11. Spawn /healthz, /readyz, /metrics on observability port
12. Signal ready
```

Any change to the startup sequence requires review by @Harness.

### 5.2 Shutdown Sequence Contract

```
SIGTERM → stop accepting new RPC → drain mempool admit → stop block prod →
flush RocksDB → close P2P → flush metrics → exit
```

**Hard constraint**: shutdown must be graceful; a hard kill may only occur after the graceful timeout (default 30 s).

### 5.3 Trait Boundaries (must not be bypassed)

| Boundary | Trait | Call direction |
|----------|-------|----------------|
| Consensus ↔ Execution | `ConsensusEngine` | node → consensus |
| Execution ↔ Storage | revm `Database` | evm → storage (via WorldState adapter) |
| RPC ↔ Node | `NodeApi` (handler dispatch table) | rpc → node |
| Network ↔ Sync | `SyncProtocol` | network → node sync |
| Crypto ↔ Verify | `Signer` / `Verifier` | crypto consumers → crypto |

---

## Chapter 6 · RPC Contract

### 6.1 Naming Convention (T-6)

- **Request/response fields**: `snake_case` (Rust default)
- **Method names**: preserve Ethereum namespace conventions
  - `eth_*` — Ethereum compatible; field names retain camelCase (only this namespace is exempt)
  - `shell_*` — project-specific; all snake_case
  - `net_*` / `web3_*` — compatible
  - `admin_*` / `debug_*` / `evm_*` — internal, snake_case
- **Rust types**: Shell-specific request/response structs such as `BatchEstimateRequest` **must not** use `#[serde(rename_all = "camelCase")]`

### 6.2 Compatibility Tiers

| Tier | Meaning | When to bump minor |
|------|---------|-------------------|
| **Stable** | `eth_*`, `net_*`, `web3_*`, published `shell_*` | Fields may only be added (must be `Option`); field names/types cannot change |
| **Preview** | `shell_*`/`debug_*` marked `(preview)` | Breaking changes allowed; must be noted in CHANGELOG |
| **Internal** | `admin_*`, `evm_*` (dev mode only) | Free to change |

### 6.3 Error Conventions (T-10)

- Must use the named constructors from `crates/rpc/src/error.rs`; bare `-32xxx` codes are forbidden
- "Not found" and "not enabled" are distinct: `NOT_FOUND` vs `FEATURE_NOT_ENABLED`
- Internal details are not exposed to clients (`internal_err()` sanitizes automatically)

### 6.4 Current v0.18.0 RPC Surface (excerpt)

**AA Phase 1**:
- `shell_estimateBatch(request) → {total_gas, outer_intrinsic, inner_sum, intrinsic_surcharge, per_inner[], paymaster}`
- `shell_getPaymasterPolicy(address) → {address, has_pq_pubkey, pubkey_bytes, balance, policy, max_gas_sponsorship}`
- `shell_isSponsored(tx_hash) → {found, location, is_aa_bundle, sponsored, paymaster, sender, inner_call_count}`

**Ops**:
- `shell_getStorageProfile() → StorageProfileInfo`
- `shell_getWitness(block, addr) → {proof, state_root, ...}`
- `shell_verifyWitnessRoot(block) → {ok, reason}`
- `/metrics` (Prometheus), `/healthz`, `/readyz`

---

## Chapter 7 · Security Invariants

| # | Invariant | Location |
|---|-----------|----------|
| S-1 | `ecrecover` precompile permanently disabled; calls return OOG | `evm/src/precompiles.rs` |
| S-2 | Mempool admission must perform PQ signature verification | `mempool/src/pool.rs` |
| S-3 | AA bundle admission must verify paymaster signature (from v0.18.0-patch1) | `evm/src/aa_validation.rs` |
| S-4 | AA bundle admission must verify paymaster balance (from v0.18.0-patch1) | `mempool/src/pool.rs` |
| S-5 | RPC CORS defaults to None (same-origin); must be explicitly enabled | `rpc` config |
| S-6 | `eth_call`/`eth_estimateGas` gas cap = 50 M (`RPC_GAS_CAP`) | `rpc/src/handler/mod.rs:353` |
| S-7 | RPC error details are logged server-side; clients see only generic errors | `rpc/src/error.rs::internal_err` |
| S-8 | `BlockRequest` count capped at `MAX_BLOCK_RESPONSE=128` to prevent OOM DoS | `node/src/node/event_loop.rs:368` |
| S-9 | Mempool tx size capped at `MAX_TX_SIZE = 128 KiB` | `mempool/src/pool.rs` |
| S-10 | Block timestamp must not exceed `now + DEFAULT_MAX_FUTURE_SECS=60s` | `consensus/src/poa.rs:29` |
| S-11 | Different hash domains are strictly isolated (legacy / batch / paymaster) | `core/src/transaction.rs` |
| S-12 | Config changes (CORS / dev mode / feature flag) must fail-secure | various configs |

**Any PR that weakens the above invariants requires review by @Security.**

---

## Chapter 8 · Testing and Quality Gates

### 8.1 Minimum Bar for Merging to main

- ✅ `cargo build --workspace` passes
- ✅ `cargo test --workspace` 0 failures
- ✅ `cargo clippy --workspace --all-targets -- -D warnings` passes
- ✅ `cargo fmt --check` passes
- ✅ CHANGELOG updated
- ✅ When the RPC contract is affected, `docs/rpc-reference.md` is updated in sync
- ✅ When the wire format is affected, spec documents are updated in sync

### 8.2 e2e Test Coverage (must be maintained)

- `tests/e2e/aa_batch_test.rs` — 9 cases
- `tests/e2e/aa_sponsored_test.rs` — 6 cases
- Any AA modification must not reduce the above e2e counts

### 8.3 Review Board Trigger Conditions

| Change scope | Roles required |
|-------------|----------------|
| Constitution clauses | All roles |
| Wire format / hash domain | @Architecture, @PQCrypto, @Security, @Harness |
| RPC contract | @Architecture, @Security, @Quality |
| Storage profile / data layout | @Architecture, @Harness |
| Consensus parameters | @Architecture, @Security |
| Weakening a security invariant | @Security (veto power) |
| General feature | @Architecture, @Quality |

---

## Chapter 9 · Release and Version Governance

### 9.1 SemVer Rules

shell-chain `0.x.y` is in **pre-1.0**:
- `x` (minor) — new features / breaking changes accepted; must add `BREAKING:` at the top of the CHANGELOG entry
- `y` (patch) — bug fixes / docs / internal changes that do not break the wire or RPC contract
- Cross-minor wire format changes must include a migration document

### 9.2 Release Process

```
feature freeze
  → tag vX.Y.Z on contributor fork or release branch
  → PR contributor branch → ShellDAO:main
  → CI green
  → @Architecture + @Security sign off
  → merge → GitHub Release
  → notify SDK team to bump
  → SDK release
  → notify wallet/explorer teams to bump
  → notify site team to publish release notes
```

**Prohibited**: pushing commits directly to ShellDAO/shell-chain; all changes must go through a PR.

### 9.3 Cross-Repo Sequencing

```
shell-chain release
   ↓ (RPC schema lands)
shell-sdk release (npm publish)
   ↓
wallet + explorer bump sdk dep
   ↓
shell-site release notes / blog
```

### 9.4 Version Alignment (baseline v0.21.0)

| Repo | Version | Notes |
|------|---------|-------|
| shell-chain | 0.21.0 | F-PQ1-ONLY: pq1-only addresses + STARK proof integration + fork finality |
| shell-sdk | 0.7.0 | F-PQ1-ONLY: getAddress() pq1, getHexAddress() removed, v0.7.0 breaking |
| shell-explorer | 0.20.0 | F-PQ1-ONLY: all 0x addresses → pq1; faucet service proxied |
| shella-chrome-wallet | 0.20.0 | aligned with chain v0.20.x |
| shell-site | 0.20.0 | docs aligned with chain v0.20.x |

---

## Chapter 10 · Drift Audit Protocol

### 10.1 Trigger Conditions

- A full drift audit **must** be performed before every minor release
- A single-point drift discovery may trigger an immediate audit
- Quarterly rolling audit (even without a release)

### 10.2 Five Tracks

| Track | Scope | Lead reviewer |
|-------|-------|---------------|
| **A — Wire Format** | Serialization, hash domain, tx type | @Architecture |
| **B — Execution** | EVM/AA/mempool validation flow | @Security |
| **C — RPC Contract** | Request/response fields, error codes, doc alignment | @Quality |
| **D — Infrastructure** | Storage / consensus / genesis parameters | @Harness |
| **E — Docs/Version** | CHANGELOG / README / spec consistency | @Quality |

### 10.3 Severity Levels

| Level | Disposition |
|-------|------------|
| 🔴 Critical | Must be fixed before release; vetoes publication |
| 🟠 Medium | Fix within current release patch; does not block main version |
| 🟡 Low | Track as an issue; fix in next release |

### 10.4 Historical Audits

- v0.18.0 → v0.18.0-patch1 (2026-04-24): Fixed all 5 new RPC camelCase→snake_case regressions + paymaster mempool security hardening. See CHANGELOG `[0.18.0-patch1]`.

---

## Chapter 11 · Agent Review Governance (FDD Reviews)

### 11.1 Roles

The Review Board for shell-chain consists of five roles. Each role is filled by an agent or contributor with the corresponding specialization. Roles are defined here; no external role definition files are required.

| Role | Responsibility |
|------|----------------|
| **@Architecture** | Layering, trait boundaries, design consistency |
| **@Quality** | Code quality, test coverage, maintainability |
| **@Security** | Vulnerabilities, input validation, key management (veto power over any PR weakening security) |
| **@Harness** | Node assembly, startup/shutdown sequences, configuration consistency |
| **@PQCrypto** | PQ algorithm selection, signature formats, cryptographic correctness |

### 11.2 Review Session Archiving

Every Review Board session must record the following:
- Triggering PR / commit hash
- Per-role finding list (with severity)
- Disposition: RESOLVED / ACCEPTED / DEFERRED
- F-number (globally unique, monotonically increasing)

Review session records are kept in the shell-dev orchestration workspace; see project README for details.

### 11.3 Archived Reviews

Review session records are kept in the shell-dev orchestration workspace; see project README for details.

---

## Chapter 13 · Implementation Status Inventory

> Audit date: 2026-04-25. Verified by actual `grep`/`wc -l`, not self-reported.

### 13.1 Fully Implemented and Wired into Production Path ✅

| Component | File / Location | Notes |
|-----------|----------------|-------|
| PoA Consensus | `consensus/poa.rs` (1095 lines) | Only consensus engine in Node; full test coverage |
| **wPoA Consensus** ✅ **v0.20.0** | `consensus/wpoa.rs` + `consensus/validator.rs` | W.1-W.7 all wired; CLI `--consensus-engine wpoa` |
| Double-sign Slashing | `consensus/slashing.rs` (380 lines) | Wired into `block_importer.rs` + `event_loop.rs` |
| Fork Choice | `consensus/fork_choice.rs` (658 lines) | Node holds `Arc<RwLock<ForkChoice>>` |
| Finality State | `consensus/finality.rs` (726 lines) | Node holds instance; drives pruning |
| Validator Epoch Rotation | `node/mod.rs:318` | Reloads consensus authority list across epochs |
| AA Phase 1 (AaBundle + Paymaster) | across `core/evm/mempool/rpc` | v0.18.0 + patch1 |
| EVM (revm + PQ precompiles) | `crates/evm` | ecrecover disabled; Dilithium verify at 0x0100 |
| **Dilithium3** | `crypto/dilithium.rs` (427 lines) | Backward-compatible scheme; `key_type="dilithium3"`, `algo_id=0` |
| **ML-DSA-65 (FIPS 204)** ✅ **v0.20.0** | `crypto/mldsa.rs` | Independent algorithm (not a Dilithium3 alias); `key_type="mldsa65"`, `algo_id=1`; `fips204` crate; SIG_IDS fixed |
| SPHINCS+ | `crypto/sphincs.rs` (277 lines) | Alternative scheme; MultiVerifier support |
| **Keystore v1 (sk-only)** ✅ **v0.20.0** | `crates/keystore` | Unified sk-only format; `shell-sdk` + Rust CLI fully interoperable; ks-3/ks-4 bidirectional tests |
| **CLI Non-interactive Password** ✅ **v0.20.0** | `crates/cli/src/password.rs` | `--password-file`/`--password-stdin`/`SHELL_KEYSTORE_PASSWORD` (with `--allow-env-password`) |
| P2P Network | `crates/network` (libp2p + PeerTracker) | Gossipsub/Kademlia/mDNS; peer scoring wired |
| Storage (RocksDB) | `crates/storage` (5 CFs) | body/witness/state pruning fully wired |
| Proof Challenge/Response (I2) | `event_loop.rs:535-568` | Broadcasts challenge, verifies and stores response |
| Stark Prover L1 + async (I3) | `node/prover_service.rs` | L1 per-block + L2 async backlog wired |
| NodeRole (Validator/ValidatorProver/Prover) | `node/config.rs:26` | CLI-configurable; event_loop branches |
| Idle-skip Heartbeat | `node/event_loop.rs:190-210` | Default 60s |
| All v0.18.0 RPC | `crates/rpc` | snake_case; 6 `shell_*` methods |
| **ProofWindowManager** (I4) ✅ **v0.19.0-dev** | `consensus/window.rs` + `node/mod.rs` | `advance()` called each block; `gc()` every 100 blocks; §13.2 → production |
| **pq1-only address format (F-PQ1-ONLY)** ✅ **v0.21.0** | full stack | CLI/RPC/SDK/genesis/keystore/explorer all enforce `pq1...` bech32m; T-1 invariant strengthened; `0x` input paths removed |
| **STARK aggregation proof integration (STK.1–STK.5)** ✅ **v0.21.0** | `node/prover_service.rs` + `rpc/handler/shell_api.rs` | `--enable-stark-aggregation` default true; RPC fallback ProofAmendmentStore; `shell_getProofAmendment` added; metric counter |
| **Faucet PQ signing (FAU.1–FAU.5)** ✅ **v0.21.0** | faucet service (external to shell-chain crate) | shell-sdk signing replaces ethers; keystore auth; `/drip` endpoint |

### 13.2 Library Code Complete but Not Wired into Production Path ⚠️ lib-only

| Component | File | Lines | Missing wire-up point | Next-phase plan |
|-----------|------|-------|----------------------|-----------------|
| **ProverRegistry** (I5) | `consensus/prover_registry.rs` | 329 | Not held by Node; on-chain stake verification explicitly deferred in comments | Needs `Node` to hold instance + on-chain interaction interface |
| **ProofRateLimiter** | `consensus/rate_limiter.rs` | 250 | Not used by node | Enable together with ProverRegistry |

> **v0.20.0 upgrade**: wPoA Engine (`consensus/wpoa.rs`), ValidatorSet (`consensus/validator.rs`), and Consensus PeerScoring (`consensus/peer_scoring.rs`) are all wired into the Node production path and removed from this list.

### 13.3 Research-Phase Skeleton, Not Production-Ready 🔬 scaffold

| Component | File | Notes |
|-----------|------|-------|
| **Recursive L2 STARK** | `stark-prover/recursive_air.rs` (363 lines) | Comments explicitly state "research-phase scaffold"; feature gate `recursive` undefined/not enabled; AIR transition constraints are placeholders |

### 13.4 Pending Activation / Pending Implementation 📋 planned

| Item | Current status | Notes |
|------|---------------|-------|
| Mainnet (chain_id = 1) | Reserved, not activated | genesis/node supports Mainnet config but no public mainnet |
| On-chain Stake Verification (ProverRegistry) | Deferred in comments | Requires EVM contract interaction |
| Recursive STARK L2 | scaffold | Requires complete mathematical proof + feature enablement |
| **AA Phase 2** (Contract Paymaster + Session Keys + Guardian Recovery) | ✅ v0.19.0 complete | `docs/AA_PHASE2_SPEC.md`; live |

> **v0.20.0 upgrade**: wPoA wired into production (W.1-W.7), Peer Scoring bridged (PS.1-PS.2), public testnet (chain_id=10) launched (T.1-T.6) — all removed from §13.4.

### 13.5 Key Distinction: `consensus/peer_scoring.rs` vs `network/security.rs`

**v0.20.0 status: both bridged and in the production path.**

Two layers of peer scoring work together:

- **`consensus/peer_scoring.rs` (`PeerScorer`)** — high-level behavioral scoring (wPoA vote quality).
  `Node.peer_scorer` holds the instance; `handle_wpoa_vote()` drives scoring:
  - `DuplicateVote` → `DuplicateMessage` penalty (-2)
  - `WrongBlockHash` → `InvalidProofPayload` penalty (-20)
  - `BlockCommitted` → `ValidProofDelivered` reward (+5, per quorum signer)
  After each wPoA vote, `flush_scorer_bans()` feeds peers below the disconnect threshold into `PeerBanList`.

- **`network/security.rs` (`PeerBanList` + `PeerTracker`)** — P2P layer banning.
  `Node.peer_ban_list` holds `PeerBanList` (3 violations → 5-minute ban).
  `ScoringPeerId(String)` ↔ `PeerId(String)` bridging occurs in `flush_scorer_bans()`.

Bridge implementation is in `crates/node/src/node/p2p_handlers.rs::flush_scorer_bans()`,
called after `NetworkMessage::WPoaVote` handling in `event_loop.rs`.

---


| Version | Date | Change | Review |
|---------|------|--------|--------|
| 1.0 | 2026-04-24 | Initial version, baseline v0.18.0-patch1. Canonicalized T-1~T-10, §2 SSOT constant table, §3 module topology, §4 feature registry, §5 harness contracts, §6 RPC contract, §7 security invariants, §8 quality gates, §9 release governance, §10 drift audit, §11 review governance | TBD |
| 1.2 | 2026-04-25 | §4 feature registry expanded with P4 lib-only/scaffold entries (wPoA, recursive STARK, ProverRegistry, ProofWindowManager, consensus PeerScoring). Added §13 implementation status inventory (13.1 production-ready ✅ / 13.2 lib-only ⚠️ / 13.3 scaffold 🔬 / 13.4 planned / 13.5 dual peer-scoring distinction). Version bumped to 1.2. | @Architecture, @Quality |
| 1.3 | 2026-04-25 | v0.19.0-dev scope frozen: I4 ProofWindowManager promoted from lib-only to production (§13.1); removed from §13.2; §13.4 added AA Phase 2 entry (spec complete, implementation pending); §9.4 version table updated to 0.19.0-dev; dual PQ sig dedup fix (Track B) noted in §13.1; peer_scoring comments updated for wPoA-era. | @Architecture, @Quality |
| 1.4 | 2026-05-XX | v0.20.0-dev scope frozen: wPoA consensus engine promoted from lib-only to production (§13.1); consensus PeerScoring promoted from lib-only to production (§4 + §13.5 fully rewritten); PS.1+PS.2 bridge two scoring layers; testnet chain_id=10; F-TESTNET-LAUNCH T.1-T.6 launched. | @Architecture, @Quality |
| 1.5 | 2026-04-29 | F-TESTNET-FIXES complete: ML-DSA-65 (FIPS 204) independent algorithm (not a Dilithium3 alias, `algo_id=1`, `mldsa.rs`) promoted to §13.1; Keystore v1 sk-only unified format (SDK + Rust CLI bidirectional compat, ks-3/ks-4 tests) promoted to §13.1; CLI non-interactive password (`--password-file`/`--password-stdin`/env-var) promoted to §13.1; SIG_IDS bugfix (ML-DSA-65 addr derivation); testnet restarted at genesis-0 (ML-DSA-65 validator + 10 Dilithium3 test accounts). | @Architecture, @Quality |
| 1.6 | 2026-05-02 | **F-PQ1-ONLY complete**: `0x` hex address format completely removed from all user-layer interfaces (CLI, RPC, SDK, genesis, keystore, explorer, faucet); `pq1...` bech32m is the only valid address format. T-1 invariant strengthened: any input path accepting an address rejects `0x` format. STARK aggregate proof integration (STK.1–STK.5): `--enable-stark-aggregation` default `true`; `shell_getProofAmendment` RPC; RPC fallback to `ProofAmendmentStore`. Fork finality released as stable. Faucet migrated to shell-sdk PQ signing (no ethers). New docs: `stark-aggregation.md`, `genesis-format.md`. Version bumped to 0.21.0. | @Architecture, @PQCrypto, @Quality |

---

## Appendix A · Referenced Documents

- Harness detailed design (historical planning document)
- Release milestone roadmap (historical planning document)
- `features/README.md` — Feature registry
- `../AA_BATCH_AND_SPONSORED_SPEC.md`
- `../CONSENSUS_DETAILS.md`
- `../storage-profiles.md`
- `../rpc-reference.md`
- `../observability.md`
- `../../CHANGELOG.md`
