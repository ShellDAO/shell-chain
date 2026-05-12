# Feature: Genesis

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Defines the genesis block configuration format and initialization flow:
loading a JSON genesis config, applying initial account allocations to world
state, registering the initial validator set, marking system-contract addresses,
computing the genesis state root, producing Block #0, and persisting it with
the `ChainConfig` record. Also exports `initialize_authority_pubkeys` for
writing initial validator PQ public keys into the pubkey registry as a
separate startup step.

The crate lives at `shell-chain/crates/genesis` — not in `core` or `node`
as the M2 draft stated.

## 2. Public API surface

All items re-exported from `shell-chain/crates/genesis/src/lib.rs:1-8`:

| Symbol | Kind | Notes |
|--------|------|-------|
| `GenesisConfig` | struct | Top-level JSON-loadable genesis configuration |
| `AllocEntry` | struct | Initial account entry: `balance: U256`, optional `nonce: u64`, optional `code` |
| `ConsensusConfig` | struct | Consensus-specific genesis params; provides `authorities()` and `authority_weights()` |
| `NetworkType` | enum | `Dev` / `Testnet` / `Mainnet` — drives default parameters |
| `NetworkParams` | struct | Network-specific defaults derived from `NetworkType` |
| `GenesisError` | enum | Initialization errors |
| `initialize_genesis` | fn | Main entry point: produces and persists Block #0 |
| `initialize_authority_pubkeys` | fn | Separate startup step: writes PQ pubkeys for initial validators |

### `NetworkType` and `NetworkParams` (`config.rs:1-100`)

| `NetworkType` variant | `block_time_ms` | `stark_aggregation` | `min_validators` | `slashing_enabled` |
|-----------------------|-----------------|---------------------|------------------|--------------------|
| `Dev` (default) | 30 000 ms | `false` | 1 | `false` |
| `Testnet` | 2 000 ms | `true` | 3 | `true` |
| `Mainnet` | 2 000 ms | `true` | 5 | `true` |

Additional `NetworkParams` fields: `max_tx_per_block`, `async_prover`,
`proof_challenge_window`.

`NetworkType::default_block_time_ms(self) -> u64` — convenience accessor.
`NetworkType::default_params(self) -> NetworkParams` — full defaults.
`NetworkType::from_network_str(s: &str) -> NetworkType` — parse from CLI flag.

### `GenesisConfig` structure

```rust
pub struct GenesisConfig {
    pub chain_id: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub network_type: NetworkType,          // default: Dev
    pub consensus: ConsensusConfig,
    pub alloc: HashMap<Address, AllocEntry>,
    pub extra_data: Bytes,                  // optional; default empty
    pub boot_nodes: Vec<String>,            // multiaddr strings; optional
}
```

JSON example with correct authority format:

```json
{
  "chain_id": 1337,
  "timestamp": 0,
  "gas_limit": 30000000,
  "network_type": "Dev",
  "consensus": {
    "engine": "wpoa",
    "block_interval_ms": 2000,
    "authorities": [
      "0xabcd...1234",
      "0xef01...5678"
    ],
    "weights": [1, 1]
  },
  "alloc": {
    "pq1abc...": { "balance": "1000000000000000000000" }
  }
}
```

> ⚠️ **Authority format**: `ConsensusConfig.authorities` stores 20-byte
> `Address` values, NOT `pq1…` bech32m strings in the wire format — Address
> handles its own JSON serialization as bech32m. Authority **PQ public key bytes**
> (not addresses) are passed to `initialize_authority_pubkeys` separately.
> The genesis config does not embed raw public key bytes.

### `initialize_genesis` (`init.rs:1-80`)

```rust
pub fn initialize_genesis<S: KvStore + 'static>(
    config: &GenesisConfig,
    store: Arc<S>,
) -> Result<Block, GenesisError>
```

Steps performed:
1. Apply `alloc` entries to `WorldState`
2. Set initial validators and weights in world state via `WorldState::set_validators` / `set_validator_weights`
3. Mark native system-contract addresses (`AccountManager`, `ValidatorRegistry`) with placeholder code hashes
4. Compute `state_root`
5. Build `BlockHeader` (number=0, parent_hash=ZERO)
6. Write the block to `ChainStore`
7. Persist `ChainConfig { chain_id, genesis_hash }`

### `initialize_authority_pubkeys` (`init.rs`)

```rust
pub fn initialize_authority_pubkeys<S: KvStore + 'static>(
    config: &GenesisConfig,
    pubkeys: &[(Address, Vec<u8>)],  // address → raw PQ pubkey bytes
    store: Arc<S>,
) -> Result<(), GenesisError>
```

Distinct from `initialize_genesis`. Called at node startup (after genesis block
exists) to write PQ public keys for initial validators into the pubkey registry
in world state. Takes raw PQ public key bytes — not `pq1…` bech32m addresses.

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| `GenesisConfig`, `AllocEntry`, `ConsensusConfig`, `NetworkType`, `NetworkParams` | `config.rs` | `genesis/src/config.rs:1-200` |
| `initialize_genesis`, `initialize_authority_pubkeys` | `init.rs` | `genesis/src/init.rs:1-120` |
| Public re-exports | `lib.rs` | `genesis/src/lib.rs:1-8` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-1 (PQ-Native)**: `initialize_authority_pubkeys` stores raw PQ public key bytes. The keys must be Dilithium3 or ML-DSA-65 bytes matching `ALLOWED_ALGORITHMS`.
- **`NetworkType::Dev` is the default** for genesis configs that omit the field — always check `network_type` before assuming mainnet parameters.
- **Genesis block must be idempotent**: calling `initialize_genesis` twice on the same store is safe iff the genesis hash already matches. A mismatch signals a different chain identity and must be rejected.
- **State root determinism**: given the same `alloc` and `consensus` config, `initialize_genesis` must always produce the same `state_root`. This is enforced by deterministic ordering of alloc application.
- **System contracts must be marked at genesis** (`mark_system_contract` call in `initialize_genesis`) — the EVM `is_system_contract()` check relies on these code hashes being present from block 0.
- **`consensus.authorities` are `Address` values** — NOT raw pubkey bytes. Raw pubkeys are passed to `initialize_authority_pubkeys` separately. Mixing the two is a protocol error.

## 5. Tests

```
cargo test -p shell-genesis
```

Key tests and locations:

| Test | File |
|------|------|
| `parse_genesis_json` | `config.rs` |
| `consensus_config_is_poa` | `config.rs` |
| `alloc_entry_with_nonce` | `config.rs` |
| `roundtrip_json` | `config.rs` |
| `serialized_genesis_uses_bech32m_addresses` | `config.rs` |
| `defaults_applied` | `config.rs` |
| `boot_nodes_deserialization` | `config.rs` |
| `boot_nodes_optional_defaults_to_empty` | `config.rs` |
| `boot_nodes_roundtrip_json` | `config.rs` |
| `network_type_default_is_dev` | `config.rs` |
| `initialize_genesis_produces_block_zero` | `init.rs` |
| `genesis_state_root_is_deterministic` | `init.rs` |

## 6. Related ADRs

- CONSTITUTION T-1 (PQ-Native — authority pubkeys must be PQ)
- CONSTITUTION T-3 (EVM Compatible — system contracts must be registered at genesis)
- CONSTITUTION §2.3 (Address derivation — `Address` not raw pubkey in genesis authorities list)

## 7. Known limitations / open work

- `initialize_authority_pubkeys` is not yet called automatically by the node on first boot; the CLI `genesis` command must be run explicitly or the node operator must call it.
- `ConsensusConfig` does not support heterogeneous key types per validator (e.g., one Dilithium3, one ML-DSA-65) — all validators in a genesis config share a single algorithm. Mixed-algorithm genesis is a future work item.
- `boot_nodes` in `GenesisConfig` are stored but not automatically applied to `NetworkConfig` at startup; the node harness reads them separately from `NodeConfig`.

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; crate location corrected to `crates/genesis`; `NetworkType` (Dev/Testnet/Mainnet) and `NetworkParams` documented; `initialize_authority_pubkeys` documented and distinguished from `initialize_genesis`; authority format corrected (Address values, not `pq1…` strings, not raw bytes); JSON example corrected; system-contract marking step noted
