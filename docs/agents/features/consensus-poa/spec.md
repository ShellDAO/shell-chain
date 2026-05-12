# Feature: Consensus PoA / WPoA

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

## 1. Purpose

Implements Shell-Chain's consensus framework: a pluggable `ConsensusEngine`
trait with two concrete engines (`PoaEngine` basic round-robin,
`WPoaEngine` weighted round-robin), a live validator set with
`Pending → Active → Exiting → Exited / Slashed` lifecycle, slashing evidence
detection and propagation, a standalone prover registry (I5 anti-Sybil), proof
submission window management (I4 squatting prevention), fork choice, finality
tracking, and P2P peer quality scoring.

## 2. Public API surface

All items re-exported from `shell-chain/crates/consensus/src/lib.rs:1-33`:

### Core engine trait and types

| Symbol | Kind | Notes |
|--------|------|-------|
| `ConsensusEngine` | trait | Pluggable consensus interface |
| `EngineType` | enum | `PoA`, `WPoA`, `BFT` (reserved) |
| `ConsensusError` | enum | Unified error type |

**`ConsensusEngine` trait** (`engine.rs:27-70`):

```rust
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    fn verify_header(&self, header: &BlockHeader) -> Result<(), ConsensusError>;
    async fn seal_block(&self, block: &mut Block) -> Result<(), ConsensusError>;
    fn is_proposer(&self, slot: u64, address: &Address) -> bool;
    fn engine_type(&self) -> EngineType;
    fn poa_config(&self) -> &PoaConfig;
    fn poa_config_mut(&mut self) -> &mut PoaConfig;
    fn set_authorities(&mut self, authorities: Vec<Address>);
    fn set_authorities_with_weights(&mut self, authorities: Vec<Address>, weights: Vec<u64>);
}
```

### Basic PoA engine

| Symbol | Notes |
|--------|-------|
| `PoaEngine` | Round-robin proposer: `proposer = authorities[slot % authorities.len()]`; `slot = timestamp / block_interval` |
| `PoaConfig` | `authorities: Vec<Address>`, `block_interval_ms: u64` |

### Weighted PoA engine (active in production)

| Symbol | Notes |
|--------|-------|
| `WPoaEngine` | Weighted round-robin: `slot = block_number % total_weight`; validator with cumulative-weight window containing `slot` is elected |
| `WPoaConfig` | `poa: PoaConfig`, `weights: Vec<u64>` (indexed by position in `poa.authorities`), `validator_set_config: ValidatorSetConfig` |

**Weighted proposer selection** (`wpoa.rs:11-14`):
- `total_weight = sum(active validator weights)`
- `slot = block_number % total_weight`
- Walk the active validator list accumulating weight until the window covering `slot` is found — that validator is the proposer
- Missing weight entries default to `1`

### Validator set

| Symbol | Notes |
|--------|-------|
| `ValidatorSet` | Live validator set with weighted round-robin selection and lifecycle management |
| `ValidatorInfo` | `address`, `weight: u64`, `status: ValidatorStatus`, `activation_epoch`, `exit_epoch` |
| `ValidatorStatus` | `Pending` / `Active` / `Exiting { exit_epoch }` / `Exited` / `Slashed` |
| `ValidatorSetConfig` | Lifecycle parameters: cooldown epochs, min/max validator counts |

### Slashing (I1 equivocation detection)

| Symbol | Notes |
|--------|-------|
| `detect_double_sign(header_a, header_b) -> Option<SlashRecord>` | Detects same-height different-hash from same proposer |
| `detect_offline(missed_slots, threshold) -> Option<SlashRecord>` | Detects consecutive slot misses |
| `EquivocationProof` | Broadcastable bundle: `offender`, `header_a`, `header_b`, `hash_a`, `hash_b` |
| `SlashEvidence` | `DoubleSign { header_a, header_b }` / `Offline { missed_slots }` |
| `SlashRecord` | `offender: Address`, `evidence: SlashEvidence`, `slash_type: SlashType` |
| `SlashType` | `DoubleSign` / `Offline` |
| `SlashingConfig` | Penalty parameters per slash type |

### Proof submission window (I4)

| Symbol | Notes |
|--------|-------|
| `ProofWindowManager` | Tracks per-block proof windows; enforces claim/submission lifecycle |
| `WindowConfig` | `window_size_blocks: 100`, `claim_timeout_blocks: 20`, `max_expired_claims: 3` |
| `WindowState` | `Unclaimed` / `Claimed { claimer, expires_at_block }` / `Submitted` / `Expired` |
| `WindowError` | Window management errors (already claimed, expired, etc.) |

### Prover registry (I5 anti-Sybil)

| Symbol | Notes |
|--------|-------|
| `ProverRegistry` | Tracks registered standalone prover nodes with reputation scoring |
| `ProverRecord` | `address`, `stake: u64`, `reputation: i64`, `registered_at` |
| `ProverRegistryConfig` | `min_stake: 1000`, `initial_reputation: 100`, `min_reputation: 0`, decay/penalty rates |
| `RegistryError` | Insufficient stake, already registered, etc. |

**Reputation mechanics** (`prover_registry.rs:30-60`):
- Initial reputation: `100`; decays `-1` per 100 idle blocks
- `+10` per successful proof, `-20` per expired window claim (I4 linkage), `-50` per invalid proof
- Reputation < `min_reputation` (0) → automatic deregistration

### Proof rate limiter

| Symbol | Notes |
|--------|-------|
| `ProofRateLimiter` | Prevents proof spam; token-bucket or block-count based |
| `RateLimiterConfig` | Rate limit parameters |

### Fork choice

| Symbol | Notes |
|--------|-------|
| `ForkChoice` | Selects canonical chain tip from competing heads |
| `BlockScore` | Scoring components for fork comparison (total weight, timestamp, hash tiebreak) |

### Finality

| Symbol | Notes |
|--------|-------|
| `FinalityState` | Tracks finalized block height and attestation accumulation |
| `Attestation` | Validator signature on a block hash confirming finality |

### Peer scoring

| Symbol | Notes |
|--------|-------|
| `PeerScorer` | Per-peer quality score for consensus-layer gossip prioritization |
| `PeerEvent` | Events that affect peer score (valid block, invalid block, timeout, etc.) |
| `PeerScoringConfig` | Score deltas per event type, decay rate |
| `ScoringPeerId` | Opaque peer identity (re-exported as `consensus::ScoringPeerId`) |

### Fraud challenges

| Symbol | Notes |
|--------|-------|
| `ProofChallenge` | Challenge record: `block_hash`, `challenger`, `reason` |
| `ChallengeReason` | Reason for challenge (invalid proof, missing witness, etc.) |
| `ChallengeResponse` | Response from the challenged prover |

### Round state machine (`wpoa_state.rs`)

| Symbol | Notes |
|--------|-------|
| `WPoaRound` | State of one wPoA round: proposer, start time, received seals |
| `WPoaEvent` | Events driving round transitions |

## 3. Implementation map

| Concern | Module | File:Line |
|---------|--------|-----------|
| `ConsensusEngine` trait, `EngineType` | `engine.rs` | `consensus/src/engine.rs:1-80` |
| Basic `PoaEngine`, `PoaConfig` | `poa.rs` | `consensus/src/poa.rs` |
| `WPoaEngine`, `WPoaConfig`, weighted selection | `wpoa.rs` | `consensus/src/wpoa.rs:1-60` |
| `WPoaRound`, `WPoaEvent` | `wpoa_state.rs` | `consensus/src/wpoa_state.rs` |
| `ValidatorSet`, `ValidatorInfo`, `ValidatorStatus` | `validator.rs` | `consensus/src/validator.rs:1-120` |
| `SlashEvidence`, `EquivocationProof`, `detect_*` | `slashing.rs` | `consensus/src/slashing.rs:1-80` |
| `ProofWindowManager`, `WindowConfig`, `WindowState` | `window.rs` | `consensus/src/window.rs:1-80` |
| `ProverRegistry`, `ProverRecord`, `ProverRegistryConfig` | `prover_registry.rs` | `consensus/src/prover_registry.rs:1-80` |
| `ProofRateLimiter`, `RateLimiterConfig` | `rate_limiter.rs` | `consensus/src/rate_limiter.rs` |
| `ForkChoice`, `BlockScore` | `fork_choice.rs` | `consensus/src/fork_choice.rs` |
| `FinalityState`, `Attestation` | `finality.rs` | `consensus/src/finality.rs` |
| `PeerScorer`, `PeerEvent`, `PeerScoringConfig` | `peer_scoring.rs` | `consensus/src/peer_scoring.rs` |
| `ProofChallenge`, `ChallengeReason`, `ChallengeResponse` | `challenge.rs` | `consensus/src/challenge.rs` |
| Error type | `error.rs` | `consensus/src/error.rs` |
| Public re-exports | `lib.rs` | `consensus/src/lib.rs:1-33` |

## 4. Invariants (cross-ref CONSTITUTION & ADRs)

- **T-1 (PQ-Native)**: `seal_block` must sign the block header with a PQ key (Dilithium3 or ML-DSA-65). ECDSA sealing is permanently prohibited.
- **`EngineType::BFT` is reserved**: The enum variant exists for forward-compatibility only; no `BFT` implementation exists in v0.22.x.
- **`WPoaEngine` supersedes `PoaEngine` in production**: `NodeConfig` activates `WPoA` when `validator_set_config` carries weights. `PoaEngine` is kept for single-validator devnet (`NetworkType::Dev`).
- **Weighted round-robin formula** (`wpoa.rs:11-14`): proposer = validator whose cumulative weight covers `block_number % total_weight`. The old `slot = timestamp / block_interval` formula applies only to `PoaEngine`.
- **Equivocation proofs must be broadcast** (`slashing.rs` I1): when a double-sign is detected during `import_block`, an `EquivocationProof` is sent via `NetworkMessage::EquivocationEvidence`. Receiving nodes independently verify before applying.
- **`SlashType::Slashed` is immediate**: a slashed validator is removed from the active set at the current block; there is no cooldown period for `DoubleSign`.
- **I4/I5 coupling**: `ProverRegistry::penalize()` is called by `ProofWindowManager` when a prover's claim expires (`max_expired_claims` threshold).

## 5. Tests

```
cargo test -p shell-consensus
```

Key test areas:

| Concern | File |
|---------|------|
| `WPoaEngine` weighted proposer selection | `wpoa.rs` |
| `ValidatorSet` lifecycle transitions | `validator.rs` |
| `detect_double_sign` / `detect_offline` | `slashing.rs` |
| `ProofWindowManager` claim/expire/submit | `window.rs` |
| `ProverRegistry` registration + reputation decay | `prover_registry.rs` |
| `ForkChoice` canonical tip selection | `fork_choice.rs` |
| `PeerScorer` score accumulation | `peer_scoring.rs` |

## 6. Related ADRs

- CONSTITUTION T-1 (PQ-Native — PQ sealing mandatory)
- CONSTITUTION T-4 (Modular Harness — consensus/node boundary via trait)
- `../adrs/ADR-004-l2-aggregation-scaffold.md` (wPoA + STARK prover coupling)
- `../adrs/ADR-002-stark-tx-level-settlement.md` (ProofWindowManager I4 rationale)

## 7. Known limitations / open work

- `WPoaState` round state machine (`wpoa_state.rs`) is implemented but not yet fully integrated into block import — `WPoaRound` lifecycle events are not persisted across restarts.
- `FinalityState` attestation accumulation is in-memory; no persistent finality checkpointing.
- `ChallengeResponse` protocol is defined but the full on-chain dispute resolution flow (penalizing the losing party) is not yet implemented.
- `ProofRateLimiter` configuration is not yet exposed in `NodeConfig`.
- `EngineType::BFT` reserve slot: no BFT implementation is planned for v0.22.x.

## 8. Change log (this spec)

- v0.22.2 (2026-05): rewritten from M2 draft to production; `WPoaEngine` + weighted round-robin formula documented; `ValidatorSet` lifecycle added; `EngineType` corrected (WPoA not BFT); slashing/equivocation (I1) documented; `ProverRegistry` (I5) added; `ProofWindowManager` (I4) added; `ProofRateLimiter`, `ForkChoice`, `FinalityState`, `PeerScorer`, `ProofChallenge`, `WPoaRound`/`WPoaEvent` all added
