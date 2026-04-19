# Consensus Details

Shell-Chain uses a **Proof of Authority (PoA)** consensus engine with an
optional **weighted PoA (wPoA)** extension and async STARK proof aggregation.

---

## Table of Contents

- [PoA Engine](#poa-engine)
- [wPoA Extension](#wpoa-extension)
- [Validator Set](#validator-set)
- [Finality](#finality)
- [Fork Choice](#fork-choice)
- [Slashing](#slashing)
- [Proof Challenges](#proof-challenges)

---

## PoA Engine

In the base PoA engine (`PoaEngine`), authority nodes take turns proposing
blocks in round-robin order. A block is valid if:

1. The proposer is in the current `ValidatorSet`.
2. The block header `authority` field matches the proposer's address.
3. All transactions have valid Dilithium3 signatures (verified via `WitnessBundle`).
4. The block timestamp is within the allowed drift window.
5. State root and witness root match the executed result.

### Configuration

```toml
[consensus]
engine = "poa"
enable_stark_aggregation = false  # enable async STARK proofs (see PROVER_GUIDE.md)
```

---

## wPoA Extension

The `WPoaEngine` adds weight-based voting on top of base PoA. Validators accrue
stake-weight over time, and the fork-choice rule favours the chain with highest
cumulative weight rather than longest chain.

`WPoaConfig` fields:

| Field | Default | Description |
|-------|---------|-------------|
| `slot_duration_ms` | 2000 | Slot length in milliseconds |
| `min_validators` | 1 | Minimum validators to produce blocks |
| `max_missed_slots` | 10 | Missed slots before offline detection |

Enable wPoA:

```toml
[consensus]
engine = "wpoa"
```

---

## Validator Set

The validator set is maintained in the `ValidatorRegistry` system contract
(`0x0000…0001`) and the in-memory `ValidatorSet`. Changes take effect at the
next epoch boundary.

### ValidatorStatus

| Status | Description |
|--------|-------------|
| `Active` | Participating in block production |
| `Pending` | Added via governance, not yet active |
| `Suspended` | Temporarily suspended (missed slots) |
| `Slashed` | Permanently removed due to misbehaviour |

### Epoch management

`ValidatorSetConfig` controls epoch length. At each epoch boundary:
- Pending additions become active
- Slashed validators are removed
- Validator weights are recalculated

---

## Finality

Shell-Chain uses a **threshold attestation** model for finality. Blocks become
final when ≥ 2/3 of validators have attested to them via `Attestation` messages.

`FinalityState` tracks:
- `finalized_height` — highest finalized block
- `attestation_counts` — votes per block hash
- `quorum_threshold` — ceil(2/3 × validator_count)

A block at height H is **safe** once ≥ 1/3 + 1 validators have attested.
A block is **finalized** once ≥ 2/3 have attested.

RPC block tags map to these states:
| Tag | Meaning |
|-----|---------|
| `latest` | Most recent sealed block |
| `safe` | Block with ≥ 1/3+1 attestations |
| `finalized` | Block with ≥ 2/3 attestations |
| `pending` | Not yet sealed |
| `earliest` | Genesis block |

---

## Fork Choice

`ForkChoice` assigns a `BlockScore` to each candidate chain head. The rule
prefers the chain with:

1. **Highest finalized height** (safety over liveness)
2. **Highest cumulative validator weight** (wPoA tiebreak)
3. **Lowest block hash** (deterministic last tiebreak)

In the base PoA engine, validator weights are uniform, making rule 2 equivalent
to longest-chain.

---

## Slashing

The slashing system detects two categories of misbehaviour:

### Double-sign (equivocation)

Detected by `detect_double_sign(h1, h2)` — triggered when the same validator
proposes two different blocks at the same height with different hashes.

```
SlashType::DoubleSign
SlashEvidence::Equivocation { h1: BlockHeader, h2: BlockHeader }
```

`EquivocationProof` can be broadcast by any node that observes two conflicting
headers from the same authority.

### Offline

Detected by `detect_offline(addr, last_proposed, current_block, config)` —
triggered when a validator hasn't proposed a block for more than
`SlashingConfig::offline_threshold` slots.

```
SlashType::Offline
```

### SlashingConfig defaults

| Field | Default | Description |
|-------|---------|-------------|
| `offline_threshold` | 100 | Slots without a proposal before offline detection |
| `slash_on_double_sign` | true | Slash immediately on equivocation |
| `slash_on_offline` | false | Offline triggers suspension, not slash (configurable) |

### SlashRecord

```rust
SlashRecord {
    validator: Address,
    slash_type: SlashType,       // DoubleSign | Offline
    evidence: SlashEvidence,
    block_height: u64,
    epoch: u64,
}
```

Slash records are written to `ValidatorSet` and change the validator's status
to `Slashed`. The validator is removed at the next epoch boundary.

---

## Proof Challenges

When `enable_stark_aggregation = true`, received `ProofAmendment` messages are
verified by all peers. If verification fails, the peer broadcasts a
`ProofChallenge`:

### ChallengeReason

| Value | Description |
|-------|-------------|
| `VerificationFailed` | Winterfell STARK verification returned false |
| `InvalidBatchRoot` | `batch_root_bytes` doesn't match expected public output |
| `InvalidProverSignature` | Prover's PQ signature on the amendment is invalid |
| `UnregisteredProver` | Prover address not in `ProverRegistry` |

### Rate limiting

Challenges are rate-limited per-challenger via `ProofRateLimiter` to prevent
DoS. `RateLimiterConfig` sets:
- `max_challenges_per_window` — max challenges in any rolling window
- `window_seconds` — rolling window duration

A challenger that exceeds the limit has its challenges silently dropped by peers.

### Challenge flow

```
Node A cannot verify ProofAmendment for block #N
  │
  └─► Broadcast ProofChallenge { block_hash: N, reason, challenger: A, sequence: k }
          │
          └─► Any peer holding proof bytes broadcasts:
                ChallengeResponse { block_hash: N, proof_bytes: [...] }
                      │
                      └─► Node A retries verification with raw proof bytes
```
