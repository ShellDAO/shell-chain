# Consensus Details

Shell-Chain uses a **Proof of Authority (PoA)** consensus engine with an
optional **weighted PoA (wPoA)** extension and async STARK proof aggregation.

---

## Table of Contents

- [PoA Engine](#poa-engine)
- [wPoA Extension](#wpoa-extension)
- [Validator Set](#validator-set)
- [Core Chain Invariants](#core-chain-invariants)
- [Finality](#finality)
- [Fork Choice](#fork-choice)
- [Slashing](#slashing)
- [Proof Challenges](#proof-challenges)

---

## Core Chain Invariants

`shell-node` treats these as the minimum safety invariants for production,
import, sync, and RPC readiness:

1. The persisted head block must exist and its `(number -> hash)` canonical
   mapping must point back to the same hash.
2. `last_finalized_number` must never be ahead of the canonical head.
3. When `last_finalized_number > 0`, the finalized hash tracked by finality must
   equal the canonical hash at that height.
4. The live `WorldState` root must equal the canonical head `state_root`.
5. Canonical aggregate counters may lag and be rebuilt, but their persisted
   `totals_head` must never be ahead of the canonical head.
6. Side forks may be persisted for fork-choice/reorg inspection, but they must
   not overwrite `(number -> hash)` canonical mappings unless an explicit
   non-finalized reorg transition is executed.
7. Production readiness must be `Ready` before an SG/testnet validator proposes;
   isolated production is allowed only for explicit dev profiles.

The node exposes these rules internally through `check_core_invariants()`. A
failure is a degraded/startup error, not a recoverable mempool condition.

---

## PoA Engine

In the base PoA engine (`PoaEngine`), authority nodes take turns proposing
blocks in round-robin order. A block is valid if:

1. The proposer is in the current `ValidatorSet`.
2. The block header `authority` field matches the proposer's address.
3. All transactions have valid PQ signatures (ML-DSA-65 primary, Dilithium3 legacy-compatible, SPHINCS+ supported) verified via the witness pipeline.
4. The block timestamp is within the allowed drift window.
5. State root and witness root match the executed result.

### Demand-driven production and rewards

Testnet/mainnet production ticks every 2 seconds, but validators only build a
normal block when executable transactions are available. While idle, validators
skip empty slots and produce only a 600-second heartbeat block. Heartbeat blocks
carry no user transactions, consume zero gas, and do not pay rewards.

For normal transaction blocks, the reward rules are:

- the block producer receives **100% of effective gas fees** as a deterministic
  `blockGasReward` system transaction;
- L1 STARK settlement receives a **mint-only** reward of `100 SHELL / 2^1 × source_count`
  (where `source_count` counts covered source blocks that contain user transactions);
- L2+ recursive STARK settlements receive only the layer-discounted mint reward
  `100 SHELL / 2^L × source_count`; no gas-fee share at any STARK layer.
- every STARK mint increases the canonical `totalSupply` state value by the
  exact reward amount.

Reward records are first-class system transactions with deterministic hashes,
receipts, block inclusion indexes, and address-history indexing.

### Algorithm governance timelock activation

The optional `algorithm_timelock_activation_height` in `genesis.json` selects
when algorithm activation votes enforce the white-paper minimum of 1,296,000
blocks (30 days at a two-second slot time). Missing or null keeps legacy rules;
no existing network changes automatically. This is a block count, not a wall-clock
deadline when a network uses a different block interval.

For a vote executed in block `N` at or after the configured height, the proposed
algorithm activation must be at least `N + 1,296,000`. Equality is accepted;
one block less and arithmetic overflow are rejected without applying the vote.
Before the upgrade, validation retains the exact legacy rule: canonical parent
height plus 500,000 blocks, including its original saturating arithmetic.
Production, import, simulation and historical replay select the rule from the
executed block header, rather than the current tip. Already accepted proposals
keep their recorded activation heights; the scheduled activation processor is
unchanged.

The delay is checked on **every submitted vote**, as in the legacy implementation.
Complete pending voting rounds before the upgrade, or choose an activation height
that leaves the new minimum delay for all votes after the boundary. An incomplete
legacy proposal with a shorter delay cannot receive further votes under the new
rule. Existing proposal identity, quorum and duplicate-vote behavior is unchanged.
This option does not implement the separate seven-day voting-window or emergency
signature-policy requirements in the white paper.

The schedule is independent of the fee, Bloom and log emitter schedules. It is
persisted and checked on restart and trusted snapshot import. On an existing
chain, configure the same future height on every upgraded node using its original
genesis configuration; startup requires that height to be strictly above the
canonical head. Once saved, the height cannot be changed or removed. For an
explicitly configured fresh test chain, height zero enables the rule immediately.
Coordinate a client rollout before choosing an activation height on a live network.
See [the compatibility decision](adr/algorithm-governance-timelock.md).

### Algorithm proposal staging

The independent optional `algorithm_proposal_staging_height` in `genesis.json`
preserves live algorithm policy until a new proposal reaches quorum. At and after
that height, a first vote stores candidate height and verifier hash separately
from the registry. A sub-quorum vote returns false without changing live status,
activation height or verifier hash. An active algorithm therefore remains usable
for signatures; a deprecated algorithm remains disabled. Restart and historical
replay retain the same distinction.

The quorum-reaching vote publishes the candidate as `pending_activation`, stores
approval for the maturity processor, and clears the staged parameters. Activation
still waits for the proposal height. Staged proposals always receive the approval
guard, even when `algorithm_quorum_activation_height` is absent. Quorum arithmetic,
duplicate-vote handling and the independently selected per-vote timelock remain
unchanged. Conflicting height or verifier hash is rejected before recording a vote.

Missing configuration and pre-upgrade blocks preserve legacy behavior. Already
pending proposals are not restaged when execution crosses the boundary. The
schedule follows immutable, future-only startup and trusted snapshot rules;
height zero is for explicitly configured fresh test chains. No existing network
changes automatically. Coordinate the rollout before selecting a live height.

This change only postpones publication until approval. Approved pending algorithms
still reject new signatures until maturity. Voting expiry requires the separate
[window upgrade](#algorithm-voting-window), and explicit proposal IDs require the
[identity upgrade](#algorithm-proposal-identity). Verifier-hash matching and emergency policy remain separate requirements. See [the compatibility decision](adr/algorithm-proposal-staging.md).

### Algorithm voting window

The optional `algorithm_voting_window_activation_height` in `genesis.json`
adds a seven-day **nominal block window** for newly staged algorithm proposals.
It requires `algorithm_proposal_staging_height` at or below the window activation
height. Missing or null preserves previous rules; no network activates by default.

The first vote in block `N` stores the exclusive deadline
`D = N + floor(604800 / block_time_secs)`. The interval is the effective consensus
interval from genesis, persisted with the upgrade schedule, not the local CLI
`--block-time` scheduling interval. For a two-second consensus interval the window
is 302,400 blocks. Floor division avoids exceeding seven nominal days; the interval
must be between one second and 604,800 seconds. This is not a wall-clock deadline:
actual elapsed time depends on block production. Deadline overflow rejects the
proposal before candidate state or votes are written.

Matching votes in blocks `N` through `D - 1` can reach quorum; votes at `D` or later
are rejected. Until approval, live algorithm policy remains unchanged. Quorum
publishes the pending specification, records approval and clears the candidate
and deadline; subsequent maturity still uses the stored activation height. Existing
per-vote timelock, weighted quorum and duplicate-vote checks remain in force.
Expired candidates and existing votes are retained, and cannot publish or mature.
This window upgrade alone provides no reset or reproposal mechanism. The separate
[identity upgrade](#algorithm-proposal-identity) adds ID-bound voting and retry.

Proposals staged before the window activates have no deadline and retain their
previous voting behavior, as do already-published pending proposals. Rollout must
account for these grandfathered proposals. Production, import, simulation and
historical replay use the executing block height and canonical candidate state;
restart preserves the deadline. Snapshot import requires the trusted schedule and
interval and rejects a mismatch before writing state.

On an existing chain, the window must first be scheduled strictly above the
canonical head. Once persisted, neither its height nor its nominal interval can
be changed or removed. Stage activation must be scheduled no later than the
window. Height zero is available for explicitly configured fresh test chains.
Coordinate upgraded clients and configuration before choosing a live height.
This implements expiry for new staged candidates, not the complete governance
lifecycle or emergency signature policy. See [the compatibility decision](adr/algorithm-voting-window.md).

### Algorithm activation quorum guard

The independent optional `algorithm_quorum_activation_height` in `genesis.json`
requires recorded quorum approval before newly created proposals can activate.
Missing or null preserves legacy behavior. A proposal first created in block `N`
at or after this schedule stores a quorum-required marker in canonical state.
The vote that reaches the existing weighted quorum records approval. At maturity,
production and import leave an unapproved guarded proposal pending. Restart and
historical replay use the same persisted markers; later validator changes do not
revoke approval that was already obtained.

Pending proposals created before the upgrade retain legacy activation behavior,
including activation at maturity without recorded quorum approval. Complete or
otherwise account for those proposals before a coordinated rollout. New guarded
proposals clear any old approval marker. This option uses the same immutable,
future-only startup scheduling and trusted snapshot checks as the other upgrades;
height zero is available for explicitly configured fresh test chains. No existing
network activates this change automatically.

Without the independent proposal-staging upgrade, the first vote still marks an
algorithm pending before quorum, which disables it for new signatures. This guard
only fixes activation without approval; it does
not complete proposal lifecycle, seven-day voting expiry, full proposal identity,
verifier-hash validation, or emergency signature policy. The timelock schedule is
separate and continues to validate every vote. See
[the compatibility decision](adr/algorithm-activation-quorum.md).

### Log emitter address activation

The optional `log_address_activation_height` in `genesis.json` restores known
full-width emitting contract addresses in ordinary and AA execution logs at
and after the selected height. Execution uses the same address registry as
state updates; AA resolves each inner call's logs from that call's saved registry.
Addresses absent from the registry retain the existing zero-padding fallback.
Reverted AA bundles discard their logs and per-call mappings.

Before activation, logs retain the legacy zero-padded emitter values. The change
therefore preserves historical receipts, Bloom bytes and hashes. Activated logs
are discoverable by their recorded full Shell address through normal RPC log
filters. This schedule is independent of the fee and Bloom schedules, is absent
by default, and follows the same immutable startup and trusted snapshot rules.
Existing networks require a coordinated future height; no deployment or
activation is performed by adding this option.

### Log Bloom activation

The optional `bloom_activation_height` in `genesis.json` independently selects
standard Bloom bit ordering. Missing or null values retain legacy behavior at
all heights. No existing network activates by default.

Each address and topic uses three indices from the first six Keccak-256 hash
bytes, masked to 2047. Before activation, index `k` sets byte `k / 8`, bit
`7 - k % 8`. At and after activation, it sets byte `255 - k / 8`, bit `k % 8`,
matching Ethereum/Alloy ordering. Address inputs remain the full 32 bytes of
recorded Shell log addresses; this is not a change to log address encoding or
a promise of 20-byte Ethereum address compatibility.

Execution selects the format from the executed block height, including ordinary,
AA and native transactions. Producers aggregate receipt blooms, and importers
and fork replay verify the same committed bytes. Historical receipts, headers,
signing payloads and hashes are preserved. RPC returns their stored Bloom bytes.
Both log-range queries and filter polling select the format for each queried
block, including removed logs after a reorganization.

The fee, Bloom, log emitter, algorithm timelock, quorum, proposal-staging and voting
window schedules are persisted chain configuration. The voting window additionally
requires proposal staging no later than its activation; the other schedules are independent.
Startup validates all proposed schedules before publishing any of them. A new
schedule on an existing chain must be strictly above its canonical head; an
existing schedule cannot be removed or changed. Restart and snapshot import
require matching trusted schedules, and conflicting imports fail before writes.
Operators must coordinate node upgrades and a common activation height before
using the new format on an existing network.

### Fee accounting activation

The optional `fee_accounting_activation_height` in `genesis.json` selects the
first block with reconciled execution fees. Missing or `null` preserves legacy
execution at every height. Existing genesis defaults and historical blocks are
unchanged; height `0` is available for explicitly configured new test chains.

At and after activation, ordinary execution charges
`min(max_fee_per_gas, base_fee_per_gas + max_priority_fee_per_gas)` multiplied by
gas consumed after permitted refunds. The receipt and block gas reward use that
same billed gas. Revm's separate beneficiary credit is suppressed because the
deterministic system reward pays the full execution fee once. AA charges its
sender or paymaster at the same effective price, including the bundle overhead;
native calls use that price on both success and failure. STARK minting and blob
gas accounting remain separate. RPC gas-limit estimates use gas spent before
refunds, since refunds cannot fund execution that has not finished.

The rule is selected from the block being executed, including fork adoption and
historical replay. Contract validation and simulation use their own block
context, including the corresponding `BASEFEE`; a current tip cannot change an
older block's execution rules.

The activation height is persisted with chain configuration and checked on
restart and snapshot import. To schedule an existing legacy chain, all validators
must first coordinate a future height and run compatible software. At startup,
an explicit height in the original genesis configuration may be installed once
only if it is above the local canonical head. This preserves the genesis hash
and existing history. A persisted height cannot be changed or removed through
the genesis file. Snapshots with conflicting activation schedules are rejected
before import; restore an older legacy snapshot with its original configuration
before scheduling a future upgrade. No activation height is selected by default.

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
| `slash_weight_bps` | 1000 | Economic slash amount in basis points (10% per offence by default) |

Enable wPoA:

```toml
[consensus]
engine = "wpoa"
```

If the expected proposer misses its slot, validators broadcast a signed `ViewChangeMessage`. Once the weighted quorum reaches `ceil(2/3 × total_active_weight)`, the engine advances `current_view` and rotates proposer selection across the ordered authority list for that height. The timeout is `max(block_time_ms, 10_000)` milliseconds.

If slashing reduces total active validator weight to zero, no view-change quorum
can form. Validator weight must be restored through the authority-management
path before proposer rotation resumes.

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

Shell-Chain uses a **BFT threshold attestation** model for wPoA finality. When a
validator observes a valid block it signs the block hash and broadcasts a
`WPoaVote`. The proposer and non-proposer validators also record their own vote
locally, because libp2p broadcast does not echo a node's message back to itself.

A block becomes finalized when votes for the same block hash reach the weighted
wPoA quorum:

```text
quorum = floor(2 * total_active_validator_weight / 3) + 1
```

For the 3-validator testnet profile with weights `[2, 1, 1]`, total weight is 4
and quorum is 3. Finality therefore requires the weight-2 validator plus at
least one weight-1 validator, or all three validators.

A zero total active weight never satisfies finality, even though the numeric
threshold formula evaluates to zero. Live votes and synchronized commit
certificates both enforce this nonzero-total invariant.

`FinalityState` tracks:
- `last_finalized_number` — highest finalized block number
- `last_finalized_hash` — canonical hash at the finalized height
- pending attestations — votes by block hash before quorum

When a quorum is reached, the node stores a **commit certificate** sidecar keyed
by block hash. The sidecar contains the quorum signatures as a map of validator
address to `PQSignature`, preserving the signature algorithm tag for verification.
The certificate is intentionally stored outside the block header so finality can
be deployed without changing existing block hashes.

Finality is safety-critical:
- Blocks at or below `last_finalized_number` cannot be replaced by a different
  hash; import returns `ConflictsWithFinalized`.
- A quorum advances finality only when its block hash is canonical at the
  attested height.
- The wPoA commit certificate and durable finalized cursor are written
  atomically before in-memory finality advances. A failed write restores the
  voting round so the triggering vote can safely retry persistence.
- Validators ignore stale or conflicting votes for finalized heights.
- Producers refuse to build from a parent that conflicts with the finalized
  chain.
- Sync responses include available commit-certificate sidecars. A node that
  receives a valid certificate verifies signer membership, PQ signatures, and
  weighted quorum, then fast-finalizes the block without waiting to recollect
  votes.

RPC block tags map to these states:
| Tag | Meaning |
|-----|---------|
| `latest` | Most recent sealed block |
| `safe` | Currently aliases the finalized block |
| `finalized` | Latest block finalized by weighted wPoA quorum |
| `pending` | Not yet sealed |
| `earliest` | Genesis block |

Finality status is exposed through:
- `shell_getFinalityInfo` — current head, latest finalized block/hash, lag, and
  pending attestation count.
- `shell_finalityProof(blockHash)` — commit certificate sidecar for a finalized
  block; the returned object's `certificate` field is `null` if no certificate
  is stored locally.
- Prometheus gauges `shell_last_finalized_number` and
  `shell_finality_lag_blocks`.

---

## Fork Choice

`ForkChoice` assigns a `BlockScore` to each candidate chain head. The rule
prefers the chain with:

1. **Highest finalized height** (safety over liveness)
2. **Highest cumulative validator weight** (wPoA tiebreak)
3. **Lowest block hash** (deterministic last tiebreak)

In the base PoA engine, validator weights are uniform, making rule 2 equivalent
to longest-chain.

Before validating transactions in a side-fork descendant, the node reconstructs
its parent's state from the retained common ancestor in a disposable overlay.
Canonical address metadata is rolled back in that overlay and the known branch
prefix is replayed with its own public keys, block mappings and algorithm policy.
The path must remain above finality and have complete, continuous retained blocks.
Replay work scales with the unfinalized branch prefix; no branch cache is persisted.

Governance calls and scheduled algorithm changes during this replay use a
thread-local registry. They cannot publish policy to concurrent canonical
validation. Invalid descendants leave canonical state and metadata unchanged.
Empty transaction lists require no account validation. Preferred-fork adoption
continues to replay and verify the selected branch before committing it.

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
| `slash_weight_bps` | 1000 | Reduce effective validator weight by 10% per slash, capped at the validator's base weight |

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

Slash records are written to `ValidatorSet`. Equivocation still marks the validator as slashed for epoch-boundary removal, while the economic penalty is applied immediately by reducing effective proposer/finality weight according to `slash_weight_bps`. Offline detection defaults to suspension-only until `slash_on_offline` is enabled.

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

### Challenge lifecycle

Challenges are tracked in-process with the following status machine:

| Status | Meaning | Transition |
|--------|---------|------------|
| `Open` | challenge accepted and awaiting proof bytes | created when a node broadcasts `ProofChallenge` |
| `Resolved` | a valid response was received before timeout | `ChallengeResponse` verifies successfully |
| `Slashed` | the prover failed to answer within the timeout | automatic at `T_c = 7200` blocks |

A timed-out challenge slashes the prover responsible for the amendment unless
the prover could not be identified from a stored amendment or block matching the
challenged hash. The challenge's block number is only a logging and routing hint;
it does not identify a prover when that hash is unknown.

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

### Algorithm proposal identity

The optional `algorithm_proposal_identity_height` requires the voting-window
upgrade no later than its activation. It enables explicit full-spec submission,
ID-bound voting and expired-candidate replacement. Historical calls retain their
original behavior; only pre-upgrade legacy rounds may continue using the old
selector after activation. See the [native ABI and compatibility rules](SYSTEM_CONTRACTS.md#explicit-algorithm-proposal-identity)
and [encoding decision](adr/algorithm-proposal-identity.md). Omitted configuration
keeps the new selectors disabled. This rule does not automatically activate on
an existing network.
