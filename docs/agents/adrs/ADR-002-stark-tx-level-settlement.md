# ADR-002: STARK Proof Settlement via Canonical `StarkReward` System Transactions

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: `docs/agents/adrs/ADR-002-stark-tx-level-settlement.md` (self); CHANGELOG v0.21.1, v0.22.0; ADR-003; ADR-006

## Context

After an async STARK proof (`ProofAmendment`) is generated for a range of source
blocks, the settlement payload must be permanently recorded on-chain so that all
nodes can independently verify and index which source blocks have been proved.

Two candidate wire locations were considered:

- **Block header `extra_data`** — a legacy field previously used for ad-hoc
  STARK payloads; injected by the proposer into the block it is producing.
- **`Block::system_transactions`** — the canonical list of protocol-level
  transactions (e.g., validator rewards); a `StarkReward` tx carries the
  `proof_payload` bytes (serialised `ProofAmendment` JSON) inside the RLP block
  body.

The existing async proving pipeline generates `ProofAmendment` only after the
source blocks are already sealed. Injecting a settlement into an already-sealed
block would require redesigning sealing/consensus timing and placing proof
generation on the proposer's critical path.

## Decision

STARK proof settlements are carried exclusively by canonical `StarkReward`
system transactions inside `Block::system_transactions`. The block header
`extra_data` field is deprecated for this purpose: any imported block that
carries STARK settlement data in `extra_data` is rejected at import time with a
`NodeError::Startup` describing the violation.

Settlement always occurs in a **following block** after the final source block
(async pipeline, Option B from the plans ADR). The `ProofAmendment.block_number`
field is serialised as `end_block`; the old `block_number` key is accepted as a
decode alias for backward compatibility.

## Rationale

- **Preserves block-time liveness**: keeping proof generation off the proposer
  seal path prevents slot misses and finality lag under real proving latency.
- **Matches existing architecture**: async prover + ordered frontier + pointer
  artifacts are already implemented and exercised on SG testnet.
- **Lower consensus risk**: no pre-seal / provisional-block protocol change is
  required; the change is purely in how the settlement payload is embedded.
- **Operationally proven**: the SG flow already distinguishes "settlement
  inclusion block" (the block carrying `StarkReward`) from "final source block"
  (the last block in the proved range).
- Option A (pre-seal synchronous settlement) was explicitly rejected in the
  plans ADR because it converts the async proof into a seal-path dependency,
  risks proposer slot misses, complicates validator/prover role separation, and
  introduces a larger fork-risk surface.

## Alternatives considered

- **Option A — pre-seal synchronous settlement**: Proof generation would block
  block sealing. Rejected: see rationale above. May be reconsidered only after a
  dedicated protocol phase with explicit consensus versioning and performance
  budget.
- **Header `extra_data` settlement (status quo ante)**: Simple to implement;
  already partially deployed. Rejected: `extra_data` has no schema, is
  untyped, and conflates settlement data with other header extensions. The
  `system_transactions` list provides a typed, extensible, and RLP-canonical
  location.

## Consequences

- **Positive**: Block production liveness is unaffected by proving latency.
- **Positive**: Settlement payload is typed and versioned inside `SystemTxKind::StarkReward`.
- **Positive**: Prometheus counters `shell_stark_settlements_accepted_total`,
  `shell_stark_settlements_rejected_total`, and `shell_stark_frontier_lag` are
  emitted per settlement event (CHANGELOG v0.22.0).
- **Negative**: A gap exists between "proof artifacts exist" and "settlement tx
  confirmed on-chain"; `settlement_tx_hash` on pointer artifacts is `null` until
  the canonical settlement is accepted. Explorer and SDK must handle this
  intermediate state.
- **Negative**: System-tx wire encoding uses JSON bytes inside RLP — pragmatic
  but not ideally compact; marked for future binary-format cleanup.
- **Risks / mitigations**: Ordering/layer invariants are strictly enforced by
  `validate_stark_amendment_ordering_with_overlay`; rejected settlements
  increment the rejection counter and are logged; orphaned amendment artifacts
  must be explicitly deleted (see ADR-003 context).

## Implementation references

- Code: `crates/node/src/node/block_importer.rs:203-207` — rejection of
  `extra_data`-based STARK settlement at import
- Code: `crates/node/src/node/system_rewards.rs` — STARK reward value calc,
  ordering validation
- Code: `crates/node/src/node/event_loop.rs` — settlement queue, settlement tx
  injection during block production
- Code: `crates/stark-prover/src/amendment.rs` — `ProofAmendment` struct, full
  proof + pointer artifact model
- Spec: `docs/agents/adrs/ADR-002-stark-tx-level-settlement.md`
  (Option B decision, full rationale)
- Tests: `stark_settlement_sequence_allows_l2_after_l1_in_same_block`,
  `import_block_materializes_canonical_proof_pointers`,
  `block_producer_settles_l1_and_l2_in_same_block`,
  `stark_settled_index_survives_simulated_restart`,
  `import_invalid_stark_settlement_does_not_poison_settled_index`
- CHANGELOG: v0.21.1 (STARK settlement hardening patch); v0.22.0 (durable
  settled-source index, proof input decode in RPC, settlement liveness metrics)

## Revisit triggers

- A future protocol phase dedicates a consensus-versioned "pre-seal hook" that
  allows inline settlement without proposer latency risk.
- The JSON-in-RLP system-tx encoding is replaced by a compact binary format
  (e.g., CBOR or protobuf).
- L2 STARK aggregation (`StarkReward` for layer 2+) requires additional fields
  that cannot be accommodated in the current `ProofAmendment` schema.
