# Validation Rules

> Implementation specification for block and transaction validation in `shell-chain`.
>
> This document translates the current `shell-chain` protocol assumptions into Rust-facing pipelines, crate boundaries, error surfaces, and peer-handling policy.
> It is intentionally self-contained for implementers working in this repository: rules that are closed enough to build against are stated directly here, and unresolved areas are marked as pending protocol closure instead of being presented as final guarantees.

## Status: DRAFT (pipeline definition expanded; some thresholds still pending upstream closure)

## Purpose

Define the validation order, failure classes, and crate responsibilities for:
- transaction admission and rebroadcast,
- block import and stateless execution checks,
- signature verification dispatch across user and validator paths,
- peer-handling decisions for malformed vs. merely excessive traffic.

## 1. Local Protocol Assumptions

The implementation in this repository should treat the following assumptions as the current working contract:

- `TransactionPayload` is an append-only SSZ union with tag `0` for `BasicTransactionPayload` and tag `1` for `CreateTransactionPayload`; unknown tags are rejected as unsupported.
- `Authorization.payload_root` must match the exact `hash_tree_root(TransactionPayload)` used to construct the transaction-path signing root.
- Block import must validate `header.transactions_root`, `sidecar.block_root`, and `header.execution_witnesses_root` before stateless execution begins.
- Transaction admission and block import both use a cheap-first ordering: structural decoding and commitment checks run before signature verification, and signature verification runs before witness reconstruction.
- User-path authorization signatures above 8 KB are rejected by default as a local stress-control rule. Scheme-local limits may be stricter, but not looser, on that path.
- `header.witness_bytes` must be checked before sidecar fetch or deep parsing, but its final protocol ceiling is still open, so implementations must expose a configurable ingress guard rather than a frozen consensus number.
- Block witness sidecars must be validated exactly as committed. Committed ordering and bytes are preserved through the commitment-check phase, even if later execution builds a deduplicated or indexed in-memory view.
- Witness compression, canonical witness encoding, validator credential modeling, validator-path size tolerance, supported signature-family narrowing, multi-authorization semantics, and scheme-specific gas coefficients remain pending-closure items.

This file is intentionally implementation-focused:
- these assumptions define the protocol objects and validation gates that `shell-chain` currently builds against,
- this file defines who validates what, in what order, and how failures are surfaced in Rust.

### 1.1 Repository-local closure decisions

To keep the first implementation pass stable, this repository treats the following as **closed local rules** even if adjacent protocol areas are still evolving elsewhere:

| Area | Closed local rule in this repository | Notes |
|---|---|---|
| Transaction payload variants | Only tags `0` and `1` are accepted. Unknown tags are invalid. | Future variants may append, but are not locally supported until this spec set adopts them. |
| Payload-root binding | `Authorization.payload_root` must match the canonical `hash_tree_root(TransactionPayload)` exactly. | No alternate in-memory root path is allowed. |
| Cheap-first ordering | Structural checks and commitment checks must run before signature verification; signature verification must run before witness reconstruction. | This is a local implementation contract, not an optimization hint. |
| User-path signature limit | Transaction-path authorization artifacts above 8 KB are rejected by default. | This is a deliberate local stress-control rule. |
| Transaction authorization presence | The default transaction path requires `authorizations.len() >= 1`. | A future empty-authorization path would require an explicit local spec update, not a silent interpretation change. |
| Block commitment checking | `transactions_root`, `sidecar.block_root`, and `execution_witnesses_root` must all bind before stateless execution. | These checks are mandatory on the local block-import path. |
| Sidecar byte preservation | Committed witness ordering and bytes must be preserved through commitment verification. | Any deduplicated or indexed view is downstream and local-only. |
| Unsupported schemes | Unsupported transaction-path or validator-path schemes fail validation rather than falling back. | Scheme agility does not imply permissive decoding. |

Everything not listed as closed above should be treated as provisional if this file later describes it as configurable, pending, or subject to narrowing.

## 2. Validation Outcomes and Error Taxonomy

Validation code should separate **object validity** from **peer consequences**.
The same invalid object may arrive from P2P, RPC, local tests, or block production code paths; only P2P-originated failures carry peer scoring consequences.

### 2.1 Object-Level Error Classes

- `MalformedSszError(Context)`: SSZ decoding or structural decoding failed.
- `UnsupportedPayloadVariant(Tag)`: `TransactionPayload` discriminant is unknown.
- `UnsupportedSchemeError(SchemeId)`: `Authorization.scheme_id` or validator credential scheme is not supported by the local dispatcher.
- `AuthorizationCountError(ExpectedPolicy, Actual)`: authorization list violates the currently supported policy.
- `PayloadRootMismatchError(ExpectedRoot, ActualRoot)`: `Authorization.payload_root` does not match `hash_tree_root(TransactionPayload)`.
- `SignatureSizeExceededError(MaxSize, ActualSize)`: signature artifact exceeds the locally enforced bound for the selected scheme or path.
- `WitnessSizeExceededError(MaxSize, ActualSize)`: witness artifact volume exceeded the applicable ingress bound.
- `TransactionsRootMismatchError(ExpectedRoot, ActualRoot)`: block body does not match `header.transactions_root`.
- `SidecarMismatchError(ExpectedRoot, ActualRoot)`: sidecar commitment validation failed.
- `SigningRootConstructionError(Context)`: `SigningData` or domain separation inputs could not be formed as required.
- `SignatureVerificationError(SchemeId)`: cryptographic verification failed.
- `FeeFloorError(Path, Required, Actual)`: transaction does not clear the current payload or witness fee floor.
- `NoncePolicyError(Context)`: transaction does not satisfy the active replay or nonce policy.
- `StateProofValidationError(Context)`: witness proof data cannot reconstruct the required state view.
- `StateRootMismatchError(ExpectedRoot, ActualRoot)`: execution output does not match `header.state_root`.
- `ReceiptsRootMismatchError(ExpectedRoot, ActualRoot)`: execution output does not match `header.receipts_root`.

### 2.2 Peer-Handling Classes

Peer handling must follow the local split between malformed-protocol failures and soft policy failures:

- **Disconnect / blacklist**: malformed or malicious data that proves the peer sent invalid protocol objects.
  - Examples: malformed SSZ, invalid signature after full decoding, root-binding mismatch, forged sidecar linkage.
- **Ignore / rate-limit / lower reputation**: objects that are merely too large, unsolicited, or not worth downloading yet.
  - Examples: oversize witness sidecar advertisement, transactions that fail local fee-floor policy, redundant announcements.
- **No peer penalty**: failures originating from local RPC, local builder code, or block construction tests.

Implementation note: peer scoring belongs to `shell-network`; validation crates return structured reasons and let `shell-network` translate them into reputation or disconnect actions.

## 3. Crate Responsibilities

| Area | Primary crate | Responsibilities |
|---|---|---|
| SSZ decoding, roots, domain object hashing | `shell-primitives` | Canonical SSZ encode/decode helpers, `hash_tree_root` wrappers, domain-separated signing-root helpers. No policy decisions. |
| Signature family dispatch | `shell-crypto` | Map `scheme_id` or validator credential type to a verifier implementation, enforce scheme-local byte bounds, expose unified verification traits. |
| Tx admission and rebroadcast policy | `shell-mempool` | Cheap-first transaction validation, fee-floor gating, replay/nonce policy, admission tiers, caching of stateless results. |
| Proof reconstruction and state witness checks | `shell-state` | Canonical witness sorting checks, state proof verification, stateless reconstruction helpers behind traits. |
| Heavy execution validation | `shell-execution` | Stateless execution using validated witness data, computation of post-state and receipts roots. |
| Block import and block-level binding | `shell-consensus` | Header checks, proposer-signature verification dispatch, header/body/sidecar binding, orchestration of block execution. |
| Peer consequences and fetch policy | `shell-network` | Announcement filtering, sidecar fetch policy, rate limiting, peer reputation, disconnect decisions. |

Boundary constraints from `crate-structure.md` remain mandatory:
- `shell-primitives` must not reverse-depend on higher-level crates.
- `shell-mempool` must not pull the full state implementation directly; it should depend on traits for optional stateless checks.
- `shell-network` should not duplicate cryptographic logic; it consumes typed validation outcomes.

## 4. Signature Verification Dispatch

## 4.1 Dispatcher Responsibilities

Signature verification must be scheme-agile and centralized in `shell-crypto`.
The dispatcher is responsible for:
- mapping `scheme_id` or validator credential type to a concrete verifier,
- checking scheme-local artifact constraints before expensive verification begins,
- constructing a uniform `VerificationError` surface for callers,
- exposing a stable trait so `shell-mempool` and `shell-consensus` do not depend on individual PQ libraries.

Recommended trait shape:

```rust
pub trait SignatureVerifier {
    fn scheme_id(&self) -> u8;
    fn max_signature_bytes(&self) -> usize;
    fn verify(&self, public_key: &[u8], signing_root: [u8; 32], signature: &[u8]) -> Result<(), VerificationError>;
}
```

`SignatureDispatcher` should offer two call paths:
- `verify_transaction_authorization(...)` for `TransactionEnvelope.authorizations`
- `verify_validator_message(...)` for proposer and future validator-path messages

The separation is important because the current spec set treats account-path and validator-path tolerances differently.

## 4.2 Transaction-Path Dispatch

For transaction authorizations, the caller flow is:
1. `shell-mempool` computes `payload_root = hash_tree_root(TransactionPayload)`.
2. `shell-mempool` checks that every `Authorization.payload_root == payload_root` before any signature verification.
3. `shell-primitives` constructs `SigningData { object_root: payload_root, domain_type: DOMAIN_TX_SHELL }` and derives `signing_root`.
4. `shell-mempool` passes `(scheme_id, public_key_material, signing_root, signature)` to `shell-crypto`.
5. `shell-crypto` selects the verifier, performs byte-bound checks, then runs the cryptographic verification.

Failure handling:
- Unknown or unsupported `scheme_id`: reject the transaction. On a P2P path this is disconnect-grade because the peer sent an invalid protocol object.
- `payload_root` mismatch: reject immediately without calling the verifier; this is cheaper than cryptography and should be treated as malformed.
- Signature size above the scheme-local bound: reject immediately. If the artifact exceeds the current user-path stress limit of 8 KB, admission must fail even if the scheme library could technically parse it.
- Signature verification failure after full decoding: reject immediately; on a P2P path this is disconnect-grade.

## 4.3 Validator-Path Dispatch

`SignedBlockEnvelope` introduces a separate validator-path signature surface.
Implementation responsibilities are:
- `shell-consensus` computes `block_root = hash_tree_root(header)`.
- `shell-consensus` resolves the active proposer credential from validator state.
- `shell-consensus` delegates verification to `shell-crypto` using a validator-specific domain.

Open items that must remain explicit in code and docs:
- The exact validator credential object model is still pending closure around validator credential separation.
- The current validator message tolerance is only a candidate range, not a finalized protocol hard limit. Implementations may use configurable local transport guards, but must not present them as finalized consensus-invalidating rules.
- Supported validator signature families remain subject to later narrowing.

## 5. Transaction Validation Pipeline

Transaction admission must remain **cheap-first, heavy-last**.
A node should not reconstruct state proofs or retain expensive sidecars until structure, fee floor, and signature checks have already passed.

## 5.1 Stage T0: Network Decode and Announcement Filtering

Primary crates: `shell-network` -> `shell-primitives`

Steps:
1. Decode announcement metadata or requested `TransactionEnvelope` bytes.
2. Enforce transport-level message framing and SSZ decoding.
3. Drop unsolicited large objects before passing them to mempool logic when local fetch policy did not request them.

Failure handling:
- Malformed SSZ or structurally impossible envelope: disconnect-grade.
- Oversize but otherwise decodable advertisement or sidecar: ignore, rate-limit, or lower reputation; do not disconnect solely for size.

## 5.2 Stage T1: Stateless Structural Checks

Primary crate: `shell-mempool`

Required ordering inside this stage:
1. Recompute `payload_root` from `TransactionPayload`.
2. Verify the payload discriminant is one of the supported upstream variants.
3. Verify `authorizations` satisfies the currently supported policy.
   - Default implementation path: require `authorizations.len() >= 1`.
   - If a future external-account-abstraction path allows empty authorization lists, gate it behind an explicit feature or transaction subtype once the protocol shape is locally adopted here.
4. Verify every `Authorization.payload_root` matches the recomputed `payload_root`.
5. Apply signature-size prefilters before cryptographic verification.

8 KB limit note:
- The default mempool implementation must reject a transaction authorization whose signature artifact exceeds the 8 KB stress limit on the user path.
- Scheme-specific limits may be stricter, but not looser, on the user path.

## 5.3 Stage T2: Fee-Floor and Admission Policy Checks

Primary crate: `shell-mempool`

Upstream mempool policy requires dual-lane admission:
- payload-lane floor derived from the current execution `BaseFee`,
- witness-lane floor derived from the current witness pricing lane.

This stage should run before cryptographic verification on untrusted gossip traffic because it is cheaper and drops obvious spam early.

Checks:
1. Validate the transaction declares fees compatible with the current payload-lane base fee.
2. Validate the transaction declares fees compatible with the current witness-lane base fee.
3. Apply local pool-capacity and replacement-key policy.
4. Apply replay or nonce-lane policy using lightweight cached account metadata when available.

Failure handling:
- Fee-floor failure: reject from the local pool and optionally lower peer reputation for repeated spam; do not disconnect.
- Local capacity eviction or replacement failure: local policy outcome only; no disconnect.
- Nonce/replay conflicts: reject or place into a deferred queue; no disconnect unless the object is otherwise malformed.

Implementation note:
- Replacement keys must follow the `Execution Identity + Nonce Lane / Replay Domain` direction, not a legacy `sender + nonce` shortcut.
- The exact replay-domain surface may evolve as protocol details close; isolate it behind a dedicated type instead of hard-coding tuple layouts across the crate.

## 5.4 Stage T3: Signature Verification

Primary crates: `shell-mempool` -> `shell-crypto`

Checks:
1. Construct `SigningData` with the transaction domain.
2. Dispatch each authorization to the scheme verifier.
3. Apply the transaction-path acceptance policy for multiple authorizations.

Acceptance policy guidance:
- The verifier must return per-authorization results.
- The mempool admission policy must not treat a transaction as valid until the required authorization condition for the locally supported transaction shape is satisfied.
- If the protocol later defines threshold or role-based multi-authorization semantics, that policy belongs in `shell-mempool`; `shell-crypto` remains a pure verifier.

Pending protocol-closure note:
- The `authorizations` container is part of the current transaction shape, but richer multi-authorization semantics are not yet closed here. Until that closes, the default implementation should require that all currently interpreted required authorizations verify successfully, and document any narrower assumption explicitly in code.

Failure handling:
- Any cryptographic failure on a required authorization rejects the transaction.
- P2P-originated invalid signatures are disconnect-grade.
- Local RPC submission with an invalid signature returns a validation error only.

## 5.5 Stage T4: Optional Witness Sidecar Checks

Primary crates: `shell-mempool` + `shell-state`

This stage is optional for ordinary nodes and expected for builders, heavy validators, or nodes maintaining a higher-fidelity pool.

Checks when `TransactionWitnessSidecar` is available:
1. Verify `sidecar.tx_root == hash_tree_root(TransactionEnvelope)`.
2. Verify any advertised sidecar byte ceiling before deep parsing.
3. Verify `state_proofs` are canonically ordered by `StateKey` before reconstruction (ordering is defined by the key, not by the provisional witness byte encoding).
4. Use `shell-state` traits to verify proof paths and reconstruct a stateless read view.
5. Validate nonce, balance, and capability-linked preconditions that cannot be checked from envelope data alone.

Failure handling:
- `tx_root` mismatch or malformed proof encoding: disconnect-grade on P2P ingress.
- Oversize sidecar: ignore, rate-limit, or lower reputation unless the peer violated an already accepted fetch contract in a malicious way.
- Proof insufficiency or stale state: remove from the high-fidelity pool; the transaction may still remain in a lighter tentative pool depending on local policy.

Pending protocol-closure note:
- Witness compression and canonical encoding are not yet frozen in this spec set. Hash committed bytes exactly as received by protocol definition; do not normalize, recompress, or re-encode a sidecar before commitment checks unless a later local spec update makes that transformation canonical.

## 5.6 Transaction Validation Outputs

Recommended reusable outputs:
- `TentativeAccepted`: passed structural and fee-floor checks, but no witness-sidecar execution precheck was performed.
- `StatelesslyValidated`: passed witness-sidecar proof validation and any optional dry-run checks.
- `Rejected(ValidationError)`: object-level rejection.

Cacheable artifacts:
- `payload_root`
- `signing_root`
- per-authorization signature verification results
- fee-floor evaluation snapshot keyed by base-fee epoch or block number

## 6. Block Validation Pipeline

Block validation must also remain cheap-first.
Do not fetch or deeply parse witness sidecars until the header-level and body-binding gates have already passed.

## 6.1 Stage B0: Envelope Decode and Header Prefilter

Primary crates: `shell-network` -> `shell-consensus`

Checks:
1. Decode `SignedBlockEnvelope` and `BlockHeader`.
2. Compute `block_root = hash_tree_root(header)` once and retain it for later stages.
3. Apply the header stateless prefilter defined by this validation pipeline.

`witness_bytes` handling:
- `header.witness_bytes` must be checked before sidecar fetch or deep sidecar parsing.
- The current protocol shape clearly requires this prefilter, but does not yet freeze the final protocol threshold for block-level witness volume.
- Therefore the implementation must expose a configurable ingress ceiling and mark it as pending protocol closure rather than hard-coding an invented consensus value.

Failure handling:
- Malformed header or impossible field encoding: disconnect-grade on P2P ingress.
- Header advertising witness volume above the local download ceiling: drop or refuse sidecar fetch; usually reputation impact, not immediate disconnect, unless the object is otherwise malformed.

## 6.2 Stage B1: Header-Only Signature Verification

Primary crates: `shell-consensus` -> `shell-crypto`

Checks:
1. Resolve the active proposer credential from validator state.
2. Construct the validator-path signing root for the header.
3. Verify `proposer_signature` via the signature dispatcher.

Ordering rule:
- This stage must run before any heavy sidecar or execution work.
- A node may run `B2` before or after `B1` when the full body is already present, but both are cheaper than sidecar reconstruction and both must complete before `B4`.

Pending protocol-closure note:
- Do not hard-code current candidate validator-path numbers as finalized consensus-invalidating limits.
- Use configurable transport guards for validator-path signature size, and keep the consensus validity rule tied to a future local spec closure.

## 6.3 Stage B2: Header / Body Binding

Primary crate: `shell-consensus`

Required check:
- `hash_tree_root(BlockBody.transactions) == header.transactions_root`

This is a mandatory precondition for any per-transaction reuse or execution.
If the block body does not bind to the header, all deeper work is wasted.

Failure handling:
- Root mismatch is invalid block data and disconnect-grade on P2P ingress.

## 6.4 Stage B3: Per-Transaction Revalidation

Primary crates: `shell-consensus` -> `shell-mempool`

Checks:
1. For each transaction in block order, reuse cached transaction validation results when available.
2. If no cache entry exists, run transaction stages `T1` through `T3` at minimum.
3. If a cached result depends on stale local fee or nonce snapshots, invalidate and recompute the required stages.

Rules:
- A block importer must not assume mempool presence.
- Transactions included in a block still require stateless structural and signature validity even if a local pool previously accepted them.
- Optional mempool-only admission policies should not be allowed to make a consensus-valid block fail.

Implementation split:
- `shell-mempool` may provide reusable validators.
- `shell-consensus` owns the final import decision and chooses which mempool-policy results are consensus-critical vs. local-policy only.

## 6.5 Stage B4: Sidecar Binding and Witness Preparation

Primary crates: `shell-consensus` -> `shell-state`

Required checks:
1. `sidecar.block_root == hash_tree_root(header)`
2. `hash_tree_root(sidecar) == header.execution_witnesses_root`

Additional implementation checks:
- Validate witness container structure before execution.
- Preserve committed ordering and bytes for root checks.
- Only after commitment checks pass may the implementation build any optimized in-memory witness index.

Ordering rules:
- Sidecar binding must complete before stateless execution.
- Any deduplication or indexing used for execution must be downstream of commitment checks.
- Because the current block shape allows witness deduplication at block-building time, import code must validate the committed sidecar as provided; it must not require a non-deduplicated per-transaction layout.

Failure handling:
- Sidecar commitment mismatch is invalid block data and disconnect-grade on P2P ingress.
- Oversize sidecar relative to local download policy should normally stop fetch earlier at `B0`; if encountered late, treat it as a policy failure unless malformed structure is also present.

## 6.6 Stage B5: Stateless Execution and Root Comparison

Primary crates: `shell-execution` + `shell-state`

Checks:
1. Reconstruct the execution witness view from the already-bound sidecar.
2. Execute transactions in block order.
3. Compute the resulting post-state root.
4. Compute the receipts root.
5. Compare computed roots to `header.state_root` and `header.receipts_root`.

Rules:
- Transaction execution order is the block order; no reordering for convenience.
- Cheap failures must already have been exhausted before entering this stage.
- Execution caches are acceptable, but the final compared roots must correspond to the exact committed header and sidecar under import.

Failure handling:
- Any execution failure that proves the block cannot realize the committed roots rejects the block.
- On a P2P path, root mismatches are disconnect-grade because the peer supplied invalid block data.

## 7. Validation Ordering Constraints

The following ordering constraints are mandatory unless a narrower optimization preserves the same rejection semantics.

### 7.1 Transaction Ordering

Default order for untrusted gossip:
1. Decode and structural SSZ checks.
2. Payload-root recomputation and authorization-root matching.
3. User-path size limits, including the 8 KB authorization signature limit.
4. Fee-floor and lightweight replay policy.
5. Signature verification dispatch.
6. Optional witness-sidecar proof validation.

Rationale:
- structure and root checks are cheaper than signature verification,
- fee-floor rejection is cheaper than signature verification and should drop spam before PQ work,
- witness proof reconstruction is the heaviest pre-execution path and must come last.

### 7.2 Block Ordering

Default order for block import:
1. Decode header envelope.
2. Apply `header.witness_bytes` prefilter before sidecar fetch.
3. Verify header/body binding when the body is present.
4. Verify proposer signature.
5. Revalidate transaction structure/signatures as needed.
6. Verify sidecar/header binding.
7. Run stateless execution and compare state/receipts roots.

Rationale:
- sidecar fetch and stateless execution are strictly downstream of cheaper commitment checks,
- proposer-signature failure must short-circuit deeper work,
- transaction revalidation must occur before execution to keep execution code free of malformed objects.

### 7.3 Allowed Reordering

Implementations may reorder checks inside the same cost class only when:
- no cheaper rejection opportunity is lost,
- the same invalid object is still rejected,
- no heavy cryptographic or state-proof work is pulled earlier without a documented reason.

Examples:
- `B1` and `B2` may swap when both header and body are already local and neither triggers sidecar fetch.
- A cached signature result may skip repeated PQ verification, but only if it is keyed by the exact signing root and verifier configuration.

## 8. Reputation, Rate Limiting, and Disconnect Guidance

This section is intentionally operational rather than consensus-critical.

| Failure kind | Default action | Notes |
|---|---|---|
| Malformed SSZ object | Disconnect | Invalid protocol object. |
| Unsupported `scheme_id` on P2P path | Disconnect | Treated as malformed protocol data, not a soft policy miss. |
| Invalid signature after full decoding | Disconnect | Upstream networking guidance classifies this as malicious or malformed. |
| Root-binding mismatch (`payload_root`, `tx_root`, `transactions_root`, `execution_witnesses_root`) | Disconnect | Indicates forged or corrupted object linkage. |
| Oversize announcement or oversize sidecar beyond local fetch policy | Ignore / rate-limit / lower reputation | Do not disconnect solely for size pressure. |
| Fee-floor failure | Reject locally; optional reputation reduction for spam patterns | Policy failure, not protocol forgery. |
| Nonce conflict or stale state proof | Reject locally or evict from high-fidelity pool | Usually not a disconnect event by itself. |
| Repeated unsolicited heavy objects | Lower reputation, then rate-limit | Escalate operationally before disconnecting. |

Implementation note:
- Keep peer-action mapping outside the pure validation crates.
- Pure validators should return a machine-readable `PeerActionHint` or equivalent classification rather than calling network code directly.

## 9. Pending Protocol-Closure Items

The following items must remain marked as pending in code comments, config surfaces, or TODOs until upstream freezes them:

1. **Block-level witness volume threshold**
   - `header.witness_bytes` must be checked early, but the final protocol ceiling is not frozen yet in this spec set.
   - Implementation action: keep this as a configurable ingress limit, not a hard-coded consensus number.

2. **Validator-path signature size tolerance**
   - Candidate range exists, but not a finalized protocol hard limit.
   - Implementation action: separate transport guards from consensus-invalidating rules.

3. **Validator credential object model and lifecycle**
   - Validator credential separation is still treated as tentative in this spec set.
   - Implementation action: keep proposer-signature resolution behind traits or registries, not hard-wired account-path logic.

4. **Supported signature-family narrowing**
   - The current protocol posture still allows a multi-family bootstrap surface.
   - Implementation action: keep `shell-crypto` dispatcher scheme-agile and avoid leaking family-specific assumptions into mempool or consensus code.

5. **Multi-authorization semantics**
   - The container is defined, but richer threshold or role semantics are not closed here.
   - Implementation action: keep acceptance policy explicit and isolated from cryptographic verification.

6. **Witness compression and canonical encoding rules**
   - This remains open in the current local assumptions.
   - Implementation action: never rewrite or normalize sidecar bytes before commitment verification.

7. **Scheme-specific verification gas coefficients**
   - Still unset in the current protocol assumptions.
   - Implementation action: keep execution metering hooks configurable and clearly marked as provisional.

Practical rule:

- if an implementation choice would change wire bytes, change commitment inputs, reinterpret signature acceptance, or turn a configurable transport guard into a consensus-invalidating constant, it is **not** closed yet unless Section `1.1` says otherwise.

## 10. Implementation Checklist

Future Rust work should be able to implement directly from this document:
- `shell-primitives`: provide signing-root helpers for transaction and validator domains.
- `shell-crypto`: expose a scheme dispatcher with byte-bound prechecks and uniform errors.
- `shell-mempool`: implement `T0`-`T4` with cacheable outputs and clear policy vs. validity separation.
- `shell-consensus`: implement `B0`-`B5`, including proposer-signature dispatch and sidecar-root binding.
- `shell-state`: expose proof-ordering and witness-verification helpers without embedding network policy.
- `shell-network`: translate validation classifications into ignore, rate-limit, reputation, disconnect, or blacklist actions.
