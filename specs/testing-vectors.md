# Testing Vectors

> Implementation-ready testing-vector contract for `shell-chain`.
>
> This document defines what must be tested, which crate owns each invariant, how shared fixtures should be organized, and which areas remain provisional until more protocol details close.

## Status

Draft, but intended to be specific enough to drive the first repository-local fixture layout and crate test plan.

## 1. Purpose

The testing surface in `shell-chain` must prove more than "bytes can decode."
It must demonstrate that the repository preserves the local protocol contract across four layers:

1. **canonical wire behavior**
   - SSZ encode/decode, discriminants, and root calculation match the repository's declared object model,

2. **binding commitments**
   - payload, transaction, block, and sidecar commitments fail closed on mismatch,

3. **validation ordering**
   - cheap rejection paths remain ahead of cryptographic verification and witness reconstruction,

4. **separation of finalized vs. provisional behavior**
   - tests for open protocol areas must not accidentally freeze local implementation policy as if it were consensus.

## 2. Repository-Local Testing Assumptions

Until a full fixture corpus is checked in, this repository should treat the following as the minimum local contract:

- `TransactionPayload` is an append-only SSZ union with tag `0` for `BasicTransactionPayload` and tag `1` for `CreateTransactionPayload`.
- `payload_root`, `tx_root`, `transactions_root`, and `execution_witnesses_root` are binding commitments and must fail closed on mismatch.
- User-path authorization signatures above 8 KB are rejected by default as a local stress-control rule.
- Witness ordering checks run against one canonical `StateKey` comparator before proof reconstruction.
- `header.witness_bytes` and validator-path signature-size controls are configurable ingress guards, not frozen consensus constants.
- Witness compression, canonical witness encoding, richer multi-authorization semantics, and parts of the detailed proof-node layout remain provisional and must be tested as provisional behavior.

## 3. Fixture Placement and Naming

When repository-level fixtures are added, they should live under:

```text
vectors/
├── transactions/
├── blocks/
└── witnesses/
```

Recommended naming pattern:

- `tx-basic-valid-001`
- `tx-basic-unknown-tag-001`
- `tx-auth-payload-root-mismatch-001`
- `block-body-root-mismatch-001`
- `witness-noncanonical-order-001`

Naming rules:

- use stable semantic names, not implementation-specific file names,
- encode whether the vector is expected to pass or fail,
- increment suffixes only when multiple vectors exercise the same invariant family.

## 4. Fixture Shape

Shared vectors should use a data model that is easy to consume from Rust tests without embedding crate-specific assumptions.

At minimum, each vector should carry:

| Field | Meaning |
|---|---|
| `id` | Stable unique vector identifier |
| `category` | `transaction`, `signature`, `witness`, `block`, or `policy` |
| `description` | Human-readable explanation of the invariant being tested |
| `input` | Canonical encoded object or structured object fields needed to build it |
| `expected_outcome` | `accept`, `reject`, or `policy_reject` |
| `expected_error` | Structured failure kind when rejection is expected |
| `owned_by` | Primary crate responsible for enforcing the invariant |
| `notes` | Optional explanation for provisional or cross-crate behavior |

Recommended extra fields by category:

- transaction vectors
  - `payload_tag`
  - `payload_root`
  - `signing_root`
  - `authorization_count`

- witness vectors
  - `tx_root` or `block_root`
  - `state_keys`
  - `proof_shape_kind`
  - `ordering_is_canonical`

- block vectors
  - `transactions_root`
  - `execution_witnesses_root`
  - `state_root`
  - `receipts_root`

Fixture format is not yet frozen, but it should be chosen once at the repository level and reused consistently.
Tests should not require each crate to invent its own incompatible fixture schema.

## 5. Outcome Classes

Every vector should map to one of three outcomes:

- `accept`
  - the object satisfies the relevant canonical or policy checks.

- `reject`
  - the object is invalid for the tested path and must fail with a structured validation error.

- `policy_reject`
  - the object is not malformed, but local policy declines it without treating it as forged protocol data.

This distinction matters because `validation-rules.md` separates malformed-object rejection from soft policy outcomes such as fee-floor rejection or local download ceilings.

## 6. Ownership by Crate

### 6.1 `shell-primitives`

Owns vectors for:

- SSZ round-trip behavior,
- union-tag compatibility,
- canonical root calculation,
- block/body/witness object binding inputs,
- low-level decode failures and unsupported discriminants.

Typical pass/fail examples:

- valid `TransactionPayload` tag `0` round-trips and produces the expected root,
- valid `TransactionPayload` tag `1` round-trips and produces the expected root,
- unknown payload tag is rejected as `UnsupportedPayloadVariant`,
- malformed SSZ bytes fail decode before any higher-level validation step.

### 6.2 `shell-crypto`

Owns vectors for:

- supported-scheme verification success,
- supported-scheme verification failure,
- unsupported `scheme_id`,
- scheme-local artifact-size guards,
- normalized error mapping returned to callers.

Typical pass/fail examples:

- correct public key, signing root, and signature verify successfully,
- same signature with a different signing root fails verification,
- oversize user-path signature fails the local bound before cryptographic verification.

### 6.3 `shell-state`

Owns vectors for:

- canonical `StateKey` ordering,
- witness proof-shape decoding,
- proof reconstruction success/failure,
- accumulator invariants,
- separation between committed witness form and any optimized derived proof index.

Typical pass/fail examples:

- witness list already sorted by canonical comparator is accepted,
- same witness list in non-canonical order is rejected before proof reconstruction,
- malformed proof data fails as a state-proof validation error,
- block sidecar bytes are preserved through commitment checks before any derived indexing.

### 6.4 `shell-execution`

Owns vectors for:

- post-state root calculation,
- receipts-root calculation,
- execution ordering in block order,
- transition-output determinism for a fixed witness view.

### 6.5 `shell-mempool`

Owns vectors for:

- cheap-first transaction admission ordering,
- fee-floor policy checks,
- replay / nonce-lane policy checks,
- caching behavior that reuses exact signing-root results without changing correctness.

Typical pass/fail examples:

- fee-floor failure rejects before signature verification on untrusted gossip,
- payload-root mismatch rejects before PQ verification,
- a valid transaction can move from tentative acceptance to stateless acceptance when a valid sidecar becomes available.

### 6.6 `shell-consensus`

Owns vectors for:

- header/body binding,
- block-sidecar binding,
- proposer-signature validation flow,
- per-transaction revalidation inside block import,
- block-level root comparison after stateless execution.

### 6.7 `shell-network`

Owns vectors for:

- mapping validation outcomes into disconnect / ignore / rate-limit actions,
- download refusal based on local size policy,
- non-penalizing treatment of purely local-policy failures.

These are operational vectors rather than consensus vectors, but they still need a stable local contract.

## 7. Required Vector Matrix

The first complete test corpus should cover the following matrix.

### 7.1 Transaction Codec and Union Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `tx-basic-valid-*` | `BasicTransactionPayload` tag `0` decodes, re-encodes, and roots canonically | accept | `shell-primitives` |
| `tx-create-valid-*` | `CreateTransactionPayload` tag `1` decodes, re-encodes, and roots canonically | accept | `shell-primitives` |
| `tx-unknown-tag-*` | unsupported payload tag fails cleanly | reject | `shell-primitives` |
| `tx-malformed-ssz-*` | malformed bytes fail low-level decode | reject | `shell-primitives` |

### 7.2 Payload-Root and Signing-Root Binding Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `tx-payload-root-match-*` | `Authorization.payload_root` matches canonical payload root | accept | `shell-primitives` + `shell-mempool` |
| `tx-payload-root-mismatch-*` | mismatched `payload_root` fails before signature verification | reject | `shell-mempool` |
| `tx-signing-root-match-*` | canonical signing-root construction validates against known signature | accept | `shell-primitives` + `shell-crypto` |
| `tx-signing-root-mismatch-*` | signing with a different root fails verification | reject | `shell-crypto` |
| `tx-auth-empty-*` | empty authorization list is rejected by default | reject | `shell-mempool` |

### 7.3 Signature and Scheme Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `sig-supported-valid-*` | supported scheme verifies successfully | accept | `shell-crypto` |
| `sig-supported-invalid-*` | signature bytes fail verification for the same scheme | reject | `shell-crypto` |
| `sig-validator-valid-*` | validator-path signature verifies successfully | accept | `shell-crypto` |
| `sig-validator-invalid-*` | validator-path signature fails verification | reject | `shell-crypto` |
| `sig-unsupported-scheme-*` | unsupported `scheme_id` is rejected | reject | `shell-crypto` |
| `sig-user-oversize-*` | user-path signature larger than 8 KB fails local stress limit | reject | `shell-mempool` + `shell-crypto` |
| `sig-validator-oversize-*` | validator-path size guard is handled as configurable transport policy, not frozen consensus | policy_reject | `shell-consensus` + `shell-network` |

### 7.4 Witness Ordering and Reconstruction Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `witness-order-canonical-*` | canonically sorted `StateKey` witness list is accepted (byte encoding is provisional) | accept | `shell-state` |
| `witness-order-noncanonical-*` | non-canonical `StateKey` witness ordering rejects before reconstruction | reject | `shell-state` |
| `witness-proof-valid-*` | witness proof reconstructs the expected state view | accept | `shell-state` |
| `witness-proof-invalid-*` | malformed or insufficient proof fails reconstruction | reject | `shell-state` |
| `witness-tx-root-mismatch-*` | `sidecar.tx_root` does not match envelope root | reject | `shell-mempool` + `shell-state` |

### 7.5 Block Binding Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `block-transactions-root-match-*` | body transactions root matches header | accept | `shell-consensus` |
| `block-transactions-root-mismatch-*` | body/header mismatch fails import | reject | `shell-consensus` |
| `block-sidecar-root-match-*` | `sidecar.block_root` and `execution_witnesses_root` both bind | accept | `shell-consensus` |
| `block-sidecar-root-mismatch-*` | sidecar/header commitment mismatch fails import | reject | `shell-consensus` |
| `block-execution-roots-match-*` | computed `state_root` and `receipts_root` match header after execution | accept | `shell-execution` + `shell-consensus` |
| `block-execution-roots-mismatch-*` | execution output fails final root comparison | reject | `shell-execution` + `shell-consensus` |

### 7.6 Validation-Ordering Vectors

These vectors prove that the implementation preserves cheap-first behavior rather than merely producing the right final answer.

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `order-payload-before-signature-*` | payload-root mismatch is rejected before verifier dispatch | reject | `shell-mempool` |
| `order-fee-before-signature-*` | fee-floor failure short-circuits signature verification on untrusted gossip | policy_reject | `shell-mempool` |
| `order-header-before-sidecar-*` | `witness_bytes` prefilter prevents unnecessary sidecar work | policy_reject | `shell-consensus` + `shell-network` |
| `order-body-root-mismatch-stops-sidecar-*` | transactions-root mismatch prevents sidecar processing | reject | `shell-consensus` |
| `order-sidecar-before-execution-*` | sidecar binding failure stops execution | reject | `shell-consensus` |

### 7.7 Operational and Reputation Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `peer-malformed-ssz-*` | malformed protocol object maps to disconnect | reject | `shell-network` |
| `peer-invalid-signature-*` | invalid signature on P2P path maps to disconnect | reject | `shell-network` |
| `peer-oversize-sidecar-*` | oversize sidecar maps to ignore / rate-limit, not disconnect by default | policy_reject | `shell-network` |
| `peer-fee-spam-*` | repeated fee-floor failures may lower reputation without protocol-malformed handling | policy_reject | `shell-network` |

### 7.8 Fee and Nonce Policy Vectors

| ID family | Invariant | Expected outcome | Primary crate |
|---|---|---|---|
| `fee-payload-insufficient-*` | transaction payload fee below base fee | policy_reject | `shell-mempool` |
| `fee-witness-insufficient-*` | transaction witness fee below witness-lane base fee | policy_reject | `shell-mempool` |
| `nonce-replay-conflict-*` | transaction nonce/lane conflicts with known state | policy_reject | `shell-mempool` |
| `nonce-too-high-*` | transaction nonce gap exceeds local pool limit | policy_reject | `shell-mempool` |

## 8. Negative-Vector Requirements

The corpus must contain deliberate failure cases, not only happy-path examples.

For each major invariant family, include at least:

- one malformed-object vector,
- one root-binding mismatch vector,
- one policy-only rejection vector where applicable,
- one "same shape, different bytes" vector showing that commitment checks are byte-sensitive and fail closed.

This requirement is especially important for:

- payload-root checks,
- sidecar-root checks,
- witness ordering,
- block header/body binding,
- signature verification.

## 9. Provisional-Area Testing Rules

Some areas are not yet closed enough to deserve hard-coded canonical vectors that pretend to be final protocol truth.

Those areas currently include:

- witness compression and canonical witness byte encoding,
- detailed internal proof-node layout,
- richer multi-authorization semantics,
- final validator-path artifact-size rules,
- some transport ceilings around witness volume.

Testing rule for provisional areas:

- verify that the implementation exposes the intended boundary,
- verify that the implementation labels policy vs. consensus behavior correctly,
- avoid fixtures that imply a permanently frozen wire contract where this repository has not declared one.

In practice, provisional vectors should focus on:

- stable failure classification,
- configurability boundaries,
- preservation of committed bytes before any local normalization,
- explicit documentation of what remains open.

## 10. Acceptance Criteria for the First Real Corpus

The vector set is in good shape when all of the following are true:

- both currently known transaction payload variants have canonical pass and fail vectors,
- root-binding mismatches exist for transaction, sidecar, and block paths,
- signature vectors cover success, failure, unsupported scheme, and oversize user-path artifacts,
- witness vectors cover canonical ordering and failure-before-reconstruction behavior,
- block vectors cover body binding, sidecar binding, and final execution-root comparison,
- ordering vectors prove that cheap-first rejection is preserved,
- at least one operational vector exists for each peer consequence class,
- provisional areas are tested without pretending to be finalized protocol law.

## 11. Initial Rollout Order

When the repository starts checking in fixtures, add them in this order:

1. transaction codec and payload-root vectors,
2. signature vectors,
3. witness ordering vectors,
4. block binding vectors,
5. execution-root vectors,
6. reputation / operational vectors.

This order matches the implementation strategy recommended elsewhere in the spec set: establish canonical object and root behavior first, then add cryptographic checks, then witness/state paths, and finally full block import and network consequences.
