# Data Types (Rust API Mapping)

> **Non-normative Rust binding:** this document describes the Rust-facing data types and local protocol assumptions that `shell-chain` should implement.
> It is meant to stand on its own for repository-local work: closed wire contracts are stated directly here, and still-open areas are kept explicitly provisional.

## 1. Binding goals

This file is intentionally implementation-oriented:

- prefer strongly typed Rust wrappers over raw SSZ containers,
- preserve exact upstream commitment behavior where upstream is already frozen,
- isolate still-open protocol areas behind traits, wrappers, or codec boundaries,
- avoid baking temporary mock container limits into consensus or fee logic.

The most important consequence is that Rust types may be richer than the wire schema, but any wire-facing codec must still round-trip to the exact upstream SSZ object and `hash_tree_root`.

## 2. Core aliases and temporary progressive containers

```rust
use ssz_rs::prelude::*;

pub type Root = Vector<u8, 32>;
pub type Bytes32 = Vector<u8, 32>;
pub type Bytes31 = Vector<u8, 31>;
pub type ExecutionAddress = Vector<u8, 20>;

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct ChainId(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct TxValue(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize)]
pub struct GasPrice(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct BasicFeesPerGas {
    pub regular: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub max_witness_priority_fee: GasPrice,
}

// Temporary stand-ins for upstream Progressive containers.
// These names must remain obviously provisional in Rust code.
pub type MockProgressiveByteList = List<u8, 1048576>;
pub type MockProgressiveList<T> = List<T, 8192>;
```

### 2.1 Mock-container discipline

Upstream transaction and witness specs treat `ProgressiveByteList` / `ProgressiveList[T]` as protocol-level semantic types. The current bounded aliases above are only local implementation substitutes until the upstream-compatible container story is closed in the Rust stack.

Rust implementation guidance:

- treat `MockProgressiveByteList` and `MockProgressiveList<T>` as **codec adapters**, not as protocol constants,
- do **not** derive fee heuristics, mempool scoring, gossip assumptions, or proof-shape assumptions from `1048576` or `8192`,
- keep local ingress ceilings configurable and clearly labeled as implementation policy unless upstream freezes a protocol number,
- keep the merkleization / gindex mental model tied to the upstream progressive semantics, not to the temporary bounded replacement.

Within this spec set, mock container bounds are implementation-only adapters and are not part of frozen protocol behavior.

## 3. Transaction bindings

```rust
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct BasicTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub to: ExecutionAddress,
    pub value: TxValue,
    pub input: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct CreateTransactionPayload {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub gas_limit: u64,
    pub fees: BasicFeesPerGas,
    pub value: TxValue,
    pub initcode: MockProgressiveByteList,
    pub access_commitment: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct Authorization {
    pub scheme_id: u8,
    pub payload_root: Root,
    pub signature: MockProgressiveByteList,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct TransactionEnvelope {
    pub payload: TransactionPayload,
    pub authorizations: MockProgressiveList<Authorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct SigningData {
    pub object_root: Root,
    pub domain_type: Bytes32,
}
```

### 3.1 `TransactionPayload` is a frozen SSZ union contract

Upstream has already frozen the wire-level meaning of `TransactionPayload` as a `CompatibleUnion` with append-only evolution.

That means the Rust binding must implement the following contract explicitly:

1. **Frozen discriminants**
   - tag `0` = `BasicTransactionPayload`
   - tag `1` = `CreateTransactionPayload`
   - future variants may only append new tags; existing tags must never be reused, reordered, or deleted.

2. **Codec ownership**
   - a plain Rust `enum` declaration is not itself the contract,
   - the wire-facing implementation must be owned by a dedicated wrapper, custom SSZ codec, or equivalent macro expansion that guarantees the exact upstream union encoding,
   - decode must reject unknown tags as an unsupported payload variant rather than silently coercing them.

3. **Root stability**
   - `hash_tree_root(TransactionPayload)` must be computed from the exact upstream union representation,
   - `Authorization.payload_root` validation depends on this being stable,
   - mempool, consensus, and signing helpers must all share the same codec path or a provably identical one.

4. **Wrapper expectation**
   - if the ergonomic Rust API uses a native enum, keep it behind a wrapper that controls SSZ encode/decode and root calculation,
   - do not rely on `repr(...)`, compiler layout, or derive defaults to define the wire format,
   - round-trip tests should assert `(bytes, tag, hash_tree_root)` compatibility for each known variant.

Illustrative shape:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionPayload {
    Basic(BasicTransactionPayload),
    Create(CreateTransactionPayload),
}

pub struct TransactionPayloadSsz(TransactionPayload);

impl TransactionPayloadSsz {
    pub const TAG_BASIC: u8 = 0;
    pub const TAG_CREATE: u8 = 1;

    pub fn protocol_tag(&self) -> u8 { /* custom mapping */ }
    pub fn hash_tree_root(&self) -> Root { /* exact union root */ }
    pub fn to_wire_bytes(&self) -> Vec<u8> { /* exact union codec */ }
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, DecodeError> { /* reject unknown tag */ }
}
```

The example above is not itself normative API, but the separation of:

- ergonomic domain enum,
- frozen union tags,
- explicit encode/decode/root logic,

should be treated as the expected Rust binding shape.

### 3.2 Validation alignment for transaction types

`specs/validation-rules.md` now assumes:

- unknown `TransactionPayload` tags fail as `UnsupportedPayloadVariant(Tag)`,
- `payload_root` is recomputed from the exact `TransactionPayload` wire object,
- witness-sidecar work stays downstream of cheaper structural and fee-floor checks.

The Rust binding should therefore make it difficult to:

- compute roots from an alternate in-memory shape,
- accept tag aliases,
- or run sidecar logic through payload codecs that differ from the shared canonical path.

## 4. State-layer bindings

```rust
pub enum StateKey {
    AccountHeader(ExecutionAddress),
    StorageSlot { address: ExecutionAddress, slot: Bytes32 },
    CodeChunk { address: ExecutionAddress, chunk_index: u32 },
    RawTreeKey(Bytes32),
    Stem(Bytes31),
}

pub fn canonicalize_execution_address(addr: &ExecutionAddress) -> Bytes32 {
    let mut key = Bytes32::default();
    key[12..32].copy_from_slice(addr.as_ref());
    key
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StateWitness {
    pub key: StateKey,
    pub leaf_value: MockProgressiveByteList,
    pub proof: MockProgressiveList<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StatePatch {
    pub accesses: MockProgressiveList<StateKey>,
    pub new_values: MockProgressiveList<MockProgressiveByteList>,
}

pub trait StateAccumulator {
    fn get_witness_for_accesses(&self, accesses: &[StateKey]) -> Result<Vec<StateWitness>, StateError>;
    fn apply_transition(&mut self, patch: StatePatch) -> Result<Root, StateError>;
    fn state_root(&self) -> Root;
}
```

### 4.1 What is known now vs. what is still pending upstream closure

The Rust binding should separate already-closed assumptions from still-open ones.

| Area | Closed enough to bind now | Still pending / should stay abstract |
|---|---|---|
| State accumulator family | Unified binary tree / JMT-style compressed binary accumulator is selected upstream. | Exact proof-node object model exposed on the wire may still evolve. |
| Address normalization | `ExecutionAddress` should canonicalize to a 32-byte tree key by left-padding with 12 zero bytes. | No additional alternate address-key encodings should be assumed. |
| Witness transport containers | `StateWitness` exists as the witness unit referenced by tx sidecars and block sidecars. | Witness compression and canonical byte encoding are not yet frozen upstream. |
| Proof verification flow | Validation requires canonical `StateKey` ordering before reconstruction and proof verification in `shell-state`. | Exact proof element layout inside `proof` is still placeholder-grade in the current upstream state-transition text. |
| Block-sidecar handling | Commitment checks must preserve committed ordering and bytes before any optimized indexing or dedup-aware execution view is built. | Any normalized in-memory proof index is local-only and must not be treated as a new canonical protocol form. |

### 4.2 `StateWitness.proof` should be treated as a proof-shape abstraction

The current placeholder:

```rust
pub proof: MockProgressiveList<Bytes32>
```

is useful as a temporary Rust field, but it should not be misread as a final statement that every upstream proof will forever be a flat list of hashes.

Binding guidance:

- expose proof verification behind traits or wrapper types in `shell-state`,
- keep `StateWitness` as the committed transport object and allow a separate decoded proof view for execution,
- assume the internal meaning of each proof element may later become richer once upstream closes the exact `InternalNode` / `StemNode` witness encoding,
- keep the verification API centered on `StateKey`, committed proof bytes/elements, and expected root reconstruction outcome.

In practice, a useful Rust split is:

- **committed form:** what SSZ decodes from the sidecar and what commitment checks see,
- **derived form:** an execution-friendly proof/index structure built only after ordering and commitment checks pass.

That split keeps `shell-state` aligned with validation ordering and avoids coupling execution optimizations to a still-open wire proof shape.

### 4.3 Canonical ordering requirements

For transaction witness sidecars, upstream-facing validation now expects `state_proofs` to be canonically ordered by `StateKey` before proof reconstruction.

Rust guidance:

- define one canonical comparator for `StateKey`,
- reuse it everywhere sidecar ordering is validated,
- reject non-canonical ordering before heavy proof work,
- keep any later in-memory grouping, deduplication, or indexing downstream of that check.

For block witness sidecars, preserve the committed sidecar ordering and bytes during root checks even if execution later builds a deduplicated index. Import code must not require a non-deduplicated per-transaction layout because upstream explicitly allows block-building deduplication.

### 4.4 Mock bounds must not leak into protocol heuristics

The witness path is where temporary implementation choices are most likely to become accidental protocol assumptions. Avoid that.

Specifically:

- do not interpret `List<Bytes32, 8192>` as proof-count consensus,
- do not price witnesses as if the temporary list ceiling were a protocol witness budget,
- do not use the mock container size to justify search depth, proof branching expectations, or cache eviction heuristics,
- do not rewrite, normalize, recompress, or canonicalize sidecar bytes before commitment verification unless upstream later freezes that transform.

This matters because witness compression and canonical sidecar encoding are still open within this spec set, and `validation-rules.md` requires committed bytes to be preserved through the commitment-check stage.

## 5. Practical implementation checklist

For future Rust work, the binding is in good shape if it satisfies all of the following:

- `TransactionPayload` encode/decode/root logic is centralized and tag-frozen.
- Unknown payload tags fail cleanly and early.
- `payload_root` uses the same canonical codec path everywhere.
- `StateKey` ordering is implemented once and reused for sidecar checks.
- `StateWitness` transport form is kept separate from any optimized proof index.
- Commitment verification always sees the committed sidecar bytes / order first.
- Temporary progressive mock bounds remain local implementation details, not consensus rules.

That is the intended Rust-facing contract until upstream closes the remaining witness encoding details.
