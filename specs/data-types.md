# Data Types (Rust API Mapping)

> **Non-Normative Binding**: This document dictates internal Rust API and Trait mappings for `shell-chain`. For absolute wire-level network truth, consult `../../specs/protocol/` (e.g., `transaction-format.md`).

## 1. Domain-Driven Semantic Mapping
Rather than exposing raw `ssz_rs` containers, we safely wrap fields using strongly typed Rust structures with mandatory derivation bounds:

```rust
use ssz_rs::prelude::*;

// Aliasing raw bytes into semantic pointers
pub type Root = Vector<u8, 32>;
pub type Bytes32 = Vector<u8, 32>;
pub type ExecutionAddress = Vector<u8, 20>;

// Error-prevention typing (SimpleSerialize derivation is mandatory)
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

// ==========================================
// ⚠️ IMPLEMENTATION PLACEHOLDER (Mock)
// ==========================================
// Protocol specs require EIP-7688 defined Progressive structures.
// Due to current client dependency limits natively supporting Progressive Lists,
// these Bounded Lists prefixed with "Mock" are temporary simulators.
// Admission/Gas heuristics relying on exactly these limits are considered implementation bugs
// and do not represent the final wire-level merkleization.
// See `../../specs/protocol/transaction-format.md` Section 1: Mock Disciplinary Constraints
pub type MockProgressiveByteList = List<u8, 1048576>;
pub type MockProgressiveList<T> = List<T, 8192>;     
```

## 2. Resolving Crate-Level Transactions

Connecting the `Protocol SSZ Schema` into the local Rust API:

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

// SSZ Encoding Contract Actualization:
// Rust Enums do NOT automatically map to SSZ Unions. The implementation here
// MUST provide custom wrappers or dedicated macros to ensure the emitted wire format
// adheres exactly to an EIP-6493 CompatibleUnion memory layout.
// Tag mapping is strictly locked: 0 => Basic, 1 => Create. Tag reordering is forbidden.
#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub enum TransactionPayload {
    Basic(BasicTransactionPayload),
    Create(CreateTransactionPayload),
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

## 3. State Layer API Boundaries (`shell-state`)

```rust
pub enum StateKey {
    AccountHeader(ExecutionAddress),
    StorageSlot { address: ExecutionAddress, slot: Bytes32 },
    CodeChunk { address: ExecutionAddress, chunk_index: u32 },
    RawTreeKey(Bytes32),
    Stem(Bytes31), 
}

/// Globally canonical execution address formatter.
/// The Rust implementation MUST exclusively invoke this helper to convert
/// a 20-byte ExecutionAddress into a 32-byte standardized Tree key.
/// Algorithm: Left-pad with 12 zero bytes.
pub fn canonicalize_execution_address(addr: &ExecutionAddress) -> Bytes32 {
    let mut key = Bytes32::default();
    key[12..32].copy_from_slice(addr.as_ref());
    key
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StateWitness {
    pub key: StateKey,
    pub leaf_value: MockProgressiveByteList,
    pub proof: MockProgressiveList<Bytes32>, // Schema adheres to protocol spec
}

#[derive(Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct StatePatch {
    pub accesses: MockProgressiveList<StateKey>,
    pub new_values: MockProgressiveList<MockProgressiveByteList>,
}

pub trait StateAccumulator {
    fn get_witness_for_accesses(&self, accesses: &[StateKey]) -> Result<Vec<StateWitness>, StateError>;
    
    fn apply_transition(&mut self, patch: StatePatch) -> Result<Root, StateError>;
    
    /// Extracts the logical "state accumulator tree root", strictly detached
    /// from root structural hash_tree_root object mechanics.
    fn state_root(&self) -> Root;
}
```
