use crate::errors::PrimitiveError;
use crate::types::{
    Bytes31, Bytes32, ExecutionAddress, MockProgressiveByteList, MockProgressiveList,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateKey {
    AccountHeader(ExecutionAddress),
    StorageSlot {
        address: ExecutionAddress,
        slot: Bytes32,
    },
    CodeChunk {
        address: ExecutionAddress,
        chunk_index: u32,
    },
    RawTreeKey(Bytes32),
    Stem(Bytes31),
}

impl StateKey {
    pub fn canonical_sort_key(&self) -> Result<MockProgressiveByteList, PrimitiveError> {
        Err(PrimitiveError::Unimplemented(
            "StateKey canonical ordering depends on the shared SSZ encoding path chosen in shell-state",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWitness {
    pub key: StateKey,
    pub leaf_value: MockProgressiveByteList,
    pub proof: MockProgressiveList<Bytes32>,
}

pub fn canonicalize_execution_address(addr: &ExecutionAddress) -> Bytes32 {
    let mut key = [0; 32];
    key[12..].copy_from_slice(addr);
    key
}
