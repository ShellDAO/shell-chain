use alloc::vec::Vec;
use core::cmp::Ordering;

pub use shell_primitives::canonicalize_execution_address;
use shell_primitives::StateKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateKeyBytes(Vec<u8>);

impl StateKeyBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

pub fn encode_state_key(key: &StateKey) -> StateKeyBytes {
    let mut bytes = Vec::new();

    match key {
        StateKey::AccountHeader(address) => {
            bytes.push(0);
            bytes.extend_from_slice(&canonicalize_execution_address(address));
        }
        StateKey::StorageSlot { address, slot } => {
            bytes.push(1);
            bytes.extend_from_slice(&canonicalize_execution_address(address));
            bytes.extend_from_slice(slot);
        }
        StateKey::CodeChunk {
            address,
            chunk_index,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&canonicalize_execution_address(address));
            bytes.extend_from_slice(&chunk_index.to_be_bytes());
        }
        StateKey::RawTreeKey(raw) => {
            bytes.push(3);
            bytes.extend_from_slice(raw);
        }
        StateKey::Stem(stem) => {
            bytes.push(4);
            bytes.extend_from_slice(stem);
        }
    }

    StateKeyBytes(bytes)
}

pub fn compare_state_keys(left: &StateKey, right: &StateKey) -> Ordering {
    encode_state_key(left)
        .as_slice()
        .cmp(encode_state_key(right).as_slice())
}
