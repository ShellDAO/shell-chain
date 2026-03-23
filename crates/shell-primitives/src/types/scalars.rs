use alloc::vec::Vec;

pub type Root = [u8; 32];
pub type Bytes32 = [u8; 32];
pub type Bytes31 = [u8; 31];
pub type Bytes4 = [u8; 4];
pub type ExecutionAddress = [u8; 20];

pub const MOCK_PROGRESSIVE_BYTE_LIST_LIMIT: usize = 1_048_576;
pub const MOCK_PROGRESSIVE_LIST_LIMIT: usize = 8_192;

// These aliases keep the provisional container names visible in Rust without
// freezing the current temporary bounds as consensus constants.
pub type MockProgressiveByteList = Vec<u8>;
pub type MockProgressiveList<T> = Vec<T>;

// Bootstrap placeholder until the workspace adopts one shared external U256
// dependency for every crate that needs large integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct U256(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChainId(pub U256);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxValue(pub U256);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GasPrice(pub U256);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicFeesPerGas {
    pub regular: GasPrice,
    pub max_priority_fee_per_gas: GasPrice,
    pub max_witness_priority_fee: GasPrice,
}
