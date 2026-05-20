use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrimitivesError {
    #[error("invalid hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("invalid slice length: expected {expected}, got {got}")]
    InvalidSliceLength { expected: usize, got: usize },
}
