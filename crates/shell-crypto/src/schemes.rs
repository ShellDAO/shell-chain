pub const DEFAULT_USER_PATH_MAX_SIGNATURE_SIZE: usize = 8 * 1024;

pub mod ed25519;
pub use ed25519::{Ed25519Verifier, SCHEME_ID_ED25519};
