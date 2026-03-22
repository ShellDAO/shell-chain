//! Closed-rule validation helpers for `shell-primitives`.
//!
//! Only the rules declared as closed in `specs/validation-rules.md §1.1` are
//! implemented here.  Open areas (scheme-specific checks, witness sizing,
//! validator credentials) are deliberately excluded.

use crate::errors::{
    AuthorizationCountError, PayloadRootMismatchError, PrimitiveError, SignatureSizeExceededError,
};
use crate::types::{Authorization, TransactionPayloadSsz};

/// Maximum signature artifact size on the user transaction path.
///
/// Per `validation-rules.md §1.1`: "Transaction-path authorization artifacts
/// above 8 KB are rejected by default as a local stress-control rule."
/// Scheme-local limits may be stricter but must not be looser on this path.
pub const MAX_USER_SIGNATURE_BYTES: usize = 8 * 1024;

/// Checks that the authorization list contains at least one entry.
///
/// Per `validation-rules.md §1.1`: "The default transaction path requires
/// `authorizations.len() >= 1`."
pub fn check_authorization_count(authorizations: &[Authorization]) -> Result<(), PrimitiveError> {
    if authorizations.is_empty() {
        Err(PrimitiveError::AuthorizationCount(
            AuthorizationCountError {
                expected_at_least: 1,
                actual: 0,
            },
        ))
    } else {
        Ok(())
    }
}

/// Checks that a signature artifact does not exceed the user-path 8 KB limit.
///
/// Per `validation-rules.md §1.1`: must reject before any cryptographic
/// verification begins.
pub fn check_user_signature_size(signature_bytes: &[u8]) -> Result<(), PrimitiveError> {
    if signature_bytes.len() > MAX_USER_SIGNATURE_BYTES {
        Err(PrimitiveError::SignatureSizeExceeded(
            SignatureSizeExceededError {
                max_bytes: MAX_USER_SIGNATURE_BYTES,
                actual_bytes: signature_bytes.len(),
            },
        ))
    } else {
        Ok(())
    }
}

/// Checks that every `Authorization.payload_root` matches the canonical
/// `hash_tree_root(TransactionPayload)`.
///
/// Per `validation-rules.md §1.1`: "Authorization.payload_root must match the
/// canonical hash_tree_root(TransactionPayload) exactly."  This check must run
/// before signature verification dispatch.
pub fn check_authorization_payload_roots(
    payload: &TransactionPayloadSsz,
    authorizations: &[Authorization],
) -> Result<(), PrimitiveError> {
    let expected_root = payload.hash_tree_root()?;
    for auth in authorizations {
        if auth.payload_root != expected_root {
            return Err(PrimitiveError::PayloadRootMismatch(
                PayloadRootMismatchError {
                    expected: expected_root,
                    actual: auth.payload_root,
                },
            ));
        }
    }
    Ok(())
}
