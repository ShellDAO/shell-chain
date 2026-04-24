//! Unified JSON-RPC error code table for shell-chain.
//!
//! All error codes used by shell RPC handlers are declared here as named
//! constants. Handler code should import these constants rather than
//! hard-coding numeric literals, so that the full error surface is visible in
//! one place.
//!
//! # Error code ranges
//!
//! | Range              | Meaning                             |
//! |--------------------|-------------------------------------|
//! | `-32700`           | Parse error                         |
//! | `-32600`           | Invalid request                     |
//! | `-32601`           | Method not found / not enabled      |
//! | `-32602`           | Invalid params                      |
//! | `-32603`           | Internal error                      |
//! | `-32000` … `-32099`| Server-defined application errors   |
//! | `-32005`           | Limit exceeded (eth_ convention)    |

use jsonrpsee::types::ErrorObjectOwned;

// ---------------------------------------------------------------------------
// Standard JSON-RPC codes
// ---------------------------------------------------------------------------

/// `-32601` — The method does not exist or is not enabled on this node.
pub const METHOD_NOT_FOUND: i32 = -32601;

/// `-32602` — Invalid method parameters.
pub const INVALID_PARAMS: i32 = -32602;

/// `-32603` — Internal JSON-RPC error.
pub const INTERNAL_ERROR: i32 = -32603;

// ---------------------------------------------------------------------------
// Server-defined application codes  (`-32000` … `-32099`)
// ---------------------------------------------------------------------------

/// `-32000` — Generic server error / resource not found.
///
/// Used for "block not found", "filter not found", "storage profile not
/// configured", and similar not-found / precondition failures.
pub const SERVER_ERROR: i32 = -32000;

/// `-32001` — The requested resource (block, tx, receipt) was not found.
pub const NOT_FOUND: i32 = -32001;

/// `-32002` — The operation requires the node to be in dev mode.
pub const DEV_MODE_REQUIRED: i32 = -32002;

/// `-32003` — The node does not have the requested feature enabled (e.g. no
/// storage backend, no witness store, paymaster not configured).
pub const FEATURE_NOT_ENABLED: i32 = -32003;

// ---------------------------------------------------------------------------
// eth_ namespace codes (widely adopted convention)
// ---------------------------------------------------------------------------

/// `-32005` — Result limit exceeded (used by `eth_getLogs`).
pub const LIMIT_EXCEEDED: i32 = -32005;

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Build a `-32601` "method not found / not enabled" error.
pub fn method_not_found(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(METHOD_NOT_FOUND, msg.into(), None::<()>)
}

/// Build a `-32602` "invalid params" error.
pub fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS, msg.into(), None::<()>)
}

/// Build a `-32000` "server error" (generic / not found).
pub fn server_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(SERVER_ERROR, msg.into(), None::<()>)
}

/// Build a `-32001` "not found" error.
pub fn not_found(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(NOT_FOUND, msg.into(), None::<()>)
}

/// Build a `-32002` "dev mode required" error.
pub fn dev_mode_required(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(DEV_MODE_REQUIRED, msg.into(), None::<()>)
}

/// Build a `-32003` "feature not enabled" error.
pub fn feature_not_enabled(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(FEATURE_NOT_ENABLED, msg.into(), None::<()>)
}

/// Build a `-32005` "limit exceeded" error.
pub fn limit_exceeded(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(LIMIT_EXCEEDED, msg.into(), None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
        assert_eq!(SERVER_ERROR, -32000);
        assert_eq!(NOT_FOUND, -32001);
        assert_eq!(DEV_MODE_REQUIRED, -32002);
        assert_eq!(FEATURE_NOT_ENABLED, -32003);
        assert_eq!(LIMIT_EXCEEDED, -32005);
    }

    #[test]
    fn constructors_return_correct_codes() {
        assert_eq!(method_not_found("x").code(), METHOD_NOT_FOUND);
        assert_eq!(invalid_params("x").code(), INVALID_PARAMS);
        assert_eq!(server_error("x").code(), SERVER_ERROR);
        assert_eq!(not_found("x").code(), NOT_FOUND);
        assert_eq!(dev_mode_required("x").code(), DEV_MODE_REQUIRED);
        assert_eq!(feature_not_enabled("x").code(), FEATURE_NOT_ENABLED);
        assert_eq!(limit_exceeded("x").code(), LIMIT_EXCEEDED);
    }

    #[test]
    fn constructors_carry_message() {
        let e = server_error("block not found");
        assert_eq!(e.message(), "block not found");
    }
}
