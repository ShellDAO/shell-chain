//! EVM call tracer for debug_traceTransaction.
//!
//! Provides [`CallFrame`] and [`TraceResult`] types that mirror Geth's
//! `callTracer` output, plus a helper to decode Solidity revert reasons.

use serde::{Deserialize, Serialize};
use shell_primitives::{Address, Bytes, U256};

/// A single call frame in an PQVM/revm execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallFrame {
    /// Call type: "CALL", "STATICCALL", "DELEGATECALL", "CREATE", "CREATE2", "SELFDESTRUCT"
    #[serde(rename = "type")]
    pub call_type: String,
    /// Caller address
    pub from: Address,
    /// Callee address (or created address for CREATE/CREATE2)
    pub to: Address,
    /// Value transferred in wei
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Gas provided to this call
    pub gas: u64,
    /// Gas actually used
    pub gas_used: u64,
    /// Input data
    pub input: Bytes,
    /// Output data (return data or revert reason)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Bytes>,
    /// Error message if the call reverted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Revert reason decoded from ABI error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    /// Nested calls
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub calls: Vec<CallFrame>,
}

/// Trace result returned by debug_traceTransaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    /// Top-level call frame
    #[serde(flatten)]
    pub frame: CallFrame,
    /// Whether the transaction failed
    pub failed: bool,
}

impl CallFrame {
    /// Create a new call frame.
    pub fn new(call_type: &str, from: Address, to: Address, gas: u64, input: Bytes) -> Self {
        Self {
            call_type: call_type.to_string(),
            from,
            to,
            value: None,
            gas,
            gas_used: 0,
            input,
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
        }
    }

    /// Set the value transferred.
    pub fn with_value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }
}

/// Decode a Solidity revert reason from the output bytes.
/// Standard revert reason: `Error(string)` = `0x08c379a0` + ABI-encoded string.
pub fn decode_revert_reason(output: &[u8]) -> Option<String> {
    // Minimum: 4 (selector) + 32 (offset) + 32 (length) + 0 (data) = 68 bytes
    if output.len() < 68 {
        return None;
    }
    // Check for Error(string) selector: 0x08c379a0
    if output.get(0..4) != Some(&[0x08, 0xc3, 0x79, 0xa0]) {
        return None;
    }
    // Read string length from offset 36..68
    let len_bytes = output.get(36..68)?;
    let b28 = len_bytes.get(28).copied().unwrap_or(0);
    let b29 = len_bytes.get(29).copied().unwrap_or(0);
    let b30 = len_bytes.get(30).copied().unwrap_or(0);
    let b31 = len_bytes.get(31).copied().unwrap_or(0);
    let len = u32::from_be_bytes([b28, b29, b30, b31]) as usize;

    if output.len() < 68usize.saturating_add(len) {
        return None;
    }

    String::from_utf8(output.get(68..68usize.saturating_add(len))?.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_frame_new() {
        let frame = CallFrame::new(
            "CALL",
            Address::default(),
            Address::default(),
            21000,
            Bytes::default(),
        );
        assert_eq!(frame.call_type, "CALL");
        assert_eq!(frame.gas, 21000);
        assert!(frame.calls.is_empty());
    }

    #[test]
    fn test_call_frame_with_value() {
        let frame = CallFrame::new(
            "CALL",
            Address::default(),
            Address::default(),
            21000,
            Bytes::default(),
        )
        .with_value(U256::from(100));
        assert_eq!(frame.value, Some(U256::from(100)));
    }

    #[test]
    fn test_trace_result_serialization() {
        let frame = CallFrame::new(
            "CALL",
            Address::default(),
            Address::default(),
            21000,
            Bytes::default(),
        );
        let result = TraceResult {
            frame,
            failed: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"type\":\"CALL\""));
        assert!(json.contains("\"failed\":false"));
    }

    #[test]
    fn test_nested_calls_serialization() {
        let mut parent = CallFrame::new(
            "CALL",
            Address::default(),
            Address::default(),
            100000,
            Bytes::default(),
        );
        let child = CallFrame::new(
            "STATICCALL",
            Address::default(),
            Address::default(),
            50000,
            Bytes::default(),
        );
        parent.calls.push(child);

        let json = serde_json::to_string(&parent).unwrap();
        assert!(json.contains("STATICCALL"));
    }

    #[test]
    fn test_decode_revert_reason_valid() {
        // Error("Insufficient balance")
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0]; // selector
        data.extend_from_slice(&[0u8; 32]); // offset = 32
        data[35] = 0x20;
        let msg = b"Insufficient balance";
        let mut len_bytes = [0u8; 32];
        len_bytes[31] = msg.len() as u8;
        data.extend_from_slice(&len_bytes); // length
        data.extend_from_slice(msg); // data

        let reason = decode_revert_reason(&data);
        assert_eq!(reason, Some("Insufficient balance".to_string()));
    }

    #[test]
    fn test_decode_revert_reason_too_short() {
        assert_eq!(decode_revert_reason(&[0x08, 0xc3, 0x79, 0xa0]), None);
    }

    #[test]
    fn test_decode_revert_reason_wrong_selector() {
        let data = vec![0xFF; 68];
        assert_eq!(decode_revert_reason(&data), None);
    }

    #[test]
    fn test_empty_calls_not_serialized() {
        let frame = CallFrame::new(
            "CALL",
            Address::default(),
            Address::default(),
            21000,
            Bytes::default(),
        );
        let json = serde_json::to_string(&frame).unwrap();
        assert!(!json.contains("calls"));
    }
}
