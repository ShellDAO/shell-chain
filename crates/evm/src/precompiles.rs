//! Shell-chain custom precompiles.
//!
//! Wraps the standard Ethereum precompiles and adds:
//! - **0x0100** (`PQ_DILITHIUM_VERIFY`): Dilithium3 signature verification
//! - **0x01** (`ecrecover`): DISABLED — returns empty (forces PQ migration)
//!
//! # PQ_DILITHIUM_VERIFY Input Format
//!
//! Simple length-prefixed binary (no ABI encoding overhead):
//! ```text
//! [4 bytes: pubkey_len (BE u32)] [pubkey bytes]
//! [4 bytes: msg_len (BE u32)]    [message bytes]
//! [remaining bytes]              [signature bytes]
//! ```
//!
//! # Output
//!
//! 32 bytes: `0x..01` (valid) or `0x..00` (invalid/error).

use alloy_primitives::{address, Address, Bytes};
use interpreter::{CallInput, CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::context::{Cfg, LocalContextTr};
use revm::context_interface::ContextTr;
use revm::handler::PrecompileProvider;
use revm::interpreter;
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::hardfork::SpecId;
use shell_crypto::{DilithiumVerifier, PQSignature, SignatureType, Verifier};
use std::boxed::Box;

/// Address of the ecrecover precompile (DISABLED in shell-chain).
const ECRECOVER_ADDR: Address = address!("0x0000000000000000000000000000000000000001");

/// Address of the PQ Dilithium3 verify precompile.
const PQ_DILITHIUM_VERIFY_ADDR: Address = address!("0x0000000000000000000000000000000000000100");

/// Gas cost for PQ Dilithium3 signature verification.
pub const PQ_DILITHIUM_VERIFY_GAS: u64 = 10_000;

/// Shell-chain precompile provider.
///
/// Wraps standard Ethereum precompiles and overrides:
/// - ecrecover (0x01): returns empty bytes (disabled)
/// - 0x0100: Dilithium3 signature verification
#[derive(Debug, Clone)]
pub struct ShellPrecompiles {
    inner: &'static Precompiles,
    spec: SpecId,
}

impl ShellPrecompiles {
    pub fn new(spec: SpecId) -> Self {
        Self {
            inner: Precompiles::new(PrecompileSpecId::from_spec_id(spec)),
            spec,
        }
    }

    /// Check if the address is a precompile (inherent method for non-generic contexts).
    pub fn is_precompile(&self, address: &Address) -> bool {
        *address == PQ_DILITHIUM_VERIFY_ADDR
            || *address == ECRECOVER_ADDR
            || self.inner.contains(address)
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for ShellPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec: SpecId = spec.into();
        if spec == self.spec {
            return false;
        }
        self.inner = Precompiles::new(PrecompileSpecId::from_spec_id(spec));
        self.spec = spec;
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        let target = &inputs.bytecode_address;

        // Override: ecrecover disabled
        if *target == ECRECOVER_ADDR {
            return Ok(Some(InterpreterResult {
                result: InstructionResult::Return,
                gas: Gas::new(inputs.gas_limit),
                output: Bytes::new(), // empty = disabled
            }));
        }

        // Override: PQ Dilithium3 verify
        if *target == PQ_DILITHIUM_VERIFY_ADDR {
            return Ok(Some(run_pq_verify(inputs, context)));
        }

        // Delegate to standard precompiles
        let Some(precompile) = self.inner.get(target) else {
            return Ok(None);
        };

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        };

        let input_bytes = match &inputs.input {
            CallInput::SharedBuffer(range) => {
                if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                    slice.as_ref().to_vec()
                } else {
                    vec![]
                }
            }
            CallInput::Bytes(bytes) => bytes.0.to_vec(),
        };

        match precompile.execute(&input_bytes, inputs.gas_limit) {
            Ok(output) => {
                result.gas.record_refund(output.gas_refunded);
                let underflow = result.gas.record_cost(output.gas_used);
                assert!(underflow, "Gas underflow is not possible");
                result.result = if output.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                };
                result.output = output.bytes;
            }
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
            }
        }
        Ok(Some(result))
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let standard = self.inner.addresses().cloned().collect::<Vec<_>>();
        Box::new(
            standard
                .into_iter()
                .chain(std::iter::once(PQ_DILITHIUM_VERIFY_ADDR)),
        )
    }

    fn contains(&self, address: &Address) -> bool {
        *address == PQ_DILITHIUM_VERIFY_ADDR
            || *address == ECRECOVER_ADDR
            || self.inner.contains(address)
    }
}

// ── PQ Dilithium3 verify implementation ───────────────────────

/// Execute the PQ_DILITHIUM_VERIFY precompile.
///
/// Input format: `[4:pubkey_len][pubkey][4:msg_len][msg][signature]`
/// Output: 32 bytes — 1 for valid, 0 for invalid.
fn run_pq_verify<CTX: ContextTr>(inputs: &CallInputs, context: &mut CTX) -> InterpreterResult {
    let mut result = InterpreterResult {
        result: InstructionResult::Return,
        gas: Gas::new(inputs.gas_limit),
        output: encode_bool(false),
    };

    // Charge gas
    if !result.gas.record_cost(PQ_DILITHIUM_VERIFY_GAS) {
        result.result = InstructionResult::PrecompileOOG;
        return result;
    }

    let input_bytes: Vec<u8> = match &inputs.input {
        CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                slice.as_ref().to_vec()
            } else {
                return result;
            }
        }
        CallInput::Bytes(bytes) => bytes.0.to_vec(),
    };

    // Parse input
    let parsed = match parse_pq_verify_input(&input_bytes) {
        Some(p) => p,
        None => return result, // malformed input → return false
    };

    // Verify signature
    let verifier = DilithiumVerifier;
    let sig = PQSignature::new(SignatureType::Dilithium3, parsed.signature.to_vec());
    match verifier.verify(parsed.pubkey, parsed.message, &sig) {
        Ok(true) => {
            result.output = encode_bool(true);
        }
        _ => {
            // Invalid signature or verification error → return false
        }
    }

    result
}

struct PqVerifyInput<'a> {
    pubkey: &'a [u8],
    message: &'a [u8],
    signature: &'a [u8],
}

/// Parse length-prefixed PQ verify input.
fn parse_pq_verify_input(data: &[u8]) -> Option<PqVerifyInput<'_>> {
    if data.len() < 8 {
        return None;
    }

    // Read pubkey
    let pk_len = u32::from_be_bytes(
        data.get(0..4)
            .unwrap_or_else(|| unreachable!("data.len() >= 8 checked above"))
            .try_into()
            .ok()?,
    ) as usize;
    let pk_end = 4usize.saturating_add(pk_len);
    if data.len() < pk_end.saturating_add(4) {
        return None;
    }
    let pubkey = data.get(4..pk_end)?;

    // Read message
    let msg_len = u32::from_be_bytes(
        data.get(pk_end..pk_end.saturating_add(4))
            .unwrap_or_else(|| unreachable!("data.len() >= pk_end + 4 checked above"))
            .try_into()
            .ok()?,
    ) as usize;
    let msg_end = pk_end.saturating_add(4).saturating_add(msg_len);
    if data.len() < msg_end {
        return None;
    }
    let message = data.get(pk_end.saturating_add(4)..msg_end)?;

    // Remaining = signature
    let signature = data.get(msg_end..)?;
    if signature.is_empty() {
        return None;
    }

    Some(PqVerifyInput {
        pubkey,
        message,
        signature,
    })
}

/// Encode a boolean as 32-byte ABI output.
fn encode_bool(value: bool) -> Bytes {
    let mut out = [0u8; 32];
    if value {
        out[31] = 1;
    }
    Bytes::from(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{DilithiumSigner, Signer};

    #[test]
    fn parse_valid_input() {
        let pubkey = vec![0xAA; 1952];
        let message = b"hello world";
        let signature = vec![0xBB; 3293];

        let mut input = Vec::new();
        input.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
        input.extend_from_slice(&pubkey);
        input.extend_from_slice(&(message.len() as u32).to_be_bytes());
        input.extend_from_slice(message);
        input.extend_from_slice(&signature);

        let parsed = parse_pq_verify_input(&input).unwrap();
        assert_eq!(parsed.pubkey.len(), 1952);
        assert_eq!(parsed.message, b"hello world");
        assert_eq!(parsed.signature.len(), 3293);
    }

    #[test]
    fn parse_empty_input_returns_none() {
        assert!(parse_pq_verify_input(&[]).is_none());
    }

    #[test]
    fn parse_truncated_input_returns_none() {
        let mut input = Vec::new();
        input.extend_from_slice(&(100u32).to_be_bytes());
        // Missing pubkey data
        assert!(parse_pq_verify_input(&input).is_none());
    }

    #[test]
    fn encode_bool_true() {
        let out = encode_bool(true);
        assert_eq!(out.len(), 32);
        assert_eq!(out[31], 1);
        assert!(out[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_bool_false() {
        let out = encode_bool(false);
        assert_eq!(out.len(), 32);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn pq_verify_real_signature() {
        let signer = DilithiumSigner::generate();
        let message = b"test message for precompile";
        let sig = signer.sign(message).unwrap();

        let mut input = Vec::new();
        let pk = signer.public_key();
        input.extend_from_slice(&(pk.len() as u32).to_be_bytes());
        input.extend_from_slice(pk);
        input.extend_from_slice(&(message.len() as u32).to_be_bytes());
        input.extend_from_slice(message);
        input.extend_from_slice(&sig.data); // field name is `data`

        let parsed = parse_pq_verify_input(&input).unwrap();
        let verifier = DilithiumVerifier;
        let pq_sig = PQSignature::new(SignatureType::Dilithium3, parsed.signature.to_vec());
        let valid = verifier
            .verify(parsed.pubkey, parsed.message, &pq_sig)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn pq_verify_bad_signature() {
        let signer = DilithiumSigner::generate();
        let message = b"test message";

        let mut input = Vec::new();
        let pk = signer.public_key();
        input.extend_from_slice(&(pk.len() as u32).to_be_bytes());
        input.extend_from_slice(pk);
        input.extend_from_slice(&(message.len() as u32).to_be_bytes());
        input.extend_from_slice(message);
        input.extend_from_slice(&[0xDE; 100]); // bad signature

        let parsed = parse_pq_verify_input(&input).unwrap();
        let verifier = DilithiumVerifier;
        let pq_sig = PQSignature::new(SignatureType::Dilithium3, parsed.signature.to_vec());
        let result = verifier.verify(parsed.pubkey, parsed.message, &pq_sig);
        // Should either return Ok(false) or Err
        assert!(!result.unwrap_or(false));
    }

    #[test]
    fn ecrecover_address_is_0x01() {
        assert_eq!(
            ECRECOVER_ADDR,
            address!("0x0000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn pq_verify_address_is_0x0100() {
        assert_eq!(
            PQ_DILITHIUM_VERIFY_ADDR,
            address!("0x0000000000000000000000000000000000000100")
        );
    }

    #[test]
    fn shell_precompiles_contains_custom() {
        let sp = ShellPrecompiles::new(SpecId::CANCUN);
        assert!(sp.is_precompile(&ECRECOVER_ADDR));
        assert!(sp.is_precompile(&PQ_DILITHIUM_VERIFY_ADDR));
    }
}
