//! Shell-chain custom precompiles.
//!
//! Overrides the standard Ethereum precompiles at `0x0001`–`0x0006` with the
//! Shell PQ suite:
//! - `0x0001`: ML-DSA-65 verify (implemented with the existing Dilithium3-compatible verifier)
//! - `0x0002`: SLH-DSA-SHA2-256f verify
//! - `0x0003`: ML-DSA-65 batch verify
//! - `0x0004`: BLAKE3-256 hash
//! - `0x0005`: BLAKE3-512 hash
//! - `0x0006`: PQAddr derive (`BLAKE3(algo_id || public_key)`)
//!
//! This keeps `ecrecover` disabled by overriding `0x0001` with the Shell PQ verifier.

use alloy_primitives::{address, Address, Bytes};
use revm::interpreter::{CallInput, CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::context::{Cfg, LocalContextTr};
use revm::context_interface::ContextTr;
use revm::handler::PrecompileProvider;
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::hardfork::SpecId;
use shell_crypto::{DilithiumVerifier, PQSignature, SignatureType, SphincsVerifier, Verifier};
use std::boxed::Box;

pub const PQ_MLDSA65_VERIFY_ADDR: Address =
    address!("0x0000000000000000000000000000000000000001");
pub const PQ_SLHDSA_SHA2_256F_VERIFY_ADDR: Address =
    address!("0x0000000000000000000000000000000000000002");
pub const PQ_MLDSA65_BATCH_VERIFY_ADDR: Address =
    address!("0x0000000000000000000000000000000000000003");
pub const PQ_BLAKE3_256_ADDR: Address =
    address!("0x0000000000000000000000000000000000000004");
pub const PQ_BLAKE3_512_ADDR: Address =
    address!("0x0000000000000000000000000000000000000005");
pub const PQ_ADDR_DERIVE_ADDR: Address =
    address!("0x0000000000000000000000000000000000000006");

const PQ_PRECOMPILE_ADDRS: [Address; 6] = [
    PQ_MLDSA65_VERIFY_ADDR,
    PQ_SLHDSA_SHA2_256F_VERIFY_ADDR,
    PQ_MLDSA65_BATCH_VERIFY_ADDR,
    PQ_BLAKE3_256_ADDR,
    PQ_BLAKE3_512_ADDR,
    PQ_ADDR_DERIVE_ADDR,
];

pub const PQ_MLDSA65_VERIFY_GAS: u64 = 46_000;
pub const PQ_SLHDSA_VERIFY_GAS: u64 = 2_300_000;
pub const PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG: u64 = 12_000;
pub const BLAKE3_BASE_GAS: u64 = 30;
pub const BLAKE3_WORD_GAS: u64 = 6;
pub const PQ_ADDR_DERIVE_GAS: u64 = 200;

const DILITHIUM3_PUBLIC_KEY_BYTES: usize = 1952;
const DILITHIUM3_SIGNATURE_BYTES: usize = 3309;
const SPHINCS_PUBLIC_KEY_BYTES: usize = 64;
const SPHINCS_SIGNATURE_BYTES: usize = 49_856;

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

    pub fn is_precompile(&self, address: &Address) -> bool {
        is_pq_precompile(address) || self.inner.contains(address)
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

        if is_pq_precompile(target) {
            return Ok(Some(run_pq_precompile(target, inputs, context)));
        }

        let Some(precompile) = self.inner.get(target) else {
            return Ok(None);
        };

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        };

        let input_bytes = read_input(inputs, context);

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
        let standard = self
            .inner
            .addresses()
            .cloned()
            .filter(|address| !is_pq_precompile(address))
            .collect::<Vec<_>>();
        Box::new(PQ_PRECOMPILE_ADDRS.into_iter().chain(standard))
    }

    fn contains(&self, address: &Address) -> bool {
        is_pq_precompile(address) || self.inner.contains(address)
    }
}

fn is_pq_precompile(address: &Address) -> bool {
    PQ_PRECOMPILE_ADDRS.contains(address)
}

fn run_pq_precompile<CTX: ContextTr>(
    target: &Address,
    inputs: &CallInputs,
    context: &mut CTX,
) -> InterpreterResult {
    let input = read_input(inputs, context);
    match *target {
        PQ_MLDSA65_VERIFY_ADDR => run_mldsa65_verify(inputs.gas_limit, &input),
        PQ_SLHDSA_SHA2_256F_VERIFY_ADDR => run_slhdsa_sha2_256f_verify(inputs.gas_limit, &input),
        PQ_MLDSA65_BATCH_VERIFY_ADDR => run_mldsa65_batch_verify(inputs.gas_limit, &input),
        PQ_BLAKE3_256_ADDR => run_blake3_256(inputs.gas_limit, &input),
        PQ_BLAKE3_512_ADDR => run_blake3_512(inputs.gas_limit, &input),
        PQ_ADDR_DERIVE_ADDR => run_pq_addr_derive(inputs.gas_limit, &input),
        _ => InterpreterResult {
            result: InstructionResult::PrecompileError,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        },
    }
}

fn read_input<CTX: ContextTr>(inputs: &CallInputs, context: &mut CTX) -> Vec<u8> {
    match &inputs.input {
        CallInput::SharedBuffer(range) => context
            .local()
            .shared_memory_buffer_slice(range.clone())
            .map(|slice| slice.as_ref().to_vec())
            .unwrap_or_default(),
        CallInput::Bytes(bytes) => bytes.0.to_vec(),
    }
}

fn base_result(gas_limit: u64) -> InterpreterResult {
    InterpreterResult {
        result: InstructionResult::Return,
        gas: Gas::new(gas_limit),
        output: Bytes::new(),
    }
}

fn charge_gas(result: &mut InterpreterResult, gas: u64) -> bool {
    if !result.gas.record_cost(gas) {
        result.result = InstructionResult::PrecompileOOG;
        return false;
    }
    true
}

fn run_mldsa65_verify(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    if !charge_gas(&mut result, PQ_MLDSA65_VERIFY_GAS) {
        return result;
    }
    result.output = bool_output(verify_mldsa65(input));
    result
}

fn run_slhdsa_sha2_256f_verify(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    if !charge_gas(&mut result, PQ_SLHDSA_VERIFY_GAS) {
        return result;
    }
    result.output = bool_output(verify_slhdsa_sha2_256f(input));
    result
}

fn run_mldsa65_batch_verify(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let (count, valid) = verify_mldsa65_batch(input);
    let gas = PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG.saturating_mul(count as u64);
    if !charge_gas(&mut result, gas) {
        return result;
    }
    result.output = bool_output(valid);
    result
}

fn run_blake3_256(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let words = (input.len() as u64 + 31) / 32;
    let gas = BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words;
    if !charge_gas(&mut result, gas) {
        return result;
    }
    result.output = Bytes::copy_from_slice(blake3::hash(input).as_bytes());
    result
}

fn run_blake3_512(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let words = (input.len() as u64 + 31) / 32;
    let gas = BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words;
    if !charge_gas(&mut result, gas) {
        return result;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    let mut output = [0u8; 64];
    hasher.finalize_xof().fill(&mut output);
    result.output = Bytes::copy_from_slice(&output);
    result
}

fn run_pq_addr_derive(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    if !charge_gas(&mut result, PQ_ADDR_DERIVE_GAS) {
        return result;
    }
    let Some((&algo_id, public_key)) = input.split_first() else {
        result.output = Bytes::copy_from_slice(&[0u8; 32]);
        return result;
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(&[algo_id]);
    hasher.update(public_key);
    result.output = Bytes::copy_from_slice(hasher.finalize().as_bytes());
    result
}

fn verify_mldsa65(input: &[u8]) -> bool {
    if input.len() < DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_SIGNATURE_BYTES {
        return false;
    }

    let public_key = &input[..DILITHIUM3_PUBLIC_KEY_BYTES];
    let signature = &input
        [DILITHIUM3_PUBLIC_KEY_BYTES..DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_SIGNATURE_BYTES];
    let message = &input[DILITHIUM3_PUBLIC_KEY_BYTES + DILITHIUM3_SIGNATURE_BYTES..];
    let signature = PQSignature::new(SignatureType::Dilithium3, signature.to_vec());
    DilithiumVerifier
        .verify(public_key, message, &signature)
        .unwrap_or(false)
}

fn verify_slhdsa_sha2_256f(input: &[u8]) -> bool {
    if input.len() < SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES {
        return false;
    }

    let public_key = &input[..SPHINCS_PUBLIC_KEY_BYTES];
    let signature = &input[SPHINCS_PUBLIC_KEY_BYTES..SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES];
    let message = &input[SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES..];
    let signature = PQSignature::new(SignatureType::SphincsSha2256f, signature.to_vec());
    SphincsVerifier
        .verify(public_key, message, &signature)
        .unwrap_or(false)
}

fn verify_mldsa65_batch(input: &[u8]) -> (usize, bool) {
    let Some(count_bytes) = input.get(..4) else {
        return (0, false);
    };
    let count = u32::from_be_bytes(count_bytes.try_into().expect("slice length checked")) as usize;
    let mut cursor = 4usize;
    let mut valid = true;

    for _ in 0..count {
        let Some(len_bytes) = input.get(cursor..cursor + 4) else {
            return (count, false);
        };
        cursor += 4;
        let msg_len = u32::from_be_bytes(len_bytes.try_into().expect("slice length checked")) as usize;
        let Some(end) = cursor
            .checked_add(DILITHIUM3_PUBLIC_KEY_BYTES)
            .and_then(|value| value.checked_add(DILITHIUM3_SIGNATURE_BYTES))
            .and_then(|value| value.checked_add(msg_len))
        else {
            return (count, false);
        };
        let Some(item) = input.get(cursor..end) else {
            return (count, false);
        };
        valid &= verify_mldsa65(item);
        cursor = end;
    }

    (count, valid && cursor == input.len())
}

fn bool_output(valid: bool) -> Bytes {
    let mut out = [0u8; 32];
    out[31] = u8::from(valid);
    Bytes::copy_from_slice(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_crypto::{DilithiumSigner, Signer, SphincsSigner};

    #[test]
    fn pq_suite_addresses_match_spec() {
        assert_eq!(PQ_MLDSA65_VERIFY_ADDR, address!("0x0000000000000000000000000000000000000001"));
        assert_eq!(PQ_SLHDSA_SHA2_256F_VERIFY_ADDR, address!("0x0000000000000000000000000000000000000002"));
        assert_eq!(PQ_MLDSA65_BATCH_VERIFY_ADDR, address!("0x0000000000000000000000000000000000000003"));
        assert_eq!(PQ_BLAKE3_256_ADDR, address!("0x0000000000000000000000000000000000000004"));
        assert_eq!(PQ_BLAKE3_512_ADDR, address!("0x0000000000000000000000000000000000000005"));
        assert_eq!(PQ_ADDR_DERIVE_ADDR, address!("0x0000000000000000000000000000000000000006"));
    }

    #[test]
    fn blake3_256_precompile_hashes_input() {
        let output = run_blake3_256(1_000, b"abc");
        assert_eq!(output.output.as_ref(), blake3::hash(b"abc").as_bytes());
    }

    #[test]
    fn mldsa_verify_precompile_accepts_valid_signature() {
        let signer = DilithiumSigner::generate();
        let message = b"pqvm ml-dsa precompile";
        let sig = signer.sign(message).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(signer.public_key());
        input.extend_from_slice(&sig.data);
        input.extend_from_slice(message);

        let output = run_mldsa65_verify(PQ_MLDSA65_VERIFY_GAS, &input);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(output.output.as_ref(), &expected);
    }

    #[test]
    fn slhdsa_verify_precompile_accepts_valid_signature() {
        let signer = SphincsSigner::generate();
        let message = b"pqvm slh-dsa precompile";
        let sig = signer.sign(message).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(signer.public_key());
        input.extend_from_slice(&sig.data);
        input.extend_from_slice(message);

        let output = run_slhdsa_sha2_256f_verify(PQ_SLHDSA_VERIFY_GAS, &input);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(output.output.as_ref(), &expected);
    }

    #[test]
    fn pq_addr_derive_precompile_outputs_32_bytes() {
        let mut input = vec![0x01];
        input.extend_from_slice(b"public-key");
        let output = run_pq_addr_derive(PQ_ADDR_DERIVE_GAS, &input);
        assert_eq!(output.output.len(), 32);
    }

    #[test]
    fn shell_precompiles_contains_custom_suite() {
        let sp = ShellPrecompiles::new(SpecId::CANCUN);
        for address in PQ_PRECOMPILE_ADDRS {
            assert!(sp.is_precompile(&address));
        }
    }
}
