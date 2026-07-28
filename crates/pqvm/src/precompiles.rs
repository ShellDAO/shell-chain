//! Shell-chain custom precompiles.
//!
//! Replaces the standard Ethereum precompile table with the Shell PQ suite:
//! - `0x0001`: ML-DSA-family verify (ML-DSA-65 primary, Dilithium3 legacy)
//! - `0x0002`: SLH-DSA-SHA2-256f verify
//! - `0x0003`: ML-DSA-65 batch verify
//! - `0x0004`: BLAKE3-256 hash
//! - `0x0005`: BLAKE3-512 hash
//! - `0x0006`: PQ address derive
//!
//! This keeps all classical Ethereum precompiles disabled, including
//! `ecrecover`, BN256, and BLAKE2f.

use alloy_primitives::{address, Address, Bytes};
use revm::context::{Cfg, LocalContextTr};
use revm::context_interface::ContextTr;
use revm::handler::PrecompileProvider;
use revm::interpreter::{CallInput, CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::primitives::hardfork::SpecId;
use shell_crypto::{verify_signature, SignatureType};
use shell_primitives::Address as ShellAddress;
use std::boxed::Box;

pub const PQ_MLDSA65_VERIFY_ADDR: Address = address!("0x0000000000000000000000000000000000000001");
pub const PQ_SLHDSA_SHA2_256F_VERIFY_ADDR: Address =
    address!("0x0000000000000000000000000000000000000002");
pub const PQ_MLDSA65_BATCH_VERIFY_ADDR: Address =
    address!("0x0000000000000000000000000000000000000003");
pub const PQ_BLAKE3_256_ADDR: Address = address!("0x0000000000000000000000000000000000000004");
pub const PQ_BLAKE3_512_ADDR: Address = address!("0x0000000000000000000000000000000000000005");
pub const PQ_ADDRESS_DERIVE_ADDR: Address = address!("0x0000000000000000000000000000000000000006");

const PQ_PRECOMPILE_ADDRS: [Address; 6] = [
    PQ_MLDSA65_VERIFY_ADDR,
    PQ_SLHDSA_SHA2_256F_VERIFY_ADDR,
    PQ_MLDSA65_BATCH_VERIFY_ADDR,
    PQ_BLAKE3_256_ADDR,
    PQ_BLAKE3_512_ADDR,
    PQ_ADDRESS_DERIVE_ADDR,
];

pub const PQ_MLDSA65_VERIFY_GAS: u64 = 46_000;
pub const PQ_SLHDSA_VERIFY_GAS: u64 = 2_300_000;
pub const PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG: u64 = 12_000;
/// C-1: Hard cap on batch size to prevent unbounded CPU work regardless of gas.
pub const MAX_BATCH_SIGNATURES: u32 = 256;
pub const BLAKE3_BASE_GAS: u64 = 30;
pub const BLAKE3_WORD_GAS: u64 = 6;
pub const PQ_ADDRESS_DERIVE_BASE_GAS: u64 = 200;
/// Legacy name for the PQ address derivation base gas.
pub const PQ_ADDRESS_DERIVE_GAS: u64 = PQ_ADDRESS_DERIVE_BASE_GAS;

const DILITHIUM3_SIGNATURE_BYTES: usize = 3309;
const SPHINCS_PUBLIC_KEY_BYTES: usize = 64;
const SPHINCS_SIGNATURE_BYTES: usize = 49_856;

#[derive(Debug, Clone)]
pub struct ShellPrecompiles {
    spec: SpecId,
}

impl ShellPrecompiles {
    pub fn new(spec: SpecId) -> Self {
        Self { spec }
    }

    pub fn is_precompile(&self, address: &Address) -> bool {
        is_pq_precompile(address)
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for ShellPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec: SpecId = spec.into();
        if spec == self.spec {
            return false;
        }
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

        Ok(None)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        Box::new(PQ_PRECOMPILE_ADDRS.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        is_pq_precompile(address)
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
    // Hold the shared-memory guard through execution so precompiles can read
    // calldata in place instead of cloning it into a temporary buffer.
    let shared_input;
    let input = match &inputs.input {
        CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                shared_input = slice;
                shared_input.as_ref()
            } else {
                &[]
            }
        }
        CallInput::Bytes(bytes) => bytes.as_ref(),
    };

    match *target {
        PQ_MLDSA65_VERIFY_ADDR => run_mldsa65_verify(inputs.gas_limit, input),
        PQ_SLHDSA_SHA2_256F_VERIFY_ADDR => run_slhdsa_sha2_256f_verify(inputs.gas_limit, input),
        PQ_MLDSA65_BATCH_VERIFY_ADDR => run_mldsa65_batch_verify(inputs.gas_limit, input),
        PQ_BLAKE3_256_ADDR => run_blake3_256(inputs.gas_limit, input),
        PQ_BLAKE3_512_ADDR => run_blake3_512(inputs.gas_limit, input),
        PQ_ADDRESS_DERIVE_ADDR => run_pq_address_derive(inputs.gas_limit, input),
        _ => InterpreterResult {
            result: InstructionResult::PrecompileError,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        },
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

    // C-1: Parse count from the header BEFORE any verification work.
    let Some(count_bytes) = input.get(..4) else {
        result.result = InstructionResult::PrecompileError;
        return result;
    };
    let count = u32::from_be_bytes(count_bytes.try_into().expect("slice length checked"));

    // Reject empty batches so the universal "all signatures valid" result
    // cannot authorize a call without presenting a signature.
    if count == 0 || count > MAX_BATCH_SIGNATURES {
        result.result = InstructionResult::PrecompileError;
        return result;
    }

    // C-1: Charge the full gas cost BEFORE entering the verification loop so
    // that a caller with gas_limit = 0 receives OOG without doing any work.
    let total_cost = PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG.saturating_mul(count as u64);
    if !charge_gas(&mut result, total_cost) {
        return result;
    }

    let (_, valid) = verify_mldsa65_batch(input);
    result.output = bool_output(valid);
    result
}

fn run_blake3_256(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let words = (input.len() as u64).div_ceil(32);
    let gas = BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words;
    if !charge_gas(&mut result, gas) {
        return result;
    }
    result.output = Bytes::copy_from_slice(blake3::hash(input).as_bytes());
    result
}

fn run_blake3_512(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let words = (input.len() as u64).div_ceil(32);
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

fn run_pq_address_derive(gas_limit: u64, input: &[u8]) -> InterpreterResult {
    let mut result = base_result(gas_limit);
    let pubkey_len = input.len().saturating_sub(1);
    if !charge_gas(&mut result, pq_address_derive_gas(pubkey_len)) {
        return result;
    }

    let Some((&algo_id, pubkey)) = input.split_first() else {
        result.result = InstructionResult::PrecompileError;
        return result;
    };
    let Some(address) = derive_pq_address(algo_id, pubkey) else {
        result.result = InstructionResult::PrecompileError;
        return result;
    };

    result.output = Bytes::copy_from_slice(&address);
    result
}

pub(crate) fn pq_address_derive_gas(pubkey_len: usize) -> u64 {
    let words = (pubkey_len as u64).div_ceil(32);
    PQ_ADDRESS_DERIVE_BASE_GAS.saturating_add(BLAKE3_WORD_GAS.saturating_mul(words))
}

pub(crate) fn derive_pq_address(algo_id: u8, pubkey: &[u8]) -> Option<[u8; 32]> {
    SignatureType::from_u8(algo_id)?;
    Some(*ShellAddress::from_public_key(pubkey, algo_id).as_bytes())
}

fn verify_mldsa65(input: &[u8]) -> bool {
    // Wire format (length-prefixed) — ABI-stable across upgrades:
    // [4-byte pubkey_len][pubkey][4-byte msg_len][msg][sig]
    // Algorithm dispatch is Dilithium3/ML-DSA-65 (binary-compatible); the
    // sig_type prefix convention is used only for new protocols, not here.
    if input.len() < 8 {
        return false;
    }
    let pk_len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    if input.len() < 4 + pk_len + 4 {
        return false;
    }
    let public_key = &input[4..4 + pk_len];
    let msg_len =
        u32::from_be_bytes(input[4 + pk_len..4 + pk_len + 4].try_into().unwrap()) as usize;
    if input.len() < 4 + pk_len + 4 + msg_len {
        return false;
    }
    let message = &input[4 + pk_len + 4..4 + pk_len + 4 + msg_len];
    let sig_bytes = &input[4 + pk_len + 4 + msg_len..];
    // Try ML-DSA-65 first (primary algorithm); fall back to Dilithium3 for
    // legacy wire-compatible signatures on the same wire shape.
    if verify_signature(SignatureType::MlDsa65, public_key, message, sig_bytes).unwrap_or(false) {
        return true;
    }
    verify_signature(SignatureType::Dilithium3, public_key, message, sig_bytes).unwrap_or(false)
}

fn verify_slhdsa_sha2_256f(input: &[u8]) -> bool {
    if input.len() < SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES {
        return false;
    }

    let public_key = &input[..SPHINCS_PUBLIC_KEY_BYTES];
    let signature =
        &input[SPHINCS_PUBLIC_KEY_BYTES..SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES];
    let message = &input[SPHINCS_PUBLIC_KEY_BYTES + SPHINCS_SIGNATURE_BYTES..];
    verify_signature(
        SignatureType::SphincsSha2256f,
        public_key,
        message,
        signature,
    )
    .unwrap_or(false)
}

fn verify_mldsa65_batch(input: &[u8]) -> (usize, bool) {
    // Batch wire format:
    // [4-byte count][item_0][item_1]...
    // Each item: [4-byte pubkey_len][pubkey][4-byte msg_len][msg][sig]
    let Some(count_bytes) = input.get(..4) else {
        return (0, false);
    };
    let count = u32::from_be_bytes(count_bytes.try_into().expect("slice length checked")) as usize;
    let mut cursor = 4usize;
    let mut valid = true;

    for _ in 0..count {
        // Read pubkey_len
        let Some(pk_len_bytes) = input.get(cursor..cursor + 4) else {
            return (count, false);
        };
        let pk_len = u32::from_be_bytes(pk_len_bytes.try_into().unwrap()) as usize;
        cursor += 4;
        // Read msg_len (after pubkey)
        let Some(msg_len_bytes) = input.get(cursor + pk_len..cursor + pk_len + 4) else {
            return (count, false);
        };
        let msg_len = u32::from_be_bytes(msg_len_bytes.try_into().unwrap()) as usize;
        // Full item = pk_len_prefix(4) + pubkey + msg_len_prefix(4) + msg + sig_to_end_of_item
        // sig ends at next item or end of input; we compute dynamically
        let sig_start = cursor + pk_len + 4 + msg_len;
        if sig_start > input.len() {
            return (count, false);
        }
        // Compute exact item boundaries before verifying so we pass only
        // [item_start..item_end] to verify_mldsa65 — not an open-ended slice
        // that would expose trailing bytes from subsequent items.
        let sig_len = DILITHIUM3_SIGNATURE_BYTES;
        let item_start = cursor - 4; // include pk_len prefix
        let item_end = cursor + pk_len + 4 + msg_len + sig_len;
        if item_end > input.len() {
            return (count, false);
        }
        // H-3: ML-DSA-65-first dispatch (ML-DSA-65 primary + Dilithium3 fallback)
        // matches the single-verify path so batch and single verification are consistent.
        let item = &input[item_start..item_end];
        valid &= verify_mldsa65(item);
        cursor = item_end;
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
        assert_eq!(
            PQ_MLDSA65_VERIFY_ADDR,
            address!("0x0000000000000000000000000000000000000001")
        );
        assert_eq!(
            PQ_SLHDSA_SHA2_256F_VERIFY_ADDR,
            address!("0x0000000000000000000000000000000000000002")
        );
        assert_eq!(
            PQ_MLDSA65_BATCH_VERIFY_ADDR,
            address!("0x0000000000000000000000000000000000000003")
        );
        assert_eq!(
            PQ_BLAKE3_256_ADDR,
            address!("0x0000000000000000000000000000000000000004")
        );
        assert_eq!(
            PQ_BLAKE3_512_ADDR,
            address!("0x0000000000000000000000000000000000000005")
        );
        assert_eq!(
            PQ_ADDRESS_DERIVE_ADDR,
            address!("0x0000000000000000000000000000000000000006")
        );
    }

    #[test]
    fn blake3_256_precompile_hashes_input() {
        let output = run_blake3_256(1_000, b"abc");
        assert_eq!(output.output.as_ref(), blake3::hash(b"abc").as_bytes());
    }

    #[test]
    fn pq_address_derive_precompile_derives_shell_address() {
        let pubkey = [0x11, 0x22, 0x33, 0x44];
        let mut input = vec![SignatureType::MlDsa65.as_u8()];
        input.extend_from_slice(&pubkey);

        let output = run_pq_address_derive(pq_address_derive_gas(pubkey.len()), &input);
        let expected = ShellAddress::from_public_key(&pubkey, SignatureType::MlDsa65.as_u8());
        assert_eq!(output.result, InstructionResult::Return);
        assert_eq!(output.output.as_ref(), expected.as_bytes());
    }

    #[test]
    fn pq_address_derive_precompile_rejects_unknown_algorithm() {
        let result = run_pq_address_derive(pq_address_derive_gas(1), &[0xFF, 0x11]);
        assert_eq!(result.result, InstructionResult::PrecompileError);
        assert!(result.output.is_empty());
    }

    #[test]
    fn pq_address_derive_precompile_charges_gas_before_parsing() {
        let result = run_pq_address_derive(PQ_ADDRESS_DERIVE_BASE_GAS - 1, &[0x01, 0x11]);
        assert_eq!(result.result, InstructionResult::PrecompileOOG);
    }

    #[test]
    fn pq_address_derive_precompile_charges_for_every_pubkey_word() {
        let input = vec![SignatureType::MlDsa65.as_u8(); 1 + 64];
        let required_gas = pq_address_derive_gas(64);

        let result = run_pq_address_derive(required_gas - 1, &input);
        assert_eq!(result.result, InstructionResult::PrecompileOOG);

        let result = run_pq_address_derive(required_gas, &input);
        assert_eq!(result.result, InstructionResult::Return);
    }

    #[test]
    fn pq_address_derive_gas_rounds_pubkey_length_to_words() {
        assert_eq!(pq_address_derive_gas(0), PQ_ADDRESS_DERIVE_BASE_GAS);
        assert_eq!(pq_address_derive_gas(1), PQ_ADDRESS_DERIVE_BASE_GAS + 6);
        assert_eq!(pq_address_derive_gas(32), PQ_ADDRESS_DERIVE_BASE_GAS + 6);
        assert_eq!(pq_address_derive_gas(33), PQ_ADDRESS_DERIVE_BASE_GAS + 12);
    }

    #[test]
    fn mldsa_verify_precompile_accepts_mldsa65_signature() {
        // Precompile 0x0001 uses the stable wire format:
        // [4-byte pubkey_len][pubkey][4-byte msg_len][msg][sig]
        // Algorithm is Dilithium3 (binary-compatible with ML-DSA-65 keys in use).
        let signer = DilithiumSigner::generate();
        let message = b"pqvm ml-dsa precompile";
        let sig = signer.sign(message).unwrap();
        let pubkey = signer.public_key();
        let mut input = Vec::new();
        input.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
        input.extend_from_slice(pubkey);
        input.extend_from_slice(&(message.len() as u32).to_be_bytes());
        input.extend_from_slice(message);
        input.extend_from_slice(&sig.data);

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
    fn shell_precompiles_contains_custom_suite() {
        let sp = ShellPrecompiles::new(SpecId::CANCUN);
        for address in PQ_PRECOMPILE_ADDRS {
            assert!(sp.is_precompile(&address));
        }
    }

    #[test]
    fn shell_precompiles_exclude_classic_ethereum_precompiles() {
        let sp = ShellPrecompiles::new(SpecId::CANCUN);
        for address in [
            address!("0x0000000000000000000000000000000000000007"),
            address!("0x0000000000000000000000000000000000000008"),
            address!("0x0000000000000000000000000000000000000009"),
        ] {
            assert!(!sp.is_precompile(&address));
        }
    }

    /// C-1: gas_limit=0 with count=100 must return OOG without panicking or
    /// performing any verification work (no reachable panic path inside the
    /// verification loop should be triggered).
    #[test]
    fn batch_verify_oog_before_verification_loop() {
        // Build a minimal input with count=100 and no actual signature data.
        // The function must return PrecompileOOG before entering the loop.
        let mut input = Vec::new();
        input.extend_from_slice(&100u32.to_be_bytes()); // count = 100
                                                        // No signature items — if the loop ran it would return false due to
                                                        // missing data, but it must never reach there with gas_limit=0.

        let result = run_mldsa65_batch_verify(0, &input);
        assert_eq!(
            result.result,
            InstructionResult::PrecompileOOG,
            "C-1: expected OOG with gas_limit=0"
        );
    }

    /// C-1: count > MAX_BATCH_SIGNATURES must be rejected immediately.
    #[test]
    fn batch_verify_rejects_oversized_count() {
        let mut input = Vec::new();
        input.extend_from_slice(&(MAX_BATCH_SIGNATURES + 1).to_be_bytes());
        let result = run_mldsa65_batch_verify(u64::MAX, &input);
        assert_eq!(
            result.result,
            InstructionResult::PrecompileError,
            "C-1: expected PrecompileError for count > MAX_BATCH_SIGNATURES"
        );
    }

    #[test]
    fn batch_verify_rejects_empty_batch() {
        let input = 0u32.to_be_bytes();
        let result = run_mldsa65_batch_verify(0, &input);

        assert_eq!(result.result, InstructionResult::PrecompileError);
        assert!(result.output.is_empty());
    }

    /// Helper: encode one batch item as [pk_len(4)][pubkey][msg_len(4)][msg][sig].
    fn encode_batch_item(pubkey: &[u8], message: &[u8], sig: &[u8]) -> Vec<u8> {
        let mut item = Vec::new();
        item.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
        item.extend_from_slice(pubkey);
        item.extend_from_slice(&(message.len() as u32).to_be_bytes());
        item.extend_from_slice(message);
        item.extend_from_slice(sig);
        item
    }

    /// Regression test: count=2 happy path — both items must verify correctly.
    /// Verifies the slicing fix: item_start..item_end rather than item_start..
    #[test]
    fn batch_verify_multi_item_happy_path() {
        let signer1 = DilithiumSigner::generate();
        let signer2 = DilithiumSigner::generate();

        let msg1 = b"batch item one";
        let msg2 = b"batch item two";
        let sig1 = signer1.sign(msg1).unwrap();
        let sig2 = signer2.sign(msg2).unwrap();

        let mut input = Vec::new();
        input.extend_from_slice(&2u32.to_be_bytes()); // count = 2
        input.extend(encode_batch_item(signer1.public_key(), msg1, &sig1.data));
        input.extend(encode_batch_item(signer2.public_key(), msg2, &sig2.data));

        let gas = PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG * 2 + 1_000;
        let result = run_mldsa65_batch_verify(gas, &input);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(
            result.output.as_ref(),
            &expected,
            "count=2 batch should verify successfully"
        );
    }

    /// Regression test: count=2 with one tampered signature must return false.
    #[test]
    fn batch_verify_multi_item_tampered_sig_fails() {
        let signer1 = DilithiumSigner::generate();
        let signer2 = DilithiumSigner::generate();

        let msg1 = b"batch item one";
        let msg2 = b"batch item two";
        let sig1 = signer1.sign(msg1).unwrap();
        let sig2 = signer2.sign(msg2).unwrap();

        // Tamper sig2: flip a byte in the middle.
        let mut sig2_tampered = sig2.data.clone();
        let mid = sig2_tampered.len() / 2;
        sig2_tampered[mid] ^= 0xFF;

        let mut input = Vec::new();
        input.extend_from_slice(&2u32.to_be_bytes()); // count = 2
        input.extend(encode_batch_item(signer1.public_key(), msg1, &sig1.data));
        input.extend(encode_batch_item(
            signer2.public_key(),
            msg2,
            &sig2_tampered,
        ));

        let gas = PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG * 2 + 1_000;
        let result = run_mldsa65_batch_verify(gas, &input);
        let expected_false = [0u8; 32];
        assert_eq!(
            result.output.as_ref(),
            &expected_false,
            "count=2 batch with tampered second sig must return false"
        );
    }
}
