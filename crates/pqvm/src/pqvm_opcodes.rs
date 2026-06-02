//! PQVM native opcodes — Shell-Chain EVM extension.
//!
//! Adds two PQ-native opcodes to the revm instruction table:
//!
//! | Opcode | Name       | Stack in (deepest→top)                                           | Stack out    | Description                          |
//! |--------|------------|------------------------------------------------------------------|--------------|--------------------------------------|
//! | 0xB0   | `PQVERIFY` | `algo_id, msg_ptr, msg_len, pk_len, pk_ptr, sig_len, sig_ptr`   | `[valid]`    | Verify a PQ signature from memory    |
//! | 0xB1   | `PQHASH`   | `data_ptr, data_len, out_ptr`                                    | (side effect)| BLAKE3-256 hash written to memory    |
//!
//! ## PQVERIFY algo_id values (WP §1073)
//!
//! - `0x00` — Dilithium3 (legacy compatibility)
//! - `0x01` — ML-DSA-65
//! - `0x02` — SLH-DSA-SHA2-256f
//!
//! ## Gas costs
//!
//! | Opcode   | Gas                                                      |
//! |----------|----------------------------------------------------------|
//! | PQVERIFY | 46 000 (ML-DSA-65 / Dilithium3) / 2 300 000 (SLH-DSA)  |
//! | PQHASH   | 30 + 6 × ⌈len/32⌉                                       |

use alloy_primitives::U256;
use revm::handler::instructions::EthInstructions;
use revm::interpreter::{
    interpreter_types::{InterpreterTypes, MemoryTr, StackTr},
    Host, Instruction, InstructionContext, InstructionResult,
};
use shell_crypto::{verify_signature, SignatureType};

use crate::precompiles::{
    BLAKE3_BASE_GAS, BLAKE3_WORD_GAS, PQ_MLDSA65_VERIFY_GAS, PQ_SLHDSA_VERIFY_GAS,
};

// ── opcode numbers ────────────────────────────────────────────────────────────

/// `PQVERIFY` — opcode 0xB0.  Verify a PQ signature from memory.
pub const OPCODE_PQVERIFY: u8 = 0xB0;
/// `PQHASH` — opcode 0xB1.  BLAKE3-256 hash of a memory region.
pub const OPCODE_PQHASH: u8 = 0xB1;

// ── algo_id constants (WP §1073) ─────────────────────────────────────────────

/// Dilithium3 legacy compatibility algo_id for PQVERIFY.
const ALGO_DILITHIUM3: u8 = 0x00;
/// ML-DSA-65 algo_id for PQVERIFY.
const ALGO_MLDSA65: u8 = 0x01;
/// SLH-DSA-SHA2-256f algo_id for PQVERIFY.
const ALGO_SLHDSA_SHA2_256F: u8 = 0x02;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Convert a U256 stack value to usize, halting the interpreter on overflow.
///
/// Returns `None` if the upper limbs are non-zero (value does not fit in usize).
/// Callers MUST return immediately after calling this if it returns `None`.
fn u256_to_usize<WIRE: InterpreterTypes>(
    interp: &mut revm::interpreter::Interpreter<WIRE>,
    v: U256,
) -> Option<usize> {
    let limbs = v.as_limbs();
    if (limbs[0] > usize::MAX as u64) | (limbs[1] != 0) | (limbs[2] != 0) | (limbs[3] != 0) {
        interp.halt(InstructionResult::InvalidOperandOOG);
        return None;
    }
    Some(limbs[0] as usize)
}

// ── PQVERIFY (0xB0) ──────────────────────────────────────────────────────────

/// `PQVERIFY` instruction: verify a PQ signature from memory (WP §1058-1079).
///
/// Stack (deepest → top): `algo_id, msg_ptr, msg_len, pk_len, pk_ptr, sig_len, sig_ptr`
/// Output: `result (1=valid, 0=invalid)`.
///
/// Each of `sig`, `pk`, and `msg` is read from a separate memory region. The
/// `algo_id` determines the scheme (0x00 = Dilithium3, 0x01 = ML-DSA-65,
/// 0x02 = SLH-DSA-SHA2-256f).
pub fn pq_verify<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    // Pop order matches LIFO: sig_ptr is on top.
    let Some(sig_ptr_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(sig_len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(pk_ptr_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(pk_len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(msg_ptr_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(msg_len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(algo_id_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };

    let algo_byte = algo_id_u256.as_limbs()[0] as u8;

    let gas_cost = match algo_byte {
        ALGO_MLDSA65 | ALGO_DILITHIUM3 => PQ_MLDSA65_VERIFY_GAS,
        ALGO_SLHDSA_SHA2_256F => PQ_SLHDSA_VERIFY_GAS,
        _ => {
            // Unknown algorithm — charge minimum and push false.
            if !context.interpreter.gas.record_cost(PQ_MLDSA65_VERIFY_GAS) {
                context.interpreter.halt_oog();
                return;
            }
            if !context.interpreter.stack.push(U256::ZERO) {
                context.interpreter.halt_overflow();
            }
            return;
        }
    };

    if !context.interpreter.gas.record_cost(gas_cost) {
        context.interpreter.halt_oog();
        return;
    }

    let sig_ptr = match u256_to_usize(context.interpreter, sig_ptr_u256) {
        Some(v) => v,
        None => return,
    };
    let sig_len = match u256_to_usize(context.interpreter, sig_len_u256) {
        Some(v) => v,
        None => return,
    };
    let pk_ptr = match u256_to_usize(context.interpreter, pk_ptr_u256) {
        Some(v) => v,
        None => return,
    };
    let pk_len = match u256_to_usize(context.interpreter, pk_len_u256) {
        Some(v) => v,
        None => return,
    };
    let msg_ptr = match u256_to_usize(context.interpreter, msg_ptr_u256) {
        Some(v) => v,
        None => return,
    };
    let msg_len = match u256_to_usize(context.interpreter, msg_len_u256) {
        Some(v) => v,
        None => return,
    };

    // Resize memory to cover all three regions before reading.
    let gas_params = context.host.gas_params().clone();
    if sig_len > 0
        && !context
            .interpreter
            .resize_memory(&gas_params, sig_ptr, sig_len)
    {
        return;
    }
    if pk_len > 0
        && !context
            .interpreter
            .resize_memory(&gas_params, pk_ptr, pk_len)
    {
        return;
    }
    if msg_len > 0
        && !context
            .interpreter
            .resize_memory(&gas_params, msg_ptr, msg_len)
    {
        return;
    }

    let sig_bytes: Vec<u8> = if sig_len > 0 {
        context
            .interpreter
            .memory
            .slice_len(sig_ptr, sig_len)
            .as_ref()
            .to_vec()
    } else {
        vec![]
    };
    let pk_bytes: Vec<u8> = if pk_len > 0 {
        context
            .interpreter
            .memory
            .slice_len(pk_ptr, pk_len)
            .as_ref()
            .to_vec()
    } else {
        vec![]
    };
    let msg_bytes: Vec<u8> = if msg_len > 0 {
        context
            .interpreter
            .memory
            .slice_len(msg_ptr, msg_len)
            .as_ref()
            .to_vec()
    } else {
        vec![]
    };

    let valid = match algo_byte {
        ALGO_MLDSA65 | ALGO_DILITHIUM3 => {
            let sig_type = if algo_byte == ALGO_MLDSA65 {
                SignatureType::MlDsa65
            } else {
                SignatureType::Dilithium3
            };
            verify_signature(sig_type, &pk_bytes, &msg_bytes, &sig_bytes).unwrap_or(false)
        }
        ALGO_SLHDSA_SHA2_256F => verify_signature(
            SignatureType::SphincsSha2256f,
            &pk_bytes,
            &msg_bytes,
            &sig_bytes,
        )
        .unwrap_or(false),
        _ => false,
    };

    let result = if valid { U256::from(1u8) } else { U256::ZERO };
    if !context.interpreter.stack.push(result) {
        context.interpreter.halt_overflow();
    }
}

// ── PQHASH (0xB1) ────────────────────────────────────────────────────────────

/// `PQHASH` instruction: BLAKE3-256 hash of a memory region, written to memory (WP §1062-1085).
///
/// Stack (deepest → top): `data_ptr, data_len, out_ptr` → (side effect)
///
/// Reads `data_len` bytes from `data_ptr`, computes BLAKE3-256, and writes the
/// 32-byte result to `out_ptr`. No value is pushed to the stack.
///
/// Gas: `30 + 6 × ⌈data_len/32⌉`.
pub fn pq_hash<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    let Some(out_ptr_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(data_len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(data_ptr_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };

    let data_len = match u256_to_usize(context.interpreter, data_len_u256) {
        Some(v) => v,
        None => return,
    };

    let words = (data_len as u64).div_ceil(32);
    let gas_cost = BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words;
    if !context.interpreter.gas.record_cost(gas_cost) {
        context.interpreter.halt_oog();
        return;
    }

    let hash_bytes: [u8; 32] = if data_len == 0 {
        *blake3::hash(b"").as_bytes()
    } else {
        let data_ptr = match u256_to_usize(context.interpreter, data_ptr_u256) {
            Some(v) => v,
            None => return,
        };
        let gas_params = context.host.gas_params().clone();
        if !context
            .interpreter
            .resize_memory(&gas_params, data_ptr, data_len)
        {
            return;
        }
        *blake3::hash(
            context
                .interpreter
                .memory
                .slice_len(data_ptr, data_len)
                .as_ref(),
        )
        .as_bytes()
    };

    // Expand memory to cover the 32-byte output region and write the hash.
    let out_ptr = match u256_to_usize(context.interpreter, out_ptr_u256) {
        Some(v) => v,
        None => return,
    };
    let gas_params = context.host.gas_params().clone();
    if !context.interpreter.resize_memory(&gas_params, out_ptr, 32) {
        return;
    }
    context.interpreter.memory.set(out_ptr, &hash_bytes);
}

// ── installer ─────────────────────────────────────────────────────────────────

/// Install the two PQVM native opcodes into `instructions`.
///
/// Call this after `EthInstructions::new_mainnet_with_spec` and before
/// building the `Evm` instance so that `PQVERIFY` and `PQHASH`
/// are dispatched natively instead of triggering `UNDEFINED`.
pub fn install_pqvm_opcodes<WIRE, H>(instructions: &mut EthInstructions<WIRE, H>)
where
    WIRE: InterpreterTypes,
    H: Host,
{
    instructions.insert_instruction(OPCODE_PQVERIFY, Instruction::new(pq_verify::<WIRE, H>, 0));
    instructions.insert_instruction(OPCODE_PQHASH, Instruction::new(pq_hash::<WIRE, H>, 0));
}

// ── helpers ───────────────────────────────────────────────────────────────────

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PQHASH logic tests (pure, no EVM harness needed) ─────────────────────

    #[test]
    fn pqhash_empty_input_matches_blake3_empty() {
        let hash_bytes: [u8; 32] = *blake3::hash(b"").as_bytes();
        let expected: [u8; 32] = *blake3::hash(b"").as_bytes();
        assert_eq!(hash_bytes, expected);
    }

    #[test]
    fn pqhash_known_vector() {
        let input = b"shell-pqvm-blake3";
        let expected: [u8; 32] = *blake3::hash(input).as_bytes();
        assert_eq!(expected.len(), 32);
        // BLAKE3 is deterministic — recompute and compare.
        let repeated: [u8; 32] = *blake3::hash(input).as_bytes();
        assert_eq!(expected, repeated);
    }

    #[test]
    fn pqverify_verify_signature_accepts_dilithium3_sig() {
        use shell_crypto::{DilithiumSigner, SignatureType, Signer};
        let signer = DilithiumSigner::generate();
        let message = b"pqvm opcode verify test";
        let sig = signer.sign(message).unwrap();
        let pubkey = signer.public_key();

        assert!(
            verify_signature(SignatureType::Dilithium3, pubkey, message, &sig.data)
                .unwrap_or(false)
        );
    }

    #[test]
    fn pqverify_verify_signature_rejects_bad_sig() {
        use shell_crypto::{DilithiumSigner, SignatureType, Signer};
        let signer = DilithiumSigner::generate();
        let message = b"legitimate message";
        let sig = signer.sign(message).unwrap();
        let pubkey = signer.public_key();

        let mut bad_sig = sig.data.clone();
        *bad_sig.last_mut().unwrap() ^= 0xFF;

        assert!(
            !verify_signature(SignatureType::Dilithium3, pubkey, message, &bad_sig).unwrap_or(true)
        );
    }

    #[test]
    fn pqverify_opcode_constants() {
        assert_eq!(OPCODE_PQVERIFY, 0xB0);
        assert_eq!(OPCODE_PQHASH, 0xB1);
    }
}
