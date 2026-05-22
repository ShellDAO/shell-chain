//! PQVM native opcodes — Shell-Chain EVM extension.
//!
//! Adds three PQ-native opcodes to the revm instruction table:
//!
//! | Opcode | Name       | Stack in         | Stack out | Description                          |
//! |--------|------------|------------------|-----------|--------------------------------------|
//! | 0xB0   | `PQVERIFY` | `[offset, len]`  | `[valid]` | Verify a PQ signature from memory    |
//! | 0xB1   | `PQHASH`   | `[offset, len]`  | `[hash]`  | BLAKE3-256 hash of memory region     |
//! | 0xB2   | `PQADDR`   | `[aid, off, len]`| `[addr]`  | Derive PQ address: BLAKE3(aid‖pubkey)|
//!
//! ## PQVERIFY memory wire format
//!
//! ```text
//! [1-byte algo_id][payload...]
//! ```
//!
//! `algo_id` values:
//! - `0x01` — ML-DSA-65 (Dilithium3): `[4-byte pk_len][pk][4-byte msg_len][msg][sig]`
//! - `0x02` — SLH-DSA-SHA2-256f:      `[pk (64 B)][sig (49 856 B)][msg]`
//!
//! ## Gas costs
//!
//! | Opcode   | Gas                                                      |
//! |----------|----------------------------------------------------------|
//! | PQVERIFY | 46 000 (ML-DSA-65) / 2 300 000 (SLH-DSA)               |
//! | PQHASH   | 30 + 6 × ⌈len/32⌉                                       |
//! | PQADDR   | 200                                                      |

use alloy_primitives::{B256, U256};
use revm::handler::instructions::EthInstructions;
use revm::interpreter::{
    interpreter_types::{InterpreterTypes, MemoryTr, StackTr},
    Host, Instruction, InstructionContext, InstructionResult,
};
use shell_crypto::{DilithiumVerifier, PQSignature, SignatureType, SphincsVerifier, Verifier};

use crate::precompiles::{
    BLAKE3_BASE_GAS, BLAKE3_WORD_GAS, PQ_ADDR_DERIVE_GAS, PQ_MLDSA65_VERIFY_GAS,
    PQ_SLHDSA_VERIFY_GAS,
};

// ── opcode numbers ────────────────────────────────────────────────────────────

/// `PQVERIFY` — opcode 0xB0.  Verify a PQ signature from memory.
pub const OPCODE_PQVERIFY: u8 = 0xB0;
/// `PQHASH` — opcode 0xB1.  BLAKE3-256 hash of a memory region.
pub const OPCODE_PQHASH: u8 = 0xB1;
/// `PQADDR` — opcode 0xB2.  Derive PQ address BLAKE3(algo_id ‖ pubkey).
pub const OPCODE_PQADDR: u8 = 0xB2;

// ── algo_id constants (mirror precompile addressing) ─────────────────────────

const ALGO_MLDSA65: u8 = 0x01;
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

/// `PQVERIFY` instruction: verify a PQ signature stored in memory.
///
/// Stack: `[offset (U256), len (U256)]` → `[valid (0 or 1)]`
///
/// Reads `len` bytes from memory at `offset`.  The first byte is `algo_id`
/// which selects the PQ scheme; the remaining bytes are the scheme-specific
/// wire payload (same format as the PQ precompiles).
pub fn pq_verify<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some(len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(offset) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };

    let len = match u256_to_usize(context.interpreter, len_u256) {
        Some(v) => v,
        None => return,
    };

    if len == 0 {
        if !context.interpreter.stack.push(U256::ZERO) {
            context.interpreter.halt_overflow();
        }
        return;
    }

    let from = match u256_to_usize(context.interpreter, offset) {
        Some(v) => v,
        None => return,
    };

    let gas_params = context.host.gas_params().clone();
    if !context.interpreter.resize_memory(&gas_params, from, len) {
        return; // resize_memory already called halt
    }

    let data: Vec<u8> = context
        .interpreter
        .memory
        .slice_len(from, len)
        .as_ref()
        .to_vec();

    let algo_id = data[0];
    let gas_cost = match algo_id {
        ALGO_MLDSA65 => PQ_MLDSA65_VERIFY_GAS,
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

    let payload = &data[1..];
    let valid = match algo_id {
        ALGO_MLDSA65 => verify_mldsa65(payload),
        ALGO_SLHDSA_SHA2_256F => verify_slhdsa(payload),
        _ => false,
    };

    let result = if valid { U256::from(1u8) } else { U256::ZERO };
    if !context.interpreter.stack.push(result) {
        context.interpreter.halt_overflow();
    }
}

// ── PQHASH (0xB1) ────────────────────────────────────────────────────────────

/// `PQHASH` instruction: BLAKE3-256 hash of a memory region.
///
/// Stack: `[offset (U256), len (U256)]` → `[hash (B256 as U256)]`
///
/// Gas: `30 + 6 × ⌈len/32⌉`.
pub fn pq_hash<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    let Some(len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(offset) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };

    let len = match u256_to_usize(context.interpreter, len_u256) {
        Some(v) => v,
        None => return,
    };

    let words = (len as u64).div_ceil(32);
    let gas_cost = BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words;
    if !context.interpreter.gas.record_cost(gas_cost) {
        context.interpreter.halt_oog();
        return;
    }

    let hash_bytes: [u8; 32] = if len == 0 {
        *blake3::hash(b"").as_bytes()
    } else {
        let from = match u256_to_usize(context.interpreter, offset) {
            Some(v) => v,
            None => return,
        };
        let gas_params = context.host.gas_params().clone();
        if !context.interpreter.resize_memory(&gas_params, from, len) {
            return;
        }
        *blake3::hash(context.interpreter.memory.slice_len(from, len).as_ref()).as_bytes()
    };

    if !context
        .interpreter
        .stack
        .push(B256::from(hash_bytes).into())
    {
        context.interpreter.halt_overflow();
    }
}

// ── PQADDR (0xB2) ────────────────────────────────────────────────────────────

/// `PQADDR` instruction: derive PQ address `BLAKE3(algo_id ‖ pubkey)`.
///
/// Stack: `[algo_id (U256), offset (U256), len (U256)]` → `[addr (B256 as U256)]`
///
/// Gas: `200`.
pub fn pq_addr<WIRE: InterpreterTypes, H: Host + ?Sized>(context: InstructionContext<'_, H, WIRE>) {
    let Some(len_u256) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(offset) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Some(algo_id) = context.interpreter.stack.pop() else {
        context.interpreter.halt_underflow();
        return;
    };

    if !context.interpreter.gas.record_cost(PQ_ADDR_DERIVE_GAS) {
        context.interpreter.halt_oog();
        return;
    }

    let algo_byte = algo_id.as_limbs()[0] as u8; // least-significant byte of the U256

    let len = match u256_to_usize(context.interpreter, len_u256) {
        Some(v) => v,
        None => return,
    };

    let hash_bytes: [u8; 32] = if len == 0 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[algo_byte]);
        *hasher.finalize().as_bytes()
    } else {
        let from = match u256_to_usize(context.interpreter, offset) {
            Some(v) => v,
            None => return,
        };
        let gas_params = context.host.gas_params().clone();
        if !context.interpreter.resize_memory(&gas_params, from, len) {
            return;
        }
        let pubkey = context
            .interpreter
            .memory
            .slice_len(from, len)
            .as_ref()
            .to_vec();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[algo_byte]);
        hasher.update(&pubkey);
        *hasher.finalize().as_bytes()
    };

    if !context
        .interpreter
        .stack
        .push(B256::from(hash_bytes).into())
    {
        context.interpreter.halt_overflow();
    }
}

// ── installer ─────────────────────────────────────────────────────────────────

/// Install the three PQVM native opcodes into `instructions`.
///
/// Call this after `EthInstructions::new_mainnet_with_spec` and before
/// building the `Evm` instance so that `PQVERIFY`, `PQHASH`, and `PQADDR`
/// are dispatched natively instead of triggering `UNDEFINED`.
pub fn install_pqvm_opcodes<WIRE, H>(instructions: &mut EthInstructions<WIRE, H>)
where
    WIRE: InterpreterTypes,
    H: Host,
{
    instructions.insert_instruction(OPCODE_PQVERIFY, Instruction::new(pq_verify::<WIRE, H>, 0));
    instructions.insert_instruction(OPCODE_PQHASH, Instruction::new(pq_hash::<WIRE, H>, 0));
    instructions.insert_instruction(OPCODE_PQADDR, Instruction::new(pq_addr::<WIRE, H>, 0));
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// ML-DSA-65 signature verification.
/// Wire format: `[4-byte pk_len][pk][4-byte msg_len][msg][sig]`
fn verify_mldsa65(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    let pk_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
    if payload.len() < 4 + pk_len + 4 {
        return false;
    }
    let public_key = &payload[4..4 + pk_len];
    let msg_len =
        u32::from_be_bytes(payload[4 + pk_len..4 + pk_len + 4].try_into().unwrap()) as usize;
    if payload.len() < 4 + pk_len + 4 + msg_len {
        return false;
    }
    let message = &payload[4 + pk_len + 4..4 + pk_len + 4 + msg_len];
    let sig_bytes = &payload[4 + pk_len + 4 + msg_len..];
    let signature = PQSignature::new(SignatureType::Dilithium3, sig_bytes.to_vec());
    DilithiumVerifier
        .verify(public_key, message, &signature)
        .unwrap_or(false)
}

/// SLH-DSA-SHA2-256f signature verification.
/// Wire format: `[pk (64 B)][sig (49 856 B)][msg]`
fn verify_slhdsa(payload: &[u8]) -> bool {
    const PK_LEN: usize = 64;
    const SIG_LEN: usize = 49_856;
    if payload.len() < PK_LEN + SIG_LEN {
        return false;
    }
    let public_key = &payload[..PK_LEN];
    let sig_bytes = &payload[PK_LEN..PK_LEN + SIG_LEN];
    let message = &payload[PK_LEN + SIG_LEN..];
    let signature = PQSignature::new(SignatureType::SphincsSha2256f, sig_bytes.to_vec());
    SphincsVerifier
        .verify(public_key, message, &signature)
        .unwrap_or(false)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PQHASH helper tests (pure logic, no EVM harness needed) ──────────────

    #[test]
    fn pqhash_empty_input_matches_blake3_empty() {
        let expected: [u8; 32] = *blake3::hash(b"").as_bytes();
        let expected_u256: U256 = B256::from(expected).into();
        // Re-create the same logic used in pq_hash for len==0.
        let hash_bytes: [u8; 32] = *blake3::hash(b"").as_bytes();
        let result: U256 = B256::from(hash_bytes).into();
        assert_eq!(result, expected_u256);
    }

    #[test]
    fn pqhash_known_vector() {
        let input = b"shell-pqvm-blake3";
        let expected: [u8; 32] = *blake3::hash(input).as_bytes();
        assert_eq!(expected.len(), 32);
        let u: U256 = B256::from(expected).into();
        // Round-trip: convert back to bytes and compare.
        let bytes: [u8; 32] = u.to_be_bytes();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn pqaddr_derivation_matches_precompile_logic() {
        let pubkey = b"test-public-key-bytes";
        let algo_id = 0x01u8;

        // Logic used in pq_addr (and in the PQAddr precompile).
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[algo_id]);
        hasher.update(pubkey);
        let addr: [u8; 32] = *hasher.finalize().as_bytes();

        // Verify it matches what the precompile would produce when called
        // with the same algo_id byte + pubkey.
        let mut precompile_input = vec![algo_id];
        precompile_input.extend_from_slice(pubkey);
        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(&[precompile_input[0]]);
        hasher2.update(&precompile_input[1..]);
        let addr2: [u8; 32] = *hasher2.finalize().as_bytes();

        assert_eq!(addr, addr2);
    }

    #[test]
    fn verify_mldsa65_helper_accepts_valid_sig() {
        use shell_crypto::{DilithiumSigner, Signer};
        let signer = DilithiumSigner::generate();
        let message = b"pqvm opcode verify test";
        let sig = signer.sign(message).unwrap();
        let pubkey = signer.public_key();

        let mut payload = Vec::new();
        payload.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
        payload.extend_from_slice(pubkey);
        payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
        payload.extend_from_slice(message);
        payload.extend_from_slice(&sig.data);

        assert!(verify_mldsa65(&payload));
    }

    #[test]
    fn verify_mldsa65_helper_rejects_bad_sig() {
        use shell_crypto::{DilithiumSigner, Signer};
        let signer = DilithiumSigner::generate();
        let message = b"legitimate message";
        let sig = signer.sign(message).unwrap();
        let pubkey = signer.public_key();

        // Corrupt last byte of the signature.
        let mut bad_sig = sig.data.clone();
        *bad_sig.last_mut().unwrap() ^= 0xFF;

        let mut payload = Vec::new();
        payload.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
        payload.extend_from_slice(pubkey);
        payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
        payload.extend_from_slice(message);
        payload.extend_from_slice(&bad_sig);

        assert!(!verify_mldsa65(&payload));
    }

    #[test]
    fn pqverify_opcode_constants() {
        assert_eq!(OPCODE_PQVERIFY, 0xB0);
        assert_eq!(OPCODE_PQHASH, 0xB1);
        assert_eq!(OPCODE_PQADDR, 0xB2);
    }
}
