//! Smart contract integration tests.
//!
//! Tests cover the full deploy→call pipeline using hand-assembled EVM bytecodes
//! (no external Solidity compiler required). Each test exercises a distinct aspect
//! of the PQVM execution environment.

mod common;

use alloy_primitives::{keccak256, U256};
use common::{abi_decode_u256, call_contract, deploy_runtime_contract, fund_account, setup};
use shell_crypto::{DilithiumSigner, SignatureType, Signer};
use shell_primitives::Address as ShellAddress;

// ── Bytecode builders ─────────────────────────────────────────────────────────

/// Minimal Counter contract runtime bytecode.
///
/// Dispatcher (top 4 bytes of calldata → selector):
///   - `increment()` → SLOAD slot 0, ADD 1, SSTORE, RETURN empty
///   - `get()`       → SLOAD slot 0, MSTORE, RETURN 32 bytes
///   - default       → REVERT
///
/// Offsets (computed by hand):
///   0x1F: increment() JUMPDEST
///   0x2F: get() JUMPDEST
fn counter_runtime() -> Vec<u8> {
    let incr_sel = &keccak256(b"increment()")[..4];
    let get_sel = &keccak256(b"get()")[..4];

    // Dispatcher: extract 4-byte selector from calldata
    let mut code = vec![
        0x60, 0x00, // PUSH1 0
        0x35, // CALLDATALOAD  → stack: [calldata[0:32]]
        0x60, 0xE0, // PUSH1 224
        0x1C, // SHR           → stack: [selector]
        // Check increment()
        0x80, // DUP1
        0x63, // PUSH4 ...
    ];
    code.extend_from_slice(incr_sel); // bytes 0x08..0x0B
    code.extend_from_slice(&[
        0x14, // EQ
        0x60, 0x1F, // PUSH1 0x1F
        0x57, // JUMPI
        // Check get()
        0x80, // DUP1
        0x63, // PUSH4 ...
    ]);
    code.extend_from_slice(get_sel); // bytes 0x12..0x15
    code.extend_from_slice(&[
        0x14, // EQ
        0x60, 0x2F, // PUSH1 0x2F
        0x57, // JUMPI
        // Default: revert
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xFD, // REVERT
        // ── increment() at offset 0x1F ──
        0x5B, // JUMPDEST
        0x50, // POP
        0x60, 0x00, // PUSH1 0        (slot)
        0x54, // SLOAD          → [value]
        0x60, 0x01, // PUSH1 1
        0x01, // ADD            → [value+1]
        0x60, 0x00, // PUSH1 0        (slot)
        0x55, // SSTORE
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xF3, // RETURN (empty)
        // ── get() at offset 0x2F ──
        0x5B, // JUMPDEST
        0x50, // POP
        0x60, 0x00, // PUSH1 0        (slot)
        0x54, // SLOAD          → [value]
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE         → mem[0:32] = value
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xF3, // RETURN mem[0:32]
    ]);

    // Verify the JUMPDEST offsets are correct at compile time in tests.
    // Dispatcher ends at offset 0x1E (REVERT), so JUMPDEST must be at 0x1F.
    debug_assert_eq!(
        code[0x1F], 0x5B,
        "increment() JUMPDEST must be at offset 0x1F; bytecode layout changed"
    );
    debug_assert_eq!(
        code[0x2F], 0x5B,
        "get() JUMPDEST must be at offset 0x2F; bytecode layout changed"
    );

    code
}

/// Passthrough contract: forwards all calldata to a given precompile and returns
/// the 32-byte output.
///
/// Stack shape for STATICCALL:
///   [gas, addr, argsOff, argsLen, retOff, retLen] (top → bottom at call)
fn precompile_relay_runtime(precompile_addr_byte: u8) -> Vec<u8> {
    vec![
        // Copy calldata to memory[0..]
        0x36, // CALLDATASIZE
        0x60,
        0x00, // PUSH1 0  (destOffset)
        0x60,
        0x00, // PUSH1 0  (dataOffset)
        0x37, // CALLDATACOPY
        // STATICCALL(gas, addr, inOff=0, inLen=calldatasize, outOff=0, outLen=32)
        0x60,
        0x20, // PUSH1 32   retLen
        0x60,
        0x00, // PUSH1 0    retOff
        0x36, // CALLDATASIZE  argsLen
        0x60,
        0x00, // PUSH1 0    argsOff
        0x60,
        precompile_addr_byte, // PUSH1 addr
        0x5A,                 // GAS
        0xFA,                 // STATICCALL  → [success]
        0x50,                 // POP
        // Return mem[0:32]
        0x60,
        0x20, // PUSH1 32
        0x60,
        0x00, // PUSH1 0
        0xF3, // RETURN
    ]
}

/// Contract A: exposes `set(uint256)` (writes to slot 0) and `get()`.
///
/// Selector layout:
///   set(uint256)  → CALLDATALOAD(4) → SSTORE slot 0
///   get()         → SLOAD slot 0    → RETURN 32 bytes
///
/// Offsets:
///   0x22: set() JUMPDEST
///   0x2F: get() JUMPDEST
fn contract_a_runtime() -> Vec<u8> {
    let set_sel = &keccak256(b"set(uint256)")[..4];
    let get_sel = &keccak256(b"get()")[..4];

    let mut code = vec![
        0x60, 0x00, // PUSH1 0
        0x35, // CALLDATALOAD
        0x60, 0xE0, // PUSH1 224
        0x1C, // SHR  → selector
        0x80, // DUP1
        0x63, // PUSH4 set_sel
    ];
    code.extend_from_slice(set_sel);
    code.extend_from_slice(&[
        0x14, // EQ
        0x60,
        0x1F, // PUSH1 0x1F  (set handler; 3+3+2+4+1+2+1+5 = 21 = 0x15... wait: two dispatch)
        0x57, // JUMPI
        0x80, // DUP1
        0x63, // PUSH4 get_sel
    ]);
    code.extend_from_slice(get_sel);
    code.extend_from_slice(&[
        0x14, // EQ
        0x60, 0x2C, // PUSH1 0x2C  (get handler; 0x1F + 13 = 0x2C)
        0x57, // JUMPI
        0x60, 0x00, // PUSH1 0  (revert)
        0x60, 0x00, 0xFD, // REVERT
        // ── set(uint256) at 0x1F ──
        0x5B, // JUMPDEST
        0x50, // POP       (selector)
        0x60, 0x04, // PUSH1 4   (skip selector in calldata)
        0x35, // CALLDATALOAD  → [value]
        0x60, 0x00, // PUSH1 0   (slot)
        0x55, // SSTORE
        0x60, 0x00, 0x60, 0x00, 0xF3, // RETURN empty
        // ── get() at 0x2C ──
        0x5B, // JUMPDEST
        0x50, // POP
        0x60, 0x00, // PUSH1 0
        0x54, // SLOAD
        0x60, 0x00, 0x52, // MSTORE
        0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN mem[0:32]
    ]);

    debug_assert_eq!(code[0x1F], 0x5B, "set() JUMPDEST must be at offset 0x1F");
    debug_assert_eq!(code[0x2C], 0x5B, "get() JUMPDEST must be at offset 0x2C");

    code
}

/// Contract B: calls Contract A's `set(uint256)` with a hardcoded value (42).
///
/// The address of Contract A is supplied as calldata (32 bytes).
/// B calls `set(42)` on A, then returns.
///
/// Memory layout:
///   mem[0:32]  = selector left-aligned (via sel << 224 + MSTORE)
///   mem[4:36]  = uint256(42) right-aligned (via MSTORE at offset 4)
///   Combined:  mem[0:4]=selector, mem[4:35]=0, mem[35]=42 → 36-byte set(42) calldata
fn contract_b_runtime() -> Vec<u8> {
    let set_sel = &keccak256(b"set(uint256)")[..4];

    let mut code = Vec::new();

    // Step 1: Write selector to mem[0:32] (selector occupies bytes 0-3)
    code.extend_from_slice(&[0x63]); // PUSH4
    code.extend_from_slice(set_sel);
    code.extend_from_slice(&[
        0x60, 0xE0, // PUSH1 224
        0x1B, // SHL     → sel << 224
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE  → mem[0:32]: selector at bytes 0-3
    ]);

    // Step 2: Write uint256(42) to mem[4:36]
    code.extend_from_slice(&[
        0x60, 0x2A, // PUSH1 42
        0x60, 0x04, // PUSH1 4
        0x52, // MSTORE  → mem[4:36]: 42 right-aligned; overlapping zeroes overwrite [4:32]
    ]);

    // Step 3: Load Contract A address from calldata[0:32]
    code.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0
        0x35, // CALLDATALOAD  → stack: [addrA]
    ]);

    // Step 4: CALL(gas, addr, value, argsOff, argsLen, retOff, retLen)  — 7 args
    // Push in reverse: retLen(deepest), retOff, argsLen, argsOff, value, then DUP6→addr, GAS, CALL
    code.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0   retLen   → [0, addrA]
        0x60, 0x00, // PUSH1 0   retOff   → [0, 0, addrA]
        0x60, 0x24, // PUSH1 36  argsLen  → [36, 0, 0, addrA]
        0x60, 0x00, // PUSH1 0   argsOff  → [0, 36, 0, 0, addrA]
        0x60, 0x00, // PUSH1 0   value    → [0, 0, 36, 0, 0, addrA]
        // Stack (top→bottom): [value=0, argsOff=0, argsLen=36, retOff=0, retLen=0, addrA]
        0x85, // DUP6  → [addrA, value=0, argsOff=0, argsLen=36, retOff=0, retLen=0, addrA]
        0x5A, // GAS   → [gas, addrA, value=0, argsOff=0, argsLen=36, retOff=0, retLen=0, addrA]
        0xF1, // CALL  pops 7, pushes success
        0x50, // POP   (success)
        0x50, // POP   (remaining addrA)
    ]);

    // Step 5: Return empty
    code.extend_from_slice(&[
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xF3, // RETURN
    ]);

    code
}

/// Contract that reverts with a custom 4-byte error selector.
///
/// The function `alwaysReverts()` REVERTs with the selector of `CustomError()`.
///
/// Selector: keccak256("alwaysReverts()")[0:4] → dispatch
/// Error:    custom error selector = keccak256("CustomError()")[0:4]
fn revert_contract_runtime() -> Vec<u8> {
    let revert_sel = &keccak256(b"alwaysReverts()")[..4];
    let err_sel = &keccak256(b"CustomError()")[..4];

    // Layout:
    //   Dispatcher (same pattern as counter)
    //   alwaysReverts() handler:
    //     Write err_sel to mem[0:4]
    //     REVERT(0, 4)

    let mut code = vec![
        0x60, 0x00, 0x35, // PUSH1 0; CALLDATALOAD
        0x60, 0xE0, 0x1C, // PUSH1 224; SHR  → selector
        0x80, 0x63, // DUP1; PUSH4 ...
    ];
    code.extend_from_slice(revert_sel);
    code.extend_from_slice(&[
        0x14, // EQ
        0x60, 0x15, // PUSH1 0x15  (handler offset: 3+3+2+4+1+2+1+5 = 21 = 0x15)
        0x57, // JUMPI
        // Default fallback: REVERT empty
        0x60, 0x00, 0x60, 0x00, 0xFD, // REVERT
        // ── alwaysReverts() at 0x15 ──
        0x5B, // JUMPDEST
        0x50, // POP
        // Write err_sel to mem[0]
        0x63, // PUSH4 err_sel
    ]);
    code.extend_from_slice(err_sel);
    code.extend_from_slice(&[
        0x60, 0xE0, // PUSH1 224
        0x1B, // SHL          → err_sel << 224
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE       → mem[0:32] contains err_sel at bytes 0-3
        0x60, 0x04, // PUSH1 4      (revert data size)
        0x60, 0x00, // PUSH1 0      (offset)
        0xFD, // REVERT
    ]);

    debug_assert_eq!(
        code[0x15], 0x5B,
        "alwaysReverts() JUMPDEST must be at offset 0x15"
    );

    code
}

/// Contract that emits a `Transfer(address,address,uint256)` log.
///
/// Calldata: none required (uses hardcoded values for simplicity).
/// Emits: LOG3(data=abi_encode(100), topic0=Transfer_sig, topic1=from, topic2=to)
///   from = 0xAAAA...AAAA (20 bytes padded to 32)
///   to   = 0xBBBB...BBBB (20 bytes padded to 32)
///   amount = 100
fn log_emitter_runtime() -> Vec<u8> {
    // topic0 = keccak256("Transfer(address,address,uint256)")
    let topic0 = keccak256(b"Transfer(address,address,uint256)");
    let from_addr = [0xAA_u8; 32]; // address padded to 32 bytes
    let to_addr = [0xBB_u8; 32]; // address padded to 32 bytes

    // Memory layout: mem[0x00..0x20] = uint256(100)
    // LOG3 pops (top→bottom): offset, size, topic0, topic1, topic2
    // Push order (deepest=first): topic2=to, topic1=from, topic0=Transfer sig, size=32, offset=0

    let mut code = Vec::new();

    // Store amount (100) at mem[0]
    code.push(0x60); // PUSH1 100
    code.push(100u8);
    code.extend_from_slice(&[0x60, 0x00, 0x52]); // PUSH1 0; MSTORE

    // PUSH32 to_addr (topic2 — deepest)
    code.push(0x7F);
    code.extend_from_slice(&to_addr);

    // PUSH32 from_addr (topic1)
    code.push(0x7F);
    code.extend_from_slice(&from_addr);

    // PUSH32 topic0 = Transfer event signature (topic0 — shallowest topic)
    code.push(0x7F);
    code.extend_from_slice(topic0.as_slice());

    // size and offset on top
    code.extend_from_slice(&[
        0x60, 0x20, // PUSH1 32  (size)
        0x60, 0x00, // PUSH1 0   (offset — top of stack, popped first by LOG3)
        0xA3, // LOG3
        // Return empty
        0x60, 0x00, 0x60, 0x00, 0xF3, // RETURN
    ]);

    code
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// T1: Deploy a Counter contract, call `increment()` once, verify `get()` returns 1.
#[test]
fn t1_counter_deploy_increment_get() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &counter_runtime(),
    );

    // Call increment()
    let incr_sel = keccak256(b"increment()");
    let result = call_contract(&mut evm, from, 1, contract, incr_sel[..4].to_vec(), 2);
    assert_eq!(result.receipt.status, 1, "increment() should succeed");

    // Call get() — should return 1
    let get_sel = keccak256(b"get()");
    let result2 = call_contract(&mut evm, from, 2, contract, get_sel[..4].to_vec(), 3);
    assert_eq!(result2.receipt.status, 1, "get() should succeed");
    let value = abi_decode_u256(&result2.output);
    assert_eq!(
        value,
        U256::from(1u64),
        "counter should be 1 after one increment"
    );
}

/// T2: Deploy a relay contract that calls the BLAKE3-256 precompile (0x0004) and returns
/// the hash. Verify the output matches `blake3::hash(input)`.
#[test]
fn t2_blake3_precompile_from_contract() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &precompile_relay_runtime(0x04),
    );

    let input = b"shell-chain pq hash test";
    let expected = blake3::hash(input);

    let result = call_contract(&mut evm, from, 1, contract, input.to_vec(), 2);
    assert_eq!(result.receipt.status, 1, "BLAKE3 relay call should succeed");
    assert_eq!(
        &result.output[..32],
        expected.as_bytes(),
        "BLAKE3 output from contract should match blake3::hash(input)"
    );
}

/// T4: Deploy a log-emitting contract. Verify the receipt has one log with the
/// correct Transfer event topic and amount in the data field.
#[test]
fn t4_event_log_emission() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &log_emitter_runtime(),
    );

    // Trigger the log (no calldata needed — contract uses hardcoded values)
    let result = call_contract(&mut evm, from, 1, contract, vec![], 2);
    assert_eq!(result.receipt.status, 1, "log emitter should succeed");

    let logs = &result.receipt.logs;
    assert_eq!(logs.len(), 1, "should emit exactly one log");

    let log = &logs[0];
    // topic[0] must be keccak256("Transfer(address,address,uint256)")
    let expected_topic0 = keccak256(b"Transfer(address,address,uint256)");
    assert_eq!(
        log.topics[0].as_bytes(),
        expected_topic0.as_slice(),
        "topic[0] should be Transfer event signature"
    );
    // Log data should encode amount = 100
    let logged_amount = abi_decode_u256(log.data.as_ref());
    assert_eq!(
        logged_amount,
        U256::from(100u64),
        "logged amount should be 100"
    );
}

/// T5: Deploy a contract with a function that always reverts with a custom error selector.
/// Verify receipt.status == 0 and output starts with the custom error selector.
#[test]
fn t5_revert_propagation() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &revert_contract_runtime(),
    );

    let revert_fn_sel = keccak256(b"alwaysReverts()");
    let result = call_contract(&mut evm, from, 1, contract, revert_fn_sel[..4].to_vec(), 2);

    assert_eq!(
        result.receipt.status, 0,
        "reverted call should have status 0"
    );

    let expected_err_sel = &keccak256(b"CustomError()")[..4];
    assert!(
        result.output.len() >= 4,
        "revert data should be at least 4 bytes"
    );
    assert_eq!(
        &result.output[..4],
        expected_err_sel,
        "revert data should start with CustomError() selector"
    );
}

/// T6: Deploy contracts A and B. Call B with A's address; B internally calls A's
/// `set(42)`. Verify A's storage slot 0 == 42.
#[test]
fn t6_contract_to_contract_call() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    // Deploy A
    let (contract_a, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &contract_a_runtime(),
    );

    // Deploy B
    let (contract_b, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        1,
        2,
        &contract_b_runtime(),
    );

    // Call B with A's address as calldata (left-padded to 32 bytes)
    let mut calldata = [0u8; 32];
    // ShellAddress is 32 bytes; copy it directly
    calldata.copy_from_slice(contract_a.0.as_slice());

    let result = call_contract(&mut evm, from, 2, contract_b, calldata.to_vec(), 3);
    assert_eq!(result.receipt.status, 1, "B→A call should succeed");

    // Verify A's storage: call get() on A
    let get_sel = keccak256(b"get()");
    let get_result = call_contract(&mut evm, from, 3, contract_a, get_sel[..4].to_vec(), 4);
    assert_eq!(get_result.receipt.status, 1, "get() on A should succeed");
    let stored = abi_decode_u256(&get_result.output);
    assert_eq!(
        stored,
        U256::from(42u64),
        "A's storage should be 42 after B called set(42)"
    );
}

/// T7: ML-DSA verify precompile (0x0001) invoked from a deployed contract.
/// Valid signature → return last byte = 1.
/// Tampered signature → return last byte = 0.
#[test]
fn t7_mldsa_verify_precompile_from_contract() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        0,
        1,
        &precompile_relay_runtime(0x01),
    );

    let message = b"verify this message via precompile";
    let sig = signer.sign(message).expect("sign failed");
    let pk = signer.public_key();

    // Build wire format: [4-byte pk_len][pk][4-byte msg_len][msg][sig_bytes]
    let mut wire = Vec::new();
    wire.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    wire.extend_from_slice(pk);
    wire.extend_from_slice(&(message.len() as u32).to_be_bytes());
    wire.extend_from_slice(message);
    wire.extend_from_slice(&sig.data);

    // Valid signature → output[31] == 1
    let result = call_contract(&mut evm, from, 1, contract, wire.clone(), 2);
    assert_eq!(
        result.receipt.status, 1,
        "ML-DSA verify call should succeed"
    );
    assert_eq!(
        result.output[31], 1,
        "valid ML-DSA signature should return 1"
    );

    // Tamper the signature: flip last byte of sig_bytes
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    let result2 = call_contract(&mut evm, from, 2, contract, tampered, 3);
    assert_eq!(
        result2.receipt.status, 1,
        "tampered sig call should not revert (precompile returns 0)"
    );
    assert_eq!(
        result2.output[31], 0,
        "tampered ML-DSA signature should return 0"
    );
}

/// T8: PQADDR native opcode (0xB2) derives a 32-byte Shell address in-contract.
#[test]
fn t8_pqaddr_native_opcode_derives_address() {
    let (mut evm, chain_store) = setup();
    let verifier = shell_crypto::DilithiumVerifier;

    let signer = DilithiumSigner::generate();
    let from = ShellAddress::from_public_key(signer.public_key(), signer.sig_type().as_u8());

    fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

    let pubkey = [0x11, 0x22, 0x33, 0x44];
    let runtime = vec![
        0x60,
        pubkey[0],
        0x60,
        0x00,
        0x53, // memory[0] = pubkey[0]
        0x60,
        pubkey[1],
        0x60,
        0x01,
        0x53, // memory[1] = pubkey[1]
        0x60,
        pubkey[2],
        0x60,
        0x02,
        0x53, // memory[2] = pubkey[2]
        0x60,
        pubkey[3],
        0x60,
        0x03,
        0x53, // memory[3] = pubkey[3]
        0x60,
        SignatureType::MlDsa65.as_u8(), // algo_id
        0x60,
        0x00, // pk_ptr
        0x60,
        pubkey.len() as u8, // pk_len
        0x60,
        0x20, // out_ptr
        0xB2, // PQADDR
        0x60,
        0x20, // return length
        0x60,
        0x20, // return offset
        0xF3, // RETURN
    ];

    let deploy_nonce = evm
        .state_db()
        .world_state()
        .get_nonce(&from)
        .expect("funded sender nonce should be readable");

    let (contract, _) = deploy_runtime_contract(
        &mut evm,
        &chain_store,
        &verifier,
        &signer,
        from,
        deploy_nonce,
        1,
        &runtime,
    );

    let call_nonce = evm
        .state_db()
        .world_state()
        .get_nonce(&from)
        .expect("sender nonce should advance after deployment");
    let result = call_contract(&mut evm, from, call_nonce, contract, vec![], 2);
    let expected = ShellAddress::from_public_key(&pubkey, SignatureType::MlDsa65.as_u8());
    assert_eq!(result.receipt.status, 1, "PQADDR call should succeed");
    assert_eq!(result.output, expected.as_bytes());
}
