//! Transaction-local native address context for the revm instruction boundary.
//!
//! Context and account operands share full identities through transaction-local
//! handles. Creation frames and all production execution entry points must be
//! integrated before enabling this instruction table in consensus or RPC.

use alloy_primitives::{Address, U256};
use revm::context_interface::ContextTr;
use revm::handler::instructions::EthInstructions;
use revm::interpreter::{
    instructions::{contract, host},
    interpreter_types::{InputsTr, InterpreterTypes, StackTr},
    Instruction, InstructionContext, InstructionResult,
};
use shell_primitives::Address as ShellAddress;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub(crate) struct NativeAddressContext {
    addresses: std::sync::Arc<std::sync::RwLock<AddressKeys>>,
}

#[derive(Default)]
struct AddressKeys {
    by_key: HashMap<Address, ShellAddress>,
    by_native: HashMap<ShellAddress, Address>,
}

impl NativeAddressContext {
    pub(crate) fn at_height<S: shell_storage::KvStore + 'static>(
        chain: &shell_storage::ChainStore<S>,
        number: u64,
    ) -> Result<Option<Self>, shell_storage::StorageError> {
        Ok(chain
            .get_chain_config()?
            .and_then(|config| config.native_address_context_height)
            .filter(|height| number >= *height)
            .map(|_| Self::default()))
    }

    /// Allocate a transaction-local revm key without truncating native identity.
    /// Keys are internal handles, never persisted or returned to contracts.
    pub(crate) fn register(&self, address: ShellAddress) -> Result<Address, &'static str> {
        let mut keys = self
            .addresses
            .write()
            .expect("native address lock poisoned");
        if let Some(key) = keys.by_native.get(&address) {
            return Ok(*key);
        }
        let canonical = ShellAddress::from(address.to_alloy()) == address;
        let mut counter = 0_u64;
        loop {
            let key = if canonical && counter == 0 {
                address.to_alloy()
            } else {
                let mut hash = blake3::Hasher::new();
                hash.update(b"shell-pqvm-address-handle-v1");
                hash.update(address.as_bytes());
                hash.update(&counter.to_be_bytes());
                Address::from_slice(&hash.finalize().as_bytes()[12..])
            };
            // Native precompile handles must remain their canonical keys.
            // A full address hashing onto one retries before becoming visible.
            let reserved = crate::ShellPrecompiles::new(revm::primitives::hardfork::SpecId::CANCUN)
                .is_precompile(&key)
                || key == crate::NATIVE_REGISTRY_VIEW_ADDR;
            if (!canonical || counter > 0) && reserved {
                counter = counter
                    .checked_add(1)
                    .ok_or("native handle space exhausted")?;
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = keys.by_key.entry(key) {
                entry.insert(address);
                keys.by_native.insert(address, key);
                return Ok(key);
            }
            counter = counter
                .checked_add(1)
                .ok_or("native handle space exhausted")?;
        }
    }

    pub(crate) fn resolve(&self, address: Address) -> ShellAddress {
        self.addresses
            .read()
            .expect("native address lock poisoned")
            .by_key
            .get(&address)
            .copied()
            .unwrap_or_else(|| ShellAddress::from(address))
    }

    pub(crate) fn snapshot(&self) -> HashMap<Address, ShellAddress> {
        self.addresses
            .read()
            .expect("native address lock poisoned")
            .by_key
            .clone()
    }
}

pub(crate) fn install<WIRE, H>(instructions: &mut EthInstructions<WIRE, H>)
where
    WIRE: InterpreterTypes,
    H: ContextTr<Chain = NativeAddressContext>,
{
    // Creation remains unavailable in this internal profile until its native
    // derivation and frame/output hooks are complete.
    instructions.insert_instruction(
        0xf0,
        Instruction::new(revm::interpreter::instructions::control::invalid, 0),
    );
    instructions.insert_instruction(
        0xf5,
        Instruction::new(revm::interpreter::instructions::control::invalid, 0),
    );
    // Retain the instruction table's static gas. Only the value pushed
    // by the three address-context instructions changes.
    let gas = instructions.instruction_table[0x30].static_gas();
    instructions.insert_instruction(0x30, Instruction::new(address::<WIRE, H>, gas));
    let gas = instructions.instruction_table[0x32].static_gas();
    instructions.insert_instruction(0x32, Instruction::new(origin::<WIRE, H>, gas));
    let gas = instructions.instruction_table[0x41].static_gas();
    instructions.insert_instruction(0x41, Instruction::new(coinbase::<WIRE, H>, gas));
    let gas = instructions.instruction_table[0x33].static_gas();
    instructions.insert_instruction(0x33, Instruction::new(caller::<WIRE, H>, gas));
    for (opcode, implementation) in [
        (0xf1, call::<WIRE, H> as fn(InstructionContext<'_, H, WIRE>)),
        (0xf4, delegate_call::<WIRE, H>),
        (0xfa, static_call::<WIRE, H>),
        (0x31, balance::<WIRE, H>),
        (0x3b, extcodesize::<WIRE, H>),
        (0x3c, extcodecopy::<WIRE, H>),
        (0x3f, extcodehash::<WIRE, H>),
    ] {
        let gas = instructions.instruction_table[opcode].static_gas();
        instructions.insert_instruction(opcode as u8, Instruction::new(implementation, gas));
    }
}

fn address<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = context.interpreter.input.target_address();
    let word = U256::from_be_bytes(*context.host.chain().resolve(address).as_bytes());
    revm::interpreter::push!(context.interpreter, word);
}

fn caller<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = context.interpreter.input.caller_address();
    let word = U256::from_be_bytes(*context.host.chain().resolve(address).as_bytes());
    revm::interpreter::push!(context.interpreter, word);
}

fn origin<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = context.host.caller();
    let word = U256::from_be_bytes(*context.host.chain().resolve(address).as_bytes());
    revm::interpreter::push!(context.interpreter, word);
}

fn coinbase<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let address = context.host.beneficiary();
    let word = U256::from_be_bytes(*context.host.chain().resolve(address).as_bytes());
    revm::interpreter::push!(context.interpreter, word);
}

/// Translate a full stack operand before the retained revm opcode consumes it.
/// Swapping rather than popping preserves the operand count and error behavior.
fn translate<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
    context: &mut InstructionContext<'_, H, WIRE>,
    depth: usize,
) -> bool {
    if context.interpreter.stack.len() <= depth {
        return true;
    }
    if depth != 0 {
        assert!(context.interpreter.stack.exchange(0, depth));
    }
    let word = context
        .interpreter
        .stack
        .top()
        .expect("checked stack length");
    let address = ShellAddress::from(word.to_be_bytes::<32>());
    let key = context.host.chain().register(address);
    if let Ok(key) = key {
        *word = key.into_word().into();
    }
    if depth != 0 {
        assert!(context.interpreter.stack.exchange(0, depth));
    }
    if key.is_err() {
        context.interpreter.halt(InstructionResult::InvalidFEOpcode);
        return false;
    }
    true
}

macro_rules! native_operand {
    ($name:ident, $module:ident, $depth:expr) => {
        fn $name<WIRE: InterpreterTypes, H: ContextTr<Chain = NativeAddressContext>>(
            mut context: InstructionContext<'_, H, WIRE>,
        ) {
            if translate(&mut context, $depth) {
                $module::$name(context);
            }
        }
    };
}
native_operand!(call, contract, 1);
native_operand!(delegate_call, contract, 1);
native_operand!(static_call, contract, 1);
native_operand!(balance, host, 0);
native_operand!(extcodesize, host, 0);
native_operand!(extcodecopy, host, 0);
native_operand!(extcodehash, host, 0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ShellPrecompiles, ShellStateDb};
    use revm::context::{Context, Evm, TxEnv};
    use revm::handler::{ExecuteEvm, MainnetContext};
    use revm::primitives::{hardfork::SpecId, TxKind};
    use shell_core::Account;
    use shell_storage::{ChainStore, MemoryDb, WorldState};
    use std::sync::Arc;

    fn run(from: ShellAddress, enabled: bool) -> (Vec<u8>, u64) {
        let store = Arc::new(MemoryDb::new());
        let mut state = WorldState::new(store.clone());
        state
            .set_account(
                &from,
                &Account::new_user_account(
                    shell_primitives::ShellHash::ZERO,
                    U256::from(10_u64.pow(18)),
                ),
            )
            .unwrap();
        let mut db = ShellStateDb::new(state, ChainStore::new(store));
        db.register_pq_address(from);
        let identities = NativeAddressContext::default();
        let caller_key = if enabled {
            identities.register(from).unwrap()
        } else {
            from.to_alloy()
        };
        if enabled {
            db.set_native_context(identities.clone());
        }
        // Call frame returns CALLER, ORIGIN, ADDRESS as three full words.
        let code = vec![
            0x33, 0x60, 0, 0x52, 0x32, 0x60, 32, 0x52, 0x30, 0x60, 64, 0x52, 0x60, 96, 0x60, 0,
            0xf3,
        ];
        let target = ShellAddress::from([0x98; 32]);
        let target_key = if enabled {
            identities.register(target).unwrap()
        } else {
            target.to_alloy()
        };
        db.register_pq_address(target);
        let code_hash = shell_primitives::keccak256(&code);
        db.chain_store().put_code(&code_hash, &code).unwrap();
        let mut account = Account::new_user_account(shell_primitives::ShellHash::ZERO, U256::ZERO);
        account.code_hash = Some(code_hash);
        db.world_state_mut().set_account(&target, &account).unwrap();
        let context: MainnetContext<&mut ShellStateDb<MemoryDb>> =
            Context::new(&mut db, SpecId::CANCUN);
        let context = context.with_chain(identities).modify_cfg_chained(|cfg| {
            cfg.disable_nonce_check = true;
            cfg.disable_base_fee = true;
        });
        let mut instructions = EthInstructions::new_mainnet_with_spec(SpecId::CANCUN);
        if enabled {
            install(&mut instructions);
        }
        let mut evm = Evm::new(context, instructions, ShellPrecompiles::new(SpecId::CANCUN));
        let tx = TxEnv::builder()
            .caller(caller_key)
            .kind(TxKind::Call(target_key))
            .gas_limit(200_000)
            .data(Default::default())
            .build_fill();
        let result = evm.transact(tx).unwrap().result;
        assert!(result.is_success());
        (result.output().unwrap().to_vec(), result.gas_used())
    }

    #[test]
    fn context_words_preserve_full_sender_without_changing_gas() {
        let mut first = [0x12; 32];
        first[..12].fill(0x34);
        let mut second = first;
        second[..12].fill(0x56);
        for bytes in [first, second] {
            let from = ShellAddress::from(bytes);
            let (legacy, legacy_gas) = run(from, false);
            let (native, native_gas) = run(from, true);
            assert_eq!(&legacy[..12], &[0; 12]);
            assert_eq!(&native[..32], &bytes);
            assert_eq!(&native[32..64], &bytes);
            assert_eq!(&native[64..], &[0x98; 32]);
            assert_eq!(&legacy[64..76], &[0; 12]);
            assert_eq!(native_gas, legacy_gas);
        }
    }

    #[test]
    fn colliding_low_bits_have_distinct_account_handles() {
        let mut first = [0x12; 32];
        first[..12].fill(0x34);
        let mut second = first;
        second[..12].fill(0x56);
        let context = NativeAddressContext::default();
        let a = ShellAddress::from(first);
        let b = ShellAddress::from(second);
        let ka = context.register(a).unwrap();
        let kb = context.register(b).unwrap();
        assert_ne!(ka, kb);
        assert_eq!(context.register(a).unwrap(), ka);
        assert_eq!(context.resolve(ka), a);
        assert_eq!(context.resolve(kb), b);
        let low = ShellAddress::from(a.to_alloy());
        let klow = context.register(low).unwrap();
        assert_eq!(context.resolve(klow), low);
        assert_ne!(ka, klow);
        assert_ne!(kb, klow);
    }
    #[test]
    fn canonical_address_cannot_alias_an_existing_native_handle() {
        let context = NativeAddressContext::default();
        let full = ShellAddress::from([0x34; 32]);
        let native_key = context.register(full).unwrap();
        let canonical = ShellAddress::from(native_key);
        let canonical_key = context.register(canonical).unwrap();
        assert_ne!(native_key, canonical_key);
        assert_eq!(context.resolve(native_key), full);
        assert_eq!(context.resolve(canonical_key), canonical);
        assert_eq!(context.register(canonical).unwrap(), canonical_key);
        for last in 1..=6 {
            let mut bytes = [0; 32];
            bytes[31] = last;
            let precompile = ShellAddress::from(bytes);
            assert_eq!(context.register(precompile).unwrap(), precompile.to_alloy());
        }
    }

    #[test]
    fn nested_calls_keep_same_low160_contracts_and_commits_distinct() {
        for revert in [false, true] {
            for opcode in [0xf1, 0xf4, 0xfa] {
                run_nested(revert, opcode);
            }
        }
    }

    fn run_nested(revert: bool, opcode: u8) {
        use crate::{commit_pqvm_state, TxExecutionResult};
        use shell_core::TransactionReceipt;
        use shell_primitives::{Bytes, ShellHash};
        let from = ShellAddress::from([0x77; 32]);
        let root = ShellAddress::from([0x88; 32]);
        let a = ShellAddress::from([0x12; 32]);
        let mut bbytes = [0x12; 32];
        bbytes[..12].fill(0x56);
        let b = ShellAddress::from(bbytes);
        let store = Arc::new(MemoryDb::new());
        let ws = WorldState::new(store.clone());
        let cs = ChainStore::new(store);
        let mut db = ShellStateDb::new(ws, cs);
        let identities = NativeAddressContext::default();
        let sender_key = identities.register(from).unwrap();
        let root_key = identities.register(root).unwrap();
        db.set_native_context(identities.clone());
        db.world_state_mut()
            .set_account(
                &from,
                &Account::new_user_account(ShellHash::ZERO, U256::from(10_u64.pow(18))),
            )
            .unwrap();
        // Each callee records its full caller and own identity, then returns
        // CALLER / ADDRESS / ORIGIN. The root reaches both using PUSH32 targets.
        let callee = vec![
            0x33, 0x60, 0, 0x55, 0x30, 0x60, 1, 0x55, 0x33, 0x60, 0, 0x52, 0x30, 0x60, 32, 0x52,
            0x32, 0x60, 64, 0x52, 0x60, 96, 0x60, 0, 0xf3,
        ];
        let callee = if opcode == 0xfa {
            callee[8..].to_vec()
        } else {
            callee
        };
        let mut code = Vec::new();
        for (target, offset) in [(a, 0_u8), (b, 96)] {
            code.extend_from_slice(&[0x60, 96, 0x60, offset, 0x60, 0, 0x60, 0]);
            if opcode == 0xf1 {
                code.extend_from_slice(&[0x60, 0]);
            }
            code.push(0x7f);
            code.extend_from_slice(target.as_bytes());
            code.extend_from_slice(&[0x62, 0x03, 0x0d, 0x40, opcode, 0x50]);
        }
        code.extend_from_slice(&[0x60, 192, 0x60, 0, if revert { 0xfd } else { 0xf3 }]);
        for (target, runtime) in [(root, code), (a, callee.clone()), (b, callee)] {
            let hash = shell_primitives::keccak256(&runtime);
            db.chain_store().put_code(&hash, &runtime).unwrap();
            let mut account = Account::new_user_account(ShellHash::ZERO, U256::ZERO);
            account.code_hash = Some(hash);
            db.world_state_mut().set_account(&target, &account).unwrap();
        }
        let context: MainnetContext<&mut ShellStateDb<MemoryDb>> =
            Context::new(&mut db, SpecId::CANCUN);
        let context = context.with_chain(identities).modify_cfg_chained(|cfg| {
            cfg.disable_base_fee = true;
            cfg.disable_nonce_check = true;
        });
        let mut instructions = EthInstructions::new_mainnet_with_spec(SpecId::CANCUN);
        install(&mut instructions);
        let mut evm = Evm::new(context, instructions, ShellPrecompiles::new(SpecId::CANCUN));
        let result = evm
            .transact(
                TxEnv::builder()
                    .caller(sender_key)
                    .kind(TxKind::Call(root_key))
                    .gas_limit(1_000_000)
                    .build_fill(),
            )
            .unwrap();
        assert_eq!(result.result.is_success(), !revert);
        let output = result.result.output().unwrap().to_vec();
        for (start, target) in [(0, a), (96, b)] {
            assert_eq!(
                &output[start..start + 32],
                if opcode == 0xf4 {
                    from.as_bytes()
                } else {
                    root.as_bytes()
                }
            );
            assert_eq!(
                &output[start + 32..start + 64],
                if opcode == 0xf4 {
                    root.as_bytes()
                } else {
                    target.as_bytes()
                }
            );
            assert_eq!(&output[start + 64..start + 96], from.as_bytes());
        }
        let gas_used = result.result.gas_used();
        drop(evm);
        let execution = TxExecutionResult {
            receipt: TransactionReceipt {
                tx_hash: ShellHash::ZERO,
                block_number: 1,
                tx_index: 0,
                status: u8::from(!revert),
                gas_used,
                cumulative_gas_used: gas_used,
                contract_address: None,
                logs_bloom: Bytes::from(vec![0; 256]),
                logs: vec![],
            },
            state_changes: result.state,
            sender_shell_addr: from,
            sender_nonce_after: 1,
            gas_used,
            gas_spent: gas_used,
            output,
            is_system_tx: false,
            system_contract_effects: Default::default(),
        };
        commit_pqvm_state(&execution, &mut db).unwrap();
        for target in [a, b, root] {
            let writes = !revert
                && ((opcode == 0xf1 && target != root) || (opcode == 0xf4 && target == root));
            let expected_caller = if writes {
                if opcode == 0xf4 {
                    from
                } else {
                    root
                }
            } else {
                ShellAddress::ZERO
            };
            let expected_address = if writes { target } else { ShellAddress::ZERO };
            assert_eq!(
                db.world_state()
                    .get_storage(&target, &ShellHash::ZERO)
                    .unwrap()
                    .as_bytes(),
                expected_caller.as_bytes()
            );
            let slot1 = ShellHash::from(alloy_primitives::B256::from(U256::from(1)));
            assert_eq!(
                db.world_state()
                    .get_storage(&target, &slot1)
                    .unwrap()
                    .as_bytes(),
                expected_address.as_bytes()
            );
        }
        assert!(db.address_registry_snapshot().is_empty());
    }
    // Proposed creation profile only; no production derivation is installed.
    // Approval must precede enabling this new consensus address scheme.
    #[test]
    fn proposed_native_create_profile_matches_independent_vectors() {
        use alloy_rlp::{Encodable, Header};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native-create-proposal.json"
        ))
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let caller = hex::decode(vector["caller"].as_str().unwrap()).unwrap();
            let mut input = Vec::new();
            if vector["scheme"] == "CREATE" {
                let nonce = vector["nonce"].as_str().unwrap().parse::<u64>().unwrap();
                Header {
                    list: true,
                    payload_length: caller.as_slice().length() + nonce.length(),
                }
                .encode(&mut input);
                caller.as_slice().encode(&mut input);
                nonce.encode(&mut input);
            } else {
                input.push(0xff);
                input.extend_from_slice(&caller);
                input.extend_from_slice(&hex::decode(vector["salt"].as_str().unwrap()).unwrap());
                let init = hex::decode(vector["init"].as_str().unwrap()).unwrap();
                input.extend_from_slice(blake3::hash(&init).as_bytes());
            }
            assert_eq!(hex::encode(&input), vector["input"].as_str().unwrap());
            assert_eq!(
                blake3::hash(&input).to_hex().as_str(),
                vector["address"].as_str().unwrap()
            );
        }
    }
}
