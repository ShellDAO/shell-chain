//! Bounded execution observations for read-only RPC replay.

use revm::bytecode::opcode::{SLOAD, SSTORE};
use revm::context::{BlockEnv, CfgEnv, Context, Journal, TxEnv};
use revm::context_interface::ContextTr;
use revm::inspector::Inspector;
use revm::interpreter::interpreter_types::{Jumps, LoopControl};
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter, InterpreterResult,
};
use serde::Serialize;
use shell_primitives::{Address, Bytes, ShellHash};
use shell_storage::KvStore;
use std::collections::{BTreeMap, BTreeSet};

use crate::{decode_revert_reason, CallFrame, ShellStateDb};

const MAX_TRACE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRACE_INSTRUCTIONS: usize = 50_000;
const TRACE_RECORD_OVERHEAD: usize = 512;
const ENCODED_STACK_WORD_BUDGET: usize = 68;

/// Controls optional opcode payloads; call frames are always retained.
#[derive(Clone, Copy, Default)]
pub struct TraceConfig {
    pub disable_stack: bool,
    pub disable_memory: bool,
    pub disable_storage: bool,
}

/// An observed instruction, with gas measured before and after execution.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpcodeTrace {
    pub pc: usize,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<std::collections::BTreeMap<String, String>>,
}

/// A real execution call tree and its opcode observations.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionTrace {
    #[serde(flatten)]
    pub result: crate::TraceResult,
    pub struct_logs: Vec<OpcodeTrace>,
}

/// Bounded access discovery; accesses in reverted frames are retained.
pub(crate) struct AccessListCollector {
    entries: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    excluded: BTreeSet<[u8; 32]>,
    exceeded: bool,
}

impl AccessListCollector {
    fn new(seed: &[shell_core::AccessListItem]) -> Self {
        let mut collector = Self {
            entries: BTreeMap::new(),
            excluded: BTreeSet::new(),
            exceeded: false,
        };
        for item in seed {
            collector.account(item.address);
            for key in &item.storage_keys {
                collector.storage(item.address, *key);
            }
        }
        collector
    }

    fn account(&mut self, address: Address) {
        let address = *address.as_bytes();
        if self.exceeded || self.excluded.contains(&address) || self.entries.contains_key(&address)
        {
            return;
        }
        if self.entries.len() >= shell_core::MAX_ACCESS_LIST_ENTRIES {
            self.exceeded = true;
            return;
        }
        self.entries.insert(address, BTreeSet::new());
    }

    fn storage(&mut self, address: Address, key: ShellHash) {
        let address = *address.as_bytes();
        let key = *key.as_bytes();
        if self.exceeded {
            return;
        }
        if !self.entries.contains_key(&address)
            && self.entries.len() >= shell_core::MAX_ACCESS_LIST_ENTRIES
        {
            self.exceeded = true;
            return;
        }
        let keys = self.entries.entry(address).or_default();
        if !keys.contains(&key) && keys.len() >= shell_core::MAX_ACCESS_LIST_STORAGE_KEYS {
            self.exceeded = true;
            return;
        }
        keys.insert(key);
    }

    pub(crate) fn finish(self) -> Result<Vec<shell_core::AccessListItem>, String> {
        if self.exceeded {
            return Err("generated access list exceeds transaction access-list limits".into());
        }
        Ok(self
            .entries
            .into_iter()
            .map(|(address, keys)| shell_core::AccessListItem {
                address: Address::from(address),
                storage_keys: keys.into_iter().map(ShellHash::from).collect(),
            })
            .collect())
    }
}

/// Captures actual interpreter events without changing execution outcomes.
pub(crate) struct ExecutionTracer {
    config: TraceConfig,
    pub(crate) accesses: Option<AccessListCollector>,
    pub roots: Vec<CallFrame>,
    frames: Vec<CallFrame>,
    pub steps: Vec<OpcodeTrace>,
    bytes: usize,
    pub exceeded: bool,
    current_step: Option<(usize, u8, Option<String>)>,
}

impl ExecutionTracer {
    pub fn new(config: TraceConfig) -> Self {
        Self {
            config,
            accesses: None,
            roots: Vec::new(),
            frames: Vec::new(),
            steps: Vec::new(),
            bytes: 0,
            exceeded: false,
            current_step: None,
        }
    }

    pub(crate) fn for_access_list(seed: &[shell_core::AccessListItem]) -> Self {
        let mut tracer = Self::new(TraceConfig::default());
        tracer.accesses = Some(AccessListCollector::new(seed));
        tracer
    }

    pub(crate) fn exclude_access_list_accounts(
        &mut self,
        accounts: impl IntoIterator<Item = Address>,
    ) {
        if let Some(accesses) = &mut self.accesses {
            accesses
                .excluded
                .extend(accounts.into_iter().map(|address| *address.as_bytes()));
        }
    }

    pub(crate) fn record_native_call(&mut self, frame: CallFrame) {
        if self.accesses.is_some() {
            return;
        }
        let bytes = TRACE_RECORD_OVERHEAD
            .saturating_add(frame.input.len().saturating_mul(2))
            .saturating_add(
                frame
                    .output
                    .as_ref()
                    .map_or(0, |output| output.len().saturating_mul(2)),
            );
        if self.reserve(bytes) {
            self.roots.push(frame);
        }
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        self.bytes = self.bytes.saturating_add(bytes);
        self.exceeded |=
            self.bytes > MAX_TRACE_CAPTURE_BYTES || self.steps.len() >= MAX_TRACE_INSTRUCTIONS;
        !self.exceeded
    }

    fn end(&mut self, result: &InterpreterResult, created: Option<Address>) {
        if !self.reserve(result.output.len().saturating_mul(2)) {
            return;
        }
        let Some(mut frame) = self.frames.pop() else {
            return;
        };
        if let Some(address) = created {
            frame.to = address;
        }
        frame.gas_used = result.gas.spent();
        frame.output = Some(Bytes::from(result.output.to_vec()));
        if !result.result.is_ok() {
            frame.error = Some(if result.result.is_revert() {
                "execution reverted".into()
            } else {
                format!("{:?}", result.result)
            });
            frame.revert_reason = decode_revert_reason(&result.output);
        }
        if let Some(parent) = self.frames.last_mut() {
            parent.calls.push(frame);
        } else {
            self.roots.push(frame);
        }
    }
}

type ExecutionContext<'a, S, C> =
    Context<BlockEnv, TxEnv, CfgEnv, &'a mut ShellStateDb<S>, Journal<&'a mut ShellStateDb<S>>, C>;

impl<S: KvStore + 'static, C> Inspector<ExecutionContext<'_, S, C>> for ExecutionTracer {
    fn call(
        &mut self,
        ctx: &mut ExecutionContext<'_, S, C>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if let Some(accesses) = &mut self.accesses {
            accesses.account(ctx.db().resolve_address(&inputs.bytecode_address));
            return None;
        }
        if !self.reserve(TRACE_RECORD_OVERHEAD + inputs.input.len().saturating_mul(2)) {
            return None;
        }
        let mut frame = CallFrame::new(
            &format!("{:?}", inputs.scheme).to_uppercase(),
            ctx.db()
                .resolve_address(&if inputs.scheme.is_delegate_call() {
                    inputs.target_address
                } else {
                    inputs.caller
                }),
            ctx.db().resolve_address(&inputs.bytecode_address),
            inputs.gas_limit,
            Bytes::from(inputs.input.bytes(ctx).to_vec()),
        );
        frame.value = inputs.transfer_value().or(inputs.apparent_value());
        self.frames.push(frame);
        None
    }

    fn call_end(
        &mut self,
        _ctx: &mut ExecutionContext<'_, S, C>,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        if self.accesses.is_none() {
            self.end(&outcome.result, None);
        }
    }

    fn create(
        &mut self,
        ctx: &mut ExecutionContext<'_, S, C>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        if self.accesses.is_some() {
            return None;
        }
        if !self.reserve(TRACE_RECORD_OVERHEAD + inputs.init_code().len().saturating_mul(2)) {
            return None;
        }
        let kind = match inputs.scheme() {
            revm::context_interface::CreateScheme::Create2 { .. } => "CREATE2",
            _ => "CREATE",
        };
        self.frames.push(
            CallFrame::new(
                kind,
                ctx.db().resolve_address(&inputs.caller()),
                Address::ZERO,
                inputs.gas_limit(),
                Bytes::from(inputs.init_code().to_vec()),
            )
            .with_value(inputs.value()),
        );
        None
    }

    fn create_end(
        &mut self,
        _ctx: &mut ExecutionContext<'_, S, C>,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        if self.accesses.is_none() {
            self.end(&outcome.result, outcome.address.map(Address::from));
        }
    }

    fn step(&mut self, interp: &mut Interpreter, ctx: &mut ExecutionContext<'_, S, C>) {
        if let Some(accesses) = &mut self.accesses {
            let op = interp.bytecode.opcode();
            if let Some(word) = interp.stack.data().last() {
                if matches!(op, SLOAD | SSTORE) {
                    let address = ctx.db().resolve_address(&interp.input.target_address);
                    accesses.storage(address, ShellHash::from(word.to_be_bytes::<32>()));
                } else if matches!(op, 0x31 | 0x3b | 0x3c | 0x3f) {
                    let bytes = word.to_be_bytes::<32>();
                    let address = if ctx.db().native_context_enabled() {
                        Address::from(bytes)
                    } else {
                        ctx.db()
                            .resolve_address(&alloy_primitives::Address::from_slice(&bytes[12..]))
                    };
                    accesses.account(address);
                }
            }
            return;
        }
        self.current_step = None;
        let stack_bytes = if self.config.disable_stack {
            0
        } else {
            interp.stack.len().saturating_mul(ENCODED_STACK_WORD_BUDGET)
        };
        let memory = interp.memory.context_memory();
        let memory_bytes = if self.config.disable_memory {
            0
        } else {
            memory.len().saturating_mul(2)
        };
        if !self.reserve(TRACE_RECORD_OVERHEAD + stack_bytes + memory_bytes) {
            return;
        }
        let op = interp.bytecode.opcode();
        let key = if !self.config.disable_storage && matches!(op, SLOAD | SSTORE) {
            interp.stack.data().last().map(|key| format!("{key:#066x}"))
        } else {
            None
        };
        let storage = if op == SSTORE {
            key.as_ref().and_then(|key| {
                interp.stack.data().iter().rev().nth(1).map(|value| {
                    [(key.clone(), format!("{value:#066x}"))]
                        .into_iter()
                        .collect()
                })
            })
        } else {
            None
        };
        self.current_step = Some((self.steps.len(), op, key));
        self.steps.push(OpcodeTrace {
            pc: interp.bytecode.pc(),
            op: revm::bytecode::opcode::OpCode::new(op)
                .map(|op| op.as_str().to_string())
                .unwrap_or_else(|| format!("0x{op:02x}")),
            gas: interp.gas.remaining(),
            gas_cost: 0,
            depth: self.frames.len(),
            stack: (!self.config.disable_stack).then(|| {
                interp
                    .stack
                    .data()
                    .iter()
                    .map(|v| format!("{v:#066x}"))
                    .collect()
            }),
            memory: (!self.config.disable_memory).then(|| format!("0x{}", hex::encode(&*memory))),
            storage,
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter, _ctx: &mut ExecutionContext<'_, S, C>) {
        let Some((index, op, key)) = self.current_step.take() else {
            return;
        };
        let step = &mut self.steps[index];
        step.gas_cost = step.gas.saturating_sub(interp.gas.remaining());
        if op == SLOAD && interp.bytecode.instruction_result().is_none() {
            if let (Some(key), Some(value)) = (key, interp.stack.data().last()) {
                step.storage = Some([(key, format!("{value:#066x}"))].into_iter().collect());
            }
        }
    }
}
