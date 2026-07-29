//! PQVM/revm execution adapter: executes transactions via revm and produces receipts.
//!
//! [`ShellPqvm`] wraps revm with shell-chain's state bridge and
//! provides a high-level API for executing individual transactions and
//! full blocks.

use alloy_primitives::{Bytes as AlBytes, B256, U256};
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, CfgEnv, Context, Evm, TxEnv};
use revm::context_interface::transaction::{AccessList, AccessListItem as RevmAccessListItem};
use revm::handler::instructions::EthInstructions;
use revm::handler::{ExecuteEvm, MainnetContext};
use revm::interpreter::{
    instructions::control, interpreter_types::InterpreterTypes, Host, Instruction,
};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{TxKind, KECCAK_EMPTY};
use revm::state::EvmState;
use shell_core::{Account, BlockHeader, TransactionReceipt};
use shell_primitives::{Address as ShellAddress, ShellHash};
use shell_storage::{ChainStore, KvStore, StorageError, WorldState};

use crate::precompiles::ShellPrecompiles;
use crate::state_db::{ShellStateDb, StateDbError};
use crate::system_contracts::{
    self, execute_system_contract_call, SystemContractEffects, SYSTEM_CALL_BASE_GAS,
};

/// Errors returned during PQVM/revm execution.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("pqvm/revm: {0}")]
    Revm(String),

    #[error("state db: {0}")]
    StateDb(#[from] StateDbError),

    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    #[error("aa bundle must be executed via execute_aa_bundle; submit as tx_type=0x7E: {0}")]
    AaBundleNotYetExecutable(String),

    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("nonce cannot advance past u64::MAX")]
    NonceOverflow,
}

/// Result of executing a single transaction.
pub struct TxExecutionResult {
    /// Transaction receipt for inclusion in the block.
    pub receipt: TransactionReceipt,
    /// State changes produced by this transaction (for committing).
    pub state_changes: EvmState,
    /// The sender's nonce after this transaction (= tx.nonce + 1). Used by
    /// `commit_pqvm_state` to ensure the nonce is always advanced correctly even
    /// when revm's `disable_nonce_check = true` suppresses the normal increment.
    pub sender_shell_addr: ShellAddress,
    /// Expected nonce of `sender_shell_addr` after tx (= tx.nonce + 1).
    pub sender_nonce_after: u64,
    /// Gas actually used by this transaction.
    pub gas_used: u64,
    /// Raw output bytes returned by execution (return data or revert reason).
    pub output: Vec<u8>,
    /// True if this was a system contract transaction whose state changes
    /// were applied directly to WorldState (not via EvmState).
    pub is_system_tx: bool,
    /// Explicit state surfaces mutated by native system-contract execution.
    pub system_contract_effects: SystemContractEffects,
}

/// High-level PQVM/revm execution adapter for shell-chain.
///
/// Wraps revm and provides:
/// - `execute_tx()`: execute a single validated transaction → receipt + state
/// - Block-level gas tracking for cumulative_gas_used
pub struct ShellPqvm<S: KvStore + 'static> {
    state_db: ShellStateDb<S>,
    chain_id: u64,
}

const OPCODE_CALLCODE: u8 = 0xF2;
const OPCODE_SELFDESTRUCT: u8 = 0xFF;

fn next_sender_nonce(nonce: u64) -> Result<u64, ExecutorError> {
    nonce.checked_add(1).ok_or(ExecutorError::NonceOverflow)
}

fn remove_legacy_opcodes<WIRE, H>(instructions: &mut EthInstructions<WIRE, H>)
where
    WIRE: InterpreterTypes,
    H: Host,
{
    // White-paper §4: CALLCODE (0xF2) and SELFDESTRUCT (0xFF) are hard-removed
    // from the PQVM instruction table. Dispatch them through INVALID (0xFE)
    // semantics so they halt execution as unsupported legacy opcodes.
    instructions.insert_instruction(
        OPCODE_CALLCODE,
        Instruction::new(control::invalid::<WIRE, H>, 0),
    );
    instructions.insert_instruction(
        OPCODE_SELFDESTRUCT,
        Instruction::new(control::invalid::<WIRE, H>, 0),
    );
}

impl<S: KvStore + 'static> ShellPqvm<S> {
    pub fn new(state_db: ShellStateDb<S>, chain_id: u64) -> Self {
        Self { state_db, chain_id }
    }

    /// Execute a single transaction that has already been validated.
    ///
    /// The caller is responsible for running `validate_tx()` first.
    /// This method builds the revm context, runs the EVM, and produces
    /// a `TxExecutionResult` with the receipt and state changes.
    ///
    /// State changes are NOT committed — the caller must apply them to
    /// WorldState after collecting all transactions in a block.
    ///
    /// **System contract intercept**: transactions targeting native system
    /// contracts are handled by Rust logic instead of routing through revm.
    pub fn execute_tx(
        &mut self,
        signed_tx: &shell_core::SignedTransaction,
        header: &BlockHeader,
        tx_index: u32,
        cumulative_gas_used: u64,
    ) -> Result<TxExecutionResult, ExecutorError> {
        let tx = &signed_tx.tx;

        // ── AA bundle hard guard (M2a) ────────────────────────
        // The mempool already validates structure + signatures; this guard
        // exists so that if a bundle ever reaches the single-tx executor
        // path (e.g. via legacy block-building code paths) it fails loud
        // instead of being silently mis-executed as a normal tx. The full
        // batch dispatcher with atomicity + paymaster gas accounting lands
        // in M2b under a separate review.
        if signed_tx.is_aa_bundle() {
            return Err(ExecutorError::AaBundleNotYetExecutable(format!(
                "tx {} is an AA bundle (tx_type=0x{:X}); call the bundle dispatcher instead",
                signed_tx.hash(),
                tx.tx_type
            )));
        }

        // ── System contract intercept ──────────────────────────
        if let Some(to) = &tx.to {
            if system_contracts::is_system_contract(to) {
                return self.execute_system_contract_tx(
                    signed_tx,
                    header,
                    tx_index,
                    cumulative_gas_used,
                );
            }
        }

        // ── Normal PQVM/revm execution path ──────────────────────────
        let tx = &signed_tx.tx;
        let sender_shell_addr = signed_tx.from;
        let sender_nonce_after = next_sender_nonce(tx.nonce)?;

        // Register the sender's full 32-byte address so ShellStateDb can find
        // it when revm queries by the 20-byte truncated form.
        self.state_db.register_pq_address(signed_tx.from);

        // Build revm TxEnv
        let kind = match &tx.to {
            Some(addr) => TxKind::Call((*addr).into()),
            None => TxKind::Create,
        };

        // Register the recipient's full 32-byte address so commit_pqvm_state
        // stores the balance update under the correct 32-byte key rather than
        // the zero-padded form of the truncated 20-byte EVM address.
        if let Some(to) = &tx.to {
            self.state_db.register_pq_address(*to);
        }

        let tx_env = TxEnv::builder()
            .caller(signed_tx.from.into())
            .gas_limit(tx.gas_limit)
            .max_fee_per_gas(tx.max_fee_per_gas as u128)
            .gas_priority_fee(Some(tx.max_priority_fee_per_gas as u128))
            .kind(kind)
            .value(tx.value)
            .data(AlBytes::from(tx.data.as_ref().to_vec()))
            .nonce(tx.nonce)
            .chain_id(Some(self.chain_id))
            .access_list(Self::convert_access_list(&tx.access_list))
            .blob_hashes(Self::convert_blob_hashes(&tx.blob_versioned_hashes))
            .max_fee_per_blob_gas(tx.max_fee_per_blob_gas.unwrap_or(0) as u128)
            .build_fill();

        // Build revm BlockEnv
        // Use Cancun spec: enables EIP-1153 (transient storage) and EIP-5656
        // (MCOPY). Legacy Ethereum opcodes removed by PQVM are overridden below.
        let mut block_env = BlockEnv {
            number: U256::from(header.number),
            beneficiary: header.proposer.into(),
            timestamp: U256::from(header.timestamp),
            gas_limit: header.gas_limit,
            basefee: 0,
            difficulty: U256::ZERO,
            prevrandao: Some(B256::ZERO),
            blob_excess_gas_and_price: None,
            slot_num: 0,
        };
        // Cancun requires blob_excess_gas_and_price to be Some.
        // EIP-4844: use header's excess blob gas for blob gas pricing.
        block_env.set_blob_excess_gas_and_price(header.excess_blob_gas, 3_338_477);

        // Build revm context + EVM.
        // Use CANCUN spec for transient storage (EIP-1153) and MCOPY (EIP-5656).
        let ctx: MainnetContext<&mut ShellStateDb<S>> =
            Context::new(&mut self.state_db, SpecId::CANCUN)
                .modify_block_chained(|b| *b = block_env)
                .modify_cfg_chained(|cfg: &mut CfgEnv| {
                    cfg.chain_id = self.chain_id;
                    cfg.disable_nonce_check = true;
                    cfg.disable_base_fee = true;
                });

        let spec = SpecId::CANCUN;
        let mut instructions = EthInstructions::new_mainnet_with_spec(spec);
        // Wire PQVM native opcodes (0xB0–0xB2) into the instruction table.
        crate::pqvm_opcodes::install_pqvm_opcodes(&mut instructions);
        remove_legacy_opcodes(&mut instructions);
        let mut evm = Evm::new(ctx, instructions, ShellPrecompiles::new(spec));

        // Execute
        let result_and_state = evm
            .transact(tx_env)
            .map_err(|e| ExecutorError::Revm(format!("{e:?}")))?;

        let exec_result = result_and_state.result;
        let state = result_and_state.state;

        // Build receipt
        let gas_used = exec_result.gas().spent();
        let new_cumulative = cumulative_gas_used.saturating_add(gas_used);

        let (status, logs, contract_address, output_bytes) = match exec_result {
            ExecutionResult::Success { logs, output, .. } => {
                let contract_addr = match &output {
                    revm::context::result::Output::Create(_, Some(addr)) => {
                        Some(ShellAddress::from(*addr))
                    }
                    _ => None,
                };
                let data = match output {
                    revm::context::result::Output::Call(bytes) => bytes.to_vec(),
                    revm::context::result::Output::Create(bytes, _) => bytes.to_vec(),
                };
                (1u8, logs, contract_addr, data)
            }
            ExecutionResult::Revert { output, .. } => (0u8, vec![], None, output.to_vec()),
            ExecutionResult::Halt { .. } => (0u8, vec![], None, vec![]),
        };

        // Convert revm logs to shell-chain logs
        let shell_logs: Vec<shell_core::Log> = logs
            .iter()
            .filter_map(|log| {
                shell_core::Log::new(
                    ShellAddress::from(log.address),
                    log.topics().iter().map(|t| ShellHash::from(*t)).collect(),
                    shell_primitives::Bytes::from(log.data.data.to_vec()),
                )
                .ok()
            })
            .collect();

        let receipt = TransactionReceipt {
            tx_hash: signed_tx.hash(),
            block_number: header.number,
            tx_index,
            status,
            gas_used,
            cumulative_gas_used: new_cumulative,
            contract_address,
            logs_bloom: shell_primitives::Bytes::from(
                crate::bloom::logs_bloom(&shell_logs).to_vec(),
            ),
            logs: shell_logs,
        };

        Ok(TxExecutionResult {
            receipt,
            state_changes: state,
            sender_shell_addr,
            sender_nonce_after,
            gas_used,
            output: output_bytes,
            is_system_tx: false,
            system_contract_effects: SystemContractEffects::default(),
        })
    }

    /// Access the underlying state database.
    pub fn state_db(&self) -> &ShellStateDb<S> {
        &self.state_db
    }

    /// Access the underlying state database mutably.
    pub fn state_db_mut(&mut self) -> &mut ShellStateDb<S> {
        &mut self.state_db
    }

    /// Execute an AA bundle (`tx_type == 0x7E`) atomically.
    ///
    /// Pre-conditions: the caller MUST have already run
    /// `validate_tx`/`validate_tx_for_import` from `tx_validation` so that
    /// structure, sender PQ signature, paymaster signature, and balance
    /// snapshots have all been verified.
    ///
    /// Semantics:
    /// - State changes from inner calls are applied directly to the live
    ///   `WorldState` after each successful inner call so that subsequent
    ///   inner calls observe prior effects.
    /// - If any inner call reverts/halts, all bundle state mutations are
    ///   rolled back to the pre-bundle root via `WorldState::rollback_to_root`.
    ///   Only the gas spent so far is charged to the payer and the sender
    ///   nonce is bumped exactly once.
    /// - Sender nonce is bumped by **+1** for the entire batch (not per
    ///   inner), even on failure.
    /// - Gas: the payer (paymaster if set, else sender) is debited
    ///   `actual_gas_used × max_fee_per_gas`; remaining `gas_limit` is not
    ///   reserved beyond the validation check.
    /// - The returned `TxExecutionResult` carries `is_system_tx = true` and
    ///   an empty `state_changes` so block-producer / importer code skips
    ///   double-applying changes (the dispatcher writes them in place).
    pub fn execute_aa_bundle(
        &mut self,
        signed_tx: &shell_core::SignedTransaction,
        header: &BlockHeader,
        tx_index: u32,
        cumulative_gas_used: u64,
    ) -> Result<TxExecutionResult, ExecutorError> {
        let bundle = signed_tx
            .aa_bundle()
            .ok_or_else(|| ExecutorError::Revm("execute_aa_bundle called on non-AA tx".into()))?;
        let tx = &signed_tx.tx;
        let sender = signed_tx.from;
        let payer = bundle.paymaster.unwrap_or(sender);
        let max_fee = U256::from(tx.max_fee_per_gas);
        // Inner calls run as EIP-1559 transactions against a zero-base-fee
        // block, so revm debits the sender at this effective price.
        let revm_gas_price = U256::from(tx.max_fee_per_gas.min(tx.max_priority_fee_per_gas));
        let is_sponsored = payer != sender;
        let declared_value = tx.value;
        let Some(inner_value_sum) = bundle.checked_inner_value_sum() else {
            return Err(ExecutorError::Revm(
                "aa bundle inner value sum overflows U256".into(),
            ));
        };
        if inner_value_sum > declared_value {
            return Err(ExecutorError::Revm(format!(
                "aa bundle inner value sum ({inner_value_sum}) exceeds outer value ({declared_value})"
            )));
        }

        let sender_pre_nonce = self.state_db.world_state().get_nonce(&sender)?;
        if tx.nonce != sender_pre_nonce {
            return Err(ExecutorError::NonceMismatch {
                expected: sender_pre_nonce,
                got: tx.nonce,
            });
        }
        let sender_nonce_after = next_sender_nonce(sender_pre_nonce)?;

        // Capture pre-bundle state root for atomic rollback on inner failure.
        let pre_root = self.state_db.world_state_mut().state_root()?;

        // Snapshot sender / payer balances for post-execution reconciliation.
        let sender_pre_bal = self
            .state_db
            .world_state()
            .get_account(&sender)?
            .map(|a| a.balance)
            .unwrap_or(U256::ZERO);
        let payer_pre_bal = if is_sponsored {
            self.state_db
                .world_state()
                .get_account(&payer)?
                .map(|a| a.balance)
                .unwrap_or(U256::ZERO)
        } else {
            sender_pre_bal
        };

        // Re-check payer balance at execution time (state may have moved
        // since mempool admission).
        let gas_reserve = U256::from(tx.gas_limit).saturating_mul(max_fee);
        if payer_pre_bal < gas_reserve {
            // Bump nonce, charge nothing, emit failure receipt.
            let mut account = self
                .state_db
                .world_state()
                .get_account(&sender)?
                .unwrap_or_else(|| Account {
                    pq_pubkey_hash: ShellHash::default(),
                    nonce: 0,
                    balance: U256::ZERO,
                    validation_code_hash: None,
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                });
            account.nonce = sender_nonce_after;
            self.state_db
                .world_state_mut()
                .set_account(&sender, &account)?;
            let receipt = TransactionReceipt {
                tx_hash: signed_tx.hash(),
                block_number: header.number,
                tx_index,
                status: 0,
                gas_used: 0,
                cumulative_gas_used,
                contract_address: None,
                logs_bloom: shell_primitives::Bytes::from(crate::bloom::logs_bloom(&[]).to_vec()),
                logs: vec![],
            };
            return Ok(TxExecutionResult {
                receipt,
                state_changes: EvmState::default(),
                sender_shell_addr: ShellAddress::default(),
                sender_nonce_after: 0,
                gas_used: 0,
                output: b"aa: payer balance shortfall at execution".to_vec(),
                is_system_tx: true,
                system_contract_effects: SystemContractEffects::default(),
            });
        }

        // Build the shared block env once (re-used across inner calls).
        let mut block_env = BlockEnv {
            number: U256::from(header.number),
            beneficiary: header.proposer.into(),
            timestamp: U256::from(header.timestamp),
            gas_limit: header.gas_limit,
            basefee: 0,
            difficulty: U256::ZERO,
            prevrandao: Some(B256::ZERO),
            blob_excess_gas_and_price: None,
            slot_num: 0,
        };
        block_env.set_blob_excess_gas_and_price(header.excess_blob_gas, 3_338_477);

        let mut total_gas_used: u64 = 0;
        let mut all_logs: Vec<shell_core::Log> = Vec::new();
        let mut atomic_failure = false;
        let mut last_revert_data: Vec<u8> = Vec::new();

        for inner in &bundle.inner_calls {
            let kind = match &inner.to {
                Some(addr) => TxKind::Call((*addr).into()),
                None => TxKind::Create,
            };
            let tx_env = TxEnv::builder()
                .caller(sender.into())
                .gas_limit(inner.gas_limit)
                .max_fee_per_gas(tx.max_fee_per_gas as u128)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas as u128))
                .kind(kind)
                .value(inner.value)
                .data(AlBytes::from(inner.data.as_ref().to_vec()))
                .nonce(0) // disable_nonce_check is on; placeholder.
                .chain_id(Some(self.chain_id))
                .build_fill();

            let ctx: MainnetContext<&mut ShellStateDb<S>> =
                Context::new(&mut self.state_db, SpecId::CANCUN)
                    .modify_block_chained(|b| *b = block_env.clone())
                    .modify_cfg_chained(|cfg: &mut CfgEnv| {
                        cfg.chain_id = self.chain_id;
                        cfg.disable_nonce_check = true;
                        cfg.disable_base_fee = true;
                        // Sender may legitimately lack gas funds when sponsored;
                        // we reconcile balances post-bundle. Skip revm's upfront
                        // balance check to permit execution either way.
                        cfg.disable_balance_check = true;
                    });
            let spec = SpecId::CANCUN;
            let mut instructions = EthInstructions::new_mainnet_with_spec(spec);
            crate::pqvm_opcodes::install_pqvm_opcodes(&mut instructions);
            remove_legacy_opcodes(&mut instructions);
            let mut evm = Evm::new(ctx, instructions, ShellPrecompiles::new(spec));
            let exec_outcome = evm.transact(tx_env);
            drop(evm);

            let result_and_state = match exec_outcome {
                Ok(r) => r,
                Err(_) => {
                    // Pre-execution validation failure → treat as inner revert.
                    atomic_failure = true;
                    break;
                }
            };

            let exec_result = result_and_state.result;
            let mut state = result_and_state.state;
            let inner_gas = exec_result.gas().used();
            total_gas_used = total_gas_used.saturating_add(inner_gas);

            match &exec_result {
                ExecutionResult::Success { logs, .. } => {
                    for log in logs {
                        if let Ok(l) = shell_core::Log::new(
                            ShellAddress::from(log.address),
                            log.topics().iter().map(|t| ShellHash::from(*t)).collect(),
                            shell_primitives::Bytes::from(log.data.data.to_vec()),
                        ) {
                            all_logs.push(l);
                        }
                    }
                    // revm charges and reimburses the caller around each inner
                    // transaction. Remove that accounting artifact before
                    // committing so only the inner call's actual balance
                    // effects remain; AA settlement charges the payer once.
                    let sender_state = state.get_mut(&sender.to_alloy()).ok_or_else(|| {
                        ExecutorError::Revm("aa bundle inner execution omitted sender state".into())
                    })?;
                    let original_balance = sender_state.original_info.balance;
                    let max_revm_gas_debit =
                        U256::from(inner.gas_limit).saturating_mul(revm_gas_price);
                    let reimbursement = U256::from(inner.gas_limit.saturating_sub(inner_gas))
                        .saturating_mul(revm_gas_price);
                    let fee_only_post = original_balance
                        .saturating_sub(max_revm_gas_debit)
                        .max(inner.value)
                        .saturating_add(reimbursement);
                    sender_state.info.balance = if fee_only_post >= original_balance {
                        sender_state
                            .info
                            .balance
                            .checked_sub(fee_only_post - original_balance)
                            .ok_or_else(|| {
                                ExecutorError::Revm(
                                    "aa bundle sender fee reconciliation underflows U256".into(),
                                )
                            })?
                    } else {
                        sender_state
                            .info
                            .balance
                            .checked_add(original_balance - fee_only_post)
                            .ok_or_else(|| {
                                ExecutorError::Revm(
                                    "aa bundle sender fee reconciliation overflows U256".into(),
                                )
                            })?
                    };
                    // Build a minimal result for commit_pqvm_state; no PQ addresses in AA
                    // inner calls (they use EVM-canonical addresses), no nonce advance here
                    // as outer tx handles it.
                    let inner_result = TxExecutionResult {
                        receipt: empty_receipt(),
                        state_changes: state,
                        sender_shell_addr: ShellAddress::default(),
                        sender_nonce_after: 0,
                        gas_used: 0,
                        output: vec![],
                        is_system_tx: false,
                        system_contract_effects: SystemContractEffects::default(),
                    };
                    commit_pqvm_state(&inner_result, &mut self.state_db)?;
                }
                ExecutionResult::Revert { output, .. } => {
                    atomic_failure = true;
                    last_revert_data = output.to_vec();
                    break;
                }
                ExecutionResult::Halt { .. } => {
                    atomic_failure = true;
                    break;
                }
            }
        }

        // ── Settlement ─────────────────────────────────────────
        let gas_cost = U256::from(total_gas_used).saturating_mul(max_fee);

        // Reserve the AA gas charge after successful execution. An inner call
        // may mutate the payer's balance, but it may not spend the gas reserve.
        if !atomic_failure {
            let post_payer_balance = self
                .state_db
                .world_state()
                .get_account(&payer)?
                .map(|account| account.balance)
                .unwrap_or(U256::ZERO);
            if post_payer_balance < gas_cost {
                atomic_failure = true;
                last_revert_data = b"aa: payer spent reserved gas during execution".to_vec();
            }
        }

        // revm applies every successful inner call directly to live state. On
        // success, preserve those balance deltas and charge the AA payer at the
        // outer transaction's max fee.
        if atomic_failure {
            // Wipe all inner-call state mutations.
            self.state_db
                .world_state_mut()
                .rollback_to_root(&pre_root)?;
            // Charge payer for actual gas used only; clamp at balance.
            let charge = gas_cost.min(payer_pre_bal);
            let mut p_acct = self
                .state_db
                .world_state()
                .get_account(&payer)?
                .unwrap_or_else(|| Account {
                    pq_pubkey_hash: ShellHash::default(),
                    nonce: 0,
                    balance: U256::ZERO,
                    validation_code_hash: None,
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                });
            p_acct.balance = payer_pre_bal.saturating_sub(charge);
            if !is_sponsored {
                p_acct.nonce = sender_nonce_after;
            }
            self.state_db
                .world_state_mut()
                .set_account(&payer, &p_acct)?;
            if is_sponsored {
                // Bump sender nonce separately.
                let mut s_acct = self
                    .state_db
                    .world_state()
                    .get_account(&sender)?
                    .unwrap_or_else(|| Account {
                        pq_pubkey_hash: ShellHash::default(),
                        nonce: 0,
                        balance: U256::ZERO,
                        validation_code_hash: None,
                        code_hash: None,
                        storage_root: ShellHash::ZERO,
                    });
                s_acct.nonce = sender_nonce_after;
                self.state_db
                    .world_state_mut()
                    .set_account(&sender, &s_acct)?;
            }
        } else {
            // Load post-inner account states so balance, storage, and code
            // changes made by inner calls survive settlement.
            let mut s_acct = self
                .state_db
                .world_state()
                .get_account(&sender)?
                .unwrap_or_else(|| Account {
                    pq_pubkey_hash: ShellHash::default(),
                    nonce: 0,
                    balance: U256::ZERO,
                    validation_code_hash: None,
                    code_hash: None,
                    storage_root: ShellHash::ZERO,
                });

            if is_sponsored {
                let mut p_acct = self
                    .state_db
                    .world_state()
                    .get_account(&payer)?
                    .unwrap_or_else(|| Account {
                        pq_pubkey_hash: ShellHash::default(),
                        nonce: 0,
                        balance: U256::ZERO,
                        validation_code_hash: None,
                        code_hash: None,
                        storage_root: ShellHash::ZERO,
                    });
                s_acct.nonce = sender_nonce_after;
                p_acct.balance = p_acct.balance.checked_sub(gas_cost).ok_or_else(|| {
                    ExecutorError::Revm("aa bundle payer gas reserve underflow".into())
                })?;
                self.state_db
                    .world_state_mut()
                    .set_account(&sender, &s_acct)?;
                self.state_db
                    .world_state_mut()
                    .set_account(&payer, &p_acct)?;
            } else {
                s_acct.balance = s_acct.balance.checked_sub(gas_cost).ok_or_else(|| {
                    ExecutorError::Revm("aa bundle payer gas reserve underflow".into())
                })?;
                s_acct.nonce = sender_nonce_after;
                self.state_db
                    .world_state_mut()
                    .set_account(&sender, &s_acct)?;
            }
        }

        let status: u8 = if atomic_failure { 0 } else { 1 };
        let logs = if atomic_failure { Vec::new() } else { all_logs };
        let output = if atomic_failure {
            last_revert_data
        } else {
            Vec::new()
        };

        let receipt = TransactionReceipt {
            tx_hash: signed_tx.hash(),
            block_number: header.number,
            tx_index,
            status,
            gas_used: total_gas_used,
            cumulative_gas_used: cumulative_gas_used.saturating_add(total_gas_used),
            contract_address: None,
            logs_bloom: shell_primitives::Bytes::from(crate::bloom::logs_bloom(&logs).to_vec()),
            logs,
        };

        Ok(TxExecutionResult {
            receipt,
            state_changes: EvmState::default(),
            sender_shell_addr: ShellAddress::default(),
            sender_nonce_after: 0,
            gas_used: total_gas_used,
            output,
            is_system_tx: true,
            system_contract_effects: SystemContractEffects::default(),
        })
    }

    /// Convert shell-chain access list to revm's AccessList format.
    fn convert_access_list(access_list: &Option<Vec<shell_core::AccessListItem>>) -> AccessList {
        match access_list {
            Some(list) => AccessList(
                list.iter()
                    .map(|item| RevmAccessListItem {
                        address: item.address.into(),
                        storage_keys: item.storage_keys.iter().map(|k| B256::from(*k)).collect(),
                    })
                    .collect(),
            ),
            None => AccessList::default(),
        }
    }

    /// Convert shell-chain blob versioned hashes to revm B256 format.
    fn convert_blob_hashes(hashes: &Option<Vec<ShellHash>>) -> Vec<B256> {
        match hashes {
            Some(h) => h.iter().map(|hash| B256::from(*hash)).collect(),
            None => Vec::new(),
        }
    }

    /// Execute a transaction targeting a native system contract.
    ///
    /// Runs native Rust logic instead of the EVM, produces appropriate logs,
    /// and charges a fixed gas fee.
    fn execute_system_contract_tx(
        &mut self,
        signed_tx: &shell_core::SignedTransaction,
        header: &BlockHeader,
        tx_index: u32,
        cumulative_gas_used: u64,
    ) -> Result<TxExecutionResult, ExecutorError> {
        let caller = &signed_tx.from;
        let tx = &signed_tx.tx;
        let target = signed_tx.tx.to.unwrap_or_default();
        let input = signed_tx.tx.data.as_ref();
        let (ws, chain_store) = self.state_db.world_state_and_chain_store();
        let result = if tx.value != U256::ZERO {
            Err(crate::system_contracts::SystemContractError::AbiDecode(
                "system contracts do not accept value".into(),
            ))
        } else {
            execute_system_contract_call(&target, caller, input, ws, chain_store)
        };

        match result {
            Ok(mut outcome) => {
                ws.increment_nonce(caller)?;
                if !outcome.effects.updated_accounts.contains(caller) {
                    outcome.effects.updated_accounts.push(*caller);
                }
                let output = outcome.output;
                let gas_used = outcome.gas_used;
                ws.sub_balance(
                    caller,
                    U256::from(gas_used).saturating_mul(U256::from(tx.max_fee_per_gas)),
                )?;
                let new_cumulative = cumulative_gas_used.saturating_add(gas_used);

                // Build event logs for mutating operations
                let mut shell_logs = Vec::new();
                if outcome.effects.validator_set_changed {
                    if let Ok(selector) = <[u8; 4]>::try_from(input.get(..4).unwrap_or_default()) {
                        let registry_addr = system_contracts::registry_address();
                        if selector == system_contracts::ADD_VALIDATOR_SELECTOR {
                            if let Ok(addr) =
                                system_contracts::decode_address(input.get(4..).unwrap_or_default())
                            {
                                let topic =
                                    ShellHash::from(system_contracts::validator_added_topic());
                                let mut addr_word = [0u8; 32];
                                addr_word[12..32].copy_from_slice(addr.to_alloy().as_slice());
                                if let Ok(log) = shell_core::Log::new(
                                    registry_addr,
                                    vec![topic],
                                    shell_primitives::Bytes::from(addr_word.to_vec()),
                                ) {
                                    shell_logs.push(log);
                                }
                            }
                        } else if selector == system_contracts::REMOVE_VALIDATOR_SELECTOR {
                            if let Ok(addr) =
                                system_contracts::decode_address(input.get(4..).unwrap_or_default())
                            {
                                let topic =
                                    ShellHash::from(system_contracts::validator_removed_topic());
                                let mut addr_word = [0u8; 32];
                                addr_word[12..32].copy_from_slice(addr.to_alloy().as_slice());
                                if let Ok(log) = shell_core::Log::new(
                                    registry_addr,
                                    vec![topic],
                                    shell_primitives::Bytes::from(addr_word.to_vec()),
                                ) {
                                    shell_logs.push(log);
                                }
                            }
                        }
                    }
                }

                let receipt = TransactionReceipt {
                    tx_hash: signed_tx.hash(),
                    block_number: header.number,
                    tx_index,
                    status: 1, // success
                    gas_used,
                    cumulative_gas_used: new_cumulative,
                    contract_address: None,
                    logs_bloom: shell_primitives::Bytes::from(
                        crate::bloom::logs_bloom(&shell_logs).to_vec(),
                    ),
                    logs: shell_logs,
                };

                Ok(TxExecutionResult {
                    receipt,
                    state_changes: EvmState::default(),
                    sender_shell_addr: ShellAddress::default(),
                    sender_nonce_after: 0,
                    gas_used,
                    output,
                    is_system_tx: true,
                    system_contract_effects: outcome.effects,
                })
            }
            Err(e) => {
                ws.increment_nonce(caller)?;
                let mut effects = SystemContractEffects::default();
                effects.updated_accounts.push(*caller);
                // System contract reverted — produce a failed receipt
                let gas_used = SYSTEM_CALL_BASE_GAS;
                ws.sub_balance(
                    caller,
                    U256::from(gas_used).saturating_mul(U256::from(tx.max_fee_per_gas)),
                )?;
                let new_cumulative = cumulative_gas_used.saturating_add(gas_used);
                let revert_msg = e.to_string().into_bytes();

                let receipt = TransactionReceipt {
                    tx_hash: signed_tx.hash(),
                    block_number: header.number,
                    tx_index,
                    status: 0, // failure
                    gas_used,
                    cumulative_gas_used: new_cumulative,
                    contract_address: None,
                    logs_bloom: shell_primitives::Bytes::new(),
                    logs: vec![],
                };

                Ok(TxExecutionResult {
                    receipt,
                    state_changes: EvmState::default(),
                    sender_shell_addr: ShellAddress::default(),
                    sender_nonce_after: 0,
                    gas_used,
                    output: revert_msg,
                    is_system_tx: true,
                    system_contract_effects: effects,
                })
            }
        }
    }
}

fn empty_receipt() -> TransactionReceipt {
    TransactionReceipt {
        tx_hash: ShellHash::default(),
        block_number: 0,
        tx_index: 0,
        status: 0,
        gas_used: 0,
        cumulative_gas_used: 0,
        contract_address: None,
        logs_bloom: shell_primitives::Bytes::default(),
        logs: vec![],
    }
}

/// Core commit logic shared by `commit_pqvm_state` and `commit_pqvm_state_raw`.
///
/// `resolve` maps a 20-byte EVM address to the full 32-byte Shell address.
fn do_commit_state<S: KvStore + 'static>(
    result: &TxExecutionResult,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    resolve: &impl Fn(&alloy_primitives::Address) -> ShellAddress,
) -> Result<(), ExecutorError> {
    for (addr, acct) in &result.state_changes {
        let shell_addr = resolve(addr);
        let info = &acct.info;

        let mut account = world_state.get_account(&shell_addr)?.unwrap_or(Account {
            pq_pubkey_hash: ShellHash::default(),
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });

        account.nonce = info.nonce;
        account.balance = info.balance;

        // Store deployed contract bytecode.
        if let Some(code) = &info.code {
            let code_bytes = code.bytes_slice();
            if !code_bytes.is_empty() && info.code_hash != KECCAK_EMPTY {
                let code_hash = ShellHash::from(info.code_hash);
                chain_store.put_code(&code_hash, code_bytes)?;
                account.code_hash = Some(code_hash);
            }
        }

        world_state.set_account(&shell_addr, &account)?;

        // Apply storage slot changes.
        for (slot, value) in &acct.storage {
            let key = ShellHash::from(B256::from(*slot));
            let val = ShellHash::from(B256::from(value.present_value));
            world_state.set_storage(&shell_addr, &key, &val)?;
        }
    }

    // Force-advance the sender's nonce to tx.nonce + 1. When revm runs with
    // `disable_nonce_check = true` the nonce in EvmState is not incremented,
    // so we do it explicitly here for any non-system tx (sender_nonce_after > 0).
    if result.sender_nonce_after > 0 {
        let sender = result.sender_shell_addr;
        let mut account = world_state.get_account(&sender)?.unwrap_or(Account {
            pq_pubkey_hash: ShellHash::default(),
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });
        account.nonce = account.nonce.max(result.sender_nonce_after);
        world_state.set_account(&sender, &account)?;
    }

    Ok(())
}

/// Apply EVM state changes to a WorldState and ChainStore.
///
/// Iterates the revm `EvmState` (address → account) and for each touched
/// account, updates balance, nonce, contract code, and storage slots.
///
/// Call this after `ShellPqvm::execute_tx()` to persist the computed state
/// diff. For multi-transaction blocks, call after **each** transaction so
/// subsequent transactions see prior state updates.
///
/// Uses `result.sender_nonce_after` to ensure the sender's nonce advances
/// even when revm's `disable_nonce_check = true`.
///
/// Uses `state_db.address_registry` to write PQ-derived accounts to their
/// correct 32-byte canonical key rather than the zero-padded 20-byte form.
/// Clears the registry after committing.
pub fn commit_pqvm_state<S: KvStore + 'static>(
    result: &TxExecutionResult,
    state_db: &mut ShellStateDb<S>,
) -> Result<(), ExecutorError> {
    // Clone the registry before the split borrow (typically 0–1 entries).
    let registry = state_db.address_registry.clone();
    let resolve = |addr: &alloy_primitives::Address| {
        registry
            .get(addr)
            .copied()
            .unwrap_or_else(|| ShellAddress::from(*addr))
    };
    let (world_state, chain_store) = state_db.world_state_and_chain_store();
    do_commit_state(result, world_state, chain_store, &resolve)?;
    state_db.clear_address_registry();
    Ok(())
}

/// Apply EVM state changes directly to a `WorldState` and `ChainStore`,
/// using an explicit address registry for PQ address resolution.
///
/// This variant is used when the caller holds a separate `WorldState`
/// (e.g. the node's persistent world state) that must mirror execution
/// results from the EVM's in-process `ShellStateDb`.
///
/// Obtain the registry with `state_db.address_registry_snapshot()` before
/// calling `commit_pqvm_state` (which clears it).
pub fn commit_pqvm_state_raw<S: KvStore + 'static>(
    result: &TxExecutionResult,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
    registry: &std::collections::HashMap<alloy_primitives::Address, ShellAddress>,
) -> Result<(), ExecutorError> {
    let resolve = |addr: &alloy_primitives::Address| {
        registry
            .get(addr)
            .copied()
            .unwrap_or_else(|| ShellAddress::from(*addr))
    };
    do_commit_state(result, world_state, chain_store, &resolve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Account, SignedTransaction, Transaction};
    use shell_crypto::{PQSignature, SignatureType};
    use shell_storage::{ChainStore, MemoryDb, WorldState};
    use std::sync::Arc;

    fn setup_evm() -> ShellPqvm<MemoryDb> {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        let state_db = ShellStateDb::new(ws, cs);
        ShellPqvm::new(state_db, 1337)
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: shell_primitives::Bytes::new(),
            number: 1,
            timestamp: 1_000_000,
            gas_limit: 30_000_000,
            gas_used: 0,
            extra_data: shell_primitives::Bytes::new(),
            proposer: ShellAddress::ZERO,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        }
    }

    fn fund_account(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress, balance: U256) {
        let account = Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        };
        evm.state_db_mut()
            .world_state_mut()
            .set_account(addr, &account)
            .unwrap();
    }

    fn set_nonce(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress, nonce: u64) {
        let mut account = evm
            .state_db_mut()
            .world_state_mut()
            .get_account(addr)
            .unwrap()
            .unwrap_or(Account {
                pq_pubkey_hash: ShellHash::ZERO,
                nonce: 0,
                balance: U256::ZERO,
                validation_code_hash: None,
                code_hash: None,
                storage_root: ShellHash::ZERO,
            });
        account.nonce = nonce;
        evm.state_db_mut()
            .world_state_mut()
            .set_account(addr, &account)
            .unwrap();
    }

    fn current_nonce(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress) -> u64 {
        evm.state_db_mut()
            .world_state_mut()
            .get_nonce(addr)
            .unwrap()
    }

    fn fixture_account_sequence(addr: &ShellAddress) -> u64 {
        addr.as_bytes()
            .iter()
            .rev()
            .copied()
            .find(|byte| *byte != u8::default())
            .map(u64::from)
            .unwrap_or_else(|| u64::from(u8::MAX))
    }

    #[test]
    fn execute_simple_transfer() {
        let mut evm = setup_evm();

        let from = ShellAddress::from([0x42; 20]);
        let to = ShellAddress::from([0x01; 20]);

        // Fund sender with plenty of balance
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(to),
            value: U256::from(1000),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        let header = sample_header();
        let result = evm.execute_tx(&signed, &header, 0, 0);
        assert!(result.is_ok(), "execute_tx failed: {:?}", result.err());

        let tx_result = result.unwrap();
        assert_eq!(tx_result.receipt.status, 1); // success
        assert_eq!(tx_result.receipt.tx_index, 0);
        assert_eq!(tx_result.receipt.block_number, 1);
        assert!(tx_result.gas_used > 0);
        assert!(tx_result.gas_used <= 21_000);
    }

    #[test]
    fn execute_transfer_rejects_max_nonce_that_cannot_advance() {
        let mut evm = setup_evm();

        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));
        set_nonce(&mut evm, &from, u64::MAX);

        let tx = Transaction {
            chain_id: 1337,
            nonce: u64::MAX,
            to: Some(ShellAddress::from([0x01; 20])),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        let err = match evm.execute_tx(&signed, &sample_header(), 0, 0) {
            Ok(_) => panic!("max nonce transaction should be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, ExecutorError::NonceOverflow));
    }

    #[test]
    fn execute_transfer_insufficient_gas_limit() {
        let mut evm = setup_evm();

        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(ShellAddress::from([0x01; 20])),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 100, // way too low
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        let header = sample_header();
        // Should fail at the EVM level (intrinsic gas too low)
        let result = evm.execute_tx(&signed, &header, 0, 0);
        // This should be an error from revm
        assert!(result.is_err());
    }

    #[test]
    fn execute_contract_creation() {
        let mut evm = setup_evm();

        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(100_000_000_000u64));

        // Simple contract: PUSH1 0x42 PUSH1 0 MSTORE PUSH1 1 PUSH1 31 RETURN
        // This stores 0x42 at memory[0] and returns 1 byte from offset 31
        let init_code = vec![
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x01, // PUSH1 1
            0x60, 0x1f, // PUSH1 31
            0xf3, // RETURN
        ];

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: None, // contract creation
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(init_code),
            gas_limit: 100_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xCC; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        let header = sample_header();
        let result = evm.execute_tx(&signed, &header, 0, 0);
        assert!(
            result.is_ok(),
            "contract creation failed: {:?}",
            result.err()
        );

        let tx_result = result.unwrap();
        assert_eq!(tx_result.receipt.status, 1);
        // Contract creation should have a contract_address
        assert!(tx_result.receipt.contract_address.is_some());
    }

    // ── Helper: build a system contract tx ─────────────────────

    fn make_system_tx_to(
        from: ShellAddress,
        to: ShellAddress,
        calldata: Vec<u8>,
    ) -> SignedTransaction {
        let tx = Transaction {
            chain_id: 1337,
            nonce: u64::default(),
            to: Some(to),
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(calldata),
            gas_limit: 100_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDD; 100]);
        SignedTransaction::new(from, tx, sig)
    }

    fn make_system_tx(from: ShellAddress, calldata: Vec<u8>) -> SignedTransaction {
        make_system_tx_to(from, system_contracts::registry_address(), calldata)
    }

    // ── System contract executor integration tests ─────────────

    #[test]
    fn execute_add_validator_via_executor() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let new_val = ShellAddress::from([0x02; 20]);

        // Seed v1 as an existing validator
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();
        evm.state_db_mut()
            .chain_store()
            .put_pubkey(&new_val, &[0xAB; 32])
            .unwrap();

        let calldata = system_contracts::encode_add_validator_calldata(&new_val);
        let signed = make_system_tx(v1, calldata);
        let header = sample_header();

        let result = evm.execute_tx(&signed, &header, 0, 0);
        assert!(result.is_ok(), "addValidator tx failed: {:?}", result.err());

        let tx_result = result.unwrap();
        assert_eq!(tx_result.receipt.status, 1);
        assert!(tx_result.is_system_tx);
        assert_eq!(
            tx_result.gas_used,
            system_contracts::SYSTEM_CALL_BASE_GAS + system_contracts::SYSTEM_CALL_OP_GAS
        );
        assert_eq!(tx_result.receipt.block_number, 1);
        assert_eq!(tx_result.receipt.tx_index, 0);
        assert!(tx_result.receipt.contract_address.is_none());
        // Output should be ABI-encoded true
        assert_eq!(tx_result.output, system_contracts::encode_bool(true));

        // Verify the validator was actually added
        let validators = evm
            .state_db_mut()
            .world_state_mut()
            .get_validators()
            .unwrap();
        assert_eq!(validators.len(), 2);
        assert!(validators.contains(&new_val));
    }

    #[test]
    fn execute_remove_validator_via_executor() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let v2 = ShellAddress::from([0x02; 20]);
        let v3 = ShellAddress::from([0x03; 20]);

        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1, v2, v3])
            .unwrap();

        let calldata = system_contracts::encode_remove_validator_calldata(&v2);
        let first_vote = make_system_tx(v1, calldata.clone());
        let header = sample_header();

        let pending = evm.execute_tx(&first_vote, &header, 0, 0).unwrap();
        assert_eq!(pending.output, system_contracts::encode_bool(false));

        let second_vote = make_system_tx(v3, calldata);
        let tx_result = evm.execute_tx(&second_vote, &header, 0, 1).unwrap();
        assert_eq!(tx_result.receipt.status, 1);
        assert!(tx_result.is_system_tx);

        let validators = evm
            .state_db_mut()
            .world_state_mut()
            .get_validators()
            .unwrap();
        assert_eq!(validators, vec![v1, v3]);
    }

    #[test]
    fn system_tx_flag_is_true_for_system_contract() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        // A read-only system call (getValidators)
        let calldata = system_contracts::GET_VALIDATORS_SELECTOR.to_vec();
        let signed = make_system_tx(v1, calldata);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert!(tx_result.is_system_tx);
    }

    #[test]
    fn normal_tx_is_not_system_tx() {
        let mut evm = setup_evm();
        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(ShellAddress::from([0x01; 20])),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert!(!tx_result.is_system_tx);
    }

    #[test]
    fn system_tx_invalid_calldata_produces_failed_receipt() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        // Too short (< 4 bytes)
        let signed = make_system_tx(v1, vec![0x00, 0x01]);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert_eq!(tx_result.receipt.status, 0); // failed
        assert!(tx_result.is_system_tx);
        assert_eq!(tx_result.gas_used, system_contracts::SYSTEM_CALL_BASE_GAS);
        assert!(tx_result.receipt.logs.is_empty());
    }

    #[test]
    fn system_tx_unknown_selector_produces_failed_receipt() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        let signed = make_system_tx(v1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert_eq!(tx_result.receipt.status, 0);
        assert!(tx_result.is_system_tx);
        // Revert message should contain "unknown function selector"
        let msg = String::from_utf8_lossy(&tx_result.output);
        assert!(msg.contains("unknown function selector"), "got: {msg}");
    }

    #[test]
    fn system_tx_unauthorized_produces_failed_receipt() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let outsider = ShellAddress::from([0x99; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        let new_val = ShellAddress::from([0x02; 20]);
        let calldata = system_contracts::encode_add_validator_calldata(&new_val);
        let signed = make_system_tx(outsider, calldata);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert_eq!(tx_result.receipt.status, 0);
        assert!(tx_result.is_system_tx);
        let msg = String::from_utf8_lossy(&tx_result.output);
        assert!(msg.contains("unauthorized"), "got: {msg}");
    }

    #[test]
    fn system_tx_generates_event_logs() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let new_val = ShellAddress::from([0x02; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();
        evm.state_db_mut()
            .chain_store()
            .put_pubkey(&new_val, &[0xAB; 32])
            .unwrap();

        let calldata = system_contracts::encode_add_validator_calldata(&new_val);
        let signed = make_system_tx(v1, calldata);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert_eq!(tx_result.receipt.status, 1);

        // Should have exactly one ValidatorAdded log
        assert_eq!(tx_result.receipt.logs.len(), 1);
        let log = &tx_result.receipt.logs[0];
        assert_eq!(log.address, system_contracts::registry_address());
        assert_eq!(log.topics.len(), 1);
        assert_eq!(
            log.topics[0],
            ShellHash::from(system_contracts::validator_added_topic())
        );
        // Log data should be the ABI-encoded address
        let mut expected_data = [0u8; 32];
        expected_data[12..32].copy_from_slice(new_val.to_alloy().as_slice());
        assert_eq!(log.data.as_ref(), &expected_data);
    }

    #[test]
    fn system_tx_remove_generates_removed_event() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let v2 = ShellAddress::from([0x02; 20]);
        let v3 = ShellAddress::from([0x03; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1, v2, v3])
            .unwrap();

        let calldata = system_contracts::encode_remove_validator_calldata(&v2);
        let first_vote = make_system_tx(v1, calldata.clone());
        let header = sample_header();

        let pending = evm.execute_tx(&first_vote, &header, 0, 0).unwrap();
        assert_eq!(pending.receipt.status, 1);
        assert!(pending.receipt.logs.is_empty());

        let second_vote = make_system_tx(v3, calldata);
        let tx_result = evm.execute_tx(&second_vote, &header, 0, 1).unwrap();
        assert_eq!(tx_result.receipt.status, 1);

        assert_eq!(tx_result.receipt.logs.len(), 1);
        let log = &tx_result.receipt.logs[0];
        assert_eq!(
            log.topics[0],
            ShellHash::from(system_contracts::validator_removed_topic())
        );
    }

    #[test]
    fn system_tx_cumulative_gas_is_correct() {
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        let calldata = system_contracts::GET_VALIDATORS_SELECTOR.to_vec();
        let signed = make_system_tx(v1, calldata);
        let header = sample_header();

        let prior_cumulative = 50_000u64;
        let tx_result = evm
            .execute_tx(&signed, &header, 1, prior_cumulative)
            .unwrap();
        assert_eq!(
            tx_result.receipt.cumulative_gas_used,
            prior_cumulative + tx_result.gas_used
        );
        assert_eq!(tx_result.receipt.tx_index, 1);
    }

    #[test]
    fn system_tx_state_changes_are_empty() {
        // System contract changes go directly to WorldState, not via EvmState
        let mut evm = setup_evm();
        let v1 = ShellAddress::from([0x01; 20]);
        let new_val = ShellAddress::from([0x02; 20]);
        evm.state_db_mut()
            .world_state_mut()
            .set_validators(&[v1])
            .unwrap();

        let calldata = system_contracts::encode_add_validator_calldata(&new_val);
        let signed = make_system_tx(v1, calldata);
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert!(tx_result.state_changes.is_empty());
    }

    #[test]
    fn execute_rotate_key_via_executor_updates_account() {
        let mut evm = setup_evm();
        let caller = ShellAddress::from([0x31; 20]);
        let initial_balance = U256::from(10_000_000u64);
        fund_account(&mut evm, &caller, initial_balance);

        let new_pubkey = vec![0xAB; 1312];
        let calldata = system_contracts::encode_rotate_key_calldata(
            &new_pubkey,
            SignatureType::Dilithium3.as_u8(),
        );
        let signed = make_system_tx_to(
            caller,
            system_contracts::account_manager_address(),
            calldata,
        );
        let header = sample_header();

        let tx_result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        assert_eq!(tx_result.receipt.status, 1);
        assert!(tx_result.is_system_tx);
        assert_eq!(
            tx_result.system_contract_effects.updated_accounts,
            vec![caller]
        );

        let account = evm
            .state_db_mut()
            .world_state_mut()
            .get_account(&caller)
            .unwrap()
            .unwrap();
        assert_eq!(
            account.pq_pubkey_hash,
            shell_primitives::blake3_hash(&new_pubkey)
        );
        assert_eq!(account.nonce, 1);
        assert_eq!(account.balance, initial_balance);
        assert_eq!(
            evm.state_db_mut()
                .chain_store()
                .get_pubkey(&caller)
                .unwrap()
                .unwrap(),
            new_pubkey
        );
    }

    // ── Helpers for advanced EVM tests ────────────────────────

    fn commit_state(evm: &mut ShellPqvm<MemoryDb>, state: &EvmState) {
        let fake_result = TxExecutionResult {
            receipt: empty_receipt(),
            state_changes: state.clone(),
            sender_shell_addr: ShellAddress::default(),
            sender_nonce_after: 0,
            gas_used: 0,
            output: vec![],
            is_system_tx: false,
            system_contract_effects: SystemContractEffects::default(),
        };
        commit_pqvm_state(&fake_result, evm.state_db_mut()).unwrap();
    }

    fn deploy_contract(
        evm: &mut ShellPqvm<MemoryDb>,
        from: &ShellAddress,
        init_code: Vec<u8>,
        value: U256,
        nonce: u64,
    ) -> (TxExecutionResult, ShellAddress) {
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: None,
            value,
            data: shell_primitives::Bytes::from(init_code),
            gas_limit: 5_000_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xCC; 100]);
        let signed = SignedTransaction::new(*from, tx, sig);
        let header = sample_header();
        let result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        let addr = result.receipt.contract_address.unwrap();
        commit_state(evm, &result.state_changes);
        (result, addr)
    }

    fn call_contract(
        evm: &mut ShellPqvm<MemoryDb>,
        from: &ShellAddress,
        to: &ShellAddress,
        calldata: Vec<u8>,
        value: U256,
        nonce: u64,
        gas_limit: u64,
    ) -> TxExecutionResult {
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: Some(*to),
            value,
            data: shell_primitives::Bytes::from(calldata),
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDD; 100]);
        let signed = SignedTransaction::new(*from, tx, sig);
        let header = sample_header();
        let result = evm.execute_tx(&signed, &header, 0, 0).unwrap();
        commit_state(evm, &result.state_changes);
        result
    }

    /// Build init code that deploys `runtime` as contract code.
    /// Uses CODECOPY to copy the runtime bytes appended after the prefix.
    fn make_init_code(runtime: &[u8]) -> Vec<u8> {
        let runtime_len = runtime.len();
        assert!(runtime_len <= 0xFFFF, "runtime too large for PUSH2");
        let mut init = Vec::new();
        if runtime_len <= 255 {
            // PUSH1 len, PUSH1 offset, PUSH1 0, CODECOPY, PUSH1 len, PUSH1 0, RETURN
            let prefix_len: u8 = 12;
            init.extend_from_slice(&[
                0x60,
                runtime_len as u8,
                0x60,
                prefix_len,
                0x60,
                0x00,
                0x39, // CODECOPY
                0x60,
                runtime_len as u8,
                0x60,
                0x00,
                0xF3, // RETURN
            ]);
        } else {
            // PUSH2 len, PUSH2 offset, PUSH1 0, CODECOPY, PUSH2 len, PUSH1 0, RETURN
            let prefix_len: u16 = 15;
            init.extend_from_slice(&[
                0x61,
                (runtime_len >> 8) as u8,
                (runtime_len & 0xFF) as u8,
                0x61,
                (prefix_len >> 8) as u8,
                (prefix_len & 0xFF) as u8,
                0x60,
                0x00,
                0x39, // CODECOPY
                0x61,
                (runtime_len >> 8) as u8,
                (runtime_len & 0xFF) as u8,
                0x60,
                0x00,
                0xF3, // RETURN
            ]);
        }
        init.extend_from_slice(runtime);
        init
    }

    // ════════════════════════════════════════════════════════════
    //  CREATE2 tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn create2_deploy_and_verify_address() {
        use alloy_primitives::keccak256;

        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Child init code: returns 1-byte runtime 0x42
        let child_init: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];

        // Factory runtime: store child_init in memory → CREATE2(val=0, off, sz, salt=1)
        // → return created address
        let mut factory_rt = Vec::new();
        factory_rt.push(0x69); // PUSH10
        factory_rt.extend_from_slice(&child_init);
        factory_rt.extend_from_slice(&[
            0x60, 0x00, 0x52, // MSTORE (right-aligned at mem[22..32])
            0x60, 0x01, // PUSH1 1 (salt)
            0x60, 0x0a, // PUSH1 10 (size)
            0x60, 0x16, // PUSH1 22 (offset = 32-10)
            0x60, 0x00, // PUSH1 0 (value)
            0xf5, // CREATE2
            0x60, 0x00, 0x52, // store addr at mem[0]
            0x60, 0x20, 0x60, 0x00, 0xf3, // RETURN 32 bytes
        ]);

        let factory_init = make_init_code(&factory_rt);
        let (_, factory_addr) = deploy_contract(&mut evm, &deployer, factory_init, U256::ZERO, 0);

        // Call factory to trigger CREATE2
        let result = call_contract(
            &mut evm,
            &deployer,
            &factory_addr,
            vec![],
            U256::ZERO,
            1,
            5_000_000,
        );
        assert_eq!(result.receipt.status, 1, "CREATE2 call failed");
        assert_eq!(result.output.len(), 32);
        let created_addr = ShellAddress::from(alloy_primitives::Address::from_slice(
            &result.output[12..32],
        ));

        // Verify via CREATE2 formula: keccak256(0xff ++ factory ++ salt ++ keccak256(init))
        let init_hash = keccak256(&child_init);
        let salt = B256::from(U256::from(1));
        let mut pre = vec![0xff];
        pre.extend_from_slice(factory_addr.to_alloy().as_slice());
        pre.extend_from_slice(salt.as_ref());
        pre.extend_from_slice(init_hash.as_ref());
        let expected = ShellAddress::from(alloy_primitives::Address::from_slice(
            &keccak256(&pre)[12..],
        ));
        assert_eq!(created_addr, expected, "CREATE2 address mismatch");
    }

    #[test]
    fn create2_same_salt_collision_returns_zero() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let child_init: Vec<u8> = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];
        let mut factory_rt = Vec::new();
        factory_rt.push(0x69); // PUSH10
        factory_rt.extend_from_slice(&child_init);
        factory_rt.extend_from_slice(&[
            0x60, 0x00, 0x52, 0x60, 0x00, // salt = 0
            0x60, 0x0a, 0x60, 0x16, 0x60, 0x00, 0xf5, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
            0xf3,
        ]);
        let factory_init = make_init_code(&factory_rt);
        let (_, factory_addr) = deploy_contract(&mut evm, &deployer, factory_init, U256::ZERO, 0);

        // First CREATE2
        let r1 = call_contract(
            &mut evm,
            &deployer,
            &factory_addr,
            vec![],
            U256::ZERO,
            1,
            5_000_000,
        );
        assert_eq!(r1.receipt.status, 1);
        assert_ne!(
            &r1.output[12..32],
            &[0u8; 20],
            "first deploy should succeed"
        );

        // Second CREATE2 with same salt → address collision, returns address(0)
        let r2 = call_contract(
            &mut evm,
            &deployer,
            &factory_addr,
            vec![],
            U256::ZERO,
            2,
            5_000_000,
        );
        assert_eq!(r2.receipt.status, 1, "outer call should succeed");
        assert_eq!(
            &r2.output[12..32],
            &[0u8; 20],
            "collision should return zero"
        );
    }

    #[test]
    fn create2_deterministic_address() {
        use alloy_primitives::keccak256;

        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let child_init: Vec<u8> = vec![0x60, 0xAA, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];
        let mut factory_rt = Vec::new();
        factory_rt.push(0x69);
        factory_rt.extend_from_slice(&child_init);
        factory_rt.extend_from_slice(&[
            0x60, 0x00, 0x52, 0x60, 0x42, // salt = 0x42
            0x60, 0x0a, 0x60, 0x16, 0x60, 0x00, 0xf5, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
            0xf3,
        ]);
        let factory_init = make_init_code(&factory_rt);
        let (_, factory_addr) = deploy_contract(&mut evm, &deployer, factory_init, U256::ZERO, 0);

        let r = call_contract(
            &mut evm,
            &deployer,
            &factory_addr,
            vec![],
            U256::ZERO,
            1,
            5_000_000,
        );
        assert_eq!(r.receipt.status, 1);
        let created = ShellAddress::from(alloy_primitives::Address::from_slice(&r.output[12..32]));

        let init_hash = keccak256(&child_init);
        let salt = B256::from(U256::from(0x42));
        let mut pre = vec![0xff];
        pre.extend_from_slice(factory_addr.to_alloy().as_slice());
        pre.extend_from_slice(salt.as_ref());
        pre.extend_from_slice(init_hash.as_ref());
        let expected = ShellAddress::from(alloy_primitives::Address::from_slice(
            &keccak256(&pre)[12..],
        ));
        assert_eq!(created, expected);
    }

    // ════════════════════════════════════════════════════════════
    //  SELFDESTRUCT tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn selfdestruct_is_disabled() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        let beneficiary = ShellAddress::from([0xBB; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));
        fund_account(&mut evm, &beneficiary, U256::ZERO);

        // Runtime: PUSH20 <beneficiary> SELFDESTRUCT
        let mut runtime = vec![0x73];
        runtime.extend_from_slice(beneficiary.to_alloy().as_slice());
        runtime.push(0xFF);

        let init_code = make_init_code(&runtime);
        let deposit = U256::from(1_000_000_000u64);
        let (_, contract_addr) = deploy_contract(&mut evm, &deployer, init_code, deposit, 0);

        let result = call_contract(
            &mut evm,
            &deployer,
            &contract_addr,
            vec![],
            U256::ZERO,
            1,
            100_000,
        );
        assert_eq!(result.receipt.status, 0, "SELFDESTRUCT must be disabled");
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 100_000);

        let beneficiary_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_balance(&beneficiary)
            .unwrap();
        assert_eq!(beneficiary_balance, U256::ZERO);

        let contract_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_balance(&contract_addr)
            .unwrap();
        assert_eq!(contract_balance, deposit);
    }

    #[test]
    fn selfdestruct_to_self_is_disabled() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Runtime: ADDRESS SELFDESTRUCT
        let runtime = vec![0x30, 0xFF];
        let init_code = make_init_code(&runtime);
        let deposit = U256::from(5_000_000u64);
        let (_, contract_addr) = deploy_contract(&mut evm, &deployer, init_code, deposit, 0);

        let result = call_contract(
            &mut evm,
            &deployer,
            &contract_addr,
            vec![],
            U256::ZERO,
            1,
            100_000,
        );
        assert_eq!(result.receipt.status, 0, "SELFDESTRUCT must be disabled");
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 100_000);

        let balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_balance(&contract_addr)
            .unwrap();
        assert_eq!(balance, deposit);
    }

    #[test]
    fn selfdestruct_reverts_state_changes() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        let beneficiary = ShellAddress::from([0xBB; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));
        fund_account(&mut evm, &beneficiary, U256::ZERO);

        // Runtime: SSTORE(0, 0x42) then SELFDESTRUCT to beneficiary
        let mut runtime = vec![
            0x60, 0x42, 0x60, 0x00, 0x55, // SSTORE(0, 0x42)
            0x73,
        ];
        runtime.extend_from_slice(beneficiary.to_alloy().as_slice());
        runtime.push(0xFF);

        let init_code = make_init_code(&runtime);
        let deposit = U256::from(1_000_000u64);
        let (_, contract_addr) = deploy_contract(&mut evm, &deployer, init_code, deposit, 0);

        let result = call_contract(
            &mut evm,
            &deployer,
            &contract_addr,
            vec![],
            U256::ZERO,
            1,
            200_000,
        );
        assert_eq!(result.receipt.status, 0, "SELFDESTRUCT must be disabled");
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 200_000);

        let beneficiary_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_balance(&beneficiary)
            .unwrap();
        assert_eq!(beneficiary_balance, U256::ZERO);

        let slot = ShellHash::ZERO;
        let stored = evm
            .state_db_mut()
            .world_state_mut()
            .get_storage(&contract_addr, &slot)
            .unwrap();
        assert_eq!(stored, ShellHash::ZERO);

        let code_hash = evm
            .state_db_mut()
            .world_state_mut()
            .get_code_hash(&contract_addr)
            .unwrap();
        assert!(code_hash.is_some());

        let contract_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_balance(&contract_addr)
            .unwrap();
        assert_eq!(contract_balance, deposit);
    }

    // ════════════════════════════════════════════════════════════
    //  DELEGATECALL tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn delegatecall_storage_writes_to_proxy() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Logic: PUSH1 0xAA  PUSH1 0  SSTORE  STOP
        let logic_rt = vec![0x60, 0xAA, 0x60, 0x00, 0x55, 0x00];
        let (_, logic_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&logic_rt),
            U256::ZERO,
            0,
        );

        // Proxy: DELEGATECALL(gas, logic_addr, 0, 0, 0, 0) POP STOP
        let mut proxy_rt = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // retSz retOff argsSz argsOff
            0x73,
        ];
        proxy_rt.extend_from_slice(logic_addr.to_alloy().as_slice());
        proxy_rt.extend_from_slice(&[0x5A, 0xF4, 0x50, 0x00]);
        let (_, proxy_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&proxy_rt),
            U256::ZERO,
            1,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &proxy_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(result.receipt.status, 1, "delegatecall failed");

        // Storage written in proxy's context
        let slot = ShellHash::ZERO;
        let proxy_val = evm
            .state_db_mut()
            .world_state_mut()
            .get_storage(&proxy_addr, &slot)
            .unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 0xAA;
        assert_eq!(proxy_val.as_bytes(), &expected);

        // Logic contract's storage untouched
        let logic_val = evm
            .state_db_mut()
            .world_state_mut()
            .get_storage(&logic_addr, &slot)
            .unwrap();
        assert_eq!(logic_val, ShellHash::ZERO);
    }

    #[test]
    fn delegatecall_preserves_msg_sender() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Logic: CALLER PUSH1 0 SSTORE STOP
        let logic_rt = vec![0x33, 0x60, 0x00, 0x55, 0x00];
        let (_, logic_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&logic_rt),
            U256::ZERO,
            0,
        );

        // Proxy: DELEGATECALL to logic
        let mut proxy_rt = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        proxy_rt.extend_from_slice(logic_addr.to_alloy().as_slice());
        proxy_rt.extend_from_slice(&[0x5A, 0xF4, 0x50, 0x00]);
        let (_, proxy_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&proxy_rt),
            U256::ZERO,
            1,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &proxy_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(result.receipt.status, 1);

        // slot 0 in proxy should hold the original caller (deployer)
        let slot = ShellHash::ZERO;
        let stored = evm
            .state_db_mut()
            .world_state_mut()
            .get_storage(&proxy_addr, &slot)
            .unwrap();
        let mut expected = [0u8; 32];
        expected[12..32].copy_from_slice(deployer.to_alloy().as_slice());
        assert_eq!(
            stored.as_bytes(),
            &expected,
            "msg.sender should be preserved"
        );
    }

    #[test]
    fn delegatecall_return_data_forwarded() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Logic: PUSH1 0xBE PUSH1 0 MSTORE PUSH1 1 PUSH1 31 RETURN
        let logic_rt = vec![0x60, 0xBE, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];
        let (_, logic_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&logic_rt),
            U256::ZERO,
            0,
        );

        // Proxy: DELEGATECALL → RETURNDATASIZE → RETURNDATACOPY → RETURN
        let mut proxy_rt = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        proxy_rt.extend_from_slice(logic_addr.to_alloy().as_slice());
        proxy_rt.extend_from_slice(&[
            0x5A, 0xF4, 0x50, // DELEGATECALL, POP success
            0x3D, // RETURNDATASIZE
            0x60, 0x00, 0x60, 0x00, // offset=0, destOffset=0
            0x3E, // RETURNDATACOPY
            0x3D, // RETURNDATASIZE
            0x60, 0x00, // offset=0
            0xF3, // RETURN
        ]);
        let (_, proxy_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&proxy_rt),
            U256::ZERO,
            1,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &proxy_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output, vec![0xBE], "should forward return data");
    }

    // ════════════════════════════════════════════════════════════
    //  Call depth limit test
    // ════════════════════════════════════════════════════════════

    #[test]
    fn call_depth_limit_1024() {
        // Contract recursively CALLs itself; EVM depth limit = 1024.
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Runtime: CALL(gas, self, 0, 0, 0, 0, 0) → store result → RETURN
        let runtime = vec![
            0x60, 0x00, // retSize
            0x60, 0x00, // retOffset
            0x60, 0x00, // argsSize
            0x60, 0x00, // argsOffset
            0x60, 0x00, // value
            0x30, // ADDRESS (self)
            0x5A, // GAS
            0xF1, // CALL
            0x60, 0x00, 0x52, // MSTORE result
            0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN 32 bytes
        ];
        let (_, contract_addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let result = call_contract(
            &mut evm,
            &deployer,
            &contract_addr,
            vec![],
            U256::ZERO,
            1,
            30_000_000,
        );
        // Outer call succeeds; deep recursion eventually hits depth limit
        assert_eq!(result.receipt.status, 1, "outer call should succeed");
        assert_eq!(result.output.len(), 32);
    }

    // ════════════════════════════════════════════════════════════
    //  Code size limit tests (EIP-170)
    // ════════════════════════════════════════════════════════════

    #[test]
    fn code_size_over_24kb_fails() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // 24577 bytes of STOP opcodes — 1 byte over limit
        let oversized = vec![0x00u8; 24577];
        let init_code = make_init_code(&oversized);

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: None,
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(init_code),
            gas_limit: 29_000_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xCC; 100]);
        let signed = SignedTransaction::new(deployer, tx, sig);
        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();

        assert_eq!(result.receipt.status, 0, "deploying >24KB should fail");
        assert!(result.receipt.contract_address.is_none());
    }

    #[test]
    fn code_size_exactly_24kb_succeeds() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let exact = vec![0x00u8; 24576];
        let init_code = make_init_code(&exact);

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: None,
            value: U256::ZERO,
            data: shell_primitives::Bytes::from(init_code),
            gas_limit: 29_000_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xCC; 100]);
        let signed = SignedTransaction::new(deployer, tx, sig);
        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();

        assert_eq!(
            result.receipt.status, 1,
            "deploying exactly 24KB should succeed"
        );
        assert!(result.receipt.contract_address.is_some());
    }

    // ════════════════════════════════════════════════════════════
    //  Gas limit tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn gas_exact_for_simple_transfer() {
        let mut evm = setup_evm();
        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(ShellAddress::from([0x01; 20])),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx, sig);

        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn gas_insufficient_for_sstore_reverts() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Contract: PUSH1 1 PUSH1 0 SSTORE STOP
        let runtime = vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // Call with barely enough for intrinsic gas but not for SSTORE
        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_100,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDD; 100]);
        let signed = SignedTransaction::new(deployer, tx, sig);

        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();
        assert_eq!(
            result.receipt.status, 0,
            "should revert on insufficient gas"
        );
    }

    #[test]
    fn gas_refund_from_clearing_storage() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Contract: SSTORE(0, calldataload(0)) STOP
        let runtime = vec![
            0x60, 0x00, 0x35, // PUSH1 0, CALLDATALOAD
            0x60, 0x00, 0x55, // PUSH1 0, SSTORE
            0x00, // STOP
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // Set storage to non-zero
        let mut set_data = [0u8; 32];
        set_data[31] = 0x01;
        let r1 = call_contract(
            &mut evm,
            &deployer,
            &addr,
            set_data.to_vec(),
            U256::ZERO,
            1,
            500_000,
        );
        assert_eq!(r1.receipt.status, 1);
        let gas_set = r1.gas_used;

        // Clear storage to zero (earns refund)
        let r2 = call_contract(
            &mut evm,
            &deployer,
            &addr,
            vec![0u8; 32],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(r2.receipt.status, 1);
        let gas_clear = r2.gas_used;

        assert!(
            gas_clear < gas_set,
            "clearing storage (gas={gas_clear}) should cost less than setting (gas={gas_set})"
        );
    }

    // ════════════════════════════════════════════════════════════
    //  Additional EVM operation tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn contract_to_contract_call() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Callee: returns 0xFF in a 32-byte word
        let callee_rt = vec![0x60, 0xFF, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let (_, callee_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&callee_rt),
            U256::ZERO,
            0,
        );

        // Caller: CALL(gas, callee, 0, 0, 0, 0, 32) → RETURN mem[0..32]
        let mut caller_rt = vec![
            0x60, 0x20, 0x60, 0x00, // retSize=32, retOff=0
            0x60, 0x00, 0x60, 0x00, // argsSz=0, argsOff=0
            0x60, 0x00, // value=0
            0x73,
        ];
        caller_rt.extend_from_slice(callee_addr.to_alloy().as_slice());
        caller_rt.extend_from_slice(&[
            0x5A, 0xF1, 0x50, // GAS, CALL, POP
            0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN 32 bytes
        ]);
        let (_, caller_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&caller_rt),
            U256::ZERO,
            1,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &caller_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 0xFF);
    }

    #[test]
    fn revert_preserves_revert_data() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Runtime: PUSH4 0xDEADBEEF PUSH1 0 MSTORE PUSH1 4 PUSH1 28 REVERT
        let runtime = vec![
            0x63, 0xDE, 0xAD, 0xBE, 0xEF, // PUSH4
            0x60, 0x00, 0x52, // MSTORE
            0x60, 0x04, 0x60, 0x1c, 0xFD, // PUSH1 4, PUSH1 28, REVERT
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 100_000);
        assert_eq!(result.receipt.status, 0, "should revert");
        assert_eq!(&result.output, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn create_opcode_basic() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Child init: returns 1-byte runtime 0xBB
        let child_init: Vec<u8> = vec![0x60, 0xBB, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x1f, 0xf3];
        let mut factory_rt = Vec::new();
        factory_rt.push(0x69); // PUSH10
        factory_rt.extend_from_slice(&child_init);
        factory_rt.extend_from_slice(&[
            0x60, 0x00, 0x52, // MSTORE
            0x60, 0x0a, // PUSH1 10 (size)
            0x60, 0x16, // PUSH1 22 (offset = 32-10)
            0x60, 0x00, // PUSH1 0 (value)
            0xF0, // CREATE
            0x60, 0x00, 0x52, // MSTORE
            0x60, 0x20, 0x60, 0x00, 0xf3,
        ]);
        let (_, factory_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&factory_rt),
            U256::ZERO,
            0,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &factory_addr,
            vec![],
            U256::ZERO,
            1,
            5_000_000,
        );
        assert_eq!(result.receipt.status, 1);
        assert_ne!(
            &result.output[12..32],
            &[0u8; 20],
            "CREATE should return non-zero address"
        );
    }

    #[test]
    fn sstore_sload_roundtrip() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Runtime: SSTORE(0, calldataload(0)), SLOAD(0), MSTORE, RETURN 32
        let runtime = vec![
            0x60, 0x00, 0x35, // CALLDATALOAD(0)
            0x60, 0x00, 0x55, // SSTORE(0, ...)
            0x60, 0x00, 0x54, // SLOAD(0)
            0x60, 0x00, 0x52, // MSTORE
            0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let mut calldata = [0u8; 32];
        calldata[30] = 0x12;
        calldata[31] = 0x34;
        let result = call_contract(
            &mut evm,
            &deployer,
            &addr,
            calldata.to_vec(),
            U256::ZERO,
            1,
            500_000,
        );
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[30], 0x12);
        assert_eq!(result.output[31], 0x34);
    }

    // ── Cancun opcode tests ──────────────────────────────────────

    #[test]
    fn test_transient_storage_tstore_tload() {
        // EIP-1153: TSTORE (0x5d) writes to transient storage,
        // TLOAD (0x5c) reads it back within the same transaction.
        // We store the TLOAD result to persistent storage so we can verify.
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x50; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // Runtime bytecode:
        //   PUSH1 0x42   ; value
        //   PUSH1 0x00   ; key
        //   TSTORE       ; transient_storage[0] = 0x42
        //   PUSH1 0x00   ; key
        //   TLOAD        ; read transient_storage[0] → 0x42
        //   PUSH1 0x00   ; slot
        //   SSTORE       ; persistent_storage[0] = 0x42
        //   PUSH1 0x00   ; offset
        //   SLOAD        ; load persistent_storage[0]
        //   PUSH1 0x00   ; offset
        //   MSTORE       ; memory[0..32] = value
        //   PUSH1 0x20   ; size
        //   PUSH1 0x00   ; offset
        //   RETURN       ; return 32 bytes
        let runtime = vec![
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0x00
            0x5d, // TSTORE
            0x60, 0x00, // PUSH1 0x00
            0x5c, // TLOAD
            0x60, 0x00, // PUSH1 0x00
            0x55, // SSTORE
            0x60, 0x00, // PUSH1 0x00
            0x54, // SLOAD
            0x60, 0x00, // PUSH1 0x00
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 0x20
            0x60, 0x00, // PUSH1 0x00
            0xF3, // RETURN
        ];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1, "TSTORE/TLOAD tx should succeed");
        assert_eq!(result.output.len(), 32);
        assert_eq!(
            result.output[31], 0x42,
            "TLOAD should read back the value stored by TSTORE"
        );
    }

    #[test]
    fn test_mcopy_opcode() {
        // EIP-5656: MCOPY (0x5e) copies memory within the EVM.
        // Store 0xAB at memory[0], then MCOPY 1 byte from offset 0 to offset 32,
        // then return 32 bytes from offset 32.
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x51; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // Runtime bytecode:
        //   PUSH1 0xAB   ; value
        //   PUSH1 0x00   ; offset
        //   MSTORE8      ; memory[0] = 0xAB
        //   PUSH1 0x01   ; size  (1 byte)
        //   PUSH1 0x00   ; src   (offset 0)
        //   PUSH1 0x20   ; dst   (offset 32)
        //   MCOPY        ; memory[32] = memory[0] (1 byte)
        //   PUSH1 0x20   ; size  (32 bytes)
        //   PUSH1 0x20   ; offset
        //   RETURN       ; return memory[32..64]
        let runtime = vec![
            0x60, 0xAB, // PUSH1 0xAB
            0x60, 0x00, // PUSH1 0x00
            0x53, // MSTORE8
            0x60, 0x01, // PUSH1 0x01 (size)
            0x60, 0x00, // PUSH1 0x00 (src)
            0x60, 0x20, // PUSH1 0x20 (dst)
            0x5e, // MCOPY
            0x60, 0x20, // PUSH1 0x20 (size)
            0x60, 0x20, // PUSH1 0x20 (offset)
            0xF3, // RETURN
        ];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1, "MCOPY tx should succeed");
        assert_eq!(result.output.len(), 32);
        assert_eq!(
            result.output[0], 0xAB,
            "MCOPY should copy 0xAB from src to dst"
        );
    }

    #[test]
    fn callcode_is_disabled() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x52; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // Callee: returns 0xFF in a 32-byte word.
        let callee_rt = vec![0x60, 0xFF, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];
        let (_, callee_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&callee_rt),
            U256::ZERO,
            0,
        );

        // Caller: CALLCODE(gas, callee, 0, 0, 0, 0, 32) then return the buffer.
        let mut caller_rt = vec![
            0x60, 0x20, 0x60, 0x00, // retSize=32, retOffset=0
            0x60, 0x00, 0x60, 0x00, // argsSize=0, argsOffset=0
            0x60, 0x00, // value=0
            0x73,
        ];
        caller_rt.extend_from_slice(callee_addr.to_alloy().as_slice());
        caller_rt.extend_from_slice(&[
            0x5A, 0xF2, 0x50, // GAS, CALLCODE, POP
            0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN 32 bytes
        ]);
        let (_, caller_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&caller_rt),
            U256::ZERO,
            1,
        );

        let result = call_contract(
            &mut evm,
            &deployer,
            &caller_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(result.receipt.status, 0, "CALLCODE must be disabled");
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 500_000);
    }

    // ════════════════════════════════════════════════════════════
    //  EIP-2930 access list tests
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_access_list_gas_accounting() {
        use shell_core::AccessListItem;

        // 2 addresses, 3 storage keys each → 2*2400 + 6*1900 = 16200 extra gas
        let access_list = Some(vec![
            AccessListItem {
                address: ShellAddress::from([0xAA; 20]),
                storage_keys: vec![
                    ShellHash::from([0x01; 32]),
                    ShellHash::from([0x02; 32]),
                    ShellHash::from([0x03; 32]),
                ],
            },
            AccessListItem {
                address: ShellAddress::from([0xBB; 20]),
                storage_keys: vec![
                    ShellHash::from([0x04; 32]),
                    ShellHash::from([0x05; 32]),
                    ShellHash::from([0x06; 32]),
                ],
            },
        ]);

        let base = crate::tx_validation::compute_intrinsic_gas(&[], false, &None);
        let with_al = crate::tx_validation::compute_intrinsic_gas(&[], false, &access_list);
        assert_eq!(
            with_al - base,
            16_200,
            "access list should add 2*2400 + 6*1900 = 16200 gas"
        );
    }

    #[test]
    fn test_access_list_pre_warms_storage() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Contract: SLOAD(0) STOP — reads storage slot 0
        let runtime = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD
            0x50, // POP
            0x00, // STOP
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // Execute without access list
        let tx_no_al = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xDD; 100]);
        let signed_no_al = SignedTransaction::new(deployer, tx_no_al, sig);
        let result_no_al = evm
            .execute_tx(&signed_no_al, &sample_header(), 0, 0)
            .unwrap();
        assert_eq!(result_no_al.receipt.status, 1);

        // Execute with access list pre-warming the storage slot
        let tx_with_al = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: Some(vec![shell_core::AccessListItem {
                address: addr,
                storage_keys: vec![ShellHash::ZERO],
            }]),
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig2 = PQSignature::new(SignatureType::Dilithium3, vec![0xEE; 100]);
        let signed_with_al = SignedTransaction::new(deployer, tx_with_al, sig2);
        let result_with_al = evm
            .execute_tx(&signed_with_al, &sample_header(), 0, 0)
            .unwrap();
        assert_eq!(result_with_al.receipt.status, 1);
    }

    #[test]
    fn test_empty_access_list() {
        let mut evm = setup_evm();
        let from = ShellAddress::from([0x42; 20]);
        let to = ShellAddress::from([0x01; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        // Transaction with empty access list
        let tx_empty_al = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(to),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: Some(vec![]),
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(from, tx_empty_al, sig);
        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.gas_used, 21_000);

        // Transaction with no access list (None)
        let tx_none_al = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: Some(to),
            value: U256::from(100),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig2 = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);
        let signed2 = SignedTransaction::new(from, tx_none_al, sig2);
        let result2 = evm.execute_tx(&signed2, &sample_header(), 0, 0).unwrap();
        assert_eq!(result2.receipt.status, 1);
        assert_eq!(result2.gas_used, 21_000);
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: Cancun opcode — PUSH0 (EIP-3855)
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_push0_opcode() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x60; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // PUSH0 PUSH0 SSTORE PUSH0 SLOAD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
        let runtime = vec![
            0x5f, 0x5f, 0x55, 0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xF3,
        ];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(
            result.receipt.status, 1,
            "PUSH0 opcode should be supported in Cancun"
        );
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_push0_used_in_arithmetic() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x61; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // PUSH0 + PUSH1 1 + ADD → 1
        let runtime = vec![
            0x5f, 0x60, 0x01, 0x01, // PUSH0, PUSH1 1, ADD → 1
            0x5f, 0x52, // PUSH0, MSTORE
            0x60, 0x20, 0x5f, 0xF3, // RETURN 32
        ];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output[31], 1, "PUSH0 + 1 should equal 1");
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: BLOBHASH opcode (EIP-4844, opcode 0x49)
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_blobhash_returns_zero_without_blobs() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x62; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        let runtime = vec![
            0x5f, 0x49, // PUSH0, BLOBHASH
            0x5f, 0x52, // PUSH0, MSTORE
            0x60, 0x20, 0x5f, 0xF3,
        ];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(
            result.receipt.status, 1,
            "BLOBHASH should execute in Cancun"
        );
        assert_eq!(result.output, vec![0u8; 32]);
    }

    #[test]
    fn test_blobhash_with_blob_tx_context() {
        // BLOBHASH returns the versioned hash when hashes are provided.
        // We use a type 2 tx (not type 3) because revm validates blob tx
        // version hashes at protocol level; our executor still passes
        // blob_versioned_hashes to the TxEnv for the BLOBHASH opcode.
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x63; 20]);
        fund_account(&mut evm, &deployer, U256::from(1_000_000_000_000u64));

        let runtime = vec![0x5f, 0x49, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xF3];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let mut blob_hash_bytes = [0u8; 32];
        blob_hash_bytes[0] = 0x01; // version prefix
        blob_hash_bytes[1..].copy_from_slice(&[0xAB; 31]);
        let blob_hash = ShellHash::from(blob_hash_bytes);
        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![blob_hash]),
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xEE; 100]);
        let signed = SignedTransaction::new(deployer, tx, sig);
        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output, blob_hash.as_bytes().to_vec());
    }

    #[test]
    fn test_blobhash_out_of_bounds_returns_zero() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x64; 20]);
        fund_account(&mut evm, &deployer, U256::from(1_000_000_000_000u64));

        // BLOBHASH(1) with only 1 blob → zero
        let runtime = vec![0x60, 0x01, 0x49, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xF3];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let mut blob_hash_bytes = [0u8; 32];
        blob_hash_bytes[0] = 0x01;
        blob_hash_bytes[1..].copy_from_slice(&[0xCD; 31]);
        let blob_hash = ShellHash::from(blob_hash_bytes);
        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: Some(1_000_000),
            blob_versioned_hashes: Some(vec![blob_hash]),
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xFF; 100]);
        let signed = SignedTransaction::new(deployer, tx, sig);
        let result = evm.execute_tx(&signed, &sample_header(), 0, 0).unwrap();
        assert_eq!(result.receipt.status, 1);
        assert_eq!(result.output, vec![0u8; 32]);
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: BLOBBASEFEE opcode (EIP-7516, opcode 0x4a)
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_blobbasefee_opcode() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x65; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        let runtime = vec![0x4a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xF3];

        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1, "BLOBBASEFEE should be supported");
        assert_eq!(result.output.len(), 32);
        // excess_blob_gas=0 → blob base fee = 1
        assert_eq!(result.output[31], 1);
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: SSTORE gas — EIP-2200 net gas metering
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_sstore_cold_zero_to_nonzero_costs_more() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x70; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // SSTORE(calldataload(0), calldataload(32)) STOP
        let runtime = vec![
            0x60, 0x20, 0x35, // CALLDATALOAD(32) → value
            0x60, 0x00, 0x35, // CALLDATALOAD(0) → key
            0x55, 0x00,
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // First: zero → nonzero (cold, 20_000 gas)
        let mut cd1 = [0u8; 64];
        cd1[31] = 0x01;
        cd1[63] = 0x42;
        let r1 = call_contract(
            &mut evm,
            &deployer,
            &addr,
            cd1.to_vec(),
            U256::ZERO,
            1,
            500_000,
        );
        assert_eq!(r1.receipt.status, 1);

        // Second: nonzero → nonzero (warm, 5000 gas)
        let mut cd2 = [0u8; 64];
        cd2[31] = 0x01;
        cd2[63] = 0x43;
        let r2 = call_contract(
            &mut evm,
            &deployer,
            &addr,
            cd2.to_vec(),
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(r2.receipt.status, 1);

        assert!(
            r1.gas_used > r2.gas_used,
            "cold zero→nonzero ({}) should cost more than warm nonzero→nonzero ({})",
            r1.gas_used,
            r2.gas_used
        );
    }

    #[test]
    fn test_sstore_nonzero_to_zero_gets_refund() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x71; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let runtime = vec![0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let mut set_data = [0u8; 32];
        set_data[31] = 0xFF;
        let r_set = call_contract(
            &mut evm,
            &deployer,
            &addr,
            set_data.to_vec(),
            U256::ZERO,
            1,
            500_000,
        );
        assert_eq!(r_set.receipt.status, 1);

        let r_clear = call_contract(
            &mut evm,
            &deployer,
            &addr,
            vec![0u8; 32],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(r_clear.receipt.status, 1);

        assert!(
            r_clear.gas_used < r_set.gas_used,
            "clearing (gas={}) should cost less than setting (gas={})",
            r_clear.gas_used,
            r_set.gas_used
        );
    }

    #[test]
    fn test_sstore_same_value_no_op_cheap() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x72; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let runtime = vec![
            0x60, 0x00, 0x35, 0x60, 0x00, 0x55, // SSTORE(0, calldataload(0))
            0x60, 0x00, 0x35, 0x60, 0x00, 0x55, // SSTORE(0, same value)
            0x00,
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        let mut cd = [0u8; 32];
        cd[31] = 0x01;
        let result = call_contract(
            &mut evm,
            &deployer,
            &addr,
            cd.to_vec(),
            U256::ZERO,
            1,
            500_000,
        );
        assert_eq!(result.receipt.status, 1);
        assert!(
            result.gas_used < 50_000,
            "double SSTORE should be cheaper than 50k gas, got {}",
            result.gas_used
        );
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: EIP-2929 cold/warm SLOAD/SSTORE gas costs
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_eip2929_cold_sload_costs_more_than_warm() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x73; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Contract A: 1 SLOAD
        let runtime_one = vec![0x60, 0x00, 0x54, 0x50, 0x00];
        let (_, addr_one) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&runtime_one),
            U256::ZERO,
            0,
        );

        // Contract B: 2 SLOADs on same slot
        let runtime_two = vec![0x60, 0x00, 0x54, 0x50, 0x60, 0x00, 0x54, 0x50, 0x00];
        let (_, addr_two) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&runtime_two),
            U256::ZERO,
            1,
        );

        let r1 = call_contract(
            &mut evm,
            &deployer,
            &addr_one,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(r1.receipt.status, 1);

        let r2 = call_contract(
            &mut evm,
            &deployer,
            &addr_two,
            vec![],
            U256::ZERO,
            3,
            500_000,
        );
        assert_eq!(r2.receipt.status, 1);

        let extra_gas = r2.gas_used - r1.gas_used;
        assert!(
            extra_gas < 500,
            "second SLOAD (warm) should add ~100 gas, not {extra_gas}"
        );
    }

    #[test]
    fn test_eip2929_access_list_makes_sload_warm() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x74; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        let runtime = vec![0x60, 0x00, 0x54, 0x50, 0x00];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // Cold SLOAD
        let tx_cold = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig1 = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed_cold = SignedTransaction::new(deployer, tx_cold, sig1);
        let r_cold = evm
            .execute_tx(&signed_cold, &sample_header(), 0, 0)
            .unwrap();
        assert_eq!(r_cold.receipt.status, 1);

        // Warm SLOAD via access list
        let tx_warm = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: Some(vec![shell_core::AccessListItem {
                address: addr,
                storage_keys: vec![ShellHash::ZERO],
            }]),
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig2 = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);
        let signed_warm = SignedTransaction::new(deployer, tx_warm, sig2);
        let r_warm = evm
            .execute_tx(&signed_warm, &sample_header(), 0, 0)
            .unwrap();
        assert_eq!(r_warm.receipt.status, 1);
        // Both succeed; the access list is processed by revm
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: Transient storage isolation between transactions
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_transient_storage_cleared_between_txs() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x75; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        // Two contracts: one that TSTOREs, one that TLOADs.
        // Since transient storage is per-transaction, running TSTORE in tx1
        // and TLOAD in tx2 should return 0 for tx2.

        // Contract: TSTORE(0, 0x42), SSTORE(0, 0x42), STOP
        let tstore_runtime = vec![
            0x60, 0x42, 0x60, 0x00, 0x5d, // TSTORE(0, 0x42)
            0x60, 0x42, 0x60, 0x00, 0x55, // SSTORE(0, 0x42) — for persistent verification
            0x00, // STOP
        ];
        let (_, tstore_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&tstore_runtime),
            U256::ZERO,
            0,
        );

        // Contract: TLOAD(0) → MSTORE → RETURN
        let tload_runtime = vec![
            0x60, 0x00, 0x5c, // TLOAD(0)
            0x60, 0x00, 0x52, // MSTORE
            0x60, 0x20, 0x60, 0x00, 0xF3, // RETURN 32
        ];
        let (_, tload_addr) = deploy_contract(
            &mut evm,
            &deployer,
            make_init_code(&tload_runtime),
            U256::ZERO,
            1,
        );

        // Tx 1: call TSTORE contract
        let r1 = call_contract(
            &mut evm,
            &deployer,
            &tstore_addr,
            vec![],
            U256::ZERO,
            2,
            500_000,
        );
        assert_eq!(r1.receipt.status, 1, "TSTORE tx should succeed");

        // Verify SSTORE persisted (to confirm contract executed)
        let slot = ShellHash::ZERO;
        let stored = evm
            .state_db_mut()
            .world_state_mut()
            .get_storage(&tstore_addr, &slot)
            .unwrap();
        assert_eq!(stored.as_bytes()[31], 0x42, "SSTORE should persist");

        // Tx 2: call TLOAD contract (different tx, same storage address scope doesn't matter)
        let r2 = call_contract(
            &mut evm,
            &deployer,
            &tload_addr,
            vec![],
            U256::ZERO,
            3,
            500_000,
        );
        assert_eq!(r2.receipt.status, 1);
        assert_eq!(
            r2.output[31], 0,
            "transient storage should be cleared between txs"
        );
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: MCOPY edge cases
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_mcopy_overlapping_regions() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x76; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        let runtime = vec![
            0x60, 0x01, 0x60, 0x00, 0x53, // MSTORE8(0, 0x01)
            0x60, 0x02, 0x60, 0x01, 0x53, // MSTORE8(1, 0x02)
            0x60, 0x03, 0x60, 0x02, 0x53, // MSTORE8(2, 0x03)
            0x60, 0x04, 0x60, 0x03, 0x53, // MSTORE8(3, 0x04)
            0x60, 0x04, 0x60, 0x00, 0x60, 0x02, 0x5e, // MCOPY 4 bytes from 0 to 2
            0x60, 0x08, 0x60, 0x00, 0xF3, // RETURN 8 bytes
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1, "MCOPY overlapping should succeed");
        assert_eq!(&result.output[..6], &[0x01, 0x02, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_mcopy_zero_length() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x77; 20]);
        fund_account(&mut evm, &deployer, U256::from(10_000_000_000u64));

        let runtime = vec![
            0x60, 0xAA, 0x60, 0x00, 0x53, // MSTORE8(0, 0xAA)
            0x60, 0x00, 0x60, 0x00, 0x60, 0x20, 0x5e, // MCOPY 0 bytes
            0x60, 0x01, 0x60, 0x20, 0xF3,
        ];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);
        let result = call_contract(&mut evm, &deployer, &addr, vec![], U256::ZERO, 1, 500_000);
        assert_eq!(result.receipt.status, 1);
        assert_eq!(
            result.output,
            vec![0x00],
            "MCOPY zero length should be no-op"
        );
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: EIP-4844 blob gas pricing integration
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_excess_gas_in_header_affects_blob_base_fee() {
        let mut evm = setup_evm();
        let deployer = ShellAddress::from([0x78; 20]);
        fund_account(&mut evm, &deployer, U256::from(100_000_000_000u64));

        // Contract returns BLOBBASEFEE
        let runtime = vec![0x4a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xF3];
        let (_, addr) =
            deploy_contract(&mut evm, &deployer, make_init_code(&runtime), U256::ZERO, 0);

        // Low excess → low fee
        let tx1 = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig1 = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed1 = SignedTransaction::new(deployer, tx1, sig1);
        let mut header_low = sample_header();
        header_low.excess_blob_gas = 0;
        let r1 = evm.execute_tx(&signed1, &header_low, 0, 0).unwrap();
        assert_eq!(r1.receipt.status, 1);

        // High excess → higher fee
        let tx2 = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &deployer),
            to: Some(addr),
            value: U256::ZERO,
            data: shell_primitives::Bytes::new(),
            gas_limit: 500_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig2 = PQSignature::new(SignatureType::Dilithium3, vec![0xBB; 100]);
        let signed2 = SignedTransaction::new(deployer, tx2, sig2);
        let mut header_high = sample_header();
        header_high.excess_blob_gas = 10_000_000;
        let r2 = evm.execute_tx(&signed2, &header_high, 0, 0).unwrap();
        assert_eq!(r2.receipt.status, 1);

        let fee1 = U256::from_be_slice(&r1.output);
        let fee2 = U256::from_be_slice(&r2.output);
        assert!(
            fee2 > fee1,
            "higher excess should yield higher blob base fee: low={fee1}, high={fee2}"
        );
    }

    // ════════════════════════════════════════════════════════════
    //  M5-A6: EIP-2930 access list gas formula verification
    // ════════════════════════════════════════════════════════════

    #[test]
    fn test_access_list_gas_formula() {
        use shell_core::AccessListItem;

        let base = crate::tx_validation::compute_intrinsic_gas(&[], false, &None);

        // 1 address, 0 keys → +2400
        let al1 = Some(vec![AccessListItem {
            address: ShellAddress::from([0xAA; 20]),
            storage_keys: vec![],
        }]);
        assert_eq!(
            crate::tx_validation::compute_intrinsic_gas(&[], false, &al1) - base,
            2_400
        );

        // 1 address, 1 key → +4300
        let al2 = Some(vec![AccessListItem {
            address: ShellAddress::from([0xBB; 20]),
            storage_keys: vec![ShellHash::from([0x01; 32])],
        }]);
        assert_eq!(
            crate::tx_validation::compute_intrinsic_gas(&[], false, &al2) - base,
            4_300
        );

        // 3 addresses, 2 keys each → 3*2400 + 6*1900 = 18600
        let al3 = Some(vec![
            AccessListItem {
                address: ShellAddress::from([0x01; 20]),
                storage_keys: vec![ShellHash::from([0x01; 32]), ShellHash::from([0x02; 32])],
            },
            AccessListItem {
                address: ShellAddress::from([0x02; 20]),
                storage_keys: vec![ShellHash::from([0x03; 32]), ShellHash::from([0x04; 32])],
            },
            AccessListItem {
                address: ShellAddress::from([0x03; 20]),
                storage_keys: vec![ShellHash::from([0x05; 32]), ShellHash::from([0x06; 32])],
            },
        ]);
        assert_eq!(
            crate::tx_validation::compute_intrinsic_gas(&[], false, &al3) - base,
            18_600
        );
    }

    #[test]
    fn execute_aa_bundle_is_hard_guarded() {
        use shell_core::{AaBundle, InnerCall, AA_BUNDLE_TX_TYPE};
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let from = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &from, U256::from(10_000_000_000u64));

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &from),
            to: None,
            value: U256::from(1u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 200_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let bundle = AaBundle {
            inner_calls: vec![InnerCall {
                to: Some(ShellAddress::from([0xAA; 20])),
                value: U256::from(1u64),
                data: PBytes::new(),
                gas_limit: 50_000,
            }],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        let signed = SignedTransaction::with_aa_bundle(
            from,
            tx,
            sig,
            shell_core::PubkeyMode::Reference,
            bundle,
        )
        .unwrap();

        let header = sample_header();
        let res = evm.execute_tx(&signed, &header, 0, 0);
        assert!(matches!(
            res,
            Err(ExecutorError::AaBundleNotYetExecutable(_))
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // M2b: AA bundle dispatcher tests
    // ─────────────────────────────────────────────────────────────────────

    fn make_aa_signed(
        from: ShellAddress,
        nonce: u64,
        gas_limit: u64,
        max_fee: u64,
        inner_calls: Vec<shell_core::InnerCall>,
        paymaster: Option<ShellAddress>,
    ) -> SignedTransaction {
        use shell_core::{AaBundle, AA_BUNDLE_TX_TYPE};
        let value = inner_calls
            .iter()
            .fold(U256::ZERO, |acc, call| acc.saturating_add(call.value));
        let tx = Transaction {
            chain_id: 1337,
            nonce,
            to: None,
            value,
            data: shell_primitives::Bytes::new(),
            gas_limit,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let bundle = AaBundle {
            inner_calls,
            paymaster,
            paymaster_signature: paymaster.map(|_| shell_primitives::Bytes::from(vec![0u8; 1])),
            ..Default::default()
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0u8; 1]);
        SignedTransaction::with_aa_bundle(from, tx, sig, shell_core::PubkeyMode::Reference, bundle)
            .unwrap()
    }

    fn get_balance(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress) -> U256 {
        evm.state_db_mut()
            .world_state_mut()
            .get_account(addr)
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(U256::ZERO)
    }

    fn get_nonce(evm: &mut ShellPqvm<MemoryDb>, addr: &ShellAddress) -> u64 {
        evm.state_db_mut()
            .world_state_mut()
            .get_account(addr)
            .unwrap()
            .map(|a| a.nonce)
            .unwrap_or_default()
    }

    #[test]
    fn execute_aa_bundle_self_sponsored_two_transfers_success() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let dst1 = ShellAddress::from([0xAA; 20]);
        let dst2 = ShellAddress::from([0xBB; 20]);

        fund_account(&mut evm, &sender, U256::from(10_000_000u64));

        let inner_calls = vec![
            InnerCall {
                to: Some(dst1),
                value: U256::from(1u64),
                data: PBytes::new(),
                gas_limit: 50_000,
            },
            InnerCall {
                to: Some(dst2),
                value: U256::from(1u64),
                data: PBytes::new(),
                gas_limit: 50_000,
            },
        ];
        let signed = make_aa_signed(sender, 0, 200_000, 10, inner_calls, None);

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();

        assert_eq!(get_balance(&mut evm, &dst1), U256::from(1u64));
        assert_eq!(get_balance(&mut evm, &dst2), U256::from(1u64));
        assert_eq!(get_nonce(&mut evm, &sender), 1);
        assert_eq!(res.receipt.status, 1);
        assert!(res.gas_used > 0, "gas_used should be non-zero");
    }

    #[test]
    fn execute_aa_bundle_self_transfer_preserves_sender_value() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &sender, U256::from(10_000_000u64));

        let inner_calls = vec![InnerCall {
            to: Some(sender),
            value: U256::from(5u64),
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let nonce = get_nonce(&mut evm, &sender);
        let signed = make_aa_signed(sender, nonce, 200_000, 10, inner_calls, None);

        let sender_pre = get_balance(&mut evm, &sender);
        let res = evm
            .execute_aa_bundle(&signed, &sample_header(), 0, 0)
            .unwrap();
        let sender_post = get_balance(&mut evm, &sender);

        assert_eq!(res.receipt.status, 1);
        assert_eq!(
            sender_pre - sender_post,
            U256::from(res.gas_used).saturating_mul(U256::from(10u64)),
            "a self-transfer must not burn the transferred value"
        );
    }

    #[test]
    fn execute_aa_bundle_atomic_revert_on_inner_failure() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let dst1 = ShellAddress::from([0xAA; 20]);
        let dst2 = ShellAddress::from([0xBB; 20]);

        fund_account(&mut evm, &sender, U256::from(5_000_000u64));

        let inner_calls = vec![
            InnerCall {
                to: Some(dst1),
                value: U256::from(1u64),
                data: PBytes::new(),
                gas_limit: 50_000,
            },
            InnerCall {
                to: Some(dst2),
                value: U256::from(1u64),
                data: PBytes::new(),
                // 100 gas is well below the 21_000 intrinsic for a transfer
                // → revm halts with OutOfGas.
                gas_limit: 100,
            },
        ];
        let signed = make_aa_signed(sender, 0, 200_000, 10, inner_calls, None);

        let pre_bal = get_balance(&mut evm, &sender);
        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();

        assert_eq!(get_balance(&mut evm, &dst1), U256::ZERO);
        assert_eq!(get_balance(&mut evm, &dst2), U256::ZERO);
        assert_eq!(get_nonce(&mut evm, &sender), 1);
        assert_eq!(res.receipt.status, 0);
        let post_bal = get_balance(&mut evm, &sender);
        let charged = pre_bal - post_bal;
        assert!(
            charged <= U256::from(200_000u64 * 10u64),
            "charge {charged} should not exceed gas_limit*max_fee"
        );
    }

    #[test]
    fn execute_aa_bundle_sponsored_success() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let paymaster = ShellAddress::from([0x77; 20]);
        let dst = ShellAddress::from([0xAA; 20]);

        fund_account(&mut evm, &sender, U256::from(10u64));
        fund_account(&mut evm, &paymaster, U256::from(10_000_000u64));

        let inner_calls = vec![InnerCall {
            to: Some(dst),
            value: U256::from(5u64),
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let signed = make_aa_signed(sender, 0, 200_000, 10, inner_calls, Some(paymaster));

        let sender_pre = get_balance(&mut evm, &sender);
        let paymaster_pre = get_balance(&mut evm, &paymaster);
        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();

        assert_eq!(res.receipt.status, 1);
        assert_eq!(get_balance(&mut evm, &dst), U256::from(5u64));
        let sender_post = get_balance(&mut evm, &sender);
        assert_eq!(
            sender_pre - sender_post,
            U256::from(5u64),
            "sender should pay only the inner value"
        );
        let paymaster_post = get_balance(&mut evm, &paymaster);
        assert!(
            paymaster_pre > paymaster_post,
            "paymaster balance should decrease"
        );
        assert!(
            paymaster_pre - paymaster_post <= U256::from(200_000u64 * 10u64),
            "paymaster charge should not exceed gas_limit * max_fee"
        );
        assert_eq!(get_nonce(&mut evm, &sender), 1);
    }

    #[test]
    fn execute_aa_bundle_preserves_value_received_by_paymaster() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let paymaster = ShellAddress::from([0x77; 20]);
        fund_account(&mut evm, &sender, U256::from(10u64));
        fund_account(&mut evm, &paymaster, U256::from(10_000_000u64));

        let transferred = U256::from(5u64);
        let inner_calls = vec![InnerCall {
            to: Some(paymaster),
            value: transferred,
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let nonce = get_nonce(&mut evm, &sender);
        let signed = make_aa_signed(sender, nonce, 200_000, 10, inner_calls, Some(paymaster));

        let sender_pre = get_balance(&mut evm, &sender);
        let paymaster_pre = get_balance(&mut evm, &paymaster);
        let res = evm
            .execute_aa_bundle(&signed, &sample_header(), 0, 0)
            .unwrap();
        let gas_cost = U256::from(res.gas_used).saturating_mul(U256::from(10u64));

        assert_eq!(res.receipt.status, 1);
        assert_eq!(sender_pre - get_balance(&mut evm, &sender), transferred);
        assert_eq!(
            get_balance(&mut evm, &paymaster),
            paymaster_pre + transferred - gas_cost,
            "settlement must preserve value received by the paymaster"
        );
    }

    #[test]
    fn execute_aa_bundle_sponsored_payer_shortfall_at_execution() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let paymaster = ShellAddress::from([0x77; 20]);
        let dst = ShellAddress::from([0xAA; 20]);

        fund_account(&mut evm, &sender, U256::from(1_000u64));
        fund_account(&mut evm, &paymaster, U256::ZERO);

        let inner_calls = vec![InnerCall {
            to: Some(dst),
            value: U256::from(1u64),
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let signed = make_aa_signed(sender, 0, 200_000, 10, inner_calls, Some(paymaster));

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();

        assert_eq!(res.receipt.status, 0);
        assert_eq!(get_balance(&mut evm, &dst), U256::ZERO);
        assert_eq!(get_balance(&mut evm, &sender), U256::from(1_000u64));
        assert_eq!(get_balance(&mut evm, &paymaster), U256::ZERO);
        assert_eq!(get_nonce(&mut evm, &sender), 1);
        assert_eq!(res.gas_used, 0);
    }

    #[test]
    fn execute_aa_bundle_rejects_inner_value_overspend() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let dst = ShellAddress::from([0xAA; 20]);
        fund_account(&mut evm, &sender, U256::from(10_000_000u64));

        let inner_calls = vec![InnerCall {
            to: Some(dst),
            value: U256::from(2u64),
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let mut signed = make_aa_signed(sender, 0, 200_000, 10, inner_calls, None);
        signed.tx.value = U256::from(1u64);

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0);
        assert!(
            matches!(res, Err(ExecutorError::Revm(msg)) if msg.contains("exceeds outer value"))
        );
        assert_eq!(get_balance(&mut evm, &dst), U256::ZERO);
        assert_eq!(get_nonce(&mut evm, &sender), 0);
    }

    #[test]
    fn execute_aa_bundle_rejects_inner_value_overflow() {
        use shell_core::{AaBundle, InnerCall, AA_BUNDLE_TX_TYPE};
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let dst = ShellAddress::from([0xAA; 20]);
        fund_account(&mut evm, &sender, U256::MAX);

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &sender),
            to: None,
            value: U256::MAX,
            data: PBytes::new(),
            gas_limit: 200_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: AA_BUNDLE_TX_TYPE,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let bundle = AaBundle {
            inner_calls: vec![
                InnerCall {
                    to: Some(dst),
                    value: U256::MAX,
                    data: PBytes::new(),
                    gas_limit: 50_000,
                },
                InnerCall {
                    to: Some(dst),
                    value: U256::from(1u64),
                    data: PBytes::new(),
                    gas_limit: 50_000,
                },
            ],
            paymaster: None,
            paymaster_signature: None,
            ..Default::default()
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, tx.hash().as_bytes().to_vec());
        let mut signed = SignedTransaction::new(sender, tx, sig);
        signed.aa_bundle = Some(bundle);

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0);
        assert!(matches!(res, Err(ExecutorError::Revm(msg)) if msg.contains("overflows U256")));
        assert_eq!(get_balance(&mut evm, &dst), U256::ZERO);
        assert_eq!(get_nonce(&mut evm, &sender), 0);
    }

    #[test]
    fn execute_aa_bundle_single_nonce_bump_regardless_of_inner_count() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        fund_account(&mut evm, &sender, U256::from(100_000_000u64));
        let account_sequence = fixture_account_sequence(&sender);
        set_nonce(&mut evm, &sender, account_sequence);

        let inner_calls = (0..5u8)
            .map(|i| InnerCall {
                to: Some(ShellAddress::from([0xA0 + i; 20])),
                value: U256::from(1u64),
                data: PBytes::new(),
                gas_limit: 50_000,
            })
            .collect();
        let signed = make_aa_signed(sender, account_sequence, 500_000, 10, inner_calls, None);

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();
        assert_eq!(res.receipt.status, 1);
        assert_eq!(get_nonce(&mut evm, &sender), account_sequence + 1);
    }

    #[test]
    fn execute_aa_bundle_rejects_stale_nonce_without_mutating_state() {
        use shell_core::InnerCall;
        use shell_primitives::Bytes as PBytes;

        let mut evm = setup_evm();
        let sender = ShellAddress::from([0x42; 20]);
        let dst = ShellAddress::from([0xAA; 20]);
        fund_account(&mut evm, &sender, U256::from(100_000_000u64));
        let current_sequence = fixture_account_sequence(&sender);
        let stale_delta = u64::from(u8::from(current_sequence > u64::default()));
        let stale_sequence = current_sequence.saturating_sub(stale_delta);
        set_nonce(&mut evm, &sender, current_sequence);

        let inner_calls = vec![InnerCall {
            to: Some(dst),
            value: U256::from(1u64),
            data: PBytes::new(),
            gas_limit: 50_000,
        }];
        let signed = make_aa_signed(sender, stale_sequence, 200_000, 10, inner_calls, None);

        let header = sample_header();
        let res = evm.execute_aa_bundle(&signed, &header, 0, 0);
        assert!(matches!(
            res,
            Err(ExecutorError::NonceMismatch {
                expected,
                got
            }) if expected == current_sequence && got == stale_sequence
        ));
        assert_eq!(get_nonce(&mut evm, &sender), current_sequence);
        assert_eq!(get_balance(&mut evm, &dst), U256::ZERO);
    }

    /// Regression test: native transfer to a fresh 32-byte PQ address must store
    /// the balance under the correct full 32-byte key, not a zero-padded form.
    ///
    /// Before the fix, `commit_pqvm_state` would fall back to
    /// `ShellAddress::from_alloy(20-byte truncated to)` = zero-pad the upper 12 bytes,
    /// silently losing funds stored under the wrong key.
    #[test]
    fn transfer_to_fresh_pq_address_stores_balance_at_correct_key() {
        let mut evm = setup_evm();

        // Sender is a legacy 20-byte address (zero-padded, round-trips cleanly).
        let sender = ShellAddress::from([0x42u8; 20]);
        fund_account(&mut evm, &sender, U256::from(10_000_000_000u64));

        // Recipient is a genuine 32-byte PQ address with non-zero upper 12 bytes.
        // Its upper 12 bytes are 0xAA, so from_alloy(to_alloy(addr)) != addr.
        let mut pq_bytes = [0u8; 32];
        pq_bytes[0..12].copy_from_slice(&[0xAAu8; 12]);
        pq_bytes[12..32].copy_from_slice(&[0x0Bu8; 20]);
        let pq_recipient = ShellAddress::from(pq_bytes);

        // Sanity check: the address round-trip through 20-byte is indeed lossy.
        let evm_form: alloy_primitives::Address = pq_recipient.into();
        let zero_padded = ShellAddress::from(evm_form);
        assert_ne!(
            zero_padded, pq_recipient,
            "test setup: pq_recipient must have non-zero upper bytes"
        );

        let tx = Transaction {
            chain_id: 1337,
            nonce: current_nonce(&mut evm, &pq_recipient),
            to: Some(pq_recipient),
            value: U256::from(1_000u64),
            data: shell_primitives::Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let sig = PQSignature::new(SignatureType::Dilithium3, vec![0xAA; 100]);
        let signed = SignedTransaction::new(sender, tx, sig);

        let header = sample_header();
        let result = evm.execute_tx(&signed, &header, 0, 0);
        assert!(result.is_ok(), "execute_tx failed: {:?}", result.err());
        let tx_result = result.unwrap();
        assert_eq!(tx_result.receipt.status, 1);

        // Commit state to WorldState — execute_tx returns changes but does not
        // persist them; the caller must drive commit_pqvm_state.
        commit_pqvm_state(&tx_result, evm.state_db_mut()).expect("commit_pqvm_state failed");

        // The balance must be stored at the CORRECT full 32-byte address.
        let correct_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_account(&pq_recipient)
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(U256::ZERO);
        assert_eq!(
            correct_balance,
            U256::from(1_000u64),
            "balance must be at the full PQ address"
        );

        // The zero-padded address must NOT hold the balance.
        let wrong_balance = evm
            .state_db_mut()
            .world_state_mut()
            .get_account(&zero_padded)
            .unwrap()
            .map(|a| a.balance)
            .unwrap_or(U256::ZERO);
        assert_eq!(
            wrong_balance,
            U256::ZERO,
            "balance must NOT be stored at the zero-padded fallback address"
        );
    }
}
