//! Shell-chain PQVM execution layer.
//!
//! This crate bridges the shell-chain storage layer (WorldState + ChainStore)
//! with revm, providing:
//!
//! - [`ShellStateDb`]: implements `revm::Database` over WorldState + ChainStore
//! - [`ShellPqvm`]: transaction executor backed by retained Cancun-style semantics
//! - [`ShellPrecompiles`]: PQ precompile provider (6-precompile suite at 0x0001-0x0006)
//! - [`pqvm_opcodes`]: Native PQ opcodes (0xB0 PQVERIFY, 0xB1 PQHASH, 0xB2 PQADDR)
//! - [`validate_tx`]: PQ signature verification + hybrid pubkey registration

mod aa_validation;
pub mod bloom;
mod executor;
mod parallel;
pub mod pqvm_opcodes;
mod precompiles;
mod rwset;
mod state_db;
pub mod system_contracts;
pub mod tracer;
mod tx_validation;

pub use aa_validation::{
    validate_aa_tx, AaValidationError, AaValidationOutcome, VALIDATION_GAS_CAP,
};
pub use executor::{
    commit_pqvm_state, commit_pqvm_state_raw, ExecutorError, ShellPqvm, TxExecutionResult,
};
pub use parallel::{
    ConflictMetric, ConflictReason, ExecutionWave, ParallelExecutionPlan, ParallelPqvmConfig,
    ParallelScheduler, TxConflict, TxConflictGraph,
};
pub use pqvm_opcodes::{OPCODE_PQHASH, OPCODE_PQVERIFY};
pub use precompiles::{
    ShellPrecompiles, BLAKE3_BASE_GAS, BLAKE3_WORD_GAS,
    PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG, PQ_MLDSA65_VERIFY_GAS, PQ_SLHDSA_VERIFY_GAS,
};
pub use rwset::{HeuristicRwSetExtractor, ReadWriteSetExtractor, TxAccessPath, TxReadWriteSet};
pub use state_db::{ShellStateDb, StateDbError};
pub use system_contracts::{
    account_manager_address, account_manager_code_hash, decode_address_u64,
    encode_add_validator_calldata, encode_clear_validation_code_calldata,
    encode_propose_algorithm_activation_calldata, encode_remove_validator_calldata,
    encode_rotate_key_calldata, encode_set_validation_code_calldata,
    encode_set_validator_weight_calldata, execute_system_contract, execute_system_contract_call,
    is_system_contract, process_pending_activations, registry_address, system_contract_code_hash,
    SystemContractEffects, SystemContractError, SystemContractOutcome, ACCOUNT_MANAGER_ADDR,
    ALGO_GOVERNANCE_DELTA_MIN, SET_VALIDATOR_WEIGHT_SELECTOR, SYSTEM_CALL_BASE_GAS,
    SYSTEM_CALL_OP_GAS, VALIDATOR_REGISTRY_ADDR,
};
pub use tracer::{decode_revert_reason, CallFrame, TraceResult};
pub use tx_validation::{
    compute_intrinsic_gas, validate_aa_bundle_structure, validate_tx, validate_tx_for_import,
    TxValidationError,
};
