//! Shell-chain EVM integration layer.
//!
//! This crate bridges the shell-chain storage layer (WorldState + ChainStore)
//! with revm, providing:
//!
//! - [`ShellStateDb`]: implements `revm::Database` over WorldState + ChainStore
//! - [`ShellEvm`]: transaction executor (Shanghai spec)
//! - [`ShellPrecompiles`]: PQ precompile provider (6-precompile suite at 0x0001-0x0006)
//! - [`validate_tx`]: PQ signature verification + hybrid pubkey registration

mod aa_validation;
pub mod bloom;
mod executor;
mod parallel;
mod precompiles;
mod rwset;
mod state_db;
pub mod system_contracts;
pub mod tracer;
mod tx_validation;

pub use aa_validation::{
    validate_aa_tx, AaValidationError, AaValidationOutcome, VALIDATION_GAS_CAP,
};
pub use executor::{commit_evm_state, ExecutorError, ShellEvm, TxExecutionResult};
pub use parallel::{
    ConflictMetric, ConflictReason, ExecutionWave, ParallelEvmConfig, ParallelExecutionPlan,
    ParallelScheduler, TxConflict, TxConflictGraph,
};
pub use precompiles::{
    ShellPrecompiles, BLAKE3_BASE_GAS, BLAKE3_WORD_GAS, PQ_ADDR_DERIVE_GAS,
    PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG, PQ_MLDSA65_VERIFY_GAS, PQ_SLHDSA_VERIFY_GAS,
};
pub use rwset::{HeuristicRwSetExtractor, ReadWriteSetExtractor, TxAccessPath, TxReadWriteSet};
pub use state_db::{ShellStateDb, StateDbError};
pub use system_contracts::{
    account_manager_address, account_manager_code_hash, encode_add_validator_calldata,
    encode_clear_validation_code_calldata, encode_remove_validator_calldata,
    encode_rotate_key_calldata, encode_set_validation_code_calldata, execute_system_contract,
    execute_system_contract_call, is_system_contract, registry_address, system_contract_code_hash,
    SystemContractEffects, SystemContractError, SystemContractOutcome, ACCOUNT_MANAGER_ADDR,
    SYSTEM_CALL_BASE_GAS, SYSTEM_CALL_OP_GAS, VALIDATOR_REGISTRY_ADDR,
};
pub use tracer::{decode_revert_reason, CallFrame, TraceResult};
pub use tx_validation::{
    compute_intrinsic_gas, validate_aa_bundle_structure, validate_tx, validate_tx_for_import,
    TxValidationError,
};
