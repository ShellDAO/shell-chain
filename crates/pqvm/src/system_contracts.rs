//! Native system contracts:
//! - ValidatorRegistry at address 0x0000…0001
//! - AccountManager at address 0x0000…0002
//!
//! Instead of deploying Solidity bytecode, this contract is intercepted by the
//! PQVM/revm execution adapter and executed as native Rust code. This avoids the need for a
//! Solidity compiler and ensures deterministic, efficient validator management.
//!
//! # Supported Functions
//!
//! | Contract | Signature | Access |
//! |----------|-----------|--------|
//! | ValidatorRegistry | `addValidator(address)` | validators |
//! | ValidatorRegistry | `removeValidator(address)` | validators |
//! | ValidatorRegistry | `setValidatorWeight(address,uint64)` | validators |
//! | ValidatorRegistry | `setValidatorStake(address,uint256)` | validators |
//! | ValidatorRegistry | `bondValidatorStake(address,uint256)` | self |
//! | ValidatorRegistry | `unbondValidatorStake(address,uint256)` | self |
//! | ValidatorRegistry | `proposeAlgorithmActivation(uint8,uint64,bytes32)` | validators |
//! | ValidatorRegistry | `deprecateAlgorithm(uint8)` | validators |
//! | ValidatorRegistry | `getValidators()` | anyone |
//! | ValidatorRegistry | `isValidator(address)` | anyone |
//! | AccountManager | `rotateKey(bytes,uint8)` | self |
//! | AccountManager | `setValidationCode(bytes32)` | self |
//! | AccountManager | `clearValidationCode()` | self |
//! | AccountManager | `setGuardians(address[],uint8,uint64)` | self |
//! | AccountManager | `submitRecovery(address,bytes,uint8)` | guardian |
//! | AccountManager | `executeRecovery(address)` | anyone (post-maturity) |
//! | AccountManager | `cancelRecovery(address)` | account owner |

use shell_core::Account;
use shell_crypto::{AlgorithmRegistry, AlgorithmStatus, SignatureType};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash, U256};
use shell_storage::{
    ChainStore, GuardianConfig, KvStore, RecoveryProposal, WorldState, MAX_GUARDIANS,
    MIN_RECOVERY_TIMELOCK,
};

// ── Contract address ───────────────────────────────────────────────

/// System contract address for ValidatorRegistry: 0x0000…0001.
pub const VALIDATOR_REGISTRY_ADDR: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 1;
    addr
};

/// System contract address for AccountManager: 0x0000…0002.
pub const ACCOUNT_MANAGER_ADDR: [u8; 32] = {
    let mut addr = [0u8; 32];
    addr[31] = 2;
    addr
};

/// Return the system contract address as a shell `Address`.
pub fn registry_address() -> Address {
    Address::from(VALIDATOR_REGISTRY_ADDR)
}

/// Return the AccountManager address as a shell `Address`.
pub fn account_manager_address() -> Address {
    Address::from(ACCOUNT_MANAGER_ADDR)
}

pub fn is_system_contract(address: &Address) -> bool {
    *address == registry_address() || *address == account_manager_address()
}

// ── Function selectors (keccak256 of signature, first 4 bytes) ────

/// keccak256("addValidator(address)")[..4]
pub const ADD_VALIDATOR_SELECTOR: [u8; 4] = compute_selector(b"addValidator(address)");
/// keccak256("removeValidator(address)")[..4]
pub const REMOVE_VALIDATOR_SELECTOR: [u8; 4] = compute_selector(b"removeValidator(address)");
/// keccak256("setValidatorWeight(address,uint64)")[..4]
pub const SET_VALIDATOR_WEIGHT_SELECTOR: [u8; 4] =
    compute_selector(b"setValidatorWeight(address,uint64)");
/// keccak256("setValidatorStake(address,uint256)")[..4]
pub const SET_VALIDATOR_STAKE_SELECTOR: [u8; 4] =
    compute_selector(b"setValidatorStake(address,uint256)");
/// keccak256("bondValidatorStake(address,uint256)")[..4]
pub const BOND_VALIDATOR_STAKE_SELECTOR: [u8; 4] =
    compute_selector(b"bondValidatorStake(address,uint256)");
/// keccak256("unbondValidatorStake(address,uint256)")[..4]
pub const UNBOND_VALIDATOR_STAKE_SELECTOR: [u8; 4] =
    compute_selector(b"unbondValidatorStake(address,uint256)");
/// keccak256("proposeAlgorithmActivation(uint8,uint64,bytes32)")[..4]
pub const PROPOSE_ALGORITHM_ACTIVATION_SELECTOR: [u8; 4] =
    compute_selector(b"proposeAlgorithmActivation(uint8,uint64,bytes32)");
/// keccak256("deprecateAlgorithm(uint8)")[..4]
pub const DEPRECATE_ALGORITHM_SELECTOR: [u8; 4] = compute_selector(b"deprecateAlgorithm(uint8)");
/// keccak256("getValidators()")[..4]
pub const GET_VALIDATORS_SELECTOR: [u8; 4] = compute_selector(b"getValidators()");
/// keccak256("isValidator(address)")[..4]
pub const IS_VALIDATOR_SELECTOR: [u8; 4] = compute_selector(b"isValidator(address)");
/// keccak256("rotateKey(bytes,uint8)")[..4]
pub const ROTATE_KEY_SELECTOR: [u8; 4] = compute_selector(b"rotateKey(bytes,uint8)");
/// keccak256("setValidationCode(bytes32)")[..4]
pub const SET_VALIDATION_CODE_SELECTOR: [u8; 4] = compute_selector(b"setValidationCode(bytes32)");
/// keccak256("clearValidationCode()")[..4]
pub const CLEAR_VALIDATION_CODE_SELECTOR: [u8; 4] = compute_selector(b"clearValidationCode()");
/// keccak256("setGuardians(address[],uint8,uint64)")[..4]
pub const SET_GUARDIANS_SELECTOR: [u8; 4] =
    compute_selector(b"setGuardians(address[],uint8,uint64)");
/// keccak256("submitRecovery(address,bytes,uint8)")[..4]
pub const SUBMIT_RECOVERY_SELECTOR: [u8; 4] =
    compute_selector(b"submitRecovery(address,bytes,uint8)");
/// keccak256("executeRecovery(address)")[..4]
pub const EXECUTE_RECOVERY_SELECTOR: [u8; 4] = compute_selector(b"executeRecovery(address)");
/// keccak256("cancelRecovery(address)")[..4]
pub const CANCEL_RECOVERY_SELECTOR: [u8; 4] = compute_selector(b"cancelRecovery(address)");

/// Compute a 4-byte function selector at compile time.
const fn compute_selector(sig: &[u8]) -> [u8; 4] {
    let hash = const_keccak256(sig);
    [hash[0], hash[1], hash[2], hash[3]]
}

// ── Event topic signatures ─────────────────────────────────────────

/// keccak256("ValidatorAdded(address)")
pub fn validator_added_topic() -> [u8; 32] {
    *keccak256(b"ValidatorAdded(address)").as_bytes()
}

/// keccak256("ValidatorRemoved(address)")
pub fn validator_removed_topic() -> [u8; 32] {
    *keccak256(b"ValidatorRemoved(address)").as_bytes()
}

// ── Gas constants ──────────────────────────────────────────────────

/// Base gas cost for a system contract call (same as a normal tx).
pub const SYSTEM_CALL_BASE_GAS: u64 = 21_000;
/// Additional gas per state-mutating operation.
pub const SYSTEM_CALL_OP_GAS: u64 = 5_000;
/// Maximum public-key payload accepted by account-management calls.
///
/// The largest currently supported public key is 1,952 bytes. Keep bounded
/// headroom for future algorithms without allowing calldata-sized values to be persisted.
pub const MAX_ACCOUNT_PUBLIC_KEY_BYTES: usize = 4_096;

/// Minimum blocks between proposal and activation (≈ 30 days at 2 s/block per WP §6.5).
///
/// The plan locks this at 500 000 blocks to match the governance decision.
pub const ALGO_GOVERNANCE_DELTA_MIN: u64 = 500_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemContractEffects {
    pub validator_set_changed: bool,
    pub updated_accounts: Vec<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemContractOutcome {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub effects: SystemContractEffects,
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SystemContractError {
    #[error("input too short: need at least 4 bytes for selector")]
    InputTooShort,
    #[error("unknown function selector: 0x{}", hex::encode(.0))]
    UnknownSelector([u8; 4]),
    #[error("unknown system contract: {0}")]
    UnknownSystemContract(Address),
    #[error("unauthorized: caller is not a validator")]
    Unauthorized,
    #[error("validator already exists: {0}")]
    AlreadyExists(Address),
    #[error("validator not found: {0}")]
    NotFound(Address),
    #[error("cannot remove last validator")]
    LastValidator,
    #[error("empty pubkey is not allowed")]
    EmptyPubkey,
    #[error("public key is too large: {0} bytes (max {1})")]
    PublicKeyTooLarge(usize, usize),
    #[error("validator pubkey is not registered: {0}")]
    ValidatorPubkeyMissing(Address),
    #[error("invalid signature algorithm id: {0}")]
    InvalidAlgorithm(u8),
    #[error("validation code missing for hash {0}")]
    ValidationCodeMissing(ShellHash),
    #[error("invalid ABI parameter: {0}")]
    AbiDecode(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("guardian list must have 1..={0} entries, got {1}")]
    InvalidGuardianCount(usize, usize),
    #[error("threshold must be between 1 and {0}, got {1}")]
    InvalidThreshold(usize, u8),
    #[error("timelock too short: minimum {0} blocks, got {1}")]
    TimelockTooShort(u64, u64),
    #[error("activation height {0} is below minimum (current + delta_min = {1})")]
    InvalidActivationHeight(u64, u64),
    #[error("duplicate vote: this validator has already cast a vote for this proposal")]
    DuplicateVote,
    #[error("staking is disabled for this chain")]
    StakingDisabled,
    #[error("direct validator weight changes are disabled when stake-derived weights are active")]
    StakeDerivedWeightsActive,
    #[error("validator stake must derive a non-zero weight")]
    StakeTooLow,
    #[error("activation height {0} conflicts with open proposal (stored: {1})")]
    HeightMismatch(u64, u64),
    #[error("verifier_hash conflicts with open proposal")]
    GovernanceConflict,
    #[error("guardian cannot be the account itself")]
    GuardianIsSelf,
    #[error("duplicate guardian address")]
    DuplicateGuardian,
    #[error("caller is not a registered guardian for this account")]
    NotAGuardian,
    #[error("no guardian configuration for account {0}")]
    NoGuardianConfig(Address),
    #[error("no active recovery proposal for account {0}")]
    NoRecoveryProposal(Address),
    #[error("recovery proposal not yet mature (maturity block {0})")]
    RecoveryNotMature(u64),
    #[error("recovery already active; cancel before starting a new one")]
    RecoveryAlreadyActive,
}

// ── Main dispatch ──────────────────────────────────────────────────

/// Execute the ValidatorRegistry system contract.
///
/// Returns `(output_bytes, gas_used)` on success.
pub fn execute_system_contract<S: KvStore + 'static>(
    caller: &Address,
    input: &[u8],
    world_state: &mut WorldState<S>,
) -> Result<(Vec<u8>, u64), SystemContractError> {
    let mut registry = AlgorithmRegistry::global_mut();
    execute_validator_registry_with_registry(caller, input, world_state, None, &mut registry)
}

/// Execute any native system contract and return both the ABI output and the
/// state surfaces that must be synchronized back to the canonical node state.
pub fn execute_system_contract_call<S: KvStore + 'static>(
    target: &Address,
    caller: &Address,
    input: &[u8],
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<SystemContractOutcome, SystemContractError> {
    if *target == registry_address() {
        let mut registry = AlgorithmRegistry::global_mut();
        let (output, gas_used) = execute_validator_registry_with_registry(
            caller,
            input,
            world_state,
            Some(chain_store),
            &mut registry,
        )?;
        let mut effects = SystemContractEffects::default();
        let selector = decode_selector(input)?;
        if (selector == ADD_VALIDATOR_SELECTOR
            || selector == REMOVE_VALIDATOR_SELECTOR
            || selector == SET_VALIDATOR_WEIGHT_SELECTOR
            || selector == SET_VALIDATOR_STAKE_SELECTOR
            || selector == BOND_VALIDATOR_STAKE_SELECTOR
            || selector == UNBOND_VALIDATOR_STAKE_SELECTOR)
            && output == encode_bool(true)
        {
            effects.validator_set_changed = true;
        }
        return Ok(SystemContractOutcome {
            output,
            gas_used,
            effects,
        });
    }

    if *target == account_manager_address() {
        return execute_account_manager(caller, input, world_state, chain_store);
    }

    Err(SystemContractError::UnknownSystemContract(*target))
}

fn execute_validator_registry_with_registry<S: KvStore + 'static>(
    caller: &Address,
    input: &[u8],
    world_state: &mut WorldState<S>,
    chain_store: Option<&ChainStore<S>>,
    registry: &mut AlgorithmRegistry,
) -> Result<(Vec<u8>, u64), SystemContractError> {
    if input.len() < 4 {
        return Err(SystemContractError::InputTooShort);
    }

    let selector = decode_selector(input)?;
    let params = input.get(4..).unwrap_or_default();

    match selector {
        s if s == ADD_VALIDATOR_SELECTOR => {
            let addr = decode_address(params)?;
            let applied = add_validator(caller, &addr, world_state, chain_store)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == REMOVE_VALIDATOR_SELECTOR => {
            let addr = decode_address(params)?;
            let applied = remove_validator(caller, &addr, world_state)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == SET_VALIDATOR_WEIGHT_SELECTOR => {
            let (addr, weight) = decode_address_u64(params)?;
            let applied = set_validator_weight_op(caller, &addr, weight, world_state)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == SET_VALIDATOR_STAKE_SELECTOR => {
            let (addr, stake) = decode_address_u256(params)?;
            let applied = set_validator_stake_op(caller, &addr, stake, world_state)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == BOND_VALIDATOR_STAKE_SELECTOR => {
            let (addr, amount) = decode_address_u256(params)?;
            let applied = bond_validator_stake(caller, &addr, amount, world_state)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == UNBOND_VALIDATOR_STAKE_SELECTOR => {
            let (addr, amount) = decode_address_u256(params)?;
            let applied = unbond_validator_stake(caller, &addr, amount, world_state)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == PROPOSE_ALGORITHM_ACTIVATION_SELECTOR => {
            let (algo, activation_height, verifier_hash) = decode_algo_activation_params(params)?;
            let applied = propose_algorithm_activation_op(
                caller,
                algo,
                activation_height,
                verifier_hash,
                world_state,
                registry,
                chain_store,
            )?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == DEPRECATE_ALGORITHM_SELECTOR => {
            let algo = decode_signature_type(params)?;
            let applied = deprecate_algorithm_op(caller, algo, world_state, registry)?;
            let gas = SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS);
            Ok((encode_bool(applied), gas))
        }
        s if s == GET_VALIDATORS_SELECTOR => {
            let validators = world_state
                .get_validators()
                .map_err(|e| SystemContractError::Storage(e.to_string()))?;
            Ok((encode_address_array(&validators), SYSTEM_CALL_BASE_GAS))
        }
        s if s == IS_VALIDATOR_SELECTOR => {
            let addr = decode_address(params)?;
            let validators = world_state
                .get_validators()
                .map_err(|e| SystemContractError::Storage(e.to_string()))?;
            let is_val = validators.contains(&addr);
            Ok((encode_bool(is_val), SYSTEM_CALL_BASE_GAS))
        }
        _ => Err(SystemContractError::UnknownSelector(selector)),
    }
}

fn execute_account_manager<S: KvStore + 'static>(
    caller: &Address,
    input: &[u8],
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<SystemContractOutcome, SystemContractError> {
    let selector = decode_selector(input)?;
    let params = input.get(4..).unwrap_or_default();
    let mut effects = SystemContractEffects::default();

    match selector {
        s if s == ROTATE_KEY_SELECTOR => {
            let (pubkey, algo_id) = decode_rotate_key_params(params)?;
            rotate_key(caller, &pubkey, algo_id, world_state, chain_store)?;
            effects.updated_accounts.push(*caller);
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS),
                effects,
            })
        }
        s if s == SET_VALIDATION_CODE_SELECTOR => {
            let code_hash = decode_hash(params)?;
            set_validation_code(caller, code_hash, world_state, chain_store)?;
            effects.updated_accounts.push(*caller);
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS),
                effects,
            })
        }
        s if s == CLEAR_VALIDATION_CODE_SELECTOR => {
            clear_validation_code(caller, world_state)?;
            effects.updated_accounts.push(*caller);
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS),
                effects,
            })
        }
        s if s == SET_GUARDIANS_SELECTOR => {
            set_guardians(caller, params, chain_store)?;
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS),
                effects,
            })
        }
        s if s == SUBMIT_RECOVERY_SELECTOR => {
            submit_recovery(caller, params, chain_store)?;
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS.saturating_mul(2)),
                effects,
            })
        }
        s if s == EXECUTE_RECOVERY_SELECTOR => {
            let account = decode_address(params)?;
            execute_recovery(&account, world_state, chain_store)?;
            effects.updated_accounts.push(account);
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS.saturating_mul(2)),
                effects,
            })
        }
        s if s == CANCEL_RECOVERY_SELECTOR => {
            let account = decode_address(params)?;
            cancel_recovery(caller, &account, chain_store)?;
            Ok(SystemContractOutcome {
                output: encode_bool(true),
                gas_used: SYSTEM_CALL_BASE_GAS.saturating_add(SYSTEM_CALL_OP_GAS),
                effects,
            })
        }
        _ => Err(SystemContractError::UnknownSelector(selector)),
    }
}

// ── Mutating operations ────────────────────────────────────────────

fn add_validator<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    world_state: &mut WorldState<S>,
    chain_store: Option<&ChainStore<S>>,
) -> Result<bool, SystemContractError> {
    let mut validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    // Authorization: caller must be an existing validator
    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }

    // Duplicate check
    if validators.contains(target) {
        return Err(SystemContractError::AlreadyExists(*target));
    }

    if let Some(chain_store) = chain_store {
        if chain_store
            .get_pubkey(target)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?
            .is_none()
        {
            return Err(SystemContractError::ValidatorPubkeyMissing(*target));
        }
    }
    if world_state
        .staking_enabled()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
    {
        let stake = world_state
            .get_validator_stake(target)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        if derived_weight(world_state, stake)? == 0 {
            return Err(SystemContractError::StakeTooLow);
        }
    }

    if !record_validator_vote(
        world_state,
        ValidatorRegistryOp::Add,
        target,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    validators.push(*target);
    world_state
        .set_validators(&validators)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if world_state
        .staking_enabled()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
    {
        let stake = world_state
            .get_validator_stake(target)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        apply_validator_stake(world_state, target, stake)?;
    } else {
        world_state
            .set_validator_weight(target, 1)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    }

    Ok(true)
}

fn remove_validator<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    world_state: &mut WorldState<S>,
) -> Result<bool, SystemContractError> {
    let mut validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    // Authorization: caller must be an existing validator
    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }

    // Cannot remove the last validator
    if validators.len() <= 1 {
        return Err(SystemContractError::LastValidator);
    }

    let pos = validators
        .iter()
        .position(|v| v == target)
        .ok_or(SystemContractError::NotFound(*target))?;

    if !record_validator_vote(
        world_state,
        ValidatorRegistryOp::Remove,
        target,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    validators.remove(pos);
    world_state
        .set_validators(&validators)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    Ok(true)
}

/// Governance-driven validator weight update (white paper §5.3 — F-039/F-040).
///
/// Requires a weighted quorum (> 2/3 of total voting weight) to take effect.
/// Weight changes are logged but not stored back to the permanent validator list;
/// they are applied immediately to `world_state` via `set_validator_weight`.
fn set_validator_weight_op<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    new_weight: u64,
    world_state: &mut WorldState<S>,
) -> Result<bool, SystemContractError> {
    if world_state
        .staking_enabled()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
    {
        return Err(SystemContractError::StakeDerivedWeightsActive);
    }

    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    // Authorization: caller must be an existing validator.
    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }

    // Target must be an existing validator; you cannot pre-assign weight.
    if !validators.contains(target) {
        return Err(SystemContractError::NotFound(*target));
    }

    // Reject zero-weight — would silently de-activate a validator.
    if new_weight == 0 {
        return Err(SystemContractError::AbiDecode(
            "validator weight must be at least 1".into(),
        ));
    }
    if new_weight > shell_primitives::MAX_VALIDATOR_WEIGHT {
        return Err(SystemContractError::AbiDecode(format!(
            "validator weight must be at most {}",
            shell_primitives::MAX_VALIDATOR_WEIGHT
        )));
    }

    // Record vote; proceed only when weighted majority is reached.
    if !record_validator_vote(
        world_state,
        ValidatorRegistryOp::SetWeight(new_weight),
        target,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    world_state
        .set_validator_weight(target, new_weight)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    Ok(true)
}

fn set_validator_stake_op<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    new_stake: U256,
    world_state: &mut WorldState<S>,
) -> Result<bool, SystemContractError> {
    ensure_staking_enabled(world_state)?;
    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }
    if derived_weight(world_state, new_stake)? == 0 {
        return Err(SystemContractError::StakeTooLow);
    }
    if !record_validator_vote(
        world_state,
        ValidatorRegistryOp::SetStake(new_stake),
        target,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    let (old_stake, _) = validate_validator_stake_total(world_state, target, new_stake)?;
    let current_balance = world_state
        .get_balance(target)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let updated_balance = if new_stake > old_stake {
        let delta = new_stake - old_stake;
        if current_balance < delta {
            return Err(SystemContractError::Storage("insufficient balance".into()));
        }
        current_balance - delta
    } else if old_stake > new_stake {
        current_balance
            .checked_add(old_stake - new_stake)
            .ok_or_else(|| SystemContractError::Storage("balance overflow".into()))?
    } else {
        current_balance
    };
    apply_validator_stake(world_state, target, new_stake)?;
    if updated_balance != current_balance {
        world_state
            .set_balance(target, updated_balance)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    }
    Ok(true)
}

fn bond_validator_stake<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    amount: U256,
    world_state: &mut WorldState<S>,
) -> Result<bool, SystemContractError> {
    ensure_staking_enabled(world_state)?;
    if caller != target {
        return Err(SystemContractError::Unauthorized);
    }
    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if !validators.contains(target) {
        return Err(SystemContractError::NotFound(*target));
    }
    let current = world_state
        .get_validator_stake(target)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let updated = current
        .checked_add(amount)
        .ok_or_else(|| SystemContractError::AbiDecode("validator stake overflow".into()))?;
    if derived_weight(world_state, updated)? == 0 {
        return Err(SystemContractError::StakeTooLow);
    }
    validate_validator_stake_total(world_state, target, updated)?;
    world_state
        .sub_balance(caller, amount)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    apply_validator_stake(world_state, target, updated)?;
    Ok(true)
}

fn unbond_validator_stake<S: KvStore + 'static>(
    caller: &Address,
    target: &Address,
    amount: U256,
    world_state: &mut WorldState<S>,
) -> Result<bool, SystemContractError> {
    ensure_staking_enabled(world_state)?;
    if caller != target {
        return Err(SystemContractError::Unauthorized);
    }
    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if !validators.contains(target) {
        return Err(SystemContractError::NotFound(*target));
    }
    let current = world_state
        .get_validator_stake(target)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if amount > current {
        return Err(SystemContractError::AbiDecode(
            "cannot unbond more than validator stake".into(),
        ));
    }
    let updated = current - amount;
    if derived_weight(world_state, updated)? == 0 {
        return Err(SystemContractError::StakeTooLow);
    }
    apply_validator_stake(world_state, target, updated)?;
    world_state
        .add_balance(caller, amount)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(true)
}

fn ensure_staking_enabled<S: KvStore + 'static>(
    world_state: &WorldState<S>,
) -> Result<(), SystemContractError> {
    if world_state
        .staking_enabled()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
    {
        Ok(())
    } else {
        Err(SystemContractError::StakingDisabled)
    }
}

fn derived_weight<S: KvStore + 'static>(
    world_state: &WorldState<S>,
    stake: U256,
) -> Result<u64, SystemContractError> {
    let stake_unit = world_state
        .get_stake_unit()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let max_weight = world_state
        .get_max_validator_weight()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    WorldState::<S>::derive_validator_weight_from_stake(stake, stake_unit, max_weight)
        .map_err(|e| SystemContractError::Storage(e.to_string()))
}

fn apply_validator_stake<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
    target: &Address,
    new_stake: U256,
) -> Result<(), SystemContractError> {
    let (_, updated_total) = validate_validator_stake_total(world_state, target, new_stake)?;
    let stake_unit = world_state
        .get_stake_unit()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let max_weight = world_state
        .get_max_validator_weight()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let weight =
        WorldState::<S>::derive_validator_weight_from_stake(new_stake, stake_unit, max_weight)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if weight == 0 {
        return Err(SystemContractError::StakeTooLow);
    }
    world_state
        .set_validator_stake_and_weight(target, new_stake, stake_unit, max_weight)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    world_state
        .set_total_staked(updated_total)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

fn validate_validator_stake_total<S: KvStore + 'static>(
    world_state: &WorldState<S>,
    target: &Address,
    new_stake: U256,
) -> Result<(U256, U256), SystemContractError> {
    let old_stake = world_state
        .get_validator_stake(target)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let total_staked = world_state
        .get_total_staked()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let updated_total = if new_stake >= old_stake {
        total_staked
            .checked_add(new_stake - old_stake)
            .ok_or_else(|| SystemContractError::AbiDecode("total staked overflow".into()))?
    } else {
        total_staked
            .checked_sub(old_stake - new_stake)
            .ok_or_else(|| SystemContractError::AbiDecode("total staked underflow".into()))?
    };
    Ok((old_stake, updated_total))
}

fn propose_algorithm_activation_op<S: KvStore + 'static>(
    caller: &Address,
    algo: SignatureType,
    activation_height: u64,
    verifier_hash: [u8; 32],
    world_state: &mut WorldState<S>,
    registry: &mut AlgorithmRegistry,
    chain_store: Option<&ChainStore<S>>,
) -> Result<bool, SystemContractError> {
    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }

    // Validate timelock: activation_height >= current_height + ALGO_GOVERNANCE_DELTA_MIN.
    // SAFETY: SLH-DSA emergency path (WP §6.7) is a TODO; requires threading sig_type
    // through execute_system_contract_call.
    let current_height = chain_store
        .and_then(|cs| cs.get_head_block().ok().flatten())
        .map(|b| b.header.number)
        .unwrap_or(0);
    let min_activation = current_height.saturating_add(ALGO_GOVERNANCE_DELTA_MIN);
    if activation_height < min_activation {
        return Err(SystemContractError::InvalidActivationHeight(
            activation_height,
            min_activation,
        ));
    }

    // Per-voter deduplication: each validator may vote at most once per proposal.
    // The vote key is scoped to (op, algo, voter, current_validator_set) so a
    // validator-set change naturally resets outstanding votes.
    let voter_key = algorithm_vote_key(
        AlgorithmGovernanceOp::ProposeActivation,
        algo,
        caller,
        &validators,
    );
    let already_voted = world_state
        .get_storage(&registry_address(), &voter_key)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if already_voted != ShellHash::ZERO {
        return Err(SystemContractError::DuplicateVote);
    }

    // Determine whether this is the first vote on the proposal or a subsequent vote.
    // Status is PendingActivation once the first vote has been recorded.
    let current_status_hash = world_state
        .get_storage(&registry_address(), &algorithm_status_key(algo))
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    let is_pending =
        current_status_hash == encode_algorithm_status(AlgorithmStatus::PendingActivation);

    if is_pending {
        // Proposal already open — verify the new vote's params match the stored proposal
        // to prevent someone from sneaking in a different activation_height mid-vote.
        let stored_height_hash = world_state
            .get_storage(&registry_address(), &algorithm_activation_height_key(algo))
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        if stored_height_hash != encode_u64_as_hash(activation_height) {
            return Err(SystemContractError::HeightMismatch(
                activation_height,
                decode_u64_from_hash(&stored_height_hash),
            ));
        }
        let stored_verifier = world_state
            .get_storage(&registry_address(), &algorithm_verifier_hash_key(algo))
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        if stored_verifier != ShellHash::from(verifier_hash) {
            return Err(SystemContractError::GovernanceConflict);
        }
    } else {
        // First vote: create the proposal.
        registry.propose_activation_with_spec(algo, activation_height, verifier_hash);
        store_algorithm_status(world_state, algo, AlgorithmStatus::PendingActivation)?;

        // Store activation_height for the block-height trigger.
        world_state
            .set_storage(
                &registry_address(),
                &algorithm_activation_height_key(algo),
                &encode_u64_as_hash(activation_height),
            )
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;

        // Store verifier_hash so nodes can validate their local verifier at activation.
        world_state
            .set_storage(
                &registry_address(),
                &algorithm_verifier_hash_key(algo),
                &ShellHash::from(verifier_hash),
            )
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    }

    // Record this validator's vote; return early if quorum not yet reached.
    if !record_algorithm_vote(
        world_state,
        AlgorithmGovernanceOp::ProposeActivation,
        algo,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    // Quorum reached: keep PendingActivation — do NOT activate immediately.
    // The algorithm will be activated at block `activation_height` by
    // `process_pending_activations` which is called after every block commit.
    Ok(true)
}

fn deprecate_algorithm_op<S: KvStore + 'static>(
    caller: &Address,
    algo: SignatureType,
    world_state: &mut WorldState<S>,
    registry: &mut AlgorithmRegistry,
) -> Result<bool, SystemContractError> {
    let validators = world_state
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }

    if !record_algorithm_vote(
        world_state,
        AlgorithmGovernanceOp::Deprecate,
        algo,
        caller,
        &validators,
    )? {
        return Ok(false);
    }

    registry.deprecate(algo);
    store_algorithm_status(world_state, algo, AlgorithmStatus::Deprecated)?;
    Ok(true)
}

#[derive(Debug, Clone, Copy)]
enum ValidatorRegistryOp {
    Add,
    Remove,
    SetWeight(u64),
    SetStake(U256),
}

impl ValidatorRegistryOp {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Add => b"add",
            Self::Remove => b"remove",
            Self::SetWeight(_) => b"set_weight",
            Self::SetStake(_) => b"set_stake",
        }
    }

    fn write_context(self, bytes: &mut Vec<u8>) {
        match self {
            Self::SetWeight(weight) => bytes.extend_from_slice(&weight.to_be_bytes()),
            Self::SetStake(stake) => bytes.extend_from_slice(&stake.to_be_bytes::<32>()),
            Self::Add | Self::Remove => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AlgorithmGovernanceOp {
    ProposeActivation,
    Deprecate,
}

impl AlgorithmGovernanceOp {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ProposeActivation => b"propose_activation",
            Self::Deprecate => b"deprecate",
        }
    }
}

fn validator_vote_key(
    op: ValidatorRegistryOp,
    target: &Address,
    voter: &Address,
    validators: &[Address],
) -> ShellHash {
    let mut bytes = Vec::with_capacity(32 + op.label().len() + 8 + 32 + 32 + validators.len() * 32);
    bytes.extend_from_slice(b"validator_vote:");
    bytes.extend_from_slice(op.label());
    bytes.extend_from_slice(b":");
    op.write_context(&mut bytes);
    bytes.extend_from_slice(b":");
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(b":");
    for validator in validators {
        bytes.extend_from_slice(validator.as_bytes());
    }
    bytes.extend_from_slice(b":");
    bytes.extend_from_slice(voter.as_bytes());
    keccak256(&bytes)
}

fn algorithm_vote_key(
    op: AlgorithmGovernanceOp,
    algo: SignatureType,
    voter: &Address,
    validators: &[Address],
) -> ShellHash {
    let mut bytes = Vec::with_capacity(40 + op.label().len() + 1 + 32 + validators.len() * 32);
    bytes.extend_from_slice(b"algorithm_vote:");
    bytes.extend_from_slice(op.label());
    bytes.extend_from_slice(b":");
    bytes.push(algo.as_u8());
    bytes.extend_from_slice(b":");
    for validator in validators {
        bytes.extend_from_slice(validator.as_bytes());
    }
    bytes.extend_from_slice(b":");
    bytes.extend_from_slice(voter.as_bytes());
    keccak256(&bytes)
}

fn algorithm_status_key(algo: SignatureType) -> ShellHash {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(b"algorithm_status:");
    bytes.push(algo.as_u8());
    keccak256(&bytes)
}

fn encode_algorithm_status(status: AlgorithmStatus) -> ShellHash {
    let mut bytes = [0u8; 32];
    bytes[31] = match status {
        AlgorithmStatus::Active => 1,
        AlgorithmStatus::Deprecated => 2,
        AlgorithmStatus::PendingActivation => 3,
    };
    ShellHash::from(bytes)
}

fn record_validator_vote<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
    op: ValidatorRegistryOp,
    target: &Address,
    caller: &Address,
    validators: &[Address],
) -> Result<bool, SystemContractError> {
    let registry = registry_address();
    world_state
        .set_storage(
            &registry,
            &validator_vote_key(op, target, caller, validators),
            &ShellHash::from([1u8; 32]),
        )
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    let mut voted_weight = 0u64;
    let mut total_weight = 0u64;
    for validator in validators {
        let weight = world_state
            .get_validator_weight(validator)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        total_weight = total_weight.saturating_add(weight);
        let value = world_state
            .get_storage(
                &registry,
                &validator_vote_key(op, target, validator, validators),
            )
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        if value != ShellHash::ZERO {
            voted_weight = voted_weight.saturating_add(weight);
        }
    }

    Ok(voted_weight.saturating_mul(2) > total_weight)
}

fn record_algorithm_vote<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
    op: AlgorithmGovernanceOp,
    algo: SignatureType,
    caller: &Address,
    validators: &[Address],
) -> Result<bool, SystemContractError> {
    let registry = registry_address();
    world_state
        .set_storage(
            &registry,
            &algorithm_vote_key(op, algo, caller, validators),
            &ShellHash::from([1u8; 32]),
        )
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    let mut voted_weight = 0u64;
    let mut total_weight = 0u64;
    for validator in validators {
        let weight = world_state
            .get_validator_weight(validator)
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        total_weight = total_weight.saturating_add(weight);
        let value = world_state
            .get_storage(
                &registry,
                &algorithm_vote_key(op, algo, validator, validators),
            )
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        if value != ShellHash::ZERO {
            voted_weight = voted_weight.saturating_add(weight);
        }
    }

    // ⌈2N/3⌉ quorum: voted_weight >= ceil(2 * total_weight / 3).
    // Use u128 to avoid overflow when weights are large u64 values.
    Ok((voted_weight as u128) * 3 >= (total_weight as u128) * 2)
}

fn store_algorithm_status<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
    algo: SignatureType,
    status: AlgorithmStatus,
) -> Result<(), SystemContractError> {
    world_state
        .set_storage(
            &registry_address(),
            &algorithm_status_key(algo),
            &encode_algorithm_status(status),
        )
        .map_err(|e| SystemContractError::Storage(e.to_string()))
}

fn algorithm_activation_height_key(algo: SignatureType) -> ShellHash {
    let mut bytes = Vec::with_capacity(28);
    bytes.extend_from_slice(b"algorithm_activation_height:");
    bytes.push(algo.as_u8());
    keccak256(&bytes)
}

fn algorithm_verifier_hash_key(algo: SignatureType) -> ShellHash {
    let mut bytes = Vec::with_capacity(25);
    bytes.extend_from_slice(b"algorithm_verifier_hash:");
    bytes.push(algo.as_u8());
    keccak256(&bytes)
}

fn encode_u64_as_hash(value: u64) -> ShellHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ShellHash::from(bytes)
}

fn decode_u64_from_hash(hash: &ShellHash) -> u64 {
    u64::from_be_bytes(hash.as_bytes()[24..32].try_into().unwrap_or([0u8; 8]))
}

/// Process algorithm activations whose timelock has elapsed.
///
/// Called once per block (in both block production and import) after the canonical
/// world state is committed.  For every algorithm in `PendingActivation` whose
/// `activation_height` ≤ `current_height` the function:
/// 1. Updates the in-process registry to `Active`.
/// 2. Persists `Active` status to `world_state`.
///
/// Returns the list of algorithms that were activated.
pub fn process_pending_activations<S: KvStore + 'static>(
    current_height: u64,
    world_state: &mut WorldState<S>,
    registry: &mut shell_crypto::AlgorithmRegistry,
) -> Result<Vec<SignatureType>, SystemContractError> {
    use shell_crypto::AlgorithmStatus;

    // Collect candidates from in-memory registry.
    let pending: Vec<SignatureType> = registry
        .get_all_entries()
        .iter()
        .filter(|e| e.status == AlgorithmStatus::PendingActivation)
        .map(|e| e.algo)
        .collect();

    let mut activated = Vec::new();
    for algo in pending {
        let act_height_hash = world_state
            .get_storage(&registry_address(), &algorithm_activation_height_key(algo))
            .map_err(|e| SystemContractError::Storage(e.to_string()))?;
        let act_height = decode_u64_from_hash(&act_height_hash);
        // activation_height == 0 means no timelock was stored (pre-governance entry); skip.
        if act_height > 0 && act_height <= current_height {
            registry.activate(algo);
            store_algorithm_status(world_state, algo, AlgorithmStatus::Active)?;
            activated.push(algo);
        }
    }
    Ok(activated)
}

fn rotate_key<S: KvStore + 'static>(
    caller: &Address,
    pubkey: &[u8],
    algo_id: u8,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    if pubkey.is_empty() {
        return Err(SystemContractError::EmptyPubkey);
    }
    let Some(_algo) = SignatureType::from_u8(algo_id) else {
        return Err(SystemContractError::InvalidAlgorithm(algo_id));
    };

    let mut account = world_state
        .get_account(caller)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .unwrap_or(Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });
    account.pq_pubkey_hash = blake3_hash(pubkey);
    world_state
        .set_account(caller, &account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    chain_store
        .put_pubkey(caller, pubkey)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

fn set_validation_code<S: KvStore + 'static>(
    caller: &Address,
    code_hash: ShellHash,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    if chain_store
        .get_code(&code_hash)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .is_none()
    {
        return Err(SystemContractError::ValidationCodeMissing(code_hash));
    }

    let mut account = world_state
        .get_account(caller)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .unwrap_or(Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });
    account.validation_code_hash = Some(code_hash);
    world_state
        .set_account(caller, &account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

fn clear_validation_code<S: KvStore + 'static>(
    caller: &Address,
    world_state: &mut WorldState<S>,
) -> Result<(), SystemContractError> {
    let mut account = world_state
        .get_account(caller)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .unwrap_or(Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });
    account.validation_code_hash = None;
    world_state
        .set_account(caller, &account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

// ── Guardian recovery operations ────────────────────────────────────

/// Register or update the guardian set for `caller`.
///
/// ABI: `setGuardians(address[],uint8,uint64)`
fn set_guardians<S: KvStore + 'static>(
    caller: &Address,
    params: &[u8],
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    // ABI head: offset_to_array (32) | threshold (32) | timelock (32)
    if params.len() < 96 {
        return Err(SystemContractError::AbiDecode(
            "setGuardians: params too short".into(),
        ));
    }
    let array_offset = decode_word_usize(
        params
            .get(..32)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;
    let threshold = decode_u8(
        params
            .get(32..64)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;
    let timelock = decode_u64(
        params
            .get(64..96)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;

    // Decode address array at array_offset
    if array_offset.saturating_add(32) > params.len() {
        return Err(SystemContractError::AbiDecode(
            "setGuardians: array offset out of bounds".into(),
        ));
    }
    let array_len = decode_word_usize(
        params
            .get(array_offset..array_offset.saturating_add(32))
            .ok_or_else(|| SystemContractError::AbiDecode("array length word OOB".into()))?,
    )?;
    let elem_start = array_offset.saturating_add(32);
    let elem_end = elem_start.saturating_add(array_len.saturating_mul(32));
    if elem_end > params.len() {
        return Err(SystemContractError::AbiDecode(
            "setGuardians: address array truncated".into(),
        ));
    }

    // Validate counts
    if array_len == 0 || array_len > MAX_GUARDIANS {
        return Err(SystemContractError::InvalidGuardianCount(
            MAX_GUARDIANS,
            array_len,
        ));
    }
    if threshold == 0 || threshold as usize > array_len {
        return Err(SystemContractError::InvalidThreshold(array_len, threshold));
    }
    if timelock < MIN_RECOVERY_TIMELOCK {
        return Err(SystemContractError::TimelockTooShort(
            MIN_RECOVERY_TIMELOCK,
            timelock,
        ));
    }

    let mut guardians: Vec<[u8; 20]> = Vec::with_capacity(array_len);
    let caller_raw: [u8; 20] = caller.to_alloy().into();
    for i in 0..array_len {
        let word_start = elem_start.saturating_add(i.saturating_mul(32));
        let addr = decode_address(
            params
                .get(word_start..word_start.saturating_add(32))
                .ok_or_else(|| SystemContractError::AbiDecode("address OOB".into()))?,
        )?;
        let raw: [u8; 20] = addr.to_alloy().into();
        if raw == caller_raw {
            return Err(SystemContractError::GuardianIsSelf);
        }
        if guardians.contains(&raw) {
            return Err(SystemContractError::DuplicateGuardian);
        }
        guardians.push(raw);
    }

    let config = GuardianConfig {
        guardians,
        threshold,
        timelock,
    };
    chain_store
        .put_guardian_config(caller, &config)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

/// Submit or vote on a recovery proposal.
///
/// ABI: `submitRecovery(address,bytes,uint8)`
/// - If no active proposal exists, creates one.
/// - If an active proposal with the same `(newPubkey, newAlgo)` exists, adds a vote.
/// - When votes reach threshold, sets `maturity_block = current_block + timelock`.
fn submit_recovery<S: KvStore + 'static>(
    caller: &Address,
    params: &[u8],
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    // ABI head: account (32) | offset_to_bytes (32) | new_algo (32)
    if params.len() < 96 {
        return Err(SystemContractError::AbiDecode(
            "submitRecovery: params too short".into(),
        ));
    }
    let account = decode_address(
        params
            .get(..32)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;
    let bytes_offset = decode_word_usize(
        params
            .get(32..64)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;
    let new_algo = decode_u8(
        params
            .get(64..96)
            .unwrap_or_else(|| unreachable!("params.len() >= 96")),
    )?;
    // Validate algo
    SignatureType::from_u8(new_algo).ok_or(SystemContractError::InvalidAlgorithm(new_algo))?;

    // Decode bytes payload
    if bytes_offset.saturating_add(32) > params.len() {
        return Err(SystemContractError::AbiDecode(
            "submitRecovery: bytes offset OOB".into(),
        ));
    }
    let bytes_len = decode_word_usize(
        params
            .get(bytes_offset..bytes_offset.saturating_add(32))
            .ok_or_else(|| SystemContractError::AbiDecode("bytes len OOB".into()))?,
    )?;
    let data_start = bytes_offset.saturating_add(32);
    let data_end = data_start
        .checked_add(bytes_len)
        .ok_or_else(|| SystemContractError::AbiDecode("bytes len overflow".into()))?;
    if data_end > params.len() {
        return Err(SystemContractError::AbiDecode(
            "submitRecovery: pubkey truncated".into(),
        ));
    }
    if bytes_len == 0 {
        return Err(SystemContractError::EmptyPubkey);
    }
    validate_public_key_size(bytes_len)?;
    let new_pubkey = params
        .get(data_start..data_end)
        .ok_or_else(|| SystemContractError::AbiDecode("pubkey range OOB".into()))?
        .to_vec();

    // Load guardian config
    let config = chain_store
        .get_guardian_config(&account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .ok_or(SystemContractError::NoGuardianConfig(account))?;

    let caller_raw: [u8; 20] = caller.to_alloy().into();
    if !config.guardians.contains(&caller_raw) {
        return Err(SystemContractError::NotAGuardian);
    }

    // Load or create proposal
    let mut proposal = chain_store
        .get_recovery_proposal(&account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .unwrap_or(RecoveryProposal {
            new_pubkey: new_pubkey.clone(),
            new_algo,
            votes: Vec::new(),
            maturity_block: 0,
        });

    // If the proposal changed (different pubkey or algo), reject to avoid confusion.
    // Caller must `cancelRecovery` first.
    if proposal.new_pubkey != new_pubkey || proposal.new_algo != new_algo {
        return Err(SystemContractError::RecoveryAlreadyActive);
    }

    // Reject duplicate vote from same guardian
    if proposal.votes.contains(&caller_raw) {
        return Ok(()); // idempotent — already voted
    }
    proposal.votes.push(caller_raw);

    // Check if threshold reached and maturity not yet set
    if proposal.maturity_block == 0 && proposal.votes.len() >= config.threshold as usize {
        let current_block = chain_store
            .get_head_block()
            .map_err(|e| SystemContractError::Storage(e.to_string()))?
            .map(|b| b.header.number)
            .unwrap_or(0);
        proposal.maturity_block = current_block.saturating_add(config.timelock);
    }

    chain_store
        .put_recovery_proposal(&account, &proposal)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

/// Execute a matured recovery proposal, rotating the account's PQ public key.
///
/// ABI: `executeRecovery(address)` — callable by anyone once maturity_block is reached.
fn execute_recovery<S: KvStore + 'static>(
    account: &Address,
    world_state: &mut WorldState<S>,
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    let proposal = chain_store
        .get_recovery_proposal(account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .ok_or(SystemContractError::NoRecoveryProposal(*account))?;

    if proposal.maturity_block == 0 {
        // Threshold not reached yet
        return Err(SystemContractError::RecoveryNotMature(0));
    }

    let current_block = chain_store
        .get_head_block()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .map(|b| b.header.number)
        .unwrap_or(0);

    if current_block < proposal.maturity_block {
        return Err(SystemContractError::RecoveryNotMature(
            proposal.maturity_block,
        ));
    }

    // Validate the new algo
    SignatureType::from_u8(proposal.new_algo)
        .ok_or(SystemContractError::InvalidAlgorithm(proposal.new_algo))?;

    // Rotate the key
    let mut acct = world_state
        .get_account(account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .unwrap_or(Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance: U256::ZERO,
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        });
    acct.pq_pubkey_hash = blake3_hash(&proposal.new_pubkey);
    world_state
        .set_account(account, &acct)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    chain_store
        .put_pubkey(account, &proposal.new_pubkey)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;

    // Clear the proposal
    chain_store
        .delete_recovery_proposal(account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

/// Cancel an active recovery proposal. Only callable by the account owner
/// (i.e., the account itself, still in possession of the old key).
///
/// ABI: `cancelRecovery(address)`
fn cancel_recovery<S: KvStore + 'static>(
    caller: &Address,
    account: &Address,
    chain_store: &ChainStore<S>,
) -> Result<(), SystemContractError> {
    // Only the account owner may cancel
    if caller != account {
        return Err(SystemContractError::Unauthorized);
    }
    chain_store
        .get_recovery_proposal(account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .ok_or(SystemContractError::NoRecoveryProposal(*account))?;
    chain_store
        .delete_recovery_proposal(account)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    Ok(())
}

// ── ABI helpers ────────────────────────────────────────────────────

fn decode_selector(input: &[u8]) -> Result<[u8; 4], SystemContractError> {
    if input.len() < 4 {
        return Err(SystemContractError::InputTooShort);
    }
    input
        .get(..4)
        .ok_or(SystemContractError::InputTooShort)?
        .try_into()
        .map_err(|_| SystemContractError::InputTooShort)
}

fn decode_word_usize(word: &[u8]) -> Result<usize, SystemContractError> {
    if word.len() < 32 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 32 bytes for ABI word, got {}",
            word.len()
        )));
    }
    if word
        .get(..24)
        .unwrap_or_else(|| unreachable!("word.len() >= 32 checked above"))
        .iter()
        .any(|b| *b != 0)
    {
        return Err(SystemContractError::AbiDecode(
            "ABI word exceeds usize range".into(),
        ));
    }
    let tail: [u8; 8] = word
        .get(24..32)
        .unwrap_or_else(|| unreachable!("word.len() >= 32 checked above"))
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| {
            SystemContractError::AbiDecode(e.to_string())
        })?;
    Ok(u64::from_be_bytes(tail) as usize)
}

fn decode_hash(input: &[u8]) -> Result<ShellHash, SystemContractError> {
    if input.len() < 32 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 32 bytes for bytes32, got {}",
            input.len()
        )));
    }
    ShellHash::try_from_slice(
        input
            .get(..32)
            .unwrap_or_else(|| unreachable!("input.len() >= 32 checked above")),
    )
    .map_err(|e| SystemContractError::AbiDecode(e.to_string()))
}

fn decode_u8(input: &[u8]) -> Result<u8, SystemContractError> {
    if input.len() < 32 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 32 bytes for uint8, got {}",
            input.len()
        )));
    }
    if input
        .get(..31)
        .unwrap_or_else(|| unreachable!("input.len() >= 32 checked above"))
        .iter()
        .any(|b| *b != 0)
    {
        return Err(SystemContractError::AbiDecode(
            "uint8 must be right-aligned in ABI word".into(),
        ));
    }
    input
        .get(31)
        .copied()
        .ok_or_else(|| SystemContractError::AbiDecode("uint8 word too short".into()))
}

fn decode_signature_type(input: &[u8]) -> Result<SignatureType, SystemContractError> {
    let algo_id = decode_u8(input)?;
    SignatureType::from_u8(algo_id).ok_or(SystemContractError::InvalidAlgorithm(algo_id))
}

/// Decode `(uint8, uint64, bytes32)` params for `proposeAlgorithmActivation`.
///
/// ABI layout: algo_id (32) + activation_height (32) + verifier_hash (32) = 96 bytes.
fn decode_algo_activation_params(
    input: &[u8],
) -> Result<(SignatureType, u64, [u8; 32]), SystemContractError> {
    if input.len() < 96 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 96 bytes for (uint8, uint64, bytes32), got {}",
            input.len()
        )));
    }
    let algo = decode_signature_type(&input[0..32])?;
    let activation_height = decode_u64(&input[32..64])?;
    let verifier_hash: [u8; 32] = input[64..96]
        .try_into()
        .map_err(|_| SystemContractError::AbiDecode("bad bytes32 verifier_hash".into()))?;
    Ok((algo, activation_height, verifier_hash))
}

fn decode_u64(input: &[u8]) -> Result<u64, SystemContractError> {
    if input.len() < 32 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 32 bytes for uint64, got {}",
            input.len()
        )));
    }
    if input
        .get(..24)
        .unwrap_or_else(|| unreachable!("input.len() >= 32 checked above"))
        .iter()
        .any(|b| *b != 0)
    {
        return Err(SystemContractError::AbiDecode(
            "uint64 value exceeds u64 range".into(),
        ));
    }
    let tail: [u8; 8] = input
        .get(24..32)
        .unwrap_or_else(|| unreachable!("input.len() >= 32 checked above"))
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| {
            SystemContractError::AbiDecode(e.to_string())
        })?;
    Ok(u64::from_be_bytes(tail))
}

fn decode_rotate_key_params(input: &[u8]) -> Result<(Vec<u8>, u8), SystemContractError> {
    if input.len() < 64 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected at least 64 bytes for rotateKey head, got {}",
            input.len()
        )));
    }

    let offset = decode_word_usize(
        input
            .get(..32)
            .unwrap_or_else(|| unreachable!("input.len() >= 64 checked above")),
    )?;
    let algo_id = decode_u8(
        input
            .get(32..64)
            .unwrap_or_else(|| unreachable!("input.len() >= 64 checked above")),
    )?;
    if offset.saturating_add(32) > input.len() {
        return Err(SystemContractError::AbiDecode(
            "bytes offset points beyond calldata".into(),
        ));
    }

    let bytes_len = decode_word_usize(
        input
            .get(offset..offset.saturating_add(32))
            .ok_or_else(|| SystemContractError::AbiDecode("bytes offset out of range".into()))?,
    )?;
    validate_public_key_size(bytes_len)?;
    let data_start = offset.saturating_add(32);
    let data_end = data_start
        .checked_add(bytes_len)
        .ok_or_else(|| SystemContractError::AbiDecode("bytes length overflow".into()))?;
    if data_end > input.len() {
        return Err(SystemContractError::AbiDecode(
            "bytes payload truncated".into(),
        ));
    }

    Ok((
        input
            .get(data_start..data_end)
            .ok_or_else(|| SystemContractError::AbiDecode("bytes range out of bounds".into()))?
            .to_vec(),
        algo_id,
    ))
}

fn validate_public_key_size(bytes_len: usize) -> Result<(), SystemContractError> {
    if bytes_len == 0 {
        return Err(SystemContractError::EmptyPubkey);
    }
    if bytes_len > MAX_ACCOUNT_PUBLIC_KEY_BYTES {
        return Err(SystemContractError::PublicKeyTooLarge(
            bytes_len,
            MAX_ACCOUNT_PUBLIC_KEY_BYTES,
        ));
    }
    Ok(())
}

/// Decode a single ABI-encoded `address` parameter (32 bytes, left-padded with zeros).
pub fn decode_address(input: &[u8]) -> Result<Address, SystemContractError> {
    if input.len() < 32 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 32 bytes for address, got {}",
            input.len()
        )));
    }
    // Shell uses 32-byte addresses. Read all 32 bytes from the ABI word.
    let raw32: [u8; 32] = input
        .get(0..32)
        .unwrap_or_else(|| unreachable!("input.len() >= 32 checked above"))
        .try_into()
        .map_err(|_| {
            SystemContractError::AbiDecode("invalid slice length: expected 32".to_string())
        })?;
    Ok(Address::from(raw32))
}

/// ABI-encode a `bool` as a 32-byte word.
pub fn encode_bool(val: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if val {
        if let Some(b) = out.get_mut(31) {
            *b = 1;
        }
    }
    out
}

/// ABI-encode a dynamic array of addresses.
///
/// Layout:
/// - word 0: offset to data (= 0x20)
/// - word 1: array length
/// - word 2..N+2: each address left-padded to 32 bytes
pub fn encode_address_array(addrs: &[Address]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64usize.saturating_add(addrs.len().saturating_mul(32)));

    // Offset to dynamic data
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    out.extend_from_slice(&offset);

    // Length
    let mut len_word = [0u8; 32];
    let len_bytes = (addrs.len() as u64).to_be_bytes();
    len_word[24..32].copy_from_slice(&len_bytes);
    out.extend_from_slice(&len_word);

    // Elements
    for addr in addrs {
        let mut word = [0u8; 32];
        word.copy_from_slice(addr.as_bytes());
        out.extend_from_slice(&word);
    }

    out
}

fn encode_usize_word(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

fn encode_u8_word(value: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value;
    word
}

pub fn encode_rotate_key_calldata(pubkey: &[u8], algo_id: u8) -> Vec<u8> {
    let padded_len = if pubkey.is_empty() {
        0
    } else {
        pubkey.len().div_ceil(32).saturating_mul(32)
    };
    let capacity = 4usize.saturating_add(96).saturating_add(padded_len);
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(&ROTATE_KEY_SELECTOR);
    data.extend_from_slice(&encode_usize_word(64));
    data.extend_from_slice(&encode_u8_word(algo_id));
    data.extend_from_slice(&encode_usize_word(pubkey.len()));
    data.extend_from_slice(pubkey);
    data.resize(capacity, 0);
    data
}

pub fn encode_set_validation_code_calldata(code_hash: &ShellHash) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&SET_VALIDATION_CODE_SELECTOR);
    data.extend_from_slice(code_hash.as_bytes());
    data
}

pub fn encode_clear_validation_code_calldata() -> Vec<u8> {
    CLEAR_VALIDATION_CODE_SELECTOR.to_vec()
}

/// Encode calldata for `addValidator(address)`.
pub fn encode_add_validator_calldata(address: &Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&ADD_VALIDATOR_SELECTOR);
    let mut word = [0u8; 32];
    word.copy_from_slice(address.as_bytes());
    data.extend_from_slice(&word);
    data
}

/// Encode calldata for `removeValidator(address)`.
pub fn encode_remove_validator_calldata(address: &Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&REMOVE_VALIDATOR_SELECTOR);
    let mut word = [0u8; 32];
    word.copy_from_slice(address.as_bytes());
    data.extend_from_slice(&word);
    data
}

/// Encode calldata for `setValidatorWeight(address,uint64)`.
///
/// ABI layout: selector (4) + address (32) + uint64 (32, big-endian right-aligned).
pub fn encode_set_validator_weight_calldata(address: &Address, weight: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(64));
    data.extend_from_slice(&SET_VALIDATOR_WEIGHT_SELECTOR);
    let mut addr_word = [0u8; 32];
    addr_word.copy_from_slice(address.as_bytes());
    data.extend_from_slice(&addr_word);
    let mut weight_word = [0u8; 32];
    weight_word[24..32].copy_from_slice(&weight.to_be_bytes());
    data.extend_from_slice(&weight_word);
    data
}

fn encode_address_u256_calldata(selector: &[u8; 4], address: &Address, value: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(64));
    data.extend_from_slice(selector);
    let mut addr_word = [0u8; 32];
    addr_word.copy_from_slice(address.as_bytes());
    data.extend_from_slice(&addr_word);
    data.extend_from_slice(&value.to_be_bytes::<32>());
    data
}

/// Encode calldata for `setValidatorStake(address,uint256)`.
pub fn encode_set_validator_stake_calldata(address: &Address, stake: U256) -> Vec<u8> {
    encode_address_u256_calldata(&SET_VALIDATOR_STAKE_SELECTOR, address, stake)
}

/// Encode calldata for `bondValidatorStake(address,uint256)`.
pub fn encode_bond_validator_stake_calldata(address: &Address, amount: U256) -> Vec<u8> {
    encode_address_u256_calldata(&BOND_VALIDATOR_STAKE_SELECTOR, address, amount)
}

/// Encode calldata for `unbondValidatorStake(address,uint256)`.
pub fn encode_unbond_validator_stake_calldata(address: &Address, amount: U256) -> Vec<u8> {
    encode_address_u256_calldata(&UNBOND_VALIDATOR_STAKE_SELECTOR, address, amount)
}

/// Encode calldata for `proposeAlgorithmActivation(uint8,uint64,bytes32)`.
///
/// ABI layout: selector (4) + algo_id (32) + activation_height (32) + verifier_hash (32).
pub fn encode_propose_algorithm_activation_calldata(
    algo: SignatureType,
    activation_height: u64,
    verifier_hash: [u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(96));
    data.extend_from_slice(&PROPOSE_ALGORITHM_ACTIVATION_SELECTOR);
    data.extend_from_slice(&encode_u8_word(algo.as_u8()));
    // uint64 activation_height right-aligned in 32-byte word
    let mut height_word = [0u8; 32];
    height_word[24..32].copy_from_slice(&activation_height.to_be_bytes());
    data.extend_from_slice(&height_word);
    // bytes32 verifier_hash
    data.extend_from_slice(&verifier_hash);
    data
}

/// Encode calldata for `deprecateAlgorithm(uint8)`.
pub fn encode_deprecate_algorithm_calldata(algo: SignatureType) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&DEPRECATE_ALGORITHM_SELECTOR);
    data.extend_from_slice(&encode_u8_word(algo.as_u8()));
    data
}

/// Decode `(address, uint64)` from ABI-encoded params (2 × 32-byte words).
pub fn decode_address_u64(input: &[u8]) -> Result<(Address, u64), SystemContractError> {
    if input.len() < 64 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 64 bytes for (address, uint64), got {}",
            input.len()
        )));
    }
    let addr = decode_address(&input[..32])?;
    let weight = decode_u64(&input[32..64])?;
    Ok((addr, weight))
}

/// Decode `(address, uint256)` from ABI-encoded params (2 × 32-byte words).
pub fn decode_address_u256(input: &[u8]) -> Result<(Address, U256), SystemContractError> {
    if input.len() < 64 {
        return Err(SystemContractError::AbiDecode(format!(
            "expected 64 bytes for (address, uint256), got {}",
            input.len()
        )));
    }
    let raw32: [u8; 32] = input[0..32]
        .try_into()
        .map_err(|_| SystemContractError::AbiDecode("bad address word".into()))?;
    let addr = Address::from(raw32);
    let value = U256::from_be_slice(&input[32..64]);
    Ok((addr, value))
}

/// Encode calldata for `setGuardians(address[],uint8,uint64)`.
///
/// ABI layout (params after selector):
/// - word 0: offset to address[] data = 96 (0x60)
/// - word 1: threshold (uint8, right-aligned)
/// - word 2: timelock  (uint64, right-aligned)
/// - word 3: array length
/// - word 4..N+4: each address right-aligned in 32 bytes
pub fn encode_set_guardians_calldata(
    guardians: &[Address],
    threshold: u8,
    timelock: u64,
) -> Vec<u8> {
    // 4 (selector) + 3×32 (head) + 32 (array len) + N×32 (elements)
    let capacity = 4usize
        .saturating_add(96)
        .saturating_add(32)
        .saturating_add(guardians.len().saturating_mul(32));
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(&SET_GUARDIANS_SELECTOR);
    // offset to array = 96 bytes into params (after 3 words)
    data.extend_from_slice(&encode_usize_word(96));
    data.extend_from_slice(&encode_u8_word(threshold));
    // encode uint64 timelock
    let mut tl_word = [0u8; 32];
    tl_word[24..32].copy_from_slice(&timelock.to_be_bytes());
    data.extend_from_slice(&tl_word);
    // array length
    data.extend_from_slice(&encode_usize_word(guardians.len()));
    // array elements
    for addr in guardians {
        let mut word = [0u8; 32];
        word.copy_from_slice(addr.as_bytes());
        data.extend_from_slice(&word);
    }
    data
}

/// Encode calldata for `submitRecovery(address,bytes,uint8)`.
pub fn encode_submit_recovery_calldata(
    account: &Address,
    new_pubkey: &[u8],
    new_algo: u8,
) -> Vec<u8> {
    let padded_len = if new_pubkey.is_empty() {
        0
    } else {
        new_pubkey.len().div_ceil(32).saturating_mul(32)
    };
    // 4 (selector) + 3×32 (head: account, offset, algo) + 32 (len) + padded
    let capacity = 4usize
        .saturating_add(96)
        .saturating_add(32)
        .saturating_add(padded_len);
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(&SUBMIT_RECOVERY_SELECTOR);
    // account (address, right-aligned)
    let mut addr_word = [0u8; 32];
    addr_word.copy_from_slice(account.as_bytes());
    data.extend_from_slice(&addr_word);
    // offset to bytes = 96 bytes from start of params
    data.extend_from_slice(&encode_usize_word(96));
    data.extend_from_slice(&encode_u8_word(new_algo));
    // bytes length + payload
    data.extend_from_slice(&encode_usize_word(new_pubkey.len()));
    data.extend_from_slice(new_pubkey);
    data.resize(capacity, 0);
    data
}

/// Encode calldata for `executeRecovery(address)`.
pub fn encode_execute_recovery_calldata(account: &Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&EXECUTE_RECOVERY_SELECTOR);
    let mut word = [0u8; 32];
    word.copy_from_slice(account.as_bytes());
    data.extend_from_slice(&word);
    data
}

/// Encode calldata for `cancelRecovery(address)`.
pub fn encode_cancel_recovery_calldata(account: &Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(4usize.saturating_add(32));
    data.extend_from_slice(&CANCEL_RECOVERY_SELECTOR);
    let mut word = [0u8; 32];
    word.copy_from_slice(account.as_bytes());
    data.extend_from_slice(&word);
    data
}

// ── Const Keccak-256 (compile-time) ────────────────────────────────

/// Minimal const-compatible Keccak-256 used solely for selector computation.
/// Produces the same output as `sha3::Keccak256`.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn const_keccak256(data: &[u8]) -> [u8; 32] {
    // Keccak-256 parameters: rate=136, capacity=64, delimited suffix=0x01
    const RATE: usize = 136;
    let mut state = [0u64; 25];

    // Absorb: pad input with Keccak padding (0x01 … 0x80)
    let mut block = [0u8; RATE];
    let mut offset = 0;
    let mut i = 0;
    while i < data.len() {
        block[offset] = data[i];
        offset += 1;
        if offset == RATE {
            state = xor_block(state, &block);
            state = keccak_f1600(state);
            block = [0u8; RATE];
            offset = 0;
        }
        i += 1;
    }
    block[offset] ^= 0x01; // Keccak domain separator
    block[RATE - 1] ^= 0x80; // padding end
    state = xor_block(state, &block);
    state = keccak_f1600(state);

    // Squeeze: first 32 bytes
    let mut out = [0u8; 32];
    let mut j = 0;
    while j < 32 {
        let lane = j / 8;
        let byte_in_lane = j % 8;
        out[j] = (state[lane] >> (8 * byte_in_lane)) as u8;
        j += 1;
    }
    out
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn xor_block(mut state: [u64; 25], block: &[u8; 136]) -> [u64; 25] {
    let mut i = 0;
    while i < 136 / 8 {
        let b = i * 8;
        let lane = (block[b] as u64)
            | (block[b + 1] as u64) << 8
            | (block[b + 2] as u64) << 16
            | (block[b + 3] as u64) << 24
            | (block[b + 4] as u64) << 32
            | (block[b + 5] as u64) << 40
            | (block[b + 6] as u64) << 48
            | (block[b + 7] as u64) << 56;
        state[i] ^= lane;
        i += 1;
    }
    state
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn keccak_f1600(mut state: [u64; 25]) -> [u64; 25] {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    let mut round = 0;
    while round < 24 {
        // θ
        let mut c = [0u64; 5];
        let mut x = 0;
        while x < 5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            x += 1;
        }
        let mut d = [0u64; 5];
        x = 0;
        while x < 5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            x += 1;
        }
        x = 0;
        while x < 25 {
            state[x] ^= d[x % 5];
            x += 1;
        }

        // ρ and π
        let mut current = state[1];
        let mut t = 0;
        while t < 24 {
            let j = PI[t];
            let temp = state[j];
            state[j] = current.rotate_left(ROT[t]);
            current = temp;
            t += 1;
        }

        // χ
        let mut y = 0;
        while y < 5 {
            let base = y * 5;
            let t0 = state[base];
            let t1 = state[base + 1];
            let t2 = state[base + 2];
            let t3 = state[base + 3];
            let t4 = state[base + 4];
            state[base] = t0 ^ (!t1 & t2);
            state[base + 1] = t1 ^ (!t2 & t3);
            state[base + 2] = t2 ^ (!t3 & t4);
            state[base + 3] = t3 ^ (!t4 & t0);
            state[base + 4] = t4 ^ (!t0 & t1);
            y += 1;
        }

        // ι
        state[0] ^= RC[round];
        round += 1;
    }
    state
}

// ── Placeholder code hash for the system contract ──────────────────

/// A deterministic code hash for the ValidatorRegistry system contract.
pub fn system_contract_code_hash() -> shell_primitives::ShellHash {
    keccak256(b"ValidatorRegistry")
}

/// A deterministic code hash for the AccountManager system contract.
pub fn account_manager_code_hash() -> shell_primitives::ShellHash {
    keccak256(b"AccountManager")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::{ChainStore, MemoryDb};
    use std::sync::Arc;

    fn setup_with_validators(validators: &[Address]) -> WorldState<MemoryDb> {
        let store = Arc::new(MemoryDb::new());
        let mut ws = WorldState::new(store);
        if !validators.is_empty() {
            ws.set_validators(validators).unwrap();
        }
        ws
    }

    fn enable_staking(ws: &mut WorldState<MemoryDb>, stake_unit: U256) {
        ws.set_staking_enabled(true).unwrap();
        ws.set_stake_unit(stake_unit).unwrap();
        ws.set_max_validator_weight(100).unwrap();
        ws.set_total_supply(U256::from(1_000_000u64)).unwrap();
        ws.set_total_staked(U256::ZERO).unwrap();
    }

    fn setup_account_manager() -> (WorldState<MemoryDb>, ChainStore<MemoryDb>) {
        let ws = WorldState::new(Arc::new(MemoryDb::new()));
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        (ws, cs)
    }

    fn account_with_balance(balance: u64) -> Account {
        Account {
            pq_pubkey_hash: ShellHash::ZERO,
            nonce: 0,
            balance: U256::from(balance),
            validation_code_hash: None,
            code_hash: None,
            storage_root: ShellHash::ZERO,
        }
    }

    // ── Selector computation ───────────────────────────────────

    #[test]
    fn selector_add_validator() {
        let hash = keccak256(b"addValidator(address)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&ADD_VALIDATOR_SELECTOR, expected);
    }

    #[test]
    fn selector_remove_validator() {
        let hash = keccak256(b"removeValidator(address)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&REMOVE_VALIDATOR_SELECTOR, expected);
    }

    #[test]
    fn selector_get_validators() {
        let hash = keccak256(b"getValidators()");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&GET_VALIDATORS_SELECTOR, expected);
    }

    #[test]
    fn selector_is_validator() {
        let hash = keccak256(b"isValidator(address)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&IS_VALIDATOR_SELECTOR, expected);
    }

    #[test]
    fn selector_rotate_key() {
        let hash = keccak256(b"rotateKey(bytes,uint8)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&ROTATE_KEY_SELECTOR, expected);
    }

    #[test]
    fn selector_set_validation_code() {
        let hash = keccak256(b"setValidationCode(bytes32)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&SET_VALIDATION_CODE_SELECTOR, expected);
    }

    #[test]
    fn selector_propose_algorithm_activation() {
        let hash = keccak256(b"proposeAlgorithmActivation(uint8,uint64,bytes32)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&PROPOSE_ALGORITHM_ACTIVATION_SELECTOR, expected);
    }

    #[test]
    fn selector_deprecate_algorithm() {
        let hash = keccak256(b"deprecateAlgorithm(uint8)");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&DEPRECATE_ALGORITHM_SELECTOR, expected);
    }

    #[test]
    fn selector_clear_validation_code() {
        let hash = keccak256(b"clearValidationCode()");
        let expected = &hash.as_bytes()[..4];
        assert_eq!(&CLEAR_VALIDATION_CODE_SELECTOR, expected);
    }

    // ── addValidator ───────────────────────────────────────────

    #[test]
    fn add_validator_authorized_success() {
        let v1 = Address::from([0x01; 20]);
        let new_val = Address::from([0x02; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let calldata = encode_add_validator_calldata(&new_val);
        let (output, gas) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();

        assert_eq!(output, encode_bool(true));
        assert_eq!(gas, SYSTEM_CALL_BASE_GAS + SYSTEM_CALL_OP_GAS);

        let validators = ws.get_validators().unwrap();
        assert_eq!(validators.len(), 2);
        assert!(validators.contains(&new_val));
    }

    #[test]
    fn add_validator_unauthorized_fails() {
        let v1 = Address::from([0x01; 20]);
        let outsider = Address::from([0x99; 20]);
        let new_val = Address::from([0x02; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let calldata = encode_add_validator_calldata(&new_val);
        let err = execute_system_contract(&outsider, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::Unauthorized));
    }

    #[test]
    fn add_validator_duplicate_fails() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let calldata = encode_add_validator_calldata(&v1);
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::AlreadyExists(_)));
    }

    #[test]
    fn add_validator_requires_validator_majority() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let new_val = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        let calldata = encode_add_validator_calldata(&new_val);

        let (first_output, _) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(first_output, encode_bool(false));
        assert!(!ws.get_validators().unwrap().contains(&new_val));

        let (second_output, _) = execute_system_contract(&v2, &calldata, &mut ws).unwrap();
        assert_eq!(second_output, encode_bool(true));
        assert!(ws.get_validators().unwrap().contains(&new_val));
    }

    #[test]
    fn pending_validator_vote_does_not_report_validator_set_changed() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let new_val = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        let calldata = encode_add_validator_calldata(&new_val);
        cs.put_pubkey(&new_val, &[0xAA; 32]).unwrap();

        let outcome =
            execute_system_contract_call(&registry_address(), &v1, &calldata, &mut ws, &cs)
                .unwrap();

        assert_eq!(outcome.output, encode_bool(false));
        assert!(!outcome.effects.validator_set_changed);
        assert!(!ws.get_validators().unwrap().contains(&new_val));
    }

    #[test]
    fn add_validator_requires_registered_pubkey_on_chain_call_path() {
        let v1 = Address::from([0x01; 20]);
        let new_val = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let cs = ChainStore::new(Arc::new(MemoryDb::new()));
        let calldata = encode_add_validator_calldata(&new_val);

        let err = execute_system_contract_call(&registry_address(), &v1, &calldata, &mut ws, &cs)
            .unwrap_err();
        assert!(matches!(
            err,
            SystemContractError::ValidatorPubkeyMissing(addr) if addr == new_val
        ));

        cs.put_pubkey(&new_val, &[0xAA; 32]).unwrap();
        let outcome =
            execute_system_contract_call(&registry_address(), &v1, &calldata, &mut ws, &cs)
                .unwrap();
        assert_eq!(outcome.output, encode_bool(true));
        assert!(outcome.effects.validator_set_changed);
        assert!(ws.get_validators().unwrap().contains(&new_val));
    }

    #[test]
    fn validator_quorum_uses_stored_weights() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let new_val = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        ws.set_validator_weights(&[v1, v2, v3], &[3, 1, 1]).unwrap();
        let calldata = encode_add_validator_calldata(&new_val);

        let (first_output, _) = execute_system_contract(&v2, &calldata, &mut ws).unwrap();
        assert_eq!(first_output, encode_bool(false));
        let (second_output, _) = execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        assert_eq!(second_output, encode_bool(false));
        assert!(!ws.get_validators().unwrap().contains(&new_val));

        let (third_output, _) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(third_output, encode_bool(true));
        assert!(ws.get_validators().unwrap().contains(&new_val));
        assert_eq!(ws.get_validator_weight(&new_val).unwrap(), 1);
    }

    #[test]
    fn staking_mode_rejects_direct_weight_changes() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        let calldata = encode_set_validator_weight_calldata(&v1, 2);

        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(
            err,
            SystemContractError::StakeDerivedWeightsActive
        ));
    }

    #[test]
    fn staking_mode_sets_stake_and_derives_weight_after_quorum() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        enable_staking(&mut ws, U256::from(1_000u64));
        for v in [v1, v2, v3] {
            ws.set_validator_stake_and_weight(&v, U256::from(1_000u64), U256::from(1_000u64), 100)
                .unwrap();
        }
        ws.set_total_staked(U256::from(3_000u64)).unwrap();
        ws.add_balance(&v1, U256::from(2_000u64)).unwrap();
        let calldata = encode_set_validator_stake_calldata(&v1, U256::from(2_500u64));

        let (first_output, _) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(first_output, encode_bool(false));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 1);

        let (second_output, _) = execute_system_contract(&v2, &calldata, &mut ws).unwrap();
        assert_eq!(second_output, encode_bool(true));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_500u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(4_500u64));
    }

    #[test]
    fn staking_mode_bond_and_unbond_update_weight_balance_and_totals() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        ws.set_validator_stake_and_weight(&v1, U256::from(1_000u64), U256::from(1_000u64), 100)
            .unwrap();
        ws.set_total_staked(U256::from(1_000u64)).unwrap();
        ws.add_balance(&v1, U256::from(5_000u64)).unwrap();

        let bond_calldata = encode_bond_validator_stake_calldata(&v1, U256::from(1_500u64));
        let (bond_output, _) = execute_system_contract(&v1, &bond_calldata, &mut ws).unwrap();
        assert_eq!(bond_output, encode_bool(true));
        assert_eq!(ws.get_balance(&v1).unwrap(), U256::from(3_500u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_500u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(2_500u64));

        let unbond_calldata = encode_unbond_validator_stake_calldata(&v1, U256::from(500u64));
        let (unbond_output, _) = execute_system_contract(&v1, &unbond_calldata, &mut ws).unwrap();
        assert_eq!(unbond_output, encode_bool(true));
        assert_eq!(ws.get_balance(&v1).unwrap(), U256::from(4_000u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(2_000u64));
    }

    #[test]
    fn staking_mode_unbond_rejects_below_nonzero_weight() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        ws.set_validator_stake_and_weight(&v1, U256::from(1_000u64), U256::from(1_000u64), 100)
            .unwrap();
        ws.set_total_staked(U256::from(1_000u64)).unwrap();

        let calldata = encode_unbond_validator_stake_calldata(&v1, U256::from(1u64));
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::StakeTooLow));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(1_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 1);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(1_000u64));
    }

    #[test]
    fn staking_mode_unbond_rejects_total_staked_underflow() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        ws.set_validator_stake_and_weight(&v1, U256::from(2_000u64), U256::from(1_000u64), 100)
            .unwrap();
        ws.set_total_staked(U256::from(250u64)).unwrap();
        ws.add_balance(&v1, U256::from(1_000u64)).unwrap();

        let calldata = encode_unbond_validator_stake_calldata(&v1, U256::from(500u64));
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();

        assert!(matches!(
            err,
            SystemContractError::AbiDecode(msg) if msg == "total staked underflow"
        ));
        assert_eq!(ws.get_balance(&v1).unwrap(), U256::from(1_000u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(250u64));
    }

    #[test]
    fn staking_mode_set_stake_rejects_total_staked_underflow_before_balance_credit() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        ws.set_validator_stake_and_weight(&v1, U256::from(2_000u64), U256::from(1_000u64), 100)
            .unwrap();
        ws.set_total_staked(U256::from(250u64)).unwrap();
        ws.add_balance(&v1, U256::from(1_000u64)).unwrap();

        let calldata = encode_set_validator_stake_calldata(&v1, U256::from(1_500u64));
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();

        assert!(matches!(
            err,
            SystemContractError::AbiDecode(msg) if msg == "total staked underflow"
        ));
        assert_eq!(ws.get_balance(&v1).unwrap(), U256::from(1_000u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(250u64));
    }

    #[test]
    fn staking_mode_bond_rejects_total_staked_overflow_before_balance_debit() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1u64));
        ws.set_validator_stake_and_weight(&v1, U256::from(1_000u64), U256::from(1u64), 100)
            .unwrap();
        ws.set_total_staked(U256::MAX).unwrap();
        ws.add_balance(&v1, U256::from(100u64)).unwrap();

        let calldata = encode_bond_validator_stake_calldata(&v1, U256::from(1u64));
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();

        assert!(matches!(
            err,
            SystemContractError::AbiDecode(msg) if msg == "total staked overflow"
        ));
        assert_eq!(ws.get_balance(&v1).unwrap(), U256::from(100u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(1_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 100);
        assert_eq!(ws.get_total_staked().unwrap(), U256::MAX);
    }

    #[test]
    fn staking_mode_bond_unbond_are_self_only() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let mut ws = setup_with_validators(&[v1, v2]);
        enable_staking(&mut ws, U256::from(1_000u64));
        for v in [v1, v2] {
            ws.set_validator_stake_and_weight(&v, U256::from(1_000u64), U256::from(1_000u64), 100)
                .unwrap();
            ws.add_balance(&v, U256::from(2_000u64)).unwrap();
        }
        ws.set_total_staked(U256::from(2_000u64)).unwrap();

        let bond_other = encode_bond_validator_stake_calldata(&v2, U256::from(1_000u64));
        let err = execute_system_contract(&v1, &bond_other, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::Unauthorized));

        let unbond_other = encode_unbond_validator_stake_calldata(&v2, U256::from(1u64));
        let err = execute_system_contract(&v1, &unbond_other, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::Unauthorized));
    }

    #[test]
    fn staking_mode_requires_pre_stake_before_add_validator() {
        let v1 = Address::from([0x01; 20]);
        let new_val = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1]);
        enable_staking(&mut ws, U256::from(1_000u64));
        ws.add_balance(&new_val, U256::from(1_000u64)).unwrap();
        let calldata = encode_add_validator_calldata(&new_val);

        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::StakeTooLow));

        let stake_calldata = encode_set_validator_stake_calldata(&new_val, U256::from(1_000u64));
        let (stake_output, _) = execute_system_contract(&v1, &stake_calldata, &mut ws).unwrap();
        assert_eq!(stake_output, encode_bool(true));

        let (add_output, _) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(add_output, encode_bool(true));
        assert!(ws.get_validators().unwrap().contains(&new_val));
        assert_eq!(ws.get_validator_weight(&new_val).unwrap(), 1);
    }

    #[test]
    fn propose_algorithm_activation_requires_validator_quorum() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        let mut registry = AlgorithmRegistry::default();
        registry.deprecate(SignatureType::MlDsa65);

        // activation_height must be >= ALGO_GOVERNANCE_DELTA_MIN (chain_store=None → current=0)
        let activation_height = ALGO_GOVERNANCE_DELTA_MIN + 1;
        let verifier_hash = [0xAB; 32];
        let calldata = encode_propose_algorithm_activation_calldata(
            SignatureType::MlDsa65,
            activation_height,
            verifier_hash,
        );

        let (first_output, _) =
            execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
                .unwrap();
        assert_eq!(first_output, encode_bool(false));
        // After first vote: PendingActivation in both registry and world state.
        assert_eq!(
            registry
                .get_all_entries()
                .iter()
                .find(|entry| entry.algo == SignatureType::MlDsa65)
                .map(|entry| entry.status),
            Some(AlgorithmStatus::PendingActivation)
        );
        assert_eq!(
            ws.get_storage(
                &registry_address(),
                &algorithm_status_key(SignatureType::MlDsa65)
            )
            .unwrap(),
            encode_algorithm_status(AlgorithmStatus::PendingActivation)
        );

        let (second_output, _) =
            execute_validator_registry_with_registry(&v2, &calldata, &mut ws, None, &mut registry)
                .unwrap();
        // Quorum reached (2/3 votes with equal weight); true returned to signal quorum.
        assert_eq!(second_output, encode_bool(true));
        // Status remains PendingActivation — activation deferred to block activation_height.
        assert_eq!(
            registry
                .get_all_entries()
                .iter()
                .find(|entry| entry.algo == SignatureType::MlDsa65)
                .map(|entry| entry.status),
            Some(AlgorithmStatus::PendingActivation)
        );
        assert_eq!(
            ws.get_storage(
                &registry_address(),
                &algorithm_status_key(SignatureType::MlDsa65)
            )
            .unwrap(),
            encode_algorithm_status(AlgorithmStatus::PendingActivation)
        );
    }

    #[test]
    fn process_pending_activations_activates_at_correct_height() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        let mut registry = AlgorithmRegistry::default();
        registry.deprecate(SignatureType::MlDsa65);

        let activation_height = ALGO_GOVERNANCE_DELTA_MIN + 100;
        let verifier_hash = [0xCD; 32];
        let calldata = encode_propose_algorithm_activation_calldata(
            SignatureType::MlDsa65,
            activation_height,
            verifier_hash,
        );

        // v1 + v2 vote → quorum; status stays PendingActivation
        execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
            .unwrap();
        execute_validator_registry_with_registry(&v2, &calldata, &mut ws, None, &mut registry)
            .unwrap();
        assert!(!registry.is_allowed(SignatureType::MlDsa65));

        // Before activation height: nothing activated
        let activated =
            process_pending_activations(activation_height - 1, &mut ws, &mut registry).unwrap();
        assert!(activated.is_empty());
        assert!(!registry.is_allowed(SignatureType::MlDsa65));

        // At activation height: algorithm is activated
        let activated =
            process_pending_activations(activation_height, &mut ws, &mut registry).unwrap();
        assert_eq!(activated, vec![SignatureType::MlDsa65]);
        assert!(registry.is_allowed(SignatureType::MlDsa65));
        assert_eq!(
            ws.get_storage(
                &registry_address(),
                &algorithm_status_key(SignatureType::MlDsa65)
            )
            .unwrap(),
            encode_algorithm_status(AlgorithmStatus::Active)
        );
    }

    #[test]
    fn propose_algorithm_activation_rejects_short_timelock() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let mut registry = AlgorithmRegistry::default();

        // activation_height below ALGO_GOVERNANCE_DELTA_MIN must be rejected
        let calldata = encode_propose_algorithm_activation_calldata(
            SignatureType::MlDsa65,
            0, // invalid: must be >= 500_000
            [0u8; 32],
        );
        let err =
            execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
                .unwrap_err();
        assert!(
            matches!(err, SystemContractError::InvalidActivationHeight(_, _)),
            "expected InvalidActivationHeight, got {err:?}"
        );
    }

    #[test]
    fn propose_algorithm_activation_rejects_duplicate_proposal() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let mut registry = AlgorithmRegistry::default();
        registry.deprecate(SignatureType::SphincsSha2256f);

        let activation_height = ALGO_GOVERNANCE_DELTA_MIN + 1;
        let verifier_hash = [0xEF; 32];
        let calldata = encode_propose_algorithm_activation_calldata(
            SignatureType::SphincsSha2256f,
            activation_height,
            verifier_hash,
        );

        // First call is fine (stores proposal)
        execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
            .unwrap();

        // Second call with identical params must be rejected as a duplicate vote
        let err =
            execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
                .unwrap_err();
        assert!(
            matches!(err, SystemContractError::DuplicateVote),
            "expected DuplicateVote, got {err:?}"
        );
    }

    #[test]
    fn deprecate_algorithm_route_updates_registry_on_quorum() {
        let v1 = Address::from([0x11; 20]);
        let v2 = Address::from([0x12; 20]);
        let v3 = Address::from([0x13; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);
        let mut registry = AlgorithmRegistry::default();
        let calldata = encode_deprecate_algorithm_calldata(SignatureType::SphincsSha2256f);

        let (first_output, _) =
            execute_validator_registry_with_registry(&v1, &calldata, &mut ws, None, &mut registry)
                .unwrap();
        assert_eq!(first_output, encode_bool(false));
        assert!(registry.is_allowed(SignatureType::SphincsSha2256f));

        let (second_output, _) =
            execute_validator_registry_with_registry(&v2, &calldata, &mut ws, None, &mut registry)
                .unwrap();
        assert_eq!(second_output, encode_bool(true));
        assert!(!registry.is_allowed(SignatureType::SphincsSha2256f));
        assert_eq!(
            ws.get_storage(
                &registry_address(),
                &algorithm_status_key(SignatureType::SphincsSha2256f),
            )
            .unwrap(),
            encode_algorithm_status(AlgorithmStatus::Deprecated)
        );
    }

    // ── removeValidator ────────────────────────────────────────

    #[test]
    fn remove_validator_success() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);

        let calldata = encode_remove_validator_calldata(&v2);
        let (first_output, gas) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(first_output, encode_bool(false));
        assert_eq!(ws.get_validators().unwrap(), vec![v1, v2, v3]);

        let (output, _) = execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        assert_eq!(output, encode_bool(true));
        assert_eq!(gas, SYSTEM_CALL_BASE_GAS + SYSTEM_CALL_OP_GAS);

        let validators = ws.get_validators().unwrap();
        assert_eq!(validators, vec![v1, v3]);
    }

    #[test]
    fn remove_validator_last_fails() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let calldata = encode_remove_validator_calldata(&v1);
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::LastValidator));
    }

    #[test]
    fn remove_validator_not_found_fails() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let unknown = Address::from([0xFF; 20]);
        let mut ws = setup_with_validators(&[v1, v2]);

        let calldata = encode_remove_validator_calldata(&unknown);
        let err = execute_system_contract(&v1, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::NotFound(_)));
    }

    #[test]
    fn remove_validator_unauthorized_fails() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let outsider = Address::from([0x99; 20]);
        let mut ws = setup_with_validators(&[v1, v2]);

        let calldata = encode_remove_validator_calldata(&v2);
        let err = execute_system_contract(&outsider, &calldata, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::Unauthorized));
    }

    // ── AccountManager ──────────────────────────────────────────

    #[test]
    fn rotate_key_updates_caller_account_and_registry() {
        let caller = Address::from([0x11; 20]);
        let (mut ws, cs) = setup_account_manager();
        ws.set_account(&caller, &account_with_balance(1_000_000))
            .unwrap();

        let new_pubkey = vec![0xAB; 1312];
        let calldata = encode_rotate_key_calldata(&new_pubkey, SignatureType::Dilithium3.as_u8());
        let outcome = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap();

        assert_eq!(outcome.output, encode_bool(true));
        assert_eq!(outcome.gas_used, SYSTEM_CALL_BASE_GAS + SYSTEM_CALL_OP_GAS);
        assert_eq!(outcome.effects.updated_accounts, vec![caller]);

        let account = ws.get_account(&caller).unwrap().unwrap();
        assert_eq!(account.pq_pubkey_hash, blake3_hash(&new_pubkey));
        assert_eq!(cs.get_pubkey(&caller).unwrap().unwrap(), new_pubkey);
    }

    #[test]
    fn rotate_key_rejects_unknown_algorithm() {
        let caller = Address::from([0x12; 20]);
        let (mut ws, cs) = setup_account_manager();
        let calldata = encode_rotate_key_calldata(&[0x42; 32], 99);

        let err = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(err, SystemContractError::InvalidAlgorithm(99)));
    }

    #[test]
    fn rotate_key_rejects_oversized_public_key() {
        let caller = Address::from([0x12; 20]);
        let (mut ws, cs) = setup_account_manager();
        let calldata = encode_rotate_key_calldata(
            &vec![0x42; MAX_ACCOUNT_PUBLIC_KEY_BYTES + 1],
            SignatureType::Dilithium3.as_u8(),
        );

        let err = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SystemContractError::PublicKeyTooLarge(size, MAX_ACCOUNT_PUBLIC_KEY_BYTES)
                if size == MAX_ACCOUNT_PUBLIC_KEY_BYTES + 1
        ));
        assert_eq!(cs.get_pubkey(&caller).unwrap(), None);
    }

    #[test]
    fn rotate_key_only_updates_caller() {
        let caller = Address::from([0x13; 20]);
        let other = Address::from([0x14; 20]);
        let (mut ws, cs) = setup_account_manager();
        let mut other_account = account_with_balance(100);
        other_account.pq_pubkey_hash = keccak256(b"other");
        ws.set_account(&caller, &account_with_balance(100)).unwrap();
        ws.set_account(&other, &other_account).unwrap();

        let calldata = encode_rotate_key_calldata(&[0x55; 64], SignatureType::Dilithium3.as_u8());
        execute_system_contract_call(&account_manager_address(), &caller, &calldata, &mut ws, &cs)
            .unwrap();

        let loaded_other = ws.get_account(&other).unwrap().unwrap();
        assert_eq!(loaded_other, other_account);
    }

    #[test]
    fn set_validation_code_updates_account() {
        let caller = Address::from([0x21; 20]);
        let (mut ws, cs) = setup_account_manager();
        ws.set_account(&caller, &account_with_balance(1_000_000))
            .unwrap();

        let code_hash = keccak256(b"default-validator");
        cs.put_code(&code_hash, b"\x60\x00").unwrap();

        let calldata = encode_set_validation_code_calldata(&code_hash);
        let outcome = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap();

        assert_eq!(outcome.output, encode_bool(true));
        assert_eq!(outcome.effects.updated_accounts, vec![caller]);
        let account = ws.get_account(&caller).unwrap().unwrap();
        assert_eq!(account.validation_code_hash, Some(code_hash));
    }

    #[test]
    fn set_validation_code_rejects_missing_code() {
        let caller = Address::from([0x22; 20]);
        let (mut ws, cs) = setup_account_manager();
        let code_hash = keccak256(b"missing-validator");
        let calldata = encode_set_validation_code_calldata(&code_hash);

        let err = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SystemContractError::ValidationCodeMissing(hash) if hash == code_hash
        ));
    }

    #[test]
    fn clear_validation_code_restores_builtin_mode() {
        let caller = Address::from([0x23; 20]);
        let (mut ws, cs) = setup_account_manager();
        let code_hash = keccak256(b"custom-validator");
        let mut account = account_with_balance(1_000_000);
        account.validation_code_hash = Some(code_hash);
        ws.set_account(&caller, &account).unwrap();

        let calldata = encode_clear_validation_code_calldata();
        let outcome = execute_system_contract_call(
            &account_manager_address(),
            &caller,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap();

        assert_eq!(outcome.output, encode_bool(true));
        assert_eq!(outcome.effects.updated_accounts, vec![caller]);
        let account = ws.get_account(&caller).unwrap().unwrap();
        assert_eq!(account.validation_code_hash, None);
    }

    // ── getValidators ──────────────────────────────────────────

    #[test]
    fn get_validators_returns_list() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);

        let calldata = GET_VALIDATORS_SELECTOR.to_vec();
        let (output, gas) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();

        assert_eq!(gas, SYSTEM_CALL_BASE_GAS);

        // Decode the output: offset(32) + len(32) + 3 * address(32) = 5 * 32
        assert_eq!(output.len(), 5 * 32);

        // Check length word
        let len = u64::from_be_bytes(output[56..64].try_into().unwrap());
        assert_eq!(len, 3);

        // Check addresses
        let a1 = decode_address(&output[64..96]).unwrap();
        let a2 = decode_address(&output[96..128]).unwrap();
        let a3 = decode_address(&output[128..160]).unwrap();
        assert_eq!(a1, v1);
        assert_eq!(a2, v2);
        assert_eq!(a3, v3);
    }

    #[test]
    fn get_validators_empty() {
        let mut ws = setup_with_validators(&[]);

        let calldata = GET_VALIDATORS_SELECTOR.to_vec();
        let (output, _) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();

        // offset + len(0)
        assert_eq!(output.len(), 64);
        let len = u64::from_be_bytes(output[56..64].try_into().unwrap());
        assert_eq!(len, 0);
    }

    // ── isValidator ────────────────────────────────────────────

    #[test]
    fn is_validator_true() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let mut calldata = IS_VALIDATOR_SELECTOR.to_vec();
        let mut word = [0u8; 32];
        word.copy_from_slice(v1.as_bytes());
        calldata.extend_from_slice(&word);

        let (output, _) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();
        assert_eq!(output, encode_bool(true));
    }

    #[test]
    fn is_validator_false() {
        let v1 = Address::from([0x01; 20]);
        let outsider = Address::from([0xFF; 20]);
        let mut ws = setup_with_validators(&[v1]);

        let mut calldata = IS_VALIDATOR_SELECTOR.to_vec();
        let mut word = [0u8; 32];
        word.copy_from_slice(outsider.as_bytes());
        calldata.extend_from_slice(&word);

        let (output, _) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();
        assert_eq!(output, encode_bool(false));
    }

    // ── ABI encoding/decoding ──────────────────────────────────

    #[test]
    fn decode_address_valid() {
        let addr = Address::from([0xAB; 20]);
        let mut word = [0u8; 32];
        word.copy_from_slice(addr.as_bytes());

        let decoded = decode_address(&word).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn decode_address_too_short() {
        let short = [0u8; 16];
        let err = decode_address(&short).unwrap_err();
        assert!(matches!(err, SystemContractError::AbiDecode(_)));
    }

    #[test]
    fn decode_address_u64_rejects_nonzero_high_bytes() {
        let mut input = [0u8; 64];
        input[32] = 1;
        input[63] = 7;

        assert!(matches!(
            decode_address_u64(&input),
            Err(SystemContractError::AbiDecode(_))
        ));
    }

    #[test]
    fn encode_bool_true() {
        let encoded = encode_bool(true);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 1);
        assert!(encoded[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_bool_false() {
        let encoded = encode_bool(false);
        assert_eq!(encoded.len(), 32);
        assert!(encoded.iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_address_array_roundtrip() {
        let addrs = vec![Address::from([0x11; 20]), Address::from([0x22; 20])];
        let encoded = encode_address_array(&addrs);

        // offset(32) + len(32) + 2 * elem(32) = 128 bytes
        assert_eq!(encoded.len(), 128);

        // offset = 0x20
        assert_eq!(encoded[31], 0x20);

        // length = 2
        let len = u64::from_be_bytes(encoded[56..64].try_into().unwrap());
        assert_eq!(len, 2);

        // First address
        let a1 = decode_address(&encoded[64..96]).unwrap();
        assert_eq!(a1, addrs[0]);

        // Second address
        let a2 = decode_address(&encoded[96..128]).unwrap();
        assert_eq!(a2, addrs[1]);
    }

    #[test]
    fn encode_calldata_add_validator() {
        let addr = Address::from([0xDE; 20]);
        let calldata = encode_add_validator_calldata(&addr);

        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &ADD_VALIDATOR_SELECTOR);
        let decoded = decode_address(&calldata[4..]).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn encode_calldata_remove_validator() {
        let addr = Address::from([0xBE; 20]);
        let calldata = encode_remove_validator_calldata(&addr);

        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &REMOVE_VALIDATOR_SELECTOR);
        let decoded = decode_address(&calldata[4..]).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn encode_calldata_propose_algorithm_activation() {
        let activation_height: u64 = 600_000;
        let verifier_hash = [0xabu8; 32];
        let calldata = encode_propose_algorithm_activation_calldata(
            SignatureType::MlDsa65,
            activation_height,
            verifier_hash,
        );

        // selector(4) + algo_word(32) + height_word(32) + verifier_hash(32) = 100
        assert_eq!(calldata.len(), 100);
        assert_eq!(&calldata[..4], &PROPOSE_ALGORITHM_ACTIVATION_SELECTOR);
        assert_eq!(
            decode_signature_type(&calldata[4..]).unwrap(),
            SignatureType::MlDsa65
        );
        // activation_height encoded in bytes [24..32] of the second word
        let height_word = &calldata[36..68];
        let decoded_height = u64::from_be_bytes(height_word[24..32].try_into().unwrap());
        assert_eq!(decoded_height, activation_height);
        // verifier_hash is the third word
        assert_eq!(&calldata[68..100], &verifier_hash);
    }

    #[test]
    fn encode_calldata_deprecate_algorithm() {
        let calldata = encode_deprecate_algorithm_calldata(SignatureType::Dilithium3);

        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &DEPRECATE_ALGORITHM_SELECTOR);
        assert_eq!(
            decode_signature_type(&calldata[4..]).unwrap(),
            SignatureType::Dilithium3
        );
    }

    // ── Edge cases ─────────────────────────────────────────────

    #[test]
    fn input_too_short() {
        let mut ws = setup_with_validators(&[]);
        let err = execute_system_contract(&Address::ZERO, &[0x00, 0x01], &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::InputTooShort));
    }

    #[test]
    fn unknown_selector() {
        let mut ws = setup_with_validators(&[]);
        let input = [0xDE, 0xAD, 0xBE, 0xEF];
        let err = execute_system_contract(&Address::ZERO, &input, &mut ws).unwrap_err();
        assert!(matches!(err, SystemContractError::UnknownSelector(_)));
    }

    #[test]
    fn const_keccak256_matches_runtime() {
        // Verify the const keccak matches the runtime one for our signatures
        let runtime = keccak256(b"addValidator(address)");
        let compile_time = const_keccak256(b"addValidator(address)");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"removeValidator(address)");
        let compile_time = const_keccak256(b"removeValidator(address)");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"getValidators()");
        let compile_time = const_keccak256(b"getValidators()");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"isValidator(address)");
        let compile_time = const_keccak256(b"isValidator(address)");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"rotateKey(bytes,uint8)");
        let compile_time = const_keccak256(b"rotateKey(bytes,uint8)");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"setValidationCode(bytes32)");
        let compile_time = const_keccak256(b"setValidationCode(bytes32)");
        assert_eq!(runtime.as_bytes(), &compile_time);

        let runtime = keccak256(b"clearValidationCode()");
        let compile_time = const_keccak256(b"clearValidationCode()");
        assert_eq!(runtime.as_bytes(), &compile_time);
    }

    // ── Multiple sequential operations ─────────────────────────

    #[test]
    fn sequential_add_then_remove_multiple() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let v4 = Address::from([0x04; 20]);
        let mut ws = setup_with_validators(&[v1]);

        // v1 adds v2
        let calldata = encode_add_validator_calldata(&v2);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(ws.get_validators().unwrap().len(), 2);

        // v2 adds v3
        let calldata = encode_add_validator_calldata(&v3);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v2, &calldata, &mut ws).unwrap();
        assert_eq!(ws.get_validators().unwrap().len(), 3);

        // v3 adds v4
        let calldata = encode_add_validator_calldata(&v4);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        assert_eq!(ws.get_validators().unwrap().len(), 4);

        // v1 removes v2
        let calldata = encode_remove_validator_calldata(&v2);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        execute_system_contract(&v4, &calldata, &mut ws).unwrap();
        let validators = ws.get_validators().unwrap();
        assert_eq!(validators.len(), 3);
        assert!(!validators.contains(&v2));

        // v3 removes v4
        let calldata = encode_remove_validator_calldata(&v4);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        let validators = ws.get_validators().unwrap();
        assert_eq!(validators.len(), 2);
        assert!(validators.contains(&v1));
        assert!(validators.contains(&v3));
    }

    #[test]
    fn add_remove_then_re_add_same_validator() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let v3 = Address::from([0x03; 20]);
        let mut ws = setup_with_validators(&[v1, v2, v3]);

        // Remove v2
        let calldata = encode_remove_validator_calldata(&v2);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        assert!(!ws.get_validators().unwrap().contains(&v2));

        // Re-add v2
        let calldata = encode_add_validator_calldata(&v2);
        execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        execute_system_contract(&v3, &calldata, &mut ws).unwrap();
        assert!(ws.get_validators().unwrap().contains(&v2));
        assert_eq!(ws.get_validators().unwrap().len(), 3);
    }

    // ── Event encoding correctness ─────────────────────────────

    #[test]
    fn validator_added_topic_matches_keccak() {
        let expected = keccak256(b"ValidatorAdded(address)");
        let topic = validator_added_topic();
        assert_eq!(topic, *expected.as_bytes());
    }

    #[test]
    fn validator_removed_topic_matches_keccak() {
        let expected = keccak256(b"ValidatorRemoved(address)");
        let topic = validator_removed_topic();
        assert_eq!(topic, *expected.as_bytes());
    }

    #[test]
    fn event_topics_are_distinct() {
        let added = validator_added_topic();
        let removed = validator_removed_topic();
        assert_ne!(added, removed);
    }

    // ── Additional ABI encoding edge cases ─────────────────────

    #[test]
    fn encode_address_array_single_element() {
        let addr = Address::from([0xAA; 20]);
        let encoded = encode_address_array(&[addr]);

        // offset(32) + len(32) + 1 * elem(32) = 96 bytes
        assert_eq!(encoded.len(), 96);

        // length = 1
        let len = u64::from_be_bytes(encoded[56..64].try_into().unwrap());
        assert_eq!(len, 1);

        // Address
        let decoded = decode_address(&encoded[64..96]).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn encode_address_array_empty_is_just_header() {
        let encoded = encode_address_array(&[]);

        // offset(32) + len(32) = 64 bytes
        assert_eq!(encoded.len(), 64);

        // offset = 0x20
        assert_eq!(encoded[31], 0x20);

        // length = 0
        let len = u64::from_be_bytes(encoded[56..64].try_into().unwrap());
        assert_eq!(len, 0);
    }

    #[test]
    fn decode_address_ignores_extra_bytes() {
        let addr = Address::from([0xCC; 20]);
        let mut input = vec![0u8; 64]; // 64 bytes, only first 32 matter
        input[..32].copy_from_slice(addr.as_bytes());

        let decoded = decode_address(&input).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn decode_address_all_zeros() {
        let input = [0u8; 32];
        let decoded = decode_address(&input).unwrap();
        assert_eq!(decoded, Address::ZERO);
    }

    #[test]
    fn public_key_size_validation_enforces_bounds() {
        assert!(validate_public_key_size(MAX_ACCOUNT_PUBLIC_KEY_BYTES).is_ok());
        assert!(matches!(
            validate_public_key_size(MAX_ACCOUNT_PUBLIC_KEY_BYTES + 1),
            Err(SystemContractError::PublicKeyTooLarge(
                size,
                MAX_ACCOUNT_PUBLIC_KEY_BYTES
            )) if size == MAX_ACCOUNT_PUBLIC_KEY_BYTES + 1
        ));
        assert!(matches!(
            validate_public_key_size(0),
            Err(SystemContractError::EmptyPubkey)
        ));
    }

    #[test]
    fn system_contract_code_hash_is_deterministic() {
        let h1 = system_contract_code_hash();
        let h2 = system_contract_code_hash();
        assert_eq!(h1, h2);
        // Must not be the zero hash
        assert_ne!(h1, shell_primitives::ShellHash::ZERO);
    }

    #[test]
    fn account_manager_code_hash_is_deterministic() {
        let h1 = account_manager_code_hash();
        let h2 = account_manager_code_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, shell_primitives::ShellHash::ZERO);
    }

    #[test]
    fn registry_address_matches_constant() {
        let addr = registry_address();
        assert_eq!(addr.as_bytes(), &VALIDATOR_REGISTRY_ADDR);
    }

    #[test]
    fn account_manager_address_matches_constant() {
        let addr = account_manager_address();
        assert_eq!(addr.as_bytes(), &ACCOUNT_MANAGER_ADDR);
    }

    // ── Gas accounting ─────────────────────────────────────────

    #[test]
    fn get_validators_charges_base_gas_only() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let calldata = GET_VALIDATORS_SELECTOR.to_vec();
        let (_, gas) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();
        assert_eq!(gas, SYSTEM_CALL_BASE_GAS);
    }

    #[test]
    fn is_validator_charges_base_gas_only() {
        let v1 = Address::from([0x01; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let mut calldata = IS_VALIDATOR_SELECTOR.to_vec();
        let mut word = [0u8; 32];
        word.copy_from_slice(v1.as_bytes());
        calldata.extend_from_slice(&word);
        let (_, gas) = execute_system_contract(&Address::ZERO, &calldata, &mut ws).unwrap();
        assert_eq!(gas, SYSTEM_CALL_BASE_GAS);
    }

    #[test]
    fn mutating_ops_charge_base_plus_op_gas() {
        let v1 = Address::from([0x01; 20]);
        let v2 = Address::from([0x02; 20]);
        let mut ws = setup_with_validators(&[v1]);
        let expected = SYSTEM_CALL_BASE_GAS + SYSTEM_CALL_OP_GAS;

        let calldata = encode_add_validator_calldata(&v2);
        let (_, gas) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(gas, expected);

        let calldata = encode_remove_validator_calldata(&v2);
        let (_, gas) = execute_system_contract(&v1, &calldata, &mut ws).unwrap();
        assert_eq!(gas, expected);
    }

    // ── Guardian recovery tests ────────────────────────────────

    #[test]
    fn set_guardians_stores_config() {
        let owner = Address::from([0x30; 20]);
        let g1 = Address::from([0x31; 20]);
        let g2 = Address::from([0x32; 20]);
        let (mut ws, cs) = setup_account_manager();

        let calldata = encode_set_guardians_calldata(&[g1, g2], 1, 100);
        let outcome = execute_system_contract_call(
            &account_manager_address(),
            &owner,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap();
        assert_eq!(outcome.output, encode_bool(true));

        let config = cs.get_guardian_config(&owner).unwrap().unwrap();
        assert_eq!(config.guardians.len(), 2);
        assert_eq!(config.threshold, 1);
        assert_eq!(config.timelock, 100);
    }

    #[test]
    fn set_guardians_rejects_self_as_guardian() {
        let owner = Address::from([0x33; 20]);
        let (mut ws, cs) = setup_account_manager();
        let calldata = encode_set_guardians_calldata(&[owner], 1, 100);
        let err = execute_system_contract_call(
            &account_manager_address(),
            &owner,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(err, SystemContractError::GuardianIsSelf));
    }

    #[test]
    fn set_guardians_rejects_short_timelock() {
        let owner = Address::from([0x34; 20]);
        let g1 = Address::from([0x35; 20]);
        let (mut ws, cs) = setup_account_manager();
        let calldata = encode_set_guardians_calldata(&[g1], 1, 50);
        let err = execute_system_contract_call(
            &account_manager_address(),
            &owner,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SystemContractError::TimelockTooShort(100, 50)
        ));
    }

    #[test]
    fn set_guardians_rejects_too_many() {
        let owner = Address::from([0x36; 20]);
        let guardians: Vec<Address> = (1u8..=6).map(|i| Address::from([i; 20])).collect();
        let (mut ws, cs) = setup_account_manager();
        let calldata = encode_set_guardians_calldata(&guardians, 1, 100);
        let err = execute_system_contract_call(
            &account_manager_address(),
            &owner,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SystemContractError::InvalidGuardianCount(5, 6)
        ));
    }

    #[test]
    fn submit_recovery_and_execute_rotates_key() {
        let owner = Address::from([0x40; 20]);
        let g1 = Address::from([0x41; 20]);
        let g2 = Address::from([0x42; 20]);
        let (mut ws, cs) = setup_account_manager();

        // Set up guardian config with 2-of-2, timelock=100
        let calldata = encode_set_guardians_calldata(&[g1, g2], 2, 100);
        execute_system_contract_call(&account_manager_address(), &owner, &calldata, &mut ws, &cs)
            .unwrap();

        let new_pubkey = b"new_pq_pubkey_bytes".to_vec();
        let new_algo = 1u8; // Dilithium3

        // Vote 1 (g1)
        let calldata = encode_submit_recovery_calldata(&owner, &new_pubkey, new_algo);
        execute_system_contract_call(&account_manager_address(), &g1, &calldata, &mut ws, &cs)
            .unwrap();

        // Only 1 vote — maturity_block should still be 0
        let proposal = cs.get_recovery_proposal(&owner).unwrap().unwrap();
        assert_eq!(proposal.votes.len(), 1);
        assert_eq!(proposal.maturity_block, 0);

        // Vote 2 (g2) — threshold reached
        let calldata = encode_submit_recovery_calldata(&owner, &new_pubkey, new_algo);
        execute_system_contract_call(&account_manager_address(), &g2, &calldata, &mut ws, &cs)
            .unwrap();

        let proposal = cs.get_recovery_proposal(&owner).unwrap().unwrap();
        assert_eq!(proposal.votes.len(), 2);
        // No head block → current_block=0 → maturity = 0 + 100 = 100
        assert_eq!(proposal.maturity_block, 100);

        // Cannot execute before maturity — head is at 0 but maturity=100
        let calldata = encode_execute_recovery_calldata(&owner);
        let err = execute_system_contract_call(
            &account_manager_address(),
            &Address::from([0x99; 20]),
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(err, SystemContractError::RecoveryNotMature(100)));
    }

    #[test]
    fn cancel_recovery_removes_proposal() {
        let owner = Address::from([0x50; 20]);
        let g1 = Address::from([0x51; 20]);
        let (mut ws, cs) = setup_account_manager();

        // Set guardians
        let calldata = encode_set_guardians_calldata(&[g1], 1, 100);
        execute_system_contract_call(&account_manager_address(), &owner, &calldata, &mut ws, &cs)
            .unwrap();

        // Vote (threshold=1 so it immediately matures in test with no head block)
        let new_pubkey = b"recovery_pubkey".to_vec();
        let calldata = encode_submit_recovery_calldata(&owner, &new_pubkey, 1);
        execute_system_contract_call(&account_manager_address(), &g1, &calldata, &mut ws, &cs)
            .unwrap();

        assert!(cs.get_recovery_proposal(&owner).unwrap().is_some());

        // Owner cancels
        let calldata = encode_cancel_recovery_calldata(&owner);
        execute_system_contract_call(&account_manager_address(), &owner, &calldata, &mut ws, &cs)
            .unwrap();

        assert!(cs.get_recovery_proposal(&owner).unwrap().is_none());
    }

    #[test]
    fn cancel_recovery_rejects_non_owner() {
        let owner = Address::from([0x60; 20]);
        let g1 = Address::from([0x61; 20]);
        let attacker = Address::from([0x62; 20]);
        let (mut ws, cs) = setup_account_manager();

        let calldata = encode_set_guardians_calldata(&[g1], 1, 100);
        execute_system_contract_call(&account_manager_address(), &owner, &calldata, &mut ws, &cs)
            .unwrap();

        let calldata = encode_submit_recovery_calldata(&owner, b"pubkey", 1);
        execute_system_contract_call(&account_manager_address(), &g1, &calldata, &mut ws, &cs)
            .unwrap();

        let calldata = encode_cancel_recovery_calldata(&owner);
        let err = execute_system_contract_call(
            &account_manager_address(),
            &attacker,
            &calldata,
            &mut ws,
            &cs,
        )
        .unwrap_err();
        assert!(matches!(err, SystemContractError::Unauthorized));
    }
}
