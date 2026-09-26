//! Explicit proposal identities. Legacy governance storage remains untouched
//! unless an expired staged candidate is replaced after the identity upgrade.
use super::*;
use crate::precompiles::{
    PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG, PQ_MLDSA65_VERIFY_GAS, PQ_SLHDSA_VERIFY_GAS,
};

pub const SUBMIT_ALGORITHM_PROPOSAL_SELECTOR: [u8; 4] = compute_selector(
    b"submitAlgorithmProposal(uint8,bytes32,uint32,uint32,uint64,uint64,bytes32,uint64)",
);
pub const VOTE_ALGORITHM_PROPOSAL_SELECTOR: [u8; 4] =
    compute_selector(b"voteAlgorithmProposal(uint8,bytes32)");
pub const GET_ALGORITHM_PROPOSAL_SELECTOR: [u8; 4] =
    compute_selector(b"getAlgorithmProposal(bytes32)");
const SPEC_WORDS: usize = 8;
const DEADLINE: u8 = 8;
const APPROVED: u8 = 9;

fn invalid(message: &str) -> SystemContractError {
    SystemContractError::AbiDecode(message.into())
}

fn current_key(algo: SignatureType) -> ShellHash {
    let mut bytes = b"algorithm_proposal_id:".to_vec();
    bytes.push(algo.as_u8());
    keccak256(&bytes)
}

fn field_key(id: &ShellHash, field: u8) -> ShellHash {
    let mut bytes = b"algorithm_proposal_record:".to_vec();
    bytes.extend_from_slice(id.as_bytes());
    bytes.push(field);
    keccak256(&bytes)
}

fn vote_key(id: &ShellHash, voter: &Address) -> ShellHash {
    let mut bytes = b"algorithm_proposal_vote:".to_vec();
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(voter.as_bytes());
    keccak256(&bytes)
}

fn read<S: KvStore + 'static>(
    ws: &WorldState<S>,
    key: &ShellHash,
) -> Result<ShellHash, SystemContractError> {
    ws.get_storage(&registry_address(), key)
        .map_err(|e| SystemContractError::Storage(e.to_string()))
}

fn write<S: KvStore + 'static>(
    ws: &mut WorldState<S>,
    key: &ShellHash,
    value: &ShellHash,
) -> Result<(), SystemContractError> {
    ws.set_storage(&registry_address(), key, value)
        .map_err(|e| SystemContractError::Storage(e.to_string()))
}

/// Before activation, the new selectors remain unknown, including in replay.
pub(super) fn execute<S: KvStore + 'static>(
    caller: &Address,
    input: &[u8],
    ws: &mut WorldState<S>,
    cs: Option<&ChainStore<S>>,
    registry: &mut AlgorithmRegistry,
    number: Option<u64>,
) -> Result<(Vec<u8>, u64), SystemContractError> {
    let selector = decode_selector(input)?;
    let rules = algorithm_activation_rules(cs, number)?;
    if !rules.proposal_identity {
        return Err(SystemContractError::UnknownSelector(selector));
    }
    let params = &input[4..];
    match selector {
        SUBMIT_ALGORITHM_PROPOSAL_SELECTOR => {
            let id = submit(caller, params, ws, cs, rules)?;
            Ok((
                id.as_bytes().to_vec(),
                SYSTEM_CALL_BASE_GAS + 12 * SYSTEM_CALL_OP_GAS,
            ))
        }
        VOTE_ALGORITHM_PROPOSAL_SELECTOR => {
            if params.len() != 64 {
                return Err(invalid("vote requires algorithm and proposal ID"));
            }
            let algo = decode_signature_type(&params[..32])?;
            let id = ShellHash::from_slice(&params[32..64]);
            let approved = vote(caller, algo, id, ws, registry, rules)?;
            Ok((
                encode_bool(approved),
                SYSTEM_CALL_BASE_GAS + 5 * SYSTEM_CALL_OP_GAS,
            ))
        }
        GET_ALGORITHM_PROPOSAL_SELECTOR => {
            if params.len() != 32 {
                return Err(invalid("getter requires proposal ID"));
            }
            let id = ShellHash::from_slice(params);
            if read(ws, &field_key(&id, DEADLINE))? == ShellHash::ZERO {
                return Err(invalid("unknown algorithm proposal"));
            }
            let mut out = Vec::with_capacity(320);
            for field in 0..=APPROVED {
                out.extend_from_slice(read(ws, &field_key(&id, field))?.as_bytes());
            }
            Ok((out, SYSTEM_CALL_BASE_GAS))
        }
        _ => Err(SystemContractError::UnknownSelector(selector)),
    }
}

/// Reject unbound calls for new proposals, but let pre-upgrade rounds finish.
pub(super) fn guard_legacy<S: KvStore + 'static>(
    ws: &WorldState<S>,
    algo: SignatureType,
) -> Result<(), SystemContractError> {
    if read(ws, &current_key(algo))? != ShellHash::ZERO {
        return Err(invalid(
            "algorithm proposal requires an explicit ID-bound vote",
        ));
    }
    if read(ws, &algorithm_proposal_height_key(algo))? != ShellHash::ZERO
        || read(ws, &algorithm_status_key(algo))?
            == encode_algorithm_status(AlgorithmStatus::PendingActivation)
    {
        return Ok(());
    }
    Err(invalid(
        "use submitAlgorithmProposal and voteAlgorithmProposal",
    ))
}

// Only installed algorithm descriptors are accepted. Governance does not
// silently accept new sizes or gas prices that this client cannot execute.
fn validate_spec(params: &[u8]) -> Result<(SignatureType, u64), SystemContractError> {
    if params.len() != SPEC_WORDS * 32 {
        return Err(invalid("proposal requires exactly eight ABI words"));
    }
    let algo = decode_signature_type(&params[..32])?;
    let (name, pk, sig, verify, batch) = match algo {
        SignatureType::Dilithium3 => (
            "Dilithium3",
            1952,
            3309,
            PQ_MLDSA65_VERIFY_GAS,
            PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG,
        ),
        SignatureType::MlDsa65 => (
            "ML-DSA-65",
            1952,
            3309,
            PQ_MLDSA65_VERIFY_GAS,
            PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG,
        ),
        SignatureType::SphincsSha2256f => {
            ("SLH-DSA-SHA2-256f", 64, 49_856, PQ_SLHDSA_VERIFY_GAS, 0)
        }
    };
    let mut expected_name = [0; 32];
    expected_name[..name.len()].copy_from_slice(name.as_bytes());
    if params[32..64] != expected_name
        || decode_u64(&params[64..96])? != pk
        || decode_u64(&params[96..128])? != sig
        || decode_u64(&params[128..160])? != verify
        || decode_u64(&params[160..192])? != batch
    {
        return Err(invalid(
            "proposal spec does not match an installed algorithm",
        ));
    }
    if params[192..224].iter().all(|byte| *byte == 0) {
        return Err(invalid("proposal verifier hash must be nonzero"));
    }
    Ok((algo, decode_u64(&params[224..256])?))
}

fn proposal_id(params: &[u8], public_key: &[u8]) -> ShellHash {
    // algo || name32 || pk_u32 || sig_u32 || verify_u64 || batch_u64 ||
    // verifier32 || requested_status(Active=0) || activation_u64 || proposer_pk.
    let mut bytes = Vec::with_capacity(98 + public_key.len());
    bytes.push(params[31]);
    bytes.extend_from_slice(&params[32..64]);
    bytes.extend_from_slice(&params[92..96]);
    bytes.extend_from_slice(&params[124..128]);
    bytes.extend_from_slice(&params[152..160]);
    bytes.extend_from_slice(&params[184..192]);
    bytes.extend_from_slice(&params[192..224]);
    bytes.push(0);
    bytes.extend_from_slice(&params[248..256]);
    bytes.extend_from_slice(public_key);
    blake3_hash(&bytes)
}

fn submit<S: KvStore + 'static>(
    caller: &Address,
    params: &[u8],
    ws: &mut WorldState<S>,
    cs: Option<&ChainStore<S>>,
    rules: AlgorithmActivationRules,
) -> Result<ShellHash, SystemContractError> {
    let validators = ws
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }
    let (algo, height) = validate_spec(params)?;
    if height < rules.minimum_height {
        return Err(SystemContractError::InvalidActivationHeight(
            height,
            rules.minimum_height,
        ));
    }
    let (number, duration) = rules
        .voting_window
        .ok_or_else(|| invalid("proposal identity requires voting window"))?;
    let deadline = number
        .checked_add(duration)
        .ok_or_else(|| invalid("algorithm voting deadline exceeds block height range"))?;
    let public_key = cs
        .ok_or_else(|| invalid("proposal identity requires chain context"))?
        .get_pubkey(caller)
        .map_err(|e| SystemContractError::Storage(e.to_string()))?
        .filter(|key| !key.is_empty() && key.len() <= MAX_ACCOUNT_PUBLIC_KEY_BYTES)
        .ok_or(SystemContractError::ValidatorPubkeyMissing(*caller))?;
    let id = proposal_id(params, &public_key);
    if id == ShellHash::ZERO || read(ws, &field_key(&id, DEADLINE))? != ShellHash::ZERO {
        return Err(invalid("duplicate algorithm proposal ID"));
    }
    if read(ws, &algorithm_status_key(algo))?
        == encode_algorithm_status(AlgorithmStatus::PendingActivation)
    {
        return Err(SystemContractError::GovernanceConflict);
    }
    let previous_id = read(ws, &current_key(algo))?;
    let legacy_height = read(ws, &algorithm_proposal_height_key(algo))?;
    let previous_deadline = if previous_id != ShellHash::ZERO {
        if read(ws, &field_key(&previous_id, APPROVED))? != ShellHash::ZERO {
            None
        } else {
            Some(read(ws, &field_key(&previous_id, DEADLINE))?)
        }
    } else if legacy_height != ShellHash::ZERO {
        Some(read(ws, &algorithm_voting_deadline_key(algo))?)
    } else {
        None
    };
    if previous_deadline
        .is_some_and(|end| end == ShellHash::ZERO || number < decode_u64_from_hash(&end))
    {
        return Err(SystemContractError::GovernanceConflict);
    }
    // All semantic rejection checks precede writes. Old records and votes stay
    // immutable so duplicate IDs remain rejected after expiry and replacement.
    for (field, word) in params.chunks_exact(32).enumerate() {
        write(
            ws,
            &field_key(&id, field as u8),
            &ShellHash::from_slice(word),
        )?;
    }
    write(ws, &field_key(&id, DEADLINE), &encode_u64_as_hash(deadline))?;
    write(ws, &current_key(algo), &id)?;
    if legacy_height != ShellHash::ZERO {
        for key in [
            algorithm_proposal_height_key(algo),
            algorithm_proposal_verifier_key(algo),
            algorithm_voting_deadline_key(algo),
        ] {
            write(ws, &key, &ShellHash::ZERO)?;
        }
    }
    Ok(id)
}

fn vote<S: KvStore + 'static>(
    caller: &Address,
    algo: SignatureType,
    id: ShellHash,
    ws: &mut WorldState<S>,
    registry: &mut AlgorithmRegistry,
    rules: AlgorithmActivationRules,
) -> Result<bool, SystemContractError> {
    let validators = ws
        .get_validators()
        .map_err(|e| SystemContractError::Storage(e.to_string()))?;
    if !validators.contains(caller) {
        return Err(SystemContractError::Unauthorized);
    }
    if id == ShellHash::ZERO || read(ws, &current_key(algo))? != id {
        return Err(invalid("vote does not match current algorithm proposal ID"));
    }
    if read(ws, &field_key(&id, APPROVED))? != ShellHash::ZERO {
        return Err(invalid("algorithm proposal already approved"));
    }
    let (number, _) = rules
        .voting_window
        .ok_or_else(|| invalid("proposal identity requires voting window"))?;
    let deadline = decode_u64_from_hash(&read(ws, &field_key(&id, DEADLINE))?);
    if number >= deadline {
        return Err(SystemContractError::VotingWindowExpired(deadline));
    }
    let height = decode_u64_from_hash(&read(ws, &field_key(&id, 7))?);
    if height < rules.minimum_height {
        return Err(SystemContractError::InvalidActivationHeight(
            height,
            rules.minimum_height,
        ));
    }
    if read(ws, &vote_key(&id, caller))? != ShellHash::ZERO {
        return Err(SystemContractError::DuplicateVote);
    }
    let mut total = 0u128;
    let mut voted = 0u128;
    for validator in &validators {
        let weight = u128::from(
            ws.get_validator_weight(validator)
                .map_err(|e| SystemContractError::Storage(e.to_string()))?,
        );
        total += weight;
        if validator == caller || read(ws, &vote_key(&id, validator))? != ShellHash::ZERO {
            voted += weight;
        }
    }
    let verifier = read(ws, &field_key(&id, 6))?;
    write(ws, &vote_key(&id, caller), &encode_u64_as_hash(1))?;
    if total == 0 || voted * 3 < total * 2 {
        return Ok(false);
    }
    publish_algorithm_proposal(ws, registry, algo, height, *verifier.as_bytes())?;
    for key in [
        algorithm_quorum_required_key(algo),
        algorithm_quorum_approved_key(algo),
        field_key(&id, APPROVED),
    ] {
        write(ws, &key, &encode_u64_as_hash(1))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_storage::{AlgorithmVotingWindow, ChainConfig, MemoryDb};
    use std::sync::Arc;

    struct Fixture {
        ws: WorldState<MemoryDb>,
        cs: ChainStore<MemoryDb>,
        registry: AlgorithmRegistry,
        voters: [Address; 3],
    }
    impl Fixture {
        fn new(activation: Option<u64>, interval: u64) -> Self {
            let db = Arc::new(MemoryDb::new());
            let cs = ChainStore::new(db.clone());
            let config: ChainConfig = serde_json::from_value(serde_json::json!({
                "chain_id":1337,"genesis_hash":ShellHash::ZERO,
                "algorithm_proposal_staging_height":0,
                "algorithm_proposal_identity_height":activation,
                "algorithm_voting_window":AlgorithmVotingWindow { activation_height:0, block_time_secs:interval }
            })).unwrap();
            cs.put_chain_config(&config).unwrap();
            let voters = [
                Address::from([1; 32]),
                Address::from([2; 32]),
                Address::from([3; 32]),
            ];
            let mut ws = WorldState::new(db);
            ws.set_validators(&voters).unwrap();
            for (i, voter) in voters.iter().enumerate() {
                cs.put_pubkey(voter, &[i as u8 + 1; 1952]).unwrap();
            }
            Self {
                ws,
                cs,
                registry: AlgorithmRegistry::default(),
                voters,
            }
        }
        fn call(
            &mut self,
            voter: usize,
            input: &[u8],
            height: u64,
        ) -> Result<Vec<u8>, SystemContractError> {
            execute_validator_registry_with_registry(
                &self.voters[voter],
                input,
                &mut self.ws,
                Some(&self.cs),
                &mut self.registry,
                Some(height),
            )
            .map(|out| out.0)
        }
        fn reject(&mut self, voter: usize, input: &[u8], height: u64, message: &str) {
            let root = self.ws.state_root().unwrap();
            let registry = self.registry.clone();
            let error = self.call(voter, input, height).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
            assert_eq!(self.ws.state_root().unwrap(), root);
            assert_eq!(self.registry, registry);
        }
    }
    fn submission(height: u64) -> Vec<u8> {
        let mut input = SUBMIT_ALGORITHM_PROPOSAL_SELECTOR.to_vec();
        input.extend_from_slice(&encode_u8_word(1));
        let mut name = [0; 32];
        name[..9].copy_from_slice(b"ML-DSA-65");
        input.extend_from_slice(&name);
        for n in [
            1952,
            3309,
            PQ_MLDSA65_VERIFY_GAS,
            PQ_MLDSA65_BATCH_VERIFY_GAS_PER_SIG,
        ] {
            input.extend_from_slice(encode_u64_as_hash(n).as_bytes());
        }
        input.extend_from_slice(&[0x44; 32]);
        input.extend_from_slice(encode_u64_as_hash(height).as_bytes());
        input
    }
    fn ballot(algo: u8, id: &[u8]) -> Vec<u8> {
        let mut input = VOTE_ALGORITHM_PROPOSAL_SELECTOR.to_vec();
        input.extend_from_slice(&encode_u8_word(algo));
        input.extend_from_slice(id);
        input
    }
    fn getter(id: &[u8]) -> Vec<u8> {
        [GET_ALGORITHM_PROPOSAL_SELECTOR.as_slice(), id].concat()
    }

    #[test]
    fn algorithm_identity_expiry_retry_replay_and_quorum() {
        let mut f = Fixture::new(Some(0), 604_800);
        let original = f.registry.clone();
        let first = submission(2_000_000);
        let id = f.call(0, &first, 1).unwrap();
        assert_eq!(f.registry, original); // Submission itself is not a vote.
        assert_eq!(f.call(1, &ballot(1, &id), 1).unwrap(), encode_bool(false));
        f.reject(1, &ballot(1, &id), 1, "duplicate vote");
        f.reject(0, &first, 1, "duplicate algorithm proposal ID");
        f.reject(2, &submission(2_000_001), 1, "conflicts");
        f.reject(2, &ballot(1, &id), 2, "expired");
        f.reject(0, &first, 2, "duplicate algorithm proposal ID");
        assert_eq!(f.registry, original);
        let second = submission(2_000_001);
        let next = f.call(0, &second, 2).unwrap();
        assert_ne!(id, next);
        f.reject(2, &ballot(1, &id), 2, "does not match");
        f.reject(2, &ballot(2, &next), 2, "does not match");
        f.reject(
            0,
            &encode_propose_algorithm_activation_calldata(
                SignatureType::MlDsa65,
                2_000_001,
                [0x44; 32],
            ),
            2,
            "ID-bound",
        );
        // Previous-round votes cannot satisfy this round, including after reload.
        assert_eq!(f.call(1, &ballot(1, &next), 2).unwrap(), encode_bool(false));
        f.registry = load_algorithm_registry(&f.ws).unwrap();
        assert_eq!(f.registry, original);
        assert_eq!(f.call(2, &ballot(1, &next), 2).unwrap(), encode_bool(true));
        let record = f.call(0, &getter(&next), 2).unwrap();
        assert_eq!(&record[..256], &second[4..]);
        assert_eq!(&record[256..288], encode_u64_as_hash(3).as_bytes());
        assert_eq!(&record[288..320], encode_u64_as_hash(1).as_bytes());
        f.reject(0, &ballot(1, &next), 2, "already approved");
        assert!(
            process_pending_activations(2_000_000, &mut f.ws, &mut f.registry)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            process_pending_activations(2_000_001, &mut f.ws, &mut f.registry).unwrap(),
            vec![SignatureType::MlDsa65]
        );
        f.reject(0, &first, 3, "duplicate algorithm proposal ID");
        assert_eq!(f.call(0, &getter(&id), 3).unwrap()[288..320], [0; 32]);
    }

    #[test]
    fn algorithm_identity_activation_preserves_legacy_rounds() {
        for activation in [None, Some(10)] {
            let mut f = Fixture::new(activation, 2);
            for selector in [
                SUBMIT_ALGORITHM_PROPOSAL_SELECTOR,
                VOTE_ALGORITHM_PROPOSAL_SELECTOR,
                GET_ALGORITHM_PROPOSAL_SELECTOR,
            ] {
                f.reject(0, &selector, 9, "unknown function selector");
            }
            let legacy = encode_propose_algorithm_activation_calldata(
                SignatureType::MlDsa65,
                2_000_000,
                [0x44; 32],
            );
            assert_eq!(f.call(0, &legacy, 9).unwrap(), encode_bool(false));
            assert_eq!(f.call(1, &legacy, 10).unwrap(), encode_bool(true));
            if activation.is_some() {
                f.reject(2, &submission(2_000_001), 10, "conflicts");
                let fresh = encode_propose_algorithm_activation_calldata(
                    SignatureType::SphincsSha2256f,
                    2_000_000,
                    [0x44; 32],
                );
                f.reject(2, &fresh, 10, "use submitAlgorithmProposal");
            }
        }
    }

    #[test]
    fn algorithm_identity_replaces_expired_legacy_candidate() {
        let mut f = Fixture::new(Some(2), 604_800);
        let legacy = encode_propose_algorithm_activation_calldata(
            SignatureType::MlDsa65,
            2_000_000,
            [0x44; 32],
        );
        assert_eq!(f.call(0, &legacy, 1).unwrap(), encode_bool(false));
        let id = f.call(0, &submission(2_000_000), 2).unwrap();
        assert_eq!(
            read(
                &f.ws,
                &algorithm_proposal_height_key(SignatureType::MlDsa65)
            )
            .unwrap(),
            ShellHash::ZERO
        );
        assert_eq!(f.call(1, &ballot(1, &id), 2).unwrap(), encode_bool(false));
        assert_eq!(f.call(0, &ballot(1, &id), 2).unwrap(), encode_bool(true));
    }

    #[test]
    fn algorithm_identity_spec_and_key_are_bound_and_strict() {
        let input = submission(2_000_000);
        let params = &input[4..];
        let expected = proposal_id(params, &[1; 1952]);
        assert_eq!(
            hex::encode(expected.as_bytes()),
            "7b895ae6caf76509e10a642cab098c06f38028540667ec9f882173fccfa7d4cd"
        );
        for offset in [31, 32, 95, 127, 159, 191, 192, 255] {
            let mut changed = params.to_vec();
            changed[offset] ^= 1;
            assert_ne!(proposal_id(&changed, &[1; 1952]), expected);
        }
        assert_ne!(proposal_id(params, &[2; 1952]), expected);
        let mut f = Fixture::new(Some(0), 2);
        let id = f.call(0, &input, 1).unwrap();
        assert_eq!(id, expected.as_bytes());
        for offset in [4, 35, 36, 99, 131, 163, 195] {
            let mut invalid = input.clone();
            invalid[offset] ^= 0x80;
            f.reject(1, &invalid, 2, "invalid");
        }
        let mut trailing = input.clone();
        trailing.push(0);
        f.reject(1, &trailing, 2, "eight ABI words");
        f.reject(1, &input[..input.len() - 1], 2, "eight ABI words");
        f.reject(1, &getter(&[0x99; 32]), 2, "unknown algorithm proposal");
    }

    #[test]
    fn algorithm_identity_rejects_missing_key_unauthorized_and_overflow_without_writes() {
        let mut f = Fixture::new(Some(0), 2);
        let input = submission(2_000_000);
        f.cs.put_pubkey(&f.voters[0], &[]).unwrap();
        f.reject(0, &input, 1, "pubkey is not registered");
        f.ws.set_validators(&f.voters[1..]).unwrap();
        f.reject(0, &input, 1, "unauthorized");
        f.reject(1, &input, u64::MAX, "deadline exceeds");
        f.reject(1, &submission(1), 1, "below minimum");
    }

    #[test]
    fn algorithm_identity_weighted_quorum_requires_two_thirds() {
        let mut f = Fixture::new(Some(0), 2);
        for (voter, weight) in f.voters.iter().zip([1, 3, 1]) {
            f.ws.set_validator_weight(voter, weight).unwrap();
        }
        let id = f.call(0, &submission(2_000_000), 1).unwrap();
        assert_eq!(f.call(0, &ballot(1, &id), 1).unwrap(), encode_bool(false));
        assert_eq!(f.call(1, &ballot(1, &id), 1).unwrap(), encode_bool(true));
    }
}
