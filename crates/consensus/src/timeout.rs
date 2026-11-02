//! Parent- and assignment-bound timeout verification. Canonical callers must
//! validate opportunity commitment and activation before admitting evidence.
use crate::ConsensusError;
use shell_core::BlockSignerEvidence;
pub use shell_core::{TimeoutCertificate, TimeoutContext, TimeoutVote};
use shell_crypto::{is_algorithm_allowed, Verifier};
use shell_primitives::{keccak256, Address, ShellHash};
use std::collections::{HashMap, HashSet};

fn invalid(reason: &str) -> ConsensusError {
    ConsensusError::InvalidLifecycleTransition(format!("invalid timeout evidence: {reason}"))
}

/// Commit the canonical ordered active set and effective weights. Sorting an
/// unordered map here would lose the order used by weighted proposer rotation.
pub fn timeout_authority_set_hash(
    authorities: &[(Address, u64)],
) -> Result<ShellHash, ConsensusError> {
    shell_core::timeout_authority_set_hash(authorities).map_err(|reason| invalid(&reason))
}

/// Same weighted base slot and subsequent ordered rotation as wPoA. All
/// arithmetic is widened so quorum/slot sums cannot wrap at u64 boundaries.
pub fn timeout_proposer(
    block_number: u64,
    view: u64,
    authorities: &[(Address, u64)],
) -> Result<Address, ConsensusError> {
    timeout_authority_set_hash(authorities)?;
    let total: u128 = authorities
        .iter()
        .map(|(_, weight)| u128::from(*weight))
        .sum();
    let slot = u128::from(block_number) % total;
    let mut end = 0u128;
    let base = authorities
        .iter()
        .position(|(_, weight)| {
            end += u128::from(*weight);
            slot < end
        })
        .ok_or_else(|| invalid("proposer slot outside authority set"))?;
    let index = (base as u128 + u128::from(view)) % authorities.len() as u128;
    Ok(authorities[index as usize].0)
}

fn validate_context(
    supplied: &TimeoutContext,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
) -> Result<(), ConsensusError> {
    if supplied != expected
        || expected.block_number == 0
        || expected.parent_hash == ShellHash::ZERO
        || expected.opportunity_hash == ShellHash::ZERO
        || expected.authority_set_hash != timeout_authority_set_hash(authorities)?
        || expected.proposer != timeout_proposer(expected.block_number, expected.view, authorities)?
    {
        return Err(invalid("canonical context or assignment mismatch"));
    }
    Ok(())
}

fn verify_signer(
    context: &TimeoutContext,
    signer: &BlockSignerEvidence,
    verifier: &dyn Verifier,
) -> Result<(), ConsensusError> {
    if !is_algorithm_allowed(signer.signature.sig_type)
        || Address::from_public_key(&signer.public_key, signer.signature.sig_type.as_u8())
            != signer.address
        || !verifier
            .verify(
                &signer.public_key,
                &context.signing_message(&signer.address),
                &signer.signature,
            )
            .map_err(|_| ConsensusError::InvalidSignature)?
    {
        return Err(ConsensusError::InvalidSignature);
    }
    Ok(())
}

pub fn verify_timeout_vote(
    vote: &TimeoutVote,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
    public_key: &[u8],
    verifier: &dyn Verifier,
) -> Result<(), ConsensusError> {
    validate_context(&vote.context, expected, authorities)?;
    if !authorities
        .iter()
        .any(|(address, _)| *address == vote.validator)
    {
        return Err(invalid("voter outside active set"));
    }
    verify_signer(
        &vote.context,
        &BlockSignerEvidence {
            address: vote.validator,
            public_key: public_key.to_vec(),
            signature: vote.signature.clone(),
        },
        verifier,
    )
}

pub fn verify_timeout_certificate(
    certificate: &TimeoutCertificate,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
    verifier: &dyn Verifier,
) -> Result<(), ConsensusError> {
    validate_context(&certificate.context, expected, authorities)?;
    if certificate.signers.is_empty() || certificate.signers.len() > authorities.len() {
        return Err(invalid("invalid voter count"));
    }
    let weights: HashMap<_, _> = authorities.iter().copied().collect();
    let total: u128 = weights.values().map(|weight| u128::from(*weight)).sum();
    let mut seen = HashSet::new();
    let mut signed = 0u128;
    for signer in &certificate.signers {
        let weight = weights
            .get(&signer.address)
            .ok_or_else(|| invalid("voter outside active set"))?;
        if !seen.insert(signer.address) {
            return Err(invalid("duplicate voter"));
        }
        verify_signer(&certificate.context, signer, verifier)?;
        signed += u128::from(*weight);
    }
    if signed < (2 * total).div_ceil(3) {
        return Err(invalid("insufficient weighted quorum"));
    }
    Ok(())
}

/// Validate the exact block-position envelope as well as the signed quorum.
/// The executing node must supply its admitted canonical opportunity/context.
pub fn verify_timeout_system_transaction(
    tx: &shell_core::SystemTransaction,
    expected_index: u32,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
    verifier: &dyn Verifier,
) -> Result<TimeoutCertificate, ConsensusError> {
    let certificate =
        TimeoutCertificate::from_system_transaction(tx, expected_index).map_err(|e| invalid(&e))?;
    verify_timeout_certificate(&certificate, expected, authorities, verifier)?;
    Ok(certificate)
}

/// Authenticate and apply one slot atomically to the deterministic offline state.
/// Runtime admission supplies expected context; V1 view-change votes never enter here.
pub fn apply_timeout_system_transaction(
    state: &mut shell_core::OfflineState,
    tx: &shell_core::SystemTransaction,
    expected_index: u32,
    expected: &TimeoutContext,
    authorities: &[(Address, u64)],
    verifier: &dyn Verifier,
) -> Result<(), ConsensusError> {
    verify_timeout_system_transaction(tx, expected_index, expected, authorities, verifier)?;
    let proof = tx
        .proof_payload
        .as_ref()
        .ok_or_else(|| invalid("missing proof payload"))?;
    state
        .record_verified_timeout(expected, keccak256(proof.as_ref()))
        .map_err(|e| invalid(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::SystemTransaction;
    use shell_crypto::{MlDsaSigner, MultiVerifier, Signer};

    fn fixture() -> (Vec<MlDsaSigner>, Vec<(Address, u64)>, TimeoutContext) {
        let signers = (0..3).map(|_| MlDsaSigner::generate()).collect::<Vec<_>>();
        let set = signers
            .iter()
            .zip([3, 1, 2])
            .map(|(s, w)| {
                (
                    Address::from_public_key(s.public_key(), s.sig_type().as_u8()),
                    w,
                )
            })
            .collect::<Vec<_>>();
        let context = TimeoutContext {
            chain_id: 1337,
            block_number: 7,
            view: 1,
            parent_hash: ShellHash::from([1; 32]),
            epoch: 2,
            authority_set_hash: timeout_authority_set_hash(&set).unwrap(),
            proposer: set[1].0, // 7 % 6 = 1 selects the first base; next view selects second.
            opportunity_hash: ShellHash::from([2; 32]),
        };
        (signers, set, context)
    }
    fn evidence(signer: &MlDsaSigner, context: &TimeoutContext) -> BlockSignerEvidence {
        let address = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        BlockSignerEvidence {
            address,
            public_key: signer.public_key().to_vec(),
            signature: signer.sign(&context.signing_message(&address)).unwrap(),
        }
    }

    #[test]
    fn timeout_one_hundred_assigned_misses_suspend_only_at_next_epoch() {
        use shell_core::{OfflineState, OFFLINE_ASSIGNED_MISS_THRESHOLD};
        let keys = (0..3).map(|_| MlDsaSigner::generate()).collect::<Vec<_>>();
        let set = keys
            .iter()
            .zip([1, 3, 1])
            .map(|(key, weight)| {
                (
                    Address::from_public_key(key.public_key(), key.sig_type().as_u8()),
                    weight,
                )
            })
            .collect::<Vec<_>>();
        let mut state = OfflineState::default();
        state
            .sync_membership(&set.iter().map(|(a, _)| *a).collect::<Vec<_>>())
            .unwrap();
        let mut certified = 0;
        for height in 1..=500 {
            let mut context = TimeoutContext {
                chain_id: 1337,
                block_number: height,
                view: 0,
                parent_hash: ShellHash::from([1; 32]),
                epoch: height / 32,
                authority_set_hash: timeout_authority_set_hash(&set).unwrap(),
                proposer: timeout_proposer(height, 0, &set).unwrap(),
                opportunity_hash: ShellHash::from([2; 32]),
            };
            if context.proposer == set[0].0 {
                let certificate = TimeoutCertificate {
                    opportunity: None,
                    context: context.clone(),
                    signers: vec![evidence(&keys[1], &context), evidence(&keys[2], &context)],
                };
                let tx = certificate.system_transaction(0).unwrap();
                apply_timeout_system_transaction(
                    &mut state,
                    &tx,
                    0,
                    &context,
                    &set,
                    &MultiVerifier,
                )
                .unwrap();
                certified += 1;
                let saved = state.clone();
                assert!(apply_timeout_system_transaction(
                    &mut state,
                    &tx,
                    0,
                    &context,
                    &set,
                    &MultiVerifier
                )
                .is_err());
                assert_eq!(state, saved);
                assert_eq!(
                    state.validator(&set[0].0).unwrap().consecutive_misses,
                    certified
                );
                assert_eq!(
                    state
                        .validator(&set[0].0)
                        .unwrap()
                        .suspend_at_epoch
                        .is_some(),
                    certified == OFFLINE_ASSIGNED_MISS_THRESHOLD
                );
                context.view = 1;
                context.proposer = timeout_proposer(height, 1, &set).unwrap();
            }
            state.record_verified_proposal(&context).unwrap();
            assert_eq!(state.validator(&set[2].0).unwrap().consecutive_misses, 0);
        }
        assert_eq!(certified, 100);
        assert!(!state.is_suspended(&set[0].0, 15));
        assert!(state.is_suspended(&set[0].0, 16));
        let bytes = state.to_state_bytes().unwrap();
        assert_eq!(OfflineState::from_state_bytes(&bytes).unwrap(), state);
        state.schedule_recovery_authorized(&set[0].0, 16).unwrap();
        assert!(state.is_suspended(&set[0].0, 16));
        assert!(!state.is_suspended(&set[0].0, 17));
        state.activate_recoveries(17);
        assert!(!state.is_suspended(&set[0].0, 16));
        assert_eq!(state.validator(&set[0].0).unwrap().consecutive_misses, 0);
        state.sync_membership(&[set[1].0, set[2].0]).unwrap();
        state
            .sync_membership(&[set[0].0, set[1].0, set[2].0])
            .unwrap();
        assert_eq!(state.validator(&set[0].0).unwrap().consecutive_misses, 0);
    }

    #[test]
    fn timeout_low_weight_validators_are_not_missed_during_unassigned_heights() {
        let a = Address::from([1; 32]);
        let b = Address::from([2; 32]);
        let c = Address::from([3; 32]);
        let set = vec![(a, 1), (b, 499), (c, 1)];
        let mut state = shell_core::OfflineState::default();
        state.sync_membership(&[a, b, c]).unwrap();
        for height in 1..=500u64 {
            let context = TimeoutContext {
                chain_id: 1337,
                block_number: height,
                view: 0,
                parent_hash: ShellHash::from([1; 32]),
                epoch: height / 32,
                authority_set_hash: timeout_authority_set_hash(&set).unwrap(),
                proposer: if height < 500 { b } else { c },
                opportunity_hash: ShellHash::from([2; 32]),
            };
            assert_eq!(timeout_proposer(height, 0, &set).unwrap(), context.proposer);
            state.record_verified_proposal(&context).unwrap();
            for who in [a, c] {
                assert_eq!(state.validator(&who).unwrap().consecutive_misses, 0);
                assert!(!state.is_suspended(&who, context.epoch));
            }
        }
    }

    #[test]
    fn timeout_payload_binds_every_context_word_and_identity() {
        let address = Address::from([9; 32]);
        let context = TimeoutContext {
            chain_id: 10,
            block_number: 11,
            view: 12,
            parent_hash: ShellHash::from([1; 32]),
            epoch: 13,
            authority_set_hash: ShellHash::from([2; 32]),
            proposer: Address::from([3; 32]),
            opportunity_hash: ShellHash::from([4; 32]),
        };
        let mut expected = b"SHELL_TIMEOUT_V1".to_vec();
        for n in [10u64, 11, 12] {
            expected.extend_from_slice(&n.to_be_bytes());
        }
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&13u64.to_be_bytes());
        for byte in [2u8, 3, 4, 9] {
            expected.extend_from_slice(&[byte; 32]);
        }
        assert_eq!(expected.len(), 208);
        assert_eq!(context.signing_message(&address), expected);
    }

    #[test]
    fn timeout_quorum_uses_real_signatures_and_effective_weights() {
        let (keys, set, context) = fixture();
        let mut cert = TimeoutCertificate {
            opportunity: None,
            context: context.clone(),
            signers: vec![evidence(&keys[0], &context)],
        };
        assert!(verify_timeout_certificate(&cert, &context, &set, &MultiVerifier).is_err()); // 3 < ceil(2*6/3)
        cert.signers.push(evidence(&keys[1], &context));
        verify_timeout_certificate(&cert, &context, &set, &MultiVerifier).unwrap(); // 4 reaches quorum
        let vote = TimeoutVote {
            context: context.clone(),
            validator: cert.signers[0].address,
            signature: cert.signers[0].signature.clone(),
        };
        verify_timeout_vote(&vote, &context, &set, keys[0].public_key(), &MultiVerifier).unwrap();
        assert!(
            verify_timeout_vote(&vote, &context, &set, keys[1].public_key(), &MultiVerifier)
                .is_err()
        );
        let mut duplicate = cert.clone();
        duplicate.signers[1] = duplicate.signers[0].clone();
        assert!(verify_timeout_certificate(&duplicate, &context, &set, &MultiVerifier).is_err());
        let mut corrupted = cert.clone();
        corrupted.signers[0].signature.data[0] ^= 1;
        assert!(verify_timeout_certificate(&corrupted, &context, &set, &MultiVerifier).is_err());
        let legacy = crate::ViewChangeMessage::signing_message(
            context.chain_id,
            context.block_number,
            context.view,
            &context.parent_hash,
        );
        let mut old = cert.clone();
        old.signers[0].signature = keys[0].sign(&legacy).unwrap();
        assert!(verify_timeout_certificate(&old, &context, &set, &MultiVerifier).is_err());
    }

    #[test]
    fn timeout_rejects_replay_context_set_and_assignment_changes() {
        let (keys, set, context) = fixture();
        let cert = TimeoutCertificate {
            opportunity: None,
            context: context.clone(),
            signers: vec![evidence(&keys[0], &context), evidence(&keys[1], &context)],
        };
        let mut variants = Vec::new();
        for field in 0..8 {
            let mut changed = context.clone();
            match field {
                0 => changed.chain_id += 1,
                1 => changed.block_number += 1,
                2 => changed.view += 1,
                3 => changed.epoch += 1,
                4 => changed.parent_hash = ShellHash::from([8; 32]),
                5 => changed.authority_set_hash = ShellHash::from([8; 32]),
                6 => changed.proposer = set[0].0,
                _ => changed.opportunity_hash = ShellHash::from([8; 32]),
            }
            variants.push(changed);
        }
        for expected in variants {
            assert!(verify_timeout_certificate(&cert, &expected, &set, &MultiVerifier).is_err());
        }
        let mut wrong = set.clone();
        wrong.swap(0, 1);
        assert!(verify_timeout_certificate(&cert, &context, &wrong, &MultiVerifier).is_err());
        let mut zero = context.clone();
        zero.opportunity_hash = ShellHash::ZERO;
        let empty = TimeoutCertificate {
            opportunity: None,
            context: zero.clone(),
            signers: vec![evidence(&keys[0], &zero), evidence(&keys[1], &zero)],
        };
        assert!(verify_timeout_certificate(&empty, &zero, &set, &MultiVerifier).is_err());
        let mut unassigned = context.clone();
        unassigned.proposer = set[0].0;
        let wrong = TimeoutCertificate {
            opportunity: None,
            context: unassigned.clone(),
            signers: vec![
                evidence(&keys[0], &unassigned),
                evidence(&keys[1], &unassigned),
            ],
        };
        assert!(verify_timeout_certificate(&wrong, &unassigned, &set, &MultiVerifier).is_err());
    }

    #[test]
    fn timeout_set_and_proposer_keep_full_native_words_and_boundaries() {
        let a = Address::from([0xaa; 32]);
        let mut bytes = [0xaa; 32];
        bytes[..12].fill(0xbb);
        let b = Address::from(bytes);
        let set = vec![(a, 3), (b, 1)];
        assert_eq!(timeout_proposer(2, 0, &set).unwrap(), a);
        assert_eq!(timeout_proposer(3, 0, &set).unwrap(), b);
        assert_eq!(timeout_proposer(2, 1, &set).unwrap(), b);
        assert_eq!(timeout_proposer(u64::MAX, u64::MAX, &set).unwrap(), a);
        assert_ne!(
            timeout_authority_set_hash(&set).unwrap(),
            timeout_authority_set_hash(&[(b, 3), (a, 1)]).unwrap()
        );
        for bad in [
            vec![],
            vec![(a, 0)],
            vec![(a, 1), (a, 2)],
            vec![(a, u64::MAX)],
        ] {
            assert!(timeout_authority_set_hash(&bad).is_err());
        }
    }

    #[test]
    fn timeout_system_payload_is_canonical_committed_and_not_a_reward() {
        let (keys, set, context) = fixture();
        let cert = TimeoutCertificate {
            opportunity: None,
            context: context.clone(),
            signers: vec![evidence(&keys[0], &context), evidence(&keys[1], &context)],
        };
        verify_timeout_certificate(&cert, &context, &set, &MultiVerifier).unwrap();
        let tx = cert.system_transaction(4).unwrap();
        let mut reversed = cert.clone();
        reversed.signers.reverse();
        assert_eq!(tx, reversed.system_transaction(4).unwrap());
        assert_eq!(tx.kind, shell_core::SystemTxKind::TimeoutEvidence);
        assert_eq!(tx.kind.as_u8(), 3);
        assert_eq!(tx.value, shell_primitives::U256::ZERO);
        assert_eq!(tx.from, Address::ZERO);
        assert_eq!(tx.source_hash, context.parent_hash);
        assert_eq!(
            SystemTransaction::from_wire_bytes(tx.to_wire_bytes().unwrap().as_ref()).unwrap(),
            tx
        );
        let decoded: TimeoutCertificate =
            serde_json::from_slice(tx.proof_payload.as_ref().unwrap().as_ref()).unwrap();
        verify_timeout_certificate(&decoded, &context, &set, &MultiVerifier).unwrap();
        verify_timeout_system_transaction(&tx, 4, &context, &set, &MultiVerifier).unwrap();
        assert!(verify_timeout_system_transaction(&tx, 5, &context, &set, &MultiVerifier).is_err());
        for field in 0..9 {
            let mut invalid_tx = tx.clone();
            match field {
                0 => invalid_tx.chain_id += 1,
                1 => invalid_tx.block_number += 1,
                2 => invalid_tx.from = set[0].0,
                3 => invalid_tx.to = set[0].0,
                4 => invalid_tx.value = shell_primitives::U256::from(1u64),
                5 => invalid_tx.source_hash = ShellHash::ZERO,
                6 => invalid_tx.layer = Some(1),
                7 => invalid_tx.original_size = Some(1),
                _ => invalid_tx.compressed_size = Some(1),
            }
            assert!(verify_timeout_system_transaction(
                &invalid_tx,
                4,
                &context,
                &set,
                &MultiVerifier
            )
            .is_err());
        }
        let mut changed = tx.clone();
        changed.proof_payload = Some(vec![1].into());
        assert_ne!(changed.hash(), tx.hash());
    }
}
