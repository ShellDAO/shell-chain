//! Authenticated, epoch-bound recovery of certified offline suspension.

use super::*;
use shell_core::SignedTransaction;
use shell_crypto::Verifier;

pub(super) fn execute<S: KvStore + 'static>(
    tx: &SignedTransaction,
    input: &[u8],
    state: &mut WorldState<S>,
    chain: &ChainStore<S>,
    number: u64,
) -> Result<SystemContractOutcome, SystemContractError> {
    let fail = || SystemContractError::Unauthorized;
    let config = chain
        .get_chain_config()
        .map_err(storage)?
        .ok_or_else(fail)?;
    let profile = config
        .offline_enforcement
        .filter(|p| p.is_active(number))
        .ok_or_else(fail)?;
    let epoch = profile.epoch_at(number).map_err(storage)?;
    if input.len() != 100 || tx.tx.chain_id != config.chain_id || tx.tx.value != U256::ZERO {
        return Err(fail());
    }
    // The same verified envelope may contain native AA inner calls. A caller
    // cannot substitute data that the outer root signature did not authorize.
    let scoped = match tx.aa_bundle() {
        Some(bundle) => bundle.inner_calls.iter().any(|call| {
            call.to == Some(registry_address())
                && call.value == U256::ZERO
                && call.data.as_ref() == input
        }),
        None => tx.tx.to == Some(registry_address()) && tx.tx.data.as_ref() == input,
    };
    let registered = chain.get_pubkey(&tx.from).map_err(storage)?;
    let key = match registered {
        Some(key) => {
            if tx
                .pubkey_mode
                .pubkey_bytes()
                .is_some_and(|embedded| embedded != key)
            {
                return Err(fail());
            }
            key
        }
        None => {
            let embedded = tx.pubkey_mode.pubkey_bytes().ok_or_else(fail)?;
            if Address::from_public_key(embedded, tx.signature.sig_type.as_u8()) != tx.from {
                return Err(fail());
            }
            embedded.to_vec()
        }
    };
    if !scoped
        || !shell_crypto::is_algorithm_allowed(tx.signature.sig_type)
        || !shell_crypto::MultiVerifier
            .verify(&key, tx.sender_signing_hash().as_bytes(), &tx.signature)
            .map_err(|_| fail())?
    {
        return Err(fail());
    }
    let target = decode_address(&input[4..36])?;
    let incident = decode_u64(&input[36..68])?;
    let claimed_set = ShellHash::try_from_slice(&input[68..100]).map_err(|_| fail())?;
    let mut ledger = state.load_offline_state().map_err(storage)?;
    let cursor = ledger.cursor().ok_or_else(fail)?;
    if !cursor.proposed
        || cursor.context.chain_id != config.chain_id
        || cursor.context.block_number != number
        || cursor.context.epoch != epoch
    {
        return Err(fail());
    }
    let authorities = state.load_offline_authorities().map_err(storage)?;
    let set = shell_core::timeout_authority_set_hash(&authorities).map_err(|_| fail())?;
    if claimed_set != set
        || !authorities.iter().any(|(a, w)| *a == tx.from && *w > 0)
        || ledger.is_suspended(&tx.from, epoch)
        || !ledger.is_suspended(&target, epoch)
        || !state.get_validators().map_err(storage)?.contains(&target)
        || !ledger
            .validator(&target)
            .is_some_and(|v| v.suspend_at_epoch == Some(incident) && v.recover_at_epoch.is_none())
    {
        return Err(fail());
    }
    let vote_key = |voter: &Address| {
        let mut bytes = b"shell:offline-recovery-vote:v1".to_vec();
        for value in [config.chain_id, epoch, incident] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(target.as_bytes());
        bytes.extend_from_slice(set.as_bytes());
        bytes.extend_from_slice(voter.as_bytes());
        keccak256(&bytes)
    };
    if state
        .get_storage(&registry_address(), &vote_key(&tx.from))
        .map_err(storage)?
        != ShellHash::ZERO
    {
        return Err(SystemContractError::DuplicateVote);
    }
    let mut total = 0u128;
    let mut voted = 0u128;
    for (address, weight) in &authorities {
        total += u128::from(*weight);
        if *address == tx.from
            || state
                .get_storage(&registry_address(), &vote_key(address))
                .map_err(storage)?
                != ShellHash::ZERO
        {
            voted += u128::from(*weight);
        }
    }
    // Existing validator governance uses a strict weighted supermajority.
    let approved = voted * 3 > total * 2;
    if approved {
        ledger
            .schedule_recovery_authorized(&target, epoch)
            .map_err(SystemContractError::AbiDecode)?;
    }
    let mut staged = state.snapshot().map_err(storage)?;
    staged
        .set_storage(
            &registry_address(),
            &vote_key(&tx.from),
            &ShellHash::from([1; 32]),
        )
        .map_err(storage)?;
    if approved {
        staged.save_offline_state(&ledger).map_err(storage)?;
    }
    staged.state_root().map_err(storage)?;
    *state = staged;
    Ok(SystemContractOutcome {
        output: encode_bool(approved),
        gas_used: SYSTEM_CALL_BASE_GAS + SYSTEM_CALL_OP_GAS,
        effects: SystemContractEffects::default(),
    })
}

fn storage(error: shell_storage::StorageError) -> SystemContractError {
    SystemContractError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use shell_core::{OfflineCursor, OfflineState, SignedTransaction, TimeoutContext, Transaction};
    use shell_crypto::{MlDsaSigner, Signer};
    use shell_primitives::Bytes;
    use shell_storage::MemoryDb;
    use std::sync::Arc;

    fn vote(key: &MlDsaSigner, target: Address, set: ShellHash) -> SignedTransaction {
        let mut data = compute_selector(b"recoverValidator(address,uint64,bytes32)").to_vec();
        data.extend_from_slice(target.as_bytes());
        data.extend_from_slice(&[0; 31]);
        data.push(1);
        data.extend_from_slice(set.as_bytes());
        let tx = Transaction {
            chain_id: 1337,
            nonce: 0,
            to: Some(registry_address()),
            value: U256::ZERO,
            data: Bytes::from(data),
            gas_limit: 100_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            access_list: None,
            tx_type: 2,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
        let from = Address::from_public_key(key.public_key(), key.sig_type().as_u8());
        let mut signed = SignedTransaction::with_pubkey(
            from,
            tx,
            key.sign(&[0]).unwrap(),
            key.public_key().to_vec(),
        );
        signed.signature = key.sign(signed.sender_signing_hash().as_bytes()).unwrap();
        signed
    }

    #[test]
    fn certified_offline_recovery_requires_real_weighted_signed_governance() {
        let keys = [
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
            MlDsaSigner::generate(),
        ];
        let members = keys
            .iter()
            .map(|k| Address::from_public_key(k.public_key(), k.sig_type().as_u8()))
            .collect::<Vec<_>>();
        let store = Arc::new(MemoryDb::new());
        let cs = ChainStore::new(store.clone());
        let mut ws = WorldState::new(store);
        cs.put_chain_config(&serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":ShellHash::ZERO,"aa_validator_registry_height":0,"offline_enforcement":{"activation_height":1,"epoch_length":10,"block_time_secs":2,"heartbeat_interval_secs":600}})).unwrap()).unwrap();
        ws.set_validators(&members).unwrap();
        ws.set_validator_weights(&members, &[1, 1, 2]).unwrap();
        for (m, k) in members.iter().zip(&keys).skip(1) {
            cs.put_pubkey(m, k.public_key()).unwrap();
        }
        let authorities = vec![(members[0], 1), (members[2], 2)];
        let set = shell_core::timeout_authority_set_hash(&authorities).unwrap();
        let mut ledger = OfflineState::default();
        ledger.sync_membership(&members).unwrap();
        let mut entries = ledger.validators().to_vec();
        let b = entries
            .iter_mut()
            .find(|v| v.address == members[1])
            .unwrap();
        b.consecutive_misses = 100;
        b.suspend_at_epoch = Some(1);
        let ledger = OfflineState::from_parts(
            entries,
            Some(OfflineCursor {
                context: TimeoutContext {
                    chain_id: 1337,
                    block_number: 10,
                    view: 0,
                    epoch: 1,
                    parent_hash: ShellHash::from([7; 32]),
                    authority_set_hash: set,
                    proposer: members[0],
                    opportunity_hash: ShellHash::ZERO,
                },
                proposed: true,
            }),
            ShellHash::ZERO,
        )
        .unwrap();
        ws.save_offline_state(&ledger).unwrap();
        ws.save_offline_authorities(&authorities).unwrap();
        let tx = vote(&keys[2], members[1], set);
        let result = execute_signed_system_contract_call(
            &registry_address(),
            &tx,
            tx.tx.data.as_ref(),
            &mut ws,
            &cs,
            10,
        )
        .unwrap();
        assert_eq!(result.output, encode_bool(false));
        assert!(ws
            .load_offline_state()
            .unwrap()
            .is_suspended(&members[1], 1));

        let root = ws.state_root().unwrap();
        assert!(execute_system_contract_call_at_block(
            &registry_address(),
            &members[0],
            tx.tx.data.as_ref(),
            &mut ws,
            &cs,
            10
        )
        .is_err());
        assert!(execute_signed_system_contract_call(
            &registry_address(),
            &tx,
            tx.tx.data.as_ref(),
            &mut ws,
            &cs,
            10
        )
        .is_err());
        for index in 0..6 {
            let mut bad = vote(&keys[0], members[1], set);
            match index {
                0 => bad.from = members[1],
                1 => bad.signature = keys[1].sign(b"wrong message").unwrap(),
                2 => bad.tx.chain_id = 10,
                3 => {
                    let mut bytes = bad.tx.data.as_ref().to_vec();
                    bytes[67] = 2;
                    bad.tx.data = bytes.into();
                }
                4 => {
                    let mut bytes = bad.tx.data.as_ref().to_vec();
                    bytes[99] ^= 1;
                    bad.tx.data = bytes.into();
                }
                _ => bad.tx.value = U256::from(1),
            }
            if index >= 2 {
                bad.signature = keys[0].sign(bad.sender_signing_hash().as_bytes()).unwrap();
            }
            assert!(execute_signed_system_contract_call(
                &registry_address(),
                &bad,
                bad.tx.data.as_ref(),
                &mut ws,
                &cs,
                10
            )
            .is_err());
            assert_eq!(ws.state_root().unwrap(), root);
        }
        let suspended = vote(&keys[1], members[1], set);
        assert!(execute_signed_system_contract_call(
            &registry_address(),
            &suspended,
            suspended.tx.data.as_ref(),
            &mut ws,
            &cs,
            10
        )
        .is_err());
        assert_eq!(ws.state_root().unwrap(), root);
        let approve = vote(&keys[0], members[1], set);
        assert!(execute_signed_system_contract_call(
            &registry_address(),
            &approve,
            approve.tx.data.as_ref(),
            &mut ws,
            &cs,
            9
        )
        .is_err());
        assert_eq!(ws.state_root().unwrap(), root);
        let mut substituted = approve.clone();
        substituted.tx.to = Some(Address::ZERO);
        substituted.signature = keys[0]
            .sign(substituted.sender_signing_hash().as_bytes())
            .unwrap();
        assert!(execute_signed_system_contract_call(
            &registry_address(),
            &substituted,
            approve.tx.data.as_ref(),
            &mut ws,
            &cs,
            10
        )
        .is_err());
        assert_eq!(ws.state_root().unwrap(), root);
        for activation in [None, Some(11)] {
            let inactive = ChainStore::new(Arc::new(MemoryDb::new()));
            inactive.put_chain_config(&serde_json::from_value(serde_json::json!({"chain_id":1337,"genesis_hash":ShellHash::ZERO,"offline_enforcement":activation.map(|activation_height|shell_storage::OfflineEnforcement{activation_height,epoch_length:10,block_time_secs:2,heartbeat_interval_secs:600})})).unwrap()).unwrap();
            assert!(execute_signed_system_contract_call(
                &registry_address(),
                &approve,
                approve.tx.data.as_ref(),
                &mut ws,
                &inactive,
                10
            )
            .is_err());
            assert_eq!(ws.state_root().unwrap(), root);
        }
        let approved = execute_signed_system_contract_call(
            &registry_address(),
            &approve,
            approve.tx.data.as_ref(),
            &mut ws,
            &cs,
            10,
        )
        .unwrap();
        assert_eq!(approved.output, encode_bool(true));
        let mut ledger = ws.load_offline_state().unwrap();
        assert_eq!(
            ledger.validator(&members[1]).unwrap().recover_at_epoch,
            Some(2)
        );
        assert!(ledger.is_suspended(&members[1], 1));
        assert!(!ledger.is_suspended(&members[1], 2));
        assert_eq!(
            ledger.validator(&members[1]).unwrap().consecutive_misses,
            100
        );
        let committed = ws.state_root().unwrap();
        let historical = WorldState::at_root(cs.store().clone(), &root).unwrap();
        assert_eq!(
            historical
                .load_offline_state()
                .unwrap()
                .validator(&members[1])
                .unwrap()
                .recover_at_epoch,
            None
        );
        let reopened = WorldState::at_root(cs.store().clone(), &committed).unwrap();
        assert_eq!(reopened.load_offline_state().unwrap(), ledger);
        ledger.activate_recoveries(2);
        assert_eq!(ledger.validator(&members[1]).unwrap().consecutive_misses, 0);
        assert_eq!(
            ledger.validator(&members[1]).unwrap().suspend_at_epoch,
            None
        );

        // An endorsement from the previous epoch cannot be accumulated into
        // a new epoch's quorum, even when the incident and committee match.
        let mut later = WorldState::at_root(cs.store().clone(), &root).unwrap();
        let old = later.load_offline_state().unwrap();
        let mut cursor = old.cursor().unwrap().clone();
        cursor.context.block_number = 20;
        cursor.context.epoch = 2;
        let next =
            OfflineState::from_parts(old.validators().to_vec(), Some(cursor), old.transcript())
                .unwrap();
        later.save_offline_state(&next).unwrap();
        later.save_offline_authorities(&authorities).unwrap();
        let result = execute_signed_system_contract_call(
            &registry_address(),
            &approve,
            approve.tx.data.as_ref(),
            &mut later,
            &cs,
            20,
        )
        .unwrap();
        assert_eq!(result.output, encode_bool(false));
        assert_eq!(
            later
                .load_offline_state()
                .unwrap()
                .validator(&members[1])
                .unwrap()
                .recover_at_epoch,
            None
        );

        // A failing later native AA call must roll back both the vote words
        // and the pending recovery, while preserving ordinary gas/nonce effects.
        let mut atomic = WorldState::at_root(cs.store().clone(), &root).unwrap();
        atomic
            .set_balance(&members[0], U256::from(10_000_000))
            .unwrap();
        let mut evm = crate::ShellPqvm::new(
            crate::ShellStateDb::new(atomic, ChainStore::new(cs.store().clone())),
            1337,
        );
        let header = shell_core::BlockHeader {
            number: 10,
            timestamp: 1000,
            gas_limit: 30_000_000,
            base_fee_per_gas: 7,
            ..Default::default()
        };
        for (nonce, fail) in [(0, true), (1, false)] {
            let mut outer = vote(&keys[0], members[1], set).tx;
            outer.nonce = nonce;
            outer.to = None;
            outer.data = Bytes::new();
            outer.tx_type = shell_core::AA_BUNDLE_TX_TYPE;
            outer.gas_limit = 300_000;
            let mut calls = vec![shell_core::InnerCall {
                to: Some(registry_address()),
                value: U256::ZERO,
                data: approve.tx.data.clone(),
                gas_limit: 100_000,
            }];
            if fail {
                calls.push(shell_core::InnerCall {
                    to: Some(registry_address()),
                    value: U256::ZERO,
                    data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                    gas_limit: 100_000,
                });
            }
            let mut signed = SignedTransaction::with_aa_bundle(
                members[0],
                outer,
                keys[0].sign(&[0]).unwrap(),
                shell_core::PubkeyMode::Embedded(keys[0].public_key().to_vec()),
                shell_core::AaBundle {
                    inner_calls: calls,
                    ..Default::default()
                },
            )
            .unwrap();
            signed.signature = keys[0]
                .sign(signed.sender_signing_hash().as_bytes())
                .unwrap();
            let result = evm.execute_aa_bundle(&signed, &header, 0, 0).unwrap();
            assert_eq!(result.receipt.status, u8::from(!fail));
            let state = evm.state_db().world_state();
            assert_eq!(state.get_nonce(&members[0]).unwrap(), nonce + 1);
            assert_eq!(
                state
                    .load_offline_state()
                    .unwrap()
                    .validator(&members[1])
                    .unwrap()
                    .recover_at_epoch,
                if fail { None } else { Some(2) }
            );
        }
    }
}
