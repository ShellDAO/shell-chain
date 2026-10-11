use shell_core::{Account, Block, BlockHeader};
use shell_primitives::{keccak256, Address, Bytes, ShellHash};
use shell_storage::{ChainConfig, ChainStore, KvStore, StorageError, WorldState};

use crate::{AllocEntry, GenesisConfig, GenesisError};

/// Genesis commitment for the current transaction signing and identity rules.
///
/// Including this domain in the genesis header gives upgraded networks a
/// distinct genesis hash and prevents nodes with incompatible transaction
/// semantics from sharing canonical history.
pub const TRANSACTION_ID_GENESIS_DOMAIN: &[u8; 16] = b"SHELL_TXID_V3\0\0\0";

/// Initialize world state from genesis allocations and produce the genesis block.
///
/// Persists the genesis block into `chain_store` and writes chain configuration
/// (chain_id + genesis_hash) so that later boot-up can verify chain identity.
pub fn initialize_genesis<S: KvStore + 'static>(
    config: &GenesisConfig,
    store: std::sync::Arc<S>,
) -> Result<Block, GenesisError> {
    config.validate_economics()?;
    config.algorithm_voting_window()?;
    let fallback_commitment = config.governance_fallback_commitment()?;

    let mut world_state = WorldState::new(std::sync::Arc::clone(&store));

    // Apply allocations
    for (address, entry) in &config.alloc {
        apply_alloc(&mut world_state, address, entry)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
    }

    // Write initial validator set to the validator registry in world state.
    let authorities = config.consensus.authorities().to_vec();
    if !authorities.is_empty() {
        world_state
            .set_validators(&authorities)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
        let weights = config.effective_authority_weights()?;
        world_state
            .set_validator_weights(&authorities, &weights)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
    }

    if let Some(economics) = &config.economics {
        world_state
            .set_staking_enabled(economics.staking_enabled)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
        world_state
            .set_total_supply(economics.initial_supply)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
        world_state
            .set_stake_unit(economics.stake_unit)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
        world_state
            .set_max_validator_weight(economics.max_validator_weight)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;

        let stakes = config.consensus.authority_stakes();
        let mut total_staked = shell_primitives::U256::ZERO;
        for (validator, stake) in authorities.iter().zip(stakes.iter().copied()) {
            total_staked = total_staked.saturating_add(stake);
            world_state
                .set_validator_stake_and_weight(
                    validator,
                    stake,
                    economics.stake_unit,
                    economics.max_validator_weight,
                )
                .map_err(|e| GenesisError::StateInit(e.to_string()))?;
        }
        world_state
            .set_total_staked(total_staked)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
    }

    // Mark native system-contract addresses with deterministic placeholder
    // code hashes so they are recognized as contract accounts from genesis.
    mark_system_contract(&mut world_state).map_err(|e| GenesisError::StateInit(e.to_string()))?;

    // Compute state root
    let state_root = world_state
        .state_root()
        .map_err(|e| GenesisError::StateInit(e.to_string()))?;

    // Build genesis header
    let proposer = config
        .consensus
        .authorities()
        .first()
        .copied()
        .unwrap_or(Address::ZERO);

    let mut genesis_extra_data =
        Vec::with_capacity(TRANSACTION_ID_GENESIS_DOMAIN.len() + config.extra_data.len());
    genesis_extra_data.extend_from_slice(TRANSACTION_ID_GENESIS_DOMAIN);
    genesis_extra_data.extend_from_slice(config.extra_data.as_bytes());
    if let Some(commitment) = fallback_commitment {
        genesis_extra_data.extend_from_slice(b"SHELL_GOV_V1");
        genesis_extra_data.extend_from_slice(commitment.as_ref());
    }

    let header = BlockHeader {
        parent_hash: ShellHash::ZERO,
        state_root,
        transactions_root: ShellHash::ZERO,
        receipts_root: ShellHash::ZERO,
        logs_bloom: Bytes::new(),
        number: 0,
        gas_limit: config.gas_limit,
        gas_used: 0,
        timestamp: config.timestamp,
        extra_data: Bytes::from(genesis_extra_data),
        proposer,
        sig_aggregate_proof: None,
        base_fee_per_gas: 0,
        withdrawals_root: ShellHash::ZERO,
        parent_beacon_block_root: ShellHash::ZERO,
        blob_gas_used: 0,
        excess_blob_gas: 0,
        witness_root: None,
    };

    let block = Block {
        header,
        transactions: vec![],
        system_transactions: vec![],
        proposer_seal: None,
    };

    // F-012 / F-013: Persist genesis block + canonical mapping + chain config
    let chain_store = ChainStore::new(std::sync::Arc::clone(&store));
    let genesis_hash = block.hash();

    chain_store
        .commit_genesis_block(
            &block,
            &ChainConfig {
                log_address_activation_height: config.log_address_activation_height,
                algorithm_voting_window: config.algorithm_voting_window()?,
                algorithm_proposal_identity_height: config.algorithm_proposal_identity_height,
                algorithm_deprecation_height: config.algorithm_deprecation_height,
                algorithm_session_deprecation_height: config.algorithm_session_deprecation_height,
                algorithm_paymaster_deprecation_height: config
                    .algorithm_paymaster_deprecation_height,
                algorithm_activation_admission_height: config.algorithm_activation_admission_height,
                validation_pqvm_height: config.validation_pqvm_height,
                validation_deprecation_height: config.validation_deprecation_height,
                session_registered_root_height: config.session_registered_root_height,
                paymaster_registered_root_height: config.paymaster_registered_root_height,
                registered_key_algorithm_height: config.registered_key_algorithm_height,
                aa_account_manager_height: config.aa_account_manager_height,
                aa_validator_registry_height: config.aa_validator_registry_height,
                emergency_governance_height: config.emergency_governance_height,
                native_registry_view_height: config.native_registry_view_height,
                pq_address_bounds_height: config.pq_address_bounds_height,
                native_address_context_height: config.native_address_context_height,
                native_validator_events_height: config.native_validator_events_height,
                prover_registry_height: config.prover_registry_height,
                algorithm_proposal_staging_height: config.algorithm_proposal_staging_height,
                algorithm_quorum_activation_height: config.algorithm_quorum_activation_height,
                algorithm_timelock_activation_height: config.algorithm_timelock_activation_height,
                bloom_activation_height: config.bloom_activation_height,
                fee_accounting_activation_height: config.fee_accounting_activation_height,
                chain_id: config.chain_id,
                genesis_hash,
            },
        )
        .map_err(|e| GenesisError::StateInit(e.to_string()))?;

    Ok(block)
}

/// Restore missing genesis trie nodes and historical metadata from a hash-matched configuration.
/// Live account metadata and the canonical head are never used as genesis values.
pub fn bootstrap_genesis_metadata<S: KvStore + 'static>(
    config: &GenesisConfig,
    chain_store: &ChainStore<S>,
) -> Result<bool, GenesisError> {
    let Some(stored) = chain_store
        .get_chain_config()
        .map_err(|e| GenesisError::StateInit(e.to_string()))?
    else {
        // Legacy stores without a chain identity remain usable, but cannot
        // authenticate this historical metadata checkpoint.
        return Ok(false);
    };
    if stored.chain_id != config.chain_id {
        return Err(GenesisError::Validation(
            "metadata bootstrap chain ID mismatch".into(),
        ));
    }
    let isolated = std::sync::Arc::new(shell_storage::MemoryDb::new());
    let genesis = initialize_genesis(config, isolated.clone())?;
    if stored.genesis_hash != genesis.hash() {
        return Err(GenesisError::Validation(
            "metadata bootstrap genesis identity mismatch".into(),
        ));
    }
    // Checkpoint-only stores may not contain genesis history yet.
    if chain_store
        .get_block_hash_by_number(0)
        .map_err(|e| GenesisError::StateInit(e.to_string()))?
        .is_none()
    {
        return Ok(false);
    }
    let trusted = ChainStore::new(isolated);
    initialize_authority_pubkeys(config, &trusted)?;
    chain_store
        .seed_genesis_metadata_checkpoint(&trusted)
        .map_err(|e| GenesisError::StateInit(e.to_string()))
}

/// Persist authority PQ public keys from genesis into the shared pubkey registry.
pub fn initialize_authority_pubkeys<S: KvStore + 'static>(
    config: &GenesisConfig,
    chain_store: &ChainStore<S>,
) -> Result<(), GenesisError> {
    config.validate_consensus_authorities()?;

    let (authorities, authority_pubkeys) = (
        config.consensus.authorities(),
        config.consensus.authority_pubkeys(),
    );

    let commitment = config.governance_fallback_commitment()?;
    if let Some(genesis) = chain_store
        .get_block_by_number(0)
        .map_err(|e| GenesisError::StateInit(e.to_string()))?
    {
        let extra = genesis.header.extra_data.as_ref();
        if commitment.is_none()
            && extra.len() >= 44
            && &extra[extra.len() - 44..extra.len() - 32] == b"SHELL_GOV_V1"
        {
            return Err(GenesisError::Validation(
                "genesis governance bindings omitted".into(),
            ));
        }
        if let Some(hash) = commitment {
            let mut suffix = b"SHELL_GOV_V1".to_vec();
            suffix.extend_from_slice(hash.as_ref());
            if !genesis.header.extra_data.as_ref().ends_with(&suffix) {
                return Err(GenesisError::Validation(
                    "governance keys do not match genesis commitment".into(),
                ));
            }
        }
    }

    let mut fallback_keys = Vec::with_capacity(config.governance_fallback_keys.len());
    for (address, encoded) in &config.governance_fallback_keys {
        let Some(index) = authorities
            .iter()
            .position(|authority| authority == address)
        else {
            return Err(GenesisError::Validation(
                "governance key is not a genesis authority".into(),
            ));
        };
        let primary = authority_pubkeys
            .get(index)
            .and_then(|key| hex::decode(key.trim_start_matches("0x")).ok())
            .ok_or_else(|| {
                GenesisError::Validation("governance fallback requires a primary key".into())
            })?;
        if primary.len() != 1952 {
            return Err(GenesisError::Validation(
                "governance fallback requires an ML-DSA primary key".into(),
            ));
        }
        let key = hex::decode(encoded.trim_start_matches("0x"))
            .map_err(|e| GenesisError::Validation(format!("invalid governance key hex: {e}")))?;
        if key.len() != 64 {
            return Err(GenesisError::Validation(
                "invalid SLH-DSA governance key length".into(),
            ));
        }
        fallback_keys.push((*address, key));
    }
    // Validate every binding before any writes, including restart mismatches.
    for (address, key) in &fallback_keys {
        if let Some(existing) = chain_store
            .get_governance_fallback_key(address)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?
        {
            if existing != *key {
                return Err(GenesisError::Validation(
                    "genesis governance key changed".into(),
                ));
            }
        }
    }

    if authority_pubkeys.is_empty() {
        return chain_store
            .initialize_genesis_authority_keys(&[], &[])
            .map_err(|e| GenesisError::StateInit(e.to_string()));
    }

    if authority_pubkeys.len() != authorities.len() {
        return Err(GenesisError::Validation(format!(
            "authority_pubkeys length {} does not match authorities length {}",
            authority_pubkeys.len(),
            authorities.len()
        )));
    }

    let mut primary_keys = Vec::with_capacity(authority_pubkeys.len());
    for (address, pubkey_hex) in authorities.iter().zip(authority_pubkeys.iter()) {
        let pubkey = hex::decode(pubkey_hex.trim_start_matches("0x"))
            .map_err(|e| GenesisError::Validation(format!("invalid authority pubkey hex: {e}")))?;
        primary_keys.push((*address, pubkey));
    }
    chain_store
        .initialize_genesis_authority_keys(&primary_keys, &fallback_keys)
        .map_err(|e| GenesisError::StateInit(e.to_string()))?;

    Ok(())
}

fn apply_alloc<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
    address: &Address,
    entry: &AllocEntry,
) -> Result<(), StorageError> {
    // Create account with the allocated balance
    let mut account = Account::new_user_account(ShellHash::ZERO, entry.balance);
    account.nonce = entry.nonce;

    // Set code hash if code is provided
    if let Some(ref code_hex) = entry.code {
        let code = hex::decode(code_hex.trim_start_matches("0x"))
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        let code_hash = keccak256(&code);
        ChainStore::new(std::sync::Arc::clone(world_state.store())).put_code(&code_hash, &code)?;
        account.code_hash = Some(code_hash);
    }

    world_state.set_account(address, &account)?;

    // Apply initial storage entries
    if let Some(ref storage) = entry.storage {
        for (key, value) in storage {
            world_state.set_storage(address, key, value)?;
        }
    }

    Ok(())
}

/// Mark native system-contract addresses as code accounts with deterministic
/// placeholder code hashes.
fn mark_system_contract<S: KvStore + 'static>(
    world_state: &mut WorldState<S>,
) -> Result<(), StorageError> {
    let registry_addr = shell_storage::validator_registry_addr();
    let account_manager_addr = shell_storage::account_manager_addr();
    world_state.set_code_hash(&registry_addr, keccak256(b"ValidatorRegistry"))?;
    world_state.set_code_hash(&account_manager_addr, keccak256(b"AccountManager"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConsensusConfig;
    use shell_primitives::U256;
    use shell_storage::{ChainStore, KvStore, MemoryDb, StorageError, WriteBatch};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct FailingBatchDb {
        inner: MemoryDb,
        fail_next_batch: AtomicBool,
    }

    impl FailingBatchDb {
        fn new() -> Self {
            Self {
                inner: MemoryDb::new(),
                fail_next_batch: AtomicBool::new(false),
            }
        }

        fn fail_next_batch(&self) {
            self.fail_next_batch.store(true, Ordering::SeqCst);
        }
    }

    impl KvStore for FailingBatchDb {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(key)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put(key, value)
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.inner.delete(key)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
            if self.fail_next_batch.swap(false, Ordering::SeqCst) {
                return Err(StorageError::Database("injected batch failure".into()));
            }
            self.inner.write_batch(batch)
        }

        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            self.inner.scan_prefix(prefix)
        }
    }

    fn test_genesis() -> GenesisConfig {
        let mut alloc = HashMap::new();
        let addr1 = Address::ZERO;
        alloc.insert(
            addr1,
            AllocEntry {
                balance: U256::from(1_000_000u64),
                nonce: 0,
                code: None,
                storage: None,
            },
        );

        GenesisConfig {
            governance_fallback_keys: Default::default(),
            log_address_activation_height: None,
            algorithm_voting_window_activation_height: None,
            algorithm_proposal_identity_height: None,
            algorithm_deprecation_height: None,
            algorithm_session_deprecation_height: None,
            algorithm_paymaster_deprecation_height: None,
            algorithm_activation_admission_height: None,
            validation_pqvm_height: None,
            validation_deprecation_height: None,
            session_registered_root_height: None,
            paymaster_registered_root_height: None,
            registered_key_algorithm_height: None,
            aa_account_manager_height: None,
            aa_validator_registry_height: None,
            emergency_governance_height: None,
            native_registry_view_height: None,
            pq_address_bounds_height: None,
            native_address_context_height: None,
            native_validator_events_height: None,
            prover_registry_height: None,
            algorithm_proposal_staging_height: None,
            algorithm_quorum_activation_height: None,
            algorithm_timelock_activation_height: None,
            bloom_activation_height: None,
            fee_accounting_activation_height: None,
            chain_id: 1337,
            chain_name: "test-chain".to_string(),
            network_type: crate::config::NetworkType::Dev,
            timestamp: 1700000000,
            gas_limit: 30_000_000,
            extra_data: "genesis".to_string(),
            consensus: ConsensusConfig::PoA {
                authorities: vec![addr1],
                authority_pubkeys: vec!["0x1234".to_string()],
                block_time_secs: 1,
                max_future_secs: 60,
                epoch_length: 0,
            },
            economics: None,
            alloc,
            boot_nodes: vec![],
        }
    }

    #[test]
    fn bootstrap_restores_missing_trie_and_rejects_conflicting_nodes_atomically() {
        let mut config = test_genesis();
        if let crate::ConsensusConfig::PoA {
            authority_pubkeys, ..
        } = &mut config.consensus
        {
            authority_pubkeys.clear();
        }
        let store = Arc::new(MemoryDb::new());
        let genesis = initialize_genesis(&config, store.clone()).unwrap();
        let chain = ChainStore::new(store.clone());
        store
            .put(genesis.header.state_root.as_bytes(), b"corrupt")
            .unwrap();
        let before = store.scan_prefix(b"").unwrap();
        assert!(bootstrap_genesis_metadata(&config, &chain).is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        for (key, _) in before {
            if key.len() == 32 {
                store.delete(&key).unwrap();
            }
        }
        assert!(bootstrap_genesis_metadata(&config, &chain).unwrap());
        assert!(!bootstrap_genesis_metadata(&config, &chain).unwrap());
        let state = WorldState::at_root(store, &genesis.header.state_root).unwrap();
        for (address, entry) in &config.alloc {
            assert_eq!(state.get_balance(address).unwrap(), entry.balance);
        }
        assert_eq!(chain.get_head_hash().unwrap(), Some(genesis.hash()));
    }

    #[test]
    fn metadata_bootstrap_defers_checkpoint_only_history() {
        let config = test_genesis();
        let source = Arc::new(MemoryDb::new());
        initialize_genesis(&config, source.clone()).unwrap();
        let source = ChainStore::new(source);
        let store = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(store.clone());
        let mut identity = source.get_chain_config().unwrap().unwrap();
        chain.put_chain_config(&identity).unwrap();
        let before = store.scan_prefix(b"").unwrap();
        assert!(!bootstrap_genesis_metadata(&config, &chain).unwrap());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        identity.genesis_hash = ShellHash::ZERO;
        let store = Arc::new(MemoryDb::new());
        let chain = ChainStore::new(store.clone());
        chain.put_chain_config(&identity).unwrap();
        let before = store.scan_prefix(b"").unwrap();
        assert!(bootstrap_genesis_metadata(&config, &chain).is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
    }

    #[test]
    fn metadata_bootstrap_uses_genesis_not_live_keys() {
        use shell_crypto::{MlDsaSigner, Signer};
        let signer = MlDsaSigner::generate();
        let authority = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
        let mut config = test_genesis();
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            *authorities = vec![authority];
            *authority_pubkeys = vec![format!("0x{}", hex::encode(signer.public_key()))];
        }
        let store = Arc::new(MemoryDb::new());
        let genesis = initialize_genesis(&config, store.clone()).unwrap();
        let chain = ChainStore::new(store.clone());
        let mut later = genesis.clone();
        later.header.number = 1;
        later.header.parent_hash = genesis.hash();
        chain.commit_canonical_block(&later, None).unwrap();
        chain.put_pubkey(&authority, b"later-key").unwrap();
        let before = store.scan_prefix(b"").unwrap();
        let mut wrong = config.clone();
        wrong.chain_id += 1;
        assert!(bootstrap_genesis_metadata(&wrong, &chain).is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        let mut wrong = config.clone();
        wrong.timestamp += 1;
        assert!(bootstrap_genesis_metadata(&wrong, &chain).is_err());
        assert_eq!(store.scan_prefix(b"").unwrap(), before);
        assert!(bootstrap_genesis_metadata(&config, &chain).unwrap());
        assert!(!bootstrap_genesis_metadata(&config, &chain).unwrap());
        assert_eq!(chain.get_head_hash().unwrap(), Some(later.hash()));
        assert_eq!(
            chain.get_pubkey(&authority).unwrap(),
            Some(b"later-key".to_vec())
        );
        let isolated = ChainStore::new(Arc::new(shell_storage::OverlayStore::new(store)));
        assert!(isolated
            .restore_genesis_metadata_checkpoint(&genesis.hash())
            .unwrap());
        assert_eq!(
            isolated.get_pubkey(&authority).unwrap(),
            Some(signer.public_key().to_vec())
        );
    }

    #[test]
    fn genesis_block_is_block_zero() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, store).unwrap();

        assert_eq!(block.number(), 0);
        assert!(block.header.is_genesis());
        assert!(block.transactions.is_empty());
        assert!(block.proposer_seal.is_none());
    }

    #[test]
    fn genesis_state_root_is_nonzero() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, store).unwrap();

        assert_ne!(block.header.state_root, ShellHash::ZERO);
    }

    #[test]
    fn genesis_allocations_applied() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        // Re-open world state at the genesis state root
        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        let balance = ws.get_balance(&Address::ZERO).unwrap();
        assert_eq!(balance, U256::from(1_000_000u64));
    }

    #[test]
    fn genesis_deterministic() {
        let config = test_genesis();

        let store1 = Arc::new(MemoryDb::new());
        let block1 = initialize_genesis(&config, store1).unwrap();

        let store2 = Arc::new(MemoryDb::new());
        let block2 = initialize_genesis(&config, store2).unwrap();

        assert_eq!(block1.hash(), block2.hash());
        assert_eq!(block1.header.state_root, block2.header.state_root);
    }

    #[test]
    fn governance_keys_change_genesis_and_cannot_be_added_to_legacy_chain() {
        let mut config = test_genesis();
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            authority_pubkeys[0] = hex::encode([1; 1952]);
            authorities[0] =
                Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8());
        }
        let legacy_db = Arc::new(MemoryDb::new());
        let legacy = initialize_genesis(&config, Arc::clone(&legacy_db)).unwrap();
        config.emergency_governance_height = Some(0);
        config.governance_fallback_keys.insert(
            Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8()),
            hex::encode([2; 64]),
        );
        let cs = ChainStore::new(legacy_db);
        assert!(initialize_authority_pubkeys(&config, &cs).is_err());
        assert!(cs
            .get_pubkey(&Address::from_public_key(
                &[1; 1952],
                shell_crypto::SignatureType::MlDsa65.as_u8()
            ))
            .unwrap()
            .is_none());
        let new_db = Arc::new(MemoryDb::new());
        let upgraded = initialize_genesis(&config, Arc::clone(&new_db)).unwrap();
        assert_ne!(legacy.hash(), upgraded.hash());
        let new_cs = ChainStore::new(new_db);
        initialize_authority_pubkeys(&config, &new_cs).unwrap();
        config.governance_fallback_keys.clear();
        config.emergency_governance_height = None;
        assert!(initialize_authority_pubkeys(&config, &new_cs).is_err());
        assert_eq!(
            new_cs
                .get_governance_fallback_key(&Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8()
                ))
                .unwrap(),
            Some(vec![2; 64])
        );
    }

    #[test]
    fn governance_fallback_preserves_primary_and_rejects_replacement() {
        let mut config = test_genesis();
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            authority_pubkeys[0] = hex::encode([1; 1952]);
            authorities[0] =
                Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8());
        }
        config.emergency_governance_height = Some(0);
        config.governance_fallback_keys.insert(
            Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8()),
            hex::encode([2; 64]),
        );
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));
        initialize_authority_pubkeys(&config, &chain_store).unwrap();
        let reopened = ChainStore::new(store);
        assert_eq!(
            reopened
                .get_pubkey(&Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8()
                ))
                .unwrap(),
            Some(vec![1; 1952])
        );
        assert_eq!(
            reopened
                .get_governance_fallback_key(&Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8()
                ))
                .unwrap(),
            Some(vec![2; 64])
        );
        initialize_authority_pubkeys(&config, &reopened).unwrap();
        config.emergency_governance_height = Some(0);
        config.governance_fallback_keys.insert(
            Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8()),
            hex::encode([3; 64]),
        );
        assert!(initialize_authority_pubkeys(&config, &reopened).is_err());
        assert_eq!(
            reopened
                .get_governance_fallback_key(&Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8()
                ))
                .unwrap(),
            Some(vec![2; 64])
        );
    }

    #[test]
    fn invalid_governance_binding_writes_no_primary_keys() {
        for (address, bytes) in [
            (
                Address::from_public_key(&[1; 1952], shell_crypto::SignatureType::MlDsa65.as_u8()),
                vec![2; 63],
            ),
            (Address::from([3; 32]), vec![2; 64]),
        ] {
            let mut config = test_genesis();
            if let ConsensusConfig::PoA {
                authorities,
                authority_pubkeys,
                ..
            } = &mut config.consensus
            {
                authority_pubkeys[0] = hex::encode([1; 1952]);
                authorities[0] = Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8(),
                );
            }
            config.emergency_governance_height = Some(0);
            config
                .governance_fallback_keys
                .insert(address, hex::encode(bytes));
            let chain_store = ChainStore::new(Arc::new(MemoryDb::new()));
            assert!(initialize_authority_pubkeys(&config, &chain_store).is_err());
            assert!(chain_store
                .get_pubkey(&Address::from_public_key(
                    &[1; 1952],
                    shell_crypto::SignatureType::MlDsa65.as_u8()
                ))
                .unwrap()
                .is_none());
            assert!(chain_store
                .get_governance_fallback_key(&address)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn governance_genesis_requires_complete_ml_identity_bindings() {
        use shell_crypto::{MlDsaSigner, SignatureType, Signer, SphincsSigner};
        let mut config = test_genesis();
        let primary = MlDsaSigner::generate();
        let fallback = SphincsSigner::generate();
        let owner = Address::from_public_key(primary.public_key(), SignatureType::MlDsa65.as_u8());
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            *authorities = vec![owner];
            *authority_pubkeys = vec![hex::encode(primary.public_key())];
        }
        config.emergency_governance_height = Some(5);
        config
            .governance_fallback_keys
            .insert(owner, hex::encode(fallback.public_key()));
        let db = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, db.clone()).unwrap();
        let chain = ChainStore::new(db);
        initialize_authority_pubkeys(&config, &chain).unwrap();
        assert_eq!(
            chain.get_pubkey(&owner).unwrap().unwrap(),
            primary.public_key()
        );
        assert_eq!(
            chain.get_governance_fallback_key(&owner).unwrap().unwrap(),
            fallback.public_key()
        );
        assert!(block.header.extra_data.len() >= 44);
        let mut wrong = config.clone();
        if let ConsensusConfig::PoA { authorities, .. } = &mut wrong.consensus {
            authorities[0] = Address::ZERO;
        }
        wrong.governance_fallback_keys =
            [(Address::ZERO, hex::encode(fallback.public_key()))].into();
        assert!(wrong
            .governance_fallback_commitment()
            .unwrap_err()
            .to_string()
            .contains("authority address"));
        let second = MlDsaSigner::generate();
        let second_address =
            Address::from_public_key(second.public_key(), SignatureType::MlDsa65.as_u8());
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            authorities.push(second_address);
            authority_pubkeys.push(hex::encode(second.public_key()));
        }
        assert!(config
            .governance_fallback_commitment()
            .unwrap_err()
            .to_string()
            .contains("every genesis authority"));
        let fresh = Arc::new(MemoryDb::new());
        assert!(initialize_genesis(&config, fresh.clone()).is_err());
        assert!(ChainStore::new(fresh).get_head_block().unwrap().is_none());
        config
            .governance_fallback_keys
            .insert(second_address, hex::encode(fallback.public_key()));
        assert!(config
            .governance_fallback_commitment()
            .unwrap_err()
            .to_string()
            .contains("shared by multiple"));
    }

    #[test]
    fn authority_pubkeys_are_persisted() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));

        initialize_authority_pubkeys(&config, &chain_store).unwrap();

        let loaded = chain_store.get_pubkey(&Address::ZERO).unwrap().unwrap();
        assert_eq!(loaded, vec![0x12, 0x34]);
    }

    #[test]
    fn duplicate_authorities_are_rejected_before_genesis_commit() {
        let mut config = test_genesis();
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            authorities.push(authorities[0]);
            authority_pubkeys.push("0x5678".to_string());
        }

        let store = Arc::new(MemoryDb::new());
        let error = initialize_genesis(&config, Arc::clone(&store)).unwrap_err();
        assert!(error.to_string().contains("duplicate consensus authority"));

        let chain_store = ChainStore::new(store);
        assert!(chain_store.get_head_hash().unwrap().is_none());
        assert!(chain_store.get_chain_config().unwrap().is_none());
    }

    #[test]
    fn duplicate_authorities_are_rejected_before_pubkey_writes() {
        let mut config = test_genesis();
        if let ConsensusConfig::PoA {
            authorities,
            authority_pubkeys,
            ..
        } = &mut config.consensus
        {
            authorities.push(authorities[0]);
            authority_pubkeys.push("0x5678".to_string());
        }

        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));
        let error = initialize_authority_pubkeys(&config, &chain_store).unwrap_err();
        assert!(error.to_string().contains("duplicate consensus authority"));
        assert!(chain_store.get_pubkey(&Address::ZERO).unwrap().is_none());
    }

    #[test]
    fn genesis_with_contract_code() {
        let mut config = test_genesis();
        let contract_addr = Address::from_public_key(keccak256(b"contract").as_bytes(), 0);
        config.alloc.insert(
            contract_addr,
            AllocEntry {
                balance: U256::ZERO,
                nonce: 1,
                code: Some("0x6080604052".to_string()),
                storage: None,
            },
        );

        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let chain_store = ChainStore::new(Arc::clone(&store));
        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        let acct = ws.get_account(&contract_addr).unwrap().unwrap();
        assert!(acct.is_contract());
        assert_eq!(acct.nonce, 1);
        let code = hex::decode("6080604052").unwrap();
        assert_eq!(chain_store.get_code(&keccak256(&code)).unwrap(), Some(code));
    }

    #[test]
    fn genesis_with_storage() {
        let mut config = test_genesis();
        let addr = Address::from_public_key(keccak256(b"storage-test").as_bytes(), 0);

        let slot = keccak256(b"slot-0");
        let value = keccak256(b"value-0");
        let mut storage = HashMap::new();
        storage.insert(slot, value);

        config.alloc.insert(
            addr,
            AllocEntry {
                balance: U256::from(100u64),
                nonce: 0,
                code: None,
                storage: Some(storage),
            },
        );

        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        let stored = ws.get_storage(&addr, &slot).unwrap();
        assert_eq!(stored, value);
    }

    #[test]
    fn genesis_extra_data() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, store).unwrap();

        assert_eq!(
            block.header.extra_data.as_ref(),
            [TRANSACTION_ID_GENESIS_DOMAIN.as_slice(), b"genesis"].concat()
        );
    }

    #[test]
    fn genesis_persists_chain_config() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let chain_store = ChainStore::new(store);
        let chain_cfg = chain_store.get_chain_config().unwrap().unwrap();
        assert_eq!(chain_cfg.chain_id, 1337);
        assert_eq!(chain_cfg.genesis_hash, block.hash());
    }

    #[test]
    fn genesis_sets_head_and_canonical() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let chain_store = ChainStore::new(store);
        assert_eq!(chain_store.get_head_hash().unwrap().unwrap(), block.hash());
        let loaded = chain_store.get_block_by_number(0).unwrap().unwrap();
        assert_eq!(loaded.hash(), block.hash());
    }

    #[test]
    fn genesis_commit_is_atomic_on_batch_error() {
        let config = test_genesis();
        let expected_block = initialize_genesis(&config, Arc::new(MemoryDb::new())).unwrap();
        let store = Arc::new(FailingBatchDb::new());
        store.fail_next_batch();

        let err = initialize_genesis(&config, Arc::clone(&store)).unwrap_err();
        assert!(matches!(err, GenesisError::StateInit(_)));

        let chain_store = ChainStore::new(Arc::clone(&store));
        assert!(chain_store.get_head_hash().unwrap().is_none());
        assert!(chain_store
            .get_block_by_hash(&expected_block.hash())
            .unwrap()
            .is_none());
        assert!(chain_store.get_block_by_number(0).unwrap().is_none());
        assert!(chain_store.get_chain_config().unwrap().is_none());
    }

    #[test]
    fn genesis_writes_validators_to_world_state() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        let validators = ws.get_validators().unwrap();

        let expected = config.consensus.authorities().to_vec();
        assert_eq!(validators, expected);
    }

    #[test]
    fn wpoa_genesis_writes_validator_weights_to_world_state() {
        let v1 = Address::from([0x01; 32]);
        let v2 = Address::from([0x02; 32]);
        let config = GenesisConfig {
            governance_fallback_keys: Default::default(),
            consensus: ConsensusConfig::WPoA {
                authorities: vec![v1, v2],
                authority_pubkeys: vec![],
                block_time_secs: 1,
                max_future_secs: 60,
                epoch_length: 0,
                weights: vec![3, 0],
                stakes: vec![],
            },
            ..test_genesis()
        };
        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();

        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 3);
        assert_eq!(ws.get_validator_weight(&v2).unwrap(), 1);
    }

    #[test]
    fn staking_genesis_derives_weights_and_supply_from_locked_stake() {
        let v1 = Address::from([0x01; 32]);
        let v2 = Address::from([0x02; 32]);
        let faucet = Address::from([0xAA; 32]);
        let stake_unit = U256::from(1_000u64);
        let mut alloc = HashMap::new();
        alloc.insert(
            faucet,
            AllocEntry {
                balance: U256::from(500u64),
                nonce: 0,
                code: None,
                storage: None,
            },
        );
        let config = GenesisConfig {
            governance_fallback_keys: Default::default(),
            consensus: ConsensusConfig::WPoA {
                authorities: vec![v1, v2],
                authority_pubkeys: vec![],
                block_time_secs: 1,
                max_future_secs: 60,
                epoch_length: 0,
                weights: vec![],
                stakes: vec![U256::from(2_000u64), U256::from(1_000u64)],
            },
            economics: Some(crate::EconomicsConfig {
                staking_enabled: true,
                initial_supply: U256::from(3_500u64),
                stake_unit,
                min_validator_stake: stake_unit,
                max_validator_weight: 100,
            }),
            alloc,
            ..test_genesis()
        };

        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, Arc::clone(&store)).unwrap();
        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        assert!(ws.staking_enabled().unwrap());
        assert_eq!(ws.get_total_supply().unwrap(), U256::from(3_500u64));
        assert_eq!(ws.get_total_staked().unwrap(), U256::from(3_000u64));
        assert_eq!(ws.get_validator_stake(&v1).unwrap(), U256::from(2_000u64));
        assert_eq!(ws.get_validator_stake(&v2).unwrap(), U256::from(1_000u64));
        assert_eq!(ws.get_validator_weight(&v1).unwrap(), 2);
        assert_eq!(ws.get_validator_weight(&v2).unwrap(), 1);
    }

    #[test]
    fn staking_genesis_rejects_supply_mismatch() {
        let v1 = Address::from([0x01; 32]);
        let config = GenesisConfig {
            governance_fallback_keys: Default::default(),
            consensus: ConsensusConfig::WPoA {
                authorities: vec![v1],
                authority_pubkeys: vec![],
                block_time_secs: 1,
                max_future_secs: 60,
                epoch_length: 0,
                weights: vec![],
                stakes: vec![U256::from(1_000u64)],
            },
            economics: Some(crate::EconomicsConfig {
                staking_enabled: true,
                initial_supply: U256::from(999u64),
                stake_unit: U256::from(1_000u64),
                min_validator_stake: U256::from(1_000u64),
                max_validator_weight: 100,
            }),
            alloc: HashMap::new(),
            ..test_genesis()
        };

        let err = initialize_genesis(&config, Arc::new(MemoryDb::new())).unwrap_err();
        assert!(err.to_string().contains("genesis supply mismatch"));
    }

    #[test]
    fn wpoa_genesis_parses_and_initializes() {
        let json = r#"{
            "chain_id": 10,
            "chain_name": "shell-testnet-wpoa",
            "network_type": "Testnet",
            "timestamp": 1700000000,
            "gas_limit": 30000000,
            "extra_data": "",
            "consensus": {
                "engine": "wpoa",
                "authorities": [],
                "weights": [2, 1, 1],
                "block_time_secs": 2,
                "max_future_secs": 60,
                "epoch_length": 0
            },
            "alloc": {}
        }"#;
        let config = crate::GenesisConfig::from_json(json).unwrap();
        assert_eq!(config.chain_id, 10);
        assert!(matches!(config.consensus, ConsensusConfig::WPoA { .. }));
        assert_eq!(config.consensus.block_time_secs(), 2);

        let store = Arc::new(MemoryDb::new());
        let block = initialize_genesis(&config, store).unwrap();
        assert_eq!(block.number(), 0);
    }
}
