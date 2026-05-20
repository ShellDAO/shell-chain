use shell_core::{Account, Block, BlockHeader};
use shell_primitives::{keccak256, Address, Bytes, ShellHash};
use shell_storage::{ChainConfig, ChainStore, KvStore, StorageError, WorldState};

use crate::{AllocEntry, GenesisConfig, GenesisError};

/// Initialize world state from genesis allocations and produce the genesis block.
///
/// Persists the genesis block into `chain_store` and writes chain configuration
/// (chain_id + genesis_hash) so that later boot-up can verify chain identity.
pub fn initialize_genesis<S: KvStore + 'static>(
    config: &GenesisConfig,
    store: std::sync::Arc<S>,
) -> Result<Block, GenesisError> {
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
        world_state
            .set_validator_weights(&authorities, &config.consensus.authority_weights())
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
        extra_data: Bytes::copy_from_slice(config.extra_data.as_bytes()),
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
                chain_id: config.chain_id,
                genesis_hash,
            },
        )
        .map_err(|e| GenesisError::StateInit(e.to_string()))?;

    Ok(block)
}

/// Persist authority PQ public keys from genesis into the shared pubkey registry.
pub fn initialize_authority_pubkeys<S: KvStore + 'static>(
    config: &GenesisConfig,
    chain_store: &ChainStore<S>,
) -> Result<(), GenesisError> {
    let (authorities, authority_pubkeys) = (
        config.consensus.authorities(),
        config.consensus.authority_pubkeys(),
    );

    if authority_pubkeys.is_empty() {
        return Ok(());
    }

    if authority_pubkeys.len() != authorities.len() {
        return Err(GenesisError::Validation(format!(
            "authority_pubkeys length {} does not match authorities length {}",
            authority_pubkeys.len(),
            authorities.len()
        )));
    }

    for (address, pubkey_hex) in authorities.iter().zip(authority_pubkeys.iter()) {
        let pubkey = hex::decode(pubkey_hex.trim_start_matches("0x"))
            .map_err(|e| GenesisError::Validation(format!("invalid authority pubkey hex: {e}")))?;
        chain_store
            .put_pubkey(address, &pubkey)
            .map_err(|e| GenesisError::StateInit(e.to_string()))?;
    }

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
        account.code_hash = Some(keccak256(&code));
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
            alloc,
            boot_nodes: vec![],
        }
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
    fn authority_pubkeys_are_persisted() {
        let config = test_genesis();
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(Arc::clone(&store));

        initialize_authority_pubkeys(&config, &chain_store).unwrap();

        let loaded = chain_store.get_pubkey(&Address::ZERO).unwrap().unwrap();
        assert_eq!(loaded, vec![0x12, 0x34]);
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

        let ws = WorldState::at_root(store, &block.header.state_root).unwrap();
        let acct = ws.get_account(&contract_addr).unwrap().unwrap();
        assert!(acct.is_contract());
        assert_eq!(acct.nonce, 1);
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

        assert_eq!(block.header.extra_data.as_ref(), b"genesis");
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
            consensus: ConsensusConfig::WPoA {
                authorities: vec![v1, v2],
                authority_pubkeys: vec![],
                block_time_secs: 1,
                max_future_secs: 60,
                epoch_length: 0,
                weights: vec![3, 0],
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
