//! Ergonomic node builder for assembling shell-chain components.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::ConsensusEngineConfig;
use shell_consensus::{ConsensusEngine, PoaEngine, WPoaEngine};
use shell_mempool::TxPool;
use shell_storage::{ChainStore, KvStore, MemoryDb, WorldState};

use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::node::Node;
use crate::pruning::state_trie_pruned_below;

/// Builder for constructing a `Node` with all required components.
///
/// # Example (dev mode with in-memory storage)
/// ```ignore
/// let node = NodeBuilder::new(NodeConfig::dev(authority))
///     .with_memory_storage()
///     .build()?;
/// ```
pub struct NodeBuilder<S: KvStore + 'static> {
    config: NodeConfig,
    store: Option<Arc<S>>,
}

impl NodeBuilder<MemoryDb> {
    /// Create a builder for an in-memory dev node.
    pub fn new_dev(config: NodeConfig) -> NodeBuilder<MemoryDb> {
        let db = Arc::new(MemoryDb::new());
        NodeBuilder {
            config,
            store: Some(db),
        }
    }
}

impl<S: KvStore + 'static> NodeBuilder<S> {
    /// Create a builder with a custom KvStore backend.
    pub fn new(config: NodeConfig, store: Arc<S>) -> Self {
        Self {
            config,
            store: Some(store),
        }
    }

    /// Build the node, wiring all components together.
    ///
    /// Automatically detects whether the chain has been initialized:
    /// if a head block exists, WorldState resumes from its state root;
    /// otherwise, WorldState starts empty (pre-genesis).
    ///
    /// Returns an error rather than starting with empty state when persisted
    /// chain data cannot be read or validated.
    pub fn build(mut self) -> Result<(Node<S>, Arc<S>), NodeError> {
        let store = self.store.take().expect("store must be set");

        let chain_store = Arc::new(ChainStore::new(store.clone()));
        let finalized_number = chain_store.get_finalized_number()?;
        let head = chain_store.get_head_block()?;
        let body_pruned_below = chain_store.body_pruned_below()?;
        let witness_pruned_below = chain_store.witness_pruned_below()?;
        let state_trie_pruned_below = state_trie_pruned_below(store.as_ref())?;

        // Finality is a durable safety boundary. Validate it before constructing
        // volatile state so malformed metadata cannot be downgraded to genesis.
        if let Some(finalized_number) = finalized_number {
            let head = head.as_ref().ok_or_else(|| {
                NodeError::Startup(format!(
                    "finalized block #{finalized_number} exists without a canonical head"
                ))
            })?;
            if finalized_number > head.number() {
                return Err(NodeError::Startup(format!(
                    "finalized block #{finalized_number} is ahead of canonical head #{}",
                    head.number()
                )));
            }
            chain_store
                .get_block_hash_by_number(finalized_number)?
                .ok_or_else(|| {
                    NodeError::Startup(format!(
                        "canonical mapping for finalized block #{finalized_number} is missing"
                    ))
                })?;
        }
        let finalized_number = finalized_number.unwrap_or(0);
        for (label, pruned_below) in [
            ("body", body_pruned_below),
            ("witness", witness_pruned_below),
            ("state-trie", state_trie_pruned_below),
        ] {
            if pruned_below > finalized_number {
                return Err(NodeError::Startup(format!(
                    "{label} pruning cursor {pruned_below} is ahead of finalized block #{finalized_number}"
                )));
            }
        }

        let cache_mb = self.config.state_cache_size_mb;

        // Resume from existing chain state if available.
        let world_state = match head {
            Some(head) => {
                let state_root = head.header.state_root;
                let block_number = head.number();
                let mut ws = WorldState::at_root_with_cache_mb(store.clone(), &state_root, cache_mb)
                    .map_err(|error| {
                        NodeError::Startup(format!(
                            "failed to open world state at head #{block_number} ({state_root}): {error}"
                        ))
                    })?;
                ws.validate().map_err(|error| {
                    NodeError::Startup(format!(
                        "world state validation failed at head #{block_number} ({state_root}): {error}"
                    ))
                })?;
                Arc::new(RwLock::new(ws))
            }
            None => Arc::new(RwLock::new(WorldState::new_with_cache_mb(
                store.clone(),
                cache_mb,
            ))),
        };

        let consensus: Arc<RwLock<dyn ConsensusEngine>> = match &self.config.consensus {
            ConsensusEngineConfig::Poa(poa_cfg) => {
                Arc::new(RwLock::new(PoaEngine::new(poa_cfg.clone())))
            }
            ConsensusEngineConfig::WPoa(wpoa_cfg) => Arc::new(RwLock::new(WPoaEngine::new(
                wpoa_cfg.clone(),
                Arc::new(shell_crypto::MultiVerifier),
            ))),
        };
        let tx_pool = Arc::new(TxPool::new(self.config.mempool.clone()));

        let node = Node::new(
            self.config,
            store.clone(),
            chain_store,
            world_state,
            tx_pool,
            consensus,
        );

        Ok((node, store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Block, BlockHeader};
    use shell_primitives::{Address, ShellHash};
    use shell_storage::{StorageError, WriteBatch};

    struct FailingReadStore;

    impl KvStore for FailingReadStore {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::Database("injected read failure".into()))
        }

        fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn delete(&self, _key: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn flush(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn write_batch(&self, _batch: WriteBatch) -> Result<(), StorageError> {
            Ok(())
        }

        fn scan_prefix(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn build_dev_node() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let (node, _store) = NodeBuilder::new_dev(config).build().unwrap();

        assert_eq!(node.config.chain_id, 1337);
        assert_eq!(node.tx_pool.len(), 0);
    }

    #[test]
    fn build_propagates_head_read_failure() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);

        let result = NodeBuilder::new(config, Arc::new(FailingReadStore)).build();
        let err = match result {
            Ok(_) => panic!("node build unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(matches!(err, NodeError::Storage(StorageError::Database(_))));
    }

    #[test]
    fn build_rejects_missing_head_state_root() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store.clone());
        let block = Block {
            header: BlockHeader {
                state_root: ShellHash::from([0x42; 32]),
                ..BlockHeader::default()
            },
            transactions: Vec::new(),
            system_transactions: Vec::new(),
            proposer_seal: None,
        };
        let block_hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_head(&block_hash).unwrap();

        let result = NodeBuilder::new(config, store).build();
        let err = match result {
            Ok(_) => panic!("node build unexpectedly succeeded"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            NodeError::Startup(message) if message.contains("world state validation failed")
        ));
    }

    #[test]
    fn build_rejects_malformed_finalized_number() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let store = Arc::new(MemoryDb::new());
        store.put(b"FINALIZED", &[0; 7]).unwrap();

        let result = NodeBuilder::new(config, store).build();

        assert!(matches!(
            result,
            Err(NodeError::Storage(StorageError::Codec(message)))
                if message.contains("invalid finalized number encoding")
        ));
    }

    #[test]
    fn build_rejects_malformed_pruning_cursor() {
        for (key, label) in [
            (b"BODY_PRUNED_BELOW".as_slice(), "body"),
            (b"WITNESS_PRUNED_BELOW".as_slice(), "witness"),
            (b"STATE_TRIE_PRUNED_BELOW".as_slice(), "state-trie"),
        ] {
            let authority = Address::from_public_key(b"test-authority", 0);
            let config = NodeConfig::dev(authority);
            let store = Arc::new(MemoryDb::new());
            store.put(key, &[0; 7]).unwrap();

            let result = NodeBuilder::new(config, store).build();

            assert!(matches!(
                result,
                Err(NodeError::Storage(StorageError::Codec(message)))
                    if message.contains(&format!("invalid {label} pruning cursor encoding"))
            ));
        }
    }

    #[test]
    fn build_rejects_pruning_cursor_ahead_of_finality() {
        for (key, label) in [
            (b"BODY_PRUNED_BELOW".as_slice(), "body"),
            (b"WITNESS_PRUNED_BELOW".as_slice(), "witness"),
            (b"STATE_TRIE_PRUNED_BELOW".as_slice(), "state-trie"),
        ] {
            let authority = Address::from_public_key(b"test-authority", 0);
            let config = NodeConfig::dev(authority);
            let store = Arc::new(MemoryDb::new());
            store.put(key, &1u64.to_be_bytes()).unwrap();

            let result = NodeBuilder::new(config, store).build();

            assert!(matches!(
                result,
                Err(NodeError::Startup(message))
                    if message.contains(&format!(
                        "{label} pruning cursor 1 is ahead of finalized block #0"
                    ))
            ));
        }
    }

    #[test]
    fn build_rejects_finalized_height_without_head() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store.clone());
        chain_store.set_finalized_number(0).unwrap();

        let result = NodeBuilder::new(config, store).build();

        assert!(matches!(
            result,
            Err(NodeError::Startup(message))
                if message.contains("finalized block #0 exists without a canonical head")
        ));
    }

    #[test]
    fn build_rejects_finalized_height_without_canonical_mapping() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store.clone());
        let block = Block {
            header: BlockHeader::default(),
            transactions: Vec::new(),
            system_transactions: Vec::new(),
            proposer_seal: None,
        };
        let block_hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_head(&block_hash).unwrap();
        chain_store.set_finalized_number(0).unwrap();

        let result = NodeBuilder::new(config, store).build();

        assert!(matches!(
            result,
            Err(NodeError::Startup(message))
                if message.contains("canonical mapping for finalized block #0 is missing")
        ));
    }

    #[test]
    fn build_rejects_finalized_height_ahead_of_head() {
        let authority = Address::from_public_key(b"test-authority", 0);
        let config = NodeConfig::dev(authority);
        let store = Arc::new(MemoryDb::new());
        let chain_store = ChainStore::new(store.clone());
        let block = Block {
            header: BlockHeader::default(),
            transactions: Vec::new(),
            system_transactions: Vec::new(),
            proposer_seal: None,
        };
        let block_hash = block.hash();
        chain_store.put_block(&block).unwrap();
        chain_store.set_head(&block_hash).unwrap();
        chain_store.set_finalized_number(1).unwrap();

        let result = NodeBuilder::new(config, store).build();

        assert!(matches!(
            result,
            Err(NodeError::Startup(message))
                if message.contains("finalized block #1 is ahead of canonical head #0")
        ));
    }
}
