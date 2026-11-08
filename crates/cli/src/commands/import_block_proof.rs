//! Offline canonical extension with complete registered sender proofs.
use std::{error::Error, path::PathBuf};

#[cfg(any(feature = "rocksdb", test))]
fn bounded_file(path: &std::path::Path, limit: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("proof import input must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit.checked_add(1).ok_or("input size overflow")?)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("proof import input size limit".into());
    }
    Ok(bytes)
}

pub fn import_block_proof(
    datadir: PathBuf,
    block: PathBuf,
    proof: PathBuf,
    manifest: PathBuf,
    consensus: PathBuf,
    parent: String,
) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "rocksdb")]
    {
        use shell_consensus::{PoaConfig, WPoaConfig};
        use shell_genesis::ConsensusConfig;
        use shell_node::{builder::NodeBuilder, ConsensusEngineConfig, NodeConfig, NodeRole};
        use shell_primitives::{blake3_hash, Address, ShellHash};
        let parent = ShellHash::try_from_slice(&hex::decode(parent.trim_start_matches("0x"))?)?;
        use shell_storage::{CanonicalProofManifest, ChainStore, KvStore, RocksDbStore};
        use std::sync::Arc;
        let candidate: shell_core::Block =
            serde_json::from_slice(&bounded_file(&block, 2 * 1024 * 1024)?)?;
        let manifest: CanonicalProofManifest =
            serde_json::from_slice(&bounded_file(&manifest, 64 * 1024)?)?;
        manifest.validate()?;
        if manifest.block_hash != candidate.hash() || candidate.header.parent_hash != parent {
            return Err("proof import manifest/block/parent identity mismatch".into());
        }
        let bytes = bounded_file(&proof, manifest.total_bytes)?;
        if bytes.len() as u64 != manifest.total_bytes
            || blake3_hash(&bytes) != manifest.payload_hash
        {
            return Err("proof import payload size/hash mismatch".into());
        }
        let proof = shell_stark_prover::compact_canonical::decode_payload(&bytes)?;
        drop(bytes);
        let consensus: ConsensusConfig =
            serde_json::from_slice(&bounded_file(&consensus, 64 * 1024)?)?;
        let authorities = consensus.authorities();
        if authorities.is_empty()
            || authorities.len() > 256
            || authorities
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != authorities.len()
            || consensus.block_time_secs() == 0
            || consensus
                .authority_stakes()
                .iter()
                .any(|stake| !stake.is_zero())
        {
            return Err("proof import requires explicit consensus authorities, block time and weights, without stake-derived bootstrap parameters".into());
        }
        let db = datadir.join("db");
        if !db.join("CURRENT").is_file() {
            return Err(
                "proof import requires an existing initialized RocksDB; stop the node first".into(),
            );
        }
        // RocksDB holds its native exclusive ownership lock through verification,
        // execution, atomic commit and flush. No network or background node runs.
        let stores = RocksDbStore::open_all(&db, None)?;
        let store = Arc::new(stores.state);
        let chain = ChainStore::new(store.clone());
        let cfg = chain
            .get_chain_config()?
            .ok_or("proof import trusted chain config unavailable")?;
        if cfg.chain_id != manifest.chain_id
            || cfg.genesis_hash != manifest.genesis_hash
            || chain.get_head_hash()? != Some(parent)
        {
            return Err("proof import local chain/genesis/current parent mismatch".into());
        }
        let public_keys = consensus.authority_pubkeys();
        if !public_keys.is_empty() {
            if public_keys.len() != authorities.len() {
                return Err("consensus public key count mismatch".into());
            }
            for (authority, key) in authorities.iter().zip(public_keys) {
                let key = hex::decode(key.trim_start_matches("0x"))?;
                if chain.get_pubkey(authority)?.as_ref() != Some(&key) {
                    return Err("consensus key differs from trusted local registry".into());
                }
            }
        }
        let poa = PoaConfig::new(authorities.to_vec(), consensus.block_time_secs())
            .with_max_future_secs(consensus.max_future_secs())
            .with_epoch_length(consensus.epoch_length());
        let mut config = NodeConfig::dev(Address::ZERO);
        config.chain_id = cfg.chain_id;
        config.mempool.chain_id = cfg.chain_id;
        config.node_role = NodeRole::Prover;
        config.proposer_address = None;
        config.rpc_enabled = false;
        config.enable_stark_aggregation = false;
        config.consensus = match &consensus {
            ConsensusConfig::PoA { .. } => ConsensusEngineConfig::Poa(poa),
            ConsensusConfig::WPoA { .. } => {
                let mut wpoa = WPoaConfig::with_weights(poa, consensus.authority_weights());
                wpoa.chain_id = cfg.chain_id;
                ConsensusEngineConfig::WPoa(wpoa)
            }
        };
        let (mut node, store) = NodeBuilder::new(config, store).build()?;
        let result = node.import_block_with_canonical_proof(parent, candidate, &proof)?;
        store.flush()?;
        println!("{}", serde_json::to_string(&result)?);
        Ok(())
    }
    #[cfg(not(feature = "rocksdb"))]
    {
        let _ = (datadir, block, proof, manifest, consensus, parent);
        Err("RocksDB support not compiled. Rebuild with: cargo build -p shell-cli --features rocksdb".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_inputs_reject_oversize_and_nonfiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.json");
        std::fs::write(&path, b"12345").unwrap();
        assert!(bounded_file(&path, 4).is_err());
        assert_eq!(bounded_file(&path, 5).unwrap(), b"12345");
        assert!(bounded_file(dir.path(), 8).is_err());
    }
}
