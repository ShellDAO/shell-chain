//! Read-only replay of public development quorum fixtures in a fresh process.
//! The caller independently trusts the fixture's authority configuration; this
//! entry is not a network importer or proof of historical registry provenance.
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use shell_consensus::{ConsensusEngine, PoaConfig, WPoaConfig, WPoaEngine};
use shell_crypto::MultiVerifier;
use shell_mempool::{MempoolConfig, TxPool};
use shell_node::{Node, NodeConfig};
use shell_stark_prover::commit_quorum::{
    prove_commit_quorum_persistent, verify_commit_quorum, CommitQuorumSource,
};
use shell_storage::{ChainStore, KvStore, MemoryDb, WorldState};
use std::{collections::HashMap, error::Error, io::Read, path::Path, sync::Arc};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn read<T: DeserializeOwned>(root: &Path, name: &str) -> Result<T, Box<dyn Error>> {
    let file = std::fs::File::open(root.join(name))?;
    if file.metadata()?.len() > 512 * 1024 * 1024 {
        return Err("public fixture exceeds development artifact bound".into());
    }
    let mut reader = std::io::BufReader::new(file);
    let value = ciborium::de::from_reader(&mut reader)?;
    let mut extra = [0];
    if reader.read(&mut extra)? != 0 {
        return Err("trailing public fixture bytes".into());
    }
    Ok(value)
}
fn restore(rows: &Rows) -> Result<MemoryDb, Box<dyn Error>> {
    let store = MemoryDb::new();
    for (key, value) in rows {
        if store.get(key)?.is_some() {
            return Err("duplicate fixture database key".into());
        }
        store.put(key, value)?;
    }
    Ok(store)
}
/// Compare deterministic serialization without allocating another full proof.
struct Compare(std::io::BufReader<std::fs::File>);
impl std::io::Write for Compare {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0;
        let mut expected = [0; 8192];
        while offset < bytes.len() {
            let count = (bytes.len() - offset).min(expected.len());
            self.0.read_exact(&mut expected[..count])?;
            if expected[..count] != bytes[offset..offset + count] {
                return Err(std::io::Error::other("cold proof output differs"));
            }
            offset += count;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: commit-quorum-cold <trusted-public-fixture-directory>".into());
    }
    let root = Path::new(&args[0]);
    let source: CommitQuorumSource = read(root, "source.cbor")?;
    let rows: Rows = read(root, "job-complete.cbor")?;
    let mut job = restore(&rows)?;
    let (proof, progress) = prove_commit_quorum_persistent(&mut job, &source, None)?;
    if progress.newly_proved != 0
        || progress.reused != progress.components
        || job.scan_all()? != rows
    {
        return Err(
            "cold job must reverify every original component without new work or writes".into(),
        );
    }
    let mut compare = Compare(std::io::BufReader::new(std::fs::File::open(
        root.join("proof.cbor"),
    )?));
    ciborium::ser::into_writer(&proof, &mut compare)?;
    if compare.0.read(&mut [0])? != 0 {
        return Err("original proof has trailing bytes".into());
    }
    verify_commit_quorum(&proof, &source)?;
    let native_rows: Rows = read(root, "native-before.cbor")?;
    let store = Arc::new(restore(&native_rows)?);
    let chain = Arc::new(ChainStore::new(store.clone()));
    let addresses = source
        .context
        .authorities
        .iter()
        .map(|a| a.address)
        .collect();
    let weights = source
        .context
        .authorities
        .iter()
        .map(|a| a.weight)
        .collect();
    let engine = WPoaEngine::new(
        WPoaConfig::with_weights(PoaConfig::new(addresses, 1), weights),
        Arc::new(MultiVerifier),
    );
    let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(engine));
    let mut config = NodeConfig::dev(
        source
            .signatures
            .first()
            .ok_or("no expected signers")?
            .address,
    );
    config.chain_id = source.context.chain_id;
    let node = Node::new(
        config,
        store.clone(),
        chain.clone(),
        Arc::new(RwLock::new(WorldState::new(store.clone()))),
        Arc::new(TxPool::new(MempoolConfig {
            chain_id: source.context.chain_id,
            ..Default::default()
        })),
        consensus,
    );
    for entry in &source.signatures {
        node.register_authority_pubkey(entry.address, entry.public_key.clone());
    }
    let cert = Node::<MemoryDb>::encode_commit_certificate(
        &source
            .signatures
            .iter()
            .map(|e| (e.address, e.signature.clone()))
            .collect::<HashMap<_, _>>(),
    )?;
    let context = &source.context;
    if node.commit_quorum_source(context.block_number, context.block_hash, &cert)? != source
        || store.scan_all()? != native_rows
    {
        return Err("restored Native context differs before finality".into());
    }
    if !node.fast_finalize_with_certificate_proof(
        context.block_number,
        context.block_hash,
        &cert,
        &proof,
    ) || chain.get_finalized_number()? != Some(context.block_number)
        || chain.get_commit_certificate(&context.block_hash)? != Some(cert)
        || chain.get_block_signers(&context.block_hash)? != source.signatures
        || store.scan_all()? != read::<Rows>(root, "native-finalized.cbor")?
    {
        return Err("cold Native finality differs from original control".into());
    }
    println!(
        "{}",
        serde_json::json!({"fullSignatureAndWeightAirVerified":true,"originalProofBytesEqual":true,"jobUnchanged":true,"nativeRowsMatchOriginalFinality":true,"finalized":context.block_number,"progress":progress,"networkAuthorization":false,"rocksdbRecoveryVerified":false})
    );
    Ok(())
}
