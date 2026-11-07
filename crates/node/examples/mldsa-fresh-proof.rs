//! Prepare and independently inspect an actual offline CLI proof import.
#[allow(dead_code)]
#[path = "common/canonical_proof_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../../stark-prover/examples/common/mldsa_source.rs"]
mod source;
use fixture::Context;
use serde_json::{json, Value};
use shell_consensus::{PoaConfig, WPoaConfig};
use shell_core::Block;
use shell_node::{
    builder::NodeBuilder, CanonicalProofReplay, ConsensusEngineConfig, Node, NodeConfig, NodeRole,
};
use shell_primitives::{blake3_hash, keccak256, Address, ShellHash};
use shell_storage::{ChainStore, KvStore, RocksDbStore, StorageError, WorldState, WriteBatch};
use source::{read, write, Error};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn node<S: KvStore + 'static>(store: Arc<S>, c: &Context) -> Result<Node<S>, Error> {
    let mut cfg = NodeConfig::dev(Address::ZERO);
    cfg.chain_id = 10;
    cfg.mempool.chain_id = 10;
    cfg.proposer_address = None;
    cfg.rpc_enabled = false;
    cfg.node_role = NodeRole::Prover;
    cfg.enable_stark_aggregation = false;
    let mut consensus = WPoaConfig::from_poa(PoaConfig::new(vec![c.authority], 1));
    consensus.chain_id = 10;
    cfg.consensus = ConsensusEngineConfig::WPoa(consensus);
    Ok(NodeBuilder::new(cfg, store).build()?.0)
}
fn digest<S: KvStore>(s: &S) -> Result<ShellHash, Error> {
    Ok(blake3_hash(&serde_json::to_vec(&s.scan_all()?)?))
}
fn accounts<S: KvStore + 'static>(
    s: Arc<S>,
    block: &Block,
    authority: Address,
) -> Result<Value, Error> {
    let world = WorldState::at_root(s, &block.header.state_root)?;
    let mut addresses = vec![authority];
    for tx in &block.transactions {
        addresses.push(tx.from);
        if let Some(to) = tx.tx.to {
            addresses.push(to);
        }
    }
    addresses.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    addresses.dedup();
    let mut rows = Vec::new();
    for address in addresses {
        rows.push(json!({"address":address,"nonce":world.get_nonce(&address)?,"balance":world.get_balance(&address)?}));
    }
    Ok(json!(rows))
}
fn prepare(native: &Path, cache: &Path, out: &Path) -> Result<(), Error> {
    ensure(!out.exists(), "output exists; retain it and use verify")?;
    let c: Context = read(&native.join("context.json"))?;
    let original = RocksDbStore::open_all(native.join("native-db"), None)?;
    let before = digest(&original.state)?;
    let chain = ChainStore::new(Arc::new(original.state.clone()));
    let candidate = chain
        .get_block_by_hash(&c.block)?
        .ok_or("native candidate missing")?;
    let genesis = chain
        .get_block_by_hash(&candidate.header.parent_hash)?
        .ok_or("parent missing")?;
    ensure(
        genesis.number() == 0 && candidate.transactions.len() == 2,
        "requires original two-sender first block fixture",
    )?;
    let view = chain.canonical_parent_view(c.tip, genesis.hash())?;
    std::fs::create_dir(out)?;
    for role in ["follower", "rollback"] {
        let target = RocksDbStore::open_all(out.join(role).join("db"), None)?;
        for (key, value) in original.state.scan_all()? {
            if key.len() == 32 && keccak256(&value).as_bytes().as_slice() == key {
                target.state.put(&key, &value)?;
            }
        }
        let dest = ChainStore::new(Arc::new(target.state.clone()));
        for tx in &candidate.transactions {
            let key = view
                .registered_key(&tx.from)?
                .ok_or("parent sender key missing")?;
            dest.put_pubkey(&tx.from, &key)?;
        }
        dest.put_pubkey(&c.authority, &c.authority_key)?;
        dest.commit_genesis_block(&genesis, view.config())?;
        ensure(
            dest.get_header_by_hash(&candidate.hash())?.is_none()
                && dest.get_block_hash_by_number(1)?.is_none(),
            "candidate already present before import",
        )?;
        target.state.flush()?;
        write(
            &out.join(format!("{role}-before.json")),
            &json!({"digest":digest(&target.state)?,"head":genesis.hash(),"accounts":accounts(Arc::new(target.state.clone()),&genesis,c.authority)?}),
        )?;
    }
    let saved: Value = read(&cache.join("rpc-result.json"))?;
    let manifest = saved["valid"]["manifest"].clone();
    write(&out.join("manifest.json"), &manifest)?;
    let corrupt = std::fs::read(cache.join("corrupt-payload.json"))?;
    let mut bad = manifest.clone();
    bad["totalBytes"] = json!(corrupt.len());
    bad["payloadHash"] = json!(blake3_hash(&corrupt));
    write(&out.join("bad-air-manifest.json"), &bad)?;
    let mut wrong = manifest.clone();
    wrong["payloadHash"] = json!(ShellHash::ZERO);
    write(&out.join("wrong-hash-manifest.json"), &wrong)?;
    let mut wrong = manifest.clone();
    wrong["chainId"] = json!(11);
    write(&out.join("wrong-chain-manifest.json"), &wrong)?;
    write(&out.join("candidate.json"), &candidate)?;
    let mut bad_seal = candidate.clone();
    bad_seal.proposer_seal.as_mut().ok_or("seal absent")?.data[0] ^= 1;
    write(&out.join("bad-seal-candidate.json"), &bad_seal)?;
    let mut bad_body = candidate.clone();
    bad_body.transactions.swap(0, 1);
    write(&out.join("bad-body-candidate.json"), &bad_body)?;
    write(
        &out.join("consensus.json"),
        &json!({"engine":"wpoa","authorities":[c.authority],"authority_pubkeys":[hex::encode(&c.authority_key)],"block_time_secs":1,"weights":[1]}),
    )?;
    write(&out.join("context.json"), &c)?;
    write(
        &out.join("expected.json"),
        &json!({"native":read::<CanonicalProofReplay>(&native.join("result.json"))?,"accounts":accounts(Arc::new(original.state.clone()),&candidate,c.authority)?,"parent":genesis.hash(),"block":candidate.hash()}),
    )?;
    ensure(
        digest(&original.state)? == before,
        "original native source changed",
    )?;
    Ok(())
}
struct FailCommit {
    inner: RocksDbStore,
    hit: AtomicBool,
}
impl KvStore for FailCommit {
    fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(k)
    }
    fn put(&self, k: &[u8], v: &[u8]) -> Result<(), StorageError> {
        self.inner.put(k, v)
    }
    fn delete(&self, k: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(k)
    }
    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }
    fn scan_prefix(&self, p: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.inner.scan_prefix(p)
    }
    fn snapshot_prefixes(
        &self,
        p: &[&[u8]],
        max: usize,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StorageError> {
        self.inner.snapshot_prefixes(p, max)
    }
    fn write_batch(&self, b: WriteBatch) -> Result<(), StorageError> {
        ensure_head_batch(&b)?;
        self.hit.store(true, Ordering::SeqCst);
        Err(StorageError::Database(
            "injected canonical commit failure".into(),
        ))
    }
}
fn ensure_head_batch(b: &WriteBatch) -> Result<(), StorageError> {
    if b.ops()
        .iter()
        .any(|op| matches!(op,shell_storage::WriteBatchOp::Put{key,..}if key==b"HEAD"))
    {
        Ok(())
    } else {
        Err(StorageError::Database(
            "unexpected earlier base write".into(),
        ))
    }
}
fn rollback(cache: &Path, out: &Path) -> Result<(), Error> {
    let c: Context = read(&out.join("context.json"))?;
    let candidate: Block = read(&out.join("candidate.json"))?;
    let proof = read(&cache.join("payload.json"))?;
    let stores = RocksDbStore::open_all(out.join("rollback/db"), None)?;
    let store = Arc::new(FailCommit {
        inner: stores.state,
        hit: AtomicBool::new(false),
    });
    let before = digest(store.as_ref())?;
    let registry = shell_crypto::AlgorithmRegistry::global().clone();
    let mut node = node(store.clone(), &c)?;
    let root = node.world_state.write().state_root()?;
    let error = node
        .import_block_with_canonical_proof(candidate.header.parent_hash, candidate, &proof)
        .unwrap_err()
        .to_string();
    ensure(
        error.contains("injected canonical commit failure") && store.hit.load(Ordering::SeqCst),
        &format!("did not reach canonical commit: {error}"),
    )?;
    ensure(
        digest(store.as_ref())? == before
            && node.world_state.write().state_root()? == root
            && *shell_crypto::AlgorithmRegistry::global() == registry,
        "failed commit changed native KV/world/registry",
    )?;
    write(
        &out.join("rollback-result.json"),
        &json!({"full_graph_verified_then_native_commit_refused":true,"canonical_KV_world_and_global_policy_unchanged":true,"error":error}),
    )?;
    Ok(())
}
fn snapshot(out: &Path) -> Result<Value, Error> {
    let stores = RocksDbStore::open_all(out.join("follower/db"), None)?;
    let chain = ChainStore::new(Arc::new(stores.state.clone()));
    Ok(json!({"digest":digest(&stores.state)?,"head":chain.get_head_hash()?}))
}
fn verify(cache: &Path, out: &Path) -> Result<(), Error> {
    let c: Context = read(&out.join("context.json"))?;
    let candidate: Block = read(&out.join("candidate.json"))?;
    let expected: Value = read(&out.join("expected.json"))?;
    let proof = read(&cache.join("payload.json"))?;
    let stores = RocksDbStore::open_all(out.join("follower/db"), None)?;
    let before = digest(&stores.state)?;
    let node = node(Arc::new(stores.state.clone()), &c)?;
    ensure(
        node.chain_store.get_head_hash()? == Some(candidate.hash()),
        "fresh canonical head not persisted",
    )?;
    let actual =
        node.replay_canonical_transactions_with_proof(candidate.hash(), candidate.hash(), &proof)?;
    let mut normalized = serde_json::to_value(&actual)?;
    normalized["tip"] = expected["native"]["tip"].clone();
    ensure(
        normalized == expected["native"],
        "cold proof-backed execution differs from native control",
    )?;
    ensure(
        accounts(Arc::new(stores.state.clone()), &candidate, c.authority)? == expected["accounts"],
        "persisted sender/recipient/reward accounts differ",
    )?;
    ensure(
        node.chain_store
            .get_block_by_hash(&candidate.hash())?
            .as_ref()
            == Some(&candidate),
        "candidate body not persisted",
    )?;
    ensure(
        node.chain_store.get_receipts(&candidate.hash())?.as_ref() == Some(&actual.receipts),
        "receipts not persisted",
    )?;
    ensure(
        digest(&stores.state)? == before,
        "cold proof recheck wrote native KV",
    )?;
    let mut receipt = out.join("cold-result.json");
    let mut index = 2;
    while receipt.try_exists()? {
        receipt = out.join(format!("cold-result-{index}.json"));
        index += 1;
    }
    write(
        &receipt,
        &json!({"actual":actual,"canonical_KV_unchanged":true,"reopened_body_receipts_and_accounts_match_native":true}),
    )?;
    Ok(())
}
fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(args.len()==4,"usage: mldsa-fresh-proof prepare|rollback|snapshot|verify native-fixture rpc-fixture output")?;
    let native = Path::new(&args[1]).canonicalize()?;
    let cache = Path::new(&args[2]).canonicalize()?;
    let raw = Path::new(&args[3]);
    let out = if raw.try_exists()? {
        raw.canonicalize()?
    } else {
        raw.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()?
            .join(raw.file_name().ok_or("output name missing")?)
    };
    ensure(
        !out.starts_with(&native)
            && !out.starts_with(&cache)
            && !native.starts_with(&out)
            && !cache.starts_with(&out),
        "output overlaps source fixture",
    )?;
    match args[0].as_str() {
        "prepare" => prepare(&native, &cache, &out),
        "rollback" => rollback(&cache, &out),
        "snapshot" => {
            println!("{}", snapshot(&out)?);
            Ok(())
        }
        "hold" => {
            use std::io::Write;
            let _stores = RocksDbStore::open_all(out.join("follower/db"), None)?;
            println!("locked");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(())
        }
        "verify" => verify(&cache, &out),
        _ => Err("unknown mode".into()),
    }
}
