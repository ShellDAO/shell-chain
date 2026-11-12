use crate::source::Error;
use http_body_util::BodyExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shell_consensus::{ConsensusEngine, PoaConfig, WPoaConfig, WPoaEngine};
use shell_crypto::MultiVerifier;
use shell_mempool::TxPool;
use shell_node::{Node, NodeConfig};
use shell_primitives::{Address, ShellHash};
use shell_storage::{ChainStore, KvStore, WorldState};
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) version: u8,
    pub(crate) authority: Address,
    pub(crate) authority_key: Vec<u8>,
    pub(crate) genesis_root: ShellHash,
    pub(crate) block: ShellHash,
    pub(crate) tip: ShellHash,
}
fn ensure(ok: bool, why: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
pub(crate) fn node<S: KvStore + 'static>(
    store: Arc<S>,
    authority: Address,
    key: &[u8],
) -> Result<Node<S>, Error> {
    let chain = Arc::new(ChainStore::new(store.clone()));
    ensure(
        chain.get_pubkey(&authority)?.as_deref() == Some(key),
        "saved authority key differs from native registry",
    )?;
    let head = chain.get_head_block()?.ok_or("node genesis missing")?;
    let world = Arc::new(RwLock::new(WorldState::at_root(
        store.clone(),
        &head.header.state_root,
    )?));
    let mut config = NodeConfig::dev(authority);
    config.node_role = shell_node::NodeRole::Prover;
    config.proposer_address = None;
    config.chain_id = 10;
    config.mempool.chain_id = 10;
    config.enable_stark_aggregation = false;
    config.block_time_ms = 1_000;
    let pool = Arc::new(TxPool::new(config.mempool.clone()));
    let mut consensus_config = WPoaConfig::from_poa(PoaConfig::new(vec![authority], 1));
    consensus_config.chain_id = 10;
    config.consensus = shell_node::ConsensusEngineConfig::WPoa(consensus_config.clone());
    let consensus: Arc<RwLock<dyn ConsensusEngine>> = Arc::new(RwLock::new(WPoaEngine::new(
        consensus_config,
        Arc::new(MultiVerifier),
    )));
    let node = Node::new(config, store, chain, world, pool, consensus);
    node.known_authorities
        .write()
        .insert(authority, key.to_vec());
    Ok(node)
}
pub(crate) async fn request(
    address: SocketAddr,
    token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<(u16, Value), Error> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let stream = tokio::net::TcpStream::connect(address).await?;
        let (mut client, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        let connection = tokio::spawn(connection);
        let payload =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
        let mut request = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{address}/"))
            .header("Host", address.to_string())
            .header("Content-Type", "application/json");
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = client
            .send_request(
                request.body(http_body_util::Full::new(hyper::body::Bytes::from(payload)))?,
            )
            .await?;
        let status = response.status().as_u16();
        let body = response.into_body().collect().await?.to_bytes();
        drop(client);
        connection.await??;
        Ok::<_, Error>((
            status,
            if status == 200 {
                serde_json::from_slice(&body)?
            } else {
                Value::Null
            },
        ))
    })
    .await?
}

/// Restore the genuine independent Native parent without importing the proof target.
#[cfg(feature = "rocksdb")]
// Other consumers of this shared fixture only use node and RPC helpers.
#[allow(dead_code)]
pub(crate) fn restore_parent(
    native: &std::path::Path,
    receiver_path: &std::path::Path,
    source: &shell_storage::RocksDbStore,
) -> Result<(), Error> {
    ensure(
        !receiver_path.exists(),
        "parent receiver exists; refusing replacement",
    )?;
    use shell_storage::RocksDbStore;
    let digest = |db: &RocksDbStore| -> Result<ShellHash, Error> {
        Ok(shell_primitives::blake3_hash(&serde_json::to_vec(
            &db.scan_all()?,
        )?))
    };
    let c: Context = serde_json::from_slice(&std::fs::read(native.join("context.json"))?)?;
    let block: shell_core::Block =
        serde_json::from_slice(&std::fs::read(native.join("candidate.json"))?)?;
    ensure(
        native.join("provider/db/CURRENT").is_file()
            && native.join("native-parent/db/CURRENT").is_file(),
        "initialized Native parent controls required",
    )?;
    let parent = RocksDbStore::open_all(native.join("native-parent/db"), None)?;
    let source_before = digest(source)?;
    let parent_before = digest(&parent.state)?;
    let chain = ChainStore::new(Arc::new(source.clone()));
    let prior = ChainStore::new(Arc::new(parent.state.clone()));
    let header = prior
        .get_header_by_hash(&block.header.parent_hash)?
        .ok_or("saved parent absent")?;
    let view = chain.canonical_parent_view(c.tip, block.header.parent_hash)?;
    ensure(
        block.hash() == c.block
            && block.number() == 2
            && prior.get_head_hash()? == Some(block.header.parent_hash)
            && header.number + 1 == block.number()
            && chain.get_header_by_hash(&block.header.parent_hash)? == Some(header.clone())
            && prior.get_chain_config()? == chain.get_chain_config()?
            && prior.get_block_by_hash(&c.block)?.is_none()
            && prior.get_receipts(&c.block)?.is_none()
            && parent
                .state
                .get(block.header.state_root.as_bytes())?
                .is_none(),
        "saved Native parent is not the canonical target predecessor",
    )?;
    let node = node(
        Arc::new(parent.state.clone()),
        c.authority,
        &c.authority_key,
    )?;
    ensure(
        node.world_state.write().state_root()? == header.state_root
            && node.finality.read().last_finalized_number() == header.number,
        "saved parent state or finality differs",
    )?;
    for address in [block.transactions[0].from, c.authority] {
        ensure(
            prior.get_pubkey(&address)? == view.registered_key(&address)?,
            "saved parent authority differs",
        )?;
    }
    std::fs::create_dir_all(
        receiver_path
            .parent()
            .ok_or("receiver parent path absent")?,
    )?;
    parent.create_checkpoint(receiver_path)?;
    ensure(
        source_before == digest(source)? && parent_before == digest(&parent.state)?,
        "parent restore changed retained Native controls",
    )
}
