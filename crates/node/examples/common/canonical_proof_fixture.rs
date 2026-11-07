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
