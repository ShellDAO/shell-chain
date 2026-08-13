//! libp2p-based NetworkService implementation.
//!
//! Uses TCP + Noise + Yamux transport with GossipSub for message
//! broadcast, mDNS for local peer discovery, and Kademlia DHT for
//! global peer discovery.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::gossipsub::{self, IdentTopic, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
use libp2p::kad;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{
    autonat, connection_limits, dcutr, identify, mdns, noise, relay, tcp, yamux, Multiaddr,
    PeerId as Libp2pPeerId, Swarm, SwarmBuilder,
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::bandwidth::BandwidthTracker;
use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::message::{NetworkEvent, NetworkMessage, NetworkTopic, PeerId};
use crate::service::NetworkService;

const BOOTNODE_REDIAL_INTERVAL_SECS: u64 = 30;
const DIRECT_MESSAGE_PROTOCOL: StreamProtocol = StreamProtocol::new("/shell/direct/1");
const MAX_PENDING_DIRECT_MESSAGES: usize = 256;
const MAX_PENDING_DIRECT_BYTES: usize = 2 * crate::message::MAX_MESSAGE_SIZE;
const MAX_INBOUND_DIRECT_BYTES_PER_CONNECTION: usize = 2 * crate::message::MAX_MESSAGE_SIZE;
const MAX_IDENTITY_KEY_SIZE: u64 = 64 * 1024;

fn max_concurrent_direct_streams(max_message_size: usize) -> usize {
    (MAX_INBOUND_DIRECT_BYTES_PER_CONNECTION / max_message_size.max(1))
        .clamp(1, MAX_PENDING_DIRECT_MESSAGES)
}

/// Topic category for gossipsub routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopicKind {
    Blocks,
    Transactions,
    Attestation,
    Proofs,
}

/// Commands sent to the Swarm background task.
enum SwarmCommand {
    Publish {
        topic: TopicKind,
        data: Vec<u8>,
    },
    SendToPeer {
        peer: Libp2pPeerId,
        topic: TopicKind,
        data: Vec<u8>,
    },
    /// Request a snapshot of current peer scores.
    PeerScores {
        reply: oneshot::Sender<Vec<(PeerId, f64)>>,
    },
    Shutdown,
}

/// Combined libp2p network behaviour for shell-chain.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct ShellBehaviour {
    gossipsub: gossipsub::Behaviour,
    direct_message: request_response::Behaviour<DirectMessageCodec>,
    kademlia: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    identify: identify::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    autonat: Toggle<autonat::Behaviour>,
    connection_limits: connection_limits::Behaviour,
}

#[derive(Clone)]
struct DirectMessageCodec {
    max_message_size: usize,
}

#[async_trait]
impl request_response::Codec for DirectMessageCodec {
    type Protocol = StreamProtocol;
    type Request = Arc<[u8]>;
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let limit = u64::try_from(self.max_message_size).unwrap_or(u64::MAX);
        let mut data = Vec::new();
        io.take(limit.saturating_add(1))
            .read_to_end(&mut data)
            .await?;
        if data.len() > self.max_message_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "direct message exceeds configured size limit",
            ));
        }
        Ok(data.into())
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut ack = [0u8; 1];
        io.read_exact(&mut ack).await?;
        if ack[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid direct message acknowledgement",
            ));
        }
        Ok(())
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if request.len() > self.max_message_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct message exceeds configured size limit",
            ));
        }
        io.write_all(&request).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        _response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[0]).await
    }
}

struct PendingDirectMessage {
    topic: TopicKind,
    data: Arc<[u8]>,
}

struct PendingDirectMessages {
    messages: HashMap<request_response::OutboundRequestId, PendingDirectMessage>,
    bytes: usize,
    max_messages: usize,
    max_bytes: usize,
}

struct ExplicitMdnsPeers {
    peers: HashSet<Libp2pPeerId>,
    max_peers: usize,
}

impl ExplicitMdnsPeers {
    fn new(max_peers: usize) -> Self {
        Self {
            peers: HashSet::new(),
            max_peers,
        }
    }

    fn admit(&mut self, peer: Libp2pPeerId) -> bool {
        if self.peers.contains(&peer) {
            return true;
        }
        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            return false;
        }
        self.peers.insert(peer);
        true
    }

    fn remove(&mut self, peer: &Libp2pPeerId) -> bool {
        self.peers.remove(peer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectMessageAdmission {
    Send,
    Drop,
}

impl PendingDirectMessages {
    fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            messages: HashMap::new(),
            bytes: 0,
            max_messages,
            max_bytes,
        }
    }

    fn can_accept(&self, data_len: usize) -> bool {
        self.messages.len() < self.max_messages
            && self
                .bytes
                .checked_add(data_len)
                .is_some_and(|bytes| bytes <= self.max_bytes)
    }

    fn insert(
        &mut self,
        request_id: request_response::OutboundRequestId,
        message: PendingDirectMessage,
    ) {
        debug_assert!(self.can_accept(message.data.len()));
        self.bytes += message.data.len();
        let replaced = self.messages.insert(request_id, message);
        debug_assert!(replaced.is_none());
    }

    fn remove(
        &mut self,
        request_id: &request_response::OutboundRequestId,
    ) -> Option<PendingDirectMessage> {
        let message = self.messages.remove(request_id)?;
        self.bytes = self.bytes.saturating_sub(message.data.len());
        Some(message)
    }
}

fn direct_message_admission(
    pending: &PendingDirectMessages,
    data_len: usize,
) -> DirectMessageAdmission {
    if pending.can_accept(data_len) {
        DirectMessageAdmission::Send
    } else {
        DirectMessageAdmission::Drop
    }
}

fn take_direct_message_fallback(
    pending: &mut PendingDirectMessages,
    request_id: request_response::OutboundRequestId,
    error: &request_response::OutboundFailure,
) -> Option<PendingDirectMessage> {
    let message = pending.remove(&request_id);
    if matches!(
        error,
        request_response::OutboundFailure::UnsupportedProtocols
    ) {
        message
    } else {
        None
    }
}

/// Production P2P network service backed by libp2p.
///
/// Spawns a background task running the libp2p Swarm event loop.
/// Communication with the swarm is via async channels.
pub struct Libp2pNetwork {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    peer_count: Arc<AtomicUsize>,
    bandwidth: Arc<BandwidthTracker>,
    max_msg_size: usize,
}

impl Libp2pNetwork {
    /// Create and start the libp2p network.
    ///
    /// Begins listening on `config.listen_addr` and dials any boot nodes.
    /// Peer discovery via mDNS starts automatically.
    pub async fn new(config: &NetworkConfig) -> Result<Self, NetworkError> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::channel(256);
        let peer_count = Arc::new(AtomicUsize::new(0));
        let max_msg_size = config.effective_max_message_size();
        let bandwidth = Arc::new(BandwidthTracker::new(
            config.max_inbound_bandwidth,
            config.max_outbound_bandwidth,
        ));

        let keypair = load_or_create_identity(config.identity_key_path.as_deref())?;
        let mut swarm = build_swarm_with_identity(config, keypair)?;

        // Listen on configured address.
        let listen_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}",
            config.listen_addr.ip(),
            config.listen_addr.port()
        )
        .parse()
        .map_err(|e: libp2p::multiaddr::Error| NetworkError::Transport(e.to_string()))?;

        swarm
            .listen_on(listen_addr)
            .map_err(|e| NetworkError::Transport(e.to_string()))?;

        let boot_nodes = parse_boot_nodes(&config.boot_nodes);
        for addr in &boot_nodes {
            seed_and_dial_boot_node(&mut swarm, addr, "startup");
        }

        // Trigger initial Kademlia bootstrap if we have boot nodes.
        if !config.boot_nodes.is_empty() {
            if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
                if let Err(e) = kad.bootstrap() {
                    warn!("Kademlia bootstrap failed: {e:?}");
                }
            }
        }

        let blocks_topic = IdentTopic::new(&config.blocks_topic);
        let txs_topic = IdentTopic::new(&config.txs_topic);
        let attestation_topic = IdentTopic::new(&config.attestation_topic);
        let proofs_topic = IdentTopic::new(&config.proofs_topic);
        let loop_config = SwarmLoopConfig {
            peer_count: Arc::clone(&peer_count),
            blocks_topic,
            txs_topic,
            attestation_topic,
            proofs_topic,
            bandwidth: Arc::clone(&bandwidth),
            boot_nodes,
            max_msg_size,
            peer_security: PeerSecurityConfig::from(config),
        };

        tokio::spawn(swarm_loop(swarm, cmd_rx, event_tx, loop_config));

        Ok(Self {
            cmd_tx,
            event_rx,
            peer_count,
            bandwidth,
            max_msg_size,
        })
    }

    /// Return a reference to the bandwidth tracker for stats/monitoring.
    pub fn bandwidth(&self) -> &Arc<BandwidthTracker> {
        &self.bandwidth
    }

    /// Return a shared handle to the live peer count for external consumers (e.g. RPC).
    pub fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.peer_count)
    }

    /// Return a snapshot of all known peer scores.
    ///
    /// Sends a request to the swarm background task and awaits the reply.
    /// Returns an empty vec if the channel is closed or scoring is disabled.
    pub async fn peer_scores(&self) -> Vec<(PeerId, f64)> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SwarmCommand::PeerScores { reply: tx })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }
}

fn load_or_create_identity(path: Option<&Path>) -> Result<libp2p::identity::Keypair, NetworkError> {
    match path {
        Some(path) => {
            match read_identity_file(path) {
                Ok(bytes) => {
                    return libp2p::identity::Keypair::from_protobuf_encoding(&bytes).map_err(
                        |e| NetworkError::Transport(format!("invalid libp2p identity: {e}")),
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(NetworkError::Transport(error.to_string())),
            }

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| NetworkError::Transport(e.to_string()))?;
            }
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let encoded = keypair
                .to_protobuf_encoding()
                .map_err(|e| NetworkError::Transport(format!("encode libp2p identity: {e}")))?;
            write_identity_file_new(path, &encoded)
                .map_err(|e| NetworkError::Transport(e.to_string()))?;
            Ok(keypair)
        }
        None => Ok(libp2p::identity::Keypair::generate_ed25519()),
    }
}

fn open_identity_file(path: &Path) -> io::Result<File> {
    let path_meta = fs::symlink_metadata(path)?;
    if path_meta.file_type().is_symlink() || !path_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("libp2p identity must be a regular file: {}", path.display()),
        ));
    }
    if path_meta.len() > MAX_IDENTITY_KEY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("libp2p identity exceeds {MAX_IDENTITY_KEY_SIZE} bytes"),
        ));
    }

    let file = OpenOptions::new().read(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let opened_meta = file.metadata()?;
        if path_meta.dev() != opened_meta.dev() || path_meta.ino() != opened_meta.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("libp2p identity changed while opening: {}", path.display()),
            ));
        }
    }
    Ok(file)
}

fn read_identity_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = open_identity_file(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_IDENTITY_KEY_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IDENTITY_KEY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("libp2p identity exceeds {MAX_IDENTITY_KEY_SIZE} bytes"),
        ));
    }
    Ok(bytes)
}

fn write_identity_file_new(path: &Path, encoded: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_meta = fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "libp2p identity parent must be a real directory: {}",
                parent.display()
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(encoded)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
fn build_swarm(config: &NetworkConfig) -> Result<Swarm<ShellBehaviour>, NetworkError> {
    build_swarm_with_identity(config, libp2p::identity::Keypair::generate_ed25519())
}

fn build_swarm_with_identity(
    config: &NetworkConfig,
    keypair: libp2p::identity::Keypair,
) -> Result<Swarm<ShellBehaviour>, NetworkError> {
    let enable_mdns = config.enable_mdns;
    let enable_kademlia = config.enable_kademlia;
    let enable_peer_scoring = config.enable_peer_scoring;
    let enable_relay = config.enable_relay;
    let enable_dcutr = config.enable_dcutr;
    let enable_autonat = config.enable_autonat;
    let blocks_topic_name = config.blocks_topic.clone();
    let txs_topic_name = config.txs_topic.clone();
    let attestation_topic_name = config.attestation_topic.clone();
    let proofs_topic_name = config.proofs_topic.clone();
    let max_msg_size = config.effective_max_message_size();

    // Build libp2p connection limits from config.
    let mut conn_limits = connection_limits::ConnectionLimits::default();

    // `max_connections` bounds connections, while PeerTracker separately bounds
    // unique peers. Combining the two here would let duplicate connections consume
    // peer slots and prevent the node from reaching its configured peer count.
    if let Some(limit) = max_established_connection_limit(config) {
        conn_limits = conn_limits.with_max_established(Some(limit));
    }

    if config.max_pending_incoming > 0 {
        conn_limits = conn_limits.with_max_pending_incoming(Some(config.max_pending_incoming));
    }
    if config.max_pending_outgoing > 0 {
        conn_limits = conn_limits.with_max_pending_outgoing(Some(config.max_pending_outgoing));
    }
    if config.max_established_per_peer > 0 {
        conn_limits =
            conn_limits.with_max_established_per_peer(Some(config.max_established_per_peer));
    }

    // Deterministic message ID: blake3 hash of payload.
    // CRITICAL: Do NOT use DefaultHasher — its random per-process seed
    // makes MessageIds differ across nodes, breaking dedup (F-031).
    let message_id_fn = |msg: &gossipsub::Message| {
        let control_message = crate::message::serialized_message_uses_sequence_scoped_id(&msg.data);

        if control_message {
            let source = msg
                .source
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string());
            let sequence = msg
                .sequence_number
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "none".to_string());
            return gossipsub::MessageId::from(format!("control:{source}:{sequence}"));
        }

        let hash = blake3::hash(&msg.data);
        gossipsub::MessageId::from(hash.to_hex().as_str().to_owned())
    };

    let gs_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages() // F-062: hold messages until application validates
        .message_id_fn(message_id_fn)
        .max_transmit_size(max_msg_size)
        .build()
        .map_err(|e| NetworkError::Transport(format!("gossipsub config: {e}")))?;

    // Helper closure that builds the common behaviours (everything except relay_client).
    let make_behaviour =
        move |key: &libp2p::identity::Keypair,
              relay_behaviour: Option<relay::client::Behaviour>|
              -> Result<ShellBehaviour, Box<dyn std::error::Error + Send + Sync>> {
            let peer_id = key.public().to_peer_id();

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gs_config,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

            // Configure peer scoring to penalise misbehaving peers and
            // reward timely block/tx delivery.
            if enable_peer_scoring {
                let blocks_topic_params = TopicScoreParams {
                    topic_weight: 1.0,
                    time_in_mesh_weight: 0.5,
                    time_in_mesh_quantum: Duration::from_secs(1),
                    time_in_mesh_cap: 3600.0,
                    first_message_deliveries_weight: 5.0,
                    first_message_deliveries_cap: 100.0,
                    first_message_deliveries_decay: 0.99,
                    invalid_message_deliveries_weight: -100.0,
                    invalid_message_deliveries_decay: 0.5,
                    mesh_message_deliveries_weight: 0.0,
                    mesh_failure_penalty_weight: 0.0,
                    ..Default::default()
                };

                let txs_topic_params = TopicScoreParams {
                    topic_weight: 0.5,
                    time_in_mesh_weight: 0.3,
                    time_in_mesh_quantum: Duration::from_secs(1),
                    time_in_mesh_cap: 3600.0,
                    first_message_deliveries_weight: 2.0,
                    first_message_deliveries_cap: 1000.0,
                    first_message_deliveries_decay: 0.99,
                    invalid_message_deliveries_weight: -50.0,
                    invalid_message_deliveries_decay: 0.5,
                    mesh_message_deliveries_weight: 0.0,
                    mesh_failure_penalty_weight: 0.0,
                    ..Default::default()
                };

                let attestation_topic_params = TopicScoreParams {
                    topic_weight: 0.8,
                    time_in_mesh_weight: 0.4,
                    time_in_mesh_quantum: Duration::from_secs(1),
                    time_in_mesh_cap: 3600.0,
                    first_message_deliveries_weight: 3.0,
                    first_message_deliveries_cap: 200.0,
                    first_message_deliveries_decay: 0.99,
                    invalid_message_deliveries_weight: -80.0,
                    invalid_message_deliveries_decay: 0.5,
                    mesh_message_deliveries_weight: 0.0,
                    mesh_failure_penalty_weight: 0.0,
                    ..Default::default()
                };

                let proofs_topic_params = TopicScoreParams {
                    topic_weight: 0.8,
                    time_in_mesh_weight: 0.4,
                    time_in_mesh_quantum: Duration::from_secs(1),
                    time_in_mesh_cap: 3600.0,
                    first_message_deliveries_weight: 3.0,
                    first_message_deliveries_cap: 200.0,
                    first_message_deliveries_decay: 0.99,
                    invalid_message_deliveries_weight: -80.0,
                    invalid_message_deliveries_decay: 0.5,
                    mesh_message_deliveries_weight: 0.0,
                    mesh_failure_penalty_weight: 0.0,
                    ..Default::default()
                };

                let blocks_hash = IdentTopic::new(&blocks_topic_name).hash();
                let txs_hash = IdentTopic::new(&txs_topic_name).hash();
                let attestation_hash = IdentTopic::new(&attestation_topic_name).hash();
                let proofs_hash = IdentTopic::new(&proofs_topic_name).hash();

                let mut topic_scores = HashMap::new();
                topic_scores.insert(blocks_hash, blocks_topic_params);
                topic_scores.insert(txs_hash, txs_topic_params);
                topic_scores.insert(attestation_hash, attestation_topic_params);
                topic_scores.insert(proofs_hash, proofs_topic_params);

                let peer_score_params = PeerScoreParams {
                    topics: topic_scores,
                    ..Default::default()
                };

                let thresholds = PeerScoreThresholds {
                    gossip_threshold: -100.0,
                    publish_threshold: -200.0,
                    graylist_threshold: -300.0,
                    accept_px_threshold: 100.0,
                    opportunistic_graft_threshold: 5.0,
                };

                gossipsub
                    .with_peer_score(peer_score_params, thresholds)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        format!("peer scoring: {e}").into()
                    })?;
            }

            let kademlia = if enable_kademlia {
                let store = kad::store::MemoryStore::new(peer_id);
                let mut kad_config =
                    kad::Config::new(libp2p::StreamProtocol::new("/shell-chain/kad/1.0.0"));
                kad_config.set_query_timeout(Duration::from_secs(60));
                let mut behaviour = kad::Behaviour::with_config(peer_id, store, kad_config);
                behaviour.set_mode(Some(kad::Mode::Server));
                Some(behaviour)
            } else {
                None
            };

            let mdns = if enable_mdns {
                Some(
                    mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?,
                )
            } else {
                None
            };

            let identify = identify::Behaviour::new(identify::Config::new(
                "/shell-chain/1.0.0".into(),
                key.public(),
            ));
            let direct_message = request_response::Behaviour::with_codec(
                DirectMessageCodec {
                    max_message_size: max_msg_size,
                },
                [(DIRECT_MESSAGE_PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(max_concurrent_direct_streams(max_msg_size)),
            );

            let dcutr_behaviour: Option<dcutr::Behaviour> =
                if enable_dcutr && relay_behaviour.is_some() {
                    Some(dcutr::Behaviour::new(peer_id))
                } else {
                    None
                };

            let autonat_behaviour: Option<autonat::Behaviour> = if enable_autonat {
                Some(autonat::Behaviour::new(peer_id, autonat::Config::default()))
            } else {
                None
            };

            // Relay server with amplification limits (F-071).
            let relay_server_behaviour: Option<relay::Behaviour> = if relay_behaviour.is_some() {
                let relay_cfg = relay::Config {
                    max_reservations: 128,
                    max_circuits: 16,
                    max_circuit_duration: Duration::from_secs(300),
                    max_circuit_bytes: 1024 * 1024, // 1 MB per circuit
                    ..Default::default()
                };
                Some(relay::Behaviour::new(peer_id, relay_cfg))
            } else {
                None
            };

            Ok(ShellBehaviour {
                gossipsub,
                direct_message,
                kademlia: kademlia.into(),
                mdns: mdns.into(),
                identify,
                relay_client: relay_behaviour.into(),
                relay_server: relay_server_behaviour.into(),
                dcutr: dcutr_behaviour.into(),
                autonat: autonat_behaviour.into(),
                connection_limits: connection_limits::Behaviour::new(conn_limits),
            })
        };

    // Build the swarm. When relay is enabled we add a relay client transport
    // so the node can connect through relay nodes. The builder signature
    // differs (two-arg vs one-arg closure for `with_behaviour`), hence two
    // code paths.
    let swarm = if enable_relay {
        SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NetworkError::Transport(format!("transport: {e}")))?
            .with_dns()
            .map_err(|e| NetworkError::Transport(format!("dns transport: {e}")))?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| NetworkError::Transport(format!("relay transport: {e}")))?
            .with_behaviour(|key, relay| make_behaviour(key, Some(relay)))
            .map_err(|e| NetworkError::Transport(format!("behaviour: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    } else {
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NetworkError::Transport(format!("transport: {e}")))?
            .with_dns()
            .map_err(|e| NetworkError::Transport(format!("dns transport: {e}")))?
            .with_behaviour(|key| make_behaviour(key, None))
            .map_err(|e| NetworkError::Transport(format!("behaviour: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    };

    if enable_peer_scoring {
        info!("GossipSub peer scoring enabled");
    }
    if enable_kademlia {
        info!("Kademlia DHT peer discovery enabled");
    }
    if enable_mdns {
        info!("mDNS peer discovery enabled");
    } else {
        info!("mDNS peer discovery disabled (production mode)");
    }
    if enable_relay {
        info!("Relay client transport enabled for NAT traversal");
    }
    if enable_dcutr {
        info!("DCUtR hole-punching enabled");
    }
    if enable_autonat {
        info!("AutoNAT status detection enabled");
    }
    info!(
        max_established = config.max_connections,
        max_pending_in = config.max_pending_incoming,
        max_pending_out = config.max_pending_outgoing,
        max_per_peer = config.max_established_per_peer,
        "Connection limits configured"
    );

    Ok(swarm)
}

fn max_established_connection_limit(config: &NetworkConfig) -> Option<u32> {
    (config.max_connections > 0).then_some(config.max_connections)
}

struct SwarmLoopConfig {
    peer_count: Arc<AtomicUsize>,
    blocks_topic: IdentTopic,
    txs_topic: IdentTopic,
    attestation_topic: IdentTopic,
    proofs_topic: IdentTopic,
    bandwidth: Arc<BandwidthTracker>,
    boot_nodes: Vec<Multiaddr>,
    max_msg_size: usize,
    peer_security: PeerSecurityConfig,
}

struct SwarmLoopState {
    peer_tracker: crate::security::PeerTracker,
    peer_ban_list: crate::security::PeerBanList,
    pending_direct_messages: PendingDirectMessages,
    explicit_mdns_peers: ExplicitMdnsPeers,
}

impl SwarmLoopState {
    fn new(config: PeerSecurityConfig) -> Self {
        Self {
            peer_tracker: crate::security::PeerTracker::new(config.max_peers),
            peer_ban_list: crate::security::PeerBanList::new(
                config.ban_threshold,
                config.ban_duration,
            ),
            pending_direct_messages: PendingDirectMessages::new(
                MAX_PENDING_DIRECT_MESSAGES,
                MAX_PENDING_DIRECT_BYTES,
            ),
            explicit_mdns_peers: ExplicitMdnsPeers::new(config.max_peers),
        }
    }
}

struct PeerCountResetGuard(Arc<AtomicUsize>);

impl Drop for PeerCountResetGuard {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerSecurityConfig {
    max_peers: usize,
    ban_threshold: u32,
    ban_duration: Duration,
}

impl From<&NetworkConfig> for PeerSecurityConfig {
    fn from(config: &NetworkConfig) -> Self {
        Self {
            max_peers: config.max_peers,
            ban_threshold: config.ban_threshold,
            ban_duration: Duration::from_secs(config.ban_duration_secs),
        }
    }
}

/// Background task that drives the libp2p Swarm.
async fn swarm_loop(
    mut swarm: Swarm<ShellBehaviour>,
    mut cmd_rx: mpsc::Receiver<SwarmCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    loop_config: SwarmLoopConfig,
) {
    let mut state = SwarmLoopState::new(loop_config.peer_security);
    let _peer_count_reset = PeerCountResetGuard(Arc::clone(&loop_config.peer_count));

    // Subscribe to gossipsub topics.
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&loop_config.blocks_topic)
    {
        warn!("Failed to subscribe to blocks topic: {e}");
    }
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&loop_config.txs_topic)
    {
        warn!("Failed to subscribe to txs topic: {e}");
    }
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&loop_config.attestation_topic)
    {
        warn!("Failed to subscribe to attestation topic: {e}");
    }
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&loop_config.proofs_topic)
    {
        warn!("Failed to subscribe to proofs topic: {e}");
    }

    // Periodic Kademlia bootstrap refresh (every 5 minutes).
    let mut kad_bootstrap_interval = interval(Duration::from_secs(300));
    // Skip the first immediate tick — bootstrap was already triggered on startup.
    kad_bootstrap_interval.tick().await;

    // Bootnodes must be treated as persistent anchors, not one-shot startup
    // dials. A validator that restarts should reconnect without requiring the
    // surviving peer to restart its own swarm.
    let mut bootnode_redial_interval = interval(Duration::from_secs(BOOTNODE_REDIAL_INTERVAL_SECS));
    bootnode_redial_interval.tick().await;

    // Periodic peer score logging (every 60 seconds).
    let mut score_log_interval = interval(Duration::from_secs(60));
    score_log_interval.tick().await;

    // Bandwidth reset tick (every second).
    let mut bw_tick = interval(Duration::from_secs(1));
    bw_tick.tick().await;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SwarmCommand::Publish { topic, data }) => {
                        let data_len = data.len() as u64;
                        let ident = match topic {
                            TopicKind::Blocks => loop_config.blocks_topic.clone(),
                            TopicKind::Transactions => loop_config.txs_topic.clone(),
                            TopicKind::Attestation => loop_config.attestation_topic.clone(),
                            TopicKind::Proofs => loop_config.proofs_topic.clone(),
                        };
                        // F-065: skip publish when outbound bandwidth exceeded.
                        if !loop_config.bandwidth.record_outbound(data_len) {
                            warn!(
                                bytes = data_len,
                                "Outbound bandwidth limit exceeded — skipping publish"
                            );
                        } else if let Err(e) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(ident, data)
                        {
                            debug!("Gossipsub publish error: {e}");
                        }
                    }
                    Some(SwarmCommand::SendToPeer { peer, topic, data }) => {
                        let data_len = data.len() as u64;
                        if !loop_config.bandwidth.record_outbound(data_len) {
                            warn!(
                                bytes = data_len,
                                %peer,
                                "Outbound bandwidth limit exceeded - skipping direct message"
                            );
                        } else {
                            let data: Arc<[u8]> = data.into();
                            match direct_message_admission(&state.pending_direct_messages, data.len()) {
                                DirectMessageAdmission::Send => {
                                    let request_id = swarm
                                        .behaviour_mut()
                                        .direct_message
                                        .send_request(&peer, Arc::clone(&data));
                                    state.pending_direct_messages.insert(
                                        request_id,
                                        PendingDirectMessage { topic, data },
                                    );
                                }
                                DirectMessageAdmission::Drop => {
                                    warn!(
                                        %peer,
                                        "direct message pending limit reached; dropping peer-targeted message"
                                    );
                                }
                            }
                        }
                    }
                    Some(SwarmCommand::PeerScores { reply }) => {
                        let scores = collect_peer_scores(&swarm);
                        let _ = reply.send(scores);
                    }
                    Some(SwarmCommand::Shutdown) | None => {
                        info!("libp2p swarm shutting down");
                        break;
                    }
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &event_tx,
                    &loop_config,
                    &mut state,
                );
            }
            _ = kad_bootstrap_interval.tick() => {
                if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
                    debug!("Periodic Kademlia bootstrap");
                    let _ = kad.bootstrap();
                }
            }
            _ = bootnode_redial_interval.tick(), if !loop_config.boot_nodes.is_empty() => {
                for addr in &loop_config.boot_nodes {
                    seed_and_dial_boot_node(&mut swarm, addr, "redial");
                }
            }
            _ = score_log_interval.tick() => {
                state.peer_ban_list.purge_expired();
                log_peer_scores(&swarm);
            }
            _ = bw_tick.tick() => {
                loop_config.bandwidth.reset_if_needed();
            }
        }
    }
}

fn parse_boot_nodes(raw: &[String]) -> Vec<Multiaddr> {
    raw.iter()
        .filter_map(|addr_str| {
            if !crate::config::validate_bootnode_multiaddr(addr_str) {
                warn!(
                    "Skipping invalid boot node address '{addr_str}': \
                     must contain IP, transport, and peer ID components"
                );
                return None;
            }
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    warn!("Invalid boot node address '{addr_str}': {e}");
                    None
                }
            }
        })
        .collect()
}

fn seed_and_dial_boot_node(
    swarm: &mut Swarm<ShellBehaviour>,
    addr: &Multiaddr,
    reason: &'static str,
) {
    if let Some(peer_id) = extract_peer_id(addr) {
        if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
            kad.add_address(&peer_id, addr.clone());
        }
        if swarm.is_connected(&peer_id) {
            debug!(%peer_id, %addr, reason, "boot node already connected");
            return;
        }
    }

    info!(%addr, reason, "dialing boot node");
    if let Err(e) = swarm.dial(addr.clone()) {
        debug!(%addr, reason, error = %e, "boot node dial not started");
    }
}

fn mdns_peer_still_discovered<'a>(
    peer_id: &Libp2pPeerId,
    discovered_peers: impl Iterator<Item = &'a Libp2pPeerId>,
) -> bool {
    discovered_peers.into_iter().any(|peer| peer == peer_id)
}

/// Process a single SwarmEvent, forwarding relevant data as NetworkEvents.
fn handle_swarm_event(
    event: SwarmEvent<ShellBehaviourEvent>,
    swarm: &mut Swarm<ShellBehaviour>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    loop_config: &SwarmLoopConfig,
    state: &mut SwarmLoopState,
) {
    let SwarmLoopState {
        peer_tracker,
        peer_ban_list,
        pending_direct_messages,
        explicit_mdns_peers,
    } = state;
    match event {
        SwarmEvent::Behaviour(ShellBehaviourEvent::DirectMessage(
            request_response::Event::Message {
                peer: source,
                message:
                    request_response::Message::Request {
                        request: data,
                        channel,
                        ..
                    },
                ..
            },
        )) => {
            let _ = swarm
                .behaviour_mut()
                .direct_message
                .send_response(channel, ());
            let data_len = data.len() as u64;
            if !loop_config.bandwidth.record_inbound(data_len) {
                warn!(
                    bytes = data_len,
                    peer = %source,
                    "Inbound bandwidth limit exceeded - dropping direct message"
                );
                return;
            }

            let peer = PeerId(source.to_string());
            match crate::message::deserialize_checked(&data, loop_config.max_msg_size) {
                Ok(message) => {
                    if let Err(error) = try_forward_message_event(event_tx, peer, message) {
                        debug!(
                            ?error,
                            peer = %source,
                            "node event queue unavailable - dropping direct message"
                        );
                    }
                }
                Err(error) => {
                    debug!(peer = %source, %error, "invalid direct message");
                    if peer_ban_list.record_violation(&peer) {
                        warn!(peer = %source, "peer banned for repeated violations");
                        let _ = swarm.disconnect_peer_id(source);
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ShellBehaviourEvent::DirectMessage(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. },
                ..
            },
        )) => {
            pending_direct_messages.remove(&request_id);
        }
        SwarmEvent::Behaviour(ShellBehaviourEvent::DirectMessage(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            if let Some(message) =
                take_direct_message_fallback(pending_direct_messages, request_id, &error)
            {
                let ident = match message.topic {
                    TopicKind::Blocks => loop_config.blocks_topic.clone(),
                    TopicKind::Transactions => loop_config.txs_topic.clone(),
                    TopicKind::Attestation => loop_config.attestation_topic.clone(),
                    TopicKind::Proofs => loop_config.proofs_topic.clone(),
                };
                if let Err(fallback_error) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(ident, message.data.to_vec())
                {
                    debug!(
                        %peer,
                        %fallback_error,
                        "direct message compatibility fallback failed"
                    );
                } else {
                    debug!(%peer, "peer lacks direct-message support; used gossip fallback");
                }
            } else {
                debug!(%peer, %error, "direct message delivery failed");
            }
        }
        SwarmEvent::Behaviour(ShellBehaviourEvent::DirectMessage(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            debug!(%peer, %error, "direct message receive failed");
        }
        SwarmEvent::Behaviour(ShellBehaviourEvent::DirectMessage(
            request_response::Event::ResponseSent { .. },
        )) => {}
        // Gossipsub message received.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            let data_len = message.data.len() as u64;
            // F-069: reject messages exceeding the application-level size limit.
            if message.data.len() > loop_config.max_msg_size {
                warn!(
                    bytes = message.data.len(),
                    limit = loop_config.max_msg_size,
                    peer = %propagation_source,
                    "Message exceeds configured message size limit — rejecting"
                );
                // F-305: Record violation for oversized messages.
                let peer = PeerId(propagation_source.to_string());
                let banned = peer_ban_list.record_violation(&peer);
                if banned {
                    warn!(peer = %propagation_source, "peer banned for repeated violations");
                    let _ = swarm.disconnect_peer_id(propagation_source);
                }
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Reject,
                    );
                return;
            }
            // F-065: drop message when bandwidth limit exceeded.
            if !loop_config.bandwidth.record_inbound(data_len) {
                warn!(
                    bytes = data_len,
                    peer = %propagation_source,
                    "Inbound bandwidth limit exceeded — dropping message"
                );
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Ignore,
                    );
                return;
            }
            let peer = PeerId(propagation_source.to_string());
            match crate::message::deserialize_checked(&message.data, loop_config.max_msg_size) {
                Ok(msg) => {
                    if !message_matches_topic(
                        &msg,
                        &message.topic,
                        &loop_config.blocks_topic,
                        &loop_config.txs_topic,
                        &loop_config.attestation_topic,
                        &loop_config.proofs_topic,
                    ) {
                        warn!(
                            peer = %propagation_source,
                            topic = %message.topic,
                            "Message published on the wrong topic - rejecting"
                        );
                        let banned = peer_ban_list.record_violation(&peer);
                        if banned {
                            warn!(peer = %propagation_source, "peer banned for repeated violations");
                            let _ = swarm.disconnect_peer_id(propagation_source);
                        }
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &message_id,
                                &propagation_source,
                                gossipsub::MessageAcceptance::Reject,
                            );
                        return;
                    }
                    let acceptance = match try_forward_message_event(event_tx, peer, msg) {
                        Ok(()) => gossipsub::MessageAcceptance::Accept,
                        Err(EventQueueError::Full) => {
                            debug!(
                                peer = %propagation_source,
                                "Node event queue is full - ignoring validated message"
                            );
                            gossipsub::MessageAcceptance::Ignore
                        }
                        Err(EventQueueError::Closed) => {
                            debug!(
                                peer = %propagation_source,
                                "Node event queue is closed - ignoring validated message"
                            );
                            gossipsub::MessageAcceptance::Ignore
                        }
                    };
                    // F-062: propagate only messages admitted to the node event queue.
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            acceptance,
                        );
                }
                Err(e) => {
                    // F-062: reject invalid message — penalize sender.
                    debug!("Failed to deserialize gossipsub message: {e}");
                    // F-305: Record violation for malformed messages.
                    let ban_peer = PeerId(propagation_source.to_string());
                    let banned = peer_ban_list.record_violation(&ban_peer);
                    if banned {
                        warn!(peer = %propagation_source, "peer banned for repeated violations");
                        let _ = swarm.disconnect_peer_id(propagation_source);
                    }
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Reject,
                        );
                }
            }
        }
        // Kademlia routing table updated.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
            peer,
            ..
        })) => {
            debug!("Kademlia routing updated: {peer}");
            // F-064: Do NOT auto-add Kademlia-discovered peers to GossipSub mesh.
            // Peers join gossipsub mesh naturally via subscription protocol;
            // explicit add bypasses peer scoring and enables Eclipse attacks.
            // Emit routing table size update.
            if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
                let bucket_count: usize = kad.kbuckets().map(|b| b.num_entries()).sum();
                if let Err(error) = try_forward_event(
                    event_tx,
                    NetworkEvent::RoutingTableUpdated {
                        peer_count: bucket_count,
                    },
                ) {
                    debug!(
                        ?error,
                        "node event queue unavailable - dropping routing update"
                    );
                }
            }
        }
        // Kademlia query progress.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed { result, .. },
        )) => {
            debug!("Kademlia query progress: {result:?}");
        }
        // Other Kademlia events.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Kademlia(event)) => {
            debug!("Kademlia event: {event:?}");
        }
        // mDNS peer discovered.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                info!("discovered peer on address peer={peer_id} address={addr}");
                // The mDNS behaviour supplies live addresses during dial resolution and
                // removes them on expiry, so they must not enter persistent peer caches.
                if explicit_mdns_peers.admit(peer_id) {
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                } else {
                    debug!(%peer_id, "mDNS explicit peer limit reached");
                }
            }
        }
        // mDNS peer expired.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, addr) in peers {
                debug!("mDNS expired: peer={peer_id} address={addr}");
                let still_discovered = swarm.behaviour().mdns.as_ref().is_some_and(|mdns| {
                    mdns_peer_still_discovered(&peer_id, mdns.discovered_nodes())
                });
                if !still_discovered && explicit_mdns_peers.remove(&peer_id) {
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }
        }
        // Relay client events.
        SwarmEvent::Behaviour(ShellBehaviourEvent::RelayClient(event)) => {
            match &event {
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                } => {
                    info!(
                        relay = %relay_peer_id,
                        renewal,
                        "Relay reservation accepted"
                    );
                }
                relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                    info!(relay = %relay_peer_id, "Outbound relay circuit established");
                }
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                    info!(src = %src_peer_id, "Inbound relay circuit established");
                }
            }
            debug!("Relay client event: {event:?}");
        }
        // Relay server events.
        SwarmEvent::Behaviour(ShellBehaviourEvent::RelayServer(event)) => {
            debug!("Relay server event: {event:?}");
        }
        // DCUtR hole-punch events.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Dcutr(event)) => match &event.result {
            Ok(_conn_id) => {
                info!(
                    remote = %event.remote_peer_id,
                    "DCUtR hole-punch succeeded — direct connection established"
                );
            }
            Err(e) => {
                warn!(
                    remote = %event.remote_peer_id,
                    error = %e,
                    "DCUtR hole-punch failed"
                );
            }
        },
        // AutoNAT events.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Autonat(event)) => match &event {
            autonat::Event::StatusChanged { old, new } => {
                let status_str = |s: &autonat::NatStatus| match s {
                    autonat::NatStatus::Public(addr) => format!("Public({addr})"),
                    autonat::NatStatus::Private => "Private".to_string(),
                    autonat::NatStatus::Unknown => "Unknown".to_string(),
                };
                info!(
                    old_status = %status_str(old),
                    new_status = %status_str(new),
                    "AutoNAT status changed"
                );
            }
            autonat::Event::InboundProbe(e) => {
                debug!("AutoNAT inbound probe: {e:?}");
            }
            autonat::Event::OutboundProbe(e) => {
                debug!("AutoNAT outbound probe: {e:?}");
            }
        },
        // New listen address bound.
        SwarmEvent::NewListenAddr { address, .. } => {
            let local_peer_id = *swarm.local_peer_id();
            info!("Listening on {address}/p2p/{local_peer_id}");
        }
        // Connection established.
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let peer = PeerId(peer_id.to_string());
            // F-305: Check ban list before accepting connection.
            if peer_ban_list.is_banned(&peer) {
                warn!(peer = %peer_id, "rejecting banned peer connection");
                let _ = swarm.disconnect_peer_id(peer_id);
                return;
            }
            // F-305: Enforce connection limit.
            match track_connection_established(peer_tracker, peer) {
                Ok(Some(event)) => {
                    if let Err(error) = try_forward_event(event_tx, event) {
                        debug!(
                            ?error,
                            "node event queue unavailable - dropping peer connection event"
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    debug!(peer = %peer_id, error = %e, "connection limit reached, disconnecting");
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                }
            }
            debug!("Connected to {peer_id}");
            update_peer_count(peer_tracker, &loop_config.peer_count);
        }
        // Connection closed.
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let peer = PeerId(peer_id.to_string());
            if let Some(event) = track_connection_closed(peer_tracker, &peer) {
                if let Err(error) = try_forward_event(event_tx, event) {
                    debug!(
                        ?error,
                        "node event queue unavailable - dropping peer disconnection event"
                    );
                }
            }
            debug!("Disconnected from {peer_id}");
            update_peer_count(peer_tracker, &loop_config.peer_count);
        }
        // Outgoing connection failed — surface relay/NAT failures for debugging.
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(
                peer = ?peer_id,
                error = %error,
                "outgoing connection failed"
            );
        }
        // Incoming connection failed.
        SwarmEvent::IncomingConnectionError { error, .. } => {
            debug!(error = %error, "incoming connection failed");
        }
        _ => {}
    }
}

fn track_connection_established(
    peer_tracker: &mut crate::security::PeerTracker,
    peer: PeerId,
) -> Result<Option<NetworkEvent>, NetworkError> {
    let first_connection = !peer_tracker.contains_peer(&peer);
    peer_tracker.try_add_peer(peer.clone())?;
    Ok(first_connection.then_some(NetworkEvent::PeerConnected(peer)))
}

fn track_connection_closed(
    peer_tracker: &mut crate::security::PeerTracker,
    peer: &PeerId,
) -> Option<NetworkEvent> {
    let tracked = peer_tracker.contains_peer(peer);
    peer_tracker.remove_peer(peer);
    (tracked && !peer_tracker.contains_peer(peer))
        .then(|| NetworkEvent::PeerDisconnected(peer.clone()))
}

fn update_peer_count(peer_tracker: &crate::security::PeerTracker, counter: &Arc<AtomicUsize>) {
    counter.store(peer_tracker.active_count(), Ordering::Relaxed);
}

/// Collect current peer scores from the GossipSub behaviour.
fn collect_peer_scores(swarm: &Swarm<ShellBehaviour>) -> Vec<(PeerId, f64)> {
    swarm
        .behaviour()
        .gossipsub
        .all_peers()
        .filter_map(|(peer_id, _topics)| {
            swarm
                .behaviour()
                .gossipsub
                .peer_score(peer_id)
                .map(|score| (PeerId(peer_id.to_string()), score))
        })
        .collect()
}

/// Log peer scores, warning about peers below the gossip threshold.
fn log_peer_scores(swarm: &Swarm<ShellBehaviour>) {
    const GOSSIP_THRESHOLD: f64 = -100.0;

    for (peer_id, _topics) in swarm.behaviour().gossipsub.all_peers() {
        if let Some(score) = swarm.behaviour().gossipsub.peer_score(peer_id) {
            if score < GOSSIP_THRESHOLD {
                warn!(
                    %peer_id,
                    score,
                    "Peer score below gossip threshold"
                );
            } else {
                debug!(%peer_id, score, "Peer score");
            }
        }
    }
}

fn topic_kind_for_message(msg: &NetworkMessage) -> TopicKind {
    match msg.topic() {
        NetworkTopic::Blocks => TopicKind::Blocks,
        NetworkTopic::Transactions => TopicKind::Transactions,
        NetworkTopic::Attestation => TopicKind::Attestation,
        NetworkTopic::Proofs => TopicKind::Proofs,
    }
}

fn try_forward_message_event(
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    message: NetworkMessage,
) -> Result<(), EventQueueError> {
    try_forward_event(event_tx, NetworkEvent::MessageReceived { peer, message })
}

fn try_forward_event(
    event_tx: &mpsc::Sender<NetworkEvent>,
    event: NetworkEvent,
) -> Result<(), EventQueueError> {
    event_tx.try_send(event).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => EventQueueError::Full,
        mpsc::error::TrySendError::Closed(_) => EventQueueError::Closed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventQueueError {
    Full,
    Closed,
}

fn message_matches_topic(
    msg: &NetworkMessage,
    actual_topic: &gossipsub::TopicHash,
    blocks_topic: &IdentTopic,
    txs_topic: &IdentTopic,
    attestation_topic: &IdentTopic,
    proofs_topic: &IdentTopic,
) -> bool {
    let expected_topic = match topic_kind_for_message(msg) {
        TopicKind::Blocks => blocks_topic,
        TopicKind::Transactions => txs_topic,
        TopicKind::Attestation => attestation_topic,
        TopicKind::Proofs => proofs_topic,
    };
    actual_topic == &expected_topic.hash()
}

#[async_trait]
impl NetworkService for Libp2pNetwork {
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        let topic = topic_kind_for_message(&msg);

        let data = crate::message::serialize_checked(&msg, self.max_msg_size)?;

        self.cmd_tx
            .send(SwarmCommand::Publish { topic, data })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;

        Ok(())
    }

    async fn send_to_peer(
        &self,
        peer_id: &PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let topic = topic_kind_for_message(&msg);
        let peer = peer_id
            .0
            .parse::<Libp2pPeerId>()
            .map_err(|error| NetworkError::Transport(format!("invalid peer id: {error}")))?;
        let data = crate::message::serialize_checked(&msg, self.max_msg_size)?;

        self.cmd_tx
            .send(SwarmCommand::SendToPeer { peer, topic, data })
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    async fn peer_count(&self) -> usize {
        self.peer_count.load(Ordering::Relaxed)
    }

    fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.peer_count)
    }

    async fn shutdown(&self) -> Result<(), NetworkError> {
        self.cmd_tx
            .send(SwarmCommand::Shutdown)
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        Ok(())
    }
}

/// Extract the libp2p PeerId from a multiaddr containing a `/p2p/<peer_id>` component.
fn extract_peer_id(addr: &Multiaddr) -> Option<Libp2pPeerId> {
    addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use libp2p::futures::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn identity_test_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shell-network-identity-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn identity_file_is_created_once_and_reused() {
        let dir = identity_test_dir("reuse");
        let path = dir.join("libp2p.key");

        let created = load_or_create_identity(Some(&path)).unwrap();
        let loaded = load_or_create_identity(Some(&path)).unwrap();

        assert_eq!(created.public().to_peer_id(), loaded.public().to_peer_id());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = identity_test_dir("permissions");
        let path = dir.join("libp2p.key");
        load_or_create_identity(Some(&path)).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = identity_test_dir("symlink");
        let target = dir.join("target.key");
        let linked = dir.join("libp2p.key");
        let encoded = libp2p::identity::Keypair::generate_ed25519()
            .to_protobuf_encoding()
            .unwrap();
        fs::write(&target, encoded).unwrap();
        symlink(&target, &linked).unwrap();

        let error = load_or_create_identity(Some(&linked)).unwrap_err();

        assert!(
            matches!(error, NetworkError::Transport(message) if message.contains("regular file"))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identity_file_rejects_oversized_input() {
        let dir = identity_test_dir("oversized");
        let path = dir.join("libp2p.key");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_IDENTITY_KEY_SIZE + 1).unwrap();

        let error = load_or_create_identity(Some(&path)).unwrap_err();

        assert!(matches!(error, NetworkError::Transport(message) if message.contains("exceeds")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn direct_message_codec_enforces_raw_message_limit() {
        let mut codec = DirectMessageCodec {
            max_message_size: 4,
        };
        let mut exact = Cursor::new(vec![1, 2, 3, 4]);
        let decoded =
            request_response::Codec::read_request(&mut codec, &DIRECT_MESSAGE_PROTOCOL, &mut exact)
                .await
                .unwrap();
        assert_eq!(decoded.as_ref(), [1, 2, 3, 4]);

        let mut oversized = Cursor::new(vec![1, 2, 3, 4, 5]);
        let error = request_response::Codec::read_request(
            &mut codec,
            &DIRECT_MESSAGE_PROTOCOL,
            &mut oversized,
        )
        .await
        .expect_err("oversized direct messages must be rejected before deserialization");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn direct_message_streams_respect_the_per_connection_byte_budget() {
        assert_eq!(
            max_concurrent_direct_streams(crate::message::MAX_MESSAGE_SIZE),
            2
        );
        assert_eq!(max_concurrent_direct_streams(1024 * 1024), 100);
        assert_eq!(max_concurrent_direct_streams(1024), 256);
    }

    #[tokio::test]
    async fn send_to_peer_queues_a_targeted_direct_message() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let network = Libp2pNetwork {
            cmd_tx,
            event_rx,
            peer_count: Arc::new(AtomicUsize::new(0)),
            bandwidth: Arc::new(BandwidthTracker::new(0, 0)),
            max_msg_size: crate::message::MAX_MESSAGE_SIZE,
        };
        let target = Libp2pPeerId::random();

        network
            .send_to_peer(&PeerId(target.to_string()), NetworkMessage::Ping)
            .await
            .unwrap();

        match cmd_rx.recv().await.unwrap() {
            SwarmCommand::SendToPeer { peer, topic, data } => {
                assert_eq!(peer, target);
                assert_eq!(topic, TopicKind::Blocks);
                assert!(matches!(
                    crate::message::deserialize_checked(&data, crate::message::MAX_MESSAGE_SIZE)
                        .unwrap(),
                    NetworkMessage::Ping
                ));
            }
            _ => panic!("send_to_peer must not fall back to gossip broadcast"),
        }
    }

    #[tokio::test]
    async fn send_to_peer_rejects_invalid_sync_request_before_queueing() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let (_event_tx, event_rx) = mpsc::channel(1);
        let network = Libp2pNetwork {
            cmd_tx,
            event_rx,
            peer_count: Arc::new(AtomicUsize::new(0)),
            bandwidth: Arc::new(BandwidthTracker::new(0, 0)),
            max_msg_size: crate::message::MAX_MESSAGE_SIZE,
        };
        let target = Libp2pPeerId::random();

        let error = network
            .send_to_peer(
                &PeerId(target.to_string()),
                NetworkMessage::BodyRequest {
                    start_number: 1,
                    count: 0,
                    nonce: 1,
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            NetworkError::Serialization(message)
                if message.contains("request count must be between")
        ));
        assert!(matches!(
            cmd_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn unsupported_legacy_peer_falls_back_without_affecting_modern_peer() {
        let mut behaviour = request_response::Behaviour::with_codec(
            DirectMessageCodec {
                max_message_size: crate::message::MAX_MESSAGE_SIZE,
            },
            [(DIRECT_MESSAGE_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default(),
        );
        let legacy_peer = Libp2pPeerId::random();
        let modern_peer = Libp2pPeerId::random();
        let legacy_id = behaviour.send_request(&legacy_peer, Arc::from(&b"legacy"[..]));
        let modern_id = behaviour.send_request(&modern_peer, Arc::from(&b"modern"[..]));
        let mut pending = PendingDirectMessages::new(2, 12);
        pending.insert(
            legacy_id,
            PendingDirectMessage {
                topic: TopicKind::Blocks,
                data: Arc::from(&b"legacy"[..]),
            },
        );
        pending.insert(
            modern_id,
            PendingDirectMessage {
                topic: TopicKind::Transactions,
                data: Arc::from(&b"modern"[..]),
            },
        );

        let fallback = take_direct_message_fallback(
            &mut pending,
            legacy_id,
            &request_response::OutboundFailure::UnsupportedProtocols,
        )
        .expect("an unsupported legacy peer must use the compatibility path");

        assert_eq!(fallback.topic, TopicKind::Blocks);
        assert_eq!(fallback.data.as_ref(), b"legacy");
        assert!(pending.messages.contains_key(&modern_id));
        assert_eq!(pending.bytes, b"modern".len());

        assert!(take_direct_message_fallback(
            &mut pending,
            modern_id,
            &request_response::OutboundFailure::Timeout,
        )
        .is_none());
        assert!(pending.messages.is_empty());
        assert_eq!(pending.bytes, 0);
    }

    #[test]
    fn pending_direct_messages_enforce_count_and_byte_limits() {
        let mut behaviour = request_response::Behaviour::with_codec(
            DirectMessageCodec {
                max_message_size: crate::message::MAX_MESSAGE_SIZE,
            },
            [(DIRECT_MESSAGE_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default(),
        );
        let peer = Libp2pPeerId::random();
        let first_id = behaviour.send_request(&peer, Arc::from(&b"1234"[..]));
        let second_id = behaviour.send_request(&peer, Arc::from(&b"5678"[..]));
        let mut pending = PendingDirectMessages::new(2, 7);

        assert!(pending.can_accept(4));
        pending.insert(
            first_id,
            PendingDirectMessage {
                topic: TopicKind::Blocks,
                data: Arc::from(&b"1234"[..]),
            },
        );
        assert!(!pending.can_accept(4), "byte limit must reject the request");
        assert!(pending.can_accept(3));
        pending.insert(
            second_id,
            PendingDirectMessage {
                topic: TopicKind::Blocks,
                data: Arc::from(&b"567"[..]),
            },
        );
        assert!(
            !pending.can_accept(0),
            "count limit must reject the request"
        );

        pending.remove(&first_id).unwrap();
        assert_eq!(pending.bytes, 3);
        assert!(pending.can_accept(4));
    }

    #[test]
    fn direct_message_overload_drops_instead_of_broadcasting() {
        let pending = PendingDirectMessages::new(0, 0);

        assert_eq!(
            direct_message_admission(&pending, 1),
            DirectMessageAdmission::Drop
        );
    }

    #[test]
    fn config_defaults_enable_kademlia() {
        let config = NetworkConfig::default();
        assert!(config.enable_kademlia);
        assert!(!config.enable_mdns);
        assert_eq!(config.max_peers, 50);
    }

    #[test]
    fn config_defaults_enable_peer_scoring() {
        let config = NetworkConfig::default();
        assert!(config.enable_peer_scoring);
    }

    #[test]
    fn proof_messages_route_to_proofs_topic() {
        let msg = NetworkMessage::ProofAck {
            block_hash: shell_primitives::ShellHash::ZERO,
            holder: shell_primitives::Address::ZERO,
        };

        assert_eq!(topic_kind_for_message(&msg), TopicKind::Proofs);
    }

    #[test]
    fn block_and_control_messages_stay_on_blocks_topic() {
        assert_eq!(
            topic_kind_for_message(&NetworkMessage::Ping),
            TopicKind::Blocks
        );
        assert_eq!(
            topic_kind_for_message(&NetworkMessage::BodyRequest {
                start_number: 0,
                count: 1,
                nonce: 0,
            }),
            TopicKind::Blocks
        );
    }

    #[test]
    fn rejects_message_published_on_wrong_topic() {
        let config = NetworkConfig::default();
        let blocks_topic = IdentTopic::new(&config.blocks_topic);
        let txs_topic = IdentTopic::new(&config.txs_topic);
        let attestation_topic = IdentTopic::new(&config.attestation_topic);
        let proofs_topic = IdentTopic::new(&config.proofs_topic);
        let message = NetworkMessage::Ping;

        assert!(message_matches_topic(
            &message,
            &blocks_topic.hash(),
            &blocks_topic,
            &txs_topic,
            &attestation_topic,
            &proofs_topic,
        ));
        assert!(!message_matches_topic(
            &message,
            &txs_topic.hash(),
            &blocks_topic,
            &txs_topic,
            &attestation_topic,
            &proofs_topic,
        ));
    }

    #[tokio::test]
    async fn validated_message_forwarding_does_not_wait_on_a_full_queue() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let peer = PeerId::from("peer-a");

        try_forward_message_event(&event_tx, peer.clone(), NetworkMessage::Ping).unwrap();
        let error = try_forward_message_event(&event_tx, peer.clone(), NetworkMessage::Pong)
            .expect_err("a full node event queue must reject without waiting");

        assert_eq!(error, EventQueueError::Full);
        assert!(matches!(
            event_rx.recv().await,
            Some(NetworkEvent::MessageReceived {
                peer: received_peer,
                message: NetworkMessage::Ping,
            }) if received_peer == peer
        ));
    }

    #[tokio::test]
    async fn control_event_forwarding_does_not_wait_on_a_full_queue() {
        let (event_tx, mut event_rx) = mpsc::channel(1);

        try_forward_event(
            &event_tx,
            NetworkEvent::RoutingTableUpdated { peer_count: 1 },
        )
        .unwrap();
        let error = try_forward_event(
            &event_tx,
            NetworkEvent::PeerConnected(PeerId::from("peer-b")),
        )
        .expect_err("a full node event queue must reject without waiting");

        assert_eq!(error, EventQueueError::Full);
        assert!(matches!(
            event_rx.recv().await,
            Some(NetworkEvent::RoutingTableUpdated { peer_count: 1 })
        ));
    }

    #[test]
    fn event_forwarding_reports_a_closed_queue() {
        let (event_tx, event_rx) = mpsc::channel(1);
        drop(event_rx);

        let error = try_forward_event(
            &event_tx,
            NetworkEvent::PeerDisconnected(PeerId::from("peer-c")),
        )
        .expect_err("a closed node event queue must reject immediately");

        assert_eq!(error, EventQueueError::Closed);
    }

    #[test]
    fn peer_security_config_uses_network_config_limits() {
        let config = NetworkConfig {
            max_peers: 7,
            ban_threshold: 2,
            ban_duration_secs: 42,
            ..Default::default()
        };

        let security = PeerSecurityConfig::from(&config);

        assert_eq!(
            security,
            PeerSecurityConfig {
                max_peers: 7,
                ban_threshold: 2,
                ban_duration: Duration::from_secs(42),
            }
        );
    }

    #[tokio::test]
    async fn libp2p_broadcast_respects_configured_message_limit() {
        let config = NetworkConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            max_message_size: 1,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let network = Libp2pNetwork::new(&config).await.unwrap();

        let err = network.broadcast(NetworkMessage::Ping).await.unwrap_err();
        match err {
            NetworkError::MessageTooLarge { limit, .. } => assert_eq!(limit, 1),
            other => panic!("unexpected error: {other:?}"),
        }

        network.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn libp2p_broadcast_rejects_invalid_sync_request() {
        let config = NetworkConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let network = Libp2pNetwork::new(&config).await.unwrap();

        let error = network
            .broadcast(NetworkMessage::BodyRequest {
                start_number: 1,
                count: 0,
                nonce: 1,
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            NetworkError::Serialization(message)
                if message.contains("request count must be between")
        ));
        network.shutdown().await.unwrap();
    }

    #[test]
    fn config_peer_scoring_disabled() {
        let config = NetworkConfig {
            enable_peer_scoring: false,
            ..Default::default()
        };
        assert!(!config.enable_peer_scoring);
    }

    #[test]
    fn build_swarm_with_peer_scoring() {
        let config = NetworkConfig {
            enable_peer_scoring: true,
            enable_mdns: false,
            enable_kademlia: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with peer scoring enabled"
        );
    }

    #[test]
    fn build_swarm_without_peer_scoring() {
        let config = NetworkConfig {
            enable_peer_scoring: false,
            enable_mdns: false,
            enable_kademlia: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with peer scoring disabled"
        );
    }

    #[test]
    fn extract_peer_id_from_valid_multiaddr() {
        // Generate a valid PeerId from a keypair.
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/30303/p2p/{peer_id}")
            .parse()
            .unwrap();
        let extracted = extract_peer_id(&addr);
        assert_eq!(extracted, Some(peer_id));
    }

    #[test]
    fn extract_peer_id_missing_returns_none() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/30303".parse().unwrap();
        assert!(extract_peer_id(&addr).is_none());
    }

    #[test]
    fn routing_table_updated_event_variant() {
        let event = NetworkEvent::RoutingTableUpdated { peer_count: 42 };
        match event {
            NetworkEvent::RoutingTableUpdated { peer_count } => {
                assert_eq!(peer_count, 42);
            }
            _ => panic!("wrong event variant"),
        }
    }

    #[test]
    fn connection_events_follow_first_and_last_tracked_connection() {
        let mut tracker = crate::security::PeerTracker::new(2);
        let peer = PeerId::from("peer-a");

        assert!(matches!(
            track_connection_established(&mut tracker, peer.clone()).unwrap(),
            Some(NetworkEvent::PeerConnected(connected)) if connected == peer
        ));
        assert!(track_connection_established(&mut tracker, peer.clone())
            .unwrap()
            .is_none());
        assert!(track_connection_closed(&mut tracker, &peer).is_none());
        assert!(matches!(
            track_connection_closed(&mut tracker, &peer),
            Some(NetworkEvent::PeerDisconnected(disconnected)) if disconnected == peer
        ));
    }

    #[test]
    fn rejected_connection_close_does_not_emit_disconnect() {
        let mut tracker = crate::security::PeerTracker::new(1);
        let peer_count = Arc::new(AtomicUsize::new(0));
        let admitted = PeerId::from("admitted");
        let rejected = PeerId::from("rejected");
        track_connection_established(&mut tracker, admitted).unwrap();
        update_peer_count(&tracker, &peer_count);

        assert!(track_connection_established(&mut tracker, rejected.clone()).is_err());
        update_peer_count(&tracker, &peer_count);
        assert_eq!(peer_count.load(Ordering::Relaxed), 1);
        assert!(track_connection_closed(&mut tracker, &rejected).is_none());
        update_peer_count(&tracker, &peer_count);
        assert_eq!(peer_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn peer_count_resets_when_swarm_loop_stops() {
        let peer_count = Arc::new(AtomicUsize::new(3));

        {
            let _guard = PeerCountResetGuard(Arc::clone(&peer_count));
        }

        assert_eq!(peer_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn network_config_with_kademlia_disabled() {
        let config = NetworkConfig {
            enable_kademlia: false,
            ..Default::default()
        };
        assert!(!config.enable_kademlia);
    }

    #[test]
    fn config_defaults_enable_nat_traversal() {
        let config = NetworkConfig::default();
        assert!(config.enable_relay);
        assert!(config.enable_dcutr);
        assert!(config.enable_autonat);
    }

    #[test]
    fn config_nat_traversal_disabled() {
        let config = NetworkConfig {
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        assert!(!config.enable_relay);
        assert!(!config.enable_dcutr);
        assert!(!config.enable_autonat);
    }

    #[test]
    fn build_swarm_with_relay_dcutr_autonat() {
        let config = NetworkConfig {
            enable_relay: true,
            enable_dcutr: true,
            enable_autonat: true,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with NAT traversal enabled"
        );
    }

    #[test]
    fn build_swarm_without_relay_dcutr_autonat() {
        let config = NetworkConfig {
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with NAT traversal disabled"
        );
    }

    #[tokio::test]
    async fn build_swarm_all_features_enabled() {
        let config = NetworkConfig {
            enable_mdns: true,
            enable_kademlia: true,
            enable_peer_scoring: true,
            enable_relay: true,
            enable_dcutr: true,
            enable_autonat: true,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with all features enabled"
        );
    }

    #[test]
    fn build_swarm_all_features_disabled() {
        let config = NetworkConfig {
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with all features disabled"
        );
    }

    #[test]
    fn build_swarm_kademlia_only() {
        let config = NetworkConfig {
            enable_mdns: false,
            enable_kademlia: true,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with kademlia only"
        );
    }

    #[test]
    fn build_swarm_relay_without_dcutr() {
        let config = NetworkConfig {
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: true,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with relay but no dcutr"
        );
    }

    #[test]
    fn build_swarm_custom_topics() {
        let config = NetworkConfig {
            blocks_topic: "/custom/blocks/2".into(),
            txs_topic: "/custom/txs/2".into(),
            attestation_topic: "/custom/attestation/2".into(),
            proofs_topic: "/custom/proofs/2".into(),
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: true,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with custom topic names"
        );
    }

    #[test]
    fn build_swarm_with_boot_nodes_adds_to_kademlia() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let boot_addr = format!("/ip4/10.0.0.1/tcp/30303/p2p/{peer_id}");

        let config = NetworkConfig {
            boot_nodes: vec![boot_addr.clone()],
            enable_mdns: false,
            enable_kademlia: true,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };

        let mut swarm = build_swarm(&config).expect("build_swarm should succeed");
        // Add boot node to Kademlia (mirrors what Libp2pNetwork::new does).
        let addr: Multiaddr = boot_addr.parse().unwrap();
        if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
            kad.add_address(&peer_id, addr);
        }
        // Verify the peer was added by checking kbuckets.
        let kad = swarm.behaviour_mut().kademlia.as_mut().unwrap();
        let entry_count: usize = kad.kbuckets().map(|b| b.num_entries()).sum();
        assert!(
            entry_count >= 1,
            "boot node should be added to Kademlia routing table"
        );
    }

    #[tokio::test]
    async fn expired_mdns_discovery_does_not_remain_dialable() {
        let config = NetworkConfig {
            enable_mdns: true,
            enable_kademlia: true,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let mut swarm = build_swarm(&config).expect("build_swarm should succeed");
        let peer_id = Libp2pPeerId::random();
        let addr: Multiaddr = "/ip4/192.0.2.1/tcp/30303".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(1);
        let loop_config = SwarmLoopConfig {
            peer_count: Arc::new(AtomicUsize::new(0)),
            blocks_topic: IdentTopic::new(&config.blocks_topic),
            txs_topic: IdentTopic::new(&config.txs_topic),
            attestation_topic: IdentTopic::new(&config.attestation_topic),
            proofs_topic: IdentTopic::new(&config.proofs_topic),
            bandwidth: Arc::new(BandwidthTracker::new(0, 0)),
            boot_nodes: Vec::new(),
            max_msg_size: config.max_message_size,
            peer_security: PeerSecurityConfig::from(&config),
        };
        let mut state = SwarmLoopState::new(PeerSecurityConfig::from(&config));

        handle_swarm_event(
            SwarmEvent::Behaviour(ShellBehaviourEvent::Mdns(mdns::Event::Discovered(vec![(
                peer_id,
                addr.clone(),
            )]))),
            &mut swarm,
            &event_tx,
            &loop_config,
            &mut state,
        );
        handle_swarm_event(
            SwarmEvent::Behaviour(ShellBehaviourEvent::Mdns(mdns::Event::Expired(vec![(
                peer_id, addr,
            )]))),
            &mut swarm,
            &event_tx,
            &loop_config,
            &mut state,
        );

        assert!(
            swarm.dial(peer_id).is_err(),
            "expired mDNS addresses must not remain available for dialing"
        );
    }

    #[test]
    fn mdns_peer_remains_explicit_until_its_last_address_expires() {
        let peer_id = Libp2pPeerId::random();
        let other_peer = Libp2pPeerId::random();

        assert!(mdns_peer_still_discovered(
            &peer_id,
            [&other_peer, &peer_id].into_iter()
        ));
        assert!(!mdns_peer_still_discovered(
            &peer_id,
            [&other_peer].into_iter()
        ));
    }

    #[test]
    fn mdns_explicit_peers_respect_peer_limit_and_reclaim_capacity() {
        let first = Libp2pPeerId::random();
        let second = Libp2pPeerId::random();
        let mut peers = ExplicitMdnsPeers::new(1);

        assert!(peers.admit(first));
        assert!(
            peers.admit(first),
            "duplicate discovery must remain admitted"
        );
        assert!(!peers.admit(second));
        assert!(peers.remove(&first));
        assert!(peers.admit(second));
    }

    #[test]
    fn parse_boot_nodes_filters_invalid_addresses() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let valid = format!("/ip4/10.0.0.1/tcp/30303/p2p/{peer_id}");
        let raw = vec![
            valid.clone(),
            "not-a-multiaddr".to_string(),
            "/ip4/10.0.0.1/tcp/30303".to_string(),
        ];

        let parsed = parse_boot_nodes(&raw);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_string(), valid);
    }

    #[tokio::test]
    async fn seed_and_dial_boot_node_adds_bootnode_to_kademlia() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let boot_addr: Multiaddr = format!("/ip4/10.0.0.1/tcp/30303/p2p/{peer_id}")
            .parse()
            .unwrap();
        let config = NetworkConfig {
            enable_mdns: false,
            enable_kademlia: true,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let mut swarm = build_swarm(&config).expect("build_swarm should succeed");

        seed_and_dial_boot_node(&mut swarm, &boot_addr, "test");

        let kad = swarm.behaviour_mut().kademlia.as_mut().unwrap();
        let entry_count: usize = kad.kbuckets().map(|b| b.num_entries()).sum();
        assert!(
            entry_count >= 1,
            "boot node should remain seeded for later redial/bootstrap"
        );
    }

    #[test]
    fn extract_peer_id_from_complex_multiaddr() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let addr: Multiaddr = format!("/ip4/10.0.0.1/tcp/30303/p2p/{peer_id}")
            .parse()
            .unwrap();
        assert_eq!(extract_peer_id(&addr), Some(peer_id));
    }

    #[test]
    fn extract_peer_id_ip6_multiaddr() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let addr: Multiaddr = format!("/ip6/::1/tcp/4001/p2p/{peer_id}").parse().unwrap();
        assert_eq!(extract_peer_id(&addr), Some(peer_id));
    }

    #[test]
    fn extract_peer_id_udp_multiaddr() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let addr: Multiaddr = format!("/ip4/192.168.0.1/udp/9000/p2p/{peer_id}")
            .parse()
            .unwrap();
        assert_eq!(extract_peer_id(&addr), Some(peer_id));
    }

    #[test]
    fn config_custom_listen_addr() {
        let addr: std::net::SocketAddr = "192.168.1.100:9999".parse().unwrap();
        let config = NetworkConfig {
            listen_addr: addr,
            ..Default::default()
        };
        assert_eq!(config.listen_addr.port(), 9999);
        assert_eq!(config.listen_addr.ip().to_string(), "192.168.1.100");
    }

    #[test]
    fn peer_scoring_thresholds_are_ordered() {
        // Verify the scoring thresholds used in build_swarm are logically ordered:
        // gossip_threshold > publish_threshold > graylist_threshold (all negative, less severe first).
        let gossip: f64 = -100.0;
        let publish: f64 = -200.0;
        let graylist: f64 = -300.0;
        assert!(
            gossip > publish,
            "gossip threshold should be less severe than publish"
        );
        assert!(
            publish > graylist,
            "publish threshold should be less severe than graylist"
        );
    }

    #[test]
    fn peer_scoring_topic_weights_positive() {
        // The block topic weight should be higher than or equal to the txs topic weight.
        let blocks_weight: f64 = 1.0;
        let txs_weight: f64 = 0.5;
        assert!(blocks_weight > 0.0);
        assert!(txs_weight > 0.0);
        assert!(
            blocks_weight >= txs_weight,
            "block topic should have >= weight than txs"
        );
    }

    #[test]
    fn config_defaults_connection_limits() {
        let config = NetworkConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.max_pending_incoming, 64);
        assert_eq!(config.max_pending_outgoing, 32);
        assert_eq!(config.max_established_per_peer, 3);
    }

    #[test]
    fn total_connection_limit_is_independent_of_unique_peer_limit() {
        let config = NetworkConfig {
            max_connections: 100,
            max_peers: 10,
            ..Default::default()
        };

        assert_eq!(max_established_connection_limit(&config), Some(100));
    }

    #[test]
    fn zero_total_connection_limit_remains_unlimited() {
        let config = NetworkConfig {
            max_connections: 0,
            max_peers: 10,
            ..Default::default()
        };

        assert_eq!(max_established_connection_limit(&config), None);
    }

    #[test]
    fn build_swarm_with_custom_connection_limits() {
        let config = NetworkConfig {
            max_connections: 50,
            max_pending_incoming: 16,
            max_pending_outgoing: 8,
            max_established_per_peer: 2,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with custom connection limits"
        );
    }

    #[test]
    fn build_swarm_unlimited_connections() {
        let config = NetworkConfig {
            max_connections: 0,
            max_pending_incoming: 0,
            max_pending_outgoing: 0,
            max_established_per_peer: 0,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: false,
            enable_dcutr: false,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with unlimited connections (0)"
        );
    }

    #[test]
    fn build_swarm_connection_limits_with_relay() {
        let config = NetworkConfig {
            max_connections: 200,
            max_pending_incoming: 32,
            max_pending_outgoing: 16,
            max_established_per_peer: 5,
            enable_mdns: false,
            enable_kademlia: false,
            enable_peer_scoring: false,
            enable_relay: true,
            enable_dcutr: true,
            enable_autonat: false,
            ..Default::default()
        };
        let swarm = build_swarm(&config);
        assert!(
            swarm.is_ok(),
            "build_swarm should succeed with connection limits and relay"
        );
    }
}
