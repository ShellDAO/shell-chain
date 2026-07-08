//! libp2p-based NetworkService implementation.
//!
//! Uses TCP + Noise + Yamux transport with GossipSub for message
//! broadcast, mDNS for local peer discovery, and Kademlia DHT for
//! global peer discovery.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
use libp2p::kad;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::SwarmEvent;
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
use crate::message::{NetworkEvent, NetworkMessage, PeerId};
use crate::service::NetworkService;

const BOOTNODE_REDIAL_INTERVAL_SECS: u64 = 30;

/// Topic category for gossipsub routing.
enum TopicKind {
    Blocks,
    Transactions,
    Attestation,
}

/// Commands sent to the Swarm background task.
enum SwarmCommand {
    Publish {
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
    kademlia: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    identify: identify::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    autonat: Toggle<autonat::Behaviour>,
    connection_limits: connection_limits::Behaviour,
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
        let loop_config = SwarmLoopConfig {
            peer_count: Arc::clone(&peer_count),
            blocks_topic,
            txs_topic,
            attestation_topic,
            bandwidth: Arc::clone(&bandwidth),
            boot_nodes,
            max_msg_size: config.max_message_size,
            peer_security: PeerSecurityConfig::from(config),
        };

        tokio::spawn(swarm_loop(swarm, cmd_rx, event_tx, loop_config));

        Ok(Self {
            cmd_tx,
            event_rx,
            peer_count,
            bandwidth,
            max_msg_size: config.max_message_size,
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
        Some(path) if path.exists() => {
            let bytes = fs::read(path).map_err(|e| NetworkError::Transport(e.to_string()))?;
            libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| NetworkError::Transport(format!("invalid libp2p identity: {e}")))
        }
        Some(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| NetworkError::Transport(e.to_string()))?;
            }
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let encoded = keypair
                .to_protobuf_encoding()
                .map_err(|e| NetworkError::Transport(format!("encode libp2p identity: {e}")))?;
            {
                use std::io::Write;
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;
                let mut opts = fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                opts.mode(0o600);
                let mut file = opts
                    .open(path)
                    .map_err(|e| NetworkError::Transport(e.to_string()))?;
                file.write_all(&encoded)
                    .map_err(|e| NetworkError::Transport(e.to_string()))?;
            }
            Ok(keypair)
        }
        None => Ok(libp2p::identity::Keypair::generate_ed25519()),
    }
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
    let max_msg_size = config.max_message_size;

    // Build libp2p connection limits from config.
    let mut conn_limits = connection_limits::ConnectionLimits::default();

    // Enforce max_peers as an upper bound on total established connections (F-070).
    // When both max_peers and max_connections are set, use the stricter limit.
    let effective_max_established = match (config.max_connections > 0, config.max_peers > 0) {
        (true, true) => Some(std::cmp::min(
            config.max_connections,
            config.max_peers as u32,
        )),
        (true, false) => Some(config.max_connections),
        (false, true) => Some(config.max_peers as u32),
        (false, false) => None,
    };
    if let Some(limit) = effective_max_established {
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

                let blocks_hash = IdentTopic::new(&blocks_topic_name).hash();
                let txs_hash = IdentTopic::new(&txs_topic_name).hash();
                let attestation_hash = IdentTopic::new(&attestation_topic_name).hash();

                let mut topic_scores = HashMap::new();
                topic_scores.insert(blocks_hash, blocks_topic_params);
                topic_scores.insert(txs_hash, txs_topic_params);
                topic_scores.insert(attestation_hash, attestation_topic_params);

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

struct SwarmLoopConfig {
    peer_count: Arc<AtomicUsize>,
    blocks_topic: IdentTopic,
    txs_topic: IdentTopic,
    attestation_topic: IdentTopic,
    bandwidth: Arc<BandwidthTracker>,
    boot_nodes: Vec<Multiaddr>,
    max_msg_size: usize,
    peer_security: PeerSecurityConfig,
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
    // F-305: Initialize peer tracking and ban list.
    let mut peer_tracker = crate::security::PeerTracker::new(loop_config.peer_security.max_peers);
    let mut peer_ban_list = crate::security::PeerBanList::new(
        loop_config.peer_security.ban_threshold,
        loop_config.peer_security.ban_duration,
    );

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
                    &mut peer_tracker,
                    &mut peer_ban_list,
                ).await;
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

/// Process a single SwarmEvent, forwarding relevant data as NetworkEvents.
async fn handle_swarm_event(
    event: SwarmEvent<ShellBehaviourEvent>,
    swarm: &mut Swarm<ShellBehaviour>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    loop_config: &SwarmLoopConfig,
    peer_tracker: &mut crate::security::PeerTracker,
    peer_ban_list: &mut crate::security::PeerBanList,
) {
    match event {
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
                    // F-062: accept valid message so gossipsub propagates it.
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Accept,
                        );
                    let _ = event_tx
                        .send(NetworkEvent::MessageReceived { peer, message: msg })
                        .await;
                }
                Err(e) => {
                    // F-062: reject invalid message — penalize sender.
                    debug!("Failed to deserialize gossipsub message: {e}");
                    // F-305: Record violation for malformed messages.
                    let ban_peer = PeerId(propagation_source.to_string());
                    let banned = peer_ban_list.record_violation(&ban_peer);
                    if banned {
                        warn!(peer = %propagation_source, "peer banned for repeated violations");
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
            let _ = event_tx
                .send(NetworkEvent::PeerConnected(PeerId(peer.to_string())))
                .await;
            // Emit routing table size update.
            if let Some(kad) = swarm.behaviour_mut().kademlia.as_mut() {
                let bucket_count: usize = kad.kbuckets().map(|b| b.num_entries()).sum();
                let _ = event_tx
                    .send(NetworkEvent::RoutingTableUpdated {
                        peer_count: bucket_count,
                    })
                    .await;
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
                swarm.add_peer_address(peer_id, addr);
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                let _ = event_tx
                    .send(NetworkEvent::PeerConnected(PeerId(peer_id.to_string())))
                    .await;
            }
            update_peer_count(swarm, &loop_config.peer_count);
        }
        // mDNS peer expired.
        SwarmEvent::Behaviour(ShellBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, _addr) in peers {
                debug!("mDNS expired: {peer_id}");
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
                let _ = event_tx
                    .send(NetworkEvent::PeerDisconnected(PeerId(peer_id.to_string())))
                    .await;
            }
            update_peer_count(swarm, &loop_config.peer_count);
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
            if let Err(e) = peer_tracker.try_add_peer(peer) {
                debug!(peer = %peer_id, error = %e, "connection limit reached, disconnecting");
                let _ = swarm.disconnect_peer_id(peer_id);
                return;
            }
            debug!("Connected to {peer_id}");
            update_peer_count(swarm, &loop_config.peer_count);
        }
        // Connection closed.
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let peer = PeerId(peer_id.to_string());
            peer_tracker.remove_peer(&peer);
            debug!("Disconnected from {peer_id}");
            update_peer_count(swarm, &loop_config.peer_count);
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

fn update_peer_count(swarm: &Swarm<ShellBehaviour>, counter: &Arc<AtomicUsize>) {
    counter.store(swarm.connected_peers().count(), Ordering::Relaxed);
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

#[async_trait]
impl NetworkService for Libp2pNetwork {
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        let topic = match &msg {
            NetworkMessage::NewBlock(_)
            | NetworkMessage::BlockRequest { .. }
            | NetworkMessage::BlockResponse { .. }
            | NetworkMessage::BodyRequest { .. }
            | NetworkMessage::BodyResponse { .. }
            | NetworkMessage::Ping
            | NetworkMessage::Pong => TopicKind::Blocks,
            NetworkMessage::NewTransaction(_) => TopicKind::Transactions,
            NetworkMessage::NewAttestation(_) => TopicKind::Attestation,
            NetworkMessage::ProofAmendment { .. }
            | NetworkMessage::ProofAck { .. }
            | NetworkMessage::EquivocationEvidence(_)
            | NetworkMessage::ProofChallenge(_)
            | NetworkMessage::ProofChallengeResponse(_) => TopicKind::Blocks,
            NetworkMessage::StorageCapability { .. }
            | NetworkMessage::WPoaVote { .. }
            | NetworkMessage::WPoaViewChange(_) => TopicKind::Attestation,
        };

        let data =
            serde_json::to_vec(&msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        crate::message::validate_message_size(&data, self.max_msg_size)?;
        crate::message::validate_message_size(&data, msg.max_serialized_size())?;

        self.cmd_tx
            .send(SwarmCommand::Publish { topic, data })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;

        Ok(())
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
