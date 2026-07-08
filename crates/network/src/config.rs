//! Network configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for the P2P network service.
///
/// # Encryption
///
/// All P2P connections are **already encrypted** via the
/// [Noise protocol](https://noiseprotocol.org/) (libp2p-noise).
/// The Noise handshake is performed on every TCP connection before any
/// application data is exchanged, providing confidentiality and mutual
/// peer authentication via ephemeral Diffie-Hellman keys.
///
/// A separate `libp2p-tls` transport (X.509 over TLS 1.3) can be layered
/// on top of or as an alternative to Noise by enabling the `tls` feature
/// in the `libp2p` dependency.  This is not required for security — Noise
/// already provides equivalent guarantees — but may simplify interop with
/// nodes that mandate TLS-based authentication.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
    /// Bootstrap peer addresses to connect to on startup.
    pub boot_nodes: Vec<String>,
    /// Gossipsub topic name for block announcements.
    pub blocks_topic: String,
    /// Gossipsub topic name for transaction announcements.
    pub txs_topic: String,
    /// Gossipsub topic name for attestation announcements.
    pub attestation_topic: String,
    /// Gossipsub topic name for STARK proof amendment announcements (G5).
    pub proofs_topic: String,
    /// Maximum number of peers to maintain.
    pub max_peers: usize,
    /// Enable mDNS local peer discovery (disable in production/cloud).
    pub enable_mdns: bool,
    /// Enable Kademlia DHT for global peer discovery.
    pub enable_kademlia: bool,
    /// Enable GossipSub peer scoring for block/transaction topics.
    pub enable_peer_scoring: bool,
    /// Enable relay client for NAT traversal (connect through relay nodes).
    pub enable_relay: bool,
    /// Enable DCUtR (Direct Connection Upgrade through Relay) for hole-punching.
    pub enable_dcutr: bool,
    /// Enable autonat for automatic NAT status detection.
    pub enable_autonat: bool,
    /// Maximum number of established connections (0 = unlimited).
    pub max_connections: u32,
    /// Maximum number of pending incoming connections.
    pub max_pending_incoming: u32,
    /// Maximum number of pending outgoing connections.
    pub max_pending_outgoing: u32,
    /// Maximum established connections per single peer (0 = unlimited).
    pub max_established_per_peer: u32,
    /// Maximum inbound bandwidth in bytes/second (0 = unlimited).
    pub max_inbound_bandwidth: u64,
    /// Maximum outbound bandwidth in bytes/second (0 = unlimited).
    pub max_outbound_bandwidth: u64,
    /// F-069: Maximum allowed incoming message size in bytes.
    pub max_message_size: usize,
    /// F-071: Number of violations before a peer is temporarily banned (0 = disabled).
    pub ban_threshold: u32,
    /// F-071: Duration of a temporary ban in seconds.
    pub ban_duration_secs: u64,
    /// Optional path to a persisted libp2p identity keypair.
    pub identity_key_path: Option<PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 30303)),
            boot_nodes: vec![],
            blocks_topic: "/shell/blocks/1".into(),
            txs_topic: "/shell/txs/1".into(),
            attestation_topic: "/shell/attestation/1".into(),
            proofs_topic: "/shell/proofs/1".into(),
            max_peers: 50,
            enable_mdns: false,
            enable_kademlia: true,
            enable_peer_scoring: true,
            enable_relay: true,
            enable_dcutr: true,
            enable_autonat: true,
            max_connections: 100,
            max_pending_incoming: 64,
            max_pending_outgoing: 32,
            max_established_per_peer: 3,
            max_inbound_bandwidth: 0,
            max_outbound_bandwidth: 0,
            max_message_size: 50 * 1024 * 1024, // 50 MiB — PQ sigs (ML-DSA-65 ~3.3 KB each) make blocks large
            ban_threshold: 5,
            ban_duration_secs: 600, // 10 minutes
            identity_key_path: None,
        }
    }
}

/// Validate that a bootnode multiaddr string is well-formed for P2P bootstrap.
///
/// Checks:
/// - Parses as a valid [`libp2p::Multiaddr`]
/// - Contains an address layer (`/ip4/`, `/ip6/`, `/dns/`, `/dns4/`,
///   `/dns6/`, or `/dnsaddr/`)
/// - Contains a TCP or UDP transport layer (`/tcp/` or `/udp/`)
/// - Contains a `/p2p/<peer_id>` component with a valid PeerId
#[cfg(feature = "libp2p")]
pub fn validate_bootnode_multiaddr(addr: &str) -> bool {
    use libp2p::Multiaddr;

    let ma: Multiaddr = match addr.parse() {
        Ok(ma) => ma,
        Err(_) => return false,
    };

    let mut has_address = false;
    let mut has_transport = false;
    let mut has_peer_id = false;

    for proto in ma.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(_)
            | libp2p::multiaddr::Protocol::Ip6(_)
            | libp2p::multiaddr::Protocol::Dns(_)
            | libp2p::multiaddr::Protocol::Dns4(_)
            | libp2p::multiaddr::Protocol::Dns6(_)
            | libp2p::multiaddr::Protocol::Dnsaddr(_) => has_address = true,
            libp2p::multiaddr::Protocol::Tcp(_) | libp2p::multiaddr::Protocol::Udp(_) => {
                has_transport = true;
            }
            libp2p::multiaddr::Protocol::P2p(_) => {
                has_peer_id = true;
            }
            _ => {}
        }
    }

    has_address && has_transport && has_peer_id
}

#[cfg(test)]
#[cfg(feature = "libp2p")]
mod tests {
    use super::*;

    #[test]
    fn valid_ipv4_tcp_multiaddr() {
        let addr =
            "/ip4/1.2.3.4/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn valid_ipv6_tcp_multiaddr() {
        let addr = "/ip6/::1/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn valid_ipv4_udp_multiaddr() {
        let addr =
            "/ip4/10.0.0.1/udp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn valid_dns4_tcp_multiaddr() {
        let addr =
            "/dns4/bootnode.shell.org/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn reject_missing_peer_id() {
        let addr = "/ip4/1.2.3.4/tcp/30303";
        assert!(!validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn reject_missing_ip() {
        let addr = "/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(!validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn reject_missing_transport() {
        let addr = "/ip4/1.2.3.4/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(!validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn reject_garbage_string() {
        assert!(!validate_bootnode_multiaddr("not-a-multiaddr"));
    }

    #[test]
    fn reject_empty_string() {
        assert!(!validate_bootnode_multiaddr(""));
    }

    #[test]
    fn default_config_all_fields() {
        let config = NetworkConfig::default();
        assert_eq!(
            config.listen_addr,
            SocketAddr::from(([127, 0, 0, 1], 30303))
        );
        assert!(config.boot_nodes.is_empty());
        assert_eq!(config.blocks_topic, "/shell/blocks/1");
        assert_eq!(config.txs_topic, "/shell/txs/1");
        assert_eq!(config.attestation_topic, "/shell/attestation/1");
        assert_eq!(config.max_peers, 50);
        assert!(!config.enable_mdns);
        assert!(config.enable_kademlia);
        assert!(config.enable_peer_scoring);
        assert!(config.enable_relay);
        assert!(config.enable_dcutr);
        assert!(config.enable_autonat);
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.max_pending_incoming, 64);
        assert_eq!(config.max_pending_outgoing, 32);
        assert_eq!(config.max_established_per_peer, 3);
        assert_eq!(config.max_inbound_bandwidth, 0);
        assert_eq!(config.max_outbound_bandwidth, 0);
        assert_eq!(config.max_message_size, 50 * 1024 * 1024);
        assert_eq!(config.ban_threshold, 5);
        assert_eq!(config.ban_duration_secs, 600);
    }

    #[test]
    fn reject_only_dns_no_transport() {
        let addr =
            "/dns4/bootnode.example.com/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(!validate_bootnode_multiaddr(addr));
    }

    #[test]
    fn reject_ip4_only() {
        assert!(!validate_bootnode_multiaddr("/ip4/192.168.1.1"));
    }

    #[test]
    fn valid_ipv6_full_addr() {
        let addr =
            "/ip6/2001:db8::1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(validate_bootnode_multiaddr(addr));
    }
}
