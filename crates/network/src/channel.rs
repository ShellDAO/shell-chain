//! Channel-based in-process network for testing and single-node operation.
//!
//! Uses tokio broadcast channels to simulate gossip between nodes
//! running in the same process. Ideal for integration tests and
//! local development without real TCP connections.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, Notify};

use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::message::{NetworkEvent, NetworkMessage, PeerId};
use crate::service::NetworkService;

/// Shared broadcast bus that multiple `ChannelNetwork` instances connect to.
pub struct NetworkBus {
    tx: broadcast::Sender<(PeerId, Vec<u8>)>,
    next_peer_id: Arc<AtomicUsize>,
    peer_counts: Arc<PeerCountState>,
}

struct PeerCountState {
    live_peers: AtomicUsize,
    handles: Mutex<Vec<Weak<AtomicUsize>>>,
}

impl PeerCountState {
    fn new() -> Self {
        Self {
            live_peers: AtomicUsize::new(0),
            handles: Mutex::new(Vec::new()),
        }
    }

    fn register(&self, connected_peer_count: &Arc<AtomicUsize>) {
        let live_peers = self.live_peers.fetch_add(1, Ordering::Relaxed) + 1;
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        handles.push(Arc::downgrade(connected_peer_count));
        Self::refresh_handles(&mut handles, live_peers);
    }

    fn unregister(&self) {
        let live_peers = self
            .live_peers
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_sub(1)
            })
            .map(|previous| previous - 1)
            .unwrap_or(0);
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        Self::refresh_handles(&mut handles, live_peers);
    }

    fn connected_peers(&self) -> usize {
        self.live_peers.load(Ordering::Relaxed).saturating_sub(1)
    }

    fn refresh_handles(handles: &mut Vec<Weak<AtomicUsize>>, live_peers: usize) {
        let connected_peers = live_peers.saturating_sub(1);
        handles.retain(|handle| {
            if let Some(handle) = handle.upgrade() {
                handle.store(connected_peers, Ordering::Relaxed);
                true
            } else {
                false
            }
        });
    }
}

impl NetworkBus {
    /// Create a new bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self {
            tx,
            next_peer_id: Arc::new(AtomicUsize::new(0)),
            peer_counts: Arc::new(PeerCountState::new()),
        }
    }

    /// Create a `ChannelNetwork` node connected to this bus.
    pub fn join(&self, config: &NetworkConfig) -> ChannelNetwork {
        let id = self.next_peer_id.fetch_add(1, Ordering::Relaxed);
        let peer_id = PeerId(format!("local-{id}"));
        let rx = self.tx.subscribe();
        let (event_tx, event_rx) = mpsc::channel(256);
        let bus_tx = self.tx.clone();
        let running = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(Notify::new());
        let max_msg_size = config.effective_max_message_size();
        let connected_peer_count = Arc::new(AtomicUsize::new(0));
        self.peer_counts.register(&connected_peer_count);

        // Background task: convert broadcast messages into NetworkEvents.
        let my_id = peer_id.clone();
        let is_running = Arc::clone(&running);
        let task_shutdown = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let mut rx = rx;
            while is_running.load(Ordering::Relaxed) {
                let received = tokio::select! {
                    biased;
                    _ = task_shutdown.notified() => break,
                    received = rx.recv() => received,
                };
                match received {
                    Ok((sender, data)) => {
                        // Skip own messages.
                        if sender == my_id {
                            continue;
                        }
                        // F-069: validate the raw payload and decoded message kind.
                        if let Ok(message) =
                            crate::message::deserialize_checked(&data, max_msg_size)
                        {
                            let event = NetworkEvent::MessageReceived {
                                peer: sender,
                                message,
                            };
                            tokio::select! {
                                biased;
                                _ = task_shutdown.notified() => break,
                                result = event_tx.send(event) => {
                                    if result.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("channel-network: lagged {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        ChannelNetwork {
            peer_id,
            bus_tx,
            event_rx,
            running,
            shutdown,
            peer_counts: Arc::clone(&self.peer_counts),
            connected_peer_count,
            max_msg_size,
        }
    }
}

/// In-process network node connected via broadcast channels.
pub struct ChannelNetwork {
    peer_id: PeerId,
    bus_tx: broadcast::Sender<(PeerId, Vec<u8>)>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    running: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    peer_counts: Arc<PeerCountState>,
    connected_peer_count: Arc<AtomicUsize>,
    max_msg_size: usize,
}

impl ChannelNetwork {
    /// Returns this node's peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

#[async_trait]
impl NetworkService for ChannelNetwork {
    async fn broadcast(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        let data = crate::message::serialize_checked(&msg, self.max_msg_size)?;
        self.bus_tx
            .send((self.peer_id.clone(), data))
            .map_err(|_| NetworkError::ChannelClosed)?;
        Ok(())
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    async fn peer_count(&self) -> usize {
        self.peer_counts.connected_peers()
    }

    fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.connected_peer_count)
    }

    async fn shutdown(&self) -> Result<(), NetworkError> {
        if self
            .running
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.peer_counts.unregister();
            self.shutdown.notify_one();
        }
        Ok(())
    }
}

impl Drop for ChannelNetwork {
    fn drop(&mut self) {
        if self
            .running
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.peer_counts.unregister();
            self.shutdown.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::{Block, BlockHeader, SignedTransaction, Transaction};
    use shell_crypto::PQSignature;
    use shell_primitives::{Address, Bytes, ShellHash, U256};
    use tokio::time::{timeout, Duration};

    fn test_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                parent_hash: ShellHash::default(),
                state_root: ShellHash::default(),
                transactions_root: ShellHash::default(),
                receipts_root: ShellHash::default(),
                logs_bloom: Bytes::default(),
                number,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000 + number,
                extra_data: Bytes::default(),
                proposer: Address::from_public_key(b"test-proposer", 0),
                sig_aggregate_proof: None,
                base_fee_per_gas: 0,
                withdrawals_root: ShellHash::ZERO,
                parent_beacon_block_root: ShellHash::ZERO,
                blob_gas_used: 0,
                excess_blob_gas: 0,
                witness_root: None,
            },
            transactions: vec![],
            system_transactions: vec![],
            proposer_seal: None,
        }
    }

    fn test_transaction(data_size: usize) -> SignedTransaction {
        SignedTransaction::new(
            Address::from_public_key(b"sender-key", 0),
            Transaction {
                chain_id: 1,
                nonce: 0,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
                gas_limit: 21_000,
                to: None,
                value: U256::ZERO,
                data: Bytes::from(vec![0xAA; data_size]),
                access_list: None,
                tx_type: 2,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            },
            PQSignature::new(shell_crypto::SignatureType::Dilithium3, vec![]),
        )
    }

    #[tokio::test]
    async fn two_nodes_exchange_block() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();

        let node_a = bus.join(&config);
        let mut node_b = bus.join(&config);

        let block = test_block(1);
        node_a
            .broadcast(NetworkMessage::NewBlock(Box::new(block.clone())))
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(1), node_b.next_event())
            .await
            .expect("timeout")
            .expect("no event");

        match event {
            NetworkEvent::MessageReceived { message, .. } => match message {
                NetworkMessage::NewBlock(b) => {
                    assert_eq!(b.header.number, 1);
                }
                other => panic!("unexpected message: {:?}", other),
            },
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn zero_capacity_bus_remains_usable() {
        let bus = NetworkBus::new(0);
        let config = NetworkConfig::default();
        let node_a = bus.join(&config);
        let mut node_b = bus.join(&config);

        node_a.broadcast(NetworkMessage::Ping).await.unwrap();

        let event = timeout(Duration::from_secs(1), node_b.next_event())
            .await
            .expect("timeout")
            .expect("no event");
        assert!(matches!(
            event,
            NetworkEvent::MessageReceived {
                message: NetworkMessage::Ping,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn node_does_not_receive_own_messages() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();

        let mut node_a = bus.join(&config);

        node_a.broadcast(NetworkMessage::Ping).await.unwrap();

        let result = timeout(Duration::from_millis(100), node_a.next_event()).await;
        assert!(result.is_err(), "should not receive own message");
    }

    #[tokio::test]
    async fn broadcast_respects_configured_message_limit() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig {
            max_message_size: 1,
            ..NetworkConfig::default()
        };

        let node = bus.join(&config);

        let err = node.broadcast(NetworkMessage::Ping).await.unwrap_err();
        match err {
            NetworkError::MessageTooLarge { limit, .. } => assert_eq!(limit, 1),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn configured_limit_cannot_raise_raw_message_ceiling() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig {
            max_message_size: usize::MAX,
            ..NetworkConfig::default()
        };

        let node = bus.join(&config);

        assert_eq!(node.max_msg_size, crate::message::MAX_MESSAGE_SIZE);
    }

    #[tokio::test]
    async fn broadcast_rejects_invalid_sync_request() {
        let bus = NetworkBus::new(64);
        let node = bus.join(&NetworkConfig::default());

        let error = node
            .broadcast(NetworkMessage::BlockRequest {
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
    }

    #[tokio::test]
    async fn inbound_rejects_variant_specific_oversized_messages() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();
        let mut node_b = bus.join(&config);

        let tx = test_transaction(crate::message::MAX_TX_GOSSIP_SIZE + 1);
        let data = serde_json::to_vec(&NetworkMessage::NewTransaction(Box::new(tx))).unwrap();
        assert!(data.len() < crate::message::MAX_MESSAGE_SIZE);

        bus.tx.send((PeerId::from("external"), data)).unwrap();

        let result = timeout(Duration::from_millis(100), node_b.next_event()).await;
        assert!(
            result.is_err(),
            "oversized transaction gossip should be dropped"
        );
    }

    #[tokio::test]
    async fn peer_count() {
        let bus = NetworkBus::new(16);
        let config = NetworkConfig::default();

        let n1 = bus.join(&config);
        let _n2 = bus.join(&config);
        let _n3 = bus.join(&config);

        assert_eq!(n1.peer_count().await, 2);
    }

    #[tokio::test]
    async fn peer_count_handle_excludes_self() {
        let bus = NetworkBus::new(16);
        let config = NetworkConfig::default();

        let n1 = bus.join(&config);
        let handle = n1.peer_count_handle();
        assert_eq!(handle.load(Ordering::Relaxed), 0);

        let _n2 = bus.join(&config);
        assert_eq!(handle.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn peer_count_updates_after_shutdown_and_drop() {
        let bus = NetworkBus::new(16);
        let config = NetworkConfig::default();

        let n1 = bus.join(&config);
        let n2 = bus.join(&config);
        let n3 = bus.join(&config);
        let handle = n1.peer_count_handle();

        assert_eq!(n1.peer_count().await, 2);
        assert_eq!(handle.load(Ordering::Relaxed), 2);

        n2.shutdown().await.unwrap();
        assert_eq!(n1.peer_count().await, 1);
        assert_eq!(handle.load(Ordering::Relaxed), 1);

        drop(n3);
        assert_eq!(n1.peer_count().await, 0);
        assert_eq!(handle.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn shutdown_closes_event_stream_without_additional_traffic() {
        let bus = NetworkBus::new(16);
        let config = NetworkConfig::default();
        let mut node = bus.join(&config);

        tokio::task::yield_now().await;
        node.shutdown().await.unwrap();

        let event = timeout(Duration::from_millis(100), node.next_event())
            .await
            .expect("event stream remained open after shutdown");
        assert!(event.is_none());
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_full_event_queue() {
        let bus = NetworkBus::new(512);
        let config = NetworkConfig::default();
        let mut node = bus.join(&config);
        let message = serde_json::to_vec(&NetworkMessage::Ping).unwrap();

        for _ in 0..=256 {
            bus.tx
                .send((PeerId::from("external"), message.clone()))
                .unwrap();
        }
        timeout(Duration::from_secs(1), async {
            while node.event_rx.len() < 256 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("event queue did not fill");

        node.shutdown().await.unwrap();
        for _ in 0..256 {
            assert!(node.next_event().await.is_some());
        }
        let event = timeout(Duration::from_millis(100), node.next_event())
            .await
            .expect("event stream remained open with a full queue after shutdown");
        assert!(event.is_none());
    }

    #[tokio::test]
    async fn broadcast_transaction() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();

        let node_a = bus.join(&config);
        let mut node_b = bus.join(&config);

        let tx = test_transaction(0);

        node_a
            .broadcast(NetworkMessage::NewTransaction(Box::new(tx)))
            .await
            .unwrap();

        let event = timeout(Duration::from_secs(1), node_b.next_event())
            .await
            .expect("timeout")
            .expect("no event");

        match event {
            NetworkEvent::MessageReceived { message, .. } => {
                assert!(matches!(message, NetworkMessage::NewTransaction(_)));
            }
            other => panic!("unexpected: {:?}", other),
        }
    }
}
