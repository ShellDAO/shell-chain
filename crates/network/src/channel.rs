//! Channel-based in-process network for testing and single-node operation.
//!
//! Uses tokio broadcast channels to simulate gossip between nodes
//! running in the same process. Ideal for integration tests and
//! local development without real TCP connections.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::message::{NetworkEvent, NetworkMessage, PeerId};
use crate::service::NetworkService;

/// Shared broadcast bus that multiple `ChannelNetwork` instances connect to.
pub struct NetworkBus {
    tx: broadcast::Sender<(PeerId, Vec<u8>)>,
    peer_counter: Arc<AtomicUsize>,
}

impl NetworkBus {
    /// Create a new bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            peer_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Create a `ChannelNetwork` node connected to this bus.
    pub fn join(&self, config: &NetworkConfig) -> ChannelNetwork {
        let id = self.peer_counter.fetch_add(1, Ordering::Relaxed);
        let peer_id = PeerId(format!("local-{id}"));
        let rx = self.tx.subscribe();
        let (event_tx, event_rx) = mpsc::channel(256);
        let bus_tx = self.tx.clone();
        let running = Arc::new(AtomicBool::new(true));
        let max_msg_size = config.max_message_size;

        // Background task: convert broadcast messages into NetworkEvents.
        let my_id = peer_id.clone();
        let is_running = Arc::clone(&running);
        tokio::spawn(async move {
            let mut rx = rx;
            while is_running.load(Ordering::Relaxed) {
                match rx.recv().await {
                    Ok((sender, data)) => {
                        // Skip own messages.
                        if sender == my_id {
                            continue;
                        }
                        // F-069: validate the raw payload and decoded message kind.
                        if let Ok(message) =
                            crate::message::deserialize_checked(&data, max_msg_size)
                        {
                            let _ = event_tx
                                .send(NetworkEvent::MessageReceived {
                                    peer: sender,
                                    message,
                                })
                                .await;
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
            peer_count: Arc::clone(&self.peer_counter),
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
    peer_count: Arc<AtomicUsize>,
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
        let data =
            serde_json::to_vec(&msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        // F-069: validate outbound message size.
        crate::message::validate_message_size(&data, self.max_msg_size)?;
        crate::message::validate_message_size(&data, msg.max_serialized_size())?;
        self.bus_tx
            .send((self.peer_id.clone(), data))
            .map_err(|_| NetworkError::ChannelClosed)?;
        Ok(())
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    async fn peer_count(&self) -> usize {
        // Subtract 1 to exclude self.
        self.peer_count.load(Ordering::Relaxed).saturating_sub(1)
    }

    fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.peer_count)
    }

    async fn shutdown(&self) -> Result<(), NetworkError> {
        self.running.store(false, Ordering::Relaxed);
        Ok(())
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

        // Give background tasks a moment to start.
        tokio::time::sleep(Duration::from_millis(10)).await;

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
    async fn node_does_not_receive_own_messages() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();

        let mut node_a = bus.join(&config);

        tokio::time::sleep(Duration::from_millis(10)).await;

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
    async fn inbound_rejects_variant_specific_oversized_messages() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();
        let mut node_b = bus.join(&config);

        tokio::time::sleep(Duration::from_millis(10)).await;

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
    async fn broadcast_transaction() {
        let bus = NetworkBus::new(64);
        let config = NetworkConfig::default();

        let node_a = bus.join(&config);
        let mut node_b = bus.join(&config);

        tokio::time::sleep(Duration::from_millis(10)).await;

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
