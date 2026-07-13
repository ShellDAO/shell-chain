//! Ethereum PubSub (eth_subscribe / eth_unsubscribe) implementation.
//!
//! Supports four subscription types:
//! - `newHeads` — pushes new block headers when blocks are produced or imported.
//! - `logs` — pushes matching logs (filtered by address / topics).
//! - `newPendingTransactions` — pushes tx hashes as transactions enter the mempool.
//! - `syncing` — pushes sync status changes (started / stopped syncing).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use jsonrpsee::core::SubscriptionResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::PendingSubscriptionSink;
use jsonrpsee::SubscriptionMessage;
use shell_core::{BlockHeader, TransactionReceipt};
use shell_primitives::{Address, ShellHash};
use shell_storage::KvStore;
use tokio::sync::broadcast;

use crate::filter::{MAX_LOG_FILTER_ADDRESSES, MAX_LOG_TOPIC_VALUES_PER_POSITION};
use crate::handler::invalid_params_err;
use crate::handler::RpcHandler;
use crate::types::{hex_bytes, hex_u64};

/// Maximum number of concurrent subscriptions across all connections.
const MAX_SUBSCRIPTIONS: u32 = 1024;

/// Maximum number of concurrent subscriptions per WebSocket connection.
const MAX_SUBSCRIPTIONS_PER_CONNECTION: u32 = 16;

/// Auto-disconnect a subscriber after this many consecutive lag events (F-042).
const MAX_CONSECUTIVE_LAGS: u32 = 3;

/// Maximum topic positions accepted by log subscriptions.
const MAX_LOG_TOPIC_POSITIONS: usize = 4;

const SUPPORTED_SUBSCRIPTION_TYPES: &str = "newHeads, logs, newPendingTransactions, or syncing";

/// Parse a user-facing address string (`0x` + 64 lowercase hex) into an `Address`.
fn parse_address_input(s: &str) -> Result<Address, jsonrpsee::types::ErrorObjectOwned> {
    Address::parse(s).map_err(|e| invalid_params_err(format!("invalid log filter address: {e}")))
}

/// Parse a hex hash string like "0x0000..." into a `ShellHash`.
fn parse_hash_hex(s: &str) -> Result<ShellHash, jsonrpsee::types::ErrorObjectOwned> {
    let Some(s) = s.strip_prefix("0x") else {
        return Err(invalid_params_err("log topic must be 0x-prefixed"));
    };
    if s.len() != 64 {
        return Err(invalid_params_err("log topic must be 32 bytes"));
    }
    let bytes =
        hex::decode(s).map_err(|e| invalid_params_err(format!("invalid log topic hex: {e}")))?;
    ShellHash::try_from_slice(&bytes)
        .map_err(|e| invalid_params_err(format!("invalid log topic length: {e}")))
}

// ---------------------------------------------------------------------------
// Block event broadcast type
// ---------------------------------------------------------------------------

/// Events broadcast from the node's block production / import pipeline.
#[derive(Debug, Clone)]
pub enum BlockEvent {
    /// A new block was produced or imported.
    NewBlock {
        header: BlockHeader,
        receipts: Vec<TransactionReceipt>,
    },
}

/// Sync status emitted by the `syncing` subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Node is actively syncing.
    Syncing {
        starting_block: u64,
        current_block: u64,
        highest_block: u64,
    },
    /// Node is fully synced and not downloading blocks.
    NotSyncing,
}

// ---------------------------------------------------------------------------
// Subscription tracker (global limit enforcement)
// ---------------------------------------------------------------------------

/// Tracks the number of active subscriptions and enforces global + per-connection limits.
#[derive(Debug, Clone)]
pub struct SubscriptionTracker {
    active: Arc<AtomicU32>,
    max: u32,
    /// Per-connection subscription counts (F-135).
    per_connection: Arc<parking_lot::Mutex<HashMap<u32, u32>>>,
    max_per_connection: u32,
}

impl SubscriptionTracker {
    /// Create a tracker with the given maximum subscription count.
    pub fn new(max: u32) -> Self {
        Self {
            active: Arc::new(AtomicU32::new(0)),
            max,
            per_connection: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_connection: MAX_SUBSCRIPTIONS_PER_CONNECTION,
        }
    }

    /// Try to acquire a subscription slot. Returns `true` on success.
    pub fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::SeqCst);
            if current >= self.max {
                return false;
            }
            if self
                .active
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Try to acquire a subscription slot for a specific connection.
    /// Enforces both global and per-connection limits.
    pub fn try_acquire_for_connection(&self, conn_id: u32) -> bool {
        let mut conns = self.per_connection.lock();
        let count = conns.get(&conn_id).copied().unwrap_or(0);
        if count >= self.max_per_connection {
            return false;
        }

        if !self.try_acquire() {
            return false;
        }

        conns.insert(conn_id, count.saturating_add(1));
        true
    }

    /// Release a subscription slot (called when the forwarding task ends).
    /// Saturates at zero to prevent underflow from double-release bugs.
    pub fn release(&self) {
        let _ = self
            .active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current > 0 {
                    Some(current - 1)
                } else {
                    tracing::warn!("subscription tracker release called with zero active count");
                    None
                }
            });
    }

    /// Release a subscription slot for a specific connection.
    pub fn release_for_connection(&self, conn_id: u32) {
        let released = {
            let mut conns = self.per_connection.lock();
            match conns.get_mut(&conn_id) {
                Some(count) if *count > 1 => {
                    *count -= 1;
                    true
                }
                Some(_) => {
                    conns.remove(&conn_id);
                    true
                }
                None => {
                    tracing::warn!(
                        conn_id,
                        "subscription tracker release called for unknown connection"
                    );
                    false
                }
            }
        };

        if released {
            self.release();
        }
    }

    /// Returns the current number of active subscriptions.
    pub fn active_count(&self) -> u32 {
        self.active.load(Ordering::SeqCst)
    }
}

impl Default for SubscriptionTracker {
    fn default() -> Self {
        Self::new(MAX_SUBSCRIPTIONS)
    }
}

struct SubscriptionSlotGuard {
    tracker: SubscriptionTracker,
    conn_id: u32,
    armed: bool,
}

impl SubscriptionSlotGuard {
    fn new(tracker: SubscriptionTracker, conn_id: u32) -> Self {
        Self {
            tracker,
            conn_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SubscriptionSlotGuard {
    fn drop(&mut self) {
        if self.armed {
            self.tracker.release_for_connection(self.conn_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Log filter (for `logs` subscriptions)
// ---------------------------------------------------------------------------

/// Simple log filter matching the subset of `eth_getLogs` filter params.
#[derive(Debug, Clone, Default)]
struct LogFilter {
    /// When present, only logs from these addresses are included.
    addresses: Option<Vec<Address>>,
    /// Per-position topic filter. `None` is a wildcard; `Some` values are ORed
    /// within the position and ANDed across positions.
    topics: Vec<Option<Vec<ShellHash>>>,
}

impl LogFilter {
    fn from_value(v: &serde_json::Value) -> Result<Self, jsonrpsee::types::ErrorObjectOwned> {
        let mut filter = LogFilter::default();

        let Some(obj) = v.as_object() else {
            return Err(invalid_params_err("log filter params must be an object"));
        };

        // Parse address(es).
        if let Some(addr_val) = obj.get("address") {
            match addr_val {
                serde_json::Value::String(s) => {
                    filter.addresses = Some(vec![parse_address_input(s)?]);
                }
                serde_json::Value::Array(arr) => {
                    if arr.len() > MAX_LOG_FILTER_ADDRESSES {
                        return Err(invalid_params_err(format!(
                            "log filter address supports at most {MAX_LOG_FILTER_ADDRESSES} entries"
                        )));
                    }
                    let mut addresses = Vec::with_capacity(arr.len());
                    for item in arr {
                        let Some(s) = item.as_str() else {
                            return Err(invalid_params_err(
                                "log filter address entries must be strings",
                            ));
                        };
                        addresses.push(parse_address_input(s)?);
                    }
                    filter.addresses = Some(addresses);
                }
                _ => {
                    return Err(invalid_params_err(
                        "log filter address must be a string or array",
                    ))
                }
            }
        }

        // Parse topics — array of (hash | hash[] | null).
        if let Some(serde_json::Value::Array(topics_arr)) = obj.get("topics") {
            if topics_arr.len() > MAX_LOG_TOPIC_POSITIONS {
                return Err(invalid_params_err(
                    "log filter topics must contain at most 4 entries",
                ));
            }
            for entry in topics_arr {
                match entry {
                    serde_json::Value::Null => {
                        filter.topics.push(None);
                    }
                    serde_json::Value::String(s) => {
                        filter.topics.push(Some(vec![parse_hash_hex(s)?]));
                    }
                    serde_json::Value::Array(arr) => {
                        if arr.len() > MAX_LOG_TOPIC_VALUES_PER_POSITION {
                            return Err(invalid_params_err(format!(
                                "log filter topic supports at most {MAX_LOG_TOPIC_VALUES_PER_POSITION} values"
                            )));
                        }
                        let hashes: Vec<ShellHash> = arr
                            .iter()
                            .map(|v| {
                                let Some(s) = v.as_str() else {
                                    return Err(invalid_params_err(
                                        "log filter topic entries must be strings",
                                    ));
                                };
                                parse_hash_hex(s)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        filter.topics.push(Some(hashes));
                    }
                    _ => {
                        return Err(invalid_params_err(
                            "log filter topic must be a hash, array, or null",
                        ))
                    }
                }
            }
        } else if obj.contains_key("topics") {
            return Err(invalid_params_err("log filter topics must be an array"));
        }

        Ok(filter)
    }

    /// Returns `true` if the given log matches this filter.
    fn matches(&self, log: &shell_core::Log) -> bool {
        // Address filter.
        if let Some(addresses) = &self.addresses {
            if addresses.is_empty() || !addresses.contains(&log.address) {
                return false;
            }
        }

        // Topic filters.
        for (i, slot) in self.topics.iter().enumerate() {
            let Some(acceptable) = slot else {
                continue;
            };
            if acceptable.is_empty() {
                return false;
            }
            match log.topics.get(i) {
                Some(log_topic) => {
                    if !acceptable.contains(log_topic) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

fn parse_pending_tx_full_txs(
    params: Option<&serde_json::Value>,
) -> Result<bool, jsonrpsee::types::ErrorObjectOwned> {
    match params {
        None => Ok(false),
        Some(serde_json::Value::Bool(full_txs)) => Ok(*full_txs),
        Some(serde_json::Value::Object(obj)) => match obj.get("includeTransactions") {
            None => Ok(false),
            Some(serde_json::Value::Bool(full_txs)) => Ok(*full_txs),
            Some(_) => Err(invalid_params_err(
                "newPendingTransactions includeTransactions must be boolean",
            )),
        },
        Some(_) => Err(invalid_params_err(
            "newPendingTransactions params must be a boolean or object",
        )),
    }
}

fn unsupported_subscription_type_err(_sub_type: &str) -> jsonrpsee::types::ErrorObjectOwned {
    invalid_params_err(format!(
        "unsupported subscription type: expected {SUPPORTED_SUBSCRIPTION_TYPES}"
    ))
}

// ---------------------------------------------------------------------------
// RPC trait definition
// ---------------------------------------------------------------------------

/// Ethereum PubSub RPC trait.
#[rpc(server, namespace = "eth")]
pub trait EthPubSub {
    /// Subscribe to live events (`newHeads`, `logs`, `newPendingTransactions`, or `syncing`).
    #[subscription(name = "subscribe" => "subscription", unsubscribe = "unsubscribe", item = serde_json::Value)]
    async fn subscribe(
        &self,
        sub_type: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> EthPubSubServer for RpcHandler<S> {
    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        sub_type: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult {
        let tracker = self.subscription_tracker();
        let conn_id = pending.connection_id().0 as u32;

        // F-135: enforce global + per-connection subscription limits.
        if !tracker.try_acquire_for_connection(conn_id) {
            pending
                .reject(jsonrpsee::types::ErrorObject::owned(
                    -32005,
                    "subscription limit reached",
                    None::<()>,
                ))
                .await;
            return Ok(());
        }
        let mut slot_guard = SubscriptionSlotGuard::new(tracker.clone(), conn_id);

        match sub_type.as_str() {
            "newHeads" => {
                let rx = self.block_event_sender().subscribe();
                let sink = pending.accept().await?;
                let forward_guard = SubscriptionSlotGuard::new(tracker.clone(), conn_id);
                tokio::spawn(async move {
                    let _guard = forward_guard;
                    forward_new_heads(rx, sink).await;
                });
                slot_guard.disarm();
            }
            "logs" => {
                let rx = self.block_event_sender().subscribe();
                let filter = match params.as_ref().map(LogFilter::from_value).transpose() {
                    Ok(Some(filter)) => filter,
                    Ok(None) => LogFilter::default(),
                    Err(err) => {
                        pending.reject(err).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                let forward_guard = SubscriptionSlotGuard::new(tracker.clone(), conn_id);
                tokio::spawn(async move {
                    let _guard = forward_guard;
                    forward_logs(rx, sink, filter).await;
                });
                slot_guard.disarm();
            }
            "newPendingTransactions" => {
                let rx = self.pending_tx_event_sender().subscribe();
                // F-138: parse Geth-compatible parameter format.
                // Accepts: true/false (bool) or {"includeTransactions": true} (object).
                let full_txs = match parse_pending_tx_full_txs(params.as_ref()) {
                    Ok(full_txs) => full_txs,
                    Err(err) => {
                        pending.reject(err).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                let forward_guard = SubscriptionSlotGuard::new(tracker.clone(), conn_id);
                tokio::spawn(async move {
                    let _guard = forward_guard;
                    forward_pending_txs(rx, sink, full_txs).await;
                });
                slot_guard.disarm();
            }
            "syncing" => {
                let rx = self.sync_event_sender().subscribe();
                let sink = pending.accept().await?;
                let forward_guard = SubscriptionSlotGuard::new(tracker.clone(), conn_id);
                tokio::spawn(async move {
                    let _guard = forward_guard;
                    forward_syncing(rx, sink).await;
                });
                slot_guard.disarm();
            }
            _ => {
                pending
                    .reject(unsupported_subscription_type_err(&sub_type))
                    .await;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Background forwarding tasks
// ---------------------------------------------------------------------------

/// Serialize a `BlockHeader` into the JSON shape expected by `eth_subscription`
/// `newHeads` notifications.
fn header_to_json(header: &BlockHeader) -> serde_json::Value {
    serde_json::json!({
        "hash": header.hash(),
        "parentHash": header.parent_hash,
        "number": hex_u64(header.number),
        "timestamp": hex_u64(header.timestamp),
        "gasLimit": hex_u64(header.gas_limit),
        "gasUsed": hex_u64(header.gas_used),
        "miner": header.proposer,
        "stateRoot": header.state_root,
        "transactionsRoot": header.transactions_root,
        "receiptsRoot": header.receipts_root,
        "logsBloom": hex_bytes(header.logs_bloom.as_ref()),
        "extraData": hex_bytes(header.extra_data.as_ref()),
    })
}

/// Serialize a log entry with contextual block/tx metadata.
fn log_to_json(
    log: &shell_core::Log,
    block_header: &BlockHeader,
    tx_hash: &ShellHash,
    tx_index: u32,
    log_index: usize,
) -> serde_json::Value {
    serde_json::json!({
        "address": log.address,
        "topics": log.topics,
        "data": hex_bytes(log.data.as_ref()),
        "blockNumber": hex_u64(block_header.number),
        "blockHash": block_header.hash(),
        "transactionHash": tx_hash,
        "transactionIndex": hex_u64(tx_index as u64),
        "logIndex": hex_u64(log_index as u64),
        "removed": false,
    })
}

async fn forward_new_heads(
    mut rx: broadcast::Receiver<BlockEvent>,
    sink: jsonrpsee::SubscriptionSink,
) {
    let mut consecutive_lags: u32 = 0;
    loop {
        let event = tokio::select! {
            _ = sink.closed() => break,
            event = rx.recv() => event,
        };
        match event {
            Ok(BlockEvent::NewBlock { header, .. }) => {
                consecutive_lags = 0;
                let value = header_to_json(&header);
                let Ok(msg) = SubscriptionMessage::from_json(&value) else {
                    tracing::error!("failed to serialize header for subscription");
                    break;
                };
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                consecutive_lags += 1;
                tracing::warn!(skipped = n, consecutive_lags, "newHeads subscriber lagged");
                if consecutive_lags >= MAX_CONSECUTIVE_LAGS {
                    tracing::error!("newHeads subscriber too slow — disconnecting");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn forward_logs(
    mut rx: broadcast::Receiver<BlockEvent>,
    sink: jsonrpsee::SubscriptionSink,
    filter: LogFilter,
) {
    let mut consecutive_lags: u32 = 0;
    loop {
        let event = tokio::select! {
            _ = sink.closed() => return,
            event = rx.recv() => event,
        };
        match event {
            Ok(BlockEvent::NewBlock { header, receipts }) => {
                consecutive_lags = 0;
                let mut global_log_index: usize = 0;
                for receipt in &receipts {
                    for log in &receipt.logs {
                        if filter.matches(log) {
                            let value = log_to_json(
                                log,
                                &header,
                                &receipt.tx_hash,
                                receipt.tx_index,
                                global_log_index,
                            );
                            let Ok(msg) = SubscriptionMessage::from_json(&value) else {
                                tracing::error!("failed to serialize log for subscription");
                                return;
                            };
                            if sink.send(msg).await.is_err() {
                                return;
                            }
                        }
                        global_log_index += 1;
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                consecutive_lags += 1;
                tracing::warn!(skipped = n, consecutive_lags, "logs subscriber lagged");
                if consecutive_lags >= MAX_CONSECUTIVE_LAGS {
                    tracing::error!("logs subscriber too slow — disconnecting");
                    return;
                }
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Forward pending transaction hashes (or full tx objects) to subscribers.
/// When `full_txs` is true, sends full tx hash (full object support requires
/// architectural changes to the broadcast channel type).
async fn forward_pending_txs(
    mut rx: broadcast::Receiver<ShellHash>,
    sink: jsonrpsee::SubscriptionSink,
    full_txs: bool,
) {
    if full_txs {
        tracing::debug!("full_txs=true requested for newPendingTransactions; sending hashes only (full objects not yet supported)");
    }
    let mut consecutive_lags: u32 = 0;
    loop {
        let event = tokio::select! {
            _ = sink.closed() => break,
            event = rx.recv() => event,
        };
        match event {
            Ok(tx_hash) => {
                consecutive_lags = 0;
                let value = serde_json::json!(tx_hash);
                let Ok(msg) = SubscriptionMessage::from_json(&value) else {
                    tracing::error!("failed to serialize tx hash for subscription");
                    break;
                };
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                consecutive_lags += 1;
                tracing::warn!(
                    skipped = n,
                    consecutive_lags,
                    "newPendingTransactions subscriber lagged"
                );
                if consecutive_lags >= MAX_CONSECUTIVE_LAGS {
                    tracing::error!("newPendingTransactions subscriber too slow — disconnecting");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Forward sync status changes to subscribers.
/// Sends an initial "not syncing" event, then relays any subsequent changes.
///
/// An idle timeout closes the subscription if no sync events arrive within
/// 10 minutes.  This prevents dead subscriptions from consuming global
/// subscription slots when the sync protocol has no active senders.
async fn forward_syncing(
    mut rx: broadcast::Receiver<SyncStatus>,
    sink: jsonrpsee::SubscriptionSink,
) {
    // Emit initial status: node is not syncing (no formal sync states yet).
    let initial = serde_json::json!(false);
    let Ok(msg) = SubscriptionMessage::from_json(&initial) else {
        tracing::error!("failed to serialize initial sync status");
        return;
    };
    if sink.send(msg).await.is_err() {
        return;
    }

    let mut consecutive_lags: u32 = 0;
    // Idle timeout: close subscription if no sync events arrive within 10 minutes.
    let idle_timeout = tokio::time::Duration::from_secs(600);
    loop {
        let event = tokio::select! {
            _ = sink.closed() => break,
            event = tokio::time::timeout(idle_timeout, rx.recv()) => event,
        };
        match event {
            Ok(Ok(status)) => {
                consecutive_lags = 0;
                let value = sync_status_to_json(&status);
                let Ok(msg) = SubscriptionMessage::from_json(&value) else {
                    tracing::error!("failed to serialize sync status for subscription");
                    break;
                };
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                consecutive_lags += 1;
                tracing::warn!(skipped = n, consecutive_lags, "syncing subscriber lagged");
                if consecutive_lags >= MAX_CONSECUTIVE_LAGS {
                    tracing::error!("syncing subscriber too slow — disconnecting");
                    break;
                }
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => {
                // Idle timeout — no sync events for 10 minutes.
                tracing::debug!("syncing subscription idle timeout — closing");
                break;
            }
        }
    }
}

/// Convert a `SyncStatus` into the JSON shape expected by `eth_subscription`.
fn sync_status_to_json(status: &SyncStatus) -> serde_json::Value {
    match status {
        SyncStatus::Syncing {
            starting_block,
            current_block,
            highest_block,
        } => serde_json::json!({
            "syncing": true,
            "status": {
                "startingBlock": hex_u64(*starting_block),
                "currentBlock": hex_u64(*current_block),
                "highestBlock": hex_u64(*highest_block),
            }
        }),
        SyncStatus::NotSyncing => serde_json::json!(false),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shell_core::Log;
    use shell_primitives::Bytes;

    fn sample_header(number: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: ShellHash::ZERO,
            state_root: ShellHash::ZERO,
            transactions_root: ShellHash::ZERO,
            receipts_root: ShellHash::ZERO,
            logs_bloom: Bytes::new(),
            number,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: Bytes::new(),
            proposer: Address::ZERO,
            sig_aggregate_proof: None,
            base_fee_per_gas: 0,
            withdrawals_root: ShellHash::ZERO,
            parent_beacon_block_root: ShellHash::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
            witness_root: None,
        }
    }

    fn sample_receipt(addr: Address, topic: ShellHash) -> TransactionReceipt {
        TransactionReceipt {
            tx_hash: ShellHash::ZERO,
            block_number: 1,
            tx_index: 0,
            status: 1,
            gas_used: 21_000,
            cumulative_gas_used: 21_000,
            contract_address: None,
            logs_bloom: Bytes::new(),
            logs: vec![Log {
                address: addr,
                topics: vec![topic],
                data: Bytes::new(),
            }],
        }
    }

    #[test]
    fn log_filter_empty_matches_everything() {
        let filter = LogFilter::default();
        let log = Log {
            address: Address::from([0xAA; 20]),
            topics: vec![ShellHash::ZERO],
            data: Bytes::new(),
        };
        assert!(filter.matches(&log));
    }

    #[test]
    fn log_filter_address_match() {
        let addr = Address::from([0xAA; 20]);
        let filter = LogFilter {
            addresses: Some(vec![addr]),
            topics: vec![],
        };
        let log = Log {
            address: addr,
            topics: vec![],
            data: Bytes::new(),
        };
        assert!(filter.matches(&log));
    }

    #[test]
    fn log_filter_address_mismatch() {
        let filter = LogFilter {
            addresses: Some(vec![Address::from([0xAA; 20])]),
            topics: vec![],
        };
        let log = Log {
            address: Address::from([0xBB; 20]),
            topics: vec![],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log));
    }

    #[test]
    fn log_filter_topic_match() {
        let topic = shell_primitives::keccak256(b"Transfer(address,address,uint256)");
        let filter = LogFilter {
            addresses: None,
            topics: vec![Some(vec![topic])],
        };
        let log = Log {
            address: Address::ZERO,
            topics: vec![topic],
            data: Bytes::new(),
        };
        assert!(filter.matches(&log));
    }

    #[test]
    fn log_filter_topic_mismatch() {
        let topic_a = shell_primitives::keccak256(b"Transfer");
        let topic_b = shell_primitives::keccak256(b"Approval");
        let filter = LogFilter {
            addresses: None,
            topics: vec![Some(vec![topic_a])],
        };
        let log = Log {
            address: Address::ZERO,
            topics: vec![topic_b],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log));
    }

    #[test]
    fn log_filter_wildcard_position() {
        let topic_b = shell_primitives::keccak256(b"value");
        let filter = LogFilter {
            addresses: None,
            // First position is wildcard, second must match.
            topics: vec![None, Some(vec![topic_b])],
        };
        let log = Log {
            address: Address::ZERO,
            topics: vec![shell_primitives::keccak256(b"anything"), topic_b],
            data: Bytes::new(),
        };
        assert!(filter.matches(&log));
    }

    #[test]
    fn log_filter_from_json() {
        let json = serde_json::json!({
            "address": Address::from([0xAA; 20]),
            "topics": [null, "0x0000000000000000000000000000000000000000000000000000000000000000"]
        });
        let filter = LogFilter::from_value(&json).unwrap();
        assert_eq!(filter.addresses.as_ref().unwrap().len(), 1);
        assert_eq!(filter.topics.len(), 2);
        assert!(filter.topics[0].is_none()); // null -> wildcard
        assert_eq!(filter.topics[1].as_ref().unwrap().len(), 1);
    }

    #[test]
    fn log_filter_rejects_non_object_params() {
        for value in [
            serde_json::Value::Null,
            serde_json::json!(true),
            serde_json::json!([]),
            serde_json::json!("latest"),
        ] {
            let err = LogFilter::from_value(&value).unwrap_err();
            assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
            assert!(err.message().contains("must be an object"));
        }
    }

    #[test]
    fn log_filter_empty_topic_array_matches_nothing() {
        let topic = shell_primitives::keccak256(b"Transfer");
        let filter = LogFilter::from_value(&serde_json::json!({
            "topics": [[]]
        }))
        .unwrap();
        let log = Log {
            address: Address::ZERO,
            topics: vec![topic],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log));
    }

    #[test]
    fn log_filter_empty_address_array_matches_nothing() {
        let filter = LogFilter::from_value(&serde_json::json!({
            "address": []
        }))
        .unwrap();
        let log = Log {
            address: Address::from([0xAA; 20]),
            topics: vec![],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log));
    }

    #[test]
    fn log_filter_rejects_more_than_four_topic_positions() {
        let json = serde_json::json!({
            "topics": [
                null,
                null,
                null,
                null,
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            ]
        });
        let err = LogFilter::from_value(&json).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("at most 4"));
    }

    #[test]
    fn log_filter_rejects_unprefixed_topic() {
        let json = serde_json::json!({
            "topics": ["00".repeat(32)]
        });
        let err = LogFilter::from_value(&json).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("0x-prefixed"));
    }

    #[test]
    fn header_to_json_roundtrip() {
        let header = sample_header(42);
        let json = header_to_json(&header);
        assert_eq!(json["number"], "0x2a");
        assert_eq!(json["gasUsed"], "0x5208");
    }

    #[tokio::test]
    async fn broadcast_channel_delivers_events() {
        let (tx, mut rx) = broadcast::channel::<BlockEvent>(16);
        let header = sample_header(1);

        tx.send(BlockEvent::NewBlock {
            header: header.clone(),
            receipts: vec![],
        })
        .unwrap();

        match rx.recv().await.unwrap() {
            BlockEvent::NewBlock {
                header: h,
                receipts: r,
            } => {
                assert_eq!(h.number, 1);
                assert!(r.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn broadcast_multiple_subscribers() {
        let (tx, _) = broadcast::channel::<BlockEvent>(16);
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();

        tx.send(BlockEvent::NewBlock {
            header: sample_header(5),
            receipts: vec![],
        })
        .unwrap();

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        match (e1, e2) {
            (BlockEvent::NewBlock { header: h1, .. }, BlockEvent::NewBlock { header: h2, .. }) => {
                assert_eq!(h1.number, 5);
                assert_eq!(h2.number, 5);
            }
        }
    }

    #[tokio::test]
    async fn logs_filter_selects_matching_receipts() {
        let addr = Address::from([0xCC; 20]);
        let topic = shell_primitives::keccak256(b"Transfer(address,address,uint256)");
        let filter = LogFilter {
            addresses: Some(vec![addr]),
            topics: vec![Some(vec![topic])],
        };

        let matching_receipt = sample_receipt(addr, topic);
        let non_matching_receipt = sample_receipt(
            Address::from([0xDD; 20]),
            shell_primitives::keccak256(b"Other"),
        );

        // The matching receipt's log should pass.
        assert!(filter.matches(&matching_receipt.logs[0]));
        // The non-matching receipt's log should NOT pass.
        assert!(!filter.matches(&non_matching_receipt.logs[0]));
    }

    #[test]
    fn logs_filter_topic_parser_requires_exact_hash_length_before_decode() {
        let valid_topic = format!("0x{}", "11".repeat(32));
        let filter = LogFilter::from_value(&serde_json::json!({
            "topics": [valid_topic]
        }))
        .unwrap();
        assert_eq!(filter.topics[0], Some(vec![ShellHash::from([0x11; 32])]));

        for topic in ["0x11".to_string(), format!("0x{}", "aa".repeat(512))] {
            let err = LogFilter::from_value(&serde_json::json!({
                "topics": [topic]
            }))
            .unwrap_err();
            assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
            assert!(err.message().contains("32 bytes"));
            assert!(
                !err.message().contains(&"aa".repeat(64)),
                "error should not reflect large topic inputs"
            );
        }

        let invalid_topic = format!("0x{}zz", "00".repeat(31));
        let err = LogFilter::from_value(&serde_json::json!({
            "topics": [invalid_topic]
        }))
        .unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("invalid log topic hex"));
    }

    #[test]
    fn log_filter_rejects_too_many_topic_values() {
        let topic = format!("0x{}", "11".repeat(32));
        let topics = vec![topic; MAX_LOG_TOPIC_VALUES_PER_POSITION + 1];
        let err = LogFilter::from_value(&serde_json::json!({
            "topics": [topics]
        }))
        .unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("topic supports at most"));
    }

    // -------------------------------------------------------------------
    // newPendingTransactions subscription tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pending_tx_channel_delivers_hash() {
        let (tx, mut rx) = broadcast::channel::<ShellHash>(16);
        let hash = shell_primitives::keccak256(b"tx-1");

        tx.send(hash).unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received, hash);
    }

    #[tokio::test]
    async fn pending_tx_channel_multiple_subscribers() {
        let (tx, _) = broadcast::channel::<ShellHash>(16);
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();

        let hash = shell_primitives::keccak256(b"tx-2");
        tx.send(hash).unwrap();

        assert_eq!(rx1.recv().await.unwrap(), hash);
        assert_eq!(rx2.recv().await.unwrap(), hash);
    }

    #[tokio::test]
    async fn pending_tx_channel_delivers_multiple_hashes() {
        let (tx, mut rx) = broadcast::channel::<ShellHash>(16);
        let h1 = shell_primitives::keccak256(b"tx-a");
        let h2 = shell_primitives::keccak256(b"tx-b");
        let h3 = shell_primitives::keccak256(b"tx-c");

        tx.send(h1).unwrap();
        tx.send(h2).unwrap();
        tx.send(h3).unwrap();

        assert_eq!(rx.recv().await.unwrap(), h1);
        assert_eq!(rx.recv().await.unwrap(), h2);
        assert_eq!(rx.recv().await.unwrap(), h3);
    }

    #[test]
    fn pending_tx_params_parse_geth_compatible_forms() {
        assert!(!parse_pending_tx_full_txs(None).unwrap());
        assert!(parse_pending_tx_full_txs(Some(&serde_json::json!(true))).unwrap());
        assert!(!parse_pending_tx_full_txs(Some(&serde_json::json!(false))).unwrap());
        assert!(
            parse_pending_tx_full_txs(Some(&serde_json::json!({"includeTransactions": true})))
                .unwrap()
        );
        assert!(!parse_pending_tx_full_txs(Some(
            &serde_json::json!({"includeTransactions": false})
        ))
        .unwrap());
        assert!(!parse_pending_tx_full_txs(Some(&serde_json::json!({}))).unwrap());
    }

    #[test]
    fn pending_tx_params_reject_malformed_values() {
        for value in [
            serde_json::json!(null),
            serde_json::json!("true"),
            serde_json::json!([]),
            serde_json::json!({"includeTransactions": "true"}),
        ] {
            let err = parse_pending_tx_full_txs(Some(&value)).unwrap_err();
            assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
            assert!(err.message().contains("newPendingTransactions"));
        }
    }

    #[test]
    fn unsupported_subscription_type_error_does_not_echo_input() {
        let oversized = "x".repeat(1024);
        let err = unsupported_subscription_type_err(&oversized);

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("unsupported subscription type"));
        assert!(err.message().contains("newPendingTransactions"));
        assert!(
            !err.message().contains(&"x".repeat(128)),
            "error should not reflect unsupported subscription type inputs"
        );
    }

    // -------------------------------------------------------------------
    // syncing subscription tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn sync_status_channel_delivers_events() {
        let (tx, mut rx) = broadcast::channel::<SyncStatus>(16);

        tx.send(SyncStatus::Syncing {
            starting_block: 0,
            current_block: 50,
            highest_block: 100,
        })
        .unwrap();

        match rx.recv().await.unwrap() {
            SyncStatus::Syncing {
                starting_block,
                current_block,
                highest_block,
            } => {
                assert_eq!(starting_block, 0);
                assert_eq!(current_block, 50);
                assert_eq!(highest_block, 100);
            }
            _ => panic!("expected Syncing variant"),
        }
    }

    #[tokio::test]
    async fn sync_status_not_syncing() {
        let (tx, mut rx) = broadcast::channel::<SyncStatus>(16);
        tx.send(SyncStatus::NotSyncing).unwrap();

        assert_eq!(rx.recv().await.unwrap(), SyncStatus::NotSyncing);
    }

    #[test]
    fn sync_status_to_json_syncing() {
        let status = SyncStatus::Syncing {
            starting_block: 0,
            current_block: 256,
            highest_block: 512,
        };
        let json = sync_status_to_json(&status);
        assert_eq!(json["syncing"], true);
        assert_eq!(json["status"]["startingBlock"], "0x0");
        assert_eq!(json["status"]["currentBlock"], "0x100");
        assert_eq!(json["status"]["highestBlock"], "0x200");
    }

    #[test]
    fn sync_status_to_json_not_syncing() {
        let json = sync_status_to_json(&SyncStatus::NotSyncing);
        assert_eq!(json, serde_json::json!(false));
    }

    // -------------------------------------------------------------------
    // Subscription tracker tests
    // -------------------------------------------------------------------

    #[test]
    fn subscription_tracker_enforces_limit() {
        let tracker = SubscriptionTracker::new(2);
        assert!(tracker.try_acquire());
        assert!(tracker.try_acquire());
        // Third should fail.
        assert!(!tracker.try_acquire());
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn subscription_tracker_release_frees_slot() {
        let tracker = SubscriptionTracker::new(1);
        assert!(tracker.try_acquire());
        assert!(!tracker.try_acquire());
        tracker.release();
        assert!(tracker.try_acquire());
    }

    #[test]
    fn subscription_slot_guard_releases_failed_handshake_slot() {
        let tracker = SubscriptionTracker::new(1);
        assert!(tracker.try_acquire_for_connection(7));

        drop(SubscriptionSlotGuard::new(tracker.clone(), 7));

        assert_eq!(tracker.active_count(), 0);
        assert!(tracker.try_acquire_for_connection(8));
    }

    #[test]
    fn subscription_slot_guard_can_transfer_release_to_forwarder() {
        let tracker = SubscriptionTracker::new(1);
        assert!(tracker.try_acquire_for_connection(7));
        let mut guard = SubscriptionSlotGuard::new(tracker.clone(), 7);

        guard.disarm();
        drop(guard);

        assert_eq!(tracker.active_count(), 1);
        tracker.release_for_connection(7);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn subscription_tracker_default_allows_many() {
        let tracker = SubscriptionTracker::default();
        // Default allows MAX_SUBSCRIPTIONS (1024).
        for _ in 0..100 {
            assert!(tracker.try_acquire());
        }
        assert_eq!(tracker.active_count(), 100);
        for _ in 0..100 {
            tracker.release();
        }
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn subscription_tracker_clone_shares_state() {
        let tracker = SubscriptionTracker::new(2);
        let tracker2 = tracker.clone();
        assert!(tracker.try_acquire());
        assert!(tracker2.try_acquire());
        // Both clones see the shared count — third should fail.
        assert!(!tracker.try_acquire());
        assert!(!tracker2.try_acquire());
    }

    #[test]
    fn subscription_tracker_enforces_per_connection_limit() {
        let tracker = SubscriptionTracker {
            active: Arc::new(AtomicU32::new(0)),
            max: 10,
            per_connection: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_connection: 2,
        };

        assert!(tracker.try_acquire_for_connection(7));
        assert!(tracker.try_acquire_for_connection(7));
        assert!(!tracker.try_acquire_for_connection(7));
        assert_eq!(tracker.active_count(), 2);

        tracker.release_for_connection(7);
        assert!(tracker.try_acquire_for_connection(7));
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn subscription_tracker_enforces_per_connection_limit_under_contention() {
        let tracker = Arc::new(SubscriptionTracker {
            active: Arc::new(AtomicU32::new(0)),
            max: 100,
            per_connection: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_connection: 1,
        });
        let ready = Arc::new(std::sync::Barrier::new(16));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let tracker = Arc::clone(&tracker);
            let ready = Arc::clone(&ready);
            handles.push(std::thread::spawn(move || {
                ready.wait();
                tracker.try_acquire_for_connection(42)
            }));
        }

        let acquired = handles
            .into_iter()
            .map(|handle| handle.join().expect("subscription worker panicked"))
            .filter(|acquired| *acquired)
            .count();

        assert_eq!(acquired, 1);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn subscription_tracker_unknown_connection_release_does_not_free_global_slot() {
        let tracker = SubscriptionTracker {
            active: Arc::new(AtomicU32::new(0)),
            max: 2,
            per_connection: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_connection: 2,
        };

        assert!(tracker.try_acquire_for_connection(1));
        assert!(tracker.try_acquire_for_connection(2));
        assert!(!tracker.try_acquire_for_connection(3));

        tracker.release_for_connection(99);

        assert_eq!(tracker.active_count(), 2);
        assert!(!tracker.try_acquire_for_connection(3));
    }

    #[test]
    fn subscription_tracker_double_connection_release_does_not_free_extra_slot() {
        let tracker = SubscriptionTracker {
            active: Arc::new(AtomicU32::new(0)),
            max: 2,
            per_connection: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_connection: 2,
        };

        assert!(tracker.try_acquire_for_connection(1));
        assert!(tracker.try_acquire_for_connection(2));

        tracker.release_for_connection(1);
        tracker.release_for_connection(1);

        assert_eq!(tracker.active_count(), 1);
        assert!(tracker.try_acquire_for_connection(3));
        assert_eq!(tracker.active_count(), 2);
    }

    // -------------------------------------------------------------------
    // Log filter combined address+topic test
    // -------------------------------------------------------------------

    #[test]
    fn log_filter_address_and_topic_combined() {
        let addr = Address::from([0xAA; 20]);
        let topic = shell_primitives::keccak256(b"Transfer(address,address,uint256)");
        let filter = LogFilter {
            addresses: Some(vec![addr]),
            topics: vec![Some(vec![topic])],
        };

        // Correct address, correct topic → match.
        let log_match = Log {
            address: addr,
            topics: vec![topic],
            data: Bytes::new(),
        };
        assert!(filter.matches(&log_match));

        // Correct address, wrong topic → no match.
        let log_wrong_topic = Log {
            address: addr,
            topics: vec![shell_primitives::keccak256(b"Other")],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log_wrong_topic));

        // Wrong address, correct topic → no match.
        let log_wrong_addr = Log {
            address: Address::from([0xBB; 20]),
            topics: vec![topic],
            data: Bytes::new(),
        };
        assert!(!filter.matches(&log_wrong_addr));
    }

    #[test]
    fn log_filter_multiple_addresses() {
        let addr_a = Address::from([0xAA; 20]);
        let addr_b = Address::from([0xBB; 20]);
        let filter = LogFilter {
            addresses: Some(vec![addr_a, addr_b]),
            topics: vec![],
        };

        let log_a = Log {
            address: addr_a,
            topics: vec![],
            data: Bytes::new(),
        };
        let log_b = Log {
            address: addr_b,
            topics: vec![],
            data: Bytes::new(),
        };
        let log_c = Log {
            address: Address::from([0xCC; 20]),
            topics: vec![],
            data: Bytes::new(),
        };

        assert!(filter.matches(&log_a));
        assert!(filter.matches(&log_b));
        assert!(!filter.matches(&log_c));
    }

    #[test]
    fn log_filter_from_json_array_of_addresses() {
        let addr_a = Address::from([0xAA; 20]);
        let addr_b = Address::from([0xBB; 20]);
        let json = serde_json::json!({
            "address": [
                addr_a.to_string(),
                addr_b.to_string(),
            ],
            "topics": []
        });
        let filter = LogFilter::from_value(&json).unwrap();
        assert_eq!(filter.addresses.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn log_filter_rejects_too_many_addresses() {
        let addresses = vec![Address::from([0xAA; 20]).to_string(); MAX_LOG_FILTER_ADDRESSES + 1];
        let json = serde_json::json!({
            "address": addresses,
            "topics": []
        });

        let err = LogFilter::from_value(&json).unwrap_err();

        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("address supports at most"));
    }

    #[test]
    fn log_filter_rejects_hex_addresses() {
        let json = serde_json::json!({
            "address": [
                Address::from([0xAA; 20]).to_string(),
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "topics": []
        });
        let err = LogFilter::from_value(&json).unwrap_err();
        assert_eq!(err.code(), jsonrpsee::types::error::INVALID_PARAMS_CODE);
        assert!(err.message().contains("invalid log filter address"));
    }

    #[test]
    fn release_saturates_at_zero() {
        let tracker = SubscriptionTracker::new(10);
        // Release without acquire should not underflow
        tracker.release();
        assert_eq!(tracker.active_count(), 0);
    }
}
