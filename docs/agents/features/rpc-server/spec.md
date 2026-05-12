# Feature: RPC Server

Status: production
Owner: shell-chain core
Last verified against: v0.22.2

> Legacy header (preserved): ID `rpc-server` · Priority P2 · Module `shell-chain/crates/rpc`

## 1. Purpose

Ethereum-compatible JSON-RPC server for shell-chain. Exposes six standard namespaces
(`eth`, `web3`, `net`, `debug`, `trace`, `evm`) plus the shell-chain extension namespace
(`shell`) with STARK proof, witness, validator-governance, and Native-AA endpoints.

Architecture: three-server fanout model with optional TLS proxy.

## 2. Public API Surface

```rust
// crates/rpc/src/lib.rs (re-exports)
pub use admin::{AdminApiServer, NodeInfo, PeerInfo};
pub use dev_control::{DevRpcControl, DynDevRpcControl};
pub use handler::RpcHandler;
pub use server::{start_rpc_server, RpcConfig, RpcServerHandle};
pub use subscriptions::{BlockEvent, SubscriptionTracker, SyncStatus};
pub use tls::TlsConfig;
pub use tls_proxy::TlsProxyHandle;

pub struct RpcConfig {
    pub listen_addr: SocketAddr,        // HTTP (+WS when ws_addr is None); default 127.0.0.1:8545
    pub max_connections: u32,           // default 100
    pub ws_addr: Option<SocketAddr>,    // dedicated WS-only server; default Some(127.0.0.1:8546)
    pub tls_cert_path: Option<String>,  // PEM cert for HTTPS/WSS
    pub tls_key_path: Option<String>,   // PEM key for HTTPS/WSS
    pub cors_allowed_origins: Option<Vec<String>>,
    pub rate_limit_per_sec: Option<u32>, // default 50 req/s/connection
    pub api_namespaces: Vec<String>,    // default ["eth","net","web3","shell"]
    pub allow_unsafe_dev_exposed: bool, // expose evm_* on non-loopback when true
    pub max_request_body_size: u32,     // default 5 MiB
    pub api_key: Option<String>,        // Bearer token auth; None = open access
}
```

### Three-server fanout

| Server | Protocol | Default port(s) | Condition |
|--------|----------|-----------------|-----------|
| Main server | HTTP + WS (combined) | 8545 | always |
| Dedicated WS server | WS only | 8546 | `ws_addr.is_some()` |
| TLS proxy | HTTPS / WSS | 8547 / 8548 (configurable) | `tls_cert_path` + `tls_key_path` set |

SG testnet fanout: HTTP 8545/8547/8549, WS 8546/8548/8550 (three separate node instances).

## 3. Implementation Map

| Component | File | Notes |
|-----------|------|-------|
| `RpcConfig`, `start_rpc_server`, `RpcServerHandle` | `crates/rpc/src/server.rs:1-80` | Server builder; three-fanout launch |
| `EthApi` trait | `crates/rpc/src/api.rs:38-248` | Standard `eth_*` namespace |
| `Web3Api` trait | `crates/rpc/src/api.rs:11-20` | `web3_clientVersion`, `web3_sha3` |
| `NetApi` trait | `crates/rpc/src/api.rs:23-36` | `net_version`, `net_listening`, `net_peerCount` |
| `DebugApi` trait | `crates/rpc/src/api.rs:250-270` | `debug_traceTransaction`, `debug_traceBlockByNumber` |
| `TraceApi` trait | `crates/rpc/src/api.rs:270-290` | `trace_block`, `trace_transaction` (OE format) |
| `EvmApi` trait | `crates/rpc/src/api.rs:288-320` | `evm_mine`, `evm_setNextBlockTimestamp`, `evm_snapshot`, `evm_revert` |
| `ShellApi` trait | `crates/rpc/src/api.rs:320-680` | Shell extension namespace (see §shell_* below) |
| `RpcHandler` | `crates/rpc/src/handler/` | All trait implementations |
| `ShellApi` impl | `crates/rpc/src/handler/shell_api.rs:1-80` | `shell_*` implementation |
| `TlsConfig` | `crates/rpc/src/tls.rs` | PEM cert/key loading, `rustls` config |
| `TlsProxyHandle` | `crates/rpc/src/tls_proxy.rs` | `start_tls_proxy()` — TCP proxy wrapping HTTP in TLS |
| `ApiKeyLayer`, `RateLimitLayer` | `crates/rpc/src/middleware.rs` | Tower middleware; Bearer auth + rate limit |
| `AdminApiServer`, `NodeInfo`, `PeerInfo` | `crates/rpc/src/admin.rs` | Admin namespace; separate server port |
| `EthPubSubServer`, `BlockEvent`, `SubscriptionTracker`, `SyncStatus` | `crates/rpc/src/subscriptions.rs` | WS subscriptions; `eth_subscribe` |
| Filter system | `crates/rpc/src/filter.rs`, `filter_registry.rs` | `eth_newFilter`, `eth_getFilterChanges`, `eth_uninstallFilter` |
| `DevRpcControl`, `DynDevRpcControl` | `crates/rpc/src/dev_control.rs` | Test harness override interface |
| Response types | `crates/rpc/src/types.rs` | `RpcBlock`, `RpcTransaction`, `RpcReceipt`, `CallRequest`, `BatchEstimateRequest` |

### API namespaces

| Namespace | Default | Methods (key) |
|-----------|---------|--------------|
| `eth` | ✅ | `eth_blockNumber`, `eth_chainId`, `eth_getBalance`, `eth_getTransactionCount`, `eth_sendRawTransaction`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_call`, `eth_estimateGas`, `eth_getLogs`, `eth_getCode`, `eth_getStorageAt`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory`, `eth_blobBaseFee`, `eth_newFilter`, `eth_newBlockFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`, `eth_createAccessList`, `eth_getBlockReceipts`, `eth_subscribe` (WS) |
| `web3` | ✅ | `web3_clientVersion`, `web3_sha3` |
| `net` | ✅ | `net_version`, `net_listening`, `net_peerCount` |
| `shell` | ✅ | See §shell_* methods below |
| `debug` | ❌ opt-in | `debug_traceTransaction`, `debug_traceBlockByNumber` |
| `trace` | ❌ opt-in | `trace_block`, `trace_transaction` (OpenEthereum format) |
| `evm` | ❌ unsafe opt-in | `evm_mine`, `evm_setNextBlockTimestamp`, `evm_increaseTime`, `evm_snapshot`, `evm_revert` |

### `shell_*` methods

| Method | Description |
|--------|-------------|
| `shell_getPqPubkey(address)` | Registered PQ public key for an address |
| `shell_pendingCount()` | Mempool pending transaction count |
| `shell_getBlockByNumber(number, tx_detail?)` | Block with `"hashes"` / `"summary"` / `"full"` tx detail modes |
| `shell_getBlockByHash(hash, tx_detail?)` | Same as above, by hash |
| `shell_sendTransaction(tx)` | Submit structured JSON SignedTransaction |
| `shell_getValidators()` | Current validator set from world state |
| `shell_addValidator(address)` | Add validator (unauthenticated until governance milestone) |
| `shell_removeValidator(address)` | Remove validator |
| `shell_encodeAddValidator(address)` | Encode `addValidator` system contract calldata |
| `shell_encodeRemoveValidator(address)` | Encode `removeValidator` system contract calldata |
| `shell_proposeAddValidator(address)` | Submit governance tx to add validator; returns tx hash |
| `shell_proposeRemoveValidator(address)` | Submit governance tx to remove validator; returns tx hash |
| `shell_getValidatorStatus(address)` | Validator membership status |
| `shell_getGovernanceInfo()` | Validator count, list, system contract address, gas limit |
| `shell_estimateGovernanceGas(operation)` | Estimated gas for `addValidator`/`removeValidator` |
| `shell_getNodeInfo()` | Comprehensive node status (performance dashboard) |
| `shell_getNetworkStats()` | Network statistics |
| `shell_getChainStats()` | Chain performance statistics |
| `shell_getFinalityInfo()` | Last finalized block, current head, pending attestations |
| `shell_finalityProof(block_hash)` | Commit certificate (quorum signatures) for a finalized block |
| `shell_consensusInfo()` | Engine type, validators, weights, current proposer, epoch info |
| `shell_setBalance(address, balance)` | Dev/testnet: set balance directly |
| `shell_transactionCount()` | Total on-chain transaction count |
| `shell_getTransactionsByAddress(address, ...)` | Transactions by address with pagination |
| `shell_getBlockWitnesses(block)` | Witness bundle for a block (PQ signatures) |
| `shell_getWitness(block)` | SDK-facing witness endpoint with OPS-2 enrichment |
| `shell_verifyWitnessRoot(block)` | Verify stored witness bundle Merkle root vs header |
| `shell_estimateBatch(req)` | Gas estimate for Native-AA bundle (tx_type 0x7E) |
| `shell_getPaymasterPolicy(address)` | Native-AA paymaster policy for an address |
| `shell_isSponsored(tx_hash)` | Whether a transaction is paymaster-sponsored |
| `shell_getStorageProfile()` | Active storage profile and pruning parameters |
| `shell_getProofAmendment(block_hash)` | STARK proof amendment for a block (with proof bytes) |

### TLS

`TlsConfig` loads PEM cert/key via `rustls`. `start_tls_proxy()` in `tls_proxy.rs` spawns
a TCP listener that terminates TLS and forwards plaintext to the HTTP server at `listen_addr`.
Both `tls_cert_path` and `tls_key_path` must be set; missing either disables TLS silently.

### Authentication

`ApiKeyLayer` (Tower middleware) checks `Authorization: Bearer <key>` header on every HTTP
request when `api_key.is_some()`. Requests without a valid key receive HTTP 401.

### Rate limiting

`RateLimitLayer` enforces `rate_limit_per_sec` requests per connection per second using a
token-bucket algorithm. Applied after auth, before RPC dispatch.

### STARK proof fields in block responses

`shell_getBlockByNumber` / `shell_getBlockByHash` with `tx_detail="summary"` or `"full"` call
`fill_stark_proof()` / `fill_stark_metadata()` to attach proof amendment data to block responses.

## 4. Invariants

- **INV-RPC-1**: `evm_*` methods MUST only be exposed when `allow_unsafe_dev_exposed = true` AND
  the listener is on loopback, OR on any address when explicitly overridden. Cross-ref: CONSTITUTION §DevAPI.
- **INV-RPC-2**: API key auth MUST be checked before any RPC dispatch. A missing or invalid key
  MUST return HTTP 401, never a JSON-RPC error (which would leak method names).
- **INV-RPC-3**: `shell_getProofAmendment` MUST return `null` (not error) when no amendment exists.
- **INV-RPC-4**: `shell_getFinalityInfo` and `shell_finalityProof` MUST be available in the
  default namespace set (no opt-in required).
- **INV-RPC-5**: The three servers (HTTP, WS, TLS) share the same `RpcHandler` state; they MUST
  present a consistent view of chain state.

## 5. Tests

Tests live in `crates/rpc/src/` (inline `#[cfg(test)]`) and integration tests in `shell-chain/tests/`.

Key test cases:
- `eth_chainId` and `eth_blockNumber` return correct values.
- `eth_sendRawTransaction` admits a valid signed transaction.
- `eth_call` executes a read-only contract call.
- `eth_blobBaseFee` returns non-error.
- WebSocket `eth_subscribe` delivers `newHeads` events.
- `shell_getProofAmendment` returns `null` when no proof stored.
- `shell_verifyWitnessRoot` returns `verified: true` for a stored bundle.
- API key middleware: missing key returns 401; correct key passes through.
- Rate limit: requests beyond `rate_limit_per_sec` are rejected with HTTP 429.
- `evm_mine` only available on loopback when `allow_unsafe_dev_exposed = false`.

Run: `cargo test -p shell-rpc -- --nocapture`

## 6. Related ADRs

- (historical AA design — superseded by `features/account-abstraction/spec.md`) — `shell_estimateBatch`, `shell_getPaymasterPolicy`
- `../adrs/ADR-002-stark-tx-level-settlement.md` — `shell_getProofAmendment`, `shell_getWitness`
- CONSTITUTION §DevAPI — `evm_*` exposure rules

## 7. Known Limitations / Open Work

- `debug_traceTransaction` does not yet support `stateDiff` or `vmTrace` modes; only call trace.
- `trace_block` / `trace_transaction` (OpenEthereum format) are partially implemented; full
  parity with OE trace format is a known gap.
- Admin namespace (separate port) is not yet documented; `AdminApiServer` exposes `NodeInfo`/`PeerInfo`.
- `shell_setBalance` has no authentication guard in testnet; anyone with network access can invoke it.
- TLS proxy (`tls_proxy.rs`) is a TCP-level proxy; it does not perform HTTP/2 multiplexing.

## 8. Change Log

| Version | Change |
|---------|--------|
| v0.22.2 | Spec rewritten from draft; added TLS, API key auth, three-fanout architecture, all 6 namespaces, full shell_* method table including shell_getProofAmendment, shell_getFinalityInfo, shell_finalityProof, shell_getWitness, shell_estimateBatch |
| M9 | Added shell_getWitness, shell_verifyWitnessRoot, shell_getProofAmendment, shell_estimateBatch, shell_getPaymasterPolicy, shell_isSponsored |
| M2 | Initial draft spec (3 shell_* methods only, single-server model) |
