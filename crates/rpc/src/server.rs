//! JSON-RPC server builder and configuration.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{Server, ServerHandle};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::middleware::{ApiKeyLayer, RateLimitLayer};
use crate::tls_proxy::{start_tls_proxy, TlsProxyHandle};

use shell_consensus::FinalityState;
use shell_core::SignedTransaction;
use shell_crypto::Signer;
use shell_mempool::TxPool;
use shell_primitives::Address;
use shell_storage::{ChainStore, KvStore, WitnessStore, WorldState};

use crate::admin::AdminApiServer;
use crate::api::{
    DebugApiServer, EthApiServer, EvmApiServer, NetApiServer, ShellApiServer, TraceApiServer,
    Web3ApiServer,
};
use crate::dev_control::DynDevRpcControl;
use crate::handler::RpcHandler;
use crate::subscriptions::{BlockEvent, EthPubSubServer};
use crate::tls;

/// Configuration for the JSON-RPC server.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Address to bind the HTTP (+WS) server (default: 127.0.0.1:8545).
    pub listen_addr: SocketAddr,
    /// Maximum number of concurrent connections (default: 100).
    pub max_connections: u32,
    /// Optional dedicated WebSocket address. When `Some`, a WS-only server is
    /// started on this address and the HTTP server becomes HTTP-only.
    /// When `None`, the main server at `listen_addr` handles both HTTP and WS.
    pub ws_addr: Option<SocketAddr>,
    /// Path to a PEM-encoded TLS certificate file for WSS/HTTPS transport.
    /// Both `tls_cert_path` and `tls_key_path` must be set to enable TLS.
    pub tls_cert_path: Option<String>,
    /// Path to a PEM-encoded TLS private key file for WSS/HTTPS transport.
    /// Both `tls_cert_path` and `tls_key_path` must be set to enable TLS.
    pub tls_key_path: Option<String>,
    /// CORS allowed origins. `None` means CORS disabled (same-origin only).
    /// Use `vec!["*".to_string()]` to allow all origins.
    pub cors_allowed_origins: Option<Vec<String>>,
    /// Maximum RPC requests per second per connection. `None` disables rate limiting.
    pub rate_limit_per_sec: Option<u32>,
    /// API namespaces to enable. Default: ["eth", "net", "web3", "shell"].
    /// Debug and trace require explicit opt-in.
    pub api_namespaces: Vec<String>,
    /// Allow exposing dev-only `evm` RPC methods on non-loopback listeners.
    pub allow_unsafe_dev_exposed: bool,
    /// Maximum request body size in bytes (default: 5 MB).
    pub max_request_body_size: u32,
    /// Optional API key for Bearer token authentication.
    /// When set, every HTTP request must include `Authorization: Bearer <key>`.
    /// `None` disables authentication (open access).
    pub api_key: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8545)),
            max_connections: 100,
            ws_addr: Some(SocketAddr::from(([127, 0, 0, 1], 8546))),
            tls_cert_path: None,
            tls_key_path: None,
            cors_allowed_origins: Some(vec!["*".to_string()]),
            rate_limit_per_sec: Some(50),
            api_namespaces: vec!["eth".into(), "net".into(), "web3".into(), "shell".into()],
            allow_unsafe_dev_exposed: false,
            max_request_body_size: 5 * 1024 * 1024,
            api_key: None,
        }
    }
}

impl RpcConfig {
    /// Returns true when the given namespace is enabled.
    pub fn has_api_namespace(&self, namespace: &str) -> bool {
        self.api_namespaces.iter().any(|n| n == namespace)
    }

    /// Reject non-loopback exposure of the dev-only `evm` RPC namespace unless
    /// the operator explicitly opts into the unsafe configuration.
    pub fn validate_dev_rpc_exposure(&self) -> Result<(), String> {
        if self.allow_unsafe_dev_exposed || !self.has_api_namespace("evm") {
            return Ok(());
        }

        let mut exposed = Vec::new();
        if !self.listen_addr.ip().is_loopback() {
            exposed.push(format!("http://{}", self.listen_addr));
        }
        if let Some(ws_addr) = self.ws_addr {
            if !ws_addr.ip().is_loopback() {
                exposed.push(format!("ws://{}", ws_addr));
            }
        }

        if exposed.is_empty() {
            return Ok(());
        }

        Err(format!(
            "refusing to expose dev-only 'evm' RPC namespace on non-loopback listener(s): {}. Bind RPC to 127.0.0.1/::1 or pass --unsafe-dev-exposed to override.",
            exposed.join(", ")
        ))
    }
}

/// Handles returned by [`start_rpc_server`] for graceful shutdown.
pub struct RpcServerHandle {
    /// Bound HTTP (or HTTP+WS) address.
    pub http_addr: SocketAddr,
    /// Handle to stop the HTTP server.
    pub http_handle: ServerHandle,
    /// Bound WebSocket address, if a dedicated WS server was started.
    pub ws_addr: Option<SocketAddr>,
    /// Handle to stop the WS server (present when `ws_addr` is `Some`).
    pub ws_handle: Option<ServerHandle>,
    /// TLS termination proxy handle, present when TLS cert+key are configured.
    pub tls_proxy: Option<TlsProxyHandle>,
}

/// Build and start the JSON-RPC server(s).
///
/// When `config.ws_addr` is `Some`, two servers are started:
///   - HTTP-only on `config.listen_addr`
///   - WS-only on `config.ws_addr`
///
/// When `config.ws_addr` is `None`, a single server on `config.listen_addr`
/// handles both HTTP and WebSocket (the jsonrpsee default).
///
/// `admin_p2p_context` is an optional tuple of `(peer_id, p2p_listen_addr)`:
///   - `peer_id` is the base58-encoded libp2p PeerId.
///   - `p2p_listen_addr` is the multiaddr the P2P layer listens on.
///
/// Both are surfaced by `admin_nodeInfo`. Pass `None` if unavailable.
///
/// Returns an [`RpcServerHandle`] for graceful shutdown.
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server<S: KvStore + 'static>(
    config: RpcConfig,
    chain_store: Arc<ChainStore<S>>,
    world_state: Arc<parking_lot::RwLock<WorldState<S>>>,
    tx_pool: Arc<TxPool>,
    chain_id: u64,
    tx_broadcast: Option<tokio::sync::mpsc::Sender<SignedTransaction>>,
    block_events: tokio::sync::broadcast::Sender<BlockEvent>,
    proposer_signer: Option<Arc<dyn Signer>>,
    proposer_address: Option<Address>,
    finalized_number: Arc<parking_lot::RwLock<u64>>,
    finality: Arc<parking_lot::RwLock<FinalityState>>,
    peer_count: Arc<std::sync::atomic::AtomicUsize>,
    dev_control: Option<DynDevRpcControl>,
    admin_p2p_context: Option<(String, String)>,
    witness_store: Option<Arc<WitnessStore<S>>>,
) -> Result<RpcServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    // Load and validate TLS configuration.
    // When cert+key are provided, we start jsonrpsee on an internal loopback
    // port and front it with a tokio-rustls TLS proxy on the configured address.
    let tls_cfg = match tls::load_tls_config(
        config.tls_cert_path.as_deref(),
        config.tls_key_path.as_deref(),
    ) {
        Ok(Some(cfg)) => {
            info!(
                "TLS enabled (cert={}, key={}). Binding jsonrpsee internally; \
                 TLS proxy will accept on configured listen_addr.",
                config.tls_cert_path.as_deref().unwrap_or(""),
                config.tls_key_path.as_deref().unwrap_or(""),
            );
            Some(cfg)
        }
        Ok(None) => {
            info!("RPC server starting without TLS (plain HTTP/WS)");
            None
        }
        Err(e) => {
            return Err(format!(
                "TLS configuration error: {e}. Refusing to start without TLS when cert/key are \
                 provided. Fix the cert/key paths or remove them to run without TLS."
            )
            .into());
        }
    };

    let mut handler = RpcHandler::new(
        chain_store,
        world_state,
        tx_pool,
        chain_id,
        tx_broadcast,
        block_events,
        finalized_number,
        finality,
    )
    .with_peer_count(peer_count);
    if let Some(dev_control) = dev_control {
        handler = handler.with_dev_control(dev_control);
    }
    if let (Some(signer), Some(addr)) = (proposer_signer, proposer_address) {
        handler = handler.with_proposer(signer, addr);
    }
    if let Some((peer_id, p2p_listen)) = admin_p2p_context {
        handler = handler.with_admin_context(peer_id, p2p_listen);
    }
    if let Some(ws) = witness_store {
        handler = handler.with_witness_store(ws);
    }
    // Populate the RPC listen address from the configured public address.
    // (The actual bound port may differ when using ephemeral port 0, but for
    // admin_nodeInfo the configured address is what operators care about.)
    handler = handler.with_admin_rpc_addr(config.listen_addr.to_string());

    // Build CORS middleware layer.
    let cors = if let Some(ref origins) = config.cors_allowed_origins {
        if origins.iter().any(|o| o == "*") {
            CorsLayer::permissive()
        } else {
            {
                let parsed: Vec<_> = origins
                    .iter()
                    .filter_map(|o| match o.parse() {
                        Ok(v) => Some(v),
                        Err(e) => {
                            warn!("Ignoring invalid CORS origin '{}': {}", o, e);
                            None
                        }
                    })
                    .collect();
                CorsLayer::new()
                    .allow_origin(parsed)
                    .allow_methods(Any)
                    .allow_headers(Any)
            }
        }
    } else {
        CorsLayer::new() // restrictive default
    };

    // Determine the actual bind address for jsonrpsee:
    // - With TLS: bind on loopback ephemeral port; TLS proxy fronts the public addr.
    //   ws_addr is ignored when TLS is active — only one TLS proxy is started
    //   (for `listen_addr`). Splitting HTTP+WS across two ports with TLS would
    //   require a second proxy; operators should use single-port mode with TLS.
    // - Without TLS: bind directly on config.listen_addr.
    let internal_http = if tls_cfg.is_some() {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        config.listen_addr
    };
    // When TLS is active, force single-port mode so the TLS proxy covers all
    // traffic. A dedicated ws_addr would be unprotected (no TLS proxy for it).
    let internal_ws = if tls_cfg.is_some() {
        if config.ws_addr.is_some() {
            warn!(
                "ws_addr is ignored when TLS is enabled; all traffic (HTTP+WS) is served on \
                 listen_addr through the TLS proxy. Use a single listen_addr for TLS mode."
            );
        }
        None
    } else {
        config.ws_addr
    };

    // Build middleware stack:
    //   1. CORS
    //   2. Optional global request rate limit (req/sec)
    //   3. Optional Bearer API key authentication
    let middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(RateLimitLayer::from_config(config.rate_limit_per_sec))
        .layer(ApiKeyLayer::new(config.api_key.clone()));

    // Conditionally merge RPC modules based on enabled namespaces.
    let ns = &config.api_namespaces;
    let mut module = jsonrpsee::server::RpcModule::new(());
    if ns.iter().any(|n| n == "eth") {
        module.merge(EthApiServer::into_rpc(handler.clone()))?;
        module.merge(EthPubSubServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "evm") {
        module.merge(EvmApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "shell") {
        module.merge(ShellApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "web3") {
        module.merge(Web3ApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "net") {
        module.merge(NetApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "debug") {
        module.merge(DebugApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "trace") {
        module.merge(TraceApiServer::into_rpc(handler.clone()))?;
    }
    if ns.iter().any(|n| n == "admin") {
        // Safety: refuse to expose the admin namespace on non-loopback listeners
        // unless an API key is configured. The admin namespace provides
        // operator-only methods and must not be accessible without authentication
        // from remote hosts.
        let exposed_publicly = !config.listen_addr.ip().is_loopback()
            || config
                .ws_addr
                .map(|a| !a.ip().is_loopback())
                .unwrap_or(false);
        if exposed_publicly && config.api_key.is_none() {
            return Err(
                "refusing to expose 'admin' RPC namespace on a non-loopback listener without \
                 API-key protection. Set --rpc-api-key or bind RPC to 127.0.0.1/::1."
                    .into(),
            );
        }
        module.merge(AdminApiServer::into_rpc(handler))?;
    }

    if let Some(ws_listen) = internal_ws {
        // Separate ports: HTTP-only + WS-only.
        let http_server = Server::builder()
            .set_http_middleware(middleware.clone())
            .max_connections(config.max_connections)
            .max_request_body_size(config.max_request_body_size)
            .http_only()
            .build(internal_http)
            .await?;
        let http_addr = http_server.local_addr()?;
        let http_handle = http_server.start(module.clone());

        let ws_server = Server::builder()
            .set_http_middleware(middleware)
            .max_connections(config.max_connections)
            .max_request_body_size(config.max_request_body_size)
            .ws_only()
            .build(ws_listen)
            .await?;
        let ws_addr = ws_server.local_addr()?;
        let ws_handle = ws_server.start(module);

        // Start TLS proxy if TLS is configured, forwarding public_addr → http_addr.
        let tls_proxy = if let Some(cfg) = tls_cfg {
            let proxy = start_tls_proxy(config.listen_addr, http_addr, cfg.server_config).await?;
            info!("TLS proxy up: {} -> {}", proxy.public_addr, http_addr);
            Some(proxy)
        } else {
            None
        };

        Ok(RpcServerHandle {
            http_addr,
            http_handle,
            ws_addr: Some(ws_addr),
            ws_handle: Some(ws_handle),
            tls_proxy,
        })
    } else {
        // Single port: both HTTP and WS on listen_addr (jsonrpsee default).
        let server = Server::builder()
            .set_http_middleware(middleware)
            .max_connections(config.max_connections)
            .max_request_body_size(config.max_request_body_size)
            .build(internal_http)
            .await?;
        let http_addr = server.local_addr()?;
        let http_handle = server.start(module);

        // Start TLS proxy if TLS is configured, forwarding public_addr → http_addr.
        let tls_proxy = if let Some(cfg) = tls_cfg {
            let proxy = start_tls_proxy(config.listen_addr, http_addr, cfg.server_config).await?;
            info!("TLS proxy up: {} -> {}", proxy.public_addr, http_addr);
            Some(proxy)
        } else {
            None
        };

        Ok(RpcServerHandle {
            http_addr,
            http_handle,
            ws_addr: None,
            ws_handle: None,
            tls_proxy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RpcConfig;
    use std::net::SocketAddr;

    #[test]
    fn rpc_config_default_disallows_unsafe_dev_exposure() {
        assert!(!RpcConfig::default().allow_unsafe_dev_exposed);
    }

    #[test]
    fn dev_rpc_exposure_allows_loopback_only_listeners() {
        let config = RpcConfig {
            api_namespaces: vec!["eth".into(), "evm".into()],
            ws_addr: Some(SocketAddr::from(([127, 0, 0, 1], 8546))),
            ..RpcConfig::default()
        };

        assert!(config.validate_dev_rpc_exposure().is_ok());
    }

    #[test]
    fn dev_rpc_exposure_rejects_public_http_listener() {
        let config = RpcConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8545)),
            api_namespaces: vec!["evm".into()],
            ws_addr: None,
            ..RpcConfig::default()
        };

        let err = config.validate_dev_rpc_exposure().unwrap_err();
        assert!(err.contains("http://0.0.0.0:8545"));
        assert!(err.contains("--unsafe-dev-exposed"));
    }

    #[test]
    fn dev_rpc_exposure_rejects_public_ws_listener() {
        let config = RpcConfig {
            api_namespaces: vec!["evm".into()],
            ws_addr: Some(SocketAddr::from(([0, 0, 0, 0], 8546))),
            ..RpcConfig::default()
        };

        let err = config.validate_dev_rpc_exposure().unwrap_err();
        assert!(err.contains("ws://0.0.0.0:8546"));
    }

    #[test]
    fn dev_rpc_exposure_allows_public_listener_when_unsafe_override_set() {
        let config = RpcConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8545)),
            api_namespaces: vec!["evm".into()],
            allow_unsafe_dev_exposed: true,
            ..RpcConfig::default()
        };

        assert!(config.validate_dev_rpc_exposure().is_ok());
    }

    #[test]
    fn dev_rpc_exposure_ignores_public_listener_without_evm_namespace() {
        let config = RpcConfig {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8545)),
            api_namespaces: vec!["eth".into(), "shell".into()],
            ws_addr: None,
            ..RpcConfig::default()
        };

        assert!(config.validate_dev_rpc_exposure().is_ok());
    }
}
