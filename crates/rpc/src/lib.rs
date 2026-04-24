//! shell-rpc: JSON-RPC server for the shell-chain node.
//!
//! Provides Ethereum-compatible `eth_*` endpoints and shell-chain
//! extension `shell_*` endpoints for post-quantum features.

pub mod admin;
pub mod api;
pub mod auth;
pub mod dev_control;
pub mod error;
pub mod filter;
pub mod filter_registry;
pub mod handler;
pub mod middleware;
pub mod server;
pub mod subscriptions;
pub mod tls;
pub mod tls_proxy;
pub mod types;

pub use admin::{AdminApiServer, NodeInfo, PeerInfo};
pub use dev_control::{DevRpcControl, DynDevRpcControl};
pub use handler::RpcHandler;
pub use server::{start_rpc_server, RpcConfig, RpcServerHandle};
pub use subscriptions::{BlockEvent, SubscriptionTracker, SyncStatus};
pub use tls::TlsConfig;
pub use tls_proxy::TlsProxyHandle;
