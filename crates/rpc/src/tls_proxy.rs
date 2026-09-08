//! TLS termination proxy for the JSON-RPC server.
//
//! When TLS cert+key are configured, the RPC server binds on an internal
//! loopback port and a tokio-rustls acceptor handles the public-facing port.
//! Each accepted TLS connection is transparently forwarded to the plain
//! HTTP/WS listener via bidirectional tokio::io::copy.
//
//! This approach keeps jsonrpsee agnostic of TLS and supports both HTTP/HTTPS
//! and WS/WSS upgrade flows without patching the jsonrpsee server builder.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub struct TlsProxyHandle {
    pub public_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl TlsProxyHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

/// Start a TLS termination proxy.
///  - public_addr  : TLS listener (externally reachable)
/// - backend_addr : plain HTTP/WS jsonrpsee server (loopback)
/// - tls_config   : pre-built rustls::ServerConfig
pub async fn start_tls_proxy(
    public_addr: SocketAddr,
    backend_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<TlsProxyHandle, std::io::Error> {
    let listener = TcpListener::bind(public_addr).await?;
    let actual_addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(tls_config);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    info!("TLS proxy listening on {actual_addr} -> backend {backend_addr}");

    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        info!("TLS proxy shutting down");
                        break;
                    }
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcp_stream, peer_addr)) => {
                            debug!("TLS proxy: new connection from {peer_addr}");
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = forward_connection(tls_stream, backend_addr).await {
                                            debug!("TLS proxy forward error from {peer_addr}: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake error from {peer_addr}: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("TLS proxy accept error: {e}");
                        }
                    }
                }
            }
        }
    });

    Ok(TlsProxyHandle {
        public_addr: actual_addr,
        shutdown: shutdown_tx,
    })
}

async fn forward_connection(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    backend_addr: SocketAddr,
) -> io::Result<()> {
    let backend = tokio::net::TcpStream::connect(backend_addr).await?;
    let (mut tls_rd, mut tls_wr) = io::split(tls_stream);
    let (mut back_rd, mut back_wr) = io::split(backend);

    let c2s = async {
        let n = io::copy(&mut tls_rd, &mut back_wr).await?;
        back_wr.shutdown().await?;
        io::Result::Ok(n)
    };
    let s2c = async {
        let n = io::copy(&mut back_rd, &mut tls_wr).await?;
        tls_wr.shutdown().await?;
        io::Result::Ok(n)
    };

    tokio::try_join!(c2s, s2c)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn start_test_proxy() -> TlsProxyHandle {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let addr = "127.0.0.1:0".parse().unwrap();
        start_tls_proxy(addr, addr, Arc::new(config)).await.unwrap()
    }

    async fn assert_listener_released(addr: SocketAddr) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match TcpListener::bind(addr).await {
                    Ok(_listener) => return,
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("failed to rebind proxy listener: {error}"),
                }
            }
        })
        .await
        .expect("proxy retained its listening socket after shutdown");
    }

    #[tokio::test]
    async fn dropping_handle_releases_listener() {
        let proxy = start_test_proxy().await;
        let addr = proxy.public_addr;
        drop(proxy);
        assert_listener_released(addr).await;
    }

    #[tokio::test]
    async fn explicit_shutdown_releases_listener() {
        let proxy = start_test_proxy().await;
        proxy.shutdown();
        assert_listener_released(proxy.public_addr).await;
    }
}
