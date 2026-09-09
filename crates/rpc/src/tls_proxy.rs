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
        // Handshakes and forwarding tasks stop when the proxy shuts down.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next() => {}
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
                            connections.spawn(async move {
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

    #[tokio::test]
    async fn stopping_proxy_closes_forwarded_connections() {
        use tokio::io::AsyncReadExt;

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_config = Arc::new(server_config);

        for drop_handle in [false, true] {
            let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = start_tls_proxy(
                "127.0.0.1:0".parse().unwrap(),
                backend.local_addr().unwrap(),
                Arc::clone(&server_config),
            )
            .await
            .unwrap();
            let (mut client, mut backend_stream) =
                tokio::time::timeout(Duration::from_secs(2), async {
                    let tcp = tokio::net::TcpStream::connect(proxy.public_addr)
                        .await
                        .unwrap();
                    let client = connector
                        .connect("localhost".try_into().unwrap(), tcp)
                        .await
                        .unwrap();
                    let (stream, _) = backend.accept().await.unwrap();
                    (client, stream)
                })
                .await
                .expect("TLS proxy connection did not start");
            client.write_all(b"ping").await.unwrap();
            let mut ping = [0; 4];
            tokio::time::timeout(Duration::from_secs(2), backend_stream.read_exact(&mut ping))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&ping, b"ping");

            if drop_handle {
                drop(proxy);
            } else {
                proxy.shutdown();
            }
            let mut byte = [0; 1];
            let count =
                tokio::time::timeout(Duration::from_secs(2), backend_stream.read(&mut byte))
                    .await
                    .expect("forwarded connection survived proxy shutdown")
                    .unwrap();
            assert_eq!(count, 0);
        }
    }
}
