//! Standalone circuit-relay service; no chain state or validator keys are opened.
use std::{net::SocketAddr, path::PathBuf};

pub async fn relay(
    datadir: PathBuf,
    listen_addr: SocketAddr,
    external_addresses: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "libp2p"))]
    {
        let _ = (datadir, listen_addr, external_addresses);
        Err("relay requires a native build with the libp2p feature".into())
    }
    #[cfg(feature = "libp2p")]
    {
        use shell_network::{Libp2pNetwork, NetworkConfig, NetworkService};
        use std::time::Duration;
        std::fs::create_dir_all(&datadir)?;
        let config = NetworkConfig {
            listen_addr,
            external_addresses,
            enable_gossip: false,
            enable_mdns: false,
            enable_kademlia: false,
            enable_relay: false,
            enable_relay_server: true,
            enable_dcutr: false,
            enable_autonat: false,
            identity_key_path: Some(datadir.join("relay.key")),
            ..Default::default()
        };
        let mut network = Libp2pNetwork::new(&config).await?;
        let info = network.local_node_info_handle();
        let bound = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let bound = info.read().unwrap().clone();
                if !bound.listen_addresses.is_empty() {
                    break bound;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        println!(
            "{}",
            serde_json::json!({"peer_id": bound.peer_id, "listen_addresses": bound.listen_addresses, "protocols": bound.protocols})
        );
        let shutdown = async {
            #[cfg(unix)]
            {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::select! {
                    result = tokio::signal::ctrl_c() => result?,
                    _ = terminate.recv() => {},
                }
            }
            #[cfg(not(unix))]
            tokio::signal::ctrl_c().await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = &mut shutdown => { result?; break; },
                event = network.next_event() => {
                    if event.is_none() { return Err("relay network stopped unexpectedly".into()); }
                },
            }
        }
        network.shutdown().await?;
        Ok(())
    }
}
