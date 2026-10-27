#[cfg(not(feature = "libp2p"))]
fn main() {
    eprintln!("Build this acceptance peer with --features libp2p");
    std::process::exit(2);
}

#[cfg(feature = "libp2p")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::{json, Value};
    use shell_consensus::EquivocationProof;
    use shell_core::BlockHeader;
    use shell_crypto::{MlDsaSigner, MultiVerifier, Signer};
    use shell_network::{Libp2pNetwork, NetworkConfig, NetworkMessage, NetworkService, PeerId};
    use shell_primitives::{Address, ShellHash};
    use std::io::Write;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};

    fn emit(value: Value) {
        println!("{value}");
        std::io::stdout().flush().unwrap();
    }

    let signer = MlDsaSigner::generate();
    let offender = Address::from_public_key(signer.public_key(), signer.sig_type().as_u8());
    let public_key: String = signer
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    emit(
        json!({"event":"ready", "offender":offender.to_string(), "public_key":format!("0x{public_key}")}),
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut network = None;
    let mut peer = None;
    let mut fixture = Value::Null;
    while let Some(line) = lines.next_line().await? {
        let command: Value = serde_json::from_str(&line)?;
        match command["action"].as_str().ok_or("missing action")? {
            "init" => {
                let bootnode = command["bootnode"].as_str().ok_or("missing bootnode")?;
                peer = Some(PeerId(
                    bootnode.rsplit('/').next().ok_or("missing peer id")?.into(),
                ));
                if let Some(saved) = command.get("fixture") {
                    fixture = saved.clone();
                } else {
                    let hex = command["parent_hash"]
                        .as_str()
                        .ok_or("missing parent hash")?
                        .trim_start_matches("0x");
                    if hex.len() != 64 {
                        return Err("parent hash must be 32 bytes".into());
                    }
                    let mut parent = [0; 32];
                    for (i, byte) in parent.iter_mut().enumerate() {
                        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
                    }
                    let header = |marker| BlockHeader {
                        parent_hash: ShellHash::from(parent),
                        number: 1,
                        proposer: offender,
                        state_root: ShellHash::from([marker; 32]),
                        gas_limit: 30_000_000,
                        timestamp: command["timestamp"]
                            .as_u64()
                            .ok_or("missing timestamp")
                            .unwrap(),
                        ..Default::default()
                    };
                    let a = header(1);
                    let b = header(2);
                    let first = EquivocationProof {
                        offender,
                        hash_a: a.hash(),
                        hash_b: b.hash(),
                        seal_a: Some(signer.sign(a.hash().as_bytes())?),
                        seal_b: Some(signer.sign(b.hash().as_bytes())?),
                        header_a: Box::new(a.clone()),
                        header_b: Box::new(b.clone()),
                    };
                    assert!(first.verify_signed(signer.public_key(), &MultiVerifier));
                    let mut reversed = first.clone();
                    std::mem::swap(&mut reversed.header_a, &mut reversed.header_b);
                    std::mem::swap(&mut reversed.hash_a, &mut reversed.hash_b);
                    std::mem::swap(&mut reversed.seal_a, &mut reversed.seal_b);
                    assert!(reversed.verify_signed(signer.public_key(), &MultiVerifier));
                    let mut invalid = first.clone();
                    invalid.seal_a = Some(signer.sign(b"wrong header digest")?);
                    assert!(!invalid.verify_signed(signer.public_key(), &MultiVerifier));
                    let mut c = header(3);
                    c.number = 2;
                    c.parent_hash = a.hash();
                    let mut d = header(4);
                    d.number = 2;
                    d.parent_hash = a.hash();
                    let distinct = EquivocationProof {
                        offender,
                        hash_a: c.hash(),
                        hash_b: d.hash(),
                        seal_a: Some(signer.sign(c.hash().as_bytes())?),
                        seal_b: Some(signer.sign(d.hash().as_bytes())?),
                        header_a: Box::new(c),
                        header_b: Box::new(d),
                    };
                    assert!(distinct.verify_signed(signer.public_key(), &MultiVerifier));
                    fixture = json!({"first":NetworkMessage::EquivocationEvidence(Box::new(first)),"reversed":NetworkMessage::EquivocationEvidence(Box::new(reversed)),"invalid":NetworkMessage::EquivocationEvidence(Box::new(invalid)),"distinct":NetworkMessage::EquivocationEvidence(Box::new(distinct))});
                }
                let config = NetworkConfig {
                    listen_addr: "127.0.0.1:0".parse()?,
                    boot_nodes: vec![bootnode.into()],
                    enable_mdns: false,
                    enable_kademlia: false,
                    enable_relay: false,
                    enable_dcutr: false,
                    enable_autonat: false,
                    ..Default::default()
                };
                let n = Libp2pNetwork::new(&config).await?;
                tokio::time::timeout(Duration::from_secs(15), async {
                    while n.peer_count().await == 0 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await?;
                network = Some(n);
                emit(json!({"event":"peered","fixture":fixture}));
            }
            "send" => {
                let kind = command["kind"].as_str().ok_or("missing kind")?;
                let message: NetworkMessage = serde_json::from_value(fixture[kind].clone())?;
                network
                    .as_ref()
                    .ok_or("not initialized")?
                    .send_to_peer(peer.as_ref().ok_or("missing peer")?, message)
                    .await?;
                tokio::time::sleep(Duration::from_millis(300)).await;
                emit(json!({"event":"queued","kind":kind}));
            }
            "stop" => break,
            _ => return Err("unknown action".into()),
        }
    }
    if let Some(n) = network {
        n.shutdown().await?;
    }
    Ok(())
}
