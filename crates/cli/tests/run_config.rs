use std::process::Command;

struct RunningNode(std::process::Child);

impl Drop for RunningNode {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn configured_consensus_engine_drives_the_running_node() {
    for (configured, cli, expected) in [
        (Some("poa"), None, "poa"),
        (Some("wpoa"), None, "wpoa"),
        (Some("poa"), Some("wpoa"), "wpoa"),
        (Some("wpoa"), Some("poa"), "poa"),
        (None, None, "wpoa"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("node.toml");
        let mut toml = "[metrics]\nenabled = false\n".to_string();
        if let Some(engine) = configured {
            toml.push_str(&format!("[consensus]\nengine = \"{engine}\"\n"));
        }
        std::fs::write(&config, toml).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log_path = dir.path().join("node.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shell-node"));
        command
            .arg("--datadir")
            .arg(dir.path())
            .args(["run", "--config"])
            .arg(config)
            .args([
                "--db",
                "memory",
                "--network",
                "dev",
                "--rpc-addr",
                &addr.to_string(),
                "--block-time",
                "1000",
                "--max-idle-interval",
                "0",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        if let Some(engine) = cli {
            command.args(["--consensus-engine", engine]);
        }
        drop(listener);
        for startup in 0..2 {
            let mut node = RunningNode(command.spawn().unwrap());
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(1))
                .build();
            let rpc = |method| -> Option<serde_json::Value> {
                agent
                    .post(&format!("http://{addr}"))
                    .send_json(
                        serde_json::json!({"jsonrpc":"2.0", "id":1, "method":method, "params":[]}),
                    )
                    .ok()?
                    .into_json::<serde_json::Value>()
                    .ok()?
                    .get("result")
                    .cloned()
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                assert!(
                    node.0.try_wait().unwrap().is_none(),
                    "{}",
                    std::fs::read_to_string(&log_path).unwrap()
                );
                if let Some(height) = rpc("eth_blockNumber") {
                    if height.as_str().is_some_and(|h| h != "0x0") {
                        break;
                    }
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "node did not produce a block: {}",
                    std::fs::read_to_string(&log_path).unwrap()
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let info = rpc("shell_consensusInfo").expect("consensus info");
            assert_eq!(
                info["engine"], expected,
                "config={configured:?}, cli={cli:?}, startup={startup}"
            );
            println!("config={configured:?}, cli={cli:?}, startup={startup}, actual={info}");
        }
    }
}

#[test]
fn configured_role_is_validated_and_explicit_cli_role_takes_precedence() {
    for override_role in [None, Some("validator"), Some("prover")] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("node.toml");
        std::fs::write(&config, "[node]\nnode_role = \"unsupported\"\n").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shell-node"));
        command
            .arg("--datadir")
            .arg(dir.path())
            .args(["run", "--config"])
            .arg(&config)
            .args([
                "--db",
                "memory",
                "--network",
                "dev",
                "--rpc-addr",
                "invalid",
            ]);
        if let Some(role) = override_role {
            command.args(["--node-role", role]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        if override_role.is_some() {
            // Role selection succeeds; stop before opening any listeners.
            assert!(stderr.contains("invalid socket address"), "{stderr}");
            assert!(!stderr.contains("invalid --node-role"), "{stderr}");
        } else {
            assert!(stderr.contains("invalid --node-role"), "{stderr}");
        }
    }
}

#[test]
fn storage_profile_file_and_cli_select_the_running_pruning_policy() {
    // The RPC uses the canonical Pruned name for the CLI light alias.
    for (configured, cli, expected, keep_recent) in [
        ("archive", None, "archive", 0),
        ("light", None, "pruned", 4096),
        ("archive", Some("full"), "full", 0),
        ("full", Some("light"), "pruned", 4096),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("node.toml");
        std::fs::write(
            &config,
            format!("[storage]\nprofile={configured:?}\n[metrics]\nenabled=false\n"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log_path = dir.path().join("node.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shell-node"));
        command
            .arg("--datadir")
            .arg(dir.path())
            .args(["run", "--config"])
            .arg(&config)
            .args(["--db", "memory", "--rpc-addr", &addr.to_string()])
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        if let Some(profile) = cli {
            command.args(["--storage-profile", profile]);
        }
        drop(listener);
        let mut node = RunningNode(command.spawn().unwrap());
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(1))
            .build();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let result = loop {
            assert!(
                node.0.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(&log_path).unwrap()
            );
            if let Ok(response) = agent.post(&format!("http://{addr}"))
                .send_json(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"shell_getStorageProfile","params":[]})) {
                let value: serde_json::Value = response.into_json().unwrap();
                break value["result"].clone();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{}",
                std::fs::read_to_string(&log_path).unwrap()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert_eq!(
            result["profile"], expected,
            "config={configured}, cli={cli:?}: {result}"
        );
        assert_eq!(result["keep_recent"], keep_recent);
        if expected == "archive" {
            assert_eq!(result["body_retention"], 0);
            assert_eq!(result["witness_retention"], 0);
        }
    }
}
