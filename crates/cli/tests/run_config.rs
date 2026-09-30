use std::process::Command;

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
