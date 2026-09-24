use std::process::Command;

#[test]
fn inspected_address_is_available_to_stdout_consumers() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    let password = dir.path().join("password");
    std::fs::write(&password, "test-password\n").unwrap();
    let generated = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .arg("--password-file")
        .arg(&password)
        .args(["key", "generate", "--algorithm", "mldsa65", "--output"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let mut encrypted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key).unwrap()).unwrap();
    let expected = encrypted["address"].as_str().unwrap().to_owned();

    for legacy in [false, true] {
        if legacy {
            encrypted["address"] = serde_json::json!("legacy-address");
            std::fs::write(&key, serde_json::to_vec(&encrypted).unwrap()).unwrap();
        }
        let inspected = Command::new(env!("CARGO_BIN_EXE_shell-node"))
            .args(["key", "inspect"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(inspected.status.success());
        let stdout = String::from_utf8(inspected.stdout).unwrap();
        let stderr = String::from_utf8(inspected.stderr).unwrap();
        let addresses: Vec<_> = stdout
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Address:"))
            .map(str::trim)
            .collect();
        assert_eq!(addresses, [expected.as_str()]);
        assert!(!stdout.contains("Legacy address field"));
        if legacy {
            assert!(stderr.contains("Legacy address field"));
        } else {
            assert!(stderr.is_empty(), "{stderr}");
        }
    }
}

#[test]
fn invalid_keystore_reports_failure_without_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("invalid.json");
    std::fs::write(&key, "not a keystore").unwrap();
    let inspected = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .args(["key", "inspect"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(!inspected.status.success());
    assert!(inspected.stdout.is_empty());
    assert!(!inspected.stderr.is_empty());
}
