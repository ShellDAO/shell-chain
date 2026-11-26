use std::process::Command;

#[test]
fn documented_slh_tag_inspects_and_migrates_without_changing_identity() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    let migrated = dir.path().join("migrated.json");
    let password = dir.path().join("password");
    std::fs::write(&password, "temporary SLH test password\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .arg("--password-file")
        .arg(&password)
        .args(["key", "generate", "--algorithm", "slhdsa", "--output"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let mut input: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key).unwrap()).unwrap();
    assert_eq!(input["key_type"], "sphincs-sha2-256f");
    input["key_type"] = "slh-dsa-sha2-256f".into();
    let bytes = serde_json::to_vec(&input).unwrap();
    std::fs::write(&key, &bytes).unwrap();
    let inspected = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .args(["key", "inspect"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(inspected.status.success(), "{:?}", inspected);
    assert!(String::from_utf8(inspected.stdout)
        .unwrap()
        .contains(input["address"].as_str().unwrap()));
    let migrate = || {
        Command::new(env!("CARGO_BIN_EXE_shell-node"))
            .arg("--password-file")
            .arg(&password)
            .args(["key", "migrate", "--input"])
            .arg(&key)
            .arg("--output")
            .arg(&migrated)
            .output()
            .unwrap()
    };
    let output = migrate();
    assert!(output.status.success(), "{:?}", output);
    let output_bytes = std::fs::read(&migrated).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output_bytes).unwrap();
    assert_eq!(value["address"], input["address"]);
    assert_eq!(value["public_key"], input["public_key"]);
    assert_eq!(value["key_type"], "sphincs-sha2-256f");
    assert_ne!(value["ciphertext"], input["ciphertext"]);
    assert_eq!(std::fs::read(&key).unwrap(), bytes);
    assert!(!migrate().status.success());
    assert_eq!(std::fs::read(&migrated).unwrap(), output_bytes);
}
