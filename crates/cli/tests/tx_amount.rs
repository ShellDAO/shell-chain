use std::process::{Command, Stdio};

#[test]
fn empty_hex_amount_is_rejected_before_keystore_access() {
    let dir = tempfile::tempdir().unwrap();
    let missing_key = dir.path().join("missing-key.json");
    let recipient = format!("0x{}", "11".repeat(32));
    for (subcommand, arguments) in [
        ("send", vec!["--to", recipient.as_str()]),
        ("deploy", vec!["--code", "0x00"]),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shell-node"))
            .args(["tx", subcommand])
            .args(arguments)
            .args(["--value", "0x", "--keystore"])
            .arg(&missing_key)
            .arg("--password-stdin")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("hex value must contain at least one digit"),
            "{subcommand} did not reject the amount before accessing the key: {stderr}"
        );
    }
}
