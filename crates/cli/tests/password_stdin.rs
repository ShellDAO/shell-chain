use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn key_generation_rejects_stdin_eof_without_creating_keystore() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    let output = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .args([
            "key",
            "generate",
            "--algorithm",
            "mldsa65",
            "--password-stdin",
            "--output",
        ])
        .arg(&key)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success(), "accepted EOF as a password");
    assert!(
        !key.exists(),
        "created a keystore without receiving a password"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("no password received"));
}

#[test]
fn key_generation_accepts_supplied_stdin_password_with_or_without_newline() {
    for (bytes, password) in [
        (b"test-password\n".as_slice(), b"test-password".as_slice()),
        (b"test-password".as_slice(), b"test-password".as_slice()),
        (b"\n".as_slice(), b"".as_slice()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.json");
        let mut child = Command::new(env!("CARGO_BIN_EXE_shell-node"))
            .args([
                "key",
                "generate",
                "--algorithm",
                "mldsa65",
                "--password-stdin",
                "--output",
            ])
            .arg(&key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let encrypted: shell_keystore::EncryptedKey =
            serde_json::from_slice(&std::fs::read(&key).unwrap()).unwrap();
        assert!(shell_keystore::decrypt_any(&encrypted, password).is_ok());
    }
}
