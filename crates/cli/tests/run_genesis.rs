use std::path::Path;
use std::process::{Command, Output};

fn run_without_listeners(datadir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .arg("--datadir")
        .arg(datadir)
        .args([
            "run",
            "--db",
            "memory",
            "--network",
            "dev",
            "--rpc-addr",
            "invalid",
        ])
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn run_does_not_generate_dev_genesis_through_a_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("missing-genesis.json");
    let genesis = dir.path().join("genesis.json");
    std::os::unix::fs::symlink(&target, &genesis).unwrap();

    let output = run_without_listeners(dir.path());
    assert!(!output.status.success());
    assert!(
        !target.exists(),
        "run generated a dev genesis through the dangling link"
    );
    assert_eq!(std::fs::read_link(&genesis).unwrap(), target);
    assert!(String::from_utf8_lossy(&output.stderr).contains("genesis"));
}

#[test]
fn run_generates_missing_dev_genesis_and_preserves_it_on_restart() {
    let dir = tempfile::tempdir().unwrap();
    let first = run_without_listeners(dir.path());
    assert!(!first.status.success());
    assert!(String::from_utf8_lossy(&first.stderr).contains("invalid socket address"));
    let genesis = dir.path().join("genesis.json");
    let original = std::fs::read(&genesis).unwrap();
    let config: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(config["chain_id"], 1337);

    let second = run_without_listeners(dir.path());
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("invalid socket address"));
    assert_eq!(std::fs::read(&genesis).unwrap(), original);

    #[cfg(unix)]
    {
        let target = dir.path().join("trusted-genesis.json");
        std::fs::rename(&genesis, &target).unwrap();
        std::os::unix::fs::symlink(&target, &genesis).unwrap();
        let linked = run_without_listeners(dir.path());
        assert!(!linked.status.success());
        assert!(String::from_utf8_lossy(&linked.stderr).contains("invalid socket address"));
        assert_eq!(std::fs::read(&target).unwrap(), original);
        assert_eq!(std::fs::read_link(&genesis).unwrap(), target);
    }
}
