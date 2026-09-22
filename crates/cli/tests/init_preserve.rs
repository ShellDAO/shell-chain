use std::path::Path;
use std::process::Command;

fn run_init(datadir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .arg("--datadir")
        .arg(datadir)
        .args(["init", "--network", "dev"])
        .output()
        .unwrap()
}

#[test]
fn init_preserves_existing_genesis_without_creating_authority() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = dir.path().join("genesis.json");
    let original = b"existing genesis must remain byte-for-byte unchanged";
    std::fs::write(&genesis, original).unwrap();

    let output = run_init(dir.path());
    assert!(
        !output.status.success(),
        "init replaced an existing genesis"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("genesis.json already exists"));
    assert_eq!(std::fs::read(&genesis).unwrap(), original);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn init_preserves_dangling_genesis_symlink_and_its_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("missing-target.json");
    let genesis = dir.path().join("genesis.json");
    symlink(&target, &genesis).unwrap();

    let output = run_init(dir.path());
    assert!(!output.status.success(), "init followed a genesis symlink");
    assert!(String::from_utf8_lossy(&output.stderr).contains("genesis.json already exists"));
    assert_eq!(std::fs::read_link(&genesis).unwrap(), target);
    assert!(!target.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
