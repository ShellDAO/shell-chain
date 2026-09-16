use std::{path::Path, process::Command};

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn watch_existing_path(path: &Path) {
    // A missing watched file makes every Cargo invocation rerun this script.
    // Watch its existing ancestor so creating a loose ref still invalidates it.
    if let Some(existing) = path.ancestors().find(|candidate| candidate.exists()) {
        println!("cargo:rerun-if-changed={}", existing.display());
    }
}

fn main() {
    // Embed git commit hash at compile time.
    let git_hash = git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={git_hash}");

    if let Some(head_path) = git_output(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head_path}");
    }
    if let Some(head_ref) = git_output(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(ref_path) = git_output(&["rev-parse", "--git-path", &head_ref]) {
            let ref_path = Path::new(&ref_path);
            watch_existing_path(ref_path);
            if !ref_path.exists() {
                if let Some(packed_refs) = git_output(&["rev-parse", "--git-path", "packed-refs"]) {
                    watch_existing_path(Path::new(&packed_refs));
                }
            }
        }
    }
}
