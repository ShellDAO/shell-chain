#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

rustc "$SCRIPT_DIR/../crates/cli/build.rs" -o "$TMP_DIR/cli-build-script"

REPO="$TMP_DIR/repository"
git init -q -b main "$REPO"
git -C "$REPO" config user.name "ShellDAO Release Test"
git -C "$REPO" config user.email "release-test@shelldao.org"
touch "$REPO/tracked"
git -C "$REPO" add tracked
git -C "$REPO" commit -qm "fixture"

check_watch_paths() {
    local checkout=$1
    local output head_path head_ref ref_path
    output=$(cd "$checkout" && "$TMP_DIR/cli-build-script")
    head_path=$(git -C "$checkout" rev-parse --git-path HEAD)
    grep -Fxq "cargo:rerun-if-changed=$head_path" <<<"$output"

    head_ref=$(git -C "$checkout" symbolic-ref -q HEAD)
    ref_path=$(git -C "$checkout" rev-parse --git-path "$head_ref")
    grep -Fxq "cargo:rerun-if-changed=$ref_path" <<<"$output"
}

check_watch_paths "$REPO"

WORKTREE="$TMP_DIR/linked-worktree"
git -C "$REPO" worktree add -qb nested/linked "$WORKTREE"
check_watch_paths "$WORKTREE"

python3 - "$TMP_DIR" "$SCRIPT_DIR/../crates/cli/build.rs" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
build_script = Path(sys.argv[2])
env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))


def git(checkout, *args):
    return subprocess.check_output(["git", *args], cwd=checkout, text=True).strip()


def build(checkout, expect_fresh=False):
    result = subprocess.run(
        ["cargo", "build", "--offline", "--message-format=json"],
        cwd=checkout, env=env, capture_output=True, text=True, check=True,
    )
    artifacts = [
        message for line in result.stdout.splitlines()
        if (message := json.loads(line)).get("reason") == "compiler-artifact"
        and message["target"]["name"] == "git-stamp-fixture"
    ]
    if expect_fresh:
        assert artifacts[-1]["fresh"], f"unchanged checkout was rebuilt: {result.stderr}"
    suffix = ".exe" if os.name == "nt" else ""
    actual = subprocess.check_output(
        [str(root / "target" / "debug" / f"git-stamp-fixture{suffix}")], text=True,
    ).strip()
    assert actual == git(checkout, "rev-parse", "--short", "HEAD"), actual


for name in ("repository", "linked-worktree"):
    checkout = root / name
    (checkout / "src").mkdir()
    (checkout / "Cargo.toml").write_text(
        '[package]\nname="git-stamp-fixture"\nversion="0.1.0"\nedition="2021"\n'
    )
    (checkout / "src/main.rs").write_text(
        'fn main() { println!("{}", env!("GIT_HASH")); }\n'
    )
    shutil.copyfile(build_script, checkout / "build.rs")
    initial = git(checkout, "rev-parse", "HEAD")
    build(checkout)
    build(checkout, expect_fresh=True)
    git(checkout, "pack-refs", "--all", "--prune")
    build(checkout)
    build(checkout, expect_fresh=True)
    build(checkout, expect_fresh=True)
    (checkout / "tracked").write_text(name)
    git(checkout, "add", "tracked")
    git(checkout, "commit", "-qm", "advance fixture HEAD")
    build(checkout)
    build(checkout, expect_fresh=True)
    git(checkout, "pack-refs", "--all", "--prune")
    build(checkout)
    git(checkout, "commit", "--allow-empty", "-qm", "advance packed fixture HEAD")
    git(checkout, "pack-refs", "--all", "--prune")
    build(checkout)
    build(checkout, expect_fresh=True)
    git(checkout, "checkout", "-q", "--detach", initial)
    build(checkout)
    build(checkout, expect_fresh=True)
PY

echo "CLI git hash watch tests passed"
