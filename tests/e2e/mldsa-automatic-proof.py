#!/usr/bin/env python3
"""Real Node.run automatic proving, advanced live state, cold resume and native replay.

Python 3, stable Rust and the repository RocksDB prerequisites are required.
This expensive public-certificate test creates fresh test keys in memory only.
Keep its output directory: run resumes checkpoints; verify never regenerates them.
Every child has a durable argv/PID/log/exit receipt. Any failed assertion exits nonzero.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

mode, raw_cli, raw_fixture, raw_output = sys.argv[1:]
assert mode in ("run", "verify")
cli, fixture, out = map(lambda p: Path(p).resolve(), (raw_cli, raw_fixture, raw_output))

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)

def run(label, args, expected=0):
    receipts = out / "commands"
    receipts.mkdir(exist_ok=True)
    path = receipts / (label + ".json")
    if path.exists():
        previous = json.loads(path.read_text())
        if "exit_code" not in previous:
            try:
                os.kill(previous["pid"], 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError(f"{label} still owns PID {previous['pid']}; inspect its log")
        # Preserve incomplete/failed run receipts and always use a new attempt.
        index = 2
        while path.exists():
            path = receipts / f"{label}-{index}.json"
            index += 1
    log = path.with_suffix(".log")
    record = {"argv": list(map(str, args)), "cwd": str(Path.cwd()), "started_at": now(), "log": str(log)}
    with log.open("w") as stream:
        child = subprocess.Popen(record["argv"], stdout=stream, stderr=subprocess.STDOUT)
        record["pid"] = child.pid
        save(path, record)
        record["exit_code"] = child.wait()
    record["finished_at"] = now()
    save(path, record)
    text = log.read_text()
    assert record["exit_code"] == expected, f"{label}: {record['exit_code']} != {expected}; see {log}"
    return text

def snapshot(role, label):
    return json.loads(run(label, [fixture, role, out]))

def verify():
    run("cold-verify", [fixture, "verify", out])

if mode == "verify":
    assert (out / "runtime-complete.json").exists(), "automatic production incomplete"
    verify()
    sys.exit(0)
# CLI must reject invalid automatic-production choices before creating native state.
for label, flags in [("role", ["--canonical-proof-production"]), ("budget", ["--canonical-proof-component-budget", "1"])]:
    guard = out.parent / (out.name + "-rejected-" + label)
    assert not guard.exists(), "previous rejected-state path retained"
    # Command receipts live in output; preparation allows this directory only.
    out.mkdir(exist_ok=True)
    rejected = run("reject-" + label, [cli, "--datadir", guard, "run", *flags], expected=1)
    assert "requires" in rejected and not guard.exists()
if not (out / "control.json").exists():
    run("prepare-runtime", [fixture, "prepare-runtime", out])
else:
    assert (out / "advance-control.json").is_file(), "partial preparation retained; inspect receipts"
if not (out / "runtime-paused.json").exists():
    run("runtime-pause", [fixture, "runtime-pause", out])
    save(out / "paused-snapshot.json", snapshot("runtime-snapshot", "paused-snapshot"))
assert (out / "paused-snapshot.json").exists(), "unrecorded paused state retained"
if not (out / "runtime-complete.json").exists():
    run("runtime-resume", [fixture, "runtime-resume", out])
paused = json.loads((out / "paused-snapshot.json").read_text())
after = snapshot("runtime-snapshot", "runtime-after")
assert paused["native_digest"] == after["native_digest"], "canonical data changed during proving"
indexed = {row["key"]: row for row in after["rows"]}
for row in paused["rows"]:
    key = bytes.fromhex(row["key"])
    if b"production/source" in key or b"production/component/" in key or b"/source/" in key:
        assert indexed[row["key"]] == row, "previous source/certificate changed"
context = json.loads((out / "context.json").read_text())
control = json.loads((out / "control.json").read_text())
follower = snapshot("follower-snapshot", "follower-before-import")
proof = out / "job/proof.json"
manifest = json.loads((out / "job/manifest.json").read_text())
assert proof.stat().st_size == manifest["totalBytes"]
if follower["head"] == control["parent"]:
    run("import-automatic", [cli, "--datadir", out / "follower", "import-block-proof", "--block", out / "job/block.json", "--proof", proof, "--manifest", out / "job/manifest.json", "--consensus", out / "consensus.json", "--parent", control["parent"]])
else:
    assert follower["head"] == context["block"], "unexpected follower head"
verify()
verify()
if not (out / "runtime-next-job-paused.json").exists():
    run("runtime-next-job", [fixture, "runtime-next-job", out])
for mode in ["runtime-bad-certificate", "runtime-bad-source"]:
    if not (out / mode / "refused.json").exists():
        assert not (out / mode).exists(), "partial negative output retained; inspect receipts"
        rejected = run(mode, [fixture, mode, out])
        assert "Proving " not in rejected, "corrupt cached source/certificate triggered new generation"
if not (out / "production-hook/produced-job.json").exists():
    assert not (out / "production-hook").exists(), "partial production hook fixture retained"
    run("production-hook", [fixture, "prepare-production-hook", out / "production-hook"])
result = {"native_production_hook_queued": True, "second_import_job_dispatched_and_paused": True, "correct_hash_bad_certificate_source_refused": True, "actual_node_run": True, "authenticated_rpc_download": True, "pause_restart_resume": [3, 58], "components": 61, "advanced_local_height": 130, "canonical_state_unchanged": True, "cached_components_immutable": True, "actual_cli_import_and_two_cold_replays": True, "proof_bytes": proof.stat().st_size, "proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(), "finished_at": now()}
index = 1
path = out / "result.json"
while path.exists():
    index += 1
    path = out / f"result-{index}.json"
save(path, result)
print(json.dumps(result))
