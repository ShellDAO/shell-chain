#!/usr/bin/env python3
"""Real ordinary block sync, proof discovery, interrupted transfer and native replay.

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

mode, raw_fixture, raw_output = sys.argv[1:]
assert mode in ("run", "verify")
fixture, out = map(lambda p: Path(p).resolve(), (raw_fixture, raw_output))

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
    run("cold-verify", [fixture, "peer-admission-verify", out])

if mode == "verify":
    assert (out / "network/complete.json").exists(), "automatic native admission incomplete"
    if (out / "network/sync-complete.json").exists():
        run("cold-sync-verify", [fixture, "peer-admission-sync-verify", out])
    else:
        verify()
    sys.exit(0)
if (out / "network/result.json").exists():
    if not (out / "network/sync-complete.json").exists():
        run("peer-admission-sync", [fixture, "peer-admission-sync", out])
    run("cold-sync-verify", [fixture, "peer-admission-sync-verify", out])
    run("cold-sync-verify", [fixture, "peer-admission-sync-verify", out])
    print((out / "network/sync-complete.json").read_text())
    sys.exit(0)
if not (out / "network/initial.json").exists():
    assert not (out / "network").exists(), "partial network preparation retained; inspect receipts"
    run("prepare-peer-admission", [fixture, "prepare-peer-admission", out])
if not (out / "network/paused.json").exists():
    run("peer-admission-pause", [fixture, "peer-admission-pause", out])
    save(out / "network/paused-snapshot.json", snapshot("peer-admission-snapshot", "peer-paused-snapshot"))
assert (out / "network/paused-snapshot.json").exists(), "unrecorded partial transfer retained"
paused = json.loads((out / "network/paused-snapshot.json").read_text())
assert len(paused["immutable_chunks"]) == 3
if not (out / "network/complete.json").exists():
    run("peer-admission-resume", [fixture, "peer-admission-resume", out])
after = snapshot("peer-admission-snapshot", "peer-completed-snapshot")
by_key = {r["key"]: r for r in after["immutable_chunks"]}
assert all(by_key[r["key"]] == r for r in paused["immutable_chunks"])
assert after["head"] == json.loads((out / "context.json").read_text())["block"]
verify()
verify()
if not (out / "network-bad-air/refused.json").exists():
    run("peer-admission-bad-air", [fixture, "peer-admission-bad-air", out])
if not (out / "network-bad-air/refused-recheck.json").exists():
    run("peer-admission-recheck-bad-air", [fixture, "peer-admission-recheck-bad-air", out])
result = {"stale_verifier_and_forged_verified_cache_refused": True, "correct_hash_invalid_AIR_refused_without_native_writes": True, "ordinary_network_import": True, "no_operator_fetch_or_import": True, "partial_three_chunks_immutable": True, "cold_restart_auto_resume": True, "independent_native_root_receipts_accounts": True, "cold_full_proof_replays": 2, "finished_at": now()}
path = out / "network/result.json"
assert not path.exists(), "network result already exists; use verify"
save(path, result)
run("peer-admission-sync", [fixture, "peer-admission-sync", out])
run("cold-sync-verify", [fixture, "peer-admission-sync-verify", out])
run("cold-sync-verify", [fixture, "peer-admission-sync-verify", out])
print((out / "network/sync-complete.json").read_text())
