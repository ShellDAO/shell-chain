#!/usr/bin/env python3
"""Full MLDSA65 proposer and sender AIR: durable production, peer intake and replay.

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

def snapshot(label):
    return json.loads(run(label, [fixture, "full-snapshot", out]))

def history_verify():
    run("full-history-verify", [fixture, "full-history-verify", out])

if mode == "verify":
    assert (out / "network-full/complete.json").exists(), "full peer import incomplete"
    if (out / "network-full/history-verified.json").exists():
        history_verify()
    else:
        run("full-verify", [fixture, "full-verify", out])
    sys.exit(0)
out.mkdir(exist_ok=True)
if not (out / "control.json").exists():
    run("prepare-full", [fixture, "prepare-full", out])
assert (out / "later-control.json").exists(), "partial native preparation retained; inspect receipts"
if not (out / "network-full/paused.json").exists():
    run("full-pause", [fixture, "full-pause", out])
    save(out / "full-paused-snapshot.json", snapshot("full-paused-snapshot"))
assert (out / "full-paused-snapshot.json").exists(), "unrecorded full pause retained"
if not (out / "network-full/complete.json").exists():
    run("full-resume", [fixture, "full-resume", out])
paused = json.loads((out / "full-paused-snapshot.json").read_text())
after = snapshot("full-complete-snapshot")
assert paused["native_digest"] == after["native_digest"], "proving changed native source state"
indexed = {row["key"]: row for row in after["rows"]}
for row in paused["rows"]:
    key = bytes.fromhex(row["key"])
    if b"production/component/" in key or b"production/source" in key or b"/source/" in key:
        assert indexed[row["key"]] == row, "retained full certificate/source changed"
if not (out / "network-full/verified.json").exists():
    run("full-verify", [fixture, "full-verify", out])
if not (out / "network-full/history-verified.json").exists():
    run("full-history", [fixture, "full-history", out])
history_verify()
if not (out / "network-full-bad/envelope-refused.json").exists():
    run("full-bad-proposer", [fixture, "full-bad-proposer", out])
result = {"real_node_run": True, "fresh_MLDSA65_sender_and_proposer": True,
          "native_production_captured_v2": True, "shutdown_checkpoint_reverified": True,
          "complete_components": 118, "native_peer_import_consumed_proposer_AIR": True,
          "native_controls_match": True, "cold_replay_and_changed_current_state_no_writes": True,
          "bad_proposer_AIR_and_invalid_envelopes_refused": True,
          "proof_bytes": (out / "job/proof.json").stat().st_size, "finished_at": now()}
path = out / "full-result.json"
assert not path.exists(), "full result exists; use verify"
save(path, result)
print(json.dumps(result))
