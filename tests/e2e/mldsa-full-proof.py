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
import re
from pathlib import Path
import subprocess
import sys

mode, raw_fixture, raw_output = sys.argv[1:]
assert mode in ("run", "verify", "consecutive")
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
    if (out / "network-consecutive/complete.json").exists():
        run("consecutive-verify", [fixture, "consecutive-verify", out])
    elif (out / "network-full/history-verified.json").exists():
        history_verify()
    else:
        run("full-verify", [fixture, "full-verify", out])
    sys.exit(0)
if mode == "consecutive":
    assert (out / "full-result.json").exists(), "complete run output required"
    if not (out / "consecutive-donor-snapshot.json").exists():
        save(out / "consecutive-donor-snapshot.json", snapshot("consecutive-donor-snapshot"))
    network = out / "network-consecutive"
    if not (network / "paused.json").exists():
        run("consecutive-pause", [fixture, "consecutive-pause", out])
        save(out / "consecutive-paused-snapshot.json", json.loads(run("consecutive-paused-snapshot", [fixture, "consecutive-snapshot", out])))
    assert (out / "consecutive-paused-snapshot.json").exists(), "unrecorded consecutive pause retained"
    if not (network / "complete.json").exists():
        run("consecutive-resume", [fixture, "consecutive-resume", out])
    after = json.loads(run("consecutive-complete-snapshot", [fixture, "consecutive-snapshot", out]))
    paused = json.loads((out / "consecutive-paused-snapshot.json").read_text())
    assert paused["native_digest"] == after["native_digest"], "consecutive proving changed native provider"
    indexed = {row["key"]: row for row in after["rows"]}
    donor = json.loads((out / "consecutive-donor-snapshot.json").read_text())
    for row in donor["rows"]:
        if bytes.fromhex(row["key"]) not in (b"local/canonical-production/v1/bytes", b"local/canonical-production/v1/jobs"):
            assert indexed[row["key"]] == row, "original donor certificate/source changed"
    logs = "\n".join(path.read_text() for label in ("consecutive-pause", "consecutive-resume") for path in (out / "commands").glob(label + "*.log"))
    generated = re.findall(r"^Proving (.+)$", logs, re.M)
    borrowed = re.findall(r"^Borrowed and reverified (.+)$", logs, re.M)
    common = re.compile(r"^(sender-0|proposer)-(key|key-hash|tagged-key|tr|matrix-[0-5]-[0-4]|t1-[0-5])$")
    assert len(generated) == len(set(generated)) == 41 and not any(common.fullmatch(name) for name in generated), "common math was regenerated"
    assert len(borrowed) == len(set(borrowed)) == 77 and all(common.fullmatch(name) for name in borrowed), "common certificates not reverified"
    run("consecutive-verify", [fixture, "consecutive-verify", out])
    run("consecutive-verify-cold", [fixture, "consecutive-verify", out])
    if not (out / "network-consecutive-bad/refused.json").exists():
        run("consecutive-bad-reference", [fixture, "consecutive-bad-reference", out])
    save(out / "consecutive-result.json", {"both_full_targets_proof_admitted": True, "common_components_reverified_not_regenerated": 77,
         "new_input_components_proved": 41, "physical_checkpoint_bytes": after["physical_checkpoint_bytes"],
         "original_donor_immutable": True, "cold_two_target_replays_no_writes": True,
         "corrupt_reference_production_refused": True, "finished_at": now()})
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
