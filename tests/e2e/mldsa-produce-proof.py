#!/usr/bin/env python3
"""Cold raw-source proving, durable pause/resume, actual CLI import and cold replay.

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
    assert (out / "job/manifest.json").is_file(), "production not complete"
    verify()
    sys.exit(0)

if not out.exists():
    out.mkdir()
    run("prepare", [fixture, "prepare", out])
else:
    assert (out / "control.json").is_file(), "partial preparation retained; inspect output"
context = json.loads((out / "context.json").read_text())
control = json.loads((out / "control.json").read_text())
produce = [cli, "--datadir", out / "native", "produce-block-proof", "--block-hash", context["block"], "--expected-tip", context["tip"], "--output", out / "job"]
before = snapshot("snapshot", "native-before")
assert before["digest"] == control["native_digest"]
if not (out / "paused.json").exists():
    assert not (out / "job").exists(), "unrecorded production job retained; inspect receipts"
    rejected = run("stale-source", [cli, "--datadir", out / "native", "produce-block-proof", "--block-hash", context["block"], "--expected-tip", "0x" + "00" * 32, "--output", out / "job"], expected=1)
    assert "unavailable" in rejected and not (out / "job").exists()
    paused = run("produce-pause", [*produce, "--component-limit", "3"], expected=1)
    assert "production paused" in paused
    progress = next(json.loads(line) for line in paused.splitlines() if line.startswith('{"components":'))
    assert progress["newly_proved"] == progress["components"] == 3
    assert not (out / "job/proof.json").exists()
    stages = snapshot("job-snapshot", "paused-job")
    save(out / "paused.json", {"native": before, "job": stages, "progress": progress})
if not (out / "negative-caches.json").exists():
    for role in ["corrupt-stage", "corrupt-source", "over-quota"]:
        if not (out / role).exists():
            run("prepare-" + role, [fixture, role, out])
        assert (out / (role + "-prepared.json")).exists(), "partial negative fixture retained; inspect receipt"
    negatives_before = snapshot("negative-snapshot", "negative-before")
    for role, error in [("corrupt-stage", "key"), ("corrupt-source", "source/index mismatch"), ("over-quota", "quota exceeded")]:
        refused = run("reject-" + role, [*produce[:-1], out / role, "--component-limit", "1"], expected=1)
        assert error in refused and "Proving " not in refused
        assert not (out / role / "proof.json").exists()
    assert snapshot("negative-snapshot", "negative-after") == negatives_before
    assert snapshot("job-snapshot", "genuine-after-rejections") == json.loads((out / "paused.json").read_text())["job"]
    assert snapshot("snapshot", "native-after-rejections") == before
    save(out / "negative-caches.json", {"correctly_hashed_bad_certificate_refused": True, "different_source_refused": True, "quota_refused": True, "cache_and_native_bytes_unchanged": True})
if not (out / "job/manifest.json").exists():
    run("produce-resume", produce)
paused = json.loads((out / "paused.json").read_text())
after = snapshot("job-snapshot", "completed-job")
indexed = {row["key"]: row for row in after["rows"]}
for row in paused["job"]["rows"]:
    # The source and completed component records are immutable; index accounting grows.
    if bytes.fromhex(row["key"]) != b"production/index":
        assert indexed[row["key"]] == row
assert snapshot("snapshot", "native-after") == before
proof = out / "job/proof.json"
assert proof.stat().st_size <= 256 * 1024 * 1024
manifest = json.loads((out / "job/manifest.json").read_text())
assert manifest["totalBytes"] == proof.stat().st_size
assert json.loads((out / "job/block.json").read_text()) == json.loads((out / "candidate.json").read_text())
follower = snapshot("follower-snapshot", "follower-before-import")
if follower["head"] == control["parent"]:
    run("import-generated", [cli, "--datadir", out / "follower", "import-block-proof", "--block", out / "job/block.json", "--proof", proof, "--manifest", out / "job/manifest.json", "--consensus", out / "consensus.json", "--parent", control["parent"]])
else:
    assert follower["head"] == context["block"], "unexpected follower head"
verify()
result_path = out / "result.json"
result_index = 2
while result_path.exists():
    result_path = out / f"result-{result_index}.json"
    result_index += 1
save(result_path, {"complete_raw_generation": True, "paused_new_components": 3, "cached_components_immutable": True, "native_source_unchanged": True, "actual_cli_import_and_cold_replay": True, "fresh_senders": 1, "proof_bytes": proof.stat().st_size, "proof_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(), "finished_at": now()})
print(json.dumps({"complete": True, "proof_bytes": proof.stat().st_size}))
