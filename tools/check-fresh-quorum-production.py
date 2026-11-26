#!/usr/bin/env python3
"""Generate three new quorum jobs through Node, then verify a fresh and cold peer."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def interrupt_production(child, log, row, save):
    """Kill only this child at the next missing component's dispatch marker."""
    marker = b"Proving commit-signer-0-signature"
    pending = b""
    reverified = []
    deadline = time.monotonic() + 900
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            require(time.monotonic() < deadline, "production dispatch marker timed out")
            if not selector.select(0.2):
                continue
            data = os.read(child.stdout.fileno(), 65536)
            if not data:
                break
            log.write(data)
            log.flush()
            pending += data
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line.startswith(b"Reverified "):
                    reverified.append(line.decode())
                if line.startswith(b"Proving ") and not row.get("signal"):
                    require(line == marker, "unexpected missing component before selected marker")
                    require(reverified == ["Reverified commit-weight", "Reverified commit-signer-0-key"],
                            "original two components were not reverified")
                    require(child.poll() is None, "child ended before selected marker")
                    row.update(marker=line.decode(), markerObservedAt=time.time(),
                               reverified=reverified, signal="SIGKILL")
                    save()
                    child.send_signal(signal.SIGKILL)
    require(row.get("signal") == "SIGKILL", "production marker was not observed")
    return child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("--resume", action="store_true", help="Continue the retained case without recreating controls or graphs")
    parser.add_argument("--interrupt-production", action="store_true", help="Interrupt one owned child before its first missing signature checkpoint, then recover")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = args.root.absolute()
    require(binary.is_file(), "built quorum-native binary required")
    require(not root.is_symlink() and root.exists() == args.resume, "use a new root, or --resume an existing case")
    if not args.resume:
        root.mkdir(mode=0o700)
    require(not any(p.is_symlink() for p in root.rglob("*")), "case contains a symbolic link")
    with (root / "run.lock").open("a+b") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exercise(binary, root, args.resume, args.interrupt_production)


def exercise(binary, root, resume, interrupt=False):
    result_path = root / "result.json"
    report = json.loads(result_path.read_text()) if resume else {"complete": False, "commands": [], "steps": 0}
    require(not (interrupt and resume and not report.get("interruptProduction")),
            "cannot add an interruption to an existing ordinary case")
    report["interruptProduction"] = report.get("interruptProduction", interrupt)
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if report.get("binarySHA256") not in [None, binary_hash]:
        report.pop("peer", None)
        report.pop("cold", None)
        report["complete"] = False
    report["binarySHA256"] = binary_hash
    report.pop("error", None)

    def summary():
        print(json.dumps({"freshNodeQuorumProductionComplete": True, "sources": 3, "seededJobs": 0,
                          "steps": report["steps"], "NativeHeadAndFinality": 3,
                          "productionInterruptionVerified": report.get("productionCrash", {}).get("verified", False),
                          "historyVerificationAttempts": [report[k]["historyVerificationAttempts"] for k in ["peer", "cold"]]}))

    def save():
        temporary = result_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(result_path)

    def run(label, arguments, tag, interrupt=False):
        row = {"label": label, "argv": [str(binary), *map(str, arguments)],
               "startedAt": time.time(), "binarySHA256": binary_hash,
               "log": f"command-{len(report['commands']):03}-{label}.log"}
        report["commands"].append(row)
        save()
        with (root / row["log"]).open("wb") as log:
            child = subprocess.Popen(row["argv"], stdout=subprocess.PIPE if interrupt else log,
                                     stderr=subprocess.STDOUT, bufsize=0)
            row["pid"] = child.pid
            save()
            try:
                if interrupt:
                    interrupt_production(child, log, row, save)
                else:
                    child.wait()
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                if child.stdout is not None:
                    child.stdout.close()
                row.update(exitCode=child.returncode, finishedAt=time.time())
                save()
        require(row["exitCode"] == (-signal.SIGKILL if interrupt else 0),
                label + " failed; retain this prefix and inspect its log")
        if interrupt:
            return row
        messages = [json.loads(line) for line in (root / row["log"]).read_text().splitlines() if line.startswith("{")]
        return next(message for message in messages if message.get(tag))

    controls, runtime = root / "controls", root / "runtime"

    def snapshot(label):
        value = run(label, ["producer-fresh-snapshot", controls, runtime], "freshQuorumSnapshot")
        require(value["logicalRowsUnchanged"] and value["head"] == value["finalized"], "snapshot changed rows or lost finality")
        return value

    def complete(value):
        return all(v and v.get("status", {}).get("state") == "complete" for v in value["production"])

    def crash(value):
        if not report["interruptProduction"] or report.get("productionCrash", {}).get("verified"):
            return value
        require(not report.get("productionCrash"), "incomplete interruption receipt; inspect retained child and case before recovery")
        require(all(not v for v in value["production"]), "interruption needs the original empty owner")
        warm = run("partial", ["producer-fresh-step", controls, runtime, "2"], "freshQuorumStep")
        report["steps"] += 1
        require(warm["newlyProvedThisProcess"] == 2 and warm["NativeRowsUnchanged"]
                and warm["existingSourceCheckpointRowsPreserved"], "two-component warmup failed")
        before = snapshot("before-interruption")
        first = before["production"][0]["status"]
        require(first["state"] == "paused" and first["components"] == 2
                and before["production"][1]["status"]["components"] == 0
                and before["NativeDigest"] == value["NativeDigest"] and not before["payloads"],
                "genuine partial checkpoint required")
        report["productionCrash"] = {"before": before, "attempted": True, "verified": False}
        save()
        row = run("interrupted-production", ["producer-fresh-step", controls, runtime, "16"], None, True)
        report["steps"] += 1
        after = snapshot("interrupted-offline")
        require(after["production"][0]["status"]["state"] == "proving"
                and all(before[k] == after[k] for k in ["NativeDigest", "immutableRowsDigest", "payloads"]),
                "crash changed original source/component rows, Native or cache")
        for old, new in zip(before["production"], after["production"]):
            require(all(old["status"][k] == new["status"][k]
                        for k in ["blockHash", "sourceHash", "components", "checkpointBytes"]),
                    "crash changed original partial checkpoint metadata")
        report["productionCrash"].update(verified=True, interrupted=after, command=row)
        save()
        return after

    def prove(value):
        while not complete(value):
            require(report["steps"] < 32, "bounded case exceeded 32 production sessions")
            step = run("step", ["producer-fresh-step", controls, runtime, "16"], "freshQuorumStep")
            report["steps"] += 1
            require(step["seededJobs"] == 0 and step["NativeRowsUnchanged"]
                    and step["existingSourceCheckpointRowsPreserved"]
                    and step["newlyProvedThisProcess"] <= 16, "invalid Node production step")
            after = snapshot("after-step")
            require(after["NativeDigest"] == value["NativeDigest"], "production changed Native state")
            require(step["newlyProvedThisProcess"] > 0 or complete(after), "incomplete worker made no progress")
            value = after
            report["lastSnapshot"] = value
            save()
        return value

    if report["complete"]:
        summary()
        return
    save()
    try:
        if not controls.exists():
            prepared = run("prepare", ["prepare-producer-successor", controls], "prepared")
            require(prepared["authorityCount"] == 2 and prepared["nativePrefix2Snapshot"]
                    and prepared["privateKeysPersisted"] is False, "genuine two-authority controls required")
        require((controls / "control.cbor").is_file(), "partial control preparation retained; inspect before resuming")
        if not runtime.exists():
            initial = run("init", ["producer-fresh-init", controls, runtime], "freshQuorumInitialized")
            require(initial["initialComponents"] == initial["initialSources"] == initial["seededJobs"] == 0
                    and initial["defaultOffObserved"] and initial["proofCacheEmpty"], "initial owner was not empty/default-off")
            report["initial"] = initial
            save()
        require(report.get("initial"), "missing successful empty-owner initialization receipt; retain prefix")
        value = prove(crash(snapshot("before-continuation")))
        if value["head"] == 2:
            run("advance", ["producer-fresh-advance", controls, runtime], "freshQuorumAdvanced")
            advanced = snapshot("after-advance")
            require(advanced["head"] == 3 and advanced["immutableRowsDigest"] == value["immutableRowsDigest"], "certified advance changed earlier checkpoints")
            value = prove(advanced)
        require(value["head"] == 3 and len(value["payloads"]) == 3, "three complete source payloads required")
        before = report.get("beforePeer", value)
        report["beforePeer"] = before
        save()
        for key, command in [("peer", "producer-fresh-peer"), ("cold", "producer-fresh-cold")]:
            if key not in report:
                peer = run(key, [command, controls, runtime], "nodeOwnedQuorumJobs")
                counts = peer["historyVerificationAttempts"]
                require(peer["actualTCPNoise"] and peer["NativeHeadAndFinality"] == 3
                        and peer["independentNative3RowsEqual"] and peer["originalCheckpointRowsPreserved"]
                        and len(counts) == 3 and all(n >= 2 for n in counts)
                        and peer["historicalNativeRowsUnchanged"] and peer["newProofMath"] == 0
                        and peer["senderOwnerUntouched"], "full automatic peer/history endpoint failed")
                if key == "cold":
                    require(counts == [n + 1 for n in report["peer"]["historyVerificationAttempts"]], "cold history did not perform a new full check")
                report[key] = peer
                save()
        after = snapshot("final")
        require(all(before[k] == after[k] for k in ["NativeDigest", "immutableRowsDigest", "payloads"]), "peer/recheck changed Native/checkpoints/payloads")
        report.update(complete=True, final=after, finishedAt=time.time())
        save()
        summary()
    except BaseException as error:
        report["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
