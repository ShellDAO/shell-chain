#!/usr/bin/env python3
"""Interrupt an owned local verifier child and recover its copied complete job."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def closed_copy(source, target):
    require(not source.is_symlink(), "source must not be a symbolic link")
    require(not any(p.is_symlink() for p in source.rglob("*")), "source contains a symbolic link")
    with (source / "LOCK").open("r+b") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        shutil.copytree(source, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("controls", type=Path)
    parser.add_argument("owner", type=Path)
    parser.add_argument("proof", type=Path)
    parser.add_argument("new_root", type=Path)
    parser.add_argument("--marker", required=True, help="Exact completed-component Reverified log line")
    parser.add_argument("--timeout", type=int, default=900, help="Seconds allowed per child")
    args = parser.parse_args()
    require(args.marker.startswith("Reverified ") and "\n" not in args.marker, "a single Reverified marker is required")
    require(args.timeout > 0, "timeout must be positive")
    binary, source, owner, proof = (p.absolute() for p in [args.binary, args.controls, args.owner, args.proof])
    root = args.new_root.absolute()
    require(binary.is_file() and proof.is_file(), "built binary and complete proof are required")
    require((source / "control.cbor").is_file() and (source / "source.cbor").is_file(), "original controls and source are required")
    require(not root.exists() and not root.is_symlink(), "output root must be new")
    root.mkdir(mode=0o700)
    controls = root / "controls"
    controls.mkdir()
    for name in ["control.cbor", "source.cbor"]:
        shutil.copy2(source / name, controls / name)
    closed_copy(source / "control-db", controls / "control-db")
    provider = root / "provider-db"
    closed_copy(owner, provider)
    artifact = root / "proof.cbor"
    shutil.copy2(proof, artifact)
    receiver = root / "receiver"
    report = {"binarySHA256": sha(binary), "sourceSHA256": sha(controls / "source.cbor"),
              "proofSHA256": sha(artifact), "marker": args.marker, "commands": [],
              "complete": False, "oldGraphNewProofMath": 0}

    def save():
        temporary = root / "result.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.replace(root / "result.json")

    def run(label, arguments, interrupt=False):
        argv = [str(binary), *map(str, arguments)]
        row = {"label": label, "argv": argv, "startedAt": time.time(), "log": label + ".log"}
        report["commands"].append(row)
        save()
        messages = []
        marker = False
        new_math = False
        pending = b""
        with (root / row["log"]).open("wb") as log:
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
            row["pid"] = child.pid
            save()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    deadline = time.monotonic() + args.timeout
                    while True:
                        require(time.monotonic() < deadline, label + " timed out; retained all inputs")
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
                            new_math |= line.startswith(b"Proving ")
                            require(not new_math, "complete-job flow attempted new proving")
                            if line.startswith(b"{"):
                                messages.append(json.loads(line))
                            if interrupt and line == args.marker.encode():
                                require(child.poll() is None, "child ended before selected marker")
                                marker = True
                                row["markerObservedAt"] = time.time()
                                row["signal"] = "SIGKILL"
                                save()
                                child.send_signal(signal.SIGKILL)
                                interrupt = False
                    code = child.wait(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
                row.update(exitCode=child.returncode, finishedAt=time.time(), markerObserved=marker,
                           newProvingObserved=new_math)
                save()
        require(code == (-signal.SIGKILL if marker else 0), label + " failed; inspect retained log")
        return messages, marker

    def snapshot(label):
        messages, _ = run(label, ["producer-snapshot", controls, provider, artifact])
        result = next(x for x in messages if x.get("quorumProducerSnapshot"))
        require(result["logicalRowsUnchanged"] and result["independentNative1RowsEqual"], "offline snapshot changed or mismatched Native")
        return result

    def equal(before, after):
        fields = ["head", "finalized", "nativeDigest", "ownedSourceHash", "componentRowsDigest",
                  "componentCount", "checkpointBytes", "payloadHash", "payloadBytes", "proofCacheReady"]
        require(all(before[k] == after[k] for k in fields), "crash/recovery changed immutable source, Native, checkpoints or payload")

    try:
        before = snapshot("before")
        require(before["status"]["status"]["state"] == "complete", "a complete existing owner job is required")
        _, marker = run("interrupted-cold", ["producer-cold", controls, provider, receiver, artifact], True)
        require(marker and not receiver.exists(), "selected inner reverify boundary was not interrupted")
        interrupted = snapshot("interrupted")
        equal(before, interrupted)
        require(interrupted["status"]["status"]["state"] != "complete", "worker already completed before interruption")
        report.update(before=before, interrupted=interrupted)
        save()
        messages, _ = run("recovered-peer", ["producer-auto", controls, provider, receiver, artifact])
        peer = next(x for x in messages if x.get("nodeQuorumProducerToFreshPeerComplete"))
        require(peer["actualTCPNoise"] and peer["head"] == peer["finalized"] == 1
                and peer["independentNativeReceiptsEqual"] and peer["balancesNonceFeesChecked"]
                and peer["status"]["status"]["newlyProved"] == 0, "recovery did not reach actual full peer endpoint")
        recovered = snapshot("recovered")
        equal(before, recovered)
        require(recovered["status"]["status"]["state"] == "complete", "recovered owner is not complete")
        messages, _ = run("receiver-cold", ["producer-recheck", controls, receiver, artifact])
        cold = next(x for x in messages if x.get("coldProducedQuorumFullHistoricalRecheck"))
        require(cold["verificationAttempts"] == 2 and cold["NativeRowsUnchanged"] and cold["newProofMath"] == 0,
                "receiver cold full replay failed")
        require(sha(artifact) == report["proofSHA256"], "actual proof bytes changed")
        report.update(complete=True, recovered=recovered, peer=peer, cold=cold)
        save()
        print(json.dumps({"quorumProducerCrashRecovery": True, "complete": True,
                          "componentCount": before["componentCount"], "newProofMath": 0,
                          "actualTCPNoise": True, "head": 1, "finalized": 1,
                          "coldVerificationAttempts": 2}))
    except BaseException as error:
        report["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
