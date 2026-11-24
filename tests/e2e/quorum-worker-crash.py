#!/usr/bin/env python3
"""Kill only the spawned verifier after its real progress marker, then cold-recover."""
import argparse
import datetime
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--controls", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--provider-db", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    if os.name != "posix" or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("POSIX SIGKILL and a positive per-process timeout required")
    binary, controls, proof, receiver, provider = (
        path.resolve() for path in (
            args.binary, args.controls, args.proof, args.receiver, args.provider_db
        )
    )
    receipt_path = receiver.with_name(receiver.name + ".crash-driver.json")
    if (not binary.is_file() or not os.access(binary, os.X_OK)
            or not (controls / "control.cbor").is_file() or not proof.is_file()
            or not (provider / "CURRENT").is_file()
            or receiver.exists() or receipt_path.exists()
            or provider.is_relative_to(controls) or receiver == provider):
        parser.error("require executable, retained controls/proof, separate Native1 provider copy, and unused receiver/receipt paths")
    receipt = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "processes": [], "power_loss_qualified": False,
               "new_signing_or_proving": False, "exit_code": None}

    def save():
        temporary = receipt_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(receipt_path)

    save()
    try:
        for mode in ("slh-live-crash-worker", "slh-live-crash-recover", "slh-live-cold"):
            log_path = receiver.with_name(receiver.name + "." + mode + ".log")
            argv = [str(binary), mode, str(controls), str(proof), str(receiver), str(provider)]
            entry = {"argv": argv, "log": str(log_path), "exit_code": None,
                     "SIGKILL_after_actual_marker": False}
            receipt["processes"].append(entry)
            child = None
            try:
                with log_path.open("xb") as log:
                    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    entry["pid"] = child.pid
                    save()
                    deadline = time.monotonic() + args.timeout
                    pending = b""
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        while True:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"{mode} exceeded its timeout")
                            events = selector.select(0.1)
                            if not events:
                                continue
                            data = os.read(child.stdout.fileno(), 65536)
                            if not data:
                                break
                            log.write(data)
                            log.flush()
                            pending += data
                            while b"\n" in pending:
                                line, pending = pending.split(b"\n", 1)
                                try:
                                    event = json.loads(line)
                                except (ValueError, UnicodeDecodeError):
                                    continue
                                if not isinstance(event, dict) or not event.get("processCrashReady"):
                                    continue
                                if mode != "slh-live-crash-worker" or event.get("pid") != child.pid:
                                    raise RuntimeError("crash marker does not identify this spawned worker")
                                if (event.get("verificationAttempts") != 1 or event.get("head") != 0
                                        or event.get("finalized") != 0
                                        or not (receiver / "recovery.json").is_file()):
                                    raise RuntimeError("crash marker missed the required durable Native0 boundary")
                                # Popen owns this exact child; no PID supplied by the marker is signalled.
                                child.kill()
                                entry["SIGKILL_after_actual_marker"] = True
                                entry["marker"] = event
                                save()
                    entry["exit_code"] = child.wait(timeout=10)
                    expected = -signal.SIGKILL if mode == "slh-live-crash-worker" else 0
                    if (entry["exit_code"] != expected
                            or (mode == "slh-live-crash-worker"
                                and not entry["SIGKILL_after_actual_marker"])):
                        raise RuntimeError(f"{mode} exited {entry['exit_code']}, expected {expected}; see {log_path}")
            finally:
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                        entry["failure_cleanup_killed_own_child"] = True
                    entry["exit_code"] = child.wait()
                    child.stdout.close()
                save()
        receipt["exit_code"] = 0
        print(json.dumps({"SIGKILLThenColdRecovery": True, "exit_codes": [
            process["exit_code"] for process in receipt["processes"]],
            "receipt": str(receipt_path), "powerLossQualified": False}))
    except Exception as error:
        receipt["exit_code"] = 1
        receipt["error"] = str(error)
        raise
    finally:
        receipt["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
