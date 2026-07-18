#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path


PHASE_END_RE = re.compile(
    r"PHASE_END name=(?P<name>\S+) status=(?P<status>\S+) rc=(?P<rc>\d+) duration_s=(?P<duration>\d+) log=(?P<log>\S+)"
)
HEALTH_RE = re.compile(
    r"^(?P<ts>\S+) block1=(?P<block1>\S*) block2=(?P<block2>\S*) block3=(?P<block3>\S*) peer1=(?P<peer1>\S*) peer2=(?P<peer2>\S*) peer3=(?P<peer3>\S*)$"
)
SUMMARY_RE = re.compile(r"^SUMMARY (?P<key>[a-zA-Z0-9_]+)=(?P<value>.+)$")
TOTAL_RE = re.compile(r"^\s*Total sent\s*:\s*(\d+)\s*$")
OK_RE = re.compile(r"^\s*Succeeded\s*:\s*(\d+)\s*$")
FAIL_RE = re.compile(r"^\s*Failed\s*:\s*(\d+)\s*$")
AVG_RE = re.compile(r"^\s*Avg latency\s*:\s*([0-9.]+)ms\s*$")
MAX_LOG_BYTES = 16 * 1024 * 1024


def validate_output_dir(output_dir: Path) -> None:
    metadata = output_dir.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"output directory must be a real directory: {output_dir}")


def read_log_lines(path: Path) -> list[str] | None:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError(f"log path must be a regular file: {path}")
    if path_metadata.st_size > MAX_LOG_BYTES:
        raise ValueError(f"log file exceeds {MAX_LOG_BYTES} bytes: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as log_file:
        opened_metadata = os.fstat(log_file.fileno())
        if (
            path_metadata.st_dev != opened_metadata.st_dev
            or path_metadata.st_ino != opened_metadata.st_ino
        ):
            raise ValueError(f"log file changed while opening: {path}")
        contents = log_file.read(MAX_LOG_BYTES + 1)

    if len(contents) > MAX_LOG_BYTES:
        raise ValueError(f"log file exceeds {MAX_LOG_BYTES} bytes: {path}")
    return contents.decode("utf-8").splitlines()


def parse_hex_int(value: str) -> int | None:
    if not value or value == "null":
        return None
    if value.startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return None
    try:
        return int(value)
    except ValueError:
        return None


def read_phase_results(output_dir: Path) -> list[dict[str, str]]:
    phases: list[dict[str, str]] = []
    orchestrator = output_dir / "orchestrator.log"
    lines = read_log_lines(orchestrator)
    if lines is None:
        return phases
    for line in lines:
        match = PHASE_END_RE.search(line)
        if match:
            phases.append(match.groupdict())
    return phases


def read_health(output_dir: Path) -> dict[str, object]:
    path = output_dir / "periodic-health.log"
    samples = []
    lines = read_log_lines(path)
    if lines is None:
        return {"samples": samples}
    for line in lines:
        match = HEALTH_RE.match(line.strip())
        if not match:
            continue
        row = match.groupdict()
        sample = {
            "ts": row["ts"],
            "block1": parse_hex_int(row["block1"]),
            "block2": parse_hex_int(row["block2"]),
            "block3": parse_hex_int(row["block3"]),
            "peer1": parse_hex_int(row["peer1"]),
            "peer2": parse_hex_int(row["peer2"]),
            "peer3": parse_hex_int(row["peer3"]),
        }
        samples.append(sample)
    if not samples:
        return {"samples": samples}

    def field_values(key: str) -> list[int]:
        return [sample[key] for sample in samples if sample[key] is not None]

    block1 = field_values("block1")
    block2 = field_values("block2")
    block3 = field_values("block3")
    peer1 = field_values("peer1")
    peer2 = field_values("peer2")
    peer3 = field_values("peer3")

    lag_samples = []
    for sample in samples:
        heights = [sample["block1"], sample["block2"], sample["block3"]]
        heights = [h for h in heights if h is not None]
        if heights:
            lag_samples.append(max(heights) - min(heights))

    return {
        "samples": samples,
        "start": samples[0],
        "end": samples[-1],
        "min_peers": {
            "node1": min(peer1) if peer1 else None,
            "node2": min(peer2) if peer2 else None,
            "node3": min(peer3) if peer3 else None,
        },
        "max_lag": max(lag_samples) if lag_samples else None,
        "block_delta": {
            "node1": (block1[-1] - block1[0]) if len(block1) >= 2 else None,
            "node2": (block2[-1] - block2[0]) if len(block2) >= 2 else None,
            "node3": (block3[-1] - block3[0]) if len(block3) >= 2 else None,
        },
    }


def read_tx_soak(output_dir: Path) -> dict[str, object]:
    rounds = []
    total_sent = total_ok = total_fail = 0
    weighted_latency = 0.0

    for path in sorted(output_dir.glob("tx-soak-round-*.log")):
        sent = ok = fail = None
        avg_latency = None
        lines = read_log_lines(path)
        if lines is None:
            continue
        for line in lines:
            if sent is None:
                match = TOTAL_RE.match(line)
                if match:
                    sent = int(match.group(1))
                    continue
            if ok is None:
                match = OK_RE.match(line)
                if match:
                    ok = int(match.group(1))
                    continue
            if fail is None:
                match = FAIL_RE.match(line)
                if match:
                    fail = int(match.group(1))
                    continue
            if avg_latency is None:
                match = AVG_RE.match(line)
                if match:
                    avg_latency = float(match.group(1))
        if sent is None and ok is None and fail is None:
            continue
        sent = sent or 0
        ok = ok or 0
        fail = fail or 0
        avg_latency = avg_latency or 0.0
        total_sent += sent
        total_ok += ok
        total_fail += fail
        weighted_latency += avg_latency * sent
        rounds.append(
            {
                "name": path.name,
                "sent": sent,
                "ok": ok,
                "fail": fail,
                "avg_latency_ms": avg_latency,
            }
        )

    avg_latency = weighted_latency / total_sent if total_sent else 0.0
    return {
        "rounds": rounds,
        "total_sent": total_sent,
        "total_ok": total_ok,
        "total_fail": total_fail,
        "avg_latency_ms": avg_latency,
    }


def read_summary_kv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    lines = read_log_lines(path)
    if lines is None:
        return result
    for line in lines:
        match = SUMMARY_RE.match(line.strip())
        if match:
            result[match.group("key")] = match.group("value")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a shell-chain long soak run")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    validate_output_dir(output_dir)
    phases = read_phase_results(output_dir)
    health = read_health(output_dir)
    tx_soak = read_tx_soak(output_dir)
    aa_mixed = read_summary_kv(output_dir / "aa-mixed.log")
    aa_attack = read_summary_kv(output_dir / "aa-attack.log")

    failed_phases = [phase for phase in phases if phase["status"] != "ok"]

    print("# Shell-Chain 6h Soak Summary")
    print()
    print(f"- output_dir: `{output_dir}`")
    print(f"- phases: {len(phases)} total, {len(failed_phases)} failed")
    print(f"- tx_soak_rounds: {len(tx_soak['rounds'])}")
    print()

    print("## Phase Results")
    if phases:
        for phase in phases:
            print(
                f"- {phase['name']}: {phase['status']} "
                f"(rc={phase['rc']}, duration={phase['duration']}s, log={phase['log']})"
            )
    else:
        print("- no phase records found")
    print()

    print("## Chain Progress")
    if health.get("samples"):
        start = health["start"]
        end = health["end"]
        print(
            f"- block heights: node1 {start['block1']} -> {end['block1']}, "
            f"node2 {start['block2']} -> {end['block2']}, "
            f"node3 {start['block3']} -> {end['block3']}"
        )
        print(
            f"- block delta: node1={health['block_delta']['node1']}, "
            f"node2={health['block_delta']['node2']}, "
            f"node3={health['block_delta']['node3']}"
        )
        print(
            f"- min peer counts: node1={health['min_peers']['node1']}, "
            f"node2={health['min_peers']['node2']}, "
            f"node3={health['min_peers']['node3']}"
        )
        print(f"- max observed height lag across nodes: {health['max_lag']}")
    else:
        print("- no periodic-health samples found")
    print()

    print("## Transaction Soak")
    print(
        f"- aggregate: sent={tx_soak['total_sent']} ok={tx_soak['total_ok']} "
        f"fail={tx_soak['total_fail']} avg_latency_ms={tx_soak['avg_latency_ms']:.1f}"
    )
    for round_info in tx_soak["rounds"]:
        print(
            f"- {round_info['name']}: sent={round_info['sent']} ok={round_info['ok']} "
            f"fail={round_info['fail']} avg_latency_ms={round_info['avg_latency_ms']:.1f}"
        )
    print()

    print("## AA Mixed Usage")
    if aa_mixed:
        for key in sorted(aa_mixed):
            print(f"- {key}: {aa_mixed[key]}")
    else:
        print("- no aa-mixed summary found")
    print()

    print("## AA Attack Injection")
    if aa_attack:
        for key in sorted(aa_attack):
            print(f"- {key}: {aa_attack[key]}")
    else:
        print("- no aa-attack summary found")
    print()

    print("## Verdict")
    if failed_phases:
        print("- overall: FAIL")
    else:
        print("- overall: PASS")


if __name__ == "__main__":
    main()
