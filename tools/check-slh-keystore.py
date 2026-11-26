#!/usr/bin/env python3
"""Verify SLH keystore aliases through migration, a live wallet and cold replay.

Requires Python 3.11+ on Unix and shell-node built with rocksdb/libp2p.
Usage: python3 tools/check-slh-keystore.py /path/to/shell-node /new/case-directory
Creates its own test keys and private Dev funds. Retains keys, DBs and command
receipts; exits nonzero on any failure. Uses no external node or proof graph.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re


spec = importlib.util.spec_from_file_location(
    "live_wallet", Path(__file__).with_name("check-live-wallet-quorum.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    binary, root = args.binary.resolve(strict=True), args.root.absolute()
    live.require(not root.exists() and not root.is_symlink(), "new case directory required")
    root.mkdir(mode=0o700)
    case = live.Case(binary, root, False, "slhdsa")
    try:
        case.initialize()
        path = root / "validator.json"
        key = json.loads(path.read_text())
        live.require(key["key_type"] == "sphincs-sha2-256f", "writer compatibility changed")
        key["key_type"] = "slh-dsa-sha2-256f"
        path.write_text(json.dumps(key, indent=2) + "\n")
        original = path.read_bytes()
        inspected = case.run("documented-tag-inspect", ["key", "inspect", "validator.json"])
        live.require(case.report["validator"] in inspected, "alias changed address")
        case.run("documented-tag-migrate", ["key", "migrate", "--input", "validator.json",
                 "--output", "migrated.json", "--password-file", "password"])
        migrated = json.loads((root / "migrated.json").read_text())
        live.require(migrated["key_type"] == "sphincs-sha2-256f"
                     and all(migrated[n] == key[n] for n in ["address", "public_key"])
                     and path.read_bytes() == original, "migration changed identity or input")
        inspected = case.run("migrated-inspect", ["key", "inspect", "migrated.json"])
        live.require(case.report["validator"] in inspected, "migration address mismatch")
        with case.node("provider", role="validator-prover") as (endpoint, child):
            text = case.run("alias-wallet-send", ["tx", "send", "--to", case.report["recipient"],
                            "--value", str(live.VALUE), "--keystore", "validator.json",
                            "--password-file", "password", "--rpc-url", endpoint])
            hashes = re.findall(r"^0x[0-9a-f]{64}$", text, re.MULTILINE)
            live.require(len(hashes) == 1, "wallet transaction hash missing")
            case.report["transaction"] = hashes[0]
            receipt = case.wait(lambda: case.rpc(endpoint, "eth_getTransactionReceipt", hashes), child, timeout=120)
            case.report["blockHash"] = receipt["blockHash"]
            case.wait(lambda: case.rpc(endpoint, "eth_getBlockByNumber", ["finalized", False])["hash"]
                      == receipt["blockHash"], child, timeout=120)
            actual = case.snapshot(endpoint)
            case.check_state(actual)
            case.report["liveState"] = actual
            case.report["liveCertificate"] = case.rpc(endpoint, "shell_finalityProof", [receipt["blockHash"]])
            case.check_scheme()
            case.rpc(endpoint, "eth_sendRawTransaction", ["0x00"], reject=True)
            # The migrated legacy-spelling file loads and signs; the real pool
            # rejects its already-consumed nonce with no state change.
            stale = case.run("migrated-stale-nonce", ["tx", "send", "--to", case.report["recipient"],
                             "--value", str(live.VALUE), "--keystore", "migrated.json",
                             "--password-file", "password", "--rpc-url", endpoint,
                             "--nonce", "0", "--gas-limit", "21000"], expected=1)
            live.require("nonce" in stale.lower(), "expected actual pool nonce refusal")
            for field in ["ciphertext", "public_key", "key_type"]:
                bad = dict(key)
                value = bad[field]
                bad[field] = ("1" if value[0] == "0" else "0") + value[1:]
                bad_path = root / ("bad-" + field + ".json")
                fd = os.open(bad_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    json.dump(bad, stream)
                case.run("reject-" + field, ["tx", "send", "--to", case.report["recipient"],
                         "--value", str(live.VALUE), "--keystore", bad_path.name,
                         "--password-file", "password", "--rpc-url", endpoint,
                         "--gas-limit", "21000"], expected=1)
                live.require(case.snapshot(endpoint) == actual, "rejected input changed Native state")
            live.require(case.snapshot(endpoint) == actual, "rejected transaction changed state")
            live.require(case.production(endpoint) is None, "default-off node produced a proof")
            def listening():
                value = case.rpc(endpoint, "admin_nodeInfo")
                return value if value["id"] and value["listenAddr"] else None
            info = case.wait(listening, child)
            multiaddr = info["listenAddr"]
            if "/p2p/" not in multiaddr:
                multiaddr += "/p2p/" + info["id"]
            with case.node("native", bootnode=multiaddr) as (peer, follower):
                case.wait(lambda: case.rpc(peer, "eth_blockNumber") == "0x1", follower, timeout=180)
                case.wait(lambda: case.rpc(peer, "eth_getBlockByNumber", ["finalized", False])["hash"]
                          == receipt["blockHash"], follower, timeout=180)
                live.require(case.snapshot(peer) == actual, "Native follower state mismatch")
                case.report["nativePeer"] = case.snapshot(peer)
        for name in ["provider", "native"]:
            with case.node(name) as (endpoint, child):
                live.require(case.snapshot(endpoint) == actual, "cold replay changed state")
                case.report[name + "Cold"] = case.snapshot(endpoint)
        live.require(path.read_bytes() == original, "input keystore changed")
        case.report["complete"] = True
        case.save()
        print(json.dumps({"SLHKeystoreComplete": True, "block": case.report["blockHash"]}))
    except BaseException as error:
        case.report["error"] = str(error)
        case.save()
        raise


if __name__ == "__main__":
    main()
