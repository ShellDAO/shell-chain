#!/usr/bin/env python3
"""Local opt-in governance acceptance. Requires a built shell-node and Python 3.

Run: NODE_BIN=target/debug/shell-node python3 tests/e2e/run-emergency-governance.py
Add --proposal-only for the signed activation vote and pending-state restart flow.
That flow preserves the real timelock and does not wait for algorithm maturity.
Use --proposal-directory DIR --observe-seconds 60 for resumable maturity acceptance.
This retains test keys/data, stops its node after each observation, and exits 75 while
pending. Repeat the same command to resume; only time spent running advances blocks.
The real delay requires at least 15 days of cumulative node uptime. No delay override.
Without that option, temporary keys/data are removed on exit.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--proposal-only", action="store_true",
                    help="verify a signed activation vote and pending-state CLI restart; does not wait for maturity")
parser.add_argument("--proposal-directory", type=Path,
                    help="create or resume a dedicated persistent proposal acceptance directory")
parser.add_argument("--observe-seconds", type=int, default=60,
                    help="bounded node observation per invocation (default: 60)")
args = parser.parse_args()
if args.observe_seconds <= 0:
    parser.error("--observe-seconds must be positive")
if args.proposal_directory and args.proposal_only:
    parser.error("--proposal-directory and --proposal-only are mutually exclusive")
proposal_mode = args.proposal_only or args.proposal_directory is not None

BIN = str(Path(os.environ.get("NODE_BIN", "target/debug/shell-node")).resolve())
REGISTRY = "0x" + "00" * 31 + "01"
RECIPIENT = "0x" + "42" * 32


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def acceptance_directory():
    if args.proposal_directory is None:
        with tempfile.TemporaryDirectory(prefix="shell-emergency-governance-") as directory:
            yield Path(directory), False
        return
    root = args.proposal_directory.absolute()
    if root.is_symlink():
        raise RuntimeError("acceptance directory must not be a symlink")
    created = not root.exists()
    if created:
        root.mkdir(mode=0o700, parents=True)
    elif not (root / "acceptance.json").is_file():
        raise RuntimeError("existing directory has no acceptance manifest; refusing to overwrite")
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield root, not created


with acceptance_directory() as (root, resume):
    password = root / "password"
    manifest_path = root / "acceptance.json"
    manifest = json.loads(manifest_path.read_text()) if resume else {}
    binary_hash = hashlib.sha256(Path(BIN).read_bytes()).hexdigest() if args.proposal_directory else None
    if resume and manifest.get("binary_sha256") != binary_hash:
        raise RuntimeError("node binary differs from the saved acceptance build")

    def save_manifest():
        if args.proposal_directory:
            temporary = manifest_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(manifest, indent=2) + "\n")
            temporary.chmod(0o600)
            temporary.replace(manifest_path)

    if not resume:
        password.write_text("local-test-password\n")
        password.chmod(0o600)

    def cli(*args):
        return subprocess.run([BIN, "--password-file", str(password), *map(str, args)],
                              capture_output=True, text=True, timeout=30, check=True).stdout.strip()

    if not resume:
        for name, algorithm in [("primary", "mldsa65"), ("fallback", "slhdsa")]:
            cli("key", "generate", "--algorithm", algorithm, "--output", root / name)
        primary = json.loads((root / "primary").read_text())
        fallback = json.loads((root / "fallback").read_text())
        owner = primary["address"]
        data = root / "data"
        data.mkdir()
        genesis = {
            "chain_id": 31337, "chain_name": "local-emergency-governance", "network_type": "Dev",
            "timestamp": int(time.time()) - 2, "gas_limit": 30000000, "extra_data": "local-governance",
            "consensus": {"engine": "poa", "authorities": [owner],
                          "authority_pubkeys": [primary["public_key"]], "block_time_secs": 1,
                          "max_future_secs": 60, "epoch_length": 0},
            "alloc": {owner: {"balance": "0xd3c21bcecceda1000000", "nonce": 0}},
            "boot_nodes": [], "emergency_governance_height": 0,
            "governance_fallback_keys": {owner: fallback["public_key"]},
        }
        if proposal_mode:
            genesis.update(algorithm_timelock_activation_height=0,
                           algorithm_proposal_staging_height=0,
                           algorithm_quorum_activation_height=0,
                           algorithm_activation_admission_height=0)
            genesis["alloc"][fallback["address"]] = {"balance": "0xd3c21bcecceda1000000", "nonce": 0}
        (data / "genesis.json").write_text(json.dumps(genesis))
        manifest = {"binary_sha256": binary_hash, "phase": "ready"}
        save_manifest()
    primary = json.loads((root / "primary").read_text())
    fallback = json.loads((root / "fallback").read_text())
    owner = primary["address"]
    data = root / "data"
    rpc_port, metrics_port = port(), port()
    url = f"http://127.0.0.1:{rpc_port}"
    process = None
    log = (root / "node.log").open("a+")

    def rpc(method, params=None):
        req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1,
              "method": method, "params": params or []}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def wait_for(check):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("node exited")
            try:
                result = check()
                if result:
                    return result
            except (OSError, RuntimeError):
                # Startup and receipt polling may fail transiently; retry until the deadline.
                pass
            time.sleep(0.2)
        raise RuntimeError("acceptance timed out")

    def start():
        global process
        process = subprocess.Popen([BIN, "--password-file", str(password), "run",
            "--datadir", str(data), "--keystore", str(root / "primary"),
            "--rpc-addr", f"127.0.0.1:{rpc_port}", "--rpc-api", "eth,net,web3,shell",
            "--metrics-addr", f"127.0.0.1:{metrics_port}", "--chain-id", "31337",
            "--block-time", "1000", "--max-idle-interval", "0", "--db", "rocksdb",
            "--consensus-engine", "poa", "--node-role", "validator"], stdout=log, stderr=log)
        wait_for(lambda: rpc("eth_chainId") == "0x7a69")

    def stop():
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def deprecated():
        return any(row["algo"] == "Dilithium3" and row["status"].lower() == "deprecated"
                   for row in rpc("shell_getAlgorithmRegistry"))

    try:
        start()
        if proposal_mode:
            if manifest.get("phase") in ("submitting", "transferring"):
                raise RuntimeError("interrupted submission has uncertain outcome; inspect saved chain before resuming")
            if "proposal_transaction" not in manifest:
                activation = int(rpc("eth_blockNumber"), 16) + 1_296_100
                calldata = "0x1b7520b8" + f"{2:064x}{activation:064x}" + "44" * 32
                manifest.update(phase="submitting", activation_height=activation, calldata=calldata)
                save_manifest()
                tx = cli("tx", "send", "--from", owner, "--to", REGISTRY, "--value", "0",
                         "--data", calldata, "--gas-limit", "500000",
                         "--keystore", root / "primary", "--rpc-url", url)
                manifest.update(phase="pending", proposal_transaction=tx)
                save_manifest()
            activation = manifest["activation_height"]
            calldata = manifest["calldata"]
            tx = manifest["proposal_transaction"]
            receipt = wait_for(lambda: rpc("eth_getTransactionReceipt", [tx]))
            assert int(receipt["status"], 16) == 1, receipt
            assert int(receipt["gasUsed"], 16) > 0
            assert activation >= int(receipt["blockNumber"], 16) + 1_296_000

            def pending():
                return any(row["algo"] == "SphincsSha2256f" and row["status"] == "pending_activation"
                           for row in rpc("shell_getAlgorithmRegistry"))

            def rejects_pending_transfer():
                try:
                    cli("tx", "send", "--to", owner, "--value", "1", "--gas-limit", "100000",
                        "--keystore", root / "fallback", "--rpc-url", url)
                except subprocess.CalledProcessError as error:
                    assert "disallowed" in error.stderr.lower(), error.stderr
                else:
                    raise AssertionError("pending algorithm admitted a transfer before maturity")
                assert int(rpc("eth_getTransactionCount", [fallback["address"], "latest"]), 16) == 0

            if int(rpc("eth_blockNumber"), 16) + 1 < activation:
                assert pending()
                rejects_pending_transfer()
                stop()
                start()
                assert pending()
                rejects_pending_transfer()
            assert rpc("eth_getTransactionReceipt", [tx])["blockHash"] == receipt["blockHash"]
            assert int(rpc("eth_getTransactionCount", [owner, "latest"]), 16) == 1
            assert rpc("shell_getPqPubkey", [owner]).removeprefix("0x") == primary["public_key"].removeprefix("0x")
            if args.proposal_directory:
                deadline = time.monotonic() + args.observe_seconds
                while int(rpc("eth_blockNumber"), 16) < activation:
                    if process.poll() is not None:
                        raise RuntimeError("node exited while awaiting maturity")
                    if time.monotonic() >= deadline:
                        manifest.update(last_height=int(rpc("eth_blockNumber"), 16))
                        save_manifest()
                        print(json.dumps({"status": "pending", "height": manifest["last_height"],
                                          "activation_height": activation}))
                        raise SystemExit(75)
                    time.sleep(1)
                assert any(row["algo"] == "SphincsSha2256f" and row["status"] == "active"
                           for row in rpc("shell_getAlgorithmRegistry"))
                if "transfer_transaction" not in manifest:
                    manifest.update(phase="transferring",
                                    recipient_balance=int(rpc("eth_getBalance", [RECIPIENT, "latest"]), 16))
                    save_manifest()
                    transfer = cli("tx", "send", "--to", RECIPIENT, "--value", "1", "--gas-limit", "100000",
                                   "--keystore", root / "fallback", "--rpc-url", url)
                    manifest.update(phase="confirming", transfer_transaction=transfer)
                    save_manifest()
                transfer = manifest["transfer_transaction"]
                transfer_receipt = wait_for(lambda: rpc("eth_getTransactionReceipt", [transfer]))
                assert int(transfer_receipt["status"], 16) == 1
                for restarted in (False, True):
                    if restarted:
                        stop()
                        start()
                    assert int(rpc("eth_getTransactionCount", [fallback["address"], "latest"]), 16) == 1
                    assert int(rpc("eth_getBalance", [RECIPIENT, "latest"]), 16) == manifest["recipient_balance"] + 1
                    assert rpc("eth_getTransactionReceipt", [transfer])["blockHash"] == transfer_receipt["blockHash"]
                    assert rpc("shell_getPqPubkey", [fallback["address"]]).removeprefix("0x") == fallback["public_key"].removeprefix("0x")
                manifest.update(phase="complete", transfer_receipt=transfer_receipt)
                save_manifest()
                print("PASS: proposal matured; fresh SLH transfer and receipt survive CLI restart")
                raise SystemExit(0)
            print(json.dumps({"proposal_transaction": tx, "calldata": calldata,
                              "activation_height": activation, "receipt": receipt,
                              "head_after_restart": rpc("eth_blockNumber"),
                              "registry_after_restart": rpc("shell_getAlgorithmRegistry")}))
            print("PASS: signed quorum vote persists pending activation across CLI restart; pre-maturity transfer rejected")
            raise SystemExit(0)
        # Retire a different algorithm so consensus continues under ML-DSA.
        tx = cli("tx", "send", "--from", owner, "--to", REGISTRY, "--value", "0",
                 "--data", "0xa4b88278" + "00" * 32, "--gas-limit", "500000",
                 "--keystore", root / "fallback", "--rpc-url", url)
        receipt = wait_for(lambda: rpc("eth_getTransactionReceipt", [tx]))
        assert int(receipt["status"], 16) == 1, receipt
        assert int(receipt["gasUsed"], 16) > 0
        assert deprecated()
        assert rpc("shell_getPqPubkey", [owner]).removeprefix("0x") == primary["public_key"].removeprefix("0x")
        assert int(rpc("eth_getTransactionCount", [owner, "latest"]), 16) == 1
        # A fallback key cannot authorize an ordinary transfer for this identity.
        try:
            cli("tx", "send", "--from", owner, "--to", owner, "--value", "1",
                "--gas-limit", "21000", "--keystore", root / "fallback", "--rpc-url", url)
        except subprocess.CalledProcessError as error:
            assert "signature" in error.stderr.lower() or "pubkey" in error.stderr.lower(), error.stderr
        else:
            raise AssertionError("fallback key authorized a non-registry transfer")
        assert int(rpc("eth_getTransactionCount", [owner, "latest"]), 16) == 1
        stop()
        start()
        assert deprecated()
        assert rpc("eth_getTransactionReceipt", [tx])["blockHash"] == receipt["blockHash"]
        assert int(rpc("eth_getTransactionCount", [owner, "latest"]), 16) == 1
        assert rpc("shell_getPqPubkey", [owner]).removeprefix("0x") == primary["public_key"].removeprefix("0x")
        print("PASS: fallback governance executes, preserves primary identity, and survives restart")
    except Exception:
        log.flush()
        log.seek(0)
        print(log.read()[-12000:])
        raise
    finally:
        stop()
        log.close()
