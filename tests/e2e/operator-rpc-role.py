"""Run with a libp2p/RocksDB shell-node via NODE_BIN or target/debug/shell-node."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("NODE_BIN", ROOT / "target/debug/shell-node")).resolve()
WORK = Path(tempfile.mkdtemp(prefix="shell-rpc-role-"))
CHAIN = "0x539"
VALIDATOR = WORK / "validator"
OBSERVER = WORK / "observer"
AUTHORITY_KEY = VALIDATOR / "dev-authority.json"


def wait_for(check):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("condition timed out")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def block(node, tag):
    return node("eth_getBlockByNumber", [tag, False])


def identity(block_data):
    return tuple(block_data[key] for key in ("hash", "stateRoot", "miner"))


@contextmanager
def node(label, datadir, extra=()):
    endpoint = f"http://127.0.0.1:{port()}"
    log = WORK / f"{label}.log"
    args = [str(BINARY), "run", "--datadir", str(datadir), "--network", "dev",
            "--chain-id", "1337", "--db", "rocksdb", "--rpc-api", "eth,net,web3,shell,evm",
            "--rpc-addr", endpoint.removeprefix("http://"), "--metrics-addr", "127.0.0.1:0",
            "--p2p", "--p2p-addr", "127.0.0.1:0", "--consensus-engine", "wpoa",
            "--log-level", "info",
            "--block-time", "1000", "--max-idle-interval", "0", *extra]

    def rpc(method, params=(), *, allow_error=False):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        req = urllib.request.Request(endpoint, body.encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as response:
            result = json.load(response)
        if allow_error:
            return result
        assert "result" in result, result
        return result["result"]

    with log.open("wb") as output:
        process = subprocess.Popen(args, cwd=WORK, stdout=output, stderr=subprocess.STDOUT)
        try:
            assert wait_for(lambda: rpc("eth_chainId") == CHAIN)
            yield rpc, log
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        assert process.returncode == 0, log


def expect_rejection(datadir, flags, reason):
    result = subprocess.run([str(BINARY), "run", "--datadir", str(datadir),
                             "--node-role", "rpc", *flags],
                            cwd=WORK, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and reason in result.stderr, result.stderr
    assert not datadir.exists()


def main():
    expect_rejection(WORK / "missing", [], "requires a trusted genesis.json")
    expect_rejection(WORK / "forbidden", ["--keystore", "unused.json"],
                     "cannot use a validator keystore")
    with node("initial-validator", VALIDATOR) as (validator, _):
        assert validator("eth_mining") is True
        wait_for(lambda: int(block(validator, "finalized")["number"], 16) >= 2)
    key = fingerprint(AUTHORITY_KEY)

    with node("reused-volume-rpc", VALIDATOR, ["--node-role", "rpc"]) as (observer, _):
        assert observer("eth_mining") is False
        before = block(observer, "latest")
        rejected = observer("evm_mine", [1], allow_error=True)
        assert "error" in rejected and "result" not in rejected, rejected
        time.sleep(3.2)
        assert block(observer, "latest") == before
        assert identity(block(observer, "finalized")) == identity(before)
    assert fingerprint(AUTHORITY_KEY) == key

    OBSERVER.mkdir()
    shutil.copyfile(VALIDATOR / "genesis.json", OBSERVER / "genesis.json")
    config = WORK / "observer.toml"
    config.write_text('[node]\nnode_role = "rpc"\n')
    with node("reopened-validator", VALIDATOR) as (validator, validator_log):
        addr = wait_for(lambda: re.search(
            r"Listening on (/ip4/127\.0\.0\.1/tcp/[1-9][0-9]*/p2p/[A-Za-z0-9]+)",
            validator_log.read_text()))
        before = block(validator, "finalized")
        with node("fresh-rpc", OBSERVER, ["--config", str(config), "--bootnode", addr[1]]) as (observer, _):
            assert observer("eth_mining") is False
            assert wait_for(lambda: int(observer("net_peerCount"), 16) > 0)
            fixed_height = hex(int(before["number"], 16) + 1)
            def caught_up():
                finalized = block(observer, "finalized")
                return finalized if int(finalized["number"], 16) >= int(fixed_height, 16) else None
            wait_for(caught_up)
            assert identity(block(observer, fixed_height)) == identity(block(validator, fixed_height))
    assert not (OBSERVER / "dev-authority.json").exists()
    print("RPC role rejected local production and followed a live validator")


if __name__ == "__main__":
    print(f"Retaining fixtures and logs in {WORK}", flush=True)
    main()
